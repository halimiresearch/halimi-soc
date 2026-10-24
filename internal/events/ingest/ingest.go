// Package ingest coordinates the authoritative ingestion pipeline.
//
// The ordering here is the security contract from DESIGN.md §10:
//
//	validate -> persist idempotently -> detect -> correlate
//
// Persistence happens before detection, and detection runs only for an event
// that was newly inserted. That ordering is what makes replay safe: a duplicate
// event returns the existing identity and never re-enters the detection engine,
// so a replayed batch cannot inflate a sliding-window count into a false alert.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/correlation"
	"github.com/halimi/halimisoc/internal/detection/engine"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/events/validation"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/storage"
)

// Rejection records a single event that was not accepted.
type Rejection struct {
	Index  int    `json:"index"`
	ID     string `json:"id,omitempty"`
	Reason string `json:"reason"`
}

// Result summarises a batch ingestion.
type Result struct {
	Received   int                   `json:"received"`
	Inserted   int                   `json:"inserted"`
	Duplicates int                   `json:"duplicates"`
	Rejected   []Rejection           `json:"rejected,omitempty"`
	Alerts     []*alerts.Alert       `json:"alerts,omitempty"`
	Incidents  []*incidents.Incident `json:"incidents,omitempty"`

	// CorrelationErrors lists alerts that could not be grouped into an incident.
	// They are reported so a caller can see the degradation instead of assuming
	// every alert produced an incident.
	CorrelationErrors []string `json:"correlation_errors,omitempty"`
}

// Publisher receives pipeline events for the realtime feed.
//
// It is an interface rather than a concrete type so ingestion does not depend on
// the stream package, and so a deployment can run with no realtime feed at all.
// Every method must be non-blocking: a slow feed must never slow ingestion.
type Publisher interface {
	PublishAlertCreated(a *alerts.Alert)
	PublishIncident(created bool, inc *incidents.Incident)
}

// Ingester runs the ingestion pipeline.
type Ingester struct {
	store      storage.Store
	detector   *engine.Engine
	correlator *correlation.Engine
	opts       validation.Options
	reg        *metrics.Registry
	maxBatch   int
	publisher  Publisher
	now        func() time.Time
}

// New builds an ingester.
func New(store storage.Store, detector *engine.Engine, correlator *correlation.Engine, opts validation.Options, reg *metrics.Registry, maxBatch int) *Ingester {
	if reg == nil {
		reg = metrics.New()
	}
	if maxBatch <= 0 {
		maxBatch = 1000
	}
	return &Ingester{
		store:      store,
		detector:   detector,
		correlator: correlator,
		opts:       opts,
		reg:        reg,
		maxBatch:   maxBatch,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the clock. Test-only.
func (i *Ingester) SetClock(f func() time.Time) { i.now = f }

// SetPublisher attaches a realtime publisher.
//
// It is optional and set after construction so that the API can build the
// ingester before the server, which is the publisher, without a cycle. A nil
// publisher is the supported default: ingestion never depends on the feed.
func (i *Ingester) SetPublisher(p Publisher) { i.publisher = p }

// MaxBatch returns the configured batch bound.
func (i *Ingester) MaxBatch() int { return i.maxBatch }

// ErrBatchTooLarge means the submitted batch exceeds the configured bound.
var ErrBatchTooLarge = errors.New("event batch exceeds maximum size")

// Ingest processes a batch of events.
//
// A malformed event is rejected individually; it never fails the whole batch,
// because one hostile line in a log stream must not stop the ingestion of the
// remaining legitimate events. The rejected entries are returned so the agent
// can account for them instead of silently dropping telemetry.
func (in *Ingester) Ingest(ctx context.Context, events []*model.Event) (*Result, error) {
	if len(events) > in.maxBatch {
		return nil, fmt.Errorf("%w: %d > %d", ErrBatchTooLarge, len(events), in.maxBatch)
	}

	start := time.Now()
	defer func() { in.reg.Observe(metrics.IngestBatchDuration, time.Since(start).Seconds()) }()

	res := &Result{Received: len(events)}
	in.reg.Add(metrics.EventsReceivedTotal, float64(len(events)))

	for idx, e := range events {
		if err := ctx.Err(); err != nil {
			return res, err
		}

		if err := validation.Normalize(e, in.opts); err != nil {
			res.Rejected = append(res.Rejected, Rejection{
				Index:  idx,
				ID:     safeID(e),
				Reason: rejectReason(err),
			})
			in.reg.Inc(metrics.EventsDroppedTotal, metrics.L("reason", rejectReason(err)))
			continue
		}

		// Past timestamps are accepted without limit for backfill legitimacy,
		// but an event older than 24h is marked and counted so a compromised
		// agent flooding ancient telemetry to evade the 30m correlation window
		// is observable instead of silent. The marker uses an allowlisted
		// attribute key and a fixed value, so it cannot carry injected content.
		if e.Time.Before(in.now().Add(-24 * time.Hour)) {
			in.reg.Inc(metrics.ClockSkewAnomalyTotal, metrics.L("reason", "old_timestamp"))
			if e.Attributes == nil {
				e.Attributes = map[string]string{}
			}
			e.Attributes["timestamp_old"] = "true"
		}

		inserted, err := in.store.InsertEvent(ctx, e)
		if err != nil {
			return res, fmt.Errorf("ingest: persist event %s: %w", e.ID, err)
		}
		if !inserted {
			res.Duplicates++
			in.reg.Inc(metrics.EventsDuplicateTotal)
			continue
		}

		res.Inserted++
		in.reg.Inc(metrics.EventsProcessedTotal)

		produced, err := in.detector.Process(ctx, e)
		if err != nil {
			return res, fmt.Errorf("ingest: detect event %s: %w", e.ID, err)
		}
		for _, a := range produced {
			res.Alerts = append(res.Alerts, a)

			// Publish before correlation so the alert is visible immediately.
			// A realtime feed is an observer: if it fails, the alert is still
			// stored and still returned in the response.
			if in.publisher != nil {
				in.publisher.PublishAlertCreated(a)
			}

			cor, err := in.correlator.Process(ctx, a)
			if err != nil {
				// Correlation is enrichment, not a security control: a failure
				// here means an alert is not grouped, not that an alert was
				// missed. Failing the whole batch would make the agent retry a
				// request whose events are already stored, and the retry would
				// be suppressed as a duplicate, so the incident would still be
				// missing while the caller saw a spurious error. The failure is
				// recorded and the alert remains visible ungrouped.
				in.reg.Inc(metrics.CorrelationErrorTotal)
				in.reg.Inc(metrics.EventsDroppedTotal, metrics.L("reason", "CORRELATION_FAILED"))
				res.CorrelationErrors = append(res.CorrelationErrors, a.ID)
				continue
			}
			if cor != nil && cor.Incident != nil {
				res.Incidents = append(res.Incidents, cor.Incident)
				if in.publisher != nil {
					in.publisher.PublishIncident(cor.Created, cor.Incident)
				}
			}
		}
	}

	return res, nil
}

// rejectReason maps a validation error to a stable, non-leaking code.
//
// The API exposes these codes to the agent operator. Internal error text is
// deliberately not forwarded: it could reveal field names or bounds to an
// attacker probing the ingestion surface.
func rejectReason(err error) string {
	switch {
	case errors.Is(err, validation.ErrUnsupportedSchema):
		return "UNSUPPORTED_SCHEMA_VERSION"
	case errors.Is(err, validation.ErrClockSkew):
		return "EVENT_TIME_OUT_OF_RANGE"
	case errors.Is(err, validation.ErrTooLarge):
		return "EVENT_FIELD_TOO_LARGE"
	case errors.Is(err, validation.ErrMalformed):
		return "EVENT_MALFORMED"
	default:
		return "EVENT_INVALID"
	}
}

func safeID(e *model.Event) string {
	if e == nil {
		return ""
	}
	return e.ID
}

package correlation

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/storage"
)

// Engine attaches alerts to incidents.
type Engine struct {
	// mu serializes the read-modify-write; a multi-instance deployment would
	// need a database transaction instead.
	mu sync.Mutex

	store storage.Store
	opts  Options
	reg   *metrics.Registry
	now   func() time.Time
	newID func() string
}

// NewEngine builds a correlation engine.
func NewEngine(store storage.Store, reg *metrics.Registry) *Engine {
	if reg == nil {
		reg = metrics.New()
	}
	return &Engine{
		store: store,
		opts:  DefaultOptions(),
		reg:   reg,
		now:   func() time.Time { return time.Now().UTC() },
		newID: func() string { return id.New(id.KindIncident) },
	}
}

// SetOptions overrides the correlation bounds. Test-only.
func (e *Engine) SetOptions(o Options) { e.opts = o }

// SetClock overrides the clock. Test-only.
func (e *Engine) SetClock(f func() time.Time) { e.now = f }

// SetIDGenerator overrides the incident id generator. Test-only.
func (e *Engine) SetIDGenerator(f func() string) { e.newID = f }

// Result describes what correlation did with an alert.
type Result struct {
	Incident *incidents.Incident
	Created  bool
	Shared   []string
}

// Process attaches an alert to an existing incident or creates a new one.
func (e *Engine) Process(ctx context.Context, a *alerts.Alert) (*Result, error) {
	if a == nil {
		return nil, fmt.Errorf("correlation: nil alert")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()

	candidates, err := e.store.ListOpenIncidents(ctx)
	if err != nil {
		return nil, fmt.Errorf("correlation: list incidents: %w", err)
	}

	best, shared := e.selectCandidate(candidates, a)
	if best != nil {
		updated := Append(best, a, now)
		if err := updated.Validate(); err != nil {
			return nil, fmt.Errorf("correlation: merged incident invalid: %w", err)
		}
		if err := e.store.SaveIncident(ctx, updated); err != nil {
			return nil, fmt.Errorf("correlation: save merged incident: %w", err)
		}
		e.reg.Inc(metrics.CorrelationMergeTotal)
		return &Result{Incident: updated, Shared: shared}, nil
	}

	inc := New(e.newID(), a, now)
	if err := inc.Validate(); err != nil {
		return nil, fmt.Errorf("correlation: new incident invalid: %w", err)
	}
	if err := e.store.SaveIncident(ctx, inc); err != nil {
		return nil, fmt.Errorf("correlation: save incident: %w", err)
	}
	e.reg.Inc(metrics.IncidentCreatedTotal)
	return &Result{Incident: inc, Created: true}, nil
}

// selectCandidate chooses the incident an alert should join.
//
// Selection is deterministic and evidence-first: the incident sharing the most
// concrete entities wins. Ties are broken by the most recent activity, then by
// id, so replaying the same alerts in a different order still converges on the
// same grouping.
func (e *Engine) selectCandidate(candidates []*incidents.Incident, a *alerts.Alert) (*incidents.Incident, []string) {
	type scored struct {
		inc    *incidents.Incident
		shared []string
	}

	var matches []scored
	for _, inc := range candidates {
		ok, shared := ShouldJoin(inc, a, e.opts)
		if !ok {
			continue
		}
		matches = append(matches, scored{inc: inc, shared: shared})
	}
	if len(matches) == 0 {
		return nil, nil
	}

	sort.SliceStable(matches, func(i, j int) bool {
		if len(matches[i].shared) != len(matches[j].shared) {
			return len(matches[i].shared) > len(matches[j].shared)
		}
		if !matches[i].inc.LastSeen.Equal(matches[j].inc.LastSeen) {
			return matches[i].inc.LastSeen.After(matches[j].inc.LastSeen)
		}
		return matches[i].inc.ID > matches[j].inc.ID
	})

	return matches[0].inc, matches[0].shared
}

// IncidentSeverity computes an incident's deterministic severity.
//
// The policy is the documented baseline: the highest severity among the
// incident's alerts. AI never participates, and no client input is consulted.
func IncidentSeverity(alertSeverities []model.Severity) model.Severity {
	var out model.Severity
	for _, s := range alertSeverities {
		out = model.MaxSeverity(out, s)
	}
	return out
}

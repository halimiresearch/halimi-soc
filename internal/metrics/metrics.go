// Package metrics is a minimal, dependency-free metrics registry.
//
// DESIGN.md §25 requires a specific set of metric names to be observable. The
// registry is intentionally tiny: a Prometheus client would be a reasonable
// dependency, but the MVP needs only counters and gauges rendered in the
// Prometheus text format, which is a few dozen lines of standard library code.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Registry holds counters and gauges by name and label set.
type Registry struct {
	mu       sync.RWMutex
	counters map[string]float64
	gauges   map[string]float64
	help     map[string]string

	histograms map[string]*histogram
	bounds     map[string][]float64
}

// histogram is a fixed-bucket distribution for one label set.
type histogram struct {
	name   string
	bounds []float64
	counts []uint64 // cumulative, last element is +Inf
	sum    float64
	count  uint64
	labels []Label
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		counters:   map[string]float64{},
		gauges:     map[string]float64{},
		help:       map[string]string{},
		histograms: map[string]*histogram{},
		bounds:     map[string][]float64{},
	}
}

// Metric names required by DESIGN.md §25 plus the recommended additions.
const (
	EventsReceivedTotal      = "events_received_total"
	EventsProcessedTotal     = "events_processed_total"
	EventsDroppedTotal       = "events_dropped_total"
	EventsDuplicateTotal     = "event_duplicate_total"
	EventsPerSecond          = "events_per_second"
	DetectionTotal           = "detection_total"
	DetectionLatencyMS       = "detection_latency_ms"
	DetectionSuppressedTotal = "detection_cooldown_suppressed_total"
	IncidentCreatedTotal     = "incident_created_total"
	AgentLastHeartbeat       = "agent_last_heartbeat"
	QueueDepth               = "queue_depth"
	AIRequestsTotal          = "ai_requests_total"
	AILatencyMS              = "ai_latency_ms"
	AIErrorsTotal            = "ai_errors_total"
	AIRateLimitedTotal       = "ai_rate_limited_total"
	ParserErrorTotal         = "parser_error_total"
	RuleLoadFailureTotal     = "rule_load_failure_total"
	CorrelationMergeTotal    = "correlation_merge_total"
	CorrelationErrorTotal    = "correlation_error_total"
	SpoolBytes               = "spool_bytes"
	ClockSkewAnomalyTotal    = "clock_skew_anomaly_total"
	SSEActiveConnections     = "sse_active_connections"
	AlertsTotal              = "alerts_total"
	DetectionStateSize       = "detection_state_size"
	WebhookSentTotal         = "webhook_sent_total"
	WebhookErrorTotal        = "webhook_error_total"
	WebhookDroppedTotal      = "webhook_dropped_total"
	EnrollRateLimitedTotal   = "enroll_rate_limited_total"
	MFAFailureTotal          = "mfa_failure_total"
	MFABackupUsedTotal       = "mfa_backup_used_total"
	PasskeyFailureTotal      = "passkey_failure_total"
	PasskeyLoginTotal        = "passkey_login_total"

	HTTPRequestDuration = "http_request_duration_seconds"
	IngestBatchDuration = "ingest_batch_duration_seconds"
)

// Describe registers help text for a metric.
func (r *Registry) Describe(name, help string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.help[name] = help
}

// Inc increments a counter by one.
func (r *Registry) Inc(name string, labels ...Label) {
	r.Add(name, 1, labels...)
}

// Add increments a counter.
func (r *Registry) Add(name string, v float64, labels ...Label) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[seriesKey(name, labels)] += v
}

// Set assigns a gauge value.
func (r *Registry) Set(name string, v float64, labels ...Label) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[seriesKey(name, labels)] = v
}

// Counter returns the current counter value for a series.
func (r *Registry) Counter(name string, labels ...Label) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.counters[seriesKey(name, labels)]
}

// Gauge returns the current gauge value for a series.
func (r *Registry) Gauge(name string, labels ...Label) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.gauges[seriesKey(name, labels)]
}

// Histogram registers a distribution. Observing a name that was never
// registered is ignored, so a typo cannot mint a series.
func (r *Registry) Histogram(name, help string, buckets []float64) {
	sorted := append([]float64(nil), buckets...)
	sort.Float64s(sorted)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.help[name] = help
	r.bounds[name] = sorted
}

// Observe records one value in a registered histogram.
func (r *Registry) Observe(name string, v float64, labels ...Label) {
	r.mu.Lock()
	defer r.mu.Unlock()

	bounds, ok := r.bounds[name]
	if !ok {
		return
	}
	key := seriesKey(name, labels)
	h := r.histograms[key]
	if h == nil {
		h = &histogram{
			name:   name,
			bounds: bounds,
			counts: make([]uint64, len(bounds)+1),
			labels: sortedLabels(labels),
		}
		r.histograms[key] = h
	}

	h.sum += v
	h.count++
	for i, bound := range bounds {
		if v <= bound {
			h.counts[i]++
		}
	}
	h.counts[len(bounds)]++
}

// Label is a single label pair.
type Label struct {
	Name  string
	Value string
}

// L builds a label pair.
func L(name, value string) Label { return Label{Name: name, Value: value} }

// seriesKey renders "name{label="value",...}" with labels sorted by name so the
// key is stable regardless of call order.
func seriesKey(name string, labels []Label) string {
	if len(labels) == 0 {
		return name
	}
	sorted := append([]Label(nil), labels...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('{')
	for i, l := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", l.Name, escapeLabel(l.Value))
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func sortedLabels(labels []Label) []Label {
	sorted := append([]Label(nil), labels...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	return sorted
}

// bucketLabels renders the le bucket plus the series labels, in that order.
func bucketLabels(labels []Label, le string) string {
	parts := make([]string, 0, len(labels)+1)
	parts = append(parts, fmt.Sprintf("le=%q", le))
	for _, l := range labels {
		parts = append(parts, fmt.Sprintf("%s=%q", l.Name, escapeLabel(l.Value)))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// seriesLabels renders the label set without a bucket. An unlabeled series has
// no braces, which is what Prometheus expects for the sum/count suffixes.
func seriesLabels(labels []Label) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, 0, len(labels))
	for _, l := range labels {
		parts = append(parts, fmt.Sprintf("%s=%q", l.Name, escapeLabel(l.Value)))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// WritePrometheus renders all series in Prometheus text exposition format.
func (r *Registry) WritePrometheus(w io.Writer) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	type series struct {
		key   string
		value float64
		kind  string
	}
	all := make([]series, 0, len(r.counters)+len(r.gauges))
	for k, v := range r.counters {
		all = append(all, series{key: k, value: v, kind: "counter"})
	}
	for k, v := range r.gauges {
		all = append(all, series{key: k, value: v, kind: "gauge"})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].key != all[j].key {
			return all[i].key < all[j].key
		}
		return all[i].kind < all[j].kind
	})

	for _, s := range all {
		if _, err := fmt.Fprintf(w, "%s %g\n", s.key, s.value); err != nil {
			return err
		}
	}

	names := make([]string, 0, len(r.histograms))
	for key := range r.histograms {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		h := r.histograms[key]
		for i, bound := range h.bounds {
			if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", h.name,
				bucketLabels(h.labels, strconv.FormatFloat(bound, 'g', -1, 64)), h.counts[i]); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, bucketLabels(h.labels, "+Inf"), h.counts[len(h.bounds)]); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_sum%s %g\n", h.name, seriesLabels(h.labels), h.sum); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_count%s %d\n", h.name, seriesLabels(h.labels), h.count); err != nil {
			return err
		}
	}
	return nil
}

// Snapshot returns a copy of all series values, useful for tests.
func (r *Registry) Snapshot() map[string]float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]float64, len(r.counters)+len(r.gauges))
	for k, v := range r.counters {
		out[k] = v
	}
	for k, v := range r.gauges {
		out[k] = v
	}
	return out
}

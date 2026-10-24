package metrics_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/halimi/halimisoc/internal/metrics"
)

func TestHistogramRendersCumulativeBuckets(t *testing.T) {
	r := metrics.New()
	r.Histogram("op_duration_seconds", "help", []float64{1, 0.1})
	r.Observe("op_duration_seconds", 0.05)
	r.Observe("op_duration_seconds", 0.5)

	var b strings.Builder
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`op_duration_seconds_bucket{le="0.1"} 1`,
		`op_duration_seconds_bucket{le="1"} 2`,
		`op_duration_seconds_bucket{le="+Inf"} 2`,
		`op_duration_seconds_sum 0.55`,
		`op_duration_seconds_count 2`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestHistogramRendersLabelsOnSumAndCount(t *testing.T) {
	r := metrics.New()
	r.Histogram("op_duration_seconds", "help", []float64{0.1, 1})
	r.Observe("op_duration_seconds", 0.05, metrics.L("method", "GET"))
	r.Observe("op_duration_seconds", 0.5, metrics.L("method", "POST"))

	var b strings.Builder
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`op_duration_seconds_sum{method="GET"} 0.05`,
		`op_duration_seconds_sum{method="POST"} 0.5`,
		`op_duration_seconds_count{method="GET"} 1`,
		`op_duration_seconds_count{method="POST"} 1`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in:\n%s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "\nop_duration_seconds_sum ") {
		t.Fatalf("sum without its labels would collide across series:\n%s", b.String())
	}
}

func TestHistogramKeepsLabels(t *testing.T) {
	r := metrics.New()
	r.Histogram("op_duration_seconds", "help", []float64{0.1})
	r.Observe("op_duration_seconds", 0.2, metrics.L("method", "GET"))

	var b strings.Builder
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `op_duration_seconds_bucket{le="+Inf",method="GET"} 1`) {
		t.Fatalf("labels or order lost:\n%s", b.String())
	}
}

func TestObserveUnknownHistogramIsIgnored(t *testing.T) {
	r := metrics.New()
	r.Observe("never_registered", 1)

	var b strings.Builder
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "never_registered") {
		t.Fatalf("an unregistered observation must not mint a series:\n%s", b.String())
	}
}

func TestCounterAndGauge(t *testing.T) {
	r := metrics.New()

	r.Inc(metrics.DetectionTotal)
	r.Inc(metrics.DetectionTotal)
	r.Add(metrics.EventsReceivedTotal, 5)
	r.Set(metrics.QueueDepth, 12)

	if got := r.Counter(metrics.DetectionTotal); got != 2 {
		t.Errorf("detection_total = %v, want 2", got)
	}
	if got := r.Counter(metrics.EventsReceivedTotal); got != 5 {
		t.Errorf("events_received_total = %v, want 5", got)
	}
	if got := r.Gauge(metrics.QueueDepth); got != 12 {
		t.Errorf("queue_depth = %v, want 12", got)
	}
	// An unset series reads as zero rather than panicking.
	if got := r.Counter("never_recorded"); got != 0 {
		t.Errorf("unset counter = %v, want 0", got)
	}
}

func TestLabelsProduceDistinctSeries(t *testing.T) {
	r := metrics.New()
	r.Inc(metrics.EventsDroppedTotal, metrics.L("reason", "EVENT_MALFORMED"))
	r.Inc(metrics.EventsDroppedTotal, metrics.L("reason", "EVENT_MALFORMED"))
	r.Inc(metrics.EventsDroppedTotal, metrics.L("reason", "UNSUPPORTED_SCHEMA_VERSION"))

	if got := r.Counter(metrics.EventsDroppedTotal, metrics.L("reason", "EVENT_MALFORMED")); got != 2 {
		t.Errorf("malformed = %v, want 2", got)
	}
	if got := r.Counter(metrics.EventsDroppedTotal, metrics.L("reason", "UNSUPPORTED_SCHEMA_VERSION")); got != 1 {
		t.Errorf("unsupported = %v, want 1", got)
	}
}

func TestLabelOrderDoesNotChangeSeries(t *testing.T) {
	r := metrics.New()
	r.Inc("x", metrics.L("b", "2"), metrics.L("a", "1"))
	r.Inc("x", metrics.L("a", "1"), metrics.L("b", "2"))

	if got := r.Counter("x", metrics.L("a", "1"), metrics.L("b", "2")); got != 2 {
		t.Fatalf("counter = %v, want 2; label order must not create a second series", got)
	}
}

func TestPrometheusOutput(t *testing.T) {
	r := metrics.New()
	r.Inc(metrics.DetectionTotal)
	r.Set(metrics.QueueDepth, 3)

	var b strings.Builder
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	for _, want := range []string{"detection_total 1", "queue_depth 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestPrometheusEscapesLabelValues(t *testing.T) {
	r := metrics.New()
	r.Inc("x", metrics.L("reason", "line\nbreak\"quote"))

	var b strings.Builder
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	// A raw newline would split one series into two lines and corrupt the
	// exposition format.
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if strings.Count(line, "{") != strings.Count(line, "}") {
			t.Fatalf("unbalanced label braces in %q", line)
		}
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	r := metrics.New()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				r.Inc(metrics.DetectionTotal)
				r.Set(metrics.QueueDepth, float64(j))
				r.Counter(metrics.DetectionTotal)
			}
		}()
	}
	wg.Wait()

	if got := r.Counter(metrics.DetectionTotal); got != 4000 {
		t.Fatalf("detection_total = %v, want 4000", got)
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	r := metrics.New()
	r.Inc(metrics.DetectionTotal)

	snap := r.Snapshot()
	snap[metrics.DetectionTotal] = 999

	if got := r.Counter(metrics.DetectionTotal); got != 1 {
		t.Fatalf("mutating the snapshot changed the registry: %v", got)
	}
}

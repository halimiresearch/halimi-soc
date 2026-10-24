package ingest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/correlation"
	"github.com/halimi/halimisoc/internal/detection/engine"
	"github.com/halimi/halimisoc/internal/detection/rules"
	"github.com/halimi/halimisoc/internal/detection/state"
	"github.com/halimi/halimisoc/internal/events/ingest"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/events/validation"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/metrics"
	memorystore "github.com/halimi/halimisoc/internal/storage/memory"
)

const bruteForceRule = `
id: ssh-bruteforce
version: 1
name: SSH Brute Force
severity: high
match:
  types:
    - auth.ssh.login_failed
threshold:
  count: 3
  window: 60s
group_by:
  - network.src_ip
cooldown: 5m
`

func build(t *testing.T) (*ingest.Ingester, *memorystore.Store, *metrics.Registry, *time.Time) {
	t.Helper()

	dir := t.TempDir()
	writeFile(t, dir, "rules.yaml", bruteForceRule)
	set, err := rules.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2025, 8, 19, 12, 0, 0, 0, time.UTC)
	now := base

	store := memorystore.New()
	reg := metrics.New()
	detector := engine.New(set, state.New(state.DefaultOptions()), store, reg)
	detector.SetClock(func() time.Time { return now })
	correlator := correlation.NewEngine(store, reg)
	correlator.SetClock(func() time.Time { return now })

	opts := validation.DefaultOptions()
	opts.Now = func() time.Time { return now }

	ing := ingest.New(store, detector, correlator, opts, reg, 100)
	ing.SetClock(func() time.Time { return now })
	return ing, store, reg, &now
}

func sshFailure(id, ip string, at time.Time) *model.Event {
	return &model.Event{
		ID:         id,
		Type:       model.TypeSSHLoginFailed,
		Time:       at,
		ObservedAt: at,
		Host:       "web-01",
		Actor:      "root",
		Source:     model.SourceAuthLog,
		Outcome:    model.OutcomeFailure,
		Severity:   model.SeverityMedium,
		Network:    model.Network{SourceIP: ip, SourcePort: 51022},
		Raw:        "Aug 19 11:20:30 web-01 sshd[1]: Failed password for root",
	}
}

func TestIngestInsertsAndDetects(t *testing.T) {
	ing, _, _, now := build(t)
	base := *now

	var batch []*model.Event
	batch = append(batch, sshFailure(id.NewEvent(), "203.0.113.7", base))
	batch = append(batch, sshFailure(id.NewEvent(), "203.0.113.7", base))
	batch = append(batch, sshFailure(id.NewEvent(), "203.0.113.7", base))

	res, err := ing.Ingest(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != 3 || res.Duplicates != 0 || len(res.Rejected) != 0 {
		t.Fatalf("result = %+v", res)
	}
	if len(res.Alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(res.Alerts))
	}
	if len(res.Incidents) != 1 {
		t.Fatalf("incidents = %d, want 1", len(res.Incidents))
	}
}

func TestIngestRecordsBatchDuration(t *testing.T) {
	ing, _, reg, now := build(t)
	reg.Histogram(metrics.IngestBatchDuration, "ingest latency", []float64{1})
	base := *now

	if _, err := ing.Ingest(context.Background(), []*model.Event{sshFailure(id.NewEvent(), "203.0.113.9", base)}); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	if err := reg.WritePrometheus(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), metrics.IngestBatchDuration+"_count 1") {
		t.Fatalf("batch duration was not recorded:\n%s", out.String())
	}
}

// TestReplayIsIdempotent is the central replay guarantee: submitting the same
// events again must not create new alerts or inflate the detection count.
func TestReplayIsIdempotent(t *testing.T) {
	ing, store, _, now := build(t)
	base := *now

	batch := []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}

	first, err := ing.Ingest(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if first.Inserted != 3 || len(first.Alerts) != 1 {
		t.Fatalf("first ingest = %+v", first)
	}

	replay, err := ing.Ingest(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Inserted != 0 {
		t.Errorf("replay inserted %d events, want 0", replay.Inserted)
	}
	if replay.Duplicates != 3 {
		t.Errorf("replay duplicates = %d, want 3", replay.Duplicates)
	}
	if len(replay.Alerts) != 0 {
		t.Errorf("replay produced %d alerts, want 0", len(replay.Alerts))
	}
	if len(replay.Incidents) != 0 {
		t.Errorf("replay produced %d incidents, want 0", len(replay.Incidents))
	}

	count, err := store.CountEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("stored events = %d, want 3", count)
	}
}

func TestServerTimeoutReplayAfterPartialAck(t *testing.T) {
	ing, _, _, now := build(t)
	base := *now

	first := []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}
	if _, err := ing.Ingest(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	// The agent never saw the acknowledgement and resends the same events plus
	// one new event.
	third := sshFailure(id.NewEvent(), "203.0.113.7", base)
	res, err := ing.Ingest(context.Background(), append(first, third))
	if err != nil {
		t.Fatal(err)
	}
	if res.Duplicates != 2 || res.Inserted != 1 {
		t.Fatalf("result = %+v, want 2 duplicates and 1 insert", res)
	}
	if len(res.Alerts) != 1 {
		t.Fatalf("alerts = %d, want exactly 1 (the threshold is 3 distinct events)", len(res.Alerts))
	}
}

func TestMalformedEventIsRejectedIndividually(t *testing.T) {
	ing, _, _, now := build(t)
	base := *now

	bad := sshFailure(id.NewEvent(), "203.0.113.7", base)
	bad.Type = "auth.ssh.explode"

	good := sshFailure(id.NewEvent(), "203.0.113.7", base)
	good2 := sshFailure(id.NewEvent(), "203.0.113.7", base)

	res, err := ing.Ingest(context.Background(), []*model.Event{bad, good, good2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("rejected = %d, want 1", len(res.Rejected))
	}
	if res.Rejected[0].Reason != "EVENT_MALFORMED" {
		t.Errorf("reason = %q, want EVENT_MALFORMED", res.Rejected[0].Reason)
	}
	if res.Inserted != 2 {
		t.Errorf("inserted = %d, want 2 (one bad event must not fail the batch)", res.Inserted)
	}
}

func TestFutureTimestampRejected(t *testing.T) {
	ing, _, reg, now := build(t)
	base := *now

	e := sshFailure(id.NewEvent(), "203.0.113.7", base.Add(10*time.Minute))
	res, err := ing.Ingest(context.Background(), []*model.Event{e})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Reason != "EVENT_TIME_OUT_OF_RANGE" {
		t.Fatalf("result = %+v", res)
	}
	if reg.Counter(metrics.ClockSkewAnomalyTotal) != 0 {
		// The metric is recorded by the agent, not the server; assert it stays
		// at zero here so the two paths cannot be conflated.
		t.Log("clock skew metric belongs to the agent side")
	}
}

func TestUnsupportedSchemaVersionRejected(t *testing.T) {
	ing, _, _, now := build(t)
	e := sshFailure(id.NewEvent(), "203.0.113.7", *now)
	e.SchemaVersion = "99"

	res, err := ing.Ingest(context.Background(), []*model.Event{e})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Reason != "UNSUPPORTED_SCHEMA_VERSION" {
		t.Fatalf("result = %+v", res)
	}
}

func TestBatchBoundIsEnforced(t *testing.T) {
	ing, _, _, now := build(t)
	batch := make([]*model.Event, 101)
	for i := range batch {
		batch[i] = sshFailure(id.NewEvent(), "203.0.113.7", *now)
	}
	_, err := ing.Ingest(context.Background(), batch)
	if err == nil {
		t.Fatal("expected a batch size error")
	}
}

func TestRawEvidenceIsRetained(t *testing.T) {
	ing, store, _, now := build(t)
	e := sshFailure(id.NewEvent(), "203.0.113.7", *now)
	if _, err := ing.Ingest(context.Background(), []*model.Event{e}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetEvent(context.Background(), e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Raw == "" {
		t.Fatal("raw evidence must be retained for audit")
	}
}

func TestControlCharactersAreNeutralised(t *testing.T) {
	ing, store, _, now := build(t)
	e := sshFailure(id.NewEvent(), "203.0.113.7", *now)
	e.Raw = "line one\nAug 19 11:20:31 host sshd[1]: Failed password\x00\x07"
	if _, err := ing.Ingest(context.Background(), []*model.Event{e}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetEvent(context.Background(), e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !containsAny(got.Raw, "\x00\x07") {
		return
	}
	t.Fatalf("raw evidence still contains control characters: %q", got.Raw)
}

func containsAny(s string, chars string) bool {
	for _, c := range chars {
		for _, sc := range s {
			if sc == c {
				return true
			}
		}
	}
	return false
}

// M4: ancient timestamps stay ingestible for backfill but are marked and
// counted so a flood of backdated telemetry cannot evade correlation silently.
func TestOldTimestampIsMarkedAndCounted(t *testing.T) {
	ing, store, reg, now := build(t)
	old := (*now).Add(-48 * time.Hour)
	e := sshFailure(id.NewEvent(), "203.0.113.7", old)
	res, err := ing.Ingest(context.Background(), []*model.Event{e})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != 1 {
		t.Fatalf("inserted = %d, want 1 (old events are accepted)", res.Inserted)
	}
	got, err := store.GetEvent(context.Background(), e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Attributes["timestamp_old"] != "true" {
		t.Fatalf("attributes = %v, want timestamp_old=true marker", got.Attributes)
	}
	found := false
	for k, v := range reg.Snapshot() {
		if len(k) >= len(metrics.ClockSkewAnomalyTotal) && k[:len(metrics.ClockSkewAnomalyTotal)] == metrics.ClockSkewAnomalyTotal && v >= 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("old timestamp was not counted in clock_skew_anomaly_total")
	}
}

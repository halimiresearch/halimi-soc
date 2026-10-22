package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/detection/rules"
	"github.com/halimi/halimisoc/internal/detection/state"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/metrics"
)

type memorySink struct {
	mu   sync.Mutex
	rows []*alerts.Alert
	fail error
}

func (s *memorySink) SaveAlert(_ context.Context, a *alerts.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	cp := *a
	cp.EventIDs = append([]string(nil), a.EventIDs...)
	s.rows = append(s.rows, &cp)
	return nil
}

func (s *memorySink) alerts() []*alerts.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*alerts.Alert(nil), s.rows...)
}

func mustSet(t *testing.T, bodies ...string) *rules.Set {
	t.Helper()
	merged := ""
	for i, b := range bodies {
		if i > 0 {
			merged += "\n---\n"
		}
		merged += b
	}
	dir := t.TempDir()
	writeRules(t, dir, merged)
	set, err := rules.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() = %v", err)
	}
	return set
}

const bruteForceRule = `
id: ssh-bruteforce
version: 1
name: SSH Brute Force
severity: high
match:
  types:
    - auth.ssh.login_failed
  outcomes:
    - failure
threshold:
  count: 5
  window: 60s
group_by:
  - network.src_ip
cooldown: 5m
`

const chainRule = `
id: login-after-bruteforce
version: 1
name: Login After Brute Force
severity: critical
match:
  types:
    - auth.ssh.login_success
threshold:
  count: 1
  window: 10m
group_by:
  - network.src_ip
requires:
  rule_id: ssh-bruteforce
  window: 10m
  match_on: network.src_ip
cooldown: 5m
`

func newEngine(t *testing.T, bodies ...string) (*Engine, *memorySink, *metrics.Registry, *time.Time) {
	t.Helper()
	clock := time.Date(2025, 8, 19, 12, 0, 0, 0, time.UTC)
	now := clock
	sink := &memorySink{}
	reg := metrics.New()
	eng := New(mustSet(t, bodies...), state.New(state.DefaultOptions()), sink, reg)
	eng.SetClock(func() time.Time { return now })
	seq := 0
	eng.SetIDGenerator(func() string {
		seq++
		return "alt_test_" + string(rune('a'+seq%26)) + string(rune('0'+seq/26%10))
	})
	return eng, sink, reg, &now
}

func failedLogin(id, ip string, at time.Time) *model.Event {
	return &model.Event{
		ID:         id,
		Type:       model.TypeSSHLoginFailed,
		Time:       at,
		ReceivedAt: at,
		Host:       "web-01",
		Actor:      "root",
		Outcome:    model.OutcomeFailure,
		Severity:   model.SeverityLow,
		Network:    model.Network{SourceIP: ip},
		Attributes: map[string]string{},
	}
}

func successLogin(id, ip string, at time.Time) *model.Event {
	return &model.Event{
		ID:         id,
		Type:       model.TypeSSHLoginSuccess,
		Time:       at,
		ReceivedAt: at,
		Host:       "web-01",
		Actor:      "root",
		Outcome:    model.OutcomeSuccess,
		Severity:   model.SeverityLow,
		Network:    model.Network{SourceIP: ip},
		Attributes: map[string]string{},
	}
}

func TestThresholdBoundary(t *testing.T) {
	eng, sink, _, now := newEngine(t, bruteForceRule)
	ctx := context.Background()
	base := *now

	// Four events: below threshold, no alert.
	for i := 0; i < 4; i++ {
		got, err := eng.Process(ctx, failedLogin(eventID(i), "203.0.113.7", base))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("alert fired at %d events, want threshold at 5", i+1)
		}
	}

	// The fifth event crosses the threshold.
	got, err := eng.Process(ctx, failedLogin(eventID(4), "203.0.113.7", base))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("alerts = %d, want 1 at threshold", len(got))
	}
	if n := len(sink.alerts()); n != 1 {
		t.Fatalf("persisted alerts = %d, want 1", n)
	}
	a := got[0]
	if a.Count != 5 {
		t.Errorf("count = %d, want 5", a.Count)
	}
	if len(a.EventIDs) != 5 {
		t.Errorf("evidence events = %d, want 5", len(a.EventIDs))
	}
	if a.RuleID != "ssh-bruteforce" || a.RuleVersion != 1 {
		t.Errorf("rule identity = %s@%d", a.RuleID, a.RuleVersion)
	}
	if a.Severity != model.SeverityHigh {
		t.Errorf("severity = %s, want the rule severity", a.Severity)
	}
	if a.Status != alerts.StatusOpen {
		t.Errorf("status = %s, want OPEN", a.Status)
	}
}

func TestSeverityComesFromRuleNotEvent(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule)
	base := *now
	for i := 0; i < 5; i++ {
		e := failedLogin(eventID(i), "203.0.113.7", base)
		// A source claiming critical must not influence the alert severity.
		e.Severity = model.SeverityCritical
		got, err := eng.Process(context.Background(), e)
		if err != nil {
			t.Fatal(err)
		}
		if i == 4 {
			if got[0].Severity != model.SeverityHigh {
				t.Fatalf("alert severity = %s, want rule severity high", got[0].Severity)
			}
		}
	}
}

func TestWindowBoundaryExcludesOldEvents(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule)
	base := *now

	// Four events at the start of the window.
	for i := 0; i < 4; i++ {
		if _, err := eng.Process(context.Background(), failedLogin(eventID(i), "203.0.113.7", base)); err != nil {
			t.Fatal(err)
		}
	}
	// The fifth arrives 61s later, outside the 60s window, so the four original
	// events have expired and only one event is in the window.
	got, err := eng.Process(context.Background(), failedLogin(eventID(4), "203.0.113.7", base.Add(61*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("alert fired across the window boundary: %+v", got[0])
	}
}

func TestGroupingIsolatesSources(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule)
	base := *now

	// Five failures from one IP must not be satisfied by spreading attempts
	// across five different IPs.
	for i := 0; i < 5; i++ {
		ip := "203.0.113." + string(rune('1'+i))
		got, err := eng.Process(context.Background(), failedLogin(eventID(i), ip, base))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("alert fired for ungrouped source at event %d", i+1)
		}
	}
}

func TestCooldownSuppressesRepeatedAlerts(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule)
	base := *now
	ctx := context.Background()

	// First alert at the fifth event.
	for i := 0; i < 5; i++ {
		if _, err := eng.Process(ctx, failedLogin(eventID(i), "203.0.113.7", base)); err != nil {
			t.Fatal(err)
		}
	}
	// Five more within the cooldown must not produce a second alert.
	for i := 5; i < 10; i++ {
		got, err := eng.Process(ctx, failedLogin(eventID(i), "203.0.113.7", base.Add(time.Duration(i)*time.Second)))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("alert %d emitted during cooldown", i)
		}
	}
	// After the cooldown elapses, a fresh burst alerts again.
	after := base.Add(6 * time.Minute)
	for i := 10; i < 15; i++ {
		got, err := eng.Process(ctx, failedLogin(eventID(i), "203.0.113.7", after.Add(time.Duration(i)*time.Second)))
		if err != nil {
			t.Fatal(err)
		}
		if i == 14 && len(got) != 1 {
			t.Fatalf("expected an alert after cooldown expiry, got %d", len(got))
		}
	}
}

func TestChainingRequiresPrerequisite(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule, chainRule)
	base := *now
	ctx := context.Background()

	// A successful login with no prior brute force must not alert, even though
	// the chained rule's threshold is satisfied.
	got, err := eng.Process(ctx, successLogin(eventID(0), "203.0.113.7", base))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("chained rule fired without its prerequisite")
	}

	// Establish the prerequisite.
	for i := 1; i <= 5; i++ {
		if _, err := eng.Process(ctx, failedLogin(eventID(i), "203.0.113.7", base)); err != nil {
			t.Fatal(err)
		}
	}

	got, err = eng.Process(ctx, successLogin(eventID(6), "203.0.113.7", base.Add(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("alerts = %d, want 1 after prerequisite fired", len(got))
	}
	if got[0].RuleID != "login-after-bruteforce" {
		t.Fatalf("rule = %s", got[0].RuleID)
	}
}

func TestChainingRequiresSameEntity(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule, chainRule)
	base := *now
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		if _, err := eng.Process(ctx, failedLogin(eventID(i), "203.0.113.7", base)); err != nil {
			t.Fatal(err)
		}
	}
	// A successful login from a different source must not chain onto the
	// brute force seen from another address.
	got, err := eng.Process(ctx, successLogin(eventID(9), "198.51.100.9", base.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("chained rule matched a different source address")
	}
}

func TestChainingWindowExpiry(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule, chainRule)
	base := *now
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		if _, err := eng.Process(ctx, failedLogin(eventID(i), "203.0.113.7", base)); err != nil {
			t.Fatal(err)
		}
	}
	// The prerequisite window is 10m; a login 11m later must not chain.
	got, err := eng.Process(ctx, successLogin(eventID(9), "203.0.113.7", base.Add(11*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("chained rule fired outside the prerequisite window")
	}
}

func TestRestartResetsDetectionState(t *testing.T) {
	ctx := context.Background()
	set := mustSet(t, bruteForceRule)
	base := time.Date(2025, 8, 19, 12, 0, 0, 0, time.UTC)

	first := New(set, state.New(state.DefaultOptions()), &memorySink{}, metrics.New())
	for i := 0; i < 4; i++ {
		if _, err := first.Process(ctx, failedLogin(eventID(i), "203.0.113.7", base)); err != nil {
			t.Fatal(err)
		}
	}

	// Simulate a process restart: a fresh state store, same rule set.
	second := New(set, state.New(state.DefaultOptions()), &memorySink{}, metrics.New())
	got, err := second.Process(ctx, failedLogin(eventID(4), "203.0.113.7", base))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("ephemeral detection state survived a restart; it must not")
	}
}

func TestUncategorisedEventIsNotCounted(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule)
	base := *now
	ctx := context.Background()

	// Events with no source IP cannot be grouped, so they must never satisfy a
	// threshold that is grouped by source IP.
	for i := 0; i < 10; i++ {
		e := failedLogin(eventID(i), "", base)
		got, err := eng.Process(ctx, e)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatal("ungroupable events contributed to a grouped threshold")
		}
	}
}

func TestMetricsAreRecorded(t *testing.T) {
	eng, _, reg, now := newEngine(t, bruteForceRule)
	base := *now
	for i := 0; i < 5; i++ {
		if _, err := eng.Process(context.Background(), failedLogin(eventID(i), "203.0.113.7", base)); err != nil {
			t.Fatal(err)
		}
	}
	if got := reg.Counter(metrics.DetectionTotal); got != 1 {
		t.Errorf("detection_total = %v, want 1", got)
	}
	if got := reg.Counter(metrics.AlertsTotal, metrics.L("severity", "high")); got != 1 {
		t.Errorf("alerts_total{severity=high} = %v, want 1", got)
	}
}

func TestProcessRejectsNilEvent(t *testing.T) {
	eng, _, _, _ := newEngine(t, bruteForceRule)
	if _, err := eng.Process(context.Background(), nil); err == nil {
		t.Fatal("expected an error for a nil event")
	}
}

func TestSinkFailureIsReported(t *testing.T) {
	eng, sink, _, now := newEngine(t, bruteForceRule)
	sink.fail = context.Canceled
	base := *now
	var err error
	for i := 0; i < 5; i++ {
		_, err = eng.Process(context.Background(), failedLogin(eventID(i), "203.0.113.7", base))
	}
	if err == nil {
		t.Fatal("expected the sink failure to surface")
	}
}

func eventID(i int) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	s := "evt_01ARZ3NDEKTSV4RRFFQ69G5"
	var b [3]byte
	b[0] = alphabet[(i/1024)%32]
	b[1] = alphabet[(i/32)%32]
	b[2] = alphabet[i%32]
	return s + string(b[:])
}

// M3: a second burst inside the cooldown is suppressed as an alert but must be
// counted, so an attacker hiding a real burst behind a trigger burst is visible
// in metrics even when no second alert fires.
func TestCooldownSuppressionIsCounted(t *testing.T) {
	eng, _, reg, now := newEngine(t, bruteForceRule)
	base := *now
	for i := 0; i < 5; i++ {
		if _, err := eng.Process(context.Background(), failedLogin(eventID(i), "203.0.113.7", base)); err != nil {
			t.Fatal(err)
		}
	}
	if got := reg.Counter(metrics.DetectionTotal); got != 1 {
		t.Fatalf("detection_total = %v, want 1", got)
	}
	for i := 5; i < 10; i++ {
		if _, err := eng.Process(context.Background(), failedLogin(eventID(i), "203.0.113.7", base.Add(10*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	if got := reg.Counter(metrics.DetectionTotal); got != 1 {
		t.Fatalf("second burst fired during cooldown: detection_total = %v, want 1", got)
	}
	if got := reg.Counter(metrics.DetectionSuppressedTotal, metrics.L("rule", "ssh-bruteforce")); got < 1 {
		t.Fatalf("suppressed_total = %v, want >=1", got)
	}
}

// A spray that stays under threshold is invisible by design: alerting on every
// few failures would be noise, so the threshold is the contract. An attacker
// who knows the rule (count 5 per 60s) can evade it with 4 per 60s.
func TestLowAndSlowSprayDoesNotAlert(t *testing.T) {
	eng, sink, _, now := newEngine(t, bruteForceRule)
	base := *now
	for i := 0; i < 4; i++ {
		if _, err := eng.Process(context.Background(), failedLogin(eventID(i), "203.0.113.7", base.Add(time.Duration(i*15)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts = %d, want 0 for a below-threshold spray", got)
	}
}

func TestPruneRemovesExpiredDetectionState(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule)
	base := *now

	if _, err := eng.Process(context.Background(), failedLogin("evt_1", "203.0.113.7", base)); err != nil {
		t.Fatal(err)
	}
	if eng.StateSize() == 0 {
		t.Fatal("expected detection state after processing an event")
	}

	eng.Prune(base.Add(25 * time.Hour))
	if got := eng.StateSize(); got != 0 {
		t.Fatalf("state size = %d after prune, want 0", got)
	}
}

func TestReloadIsSafeDuringProcessing(t *testing.T) {
	eng, _, _, now := newEngine(t, bruteForceRule)
	setA := mustSet(t, bruteForceRule)
	setB := mustSet(t, bruteForceRule, chainRule)
	base := *now

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			eng.Reload(setA)
			eng.Reload(setB)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			if _, err := eng.Process(context.Background(), failedLogin(eventID(i), "203.0.113.7", base)); err != nil {
				t.Errorf("Process() = %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

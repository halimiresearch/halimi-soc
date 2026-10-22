package correlation_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/correlation"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/metrics"
	memorystore "github.com/halimi/halimisoc/internal/storage/memory"
)

func alert(id, rule, host, actor, ip string, sev model.Severity, at time.Time) *alerts.Alert {
	return &alerts.Alert{
		ID:          id,
		RuleID:      rule,
		RuleVersion: 1,
		RuleName:    rule,
		Severity:    sev,
		Status:      alerts.StatusOpen,
		Title:       rule,
		Reason:      "test",
		Host:        host,
		Actor:       actor,
		SourceIP:    ip,
		EventIDs:    []string{"evt_01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		Count:       1,
		WindowStart: at,
		WindowEnd:   at,
		DedupeKey:   rule + "|" + host,
		CreatedAt:   at,
		UpdatedAt:   at,
	}
}

func TestSharedEntityNeverMatchesOnEmptyValues(t *testing.T) {
	a := correlation.Data{Host: "web-01"}
	b := correlation.Data{Host: "db-01"}
	if got := correlation.SharedEntity(a, b); len(got) != 0 {
		t.Fatalf("unrelated hosts shared %v", got)
	}

	// Two alerts with no entities at all must not be considered related.
	if got := correlation.SharedEntity(correlation.Data{}, correlation.Data{}); len(got) != 0 {
		t.Fatalf("empty entity sets matched: %v", got)
	}
}

func TestWeakEntityAloneDoesNotMergeDifferentHosts(t *testing.T) {
	base := time.Now().UTC()

	// Same source IP, different hosts. Merging these would attribute one
	// attacker's activity against two unrelated machines to a single incident.
	a := alert("alt_1", "ssh-bruteforce", "web-01", "", "203.0.113.7", model.SeverityHigh, base)
	b := alert("alt_2", "ssh-bruteforce", "db-01", "", "203.0.113.7", model.SeverityHigh, base.Add(time.Minute))

	inc := correlation.New("inc_1", a, base)
	ok, _ := correlation.ShouldJoin(inc, b, correlation.DefaultOptions())
	if ok {
		t.Fatal("a shared source IP alone merged two different hosts")
	}
}

func TestSameHostAndActorMerges(t *testing.T) {
	base := time.Now().UTC()
	a := alert("alt_1", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base)
	b := alert("alt_2", "ssh-login-after-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityCritical, base.Add(time.Minute))

	inc := correlation.New("inc_1", a, base)
	ok, shared := correlation.ShouldJoin(inc, b, correlation.DefaultOptions())
	if !ok {
		t.Fatal("expected alerts on the same host and actor to merge")
	}
	if len(shared) == 0 {
		t.Fatal("merge must report why it happened")
	}
}

func TestWindowBoundStopsMergingStaleAlerts(t *testing.T) {
	base := time.Now().UTC()
	opts := correlation.DefaultOptions()

	a := alert("alt_1", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base)
	inc := correlation.New("inc_1", a, base)

	// Far outside the window: a new alert is a new incident.
	stale := alert("alt_2", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh,
		base.Add(opts.Window+time.Hour))
	if ok, _ := correlation.ShouldJoin(inc, stale, opts); ok {
		t.Fatal("alert outside the correlation window merged into the incident")
	}
}

func TestAppendPromotesSeverityAndRecordsStage(t *testing.T) {
	base := time.Now().UTC()

	a := alert("alt_1", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base)
	inc := correlation.New("inc_1", a, base)

	b := alert("alt_2", "ssh-authorized-keys-modified", "web-01", "root", "203.0.113.7",
		model.SeverityCritical, base.Add(2*time.Minute))
	merged := correlation.Append(inc, b, base.Add(2*time.Minute))

	if merged.Severity != model.SeverityCritical {
		t.Fatalf("severity = %s, want critical (highest alert wins)", merged.Severity)
	}
	if len(merged.AlertIDs) != 2 {
		t.Fatalf("alert ids = %v", merged.AlertIDs)
	}
	if len(merged.Stages) != 2 {
		t.Fatalf("stages = %d, want 2", len(merged.Stages))
	}
	if merged.Stages[1].Name != incidents.StagePersistence {
		t.Errorf("stage = %s, want PERSISTENCE", merged.Stages[1].Name)
	}
	// The input incident must not be mutated: merges are applied by persisting
	// the returned copy, which keeps the operation auditable.
	if len(inc.AlertIDs) != 1 {
		t.Fatal("Append mutated its input incident")
	}
}

func TestEngineCreatesThenMerges(t *testing.T) {
	store := memorystore.New()
	reg := metrics.New()
	eng := correlation.NewEngine(store, reg)

	base := time.Now().UTC()
	eng.SetClock(func() time.Time { return base })

	first, err := eng.Process(context.Background(), alert("alt_1", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created {
		t.Fatal("expected a new incident")
	}

	second, err := eng.Process(context.Background(), alert("alt_2", "ssh-login-after-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityCritical, base.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if second.Created {
		t.Fatal("expected the second alert to merge")
	}
	if second.Incident.ID != first.Incident.ID {
		t.Fatalf("incident id changed: %s vs %s", second.Incident.ID, first.Incident.ID)
	}
	if second.Incident.Severity != model.SeverityCritical {
		t.Errorf("incident severity = %s, want critical", second.Incident.Severity)
	}

	open, err := store.ListOpenIncidents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("open incidents = %d, want 1", len(open))
	}
	if reg.Counter(metrics.IncidentCreatedTotal) != 1 {
		t.Errorf("incident_created_total = %v, want 1", reg.Counter(metrics.IncidentCreatedTotal))
	}
	if reg.Counter(metrics.CorrelationMergeTotal) != 1 {
		t.Errorf("correlation_merge_total = %v, want 1", reg.Counter(metrics.CorrelationMergeTotal))
	}
}

func TestEngineReplayDoesNotDuplicateIncidents(t *testing.T) {
	store := memorystore.New()
	eng := correlation.NewEngine(store, metrics.New())
	base := time.Now().UTC()
	eng.SetClock(func() time.Time { return base })

	a := alert("alt_1", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base)
	if _, err := eng.Process(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	// The same alert replayed must merge rather than create a second incident.
	// In practice the ingestion layer suppresses the duplicate before it reaches
	// correlation, so this is defence in depth.
	if _, err := eng.Process(context.Background(), a); err != nil {
		t.Fatal(err)
	}

	open, err := store.ListOpenIncidents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("open incidents = %d, want 1 after replay", len(open))
	}
}

func TestIncidentSeverityPolicy(t *testing.T) {
	got := correlation.IncidentSeverity([]model.Severity{
		model.SeverityLow, model.SeverityCritical, model.SeverityMedium,
	})
	if got != model.SeverityCritical {
		t.Fatalf("severity = %s, want critical", got)
	}
}

func TestIncidentLifecycleIsForwardOnly(t *testing.T) {
	cases := []struct {
		from, to incidents.Status
		want     bool
	}{
		{incidents.StatusNew, incidents.StatusAcknowledged, true},
		{incidents.StatusNew, incidents.StatusInvestigating, true},
		{incidents.StatusAcknowledged, incidents.StatusInvestigating, true},
		{incidents.StatusInvestigating, incidents.StatusContained, true},
		{incidents.StatusInvestigating, incidents.StatusResolved, true},
		{incidents.StatusContained, incidents.StatusResolved, true},
		{incidents.StatusResolved, incidents.StatusClosed, true},

		// A false positive can be recognised from any active state.
		{incidents.StatusNew, incidents.StatusFalsePositive, true},
		{incidents.StatusInvestigating, incidents.StatusFalsePositive, true},

		// Stages cannot be skipped, and terminal states cannot be reopened.
		{incidents.StatusNew, incidents.StatusContained, false},
		{incidents.StatusNew, incidents.StatusResolved, false},
		{incidents.StatusContained, incidents.StatusInvestigating, false},
		{incidents.StatusResolved, incidents.StatusInvestigating, false},
		{incidents.StatusClosed, incidents.StatusNew, false},
		{incidents.StatusFalsePositive, incidents.StatusNew, false},
		{incidents.StatusClosed, incidents.StatusResolved, false},
	}
	for _, tc := range cases {
		if got := incidents.CanTransition(tc.from, tc.to); got != tc.want {
			t.Errorf("%s -> %s = %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}

	if err := incidents.Transition(incidents.StatusClosed, incidents.StatusNew); err == nil {
		t.Error("expected a closed incident to reject reopening")
	}
	if err := incidents.Transition(incidents.StatusNew, incidents.StatusClosed); err == nil {
		t.Error("expected NEW -> CLOSED to be rejected as a skipped stage")
	}
}

func TestNewIncidentStartsAtNew(t *testing.T) {
	base := time.Now().UTC()
	inc := correlation.New("inc_1", alert("alt_1", "r", "h", "a", "1.2.3.4", model.SeverityHigh, base), base)
	if inc.Status != incidents.StatusNew {
		t.Fatalf("status = %s, want NEW", inc.Status)
	}
	if inc.Status.Terminal() {
		t.Fatal("a new incident must not be terminal")
	}
}

func TestIncidentValidation(t *testing.T) {
	base := time.Now().UTC()
	inc := correlation.New("inc_1", alert("alt_1", "r", "h", "a", "1.2.3.4", model.SeverityHigh, base), base)

	if err := inc.Validate(); err != nil {
		t.Fatalf("valid incident rejected: %v", err)
	}

	broken := *inc
	broken.AlertIDs = nil
	if err := broken.Validate(); err == nil {
		t.Error("an incident with no evidence must be rejected")
	}
}

func TestSharedIPJoinsWhenHostsDoNotConflict(t *testing.T) {
	base := time.Now().UTC()

	// Same host, same IP, different actor: one machine hit from one address
	// under two accounts is one incident, and the address is the evidence.
	a := alert("alt_1", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base)
	b := alert("alt_2", "ssh-bruteforce", "web-01", "oracle", "203.0.113.7", model.SeverityHigh, base.Add(time.Minute))
	inc := correlation.New("inc_1", a, base)
	if ok, shared := correlation.ShouldJoin(inc, b, correlation.DefaultOptions()); !ok {
		t.Fatal("expected same-host same-IP alerts to merge")
	} else if len(shared) == 0 {
		t.Fatal("merge must report why it happened")
	}

	// Host-less alerts sharing an attacker address merge: there is no host
	// mismatch to be conservative about.
	c := alert("alt_3", "http-auth-failure-spike", "", "", "203.0.113.7", model.SeverityMedium, base)
	d := alert("alt_4", "http-auth-failure-spike", "", "", "203.0.113.7", model.SeverityMedium, base.Add(time.Minute))
	hostless := correlation.New("inc_2", c, base)
	if ok, _ := correlation.ShouldJoin(hostless, d, correlation.DefaultOptions()); !ok {
		t.Fatal("expected host-less same-IP alerts to merge")
	}
}

func TestAppendTracksSourceIPs(t *testing.T) {
	base := time.Now().UTC()
	a := alert("alt_1", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base)
	inc := correlation.New("inc_1", a, base)
	if len(inc.SourceIPs) != 1 || inc.SourceIPs[0] != "203.0.113.7" {
		t.Fatalf("incident source_ips = %v, want [203.0.113.7]", inc.SourceIPs)
	}

	b := alert("alt_2", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base.Add(time.Minute))
	merged := correlation.Append(inc, b, base.Add(time.Minute))
	if len(merged.SourceIPs) != 1 {
		t.Fatalf("merged source_ips = %v, want no duplicates", merged.SourceIPs)
	}
	if len(inc.SourceIPs) != 1 {
		t.Fatal("Append mutated its input incident")
	}
}

func TestSecondHostInIncidentStillMatches(t *testing.T) {
	base := time.Now().UTC()

	// An incident spanning two hosts via a shared actor still matches an alert
	// on the second host: the match is against the whole scope, not the first
	// host recorded.
	a := alert("alt_1", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base)
	b := alert("alt_2", "ssh-bruteforce", "db-01", "root", "198.51.100.9", model.SeverityHigh, base.Add(time.Minute))
	inc := correlation.New("inc_1", a, base)
	merged := correlation.Append(inc, b, base.Add(time.Minute))

	c := alert("alt_3", "ssh-bruteforce", "db-01", "oracle", "198.51.100.99", model.SeverityHigh, base.Add(2*time.Minute))
	if ok, _ := correlation.ShouldJoin(merged, c, correlation.DefaultOptions()); !ok {
		t.Fatal("expected an alert on the incident's second host to merge")
	}
}

func TestStageForCoversShippedRules(t *testing.T) {
	cases := map[string]string{
		"ssh-bruteforce":                        incidents.StageCredentialAccess,
		"sudo-auth-failure-burst":               incidents.StageCredentialAccess,
		"http-auth-failure-spike":               incidents.StageCredentialAccess,
		"ssh-login-after-bruteforce":            incidents.StageInitialAccess,
		"sudo-after-suspicious-login":           incidents.StagePrivilegeEscalation,
		"privileged-command-after-remote-login": incidents.StageExecution,
		"ssh-authorized-keys-modified":          incidents.StagePersistence,
		"firewall-port-scan":                    incidents.StageReconnaissance,
	}
	for rule, want := range cases {
		if got := correlation.StageFor(rule); got != want {
			t.Errorf("StageFor(%s) = %s, want %s", rule, got, want)
		}
	}
	if got := correlation.StageFor("no-such-rule"); got != incidents.StageUnknown {
		t.Errorf("StageFor(unknown) = %s, want UNKNOWN", got)
	}
}

// An attacker who changes hosts, addresses and accounts between stages shares
// no concrete entity with the first incident, so the engine honestly opens a
// second one instead of inventing a chain out of time proximity.
func TestRotatedInfrastructureStartsNewIncident(t *testing.T) {
	store := memorystore.New()
	eng := correlation.NewEngine(store, metrics.New())

	base := time.Now().UTC()
	eng.SetClock(func() time.Time { return base })

	first, err := eng.Process(context.Background(), alert("alt_1", "ssh-bruteforce", "web-01", "root", "203.0.113.7", model.SeverityHigh, base))
	if err != nil {
		t.Fatal(err)
	}
	second, err := eng.Process(context.Background(), alert("alt_2", "ssh-login-after-bruteforce", "db-01", "deploy", "198.51.100.9", model.SeverityCritical, base.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if !second.Created {
		t.Fatal("rotated infrastructure merged; expected a second incident")
	}
	if second.Incident.ID == first.Incident.ID {
		t.Fatal("distinct attacks share one incident id")
	}
}

// slowOpenStore widens the read-modify-write window so concurrency does not depend on scheduler luck.
type slowOpenStore struct {
	*memorystore.Store
	delay time.Duration
}

func (s *slowOpenStore) ListOpenIncidents(ctx context.Context) ([]*incidents.Incident, error) {
	time.Sleep(s.delay)
	return s.Store.ListOpenIncidents(ctx)
}

func TestConcurrentAlertsDoNotLoseMerges(t *testing.T) {
	store := &slowOpenStore{Store: memorystore.New(), delay: 5 * time.Millisecond}
	reg := metrics.New()
	eng := correlation.NewEngine(store, reg)
	base := time.Now().UTC()
	eng.SetClock(func() time.Time { return base })

	const n = 24
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(n)
	done.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start
			a := alert(fmt.Sprintf("alt_%02d", i), "ssh-bruteforce", "web-01", "root", "203.0.113.7",
				model.SeverityHigh, base.Add(time.Duration(i)*time.Millisecond))
			if _, err := eng.Process(context.Background(), a); err != nil {
				t.Errorf("Process(%d) = %v", i, err)
			}
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()

	open, err := store.ListOpenIncidents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("open incidents = %d, want 1", len(open))
	}
	if got := len(open[0].AlertIDs); got != n {
		t.Fatalf("merged alerts = %d, want %d (lost update)", got, n)
	}
	if got := reg.Counter(metrics.IncidentCreatedTotal); got != 1 {
		t.Fatalf("incident_created_total = %v, want 1", got)
	}
}

package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/agents"
	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/storage"
	memorystore "github.com/halimi/halimisoc/internal/storage/memory"
	"github.com/halimi/halimisoc/internal/webauthn"
)

func ctx() context.Context { return context.Background() }

func newEvent(id, host string, at time.Time) *model.Event {
	return &model.Event{
		ID:            id,
		SchemaVersion: model.SchemaVersion,
		Type:          model.TypeSSHLoginFailed,
		Time:          at,
		ReceivedAt:    at,
		Host:          host,
		Actor:         "root",
		Source:        model.SourceAuthLog,
		Outcome:       model.OutcomeFailure,
		Severity:      model.SeverityMedium,
		Network:       model.Network{SourceIP: "203.0.113.7"},
		Attributes:    map[string]string{"parser": "sshd"},
		Raw:           "raw line",
	}
}

func TestInsertEventIsIdempotent(t *testing.T) {
	s := memorystore.New()
	e := newEvent("evt_1", "web-01", time.Now().UTC())

	inserted, err := s.InsertEvent(ctx(), e)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("first insert reported not inserted")
	}

	inserted, err = s.InsertEvent(ctx(), e)
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("duplicate insert reported as new; detection would re-run")
	}

	n, err := s.CountEvents(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("stored events = %d, want 1", n)
	}
}

func TestStoredEventsAreIsolatedFromCallers(t *testing.T) {
	s := memorystore.New()
	e := newEvent("evt_1", "web-01", time.Now().UTC())
	if _, err := s.InsertEvent(ctx(), e); err != nil {
		t.Fatal(err)
	}

	// Mutating the caller's copy must not change stored state.
	e.Attributes["parser"] = "tampered"
	e.Raw = "tampered"

	got, err := s.GetEvent(ctx(), "evt_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Attributes["parser"] != "sshd" || got.Raw != "raw line" {
		t.Fatalf("stored event was mutated through the caller's pointer: %+v", got)
	}
}

func TestGetEventNotFound(t *testing.T) {
	s := memorystore.New()
	if _, err := s.GetEvent(ctx(), "evt_missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListEventsOrderingAndPagination(t *testing.T) {
	s := memorystore.New()
	base := time.Date(2025, 8, 19, 12, 0, 0, 0, time.UTC)

	// Insert out of chronological order to prove ordering is by event time, not
	// insertion order.
	for i, id := range []string{"evt_b", "evt_a", "evt_c"} {
		e := newEvent(id, "web-01", base.Add(time.Duration(i)*time.Minute))
		if _, err := s.InsertEvent(ctx(), e); err != nil {
			t.Fatal(err)
		}
	}

	page, err := s.ListEvents(ctx(), storage.EventQuery{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("page size = %d, want 2", len(page.Events))
	}
	if page.Events[0].ID != "evt_c" {
		t.Errorf("first event = %s, want the newest", page.Events[0].ID)
	}
	if page.NextCursor == "" {
		t.Fatal("expected a next cursor")
	}

	next, err := s.ListEvents(ctx(), storage.EventQuery{Limit: 2, Cursor: page.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Events) != 1 {
		t.Fatalf("second page size = %d, want 1", len(next.Events))
	}
	if next.NextCursor != "" {
		t.Errorf("unexpected cursor on the final page: %q", next.NextCursor)
	}
}

func TestListEventsFilters(t *testing.T) {
	s := memorystore.New()
	base := time.Now().UTC()

	a := newEvent("evt_a", "web-01", base)
	b := newEvent("evt_b", "db-01", base)
	b.Actor = "alice"
	b.Network.SourceIP = "198.51.100.4"

	for _, e := range []*model.Event{a, b} {
		if _, err := s.InsertEvent(ctx(), e); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name  string
		query storage.EventQuery
		want  int
	}{
		{"by host", storage.EventQuery{Host: "web-01"}, 1},
		{"by actor", storage.EventQuery{Actor: "alice"}, 1},
		{"by source ip", storage.EventQuery{SourceIP: "198.51.100.4"}, 1},
		{"by type", storage.EventQuery{Type: model.TypeSSHLoginFailed}, 2},
		{"by severity", storage.EventQuery{Severity: model.SeverityMedium}, 2},
		{"by severity miss", storage.EventQuery{Severity: model.SeverityCritical}, 0},
		{"no filter", storage.EventQuery{}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := s.ListEvents(ctx(), tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Events) != tc.want {
				t.Fatalf("got %d events, want %d", len(page.Events), tc.want)
			}
		})
	}
}

func TestPurgeRawEvidenceKeepsStructuredEvent(t *testing.T) {
	s := memorystore.New()
	old := newEvent("evt_old", "web-01", time.Now().UTC().Add(-30*24*time.Hour))
	recent := newEvent("evt_new", "web-01", time.Now().UTC())

	for _, e := range []*model.Event{old, recent} {
		if _, err := s.InsertEvent(ctx(), e); err != nil {
			t.Fatal(err)
		}
	}

	purged, err := s.PurgeRawEvidence(ctx(), time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}

	// The structured event survives so alert and incident references stay valid.
	got, err := s.GetEvent(ctx(), "evt_old")
	if err != nil {
		t.Fatalf("structured event was removed: %v", err)
	}
	if got.Raw != "" {
		t.Error("raw evidence was not cleared")
	}
	if got.Attributes["raw_expired"] != "true" {
		t.Error("expiry was not marked, so the UI cannot distinguish empty from expired")
	}
	if got.Type != model.TypeSSHLoginFailed || got.Actor != "root" {
		t.Error("structured fields were damaged by retention")
	}

	kept, err := s.GetEvent(ctx(), "evt_new")
	if err != nil {
		t.Fatal(err)
	}
	if kept.Raw == "" {
		t.Error("recent raw evidence was purged too")
	}
}

func TestPurgeEventsRemovesExpiredRecords(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	old := newEvent("evt_old", "web-01", now.Add(-48*time.Hour))
	recent := newEvent("evt_new", "web-01", now)

	for _, e := range []*model.Event{old, recent} {
		if _, err := s.InsertEvent(ctx(), e); err != nil {
			t.Fatal(err)
		}
	}

	purged, err := s.PurgeEvents(ctx(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}
	if _, err := s.GetEvent(ctx(), "evt_old"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired event still present: %v", err)
	}
	if _, err := s.GetEvent(ctx(), "evt_new"); err != nil {
		t.Fatalf("recent event was purged: %v", err)
	}

	// The insertion-order index must be compacted too, otherwise a long-running
	// demo keeps the ids of deleted events forever.
	page, err := s.ListEvents(ctx(), storage.EventQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].ID != "evt_new" {
		t.Fatalf("events after purge = %v", page.Events)
	}
}

func TestPurgeAlertsRemovesExpiredRecords(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	save := func(id string, createdAt time.Time) {
		t.Helper()
		a := &alerts.Alert{
			ID: id, RuleID: "r", RuleVersion: 1, RuleName: "R",
			Severity: model.SeverityHigh, Status: alerts.StatusOpen,
			Title: "t", Reason: "why", EventIDs: []string{"evt_1"},
			WindowStart: createdAt, WindowEnd: createdAt,
			CreatedAt: createdAt, UpdatedAt: createdAt,
		}
		if err := s.SaveAlert(ctx(), a); err != nil {
			t.Fatal(err)
		}
	}
	save("alt_old", now.Add(-48*time.Hour))
	save("alt_new", now)

	purged, err := s.PurgeAlerts(ctx(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}
	if _, err := s.GetAlert(ctx(), "alt_old"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired alert still present: %v", err)
	}
	if _, err := s.GetAlert(ctx(), "alt_new"); err != nil {
		t.Fatalf("recent alert was purged: %v", err)
	}
}

func TestPurgeAuditRemovesExpiredRecords(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	for _, e := range []*audit.Entry{
		{ID: "aud_old", Actor: "operator:admin", Action: audit.ActionLoginSuccess, Resource: "session", Result: audit.ResultSuccess, Timestamp: now.Add(-48 * time.Hour)},
		{ID: "aud_new", Actor: "operator:admin", Action: audit.ActionLoginSuccess, Resource: "session", Result: audit.ResultSuccess, Timestamp: now},
	} {
		if err := s.AppendAudit(ctx(), e); err != nil {
			t.Fatal(err)
		}
	}

	purged, err := s.PurgeAudit(ctx(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}
	entries, _, err := s.ListAudit(ctx(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "aud_new" {
		t.Fatalf("audit after purge = %v", entries)
	}
}

func TestAlertStatusTransition(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	a := &alerts.Alert{
		ID: "alt_1", RuleID: "r", RuleVersion: 1, RuleName: "R",
		Severity: model.SeverityHigh, Status: alerts.StatusOpen,
		Title: "t", Reason: "why", EventIDs: []string{"evt_1"},
		WindowStart: now, WindowEnd: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.SaveAlert(ctx(), a); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAlert(ctx(), a); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("duplicate alert err = %v, want ErrConflict", err)
	}

	updated, err := s.UpdateAlertStatus(ctx(), "alt_1", alerts.StatusAcknowledged, now)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != alerts.StatusAcknowledged {
		t.Fatalf("status = %s", updated.Status)
	}

	// Terminal states cannot reopen.
	if _, err := s.UpdateAlertStatus(ctx(), "alt_1", alerts.StatusOpen, now); !errors.Is(err, storage.ErrInvalidTransition) {
		t.Fatalf("err = %v, want ErrInvalidTransition", err)
	}
	if _, err := s.UpdateAlertStatus(ctx(), "alt_missing", alerts.StatusResolved, now); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestAgentTokenLifecycle(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()

	if err := s.SaveAgent(ctx(), &agents.Agent{
		ID: "agt_1", Host: "web-01", Status: agents.StatusOnline,
		EnrolledAt: now, LastHeartbeat: now,
	}); err != nil {
		t.Fatal(err)
	}

	tok := &agents.Token{ID: "tok_1", AgentID: "agt_1", TokenHash: "hash1", Prefix: "agt_ab…", CreatedAt: now}
	if err := s.SaveToken(ctx(), tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetTokenByHash(ctx(), "hash1"); err != nil {
		t.Fatal(err)
	}

	// Rotation invalidates the old credential, which is the point of rotating.
	if err := s.RotateTokensForAgent(ctx(), "agt_1", now); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTokenByHash(ctx(), "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Rotated() || got.Active(now) {
		t.Fatal("a rotated token is still active")
	}

	next := &agents.Token{ID: "tok_2", AgentID: "agt_1", TokenHash: "hash2", CreatedAt: now}
	if err := s.SaveToken(ctx(), next); err != nil {
		t.Fatal(err)
	}

	if err := s.RevokeTokensForAgent(ctx(), "agt_1", now); err != nil {
		t.Fatal(err)
	}
	revoked, err := s.GetTokenByHash(ctx(), "hash2")
	if err != nil {
		t.Fatal(err)
	}
	if !revoked.Revoked() || revoked.Active(now) {
		t.Fatal("a revoked token is still active")
	}
}

func TestSessionRevocation(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()

	if err := s.SaveUser(ctx(), &auth.User{
		ID: "usr_1", Username: "admin", PasswordHash: "x",
		Role: authorization.RoleAdmin, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	sess, _, err := auth.NewSession("usr_1", "", "", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSession(ctx(), sess); err != nil {
		t.Fatal(err)
	}

	stored, err := s.GetSession(ctx(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CSRFToken != sess.CSRFToken {
		t.Fatal("session round-trip lost the CSRF token")
	}

	if err := s.RevokeSession(ctx(), sess.ID, now); err != nil {
		t.Fatal(err)
	}
	stored, err = s.GetSession(ctx(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Revoked() {
		t.Fatal("session was not revoked")
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()

	sess, _, err := auth.NewSession("usr_1", "", "", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSession(ctx(), sess); err != nil {
		t.Fatal(err)
	}

	removed, err := s.DeleteExpiredSessions(ctx(), now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
}

func TestUserUsernameIsCaseInsensitive(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	if err := s.SaveUser(ctx(), &auth.User{
		ID: "usr_1", Username: "admin", PasswordHash: "x",
		Role: authorization.RoleAdmin, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetUserByUsername(ctx(), "ADMIN"); err != nil {
		t.Fatalf("case-insensitive lookup failed: %v", err)
	}

	// A second account differing only in case must be rejected, otherwise the
	// login form has two accounts that look identical to an operator.
	err := s.SaveUser(ctx(), &auth.User{
		ID: "usr_2", Username: "Admin", PasswordHash: "y",
		Role: authorization.RoleAnalyst, CreatedAt: now,
	})
	if !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestRecordLogin(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	if err := s.SaveUser(ctx(), &auth.User{
		ID: "usr_1", Username: "admin", PasswordHash: "x",
		Role: authorization.RoleAdmin, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.RecordLogin(ctx(), "usr_1", now); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUser(ctx(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if u.LastLoginAt == nil {
		t.Fatal("last login was not recorded")
	}
	if err := s.RecordLogin(ctx(), "usr_missing", now); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestIncidentPersistence(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	inc := &incidents.Incident{
		ID: "inc_1", Title: "t", Summary: "s",
		Severity: model.SeverityHigh, Status: incidents.StatusNew,
		Hosts: []string{"web-01"}, Actors: []string{"root"},
		AlertIDs: []string{"alt_1"}, EventIDs: []string{"evt_1"},
		Stages:    []incidents.Stage{{Name: incidents.StageInitialAccess, At: now}},
		FirstSeen: now, LastSeen: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.SaveIncident(ctx(), inc); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetIncident(ctx(), "inc_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Stages) != 1 || got.Stages[0].Name != incidents.StageInitialAccess {
		t.Fatalf("stages did not round-trip: %+v", got.Stages)
	}

	// Terminal incidents must not appear as open candidates for correlation.
	inc.Status = incidents.StatusResolved
	if err := s.SaveIncident(ctx(), inc); err != nil {
		t.Fatal(err)
	}
	open, err := s.ListOpenIncidents(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Fatalf("open incidents = %d, want 0", len(open))
	}
}

func TestAuditAppendAndList(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		if err := s.AppendAudit(ctx(), &audit.Entry{
			ID: "audit_" + string(rune('a'+i)), Actor: "user:admin",
			Action: audit.ActionLoginSuccess, Resource: "session",
			Result: audit.ResultSuccess, Timestamp: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	entries, next, err := s.ListAudit(ctx(), 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	if next == "" {
		t.Fatal("expected a next cursor")
	}
}

func TestPingAndClose(t *testing.T) {
	s := memorystore.New()
	if err := s.Ping(ctx()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListUsersIsStableAndIsolated(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	for _, u := range []auth.User{
		{ID: "usr_b", Username: "bob", PasswordHash: "x", Role: authorization.RoleAnalyst, CreatedAt: now},
		{ID: "usr_a", Username: "admin", PasswordHash: "x", Role: authorization.RoleAdmin, CreatedAt: now},
	} {
		u := u
		if err := s.SaveUser(ctx(), &u); err != nil {
			t.Fatal(err)
		}
	}

	users, err := s.ListUsers(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].Username != "admin" || users[1].Username != "bob" {
		t.Fatalf("users not ordered by username: %+v", users)
	}

	// Mutating a returned record must not change stored state.
	users[0].Disabled = true
	fresh, err := s.GetUser(ctx(), "usr_a")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Disabled {
		t.Fatal("stored user was mutated through a listed copy")
	}
}

func TestIncidentSourceIPsRoundTrip(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	inc := &incidents.Incident{
		ID: "inc_1", Title: "t", Summary: "s",
		Severity: model.SeverityHigh, Status: incidents.StatusNew,
		Hosts: []string{"web-01"}, Actors: []string{"root"}, SourceIPs: []string{"203.0.113.7"},
		AlertIDs: []string{"alt_1"}, EventIDs: []string{"evt_1"},
		FirstSeen: now, LastSeen: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.SaveIncident(ctx(), inc); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetIncident(ctx(), "inc_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SourceIPs) != 1 || got.SourceIPs[0] != "203.0.113.7" {
		t.Fatalf("source_ips did not round-trip: %v", got.SourceIPs)
	}
}

func TestPasskeyCRUDAndConflict(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	p := &webauthn.Passkey{
		ID: "cred_db_1", UserID: "usr_a", CredentialID: "cred-wire-1",
		PublicKey: "cose-blob", SignCount: 0, Transports: []string{"internal"},
		Name: "laptop", CreatedAt: now,
	}
	if err := s.SavePasskey(ctx(), p); err != nil {
		t.Fatal(err)
	}
	// A second row for the same wire credential conflicts: one authenticator
	// must not be enrolled twice under two ids.
	dup := &webauthn.Passkey{
		ID: "cred_db_2", UserID: "usr_a", CredentialID: "cred-wire-1",
		PublicKey: "cose-blob", CreatedAt: now,
	}
	if err := s.SavePasskey(ctx(), dup); err == nil {
		t.Fatal("duplicate credential id accepted")
	}

	got, err := s.GetPasskeyByCredentialID(ctx(), "cred-wire-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "usr_a" || got.Name != "laptop" {
		t.Fatalf("passkey = %+v", got)
	}
	// Mutating the returned copy must not corrupt the store.
	got.Transports[0] = "usb"
	fresh, err := s.GetPasskeyByCredentialID(ctx(), "cred-wire-1")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Transports[0] != "internal" {
		t.Fatal("stored passkey mutated through a returned copy")
	}

	list, err := s.ListPasskeysByUser(ctx(), "usr_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("passkeys = %d, want 1", len(list))
	}

	if err := s.UpdatePasskeyCounter(ctx(), "cred_db_1", 7, now); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetPasskeyByCredentialID(ctx(), "cred-wire-1")
	if err != nil {
		t.Fatal(err)
	}
	if after.SignCount != 7 || after.LastUsedAt == nil {
		t.Fatalf("counter = %d/%v", after.SignCount, after.LastUsedAt)
	}
	if err := s.UpdatePasskeyCounter(ctx(), "missing", 1, now); err == nil {
		t.Error("counter update on missing passkey accepted")
	}

	if err := s.DeletePasskey(ctx(), "cred_db_1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePasskey(ctx(), "cred_db_1"); err == nil {
		t.Error("double delete accepted")
	}
	if _, err := s.GetPasskeyByCredentialID(ctx(), "cred-wire-1"); err == nil {
		t.Error("deleted passkey still resolvable")
	}
	if err := s.SavePasskey(ctx(), nil); err == nil {
		t.Error("nil passkey accepted")
	}
}

func TestSessionTouchAndUserSessionRevocation(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	sess := &auth.Session{
		ID: "sess_1", UserID: "usr_a", TokenHash: "hash", CSRFToken: "csrf",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now,
	}
	if err := s.SaveSession(ctx(), sess); err != nil {
		t.Fatal(err)
	}
	later := now.Add(30 * time.Minute)
	if err := s.TouchSession(ctx(), "sess_1", later); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx(), "sess_1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeenAt.Equal(later) {
		t.Fatalf("last_seen = %v, want %v", got.LastSeenAt, later)
	}
	if err := s.TouchSession(ctx(), "missing", later); err == nil {
		t.Error("touch on missing session accepted")
	}

	second := &auth.Session{
		ID: "sess_2", UserID: "usr_a", TokenHash: "hash", CSRFToken: "csrf",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now,
	}
	if err := s.SaveSession(ctx(), second); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeUserSessions(ctx(), "usr_a", now); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"sess_1", "sess_2"} {
		revoked, err := s.GetSession(ctx(), sid)
		if err != nil {
			t.Fatal(err)
		}
		if !revoked.Revoked() {
			t.Errorf("session %s not revoked", sid)
		}
	}
}

func TestUserBackupHashesAreIsolated(t *testing.T) {
	s := memorystore.New()
	now := time.Now().UTC()
	u := &auth.User{
		ID: "usr_a", Username: "alice", PasswordHash: "hash",
		Role: authorization.RoleAnalyst, CreatedAt: now,
		BackupHashes: []string{"h1", "h2"},
	}
	if err := s.SaveUser(ctx(), u); err != nil {
		t.Fatal(err)
	}
	// Mutating the caller's slice after save must not leak into the store.
	u.BackupHashes[0] = "tampered"
	got, err := s.GetUser(ctx(), "usr_a")
	if err != nil {
		t.Fatal(err)
	}
	if got.BackupHashes[0] != "h1" {
		t.Fatal("backup hashes aliased the caller's slice")
	}
	got.BackupHashes[0] = "tampered"
	fresh, err := s.GetUserByUsername(ctx(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.BackupHashes[0] != "h1" {
		t.Fatal("backup hashes mutated through a returned copy")
	}
	list, err := s.ListUsers(ctx())
	if err != nil {
		t.Fatal(err)
	}
	list[0].BackupHashes[0] = "tampered"
	again, err := s.GetUser(ctx(), "usr_a")
	if err != nil {
		t.Fatal(err)
	}
	if again.BackupHashes[0] != "h1" {
		t.Fatal("backup hashes mutated through a listed copy")
	}
}

func TestEventStoreIsBounded(t *testing.T) {
	s := memorystore.NewWithMaxEvents(3)
	base := time.Now().UTC()

	for i := 0; i < 5; i++ {
		e := newEvent("evt_"+string(rune('a'+i)), "web-01", base.Add(time.Duration(i)*time.Second))
		if _, err := s.InsertEvent(ctx(), e); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.CountEvents(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("stored events = %d, want the bound 3", n)
	}
	if _, err := s.GetEvent(ctx(), "evt_a"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("oldest event survived eviction: %v", err)
	}
	if _, err := s.GetEvent(ctx(), "evt_e"); err != nil {
		t.Fatalf("newest event was evicted: %v", err)
	}

	page, err := s.ListEvents(ctx(), storage.EventQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 3 {
		t.Fatalf("listed events = %d, want 3", len(page.Events))
	}
}

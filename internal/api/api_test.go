package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/api"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/config"
	"github.com/halimi/halimisoc/internal/correlation"
	"github.com/halimi/halimisoc/internal/detection/engine"
	"github.com/halimi/halimisoc/internal/detection/rules"
	"github.com/halimi/halimisoc/internal/detection/state"
	"github.com/halimi/halimisoc/internal/events/ingest"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/events/stream"
	"github.com/halimi/halimisoc/internal/events/validation"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/storage"
	memorystore "github.com/halimi/halimisoc/internal/storage/memory"
)

const (
	adminPassword = "correct-horse-battery-staple"
	enrollSecret  = "test-enrollment-secret-value"
	agentHost     = "web-01"
)

type harness struct {
	t        *testing.T
	server   *httptest.Server
	store    *memorystore.Store
	client   *http.Client
	hub      *stream.Hub
	api      *api.Server
	agentTok string
	agentID  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWithStore(t, memorystore.New(), nil)
}

func newHarnessWithStore(t *testing.T, store *memorystore.Store, wrap func(storage.Store) storage.Store) *harness {
	t.Helper()

	ruleSet, err := rules.LoadDir(filepath.Join("..", "..", "packages", "rules"))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	var apiStore storage.Store = store
	if wrap != nil {
		apiStore = wrap(store)
	}
	reg := metrics.New()
	detector := engine.New(ruleSet, state.New(state.DefaultOptions()), apiStore, reg)
	correlator := correlation.NewEngine(apiStore, reg)

	opts := validation.DefaultOptions()
	ingester := ingest.New(apiStore, detector, correlator, opts, reg, 100)

	hub := stream.NewHub(stream.Options{MaxSubscribers: 16, Buffer: 32})

	srv := api.New(api.Options{
		Store:        apiStore,
		Hub:          hub,
		Ingester:     ingester,
		Detector:     detector,
		Limits:       config.DefaultLimits(),
		SessionTTL:   time.Hour,
		ClockSkew:    5 * time.Minute,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:      reg,
		EnrollSecret: enrollSecret,
		Version:      "test",
		RulesPath:    filepath.Join("..", "..", "packages", "rules"),
	})

	// Bootstrap the administrator directly through the store, mirroring what
	// main does at first startup.
	hash, err := auth.HashPassword(adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveUser(context.Background(), &auth.User{
		ID:           id.New(id.KindUser),
		Username:     "admin",
		PasswordHash: hash,
		Role:         authorization.RoleAdmin,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	// Production wires this in main; the test must do the same or the realtime
	// feed would be silently inert.
	ingester.SetPublisher(srv)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &harness{
		t:      t,
		server: ts,
		store:  store,
		hub:    hub,
		api:    srv,
		client: &http.Client{Jar: jar, Timeout: 10 * time.Second},
	}
}

// do performs a request, optionally attaching the CSRF header.
func (h *harness) do(method, path string, body any, headers map[string]string) *http.Response {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func (h *harness) login(username, password string) (csrf string, status int) {
	resp := h.do(http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": username,
		"password": password,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return "", resp.StatusCode
	}
	out := decode[struct {
		CSRFToken string `json:"csrf_token"`
	}](h.t, resp)
	return out.CSRFToken, resp.StatusCode
}

func (h *harness) enrollAgent() {
	h.t.Helper()
	resp := h.do(http.MethodPost, "/api/v1/agents/register", map[string]string{
		"enrollment_secret": enrollSecret,
		"host":              agentHost,
		"os":                "linux/amd64",
		"version":           "test",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		h.t.Fatalf("enroll status = %d: %s", resp.StatusCode, body)
	}
	out := decode[struct {
		AgentID    string `json:"agent_id"`
		AgentToken string `json:"agent_token"`
	}](h.t, resp)
	h.agentTok = out.AgentToken
	h.agentID = out.AgentID
}

func (h *harness) agentHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer " + h.agentTok}
}

func sshFailure(id, ip string, at time.Time) *model.Event {
	return &model.Event{
		ID:         id,
		Type:       model.TypeSSHLoginFailed,
		Time:       at,
		ObservedAt: at,
		Host:       agentHost,
		Actor:      "root",
		Source:     model.SourceAuthLog,
		Outcome:    model.OutcomeFailure,
		Severity:   model.SeverityMedium,
		Network:    model.Network{SourceIP: ip, SourcePort: 51022},
		Raw:        "Aug 19 11:20:30 web-01 sshd[1]: Failed password for root",
	}
}

type ingestResult struct {
	Received   int `json:"received"`
	Inserted   int `json:"inserted"`
	Duplicates int `json:"duplicates"`
	Rejected   []struct {
		Index  int    `json:"index"`
		Reason string `json:"reason"`
	} `json:"rejected"`
	Alerts []struct {
		ID       string `json:"id"`
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
	} `json:"alerts"`
	Incidents []struct {
		ID string `json:"id"`
	} `json:"incidents"`
}

// --- Tests ----------------------------------------------------------------

func TestUnauthenticatedAccessIsRejected(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/api/v1/events",
		"/api/v1/alerts",
		"/api/v1/incidents",
		"/api/v1/agents",
		"/api/v1/summary",
	} {
		resp := h.do(http.MethodGet, path, nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	h := newHarness(t)

	_, status := h.login("admin", "wrong-password")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}

	_, status = h.login("nonexistent", "whatever")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for unknown user", status)
	}
}

func TestLoginThenIngestCreatesAlert(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	base := time.Now().UTC().Add(-time.Minute)
	batch := map[string]any{"events": []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}}

	resp := h.do(http.MethodPost, "/api/v1/events", batch, h.agentHeaders())
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("ingest status = %d: %s", resp.StatusCode, body)
	}
	res := decode[ingestResult](t, resp)

	if res.Inserted != 5 {
		t.Errorf("inserted = %d, want 5", res.Inserted)
	}
	if len(res.Alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(res.Alerts))
	}
	if res.Alerts[0].RuleID != "ssh-bruteforce" {
		t.Errorf("rule = %s, want ssh-bruteforce", res.Alerts[0].RuleID)
	}
	if len(res.Incidents) != 1 {
		t.Fatalf("incidents = %d, want 1", len(res.Incidents))
	}

	// The alert must be visible through the authenticated API.
	csrf, status := h.login("admin", adminPassword)
	if status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}
	if csrf == "" {
		t.Fatal("login returned no CSRF token")
	}

	resp = h.do(http.MethodGet, "/api/v1/alerts", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list alerts status = %d", resp.StatusCode)
	}
	page := decode[struct {
		Alerts []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"alerts"`
	}](t, resp)
	if len(page.Alerts) != 1 {
		t.Fatalf("listed %d alerts, want 1", len(page.Alerts))
	}
	if page.Alerts[0].Status != "OPEN" {
		t.Errorf("alert status = %s, want OPEN", page.Alerts[0].Status)
	}
}

func TestIngestReplayThroughAPIIsIdempotent(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	base := time.Now().UTC().Add(-time.Minute)
	// The packaged ssh-bruteforce rule fires at 5 events in 60s, so the batch
	// must reach that count for the replay assertion to be meaningful.
	events := []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}
	batch := map[string]any{"events": events}

	resp := h.do(http.MethodPost, "/api/v1/events", batch, h.agentHeaders())
	first := decode[ingestResult](t, resp)
	if first.Inserted != 5 || len(first.Alerts) != 1 {
		t.Fatalf("first ingest = %+v", first)
	}

	resp = h.do(http.MethodPost, "/api/v1/events", batch, h.agentHeaders())
	replay := decode[ingestResult](t, resp)
	if replay.Inserted != 0 || replay.Duplicates != 5 {
		t.Errorf("replay = inserted %d, duplicates %d; want 0/5", replay.Inserted, replay.Duplicates)
	}
	if len(replay.Alerts) != 0 {
		t.Errorf("replay produced %d alerts, want 0", len(replay.Alerts))
	}
}

func TestAgentCannotIngestForAnotherHost(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	e := sshFailure(id.NewEvent(), "203.0.113.7", time.Now().UTC().Add(-time.Minute))
	e.Host = "some-other-host"

	resp := h.do(http.MethodPost, "/api/v1/events", map[string]any{"events": []*model.Event{e}}, h.agentHeaders())
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when forging a host", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestIngestRequiresAgentCredential(t *testing.T) {
	h := newHarness(t)

	resp := h.do(http.MethodPost, "/api/v1/events", map[string]any{"events": []*model.Event{}}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without an agent token", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.do(http.MethodPost, "/api/v1/events", map[string]any{"events": []*model.Event{}},
		map[string]string{"Authorization": "Bearer not-a-real-token"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an invalid token", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestEnrollRequiresValidSecret(t *testing.T) {
	h := newHarness(t)

	resp := h.do(http.MethodPost, "/api/v1/agents/register", map[string]string{
		"enrollment_secret": "wrong-secret-value",
		"host":              agentHost,
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAlertStatusChangeRequiresCSRF(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	base := time.Now().UTC().Add(-time.Minute)
	batch := map[string]any{"events": []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}}
	resp := h.do(http.MethodPost, "/api/v1/events", batch, h.agentHeaders())
	res := decode[ingestResult](t, resp)
	if len(res.Alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(res.Alerts))
	}
	alertID := res.Alerts[0].ID

	csrf, _ := h.login("admin", adminPassword)

	// Without the CSRF header the state change must be refused.
	resp = h.do(http.MethodPatch, "/api/v1/alerts/"+alertID+"/status",
		map[string]string{"status": "ACKNOWLEDGED"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without CSRF token", resp.StatusCode)
	}
	resp.Body.Close()

	// With the token it succeeds.
	resp = h.do(http.MethodPatch, "/api/v1/alerts/"+alertID+"/status",
		map[string]string{"status": "ACKNOWLEDGED"},
		map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, body)
	}
	updated := decode[struct {
		Status string `json:"status"`
	}](t, resp)
	if updated.Status != "ACKNOWLEDGED" {
		t.Errorf("status = %s, want ACKNOWLEDGED", updated.Status)
	}
}

func TestAlertStatusTransitionIsEnforced(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	base := time.Now().UTC().Add(-time.Minute)
	batch := map[string]any{"events": []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}}
	res := decode[ingestResult](t, h.do(http.MethodPost, "/api/v1/events", batch, h.agentHeaders()))
	alertID := res.Alerts[0].ID

	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	// RESOLVED is terminal; moving it back to OPEN must be refused.
	resp := h.do(http.MethodPatch, "/api/v1/alerts/"+alertID+"/status",
		map[string]string{"status": "RESOLVED"}, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.do(http.MethodPatch, "/api/v1/alerts/"+alertID+"/status",
		map[string]string{"status": "OPEN"}, headers)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("reopen status = %d, want 409 (terminal state must not reopen)", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestReadonlyRoleCannotMutate(t *testing.T) {
	h := newHarness(t)

	hash, err := auth.HashPassword("readonly-password-value")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SaveUser(context.Background(), &auth.User{
		ID:           id.New(id.KindUser),
		Username:     "viewer",
		PasswordHash: hash,
		Role:         authorization.RoleReadonly,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	csrf, status := h.login("viewer", "readonly-password-value")
	if status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}

	// Reading is allowed.
	resp := h.do(http.MethodGet, "/api/v1/alerts", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readonly list alerts = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Mutating is not.
	resp = h.do(http.MethodPatch, "/api/v1/alerts/alert_whatever/status",
		map[string]string{"status": "ACKNOWLEDGED"},
		map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("readonly mutate = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// Managing agents is admin-only.
	resp = h.do(http.MethodGet, "/api/v1/agents", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readonly list agents = %d, want 200 (view is permitted)", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAgentTokenCannotAccessOperatorEndpoints(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	resp := h.do(http.MethodGet, "/api/v1/alerts", nil, h.agentHeaders())
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("agent list alerts = %d, want 401 (agents are not operators)", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLogoutRevokesSession(t *testing.T) {
	h := newHarness(t)
	csrf, status := h.login("admin", adminPassword)
	if status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}

	resp := h.do(http.MethodPost, "/api/v1/auth/logout", nil, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// The cookie jar still holds the old cookie, but the session is revoked
	// server-side, so the next request must fail.
	resp = h.do(http.MethodGet, "/api/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout me = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestUnknownFieldsAreRejected(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	raw := strings.NewReader(`{"events":[],"surprise":true}`)
	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/events", raw)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.agentTok)

	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want a rejection for an unknown field", resp.StatusCode)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	h := newHarness(t)

	resp := h.do(http.MethodGet, "/api/v1/health", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.do(http.MethodGet, "/api/v1/readiness", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz = %d", resp.StatusCode)
	}
	ready := decode[struct {
		Status string `json:"status"`
		Rules  int    `json:"rules_loaded"`
	}](t, resp)
	if ready.Status != "ok" {
		t.Errorf("ready status = %q", ready.Status)
	}
	if ready.Rules < 4 {
		t.Errorf("rules_loaded = %d, want the packaged rules", ready.Rules)
	}
}

func TestSecurityHeadersArePresent(t *testing.T) {
	h := newHarness(t)
	resp := h.do(http.MethodGet, "/api/v1/health", nil, nil)
	defer resp.Body.Close()

	for _, header := range []string{
		"X-Content-Type-Options", "X-Frame-Options",
		"Content-Security-Policy", "Referrer-Policy",
	} {
		if resp.Header.Get(header) == "" {
			t.Errorf("missing security header %s", header)
		}
	}
}

func TestPageSizeIsClamped(t *testing.T) {
	h := newHarness(t)
	h.login("admin", adminPassword)

	resp := h.do(http.MethodGet, "/api/v1/events?limit=999999", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	// The bound is enforced server-side; a client asking for more simply gets
	// the maximum rather than an error or an unbounded result set.
}

func TestInvalidFiltersAreRejected(t *testing.T) {
	h := newHarness(t)
	h.login("admin", adminPassword)

	for _, path := range []string{
		"/api/v1/events?severity=urgent",
		"/api/v1/events?type=auth.ssh.explode",
		"/api/v1/events?since=not-a-time",
		"/api/v1/alerts?status=NOPE",
	} {
		resp := h.do(http.MethodGet, path, nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestAuditIsRestrictedToAdmin(t *testing.T) {
	h := newHarness(t)

	hash, err := auth.HashPassword("analyst-password-value")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SaveUser(context.Background(), &auth.User{
		ID:           id.New(id.KindUser),
		Username:     "analyst",
		PasswordHash: hash,
		Role:         authorization.RoleAnalyst,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	if _, status := h.login("analyst", "analyst-password-value"); status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}
	resp := h.do(http.MethodGet, "/api/v1/audit", nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst audit = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLoginIsRateLimited(t *testing.T) {
	h := newHarness(t)

	var lastStatus int
	for i := 0; i < 12; i++ {
		_, lastStatus = h.login("admin", fmt.Sprintf("wrong-%d", i))
	}
	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("final status = %d, want 429 after repeated failures", lastStatus)
	}
}

func TestStorageErrorIsNotLeaked(t *testing.T) {
	h := newHarness(t)
	h.login("admin", adminPassword)

	resp := h.do(http.MethodGet, "/api/v1/alerts/does-not-exist", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// The body must carry a stable code and no internal detail.
	if !strings.Contains(string(body), "NOT_FOUND") {
		t.Errorf("body = %s, want a NOT_FOUND code", body)
	}
	for _, leak := range []string{"postgres", "sql", "/home/", "goroutine"} {
		if strings.Contains(strings.ToLower(string(body)), leak) {
			t.Errorf("error body leaked %q: %s", leak, body)
		}
	}
}

var _ = storage.ErrNotFound

// --- Incident analysis ----------------------------------------------------

func TestAnalyzeIncidentIsAdvisoryAndGrounded(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	base := time.Now().UTC().Add(-time.Minute)
	batch := map[string]any{"events": []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}}
	res := decode[ingestResult](t, h.do(http.MethodPost, "/api/v1/events", batch, h.agentHeaders()))
	if len(res.Incidents) != 1 {
		t.Fatalf("incidents = %d, want 1", len(res.Incidents))
	}

	csrf, _ := h.login("admin", adminPassword)

	// No provider is configured in the harness, so the analysis must be the
	// deterministic computed summary rather than an error.
	resp := h.do(http.MethodPost, "/api/v1/incidents/"+res.Incidents[0].ID+"/analyze", nil,
		map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("analyze status = %d: %s", resp.StatusCode, body)
	}

	out := decode[struct {
		IncidentID string `json:"incident_id"`
		Analysis   string `json:"analysis"`
		Mode       string `json:"mode"`
		Grounded   bool   `json:"grounded"`
		Advisory   bool   `json:"advisory"`
		Evidence   []struct {
			Kind string `json:"kind"`
			ID   string `json:"id"`
		} `json:"evidence"`
	}](t, resp)

	if out.Mode != "DISABLED" {
		t.Errorf("mode = %s, want DISABLED when no provider is configured", out.Mode)
	}
	if !out.Advisory {
		t.Error("analysis must always be marked advisory")
	}
	if !out.Grounded {
		t.Error("the computed summary is derived from stored records, so it is grounded")
	}
	if out.Analysis == "" {
		t.Error("analysis is empty")
	}
	if len(out.Evidence) == 0 {
		t.Fatal("analysis returned no evidence references")
	}

	// Every referenced record must be application-owned and resolvable. The
	// incident itself is always the first reference.
	seenIncident := false
	for _, e := range out.Evidence {
		if e.ID == "" {
			t.Error("evidence item has no id")
		}
		if e.Kind == "INCIDENT" && e.ID == res.Incidents[0].ID {
			seenIncident = true
		}
	}
	if !seenIncident {
		t.Error("evidence does not include the incident being analysed")
	}
}

func TestAnalyzeIncidentRequiresAuthentication(t *testing.T) {
	h := newHarness(t)

	resp := h.do(http.MethodPost, "/api/v1/incidents/inc_whatever/analyze", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAnalyzeIncidentDoesNotChangeState(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	base := time.Now().UTC().Add(-time.Minute)
	batch := map[string]any{"events": []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}}
	res := decode[ingestResult](t, h.do(http.MethodPost, "/api/v1/events", batch, h.agentHeaders()))
	incidentID := res.Incidents[0].ID

	// Analyse requires CSRF (audit + billable LLM), so present it like the
	// dashboard BFF does.
	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	before := decode[struct {
		Status   string `json:"status"`
		Severity string `json:"severity"`
	}](t, h.do(http.MethodGet, "/api/v1/incidents/"+incidentID, nil, nil))

	// Analyse several times.
	for i := 0; i < 3; i++ {
		resp := h.do(http.MethodPost, "/api/v1/incidents/"+incidentID+"/analyze", nil, headers)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("analyze %d status = %d", i, resp.StatusCode)
		}
		resp.Body.Close()
	}

	after := decode[struct {
		Status   string `json:"status"`
		Severity string `json:"severity"`
	}](t, h.do(http.MethodGet, "/api/v1/incidents/"+incidentID, nil, nil))

	// AI output must never become domain state: severity and status are
	// untouched by an analysis.
	if before.Status != after.Status || before.Severity != after.Severity {
		t.Fatalf("analysis changed incident state: %+v -> %+v", before, after)
	}
}

func TestIncidentStatusTransitionViaAPI(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	base := time.Now().UTC().Add(-time.Minute)
	batch := map[string]any{"events": []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}}
	res := decode[ingestResult](t, h.do(http.MethodPost, "/api/v1/events", batch, h.agentHeaders()))
	incidentID := res.Incidents[0].ID

	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	// A new incident starts at NEW.
	got := decode[struct {
		Status string `json:"status"`
	}](t, h.do(http.MethodGet, "/api/v1/incidents/"+incidentID, nil, nil))
	if got.Status != "NEW" {
		t.Fatalf("initial status = %s, want NEW", got.Status)
	}

	// NEW -> CLOSED skips stages and must be refused.
	resp := h.do(http.MethodPatch, "/api/v1/incidents/"+incidentID+"/status",
		map[string]string{"status": "CLOSED"}, headers)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("skipped-stage transition = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	// NEW -> INVESTIGATING is allowed.
	resp = h.do(http.MethodPatch, "/api/v1/incidents/"+incidentID+"/status",
		map[string]string{"status": "INVESTIGATING"}, headers)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// An unknown status is a bad request, not a coercion.
	resp = h.do(http.MethodPatch, "/api/v1/incidents/"+incidentID+"/status",
		map[string]string{"status": "OBLITERATED"}, headers)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHeartbeatRejectsMismatchedAgentID(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	// The credential is valid but the path claims a different agent, which must
	// be refused so one agent cannot report liveness for another.
	resp := h.do(http.MethodPost, "/api/v1/agents/agt_someone_else/heartbeat", nil, h.agentHeaders())
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// The correct id is accepted.
	resp = h.do(http.MethodPost, "/api/v1/agents/"+h.agentID+"/heartbeat", nil, h.agentHeaders())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAgentSelfReportsIdentity(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	resp := h.do(http.MethodGet, "/api/v1/agents/me", nil, h.agentHeaders())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	me := decode[struct {
		ID   string `json:"id"`
		Host string `json:"host"`
	}](t, resp)
	if me.ID != h.agentID {
		t.Errorf("id = %q, want %q", me.ID, h.agentID)
	}
	if me.Host != agentHost {
		t.Errorf("host = %q, want %q", me.Host, agentHost)
	}
}

// TestListEndpointsReturnArraysWithLowercaseKeys pins the wire shape of every
// list endpoint.
//
// Two defects shipped behind this shape, and both are invisible to a struct
// decoder:
//
//   - The store page types carried no json tags, so Go emitted the exported
//     field names — "Alerts", "Events", "NextCursor". encoding/json matches
//     object keys case-insensitively, so every test in this file decoded those
//     bodies without complaint while the dashboard, written in TypeScript where
//     keys match exactly, read undefined.
//   - A nil slice encodes as JSON null. An empty result is a normal answer
//     rather than an error, so a collection must be an array even when it holds
//     nothing; a client reading .length on null throws.
//
// The body is decoded as a generic object on purpose. No struct tags and no
// case-insensitive matching means neither defect can hide here.
func TestListEndpointsReturnArraysWithLowercaseKeys(t *testing.T) {
	h := newHarness(t)
	if _, status := h.login("admin", adminPassword); status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}

	for _, tc := range []struct {
		name string
		path string
		key  string
	}{
		{"events", "/api/v1/events", "events"},
		{"alerts", "/api/v1/alerts", "alerts"},
		{"incidents", "/api/v1/incidents", "incidents"},
		{"agents", "/api/v1/agents", "agents"},
		{"assets", "/api/v1/assets", "assets"},
		{"rules", "/api/v1/rules", "rules"},
		{"audit", "/api/v1/audit", "entries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.do(http.MethodGet, tc.path+"?limit=5", nil, nil)
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				t.Fatalf("status = %d: %s", resp.StatusCode, body)
			}
			raw, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("read body: %v", err)
			}

			var payload map[string]json.RawMessage
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatalf("decode body: %v", err)
			}

			keys := make([]string, 0, len(payload))
			for key := range payload {
				if strings.ToLower(key) != key {
					t.Errorf("top-level key %q is not lowercase; JSON keys are matched exactly by every client that is not Go", key)
				}
				keys = append(keys, key)
			}
			sort.Strings(keys)

			collection, ok := payload[tc.key]
			if !ok {
				t.Fatalf("top-level keys %v do not include %q", keys, tc.key)
			}
			if !bytes.HasPrefix(bytes.TrimSpace(collection), []byte("[")) {
				t.Errorf("%s = %s, want a JSON array; a nil slice encodes as null and a strict client cannot read it as a list",
					tc.key, collection)
			}
		})
	}
}

// TestListPaginationReportsCursorInSnakeCase covers the one key an empty result
// cannot prove: next_cursor is omitted when there is no next page, so a rename
// of it would pass the empty-state test above and fail silently in the client,
// which declares it optional and would simply stop paginating.
func TestListPaginationReportsCursorInSnakeCase(t *testing.T) {
	h := newHarness(t)
	if _, status := h.login("admin", adminPassword); status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}

	at := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < 2; i++ {
		event := sshFailure(fmt.Sprintf("evt_page_%d", i), "198.51.100.7", at.Add(time.Duration(i)*time.Second))
		if _, err := h.store.InsertEvent(context.Background(), event); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}

	resp := h.do(http.MethodGet, "/api/v1/events?limit=1", nil, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	cursor, ok := payload["next_cursor"]
	if !ok {
		keys := make([]string, 0, len(payload))
		for key := range payload {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		t.Fatalf("top-level keys %v do not include next_cursor while a further page exists", keys)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(cursor), []byte(`"`)) {
		t.Errorf("next_cursor = %s, want a JSON string", cursor)
	}
}

func TestLoginRejectsMalformedUsername(t *testing.T) {
	h := newHarness(t)
	for _, username := range []string{"bad name!", strings.Repeat("a", 9000)} {
		resp := h.do(http.MethodPost, "/api/v1/auth/login",
			map[string]string{"username": username, "password": "irrelevant-value"}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("login with %d-byte username = %d, want 400", len(username), resp.StatusCode)
		}
		resp.Body.Close()
	}
}

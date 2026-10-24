package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/events/stream"
	"github.com/halimi/halimisoc/internal/storage"
)

// staleCursor reports a page that cannot exist for a client that followed
// next_cursor: the anchor was purged or forged. The API only issues a cursor
// when a further page exists, so an empty page would otherwise reach the
// console as "nothing matches these filters" — a false negative.
func staleCursor(cursor string, n int) bool {
	return cursor != "" && n == 0
}

// --- Events ---------------------------------------------------------------

// handleListEvents returns a page of normalized events.
func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewEvents) {
		return
	}

	q := storage.EventQuery{
		Limit:    s.pageSize(r),
		Cursor:   r.URL.Query().Get("cursor"),
		Host:     strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host"))),
		Actor:    strings.ToLower(strings.TrimSpace(r.URL.Query().Get("actor"))),
		SourceIP: strings.TrimSpace(r.URL.Query().Get("source_ip")),
	}
	if raw := r.URL.Query().Get("type"); raw != "" {
		t := model.EventType(raw)
		if !t.Valid() {
			writeError(w, http.StatusBadRequest, CodeBadRequest, "unknown event type filter")
			return
		}
		q.Type = t
	}
	if raw := r.URL.Query().Get("severity"); raw != "" {
		sev, err := model.ParseSeverity(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeBadRequest, "unknown severity filter")
			return
		}
		q.Severity = sev
	}
	if err := parseTimeRange(r, &q.Since, &q.Until); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	page, err := s.store.ListEvents(r.Context(), q)
	if err != nil {
		s.fail(w, err, "list events")
		return
	}
	if staleCursor(q.Cursor, len(page.Events)) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "cursor is no longer valid")
		return
	}
	page.Events = nonNil(page.Events)
	writeJSON(w, http.StatusOK, page)
}

// handleGetEvent returns a single event.
func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewEvents) {
		return
	}

	e, err := s.store.GetEvent(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err, "get event")
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// ingestRequest is the agent ingestion payload.
type ingestRequest struct {
	Events []*model.Event `json:"events"`
}

// handleIngestEvents accepts a batch from an authenticated agent.
func (s *Server) handleIngestEvents(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAgent(w, r)
	if p == nil {
		return
	}
	if s.ingester == nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable, "ingestion is unavailable")
		return
	}

	var req ingestRequest
	if err := s.decodeJSON(w, r, &req, s.limits.HTTPBodyBytes.Default); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, CodeTooLarge, "payload rejected")
		return
	}

	// Bind every event to the authenticated agent. A payload that claims a
	// different host is rejected rather than rewritten: silently accepting it
	// would let one compromised agent forge events attributed to any host.
	for _, e := range req.Events {
		if e == nil {
			continue
		}
		if e.Host != "" && !strings.EqualFold(e.Host, p.Agent.Host) {
			writeError(w, http.StatusForbidden, CodeForbidden,
				"event host does not match the authenticated agent")
			return
		}
		e.Host = p.Agent.Host
		e.AgentID = p.Agent.AgentID
	}

	res, err := s.ingester.Ingest(r.Context(), req.Events)
	if err != nil {
		s.fail(w, err, "ingest events")
		return
	}
	writeJSON(w, http.StatusAccepted, res)
}

// --- Alerts ---------------------------------------------------------------

// handleListAlerts returns a page of alerts.
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewAlerts) {
		return
	}

	q := storage.AlertQuery{
		Limit:  s.pageSize(r),
		Cursor: r.URL.Query().Get("cursor"),
		Host:   strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host"))),
		RuleID: strings.TrimSpace(r.URL.Query().Get("rule_id")),
	}
	if raw := r.URL.Query().Get("status"); raw != "" {
		st := alertsStatus(raw)
		if !st.Valid() {
			writeError(w, http.StatusBadRequest, CodeBadRequest, "unknown status filter")
			return
		}
		q.Status = st
	}
	if raw := r.URL.Query().Get("severity"); raw != "" {
		sev, err := model.ParseSeverity(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeBadRequest, "unknown severity filter")
			return
		}
		q.Severity = sev
	}

	page, err := s.store.ListAlerts(r.Context(), q)
	if err != nil {
		s.fail(w, err, "list alerts")
		return
	}
	if staleCursor(q.Cursor, len(page.Alerts)) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "cursor is no longer valid")
		return
	}
	page.Alerts = nonNil(page.Alerts)
	writeJSON(w, http.StatusOK, page)
}

// handleGetAlert returns one alert.
func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewAlerts) {
		return
	}
	a, err := s.store.GetAlert(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err, "get alert")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

type statusRequest struct {
	Status string `json:"status"`
}

// handleUpdateAlertStatus changes an alert's lifecycle state.
func (s *Server) handleUpdateAlertStatus(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermChangeAlertStatus) {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}

	var req statusRequest
	if err := s.decodeJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	to := alertsStatus(strings.ToUpper(strings.TrimSpace(req.Status)))
	if !to.Valid() {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "unknown alert status")
		return
	}

	updated, err := s.store.UpdateAlertStatus(r.Context(), r.PathValue("id"), to, s.now())
	if err != nil {
		s.fail(w, err, "update alert status")
		return
	}
	s.writeAudit(r, auditEntryForAlertStatus(p, updated.ID, updated.Status))
	// The status change is realtime: another operator watching the alert list
	// should see it without reloading.
	s.publishAlert(stream.EventAlertCreated, updated)
	writeJSON(w, http.StatusOK, updated)
}

// --- Shared helpers -------------------------------------------------------

// pageSize resolves the page size, clamping to the configured bounds.
//
// An oversized or unparseable value is clamped rather than rejected: a client
// asking for more than the server allows should get the maximum, not an error.
func (s *Server) pageSize(r *http.Request) int {
	def, max := s.limits.PageBounds()
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func parseTimeRange(r *http.Request, since, until *time.Time) error {
	if raw := r.URL.Query().Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return errInvalidTimeFilter("since")
		}
		*since = t.UTC()
	}
	if raw := r.URL.Query().Get("until"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return errInvalidTimeFilter("until")
		}
		*until = t.UTC()
	}
	if !since.IsZero() && !until.IsZero() && until.Before(*since) {
		return errInvertedRange{}
	}
	return nil
}

type errInvalidTimeFilter string

func (e errInvalidTimeFilter) Error() string {
	return "invalid " + string(e) + " filter, expected RFC3339"
}

type errInvertedRange struct{}

func (errInvertedRange) Error() string { return "until must not precede since" }

// fail renders a storage error without leaking its text to the client.
func (s *Server) fail(w http.ResponseWriter, err error, op string) {
	status, code := statusFor(err)
	if status >= 500 {
		s.log.Error("request failed", "op", op, "error", err)
	}
	msg := "request failed"
	switch status {
	case http.StatusNotFound:
		msg = "resource not found"
	case http.StatusConflict:
		msg = "conflict with the current resource state"
	case http.StatusRequestEntityTooLarge:
		msg = "payload too large"
	case http.StatusUnauthorized:
		msg = "authentication required"
	}
	writeError(w, status, code, msg)
}

// handleListRules lists the loaded detection rules.
func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewEvents) {
		return
	}
	if s.detector == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}})
		return
	}
	type view struct {
		ID          string         `json:"id"`
		Version     int            `json:"version"`
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Severity    model.Severity `json:"severity"`
		GroupBy     []string       `json:"group_by"`
		Threshold   rulesThreshold `json:"threshold"`
		Requires    string         `json:"requires,omitempty"`
	}
	type ruleView = view
	resp := struct {
		Rules []ruleView `json:"rules"`
	}{}
	for _, rule := range s.detector.Rules().Rules() {
		group := make([]string, 0, len(rule.GroupBy))
		for _, g := range rule.GroupBy {
			group = append(group, string(g))
		}
		v := ruleView{
			ID:          rule.ID,
			Version:     rule.Version,
			Name:        rule.Name,
			Description: rule.Description,
			Severity:    rule.Severity,
			GroupBy:     group,
			Threshold: rulesThreshold{
				Count:  rule.Threshold.Count,
				Window: rule.Threshold.Window.String(),
			},
		}
		if rule.Requires != nil {
			v.Requires = rule.Requires.RuleID
		}
		resp.Rules = append(resp.Rules, v)
	}
	writeJSON(w, http.StatusOK, resp)
}

type rulesThreshold struct {
	Count  int    `json:"count"`
	Window string `json:"window"`
}

// handleListAudit lists audit entries. Access is restricted to the admin role.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewAudit) {
		return
	}
	limit := s.pageSize(r)
	entries, next, err := s.store.ListAudit(r.Context(), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, err, "list audit")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":     nonNil(entries),
		"next_cursor": next,
	})
}

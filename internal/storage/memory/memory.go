// Package memory is an in-process Store implementation.
//
// It exists for two reasons: unit tests should not require a database, and the
// demo should run without one. It is not a production backend: state is lost on
// restart, and it makes no durability guarantees. The PostgreSQL implementation
// is the source of truth in any real deployment.
package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/halimi/halimisoc/internal/agents"
	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/storage"
	"github.com/halimi/halimisoc/internal/webauthn"
)

// defaultMaxEvents bounds the demo store so verbose telemetry cannot OOM it.
const defaultMaxEvents = 100_000

// Store is an in-memory Store.
type Store struct {
	mu sync.RWMutex

	maxEvents int

	events    map[string]*model.Event
	alerts    map[string]*alerts.Alert
	agents    map[string]*agents.Agent
	tokens    map[string]*agents.Token
	users     map[string]*auth.User
	sessions  map[string]*auth.Session
	incidents map[string]*incidents.Incident
	audit     []*audit.Entry
	passkeys  map[string]*webauthn.Passkey

	// eventOrder preserves insertion order so pagination is stable even when
	// two events share a timestamp.
	eventOrder []string
}

// New returns an empty in-memory store with the default event bound.
func New() *Store { return NewWithMaxEvents(defaultMaxEvents) }

// NewWithMaxEvents returns an empty store that evicts the oldest event once
// more than maxEvents are retained. A non-positive limit uses the default.
func NewWithMaxEvents(maxEvents int) *Store {
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	return &Store{
		maxEvents: maxEvents,
		events:    map[string]*model.Event{},
		alerts:    map[string]*alerts.Alert{},
		agents:    map[string]*agents.Agent{},
		tokens:    map[string]*agents.Token{},
		users:     map[string]*auth.User{},
		sessions:  map[string]*auth.Session{},
		incidents: map[string]*incidents.Incident{},
		passkeys:  map[string]*webauthn.Passkey{},
	}
}

var _ storage.Store = (*Store)(nil)

// --- Events ---------------------------------------------------------------

// InsertEvent implements storage.Store.
//
// The returned boolean is the idempotency signal: a replay of an existing id
// returns false so the caller skips detection. Re-running detection on a
// duplicate would double-count it in a sliding window and could fire a
// threshold rule that the real event stream never crossed.
func (s *Store) InsertEvent(_ context.Context, e *model.Event) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.events[e.ID]; exists {
		return false, nil
	}
	s.events[e.ID] = cloneEvent(e)
	s.eventOrder = append(s.eventOrder, e.ID)
	for len(s.events) > s.maxEvents && len(s.eventOrder) > 0 {
		oldest := s.eventOrder[0]
		s.eventOrder = s.eventOrder[1:]
		delete(s.events, oldest)
	}
	return true, nil
}

func (s *Store) GetEvent(_ context.Context, id string) (*model.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.events[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneEvent(e), nil
}

func (s *Store) ListEvents(_ context.Context, q storage.EventQuery) (*storage.EventPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched []*model.Event
	for _, id := range s.eventOrder {
		e := s.events[id]
		if !matchesEvent(e, q) {
			continue
		}
		matched = append(matched, cloneEvent(e))
	}

	// Ordering is newest first with the id as a stable tie-breaker. Ordering by
	// ingestion order instead would let a spool replay rewrite history.
	sort.SliceStable(matched, func(i, j int) bool {
		if !matched[i].Time.Equal(matched[j].Time) {
			return matched[i].Time.After(matched[j].Time)
		}
		return matched[i].ID > matched[j].ID
	})

	return paginateEvents(matched, q.Limit, q.Cursor), nil
}

func matchesEvent(e *model.Event, q storage.EventQuery) bool {
	if q.Host != "" && e.Host != q.Host {
		return false
	}
	if q.Actor != "" && e.Actor != q.Actor {
		return false
	}
	if q.SourceIP != "" && e.Network.SourceIP != q.SourceIP {
		return false
	}
	if q.Type != "" && e.Type != q.Type {
		return false
	}
	if q.Severity != "" && e.Severity != q.Severity {
		return false
	}
	if !q.Since.IsZero() && e.Time.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && e.Time.After(q.Until) {
		return false
	}
	return true
}

func paginateEvents(all []*model.Event, limit int, cursor string) *storage.EventPage {
	start := 0
	if cursor != "" {
		start = len(all)
		for i, e := range all {
			if e.ID == cursor {
				start = i + 1
				break
			}
		}
	}
	if start >= len(all) {
		return &storage.EventPage{}
	}
	end := len(all)
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	page := &storage.EventPage{Events: all[start:end]}
	if end < len(all) {
		page.NextCursor = all[end-1].ID
	}
	return page
}

func (s *Store) CountEvents(_ context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.events)), nil
}

// PurgeRawEvidence removes raw evidence older than the cutoff while keeping the
// structured event, so alert and incident references stay valid.
func (s *Store) PurgeRawEvidence(_ context.Context, olderThan time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var purged int64
	for _, e := range s.events {
		if e.Raw == "" || !e.Time.Before(olderThan) {
			continue
		}
		e.Raw = ""
		if e.Attributes == nil {
			e.Attributes = map[string]string{}
		}
		e.Attributes["raw_expired"] = "true"
		purged++
	}
	return purged, nil
}

// PurgeEvents deletes the whole record, unlike PurgeRawEvidence.
// Alerts keep event ids as historical references, not foreign keys.
func (s *Store) PurgeEvents(_ context.Context, olderThan time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var purged int64
	kept := s.eventOrder[:0]
	for _, id := range s.eventOrder {
		e, ok := s.events[id]
		if !ok {
			continue
		}
		if e.Time.Before(olderThan) {
			delete(s.events, id)
			purged++
			continue
		}
		kept = append(kept, id)
	}
	s.eventOrder = kept
	return purged, nil
}

// --- Alerts ---------------------------------------------------------------

func (s *Store) SaveAlert(_ context.Context, a *alerts.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.alerts[a.ID]; exists {
		return storage.ErrConflict
	}
	s.alerts[a.ID] = cloneAlert(a)
	return nil
}

func (s *Store) GetAlert(_ context.Context, id string) (*alerts.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneAlert(a), nil
}

func (s *Store) ListAlerts(_ context.Context, q storage.AlertQuery) (*storage.AlertPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched []*alerts.Alert
	for _, a := range s.alerts {
		if q.Status != "" && a.Status != q.Status {
			continue
		}
		if q.Severity != "" && a.Severity != q.Severity {
			continue
		}
		if q.Host != "" && a.Host != q.Host {
			continue
		}
		if q.RuleID != "" && a.RuleID != q.RuleID {
			continue
		}
		matched = append(matched, cloneAlert(a))
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if !matched[i].CreatedAt.Equal(matched[j].CreatedAt) {
			return matched[i].CreatedAt.After(matched[j].CreatedAt)
		}
		return matched[i].ID > matched[j].ID
	})

	start := 0
	if q.Cursor != "" {
		start = len(matched)
		for i, a := range matched {
			if a.ID == q.Cursor {
				start = i + 1
				break
			}
		}
	}
	if start >= len(matched) {
		return &storage.AlertPage{}, nil
	}
	end := len(matched)
	if q.Limit > 0 && start+q.Limit < end {
		end = start + q.Limit
	}
	page := &storage.AlertPage{Alerts: matched[start:end]}
	if end < len(matched) {
		page.NextCursor = matched[end-1].ID
	}
	return page, nil
}

func (s *Store) UpdateAlertStatus(_ context.Context, id string, to alerts.Status, at time.Time) (*alerts.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.alerts[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	if !alerts.CanTransition(a.Status, to) {
		return nil, fmt.Errorf("%w: alert %s %s -> %s", storage.ErrInvalidTransition, id, a.Status, to)
	}
	a.Status = to
	a.UpdatedAt = at
	return cloneAlert(a), nil
}

func (s *Store) CountAlertsBySeverity(_ context.Context) (map[model.Severity]int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[model.Severity]int64{}
	for _, a := range s.alerts {
		out[a.Severity]++
	}
	return out, nil
}

func (s *Store) PurgeAlerts(_ context.Context, olderThan time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var purged int64
	for id, a := range s.alerts {
		if a.CreatedAt.Before(olderThan) {
			delete(s.alerts, id)
			purged++
		}
	}
	return purged, nil
}

// --- Agents ---------------------------------------------------------------

func (s *Store) SaveAgent(_ context.Context, a *agents.Agent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[a.ID] = cloneAgent(a)
	return nil
}

func (s *Store) GetAgent(_ context.Context, id string) (*agents.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneAgent(a), nil
}

func (s *Store) GetAgentByHost(_ context.Context, host string) (*agents.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.agents {
		if a.Host == host {
			return cloneAgent(a), nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) ListAgents(_ context.Context) ([]*agents.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Deliberately left nil rather than make()d: an empty result is nil here for
	// every list method in this store and in the Postgres one, so the two
	// implementations of the interface agree. The API normalises the difference
	// away on the way out, but a store that disagrees with its twin is how a
	// bug becomes invisible in one configuration and fatal in the other.
	var out []*agents.Agent
	for _, a := range s.agents {
		out = append(out, cloneAgent(a))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) UpdateAgentHeartbeat(_ context.Context, id string, at time.Time, queueDepth, spoolBytes int64, status agents.Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return storage.ErrNotFound
	}
	a.LastHeartbeat = at
	a.QueueDepth = queueDepth
	a.SpoolBytes = spoolBytes
	a.Status = status
	return nil
}

func (s *Store) RevokeAgent(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return storage.ErrNotFound
	}
	a.RevokedAt = &at
	a.Status = agents.StatusOffline
	return nil
}

func (s *Store) SaveToken(_ context.Context, t *agents.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.TokenHash] = cloneToken(t)
	return nil
}

func (s *Store) GetTokenByHash(_ context.Context, hash string) (*agents.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[hash]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneToken(t), nil
}

func (s *Store) RotateTokensForAgent(_ context.Context, agentID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.AgentID == agentID && t.RotatedAt == nil && t.RevokedAt == nil {
			ts := at
			t.RotatedAt = &ts
		}
	}
	return nil
}

func (s *Store) RevokeTokensForAgent(_ context.Context, agentID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.AgentID == agentID && t.RevokedAt == nil {
			ts := at
			t.RevokedAt = &ts
		}
	}
	return nil
}

func (s *Store) TouchToken(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.ID == id {
			ts := at
			t.LastUsedAt = &ts
			return nil
		}
	}
	return storage.ErrNotFound
}

// --- Users ----------------------------------------------------------------

func (s *Store) SaveUser(_ context.Context, u *auth.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.users {
		// Comparison is case-insensitive to match the PostgreSQL unique index on
		// lower(username). Two accounts differing only in case would be
		// indistinguishable to an operator reading the login form.
		if strings.EqualFold(existing.Username, u.Username) && existing.ID != u.ID {
			return fmt.Errorf("%w: username %q already exists", storage.ErrConflict, u.Username)
		}
	}
	cp := *u
	cp.BackupHashes = append([]string(nil), u.BackupHashes...)
	s.users[u.ID] = &cp
	return nil
}

func (s *Store) GetUserByUsername(_ context.Context, username string) (*auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Username, username) {
			cp := *u
			cp.BackupHashes = append([]string(nil), u.BackupHashes...)
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) GetUser(_ context.Context, id string) (*auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := *u
	cp.BackupHashes = append([]string(nil), u.BackupHashes...)
	return &cp, nil
}

func (s *Store) RecordLogin(_ context.Context, userID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return storage.ErrNotFound
	}
	ts := at
	u.LastLoginAt = &ts
	return nil
}

func (s *Store) CountUsers(_ context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.users)), nil
}

// ListUsers returns every operator account ordered by username, so the admin
// view is stable across requests.
func (s *Store) ListUsers(_ context.Context) ([]*auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*auth.User, 0, len(s.users))
	for _, u := range s.users {
		cp := *u
		cp.BackupHashes = append([]string(nil), u.BackupHashes...)
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// --- Sessions -------------------------------------------------------------

func (s *Store) SaveSession(_ context.Context, sess *auth.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.sessions[sess.ID] = &cp
	return nil
}

func (s *Store) GetSession(_ context.Context, id string) (*auth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := *sess
	return &cp, nil
}

func (s *Store) TouchSession(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return storage.ErrNotFound
	}
	sess.LastSeenAt = at.UTC()
	return nil
}

func (s *Store) RevokeSession(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return storage.ErrNotFound
	}
	ts := at
	sess.RevokedAt = &ts
	return nil
}

func (s *Store) RevokeUserSessions(_ context.Context, userID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.UserID == userID && sess.RevokedAt == nil {
			ts := at
			sess.RevokedAt = &ts
		}
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.sessions {
		if sess.Expired(now) || sess.Revoked() {
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}

// --- Incidents ------------------------------------------------------------

func (s *Store) SaveIncident(_ context.Context, inc *incidents.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidents[inc.ID] = cloneIncident(inc)
	return nil
}

func (s *Store) GetIncident(_ context.Context, id string) (*incidents.Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc, ok := s.incidents[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneIncident(inc), nil
}

func (s *Store) ListIncidents(_ context.Context, limit int, cursor string) (*incidents.IncidentList, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]*incidents.Incident, 0, len(s.incidents))
	for _, inc := range s.incidents {
		all = append(all, cloneIncident(inc))
	}
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].LastSeen.Equal(all[j].LastSeen) {
			return all[i].LastSeen.After(all[j].LastSeen)
		}
		return all[i].ID > all[j].ID
	})

	start := 0
	if cursor != "" {
		start = len(all)
		for i, inc := range all {
			if inc.ID == cursor {
				start = i + 1
				break
			}
		}
	}
	if start >= len(all) {
		return &incidents.IncidentList{}, nil
	}
	end := len(all)
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	out := &incidents.IncidentList{Incidents: all[start:end]}
	if end < len(all) {
		out.NextCursor = all[end-1].ID
	}
	return out, nil
}

func (s *Store) ListOpenIncidents(_ context.Context) ([]*incidents.Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*incidents.Incident
	for _, inc := range s.incidents {
		if !inc.Status.Terminal() {
			out = append(out, cloneIncident(inc))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

// --- Audit ----------------------------------------------------------------

func (s *Store) AppendAudit(_ context.Context, e *audit.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *e
	s.audit = append(s.audit, &cp)
	return nil
}

func (s *Store) ListAudit(_ context.Context, limit int, cursor string) ([]*audit.Entry, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	start := 0
	if cursor != "" {
		start = len(s.audit)
		for i, e := range s.audit {
			if e.ID == cursor {
				start = i + 1
				break
			}
		}
	}
	if start >= len(s.audit) {
		return nil, "", nil
	}
	end := len(s.audit)
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	out := make([]*audit.Entry, 0, end-start)
	for _, e := range s.audit[start:end] {
		cp := *e
		out = append(out, &cp)
	}
	next := ""
	if end < len(s.audit) {
		next = s.audit[end-1].ID
	}
	return out, next, nil
}

func (s *Store) PurgeAudit(_ context.Context, olderThan time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.audit[:0]
	var purged int64
	for _, e := range s.audit {
		if e.Timestamp.Before(olderThan) {
			purged++
			continue
		}
		kept = append(kept, e)
	}
	s.audit = kept
	return purged, nil
}

// --- Lifecycle ------------------------------------------------------------

func (s *Store) Ping(context.Context) error { return nil }

func (s *Store) Close() error { return nil }

// --- Passkeys -------------------------------------------------------------

func (s *Store) SavePasskey(_ context.Context, p *webauthn.Passkey) error {
	if p == nil {
		return fmt.Errorf("memory: nil passkey")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.passkeys {
		if existing.CredentialID == p.CredentialID && existing.ID != p.ID {
			return fmt.Errorf("%w: passkey already registered", storage.ErrConflict)
		}
	}
	cp := *p
	cp.Transports = append([]string(nil), p.Transports...)
	s.passkeys[p.ID] = &cp
	return nil
}

func (s *Store) ListPasskeysByUser(_ context.Context, userID string) ([]*webauthn.Passkey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*webauthn.Passkey
	for _, p := range s.passkeys {
		if p.UserID == userID {
			cp := *p
			cp.Transports = append([]string(nil), p.Transports...)
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) GetPasskeyByCredentialID(_ context.Context, credentialID string) (*webauthn.Passkey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.passkeys {
		if p.CredentialID == credentialID {
			cp := *p
			cp.Transports = append([]string(nil), p.Transports...)
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) UpdatePasskeyCounter(_ context.Context, id string, signCount uint32, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.passkeys[id]
	if !ok {
		return storage.ErrNotFound
	}
	p.SignCount = signCount
	ts := at.UTC()
	p.LastUsedAt = &ts
	return nil
}

func (s *Store) DeletePasskey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.passkeys[id]; !ok {
		return storage.ErrNotFound
	}
	delete(s.passkeys, id)
	return nil
}

// --- Cloning --------------------------------------------------------------

// Cloning on every boundary prevents a caller from mutating stored state
// through a returned pointer, which would let a handler accidentally corrupt
// the store or race with detection.

func cloneEvent(e *model.Event) *model.Event {
	cp := *e
	cp.Attributes = cloneMap(e.Attributes)
	return &cp
}

func cloneAlert(a *alerts.Alert) *alerts.Alert {
	cp := *a
	cp.EventIDs = append([]string(nil), a.EventIDs...)
	return &cp
}

func cloneAgent(a *agents.Agent) *agents.Agent {
	cp := *a
	return &cp
}

func cloneToken(t *agents.Token) *agents.Token {
	cp := *t
	return &cp
}

func cloneIncident(i *incidents.Incident) *incidents.Incident {
	cp := *i
	cp.Hosts = append([]string(nil), i.Hosts...)
	cp.Actors = append([]string(nil), i.Actors...)
	cp.SourceIPs = append([]string(nil), i.SourceIPs...)
	cp.AlertIDs = append([]string(nil), i.AlertIDs...)
	cp.EventIDs = append([]string(nil), i.EventIDs...)
	cp.Stages = append([]incidents.Stage(nil), i.Stages...)
	return &cp
}

func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

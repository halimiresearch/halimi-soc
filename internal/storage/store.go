// Package storage defines the persistence contract and its implementations.
//
// The interface is deliberately narrow and pure-Go: domain code depends on it,
// not on pgx, so the detection, correlation and API layers can be tested without
// a database. The PostgreSQL implementation is the production backend; the
// in-memory implementation exists for tests and for `--no-database` demo runs.
package storage

import (
	"context"
	"errors"
	"time"

	"github.com/halimi/halimisoc/internal/agents"
	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/webauthn"
)

// Errors returned by every implementation.
var (
	// ErrNotFound means the requested resource does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict means a uniqueness constraint was violated.
	ErrConflict = errors.New("conflict")

	// ErrInvalidTransition means a state machine rejected the change.
	ErrInvalidTransition = errors.New("invalid state transition")
)

// EventQuery selects and paginates events.
type EventQuery struct {
	Limit  int
	Cursor string

	Host     string
	Actor    string
	SourceIP string
	Type     model.EventType
	Severity model.Severity

	Since time.Time
	Until time.Time
}

// AlertQuery selects and paginates alerts.
type AlertQuery struct {
	Limit  int
	Cursor string

	Status   alerts.Status
	Severity model.Severity
	Host     string
	RuleID   string
}

// EventPage is a page of events.
//
// The API serialises this type directly, so the tags are the wire contract rather
// than an implementation detail: without them Go emits the exported field names
// ("Events", "NextCursor") and every non-Go client — which cannot rely on Go's
// case-insensitive field matching — reads a missing key.
type EventPage struct {
	Events     []*model.Event `json:"events"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

// AlertPage is a page of alerts. See EventPage for why the tags are load-bearing.
type AlertPage struct {
	Alerts     []*alerts.Alert `json:"alerts"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// Store is the persistence contract used by the whole backend.
type Store interface {
	// Events.
	InsertEvent(ctx context.Context, e *model.Event) (inserted bool, err error)
	ListEvents(ctx context.Context, q EventQuery) (*EventPage, error)
	GetEvent(ctx context.Context, id string) (*model.Event, error)
	CountEvents(ctx context.Context) (int64, error)
	PurgeRawEvidence(ctx context.Context, olderThan time.Time) (int64, error)
	PurgeEvents(ctx context.Context, olderThan time.Time) (int64, error)

	// Alerts.
	SaveAlert(ctx context.Context, a *alerts.Alert) error
	GetAlert(ctx context.Context, id string) (*alerts.Alert, error)
	ListAlerts(ctx context.Context, q AlertQuery) (*AlertPage, error)
	UpdateAlertStatus(ctx context.Context, id string, to alerts.Status, at time.Time) (*alerts.Alert, error)
	CountAlertsBySeverity(ctx context.Context) (map[model.Severity]int64, error)
	PurgeAlerts(ctx context.Context, olderThan time.Time) (int64, error)

	// Agents.
	SaveAgent(ctx context.Context, a *agents.Agent) error
	GetAgent(ctx context.Context, id string) (*agents.Agent, error)
	GetAgentByHost(ctx context.Context, host string) (*agents.Agent, error)
	ListAgents(ctx context.Context) ([]*agents.Agent, error)
	UpdateAgentHeartbeat(ctx context.Context, id string, at time.Time, queueDepth, spoolBytes int64, status agents.Status) error
	RevokeAgent(ctx context.Context, id string, at time.Time) error

	// Agent tokens.
	SaveToken(ctx context.Context, t *agents.Token) error
	GetTokenByHash(ctx context.Context, hash string) (*agents.Token, error)
	RotateTokensForAgent(ctx context.Context, agentID string, at time.Time) error
	RevokeTokensForAgent(ctx context.Context, agentID string, at time.Time) error
	TouchToken(ctx context.Context, id string, at time.Time) error

	// Users.
	SaveUser(ctx context.Context, u *auth.User) error
	GetUserByUsername(ctx context.Context, username string) (*auth.User, error)
	GetUser(ctx context.Context, id string) (*auth.User, error)
	ListUsers(ctx context.Context) ([]*auth.User, error)
	CountUsers(ctx context.Context) (int64, error)
	RecordLogin(ctx context.Context, userID string, at time.Time) error

	// Sessions.
	SaveSession(ctx context.Context, s *auth.Session) error
	GetSession(ctx context.Context, id string) (*auth.Session, error)
	TouchSession(ctx context.Context, id string, at time.Time) error
	RevokeSession(ctx context.Context, id string, at time.Time) error
	RevokeUserSessions(ctx context.Context, userID string, at time.Time) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error)

	// Incidents.
	SaveIncident(ctx context.Context, inc *incidents.Incident) error
	GetIncident(ctx context.Context, id string) (*incidents.Incident, error)
	ListIncidents(ctx context.Context, limit int, cursor string) (*incidents.IncidentList, error)
	ListOpenIncidents(ctx context.Context) ([]*incidents.Incident, error)

	// Audit.
	AppendAudit(ctx context.Context, e *audit.Entry) error
	ListAudit(ctx context.Context, limit int, cursor string) ([]*audit.Entry, string, error)
	PurgeAudit(ctx context.Context, olderThan time.Time) (int64, error)

	// Passkeys (WebAuthn).
	SavePasskey(ctx context.Context, p *webauthn.Passkey) error
	ListPasskeysByUser(ctx context.Context, userID string) ([]*webauthn.Passkey, error)
	GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*webauthn.Passkey, error)
	UpdatePasskeyCounter(ctx context.Context, id string, signCount uint32, at time.Time) error
	DeletePasskey(ctx context.Context, id string) error

	// Lifecycle.
	Ping(ctx context.Context) error
	Close() error
}

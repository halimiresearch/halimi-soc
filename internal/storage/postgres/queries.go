package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/halimi/halimisoc/internal/agents"
	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/storage"
	"github.com/halimi/halimisoc/internal/webauthn"
)

var (
	errNotFound = storage.ErrNotFound
	errConflict = storage.ErrConflict
)

// eventColumns is the canonical projection order for events, shared by every
// query that reads an event so a scan helper can be reused.
const eventColumns = `id, schema_version, type, event_time, received_at, observed_at,
	host, coalesce(agent_id, ''), source, coalesce(source_path, ''), coalesce(actor, ''),
	coalesce(target, ''), coalesce(src_ip, ''), coalesce(src_port, 0),
	coalesce(dst_ip, ''), coalesce(dst_port, 0), coalesce(protocol, ''), coalesce(outcome, ''),
	severity, attributes, coalesce(message, ''), coalesce(raw, '')`

// InsertEvent implements storage.Store.
//
// ON CONFLICT DO NOTHING makes the insert idempotent at the database level: a
// replayed event cannot create a second row, and the affected-row count is the
// authoritative signal for whether detection should run. This is what removes
// the read-then-write race a "check then insert" would have.
func (s *Store) InsertEvent(ctx context.Context, e *model.Event) (bool, error) {
	if e == nil {
		return false, fmt.Errorf("postgres: nil event")
	}
	attrs, err := marshalMap(e.Attributes)
	if err != nil {
		return false, fmt.Errorf("postgres: marshal attributes: %w", err)
	}

	var agentID *string
	if e.AgentID != "" {
		agentID = &e.AgentID
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO events (
			id, schema_version, type, event_time, received_at, observed_at,
			host, agent_id, source, source_path, actor, target,
			src_ip, src_port, dst_ip, dst_port, protocol, outcome,
			severity, attributes, message, raw, dedupe_key
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NULLIF($14,0),$15,NULLIF($16,0),$17,$18,
			$19,$20,$21,$22,$23
		)
		ON CONFLICT (id) DO NOTHING`,
		e.ID, e.SchemaVersion, string(e.Type), e.Time.UTC(), e.ReceivedAt.UTC(), e.ObservedAt.UTC(),
		e.Host, agentID, string(e.Source), nullIfEmpty(e.SourcePath), nullIfEmpty(e.Actor), nullIfEmpty(e.Target),
		nullIfEmpty(e.Network.SourceIP), e.Network.SourcePort, nullIfEmpty(e.Network.DestIP), e.Network.DestPort,
		nullIfEmpty(e.Network.Protocol), nullIfEmpty(string(e.Outcome)),
		string(e.Severity), attrs, nullIfEmpty(e.Message), nullIfEmpty(e.Raw), e.DedupeKey(),
	)
	if err != nil {
		return false, fmt.Errorf("postgres: insert event: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// GetEvent implements storage.Store.
func (s *Store) GetEvent(ctx context.Context, id string) (*model.Event, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+eventColumns+` FROM events WHERE id = $1`, id)
	e, err := scanEvent(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return e, nil
}

// ListEvents implements storage.Store using keyset pagination.
//
// Keyset pagination on (event_time, id) is used instead of OFFSET because OFFSET
// degrades linearly and, more importantly, can skip or repeat rows when new
// telemetry arrives between two page requests.
func (s *Store) ListEvents(ctx context.Context, q storage.EventQuery) (*storage.EventPage, error) {
	limit := clampLimit(q.Limit, 50, 500)

	var (
		where []string
		args  []any
	)
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if q.Host != "" {
		add("host = $%d", q.Host)
	}
	if q.Actor != "" {
		add("actor = $%d", q.Actor)
	}
	if q.SourceIP != "" {
		add("src_ip = $%d", q.SourceIP)
	}
	if q.Type != "" {
		add("type = $%d", string(q.Type))
	}
	if q.Severity != "" {
		add("severity = $%d", string(q.Severity))
	}
	if !q.Since.IsZero() {
		add("event_time >= $%d", q.Since.UTC())
	}
	if !q.Until.IsZero() {
		add("event_time <= $%d", q.Until.UTC())
	}
	if q.Cursor != "" {
		// The cursor is the last id of the previous page. Because ids are
		// time-ordered ULIDs, comparing on id alone is equivalent to comparing
		// on (event_time, id) and needs no second parameter.
		add("id < $%d", q.Cursor)
	}

	sql := `SELECT ` + eventColumns + ` FROM events`
	if len(where) > 0 {
		sql += ` WHERE ` + joinAnd(where)
	}
	sql += ` ORDER BY id DESC LIMIT ` + fmt.Sprint(limit+1)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list events: %w", err)
	}
	defer rows.Close()

	page := &storage.EventPage{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan event: %w", err)
		}
		if len(page.Events) == limit {
			page.NextCursor = page.Events[len(page.Events)-1].ID
			break
		}
		page.Events = append(page.Events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate events: %w", err)
	}
	return page, nil
}

// CountEvents implements storage.Store.
func (s *Store) CountEvents(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&n); err != nil {
		return 0, fmt.Errorf("postgres: count events: %w", err)
	}
	return n, nil
}

// PurgeRawEvidence implements storage.Store.
func (s *Store) PurgeRawEvidence(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE events
		SET raw = NULL, raw_expired = TRUE
		WHERE raw IS NOT NULL AND event_time < $1`, olderThan.UTC())
	if err != nil {
		return 0, fmt.Errorf("postgres: purge raw evidence: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PurgeEvents deletes structured events; alert and incident event ids are
// historical references, so retention cannot cascade into them.
func (s *Store) PurgeEvents(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM events WHERE event_time < $1`, olderThan.UTC())
	if err != nil {
		return 0, fmt.Errorf("postgres: purge events: %w", err)
	}
	return tag.RowsAffected(), nil
}

// --- Alerts ---------------------------------------------------------------

func (s *Store) SaveAlert(ctx context.Context, a *alerts.Alert) error {
	if a == nil {
		return fmt.Errorf("postgres: nil alert")
	}
	eventIDs, err := json.Marshal(a.EventIDs)
	if err != nil {
		return fmt.Errorf("postgres: marshal alert evidence: %w", err)
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO alerts (
			id, rule_id, rule_version, rule_name, severity, status, title, reason,
			host, actor, src_ip, entity, event_ids, count, window_start, window_end,
			dedupe_key, created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
		)
		ON CONFLICT (id) DO NOTHING`,
		a.ID, a.RuleID, a.RuleVersion, a.RuleName, string(a.Severity), string(a.Status),
		a.Title, a.Reason, nullIfEmpty(a.Host), nullIfEmpty(a.Actor), nullIfEmpty(a.SourceIP),
		nullIfEmpty(a.Entity), eventIDs, a.Count, a.WindowStart.UTC(), a.WindowEnd.UTC(),
		a.DedupeKey, a.CreatedAt.UTC(), a.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: save alert: %w", err)
	}
	// Match the memory backend: a duplicate id is a conflict, not a silent success.
	if tag.RowsAffected() == 0 {
		return storage.ErrConflict
	}
	return nil
}

func (s *Store) GetAlert(ctx context.Context, id string) (*alerts.Alert, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, rule_id, rule_version, rule_name, severity, status, title, reason,
		       coalesce(host,''), coalesce(actor,''), coalesce(src_ip,''), coalesce(entity,''),
		       event_ids, count, window_start, window_end, dedupe_key, created_at, updated_at
		FROM alerts WHERE id = $1`, id)
	a, err := scanAlert(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return a, nil
}

func (s *Store) ListAlerts(ctx context.Context, q storage.AlertQuery) (*storage.AlertPage, error) {
	limit := clampLimit(q.Limit, 50, 500)

	var (
		where []string
		args  []any
	)
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if q.Status != "" {
		add("status = $%d", string(q.Status))
	}
	if q.Severity != "" {
		add("severity = $%d", string(q.Severity))
	}
	if q.Host != "" {
		add("host = $%d", q.Host)
	}
	if q.RuleID != "" {
		add("rule_id = $%d", q.RuleID)
	}
	if q.Cursor != "" {
		add("id < $%d", q.Cursor)
	}

	sql := `SELECT id, rule_id, rule_version, rule_name, severity, status, title, reason,
		       coalesce(host,''), coalesce(actor,''), coalesce(src_ip,''), coalesce(entity,''),
		       event_ids, count, window_start, window_end, dedupe_key, created_at, updated_at
		FROM alerts`
	if len(where) > 0 {
		sql += ` WHERE ` + joinAnd(where)
	}
	sql += ` ORDER BY id DESC LIMIT ` + fmt.Sprint(limit+1)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list alerts: %w", err)
	}
	defer rows.Close()

	page := &storage.AlertPage{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan alert: %w", err)
		}
		if len(page.Alerts) == limit {
			page.NextCursor = page.Alerts[len(page.Alerts)-1].ID
			break
		}
		page.Alerts = append(page.Alerts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate alerts: %w", err)
	}
	return page, nil
}

// UpdateAlertStatus implements storage.Store.
//
// The WHERE clause pins the expected previous status, so the state machine is
// enforced by the database as well as by the domain layer. Without it, two
// concurrent requests could each read OPEN and each write a different terminal
// status, and the last writer would silently win.
func (s *Store) UpdateAlertStatus(ctx context.Context, id string, to alerts.Status, at time.Time) (*alerts.Alert, error) {
	current, err := s.GetAlert(ctx, id)
	if err != nil {
		return nil, err
	}
	if !alerts.CanTransition(current.Status, to) {
		return nil, fmt.Errorf("%w: alert %s %s -> %s", storage.ErrInvalidTransition, id, current.Status, to)
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE alerts SET status = $1, updated_at = $2
		WHERE id = $3 AND status = $4`, string(to), at.UTC(), id, string(current.Status))
	if err != nil {
		return nil, fmt.Errorf("postgres: update alert status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("%w: alert %s changed concurrently", storage.ErrInvalidTransition, id)
	}
	return s.GetAlert(ctx, id)
}

func (s *Store) CountAlertsBySeverity(ctx context.Context) (map[model.Severity]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT severity, count(*) FROM alerts GROUP BY severity`)
	if err != nil {
		return nil, fmt.Errorf("postgres: count alerts: %w", err)
	}
	defer rows.Close()

	out := map[model.Severity]int64{}
	for rows.Next() {
		var sev string
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, fmt.Errorf("postgres: scan alert count: %w", err)
		}
		out[model.Severity(sev)] = n
	}
	return out, rows.Err()
}

func (s *Store) PurgeAlerts(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM alerts WHERE created_at < $1`, olderThan.UTC())
	if err != nil {
		return 0, fmt.Errorf("postgres: purge alerts: %w", err)
	}
	return tag.RowsAffected(), nil
}

// --- Agents ---------------------------------------------------------------

func (s *Store) SaveAgent(ctx context.Context, a *agents.Agent) error {
	if a == nil {
		return fmt.Errorf("postgres: nil agent")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (id, host, os, version, status, enrolled_at, last_heartbeat, revoked_at, queue_depth, spool_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (id) DO UPDATE SET
			host = EXCLUDED.host,
			os = EXCLUDED.os,
			version = EXCLUDED.version,
			status = EXCLUDED.status,
			last_heartbeat = EXCLUDED.last_heartbeat,
			revoked_at = EXCLUDED.revoked_at,
			queue_depth = EXCLUDED.queue_depth,
			spool_bytes = EXCLUDED.spool_bytes`,
		a.ID, a.Host, nullIfEmpty(a.OS), nullIfEmpty(a.Version), string(a.Status),
		a.EnrolledAt.UTC(), nullIfZeroTime(a.LastHeartbeat), a.RevokedAt, a.QueueDepth, a.SpoolBytes,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: agent host %q already enrolled", storage.ErrConflict, a.Host)
		}
		return fmt.Errorf("postgres: save agent: %w", err)
	}
	return nil
}

func (s *Store) GetAgent(ctx context.Context, id string) (*agents.Agent, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, host, coalesce(os,''), coalesce(version,''), status, enrolled_at,
		       last_heartbeat, revoked_at, queue_depth, spool_bytes
		FROM agents WHERE id = $1`, id)
	a, err := scanAgent(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return a, nil
}

func (s *Store) GetAgentByHost(ctx context.Context, host string) (*agents.Agent, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, host, coalesce(os,''), coalesce(version,''), status, enrolled_at,
		       last_heartbeat, revoked_at, queue_depth, spool_bytes
		FROM agents WHERE host = $1`, host)
	a, err := scanAgent(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return a, nil
}

func (s *Store) ListAgents(ctx context.Context) ([]*agents.Agent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, host, coalesce(os,''), coalesce(version,''), status, enrolled_at,
		       last_heartbeat, revoked_at, queue_depth, spool_bytes
		FROM agents ORDER BY host ASC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list agents: %w", err)
	}
	defer rows.Close()

	var out []*agents.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan agent: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAgentHeartbeat(ctx context.Context, id string, at time.Time, queueDepth, spoolBytes int64, status agents.Status) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE agents SET last_heartbeat = $1, queue_depth = $2, spool_bytes = $3, status = $4
		WHERE id = $5`, at.UTC(), queueDepth, spoolBytes, string(status), id)
	if err != nil {
		return fmt.Errorf("postgres: update heartbeat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RevokeAgent(ctx context.Context, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE agents SET revoked_at = $1, status = 'OFFLINE' WHERE id = $2`, at.UTC(), id)
	if err != nil {
		return fmt.Errorf("postgres: revoke agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// --- Agent tokens ---------------------------------------------------------

func (s *Store) SaveToken(ctx context.Context, t *agents.Token) error {
	if t == nil {
		return fmt.Errorf("postgres: nil token")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_tokens (id, agent_id, token_hash, prefix, created_at, last_used_at, rotated_at, revoked_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		t.ID, t.AgentID, t.TokenHash, t.Prefix, t.CreatedAt.UTC(),
		t.LastUsedAt, t.RotatedAt, t.RevokedAt, t.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: save agent token: %w", err)
	}
	return nil
}

func (s *Store) GetTokenByHash(ctx context.Context, hash string) (*agents.Token, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, token_hash, prefix, created_at, last_used_at, rotated_at, revoked_at, expires_at
		FROM agent_tokens WHERE token_hash = $1`, hash)
	t, err := scanToken(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return t, nil
}

func (s *Store) RotateTokensForAgent(ctx context.Context, agentID string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agent_tokens SET rotated_at = $1
		WHERE agent_id = $2 AND rotated_at IS NULL AND revoked_at IS NULL`, at.UTC(), agentID)
	if err != nil {
		return fmt.Errorf("postgres: rotate agent tokens: %w", err)
	}
	return nil
}

func (s *Store) RevokeTokensForAgent(ctx context.Context, agentID string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agent_tokens SET revoked_at = $1
		WHERE agent_id = $2 AND revoked_at IS NULL`, at.UTC(), agentID)
	if err != nil {
		return fmt.Errorf("postgres: revoke agent tokens: %w", err)
	}
	return nil
}

func (s *Store) TouchToken(ctx context.Context, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_tokens SET last_used_at = $1 WHERE id = $2`, at.UTC(), id)
	if err != nil {
		return fmt.Errorf("postgres: touch agent token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// --- Users ----------------------------------------------------------------

func (s *Store) SaveUser(ctx context.Context, u *auth.User) error {
	if u == nil {
		return fmt.Errorf("postgres: nil user")
	}
	backupJSON, err := json.Marshal(nonNilStrings(u.BackupHashes))
	if err != nil {
		return fmt.Errorf("postgres: marshal backup codes: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO users (id, username, password_hash, role, disabled, created_at, last_login_at,
			totp_secret, totp_enabled, totp_enrolled_at, backup_codes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (id) DO UPDATE SET
			username = EXCLUDED.username,
			password_hash = EXCLUDED.password_hash,
			role = EXCLUDED.role,
			disabled = EXCLUDED.disabled,
			last_login_at = EXCLUDED.last_login_at,
			totp_secret = EXCLUDED.totp_secret,
			totp_enabled = EXCLUDED.totp_enabled,
			totp_enrolled_at = EXCLUDED.totp_enrolled_at,
			backup_codes = EXCLUDED.backup_codes`,
		u.ID, strings.ToLower(u.Username), u.PasswordHash, string(u.Role), u.Disabled,
		u.CreatedAt.UTC(), u.LastLoginAt,
		nullIfEmpty(u.TOTPSecret), u.TOTPEnabled, u.TOTPEnrolledAt, backupJSON,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: username %q already exists", storage.ErrConflict, u.Username)
		}
		return fmt.Errorf("postgres: save user: %w", err)
	}
	return nil
}

func (s *Store) ConsumeBackupCode(ctx context.Context, userID, hash string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE users
		SET backup_codes = COALESCE((
			SELECT jsonb_agg(code)
			FROM jsonb_array_elements(backup_codes) AS code
			WHERE code <> to_jsonb($2::text)
		), '[]'::jsonb)
		WHERE id = $1 AND backup_codes @> to_jsonb($2::text)`,
		userID, hash)
	if err != nil {
		return false, fmt.Errorf("postgres: consume backup code: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*auth.User, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, disabled, created_at, last_login_at,
		       coalesce(totp_secret,''), coalesce(totp_enabled,false), totp_enrolled_at, coalesce(backup_codes,'[]'::jsonb)
		FROM users WHERE lower(username) = lower($1)`, username)
	u, err := scanUser(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

func (s *Store) GetUser(ctx context.Context, id string) (*auth.User, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, disabled, created_at, last_login_at,
		       coalesce(totp_secret,''), coalesce(totp_enabled,false), totp_enrolled_at, coalesce(backup_codes,'[]'::jsonb)
		FROM users WHERE id = $1`, id)
	u, err := scanUser(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("postgres: count users: %w", err)
	}
	return n, nil
}

// ListUsers returns every operator account ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]*auth.User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, username, password_hash, role, disabled, created_at, last_login_at,
		       coalesce(totp_secret,''), coalesce(totp_enabled,false), totp_enrolled_at, coalesce(backup_codes,'[]'::jsonb)
		FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list users: %w", err)
	}
	defer rows.Close()
	var out []*auth.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) RecordLogin(ctx context.Context, userID string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = $1 WHERE id = $2`, at.UTC(), userID)
	if err != nil {
		return fmt.Errorf("postgres: record login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// --- Sessions -------------------------------------------------------------

func (s *Store) SaveSession(ctx context.Context, sess *auth.Session) error {
	if sess == nil {
		return fmt.Errorf("postgres: nil session")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, csrf_token, created_at, expires_at, last_seen_at, revoked_at, source_ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		sess.ID, sess.UserID, sess.TokenHash, sess.CSRFToken,
		sess.CreatedAt.UTC(), sess.ExpiresAt.UTC(), sess.LastSeenAt.UTC(),
		sess.RevokedAt, nullIfEmpty(sess.SourceIP), nullIfEmpty(sess.UserAgent),
	)
	if err != nil {
		return fmt.Errorf("postgres: save session: %w", err)
	}
	return nil
}

func (s *Store) GetSession(ctx context.Context, id string) (*auth.Session, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, csrf_token, created_at, expires_at, last_seen_at, revoked_at,
		       coalesce(source_ip,''), coalesce(user_agent,'')
		FROM sessions WHERE id = $1`, id)
	sess, err := scanSession(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return sess, nil
}

func (s *Store) TouchSession(ctx context.Context, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = $1 WHERE id = $2 AND revoked_at IS NULL`, at.UTC(), id)
	if err != nil {
		return fmt.Errorf("postgres: touch session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RevokeSession(ctx context.Context, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL`, at.UTC(), id)
	if err != nil {
		return fmt.Errorf("postgres: revoke session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`, at.UTC(), userID)
	if err != nil {
		return fmt.Errorf("postgres: revoke user sessions: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM sessions WHERE expires_at < $1 OR revoked_at IS NOT NULL`, now.UTC())
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired sessions: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// --- Incidents ------------------------------------------------------------

func (s *Store) SaveIncident(ctx context.Context, inc *incidents.Incident) error {
	if inc == nil {
		return fmt.Errorf("postgres: nil incident")
	}
	hosts, err := json.Marshal(inc.Hosts)
	if err != nil {
		return fmt.Errorf("postgres: marshal hosts: %w", err)
	}
	actors, err := json.Marshal(inc.Actors)
	if err != nil {
		return fmt.Errorf("postgres: marshal actors: %w", err)
	}
	sourceIPs, err := json.Marshal(nonNilStrings(inc.SourceIPs))
	if err != nil {
		return fmt.Errorf("postgres: marshal source ips: %w", err)
	}
	alertIDs, err := json.Marshal(inc.AlertIDs)
	if err != nil {
		return fmt.Errorf("postgres: marshal alert ids: %w", err)
	}
	eventIDs, err := json.Marshal(inc.EventIDs)
	if err != nil {
		return fmt.Errorf("postgres: marshal event ids: %w", err)
	}
	stages, err := json.Marshal(inc.Stages)
	if err != nil {
		return fmt.Errorf("postgres: marshal stages: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO incidents (
			id, title, summary, severity, status, hosts, actors, source_ips, alert_ids, event_ids, stages,
			first_seen, last_seen, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (id) DO UPDATE SET
			title = EXCLUDED.title,
			summary = EXCLUDED.summary,
			severity = EXCLUDED.severity,
			status = EXCLUDED.status,
			hosts = EXCLUDED.hosts,
			actors = EXCLUDED.actors,
			source_ips = EXCLUDED.source_ips,
			alert_ids = EXCLUDED.alert_ids,
			event_ids = EXCLUDED.event_ids,
			stages = EXCLUDED.stages,
			first_seen = EXCLUDED.first_seen,
			last_seen = EXCLUDED.last_seen,
			updated_at = EXCLUDED.updated_at`,
		inc.ID, inc.Title, inc.Summary, string(inc.Severity), string(inc.Status),
		hosts, actors, sourceIPs, alertIDs, eventIDs, stages,
		inc.FirstSeen.UTC(), inc.LastSeen.UTC(), inc.CreatedAt.UTC(), inc.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: save incident: %w", err)
	}
	return nil
}

func (s *Store) GetIncident(ctx context.Context, id string) (*incidents.Incident, error) {
	row := s.pool.QueryRow(ctx, incidentSelect+` WHERE id = $1`, id)
	inc, err := scanIncident(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return inc, nil
}

const incidentSelect = `
	SELECT id, title, summary, severity, status, hosts, actors, source_ips, alert_ids, event_ids, stages,
	       first_seen, last_seen, created_at, updated_at
	FROM incidents`

func (s *Store) ListIncidents(ctx context.Context, limit int, cursor string) (*incidents.IncidentList, error) {
	limit = clampLimit(limit, 50, 500)
	sql := incidentSelect
	args := []any{}
	if cursor != "" {
		args = append(args, cursor)
		sql += ` WHERE id < $1`
	}
	args = append(args, limit+1)
	sql += ` ORDER BY id DESC LIMIT $` + fmt.Sprint(len(args))

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list incidents: %w", err)
	}
	defer rows.Close()

	out := &incidents.IncidentList{}
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan incident: %w", err)
		}
		if len(out.Incidents) == limit {
			out.NextCursor = out.Incidents[len(out.Incidents)-1].ID
			break
		}
		out.Incidents = append(out.Incidents, inc)
	}
	return out, rows.Err()
}

func (s *Store) ListOpenIncidents(ctx context.Context) ([]*incidents.Incident, error) {
	// FALSE_POSITIVE is terminal too; merging into a rejected incident would make the rejection lie.
	rows, err := s.pool.Query(ctx, incidentSelect+`
		WHERE status NOT IN ('RESOLVED','CLOSED','FALSE_POSITIVE')
		ORDER BY id DESC
		LIMIT 1000`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list open incidents: %w", err)
	}
	defer rows.Close()

	var out []*incidents.Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan incident: %w", err)
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

// --- Audit ----------------------------------------------------------------

func (s *Store) AppendAudit(ctx context.Context, e *audit.Entry) error {
	if e == nil {
		return fmt.Errorf("postgres: nil audit entry")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs (id, actor, action, resource, resource_id, result, timestamp, source_ip, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		e.ID, e.Actor, string(e.Action), e.Resource, nullIfEmpty(e.ResourceID),
		string(e.Result), e.Timestamp.UTC(), nullIfEmpty(e.SourceIP), nullIfEmpty(e.Detail),
	)
	if err != nil {
		return fmt.Errorf("postgres: append audit: %w", err)
	}
	return nil
}

func (s *Store) ListAudit(ctx context.Context, limit int, cursor string) ([]*audit.Entry, string, error) {
	limit = clampLimit(limit, 50, 500)
	sql := `SELECT id, actor, action, resource, coalesce(resource_id,''), result, timestamp,
	               coalesce(source_ip,''), coalesce(detail,'') FROM audit_logs`
	args := []any{}
	if cursor != "" {
		args = append(args, cursor)
		sql += ` WHERE id < $1`
	}
	args = append(args, limit+1)
	sql += ` ORDER BY id DESC LIMIT $` + fmt.Sprint(len(args))

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, "", fmt.Errorf("postgres: list audit: %w", err)
	}
	defer rows.Close()

	var out []*audit.Entry
	next := ""
	for rows.Next() {
		var e audit.Entry
		var action, result string
		var ts time.Time
		if err := rows.Scan(&e.ID, &e.Actor, &action, &e.Resource, &e.ResourceID, &result, &ts, &e.SourceIP, &e.Detail); err != nil {
			return nil, "", fmt.Errorf("postgres: scan audit: %w", err)
		}
		e.Action = audit.Action(action)
		e.Result = audit.Result(result)
		e.Timestamp = ts.UTC()
		if len(out) == limit {
			next = out[len(out)-1].ID
			break
		}
		out = append(out, &e)
	}
	return out, next, rows.Err()
}

func (s *Store) PurgeAudit(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM audit_logs WHERE timestamp < $1`, olderThan.UTC())
	if err != nil {
		return 0, fmt.Errorf("postgres: purge audit: %w", err)
	}
	return tag.RowsAffected(), nil
}

// --- Passkeys -------------------------------------------------------------

func (s *Store) SavePasskey(ctx context.Context, p *webauthn.Passkey) error {
	if p == nil {
		return fmt.Errorf("postgres: nil passkey")
	}
	transports, err := json.Marshal(nonNilStrings(p.Transports))
	if err != nil {
		return fmt.Errorf("postgres: marshal transports: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO passkeys (id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
			sign_count = EXCLUDED.sign_count,
			transports = EXCLUDED.transports,
			name = EXCLUDED.name,
			last_used_at = EXCLUDED.last_used_at`,
		p.ID, p.UserID, p.CredentialID, p.PublicKey, int64(p.SignCount), transports,
		nullIfEmpty(p.Name), p.CreatedAt.UTC(), p.LastUsedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: passkey already registered", storage.ErrConflict)
		}
		return fmt.Errorf("postgres: save passkey: %w", err)
	}
	return nil
}

func (s *Store) ListPasskeysByUser(ctx context.Context, userID string) ([]*webauthn.Passkey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, credential_id, public_key, sign_count, transports, coalesce(name,''), created_at, last_used_at
		FROM passkeys WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list passkeys: %w", err)
	}
	defer rows.Close()
	var out []*webauthn.Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan passkey: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*webauthn.Passkey, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, user_id, credential_id, public_key, sign_count, transports, coalesce(name,''), created_at, last_used_at
		FROM passkeys WHERE credential_id = $1`, credentialID)
	p, err := scanPasskey(row)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return p, nil
}

func (s *Store) UpdatePasskeyCounter(ctx context.Context, id string, signCount uint32, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE passkeys SET sign_count = $1, last_used_at = $2 WHERE id = $3`,
		int64(signCount), at.UTC(), id)
	if err != nil {
		return fmt.Errorf("postgres: update passkey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeletePasskey(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM passkeys WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete passkey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanPasskey(sc scanner) (*webauthn.Passkey, error) {
	var (
		p          webauthn.Passkey
		signCount  int64
		transports []byte
		lastUsed   *time.Time
	)
	err := sc.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.PublicKey, &signCount, &transports, &p.Name, &p.CreatedAt, &lastUsed)
	if err != nil {
		return nil, err
	}
	p.SignCount = uint32(signCount)
	p.CreatedAt = p.CreatedAt.UTC()
	if lastUsed != nil {
		t := lastUsed.UTC()
		p.LastUsedAt = &t
	}
	if len(transports) > 0 {
		var t []string
		if err := json.Unmarshal(transports, &t); err == nil {
			p.Transports = t
		}
	}
	return &p, nil
}

// --- Scanners -------------------------------------------------------------

// scanner is satisfied by both pgx.Row and pgx.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanEvent(sc scanner) (*model.Event, error) {
	var (
		e          model.Event
		typ, src   string
		outcome    string
		severity   string
		attrs      []byte
		srcPort    int
		dstPort    int
		eventTime  time.Time
		receivedAt time.Time
		observedAt time.Time
	)
	err := sc.Scan(
		&e.ID, &e.SchemaVersion, &typ, &eventTime, &receivedAt, &observedAt,
		&e.Host, &e.AgentID, &src, &e.SourcePath, &e.Actor, &e.Target,
		&e.Network.SourceIP, &srcPort, &e.Network.DestIP, &dstPort, &e.Network.Protocol, &outcome,
		&severity, &attrs, &e.Message, &e.Raw,
	)
	if err != nil {
		return nil, err
	}
	e.Type = model.EventType(typ)
	e.Source = model.Source(src)
	e.Outcome = model.Outcome(outcome)
	e.Severity = model.Severity(severity)
	e.Time = eventTime.UTC()
	e.ReceivedAt = receivedAt.UTC()
	e.ObservedAt = observedAt.UTC()
	e.Network.SourcePort = srcPort
	e.Network.DestPort = dstPort
	e.Attributes = unmarshalMap(attrs)
	return &e, nil
}

func scanAlert(sc scanner) (*alerts.Alert, error) {
	var (
		a                      alerts.Alert
		severity, status       string
		eventIDs               []byte
		windowStart, windowEnd time.Time
		createdAt, updatedAt   time.Time
	)
	err := sc.Scan(
		&a.ID, &a.RuleID, &a.RuleVersion, &a.RuleName, &severity, &status, &a.Title, &a.Reason,
		&a.Host, &a.Actor, &a.SourceIP, &a.Entity,
		&eventIDs, &a.Count, &windowStart, &windowEnd, &a.DedupeKey, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.Severity = model.Severity(severity)
	a.Status = alerts.Status(status)
	if err := json.Unmarshal(eventIDs, &a.EventIDs); err != nil {
		return nil, fmt.Errorf("decode alert evidence: %w", err)
	}
	a.WindowStart = windowStart.UTC()
	a.WindowEnd = windowEnd.UTC()
	a.CreatedAt = createdAt.UTC()
	a.UpdatedAt = updatedAt.UTC()
	return &a, nil
}

func scanAgent(sc scanner) (*agents.Agent, error) {
	var (
		a             agents.Agent
		status        string
		lastHeartbeat *time.Time
		revokedAt     *time.Time
	)
	err := sc.Scan(&a.ID, &a.Host, &a.OS, &a.Version, &status, &a.EnrolledAt,
		&lastHeartbeat, &revokedAt, &a.QueueDepth, &a.SpoolBytes)
	if err != nil {
		return nil, err
	}
	a.Status = agents.Status(status)
	a.EnrolledAt = a.EnrolledAt.UTC()
	if lastHeartbeat != nil {
		a.LastHeartbeat = lastHeartbeat.UTC()
	}
	if revokedAt != nil {
		t := revokedAt.UTC()
		a.RevokedAt = &t
	}
	return &a, nil
}

func scanToken(sc scanner) (*agents.Token, error) {
	var t agents.Token
	err := sc.Scan(&t.ID, &t.AgentID, &t.TokenHash, &t.Prefix, &t.CreatedAt,
		&t.LastUsedAt, &t.RotatedAt, &t.RevokedAt, &t.ExpiresAt)
	if err != nil {
		return nil, err
	}
	t.CreatedAt = t.CreatedAt.UTC()
	return &t, nil
}

func scanUser(sc scanner) (*auth.User, error) {
	var (
		u         auth.User
		role      string
		lastLogin *time.Time
		enrolled  *time.Time
		backups   []byte
	)
	err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.Disabled, &u.CreatedAt, &lastLogin,
		&u.TOTPSecret, &u.TOTPEnabled, &enrolled, &backups)
	if err != nil {
		return nil, err
	}
	u.Role = authorizationRole(role)
	u.CreatedAt = u.CreatedAt.UTC()
	if lastLogin != nil {
		t := lastLogin.UTC()
		u.LastLoginAt = &t
	}
	if enrolled != nil {
		t := enrolled.UTC()
		u.TOTPEnrolledAt = &t
	}
	if len(backups) > 0 {
		var hashes []string
		if err := json.Unmarshal(backups, &hashes); err == nil {
			u.BackupHashes = hashes
		}
	}
	return &u, nil
}

func scanSession(sc scanner) (*auth.Session, error) {
	var (
		s          auth.Session
		createdAt  time.Time
		expiresAt  time.Time
		lastSeenAt time.Time
		revokedAt  *time.Time
	)
	err := sc.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CSRFToken, &createdAt, &expiresAt,
		&lastSeenAt, &revokedAt, &s.SourceIP, &s.UserAgent)
	if err != nil {
		return nil, err
	}
	s.CreatedAt = createdAt.UTC()
	s.ExpiresAt = expiresAt.UTC()
	s.LastSeenAt = lastSeenAt.UTC()
	if revokedAt != nil {
		t := revokedAt.UTC()
		s.RevokedAt = &t
	}
	return &s, nil
}

func scanIncident(sc scanner) (*incidents.Incident, error) {
	var (
		inc       incidents.Incident
		severity  string
		status    string
		hosts     []byte
		actors    []byte
		sourceIPs []byte
		alertIDs  []byte
		eventIDs  []byte
		stages    []byte
		firstSeen time.Time
		lastSeen  time.Time
		createdAt time.Time
		updatedAt time.Time
	)
	err := sc.Scan(&inc.ID, &inc.Title, &inc.Summary, &severity, &status,
		&hosts, &actors, &sourceIPs, &alertIDs, &eventIDs, &stages,
		&firstSeen, &lastSeen, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	inc.Severity = model.Severity(severity)
	inc.Status = incidents.Status(status)
	for _, target := range []struct {
		raw []byte
		dst *[]string
	}{
		{hosts, &inc.Hosts},
		{actors, &inc.Actors},
		{sourceIPs, &inc.SourceIPs},
		{alertIDs, &inc.AlertIDs},
		{eventIDs, &inc.EventIDs},
	} {
		if err := json.Unmarshal(target.raw, target.dst); err != nil {
			return nil, fmt.Errorf("decode incident list: %w", err)
		}
	}
	if err := json.Unmarshal(stages, &inc.Stages); err != nil {
		return nil, fmt.Errorf("decode incident stages: %w", err)
	}
	inc.FirstSeen = firstSeen.UTC()
	inc.LastSeen = lastSeen.UTC()
	inc.CreatedAt = createdAt.UTC()
	inc.UpdatedAt = updatedAt.UTC()
	return &inc, nil
}

// --- Small helpers --------------------------------------------------------

// nonNilStrings keeps a JSONB list column an array rather than null: a nil
// slice marshals to null, which would break clients that (correctly) expect [].
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func joinAnd(clauses []string) string {
	out := ""
	for i, c := range clauses {
		if i > 0 {
			out += " AND "
		}
		out += c
	}
	return out
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullIfZeroTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func marshalMap(m map[string]string) ([]byte, error) {
	if m == nil {
		m = map[string]string{}
	}
	return json.Marshal(m)
}

func unmarshalMap(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := map[string]string{}
	if err := json.Unmarshal(raw, &out); err != nil {
		// A corrupt attributes blob must not fail an event read: the structured
		// columns are the security-relevant data, and attributes are contextual.
		return nil
	}
	return out
}

func authorizationRole(s string) authorization.Role {
	r := authorization.Role(s)
	if !r.Valid() {
		// Fail closed: an unrecognised role has no permissions.
		return authorization.Role("INVALID")
	}
	return r
}

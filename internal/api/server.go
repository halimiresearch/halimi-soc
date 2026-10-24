// Package api exposes the authenticated HTTP surface.
//
// Every handler follows the same rules from DESIGN.md §15:
//
//   - authenticate before doing any work;
//   - authorize server-side, never by hiding UI;
//   - bound request bodies before decoding;
//   - return a single error envelope;
//   - never echo untrusted input into a response or a log.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/ai"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/config"
	"github.com/halimi/halimisoc/internal/detection/engine"
	"github.com/halimi/halimisoc/internal/events/ingest"
	"github.com/halimi/halimisoc/internal/events/stream"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/notify"
	"github.com/halimi/halimisoc/internal/secret"
	"github.com/halimi/halimisoc/internal/storage"
	"github.com/halimi/halimisoc/internal/webauthn"
)

// Server wires the HTTP surface.
type Server struct {
	store          storage.Store
	ingester       *ingest.Ingester
	detector       *engine.Engine
	limits         config.Limits
	sessionTTL     time.Duration
	sessionIdle    time.Duration
	clockSkew      time.Duration
	log            *slog.Logger
	reg            *metrics.Registry
	limiter        *auth.Limiter
	analyzeLimiter *auth.Limiter
	now            func() time.Time
	analyst        *ai.Analyst
	hub            *stream.Hub
	enrollSecret   string
	appVersion     string
	startedAt      time.Time
	cookieName     string
	secureCookies  bool
	rulesPath      string
	notifier       *notify.Notifier
	metricsToken   string
	mfaKey         []byte
	webauthn       webauthn.Config
	challenges     *webauthn.Challenges

	mux *http.ServeMux
}

// Options configures the server.
type Options struct {
	Store         storage.Store
	Ingester      *ingest.Ingester
	Detector      *engine.Engine
	Limits        config.Limits
	SessionTTL    time.Duration
	SessionIdle   time.Duration
	ClockSkew     time.Duration
	Logger        *slog.Logger
	Metrics       *metrics.Registry
	Analyst       *ai.Analyst
	Hub           *stream.Hub
	EnrollSecret  string
	Version       string
	SecureCookies bool
	// MetricsToken guards /metrics when set. Empty leaves it unauthenticated.
	MetricsToken string
	// MFAKey encrypts TOTP secrets at rest (32 bytes, AES-256-GCM). Empty
	// stores secrets with a "plain:" prefix (dev only); production with MFA
	// should set HALIMISOC_MFA_KEY.
	MFAKey []byte
	// WebAuthn is the passkey RP config. Zero value disables? No: New defaults
	// it to loopback dev values so tests and dev work without env.
	WebAuthn webauthn.Config
	// Challenges overrides the default in-memory challenge store (tests).
	Challenges *webauthn.Challenges
	// RulesPath is the directory rule reloads are read from. Empty disables
	// the reload endpoint rather than reloading from a guess.
	RulesPath string
	// Notifier receives incident-created webhooks. Nil disables delivery.
	Notifier *notify.Notifier
}

// New builds a server and registers its routes.
func New(opts Options) *Server {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	reg := opts.Metrics
	if reg == nil {
		reg = metrics.New()
	}
	ttl := opts.SessionTTL
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	idle := opts.SessionIdle
	if idle <= 0 {
		idle = 2 * time.Hour
	}
	// Idle must never exceed the absolute TTL: an idle window longer than the
	// session lifetime is dead configuration that suggests a misunderstanding.
	if idle > ttl {
		idle = ttl
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = 5 * time.Minute
	}

	// A nil analyst would panic on the first analyze request. Defaulting to a
	// disabled analyst keeps the endpoint working and honest rather than
	// crashing the request.
	analyst := opts.Analyst
	if analyst == nil {
		analyst = ai.New(ai.Options{})
	}

	// A nil hub would panic on the first stream connection and would silently
	// drop every realtime event. Defaulting to a working hub means a caller that
	// forgets to pass one still gets a functioning feed.
	hub := opts.Hub
	if hub == nil {
		hub = stream.NewHub(stream.DefaultOptions())
	}

	s := &Server{
		store:       opts.Store,
		analyst:     analyst,
		hub:         hub,
		ingester:    opts.Ingester,
		detector:    opts.Detector,
		limits:      opts.Limits,
		sessionTTL:  ttl,
		sessionIdle: idle,
		clockSkew:   skew,
		log:         log,
		reg:         reg,
		limiter:     auth.NewLimiter(auth.DefaultLimiterOptions()),
		analyzeLimiter: auth.NewLimiter(auth.LimiterOptions{
			MaxAttempts: 10,
			BaseDelay:   30 * time.Second,
			MaxDelay:    5 * time.Minute,
			ResetAfter:  10 * time.Minute,
			MaxEntries:  10_000,
		}),
		now:           func() time.Time { return time.Now().UTC() },
		enrollSecret:  opts.EnrollSecret,
		appVersion:    opts.Version,
		startedAt:     time.Now().UTC(),
		cookieName:    cookieNameFor(opts.SecureCookies),
		secureCookies: opts.SecureCookies,
		rulesPath:     opts.RulesPath,
		notifier:      opts.Notifier,
		metricsToken:  opts.MetricsToken,
		mfaKey:        opts.MFAKey,
		webauthn:      opts.WebAuthn,
		challenges:    opts.Challenges,
		mux:           http.NewServeMux(),
	}
	if s.webauthn.RPID == "" {
		s.webauthn.RPID = "127.0.0.1"
	}
	if s.webauthn.RPName == "" {
		s.webauthn.RPName = "HalimiSOC"
	}
	if len(s.webauthn.Origins) == 0 {
		s.webauthn.Origins = []string{"http://127.0.0.1:3000", "http://localhost:3000"}
	}
	if s.challenges == nil {
		s.challenges = webauthn.NewChallenges(10000, 5*time.Minute)
	}
	s.routes()
	return s
}

// SetClock overrides the clock. Test-only.
func (s *Server) SetClock(f func() time.Time) { s.now = f }

// SetMetricsTokenForTest overrides the /metrics bearer token. Test-only.
func (s *Server) SetMetricsTokenForTest(token string) { s.metricsToken = token }

// SetNotifier swaps the webhook notifier. Test-only.
func (s *Server) SetNotifier(n *notify.Notifier) { s.notifier = n }

// Handler returns the root handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.requestLog(s.mux))
}

func (s *Server) routes() {
	// Operational endpoints live under the versioned prefix, as the PRD
	// specifies. The bare /healthz and /readyz paths are kept as aliases because
	// container orchestrators and load balancers are conventionally configured
	// with those names and a probe should not need to know the API version.
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/readiness", s.handleReady)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReady)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)

	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/v1/auth/session", s.handleSession)

	s.mux.HandleFunc("POST /api/v1/agents/register", s.handleRegisterAgent)
	s.mux.HandleFunc("GET /api/v1/agents/me", s.handleAgentSelf)
	s.mux.HandleFunc("POST /api/v1/agents/{id}/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("GET /api/v1/agents", s.handleListAgents)
	s.mux.HandleFunc("GET /api/v1/agents/{id}", s.handleGetAgent)
	s.mux.HandleFunc("POST /api/v1/agents/{id}/rotate", s.handleRotateAgentToken)
	s.mux.HandleFunc("POST /api/v1/agents/{id}/revoke", s.handleRevokeAgent)

	s.mux.HandleFunc("POST /api/v1/events", s.handleIngestEvents)
	s.mux.HandleFunc("GET /api/v1/events", s.handleListEvents)
	s.mux.HandleFunc("GET /api/v1/events/{id}", s.handleGetEvent)

	s.mux.HandleFunc("GET /api/v1/alerts", s.handleListAlerts)
	s.mux.HandleFunc("GET /api/v1/alerts/{id}", s.handleGetAlert)
	s.mux.HandleFunc("PATCH /api/v1/alerts/{id}/status", s.handleUpdateAlertStatus)

	s.mux.HandleFunc("GET /api/v1/incidents", s.handleListIncidents)
	s.mux.HandleFunc("GET /api/v1/incidents/{id}", s.handleGetIncident)
	s.mux.HandleFunc("PATCH /api/v1/incidents/{id}/status", s.handleUpdateIncidentStatus)
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/analyze", s.handleAnalyzeIncident)

	s.mux.HandleFunc("GET /api/v1/assets", s.handleListAssets)
	s.mux.HandleFunc("GET /api/v1/summary", s.handleSummary)

	s.mux.HandleFunc("GET /api/v1/rules", s.handleListRules)
	s.mux.HandleFunc("POST /api/v1/rules/reload", s.handleReloadRules)
	s.mux.HandleFunc("POST /api/v1/rules/validate", s.handleValidateRule)
	s.mux.HandleFunc("PUT /api/v1/rules/{id}", s.handleSaveRule)
	s.mux.HandleFunc("DELETE /api/v1/rules/{id}", s.handleDeleteRule)
	s.mux.HandleFunc("GET /api/v1/rules/{id}", s.handleGetRule)
	s.mux.HandleFunc("GET /api/v1/audit", s.handleListAudit)

	s.mux.HandleFunc("GET /api/v1/users", s.handleListUsers)
	s.mux.HandleFunc("POST /api/v1/users", s.handleCreateUser)
	s.mux.HandleFunc("PATCH /api/v1/users/{id}/status", s.handleUpdateUserStatus)
	s.mux.HandleFunc("POST /api/v1/auth/password", s.handleChangeOwnPassword)
	s.mux.HandleFunc("PATCH /api/v1/users/{id}/password", s.handleResetUserPassword)
	s.mux.HandleFunc("GET /api/v1/auth/mfa/status", s.handleMFAStatus)
	s.mux.HandleFunc("POST /api/v1/auth/mfa/setup", s.handleMFASetup)
	s.mux.HandleFunc("POST /api/v1/auth/mfa/enable", s.handleMFAEnable)
	s.mux.HandleFunc("POST /api/v1/auth/mfa/disable", s.handleMFADisable)
	s.mux.HandleFunc("POST /api/v1/users/{id}/mfa/reset", s.handleMFAReset)
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/register/begin", s.handlePasskeyRegisterBegin)
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/register/complete", s.handlePasskeyRegisterComplete)
	s.mux.HandleFunc("GET /api/v1/auth/webauthn/credentials", s.handlePasskeyList)
	s.mux.HandleFunc("DELETE /api/v1/auth/webauthn/credentials/{id}", s.handlePasskeyDelete)
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/login/begin", s.handlePasskeyLoginBegin)
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/login/complete", s.handlePasskeyLoginComplete)

	s.mux.HandleFunc("GET /api/v1/stream", s.handleStream)
}

// --- Error envelope -------------------------------------------------------

// ErrorBody is the single error shape returned by the API.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail carries a stable machine code and a human message.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Stable error codes.
const (
	CodeBadRequest   = "BAD_REQUEST"
	CodeUnauthorized = "UNAUTHORIZED"
	CodeMFARequired  = "MFA_REQUIRED"
	CodeForbidden    = "FORBIDDEN"
	CodeNotFound     = "NOT_FOUND"
	CodeConflict     = "CONFLICT"
	CodeTooLarge     = "PAYLOAD_TOO_LARGE"
	CodeRateLimited  = "RATE_LIMITED"
	CodeInternal     = "INTERNAL_ERROR"
	CodeUnavailable  = "SERVICE_UNAVAILABLE"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, ErrorBody{Error: ErrorDetail{Code: code, Message: msg}})
}

func statusFor(err error) (int, string) {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return http.StatusNotFound, CodeNotFound
	case errors.Is(err, storage.ErrConflict):
		return http.StatusConflict, CodeConflict
	case errors.Is(err, storage.ErrInvalidTransition):
		return http.StatusConflict, CodeConflict
	case errors.Is(err, auth.ErrSessionNotFound),
		errors.Is(err, auth.ErrSessionExpired),
		errors.Is(err, auth.ErrSessionRevoked),
		errors.Is(err, auth.ErrCSRFMismatch):
		return http.StatusUnauthorized, CodeUnauthorized
	case errors.Is(err, ingest.ErrBatchTooLarge):
		return http.StatusRequestEntityTooLarge, CodeTooLarge
	default:
		return http.StatusInternalServerError, CodeInternal
	}
}

// --- Middleware -----------------------------------------------------------

// securityHeaders applies defensive response headers.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// The API serves JSON and metrics only; a restrictive CSP means a
		// mis-served response cannot become a script execution path.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the wrapped writer.
//
// Without this method the logging wrapper would hide http.Flusher from the
// handler, and the SSE endpoint would refuse to start because it could not detect
// that flushing is available. A middleware that wraps a ResponseWriter must
// forward every optional interface the handler may depend on, not only the ones it
// uses itself.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer for optional
// interface operations such as setting a write deadline.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// requestLog records method, path, status and duration.
//
// The query string and body are not logged: they can contain operator input,
// and the raw telemetry path would otherwise become a log-injection sink.
func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		started := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.reg.Observe(metrics.HTTPRequestDuration, time.Since(started).Seconds(), metrics.L("method", r.Method))
		s.log.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", s.now().Sub(start).Milliseconds(),
			"remote", clientIP(r),
		)
	})
}

// clientIP returns the peer address without trusting forwarding headers.
//
// X-Forwarded-For is attacker-controlled unless a trusted proxy is configured,
// and the MVP has no such configuration, so it is ignored for audit and
// rate-limiting purposes.
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// --- Body handling --------------------------------------------------------

// decodeJSON decodes a request body into v, enforcing the size bound.
//
// The body is read through MaxBytesReader so an oversized payload is rejected
// before it can be buffered in full. Unknown fields are rejected: a client that
// sends a field the server does not understand has a different contract in
// mind, and silently ignoring it would create two incompatible interpretations.
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		return err
	}
	// A second value in the body means the client sent something other than a
	// single object.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain a single JSON object")
	}
	return nil
}

// --- Auth helpers ---------------------------------------------------------

// principal is the authenticated caller.
type principal struct {
	Kind    audit.ActorKind
	User    *auth.User
	Agent   *agentPrincipal
	Session *auth.Session

	// Role is the effective role. An agent is never an operator.
	Role authorization.Role
}

type agentPrincipal struct {
	AgentID string
	Host    string
	TokenID string
}

// authenticate resolves the session cookie for operator routes.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) *principal {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
		return nil
	}

	id := auth.SessionIDFromToken(cookie.Value)
	sess, err := s.store.GetSession(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
		return nil
	}
	now := s.now()
	if err := auth.AuthenticateSession(sess, cookie.Value, now); err != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "session is no longer valid")
		return nil
	}
	// Idle timeout bounds a stolen cookie even when the absolute TTL is long.
	// A session unused for longer than sessionIdle is treated as expired.
	if sess.IdleExpired(now, s.sessionIdle) {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "session is no longer valid")
		return nil
	}

	user, err := s.store.GetUser(r.Context(), sess.UserID)
	if err != nil || !user.Active() {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "account is not active")
		return nil
	}

	// Refresh LastSeenAt best-effort so idle is measured from real activity.
	// A store failure here must not fail the request: the session already
	// authenticated, and failing open on activity tracking is safe.
	if err := s.store.TouchSession(r.Context(), sess.ID, now); err != nil {
		s.log.Warn("touch session failed", "session", sess.ID, "error", err)
	} else {
		sess.LastSeenAt = now
	}

	return &principal{
		Kind:    audit.ActorUser,
		User:    user,
		Session: sess,
		Role:    user.Role,
	}
}

// authenticateAgent resolves the agent bearer token.
func (s *Server) authenticateAgent(w http.ResponseWriter, r *http.Request) *principal {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "agent authentication required")
		return nil
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "agent authentication required")
		return nil
	}

	hash := secret.HashToken(token)
	tok, err := s.store.GetTokenByHash(r.Context(), hash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "agent authentication required")
		return nil
	}
	now := s.now()
	if !tok.Active(now) {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "agent credential is no longer valid")
		return nil
	}

	agent, err := s.store.GetAgent(r.Context(), tok.AgentID)
	if err != nil || agent.Revoked() {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "agent is not active")
		return nil
	}
	if err := s.store.TouchToken(r.Context(), tok.ID, now); err != nil {
		s.log.Warn("touch agent token failed", "error", err)
	}

	return &principal{
		Kind: audit.ActorAgent,
		Agent: &agentPrincipal{
			AgentID: agent.ID,
			Host:    agent.Host,
			TokenID: tok.ID,
		},
	}
}

// requirePermission enforces a permission and logs denials.
func (s *Server) requirePermission(w http.ResponseWriter, r *http.Request, p *principal, perm authorization.Permission) bool {
	if p == nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
		return false
	}
	if p.Kind != audit.ActorUser {
		writeError(w, http.StatusForbidden, CodeForbidden, "operator permission required")
		return false
	}
	if err := authorization.Require(p.Role, perm); err != nil {
		s.writeAudit(r, audit.Entry{
			Actor:    audit.ActorRef(audit.ActorUser, p.User.Username),
			Action:   audit.Action(p.User.Role),
			Resource: string(perm),
			Result:   audit.ResultDenied,
			Detail:   "permission denied",
		})
		writeError(w, http.StatusForbidden, CodeForbidden, "not permitted")
		return false
	}
	return true
}

// requireCSRF enforces the CSRF token on state-changing requests.
func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request, p *principal) bool {
	if p.Kind == audit.ActorAgent {
		// Agents authenticate with a bearer token in a header, which a browser
		// cannot set cross-origin, so CSRF does not apply.
		return true
	}
	if err := auth.VerifyCSRF(p.Session, r.Header.Get(auth.CSRFHeaderName)); err != nil {
		writeError(w, http.StatusForbidden, CodeForbidden, "invalid or missing CSRF token")
		return false
	}
	return true
}

// Prune drops expired rate-limit buckets so the entry bound is enforced by
// time, not only by eviction under pressure.
func (s *Server) Prune(now time.Time) {
	s.limiter.Prune(now)
	s.analyzeLimiter.Prune(now)
}

// writeAudit appends an audit entry, logging rather than failing if the write
// fails: an audit outage must not turn into an availability outage.
func (s *Server) writeAudit(r *http.Request, e audit.Entry) {
	if e.Timestamp.IsZero() {
		e.Timestamp = s.now()
	}
	if e.SourceIP == "" {
		e.SourceIP = clientIP(r)
	}
	if err := e.Validate(); err != nil {
		s.log.Error("invalid audit entry dropped", "action", e.Action, "error", err)
		return
	}
	e.ID = id.New(id.KindAudit)
	// The request context is cancelled when the client disconnects; the
	// security record must still be written after that point.
	ctx := context.WithoutCancel(r.Context())
	if err := s.store.AppendAudit(ctx, &e); err != nil {
		s.log.Error("audit append failed", "action", e.Action, "error", err)
	}
}

// cookieNameFor selects the session cookie name for the deployment.
//
// The __Host- prefix is a browser-enforced constraint: such a cookie must be
// Secure, have Path=/ and carry no Domain, which prevents a sibling subdomain
// from setting or overwriting the session. Over plain HTTP the browser rejects
// it, so development uses an unprefixed name.
func cookieNameFor(secure bool) string {
	if secure {
		return auth.SessionCookieName
	}
	return auth.DevSessionCookieName
}

// decodeOptionalJSON decodes a request body when one is present and leaves v
// untouched when it is empty. It exists for endpoints such as agent heartbeat
// where "no body" is a valid request, without weakening the unknown-field rule
// for a body that is present.
func (s *Server) decodeOptionalJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	if r.ContentLength == 0 {
		return nil
	}
	return s.decodeJSON(w, r, v, maxBytes)
}

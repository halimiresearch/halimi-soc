package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/secret"
	"github.com/halimi/halimisoc/internal/storage"
)

type loginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	TOTPCode   string `json:"totp_code"`
	BackupCode string `json:"backup_code"`
}

type loginResponse struct {
	User      userView  `json:"user"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type userView struct {
	ID         string             `json:"id"`
	Username   string             `json:"username"`
	Role       authorization.Role `json:"role"`
	MFAEnabled bool               `json:"mfa_enabled"`
}

// handleLogin authenticates an operator and starts a session.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := s.decodeJSON(w, r, &req, 8<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	username := strings.ToLower(strings.TrimSpace(req.Username))
	if !validUsername(username) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid username")
		return
	}
	ip := clientIP(r)
	now := s.now()

	// Two independent keys: one per account and one per source address. The
	// per-account key stops distributed guessing against a single account, and
	// the per-address key stops one host spraying many accounts.
	accountKey := "acct:" + username
	ipKey := "ip:" + ip

	// Bound the password before any Argon2id work: VerifyPassword fast-rejects
	// overlong values, but rejecting here keeps the failure path explicit and
	// avoids even the dummy-hash timing branch for absurd inputs.
	if len(req.Password) > auth.MaxPasswordLength {
		s.limiter.Fail(accountKey, now)
		s.limiter.Fail(ipKey, now)
		s.recordLoginFailure(r, username, "password exceeds maximum length")
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials")
		return
	}

	if wait := s.limiter.RetryAfter(accountKey, now); wait > 0 {
		s.recordLoginFailure(r, username, "account throttled")
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}
	if wait := s.limiter.RetryAfter(ipKey, now); wait > 0 {
		s.recordLoginFailure(r, username, "source throttled")
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}

	// Credential failures return one indistinguishable response. Revealing
	// whether the account exists would turn the login form into an account
	// enumeration oracle.
	user, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil || user == nil || !user.Active() {
		s.limiter.Fail(accountKey, now)
		s.limiter.Fail(ipKey, now)
		s.recordLoginFailure(r, username, "unknown or inactive account")
		// Spend roughly the same time as a real verification so the response
		// time does not leak whether the account exists.
		_, _ = auth.VerifyPassword(req.Password, dummyHash)
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials")
		return
	}

	ok, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		s.log.Error("password verification failed", "user", user.ID, "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "authentication is unavailable")
		return
	}
	if !ok {
		s.limiter.Fail(accountKey, now)
		s.limiter.Fail(ipKey, now)
		s.recordLoginFailure(r, username, "invalid password")
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials")
		return
	}

	// Second factor after a correct password. Wrong/missing codes fail with the
	// same 401 shape; missing codes use MFA_REQUIRED so the UI can prompt.
	if !s.verifyLoginMFA(w, r, user, req.TOTPCode, req.BackupCode, accountKey, ipKey, now) {
		return
	}

	s.limiter.Succeed(accountKey)
	s.limiter.Succeed(ipKey)

	// Opportunistically upgrade a hash created with weaker parameters.
	if auth.NeedsRehash(user.PasswordHash) {
		if next, err := auth.HashPassword(req.Password); err == nil {
			user.PasswordHash = next
			if err := s.store.SaveUser(r.Context(), user); err != nil {
				s.log.Warn("password rehash failed", "user", user.ID, "error", err)
			}
		}
	}

	sess, token, err := auth.NewSession(user.ID, ip, r.UserAgent(), s.sessionTTL, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not start a session")
		return
	}
	if err := s.store.SaveSession(r.Context(), sess); err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not start a session")
		return
	}
	if err := s.store.RecordLogin(r.Context(), user.ID, now); err != nil {
		s.log.Warn("record login failed", "user", user.ID, "error", err)
	}

	http.SetCookie(w, s.sessionCookie(token, sess.ExpiresAt))

	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, user.Username),
		Action:     audit.ActionLoginSuccess,
		Resource:   "session",
		ResourceID: sess.ID,
		Result:     audit.ResultSuccess,
	})

	writeJSON(w, http.StatusOK, loginResponse{
		User:      userView{ID: user.ID, Username: user.Username, Role: user.Role, MFAEnabled: user.TOTPEnabled},
		CSRFToken: sess.CSRFToken,
		ExpiresAt: sess.ExpiresAt,
	})
}

// handleLogout revokes the current session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}

	if err := s.store.RevokeSession(r.Context(), p.Session.ID, s.now()); err != nil && !errors.Is(err, storage.ErrNotFound) {
		s.log.Warn("revoke session failed", "session", p.Session.ID, "error", err)
	}
	// Tell any open stream for this session to close, so logout is immediate
	// rather than waiting for the next revalidation.
	s.PublishSessionRevoked(p.Session.ID)

	s.clearCookie(w)
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionLogout,
		Resource:   "session",
		ResourceID: p.Session.ID,
		Result:     audit.ResultSuccess,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// handleSession returns the authenticated operator and the session's CSRF token.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       userView{ID: p.User.ID, Username: p.User.Username, Role: p.User.Role, MFAEnabled: p.User.TOTPEnabled},
		"csrf_token": p.Session.CSRFToken,
		"expires_at": p.Session.ExpiresAt,
	})
}

func (s *Server) recordLoginFailure(r *http.Request, username, reason string) {
	s.writeAudit(r, audit.Entry{
		Actor:    audit.ActorRef(audit.ActorUser, username),
		Action:   audit.ActionLoginFailure,
		Resource: "session",
		Result:   audit.ResultFailure,
		Detail:   reason,
	})
}

func (s *Server) sessionCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
	}
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func formatSeconds(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

// dummyHash is a real Argon2id hash of a value no operator can supply. It is
// used to equalise the timing of a failed login for an unknown account with a
// failed login for a known one.
var dummyHash = mustDummyHash()

func mustDummyHash() string {
	h, err := auth.HashPassword(secret.RandomString(32))
	if err != nil {
		// A failure here would mean the platform RNG is broken, in which case
		// the process cannot safely authenticate anyone.
		panic("api: cannot initialise password timing equaliser: " + err.Error())
	}
	return h
}

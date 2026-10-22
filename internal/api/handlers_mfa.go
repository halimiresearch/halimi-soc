package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/mfa"
)

// MFA enrollment and verification.
//
// Flow:
//   1. POST /auth/mfa/setup (auth+CSRF) generates a secret, seals it with the
//      server MFA key, stores it with enabled=false, returns secret+otpauth_url.
//      Re-setup rotates the pending secret and disables an existing one until
//      re-verified: a stolen session alone cannot silently re-key MFA without
//      the operator noticing the authenticator stops working.
//   2. POST /auth/mfa/enable {code} verifies against the stored secret, flips
//      enabled=true, issues 10 single-use backup codes (returned once, only
//      hashes stored).
//   3. Login with {username,password,totp_code|backup_code} when enabled.
//   4. POST /auth/mfa/disable {password,code} clears secret+backups.
//   5. Admin POST /users/{id}/mfa/reset clears a lost authenticator.
//
// Rate limiting reuses the login limiter with mfa: keys so TOTP guessing
// (1M space) backs off fast. Every failure is audited without echoing the code.

type mfaEnableRequest struct {
	Code string `json:"code"`
}

type mfaSetupRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

type mfaDisableRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (s *Server) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     p.User.TOTPEnabled,
		"enrolled_at": p.User.TOTPEnrolledAt,
	})
}

func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	var req mfaSetupRequest
	if err := s.decodeJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	if !s.requireStepUp(w, r, p, req.Password, req.Code) {
		return
	}

	secret, err := mfa.GenerateSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not start MFA setup")
		return
	}
	sealed, err := mfa.Seal(secret, s.mfaKey)
	if err != nil {
		s.log.Error("seal mfa secret failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not start MFA setup")
		return
	}
	p.User.TOTPSecret = sealed
	p.User.TOTPEnabled = false
	p.User.TOTPEnrolledAt = nil
	p.User.BackupHashes = nil
	if err := s.store.SaveUser(r.Context(), p.User); err != nil {
		s.fail(w, err, "save mfa secret")
		return
	}
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionMFARequested,
		Resource:   "user",
		ResourceID: p.User.ID,
		Result:     audit.ResultSuccess,
		Detail:     "mfa setup started",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"otpauth_url": mfa.OTPAUTHURL("HalimiSOC", p.User.Username, secret),
	})
}

func (s *Server) handleMFAEnable(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	var req mfaEnableRequest
	if err := s.decodeJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	now := s.now()
	userKey := "mfa:user:" + p.User.ID
	ipKey := "mfa:ip:" + clientIP(r)
	if wait := s.limiter.RetryAfter(userKey, now); wait > 0 {
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}
	if wait := s.limiter.RetryAfter(ipKey, now); wait > 0 {
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}
	if p.User.TOTPSecret == "" {
		writeError(w, http.StatusConflict, CodeConflict, "run MFA setup first")
		return
	}
	secret, err := mfa.Open(p.User.TOTPSecret, s.mfaKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "MFA setup is unusable; run setup again")
		return
	}
	if err := mfa.Verify(secret, req.Code, now); err != nil {
		s.limiter.Fail(userKey, now)
		s.limiter.Fail(ipKey, now)
		s.writeAudit(r, audit.Entry{
			Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
			Action:     audit.ActionMFAEnabled,
			Resource:   "user",
			ResourceID: p.User.ID,
			Result:     audit.ResultDenied,
			Detail:     "mfa enable code mismatch",
		})
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid authenticator code")
		return
	}
	codes, err := mfa.GenerateBackupCodes(mfa.BackupCodeCount)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not issue backup codes")
		return
	}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		hashes = append(hashes, mfa.HashBackupCode(c))
	}
	p.User.TOTPEnabled = true
	p.User.TOTPEnrolledAt = &now
	p.User.BackupHashes = hashes
	if err := s.store.SaveUser(r.Context(), p.User); err != nil {
		s.fail(w, err, "enable mfa")
		return
	}
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionMFAEnabled,
		Resource:   "user",
		ResourceID: p.User.ID,
		Result:     audit.ResultSuccess,
		Detail:     "mfa enabled; backup codes issued",
	})
	s.limiter.Succeed(userKey)
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": codes})
}

func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	var req mfaDisableRequest
	if err := s.decodeJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	if !p.User.TOTPEnabled {
		writeError(w, http.StatusConflict, CodeConflict, "MFA is not enabled")
		return
	}
	now := s.now()
	userKey := "mfa:user:" + p.User.ID
	ipKey := "mfa:ip:" + clientIP(r)
	if wait := s.limiter.RetryAfter(userKey, now); wait > 0 {
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}
	if wait := s.limiter.RetryAfter(ipKey, now); wait > 0 {
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}
	// Prove both factors before removing the second: password + current code.
	ok, err := auth.VerifyPassword(req.Password, p.User.PasswordHash)
	if err != nil || !ok {
		s.limiter.Fail(userKey, now)
		s.limiter.Fail(ipKey, now)
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials")
		return
	}
	if _, ok := s.verifyUserCode(p.User, req.Code); !ok {
		s.limiter.Fail(userKey, now)
		s.limiter.Fail(ipKey, now)
		s.writeAudit(r, audit.Entry{
			Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
			Action:     audit.ActionMFADisabled,
			Resource:   "user",
			ResourceID: p.User.ID,
			Result:     audit.ResultDenied,
			Detail:     "mfa disable code mismatch",
		})
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid authenticator code")
		return
	}
	p.User.TOTPSecret = ""
	p.User.TOTPEnabled = false
	p.User.TOTPEnrolledAt = nil
	p.User.BackupHashes = nil
	if err := s.store.SaveUser(r.Context(), p.User); err != nil {
		s.fail(w, err, "disable mfa")
		return
	}
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionMFADisabled,
		Resource:   "user",
		ResourceID: p.User.ID,
		Result:     audit.ResultSuccess,
		Detail:     "mfa disabled",
	})
	s.limiter.Succeed(userKey)
	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_disabled"})
}

// handleMFAReset is the lost-authenticator recovery: admin-only, CSRF, audited.
// It clears the target's secret and backup codes. The target re-enrolls.
func (s *Server) handleMFAReset(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermManageUsers) {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	target, err := s.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err, "get user")
		return
	}
	target.TOTPSecret = ""
	target.TOTPEnabled = false
	target.TOTPEnrolledAt = nil
	target.BackupHashes = nil
	if err := s.store.SaveUser(r.Context(), target); err != nil {
		s.fail(w, err, "reset mfa")
		return
	}
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionMFAReset,
		Resource:   "user",
		ResourceID: target.ID,
		Result:     audit.ResultSuccess,
		Detail:     "mfa reset by admin",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_reset"})
}

// requireStepUp re-proves the operator's current factors before a sensitive
// self-service change. A stolen session alone must not rotate MFA or add a
// passkey; the limiter keys are shared with login MFA so guessing is bounded.
func (s *Server) requireStepUp(w http.ResponseWriter, r *http.Request, p *principal, password, code string) bool {
	now := s.now()
	userKey := "mfa:user:" + p.User.ID
	ipKey := "mfa:ip:" + clientIP(r)
	if wait := s.limiter.RetryAfter(userKey, now); wait > 0 {
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return false
	}
	if wait := s.limiter.RetryAfter(ipKey, now); wait > 0 {
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return false
	}
	if strings.TrimSpace(password) == "" {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "current password is required")
		return false
	}
	deny := func(detail string) bool {
		s.limiter.Fail(userKey, now)
		s.limiter.Fail(ipKey, now)
		s.writeAudit(r, audit.Entry{
			Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
			Action:     audit.ActionStepUpFailure,
			Resource:   "user",
			ResourceID: p.User.ID,
			Result:     audit.ResultDenied,
			Detail:     detail,
		})
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials")
		return false
	}
	ok, err := auth.VerifyPassword(password, p.User.PasswordHash)
	if err != nil || !ok {
		return deny("current password mismatch")
	}
	if p.User.TOTPEnabled {
		backupHash, ok := s.verifyUserCode(p.User, code)
		if !ok {
			return deny("current code mismatch")
		}
		if backupHash != "" {
			consumed, err := s.store.ConsumeBackupCode(r.Context(), p.User.ID, backupHash)
			if err != nil {
				s.fail(w, err, "consume backup code")
				return false
			}
			if !consumed {
				return deny("backup code already used")
			}
			s.reg.Inc(metrics.MFABackupUsedTotal)
			s.writeAudit(r, audit.Entry{
				Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
				Action:     audit.ActionMFABackupUsed,
				Resource:   "user",
				ResourceID: p.User.ID,
				Result:     audit.ResultSuccess,
				Detail:     "backup code consumed",
			})
		}
	}
	s.limiter.Succeed(userKey)
	return true
}

// verifyUserCode checks a TOTP code or a single-use backup code.
// For a backup code it returns the matching stored hash so the caller can
// consume it atomically instead of rewriting the whole user record.
func (s *Server) verifyUserCode(u *auth.User, code string) (backupHash string, ok bool) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", false
	}
	if u.TOTPSecret != "" {
		if secret, err := mfa.Open(u.TOTPSecret, s.mfaKey); err == nil {
			if mfa.Verify(secret, code, s.now()) == nil {
				return "", true
			}
		}
	}
	for _, h := range u.BackupHashes {
		if mfa.VerifyBackupCode(code, h) {
			return h, true
		}
	}
	return "", false
}

// verifyLoginMFA enforces the second factor after a correct password.
// Returns true when no MFA is enabled or the code verifies (consuming a backup
// code when used). On failure it throttles, audits and metrics without echoing
// the presented code.
func (s *Server) verifyLoginMFA(w http.ResponseWriter, r *http.Request, u *auth.User, totpCode, backupCode string, accountKey, ipKey string, now time.Time) bool {
	if !u.TOTPEnabled {
		return true
	}
	code := strings.TrimSpace(totpCode)
	if code == "" {
		code = strings.TrimSpace(backupCode)
	}
	userKey := "mfa:user:" + u.ID
	if wait := s.limiter.RetryAfter(userKey, now); wait > 0 {
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return false
	}
	if wait := s.limiter.RetryAfter("mfa:ip:"+clientIP(r), now); wait > 0 {
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return false
	}
	if code == "" {
		s.limiter.Fail(userKey, now)
		s.limiter.Fail(accountKey, now)
		s.limiter.Fail(ipKey, now)
		s.reg.Inc(metrics.MFAFailureTotal)
		s.writeAudit(r, audit.Entry{
			Actor:    audit.ActorRef(audit.ActorUser, u.Username),
			Action:   audit.ActionMFALoginFailure,
			Resource: "session",
			Result:   audit.ResultDenied,
			Detail:   "mfa code required",
		})
		writeError(w, http.StatusUnauthorized, CodeMFARequired, "multi-factor code required")
		return false
	}
	backupHash, ok := s.verifyUserCode(u, code)
	if !ok {
		s.limiter.Fail(userKey, now)
		s.limiter.Fail(accountKey, now)
		s.limiter.Fail(ipKey, now)
		s.reg.Inc(metrics.MFAFailureTotal)
		s.writeAudit(r, audit.Entry{
			Actor:    audit.ActorRef(audit.ActorUser, u.Username),
			Action:   audit.ActionMFALoginFailure,
			Resource: "session",
			Result:   audit.ResultDenied,
			Detail:   "mfa code mismatch",
		})
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials")
		return false
	}
	if backupHash != "" {
		consumed, err := s.store.ConsumeBackupCode(r.Context(), u.ID, backupHash)
		if err != nil {
			s.fail(w, err, "consume backup code")
			return false
		}
		if !consumed {
			// Another request redeemed this code between verify and consume.
			s.limiter.Fail(userKey, now)
			s.limiter.Fail(accountKey, now)
			s.limiter.Fail(ipKey, now)
			s.reg.Inc(metrics.MFAFailureTotal)
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials")
			return false
		}
		s.reg.Inc(metrics.MFABackupUsedTotal)
		s.writeAudit(r, audit.Entry{
			Actor:      audit.ActorRef(audit.ActorUser, u.Username),
			Action:     audit.ActionMFABackupUsed,
			Resource:   "session",
			ResourceID: u.ID,
			Result:     audit.ResultSuccess,
			Detail:     "backup code consumed",
		})
	}
	s.limiter.Succeed(userKey)
	return true
}

// CodeMFARequired is returned when the password is correct but the second
// factor is missing. It is 401 (not a distinct status) so generic tooling
// still treats it as auth failure; the code lets the UI prompt for TOTP.

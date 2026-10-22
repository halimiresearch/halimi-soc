package api

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/events/validation"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/webauthn"
)

// Passkey (WebAuthn) ceremonies. See ADR-015.
//
// Two flows:
//   - Registration (authenticated + CSRF): begin issues a challenge bound to
//     the user; complete verifies attestation (none/packed self, ES256, UV
//     required) and stores the credential.
//   - Passwordless login (unauthenticated, strictly rate-limited): begin
//     issues a challenge for the username; complete verifies the assertion,
//     checks clone detection, rotates the sign count and mints a session.
//
// A passkey verifies possession + user verification in one phishing-resistant
// step, so a successful assertion logs in without a password or TOTP code.

var b64url = base64.RawURLEncoding

var allowedTransports = map[string]bool{
	"usb": true, "nfc": true, "ble": true, "internal": true, "hybrid": true,
}

func cleanTransports(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if !allowedTransports[t] || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

type registerBeginRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	var req registerBeginRequest
	if err := s.decodeJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	if !s.requireStepUp(w, r, p, req.Password, req.Code) {
		return
	}
	if _, err := validation.Printable(req.Name, 64); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid passkey name")
		return
	}

	existing, err := s.store.ListPasskeysByUser(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, err, "list passkeys")
		return
	}
	if len(existing) >= 10 {
		writeError(w, http.StatusConflict, CodeConflict, "passkey limit reached")
		return
	}
	ch, err := s.challenges.Issue(p.User.ID, webauthn.PurposeRegister)
	if err != nil {
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}
	exclude := make([]map[string]any, 0, len(existing))
	for _, k := range existing {
		exclude = append(exclude, map[string]any{"type": "public-key", "id": k.CredentialID})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge": ch,
		"rp":        map[string]string{"id": s.webauthn.RPID, "name": s.webauthn.RPName},
		"user": map[string]string{
			"id":          p.User.ID,
			"name":        p.User.Username,
			"displayName": p.User.Username,
		},
		"pubKeyCredParams": []map[string]any{{"type": "public-key", "alg": -7}},
		"authenticatorSelection": map[string]any{
			"requireResidentKey":      false,
			"residentKey":             "preferred",
			"userVerification":        "required",
			"authenticatorAttachment": "platform",
		},
		"attestation":        "none",
		"excludeCredentials": exclude,
		"timeout":            300000,
	})
}

type registerCompleteRequest struct {
	Challenge  string   `json:"challenge"`
	ID         string   `json:"id"`
	Transports []string `json:"transports"`
	Name       string   `json:"name"`
	Response   struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	} `json:"response"`
}

func (s *Server) handlePasskeyRegisterComplete(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	var req registerCompleteRequest
	if err := s.decodeJSON(w, r, &req, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	if req.Challenge == "" || req.ID == "" || req.Response.ClientDataJSON == "" || req.Response.AttestationObject == "" {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "challenge, id and attestation are required")
		return
	}
	if len(req.ID) > 2048 {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "credential id too large")
		return
	}
	if _, err := b64url.DecodeString(req.ID); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "credential id encoding")
		return
	}
	name, err := validation.Printable(req.Name, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid passkey name")
		return
	}
	if err := s.challenges.Consume(req.Challenge, p.User.ID, webauthn.PurposeRegister); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "challenge expired; restart registration")
		return
	}
	cred, err := webauthn.VerifyRegistration(s.webauthn, req.Challenge, req.Response.ClientDataJSON, req.Response.AttestationObject)
	if err != nil {
		s.reg.Inc(metrics.PasskeyFailureTotal)
		s.writeAudit(r, audit.Entry{
			Actor:    audit.ActorRef(audit.ActorUser, p.User.Username),
			Action:   audit.ActionPasskeyRegistered,
			Resource: "passkey",
			Result:   audit.ResultDenied,
			Detail:   "attestation verification failed",
		})
		writeError(w, http.StatusBadRequest, CodeBadRequest, "attestation verification failed")
		return
	}
	if b64url.EncodeToString(cred.CredentialID) != req.ID {
		s.reg.Inc(metrics.PasskeyFailureTotal)
		writeError(w, http.StatusBadRequest, CodeBadRequest, "credential id mismatch")
		return
	}
	now := s.now()
	pk := &webauthn.Passkey{
		ID:           id.New(id.KindToken),
		UserID:       p.User.ID,
		CredentialID: req.ID,
		PublicKey:    b64url.EncodeToString(cred.PublicKey),
		SignCount:    cred.SignCount,
		Transports:   cleanTransports(req.Transports),
		Name:         name,
		CreatedAt:    now,
	}
	if err := s.store.SavePasskey(r.Context(), pk); err != nil {
		s.fail(w, err, "save passkey")
		return
	}
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionPasskeyRegistered,
		Resource:   "passkey",
		ResourceID: pk.ID,
		Result:     audit.ResultSuccess,
		Detail:     "passkey registered",
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"credential_id": pk.ID,
		"name":          pk.Name,
	})
}

func (s *Server) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	list, err := s.store.ListPasskeysByUser(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, err, "list passkeys")
		return
	}
	type view struct {
		ID         string     `json:"id"`
		Name       string     `json:"name,omitempty"`
		CreatedAt  time.Time  `json:"created_at"`
		LastUsedAt *time.Time `json:"last_used_at,omitempty"`
		SignCount  uint32     `json:"sign_count"`
		Transports []string   `json:"transports,omitempty"`
	}
	out := make([]view, 0, len(list))
	for _, k := range list {
		out = append(out, view{
			ID: k.ID, Name: k.Name, CreatedAt: k.CreatedAt,
			LastUsedAt: k.LastUsedAt, SignCount: k.SignCount, Transports: k.Transports,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": out})
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	credID := r.PathValue("id")
	keys, err := s.store.ListPasskeysByUser(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, err, "list passkeys")
		return
	}
	var target *webauthn.Passkey
	for _, k := range keys {
		if k.ID == credID {
			target = k
			break
		}
	}
	if target == nil {
		// The credential ID is unguessable; a miss is a 404. Admins remove
		// another user's key through the same self-scoped path only when the
		// key belongs to them; cross-user removal needs manage_users and an
		// explicit owner lookup, which this endpoint does not offer to keep
		// the surface minimal.
		writeError(w, http.StatusNotFound, CodeNotFound, "passkey not found")
		return
	}
	if err := s.store.DeletePasskey(r.Context(), target.ID); err != nil {
		s.fail(w, err, "delete passkey")
		return
	}
	// Prevent removing the last MFA factor without a fallback: if TOTP is off
	// and this was the last passkey, warn via audit (still allowed; the admin
	// reset path exists).
	remaining, _ := s.store.ListPasskeysByUser(r.Context(), p.User.ID)
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionPasskeyDeleted,
		Resource:   "passkey",
		ResourceID: target.ID,
		Result:     audit.ResultSuccess,
		Detail:     lastFactorWarning(p.User.TOTPEnabled, len(remaining)),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func lastFactorWarning(totpEnabled bool, remainingPasskeys int) string {
	if !totpEnabled && remainingPasskeys == 0 {
		return "last second factor removed; account is password-only until a new one is enrolled"
	}
	return "passkey deleted"
}

type loginBeginRequest struct {
	Username string `json:"username"`
}

func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req loginBeginRequest
	if err := s.decodeJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))
	if !validUsername(username) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid username")
		return
	}
	now := s.now()
	ipKey := "webauthn:ip:" + clientIP(r)
	if username != "" {
		if wait := s.limiter.RetryAfter("webauthn:user:"+username, now); wait > 0 {
			w.Header().Set("Retry-After", formatSeconds(wait))
			writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
			return
		}
	}
	if wait := s.limiter.RetryAfter(ipKey, now); wait > 0 {
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}
	user, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil || user == nil || !user.Active() {
		// Generic failure to avoid username enumeration via timing differences
		// beyond the unavoidable DB lookup. Still throttle.
		if username != "" {
			s.limiter.Fail("webauthn:user:"+username, now)
		}
		s.limiter.Fail(ipKey, now)
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}
	keys, err := s.store.ListPasskeysByUser(r.Context(), user.ID)
	if err != nil {
		s.fail(w, err, "list passkeys")
		return
	}
	if len(keys) == 0 {
		s.limiter.Fail("webauthn:user:"+username, now)
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}
	ch, err := s.challenges.Issue(username, webauthn.PurposeLogin)
	if err != nil {
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}
	allow := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		allow = append(allow, map[string]any{
			"type": "public-key", "id": k.CredentialID,
			"transports": k.Transports,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":        ch,
		"rpId":             s.webauthn.RPID,
		"allowCredentials": allow,
		"userVerification": "required",
		"timeout":          300000,
	})
}

type loginCompleteRequest struct {
	Username  string `json:"username"`
	Challenge string `json:"challenge"`
	ID        string `json:"id"`
	Response  struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

func (s *Server) handlePasskeyLoginComplete(w http.ResponseWriter, r *http.Request) {
	var req loginCompleteRequest
	if err := s.decodeJSON(w, r, &req, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))
	if !validUsername(username) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid username")
		return
	}
	now := s.now()
	ip := clientIP(r)
	userKey := "webauthn:user:" + username
	ipKey := "webauthn:ip:" + ip
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
	fail := func(detail string) {
		s.limiter.Fail(userKey, now)
		s.limiter.Fail(ipKey, now)
		s.reg.Inc(metrics.PasskeyFailureTotal)
		s.writeAudit(r, audit.Entry{
			Actor:    audit.ActorRef(audit.ActorUser, username),
			Action:   audit.ActionPasskeyLoginFailure,
			Resource: "session",
			Result:   audit.ResultDenied,
			Detail:   detail,
		})
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials")
	}

	user, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil || user == nil || !user.Active() {
		fail("unknown or inactive account")
		return
	}
	if req.Challenge == "" || req.ID == "" {
		fail("missing challenge or credential")
		return
	}
	if err := s.challenges.Consume(req.Challenge, username, webauthn.PurposeLogin); err != nil {
		fail("challenge expired")
		return
	}
	stored, err := s.store.GetPasskeyByCredentialID(r.Context(), req.ID)
	if err != nil || stored.UserID != user.ID {
		fail("unknown credential")
		return
	}
	x, y, err := webauthn.ParsePublicKey(stored.PublicKey)
	if err != nil {
		fail("unusable credential")
		return
	}
	newCount, err := webauthn.VerifyAssertion(s.webauthn, req.Challenge,
		req.Response.ClientDataJSON, req.Response.AuthenticatorData, req.Response.Signature, x, y, stored.SignCount)
	if err != nil {
		if err == webauthn.ErrCloneSuspected {
			s.writeAudit(r, audit.Entry{
				Actor:      audit.ActorRef(audit.ActorUser, user.Username),
				Action:     audit.ActionPasskeyLoginFailure,
				Resource:   "session",
				ResourceID: stored.ID,
				Result:     audit.ResultDenied,
				Detail:     "passkey clone suspected: sign count went backwards",
			})
		}
		fail("assertion verification failed")
		return
	}
	if err := s.store.UpdatePasskeyCounter(r.Context(), stored.ID, newCount, now); err != nil {
		s.log.Warn("update passkey counter failed", "passkey", stored.ID, "error", err)
	}

	s.limiter.Succeed(userKey)
	s.limiter.Succeed(ipKey)
	s.limiter.Succeed("acct:" + username)
	s.limiter.Succeed("ip:" + ip)

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
	s.reg.Inc(metrics.PasskeyLoginTotal)
	http.SetCookie(w, s.sessionCookie(token, sess.ExpiresAt))
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, user.Username),
		Action:     audit.ActionPasskeyLoginSuccess,
		Resource:   "session",
		ResourceID: sess.ID,
		Result:     audit.ResultSuccess,
		Detail:     "passkey login",
	})
	writeJSON(w, http.StatusOK, loginResponse{
		User:      userView{ID: user.ID, Username: user.Username, Role: user.Role, MFAEnabled: user.TOTPEnabled},
		CSRFToken: sess.CSRFToken,
		ExpiresAt: sess.ExpiresAt,
	})
}

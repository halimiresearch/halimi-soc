package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/secret"
)

// SessionCookieName is the session cookie.
//
// The cookie is named with the __Host- prefix, which browsers only accept when
// the cookie is Secure, has Path=/ and has no Domain attribute. That makes it
// impossible for a subdomain to set or overwrite the session cookie, which
// closes a well-known session fixation path.
const SessionCookieName = "__Host-halimisoc_session"

// DevSessionCookieName is the session cookie used over plain HTTP in local
// development. The __Host- prefix requires the Secure attribute, which a browser
// will not accept over http://localhost, so development uses an unprefixed name.
const DevSessionCookieName = "halimisoc_session"

// CSRFHeaderName is the header carrying the CSRF token.
//
// The token is delivered in a response body and echoed in a custom header. A
// custom header cannot be set by a cross-origin form post, and reading the
// token requires a successful same-origin request, so this is a synchroniser
// token pattern rather than a double-submit cookie.
const CSRFHeaderName = "X-CSRF-Token"

// Session errors.
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionRevoked  = errors.New("session revoked")
	ErrCSRFMismatch    = errors.New("csrf token mismatch")
)

// User is an operator account.
type User struct {
	ID           string             `json:"id"`
	Username     string             `json:"username"`
	PasswordHash string             `json:"-"`
	Role         authorization.Role `json:"role"`
	Disabled     bool               `json:"disabled"`

	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`

	// MFA. TOTPSecret is sealed ("v1:..." or "plain:...") and never
	// serialised; BackupHashes are SHA-256 hex of single-use recovery codes.
	TOTPSecret     string     `json:"-"`
	TOTPEnabled    bool       `json:"mfa_enabled"`
	TOTPEnrolledAt *time.Time `json:"mfa_enrolled_at,omitempty"`
	BackupHashes   []string   `json:"-"`

	// TOTPLastStep is the highest time step a code was accepted for. It makes
	// each code single-use even while it is still inside the skew window.
	TOTPLastStep uint64 `json:"-"`
}

// Active reports whether the account may authenticate.
func (u *User) Active() bool { return !u.Disabled }

// Session is a server-side session record.
//
// Sessions are stored server-side rather than encoded into a signed cookie so
// that revocation is immediate. A stateless token cannot be withdrawn before it
// expires, which is unacceptable for an administrative console.
type Session struct {
	ID         string
	UserID     string
	TokenHash  string
	CSRFToken  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	RevokedAt  *time.Time
	SourceIP   string
	UserAgent  string
}

// Revoked reports whether the session has been explicitly revoked.
func (s *Session) Revoked() bool { return s.RevokedAt != nil }

// Expired reports whether the session has passed its expiry.
func (s *Session) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt) }

// IdleExpired reports whether the session has been unused longer than idle.
// A zero idle disables the check. Idle timeout bounds the window in which a
// stolen cookie is useful even when the absolute TTL is long.
func (s *Session) IdleExpired(now time.Time, idle time.Duration) bool {
	if idle <= 0 {
		return false
	}
	if s.LastSeenAt.IsZero() {
		return false
	}
	return now.Sub(s.LastSeenAt) > idle
}

// Usable reports whether the session may authenticate at time now.
func (s *Session) Usable(now time.Time) bool {
	return !s.Revoked() && !s.Expired(now)
}

// NewSession creates a session record for a user.
//
// It returns the plaintext session token, which is sent to the client once and
// never stored.
func NewSession(userID, sourceIP, userAgent string, ttl time.Duration, now time.Time) (*Session, string, error) {
	token, hash, err := secret.NewToken("sess_")
	if err != nil {
		return nil, "", err
	}
	csrf, err := newCSRFToken()
	if err != nil {
		return nil, "", err
	}

	s := &Session{
		ID:         SessionIDFromToken(token),
		UserID:     userID,
		TokenHash:  hash,
		CSRFToken:  csrf,
		CreatedAt:  now.UTC(),
		ExpiresAt:  now.UTC().Add(ttl),
		LastSeenAt: now.UTC(),
		SourceIP:   sourceIP,
		UserAgent:  truncate(userAgent, 256),
	}
	return s, token, nil
}

// SessionIDFromToken derives the storage id of a session from its plaintext
// token.
//
// Deriving the id from the hash lets the server look a session up directly by
// the presented cookie without storing or indexing the plaintext token.
func SessionIDFromToken(token string) string {
	return secret.HashToken(token)[:24]
}

// AuthenticateSession resolves a presented token against a stored session.
func AuthenticateSession(s *Session, presented string, now time.Time) error {
	if s == nil {
		return ErrSessionNotFound
	}
	if s.Revoked() {
		return ErrSessionRevoked
	}
	if s.Expired(now) {
		return ErrSessionExpired
	}
	if !secret.VerifyToken(presented, s.TokenHash) {
		return ErrSessionNotFound
	}
	return nil
}

// VerifyCSRF compares a presented CSRF token with the session's token.
//
// State-changing requests must present it. A missing token fails closed.
func VerifyCSRF(s *Session, presented string) error {
	if s == nil || presented == "" || s.CSRFToken == "" {
		return ErrCSRFMismatch
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.CSRFToken)) != 1 {
		return ErrCSRFMismatch
	}
	return nil
}

func newCSRFToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate csrf token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// Package mfa implements TOTP-based multi-factor authentication with only the
// standard library.
//
// Design (threat model):
//   - Factor 1: Argon2id password (low entropy, memory-hard).
//   - Factor 2: TOTP 6-digit, 30s step, SHA1, ±1 step skew (RFC 6238/4226).
//   - The TOTP secret is 20 bytes (160 bits) base32 no-padding. It is stored
//     encrypted with AES-GCM under HALIMISOC_MFA_KEY when set, else plaintext
//     with a "plain:" prefix and a production warning. A DB-only leak without
//     the env key is then insufficient to forge codes.
//   - Backup codes are 10x single-use 8-char values; only SHA-256 hashes are
//     stored, compared constant-time, consumed on use.
//   - Verification is constant-time over the 6-digit string; time-step
//     comparison covers -1/0/+1 to tolerate clock drift without widening to a
//     brute-force window.
package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Step and skew.
const (
	StepSeconds = 30
	SkewSteps   = 1
	CodeDigits  = 6
	SecretBytes = 20
)

// Errors.
var (
	ErrInvalidCode   = errors.New("invalid mfa code")
	ErrInvalidSecret = errors.New("invalid mfa secret")
)

// GenerateSecret returns a new base32 (no padding) TOTP secret.
func GenerateSecret() (string, error) {
	raw := make([]byte, SecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mfa: generate secret: %w", err)
	}
	return b32.EncodeToString(raw), nil
}

// OTPAUTHURL builds the otpauth:// URL an authenticator app imports.
// Issuer and account are URL-escaped by the caller contract: they must be
// alphanumeric/dot/dash/underscore/space only; anything else is stripped.
func OTPAUTHURL(issuer, account, secret string) string {
	issuer = sanitizeLabel(issuer)
	account = sanitizeLabel(account)
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30&algorithm=SHA1",
		escapeLabel(issuer), escapeLabel(account), secret, escapeLabel(issuer))
}

func sanitizeLabel(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == ' ', r == '@':
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "halimisoc"
	}
	return out
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, " ", "%20")
	s = strings.ReplaceAll(s, "@", "%40")
	return s
}

// CodeAt returns the 6-digit TOTP for secret at time t.
func CodeAt(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(t.UTC().Unix() / StepSeconds)
	return codeFor(key, counter), nil
}

// Verify checks code against secret at time now with ±SkewSteps skew.
// It returns the time step that matched, so the caller can refuse a code that
// already authenticated. Comparison is constant-time over the candidate
// strings.
func Verify(secret, code string, now time.Time) (uint64, error) {
	code = strings.TrimSpace(code)
	if len(code) != CodeDigits || !isDigits(code) {
		return 0, ErrInvalidCode
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, err
	}
	base := int64(now.UTC().Unix() / StepSeconds)
	matched := 0
	var matchedStep uint64
	for d := -SkewSteps; d <= SkewSteps; d++ {
		c := int64(base) + int64(d)
		if c < 0 {
			continue
		}
		candidate := codeFor(key, uint64(c))
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			matched = 1
			matchedStep = uint64(c)
		}
	}
	if matched != 1 {
		return 0, ErrInvalidCode
	}
	return matchedStep, nil
}

func decodeSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(strings.ToUpper(secret))
	// Accept unpadded and padded input.
	if key, err := b32.DecodeString(secret); err == nil && len(key) >= 10 {
		return key, nil
	}
	padded := secret
	if m := len(padded) % 8; m != 0 {
		padded += strings.Repeat("=", 8-m)
	}
	key, err := base32.StdEncoding.DecodeString(padded)
	if err != nil || len(key) < 10 {
		return nil, ErrInvalidSecret
	}
	return key, nil
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func codeFor(key []byte, counter uint64) string {
	var msg [8]byte
	for i := 7; i >= 0; i-- {
		msg[i] = byte(counter)
		counter >>= 8
	}
	mac := hmac.New(func() hash.Hash { return sha1.New() }, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (int(sum[offset])&0x7f)<<24 |
		int(sum[offset+1])<<16 |
		int(sum[offset+2])<<8 |
		int(sum[offset+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// --- Backup codes -----------------------------------------------------------

// BackupCodeBytes is the entropy per backup code (5 bytes -> 8 base32 chars).
const BackupCodeBytes = 5

// BackupCodeCount is how many codes are issued per enable.
const BackupCodeCount = 10

// GenerateBackupCodes returns count single-use codes (8-char base32).
func GenerateBackupCodes(count int) ([]string, error) {
	if count <= 0 {
		count = BackupCodeCount
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw := make([]byte, BackupCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("mfa: generate backup code: %w", err)
		}
		out = append(out, b32.EncodeToString(raw))
	}
	return out, nil
}

// HashBackupCode returns the SHA-256 hex of a backup code for storage.
func HashBackupCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(strings.ToUpper(code))))
	return fmt.Sprintf("%x", sum[:])
}

// VerifyBackupCode constant-time matches a presented code against a stored hash.
func VerifyBackupCode(presented, storedHash string) bool {
	if presented == "" || storedHash == "" {
		return false
	}
	got := HashBackupCode(presented)
	if len(got) != len(storedHash) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// --- Secret encryption at rest ----------------------------------------------

// Seal encrypts a TOTP secret with AES-256-GCM under a 32-byte key.
// Format: "v1:<base64 nonce>:<base64 ciphertext>".
// An empty key returns "plain:<secret>" so dev runs without a key; production
// should always set HALIMISOC_MFA_KEY and treats plain: as a warning.
func Seal(secret string, key []byte) (string, error) {
	if len(key) == 0 {
		return "plain:" + secret, nil
	}
	if len(key) != 32 {
		return "", fmt.Errorf("mfa: encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(secret), nil)
	return "v1:" + base64.RawStdEncoding.EncodeToString(nonce) + ":" +
		base64.RawStdEncoding.EncodeToString(ct), nil
}

// Open decrypts a sealed secret. It accepts "v1:..." and "plain:..." forms.
func Open(sealed string, key []byte) (string, error) {
	if strings.HasPrefix(sealed, "plain:") {
		return strings.TrimPrefix(sealed, "plain:"), nil
	}
	parts := strings.Split(sealed, ":")
	if len(parts) != 3 || parts[0] != "v1" {
		return "", ErrInvalidSecret
	}
	if len(key) != 32 {
		return "", fmt.Errorf("mfa: decryption key must be 32 bytes")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidSecret
	}
	ct, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ErrInvalidSecret
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", ErrInvalidSecret
	}
	return string(pt), nil
}

// ParseMFAKey parses HALIMISOC_MFA_KEY as base64 (raw or padded) 32 bytes.
// Empty returns nil with no error (dev mode); production warns separately.
func ParseMFAKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("mfa: HALIMISOC_MFA_KEY must be base64 of 32 bytes")
}

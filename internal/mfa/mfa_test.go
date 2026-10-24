package mfa_test

import (
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/mfa"
)

func TestVerifyReturnsMatchedStep(t *testing.T) {
	secret, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := mfa.CodeAt(secret, now)
	if err != nil {
		t.Fatal(err)
	}

	step, err := mfa.Verify(secret, code, now)
	if err != nil {
		t.Fatalf("valid code rejected: %v", err)
	}
	if want := uint64(now.Unix() / 30); step != want {
		t.Fatalf("step = %d, want %d", step, want)
	}
}

func TestVerifyReturnsTheCodesStepNotTheCurrentOne(t *testing.T) {
	secret, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := mfa.CodeAt(secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	step, err := mfa.Verify(secret, code, now)
	if err != nil {
		t.Fatalf("code inside the skew window rejected: %v", err)
	}
	if want := uint64(now.Unix()/30) - 1; step != want {
		t.Fatalf("step = %d, want %d: recording the current step would let the code replay", step, want)
	}
}

func TestGenerateAndVerifyRoundTrip(t *testing.T) {
	secret, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	code, err := mfa.CodeAt(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("code = %q, want 6 digits", code)
	}
	if _, err := mfa.Verify(secret, code, now); err != nil {
		t.Fatalf("valid code rejected: %v", err)
	}
}

func TestSkewAcceptsAdjacentSteps(t *testing.T) {
	secret, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	prev, err := mfa.CodeAt(secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	next, err := mfa.CodeAt(secret, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mfa.Verify(secret, prev, now); err != nil {
		t.Errorf("previous step rejected: %v", err)
	}
	if _, err := mfa.Verify(secret, next, now); err != nil {
		t.Errorf("next step rejected: %v", err)
	}
	old, err := mfa.CodeAt(secret, now.Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mfa.Verify(secret, old, now); err == nil {
		t.Error("code 3 steps away accepted; skew window too wide")
	}
}

func TestWrongCodeRejected(t *testing.T) {
	secret, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "123", "1234567", "abcdef", "  "} {
		if _, err := mfa.Verify(secret, bad, time.Now().UTC()); err == nil {
			t.Errorf("code %q accepted", bad)
		}
	}
}

func TestBackupCodesAreSingleUseHashes(t *testing.T) {
	codes, err := mfa.GenerateBackupCodes(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 3 {
		t.Fatalf("codes = %d, want 3", len(codes))
	}
	h := mfa.HashBackupCode(codes[0])
	if !mfa.VerifyBackupCode(codes[0], h) {
		t.Fatal("valid backup code rejected")
	}
	if mfa.VerifyBackupCode(codes[1], h) {
		t.Fatal("wrong backup code accepted")
	}
	// Case-insensitive entry (users type lowercase).
	if !mfa.VerifyBackupCode(strings.ToLower(codes[0]), h) {
		t.Fatal("lowercase backup code rejected")
	}
}

func TestSealRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sealed, err := mfa.Seal("JBSWY3DPEHPK3PXP", key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "v1:") {
		t.Fatalf("sealed = %q, want v1: prefix", sealed)
	}
	opened, err := mfa.Open(sealed, key)
	if err != nil {
		t.Fatal(err)
	}
	if opened != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("opened = %q", opened)
	}
	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = byte(255 - i)
	}
	if _, err := mfa.Open(sealed, wrong); err == nil {
		t.Fatal("wrong key decrypted the secret")
	}
}

func TestOTPAUTHURLIsImportable(t *testing.T) {
	u := mfa.OTPAUTHURL("HalimiSOC", "admin", "JBSWY3DPEHPK3PXP")
	if !strings.HasPrefix(u, "otpauth://totp/") {
		t.Fatalf("url = %q", u)
	}
	if !strings.Contains(u, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("url missing secret: %q", u)
	}
}

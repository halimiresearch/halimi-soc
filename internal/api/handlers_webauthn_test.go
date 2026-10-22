package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/mfa"
)

var wb64 = base64.RawURLEncoding

// --- tiny CBOR encoder (test only, mirrors webauthn_test) --------------------

func wUint(n uint64) []byte {
	switch {
	case n < 24:
		return []byte{byte(n)}
	case n < 256:
		return []byte{0x18, byte(n)}
	case n < 65536:
		return []byte{0x19, byte(n >> 8), byte(n)}
	default:
		return []byte{0x1a, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func wNeg(n int64) []byte {
	b := wUint(uint64(-1 - n))
	b[0] |= 0x20
	return b
}

func wBytes(b []byte) []byte {
	h := wUint(uint64(len(b)))
	h[0] |= 0x40
	return append(h, b...)
}

func wText(s string) []byte {
	h := wUint(uint64(len(s)))
	h[0] |= 0x60
	return append(h, s...)
}

func wMap(pairs ...[]byte) []byte {
	h := wUint(uint64(len(pairs) / 2))
	h[0] |= 0xa0
	for _, p := range pairs {
		h = append(h, p...)
	}
	return h
}

type apiCredential struct {
	priv         *ecdsa.PrivateKey
	credentialID []byte
	authData     []byte
}

func newAPICredential(t *testing.T, rpID string) *apiCredential {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	cose := wMap(
		wUint(1), wUint(2),
		wUint(3), wNeg(-7),
		wNeg(-1), wUint(1),
		wNeg(-2), wBytes(xb),
		wNeg(-3), wBytes(yb),
	)
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append([]byte(nil), rpHash[:]...)
	authData = append(authData, 0x45)
	var sc [4]byte
	authData = append(authData, sc[:]...)
	var aaguid [16]byte
	authData = append(authData, aaguid[:]...)
	var idLen [2]byte
	binary.BigEndian.PutUint16(idLen[:], uint16(len(credID)))
	authData = append(authData, idLen[:]...)
	authData = append(authData, credID...)
	authData = append(authData, cose...)
	return &apiCredential{priv: priv, credentialID: credID, authData: authData}
}

func apiClientData(typ, challenge, origin string) []byte {
	raw, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": origin})
	return raw
}

// registerOne performs a full attestation-none ceremony via HTTP and returns
// the stored passkey DB id.
func registerOne(t *testing.T, h *harness, csrf, name, password string) string {
	t.Helper()
	begin := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/auth/webauthn/register/begin",
		map[string]string{"name": name, "password": password}, map[string]string{"X-CSRF-Token": csrf}))
	ch, _ := begin["challenge"].(string)
	if ch == "" {
		t.Fatal("no challenge from register begin")
	}
	cred := newAPICredential(t, "127.0.0.1")
	origin := "http://127.0.0.1:3000"
	cd := apiClientData("webauthn.create", ch, origin)
	obj := wMap(
		wText("fmt"), wText("none"),
		wText("authData"), wBytes(cred.authData),
		wText("attStmt"), wMap(),
	)
	resp := h.do(http.MethodPost, "/api/v1/auth/webauthn/register/complete", map[string]any{
		"challenge": ch,
		"id":        wb64.EncodeToString(cred.credentialID),
		"name":      name,
		"response": map[string]string{
			"clientDataJSON":    wb64.EncodeToString(cd),
			"attestationObject": wb64.EncodeToString(obj),
		},
	}, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("register complete = %d: %s", resp.StatusCode, body)
	}
	out := decode[map[string]any](t, resp)
	id, _ := out["credential_id"].(string)
	if id == "" {
		t.Fatal("no credential id returned")
	}
	return id
}

func TestPasskeyRegisterRequiresAuth(t *testing.T) {
	h := newHarness(t)
	resp := h.do(http.MethodPost, "/api/v1/auth/webauthn/register/begin", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous begin = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
	resp = h.do(http.MethodGet, "/api/v1/auth/webauthn/credentials", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous list = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPasskeyRegisterAndPasswordlessLogin(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "gail", "gail-password-value123", "ANALYST")
	csrf, _ := h.login("gail", "gail-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}

	dbID := registerOne(t, h, csrf, "laptop-key", "gail-password-value123")

	// Listing shows the key without its public material.
	list := decode[struct {
		Passkeys []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"passkeys"`
	}](t, h.do(http.MethodGet, "/api/v1/auth/webauthn/credentials", nil, nil))
	if len(list.Passkeys) != 1 || list.Passkeys[0].ID != dbID {
		t.Fatalf("list = %+v", list)
	}

	// Passwordless login with a bogus assertion fails closed.
	h.client.Jar = freshJar(t)
	beg := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/auth/webauthn/login/begin",
		map[string]string{"username": "gail"}, nil))
	if beg["challenge"] == nil {
		t.Fatal("no login challenge")
	}
	resp := h.do(http.MethodPost, "/api/v1/auth/webauthn/login/complete", map[string]any{
		"username": "gail", "challenge": "bogus", "id": "bogus",
		"response": map[string]string{
			"clientDataJSON":    wb64.EncodeToString(apiClientData("webauthn.get", "bogus", "http://127.0.0.1:3000")),
			"authenticatorData": wb64.EncodeToString(make([]byte, 37)),
			"signature":         wb64.EncodeToString(make([]byte, 32)),
		},
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bogus assertion = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
	_ = headers
}

func TestPasskeyLoginBeginUnknownUserIsGeneric(t *testing.T) {
	h := newHarness(t)
	resp := h.do(http.MethodPost, "/api/v1/auth/webauthn/login/begin",
		map[string]string{"username": "ghost-nobody"}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown user begin = %d, want generic 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPasskeyDelete(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "hank", "hank-password-value123", "ANALYST")
	csrf, _ := h.login("hank", "hank-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}
	dbID := registerOne(t, h, csrf, "yubikey", "hank-password-value123")

	resp := h.do(http.MethodDelete, "/api/v1/auth/webauthn/credentials/"+dbID, nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	list := decode[struct {
		Passkeys []struct {
			ID string `json:"id"`
		} `json:"passkeys"`
	}](t, h.do(http.MethodGet, "/api/v1/auth/webauthn/credentials", nil, nil))
	if len(list.Passkeys) != 0 {
		t.Fatalf("passkeys after delete = %d, want 0", len(list.Passkeys))
	}

	// Deleting without CSRF fails closed.
	dbID2 := registerOne(t, h, csrf, "second", "hank-password-value123")
	resp = h.do(http.MethodDelete, "/api/v1/auth/webauthn/credentials/"+dbID2, nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without CSRF = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// Full passwordless ceremony: register, then assert with the same key.
// Proves the server's rpId/origin/signature path works against real crypto,
// not just the negative cases above.
func TestPasskeyPasswordlessLoginSuccess(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "ivan", "ivan-password-value123", "ANALYST")
	csrf, _ := h.login("ivan", "ivan-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}

	// Register, keeping the private key this time.
	begin := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/auth/webauthn/register/begin",
		map[string]string{"name": "passkey", "password": "ivan-password-value123"}, headers))
	ch, _ := begin["challenge"].(string)
	cred := newAPICredential(t, "127.0.0.1")
	origin := "http://127.0.0.1:3000"
	cd := apiClientData("webauthn.create", ch, origin)
	obj := wMap(
		wText("fmt"), wText("none"),
		wText("authData"), wBytes(cred.authData),
		wText("attStmt"), wMap(),
	)
	resp := h.do(http.MethodPost, "/api/v1/auth/webauthn/register/complete", map[string]any{
		"challenge": ch,
		"id":        wb64.EncodeToString(cred.credentialID),
		"name":      "passkey",
		"response": map[string]string{
			"clientDataJSON":    wb64.EncodeToString(cd),
			"attestationObject": wb64.EncodeToString(obj),
		},
	}, headers)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("register = %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Drop the password session: the next login must be passwordless.
	h.client.Jar = freshJar(t)
	lbeg := decode[map[string]any](t, h.do(http.MethodPost, "/api/v1/auth/webauthn/login/begin",
		map[string]string{"username": "ivan"}, nil))
	lch, _ := lbeg["challenge"].(string)
	if lch == "" {
		t.Fatal("no login challenge")
	}

	rpHash := sha256.Sum256([]byte("127.0.0.1"))
	authData := append([]byte(nil), rpHash[:]...)
	authData = append(authData, 0x05)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], 1)
	authData = append(authData, sc[:]...)
	lcd := apiClientData("webauthn.get", lch, origin)
	hh := sha256.Sum256(lcd)
	var data []byte
	data = append(data, authData...)
	data = append(data, hh[:]...)
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, cred.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	complete := h.do(http.MethodPost, "/api/v1/auth/webauthn/login/complete", map[string]any{
		"username": "ivan", "challenge": lch, "id": wb64.EncodeToString(cred.credentialID),
		"response": map[string]string{
			"clientDataJSON":    wb64.EncodeToString(lcd),
			"authenticatorData": wb64.EncodeToString(authData),
			"signature":         wb64.EncodeToString(sig),
		},
	}, nil)
	if complete.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(complete.Body)
		complete.Body.Close()
		t.Fatalf("passwordless login = %d: %s", complete.StatusCode, body)
	}
	complete.Body.Close()

	// The minted session works.
	got := h.do(http.MethodGet, "/api/v1/auth/session", nil, nil)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("session after passkey login = %d, want 200", got.StatusCode)
	}
	got.Body.Close()
}

func TestPasskeyRegisterRequiresStepUp(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "laura", "laura-password-value123", "ANALYST")
	csrf, _ := h.login("laura", "laura-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}

	resp := h.do(http.MethodPost, "/api/v1/auth/webauthn/register/begin",
		map[string]string{"name": "key"}, headers)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("register without password = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.do(http.MethodPost, "/api/v1/auth/webauthn/register/begin",
		map[string]string{"name": "key", "password": "wrong-password-value"}, headers)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("register with wrong password = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.do(http.MethodPost, "/api/v1/auth/webauthn/register/begin",
		map[string]string{"name": "key", "password": "laura-password-value123"}, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register with password = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Enable MFA, then prove registration needs the second factor too.
	setup := decode[struct {
		Secret string `json:"secret"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "laura-password-value123"}, headers))
	code, _ := mfa.CodeAt(setup.Secret, time.Now().UTC())
	resp = h.do(http.MethodPost, "/api/v1/auth/mfa/enable",
		map[string]string{"code": code}, headers)
	resp.Body.Close()

	resp = h.do(http.MethodPost, "/api/v1/auth/webauthn/register/begin",
		map[string]string{"name": "key", "password": "laura-password-value123"}, headers)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("register without current code = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	code, _ = mfa.CodeAt(setup.Secret, time.Now().UTC())
	resp = h.do(http.MethodPost, "/api/v1/auth/webauthn/register/begin",
		map[string]string{"name": "key", "password": "laura-password-value123", "code": code}, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register with both factors = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPasskeyLoginRejectsMalformedUsername(t *testing.T) {
	h := newHarness(t)
	for _, username := range []string{"bad name!", strings.Repeat("a", 9000)} {
		resp := h.do(http.MethodPost, "/api/v1/auth/webauthn/login/begin",
			map[string]string{"username": username}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("begin with %d-byte username = %d, want 400", len(username), resp.StatusCode)
		}
		resp.Body.Close()
	}
}

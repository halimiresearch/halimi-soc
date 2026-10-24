package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/mfa"
	"github.com/halimi/halimisoc/internal/storage"
	memorystore "github.com/halimi/halimisoc/internal/storage/memory"
)

// Full MFA lifecycle: setup -> enable -> login with TOTP -> disable.
func TestMFALifecycle(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "dave", "dave-password-value123", "ANALYST")
	csrf, _ := h.login("dave", "dave-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}

	// Status starts disabled.
	st := decode[struct {
		Enabled bool `json:"enabled"`
	}](t, h.do(http.MethodGet, "/api/v1/auth/mfa/status", nil, nil))
	if st.Enabled {
		t.Fatal("mfa should start disabled")
	}

	// Setup returns a secret + otpauth url.
	setup := decode[struct {
		Secret     string `json:"secret"`
		OTPAUTHURL string `json:"otpauth_url"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "dave-password-value123"}, headers))
	if setup.Secret == "" || setup.OTPAUTHURL == "" {
		t.Fatalf("setup = %+v", setup)
	}

	// Enable with a wrong code fails closed.
	resp := h.do(http.MethodPost, "/api/v1/auth/mfa/enable",
		map[string]string{"code": "000000"}, headers)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("enable wrong code = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Enable with the real code.
	code, err := mfa.CodeAt(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	enabled := decode[struct {
		BackupCodes []string `json:"backup_codes"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/enable",
		map[string]string{"code": code}, headers))
	if len(enabled.BackupCodes) != mfa.BackupCodeCount {
		t.Fatalf("backup codes = %d, want %d", len(enabled.BackupCodes), mfa.BackupCodeCount)
	}

	// Password-only login now returns MFA_REQUIRED.
	h.client.Jar = freshJar(t)
	if _, status := h.login("dave", "dave-password-value123"); status != http.StatusUnauthorized {
		t.Fatalf("password-only login after enable = %d, want 401", status)
	}

	// Login with TOTP succeeds. The code that enabled MFA is spent, so use the
	// next step; replaying it is exactly what this suite forbids.
	code2, err := mfa.CodeAt(setup.Secret, time.Now().UTC().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, status := h.loginWithMFA("dave", "dave-password-value123", code2, ""); status != http.StatusOK {
		t.Fatalf("totp login = %d, want 200", status)
	}

	// Login with a backup code succeeds and consumes it.
	h.client.Jar = freshJar(t)
	if _, status := h.loginWithMFA("dave", "dave-password-value123", "", enabled.BackupCodes[0]); status != http.StatusOK {
		t.Fatalf("backup login = %d, want 200", status)
	}
	// Same backup code must not work twice.
	h.client.Jar = freshJar(t)
	if _, status := h.loginWithMFA("dave", "dave-password-value123", "", enabled.BackupCodes[0]); status == http.StatusOK {
		t.Fatal("reused backup code accepted")
	}
}

// Admin can reset a lost authenticator.
func TestMFAAdminReset(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "erin", "erin-password-value123", "ANALYST")
	csrf, _ := h.login("erin", "erin-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}
	setup := decode[struct {
		Secret string `json:"secret"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "erin-password-value123"}, headers))
	code, _ := mfa.CodeAt(setup.Secret, time.Now().UTC())
	resp := h.do(http.MethodPost, "/api/v1/auth/mfa/enable", map[string]string{"code": code}, headers)
	resp.Body.Close()

	adminCSRF, _ := h.login("admin", adminPassword)
	erinID := userIDByName(t, h, "erin")
	resp = h.do(http.MethodPost, "/api/v1/users/"+erinID+"/mfa/reset", nil,
		map[string]string{"X-CSRF-Token": adminCSRF})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin reset = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Password-only login works again after reset.
	h.client.Jar = freshJar(t)
	if _, status := h.login("erin", "erin-password-value123"); status != http.StatusOK {
		t.Fatalf("login after reset = %d, want 200", status)
	}
}

// TOTP guessing is throttled.
func TestMFALoginIsRateLimited(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "frank", "frank-password-value123", "ANALYST")
	csrf, _ := h.login("frank", "frank-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}
	setup := decode[struct {
		Secret string `json:"secret"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "frank-password-value123"}, headers))
	code, _ := mfa.CodeAt(setup.Secret, time.Now().UTC())
	resp := h.do(http.MethodPost, "/api/v1/auth/mfa/enable", map[string]string{"code": code}, headers)
	resp.Body.Close()

	var last int
	for i := 0; i < 15; i++ {
		h.client.Jar = freshJar(t)
		_, last = h.loginWithMFA("frank", "frank-password-value123", "000000", "")
		if last == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatalf("mfa guessing never throttled, last = %d", last)
}

func freshJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

// slowUserSaveStore widens the read-modify-write window around a backup code
// so a non-atomic consume cannot hide behind scheduler timing.
type slowUserSaveStore struct {
	storage.Store
	delay time.Duration
}

func (s *slowUserSaveStore) SaveUser(ctx context.Context, u *auth.User) error {
	time.Sleep(s.delay)
	return s.Store.SaveUser(ctx, u)
}

func TestBackupCodeIsSingleUseUnderConcurrency(t *testing.T) {
	store := memorystore.New()
	h := newHarnessWithStore(t, store, func(inner storage.Store) storage.Store {
		return &slowUserSaveStore{Store: inner, delay: 100 * time.Millisecond}
	})
	createOperator(t, h, "judy", "judy-password-value123", "ANALYST")
	csrf, _ := h.login("judy", "judy-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}

	setup := decode[struct {
		Secret string `json:"secret"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "judy-password-value123"}, headers))
	code, _ := mfa.CodeAt(setup.Secret, time.Now().UTC())
	enabled := decode[struct {
		BackupCodes []string `json:"backup_codes"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/enable",
		map[string]string{"code": code}, headers))

	statuses := make([]int, 8)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			raw, _ := json.Marshal(map[string]string{
				"username": "judy", "password": "judy-password-value123",
				"backup_code": enabled.BackupCodes[0],
			})
			req, err := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/auth/login", bytes.NewReader(raw))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			statuses[i] = resp.StatusCode
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	for _, status := range statuses {
		if status == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("backup code accepted %d times, want exactly 1 (statuses %v)", successes, statuses)
	}
	user, err := store.GetUserByUsername(context.Background(), "judy")
	if err != nil {
		t.Fatal(err)
	}
	if len(user.BackupHashes) != mfa.BackupCodeCount-1 {
		t.Fatalf("remaining backup hashes = %d, want %d", len(user.BackupHashes), mfa.BackupCodeCount-1)
	}
}

// A TOTP code is single-use: the enable code must not authenticate a login,
// and a login code replayed inside the skew window must fail.
func TestTOTPCodeIsNotReplayable(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "nina", "nina-password-value123", "ANALYST")
	csrf, _ := h.login("nina", "nina-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}

	setup := decode[struct {
		Secret string `json:"secret"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "nina-password-value123"}, headers))
	enableCode, err := mfa.CodeAt(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if resp := h.do(http.MethodPost, "/api/v1/auth/mfa/enable",
		map[string]string{"code": enableCode}, headers); resp.StatusCode != http.StatusOK {
		t.Fatalf("enable = %d, want 200", resp.StatusCode)
	}

	h.client.Jar = freshJar(t)
	if _, status := h.loginWithMFA("nina", "nina-password-value123", enableCode, ""); status != http.StatusUnauthorized {
		t.Fatalf("enable code replayed at login = %d, want 401", status)
	}

	code, err := mfa.CodeAt(setup.Secret, time.Now().UTC().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, status := h.loginWithMFA("nina", "nina-password-value123", code, ""); status != http.StatusOK {
		t.Fatalf("first use of the code = %d, want 200", status)
	}

	h.client.Jar = freshJar(t)
	if _, status := h.loginWithMFA("nina", "nina-password-value123", code, ""); status != http.StatusUnauthorized {
		t.Fatalf("replayed login code = %d, want 401", status)
	}
}

func (h *harness) loginWithMFA(username, password, totp, backup string) (string, int) {
	h.t.Helper()
	resp := h.do(http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": username, "password": password,
		"totp_code": totp, "backup_code": backup,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return "", resp.StatusCode
	}
	out := decode[struct {
		CSRFToken string `json:"csrf_token"`
	}](h.t, resp)
	return out.CSRFToken, resp.StatusCode
}

func userIDByName(t *testing.T, h *harness, username string) string {
	t.Helper()
	resp := h.do(http.MethodGet, "/api/v1/users", nil, nil)
	list := decode[struct {
		Users []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"users"`
	}](t, resp)
	for _, u := range list.Users {
		if u.Username == username {
			return u.ID
		}
	}
	t.Fatalf("user %q not found", username)
	return ""
}

func TestMFASetupRequiresStepUp(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "kate", "kate-password-value123", "ANALYST")
	csrf, _ := h.login("kate", "kate-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}

	// A session alone cannot rotate the factor: the current password is required.
	resp := h.do(http.MethodPost, "/api/v1/auth/mfa/setup", nil, headers)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("setup without password = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "wrong-password-value"}, headers)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("setup with wrong password = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	setup := decode[struct {
		Secret string `json:"secret"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "kate-password-value123"}, headers))
	code, _ := mfa.CodeAt(setup.Secret, time.Now().UTC())
	enabled := decode[struct {
		BackupCodes []string `json:"backup_codes"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/enable",
		map[string]string{"code": code}, headers))
	if len(enabled.BackupCodes) != mfa.BackupCodeCount {
		t.Fatalf("backup codes = %d", len(enabled.BackupCodes))
	}

	// With MFA enabled, password alone is not enough to rotate it.
	resp = h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "kate-password-value123"}, headers)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("setup without current code = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// The enable code is spent; a step-up needs the next one.
	code, _ = mfa.CodeAt(setup.Secret, time.Now().UTC().Add(30*time.Second))
	resp = h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "kate-password-value123", "code": code}, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup with both factors = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestMFAEnableIsRateLimited(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "mona", "mona-password-value123", "ANALYST")
	csrf, _ := h.login("mona", "mona-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}
	h.do(http.MethodPost, "/api/v1/auth/mfa/setup",
		map[string]string{"password": "mona-password-value123"}, headers).Body.Close()

	var last int
	for i := 0; i < 15; i++ {
		resp := h.do(http.MethodPost, "/api/v1/auth/mfa/enable",
			map[string]string{"code": "000000"}, headers)
		last = resp.StatusCode
		resp.Body.Close()
		if last == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatalf("mfa enable guessing never throttled, last = %d", last)
}

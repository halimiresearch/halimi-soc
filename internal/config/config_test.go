package config_test

import (
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/config"
)

func TestDefaultLimitsAreBounded(t *testing.T) {
	l := config.DefaultLimits()
	if err := l.Validate(); err != nil {
		t.Fatalf("default limits are invalid: %v", err)
	}

	// Every bound must have a positive default below its maximum, otherwise the
	// "safe default plus hard maximum" contract is not actually enforced.
	checks := map[string]config.Limit{
		"http_body":       l.HTTPBodyBytes,
		"event_batch":     l.EventBatchSize,
		"event_field":     l.EventFieldBytes,
		"raw_line":        l.RawLineBytes,
		"multiline":       l.MultilineBufferBytes,
		"memory_queue":    l.MemoryQueueSize,
		"disk_spool":      l.DiskSpoolBytes,
		"db_rows":         l.DBResultRows,
		"page_size":       l.PageSize,
		"ai_context":      l.AIContextBytes,
		"ai_concurrent":   l.AIConcurrent,
		"sse_connections": l.SSEConnections,
		"event_retention": l.EventRetention,
		"raw_retention":   l.RawRetention,
	}
	for name, lim := range checks {
		if lim.Default <= 0 {
			t.Errorf("%s default = %d, want positive", name, lim.Default)
		}
		if lim.Max <= 0 {
			t.Errorf("%s max = %d, want positive", name, lim.Max)
		}
		if lim.Default > lim.Max {
			t.Errorf("%s default %d exceeds max %d", name, lim.Default, lim.Max)
		}
	}
}

func TestLimitResolveClampsToMax(t *testing.T) {
	l := config.Limit{Default: 100, Max: 200}

	// A configured value above the maximum must be clamped, not honoured: a typo
	// should never be able to remove a bound.
	t.Setenv("TEST_LIMIT", "100000")
	if got := l.Resolve("TEST_LIMIT"); got != 200 {
		t.Fatalf("Resolve() = %d, want the maximum 200", got)
	}

	t.Setenv("TEST_LIMIT", "150")
	if got := l.Resolve("TEST_LIMIT"); got != 150 {
		t.Fatalf("Resolve() = %d, want 150", got)
	}

	// Negative and unparseable values fall back to the default rather than
	// producing a negative or zero bound.
	for _, bad := range []string{"-5", "abc", ""} {
		t.Setenv("TEST_LIMIT", bad)
		if got := l.Resolve("TEST_LIMIT"); got != 100 {
			t.Errorf("Resolve(%q) = %d, want the default 100", bad, got)
		}
	}
}

func TestRawRetentionMustNotExceedEventRetention(t *testing.T) {
	l := config.DefaultLimits()
	l.RawRetention.Default = l.EventRetention.Default + 1
	if err := l.Validate(); err == nil {
		t.Fatal("raw retention exceeding event retention was accepted")
	}
}

func TestProductionRequiresSecureSettings(t *testing.T) {
	base := func() *config.Config {
		return &config.Config{
			Environment:       "production",
			ListenAddr:        "127.0.0.1:8080",
			SessionTTL:        time.Hour,
			ClockSkew:         5 * time.Minute,
			Retention:         config.DefaultLimits(),
			AdminPassword:     "a-sufficiently-long-password",
			AgentEnrollSecret: "a-sufficiently-long-enrollment-secret",
			SecureCookies:     true,
		}
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}

	noCookies := base()
	noCookies.SecureCookies = false
	if err := noCookies.Validate(); err == nil {
		t.Error("production without secure cookies was accepted")
	}

	noPassword := base()
	noPassword.AdminPassword = ""
	if err := noPassword.Validate(); err == nil {
		t.Error("production without an admin password was accepted")
	}

	shortSecret := base()
	shortSecret.AgentEnrollSecret = "too-short"
	if err := shortSecret.Validate(); err == nil {
		t.Error("production with a short enrollment secret was accepted")
	}

	// Development is allowed to be lax so the project runs out of the box.
	dev := base()
	dev.Environment = "development"
	dev.SecureCookies = false
	dev.AdminPassword = ""
	dev.AgentEnrollSecret = ""
	if err := dev.Validate(); err != nil {
		t.Errorf("development config rejected: %v", err)
	}
}

func TestInvalidCoreSettingsAreRejected(t *testing.T) {
	valid := func() *config.Config {
		return &config.Config{
			Environment: "development",
			ListenAddr:  "127.0.0.1:8080",
			SessionTTL:  time.Hour,
			ClockSkew:   5 * time.Minute,
			Retention:   config.DefaultLimits(),
		}
	}

	emptyAddr := valid()
	emptyAddr.ListenAddr = ""
	if err := emptyAddr.Validate(); err == nil {
		t.Error("empty listen address accepted")
	}

	shortTTL := valid()
	shortTTL.SessionTTL = time.Minute
	if err := shortTTL.Validate(); err == nil {
		t.Error("session ttl below the minimum accepted")
	}

	badSkew := valid()
	badSkew.ClockSkew = 2 * time.Hour
	if err := badSkew.Validate(); err == nil {
		t.Error("clock skew above the maximum accepted")
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Setenv("HALIMISOC_LISTEN_ADDR", "")
	t.Setenv("HALIMISOC_ENV", "")
	t.Setenv("HALIMISOC_DATABASE_URL", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.Environment != "development" {
		t.Errorf("environment = %q, want development", cfg.Environment)
	}
	if cfg.ListenAddr == "" {
		t.Error("listen address default was not applied")
	}
	if cfg.IsProduction() {
		t.Error("default environment must not be production")
	}
}

func TestPageBounds(t *testing.T) {
	l := config.DefaultLimits()
	def, max := l.PageBounds()
	if def <= 0 || max <= 0 {
		t.Fatalf("page bounds = %d/%d", def, max)
	}
	if def > max {
		t.Fatalf("default page size %d exceeds maximum %d", def, max)
	}
}

func TestLoadReadsAIAndWebhookSettings(t *testing.T) {
	t.Setenv("HALIMISOC_AI_BASE_URL", "http://127.0.0.1:11434/v1")
	t.Setenv("HALIMISOC_AI_API_KEY", "test-key")
	t.Setenv("HALIMISOC_AI_MODEL", "test-model")
	t.Setenv("HALIMISOC_WEBHOOK_URL", "https://hooks.example.test/soc")
	t.Setenv("HALIMISOC_WEBHOOK_TIMEOUT", "3s")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.AIBaseURL != "http://127.0.0.1:11434/v1" {
		t.Errorf("ai base url = %q", cfg.AIBaseURL)
	}
	if cfg.AIAPIKey != "test-key" || cfg.AIModel != "test-model" {
		t.Errorf("ai credentials = %q/%q", cfg.AIAPIKey, cfg.AIModel)
	}
	if cfg.WebhookURL != "https://hooks.example.test/soc" {
		t.Errorf("webhook url = %q", cfg.WebhookURL)
	}
	if cfg.WebhookTimeout != 3*time.Second {
		t.Errorf("webhook timeout = %s", cfg.WebhookTimeout)
	}
}

func TestInvalidWebhookURLFailsClosed(t *testing.T) {
	valid := func() *config.Config {
		return &config.Config{
			Environment: "development",
			ListenAddr:  "127.0.0.1:8080",
			SessionTTL:  time.Hour,
			ClockSkew:   5 * time.Minute,
			Retention:   config.DefaultLimits(),
		}
	}

	for _, bad := range []string{
		"ftp://example.test/hook",
		"https://user:pass@example.test/hook",
		"://missing-scheme",
	} {
		cfg := valid()
		cfg.WebhookURL = bad
		if err := cfg.Validate(); err == nil {
			t.Errorf("webhook url %q accepted", bad)
		}
	}

	cfg := valid()
	cfg.WebhookURL = "https://hooks.example.test/soc"
	cfg.WebhookTimeout = 5 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid webhook url rejected: %v", err)
	}
}

func TestSessionIdleBoundsAreEnforced(t *testing.T) {
	base := func() *config.Config {
		return &config.Config{
			Environment: "development",
			ListenAddr:  "127.0.0.1:8080",
			SessionTTL:  time.Hour,
			SessionIdle: 30 * time.Minute,
			ClockSkew:   5 * time.Minute,
			Retention:   config.DefaultLimits(),
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid idle rejected: %v", err)
	}

	short := base()
	short.SessionIdle = time.Minute
	if err := short.Validate(); err == nil {
		t.Error("idle below the minimum accepted")
	}

	// An idle window longer than the absolute TTL is dead configuration.
	long := base()
	long.SessionIdle = 2 * time.Hour
	if err := long.Validate(); err == nil {
		t.Error("idle exceeding ttl accepted")
	}
}

func TestWebAuthnOriginsFailClosedInProduction(t *testing.T) {
	base := func() *config.Config {
		return &config.Config{
			Environment:       "production",
			ListenAddr:        "127.0.0.1:8080",
			SessionTTL:        time.Hour,
			ClockSkew:         5 * time.Minute,
			Retention:         config.DefaultLimits(),
			AdminPassword:     "a-sufficiently-long-password",
			AgentEnrollSecret: "a-sufficiently-long-enrollment-secret",
			SecureCookies:     true,
			WebAuthnRPID:      "soc.example.test",
			WebAuthnOrigins:   []string{"https://soc.example.test"},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid production webauthn rejected: %v", err)
	}

	cleartext := base()
	cleartext.WebAuthnOrigins = []string{"http://soc.example.test"}
	if err := cleartext.Validate(); err == nil {
		t.Error("cleartext non-loopback origin accepted in production")
	}

	// Loopback http stays allowed for lab deployments.
	lab := base()
	lab.WebAuthnRPID = "127.0.0.1"
	lab.WebAuthnOrigins = []string{"http://127.0.0.1:3000"}
	if err := lab.Validate(); err != nil {
		t.Errorf("loopback origin rejected: %v", err)
	}

	bare := base()
	bare.WebAuthnRPID = "soc.example.test:3000"
	if err := bare.Validate(); err == nil {
		t.Error("rp id with port accepted")
	}
}

func TestLoadReadsSecureCookies(t *testing.T) {
	t.Setenv("HALIMISOC_ENV", "development")
	t.Setenv("HALIMISOC_SECURE_COOKIES", "true")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if !cfg.SecureCookies {
		t.Fatal("HALIMISOC_SECURE_COOKIES=true was not loaded")
	}
}

func TestLoadReadsHardeningSettings(t *testing.T) {
	t.Setenv("HALIMISOC_SESSION_IDLE", "90m")
	t.Setenv("HALIMISOC_METRICS_TOKEN", "metrics-token-value")
	t.Setenv("HALIMISOC_MFA_KEY", "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=")
	t.Setenv("HALIMISOC_WEBAUTHN_RP_ID", "soc.example.test")
	t.Setenv("HALIMISOC_WEBAUTHN_ORIGINS", "https://soc.example.test")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.SessionIdle != 90*time.Minute {
		t.Errorf("session idle = %s", cfg.SessionIdle)
	}
	if cfg.MetricsToken != "metrics-token-value" {
		t.Errorf("metrics token = %q", cfg.MetricsToken)
	}
	if cfg.MFAKeyRaw == "" {
		t.Error("mfa key not loaded")
	}
	if cfg.WebauthnConfig().RPID != "soc.example.test" {
		t.Errorf("rp id = %q", cfg.WebauthnConfig().RPID)
	}
	if len(cfg.WebauthnConfig().Origins) != 1 {
		t.Errorf("origins = %v", cfg.WebauthnConfig().Origins)
	}
}

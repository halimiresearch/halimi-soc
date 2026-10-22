package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/notify"
)

// Load reads configuration from the environment.
//
// Every value has a safe default, so an unconfigured process starts in a
// bounded, non-production mode rather than an unbounded one.
func Load() (*Config, error) {
	c := &Config{
		Environment:       env("HALIMISOC_ENV", "development"),
		ListenAddr:        env("HALIMISOC_LISTEN_ADDR", "127.0.0.1:8080"),
		DatabaseURL:       os.Getenv("HALIMISOC_DATABASE_URL"),
		Retention:         LimitsFromEnv(),
		SessionTTL:        envSeconds("HALIMISOC_SESSION_TTL", 12*time.Hour),
		SessionIdle:       envSeconds("HALIMISOC_SESSION_IDLE", 2*time.Hour),
		ClockSkew:         envSeconds("HALIMISOC_CLOCK_SKEW", 5*time.Minute),
		RulesPath:         env("HALIMISOC_RULES_PATH", "rules"),
		AdminUser:         env("HALIMISOC_ADMIN_USER", "admin"),
		AdminPassword:     os.Getenv("HALIMISOC_ADMIN_PASSWORD"),
		AgentEnrollSecret: os.Getenv("HALIMISOC_AGENT_ENROLL_SECRET"),
		AIBaseURL:         strings.TrimSpace(os.Getenv("HALIMISOC_AI_BASE_URL")),
		AIAPIKey:          strings.TrimSpace(os.Getenv("HALIMISOC_AI_API_KEY")),
		AIModel:           strings.TrimSpace(os.Getenv("HALIMISOC_AI_MODEL")),
		WebhookURL:        strings.TrimSpace(os.Getenv("HALIMISOC_WEBHOOK_URL")),
		WebhookSecret:     strings.TrimSpace(os.Getenv("HALIMISOC_WEBHOOK_SECRET")),
		WebhookTimeout:    envSeconds("HALIMISOC_WEBHOOK_TIMEOUT", 5*time.Second),
		MetricsToken:      strings.TrimSpace(os.Getenv("HALIMISOC_METRICS_TOKEN")),
		MFAKeyRaw:         strings.TrimSpace(os.Getenv("HALIMISOC_MFA_KEY")),
		WebAuthnRPID:      strings.TrimSpace(os.Getenv("HALIMISOC_WEBAUTHN_RP_ID")),
		WebAuthnRPName:    env("HALIMISOC_WEBAUTHN_RP_NAME", "HalimiSOC"),
		WebAuthnOrigins:   splitCSV(os.Getenv("HALIMISOC_WEBAUTHN_ORIGINS")),
		SecureCookies:     envBool("HALIMISOC_SECURE_COOKIES", false),
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Config is the fully resolved runtime configuration.
type Config struct {
	Environment string
	ListenAddr  string
	DatabaseURL string
	RulesPath   string

	AdminUser     string
	AdminPassword string

	// AgentEnrollSecret authorizes agent enrollment. It is intentionally
	// separate from the operator password: compromise of an agent must not
	// grant operator access, and vice versa.
	AgentEnrollSecret string

	SessionTTL time.Duration

	// SessionIdle bounds inactivity: a session unused longer than this is
	// treated as expired even when the absolute TTL has not elapsed. It bounds
	// the window in which a stolen cookie stays useful.
	SessionIdle time.Duration

	// AI settings. All optional: an empty APIKey and BaseURL mean AI is
	// disabled, which is a supported and fully functional mode.
	AIBaseURL string
	AIAPIKey  string
	AIModel   string

	// WebhookURL receives an incident.created POST per new incident. Empty
	// disables delivery. The payload carries incident scope only, never raw
	// evidence.
	WebhookURL string

	// WebhookSecret signs the body with HMAC-SHA256 when set. The receiver
	// verifies X-HalimiSOC-Signature. Empty disables signing; production
	// webhooks should set ≥16 chars.
	WebhookSecret string

	// MetricsToken guards /metrics with a bearer token when set. Empty leaves
	// /metrics unauthenticated (counters only) and the reverse proxy must
	// restrict it; production deployments should set it.
	MetricsToken string

	// MFAKeyRaw is base64 of 32 bytes used to encrypt TOTP secrets at rest
	// (AES-256-GCM). Empty stores secrets with a "plain:" prefix (dev only);
	// production with MFA enabled should set it. Parsed by internal/mfa.
	MFAKeyRaw string

	// WebAuthn RP settings. RPID is the effective domain (no port); Origins is
	// the exact allowlist of console origins. Defaults cover local dev over
	// http://127.0.0.1:3000 and http://localhost:3000; production must set
	// both to the real https origin.
	WebAuthnRPID    string
	WebAuthnRPName  string
	WebAuthnOrigins []string

	// WebhookTimeout bounds a single webhook delivery attempt.
	WebhookTimeout time.Duration

	// SecureCookies marks session cookies Secure and enables the __Host-
	// cookie prefix. It must be true whenever the API is served over TLS;
	// leaving it false on an HTTPS deployment silently weakens session
	// transport, so Validate refuses that combination in production.
	SecureCookies bool

	// ClockSkew is the accepted tolerance for agent event timestamps.
	ClockSkew time.Duration

	Retention Limits
}

// Validate enforces configuration invariants.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("listen address must not be empty")
	}
	if c.SessionTTL <= 5*time.Minute {
		return errors.New("session ttl must exceed 5 minutes")
	}
	// Default idle for hand-constructed configs (tests, embeds): Load() always
	// sets it, but a zero value here would otherwise fail closed on valid
	// fixtures that predate the field.
	if c.SessionIdle == 0 {
		c.SessionIdle = 2 * time.Hour
		if c.SessionTTL > 0 && c.SessionTTL < c.SessionIdle {
			c.SessionIdle = c.SessionTTL
		}
	}
	if c.SessionIdle <= 5*time.Minute {
		return errors.New("session idle must exceed 5 minutes")
	}
	if c.SessionIdle > c.SessionTTL {
		return errors.New("session idle must not exceed session ttl")
	}
	if c.ClockSkew <= 0 || c.ClockSkew > time.Hour {
		return errors.New("clock skew must be within (0, 1h]")
	}
	if err := c.Retention.Validate(); err != nil {
		return fmt.Errorf("retention limits: %w", err)
	}
	if c.IsProduction() && !c.SecureCookies {
		return errors.New("HALIMISOC_SECURE_COOKIES must be enabled in production")
	}
	if c.IsProduction() && c.AdminPassword == "" {
		return errors.New("HALIMISOC_ADMIN_PASSWORD is required in production")
	}
	if c.IsProduction() && len(c.AgentEnrollSecret) < 24 {
		return errors.New("HALIMISOC_AGENT_ENROLL_SECRET must be at least 24 characters in production")
	}
	if err := c.webhookOptions().Validate(); err != nil {
		return err
	}
	if err := c.webauthnConfig().Validate(); err != nil {
		return err
	}
	if c.IsProduction() {
		for _, o := range c.WebAuthnOrigins {
			if strings.HasPrefix(o, "http://") && !isLoopbackOrigin(o) {
				return fmt.Errorf("HALIMISOC_WEBAUTHN_ORIGINS must use https in production (got %q)", o)
			}
		}
	}
	return nil
}

// WebhookOptions resolves the notifier configuration from the loaded config.
func (c *Config) WebhookOptions() notify.Options {
	return notify.Options{
		URL:       c.WebhookURL,
		Secret:    c.WebhookSecret,
		Timeout:   c.WebhookTimeout,
		QueueSize: 64,
	}
}

func (c *Config) webhookOptions() notify.Options { return c.WebhookOptions() }

// WebauthnConfig resolves the WebAuthn RP config with dev defaults.
func (c *Config) WebauthnConfig() WebauthnConfig {
	rpID := strings.TrimSpace(c.WebAuthnRPID)
	if rpID == "" {
		rpID = "127.0.0.1"
	}
	origins := append([]string(nil), c.WebAuthnOrigins...)
	if len(origins) == 0 {
		origins = []string{"http://127.0.0.1:3000", "http://localhost:3000"}
	}
	name := strings.TrimSpace(c.WebAuthnRPName)
	if name == "" {
		name = "HalimiSOC"
	}
	return WebauthnConfig{RPID: rpID, RPName: name, Origins: origins}
}

// WebauthnConfig is the RP allowlist. Kept in config (not webauthn) so env
// parsing stays in one package; converted to webauthn.Config at wiring.
type WebauthnConfig struct {
	RPID    string
	RPName  string
	Origins []string
}

// Validate the RP config at startup (fail closed).
func (w WebauthnConfig) Validate() error {
	if strings.TrimSpace(w.RPID) == "" {
		return fmt.Errorf("webauthn: rp id is required")
	}
	if strings.Contains(w.RPID, ":") || strings.Contains(w.RPID, "/") {
		return fmt.Errorf("webauthn: rp id must be a bare host, got %q", w.RPID)
	}
	if len(w.Origins) == 0 {
		return fmt.Errorf("webauthn: at least one origin is required")
	}
	return nil
}

func (c *Config) webauthnConfig() WebauthnConfig { return c.WebauthnConfig() }

func isLoopbackOrigin(o string) bool {
	lower := strings.ToLower(strings.TrimSpace(o))
	for _, h := range []string{"://127.0.0.1", "://localhost", "://[::1]"} {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

func splitCSV(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// IsProduction reports whether strict secret requirements apply.
func (c *Config) IsProduction() bool {
	return strings.EqualFold(c.Environment, "production")
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envSeconds(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		return time.Duration(secs) * time.Second
	}
	return def
}

func envBool(key string, def bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

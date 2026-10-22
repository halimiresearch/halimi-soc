// Command api runs the HalimiSOC server.
//
// Startup is intentionally fail-closed: if a security-critical setting is
// missing or the database cannot be reached, the process exits rather than
// starting in a degraded mode that might accept telemetry while detecting
// nothing.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/halimi/halimisoc/internal/ai"
	"github.com/halimi/halimisoc/internal/api"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/config"
	"github.com/halimi/halimisoc/internal/correlation"
	"github.com/halimi/halimisoc/internal/detection/engine"
	"github.com/halimi/halimisoc/internal/detection/rules"
	"github.com/halimi/halimisoc/internal/detection/state"
	"github.com/halimi/halimisoc/internal/events/ingest"
	"github.com/halimi/halimisoc/internal/events/stream"
	"github.com/halimi/halimisoc/internal/events/validation"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/mfa"
	"github.com/halimi/halimisoc/internal/notify"
	"github.com/halimi/halimisoc/internal/storage"
	"github.com/halimi/halimisoc/internal/storage/memory"
	"github.com/halimi/halimisoc/internal/storage/postgres"
	"github.com/halimi/halimisoc/internal/webauthn"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("halimisoc", version)
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	mfaKey, err := mfa.ParseMFAKey(cfg.MFAKeyRaw)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	log := newLogger(cfg)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := openStore(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := bootstrap(ctx, cfg, store, log); err != nil {
		return err
	}

	ruleSet, err := rules.LoadDir(cfg.RulesPath)
	if err != nil {
		// Detection with zero rules would silently stop detecting while still
		// accepting telemetry, so this is fatal.
		return fmt.Errorf("load detection rules from %q: %w", cfg.RulesPath, err)
	}
	log.Info("detection rules loaded", "count", ruleSet.Len(), "path", cfg.RulesPath)

	reg := metrics.New()
	describeMetrics(reg)

	// The analyst and the hub are built before the server because the server
	// needs both, and neither needs the server.
	analyst, err := buildAnalyst(cfg, log)
	if err != nil {
		return err
	}

	hub := stream.NewHub(stream.Options{
		MaxSubscribers: int(cfg.Retention.SSEConnections.Default),
		Buffer:         stream.DefaultOptions().Buffer,
	})

	// Webhooks are advisory delivery: a misconfigured URL fails closed here
	// so the first incident does not discover it.
	notifier := notify.New(cfg.WebhookOptions())
	notifier.SetRegistry(reg)
	if notifier.Enabled() {
		log.Info("incident webhook enabled")
		if cfg.WebhookSecret == "" {
			log.Warn("webhook signing disabled: set HALIMISOC_WEBHOOK_SECRET so receivers can verify X-HalimiSOC-Signature")
		}
	}
	if cfg.MetricsToken == "" {
		log.Warn("metrics token unset: /metrics is unauthenticated, restrict it at the reverse proxy or set HALIMISOC_METRICS_TOKEN")
	}
	if len(mfaKey) == 0 {
		log.Warn("mfa key unset: TOTP secrets are stored with a plain: prefix; set HALIMISOC_MFA_KEY (base64 32 bytes) in production")
	} else if cfg.IsProduction() {
		log.Info("mfa at-rest encryption enabled")
	}

	validationOpts := validation.DefaultOptions()
	validationOpts.FieldBytes = int(cfg.Retention.EventFieldBytes.Default)
	validationOpts.RawBytes = int(cfg.Retention.RawLineBytes.Default)
	validationOpts.ClockSkew = cfg.ClockSkew

	detector := engine.New(ruleSet, state.New(state.DefaultOptions()), store, reg)
	correlator := correlation.NewEngine(store, reg)
	ingester := ingest.New(store, detector, correlator, validationOpts, reg, int(cfg.Retention.EventBatchSize.Default))

	server := api.New(api.Options{
		Store:         store,
		Ingester:      ingester,
		Detector:      detector,
		Hub:           hub,
		Notifier:      notifier,
		Limits:        cfg.Retention,
		SessionTTL:    cfg.SessionTTL,
		SessionIdle:   cfg.SessionIdle,
		ClockSkew:     cfg.ClockSkew,
		Logger:        log,
		Metrics:       reg,
		Analyst:       analyst,
		EnrollSecret:  cfg.AgentEnrollSecret,
		Version:       version,
		SecureCookies: cfg.SecureCookies,
		MetricsToken:  cfg.MetricsToken,
		MFAKey:        mfaKey,
		WebAuthn: webauthn.Config{
			RPID:    cfg.WebauthnConfig().RPID,
			RPName:  cfg.WebauthnConfig().RPName,
			Origins: cfg.WebauthnConfig().Origins,
		},
		RulesPath: cfg.RulesPath,
	})

	// The server is the publisher, so ingestion announces alerts and incidents
	// through it. The indirection keeps the ingest package free of any
	// dependency on the realtime wire format.
	ingester.SetPublisher(server)

	// Keepalive and session revalidation. The revalidator is the backstop for
	// revocation: even if a control event were lost, a revoked session still
	// terminates within one interval.
	go hub.RunKeepalive(ctx, 30*time.Second, func() map[string]any { return server.MetricsSnapshot(ctx) }, server.StreamSessionValidator())
	go notifier.Run(ctx)

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: server.Handler(),
		// Timeouts bound how long a slow or malicious client can hold a
		// connection. Without them a handful of sockets can exhaust the server.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go maintain(ctx, store, detector, cfg, log)
	go func() {
		log.Info("halimisoc api listening", "addr", cfg.ListenAddr, "version", version, "env", cfg.Environment)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server stopped", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}

func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	if v := strings.TrimSpace(os.Getenv("HALIMISOC_LOG_LEVEL")); v != "" {
		var parsed slog.Level
		if err := parsed.UnmarshalText([]byte(v)); err == nil {
			level = parsed
		}
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}

func openStore(ctx context.Context, cfg *config.Config, log *slog.Logger) (storage.Store, error) {
	allowMemory := strings.EqualFold(strings.TrimSpace(os.Getenv("HALIMISOC_ALLOW_MEMORY_STORE")), "true")
	if cfg.DatabaseURL == "" {
		if !allowMemory {
			return nil, errors.New("HALIMISOC_DATABASE_URL is required (set HALIMISOC_ALLOW_MEMORY_STORE=true only for local demos)")
		}
		log.Warn("using in-memory storage: data is not durable and is lost on restart")
		return memory.New(), nil
	}

	store, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	migrations, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("open migrations: %w", err)
	}
	if err := postgres.Migrate(ctx, store, migrations); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

// bootstrap creates the initial administrator when no account exists.
//
// It refuses to invent a password. A shipped default credential is the single
// most common way a self-hosted security tool is compromised, so the operator
// must supply one and the process fails closed without it.
//
// Recovery: if every administrator is disabled (or none exists) the process
// creates a new admin from HALIMISOC_ADMIN_PASSWORD instead of leaving the
// deployment permanently locked out. This is break-glass, not a backdoor: it
// still requires the operator-controlled env secret and is audited.
func bootstrap(ctx context.Context, cfg *config.Config, store storage.Store, log *slog.Logger) error {
	users, err := store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	for _, u := range users {
		if u.Role == authorization.RoleAdmin && u.Active() {
			return nil
		}
	}
	if len(users) > 0 {
		log.Warn("no active administrator remains; bootstrap will create a recovery admin")
	}

	if cfg.AdminPassword == "" {
		return errors.New("no operator accounts exist and HALIMISOC_ADMIN_PASSWORD is not set; " +
			"set it to create the initial admin account")
	}
	if len(cfg.AdminPassword) < auth.MinPasswordLength {
		return errors.New("HALIMISOC_ADMIN_PASSWORD must be at least 12 characters")
	}
	if len(cfg.AdminPassword) > auth.MaxPasswordLength {
		return errors.New("HALIMISOC_ADMIN_PASSWORD must not exceed 128 characters")
	}

	hash, err := auth.HashPassword(cfg.AdminPassword)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	now := time.Now().UTC()
	admin := &auth.User{
		ID:           id.New(id.KindUser),
		Username:     strings.ToLower(cfg.AdminUser),
		PasswordHash: hash,
		Role:         authorization.RoleAdmin,
		CreatedAt:    now,
	}
	if err := store.SaveUser(ctx, admin); err != nil {
		return fmt.Errorf("create admin account: %w", err)
	}
	if err := store.AppendAudit(ctx, &audit.Entry{
		ID:        id.New(id.KindAudit),
		Actor:     audit.ActorRef(audit.ActorSystem, "bootstrap"),
		Action:    audit.ActionBootstrapAdmin,
		Resource:  "user",
		Result:    audit.ResultSuccess,
		Timestamp: now,
		Detail:    "initial administrator created",
	}); err != nil {
		log.Warn("bootstrap audit failed", "error", err)
	}
	log.Info("initial administrator created", "username", admin.Username)
	return nil
}

// maintenancePruner is the detection state cleanup used by retention.
type maintenancePruner interface {
	Prune(now time.Time)
}

// maintain runs periodic retention and cleanup work.
func maintain(ctx context.Context, store storage.Store, pruner maintenancePruner, cfg *config.Config, log *slog.Logger) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	runMaintenance(ctx, store, pruner, cfg, log)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runMaintenance(ctx, store, pruner, cfg, log)
		}
	}
}

// runMaintenance performs one retention pass. Raw evidence expires first;
// events, alerts and audit rows share the longer event window. Incidents are kept.
func runMaintenance(ctx context.Context, store storage.Store, pruner maintenancePruner, cfg *config.Config, log *slog.Logger) {
	now := time.Now().UTC()

	rawCutoff := now.Add(-time.Duration(cfg.Retention.RawRetention.Default) * time.Hour)
	if purged, err := store.PurgeRawEvidence(ctx, rawCutoff); err != nil {
		log.Error("raw evidence retention failed", "error", err)
	} else if purged > 0 {
		// Only the raw line is dropped; the structured event and its references stay valid.
		log.Info("raw evidence expired", "events", purged)
	}

	eventCutoff := now.Add(-time.Duration(cfg.Retention.EventRetention.Default) * time.Hour)
	if purged, err := store.PurgeEvents(ctx, eventCutoff); err != nil {
		log.Error("event retention failed", "error", err)
	} else if purged > 0 {
		log.Info("events expired", "count", purged)
	}
	if purged, err := store.PurgeAlerts(ctx, eventCutoff); err != nil {
		log.Error("alert retention failed", "error", err)
	} else if purged > 0 {
		log.Info("alerts expired", "count", purged)
	}
	if purged, err := store.PurgeAudit(ctx, eventCutoff); err != nil {
		log.Error("audit retention failed", "error", err)
	} else if purged > 0 {
		log.Info("audit records expired", "count", purged)
	}

	if pruner != nil {
		pruner.Prune(now)
	}

	if removed, err := store.DeleteExpiredSessions(ctx, now); err != nil {
		log.Error("session cleanup failed", "error", err)
	} else if removed > 0 {
		log.Info("expired sessions removed", "count", removed)
	}
}

func describeMetrics(reg *metrics.Registry) {
	reg.Describe(metrics.EventsReceivedTotal, "Events received from agents")
	reg.Describe(metrics.EventsProcessedTotal, "Events persisted and processed by detection")
	reg.Describe(metrics.EventsDroppedTotal, "Events rejected during validation")
	reg.Describe(metrics.EventsDuplicateTotal, "Idempotent replay duplicates suppressed")
	reg.Describe(metrics.DetectionTotal, "Alerts produced by deterministic detection")
	reg.Describe(metrics.DetectionSuppressedTotal, "Alerts suppressed by cooldown (still correlated)")
	reg.Describe(metrics.IncidentCreatedTotal, "Incidents created by correlation")
	reg.Describe(metrics.WebhookSentTotal, "Incident webhooks delivered")
	reg.Describe(metrics.WebhookErrorTotal, "Incident webhook delivery failures")
	reg.Describe(metrics.WebhookDroppedTotal, "Incident webhooks dropped on a full queue")
	reg.Describe(metrics.CorrelationMergeTotal, "Alerts merged into an existing incident")
	reg.Describe(metrics.AgentLastHeartbeat, "Unix time of the most recent agent heartbeat")
	reg.Describe(metrics.DetectionStateSize, "Tracked detection windows")
	reg.Describe(metrics.AIRequestsTotal, "AI analysis requests (throttled quota)")
	reg.Describe(metrics.AIRateLimitedTotal, "AI analysis requests rejected at the quota")
	reg.Describe(metrics.EnrollRateLimitedTotal, "Agent enrollment attempts rejected at the quota")
	reg.Describe(metrics.ClockSkewAnomalyTotal, "Old/future timestamp anomalies (old>24h marked timestamp_old)")
}

// buildAnalyst constructs the optional AI analyst.
//
// No provider is configured by default and the process starts happily without
// one. That is the point of ADR-004: every detection, correlation and
// investigation feature must work with AI absent, so a missing credential is a
// normal state rather than a misconfiguration.
func buildAnalyst(cfg *config.Config, log *slog.Logger) (*ai.Analyst, error) {
	if cfg.AIAPIKey == "" && cfg.AIBaseURL == "" {
		log.Info("ai analyst disabled: no provider configured")
		return ai.New(ai.Options{}), nil
	}

	provider, err := ai.NewOpenAICompatibleProvider(ai.ProviderOptions{
		Name:      "openai-compatible",
		BaseURL:   cfg.AIBaseURL,
		APIKey:    cfg.AIAPIKey,
		Model:     cfg.AIModel,
		MaxTokens: int(cfg.Retention.AIContextBytes.Default / 64),
	})
	if err != nil {
		// A half-configured provider is a mistake worth surfacing at startup
		// rather than discovering when an analyst clicks "explain".
		return nil, fmt.Errorf("configure ai provider: %w", err)
	}
	log.Info("ai analyst enabled", "model", cfg.AIModel, "base_url", cfg.AIBaseURL)

	return ai.New(ai.Options{
		Provider:         provider,
		MaxResponseBytes: int(cfg.Retention.AIContextBytes.Default),
		MaxConcurrent:    int(cfg.Retention.AIConcurrent.Default),
	}), nil
}

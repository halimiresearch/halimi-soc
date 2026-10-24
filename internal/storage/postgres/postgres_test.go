// Package postgres_test verifies the production Store against a real database.
//
// These tests are skipped unless HALIMISOC_TEST_DATABASE_URL is set, following
// the same rule as the black-box suite: a test that needs a database must
// never fail in an environment that does not have one. The truncate guard
// mirrors tests/reset_test.go — the database name must end in _test, so a
// wrong connection string cannot destroy real telemetry.
package postgres_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/storage/postgres"
	"github.com/halimi/halimisoc/internal/webauthn"
)

// migrationsFS reads the same migration files the server embeds, so the test
// verifies the real upgrade path rather than a copy of it.
var migrationsFS = os.DirFS("../../../apps/api/migrations")

func requireTestStore(t *testing.T) (*postgres.Store, *pgx.Conn, context.Context) {
	t.Helper()
	dsn := os.Getenv("HALIMISOC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set HALIMISOC_TEST_DATABASE_URL to run the PostgreSQL contract tests")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test dsn: %v", err)
	}
	if !strings.HasSuffix(cfg.Database, "_test") {
		t.Fatalf("refusing to test against database %q: the name must end in _test", cfg.Database)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(ctx) })

	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := postgres.Migrate(ctx, store, migrationsFS); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}

	if _, err := admin.Exec(ctx,
		`TRUNCATE TABLE audit_logs, incidents, alerts, events, agent_tokens, agents, sessions, passkeys, users RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate test tables: %v", err)
	}
	return store, admin, ctx
}

func TestMigrationsApplyFromEmpty(t *testing.T) {
	_, admin, ctx := requireTestStore(t)

	rows, err := admin.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	defer rows.Close()
	var versions []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"0001_init.sql", "0002_incident_lifecycle.sql", "0003_incident_source_ips.sql", "0004_mfa.sql", "0005_passkeys.sql", "0006_totp_last_step.sql"} {
		found := false
		for _, v := range versions {
			if v == want {
				found = true
			}
		}
		if !found {
			t.Errorf("migration %s not applied (have %v)", want, versions)
		}
	}

	// The 0003 column must exist: the incident write path selects it.
	var hasColumn bool
	if err := admin.QueryRow(ctx, `
		SELECT count(*) > 0 FROM information_schema.columns
		WHERE table_name = 'incidents' AND column_name = 'source_ips'`).Scan(&hasColumn); err != nil {
		t.Fatal(err)
	}
	if !hasColumn {
		t.Fatal("incidents.source_ips column is missing")
	}

	// The 0004 columns must exist: the user write path selects them.
	for _, col := range []string{"totp_secret", "totp_enabled", "totp_enrolled_at", "backup_codes", "totp_last_step"} {
		var has bool
		if err := admin.QueryRow(ctx, `
			SELECT count(*) > 0 FROM information_schema.columns
			WHERE table_name = 'users' AND column_name = $1`, col).Scan(&has); err != nil {
			t.Fatal(err)
		}
		if !has {
			t.Fatalf("users.%s column is missing", col)
		}
	}

	// The 0005 table must exist: the passkey write path needs it.
	var hasTable bool
	if err := admin.QueryRow(ctx, `
		SELECT count(*) > 0 FROM information_schema.tables
		WHERE table_name = 'passkeys'`).Scan(&hasTable); err != nil {
		t.Fatal(err)
	}
	if !hasTable {
		t.Fatal("passkeys table is missing")
	}
}

func TestPostgresIncidentSourceIPsRoundTrip(t *testing.T) {
	store, _, ctx := requireTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	inc := &incidents.Incident{
		ID: "inc_test1", Title: "t", Summary: "s",
		Severity: model.SeverityHigh, Status: incidents.StatusNew,
		Hosts: []string{"web-01"}, Actors: []string{"root"}, SourceIPs: []string{"203.0.113.7"},
		AlertIDs: []string{"alt_1"}, EventIDs: []string{"evt_1"},
		Stages:    []incidents.Stage{{Name: incidents.StageCredentialAccess, AlertID: "alt_1", RuleID: "ssh-bruteforce", At: now, Severity: model.SeverityHigh}},
		FirstSeen: now, LastSeen: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.SaveIncident(ctx, inc); err != nil {
		t.Fatalf("save incident: %v", err)
	}
	got, err := store.GetIncident(ctx, "inc_test1")
	if err != nil {
		t.Fatalf("get incident: %v", err)
	}
	if len(got.SourceIPs) != 1 || got.SourceIPs[0] != "203.0.113.7" {
		t.Fatalf("source_ips = %v, want [203.0.113.7]", got.SourceIPs)
	}
}

func TestPostgresListUsers(t *testing.T) {
	store, _, ctx := requireTestStore(t)
	now := time.Now().UTC()

	for _, u := range []auth.User{
		{ID: "usr_b", Username: "bob", PasswordHash: "x", Role: authorization.RoleAnalyst, CreatedAt: now},
		{ID: "usr_a", Username: "admin", PasswordHash: "x", Role: authorization.RoleAdmin, CreatedAt: now},
	} {
		u := u
		if err := store.SaveUser(ctx, &u); err != nil {
			t.Fatalf("save user: %v", err)
		}
	}
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 2 || users[0].Username != "admin" || users[1].Username != "bob" {
		t.Fatalf("users not ordered by username: %+v", users)
	}
}

func TestPostgresUserMFAAndPasskeyRoundTrip(t *testing.T) {
	store, _, ctx := requireTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	// A user with MFA material must round-trip through both stores identically:
	// this is the parity check against the memory implementation.
	u := &auth.User{
		ID: "usr_mfa", Username: "mfa-user", PasswordHash: "x",
		Role: authorization.RoleAnalyst, CreatedAt: now,
		TOTPSecret: "v1:nonce:ct", TOTPEnabled: true,
		BackupHashes: []string{"h1", "h2"}, TOTPLastStep: 42,
	}
	enrolled := now
	u.TOTPEnrolledAt = &enrolled
	if err := store.SaveUser(ctx, u); err != nil {
		t.Fatalf("save user: %v", err)
	}
	got, err := store.GetUser(ctx, "usr_mfa")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if !got.TOTPEnabled || got.TOTPSecret != "v1:nonce:ct" {
		t.Fatalf("mfa fields = %v/%q", got.TOTPEnabled, got.TOTPSecret)
	}
	if len(got.BackupHashes) != 2 || got.BackupHashes[0] != "h1" {
		t.Fatalf("backup hashes = %v", got.BackupHashes)
	}
	if got.TOTPEnrolledAt == nil {
		t.Fatal("mfa enrolled_at did not round-trip")
	}
	if got.TOTPLastStep != 42 {
		t.Fatalf("totp_last_step = %d, want 42", got.TOTPLastStep)
	}

	// A code is single-use: the accepted step and anything older must fail.
	if ok, err := store.AdvanceTOTPStep(ctx, "usr_mfa", 42); err != nil || ok {
		t.Fatalf("replayed step = %v (err %v), want false", ok, err)
	}
	if ok, err := store.AdvanceTOTPStep(ctx, "usr_mfa", 43); err != nil || !ok {
		t.Fatalf("newer step = %v (err %v), want true", ok, err)
	}
	if ok, err := store.AdvanceTOTPStep(ctx, "usr_mfa", 43); err != nil || ok {
		t.Fatalf("reused step = %v (err %v), want false", ok, err)
	}

	pk := &webauthn.Passkey{
		ID: "pk_1", UserID: "usr_mfa", CredentialID: "cred-wire-1",
		PublicKey: "cose-blob", SignCount: 0, Transports: []string{"internal"},
		Name: "laptop", CreatedAt: now,
	}
	if err := store.SavePasskey(ctx, pk); err != nil {
		t.Fatalf("save passkey: %v", err)
	}
	// The wire credential id is globally unique: a second row conflicts.
	dup := &webauthn.Passkey{
		ID: "pk_2", UserID: "usr_mfa", CredentialID: "cred-wire-1",
		PublicKey: "cose-blob", CreatedAt: now,
	}
	if err := store.SavePasskey(ctx, dup); err == nil {
		t.Fatal("duplicate credential id accepted")
	}

	byID, err := store.GetPasskeyByCredentialID(ctx, "cred-wire-1")
	if err != nil {
		t.Fatalf("get passkey: %v", err)
	}
	if byID.UserID != "usr_mfa" {
		t.Fatalf("owner = %q", byID.UserID)
	}
	list, err := store.ListPasskeysByUser(ctx, "usr_mfa")
	if err != nil {
		t.Fatalf("list passkeys: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("passkeys = %d, want 1", len(list))
	}
	if err := store.UpdatePasskeyCounter(ctx, "pk_1", 9, now); err != nil {
		t.Fatalf("update counter: %v", err)
	}
	after, err := store.GetPasskeyByCredentialID(ctx, "cred-wire-1")
	if err != nil {
		t.Fatal(err)
	}
	if after.SignCount != 9 || after.LastUsedAt == nil {
		t.Fatalf("counter = %d/%v", after.SignCount, after.LastUsedAt)
	}
	if err := store.DeletePasskey(ctx, "pk_1"); err != nil {
		t.Fatalf("delete passkey: %v", err)
	}
	if _, err := store.GetPasskeyByCredentialID(ctx, "cred-wire-1"); err == nil {
		t.Fatal("deleted passkey still resolvable")
	}
}

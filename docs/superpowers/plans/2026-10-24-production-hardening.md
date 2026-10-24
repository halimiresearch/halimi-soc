# Production Hardening Batch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close six production-readiness gaps found by the 2026-10-24 audit: TLS wiring, release path, agent operability, metrics histograms, console pagination and error states, and TOTP replay protection.

**Architecture:** Each task is independent and shipped as its own commit. Deploy tasks edit compose/workflow/manifests; Go tasks add behavior behind the existing store and metrics contracts; the console task stays server-rendered and adds no client-side data layer.

**Tech Stack:** Go 1.x (stdlib only), PostgreSQL 18, Next.js 16 App Router, Docker Compose, GitHub Actions, Caddy.

**Spec:** `docs/AUDIT-KEKURANGAN.md` (2026-10-13) plus the 2026-10-24 audit in chat. Where the old document and the code disagree, the code wins; items already fixed are not repeated here.

## Global Constraints

- Go: `gofmt` clean, `go vet` clean, `go test ./...` green. No new Go dependencies.
- Every new bound lives in `internal/config/limits.go`; no unbounded buffer, page or field.
- Untrusted input is validated once: `internal/events/validation`. Nothing from a feed or request body is interpolated raw.
- Console: strict TypeScript, no `any`, no new production npm dependencies.
- Applied migrations are immutable. New schema goes in a new file numbered above `0005_passkeys.sql`.
- Comments explain why, one or two lines. No separator banners, no restated code.
- English in code, comments, docs and commits.

## Review Focus

- Replayed TOTP code inside the ±1 step window: a code that authenticated once must fail the second time, including the code used to enable MFA.
- Agent restart after enrollment with no `-token`: it must authenticate from the persisted token rather than re-enrolling or exiting.
- Private CA with a hostname mismatch or unreadable PEM: startup must fail loudly, never fall back to the system pool silently.
- Histogram label cardinality and cumulative bucket math: a metric that grows per request path is a leak.
- Console cursor links: filters and cursor must survive the round trip, and a stale cursor must show the API error rather than an empty list.

---

### Task 1: Wire TLS termination into the stack

**Files:**
- Modify: `deploy/docker-compose.yml`
- Modify: `deploy/configs/Caddyfile`
- Modify: `.env.example`
- Modify: `docs/security/configuration.md`

**Interfaces:**
- Produces: `caddy` compose service; `HALIMISOC_SITE_ADDRESS` environment variable consumed by the Caddyfile.

- [ ] **Step 1: Add the site-address variable to the Caddyfile**

Replace the literal site block with `{$HALIMISOC_SITE_ADDRESS:halimisoc.example.test} {` and keep every directive inside it. Caddy reads the variable from the container environment; the default keeps `caddy validate` usable without a real domain.

- [ ] **Step 2: Add the service to `deploy/docker-compose.yml`**

```yaml
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    depends_on:
      - web
    environment:
      HALIMISOC_SITE_ADDRESS: ${HALIMISOC_SITE_ADDRESS:?set HALIMISOC_SITE_ADDRESS}
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./configs/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    security_opt:
      - no-new-privileges:true
```

Declare `caddy-data` and `caddy-config` under `volumes:`. Leave the `web` and `api` loopback publishes in place: the proxy is the only listener on a public interface.

- [ ] **Step 3: Document the variable**

Add `HALIMISOC_SITE_ADDRESS=soc.example.test` to `.env.example` under a `--- Deployment ---` heading, with one line stating it is the Caddy site address and that an IP address cannot obtain a public certificate.

- [ ] **Step 4: Update the reverse-proxy section of `docs/security/configuration.md`**

State that `docker compose up -d` starts Caddy, that ports 8080 and 3000 stay on loopback, and that HSTS stays commented out until the first successful certificate issuance.

- [ ] **Step 5: Verify**

Run: `docker compose -f deploy/docker-compose.yml --env-file .env.example config --quiet`
If Docker is unavailable: `python3 -c "import yaml,sys; yaml.safe_load(open('deploy/docker-compose.yml'))"`.
Expected: exit 0 with the `caddy` service present.

- [ ] **Step 6: Commit**

```bash
git add deploy/docker-compose.yml deploy/configs/Caddyfile .env.example docs/security/configuration.md
git commit -m "deploy: serve the console through Caddy instead of leaving TLS unowned"
```

---

### Task 2: Publish release images and ship the agent unit

**Files:**
- Create: `.github/workflows/release.yml`
- Create: `deploy/systemd/halimisoc-agent.service`
- Create: `docs/operations/upgrade.md`
- Modify: `README.md`

**Interfaces:**
- Produces: tagged images `ghcr.io/<owner>/<repo>-{api,agent,web}:<tag>`; a systemd unit that runs the agent from `/usr/local/bin/halimisoc-agent`.

- [ ] **Step 1: Write the release workflow**

Trigger on `push: tags: ['v*']`, permissions `contents: read, packages: write`, one job that logs in with `docker/login-action@v3` (`registry: ghcr.io`, `username: ${{ github.actor }}`, `password: ${{ secrets.GITHUB_TOKEN }}`) and builds the three Dockerfiles with `docker/build-push-action@v6`, pushing `:${{ github.ref_name }}` and `:latest`. Pass `VERSION=${{ github.ref_name }}` as a build arg. Do not rebuild tests here; CI already gates `main`.

- [ ] **Step 2: Write the unit file**

```ini
[Unit]
Description=HalimiSOC collection agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/halimisoc-agent -file /var/log/auth.log -state-dir /var/lib/halimisoc -spool-dir /var/lib/halimisoc/spool
EnvironmentFile=/etc/halimisoc/agent.env
Restart=on-failure
RestartSec=5s
StateDirectory=halimisoc
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/var/log
ReadWritePaths=/var/lib/halimisoc

[Install]
WantedBy=multi-user.target
```

`EnvironmentFile` carries `HALIMISOC_SERVER` and `HALIMISOC_ENROLL_TOKEN` for first boot; after enrollment the token file in the state directory is used.

- [ ] **Step 3: Write the upgrade guide**

Cover: pull the new tag, `docker compose up -d` (the API applies embedded migrations at startup, `apps/api/main.go:263`), the agent spool survives because it lives in `StateDirectory`, and rollback requires restoring the database backup taken before the upgrade (backup tooling is out of scope for this batch; say so plainly).

- [ ] **Step 4: Add the release and upgrade pointers to `README.md`**

Two lines under the deployment section. No capability that does not exist.

- [ ] **Step 5: Verify**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`.
Run: `systemd-analyze verify deploy/systemd/halimisoc-agent.service` if available; otherwise confirm the unit parses with `systemd-analyze` absent and state that in the commit note.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/release.yml deploy/systemd/halimisoc-agent.service docs/operations/upgrade.md README.md
git commit -m "release: publish tagged images and give the agent a supervised install"
```

---

### Task 3: Make the agent operable across restarts and private CAs

**Files:**
- Modify: `apps/agent/main.go`
- Modify: `apps/agent/client.go`
- Modify: `apps/agent/producer.go`
- Modify: `apps/agent/sender.go`
- Test: `apps/agent/token_test.go` (new), `apps/agent/client_test.go` (extend), `apps/agent/shutdown_test.go` (existing pattern)

**Interfaces:**
- Produces: `func loadToken(dir string) (string, error)`, `func saveToken(dir, token string) error`, `options.caCert string`, `options.tokenPath string`.
- Produces: `newClient` returns an error when the CA file cannot be loaded: `func newClient(opts options, log *slog.Logger) (*client, error)`. Every call site is in `main.go` and tests.

- [ ] **Step 1: Write the failing token-persistence test**

```go
func TestTokenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	if err := saveToken(dir, "agt_test-token"); err != nil {
		t.Fatal(err)
	}
	got, err := loadToken(dir)
	if err != nil || got != "agt_test-token" {
		t.Fatalf("loadToken = %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, "token"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("token mode = %o, want 600", perm)
	}
}
```

- [ ] **Step 2: Run it and confirm failure**

Run: `go test ./apps/agent -run TestTokenSurvivesRestart`
Expected: FAIL, `undefined: saveToken`.

- [ ] **Step 3: Implement token persistence**

`saveToken` writes to `dir/token.tmp` with `0o600`, `Sync`, then `os.Rename`. `loadToken` returns `""` and no error when the file is absent. In `run()`, resolve the token in this order: flag/env, token file, enrollment. After enrollment, persist before the first send. Create the state directory with `0o700`.

- [ ] **Step 4: Write the failing CA test**

```go
func TestCAFileIsRequiredWhenSet(t *testing.T) {
	_, err := newClient(options{server: "https://example.test", caCert: filepath.Join(t.TempDir(), "missing.pem")}, slog.Default())
	if err == nil {
		t.Fatal("missing CA file must fail startup")
	}
}
```

- [ ] **Step 5: Implement `-ca-cert`**

Add `flag.StringVar(&opts.caCert, "ca-cert", os.Getenv("HALIMISOC_CA_CERT"), ...)`. In `newClient`, when `caCert` is set, read the PEM, start from `x509.SystemCertPool()`, `AppendCertsFromPEM`, and install `&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}` on the transport. Return the error, do not log and continue.

- [ ] **Step 6: Report real queue depth**

Add `queued atomic.Int64` to `producer`; add `len(events)` when a batch enters the channel and subtract when the sender dequeues it or the shutdown drain spools it. Pass `p.queued.Load()` into `heartbeatLoop` and send that instead of `int64(opts.queueSize)`. Keep `spool_bytes` as the disk signal.

- [ ] **Step 7: Run the agent suite**

Run: `go test ./apps/agent -race -count=1`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add apps/agent
git commit -m "agent: keep its credential, trust a private CA, and report real backlog"
```

---

### Task 4: Add histograms for request and ingestion latency

**Files:**
- Modify: `internal/metrics/metrics.go`
- Modify: `internal/api/server.go`
- Modify: `internal/events/ingest/ingest.go`
- Modify: `apps/api/main.go`
- Test: `internal/metrics/metrics_test.go`, `internal/events/ingest/ingest_test.go`

**Interfaces:**
- Produces: `func (r *Registry) Histogram(name, help string, buckets []float64)`.
- Produces: `func (r *Registry) Observe(name string, v float64, labels ...Label)`.
- Produces: metric names `HTTPRequestDuration = "http_request_duration_seconds"`, `IngestBatchDuration = "ingest_batch_duration_seconds"`.

- [ ] **Step 1: Write the failing rendering test**

```go
func TestHistogramRendersCumulativeBuckets(t *testing.T) {
	r := New()
	r.Histogram("op_duration_seconds", "help", []float64{0.1, 1})
	r.Observe("op_duration_seconds", 0.05)
	r.Observe("op_duration_seconds", 0.5)
	var b strings.Builder
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`op_duration_seconds_bucket{le="0.1"} 1`,
		`op_duration_seconds_bucket{le="1"} 2`,
		`op_duration_seconds_bucket{le="+Inf"} 2`,
		`op_duration_seconds_sum 0.55`,
		`op_duration_seconds_count 2`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
```

- [ ] **Step 2: Run it and confirm failure**

Run: `go test ./internal/metrics -run TestHistogramRendersCumulativeBuckets`
Expected: FAIL, `Histogram` undefined.

- [ ] **Step 3: Implement the histogram**

Store per-series `count`, `sum`, and per-bucket counts in a `map[string]*histogram`, guarded by the existing mutex. Buckets are sorted and copied at registration; an observation above the last bucket only lands in `+Inf`. Render `_bucket` lines first, then `_sum` and `_count`, matching the existing sorted output. Unknown metric names are ignored rather than created, so a typo cannot mint a series.

- [ ] **Step 4: Write the failing wiring test**

In `ingest_test.go`, assert that a successful `Ingest` call leaves `IngestBatchDuration_count` at 1 in the registry's Prometheus output.

- [ ] **Step 5: Wire both histograms**

Register in `apps/api/main.go` beside the existing `Describe` calls: HTTP buckets `{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}` and ingest buckets `{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1}`. In `requestLog`, observe `time.Since(start).Seconds()` after the handler returns. In `Ingest`, observe the same around the batch. Label the HTTP series by method only, never by path: an unbounded label is a cardinality leak.

- [ ] **Step 6: Run the suites**

Run: `go test ./internal/metrics ./internal/events/ingest ./internal/api -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/metrics internal/api/server.go internal/events/ingest apps/api/main.go
git commit -m "metrics: expose latency distribution instead of a single gauge"
```

---

### Task 5: Make the console page correctly and tell the truth about failures

**Files:**
- Modify: `apps/web/src/app/events/page.tsx`
- Modify: `apps/web/src/app/alerts/page.tsx`
- Modify: `apps/web/src/app/settings/page.tsx`
- Test: `apps/web/tests/e2e/` (extend the existing spec set)

**Interfaces:**
- Consumes: `next_cursor` from `EventPage` and `AlertPage`.

- [ ] **Step 1: Add cursor navigation to the alerts page**

Read `cursor?: string` from `SearchParams`, pass it to `listAlerts`, and render an "Older alerts" link below the table when `page.next_cursor` is set. Build the href from the current filters plus `cursor`; omit empty filters. Add a "Newest" link that drops the cursor. No client component.

- [ ] **Step 2: Do the same for the events page**

Same pattern, "Older events" and "Newest".

- [ ] **Step 3: Fix the settings page error state**

Replace the two silent `catch` blocks with one failed flag. On failure render `<ErrorBanner error={error} />` above the cards and do not render `MfaSettings` or `PasskeySettings`: an API outage must not read as "MFA disabled". Keep the successful path unchanged.

- [ ] **Step 4: Verify**

Run: `cd apps/web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/app
git commit -m "console: reach older pages and stop reporting an API failure as a security state"
```

Dropped from the original item: ESLint. `tsc --noEmit` already gates the console, and adding a linter means new dev dependencies for no behavior change. Say so in the final report.

---

### Task 6: Reject a replayed TOTP code

**Files:**
- Create: `apps/api/migrations/0006_totp_last_step.sql`
- Modify: `internal/mfa/mfa.go`
- Modify: `internal/auth/session.go`
- Modify: `internal/storage/store.go`
- Modify: `internal/storage/postgres/queries.go`
- Modify: `internal/storage/memory/memory.go`
- Modify: `internal/api/handlers_mfa.go`
- Test: `internal/mfa/mfa_test.go`, `internal/storage/memory/memory_test.go`, `internal/api/handlers_mfa_test.go`

**Interfaces:**
- Produces: `func Verify(secret, code string, now time.Time) (uint64, error)` returning the matched time step.
- Produces: `Store.AdvanceTOTPStep(ctx context.Context, userID string, step uint64) (bool, error)`; true means the step was newer and is now recorded.
- Produces: `auth.User.TOTPLastStep uint64`.

- [ ] **Step 1: Write the failing replay test**

```go
func TestVerifyReturnsTheMatchedStep(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	code := CodeForTesting(secret, now) // add this helper or use Generate
	step, err := Verify(secret, code, now)
	if err != nil {
		t.Fatal(err)
	}
	if step != uint64(now.Unix()/30) {
		t.Fatalf("step = %d", step)
	}
}
```

Adapt the helper to the package's existing test style; the assertion is the returned step, not a new code generator.

- [ ] **Step 2: Run it and confirm failure**

Run: `go test ./internal/mfa -run TestVerifyReturnsTheMatchedStep`
Expected: FAIL, `Verify` returns one value.

- [ ] **Step 3: Change `Verify` and every caller**

Return the counter that matched. Update the enable path (`handlers_mfa.go:151`) and `verifyUserCode` (`handlers_mfa.go:372`). On enable, record the step with `AdvanceTOTPStep` before `SaveUser`, so the enabling code cannot be replayed at login.

- [ ] **Step 4: Write the failing replay test at the handler level**

Log in once with a valid code, then log in again with the same code inside the same 30-second step. Expected: second attempt returns 401 `invalid credentials`. Confirm it fails before the store change.

- [ ] **Step 5: Add the migration and store method**

```sql
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_last_step BIGINT NOT NULL DEFAULT 0;
```

Postgres: `UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2`. Memory: compare under the write lock and reject a step that is not greater. Add the column to `SaveUser`, `scanUser`, `GetUser`, `GetUserByUsername`.

- [ ] **Step 6: Wire the login check**

In `verifyUserCode`, after a TOTP match, call `AdvanceTOTPStep`; when it returns false, treat the code as invalid. Backup codes keep their existing path.

- [ ] **Step 7: Run the suites**

Run: `go test ./internal/mfa ./internal/storage/... ./internal/api -count=1`
Run: `go test ./... -race -count=1`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add apps/api/migrations internal/mfa internal/auth internal/storage internal/api
git commit -m "mfa: a code that already authenticated cannot authenticate again"
```

---

## Final verification

- [ ] `gofmt -l .` empty, `go vet ./...` clean, `go test ./... -race -count=1` green.
- [ ] `cd apps/web && npx tsc --noEmit && npx vitest run && npm run build`.
- [ ] `docker compose -f deploy/docker-compose.yml config --quiet` with the example env.
- [ ] `git log --oneline` shows six commits, one per task.

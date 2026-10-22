# Analisa Kekurangan Project HalimiSOC

> **Tanggal audit:** 2026-10-13
> **Cakupan:** Seluruh repo — backend Go (`internal/`, `apps/api`, `apps/agent`), web console Next.js (`apps/web`), migrations, deploy, CI/CD, dokumentasi.
> **Metode:** Audit kode manual (4 area paralel) + verifikasi langsung di kode untuk setiap temuan kritis.

**Kesimpulan utama:** Secara arsitektur dan disiplin keamanan, ini project yang luar biasa rapi untuk ukurannya — RBAC fail-closed, SQL sepenuhnya parameterized, semua request body dibatasi dan strict-decoded, CSP nonce di console, dokumentasi jujur. Tapi ada **satu bug kritis yang membuat mode produksi mustahil dijalankan**, beberapa **kebocoran memori/state yang never invoked**, satu **panic path di parser**, dan **kesenjangan operasional besar** (backup, TLS, retention). Polanya menarik: kelemahan project ini bukan di desain, tapi di *wiring* — mekanisme sudah dibangun dengan benar, tapi tidak selalu tersambung.

---

## 🔴 Kritis (production blocker)

### 1. `HALIMISOC_SECURE_COOKIES` tidak pernah dibaca — API tidak bisa start di mode production

`config.Load()` di `internal/config/config.go:19-42` tidak mengisi field `SecureCookies` sama sekali (helper `envBool` di `config.go:273` adalah dead code). Akibatnya `Validate()` di `config.go:149-151` selalu gagal ketika `HALIMISOC_ENV=production`, *bahkan saat variabelnya diset `true`*. `deploy/docker-compose.yml:38,45` menyetel variabel ini → container API crash-loop.

Ini kontradiksi langsung dengan `.env.example`, `SECURITY.md:110`, dan `docs/security/configuration.md` yang semuanya mendokumentasikan perilaku yang tidak berfungsi. Fix-nya satu baris, tapi dampaknya menutup seluruh jalur deployment produksi.

---

## 🟠 High — pipeline & deteksi

### 2. Parser sudo bisa panic pada input hostil

`internal/events/parser/sudo.go:111` — `strings.Fields(body[i+len("logname="):])[0]` meng-index slice kosong jika baris log berakhir tepat setelah `logname=`. Melanggar kontrak package sendiri ("a parser must never panic on hostile input", AGENTS.md §7.1).

Karena parser berjalan di proses agent tanpa `recover()`, siapa pun yang bisa menulis baris log curangan (misalnya via SSH gagal yang membentuk auth.log) bisa **membunuh koleksi telemetri di host**. Fuzz seed tidak mencakup kasus trailing-`logname=`.

### 3. Detection state `fired` map unbounded — kebocoran memori yang bisa dipicu attacker

`MarkFired` di `internal/detection/state/state.go:159-171` menambah entri tanpa batas, dan `State.Prune` (`state.go:199`) **tidak pernah dipanggil dari kode produksi** (loop maintenance `apps/api/main.go:317-349` hanya purge raw evidence dan sesi). Attacker yang mengirim event dengan banyak group key unik melewati threshold rule membuat memori tumbuh seumur proses. (`chain` dan `win` sudah di-cap; `fired` tidak.)

### 4. Retention adalah config mati

`EventRetention` (`internal/config/limits.go:78`) diparse, divalidasi, didokumentasikan di `.env.example` — tapi tidak ada satu pun `DELETE FROM events/alerts/audit_logs` di seluruh repo. Tabel terbesar tumbuh selamanya, dan operator percaya retention 30 hari aktif padahal tidak.

`MemoryQueueSize`, `DiskSpoolBytes`, `DBResultRows` juga tidak pernah dipakai di luar `limits.go`.

### 5. Data race di `Engine.Reload`

`internal/detection/engine/engine.go:69-74` menulis `e.set` tanpa lock, sementara `Process` (`engine.go:91`) membacanya secara konkuren dari handler ingest HTTP. Genuine data race yang akan tertangkap `-race`; reload rules bisa menghasilkan bacaan stale/torn.

### 6. Correlation punya race read-modify-write

`internal/correlation/engine.go:63-79` — `ListOpenIncidents` → `Append` (copy murni) → `SaveIncident` (upsert last-write-wins). Dua alert konkuren bisa saling menimpa merge, atau menciptakan dua incident terpisah untuk entitas yang sama. Tidak ada transaksi atau advisory lock.

### 7. Agent kehilangan telemetri saat graceful shutdown

`apps/agent/producer.go:80-83` — offset di-flush *sebelum* event pending di-enqueue ke channel; jika proses exit sebelum sender mengosongkan channel (kapasitas 8), batch terakhir hilang permanen. Melawan klaim di `apps/agent/main.go:5-6` bahwa telemetri tidak boleh hilang diam-diam.

### 8. Memory store tidak berbatas dan tidak ada retention

`internal/storage/memory/memory.go:28-44` — semua map tumbuh tanpa limit; `ListEvents` meng-clone dan mengurutkan seluruh store per request di bawah `RLock`. Mode demo (`HALIMISOC_ALLOW_MEMORY_STORE=true`) bisa OOM.

*Capability drift* dengan postgres:

- `ListOpenIncidents` memory mengecualikan FALSE_POSITIVE, postgres tidak (`queries.go:776-780`) — di postgres, alert baru bisa di-merge ke incident yang sudah ditandai false positive operator.
- `SaveAlert` beda semantik duplikat antar backend (memory `ErrConflict` vs postgres silent no-op via `ON CONFLICT DO NOTHING`).

---

## 🟡 Medium — keamanan backend

### 9. MFA setup dan registrasi passkey tanpa step-up authentication

`internal/api/handlers_mfa.go:53-93` dan `handlers_webauthn.go:57-109` — sesi yang dicuri (cookie + CSRF) bisa menjalankan ulang MFA setup, yang **menghapus diam-diam** TOTP secret dan semua backup code korban, lalu mendaftarkan authenticator penyerang dan menerima 10 backup code baru. Kontras dengan `handleMFADisable` yang mensyaratkan password. Untuk console SOC, ini harus butuh password/kode saat ini.

### 10. Konsumsi backup code tidak atomik

`handlers_mfa.go:250-269, 312-345` — user di-fetch sebagai copy, hash dihapus di memori, lalu disimpan dengan `SaveUser` full-object. Dua login konkuren dengan backup code yang sama keduanya lolos dan minta sesi; perubahan MFA/password konkuren bisa saling menimpa (lost update).

### 11. Rate limiter in-memory per-proses, dan eviction-nya bisa dimanipulasi

`internal/auth/limiter.go:155-170` — semua limiter reset saat restart dan hanya berlaku per replika; saat cap 10.000 entri tercapai, entry *tertua* yang di-evict — attacker yang spray ribuan username unik bisa meng-evict counter `acct:victim` justru saat throttling paling dibutuhkan. `Limiter.Prune` tidak pernah dipanggil dari kode produksi.

### 12. Username login tidak dibatasi panjang/karakter

`internal/api/handlers_auth.go:45` — username ~8KB jadi limiter key (≈80MB worst case) dan `Actor` unbounded di `audit_logs`. Pembuatan user punya `validUsername`, login tidak. Pola sama di passkey handlers (`handlers_webauthn.go:297, 372`).

### 13. Enumerasi username di passkey login begin

`handlers_webauthn.go:291-352` — user tak dikenal → 400; user dikenal → 200 + `allowCredentials` (kebocoran eksistensi + credential ID). Flow discoverable-login W3C dengan `allowCredentials` kosong akan menutup ini.

### 14. Kode MFA di path disable tanpa rate limit

`handlers_mfa.go:180` — ruang 1 juta kode 6 digit, hanya password di depannya. Verifikasi login sudah dibatasi; enable/disable tidak.

### 15. `audit.Entry.Validate()` adalah invariant dekoratif

Didefinisikan di `internal/audit/audit.go:77-96`, tapi tidak pernah dipanggil di write path (`server.go:601-612`). Plus: `writeAudit` memakai `r.Context()`, jadi klien yang disconnect di tengah request bisa diam-diam menjatuhkan record audit.

### 16. WebAuthn config dev default dipakai diam-diam di produksi

`server.go:181-189` default RPID `127.0.0.1` / origin `localhost:3000` tanpa pengecekan produksi; `WebauthnConfig.Validate()` ada tapi tidak pernah dipanggil dari `apps/api/main.go`.

### 17. Kecil tapi layak

- `/metrics` terbuka secara default saat `MetricsToken` kosong (`handlers_health.go:75-87`).
- TOTP replayable dalam window skew ~90 detik tanpa last-used-step (`mfa.go:106-131`).
- `id.fillRandom` fail-open saat RNG gagal — menghasilkan ID deterministik (`ulid.go:111-122`).
- Error YAML parser di-echo ke klien (`handlers_rules_author.go:51,102`), melanggar aturan envelope sendiri.
- Tidak ada batas jumlah sesi per user (`handlers_auth.go:127-135`).
- Di belakang reverse proxy, semua klien berbagi satu bucket rate limit IP (`server.go:412-418`).
- `handleValidateRule` adalah POST tanpa CSRF (terdokumentasi, tapi satu-satunya inkonsistensi).

---

## 🟡 Medium — kesiapan operasional

### 18. Tidak ada backup/restore sama sekali

Tidak ada `pg_dump` script, sidecar, cron, atau dokumentasi. Volume Postgres adalah satu-satunya penyimpanan bukti keamanan — untuk platform SOC, ini kesenjangan paling fundamental.

### 19. TLS hanya bisa dari proxy eksternal, dan proxy-nya tidak di-wire

`deploy/configs/Caddyfile` ada tapi tidak ada service yang merujuknya di compose; API tidak punya opsi TLS native sama sekali.

### 20. Ergonomi agent bermasalah

- Token enroll tidak pernah dipersist ke disk — shared bootstrap secret harus hidup di env/systemd di *setiap* host selamanya, dan token di CLI flag terlihat di `/proc/<pid>/cmdline`.
- Tidak ada flag `-ca-cert` untuk private CA (hanya system cert pool).
- Satu file per agent — tidak ada journald, syslog socket, atau multi-file/glob.
- Heartbeat mengirim `queue_depth` sebagai konfigurasi statis (4096), bukan kedalaman nyata (`sender.go:142`).
- Status DEGRADED sticky karena berbasis counter kumulatif sejak start.

### 21. Kegagalan bind exit code 0

`apps/api/main.go:194-200` — error `ListenAndServe` (port terpakai) hanya di-log lalu `run()` return nil — systemd `Restart=on-failure` tidak akan me-restart.

### 22. Deploy & release setengah jalan

- Compose tanpa resource limits di semua container; web tanpa healthcheck.
- Tidak ada release workflow, image publish, packaging systemd untuk agent, atau upgrade path.
- `sslmode=disable` di DSN compose — aman di satu host, diam-diam rusak jika stack di-split.

### 23. Observability setengah jadi

16 counter metrik bagus, tapi tanpa histogram latensi, tanpa dashboard/Grafana config, tanpa tracing, tanpa panduan log shipping — padahal operator SOC justru butuh visibilitas ingest-rate dan pertumbuhan spool. Statistik agent tidak terlihat di steady state (hanya di akhir simulasi).

---

## 🟢 Medium-low — web console (Next.js)

### 24. Settings page menelan error API

`apps/web/src/app/settings/page.tsx:13-24` — kegagalan `mfaStatus`/`listPasskeys` dirender sebagai "Not enabled." / "No passkeys registered." — **menampilkan state keamanan yang salah** saat API bermasalah. Melawan prinsip project sendiri di `audit/page.tsx:10-12`.

### 25. Kegagalan fetch diam-diam

- `page.tsx:39-46` (dashboard) tidak menyurvei error `listEvents` — chart volume bisa render nol padahal data ada.
- `MfaSettings.tsx:21-39` punya `try/finally` tanpa `catch`; handler button tidak menangkap error jaringan.
- Path auth di `api.ts:138-148` dan route webauthn tanpa `AbortSignal.timeout` — fetch login bisa menggantung selamanya (kontras `request()` yang 10 detik).

### 26. Rincian kecil console

- Cookie sesi maxAge 12h hardcoded vs TTL backend (dua sumber kebenatan bisa disagree).
- Next.js 16.3.6 → bump ke 16.3.8+ (CVE-2026-94485/94486, low).
- `Strict-Transport-Security` dan `Permissions-Policy` hilang dari headers.
- `lint` hanya `tsc` tanpa ESLint (tidak ada rule `react-hooks`/security).
- Link `rule_id` kosong (dead link) di `incidents/[id]/page.tsx:119`.
- UI pagination mengabaikan `next_cursor` — data lama tidak terjangkau dari UI.
- `RealtimeProvider` reconnect forever saat sesi expire (401) tanpa redirect ke login.
- Double-cast `` `x/y` as unknown as number `` di `page.tsx:58`.
- Error message upstream di-forward verbatim di route webauthn (inkonsisten dengan policy sendiri).

---

## Testing & CI

Yang ada sudah kuat: e2e dengan DB nyata (2x), race detector, Playwright + CSP nonce assertion, `npm audit --omit=dev` gated, govulncheck + gitleaks full history. Yang kurang:

- Tidak ada gosec/staticcheck (hanya `go vet`).
- Docker images di-build tapi tidak di-scan (trivy/grype) dan tidak pernah di-publish.
- Coverage di-generate tapi tidak di-upload/di-enforce.
- GitHub Actions pinned by tag, bukan SHA.
- Unit test web belum menyentuh: validator proxy route, pemetaan error `api.ts`, logika reconnect `RealtimeProvider`, `guard.ts`, codec `lib/webauthn.ts`. Tidak ada component test sama sekali.
- E2E web belum mencakup: filter events page, assets page, audit permission-denied, role READONLY, MFA disable, session-expiry UX.
- Fuzz parser tidak punya seed trailing-`logname=` (terkait temuan #2).

---

## Yang sudah dilakukan dengan baik (supaya adil)

- **Authorization**: matriks RBAC fail-closed dan exhaustive, dicek server-side di setiap handler, agent secara struktural dilarang punya permission operator, denial di-audit.
- **Kredensial**: Argon2id di atas minimum OWASP, timing equalizer untuk unknown-user, token agent hanya sebagai hash, WebAuthn dengan challenge single-use + clone detection + CBOR bounded.
- **Session hygiene**: server-side revocable, derived lookup id, absolute TTL + idle timeout, `__Host-` prefix, logout/password-change/disable cascade revocation.
- **Boundedness**: SSE dengan cap subscriber dan slow-client disconnect, spool agent bounded dengan drop counter, assembler multi-line bounded, semua request body di-cap dan strict-decode.
- **Postgres**: parameterized penuh, keyset pagination, status-pinned concurrent update, migrasi transaksional.
- **Web console**: BFF dengan sesi di server, allowlist mutasi tertutup (tidak ada permukaan SSRF), CSP nonce diverifikasi e2e, strict TypeScript tanpa satu pun `any`.
- **Kejujuran dokumentasi**: "Not built yet" di README dan "Explicitly not claimed" di SECURITY.md adalah praktik yang jarang ada.

---

## Prioritas perbaikan yang direkomendasikan

### P0 — segera (≈ satu hari)

1. Parse `HALIMISOC_SECURE_COOKIES` di `config.Load()` (temuan #1).
2. Guard `len(fields) == 0` di `sudo.go:111` + tambah fuzz seed trailing-`logname=` (temuan #2).
3. Wire `State.Prune` dan purge retention (`EventRetention`) ke loop `maintain()` (temuan #3, #4).

### P1 — minggu ini

1. Step-up auth (password/kode saat ini) untuk MFA setup dan passkey registration (temuan #9).
2. Konsumsi backup code atomik di layer store (temuan #10).
3. Flush pending agent ke spool sebelum exit (temuan #7).
4. Mutex/atomic pointer di `Engine.Reload` (temuan #5).
5. Isolasi transaksi/advisory lock untuk correlation (temuan #6).
6. Script/dokumentasi backup-restore Postgres (temuan #18).

### P2 — berikutnya

1. Rate limit pada disable-MFA; validasi username login; wire `audit.Entry.Validate`; panggil `WebauthnConfig.Validate()` di startup (temuan #12, #14, #15, #16).
2. Fix penampilan state keamanan yang salah di settings page + timeout fetch auth console (temuan #24, #25).
3. Exit code non-zero pada bind failure; heartbeat queue depth nyata (temuan #20, #21).
4. Resource limits + healthcheck compose; scan/publish image CI; gosec/staticcheck (temuan #22, Testing & CI).
5. Rekonsiliasi semantik memory vs postgres store (temuan #8).

---

> Intinya: fondasi keamanan dan desainnya sudah benar, tapi project ini belum *deployable* secara produksi karena satu bug config, dan belum *operable* jangka panjang karena state/retention yang tidak pernah dibersihkan. Dua hal itu adalah pembeda antara "vertical slice yang bagus" dan "platform yang siap dipercaya menyimpan bukti keamanan".

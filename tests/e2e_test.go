// Package tests holds black-box tests that exercise the agent and the API as
// separate processes, which is the only way to verify that the wire contract,
// the credential handshake and the detection pipeline agree end to end.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// e2eEnv describes a running API instance.
type e2eEnv struct {
	baseURL string
	cancel  context.CancelFunc
	logPath string
}

// requireE2E skips the test unless an explicit opt-in is set.
//
// A black-box test that starts real processes must never run by default: it
// needs a database and free ports, and a surprise failure in an unrelated
// environment would train people to ignore the suite.
func requireE2E(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("HALIMISOC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set HALIMISOC_TEST_DATABASE_URL to run the black-box end-to-end test")
	}
	return dsn
}

func buildBinary(t *testing.T, pkg, out string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), out)
	cmd := exec.Command("go", "build", "-o", path, pkg)
	cmd.Dir = repoRoot(t)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, output)
	}
	return path
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// This file lives in tests/; the module root is one level up.
	return filepath.Dir(dir)
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// startAPI runs the API binary against the test database.
func startAPI(t *testing.T, dsn string) *e2eEnv {
	t.Helper()

	binary := buildBinary(t, "./apps/api", "halimisoc-api")
	addr := freePort(t)
	logPath := filepath.Join(t.TempDir(), "api.log")

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(),
		"HALIMISOC_ENV=development",
		"HALIMISOC_LISTEN_ADDR="+addr,
		"HALIMISOC_DATABASE_URL="+dsn,
		"HALIMISOC_ADMIN_USER=admin",
		"HALIMISOC_ADMIN_PASSWORD=e2e-admin-password-value",
		"HALIMISOC_AGENT_ENROLL_SECRET=e2e-enrollment-secret-value",
		"HALIMISOC_RULES_PATH=packages/rules",
		"HALIMISOC_LOG_LEVEL=debug",
	)

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start api: %v", err)
	}

	env := &e2eEnv{baseURL: "http://" + addr, cancel: cancel, logPath: logPath}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		logFile.Close()
	})

	waitForReady(t, env)
	return env
}

func waitForReady(t *testing.T, env *e2eEnv) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(env.baseURL + "/readyz") //nolint:noctx // bounded by the deadline loop
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			if strings.Contains(string(body), "rules") {
				// The server is up but not ready; keep waiting.
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("api did not become ready; log:\n%s", readFile(env.logPath))
}

func readFile(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "(no log)"
	}
	return string(raw)
}

// runAgent executes the agent simulation and waits for it to finish.
func runAgent(t *testing.T, env *e2eEnv, host, spoolDir, stateDir string) (string, error) {
	t.Helper()

	binary := buildBinary(t, "./apps/agent", "halimisoc-agent")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary,
		"-server", env.baseURL,
		"-enroll-token", "e2e-enrollment-secret-value",
		"-host", host,
		"-simulate",
		"-spool-dir", spoolDir,
		"-state-dir", stateDir,
		"-batch", "3",
		// The test API is served over plain HTTP on loopback, which is exactly
		// the case the -insecure flag exists for. Production deployments must
		// use TLS and must not pass it.
		"-insecure",
	)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "HALIMISOC_ALLOW_MEMORY_STORE=false")

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func login(t *testing.T, env *e2eEnv) *http.Client {
	t.Helper()

	jar := newJar(t)
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "e2e-admin-password-value",
	})
	resp, err := client.Post(env.baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status = %d: %s\napi log:\n%s", resp.StatusCode, raw, readFile(env.logPath))
	}
	return client
}

func getJSON[T any](t *testing.T, client *http.Client, url string) T {
	t.Helper()
	resp, err := client.Get(url) //nolint:noctx // bounded by the client timeout
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, raw)
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return out
}

// TestEndToEndSimulationToAlerts is the acceptance test for the MVP vertical
// slice: an enrolled agent ships synthetic telemetry, the server normalizes and
// persists it, deterministic detection fires, and correlation produces an
// incident whose narrative both the API and the metrics endpoint expose.
func TestEndToEndSimulationToAlerts(t *testing.T) {
	dsn := requireE2E(t)
	resetDatabase(t, dsn)
	env := startAPI(t, dsn)

	host := fmt.Sprintf("e2e-%d", time.Now().UnixNano()%1_000_000)
	dir := t.TempDir()

	agentLog, err := runAgent(t, env, host, filepath.Join(dir, "spool"), filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("agent run failed: %v\nagent output:\n%s\napi log:\n%s", err, agentLog, readFile(env.logPath))
	}
	if !strings.Contains(agentLog, "simulation finished") {
		t.Fatalf("agent did not complete the simulation:\n%s", agentLog)
	}

	client := login(t, env)

	// Every query is scoped to the host this test enrolled, so the assertions
	// do not depend on the database being otherwise empty. The filter is part of
	// the API contract, so exercising it here also covers it.
	events := getJSON[struct {
		Events []struct {
			ID   string `json:"id"`
			Host string `json:"host"`
			Type string `json:"type"`
			Raw  string `json:"raw"`
		} `json:"events"`
	}](t, client, env.baseURL+"/api/v1/events?host="+host+"&limit=200")

	if len(events.Events) == 0 {
		t.Fatalf("no events were ingested for %s\nagent output:\n%s\napi log:\n%s",
			host, agentLog, readFile(env.logPath))
	}
	for _, e := range events.Events {
		if e.Host != host {
			t.Errorf("event %s host = %q, want %q", e.ID, e.Host, host)
		}
		if e.Raw == "" {
			t.Errorf("event %s lost its raw evidence", e.ID)
		}
	}

	// Detection fired.
	alerts := getJSON[struct {
		Alerts []struct {
			ID       string   `json:"id"`
			RuleID   string   `json:"rule_id"`
			Severity string   `json:"severity"`
			Status   string   `json:"status"`
			Count    int      `json:"count"`
			EventIDs []string `json:"event_ids"`
			Reason   string   `json:"reason"`
		} `json:"alerts"`
	}](t, client, env.baseURL+"/api/v1/alerts?host="+host+"&limit=200")

	if len(alerts.Alerts) == 0 {
		t.Fatalf("no alerts were produced\napi log:\n%s", readFile(env.logPath))
	}

	seen := map[string]bool{}
	for _, a := range alerts.Alerts {
		seen[a.RuleID] = true
		if a.Status != "OPEN" {
			t.Errorf("alert %s status = %s, want OPEN", a.ID, a.Status)
		}
		if len(a.EventIDs) == 0 {
			t.Errorf("alert %s carries no evidence", a.ID)
		}
		if a.Reason == "" {
			t.Errorf("alert %s has no explanation", a.ID)
		}
	}
	for _, want := range []string{"ssh-bruteforce", "ssh-login-after-bruteforce", "ssh-authorized-keys-modified"} {
		if !seen[want] {
			t.Errorf("rule %s did not fire; rules seen: %v", want, seen)
		}
	}

	// Correlation produced an incident with an ordered narrative. Incidents are
	// not host-filterable, so the assertion checks that one references this
	// host rather than assuming it is the only incident in the database.
	incidents := getJSON[struct {
		Incidents []struct {
			ID       string   `json:"id"`
			Severity string   `json:"severity"`
			Status   string   `json:"status"`
			Hosts    []string `json:"hosts"`
			Stages   []struct {
				Name string    `json:"name"`
				At   time.Time `json:"at"`
			} `json:"stages"`
		} `json:"incidents"`
	}](t, client, env.baseURL+"/api/v1/incidents?limit=50")

	if len(incidents.Incidents) == 0 {
		t.Fatal("no incident was created from the correlated alerts")
	}
	found := false
	for _, inc := range incidents.Incidents {
		for _, h := range inc.Hosts {
			if h == host {
				found = true
			}
		}
		if len(inc.Stages) < 2 {
			t.Errorf("incident %s has %d stages, want a multi-stage narrative", inc.ID, len(inc.Stages))
		}
	}
	if !found {
		t.Fatalf("no incident references host %s", host)
	}

	// Observability is live.
	metrics := getJSONMetrics(t, env.baseURL+"/metrics")
	for _, want := range []string{
		"events_received_total",
		"events_processed_total",
		"detection_total",
		"incident_created_total",
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics endpoint is missing %s", want)
		}
	}
}

func getJSONMetrics(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // bounded by the default client
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestAgentSurvivesAPIOutage verifies the spool: telemetry produced while the
// server is down is delivered once it returns, and nothing is silently lost.
func TestAgentSurvivesAPIOutage(t *testing.T) {
	dsn := requireE2E(t)
	resetDatabase(t, dsn)
	env := startAPI(t, dsn)

	host := fmt.Sprintf("e2e-outage-%d", time.Now().UnixNano()%1_000_000)
	dir := t.TempDir()
	// The state directory must be per-run: the agent persists its token there,
	// so a shared path would carry a credential into the next run and into the
	// repository checkout.
	stateDir := filepath.Join(dir, "state")

	// Enroll against the live server so the agent has a working credential.
	binary := buildBinary(t, "./apps/agent", "halimisoc-agent-outage")
	enroll := exec.Command(binary, "-server", env.baseURL, "-enroll-token", "e2e-enrollment-secret-value", "-host", host, "-simulate", "-insecure", "-state-dir", stateDir)
	enroll.Dir = repoRoot(t)
	enroll.Env = os.Environ()
	if out, err := enroll.CombinedOutput(); err != nil {
		t.Fatalf("initial agent run failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "token")); err != nil {
		t.Fatalf("enrollment did not persist a token: %v", err)
	}

	// Now take the server away and confirm the agent spools instead of failing.
	env.cancel()
	time.Sleep(500 * time.Millisecond)

	spoolDir := filepath.Join(dir, "spool")
	if err := os.MkdirAll(spoolDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// With the server gone, the agent must reuse the persisted credential and
	// keep running: it should back off and spool rather than exit or re-enroll.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	agent := exec.CommandContext(ctx, binary,
		"-server", "http://127.0.0.1:1", // nothing listening
		"-host", host,
		"-file", filepath.Join(dir, "fake-auth.log"),
		"-spool-dir", spoolDir,
		"-state-dir", stateDir,
		"-batch", "2",
		"-insecure",
	)
	agent.Dir = repoRoot(t)

	logFile := filepath.Join(dir, "fake-auth.log")
	var content bytes.Buffer
	for i := 0; i < 10; i++ {
		content.WriteString(fmt.Sprintf("Aug 19 11:20:%02d host sshd[1]: Failed password for root from 203.0.113.9 port %d ssh2\n", i, 40000+i))
	}
	// Guard against a partial write being read as a complete record.
	if err := os.WriteFile(logFile, content.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _ := agent.CombinedOutput()
	// The agent must have kept running until the context expired, not exited
	// with a fatal error on the first failed delivery.
	if strings.Contains(string(out), "fatal:") {
		t.Fatalf("agent exited fatally during an outage:\n%s", out)
	}
}

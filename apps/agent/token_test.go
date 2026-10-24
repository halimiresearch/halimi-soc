package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The agent must survive a restart without the enrollment secret. Losing this
// file means either re-enrolling (impossible after the secret is rotated) or
// losing collection for the host.
func TestTokenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	if err := saveToken(dir, "agt_testtoken"); err != nil {
		t.Fatal(err)
	}

	got, err := loadToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "agt_testtoken" {
		t.Fatalf("loadToken = %q, want the saved token", got)
	}

	info, err := os.Stat(filepath.Join(dir, tokenFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("token mode = %o, want 600", perm)
	}
}

func TestLoadTokenMissingIsEmpty(t *testing.T) {
	got, err := loadToken(t.TempDir())
	if err != nil {
		t.Fatalf("missing token file must not be an error: %v", err)
	}
	if got != "" {
		t.Fatalf("loadToken = %q, want empty", got)
	}
}

func TestSaveTokenCreatesStateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := saveToken(dir, "agt_x"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadToken(dir); err != nil {
		t.Fatal(err)
	}
}

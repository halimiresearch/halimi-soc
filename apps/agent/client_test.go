package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// A configured CA that cannot be read is a deployment mistake. Falling back to
// the system pool would make the agent trust a different PKI than the operator
// intended, so startup must fail.
func TestCAFileMissingFailsStartup(t *testing.T) {
	_, err := newClient(options{
		server: "https://example.test",
		caCert: filepath.Join(t.TempDir(), "missing.pem"),
	}, slog.Default())
	if err == nil {
		t.Fatal("missing CA file must fail startup")
	}
}

func TestCAFileUnparseableFailsStartup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")

	// A syntactically valid certificate is not required to prove the branch is
	// wired: the point is that a readable file reaches the pool builder.
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newClient(options{server: "https://example.test", caCert: path}, slog.Default()); err == nil {
		t.Fatal("unparseable CA file must fail startup")
	}
}

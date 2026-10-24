package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const tokenFile = "token"

// loadToken returns the token persisted by a previous enrollment, or "" when
// the agent has never enrolled.
func loadToken(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, tokenFile))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read agent token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// saveToken persists the token returned by enrollment. The plaintext has to
// live on disk for the agent to authenticate, so mode 0600 and a rename keep
// other accounts out and a crash from leaving a partial file.
func saveToken(dir, token string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	tmp := filepath.Join(dir, tokenFile+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write agent token: %w", err)
	}
	if _, err := f.WriteString(token); err != nil {
		f.Close()
		return fmt.Errorf("write agent token: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("write agent token: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write agent token: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, tokenFile)); err != nil {
		return fmt.Errorf("persist agent token: %w", err)
	}
	return nil
}

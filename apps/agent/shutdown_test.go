package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/halimi/halimisoc/internal/events/model"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestPersistPendingSpoolsBeforeAdvancingOffset(t *testing.T) {
	log := testLogger()
	spoolDir := t.TempDir()
	sp, err := newSpool(spoolDir, 1<<20, log)
	if err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logPath, []byte("line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	offsets, err := newOffsetStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tail := newTailer(logPath, offsets)
	if err := tail.Open(); err != nil {
		t.Fatal(err)
	}
	defer tail.Close()
	tail.offset = 42

	p := &producer{spool: sp, log: log}
	events := []*model.Event{{ID: "evt_1"}}
	if !p.persistPending(tail, events) {
		t.Fatal("persistPending reported failure")
	}

	stored, err := sp.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].ID != "evt_1" {
		t.Fatalf("spooled events = %v, want evt_1", stored)
	}
	saved, ok := offsets.load(logPath)
	if !ok || saved.Offset != 42 {
		t.Fatalf("offset = %+v (saved=%v), want 42", saved, ok)
	}
}

func TestPersistPendingKeepsOffsetWhenSpoolFails(t *testing.T) {
	log := testLogger()
	spoolDir := t.TempDir()
	sp, err := newSpool(spoolDir, 1<<20, log)
	if err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logPath, []byte("line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	offsets, err := newOffsetStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tail := newTailer(logPath, offsets)
	if err := tail.Open(); err != nil {
		t.Fatal(err)
	}
	defer tail.Close()
	tail.offset = 42

	// Make the spool unwritable. Advancing the reader offset now would lose the
	// events permanently; re-reading them is harmless because ingestion is
	// idempotent.
	if err := os.RemoveAll(spoolDir); err != nil {
		t.Fatal(err)
	}

	p := &producer{spool: sp, log: log}
	if p.persistPending(tail, []*model.Event{{ID: "evt_1"}}) {
		t.Fatal("persistPending succeeded with an unwritable spool")
	}
	if _, ok := offsets.load(logPath); ok {
		t.Fatal("offset advanced after a failed spool write; the events would be lost")
	}
}

func TestDrainQueueToSpoolOnShutdown(t *testing.T) {
	log := testLogger()
	sp, err := newSpool(t.TempDir(), 1<<20, log)
	if err != nil {
		t.Fatal(err)
	}

	queue := make(chan []*model.Event, 3)
	queue <- []*model.Event{{ID: "evt_1"}}
	queue <- []*model.Event{{ID: "evt_2"}}

	drainQueueToSpool(sp, queue, log)

	// The queue must be empty: a full queue on exit is telemetry nobody will
	// ever deliver.
	if len(queue) != 0 {
		t.Fatalf("queue still holds %d batches", len(queue))
	}
	stored, err := sp.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 || stored[0].ID != "evt_1" || stored[1].ID != "evt_2" {
		t.Fatalf("spooled events = %v", stored)
	}
}

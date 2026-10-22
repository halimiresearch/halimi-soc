package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/config"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/storage/memory"
)

type recordingPruner struct {
	calls int
	at    time.Time
}

func (p *recordingPruner) Prune(now time.Time) {
	p.calls++
	p.at = now
}

func TestRunMaintenanceEnforcesRetentionAndPrunesState(t *testing.T) {
	store := memory.New()
	now := time.Now().UTC()
	old := now.Add(-31 * 24 * time.Hour)

	for _, e := range []*model.Event{
		{ID: "evt_old", Type: model.TypeSSHLoginFailed, Time: old, ReceivedAt: old, Host: "web-01", Severity: model.SeverityLow, Raw: "old line", Attributes: map[string]string{}},
		{ID: "evt_new", Type: model.TypeSSHLoginFailed, Time: now, ReceivedAt: now, Host: "web-01", Severity: model.SeverityLow, Raw: "new line", Attributes: map[string]string{}},
	} {
		if _, err := store.InsertEvent(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []*alerts.Alert{
		{ID: "alt_old", RuleID: "r", RuleVersion: 1, RuleName: "R", Severity: model.SeverityLow, Status: alerts.StatusOpen, Title: "t", Reason: "r", EventIDs: []string{"evt_old"}, WindowStart: old, WindowEnd: old, CreatedAt: old, UpdatedAt: old},
		{ID: "alt_new", RuleID: "r", RuleVersion: 1, RuleName: "R", Severity: model.SeverityLow, Status: alerts.StatusOpen, Title: "t", Reason: "r", EventIDs: []string{"evt_new"}, WindowStart: now, WindowEnd: now, CreatedAt: now, UpdatedAt: now},
	} {
		if err := store.SaveAlert(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []*audit.Entry{
		{ID: "aud_old", Actor: "operator:admin", Action: audit.ActionLoginSuccess, Resource: "session", Result: audit.ResultSuccess, Timestamp: old},
		{ID: "aud_new", Actor: "operator:admin", Action: audit.ActionLoginSuccess, Resource: "session", Result: audit.ResultSuccess, Timestamp: now},
	} {
		if err := store.AppendAudit(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}

	pruner := &recordingPruner{}
	runMaintenance(context.Background(), store, pruner, &config.Config{Retention: config.DefaultLimits()},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	if n, err := store.CountEvents(context.Background()); err != nil || n != 1 {
		t.Fatalf("events after retention = %d (err %v), want 1", n, err)
	}
	if _, err := store.GetAlert(context.Background(), "alt_old"); err == nil {
		t.Fatal("expired alert survived retention")
	}
	if entries, _, err := store.ListAudit(context.Background(), 10, ""); err != nil || len(entries) != 1 {
		t.Fatalf("audit after retention = %d (err %v), want 1", len(entries), err)
	}
	if pruner.calls != 1 {
		t.Fatalf("detection prune calls = %d, want 1", pruner.calls)
	}
}

// Package engine evaluates detection rules against canonical events.
//
// Detection is deterministic, explainable and AI-independent (DESIGN.md §11).
// Given the same events in the same order, the engine produces the same alerts.
// Every alert records the rule id and version that produced it, the evidence
// event ids, and the window it was computed over.
package engine

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/detection/rules"
	"github.com/halimi/halimisoc/internal/detection/state"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/metrics"
)

// AlertSink persists alerts produced by the engine.
type AlertSink interface {
	SaveAlert(ctx context.Context, a *alerts.Alert) error
}

// Engine evaluates a rule set against events.
type Engine struct {
	// set is swapped atomically because Reload races ingestion.
	set   atomic.Pointer[rules.Set]
	state *state.State
	sink  AlertSink
	reg   *metrics.Registry
	now   func() time.Time
	newID func() string
}

// New builds an engine.
func New(set *rules.Set, st *state.State, sink AlertSink, reg *metrics.Registry) *Engine {
	if reg == nil {
		reg = metrics.New()
	}
	e := &Engine{
		state: st,
		sink:  sink,
		reg:   reg,
		now:   func() time.Time { return time.Now().UTC() },
		newID: func() string { return id.New(id.KindAlert) },
	}
	e.set.Store(set)
	return e
}

// SetClock overrides the clock. Test-only.
func (e *Engine) SetClock(f func() time.Time) { e.now = f }

// SetIDGenerator overrides the alert id generator. Test-only.
func (e *Engine) SetIDGenerator(f func() string) { e.newID = f }

// Rules returns the active rule set.
func (e *Engine) Rules() *rules.Set { return e.set.Load() }

// Reload swaps the active rule set transactionally.
//
// The swap is atomic from the caller's point of view: either the new set is
// active or the old one still is, never a mixture. Detection state is kept on
// purpose — it is keyed by rule id and version, so state for an unchanged rule
// survives while a removed rule's state simply ages out under its bounds. A
// reload never deletes history: alerts already persisted keep the rule id and
// version that produced them.
func (e *Engine) Reload(set *rules.Set) {
	if set == nil {
		return
	}
	e.set.Store(set)
}

// StateSize returns the number of tracked detection windows, for metrics.
func (e *Engine) StateSize() int { return e.state.Size() }

// Prune discards state older than the 24h rule window cap.
// Without it the cooldown map grows for every (rule, group) pair ever seen.
func (e *Engine) Prune(now time.Time) {
	e.state.Prune(now, state.DefaultOptions().MaxFiringAge)
}

// Process evaluates one event and returns any alerts it produced.
//
// Alerts are persisted through the sink before being returned, so a caller that
// observes an alert can rely on it being durable.
func (e *Engine) Process(ctx context.Context, ev *model.Event) ([]*alerts.Alert, error) {
	if ev == nil {
		return nil, fmt.Errorf("detection: nil event")
	}

	start := e.now()
	var produced []*alerts.Alert

	for _, rule := range e.set.Load().Rules() {
		if !rule.Matches(ev) {
			continue
		}
		groupKey, ok := rule.GroupKey(ev)
		if !ok {
			// A qualifying event that cannot be grouped is not counted: doing so
			// would attribute it to a key that does not identify anyone.
			continue
		}

		count := e.state.Observe(rule.Key(), groupKey, state.Observation{
			At:      ev.Time,
			EventID: ev.ID,
		}, rule.Threshold.Window)

		if count < rule.Threshold.Count {
			continue
		}

		// Deterministic rule chaining: the prerequisite must have fired
		// recently for the same chaining key.
		if rule.Requires != nil {
			value := rule.ChainingValue(ev)
			if !e.state.HasRecentFiring(rule.Requires.RuleID, rule.Requires.MatchOn, value, rule.Requires.Window, ev.Time) {
				continue
			}
		}

		if e.state.CooldownActive(rule.Key(), groupKey, rule.Cooldown, ev.Time) {
			e.reg.Inc(metrics.DetectionSuppressedTotal, metrics.L("rule", rule.ID))
			continue
		}

		alert := e.buildAlert(rule, ev, groupKey, count)
		if err := alert.Validate(); err != nil {
			return produced, fmt.Errorf("detection: invalid alert for rule %s: %w", rule.Key(), err)
		}
		if err := e.sink.SaveAlert(ctx, alert); err != nil {
			return produced, fmt.Errorf("detection: persist alert for rule %s: %w", rule.Key(), err)
		}

		e.state.MarkFired(rule.Key(), groupKey, rule.ID, ev.Time, e.chainKeys(ev))
		e.reg.Inc(metrics.DetectionTotal)
		e.reg.Inc(metrics.AlertsTotal, metrics.L("severity", string(rule.Severity)))
		produced = append(produced, alert)
	}

	latency := e.now().Sub(start).Milliseconds()
	if latency < 0 {
		latency = 0
	}
	e.reg.Set(metrics.DetectionLatencyMS, float64(latency))
	e.reg.Set(metrics.DetectionStateSize, float64(e.state.Size()))

	return produced, nil
}

// chainKeys records every addressable field value so a later rule can chain on
// whichever field its requires block names.
func (e *Engine) chainKeys(ev *model.Event) map[rules.Field]string {
	keys := make(map[rules.Field]string, len(rules.FieldSet))
	for _, f := range rules.FieldSet {
		if v := f.Value(ev); v != "" {
			keys[f] = v
		}
	}
	return keys
}

func (e *Engine) buildAlert(rule *rules.Rule, ev *model.Event, groupKey string, count int) *alerts.Alert {
	now := e.now()
	windowStart := e.state.WindowStart(rule.Key(), groupKey)
	evidence := e.state.Evidence(rule.Key(), groupKey)

	alert := &alerts.Alert{
		ID:          e.newID(),
		RuleID:      rule.ID,
		RuleVersion: rule.Version,
		RuleName:    rule.Name,
		Severity:    rule.Severity,
		Status:      alerts.StatusOpen,
		Title:       rule.Name,
		Host:        ev.Host,
		Actor:       ev.Actor,
		SourceIP:    ev.Network.SourceIP,
		Entity:      ev.EntityKey(),
		EventIDs:    evidence,
		Count:       count,
		WindowStart: windowStart,
		WindowEnd:   ev.Time,
		DedupeKey:   rule.Key() + "|" + groupKey,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	alert.Reason = e.reason(rule, ev, groupKey, count)
	return alert
}

// reason produces the human-readable explanation stored on the alert.
//
// Only validated, canonical values are interpolated: the host has passed the
// host character allowlist, the identity is lowercased and control-character
// free, and the IP is a canonical address. Raw telemetry is never interpolated,
// so an alert reason cannot be used as a log-injection vector.
func (e *Engine) reason(rule *rules.Rule, ev *model.Event, groupKey string, count int) string {
	subject := ""
	switch {
	case ev.Actor != "":
		subject = fmt.Sprintf(" for user %s", ev.Actor)
	case ev.Network.SourceIP != "":
		subject = fmt.Sprintf(" from %s", ev.Network.SourceIP)
	}

	detail := fmt.Sprintf("%d qualifying event(s)%s on host %s within %s",
		count, subject, ev.Host, rule.Threshold.Window)

	if rule.Requires != nil {
		detail += fmt.Sprintf("; prerequisite rule %s fired within %s",
			rule.Requires.RuleID, rule.Requires.Window)
	}
	if rule.Description != "" {
		detail += "; " + rule.Description
	}
	return detail
}

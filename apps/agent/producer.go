package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/events/parser"
	"github.com/halimi/halimisoc/internal/events/validation"
	"github.com/halimi/halimisoc/internal/id"
)

// producer reads telemetry, parses it, and hands batches to the sender.
type producer struct {
	opts    options
	client  *client
	spool   *spool
	queue   chan []*model.Event
	queued  *atomic.Int64
	log     *slog.Logger
	reg     *parser.Registry
	optsVal validation.Options
	now     func() time.Time

	stats producerStats
}

type producerStats struct {
	LinesRead       uint64
	EventsProduced  uint64
	Rejected        uint64
	QueueOverflow   uint64
	ClockSkewWarned uint64
	ParserErrors    uint64
}

func newProducer(opts options, client *client, spool *spool, queue chan []*model.Event, queued *atomic.Int64, log *slog.Logger) *producer {
	validationOpts := validation.DefaultOptions()
	validationOpts.ClockSkew = 5 * time.Minute

	return &producer{
		opts:    opts,
		client:  client,
		spool:   spool,
		queue:   queue,
		queued:  queued,
		log:     log,
		reg:     parser.Default(),
		optsVal: validationOpts,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// runTail collects from a log file until the context is cancelled.
func (p *producer) runTail(ctx context.Context) error {
	offsets, err := newOffsetStore(p.opts.stateDir)
	if err != nil {
		return err
	}
	t := newTailer(p.opts.file, offsets)
	if err := t.Open(); err != nil {
		return err
	}
	defer t.Close()

	p.log.Info("collecting", "file", abs(p.opts.file), "host", p.opts.host, "interval", p.opts.interval.String())

	assembler := parser.NewAssembler(8<<10, 64<<10)
	buf := make([]byte, 64<<10)
	flushTicker := time.NewTicker(500 * time.Millisecond)
	defer flushTicker.Stop()

	var pending []*model.Event
	lastOffsetSave := p.now()

	for {
		select {
		case <-ctx.Done():
			// Persist the assembler's final record before advancing the offset; the sender may already be gone.
			pending = append(pending, p.parseRecords(assembler.Flush(), p.opts.file)...)
			p.persistPending(t, pending)
			return nil
		case <-flushTicker.C:
			// Emit the assembler's held record so a busy-but-quiet file does not
			// delay detection indefinitely.
			pending = append(pending, p.parseRecords(assembler.Flush(), p.opts.file)...)
			if len(pending) > 0 {
				p.enqueue(pending)
				pending = nil
			}
			if p.now().Sub(lastOffsetSave) > 5*time.Second {
				p.flushOffset(t)
				lastOffsetSave = p.now()
			}
		default:
		}

		raw, err := t.Poll(buf)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			p.log.Error("read failed", "error", err)
			time.Sleep(time.Second)
			continue
		}
		if len(raw) > 0 {
			p.stats.LinesRead++
			pending = append(pending, p.parseRecords(assembler.Feed(string(raw)), p.opts.file)...)
			if len(pending) >= p.opts.batchSize {
				p.enqueue(pending)
				pending = nil
			}
			continue
		}
		time.Sleep(p.opts.interval)
	}
}

// persistPending spools the final batch before advancing the offset.
// A failed write keeps the offset, so the lines are re-read; the server dedupes by id.
func (p *producer) persistPending(t *tailer, events []*model.Event) bool {
	if len(events) > 0 {
		if err := p.spool.Append(events); err != nil {
			p.log.Error("spool append failed on shutdown; keeping offset so events are re-read",
				"error", err, "events", len(events))
			return false
		}
	}
	p.flushOffset(t)
	return true
}

// flushOffset persists the reader position.
//
// It is called on a timer and at shutdown. Losing it costs a re-read on restart,
// which the server collapses as duplicates, so a failure here is logged rather
// than fatal.
func (p *producer) flushOffset(t *tailer) {
	if err := t.SaveOffset(); err != nil {
		p.log.Warn("save offset failed", "error", err)
	}
}

// parseRecords converts raw assembled records into canonical, validated events.
//
// Both the live tail and the simulator go through this function, so the
// statistics and the validation rules cannot drift between the two paths. A
// record that is not VALID is counted and dropped: it is not an error, because a
// syslog stream legitimately contains records no parser cares about.
func (p *producer) parseRecords(records []string, sourcePath string) []*model.Event {
	out := make([]*model.Event, 0, len(records))
	for _, raw := range records {
		res := p.reg.Parse(parser.Line{
			Raw:        raw,
			Host:       p.opts.host,
			SourcePath: sourcePath,
			ObservedAt: p.now(),
		})
		if res.Status != parser.StatusValid || res.Event == nil {
			if res.Status == parser.StatusMalformed {
				p.stats.ParserErrors++
			}
			p.stats.Rejected++
			continue
		}

		e := res.Event
		// The id is assigned here, not by the parser: it must be stable across a
		// spool replay, and a replay re-reads the spool rather than the source,
		// so the id has to be persisted with the event.
		e.ID = id.NewEvent()
		// The agent does not assert its own identity; the server binds it from
		// the credential. Sending a value here would only be overwritten.
		e.AgentID = ""

		if err := validation.Normalize(e, p.optsVal); err != nil {
			p.stats.Rejected++
			if strings.Contains(err.Error(), "clock skew") {
				p.stats.ClockSkewWarned++
			}
			continue
		}
		p.stats.EventsProduced++
		out = append(out, e)
	}
	return out
}

// enqueue hands a batch to the sender, spilling to disk if the sender is behind.
func (p *producer) enqueue(events []*model.Event) {
	if len(events) == 0 {
		return
	}
	p.queued.Add(int64(len(events)))
	select {
	case p.queue <- events:
	default:
		p.queued.Add(-int64(len(events)))
		// The sender is behind. Spilling to disk keeps the collection loop live
		// so the file offset keeps advancing; blocking here would let the log
		// file grow faster than it is read, which is how a collector silently
		// loses the ability to catch up.
		p.stats.QueueOverflow++
		if err := p.spool.Append(events); err != nil {
			p.log.Error("spool append failed, events lost", "error", err, "events", len(events))
		}
	}
}

// runSimulation emits a deterministic synthetic attack scenario.
//
// Simulation exists so the detection pipeline can be demonstrated and regression
// tested without a real intrusion. It touches no real resource: it writes log
// lines through the same parser the live path uses, so the scenario exercises
// the real code rather than a parallel mock.
func (p *producer) runSimulation(ctx context.Context) error {
	scenario := buildScenario(p.opts.host)
	p.log.Info("simulation started", "host", p.opts.host, "lines", len(scenario))

	assembler := parser.NewAssembler(8<<10, 64<<10)
	var pending []*model.Event

	flush := func() {
		pending = append(pending, p.parseRecords(assembler.Flush(), "simulation")...)
		p.enqueue(pending)
		pending = nil
	}

	for i, line := range scenario {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Each synthetic line carries its own timestamp, so the scenario keeps
		// its internal chronology regardless of how fast it is replayed.
		p.stats.LinesRead++
		pending = append(pending, p.parseRecords(assembler.Feed(line+"\n"), "simulation")...)

		if len(pending) >= p.opts.batchSize || i == len(scenario)-1 {
			flush()
		}

		// Spread the scenario over a short window so the sliding-window rules
		// see a realistic arrival pattern.
		time.Sleep(20 * time.Millisecond)
	}

	// Give the sender time to drain before exiting.
	time.Sleep(2 * time.Second)
	p.log.Info("simulation finished",
		"lines", p.stats.LinesRead,
		"events_produced", p.stats.EventsProduced,
		"rejected", p.stats.Rejected,
		"queue_overflow", p.stats.QueueOverflow,
	)
	return nil
}

// buildScenario returns deterministic auth.log lines describing a brute force
// followed by a successful login, a privileged command, and a persistence
// action.
//
// Timestamps are relative to now and are formatted in the syslog layout with a
// space-padded day, matching what a real sshd writes.
func buildScenario(host string) []string {
	base := time.Now().UTC().Truncate(time.Second)

	const attacker = "203.0.113.77"
	const victim = "198.51.100.23"

	var out []string
	ts := func(offset time.Duration) string {
		return base.Add(offset).Format("Jan _2 15:04:05")
	}

	// Stage 1: credential access. Five failures from one source crosses the
	// ssh-bruteforce threshold.
	for i := 0; i < 6; i++ {
		out = append(out, fmt.Sprintf("%s %s sshd[%d]: Failed password for root from %s port %d ssh2",
			ts(time.Duration(i)*time.Second), host, 2000+i, attacker, 40000+i))
	}

	// Stage 2: initial access. A successful login from the same source chains
	// onto the brute force.
	out = append(out, fmt.Sprintf("%s %s sshd[2100]: Accepted password for root from %s port 41000 ssh2",
		ts(40*time.Second), host, attacker))

	// Stage 3: privilege escalation.
	out = append(out, fmt.Sprintf("%s %s sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt-get update",
		ts(45*time.Second), host))

	// Stage 4: persistence.
	out = append(out, fmt.Sprintf("%s %s auditd: file=/root/.ssh/authorized_keys modified by user=root",
		ts(50*time.Second), host))

	// A legitimate login from a different source must not raise an incident,
	// which makes the grouping behaviour visible in a demo.
	out = append(out, fmt.Sprintf("%s %s sshd[2200]: Accepted password for deploy from %s port 43000 ssh2",
		ts(60*time.Second), host, victim))

	return out
}

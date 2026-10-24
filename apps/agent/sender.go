package main

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

const (
	minBackoff = time.Second
	maxBackoff = 60 * time.Second
)

// senderLoop drains the in-memory queue and the disk spool to the server.
//
// Delivery order is deliberate: queued live events are attempted first so that
// fresh telemetry is not delayed behind a backlog, and the spool is drained
// afterwards. Both paths are idempotent on the server, so a partial failure
// results in re-delivery rather than loss.
func senderLoop(ctx context.Context, c *client, sp *spool, queue <-chan []*model.Event, queued *atomic.Int64, opts options, log *slog.Logger, producerDone <-chan struct{}) error {
	backoff := minBackoff

	for {
		select {
		case <-ctx.Done():
			// Wait for the producer's final batch, then spool whatever is still queued.
			<-producerDone
			drainQueueToSpool(sp, queue, queued, log)
			return nil
		case batch := <-queue:
			queued.Add(-int64(len(batch)))
			if err := deliver(ctx, c, sp, batch, &backoff, log); err != nil {
				return err
			}
			// Drain the spool opportunistically once connectivity is restored.
			if sp.Size() > 0 {
				if err := drainSpool(ctx, c, sp, opts, log); err != nil {
					return err
				}
			}
		case <-time.After(2 * time.Second):
			if sp.Size() > 0 {
				if err := drainSpool(ctx, c, sp, opts, log); err != nil {
					return err
				}
			}
		}
	}
}

// deliver sends one batch, applying exponential backoff with jitter on failure.
//
// Jitter matters even for a single agent: several agents recovering from the
// same outage would otherwise retry in lockstep and hit the server in bursts.
func deliver(ctx context.Context, c *client, sp *spool, batch []*model.Event, backoff *time.Duration, log *slog.Logger) error {
	if len(batch) == 0 {
		return nil
	}

	for attempt := 0; ; attempt++ {
		err := c.sendBatch(ctx, batch)
		if err == nil {
			*backoff = minBackoff
			return nil
		}
		if errors.Is(err, context.Canceled) {
			// Spool the in-flight batch; the server collapses a replay by event id.
			if serr := sp.Append(batch); serr != nil {
				log.Error("spool append failed on shutdown, events lost", "error", serr, "events", len(batch))
			}
			return nil
		}

		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.permanent() {
			// The server will never accept this batch. Spooling it would block
			// the queue forever behind a payload that cannot be delivered, so
			// it is discarded and logged with its size.
			log.Error("batch rejected permanently, discarding",
				"status", apiErr.Status, "code", apiErr.Code, "events", len(batch))
			return nil
		}

		log.Warn("delivery failed, spooling", "attempt", attempt+1, "events", len(batch), "error", err)
		if serr := sp.Append(batch); serr != nil {
			log.Error("spool append failed, events lost", "error", serr, "events", len(batch))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(jittered(*backoff)):
		}
		*backoff = nextBackoff(*backoff)
	}
}

// drainQueueToSpool persists batches left in the channel at shutdown.
func drainQueueToSpool(sp *spool, queue <-chan []*model.Event, queued *atomic.Int64, log *slog.Logger) {
	for {
		select {
		case batch := <-queue:
			queued.Add(-int64(len(batch)))
			if len(batch) == 0 {
				continue
			}
			if err := sp.Append(batch); err != nil {
				log.Error("spool append failed on shutdown, events lost", "error", err, "events", len(batch))
			}
		default:
			return
		}
	}
}

// drainSpool sends spooled events in batches.
func drainSpool(ctx context.Context, c *client, sp *spool, opts options, log *slog.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		batch, err := sp.Read(opts.batchSize)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}

		err = c.sendBatch(ctx, batch)
		if err != nil {
			var apiErr *apiError
			if errors.As(err, &apiErr) && apiErr.permanent() {
				// Drop the poison batch so the spool can make progress.
				log.Error("spooled batch rejected permanently, discarding",
					"status", apiErr.Status, "code", apiErr.Code, "events", len(batch))
				if ackErr := sp.Ack(len(batch)); ackErr != nil {
					return ackErr
				}
				continue
			}
			// Still unreachable: leave the spool untouched and retry later.
			return nil
		}

		if err := sp.Ack(len(batch)); err != nil {
			return err
		}
		log.Info("spooled events delivered", "events", len(batch), "remaining_bytes", sp.Size())
	}
}

// heartbeatLoop reports liveness and buffer health.
func heartbeatLoop(ctx context.Context, c *client, sp *spool, queued *atomic.Int64, log *slog.Logger) {
	// Send one immediately so the UI shows the agent as online without waiting
	// for the first interval.
	send := func() {
		ctxTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := c.heartbeat(ctxTimeout, queued.Load(), sp.Size(), sp.Dropped() > 0); err != nil {
			log.Warn("heartbeat failed", "error", err)
		}
	}
	send()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

// nextBackoff doubles the delay up to the cap.
func nextBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}

// jittered returns d perturbed by up to 20%.
func jittered(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	delta := float64(d) * 0.2
	return d + time.Duration((rand.Float64()*2-1)*delta)
}

// osDescription returns a short OS identifier for the agent record.
func osDescription() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

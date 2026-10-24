// Command agent collects Linux telemetry, normalizes it, and ships it to the
// HalimiSOC API.
//
// The agent is a single static binary with no runtime dependency beyond the
// operating system. Its design priorities are, in order: never lose telemetry
// silently, never grow memory or disk without bound, and never trust the log
// content it reads.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "dev"

type options struct {
	server      string
	token       string
	enrollToken string
	host        string
	file        string
	interval    time.Duration
	simulate    bool
	spoolDir    string
	stateDir    string
	queueSize   int
	spoolBytes  int64
	batchSize   int
	insecure    bool
	caCert      string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	var opts options
	flag.StringVar(&opts.server, "server", envOr("HALIMISOC_SERVER", "http://localhost:8080"), "HalimiSOC API base URL")
	flag.StringVar(&opts.token, "token", os.Getenv("HALIMISOC_AGENT_TOKEN"), "per-agent token (omit to enroll)")
	flag.StringVar(&opts.enrollToken, "enroll-token", os.Getenv("HALIMISOC_ENROLL_TOKEN"), "enrollment secret used to obtain a token")
	flag.StringVar(&opts.host, "host", defaultHost(), "hostname reported to the server")
	flag.StringVar(&opts.file, "file", "", "log file to collect (required unless -simulate)")
	flag.DurationVar(&opts.interval, "interval", 2*time.Second, "poll interval for log files")
	flag.BoolVar(&opts.simulate, "simulate", false, "generate a deterministic synthetic attack scenario instead of reading a file")
	flag.StringVar(&opts.spoolDir, "spool-dir", envOr("HALIMISOC_SPOOL_DIR", "data/spool"), "directory used to buffer events while the server is unreachable")
	flag.StringVar(&opts.stateDir, "state-dir", envOr("HALIMISOC_STATE_DIR", "data/state"), "directory used to persist read offsets")
	flag.IntVar(&opts.queueSize, "queue", 4096, "maximum events held in memory before spilling to disk")
	flag.Int64Var(&opts.spoolBytes, "spool-bytes", 100<<20, "maximum on-disk spool size in bytes")
	flag.IntVar(&opts.batchSize, "batch", 100, "maximum events per request")
	flag.BoolVar(&opts.insecure, "insecure", false, "allow plain HTTP (development only)")
	flag.StringVar(&opts.caCert, "ca-cert", os.Getenv("HALIMISOC_CA_CERT"), "PEM file with additional trusted CAs")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("halimisoc-agent", version)
		return nil
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := opts.validate(); err != nil {
		return err
	}
	if strings.HasPrefix(opts.server, "http://") && !opts.insecure {
		return errors.New("refusing to send credentials over plain HTTP; use https or pass -insecure for local development")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// An enrolled agent keeps its credential on disk so the enrollment secret
	// does not have to live on the host forever. The flag and environment still
	// win, which keeps the first boot and rotation paths explicit.
	if opts.token == "" {
		token, err := loadToken(opts.stateDir)
		if err != nil {
			return err
		}
		opts.token = token
	}

	client, err := newClient(opts, log)
	if err != nil {
		return err
	}

	if opts.token == "" {
		if opts.enrollToken == "" {
			return errors.New("either -token, a persisted token, or -enroll-token is required")
		}
		token, agentID, err := client.enroll(ctx, opts)
		if err != nil {
			return err
		}
		if err := saveToken(opts.stateDir, token); err != nil {
			return err
		}
		opts.token = token
		client.token = token
		log.Info("agent enrolled", "agent_id", agentID, "host", opts.host)
	} else if _, err := client.self(ctx); err != nil {
		// A rejected credential is fatal: continuing would spool telemetry that
		// can never be delivered. An unreachable server is not: that is exactly
		// the outage the spool exists to survive, so the agent keeps running and
		// resolves its identity when the server returns.
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			return fmt.Errorf("agent credential was rejected: %w", err)
		}
		log.Warn("could not verify agent credential yet, continuing", "error", err)
	}

	spool, err := newSpool(opts.spoolDir, opts.spoolBytes, log)
	if err != nil {
		return err
	}

	// The pipeline: a producer emits events into a bounded channel, the sender
	// consumes them. When the channel is full the producer spills to the spool
	// instead of blocking, so a slow server degrades collection rather than
	// stalling it, and no telemetry is dropped without a counter.
	queue := make(chan []*model.Event, 8)
	// queued counts events waiting in memory, which is what the heartbeat
	// reports. The configured queue size is a bound, not a backlog.
	var queued atomic.Int64
	producerDone := make(chan struct{})

	var senderWG sync.WaitGroup
	senderWG.Add(1)
	go func() {
		defer senderWG.Done()
		if err := senderLoop(ctx, client, spool, queue, &queued, opts, log, producerDone); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("sender stopped", "error", err)
			stop()
		}
	}()
	go heartbeatLoop(ctx, client, spool, &queued, log)

	producer := newProducer(opts, client, spool, queue, &queued, log)
	if opts.simulate {
		err = producer.runSimulation(ctx)
	} else {
		err = producer.runTail(ctx)
	}

	// Stop collecting before the sender drains the queue; exiting early loses the last batch.
	close(producerDone)
	stop()
	senderWG.Wait()
	return err
}

func (o options) validate() error {
	if o.server == "" {
		return errors.New("server URL is required")
	}
	if o.host == "" {
		return errors.New("host is required")
	}
	if !o.simulate && o.file == "" {
		return errors.New("either -file or -simulate is required")
	}
	if o.interval < 100*time.Millisecond {
		return errors.New("interval must be at least 100ms")
	}
	if o.batchSize < 1 || o.batchSize > 5000 {
		return errors.New("batch must be between 1 and 5000")
	}
	if o.queueSize < 1 {
		return errors.New("queue must be positive")
	}
	if o.spoolBytes < 1<<20 {
		return errors.New("spool-bytes must be at least 1 MiB")
	}
	return nil
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func defaultHost() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown-host"
}

// ensureDir creates a directory with restrictive permissions.
//
// Spooled telemetry and reader offsets are operational state, not secrets, but
// they describe the host's activity, so they are not world-readable.
func ensureDir(path string) error {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return fmt.Errorf("create directory %s: %w", path, err)
	}
	return nil
}

func abs(path string) string {
	if p, err := filepath.Abs(path); err == nil {
		return p
	}
	return path
}

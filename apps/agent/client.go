package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

// client talks to the HalimiSOC API.
type client struct {
	base  *url.URL
	token string
	http  *http.Client
	log   *slog.Logger
	opts  options

	// agentID is learned from the server. The agent does not persist its own
	// identity: it is a stateless process that may be restarted with only a
	// token, so it asks the server who it is.
	agentID string
}

// apiError is a structured error response from the server.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("server returned %d (%s): %s", e.Status, e.Code, e.Message)
}

// permanent reports whether retrying the same request could ever succeed.
//
// A 4xx that is not a rate limit means the request itself is wrong, so retrying
// it forever would block the queue behind a payload the server will never
// accept. Those batches are dropped and counted rather than retried.
func (e *apiError) permanent() bool {
	switch e.Status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return e.Status >= 400 && e.Status < 500
}

func newClient(opts options, log *slog.Logger) (*client, error) {
	base, err := url.Parse(opts.server)
	if err != nil {
		// validate() already ensured the URL parses well enough to start; this
		// guard exists so the struct is always usable.
		base = &url.URL{Scheme: "http", Host: "localhost:8080"}
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.caCert != "" {
		pem, err := os.ReadFile(opts.caCert)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no certificates", opts.caCert)
		}
		tlsConfig.RootCAs = pool
	}

	return &client{
		base:  base,
		token: opts.token,
		log:   log,
		opts:  opts,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				TLSClientConfig:     tlsConfig,
			},
		},
	}, nil
}

type enrollRequest struct {
	EnrollmentSecret string `json:"enrollment_secret"`
	Host             string `json:"host"`
	OS               string `json:"os"`
	Version          string `json:"version"`
}

type enrollResponse struct {
	AgentID    string `json:"agent_id"`
	Host       string `json:"host"`
	AgentToken string `json:"agent_token"`
}

// enroll exchanges the enrollment secret for a per-agent token.
func (c *client) enroll(ctx context.Context, opts options) (string, string, error) {
	body := enrollRequest{
		EnrollmentSecret: opts.enrollToken,
		Host:             opts.host,
		OS:               osDescription(),
		Version:          version,
	}
	var resp enrollResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/agents/register", body, &resp); err != nil {
		return "", "", fmt.Errorf("enroll: %w", err)
	}
	if resp.AgentToken == "" {
		return "", "", errors.New("enroll: server returned no agent token")
	}
	c.agentID = resp.AgentID
	return resp.AgentToken, resp.AgentID, nil
}

// self resolves the agent identity that the presented token belongs to.
func (c *client) self(ctx context.Context) (string, error) {
	var resp struct {
		ID   string `json:"id"`
		Host string `json:"host"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/agents/me", nil, &resp); err != nil {
		return "", fmt.Errorf("resolve agent identity: %w", err)
	}
	if resp.ID == "" {
		return "", errors.New("resolve agent identity: server returned no id")
	}
	c.agentID = resp.ID
	return resp.ID, nil
}

type ingestRequest struct {
	Events []*model.Event `json:"events"`
}

type ingestResponse struct {
	Received   int `json:"received"`
	Inserted   int `json:"inserted"`
	Duplicates int `json:"duplicates"`
	Rejected   []struct {
		Index  int    `json:"index"`
		ID     string `json:"id"`
		Reason string `json:"reason"`
	} `json:"rejected"`
}

// sendBatch delivers a batch of events.
func (c *client) sendBatch(ctx context.Context, events []*model.Event) error {
	if len(events) == 0 {
		return nil
	}
	var resp ingestResponse
	return c.do(ctx, http.MethodPost, "/api/v1/events", ingestRequest{Events: events}, &resp)
}

type heartbeatRequest struct {
	QueueDepth int64 `json:"queue_depth"`
	SpoolBytes int64 `json:"spool_bytes"`
	Degraded   bool  `json:"degraded"`
}

// heartbeat reports liveness and buffer health.
//
// The agent id is part of the path so the server can verify that the presented
// credential belongs to the agent being reported on.
func (c *client) heartbeat(ctx context.Context, queueDepth, spoolBytes int64, degraded bool) error {
	if c.agentID == "" {
		id, err := c.self(ctx)
		if err != nil {
			return err
		}
		c.agentID = id
	}
	return c.do(ctx, http.MethodPost, "/api/v1/agents/"+c.agentID+"/heartbeat", heartbeatRequest{
		QueueDepth: queueDepth,
		SpoolBytes: spoolBytes,
		Degraded:   degraded,
	}, nil)
}

// do performs an authenticated JSON request.
func (c *client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	target := *c.base
	target.Path = strings.TrimSuffix(target.Path, "/") + path

	req, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		// Drain so the connection can be reused, but bound the read: the
		// response is untrusted input and must not be able to exhaust memory.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		return decodeAPIError(resp)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func decodeAPIError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &envelope)
	return &apiError{Status: resp.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message}
}

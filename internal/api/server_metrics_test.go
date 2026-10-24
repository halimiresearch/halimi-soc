package api_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// r.Method is attacker-chosen on an unauthenticated endpoint. It must not be
// used as an unbounded metric label or logged verbatim, or a client can mint a
// series (and a log line) per distinct token.
func TestRequestMethodLabelIsBounded(t *testing.T) {
	h := newHarness(t)

	resp := h.do("PROPFIND", "/healthz", nil, nil)
	resp.Body.Close()
	resp = h.do(http.MethodGet, "/metrics", nil, nil)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	if strings.Contains(out, `method="PROPFIND"`) {
		t.Fatalf("an arbitrary method reached the label set:\n%s", out)
	}
	if !strings.Contains(out, `method="other"`) {
		t.Fatalf("arbitrary method was not folded into \"other\":\n%s", out)
	}
}

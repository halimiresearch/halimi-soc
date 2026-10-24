package api_test

import (
	"io"
	"net/http"
	"testing"
)

// A cursor whose anchor no longer resolves must say so. Returning an empty
// page makes the console claim, authoritatively, that nothing matches.
func TestListRejectsCursorWithNoResults(t *testing.T) {
	h := newHarness(t)
	if _, status := h.login("admin", adminPassword); status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}

	for _, path := range []string{
		"/api/v1/events?cursor=evt_does_not_exist",
		"/api/v1/alerts?cursor=alt_does_not_exist",
	} {
		resp := h.do(http.MethodGet, path, nil, nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s = %d (%s), want 400", path, resp.StatusCode, body)
		}
	}
}

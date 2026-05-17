package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGorillaFailFallsThroughToDecoy verifies that malformed WS-upgrade attempts
// produce status 200 indistinguishable from random-path GETs. Closes A2-MED-6.
//
// Without the suppression of gorilla/websocket's default error response,
// upgrades that pass the top-level `Upgrade: websocket` dispatch but fail
// gorilla's validation (bad Sec-WebSocket-Key, wrong protocol version) emit
// a 400 with a text body — a cheap active-probe vector that distinguishes a
// WS-capable endpoint from a random path that yields the decoy 200. After
// the fix, gorilla's default error writer is replaced with noopUpgradeError
// and the request is routed through failClosedToDecoy, producing a normal
// 200 decoy response sanitized via httpPlaceholderRequest.
//
// Scope note: probes that omit the `Upgrade: websocket` header never enter
// handleWebSocket — they fall through to the top-level non-POST decoy serve
// in handler.go ServeHTTP. That path's URL-echo behavior is a separately
// tracked DPI surface (path-echo via decoy 404) and is out of scope for
// A2-MED-6, which is scoped to handleWebSocket.
func TestGorillaFailFallsThroughToDecoy(t *testing.T) {
	h := newTestHandler(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	wsPath := wsAllowedPathForTest(t)
	probes := []struct {
		name   string
		modify func(r *http.Request)
	}{
		{
			name: "malformed_sec_ws_key",
			modify: func(r *http.Request) {
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "not-base64!!!")
			},
		},
		{
			name: "wrong_protocol_version",
			modify: func(r *http.Request) {
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "8")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			},
		},
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", srv.URL+wsPath, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			p.modify(req)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("probe %q got status %d, want 200 (decoy)", p.name, resp.StatusCode)
			}
		})
	}
}

// wsAllowedPathForTest returns a path accepted by IsAllowedWSPath. It uses
// "/socket.io/" — the first entry in wsURLPool — as the canonical sentinel.
func wsAllowedPathForTest(t *testing.T) string {
	t.Helper()
	const sentinel = "/socket.io/"
	if !IsAllowedWSPath(sentinel) {
		t.Fatalf("sentinel path %q no longer in wsURLPool — update test", sentinel)
	}
	return sentinel
}

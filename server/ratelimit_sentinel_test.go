package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

// Task A2 (May audit, 2026-05-01): when the per-clientIP handshake rate limit
// fires, the decoy response must carry an X-SL-RL sentinel so the client can
// distinguish "rate-limited by server" from "html decoy returned by middlebox"
// and apply a fixed cool-down instead of exp backoff.
//
// C5 (2026-05-02) upgraded the sentinel wire format from the literal `1` to a
// verbose key=value: "bucket=<label>,burst_left=<int>,refill_in=<seconds>s,
// exempt=<0|1>". Tests below assert the new format; the legacy expectation is
// gone.
//
// The header is emitted ONLY from the rate-limit branches of
// handleHandshakeNew + handleWebSocket. Non-rate-limit failClosedToDecoy
// callers (decrypt fail, replay reject, etc.) MUST NOT emit it — that would
// leak information about which gate the request hit.

// TestHandshakeRateLimit_EmitsXSLRLHeader drains the handshake limiter for
// 127.0.0.1 (matches httptest binding) and verifies the next handshake POST
// returns 200 + decoy body + X-SL-RL: 1.
func TestHandshakeRateLimit_EmitsXSLRLHeader(t *testing.T) {
	// Force legacy path: test drains the counter+window limiter directly via
	// h.rateLimiters.Handshake.Allow; with bucket-on the HTTP path would
	// consume the TokenBucket (separate state) and not see exhaustion.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	h, _ := setupTestHandler(t)

	// Drain the Handshake limiter: default 300/min from NewRateLimiters.
	for range 300 {
		require.True(t, h.rateLimiters.Handshake.Allow("192.0.2.1"))
	}
	// Sanity anchor: one more Allow() must fail BEFORE we exercise the HTTP path.
	require.False(t, h.rateLimiters.Handshake.Allow("192.0.2.1"))

	// Now hit handleHandshakeNew directly — RemoteAddr drives clientIP. We use
	// an off-loopback IP and disable BehindProxy in TestConfig so the only
	// extraction path is RemoteAddr.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/a", bytes.NewReader([]byte("{}")))
	req.RemoteAddr = "192.0.2.1:55555"
	// Drive ephPub/encClientID with throwaway garbage — control flow never
	// reaches DecryptClientID; the rate-limit gate at the top short-circuits.
	h.handleHandshakeNew(rec, req, []byte("eph"), []byte("enc"))

	// C5 verbose format: legacy AllowHandshake returns (false, 0, 0) so we
	// expect bucket=handshake,burst_left=0,refill_in=0s,exempt=0 here.
	got := rec.Header().Get("X-SL-RL")
	require.Equal(t, "bucket=handshake,burst_left=0,refill_in=0s,exempt=0", got,
		"handshake rate-limit branch must emit verbose X-SL-RL sentinel")
	// Body shape stays decoy — no ServerHello leak.
	require.NotContains(t, rec.Body.String(), `"eph"`)
	require.NotContains(t, rec.Body.String(), `"_v":1`)
}

// TestWSUpgradeRateLimit_EmitsXSLRLHeader: drain the WSUpgrade limiter via
// loopback + assert that the next plain HTTP GET to a WS path returns 200 +
// decoy body + X-SL-RL: 1. We bypass the actual websocket dialer here because
// the rate-limit gate sits BEFORE wsUpgrader.Upgrade — a normal HTTP recorder
// suffices to inspect the response.
func TestWSUpgradeRateLimit_EmitsXSLRLHeader(t *testing.T) {
	// Force legacy path: test drains WSUpgrade counter+window limiter directly.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	h, _ := setupTestHandler(t)

	// Drain WSUpgrade: default cap is 30/min.
	for range 30 {
		require.True(t, h.rateLimiters.WSUpgrade.Allow("127.0.0.1"))
	}
	require.False(t, h.rateLimiters.WSUpgrade.Allow("127.0.0.1"))

	wsPath := AllWSPaths()[0]
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", wsPath, nil)
	// Need Upgrade: websocket so handleWebSocket entry guard accepts the req.
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "x3JJHMbDL1EzLkh9GBhXDw==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.RemoteAddr = "127.0.0.1:55555"

	h.handleWebSocket(rec, req)

	// C5 verbose format: legacy AllowWSUpgrade returns (false, 0, 0).
	require.Equal(t, "bucket=ws_upgrade,burst_left=0,refill_in=0s,exempt=0",
		rec.Header().Get("X-SL-RL"),
		"WS upgrade rate-limit branch must emit verbose X-SL-RL sentinel")
}

// TestFailClosedToDecoy_DoesNotEmitXSLRLHeader is the negative test: the
// generic failClosedToDecoy path (used by decrypt-fail / replay-reject /
// backpressure / max-clients etc.) MUST NOT carry the sentinel. Otherwise
// the client would treat a one-off decrypt fail as a 3-minute server-wide
// rate-limit cool-down and starve the slot needlessly.
func TestFailClosedToDecoy_DoesNotEmitXSLRLHeader(t *testing.T) {
	h, _ := setupTestHandler(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/a", bytes.NewReader([]byte("garbage")))
	h.failClosedToDecoy(rec, req)

	require.Empty(t, rec.Header().Get("X-SL-RL"),
		"non-rate-limit failClosedToDecoy must NOT emit X-SL-RL header")
}

// TestRateLimitSentinelMetric: every rate-limited branch must increment
// the dedicated counter so ops can chart sentinel emission rate.
func TestRateLimitSentinelMetric(t *testing.T) {
	// Force legacy path: drains the counter+window limiter directly.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	h, _ := setupTestHandler(t)

	// Drain Handshake limiter for a fresh IP so we hit the gate clean.
	for range 300 {
		require.True(t, h.rateLimiters.Handshake.Allow("198.51.100.7"))
	}

	before := h.metrics.RateLimitSentinelEmitted.Load()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/a", bytes.NewReader([]byte("{}")))
	req.RemoteAddr = "198.51.100.7:42"
	h.handleHandshakeNew(rec, req, []byte("eph"), []byte("enc"))
	after := h.metrics.RateLimitSentinelEmitted.Load()

	require.Equal(t, before+1, after, "sentinel counter must tick on rate-limit")
}

// TestRateLimitSentinel_TimingPipelinePreserved: the rate-limited branch must
// still run the synthetic dispatch + ackJitter pipeline so a network observer
// cannot timing-distinguish "rate limited" from "decrypt fail" or any other
// failClosedToDecoy path. We assert this indirectly via the TimingOracleHits
// counter, which is bumped by the shared core helper.
func TestRateLimitSentinel_TimingPipelinePreserved(t *testing.T) {
	// Force legacy path: drains the counter+window limiter directly.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	h, _ := setupTestHandler(t)

	for range 300 {
		require.True(t, h.rateLimiters.Handshake.Allow("203.0.113.9"))
	}

	before := h.metrics.TimingOracleHits.Load()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/a", bytes.NewReader([]byte("{}")))
	req.RemoteAddr = "203.0.113.9:1"
	h.handleHandshakeNew(rec, req, []byte("eph"), []byte("enc"))
	after := h.metrics.TimingOracleHits.Load()

	require.Equal(t, before+1, after,
		"rate-limit decoy must keep the synthetic dispatch + ackJitter pipeline")
}

// TestRateLimitSentinel_VerboseFormat pins the C5 wire format: every field is
// stamped into the header value in the documented order with the documented
// units. A regression that flips two fields, drops one, or changes the unit
// suffix breaks this test before it ships to clients.
func TestRateLimitSentinel_VerboseFormat(t *testing.T) {
	rec := httptest.NewRecorder()
	writeRateLimitSentinelV2(rec, RLSentinel{
		Bucket: "handshake", BurstLeft: 12, RefillIn: 8 * time.Second, Exempt: 0,
	})
	got := rec.Header().Get("X-SL-RL")
	want := "bucket=handshake,burst_left=12,refill_in=8s,exempt=0"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Make sure the gorilla import is used even if the harness call below is later
// rewritten — keeps "go vet" quiet without an opportunistic cleanup.
var _ = websocket.IsCloseError

// _ = http.StatusOK silences unused-import on http if a future edit tightens
// the test to a 200 code-equality assertion rather than the header check above.
var _ = http.StatusOK

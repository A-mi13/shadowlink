package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// captureSlog redirects slog.Default to a JSON handler writing into buf for
// the duration of t. The previous default is restored on test cleanup so
// parallel tests in the same package don't bleed log output between runs.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	t.Cleanup(ResetDecoyLogStateForTest)
	return &buf
}

// parseLogLines splits a JSON-handler buffer into one map per emitted record.
// Helps tests assert per-record fields without dragging in a real test logger
// dependency.
func parseLogLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// TestFailClosedToDecoy_LogsReason exercises the new observability surface:
// every dispatch through the WithReason variant must emit a structured WARN
// carrying the reason label, the resolved client IP, the request path/method,
// a truncated UA, and the Content-Length. The JSON handler shape lets us
// assert per-field values without parsing a free-form text format.
func TestFailClosedToDecoy_LogsReason(t *testing.T) {
	ResetDecoyLogStateForTest()
	buf := captureSlog(t)

	h, _ := setupTestHandler(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader([]byte("{}")))
	req.RemoteAddr = "203.0.113.42:55555"
	req.Header.Set("User-Agent", strings.Repeat("X", 200)) // > 60-byte truncate threshold
	req.ContentLength = 2

	h.failClosedToDecoyWithReason(rec, req, DecoyReasonAuthFail)

	lines := parseLogLines(t, buf)
	require.NotEmpty(t, lines, "expected at least one log line")
	var found map[string]any
	for _, l := range lines {
		if l["msg"] == "decoy served" {
			found = l
			break
		}
	}
	require.NotNil(t, found, "missing decoy served WARN line; got=%v", lines)
	require.Equal(t, "WARN", found["level"])
	require.Equal(t, string(DecoyReasonAuthFail), found["reason"])
	require.Equal(t, "203.0.113.42", found["remote_ip"])
	require.Equal(t, "/api/v2/events", found["path"])
	require.Equal(t, "POST", found["method"])
	// UA must be truncated at 60 chars.
	ua, _ := found["ua"].(string)
	require.Len(t, ua, 60, "UA must be truncated to 60 bytes; got len=%d", len(ua))
	// content_length is JSON-encoded as float64 by encoding/json.
	require.EqualValues(t, 2, found["content_length"])
}

// TestFailClosedToDecoy_PerIPRateLimit verifies that >10 dispatches from a
// single IP within the window emit at most decoyLogPerIPLimit WARNs while
// the per-reason counter still ticks for every dispatch. This is the spam
// guard from the spec — `1000+/min` from one IP must not flood the journal.
func TestFailClosedToDecoy_PerIPRateLimit(t *testing.T) {
	ResetDecoyLogStateForTest()
	buf := captureSlog(t)

	h, _ := setupTestHandler(t)

	const burst = 50
	for i := 0; i < burst; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/x", nil)
		req.RemoteAddr = "198.51.100.7:1"
		h.failClosedToDecoyWithReason(rec, req, DecoyReasonProtocolUnknown)
	}

	lines := parseLogLines(t, buf)
	decoyLines := 0
	for _, l := range lines {
		if l["msg"] == "decoy served" {
			decoyLines++
		}
	}
	require.LessOrEqual(t, decoyLines, decoyLogPerIPLimit,
		"per-IP cap exceeded: got %d log lines, want <=%d", decoyLines, decoyLogPerIPLimit)

	// Counter must reflect every dispatch, not just the logged ones.
	snap := h.metrics.DecoyServedSnapshot()
	require.EqualValues(t, burst, snap[DecoyReasonProtocolUnknown],
		"counter must tick for every dispatch even after WARN suppression")

	logged, dropped := DecoyLogStats()
	require.LessOrEqual(t, logged, uint64(decoyLogPerIPLimit))
	require.GreaterOrEqual(t, dropped, uint64(burst-decoyLogPerIPLimit))
}

// TestFailClosedToDecoy_PerIPWindowRollover verifies that after the per-IP
// window expires the IP is allowed to log again. We synthesize a future "now"
// by directly manipulating the per-IP state; this tests the rollover branch
// of shouldLogForIP without sleeping a real minute.
func TestFailClosedToDecoy_PerIPWindowRollover(t *testing.T) {
	ResetDecoyLogStateForTest()

	now := time.Now()
	for i := 0; i < decoyLogPerIPLimit; i++ {
		allow, _ := shouldLogForIP("192.0.2.1", now)
		require.True(t, allow, "first %d must be allowed", decoyLogPerIPLimit)
	}
	// Cap reached.
	allow, _ := shouldLogForIP("192.0.2.1", now)
	require.False(t, allow, "11th call within window must be suppressed")

	// Future now beyond the window — bucket resets.
	future := now.Add(decoyLogPerIPWindow + time.Second)
	allow, suppressed := shouldLogForIP("192.0.2.1", future)
	require.True(t, allow, "post-window call must be allowed")
	// Suppressed counter from the prior window surfaces on the first allow of
	// the new window so ops can still see "X dropped during the storm".
	require.GreaterOrEqual(t, suppressed, uint64(1))
}

// TestFailClosedToDecoy_MultipleIPsIndependent verifies the per-IP cap is
// per-source: a flood from IP A must not deny logs to IP B.
func TestFailClosedToDecoy_MultipleIPsIndependent(t *testing.T) {
	ResetDecoyLogStateForTest()
	buf := captureSlog(t)
	h, _ := setupTestHandler(t)

	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/x", nil)
		req.RemoteAddr = "203.0.113.99:1"
		h.failClosedToDecoyWithReason(rec, req, DecoyReasonAuthFail)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/y", nil)
	req.RemoteAddr = "198.51.100.55:2"
	h.failClosedToDecoyWithReason(rec, req, DecoyReasonAuthFail)

	lines := parseLogLines(t, buf)
	sawSecondIP := false
	for _, l := range lines {
		if l["msg"] == "decoy served" && l["remote_ip"] == "198.51.100.55" {
			sawSecondIP = true
			break
		}
	}
	require.True(t, sawSecondIP, "second IP's first log must not be suppressed by first IP's flood")
}

// TestDecoyServed_PromExposition pins the per-reason Prom counter format —
// every reason in AllDecoyReasons must appear in the output so dashboards
// pre-built against the label list don't break when a counter happens to
// be zero at scrape time.
func TestDecoyServed_PromExposition(t *testing.T) {
	ResetDecoyLogStateForTest()
	h, _ := setupTestHandler(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.0.2.50:1"
	h.failClosedToDecoyWithReason(rec, req, DecoyReasonReplayDetected)

	mw := httptest.NewRecorder()
	mreq := httptest.NewRequest("GET", "/?format=prom", nil)
	h.metrics.ServeHTTP(mw, mreq)
	body := mw.Body.String()

	require.Contains(t, body, "shadowlink_decoy_served_total")
	for _, r := range AllDecoyReasons {
		require.Contains(t, body,
			"shadowlink_decoy_served_total{reason=\""+string(r)+"\"}",
			"missing per-reason counter line for %q", r)
	}
	// The reason we incremented must show 1.
	require.Contains(t, body,
		"shadowlink_decoy_served_total{reason=\""+string(DecoyReasonReplayDetected)+"\"} 1")
}

// TestDecoyReasonForRLSentinel pins the bucket-label → reason mapping so a
// regression that swaps two labels gets caught at compile-time-equivalent
// speed (test runs in <1ms, no network).
func TestDecoyReasonForRLSentinel(t *testing.T) {
	cases := []struct {
		info RLSentinel
		want DecoyReason
	}{
		{RLSentinel{Bucket: "ws_upgrade", Exempt: 0}, DecoyReasonRateLimitWSUpgrade},
		{RLSentinel{Bucket: "handshake", Exempt: 0}, DecoyReasonRateLimitHandshake},
		{RLSentinel{Bucket: "data", Exempt: 0}, DecoyReasonRateLimitData},
		{RLSentinel{Bucket: "handshake", Exempt: 1}, DecoyReasonRateLimitSoftLimit},
		{RLSentinel{Bucket: "data", Exempt: 1}, DecoyReasonRateLimitSoftLimit},
		{RLSentinel{Bucket: "garbage", Exempt: 0}, DecoyReasonUnspecified},
	}
	for _, tc := range cases {
		got := decoyReasonForRLSentinel(tc.info)
		require.Equal(t, tc.want, got, "info=%+v", tc.info)
	}
}

// TestTruncate covers the boundary cases of the byte-cut helper.
func TestTruncate(t *testing.T) {
	require.Equal(t, "", truncate("", 60))
	require.Equal(t, "", truncate("abc", 0))
	require.Equal(t, "abc", truncate("abc", 60))
	require.Equal(t, "ab", truncate("abcdef", 2))
	// Verify _ import is alive (helps go vet stay quiet if a future edit
	// drops the http import elsewhere in this file).
	_ = http.StatusOK
}

// TestFailClosedToDecoy_LegacyWrapper_LogsUnspecified verifies that the
// backward-compat wrapper still emits a log + counter — just under the
// `unspecified` reason. CI dashboards alarm on a sustained nonzero rate of
// `unspecified` to catch new call sites that forgot to thread a reason.
func TestFailClosedToDecoy_LegacyWrapper_LogsUnspecified(t *testing.T) {
	ResetDecoyLogStateForTest()
	buf := captureSlog(t)
	h, _ := setupTestHandler(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/legacy", nil)
	req.RemoteAddr = "192.0.2.77:1"
	h.failClosedToDecoy(rec, req)

	lines := parseLogLines(t, buf)
	var found map[string]any
	for _, l := range lines {
		if l["msg"] == "decoy served" {
			found = l
			break
		}
	}
	require.NotNil(t, found)
	require.Equal(t, string(DecoyReasonUnspecified), found["reason"])

	snap := h.metrics.DecoyServedSnapshot()
	require.EqualValues(t, 1, snap[DecoyReasonUnspecified])
}

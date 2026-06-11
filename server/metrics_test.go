package server

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withMemStats makes BackpressureCheck deterministic by injecting a fixed
// memory snapshot instead of reading the live process heap. Without this the
// backpressure tests are flaky under `go test -shuffle`/`-count`: other tests
// in the same binary inflate Alloc, tripping the heuristic. allocMB/sysMB are
// the values BackpressureCheck compares (it uses Alloc vs Sys*0.8/0.9).
func withMemStats(m *Metrics, allocMB, sysMB float64) {
	m.memStatsFn = func(ms *runtime.MemStats) {
		ms.Alloc = uint64(allocMB * 1024 * 1024)
		ms.Sys = uint64(sysMB * 1024 * 1024)
	}
}

func TestMetricsSnapshot(t *testing.T) {
	m := NewMetrics()
	m.ActiveClients.Store(5)
	m.ChunksReceived.Add(100)
	m.ChunksSent.Add(200)
	m.BytesReceived.Add(50000)
	m.BytesSent.Add(100000)
	m.HandshakesTotal.Add(10)
	m.HandshakesFailed.Add(2)

	snap := m.Snapshot()
	assert.Equal(t, int64(5), snap.ActiveClients)
	assert.Equal(t, uint64(100), snap.ChunksReceived)
	assert.Equal(t, uint64(200), snap.ChunksSent)
	assert.Equal(t, uint64(50000), snap.BytesReceived)
	assert.Equal(t, uint64(100000), snap.BytesSent)
	assert.Equal(t, uint64(10), snap.HandshakesTotal)
	assert.Equal(t, uint64(2), snap.HandshakesFailed)
	assert.GreaterOrEqual(t, snap.UptimeSeconds, 0.0)
	assert.Greater(t, snap.MemoryMB, 0.0)
	assert.Greater(t, snap.GoRoutines, 0)
	assert.False(t, snap.Backpressure)
}

func TestMetricsAtomicIncrements(t *testing.T) {
	m := NewMetrics()

	m.ActiveClients.Add(1)
	m.ActiveClients.Add(1)
	m.ActiveClients.Add(-1)
	assert.Equal(t, int64(1), m.ActiveClients.Load())

	m.ChunksReceived.Add(5)
	m.ChunksReceived.Add(3)
	assert.Equal(t, uint64(8), m.ChunksReceived.Load())
}

func TestBackpressureCheckNormal(t *testing.T) {
	m := NewMetrics()
	// Inject low memory (alloc well under sys*0.8) so the result does not depend
	// on the live process heap (deterministic under -shuffle/-count).
	withMemStats(m, 100, 2048) // 100MB alloc on a 2GB sys → normal

	maxConns, reject := m.BackpressureCheck(8)
	assert.Equal(t, 8, maxConns)
	assert.False(t, reject)
	assert.False(t, m.backpressureActive.Load())
}

func TestBackpressureStateTracking(t *testing.T) {
	m := NewMetrics()
	withMemStats(m, 100, 2048) // normal memory

	// Normal check should clear a previously-set backpressure flag.
	m.backpressureActive.Store(true)
	m.BackpressureCheck(8)
	assert.False(t, m.backpressureActive.Load())
}

// TestBackpressureCheck_HighAndCritical proves the injected memory source drives
// the heuristic: high (>80% sys) reduces conns, critical (>90%) rejects.
func TestBackpressureCheck_HighAndCritical(t *testing.T) {
	m := NewMetrics()

	withMemStats(m, 1700, 2048) // 1700/2048 ≈ 83% → high band
	maxConns, reject := m.BackpressureCheck(8)
	assert.Equal(t, 4, maxConns, "high memory reduces conns")
	assert.False(t, reject, "high band still admits new clients")
	assert.True(t, m.backpressureActive.Load())

	withMemStats(m, 1900, 2048) // 1900/2048 ≈ 93% → critical band
	maxConns, reject = m.BackpressureCheck(8)
	assert.Equal(t, 2, maxConns)
	assert.True(t, reject, "critical memory rejects new clients")
	assert.True(t, m.backpressureActive.Load())
}

func TestMetricsHTTPEndpoint(t *testing.T) {
	m := NewMetrics()
	m.ActiveClients.Store(3)
	m.ChunksReceived.Add(42)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics", nil)
	m.ServeHTTP(w, r)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var snap MetricsSnapshot
	err := json.Unmarshal(w.Body.Bytes(), &snap)
	require.NoError(t, err)
	assert.Equal(t, int64(3), snap.ActiveClients)
	assert.Equal(t, uint64(42), snap.ChunksReceived)
	assert.Greater(t, snap.MemoryMB, 0.0)
}

func TestMetricsJSON(t *testing.T) {
	m := NewMetrics()
	snap := m.Snapshot()

	data, err := json.Marshal(snap)
	require.NoError(t, err)

	// Should have all expected fields
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	expectedFields := []string{
		"active_clients", "active_connections",
		"chunks_received", "chunks_sent",
		"bytes_received", "bytes_sent",
		"handshakes_total", "handshakes_failed",
		"rejected_overload", "uptime_seconds",
		"memory_mb", "goroutines", "backpressure_active",
	}
	for _, f := range expectedFields {
		assert.Contains(t, parsed, f, "missing field: %s", f)
	}
}

func TestMetricsRejectedOverload(t *testing.T) {
	m := NewMetrics()
	m.RejectedOverload.Add(1)
	m.RejectedOverload.Add(1)
	m.RejectedOverload.Add(1)
	assert.Equal(t, uint64(3), m.RejectedOverload.Load())

	snap := m.Snapshot()
	assert.Equal(t, uint64(3), snap.RejectedOverload)
}

// TestExposer_IncludesPhase0Fields verifies that the Prometheus text exposer
// renders the 8 new Phase 0 counter/gauge fields added in Task 0.3. Regression
// guard — if a field is missing from writePromMetrics this test fails.
func TestExposer_IncludesPhase0Fields(t *testing.T) {
	m := NewMetrics()

	// Set non-zero values on a representative subset of the new fields.
	m.HandshakesOK.Store(42)
	m.HandshakesAuthFailed.Store(3)
	m.HandshakesMalformed.Store(1)
	m.RateLimitEmittedByBody.Store(7)
	m.RateLimitEmittedByBodyMissing.Store(2)
	m.RatelimitBucketHandshake.Store(95)
	m.RatelimitBucketWSUpgrade.Store(50)
	m.RatelimitBucketData.Store(200)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics?format=prom", nil)
	m.ServeHTTP(w, r)

	require.Equal(t, 200, w.Code)
	body := w.Body.String()

	expected := []string{
		"shadowlink_handshakes_ok_total 42",
		"shadowlink_handshakes_auth_failed_total 3",
		"shadowlink_handshakes_malformed_total 1",
		"shadowlink_ratelimit_emitted_by_body_total 7",
		"shadowlink_ratelimit_emitted_by_body_missing_total 2",
		"shadowlink_ratelimit_bucket_handshake 95",
		"shadowlink_ratelimit_bucket_ws_upgrade 50",
		"shadowlink_ratelimit_bucket_data 200",
	}
	for _, line := range expected {
		assert.True(t, strings.Contains(body, line),
			"prom output missing line %q\nbody:\n%s", line, body)
	}
}

// TestMetrics_WSPathLegacyHits (Wave 2.1, 2026-05-17) verifies the new
// atomic.Uint64 counter introduced for the legacy WS path observation:
// every WS upgrade that lands on /_next/webpack-hmr or /track/realtime ticks
// the counter. Used for data-driven cutoff decision on the IsAllowedWSPath
// backward-compat accept set (MINOR-V2-6).
func TestMetrics_WSPathLegacyHits(t *testing.T) {
	m := &Metrics{}
	m.WSPathLegacyHits.Add(1)
	m.WSPathLegacyHits.Add(2)
	if got := m.WSPathLegacyHits.Load(); got != 3 {
		t.Errorf("WSPathLegacyHits = %d, want 3", got)
	}
}

// TestMetrics_HandshakeByProfile verifies that IncHandshakeProfile routes
// per-profile increments to the correct atomic counter (D2, FP-mimicry).
func TestMetrics_HandshakeByProfile(t *testing.T) {
	m := NewMetrics()
	beforeChrome := m.HandshakesProfileChrome.Load()
	beforeFirefox := m.HandshakesProfileFirefox.Load()
	beforeOther := m.HandshakesProfileOther.Load()

	m.IncHandshakeProfile("chrome")
	m.IncHandshakeProfile("firefox")
	m.IncHandshakeProfile("other")
	m.IncHandshakeProfile("unknown") // also routes to "other"

	if got := m.HandshakesProfileChrome.Load(); got != beforeChrome+1 {
		t.Errorf("chrome handshake counter: got %d, want %d", got, beforeChrome+1)
	}
	if got := m.HandshakesProfileFirefox.Load(); got != beforeFirefox+1 {
		t.Errorf("firefox handshake counter: got %d, want %d", got, beforeFirefox+1)
	}
	if got := m.HandshakesProfileOther.Load(); got != beforeOther+2 {
		t.Errorf("other handshake counter: got %d, want %d (want 2: explicit 'other' + unknown)", got, beforeOther+2)
	}
}

// TestSession_HasNoProfileField verifies that core.Session does NOT carry a
// Profile field — the server must never persist client_id→profile association
// (D2 privacy invariant).
func TestSession_HasNoProfileField(t *testing.T) {
	typ := reflect.TypeOf(core.Session{})
	if _, ok := typ.FieldByName("Profile"); ok {
		t.Error("core.Session must NOT have a Profile field (D2 privacy: no client_id→profile binding)")
	}
}

// TestHandshakeProfileFromUA verifies the UA→profile classifier used in
// handleHandshakeNew to derive a profile label from the User-Agent header
// without storing it in the session.
func TestHandshakeProfileFromUA(t *testing.T) {
	cases := []struct {
		ua      string
		want    string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36", "chrome"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36", "chrome"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0", "firefox"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15", "other"},
		{"Go-http-client/1.1", "other"},
		{"", "other"},
	}
	for _, tc := range cases {
		got := handshakeProfileFromUA(tc.ua)
		if got != tc.want {
			t.Errorf("handshakeProfileFromUA(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

// TestMetrics_HandshakeProfileInSnapshot verifies that the three profile
// counters are surfaced in the MetricsSnapshot (JSON export).
func TestMetrics_HandshakeProfileInSnapshot(t *testing.T) {
	m := NewMetrics()
	m.IncHandshakeProfile("chrome")
	m.IncHandshakeProfile("chrome")
	m.IncHandshakeProfile("firefox")

	snap := m.Snapshot()
	if snap.HandshakesProfileChrome != 2 {
		t.Errorf("snapshot chrome = %d, want 2", snap.HandshakesProfileChrome)
	}
	if snap.HandshakesProfileFirefox != 1 {
		t.Errorf("snapshot firefox = %d, want 1", snap.HandshakesProfileFirefox)
	}
	if snap.HandshakesProfileOther != 0 {
		t.Errorf("snapshot other = %d, want 0", snap.HandshakesProfileOther)
	}
}

// TestRatelimitBurstCounters verifies that IncRatelimitBurstConsumed /
// IncRatelimitBurstRejected route per-path increments correctly, that an
// unknown path is a safe no-op, and that the JSON snapshot + Prom exposition
// surface the values with the expected labels. Plan §C7 (May audit,
// 2026-05-02).
func TestRatelimitBurstCounters(t *testing.T) {
	m := NewMetrics()

	// 3× ws_upgrade Consumed, 2× data Rejected, 1× unknown (no-op).
	m.IncRatelimitBurstConsumed("ws_upgrade")
	m.IncRatelimitBurstConsumed("ws_upgrade")
	m.IncRatelimitBurstConsumed("ws_upgrade")
	m.IncRatelimitBurstRejected("data")
	m.IncRatelimitBurstRejected("data")
	m.IncRatelimitBurstConsumed("unknown") // safe no-op
	m.IncRatelimitBurstRejected("garbage") // safe no-op

	// Internal atomic counters.
	assert.Equal(t, uint64(3), m.RatelimitBurstConsumed_WSUpgrade.Load(),
		"ws_upgrade Consumed must equal 3")
	assert.Equal(t, uint64(0), m.RatelimitBurstConsumed_Handshake.Load(),
		"handshake Consumed must remain 0")
	assert.Equal(t, uint64(0), m.RatelimitBurstConsumed_Data.Load(),
		"data Consumed must remain 0")
	assert.Equal(t, uint64(0), m.RatelimitBurstRejected_WSUpgrade.Load(),
		"ws_upgrade Rejected must remain 0")
	assert.Equal(t, uint64(0), m.RatelimitBurstRejected_Handshake.Load(),
		"handshake Rejected must remain 0")
	assert.Equal(t, uint64(2), m.RatelimitBurstRejected_Data.Load(),
		"data Rejected must equal 2")

	// JSON snapshot mirror.
	snap := m.Snapshot()
	assert.Equal(t, uint64(3), snap.RatelimitBurstConsumedWSUpgrade)
	assert.Equal(t, uint64(0), snap.RatelimitBurstConsumedHandshake)
	assert.Equal(t, uint64(0), snap.RatelimitBurstConsumedData)
	assert.Equal(t, uint64(0), snap.RatelimitBurstRejectedWSUpgrade)
	assert.Equal(t, uint64(0), snap.RatelimitBurstRejectedHandshake)
	assert.Equal(t, uint64(2), snap.RatelimitBurstRejectedData)

	// Prometheus exposition.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics?format=prom", nil)
	m.ServeHTTP(w, r)
	require.Equal(t, 200, w.Code)
	body := w.Body.String()

	expected := []string{
		`shadowlink_ratelimit_burst_consumed_total{path="ws_upgrade"} 3`,
		`shadowlink_ratelimit_burst_consumed_total{path="handshake"} 0`,
		`shadowlink_ratelimit_burst_consumed_total{path="data"} 0`,
		`shadowlink_ratelimit_burst_rejected_total{path="ws_upgrade"} 0`,
		`shadowlink_ratelimit_burst_rejected_total{path="handshake"} 0`,
		`shadowlink_ratelimit_burst_rejected_total{path="data"} 2`,
		`# TYPE shadowlink_ratelimit_burst_consumed_total counter`,
		`# TYPE shadowlink_ratelimit_burst_rejected_total counter`,
	}
	for _, line := range expected {
		assert.True(t, strings.Contains(body, line),
			"prom output missing line %q\nbody:\n%s", line, body)
	}
}

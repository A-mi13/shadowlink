package server

import (
	"crypto/rand"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// registerTestTunnel synthesizes a session+tunnel pair directly (skipping the
// X25519 handshake) so concurrency tests can scale to 10k tunnels without
// paying handshake CPU per setup. Returns the SessionID on success.
//
// The Outgoing buffer matches production (defaultTunnelOutgoingBuffer) so a
// single FlagFin enqueue per tunnel never blocks.
func (h *Handler) registerTestTunnel(t *testing.T) uint32 {
	t.Helper()
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)
	if _, err := rand.Read(sendKey); err != nil {
		t.Fatalf("rand sendKey: %v", err)
	}
	if _, err := rand.Read(recvKey); err != nil {
		t.Fatalf("rand recvKey: %v", err)
	}
	sess, err := h.sessions.Create(sendKey, recvKey)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}
	tun := &Tunnel{
		SessionID:   sess.ID,
		ClientID:    "test:dev",
		Incoming:    make(chan []byte, 64),
		Outgoing:    make(chan []byte, defaultTunnelOutgoingBuffer),
		OutgoingUDP: make(chan []byte, 64),
		done:        make(chan struct{}),
	}
	h.tunnelsMu.Lock()
	h.tunnels[sess.ID] = tun
	h.tunnelsMu.Unlock()
	return sess.ID
}

// registerTestTunnelWithFullChannel is identical to registerTestTunnel but
// pre-fills Outgoing to capacity so BroadcastStreamClose hits the timeout arm
// of its select on every tunnel — exercising the per-tunnel deadline path.
func (h *Handler) registerTestTunnelWithFullChannel(t *testing.T) uint32 {
	t.Helper()
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)
	_, _ = rand.Read(sendKey)
	_, _ = rand.Read(recvKey)
	sess, err := h.sessions.Create(sendKey, recvKey)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}
	out := make(chan []byte, 1)
	out <- []byte{0xff} // saturate
	tun := &Tunnel{
		SessionID:   sess.ID,
		ClientID:    "test:dev",
		Incoming:    make(chan []byte, 64),
		Outgoing:    out,
		OutgoingUDP: make(chan []byte, 64),
		done:        make(chan struct{}),
	}
	h.tunnelsMu.Lock()
	h.tunnels[sess.ID] = tun
	h.tunnelsMu.Unlock()
	return sess.ID
}

// registerTestTunnelWithBufferedDraining creates a tunnel whose Outgoing is
// continuously drained by a background goroutine — mimicking a real client
// reading off the wire. Used in load tests so the broadcast can fully complete
// even with a small per-tunnel buffer.
func (h *Handler) registerTestTunnelWithBufferedDraining(t *testing.T, buf int) uint32 {
	t.Helper()
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)
	_, _ = rand.Read(sendKey)
	_, _ = rand.Read(recvKey)
	sess, err := h.sessions.Create(sendKey, recvKey)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}
	out := make(chan []byte, buf)
	tun := &Tunnel{
		SessionID:   sess.ID,
		ClientID:    "test:dev",
		Incoming:    make(chan []byte, 64),
		Outgoing:    out,
		OutgoingUDP: make(chan []byte, 64),
		done:        make(chan struct{}),
	}
	h.tunnelsMu.Lock()
	h.tunnels[sess.ID] = tun
	h.tunnelsMu.Unlock()

	// Drain in background until the test ends.
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-out:
			}
		}
	}()
	return sess.ID
}

// newTestHandler is a thin alias around setupTestHandler that drops the
// keypair (concurrency tests don't need to drive handshakes — they synthesize
// sessions directly via registerTestTunnel). Accepts testing.TB so it can
// be reused from Benchmarks (e.g. BenchmarkFailClosedToDecoy_AsymmetricCost).
func newTestHandler(tb testing.TB) *Handler {
	tb.Helper()
	h, _ := setupTestHandler(tb)
	return h
}

// avoid unused-import errors when the helpers below this line are not exercised
// by every test in the file.
var (
	_ = core.FlagFin
	_ = runtime.NumGoroutine
)

// TestBroadcastStreamClose_TotalDeadline verifies the 5s total broadcast
// deadline (broadcastCloseTotalDeadline) holds: with N=10k full-channel
// tunnels, every per-tunnel send hits the 50ms select timeout. The errgroup
// concurrency cap (256) means total wall-clock ≈ ceil(N/256) * 50ms ≈ 2s,
// well under the 5s ctx deadline. We allow 5.5s grace to absorb test-host
// jitter, GC, and the monitor goroutine.
func TestBroadcastStreamClose_TotalDeadline(t *testing.T) {
	const N = 10000
	h := newTestHandler(t)
	for i := 0; i < N; i++ {
		h.registerTestTunnelWithFullChannel(t)
	}

	start := time.Now()
	enq := h.BroadcastStreamClose("deadline_test")
	elapsed := time.Since(start)

	if elapsed > 5500*time.Millisecond {
		t.Errorf("BroadcastStreamClose took %v, want <= 5.5s (5s deadline + grace)", elapsed)
	}
	t.Logf("enqueued=%d in %v", enq, elapsed)
}

// TestBroadcastStreamClose_EnqueuesFinToAllTunnels verifies H1 graceful
// shutdown behavior: BroadcastStreamClose must deliver one encrypted FlagFin
// chunk to every active tunnel's Outgoing channel so clients reconnect
// promptly during a rolling deploy instead of waiting out their read-timeout.
func TestBroadcastStreamClose_EnqueuesFinToAllTunnels(t *testing.T) {
	h, serverKey := setupTestHandler(t)

	// Two independent sessions + their tunnels.
	sess1, _ := completeHandshakeForTest(t, h, serverKey)
	sess2, _ := completeHandshakeForTest(t, h, serverKey)

	enqueued := h.BroadcastStreamClose("test_drain")
	if enqueued != 2 {
		t.Errorf("BroadcastStreamClose enqueued = %d, want 2", enqueued)
	}

	// Each tunnel's Outgoing must have received exactly one chunk. Drain with
	// a short deadline — the broadcast should be instant for a low-session count.
	t1, ok1 := h.GetTunnel(sess1.ID)
	if !ok1 {
		t.Fatal("tunnel for session 1 missing")
	}
	t2, ok2 := h.GetTunnel(sess2.ID)
	if !ok2 {
		t.Fatal("tunnel for session 2 missing")
	}

	for i, tu := range []*Tunnel{t1, t2} {
		select {
		case data := <-tu.Outgoing:
			if len(data) == 0 {
				t.Errorf("tunnel %d: empty broadcast chunk", i+1)
			}
		case <-time.After(500 * time.Millisecond):
			t.Errorf("tunnel %d: timeout waiting for FlagFin broadcast", i+1)
		}
	}
}

// TestBroadcastStreamClose_Empty checks that a call with zero active tunnels
// is a no-op that returns 0 without blocking or panicking.
func TestBroadcastStreamClose_Empty(t *testing.T) {
	h, _ := setupTestHandler(t)
	if got := h.BroadcastStreamClose("empty_drain"); got != 0 {
		t.Errorf("empty broadcast enqueued = %d, want 0", got)
	}
}

// TestMetrics_PrometheusFormat_ExposesSteadyStateCounters verifies the
// /metrics endpoint serves a Prometheus-scrapable text body when asked, and
// that body includes the post-migration steady-state counters (handshakes,
// body-prefix path hits).
func TestMetrics_PrometheusFormat_ExposesSteadyStateCounters(t *testing.T) {
	m := NewMetrics()
	m.NewPathHits.Add(7)
	m.HandshakesNewTotal.Add(3)
	m.HandshakesTotal.Add(3)

	req := httptest.NewRequest("GET", "/metrics?format=prom", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rec.Body.String()

	wants := []string{
		"shadowlink_new_path_hits_total 7",
		"shadowlink_handshakes_new_total 3",
		"shadowlink_handshakes_total 3",
	}
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("Prometheus body missing %q\nbody:\n%s", w, body)
		}
	}
}

// TestMetrics_AcceptHeaderNegotiatesPromFormat verifies the Accept: text/plain
// sniff path — Grafana's default scraper sends that header, not ?format=.
func TestMetrics_AcceptHeaderNegotiatesPromFormat(t *testing.T) {
	m := NewMetrics()
	m.NewPathHits.Add(11)

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Accept", "text/plain; version=0.0.4")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "shadowlink_new_path_hits_total 11") {
		t.Errorf("Accept negotiation failed — body was not Prometheus")
	}
	_ = time.Second // keep the time import live for the broadcast test
}

// TestBroadcastStreamClose_ConcurrencyBounded verifies the T1.7 contract:
// even with 10k live tunnels whose Outgoing channels are saturated (the worst
// case — every per-tunnel send hits the per-tunnel deadline) the broadcast
// must complete well under a minute (NOT the ~16+ min a serial 100ms-per-tunnel
// loop would consume) and goroutine count must stay bounded by the errgroup
// limit (256 + small slack).
//
// 2026-04-28 isolation fix: under full-suite -count=2 the absolute peak
// (peakGoroutines vs limit+baseline=320) was racing other tests' lingering
// goroutines (httptest, schedulers, etc.) and tripping the threshold around
// 360-400. Production BroadcastStreamClose is correct (errgroup.SetLimit(256));
// the bug is that the test conflated baseline-fluctuation with broadcast-
// goroutines. Now we sample baseline AFTER GC + sleep and measure the delta.
func TestBroadcastStreamClose_ConcurrencyBounded(t *testing.T) {
	const N = 10000
	const limit = 256
	const slack = 32

	h := newTestHandler(t)
	for i := 0; i < N; i++ {
		h.registerTestTunnelWithFullChannel(t)
	}

	// Quiesce: any goroutines from earlier tests in the same binary should
	// have a chance to wind down before we capture the baseline. Without
	// this, full-suite -count=2 inherited 100+ extra goroutines from
	// httptest servers and inflated the baseline above the 320 threshold.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := int64(runtime.NumGoroutine())

	var peakDelta int64
	stopMonitor := make(chan struct{})
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopMonitor:
				return
			case <-ticker.C:
				cur := int64(runtime.NumGoroutine()) - baseline
				if cur < 0 {
					cur = 0 // baseline can shrink mid-run; clamp to 0
				}
				if cur > atomic.LoadInt64(&peakDelta) {
					atomic.StoreInt64(&peakDelta, cur)
				}
			}
		}
	}()

	start := time.Now()
	enq := h.BroadcastStreamClose("test_drain")
	elapsed := time.Since(start)
	close(stopMonitor)
	<-monitorDone

	// SLA: errgroup with limit=256 should land in low single-digit seconds.
	if elapsed > 10*time.Second {
		t.Errorf("BroadcastStreamClose took %v with %d full-channel tunnels — expected well under 10s, serial impl would take ~1000s",
			elapsed, N)
	}
	t.Logf("broadcast over %d full-channel tunnels: enqueued=%d, elapsed=%v, baseline=%d, peakDelta=%d",
		N, enq, elapsed, baseline, atomic.LoadInt64(&peakDelta))

	// Delta-based threshold: limit (256) + slack (32 for monitor + scheduler + GC).
	if peak := atomic.LoadInt64(&peakDelta); peak > int64(limit+slack) {
		t.Errorf("peak goroutine delta = %d above baseline=%d, want <= %d (limit=%d + slack=%d)",
			peak, baseline, limit+slack, limit, slack)
	}
}

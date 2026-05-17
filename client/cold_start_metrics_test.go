package client

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resetColdStartMetrics zeroes the package-level cold-start counters so a
// test starts from a known baseline. Call deferred so concurrent tests in
// the same package do not accumulate drift across cases.
func resetColdStartMetrics() {
	FirstStreamMS.Store(0)
	PoolWarmupMS.Store(0)
	HandshakeDecoyReceived.Store(0)
	SOCKS5CoalesceGrouped.Store(0)
	SOCKS5CoalesceGroups.Store(0)
}

// TestSetFirstStreamMS_Updates verifies the gauge stores the millisecond
// duration passed in, exactly. Caller is expected to gate via sync.Once;
// this test only covers the storage primitive.
func TestSetFirstStreamMS_Updates(t *testing.T) {
	resetColdStartMetrics()

	SetFirstStreamMS(123 * time.Millisecond)
	if got := FirstStreamMS.Load(); got != 123 {
		t.Fatalf("FirstStreamMS = %d, want 123", got)
	}

	// Subsequent calls overwrite (gauge semantics).
	SetFirstStreamMS(456 * time.Millisecond)
	if got := FirstStreamMS.Load(); got != 456 {
		t.Fatalf("FirstStreamMS overwrite = %d, want 456", got)
	}
}

// TestSetPoolWarmupMS_Updates mirrors the gauge contract for PoolWarmupMS.
func TestSetPoolWarmupMS_Updates(t *testing.T) {
	resetColdStartMetrics()

	SetPoolWarmupMS(789 * time.Millisecond)
	if got := PoolWarmupMS.Load(); got != 789 {
		t.Fatalf("PoolWarmupMS = %d, want 789", got)
	}
}

// TestHandshakeDecoyReceivedCounter ensures the counter monotonically
// increases by exactly 1 per call (no batching, no decay).
func TestHandshakeDecoyReceivedCounter(t *testing.T) {
	resetColdStartMetrics()

	const N = 5
	for range N {
		IncHandshakeDecoyReceived()
	}
	if got := HandshakeDecoyReceived.Load(); got != N {
		t.Fatalf("HandshakeDecoyReceived = %d, want %d", got, N)
	}
}

// TestSOCKS5CoalesceMetrics_GroupsVsGrouped covers the dispatcher's two
// counters drifting independently — Grouped accepts a count, Groups always
// adds one. Their ratio is what dashboards consume.
func TestSOCKS5CoalesceMetrics_GroupsVsGrouped(t *testing.T) {
	resetColdStartMetrics()

	// Three windows, with 4, 1, and 7 joiners respectively.
	IncSOCKS5CoalesceGroups()
	IncSOCKS5CoalesceGrouped(4)

	IncSOCKS5CoalesceGroups()
	IncSOCKS5CoalesceGrouped(1)

	IncSOCKS5CoalesceGroups()
	IncSOCKS5CoalesceGrouped(7)

	if got := SOCKS5CoalesceGroups.Load(); got != 3 {
		t.Errorf("Groups = %d, want 3", got)
	}
	if got := SOCKS5CoalesceGrouped.Load(); got != 12 {
		t.Errorf("Grouped = %d, want 12 (4+1+7)", got)
	}

	// Negative / zero joiner counts must be no-ops — defensive contract
	// against bad call sites.
	prev := SOCKS5CoalesceGrouped.Load()
	IncSOCKS5CoalesceGrouped(0)
	IncSOCKS5CoalesceGrouped(-3)
	if got := SOCKS5CoalesceGrouped.Load(); got != prev {
		t.Errorf("Grouped after bad inputs = %d, want %d (no-op)", got, prev)
	}
}

// TestColdStartMetricsSurfacedInPromExporter scrapes WritePromMetrics and
// verifies every cold-start series shows up with the correct exposition
// shape (HELP + TYPE + value). Mirrors the existing PQ test in
// utls_pq_test.go::TestWritePromMetrics_PQHandshake — same pattern, same
// reset-on-exit discipline.
func TestColdStartMetricsSurfacedInPromExporter(t *testing.T) {
	// Capture prior values so we can restore them — package counters are
	// shared across tests in the suite and another case may rely on them.
	beforeFirst := FirstStreamMS.Load()
	beforeWarmup := PoolWarmupMS.Load()
	beforeDecoy := HandshakeDecoyReceived.Load()
	beforeGroup := SOCKS5CoalesceGrouped.Load()
	beforeGroups := SOCKS5CoalesceGroups.Load()
	t.Cleanup(func() {
		FirstStreamMS.Store(beforeFirst)
		PoolWarmupMS.Store(beforeWarmup)
		HandshakeDecoyReceived.Store(beforeDecoy)
		SOCKS5CoalesceGrouped.Store(beforeGroup)
		SOCKS5CoalesceGroups.Store(beforeGroups)
	})

	FirstStreamMS.Store(1500)
	PoolWarmupMS.Store(2750)
	HandshakeDecoyReceived.Store(11)
	SOCKS5CoalesceGrouped.Store(42)
	SOCKS5CoalesceGroups.Store(7)

	var buf bytes.Buffer
	WritePromMetrics(&buf)
	out := buf.String()

	wantLines := []string{
		"# TYPE shadowlink_first_stream_ms gauge",
		"shadowlink_first_stream_ms 1500",
		"# TYPE shadowlink_pool_warmup_ms gauge",
		"shadowlink_pool_warmup_ms 2750",
		"# TYPE shadowlink_handshake_decoy_received_total counter",
		"shadowlink_handshake_decoy_received_total 11",
		"# TYPE shadowlink_socks5_coalesce_grouped_total counter",
		"shadowlink_socks5_coalesce_grouped_total 42",
		"# TYPE shadowlink_socks5_coalesce_groups_total counter",
		"shadowlink_socks5_coalesce_groups_total 7",
	}
	for _, want := range wantLines {
		if !strings.Contains(out, want) {
			t.Errorf("Prom output missing %q\n\n%s", want, out)
		}
	}
}

// TestPoolWarmupMS_OnlySetWhenAllRequireDoneClose drives a phaseCoordinator
// directly and asserts that closing only one of two RequireDone phases
// does NOT stamp the gauge — the watcher must wait for every gating phase
// before recording. Replicates the watcher logic without standing up a
// full WSReadyPool (which would require a live ShadowLink server).
func TestPoolWarmupMS_OnlySetWhenAllRequireDoneClose(t *testing.T) {
	resetColdStartMetrics()
	t.Cleanup(resetColdStartMetrics)

	phases := []WarmupPhase{
		{Slots: []int{0}, RequireDone: true},
		{Slots: []int{1, 2}, RequireDone: true},
		{Slots: []int{3, 4}, RequireDone: false}, // tail — must NOT gate the gauge
	}
	pc := newPhaseCoordinator(phases)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	startedAt := time.Now()

	// Stand-alone watcher mirroring trackWarmupCompletion.
	done := make(chan struct{})
	var stamped atomic.Bool
	go func() {
		defer close(done)
		for i, ph := range pc.phases {
			if !ph.RequireDone {
				continue
			}
			select {
			case <-pc.done[i]:
			case <-ctx.Done():
				return
			}
		}
		SetPoolWarmupMS(time.Since(startedAt))
		stamped.Store(true)
	}()

	// Close phase 0 — gauge MUST stay zero (phase 1 still gating).
	pc.MarkSlotReady(0)
	time.Sleep(40 * time.Millisecond)
	if got := PoolWarmupMS.Load(); got != 0 {
		t.Errorf("PoolWarmupMS = %d after only phase 0 closed; want 0", got)
	}
	if stamped.Load() {
		t.Errorf("watcher stamped before phase 1 closed")
	}

	// Close phase 1 (slots 1 + 2). After both, gauge fires.
	pc.MarkSlotReady(1)
	pc.MarkSlotReady(2)

	// Tail phase MUST NOT be required for the gauge.
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("watcher never finished after RequireDone phases closed")
	}
	if !stamped.Load() {
		t.Fatalf("watcher exited without stamping gauge")
	}
	if got := PoolWarmupMS.Load(); got <= 0 {
		t.Errorf("PoolWarmupMS = %d after gating phases closed; want >0", got)
	}
}

// TestPoolWarmupMS_WatcherExitsOnCtxCancel guarantees the watcher does
// not leak when the pool is closed before warmup completes.
func TestPoolWarmupMS_WatcherExitsOnCtxCancel(t *testing.T) {
	resetColdStartMetrics()
	t.Cleanup(resetColdStartMetrics)

	phases := []WarmupPhase{
		{Slots: []int{0}, RequireDone: true},
	}
	pc := newPhaseCoordinator(phases)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i, ph := range pc.phases {
			if !ph.RequireDone {
				continue
			}
			select {
			case <-pc.done[i]:
			case <-ctx.Done():
				return
			}
		}
		SetPoolWarmupMS(1 * time.Millisecond)
	}()

	// Cancel without ever closing phase 0.
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("watcher did not exit within 1s after ctx cancel — goroutine leak")
	}
	if got := PoolWarmupMS.Load(); got != 0 {
		t.Errorf("PoolWarmupMS = %d after ctx-cancel; want 0 (no stamp)", got)
	}
}

// TestMarkFirstStream_OnceSemantics drives Client.MarkFirstStream from
// many concurrent goroutines and asserts only the very first call wins.
// Without the sync.Once gate, every successful CONNECT would overwrite
// the gauge with later (larger, irrelevant) measurements.
func TestMarkFirstStream_OnceSemantics(t *testing.T) {
	resetColdStartMetrics()
	t.Cleanup(resetColdStartMetrics)

	cl := &Client{}
	// Simulate Connect() stamping the start.
	cl.connectStartUnixNano.Store(time.Now().Add(-50 * time.Millisecond).UnixNano())

	var wg sync.WaitGroup
	const N = 32
	for range N {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cl.MarkFirstStream()
		}()
	}
	wg.Wait()

	if got := FirstStreamMS.Load(); got <= 0 {
		t.Fatalf("FirstStreamMS = %d, want >0", got)
	}
	first := FirstStreamMS.Load()

	// Subsequent calls must NOT overwrite the gauge (sync.Once gate).
	time.Sleep(20 * time.Millisecond)
	cl.MarkFirstStream()
	cl.MarkFirstStream()
	if got := FirstStreamMS.Load(); got != first {
		t.Errorf("FirstStreamMS overwritten by post-Once call: %d → %d", first, got)
	}
}

// TestMarkFirstStream_NoConnectIsNoop guarantees a misuse path (Mark
// called before Connect stamped the start) does not corrupt the gauge
// with a meaningless "ms since Unix epoch" reading.
func TestMarkFirstStream_NoConnectIsNoop(t *testing.T) {
	resetColdStartMetrics()
	t.Cleanup(resetColdStartMetrics)

	cl := &Client{} // connectStartUnixNano left at zero.
	cl.MarkFirstStream()

	if got := FirstStreamMS.Load(); got != 0 {
		t.Errorf("FirstStreamMS = %d; want 0 (Connect was never called)", got)
	}
}

package client

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syncBuffer is a concurrency-safe slog sink. A *bytes.Buffer is NOT
// safe for concurrent use, but drain/reconnect tests install the sink as
// p.log (or slog.Default) and then run real background goroutines
// (drainWatchdog → handleSlotDeath → reconnectLoop, connectReserveSlot)
// that keep logging while the test goroutine reads the captured output.
// That produced the Linux -race report bytes.(*Buffer).grow (handler
// Write) vs bytes.(*Buffer).Len (test String()). Guarding both Write and
// String with one mutex closes it without weakening any assertion — the
// test still reads exactly what was logged, just under the lock.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Return a copy so callers can read it lock-free without racing a
	// concurrent Write growing the underlying array.
	return append([]byte(nil), b.buf.Bytes()...)
}

// captureSlogForDrain creates a text handler bound to an in-memory buffer
// at the requested level. Unlike captureSlog in may_audit_p2_test.go this
// helper does NOT touch slog.Default — it returns a *slog.Logger that the
// caller installs into p.log directly, because drain-deferred messages
// are emitted via p.log (the pool's own logger), not the package default.
//
// The sink is a *syncBuffer (concurrency-safe) because callers run real
// drain/reconnect background goroutines that log concurrently with the
// test's String() read.
func captureSlogForDrain(t *testing.T, level slog.Level) (*syncBuffer, *slog.Logger) {
	t.Helper()
	buf := &syncBuffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})
	return buf, slog.New(handler)
}

// makeStormBrakeTestPool returns a pool wired enough to call startDrain
// and land in the inflight-cap storm-brake gate. Mirrors the construction
// in TestStartDrain_InflightCounterCaps (ws_pool_drain_test.go ~line 1379):
// poolSize=8, gracefulDrain=true, all 8 slots in slotReady. Inflight is
// pre-saturated to maxConcurrentDrains so the next startDrain trips the
// gate immediately.
//
// The caller can override p.log (e.g. via captureSlogForDrain) before
// triggering startDrain.
func makeStormBrakeTestPool(t *testing.T) *WSPoolTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	for i := 0; i < 8; i++ {
		p.slots[i] = &poolSlot{index: i}
		p.slots[i].setState(slotReady)
	}
	// Pre-saturate inflight to the cap so the very next startDrain call
	// trips the inflight-cap gate and lands in the deferred branch.
	p.inflightDrains.Store(int32(p.maxConcurrentDrains()))
	return p
}

// triggerStormBrakeInflightCapOn fires one startDrain on the given pool;
// because inflight is saturated by makeStormBrakeTestPool, the call lands
// in the inflight-cap deferred branch (Stats.InflightCapDeferredTotal
// increments + p.bumpDrainDeferrals1m fires).
func triggerStormBrakeInflightCapOn(t *testing.T, p *WSPoolTransport) {
	t.Helper()
	// Ensure inflight is still saturated (in case a prior call decremented
	// it via the !committed defer path).
	if p.inflightDrains.Load() < int32(p.maxConcurrentDrains()) {
		p.inflightDrains.Store(int32(p.maxConcurrentDrains()))
	}
	p.startDrain(nil, 0, "test")
}

// triggerStormBrakeInflightCap builds a fresh pool + fires one deferral.
// Convenience for tests that don't reuse the pool across calls.
func triggerStormBrakeInflightCap(t *testing.T) {
	t.Helper()
	triggerStormBrakeInflightCapOn(t, makeStormBrakeTestPool(t))
}

// makeCapacityFloorTestPool returns a pool wired to trip the capacity-floor
// storm-brake gate. Setup: poolSize=8 → readyCapacityFloor=ceil(8*0.25)=2.
// Only slot 0 is slotReady → readyCapacity=1, below the floor. Inflight
// is NOT pre-saturated so the inflight-cap gate passes first; the next
// startDrain lands in capacity-floor. Slot 0 must be present and ready
// because startDrain is called with oldIdx=0 and expects oldSlot != nil
// (the oldSlot is the drain TARGET, distinct from the readyCapacity calc
// which counts ALL slotReady slots).
func makeCapacityFloorTestPool(t *testing.T) *WSPoolTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	// Only idx 0 is slotReady — readyCapacity()=1, below floor of 2.
	p.slots[0] = &poolSlot{index: 0}
	p.slots[0].setState(slotReady)
	return p
}

// triggerStormBrakeCapacityFloorOn fires one startDrain on the given pool;
// because readyCapacity (1) < floor (2), the call lands in the
// capacity-floor deferred branch.
func triggerStormBrakeCapacityFloorOn(t *testing.T, p *WSPoolTransport) {
	t.Helper()
	p.startDrain(nil, 0, "test")
}

// triggerStormBrakeCapacityFloor builds a fresh pool + fires one deferral.
func triggerStormBrakeCapacityFloor(t *testing.T) {
	t.Helper()
	triggerStormBrakeCapacityFloorOn(t, makeCapacityFloorTestPool(t))
}

// TestDrainDeferred_InflightCap_LogLevelInfo — spec 2026-05-24
// re-promotion: drain-deferred (inflight cap) emits at INFO level (the
// DEBUG demotion in spec 2026-05-23 hid the diagnostic during the
// 2026-05-24 session, leading to 12326 silent deferrals).
func TestDrainDeferred_InflightCap_LogLevelInfo(t *testing.T) {
	t.Run("info_level_visible", func(t *testing.T) {
		buf, logger := captureSlogForDrain(t, slog.LevelInfo)
		p := makeStormBrakeTestPool(t)
		p.log = logger
		triggerStormBrakeInflightCapOn(t, p)
		if !strings.Contains(buf.String(), "drain deferred (inflight cap)") {
			t.Errorf("INFO-level capture SHOULD contain drain deferred:\n%s",
				buf.String())
		}
	})
	t.Run("warn_level_silent", func(t *testing.T) {
		buf, logger := captureSlogForDrain(t, slog.LevelWarn)
		p := makeStormBrakeTestPool(t)
		p.log = logger
		triggerStormBrakeInflightCapOn(t, p)
		if strings.Contains(buf.String(), "drain deferred (inflight cap)") {
			t.Errorf("WARN-level capture should NOT contain drain deferred:\n%s",
				buf.String())
		}
	})
}

// TestDrainDeferred_CapacityFloor_LogLevelInfo — symmetric for the
// capacity-floor branch.
func TestDrainDeferred_CapacityFloor_LogLevelInfo(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p := makeCapacityFloorTestPool(t)
	p.log = logger
	triggerStormBrakeCapacityFloorOn(t, p)
	if !strings.Contains(buf.String(), "drain deferred (capacity floor)") {
		t.Errorf("INFO-level capture SHOULD contain capacity-floor defer:\n%s",
			buf.String())
	}
}

// TestDrainDeferred_RateLimit_OneLogPer30sPerGate — N inflight-cap
// defers fired in tight succession produce exactly 1 INFO line; the
// counter still reflects all N defers (rate-limit gates only the log,
// not the counter).
func TestDrainDeferred_RateLimit_OneLogPer30sPerGate(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p := makeStormBrakeTestPool(t)
	p.log = logger

	beforeCount := Stats.InflightCapDeferredTotal.Load()
	const n = 20
	for i := 0; i < n; i++ {
		triggerStormBrakeInflightCapOn(t, p)
	}
	gotCount := Stats.InflightCapDeferredTotal.Load() - beforeCount
	if gotCount != n {
		t.Errorf("counter should grow by N=%d under burst, got %d", n, gotCount)
	}

	lines := strings.Count(buf.String(), "drain deferred (inflight cap)")
	if lines != 1 {
		t.Errorf("rate-limit should produce exactly 1 log line, got %d:\n%s",
			lines, buf.String())
	}
}

// TestDrainDeferred_RateLimit_PerGateIndependent — inflight-cap rate-
// limit timestamp must NOT block the capacity-floor log line and vice
// versa. Both gates can produce a log within the same 30s window
// because they have separate atomic.Int64 timestamps.
func TestDrainDeferred_RateLimit_PerGateIndependent(t *testing.T) {
	bufInflight, logInflight := captureSlogForDrain(t, slog.LevelInfo)
	pInflight := makeStormBrakeTestPool(t)
	pInflight.log = logInflight

	bufFloor, logFloor := captureSlogForDrain(t, slog.LevelInfo)
	pFloor := makeCapacityFloorTestPool(t)
	pFloor.log = logFloor

	triggerStormBrakeInflightCapOn(t, pInflight)
	triggerStormBrakeCapacityFloorOn(t, pFloor)

	if !strings.Contains(bufInflight.String(), "drain deferred (inflight cap)") {
		t.Errorf("inflight pool missing INFO line:\n%s", bufInflight.String())
	}
	if !strings.Contains(bufFloor.String(), "drain deferred (capacity floor)") {
		t.Errorf("floor pool missing INFO line:\n%s", bufFloor.String())
	}
}

// TestShouldLogDeferred_FirstCallAlwaysTrue — zero value of last (never
// logged) → helper returns true and stores `now`.
func TestShouldLogDeferred_FirstCallAlwaysTrue(t *testing.T) {
	var last atomic.Int64
	now := time.Unix(1000, 0)
	if !shouldLogDeferred(&last, now) {
		t.Fatalf("first call should return true (zero last value)")
	}
	if got := last.Load(); got != now.UnixNano() {
		t.Errorf("last.Load() = %d, want %d (CAS should have published now)",
			got, now.UnixNano())
	}
}

// TestShouldLogDeferred_BlocksWithinInterval — second call within
// drainDeferredLogInterval returns false; last is unchanged.
func TestShouldLogDeferred_BlocksWithinInterval(t *testing.T) {
	var last atomic.Int64
	t0 := time.Unix(1000, 0)
	if !shouldLogDeferred(&last, t0) {
		t.Fatalf("first call must return true")
	}
	t1 := t0.Add(drainDeferredLogInterval - time.Second) // 29s later
	if shouldLogDeferred(&last, t1) {
		t.Errorf("call within interval (%v) should return false", t1.Sub(t0))
	}
	if got := last.Load(); got != t0.UnixNano() {
		t.Errorf("last changed on blocked call: got=%d want=%d", got, t0.UnixNano())
	}
}

// TestShouldLogDeferred_AllowsAfterInterval — call after
// drainDeferredLogInterval returns true and updates last.
func TestShouldLogDeferred_AllowsAfterInterval(t *testing.T) {
	var last atomic.Int64
	t0 := time.Unix(1000, 0)
	shouldLogDeferred(&last, t0)
	t1 := t0.Add(drainDeferredLogInterval + time.Second) // 31s later
	if !shouldLogDeferred(&last, t1) {
		t.Errorf("call after interval should return true")
	}
	if got := last.Load(); got != t1.UnixNano() {
		t.Errorf("last not updated on successful call: got=%d want=%d",
			got, t1.UnixNano())
	}
}

// TestShouldLogDeferred_CASRacesProduceAtMostOneWinner — N goroutines
// race after an interval has elapsed. AT MOST one returns true. The
// guarantee is ≤1, not ==1 — if all goroutines schedule such that each
// observes a prev written by another, all CAS calls fail (correct
// behaviour — exactly the race we're guarding against).
func TestShouldLogDeferred_CASRacesProduceAtMostOneWinner(t *testing.T) {
	var last atomic.Int64
	// Seed with old timestamp so the interval has elapsed.
	last.Store(time.Unix(0, 0).UnixNano())
	now := time.Unix(1000, 0)

	const goroutines = 100
	var wg sync.WaitGroup
	var winners atomic.Int32
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if shouldLogDeferred(&last, now) {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()

	if w := winners.Load(); w > 1 {
		t.Errorf("CAS race produced %d winners, want ≤1", w)
	}
}

// TestInflightCapCounter_IncrementsPerDefer — Task 2 invariant.
// N inflight-cap defers → InflightCapDeferredTotal grows by N.
func TestInflightCapCounter_IncrementsPerDefer(t *testing.T) {
	before := Stats.InflightCapDeferredTotal.Load()
	const n = 5
	for i := 0; i < n; i++ {
		triggerStormBrakeInflightCap(t)
	}
	got := Stats.InflightCapDeferredTotal.Load() - before
	if got != n {
		t.Errorf("InflightCapDeferredTotal delta = %d, want %d", got, n)
	}
}

// TestInflightCapCounter_DoesNotIncrementCapacityFloor — Task 2 invariant.
// Inflight-cap defers MUST NOT bump the capacity-floor counter.
func TestInflightCapCounter_DoesNotIncrementCapacityFloor(t *testing.T) {
	beforeCap := Stats.CapacityFloorDeferredTotal.Load()
	for i := 0; i < 5; i++ {
		triggerStormBrakeInflightCap(t)
	}
	if got := Stats.CapacityFloorDeferredTotal.Load(); got != beforeCap {
		t.Errorf("CapacityFloorDeferredTotal advanced on inflight-cap path: before=%d after=%d",
			beforeCap, got)
	}
}

// TestCapacityFloorCounter_IncrementsPerDefer — Task 3 invariant.
// N capacity-floor defers → CapacityFloorDeferredTotal grows by N.
func TestCapacityFloorCounter_IncrementsPerDefer(t *testing.T) {
	before := Stats.CapacityFloorDeferredTotal.Load()
	const n = 5
	for i := 0; i < n; i++ {
		triggerStormBrakeCapacityFloor(t)
	}
	got := Stats.CapacityFloorDeferredTotal.Load() - before
	if got != n {
		t.Errorf("CapacityFloorDeferredTotal delta = %d, want %d", got, n)
	}
}

// TestCapacityFloorCounter_DoesNotIncrementInflightCap — symmetric
// to TestInflightCapCounter_DoesNotIncrementCapacityFloor.
func TestCapacityFloorCounter_DoesNotIncrementInflightCap(t *testing.T) {
	beforeInflight := Stats.InflightCapDeferredTotal.Load()
	for i := 0; i < 5; i++ {
		triggerStormBrakeCapacityFloor(t)
	}
	if got := Stats.InflightCapDeferredTotal.Load(); got != beforeInflight {
		t.Errorf("InflightCapDeferredTotal advanced on capacity-floor path: before=%d after=%d",
			beforeInflight, got)
	}
}

// TestDrainDeferred_BumpRollingCounter verifies bumpDrainDeferrals1m
// is called per deferral (drainDeferrals1m increases).
func TestDrainDeferred_BumpRollingCounter(t *testing.T) {
	p := makeStormBrakeTestPool(t)
	before := p.drainDeferrals1m.Load()
	triggerStormBrakeInflightCapOn(t, p)
	triggerStormBrakeInflightCapOn(t, p)
	got := p.drainDeferrals1m.Load() - before
	if got != 2 {
		t.Errorf("drainDeferrals1m delta = %d, want 2", got)
	}
	// The bumpDrainDeferrals1m helper spawns a 60s decay goroutine
	// per call. Since pool ctx has a t.Cleanup cancel, those goroutines
	// will exit via the ctx.Done() select arm — no leaks.
}

// TestHealthSnapshot_SurfacesPerGateCounters — verifies emitHealthSummary
// emits the per-gate counter fields after the spec-2026-05-24 split.
// The old aggregate field deferred_drains_total MUST NOT appear.
func TestHealthSnapshot_SurfacesPerGateCounters(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p := makeStormBrakeTestPool(t)
	p.log = logger
	// emitHealthSummary uses time.Since(p.startedAt) — set a recent
	// timestamp so the uptime calc returns something sane.
	p.startedAt = time.Now()
	triggerStormBrakeInflightCapOn(t, p)
	triggerStormBrakeInflightCapOn(t, p)
	triggerStormBrakeInflightCapOn(t, p)

	p.emitHealthSummary()

	out := buf.String()
	if !strings.Contains(out, "inflight_cap_deferred_total=") {
		t.Errorf("health snapshot missing inflight_cap_deferred_total:\n%s", out)
	}
	if !strings.Contains(out, "capacity_floor_deferred_total=") {
		t.Errorf("health snapshot missing capacity_floor_deferred_total:\n%s", out)
	}
	if !strings.Contains(out, "deferred_drains_1m=") {
		t.Errorf("health snapshot missing deferred_drains_1m:\n%s", out)
	}
	if strings.Contains(out, "deferred_drains_total=") {
		t.Errorf("health snapshot SHOULD NOT contain deferred_drains_total (legacy aggregate):\n%s", out)
	}
}

// makeHardCapTestPool returns a pool wired for emitHardCapLog direct
// invocation. Slot 0 is slotDraining (drain-target state). Caller sets
// remaining streams via slot.streams.Store(N) before calling
// emitHardCapLog.
func makeHardCapTestPool(t *testing.T) (*WSPoolTransport, *poolSlot) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &WSPoolTransport{
		poolSize: 8,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	slot := &poolSlot{index: 0}
	slot.setState(slotDraining)
	p.slots[0] = slot
	return p, slot
}

// TestHardCap_LogLevelInfo_BelowThreshold — remaining_streams=2 → INFO.
func TestHardCap_LogLevelInfo_BelowThreshold(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p, slot := makeHardCapTestPool(t)
	p.log = logger
	slot.streams.Store(2)

	emitHardCapLog(p, 0, slot, "age", 90*time.Second, 90*time.Second)

	out := buf.String()
	if !strings.Contains(out, "hard cap reached") {
		t.Fatalf("expected hard-cap log at INFO level, got:\n%s", out)
	}
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("expected level=INFO for remaining=2, got:\n%s", out)
	}
}

// TestHardCap_LogLevelWarn_AtThreshold — remaining_streams=5 → WARN.
func TestHardCap_LogLevelWarn_AtThreshold(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p, slot := makeHardCapTestPool(t)
	p.log = logger
	slot.streams.Store(5)

	emitHardCapLog(p, 0, slot, "age", 90*time.Second, 90*time.Second)

	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("expected level=WARN for remaining=5, got:\n%s", out)
	}
}

// TestHardCap_LogLevelWarn_AboveThreshold — remaining_streams=9 → WARN.
func TestHardCap_LogLevelWarn_AboveThreshold(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p, slot := makeHardCapTestPool(t)
	p.log = logger
	slot.streams.Store(9)

	emitHardCapLog(p, 0, slot, "age", 90*time.Second, 90*time.Second)

	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("expected level=WARN for remaining=9, got:\n%s", out)
	}
}

// TestHardCap_CounterIncrementsRegardlessOfLevel — DrainHardCapTotal
// must advance for both INFO and WARN paths.
func TestHardCap_CounterIncrementsRegardlessOfLevel(t *testing.T) {
	for _, streams := range []int32{2, 9} {
		before := Stats.DrainHardCapTotal.Load()
		p, slot := makeHardCapTestPool(t)
		slot.streams.Store(streams)
		emitHardCapLog(p, 0, slot, "age", 90*time.Second, 90*time.Second)
		if got := Stats.DrainHardCapTotal.Load(); got != before+1 {
			t.Errorf("DrainHardCapTotal didn't advance for streams=%d: %d → %d",
				streams, before, got)
		}
	}
}

// TestMaxConcurrentDrains_NewValueAfterLift_2026_05_24 — invariant
// freeze for the 2026-05-24 concurrency lift. Cap raised from
// ceil(N*0.25) to ceil(N*0.5). At poolSize=6 the production setting
// jumps from 2 to 3 — that's the target change driven by canary
// 2026-05-24-evening (100% defers on inflight gate, 0 on floor gate).
func TestMaxConcurrentDrains_NewValueAfterLift_2026_05_24(t *testing.T) {
	cases := []struct {
		poolSize int
		want     int
	}{
		{poolSize: 1, want: 1},  // clamp min — never zero (was: clamp to 0 then min=1)
		{poolSize: 2, want: 1},  // ceil(2*0.5)=1, then clamp to poolSize-1=1
		{poolSize: 4, want: 2},  // ceil(4*0.5)=2 (was: ceil(4*0.25)=1)
		{poolSize: 6, want: 3},  // ceil(6*0.5)=3 (was: ceil(6*0.25)=2)  ← THE TARGET
		{poolSize: 8, want: 4},  // ceil(8*0.5)=4 (was: ceil(8*0.25)=2)
		{poolSize: 16, want: 8}, // ceil(16*0.5)=8 (was: ceil(16*0.25)=4)
	}
	for _, c := range cases {
		p := &WSPoolTransport{poolSize: c.poolSize}
		if got := p.maxConcurrentDrains(); got != c.want {
			t.Errorf("maxConcurrentDrains(poolSize=%d) = %d, want %d",
				c.poolSize, got, c.want)
		}
	}
}

// TestReadyCapacityFloor_UnchangedAfterDecouple_2026_05_24 — verifies
// the decoupling preserved capacity-floor values at canonical poolSizes.
// Cross-references the existing TestStormBrakeFloor_DerivedFromPoolSize
// (which uses the same expected values but with updated derivation
// comments).
func TestReadyCapacityFloor_UnchangedAfterDecouple_2026_05_24(t *testing.T) {
	cases := []struct {
		poolSize int
		want     int
	}{
		{poolSize: 1, want: 0}, // floor(0.75)=0 → lower clamp →1 → upper clamp `>= poolSize=1` → 0.
		// Degenerate single-slot pool: floor=0 effectively DISABLES the
		// capacity-floor gate (readyCapacity >= 0 always passes). The
		// inflight-cap gate (mcd=1) still bounds concurrency correctly,
		// so a second drain trigger during a first defers on inflight.
		// Asymmetric vs maxConcurrentDrains() clamp order — see ws_pool.go
		// doc-comments for the rationale.
		{poolSize: 2, want: 1},   // floor(2*0.75)=1, within [1, 1]
		{poolSize: 4, want: 3},   // floor(4*0.75)=3 — UNCHANGED from pre-decouple
		{poolSize: 6, want: 4},   // floor(6*0.75)=4 — UNCHANGED
		{poolSize: 8, want: 6},   // floor(8*0.75)=6 — UNCHANGED
		{poolSize: 16, want: 12}, // floor(16*0.75)=12 — UNCHANGED
	}
	for _, c := range cases {
		p := &WSPoolTransport{poolSize: c.poolSize}
		if got := p.readyCapacityFloor(); got != c.want {
			t.Errorf("readyCapacityFloor(poolSize=%d) = %d, want %d",
				c.poolSize, got, c.want)
		}
	}
}

// TestKnobs_AreIndependent_2026_05_24 — fingerprint test for the
// decoupling. Before 2026-05-24 the invariant was floor = poolSize - mcd,
// so mcd + floor == poolSize exactly. After decouple they're independent,
// and at poolSize=6 we expect mcd=3 + floor=4 = 7 > poolSize=6. This is
// EXPECTED and DESIRED — the two gates evaluate different conditions
// (inflight count vs ready count) and don't constrain each other.
func TestKnobs_AreIndependent_2026_05_24(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6}
	mcd := p.maxConcurrentDrains()
	floor := p.readyCapacityFloor()
	if mcd != 3 {
		t.Errorf("at poolSize=6, maxConcurrentDrains = %d, want 3", mcd)
	}
	if floor != 4 {
		t.Errorf("at poolSize=6, readyCapacityFloor = %d, want 4", floor)
	}
	if mcd+floor <= 6 {
		t.Errorf("after decouple, knobs should not constrain each other "+
			"(mcd=%d + floor=%d = %d, expected sum > poolSize=6)",
			mcd, floor, mcd+floor)
	}
}

// absDuration returns the absolute value of a time.Duration. Used in
// jitter-bound tests to allow small slop for float rounding.
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// TestComputeReserveBackoff_FirstFailure — failures=1 with rng=0.5
// (zero jitter) yields exactly reserveConnectInitialBackoff.
func TestComputeReserveBackoff_FirstFailure(t *testing.T) {
	got := computeReserveBackoff(1, func() float64 { return 0.5 })
	if got != reserveConnectInitialBackoff {
		t.Errorf("backoff(1, rng=0.5) = %v, want %v",
			got, reserveConnectInitialBackoff)
	}
}

// TestComputeReserveBackoff_DoublesEachFailure — verifies exponential
// growth before the cap with rng=0.5 (no jitter).
func TestComputeReserveBackoff_DoublesEachFailure(t *testing.T) {
	rng := func() float64 { return 0.5 }
	cases := []struct {
		failures int32
		want     time.Duration
	}{
		{failures: 1, want: 500 * time.Millisecond},
		{failures: 2, want: 1 * time.Second},
		{failures: 3, want: 2 * time.Second},
		{failures: 4, want: 4 * time.Second},
		{failures: 5, want: 8 * time.Second},
		{failures: 6, want: 16 * time.Second},
	}
	for _, c := range cases {
		got := computeReserveBackoff(c.failures, rng)
		if got != c.want {
			t.Errorf("backoff(%d, no-jitter) = %v, want %v",
				c.failures, got, c.want)
		}
	}
}

// TestComputeReserveBackoff_CapsAtMax — beyond the doubling threshold
// (failures=7+) backoff stops at the ceiling reserveConnectMaxBackoff.
func TestComputeReserveBackoff_CapsAtMax(t *testing.T) {
	rng := func() float64 { return 0.5 }
	for _, failures := range []int32{7, 10, 100, 1000, 1 << 20} {
		got := computeReserveBackoff(failures, rng)
		if got != reserveConnectMaxBackoff {
			t.Errorf("backoff(%d) = %v, want %v (cap)",
				failures, got, reserveConnectMaxBackoff)
		}
	}
}

// TestComputeReserveBackoff_JitterBounds — verifies ±20% jitter is
// applied correctly at both extremes of the rng range.
func TestComputeReserveBackoff_JitterBounds(t *testing.T) {
	// rng=0.0 → jitterFrac = -0.2 → backoff * 0.8
	low := computeReserveBackoff(1, func() float64 { return 0.0 })
	wantLow := time.Duration(float64(reserveConnectInitialBackoff) * 0.8)
	if low != wantLow {
		t.Errorf("backoff(1, rng=0.0) = %v, want %v (low jitter bound)",
			low, wantLow)
	}

	// rng=0.999999 → jitterFrac ≈ +0.2 → backoff * ~1.2
	high := computeReserveBackoff(1, func() float64 { return 0.999999 })
	wantHigh := time.Duration(float64(reserveConnectInitialBackoff) * 1.2)
	if absDuration(high-wantHigh) > time.Microsecond {
		t.Errorf("backoff(1, rng≈1.0) = %v, want ≈%v (high jitter bound)",
			high, wantHigh)
	}
}

// TestComputeReserveBackoff_GuardsZeroFailures — defensive: failures=0
// or negative still produces initial backoff (treat as failures=1).
func TestComputeReserveBackoff_GuardsZeroFailures(t *testing.T) {
	rng := func() float64 { return 0.5 }
	for _, f := range []int32{0, -1, -100} {
		got := computeReserveBackoff(f, rng)
		if got != reserveConnectInitialBackoff {
			t.Errorf("backoff(%d) = %v, want %v (defensive)",
				f, got, reserveConnectInitialBackoff)
		}
	}
}

// makeReserveSlotTestPool returns a pool ready to exercise
// connectReserveSlot via the connectSlotForTest hook. poolSize=4 →
// slice size = 8 cells. Caller chooses newIdx and oldIdx for the
// connectReserveSlot call.
func makeReserveSlotTestPool(t *testing.T) *WSPoolTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &WSPoolTransport{
		poolSize: 4,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, p.poolSize*2)
	p.reserveConnectFailures = make([]atomic.Int32, p.poolSize*2)
	return p
}

// TestConnectReserveSlot_IncrementsFailureCounterOnFailure — verifies
// failure path bumps the pool-level counter. Two consecutive failures
// should produce counter=2.
func TestConnectReserveSlot_IncrementsFailureCounterOnFailure(t *testing.T) {
	p := makeReserveSlotTestPool(t)

	// Pre-install a slot at idx 1 so connectReserveSlot doesn't bail
	// out at the bounds check, and reserveMu cleanup has something to do.
	p.slots[1] = &poolSlot{index: 1}
	p.slots[1].setState(slotConnecting)

	prev := getConnectSlotForTest()
	setConnectSlotForTest(func() error { return errors.New("simulated failure") })
	t.Cleanup(func() { setConnectSlotForTest(prev) })

	p.connectReserveSlot(nil, 1, 0)

	if got := p.reserveConnectFailures[1].Load(); got != 1 {
		t.Errorf("after 1 failure, counter = %d, want 1", got)
	}

	// Re-install slot (cleanup nil'd it in the first call).
	p.slots[1] = &poolSlot{index: 1}
	p.slots[1].setState(slotConnecting)
	p.connectReserveSlot(nil, 1, 0)

	if got := p.reserveConnectFailures[1].Load(); got != 2 {
		t.Errorf("after 2 failures, counter = %d, want 2", got)
	}
}

// TestConnectReserveSlot_ResetsFailureCounterOnSuccess — pre-load the
// counter, drive connectReserveSlot success path via test hook, verify
// counter returns to 0. Tests real business logic via the hook (not
// the tautology p.Store(0); read==0).
func TestConnectReserveSlot_ResetsFailureCounterOnSuccess(t *testing.T) {
	p := makeReserveSlotTestPool(t)
	p.slots[2] = &poolSlot{index: 2}
	p.slots[2].setState(slotConnecting)
	p.reserveConnectFailures[2].Store(5) // simulate prior failures

	prev := getConnectSlotForTest()
	// Success: return nil. NOTE: real connectReserveSlot spawns
	// p.slotReader on success, which we cannot run here (no real Client).
	// But the counter reset happens BEFORE the slotReader spawn, so
	// we observe the side effect synchronously. The slotReader spawn
	// is harmless — it operates on a non-existent transport and exits
	// immediately when ReadMessage fails.
	setConnectSlotForTest(func() error { return nil })
	t.Cleanup(func() { setConnectSlotForTest(prev) })

	// Use a non-nil minimal Client so slotReader can dispatch into it
	// without nil deref. Read paths in slotReader will fail fast on
	// the nil transport but the counter reset already happened.
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p.connectReserveSlot(cl, 2, 0)

	if got := p.reserveConnectFailures[2].Load(); got != 0 {
		t.Errorf("after success, counter = %d, want 0 (reset)", got)
	}
}

// TestConnectReserveSlot_PoolLevelCounterSurvivesSlotRecycle —
// regression guard for opus review H2 from the spec. Pre-load 3 in
// pool-level counter. Simulate cell recycle (slot becomes nil, then a
// fresh poolSlot is installed at the same index). Trigger one more
// failure. Counter should be 4 (3 + 1), NOT 1 (which would happen if
// the counter lived on poolSlot).
func TestConnectReserveSlot_PoolLevelCounterSurvivesSlotRecycle(t *testing.T) {
	p := makeReserveSlotTestPool(t)
	const idx = 3
	p.reserveConnectFailures[idx].Store(3) // simulate prior failures

	// Simulate recycle: slot 3 was nil'd, now a fresh slot is claimed.
	p.slots[idx] = &poolSlot{index: idx}
	p.slots[idx].setState(slotConnecting)

	prev := getConnectSlotForTest()
	setConnectSlotForTest(func() error { return errors.New("still failing") })
	t.Cleanup(func() { setConnectSlotForTest(prev) })

	p.connectReserveSlot(nil, idx, 0)

	if got := p.reserveConnectFailures[idx].Load(); got != 4 {
		t.Errorf("after recycle + 1 more failure, counter = %d, want 4 "+
			"(counter must survive recycle — opus review H2 guard)", got)
	}
}

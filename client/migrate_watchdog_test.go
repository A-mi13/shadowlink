package client

import (
	"os"
	"sync"
	"testing"
	"time"
)

// migrate_watchdog_test.go — Bug #9 Task 16. Age-watchdog migration trigger:
// per-slot threshold jitter (U(0.7,1.0)×base), per-stream spread (U(0,spread)
// — NOT a synchronized burst, F7 §5.6), and young-slot target selection.

// TestMigrationThresholdJitter_InRange asserts that sampled per-slot migration
// thresholds land inside [0.7×base, 1.0×base] and exhibit real variance — a
// fixed threshold would be an FFT-visible periodicity to a middlebox.
func TestMigrationThresholdJitter_InRange(t *testing.T) {
	base := 60 * time.Second
	lo := time.Duration(float64(base) * 0.7)
	hi := base

	const n = 2000
	var first time.Duration
	allEqual := true
	for i := 0; i < n; i++ {
		got := time.Duration(sampleMigrationThreshold(base))
		if got < lo || got > hi {
			t.Fatalf("sample %d = %v out of range [%v, %v]", i, got, lo, hi)
		}
		if i == 0 {
			first = got
		} else if got != first {
			allEqual = false
		}
	}
	if allEqual {
		t.Fatal("all samples identical — jitter has zero variance (deterministic threshold is DPI-visible)")
	}
}

// TestMigrationThresholdJitter_ZeroBase guards the degenerate input.
func TestMigrationThresholdJitter_ZeroBase(t *testing.T) {
	if got := sampleMigrationThreshold(0); got != 0 {
		t.Fatalf("sampleMigrationThreshold(0) = %d, want 0", got)
	}
}

// TestMigrationThresholdBelowCutWindow is the anti-DPI safety invariant:
// even at the maximum jitter multiplier (×1.0) the effective threshold must
// stay strictly below the observed middlebox cut window (~90s) with margin,
// so a stream is migrated BEFORE the TSPU freezes the aging slot's TCP.
func TestMigrationThresholdBelowCutWindow(t *testing.T) {
	base := migrationThresholdBase()
	const observedCutWindow = 90 * time.Second
	// Max effective threshold is base × 1.0 (the high end of U(0.7,1.0)).
	maxEffective := base
	if maxEffective >= observedCutWindow {
		t.Fatalf("max migration threshold %v >= cut window %v — no margin to migrate before TSPU kill",
			maxEffective, observedCutWindow)
	}
	// Sanity: the default base is 60s, leaving a 30s margin.
	if base != 60*time.Second {
		t.Logf("note: migrationThresholdBase()=%v (env override active)", base)
	}
}

// TestMigrationThresholdBase_EnvOverride covers the env helper.
func TestMigrationThresholdBase_EnvOverride(t *testing.T) {
	t.Setenv("SHADOWLINK_MIGRATE_THRESHOLD", "45s")
	if got := migrationThresholdBase(); got != 45*time.Second {
		t.Fatalf("migrationThresholdBase() = %v, want 45s", got)
	}
	os.Unsetenv("SHADOWLINK_MIGRATE_THRESHOLD")
	if got := migrationThresholdBase(); got != 60*time.Second {
		t.Fatalf("migrationThresholdBase() default = %v, want 60s", got)
	}
}

// TestMigrationSpread_EnvOverride covers the spread env helper.
func TestMigrationSpread_EnvOverride(t *testing.T) {
	t.Setenv("SHADOWLINK_MIGRATE_SPREAD", "3s")
	if got := migrationSpread(); got != 3*time.Second {
		t.Fatalf("migrationSpread() = %v, want 3s", got)
	}
	os.Unsetenv("SHADOWLINK_MIGRATE_SPREAD")
	if got := migrationSpread(); got != 8*time.Second {
		t.Fatalf("migrationSpread() default = %v, want 8s", got)
	}
}

// TestSelectYoungTargetSlot: among ready slots != aging, pick the youngest
// (largest startedAtNs = most recently connected). false if no eligible slot.
func TestSelectYoungTargetSlot(t *testing.T) {
	p := &WSPoolTransport{poolSize: 4}
	p.slots = make([]*poolSlot, 4)
	for i := range p.slots {
		p.slots[i] = &poolSlot{index: i}
	}
	now := time.Now().UnixNano()
	// slot 0: aging (oldest)
	p.slots[0].startedAtNs.Store(now - int64(120*time.Second))
	p.slots[0].state.Store(int32(slotReady))
	// slot 1: medium age, ready
	p.slots[1].startedAtNs.Store(now - int64(40*time.Second))
	p.slots[1].state.Store(int32(slotReady))
	// slot 2: youngest, ready  → expected winner
	p.slots[2].startedAtNs.Store(now - int64(5*time.Second))
	p.slots[2].state.Store(int32(slotReady))
	// slot 3: even younger BUT not ready (connecting) → ineligible
	p.slots[3].startedAtNs.Store(now - int64(1*time.Second))
	p.slots[3].state.Store(int32(slotConnecting))

	target, ok := p.selectYoungTargetSlot(0)
	if !ok {
		t.Fatal("expected a young target slot, got ok=false")
	}
	if target != 2 {
		t.Fatalf("selectYoungTargetSlot(0) = %d, want 2 (youngest ready != aging)", target)
	}

	// Aging slot must never be its own target.
	if target == 0 {
		t.Fatal("aging slot selected as target")
	}

	// No eligible slot case: only the aging slot is ready.
	p2 := &WSPoolTransport{poolSize: 2}
	p2.slots = make([]*poolSlot, 2)
	for i := range p2.slots {
		p2.slots[i] = &poolSlot{index: i}
	}
	p2.slots[0].startedAtNs.Store(now)
	p2.slots[0].state.Store(int32(slotReady))
	p2.slots[1].state.Store(int32(slotDead))
	if _, ok := p2.selectYoungTargetSlot(0); ok {
		t.Fatal("expected ok=false when no ready slot != aging exists")
	}
}

// TestMigrationSpread_NotBurst asserts that N streams on an aged slot receive
// migration offsets spread across [0, spread) — NOT all at t0. A synchronized
// burst (slot A goes quiet + slot B lights up at the same instant) is the
// exact F7 §5.6 correlation signal we are defeating.
func TestMigrationSpread_NotBurst(t *testing.T) {
	spread := 8 * time.Second
	const n = 500
	offsets := make([]time.Duration, n)
	var first time.Duration
	allEqual := true
	zeroCount := 0
	for i := 0; i < n; i++ {
		o := sampleMigrationOffset(spread)
		offsets[i] = o
		if o < 0 || o >= spread {
			t.Fatalf("offset %d = %v out of [0, %v)", i, o, spread)
		}
		if o == 0 {
			zeroCount++
		}
		if i == 0 {
			first = o
		} else if o != first {
			allEqual = false
		}
	}
	if allEqual {
		t.Fatal("all offsets identical — migrations would fire as a synchronized burst (F7 §5.6 violation)")
	}
	// A burst would mean nearly all offsets pinned at 0. With U(0,8s) we expect
	// almost none exactly at 0.
	if zeroCount > n/10 {
		t.Fatalf("too many zero offsets (%d/%d) — distribution not spread", zeroCount, n)
	}
}

// TestMigrationSpread_ZeroSpread guards the degenerate input.
func TestMigrationSpread_ZeroSpread(t *testing.T) {
	if got := sampleMigrationOffset(0); got != 0 {
		t.Fatalf("sampleMigrationOffset(0) = %v, want 0", got)
	}
}

// TestScheduleSlotMigration_Idempotent verifies the watchdog does not
// re-schedule a slot whose migration has already been scheduled. We drive
// scheduleSlotMigration twice and confirm only one batch of timers fires per
// stream (the migrationScheduled flag gates the second call).
func TestScheduleSlotMigration_Idempotent(t *testing.T) {
	p := &WSPoolTransport{poolSize: 2}
	p.slots = make([]*poolSlot, 2)
	for i := range p.slots {
		p.slots[i] = &poolSlot{index: i}
	}
	now := time.Now().UnixNano()
	p.slots[0].startedAtNs.Store(now - int64(120*time.Second))
	p.slots[0].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(now)
	p.slots[1].state.Store(int32(slotReady))

	// Two streams attached to the aging slot 0.
	p.streamMap.Store(uint16(10), newStreamEntry(0))
	p.streamMap.Store(uint16(11), newStreamEntry(0))

	var mu sync.Mutex
	calls := map[uint16]int{}
	// Inject a test hook so we count migrateStream invocations without the
	// real wire round-trip.
	p.migrateStreamHook = func(streamID uint16) {
		mu.Lock()
		calls[streamID]++
		mu.Unlock()
	}

	// Use a tiny spread so the AfterFunc timers fire quickly in-test.
	p.migrateSpreadOverride = 10 * time.Millisecond

	// First schedule: arms timers for both streams.
	if !p.scheduleSlotMigration(0, p.slots[0]) {
		t.Fatal("first scheduleSlotMigration should report scheduled=true")
	}
	// Second schedule on the SAME aging slot must be a no-op (idempotent).
	if p.scheduleSlotMigration(0, p.slots[0]) {
		t.Fatal("second scheduleSlotMigration must be idempotent (scheduled=false)")
	}

	// Wait for the timers to fire.
	time.Sleep(120 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if calls[10] != 1 || calls[11] != 1 {
		t.Fatalf("each stream must be migrated exactly once, got %v", calls)
	}
}

// TestMigrateStream_TransfersSlotCounter is the T16 IMPORTANT fix: on a
// successful migration re-bind, the per-slot active-stream counter must move
// from the aging slot to the target so the aging slot frees cleanly
// (streams==0) and the target is correctly accounted (streams==1). A missed
// transfer leaves the aging slot phantom-occupied (rotation deferred forever)
// and undercounts the target (later Release goes negative).
func TestMigrateStream_TransfersSlotCounter(t *testing.T) {
	p := &WSPoolTransport{poolSize: 2}
	p.slots = make([]*poolSlot, 2)
	for i := range p.slots {
		p.slots[i] = &poolSlot{index: i}
	}

	// Stream lives on the aging slot 0 exactly as AssignStream would leave it:
	// streamMap entry bound to slot 0 AND slot 0's counter at 1.
	p.streamMap.Store(uint16(7), newStreamEntry(0))
	p.slots[0].streams.Store(1)
	p.slots[1].streams.Store(0)

	// Re-bind onto target slot 1 (the success-path action of migrateStream).
	p.rebindStreamToSlot(7, 1)

	if got := p.slots[0].streams.Load(); got != 0 {
		t.Fatalf("aging slot 0 streams = %d, want 0 (must free after migration)", got)
	}
	if got := p.slots[1].streams.Load(); got != 1 {
		t.Fatalf("target slot 1 streams = %d, want 1 (must be accounted after migration)", got)
	}
	// Binding must point at the target now.
	v, ok := p.streamMap.Load(uint16(7))
	if !ok {
		t.Fatal("stream entry missing after re-bind")
	}
	if e := v.(*streamEntry); e.slotIdx != 1 {
		t.Fatalf("stream slotIdx = %d, want 1 after re-bind", e.slotIdx)
	}

	// A subsequent ReleaseStream of the migrated stream must land the target
	// back at 0 — proving the +1/-1 invariant held across the migration.
	p.ReleaseStream(7)
	if got := p.slots[1].streams.Load(); got != 0 {
		t.Fatalf("target slot 1 streams = %d after Release, want 0 (paired inc/dec)", got)
	}
	if got := p.slots[0].streams.Load(); got != 0 {
		t.Fatalf("aging slot 0 streams = %d after Release, want 0 (must not go negative)", got)
	}
}

// TestMigrateStream_TransferCounter_EdgeCases covers the no-op edges: a stream
// that is already gone (concurrent slot death / Release) must not decrement a
// foreign slot, and a stream already bound to the target must not double-count.
func TestMigrateStream_TransferCounter_EdgeCases(t *testing.T) {
	p := &WSPoolTransport{poolSize: 2}
	p.slots = make([]*poolSlot, 2)
	for i := range p.slots {
		p.slots[i] = &poolSlot{index: i}
	}

	// Edge 1: stream not in the map (already released / slot died before the
	// migration timer fired). rebind must be a clean no-op — no counter touched.
	p.slots[0].streams.Store(0)
	p.slots[1].streams.Store(0)
	p.rebindStreamToSlot(99, 1)
	if got := p.slots[0].streams.Load(); got != 0 {
		t.Fatalf("slot 0 streams = %d after no-op rebind of absent stream, want 0", got)
	}
	if got := p.slots[1].streams.Load(); got != 0 {
		t.Fatalf("slot 1 streams = %d after no-op rebind of absent stream, want 0 (no phantom inc)", got)
	}

	// Edge 2: stream already on the target slot (race / repeat migration onto
	// the same slot). Must be a no-op so the target is not double-incremented
	// and the source (== target) is not decremented below its real count.
	p.streamMap.Store(uint16(5), newStreamEntry(1))
	p.slots[1].streams.Store(1)
	p.rebindStreamToSlot(5, 1)
	if got := p.slots[1].streams.Load(); got != 1 {
		t.Fatalf("target slot 1 streams = %d after repeat rebind, want 1 (no double-count)", got)
	}

	// Edge 3: between scheduling and firing, the stream moved to a DIFFERENT
	// slot than the watchdog planned. The decrement must hit the slot the
	// stream actually left (read from the live entry), never go negative.
	p.streamMap.Store(uint16(8), newStreamEntry(1)) // actually on slot 1 now
	p.slots[1].streams.Store(1)
	p.slots[0].streams.Store(0)
	p.rebindStreamToSlot(8, 0) // migrate onto slot 0
	if got := p.slots[1].streams.Load(); got != 0 {
		t.Fatalf("slot 1 (real source) streams = %d, want 0 (decremented the slot stream left)", got)
	}
	if got := p.slots[0].streams.Load(); got != 1 {
		t.Fatalf("slot 0 (target) streams = %d, want 1", got)
	}
}

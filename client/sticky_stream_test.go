package client

import (
	"sync"
	"testing"
	"time"
)

func TestEffectiveStickyMaxSlots(t *testing.T) {
	cases := []struct {
		name       string
		poolSize   int
		cfgMax     int
		wantResult int
	}{
		{"auto half of 6", 6, 0, 3},
		{"auto half of 8", 8, 0, 4},
		{"auto poolSize 2 → min 1", 2, 0, 1},
		{"auto odd 5 → 2", 5, 0, 2},
		{"explicit 1", 6, 1, 1},
		{"explicit cap above half", 6, 5, 5},
		{"negative → disabled (0)", 6, -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &WSPoolTransport{poolSize: tc.poolSize, stickyMaxSlots: tc.cfgMax}
			if got := p.effectiveStickyMaxSlots(); got != tc.wantResult {
				t.Errorf("poolSize=%d cfgMax=%d: got %d, want %d",
					tc.poolSize, tc.cfgMax, got, tc.wantResult)
			}
		})
	}
}

func TestStickyMarkReleaseIdempotent(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	slot := &poolSlot{index: 0}

	p.markSticky(slot)
	p.markSticky(slot) // idempotent via CAS
	if got := p.stickyDrainCount.Load(); got != 1 {
		t.Fatalf("after 2× markSticky: count=%d, want 1", got)
	}
	if !slot.isSticky.Load() {
		t.Fatal("isSticky should be true after markSticky")
	}

	p.releaseSticky(slot)
	p.releaseSticky(slot) // idempotent via Swap
	if got := p.stickyDrainCount.Load(); got != 0 {
		t.Fatalf("after 2× releaseSticky: count=%d, want 0", got)
	}
	if slot.isSticky.Load() {
		t.Fatal("isSticky should be false after releaseSticky")
	}

	// release on a never-marked slot must be a no-op (Task 4 defers
	// releaseSticky for slots that never reached markSticky, e.g. a fast
	// idle-finish on the first deadline tick). Swap(false)→false → no decrement.
	fresh := &poolSlot{index: 1}
	p.releaseSticky(fresh)
	if got := p.stickyDrainCount.Load(); got != 0 {
		t.Fatalf("release on unmarked slot: count=%d, want 0", got)
	}
}

func TestStickyQuotaAvailable(t *testing.T) {
	newReadyPool := func(size, cfgMax int) *WSPoolTransport {
		p := &WSPoolTransport{poolSize: size, stickyMaxSlots: cfgMax}
		p.slots = make([]*poolSlot, 2*size)
		for i := 0; i < size; i++ {
			s := &poolSlot{index: i}
			s.state.Store(int32(slotReady))
			p.slots[i] = s
		}
		return p
	}

	t.Run("already sticky → always allowed", func(t *testing.T) {
		p := newReadyPool(6, 0)
		s := &poolSlot{index: 0}
		s.isSticky.Store(true)
		if !p.stickyQuotaAvailable(s) {
			t.Fatal("already-sticky slot must always be allowed to extend")
		}
	})
	t.Run("under cap + healthy capacity → allowed", func(t *testing.T) {
		p := newReadyPool(6, 0)
		s := &poolSlot{index: 0}
		if !p.stickyQuotaAvailable(s) {
			t.Fatal("fresh slot under cap with healthy capacity should be allowed")
		}
	})
	t.Run("at static cap → denied", func(t *testing.T) {
		p := newReadyPool(6, 0)
		p.stickyDrainCount.Store(3)
		s := &poolSlot{index: 0}
		if p.stickyQuotaAvailable(s) {
			t.Fatal("at static cap, new sticky must be denied")
		}
	})
	t.Run("capacity at floor → denied", func(t *testing.T) {
		p := newReadyPool(6, 0)
		for i := 0; i < 6; i++ {
			p.slots[i].state.Store(int32(slotDraining))
		}
		s := &poolSlot{index: 0}
		if p.stickyQuotaAvailable(s) {
			t.Fatal("at/below capacity floor, new sticky must be denied")
		}
	})
	t.Run("disabled cap (cfgMax<0) → denied", func(t *testing.T) {
		p := newReadyPool(6, -1)
		s := &poolSlot{index: 0}
		if p.stickyQuotaAvailable(s) {
			t.Fatal("cfgMax<0 disables sticky → denied")
		}
	})
}

// TestDrainWatchdog_StickyAgeBackstop: an ACTIVE stream (fresh lastWriteNs)
// must survive the hard cap (drainWatchdog keeps extending past the blind
// teardown), then get torn down via the AGE backstop once StickyMaxDrainAge is
// reached — proving the deadline branch makes a real decision instead of a
// blind hard-cap kill.
//
// Timing note (spec M2-v2 / L3): the age backstop is only re-evaluated at a
// deadline fire. After the first extension the deadline is reset to the fixed
// stickyRecheckInterval (5s). So for the AGE backstop to win the race against
// the ticker's idle branch (drainPollInterval cadence), two invariants must
// hold:
//   - StickyMaxDrainAge < first-recheck-fire  → backstop trips at that fire.
//   - DrainIdleThreshold > first-recheck-fire  → stream still reads "active"
//     when the recheck fires (the static lastWriteNs must not age past the
//     idle window before then), so the ticker idle branch does NOT tear down
//     first.
//
// With hardCap=50ms the deadline fires at ~50ms (age<backstop → extend,
// Reset(5s)), then again at ~5.05s; idleThreshold=15s keeps the stream active
// across that, and StickyMaxDrainAge=2s makes the 5.05s fire trip the age
// backstop. Expected teardown ≈ stickyRecheckInterval (~5s).
func TestDrainWatchdog_StickyAgeBackstop(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:                6,
		ServerAddr:          "127.0.0.1:0",
		DrainHardCap:        50 * time.Millisecond, // hard cap small → first extend fast
		DrainIdleThreshold:  15 * time.Second,      // wide → stream stays "active" past first recheck
		StickyMaxDrainAge:   2 * time.Second,       // age backstop trips at the ~5s recheck fire
		StickyMaxTotalBytes: 1 << 30,               // 1 GiB — won't trip in this test
		// StickyMaxSlots default 0 → auto poolSize/2 = 3
	})
	// We did NOT call Connect, so no reconnect/watchdog goroutines spawned —
	// only our manual drainWatchdog runs.

	oldSlot := &poolSlot{index: 0}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(1)
	p.slots[0] = oldSlot
	// keep slots 1..5 ready so readyCapacity (5) stays above the storm-brake
	// floor (floor(6*0.75)=4) → stickyQuotaAvailable does NOT deny the extension.
	for i := 1; i < 6; i++ {
		ready := &poolSlot{index: i}
		ready.setState(slotReady)
		p.slots[i] = ready
	}

	// active stream: lastWriteNs = now (fresh, well within the 15s idleThreshold)
	p.streamMap.Store(uint16(1), newStreamEntry(0))
	p.inflightDrains.Add(1) // drainWatchdog defers -1

	before := Stats.DrainStickyBackstopAgeTotal.Load()
	start := time.Now()
	done := make(chan struct{})
	go func() {
		p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("drainWatchdog did not finish")
	}
	elapsed := time.Since(start)

	// Survived the 50ms blind hard cap — the deadline branch extended instead
	// of tearing the active stream down.
	if elapsed < 100*time.Millisecond {
		t.Errorf("teardown too early (%v): active stream should survive 50ms hard cap", elapsed)
	}
	// Torn down at the first recheck fire by the age backstop (≈ recheck 5s),
	// not left to run forever and not via the 15s idle threshold.
	if elapsed > 8*time.Second {
		t.Errorf("teardown too late (%v): age backstop should fire at the ~5s recheck", elapsed)
	}
	if got := Stats.DrainStickyBackstopAgeTotal.Load(); got != before+1 {
		t.Errorf("DrainStickyBackstopAgeTotal: %d → %d, want +1", before, got)
	}
}

// TestDrainWatchdog_StickyTeardownBumpsRotationsOnce is the regression guard
// for final-review H-1: a sticky-backstop teardown must bump rotations1m
// EXACTLY ONCE (like hard-cap / idle / streams-zero), not twice. The bug was
// that both tearDown and emitStickyTeardownLog called bumpRotations1m.
func TestDrainWatchdog_StickyTeardownBumpsRotationsOnce(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size: 6, ServerAddr: "127.0.0.1:0",
		DrainHardCap:        50 * time.Millisecond,
		DrainIdleThreshold:  15 * time.Second, // stream stays active
		StickyMaxDrainAge:   2 * time.Second,  // age backstop trips at ~5s recheck
		StickyMaxTotalBytes: 1 << 30,
	})
	oldSlot := &poolSlot{index: 0}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(1)
	p.slots[0] = oldSlot
	for i := 1; i < 6; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		p.slots[i] = s
	}
	storeStreamForTest(p, 1, 0) // active
	p.inflightDrains.Add(1)

	before := p.rotations1m.Load()
	done := make(chan struct{})
	go func() { p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test"); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("watchdog did not finish")
	}
	if got := p.rotations1m.Load(); got != before+1 {
		t.Errorf("sticky teardown bumped rotations1m by %d, want exactly 1 (H-1 double-bump regression)", got-before)
	}
}

// TestDrainWatchdog_DeadlineEmptySlotStreamsZero is the regression guard for
// final-review M-2: if the last stream closes between a ticker tick and the
// deadline fire, the deadline branch must tear the empty slot down as
// finishStreamsZero — not fall into default→extend (allStreamsIdle returns
// false for an empty set, so without the explicit streams==0 case the slot
// would be extended for a needless 5s).
func TestDrainWatchdog_DeadlineEmptySlotStreamsZero(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size: 6, ServerAddr: "127.0.0.1:0",
		DrainHardCap:        50 * time.Millisecond,
		DrainIdleThreshold:  15 * time.Second,
		StickyMaxDrainAge:   10 * time.Minute,
		StickyMaxTotalBytes: 1 << 30,
	})
	oldSlot := &poolSlot{index: 0}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(0) // empty — no stream entries in streamMap either
	p.slots[0] = oldSlot
	for i := 1; i < 6; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		p.slots[i] = s
	}
	p.inflightDrains.Add(1)

	natBefore := Stats.DrainNaturalFinishTotal.Load()
	extBefore := Stats.DrainStickyExtendedTotal.Load()
	start := time.Now()
	done := make(chan struct{})
	go func() { p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not finish")
	}
	// Empty slot torn down promptly (ticker at 500ms OR deadline at 50ms),
	// never extended.
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("empty slot took %v to tear down, should be prompt", elapsed)
	}
	if got := Stats.DrainStickyExtendedTotal.Load(); got != extBefore {
		t.Errorf("empty slot must NOT be sticky-extended: extended %d → %d", extBefore, got)
	}
	if got := Stats.DrainNaturalFinishTotal.Load(); got <= natBefore {
		t.Errorf("empty slot must tear down as natural finish (streams-zero): %d → %d", natBefore, got)
	}
}

// ---------------------------------------------------------------------------
// Task 7 — idle / bytes / kill-switch behavior at the deadline branch.
// ---------------------------------------------------------------------------

// idle stream at deadline → natural-finish (NOT hard-cap). Verifies M5: idle
// teardown in the deadline branch goes to natural-finish metrics, keeping
// DrainHardCapTotal clean.
func TestDrainWatchdog_IdleGoesToNaturalFinish(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size: 6, ServerAddr: "127.0.0.1:0",
		DrainHardCap:        50 * time.Millisecond,
		DrainIdleThreshold:  30 * time.Millisecond, // small → stream reads idle
		StickyMaxDrainAge:   10 * time.Minute,
		StickyMaxTotalBytes: 1 << 30,
	})
	oldSlot := &poolSlot{index: 0}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(1)
	p.slots[0] = oldSlot
	for i := 1; i < 6; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		p.slots[i] = s
	}
	// IDLE stream: lastWriteNs 1s in the past (> 30ms idle threshold)
	storeStreamForTestWithAge(p, 1, 0, 1*time.Second)
	p.inflightDrains.Add(1)

	hardBefore := Stats.DrainHardCapTotal.Load()
	natBefore := Stats.DrainNaturalFinishTotal.Load()
	done := make(chan struct{})
	go func() { p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not finish")
	}
	if got := Stats.DrainHardCapTotal.Load(); got != hardBefore {
		t.Errorf("idle teardown must NOT bump DrainHardCapTotal: %d → %d", hardBefore, got)
	}
	if got := Stats.DrainNaturalFinishTotal.Load(); got <= natBefore {
		t.Errorf("idle teardown must bump natural-finish: %d → %d", natBefore, got)
	}
}

// active stream whose downBytes exceeds the byte backstop → bytes backstop.
func TestDrainWatchdog_StickyBytesBackstop(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size: 6, ServerAddr: "127.0.0.1:0",
		DrainHardCap:        50 * time.Millisecond,
		DrainIdleThreshold:  15 * time.Second, // wide → stream active
		StickyMaxDrainAge:   10 * time.Minute,
		StickyMaxTotalBytes: 1024, // 1KB limit
	})
	oldSlot := &poolSlot{index: 0}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(1)
	oldSlot.downBytes.Store(2048) // > 1KB
	p.slots[0] = oldSlot
	for i := 1; i < 6; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		p.slots[i] = s
	}
	storeStreamForTest(p, 1, 0) // active
	p.inflightDrains.Add(1)

	before := Stats.DrainStickyBackstopBytesTotal.Load()
	done := make(chan struct{})
	go func() { p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not finish")
	}
	if got := Stats.DrainStickyBackstopBytesTotal.Load(); got != before+1 {
		t.Errorf("DrainStickyBackstopBytesTotal: %d → %d, want +1", before, got)
	}
}

// kill switch: StickyMaxDrainAge<=0 → blind hard-cap even for an active stream.
func TestDrainWatchdog_StickyKillSwitch(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size: 6, ServerAddr: "127.0.0.1:0",
		DrainHardCap:        50 * time.Millisecond,
		DrainIdleThreshold:  15 * time.Second,
		StickyMaxDrainAge:   -1, // kill switch (negative survives NewWSPoolTransport default)
		StickyMaxTotalBytes: 1 << 30,
	})
	oldSlot := &poolSlot{index: 0}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(1)
	p.slots[0] = oldSlot
	for i := 1; i < 6; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		p.slots[i] = s
	}
	storeStreamForTest(p, 1, 0) // active
	p.inflightDrains.Add(1)

	before := Stats.DrainHardCapTotal.Load()
	start := time.Now()
	done := make(chan struct{})
	go func() { p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not finish")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("kill switch: should tear down at hard cap (~50ms), took %v", elapsed)
	}
	if got := Stats.DrainHardCapTotal.Load(); got != before+1 {
		t.Errorf("kill switch must bump DrainHardCapTotal: %d → %d", before, got)
	}
}

// ---------------------------------------------------------------------------
// Task 8 — cross-recycle (H2) + clinch (H4) coverage.
// ---------------------------------------------------------------------------

// H2: old watchdog marked sticky, cell recycled to a NEW *poolSlot, old
// deferred releaseSticky must NOT touch the new slot or corrupt the counter.
func TestSticky_CrossRecycleNoDesync(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	oldSlot := &poolSlot{index: 0}
	newSlot := &poolSlot{index: 0} // same cell idx, NEW pointer

	p.markSticky(oldSlot)
	if p.stickyDrainCount.Load() != 1 {
		t.Fatalf("after old markSticky: count=%d want 1", p.stickyDrainCount.Load())
	}
	p.markSticky(newSlot)
	if p.stickyDrainCount.Load() != 2 {
		t.Fatalf("after new markSticky: count=%d want 2", p.stickyDrainCount.Load())
	}
	p.releaseSticky(oldSlot) // old defer — operates on its OWN pointer
	if p.stickyDrainCount.Load() != 1 {
		t.Fatalf("after old release: count=%d want 1 (newSlot still sticky)", p.stickyDrainCount.Load())
	}
	if !newSlot.isSticky.Load() {
		t.Fatal("newSlot must still be sticky — old release must not touch it")
	}
	p.releaseSticky(newSlot)
	if p.stickyDrainCount.Load() != 0 {
		t.Fatalf("after new release: count=%d want 0", p.stickyDrainCount.Load())
	}
}

// H2 reordered: old release BEFORE new mark.
func TestSticky_CrossRecycleReorderedRelease(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	oldSlot := &poolSlot{index: 0}
	newSlot := &poolSlot{index: 0}
	p.markSticky(oldSlot)
	p.releaseSticky(oldSlot)
	p.markSticky(newSlot)
	if p.stickyDrainCount.Load() != 1 {
		t.Fatalf("count=%d want 1", p.stickyDrainCount.Load())
	}
}

// H2 concurrent under -race: balanced mark/release on many slots → count 0.
func TestSticky_ConcurrentMarkRelease(t *testing.T) {
	p := &WSPoolTransport{poolSize: 100, stickyMaxSlots: 1000}
	const n = 200
	slots := make([]*poolSlot, n)
	for i := range slots {
		slots[i] = &poolSlot{index: i % 100}
	}
	var wg sync.WaitGroup
	for i := range slots {
		wg.Add(1)
		go func(s *poolSlot) {
			defer wg.Done()
			p.markSticky(s)
			p.markSticky(s)
			p.releaseSticky(s)
			p.releaseSticky(s)
		}(slots[i])
	}
	wg.Wait()
	if got := p.stickyDrainCount.Load(); got != 0 {
		t.Fatalf("after balanced concurrent mark/release: count=%d want 0", got)
	}
}

// H4: unhealthy capacity → new sticky denied (no clinch).
func TestSticky_NoClinch_UnhealthyCapacity(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	p.slots = make([]*poolSlot, 12)
	for i := 0; i < 6; i++ {
		s := &poolSlot{index: i}
		if i < p.readyCapacityFloor() {
			s.state.Store(int32(slotReady))
		} else {
			s.state.Store(int32(slotDraining))
		}
		p.slots[i] = s
	}
	fresh := &poolSlot{index: 0}
	if p.stickyQuotaAvailable(fresh) {
		t.Fatal("unhealthy capacity: new sticky must be denied (no clinch)")
	}
}

// H4: healthy capacity under cap → sticky granted (not falsely denied).
func TestSticky_HealthyCapacity_Granted(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	p.slots = make([]*poolSlot, 12)
	for i := 0; i < 6; i++ {
		s := &poolSlot{index: i}
		s.state.Store(int32(slotReady))
		p.slots[i] = s
	}
	fresh := &poolSlot{index: 0}
	if !p.stickyQuotaAvailable(fresh) {
		t.Fatal("healthy capacity under cap: sticky must be granted")
	}
}

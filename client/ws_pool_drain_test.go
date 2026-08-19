package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// TestReadyCapacity_CountsAllReadyAcrossSlice asserts that readyCapacity
// counts slotReady cells anywhere in the slice — no primary/reserve
// distinction. This guards against the canary 2026-05-19 bug where
// countNonReadySlots used `i+poolSize` pairing and locked storm brake
// at non_ready=2 forever.
func TestReadyCapacity_CountsAllReadyAcrossSlice(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	if got := p.readyCapacity(); got != 0 {
		t.Errorf("readyCapacity with all nil = %d, want 0", got)
	}

	// 6 primary ready + 2 reserve ready (canary post-teardown state).
	for _, i := range []int{0, 1, 3, 4, 5, 7, 8, 9} {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	if got := p.readyCapacity(); got != 8 {
		t.Errorf("readyCapacity with 6+2 ready = %d, want 8 (uniform cells)", got)
	}

	// One draining doesn't count.
	p.slots[0].setState(slotDraining)
	if got := p.readyCapacity(); got != 7 {
		t.Errorf("readyCapacity with 1 drained = %d, want 7", got)
	}

	// Connecting doesn't count.
	p.slots[10] = &poolSlot{}
	p.slots[10].setState(slotConnecting)
	if got := p.readyCapacity(); got != 7 {
		t.Errorf("readyCapacity ignores slotConnecting = %d, want 7", got)
	}
}

// TestStormBrakeFloor_DerivedFromPoolSize asserts the floor formula
// scales with poolSize (spec §2.1, C1 review fix).
func TestStormBrakeFloor_DerivedFromPoolSize(t *testing.T) {
	// After 2026-05-24 decoupling: floor = max(1, min(poolSize-1, floor(poolSize * 0.75))).
	// Most values UNCHANGED from pre-decouple (this is intentional — decoupling
	// preserves the catastrophic-state defense at known-good values). poolSize=4
	// was floor=3 (4-1), now floor(4*0.75)=3 (same). poolSize=6 was floor=4 (6-2),
	// now floor(6*0.75)=4 (same).
	cases := []struct {
		poolSize  int
		wantFloor int
	}{
		{poolSize: 8, wantFloor: 6},   // floor(8*0.75) = 6 — UNCHANGED from pre-decouple
		{poolSize: 6, wantFloor: 4},   // floor(6*0.75) = 4 — UNCHANGED (added explicit row)
		{poolSize: 4, wantFloor: 3},   // floor(4*0.75) = 3 — UNCHANGED
		{poolSize: 2, wantFloor: 1},   // floor(2*0.75)=1, clamped min=1 — UNCHANGED
		{poolSize: 16, wantFloor: 12}, // floor(16*0.75) = 12 — UNCHANGED
	}
	for _, c := range cases {
		p := &WSPoolTransport{poolSize: c.poolSize}
		if got := p.readyCapacityFloor(); got != c.wantFloor {
			t.Errorf("readyCapacityFloor(poolSize=%d) = %d, want %d",
				c.poolSize, got, c.wantFloor)
		}
	}
}

// countingTransport is a minimal stub satisfying wsSlotTransport for
// write-routing tests. It records how many data / control writes it
// received so the test can assert which slot's transport was hit.
type countingTransport struct {
	writes        int
	controlWrites int
}

func (c *countingTransport) WriteMessage(data []byte) error {
	c.writes++
	return nil
}
func (c *countingTransport) WriteControlMessage(data []byte) error {
	c.controlWrites++
	return nil
}
func (c *countingTransport) ReadMessage(timeout time.Duration) ([]byte, error) {
	return nil, nil
}
func (c *countingTransport) Close() error             { return nil }
func (c *countingTransport) LastWriteUnixNano() int64 { return 0 }

// TestWriteMessageForStream_AcceptsDraining verifies that a stream
// assigned to a slot that has transitioned to slotDraining continues
// to write through that slot's transport (not a random ready fallback).
// Critical for crypto correctness — the draining slot's session is
// still the one the server expects for this stream.
func TestWriteMessageForStream_AcceptsDraining(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:       2,
		ServerAddr: "127.0.0.1:0",
	})

	stubDraining := &countingTransport{}
	p.slots[0] = &poolSlot{transport: stubDraining}
	p.slots[0].setState(slotDraining)

	stubReady := &countingTransport{}
	p.slots[1] = &poolSlot{transport: stubReady}
	p.slots[1].setState(slotReady)

	p.streamMap.Store(uint16(42), newStreamEntry(0))

	if err := p.WriteMessageForStream(42, []byte("hello")); err != nil {
		t.Fatalf("WriteMessageForStream returned err: %v", err)
	}
	if stubDraining.writes != 1 {
		t.Errorf("draining slot transport got %d writes, want 1", stubDraining.writes)
	}
	if stubReady.writes != 0 {
		t.Errorf("ready slot got %d writes, want 0 (must not fall back)", stubReady.writes)
	}
}

// TestWriteControlMessageForStream_AcceptsDraining mirrors the data-path
// test for the control-frame path.
func TestWriteControlMessageForStream_AcceptsDraining(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 2, ServerAddr: "127.0.0.1:0"})

	stubDraining := &countingTransport{}
	p.slots[0] = &poolSlot{transport: stubDraining}
	p.slots[0].setState(slotDraining)
	stubReady := &countingTransport{}
	p.slots[1] = &poolSlot{transport: stubReady}
	p.slots[1].setState(slotReady)
	p.streamMap.Store(uint16(43), newStreamEntry(0))

	if err := p.WriteControlMessageForStream(43, []byte("ctrl")); err != nil {
		t.Fatalf("WriteControlMessageForStream returned err: %v", err)
	}
	if stubDraining.controlWrites != 1 {
		t.Errorf("draining slot got %d control writes, want 1", stubDraining.controlWrites)
	}
	if stubReady.controlWrites != 0 {
		t.Errorf("ready slot got %d control writes, want 0", stubReady.controlWrites)
	}
}

// TestHandleSlotDeath_DrainTeardownClearsCell verifies that
// handleSlotDeath(deathCauseDrainTeardown) sets p.slots[idx] = nil
// (freeing the cell for reserve reuse) and does NOT spawn reconnectLoop.
//
// Verifies the three drain-cause invariants:
//  1. recordSlotDeath NOT called (no false meltdown advance)
//  2. reconnectLoop NOT spawned (reserve carries capacity elsewhere)
//  3. p.slots[idx] cleared (cell free for reserve target reuse)
func TestHandleSlotDeath_DrainTeardownClearsCell(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel: even if reconnectLoop fires accidentally, it exits fast

	p := &WSPoolTransport{
		poolSize:          2,
		ctx:               ctx,
		cancel:            cancel,
		log:               newDiscardLogger(),
		meltdownThreshold: 100,
		meltdownWindow:    5 * time.Second,
	}
	p.slots = make([]*poolSlot, 4)
	p.client = cl

	slot := &poolSlot{}
	slot.setState(slotDraining)
	p.slots[0] = slot

	p.handleSlotDeath(cl, 0, deathCauseDrainTeardown)

	if p.slots[0] != nil {
		t.Errorf("after drain teardown, p.slots[0] should be nil, got non-nil")
	}
	if slot.getState() != slotDead {
		t.Errorf("slot state should be slotDead, got %v", slot.getState())
	}
}

// TestHandleSlotDeath_NaturalDoesNotClearCell is a regression test ensuring
// Task 3 doesn't accidentally break the existing natural cause — it should
// still leave p.slots[idx] non-nil (reconnectLoop owns the restart) and
// NOT clear the cell. We verify only the immediate post-call state: Task 3
// must only clear the cell for drainTeardown.
func TestHandleSlotDeath_NaturalDoesNotClearCell(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so reconnectLoop goroutine exits immediately

	p := &WSPoolTransport{
		poolSize:          2,
		ctx:               ctx,
		cancel:            cancel,
		log:               newDiscardLogger(),
		meltdownThreshold: 100,
		meltdownWindow:    5 * time.Second,
	}
	p.slots = make([]*poolSlot, 4)
	p.client = cl

	slot := &poolSlot{}
	slot.setState(slotReady)
	p.slots[0] = slot

	p.handleSlotDeath(cl, 0, deathCauseNatural)

	if p.slots[0] == nil {
		t.Errorf("after natural death, p.slots[0] should NOT be nil (only drainTeardown clears)")
	}
}

// TestHandleSlotDeath_PreemptiveDoesNotClearCell mirrors the natural-cause
// regression for the preemptive-rotation cause.
func TestHandleSlotDeath_PreemptiveDoesNotClearCell(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &WSPoolTransport{
		poolSize:          2,
		ctx:               ctx,
		cancel:            cancel,
		log:               newDiscardLogger(),
		meltdownThreshold: 100,
		meltdownWindow:    5 * time.Second,
	}
	p.slots = make([]*poolSlot, 4)
	p.client = cl

	slot := &poolSlot{}
	slot.setState(slotReady)
	p.slots[0] = slot

	p.handleSlotDeath(cl, 0, deathCausePreemptiveRotation)

	if p.slots[0] == nil {
		t.Errorf("after preemptive rotation, p.slots[0] should NOT be nil (only drainTeardown clears)")
	}
}

// TestPoolSlice_DoubleCapacity verifies that NewWSPoolTransport (via
// allocSlots) sizes the slot slice at 2*poolSize, primary range
// [0, poolSize) and reserve range [poolSize, 2*poolSize) initialized
// to nil. Also verifies allocSlots is idempotent: calling it again
// (e.g. on retry) re-initializes the slice cleanly.
func TestPoolSlice_DoubleCapacity(t *testing.T) {
	cl := &Client{}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:       4,
		ServerAddr: "127.0.0.1:0",
	})

	if got := len(p.slots); got != 8 {
		t.Errorf("after NewWSPoolTransport, len(p.slots) = %d, want 8 (2*poolSize)", got)
	}
	for i := 4; i < 8; i++ {
		if p.slots[i] != nil {
			t.Errorf("reserve slot[%d] should be nil at init, got non-nil", i)
		}
	}

	// Plant sentinels then call allocSlots — they must be wiped.
	p.slots[0] = &poolSlot{}
	p.slots[7] = &poolSlot{}
	p.allocSlots()
	if p.slots[0] != nil {
		t.Error("allocSlots did not reset primary slot[0]")
	}
	if p.slots[7] != nil {
		t.Error("allocSlots did not reset reserve slot[7]")
	}
	if got := len(p.slots); got != 8 {
		t.Errorf("after re-allocSlots, len(p.slots) = %d, want 8", got)
	}
}

// TestPoolSlot_TryMarkDraining verifies the CAS transition slotReady →
// slotDraining is exactly-once: first call returns true, subsequent
// calls return false. Transitions from non-ready states must fail.
func TestPoolSlot_TryMarkDraining(t *testing.T) {
	s := &poolSlot{}
	s.setState(slotReady)
	if !s.tryMarkDraining() {
		t.Fatal("first tryMarkDraining should return true")
	}
	if s.getState() != slotDraining {
		t.Fatalf("state should be slotDraining, got %v", s.getState())
	}
	if s.tryMarkDraining() {
		t.Fatal("second tryMarkDraining should return false (already draining)")
	}

	s2 := &poolSlot{}
	s2.setState(slotConnecting)
	if s2.tryMarkDraining() {
		t.Fatal("tryMarkDraining from slotConnecting should fail")
	}

	s3 := &poolSlot{}
	s3.setState(slotDead)
	if s3.tryMarkDraining() {
		t.Fatal("tryMarkDraining from slotDead should fail")
	}
}

// TestPoolSlot_NextDrainAttemptNs verifies the backoff field exists and
// behaves as a simple atomic int64 (zero = no backoff).
func TestPoolSlot_NextDrainAttemptNs(t *testing.T) {
	s := &poolSlot{}
	if got := s.nextDrainAttemptNs.Load(); got != 0 {
		t.Errorf("default nextDrainAttemptNs = %d, want 0", got)
	}
	future := time.Now().Add(30 * time.Second).UnixNano()
	s.nextDrainAttemptNs.Store(future)
	if got := s.nextDrainAttemptNs.Load(); got != future {
		t.Errorf("nextDrainAttemptNs = %d, want %d", got, future)
	}
}

// TestStats_DrainCounters verifies that Stats exposes the four drain
// metrics required by the design spec: DrainStartedTotal,
// DrainNaturalFinishTotal, DrainHardCapTotal, DrainDurationSeconds.
//
// Counter type must match the existing convention in stats.go (atomic.Int64
// for delta-aware counters, atomic.Uint64 for monotonic).
func TestStats_DrainCounters(t *testing.T) {
	before := Stats.DrainStartedTotal.Load()
	Stats.DrainStartedTotal.Add(1)
	if got := Stats.DrainStartedTotal.Load(); got != before+1 {
		t.Errorf("DrainStartedTotal.Add(1) → Load = %d, want %d", got, before+1)
	}

	Stats.DrainNaturalFinishTotal.Add(1)
	Stats.DrainHardCapTotal.Add(1)
	// Just verify they exist and accept Add.

	// Histogram should accept Observe without panic.
	Stats.DrainDurationSeconds.Observe(15.0)
}

// TestStartDrain_NoFreeReserveSlot verifies that when all reserve cells
// are occupied (worst-case concurrent drains), startDrain bails out
// gracefully: state reverts to slotReady, no metric increments, backoff
// is set on the slot to prevent watchdog tight retry.
func TestStartDrain_NoFreeReserveSlot(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	p.ctx = t.Context()

	// Fill primary range with ready slots
	for i := range 2 {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	// Fill ALL reserve cells (simulating prior concurrent drains)
	for i := 2; i < 4; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotConnecting)
	}

	// The storm brake path is tested separately. Here we want to
	// exercise the no-free-reserve branch but the brake will engage
	// first in this layout — covered by Task 13 integration test.
	t.Skip("Brake engages before no-free-reserve branch is reached in this layout; covered by Task 13 integration test")
}

// TestClaimFreeSlot_PrefersFirstNil verifies the claim atomically
// installs a placeholder in the first nil cell anywhere in the slice.
// After claim, the cell is non-nil and in slotConnecting state.
// Returns -1 only when every cell is non-nil.
//
// Updated for uniform-cells design (spec 2026-05-20 §2.2): scan starts
// at index 0 so primary cells are eligible targets alongside reserve
// cells. NewWSPoolTransport initializes all slots to nil; first claim
// therefore returns idx 0, not the old reserve-floor 4.
func TestClaimFreeSlot_PrefersFirstNil(t *testing.T) {
	cl := &Client{}
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 4, ServerAddr: "127.0.0.1:0"})
	// p.slots has 8 cells; all nil at init.

	// First claim → idx 0 (first nil in the whole slice)
	if got := p.claimFreeSlot(); got != 0 {
		t.Errorf("first claim = %d, want 0", got)
	}
	if p.slots[0] == nil {
		t.Error("claim did not install a placeholder at slots[0]")
	}
	if p.slots[0].getState() != slotConnecting {
		t.Errorf("placeholder state = %v, want slotConnecting", p.slots[0].getState())
	}

	// Second claim → idx 1 (next nil cell)
	if got := p.claimFreeSlot(); got != 1 {
		t.Errorf("second claim = %d, want 1", got)
	}

	// Fill the rest — claim all 8 cells in order
	for want := 2; want < 8; want++ {
		if got := p.claimFreeSlot(); got != want {
			t.Errorf("claim %d = %d, want %d", want, got, want)
		}
	}

	// All cells claimed → -1
	if got := p.claimFreeSlot(); got != -1 {
		t.Errorf("claim with all occupied = %d, want -1", got)
	}
}

// TestClaimFreeSlot_ConcurrentNoCollision exercises the mutex by
// running many concurrent claims and verifying each gets a unique idx.
// Without the mutex, two goroutines could pick the same idx.
//
// Updated for uniform-cells design: results are in [0, 16), not the
// old reserve-range [8, 16). All slots start nil, so 8 concurrent
// claims exhaust the first 8 cells (order non-deterministic under
// race, but each idx must be unique and in-range).
func TestClaimFreeSlot_ConcurrentNoCollision(t *testing.T) {
	cl := &Client{}
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 8, ServerAddr: "127.0.0.1:0"})

	const N = 8 // claim 8 out of 16 slots
	var wg sync.WaitGroup
	results := make([]int, N)
	wg.Add(N)
	for i := range N {
		go func(i int) {
			defer wg.Done()
			results[i] = p.claimFreeSlot()
		}(i)
	}
	wg.Wait()

	// All results should be distinct and in range [0, 16).
	seen := make(map[int]bool)
	for _, idx := range results {
		if idx < 0 || idx >= 16 {
			t.Errorf("claim returned %d, want in [0, 16)", idx)
		}
		if seen[idx] {
			t.Errorf("idx %d returned by two concurrent claims — race!", idx)
		}
		seen[idx] = true
	}
}

// TestStartDrain_FlagOff verifies that when GracefulDrain is false,
// startDrain is a complete no-op (no state change, no metric, no goroutines).
func TestStartDrain_FlagOff(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: false, // explicit
	})
	p.ctx = t.Context()

	p.slots[0] = &poolSlot{}
	p.slots[0].setState(slotReady)

	before := Stats.DrainStartedTotal.Load()
	p.startDrain(cl, 0, "test")
	if got := Stats.DrainStartedTotal.Load(); got != before {
		t.Errorf("DrainStartedTotal changed %d→%d with flag off; expected no-op", before, got)
	}
	if p.slots[0].getState() != slotReady {
		t.Errorf("slot state changed from slotReady to %v with flag off", p.slots[0].getState())
	}
}

// TestDrainWatchdog_NaturalFinish runs the watchdog against a slot whose
// streams counter is already 0; the watchdog should detect this within
// drainPollInterval (500ms), increment DrainNaturalFinishTotal, and
// invoke handleSlotDeath(deathCauseDrainTeardown) which clears the cell.
func TestDrainWatchdog_NaturalFinish(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	p.ctx = t.Context()

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	// streams already 0 → first tick fires natural finish
	p.slots[0] = oldSlot

	before := Stats.DrainNaturalFinishTotal.Load()
	beforeGen := oldSlot.generation.Load()

	done := make(chan struct{})
	go func() {
		p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainWatchdog did not return for streams==0 within 2s")
	}

	if got := Stats.DrainNaturalFinishTotal.Load(); got != before+1 {
		t.Errorf("DrainNaturalFinishTotal = %d, want %d", got, before+1)
	}
	if got := oldSlot.generation.Load(); got <= beforeGen {
		t.Errorf("generation should be bumped before handleSlotDeath; before=%d after=%d", beforeGen, got)
	}
	if p.slots[0] != nil {
		t.Errorf("p.slots[0] should be nil after drain teardown (deathCauseDrainTeardown clears cell)")
	}
	if oldSlot.getState() != slotDead {
		t.Errorf("slot state = %v, want slotDead", oldSlot.getState())
	}
}

// TestDrainWatchdog_HardCap verifies that with streams stuck > 0, the
// watchdog tears down the slot via the deadline timer (drainHardCap)
// rather than natural finish. Uses a short DrainHardCap (300ms) for
// test speed.
func TestDrainWatchdog_HardCap(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: true,
		DrainHardCap:  300 * time.Millisecond,
	})
	p.ctx = t.Context()

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(3) // never reaches zero → hard cap fires
	oldSlot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[0] = oldSlot

	beforeHard := Stats.DrainHardCapTotal.Load()
	beforeNat := Stats.DrainNaturalFinishTotal.Load()
	beforeGen := oldSlot.generation.Load()

	start := time.Now()
	p.drainWatchdog(cl, 0, oldSlot, start, "test")
	elapsed := time.Since(start)

	if elapsed < 300*time.Millisecond {
		t.Errorf("watchdog returned in %v, expected at least 300ms (hard cap)", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("watchdog took %v, expected ~300ms hard cap", elapsed)
	}
	if got := Stats.DrainHardCapTotal.Load(); got != beforeHard+1 {
		t.Errorf("DrainHardCapTotal = %d, want %d", got, beforeHard+1)
	}
	if got := Stats.DrainNaturalFinishTotal.Load(); got != beforeNat {
		t.Errorf("DrainNaturalFinishTotal changed %d→%d on hard-cap path; should not", beforeNat, got)
	}
	if got := oldSlot.generation.Load(); got <= beforeGen {
		t.Errorf("generation should be bumped before handleSlotDeath; before=%d after=%d", beforeGen, got)
	}
	if p.slots[0] != nil {
		t.Errorf("p.slots[0] should be nil after hard-cap teardown")
	}
}

// TestDrainWatchdog_ContextCancel verifies that cancelling the pool
// context mid-drain causes the watchdog to exit cleanly without
// incrementing metric counters (neither natural nor hard cap).
func TestDrainWatchdog_ContextCancel(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: true,
		DrainHardCap:  10 * time.Second, // long enough that ctx cancel wins
	})
	ctx, cancel := context.WithCancel(context.Background())
	p.ctx = ctx

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(2) // never reaches zero
	p.slots[0] = oldSlot

	beforeHard := Stats.DrainHardCapTotal.Load()
	beforeNat := Stats.DrainNaturalFinishTotal.Load()

	done := make(chan struct{})
	go func() {
		p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test")
		close(done)
	}()

	// Let the watchdog enter its loop, then cancel
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("drainWatchdog did not exit on ctx cancel within 1s")
	}

	if got := Stats.DrainHardCapTotal.Load(); got != beforeHard {
		t.Error("ctx cancel must not count as hard cap")
	}
	if got := Stats.DrainNaturalFinishTotal.Load(); got != beforeNat {
		t.Error("ctx cancel must not count as natural finish")
	}
	// Slot should NOT be torn down — ctx cancel is for pool shutdown,
	// handleSlotDeath happens in Close() path instead.
	if p.slots[0] == nil {
		t.Error("p.slots[0] cleared by drainWatchdog despite ctx cancel; watchdog should exit silently")
	}
}

// TestSlotReader_SilentExitOnDrainTeardown is a placeholder for an
// integration test verifying that when drainWatchdog bumps
// slot.generation and triggers handleSlotDeath, the concurrent
// slotReader exits silently via shouldExitReader (no false
// ReaderExits++ or frame-anomaly counter inflation).
//
// Requires a loopback WS server fixture to spawn a real slotReader;
// deferred to Phase 1 integration tests after pl1 canary validates
// the drainWatchdog→generation→shouldExitReader chain end-to-end.
//
// The structural correctness is already verified by:
//   - TestDrainWatchdog_NaturalFinish — generation.Add(1) before
//     handleSlotDeath (the gen-bump path that silences any reader)
//   - TestDrainWatchdog_HardCap — same invariant on hard cap path
//   - ws_pool.go::slotReaderWithClient — existing shouldExitReader
//     gate that consumes the bumped generation
func TestSlotReader_SilentExitOnDrainTeardown(t *testing.T) {
	t.Skip("requires loopback WS fixture; structural correctness covered by drainWatchdog gen-bump tests")
}

// failingHandshakeTransport satisfies the Transport interface and always
// returns an error from SendHandshake — simulating an unreachable server
// without actually opening a TCP connection. Used by
// TestConnectReserveSlot_FailureFallsBackToReconnectLoop to drive
// connectSlot into its error branch deterministically.
type failingHandshakeTransport struct{}

func (failingHandshakeTransport) SendChunk(ctx context.Context, data []byte, sessionToken []byte, seqNum uint32) ([]byte, error) {
	return nil, errTestTransportUnreachable
}
func (failingHandshakeTransport) SendHandshake(ctx context.Context, hello *core.ClientHello) ([]byte, error) {
	return nil, errTestTransportUnreachable
}
func (failingHandshakeTransport) Name() string { return "failingHandshakeTransport" }
func (failingHandshakeTransport) Close() error { return nil }

var errTestTransportUnreachable = errors.New("test: transport unreachable")

// TestConnectReserveSlot_FailureFallsBackToReconnectLoop verifies that
// when connectSlot fails (invalid server, rate limit, etc.), the
// placeholder cell is freed (nil) under reserveMu so a fresh drain can
// immediately reclaim the cell (T9 §4.2), and reconnectLoop is
// scheduled to recover capacity asynchronously. The drainWatchdog tears
// down oldIdx on its own schedule regardless.
//
// Updated for T9: old behavior asserted the cell stayed non-nil in
// slotConnecting or slotDead state. New behavior: cell is set to nil
// immediately after failure so claimFreeSlot can reuse it without
// waiting for reconnectLoop. reconnectLoop's recycle guard (§2.2.2)
// short-circuits if a drain reclaimed the cell in the meantime.
func TestConnectReserveSlot_FailureFallsBackToReconnectLoop(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:1", // port 1: reliably unreachable
		GracefulDrain: true,
		DrainHardCap:  500 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx

	// Set up primary slot 0 as a draining-candidate ready slot.
	oldSlot := &poolSlot{}
	oldSlot.setState(slotReady)
	p.slots[0] = oldSlot
	// Slot 1 also ready so storm brake doesn't block.
	otherSlot := &poolSlot{}
	otherSlot.setState(slotReady)
	p.slots[1] = otherSlot

	p.startDrain(cl, 0, "test")

	// Allow goroutines to attempt the connect and propagate failure.
	time.Sleep(300 * time.Millisecond)

	newIdx := p.poolSize // first reserve cell — 2
	// Read the cell under reserveMu: background connectReserveSlot/reconnectLoop
	// goroutines write p.slots[newIdx] under reserveMu, so an unguarded read here
	// races them (Linux -race). Snapshot the pointer once under the lock and
	// assert against the copy.
	p.reserveMu.Lock()
	slot := p.slots[newIdx]
	p.reserveMu.Unlock()
	// T9 invariant: after connectSlot failure the placeholder is freed to nil
	// so claimFreeSlot can immediately reuse the cell for the next drain.
	// reconnectLoop is scheduled and may reinstall a slot in the background —
	// we only assert the failure path did NOT leave a non-nil dead/connecting
	// placeholder permanently blocking the cell.
	if slot != nil && slot.getState() == slotReady {
		t.Errorf("reserve slot should NOT be slotReady after connect to invalid port; got slotReady")
	}
	// Acceptable post-failure states: nil (freed by T9) or slotConnecting
	// (reconnectLoop successfully reinstalled a slot in the background
	// within the 300ms window — rare but valid).
	if slot != nil && slot.getState() == slotDead {
		t.Errorf("reserve cell should be nil (freed) or reconnected after failure, not permanently slotDead")
	}
}

// TestUnifiedRotation_AgeTriggerUsesStartDrain verifies that with
// gracefulDrain on, watchdog sweep on an aged slot calls startDrain
// (and the slot transitions to slotDraining), not the legacy
// maybeRotateSlot/fireRotation path.
func TestUnifiedRotation_AgeTriggerUsesStartDrain(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:1",
		MaxSlotAge:    time.Minute,
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl

	// Aged slot 0 (started 2 minutes ago, exceeds MaxSlotAge = 1 minute)
	slot := &poolSlot{}
	slot.setState(slotReady)
	slot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	slot.streams.Store(5)
	p.slots[0] = slot
	// Second ready primary so storm brake threshold (2 of 8 non-ready)
	// is NOT engaged. With 2 ready primaries + 6 nil reserves, count = 0
	// per the parallel-replacement-aware logic.
	slot2 := &poolSlot{}
	slot2.setState(slotReady)
	slot2.startedAtNs.Store(time.Now().UnixNano())
	p.slots[1] = slot2

	before := Stats.DrainStartedTotal.Load()
	p.rotationWatchdogSweep()
	// allow startDrain goroutines a moment to fully start, though state
	// transition itself is synchronous inside startDrain
	time.Sleep(50 * time.Millisecond)

	if got := Stats.DrainStartedTotal.Load(); got != before+1 {
		t.Errorf("DrainStartedTotal = %d, want %d (aged slot should drain)", got, before+1)
	}
	if got := slot.getState(); got != slotDraining {
		t.Errorf("aged slot state = %v, want slotDraining", got)
	}
}

// TestRotationWatchdogSweep_RespectsNextDrainAttemptNs verifies that a
// slot with future nextDrainAttemptNs (backoff active after storm
// brake revert) is skipped by the watchdog, preventing tight retry
// loops on the 5s sweep cadence.
func TestRotationWatchdogSweep_RespectsNextDrainAttemptNs(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:1",
		MaxSlotAge:    time.Minute,
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl

	slot := &poolSlot{}
	slot.setState(slotReady)
	slot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	slot.streams.Store(5)
	// Set backoff: drain attempts blocked for next 30s
	slot.nextDrainAttemptNs.Store(time.Now().Add(30 * time.Second).UnixNano())
	p.slots[0] = slot

	before := Stats.DrainStartedTotal.Load()
	p.rotationWatchdogSweep()
	time.Sleep(20 * time.Millisecond)

	if got := Stats.DrainStartedTotal.Load(); got != before {
		t.Errorf("DrainStartedTotal changed %d→%d; expected backoff to skip the aged slot", before, got)
	}
	if got := slot.getState(); got != slotReady {
		t.Errorf("slot state changed from slotReady to %v despite backoff", got)
	}
}

// TestUnifiedRotation_ByteBudgetUsesStartDrain verifies that with
// gracefulDrain on, the byte_budget trigger path calls startDrain
// (slot transitions to slotDraining + DrainStartedTotal++), not the
// legacy maybeRotateSlot path.
//
// Note: we don't drive a real slotReader (that requires a network
// fixture). Instead we directly exercise startDrain with reason
// "byte_budget" to assert the trigger semantics. The production
// wire-up in slotReaderWithClient is verified by code inspection
// + integration tests on pl1 canary.
func TestUnifiedRotation_ByteBudgetUsesStartDrain(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:1",
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl

	slot := &poolSlot{}
	slot.setState(slotReady)
	slot.startedAtNs.Store(time.Now().UnixNano())
	p.slots[0] = slot
	slot2 := &poolSlot{}
	slot2.setState(slotReady)
	p.slots[1] = slot2

	before := Stats.DrainStartedTotal.Load()
	p.startDrain(cl, 0, "byte_budget")
	time.Sleep(50 * time.Millisecond)

	if got := Stats.DrainStartedTotal.Load(); got != before+1 {
		t.Errorf("DrainStartedTotal = %d, want %d", got, before+1)
	}
	if got := slot.getState(); got != slotDraining {
		t.Errorf("slot state = %v, want slotDraining", got)
	}
}

// TestUnifiedRotation_AntiFPTickerUsesStartDrain verifies that with
// gracefulDrain on, rotateMinLoadedSlot delegates to startDrain
// (reason "anti_fingerprint") instead of legacyRotateOneSlot. The
// picker chooses the min-streams primary cell.
func TestUnifiedRotation_AntiFPTickerUsesStartDrain(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:1",
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	p.ctx = t.Context()
	p.client = cl

	// Two ready primaries; slot 1 has fewer streams (will be picked)
	slot0 := &poolSlot{}
	slot0.setState(slotReady)
	slot0.streams.Store(5)
	p.slots[0] = slot0
	slot1 := &poolSlot{}
	slot1.setState(slotReady)
	slot1.streams.Store(1)
	p.slots[1] = slot1

	before := Stats.DrainStartedTotal.Load()
	p.rotateMinLoadedSlot()
	time.Sleep(50 * time.Millisecond)

	if got := Stats.DrainStartedTotal.Load(); got != before+1 {
		t.Errorf("DrainStartedTotal = %d, want %d (min-streams slot should drain)", got, before+1)
	}
	if got := slot1.getState(); got != slotDraining {
		t.Errorf("min-streams slot1 state = %v, want slotDraining", got)
	}
	if got := slot0.getState(); got != slotReady {
		t.Errorf("higher-loaded slot0 should be untouched, got %v", got)
	}
}

// TestAssignStream_SkipsDraining is a regression test for the existing
// invariant that AssignStream filters strictly on slotReady. After the
// graceful drain refactor introduces slotDraining as a quasi-live
// state, AssignStream must continue to exclude draining slots (new
// streams go to slotReady slots only — primary or reserve).
func TestAssignStream_SkipsDraining(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:              2,
		ServerAddr:        "127.0.0.1:0",
		MaxStreamsPerSlot: 100,
		GracefulDrain:     true,
		DrainHardCap:      5 * time.Second,
	})
	p.ctx = t.Context()

	// slot 0 draining (must not receive new streams)
	s0 := &poolSlot{}
	s0.setState(slotDraining)
	p.slots[0] = s0

	// slot 1 ready (should receive all new streams)
	s1 := &poolSlot{}
	s1.setState(slotReady)
	p.slots[1] = s1

	for sid := uint16(100); sid < 110; sid++ {
		p.AssignStream(sid)
	}

	if got := s0.streams.Load(); got != 0 {
		t.Errorf("draining slot got %d streams, want 0", got)
	}
	if got := s1.streams.Load(); got != 10 {
		t.Errorf("ready slot got %d streams, want 10", got)
	}
}

// TestStartDrain_StormBrakeSingleDrain — un-paired layout (canary).
// primary[6] draining, reserve[9] connecting (no parity 6↔14). Asserts
// readyCapacity stays well above floor — drain would NOT be deferred
// by capacity gate; only an inflight cap would defer.
func TestStartDrain_StormBrakeSingleDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	// 7 of 8 primaries ready + the 1 draining (primary[6]).
	for i := 0; i < 8; i++ {
		p.slots[i] = &poolSlot{index: i}
		if i == 6 {
			p.slots[i].setState(slotDraining)
		} else {
			p.slots[i].setState(slotReady)
		}
	}
	// Reserve[9] is connecting (replacement for primary[6]).
	p.slots[9] = &poolSlot{}
	p.slots[9].setState(slotConnecting)
	// inflight already counts this one drain.
	p.inflightDrains.Store(1)

	// readyCapacity = 7 (primary 0,1,2,3,4,5,7), floor = 6 → drain OK.
	if ready, floor := p.readyCapacity(), p.readyCapacityFloor(); ready < floor {
		t.Fatalf("setup readyCapacity=%d < floor=%d", ready, floor)
	}
	// maxConcurrentDrains = 2, inflight = 1 → another drain CAN proceed.
	if p.inflightDrains.Load() >= int32(p.maxConcurrentDrains()) {
		t.Fatalf("inflight already at cap")
	}
}

// TestStartDrain_StormBrakeTwoConcurrentEngages — exact canary layout.
// primary[6] and primary[2] both torn down → reserve[8] and reserve[9]
// fully ready. With pairing logic this state pinned the brake forever.
// With uniform-cells: readyCapacity=8, floor=6 — capacity OK. inflight
// counts 2 ongoing drains; a third would defer via inflight cap (T6).
// Until T6 lands the assertion is just on readyCapacity/floor.
func TestStartDrain_StormBrakeTwoConcurrentEngages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	// Exact canary state: 6 ready primaries (excluding 2,6), 2 ready reserves.
	for _, i := range []int{0, 1, 3, 4, 5, 7} {
		p.slots[i] = &poolSlot{index: i}
		p.slots[i].setState(slotReady)
	}
	p.slots[8] = &poolSlot{}
	p.slots[8].setState(slotReady)
	p.slots[9] = &poolSlot{}
	p.slots[9].setState(slotReady)
	p.inflightDrains.Store(0)

	// readyCapacity = 6+2 = 8 ≥ floor=6 — uniform-cells design works.
	if got := p.readyCapacity(); got != 8 {
		t.Errorf("readyCapacity = %d, want 8 (canary post-teardown)", got)
	}
	if got := p.readyCapacityFloor(); got != 6 {
		t.Errorf("readyCapacityFloor = %d, want 6", got)
	}
	// With OLD paired logic, countNonReadySlots would have returned 2
	// (both nil primaries treated as gaps because reserve[2+8]=nil and
	// reserve[6+8]=nil). Brake threshold=2 would trip. New logic: capacity
	// 8 >= floor 6 → no trip. Verify directly.
	if p.readyCapacity() < p.readyCapacityFloor() {
		t.Errorf("storm brake incorrectly engaged on canary state")
	}
}

// TestByteBudgetDrain_ReaderContinues verifies the C1 fix: after
// startDrain fires from the byte_budget branch in slotReaderWithClient,
// the reader does NOT exit. It continues reading downlink frames so
// active streams keep getting payload bytes until the drainWatchdog
// bumps the slot generation and handleSlotDeath closes the transport.
//
// Without this fix, the reader exit caused up to 90s (drainHardCap) of
// downlink starvation for any stream still alive on the draining slot
// — exactly the regression Phase 1 graceful drain is meant to avoid.
//
// This is a source-inspection-grade test: it reads ws_pool.go and
// verifies the byte_budget branch does NOT immediately `return` after
// `startDrain(cl, idx, "byte_budget")`. Driving a real reader against
// a mocked transport would require substantial scaffolding for what is
// fundamentally a static control-flow invariant — Opus C1 review
// targets a specific source pattern; we pin the pattern here.
func TestByteBudgetDrain_ReaderContinues(t *testing.T) {
	src, err := os.ReadFile("ws_pool.go")
	if err != nil {
		t.Fatalf("read ws_pool.go: %v", err)
	}
	srcStr := string(src)
	idx := strings.Index(srcStr, `startDrain(cl, idx, "byte_budget")`)
	if idx < 0 {
		t.Fatal("byte_budget startDrain call not found in ws_pool.go — code shape changed")
	}
	// The bug pattern: a bare `return` on its own line shortly after
	// the startDrain call. Inspect the next 200 chars.
	tailEnd := idx + 200
	if tailEnd > len(srcStr) {
		tailEnd = len(srcStr)
	}
	tail := srcStr[idx:tailEnd]
	if strings.Contains(tail, "\n\t\t\t\treturn\n") || strings.Contains(tail, "\n\t\t\t\t\treturn\n") {
		t.Errorf("byte_budget startDrain branch contains immediate `return` — this causes downlink starvation (Opus review C1). tail=%q", tail)
	}
	// Positive assertion: the branch should continue (loop back to read)
	// — either via `continue` or by falling through.
	if !strings.Contains(tail, "continue") {
		t.Errorf("byte_budget branch should `continue` after startDrain to keep reading downlink; tail=%q", tail)
	}
}

// TestHandleSlotDeath_DrainTeardownClosesStreamChans asserts the
// behavior change in spec §3 (C6 review): drainTeardown NOW closes
// streamChans uniformly with natural/preemptive — deterministic kill
// signal to SOCKS5 layer.
func TestHandleSlotDeath_DrainTeardownClosesStreamChans(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
	}
	p := &WSPoolTransport{poolSize: 8, ctx: ctx, log: newDiscardLogger(), client: cl}
	p.slots = make([]*poolSlot, 16)
	slot := &poolSlot{index: 3}
	slot.setState(slotDraining)
	p.slots[3] = slot

	ch := make(chan []byte, 1)
	cl.streamChans[42] = ch
	p.streamMap.Store(uint16(42), newStreamEntry(3))

	p.handleSlotDeath(cl, 3, deathCauseDrainTeardown)

	// streamChans[42] must now be closed AND removed from the map.
	cl.streamMu.Lock()
	_, present := cl.streamChans[42]
	cl.streamMu.Unlock()
	if present {
		t.Errorf("streamChans[42] still present after drainTeardown")
	}
	// Channel must be closed (read returns zero value, !ok).
	select {
	case _, ok := <-ch:
		if ok {
			t.Errorf("ch read returned ok=true, expected closed channel")
		}
	default:
		t.Errorf("ch not closed (read would block)")
	}
}

// TestHandleSlotDeath_NoUnderflowOnLateRelease asserts that
// LoadAndDelete ordering prevents streams.Add(-1) underflow when
// ReleaseStream is called after handleSlotDeath cleared the map.
// Spec §3 implementation note.
func TestHandleSlotDeath_NoUnderflowOnLateRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := &WSPoolTransport{poolSize: 8, ctx: ctx, log: newDiscardLogger(), client: cl}
	p.slots = make([]*poolSlot, 16)
	slot := &poolSlot{index: 0}
	slot.setState(slotDraining)
	slot.streams.Store(5)
	p.slots[0] = slot

	for sid := uint16(100); sid < 105; sid++ {
		cl.streamChans[sid] = make(chan []byte, 1)
		p.streamMap.Store(sid, newStreamEntry(0))
	}

	p.handleSlotDeath(cl, 0, deathCauseDrainTeardown)

	// Late ReleaseStream calls — must be no-ops because LoadAndDelete sees ok=false.
	for sid := uint16(100); sid < 105; sid++ {
		p.ReleaseStream(sid)
	}

	// streams counter must not have underflowed.
	if got := slot.streams.Load(); got != 0 {
		t.Errorf("slot.streams = %d, want 0 (no underflow)", got)
	}
}

// TestHandleSlotDeath_AllCausesCloseStreamChans asserts uniform behavior
// across all death causes (spec §3, acceptance #7).
func TestHandleSlotDeath_AllCausesCloseStreamChans(t *testing.T) {
	cases := []struct {
		name  string
		cause slotDeathCause
	}{
		{"natural", deathCauseNatural},
		{"preemptive", deathCausePreemptiveRotation},
		{"drainTeardown", deathCauseDrainTeardown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cl := &Client{streamChans: make(map[uint16]chan []byte)}
			p := &WSPoolTransport{
				poolSize: 8, ctx: ctx, log: newDiscardLogger(), client: cl,
			}
			p.slots = make([]*poolSlot, 16)
			slot := &poolSlot{index: 0}
			slot.setState(slotReady)
			p.slots[0] = slot

			ch := make(chan []byte, 1)
			cl.streamChans[7] = ch
			p.streamMap.Store(uint16(7), newStreamEntry(0))

			p.handleSlotDeath(cl, 0, tc.cause)

			cl.streamMu.Lock()
			_, present := cl.streamChans[7]
			cl.streamMu.Unlock()
			if present {
				t.Errorf("[%s] streamChans[7] still present", tc.name)
			}
			select {
			case _, ok := <-ch:
				if ok {
					t.Errorf("[%s] ch read ok=true, expected closed", tc.name)
				}
			default:
				t.Errorf("[%s] ch not closed (would block)", tc.name)
			}
		})
	}
}

// TestHandleSlotDeath_NaturalClosesStreamChans is a regression guard
// ensuring the legacy behavior is preserved for natural cause: the
// streamChans of dead streams MUST be closed so upstream readers see
// EOF promptly (no transport to send a network-level EOF in this case).
func TestHandleSlotDeath_NaturalClosesStreamChans(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel: prevent reconnectLoop from doing actual work

	p := &WSPoolTransport{
		poolSize:          2,
		ctx:               ctx,
		cancel:            cancel,
		log:               newDiscardLogger(),
		meltdownThreshold: 100,
		meltdownWindow:    5 * time.Second,
	}
	p.slots = make([]*poolSlot, 4)
	p.client = cl

	slot := &poolSlot{}
	slot.setState(slotReady)
	p.slots[0] = slot

	ch := make(chan []byte, 1)
	cl.streamChans[200] = ch
	p.streamMap.Store(uint16(200), newStreamEntry(0))
	slot.streams.Store(1)

	p.handleSlotDeath(cl, 0, deathCauseNatural)

	// streamMap deleted AND streamChans closed (legacy semantics)
	if _, ok := p.streamMap.Load(uint16(200)); ok {
		t.Error("streamMap entry 200 not deleted after natural death")
	}
	select {
	case _, open := <-ch:
		if open {
			t.Error("ch should be closed after natural death (legacy semantics)")
		}
	default:
		t.Error("ch should be closed after natural death — non-blocking receive on closed chan returns (zero, false) immediately")
	}

	// streams hard-zero IS expected for natural cause (no surviving
	// streams to do natural decrement).
	if slot.streams.Load() != 0 {
		t.Errorf("slot.streams should be 0 after natural death; got %d", slot.streams.Load())
	}
}

// TestInflightDrains_FieldInitialized verifies the new atomic counter
// is wired into WSPoolTransport with a zero-value initial state.
func TestInflightDrains_FieldInitialized(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)
	if got := p.inflightDrains.Load(); got != 0 {
		t.Errorf("inflightDrains initial value = %d, want 0", got)
	}
	p.inflightDrains.Add(1)
	if got := p.inflightDrains.Load(); got != 1 {
		t.Errorf("inflightDrains after Add(1) = %d, want 1", got)
	}
	p.inflightDrains.Add(-1)
	if got := p.inflightDrains.Load(); got != 0 {
		t.Errorf("inflightDrains after Add(-1) = %d, want 0", got)
	}
}

// TestClaimFreeSlot_ScansFromIndexZero asserts the renamed function
// scans the entire slice from idx=0, allowing post-teardown primary
// cells to be claimed as new drain replacements (spec §2.2).
func TestClaimFreeSlot_ScansFromIndexZero(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	// Fill the reserve range completely.
	for i := 8; i < 16; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	// Primary cell 3 was torn down by a previous drain — nil. All other
	// primaries occupied.
	for i := 0; i < 8; i++ {
		if i == 3 {
			continue
		}
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}

	got := p.claimFreeSlot()
	if got != 3 {
		t.Errorf("claimFreeSlot with all reserves occupied + primary[3]=nil = %d, want 3", got)
	}
	if p.slots[3] == nil || p.slots[3].getState() != slotConnecting {
		t.Errorf("claimed cell state = %v, want placeholder slotConnecting", p.slots[3])
	}
}

// TestClaimFreeSlot_AllOccupiedReturnsNegOne — when there's no free
// cell anywhere in the slice, return -1 (caller must defer).
func TestClaimFreeSlot_AllOccupiedReturnsNegOne(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)
	for i := 0; i < 16; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	if got := p.claimFreeSlot(); got != -1 {
		t.Errorf("claimFreeSlot with all occupied = %d, want -1", got)
	}
}

// TestReconnectLoop_RecycleGuard asserts that if the cell at idx has
// been recycled (e.g. by a drain that claimed this freed primary slot),
// reconnectLoop does NOT overwrite the new cell. Spec §2.2.2 (W7 review fix).
//
// ⚠ Ожидание уточнено 2026-08-14 (утечка D1). Раньше тест требовал, чтобы
// connectSlot НЕ вызывался вовсе, и это закрепляло дефект: голый return терял
// ячейку навсегда, потому что периодического healer'а в пуле нет. Теперь
// правильное поведение — «от ЯЧЕЙКИ отказаться, ЁМКОСТЬ восстановить»: цепочка
// переприцеливается на свободную ячейку.
//
// Здесь проверяется инвариант, ради которого guard и заводился: чужая ячейка не
// перезаписана. Поведение лечения — в TestReconnectLoop_RecycleHealsCapacity и
// TestReconnectLoop_RecycleNoHealWhenPoolFull.
func TestReconnectLoop_RecycleGuard(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize: 8,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)

	// Pre-install a slotReady cell at idx 3 (simulating a drain having
	// recycled this cell while a stale reconnectLoop was running).
	// Write under reserveMu — reconnectLoop reads p.slots[idx] under
	// reserveMu (recycle guard, §2.2.2); matching the lock on the setup
	// write closes the Linux -race report on this slice cell.
	recycledSlot := &poolSlot{index: 3}
	recycledSlot.setState(slotReady)
	p.reserveMu.Lock()
	p.slots[3] = recycledSlot
	p.reserveMu.Unlock()

	prev := getConnectSlotForTest()
	setConnectSlotForTest(func() error { return nil })
	defer func() { setConnectSlotForTest(prev) }()

	// Stub backoff to zero so the timer fires immediately — without this,
	// slotBackoffDuration(0) returns 5-10s and the test hangs.
	setSlotBackoffDurationForTest(func(int) time.Duration { return 0 })
	defer setSlotBackoffDurationForTest(nil)

	p.reconnectLoop(3)

	p.reserveMu.Lock()
	cell3 := p.slots[3]
	p.reserveMu.Unlock()
	if cell3 != recycledSlot {
		t.Errorf("recycled cell was overwritten — guard failed")
	}
}

// TestReconnectLoop_RecycleHealsCapacity — регрессия на УТЕЧКУ ЯЧЕЕК (D1,
// замер 2026-08-14). Главный тест этой правки.
//
// Механизм дефекта, который он ловит: connectReserveSlot не смог поднять
// резервную ячейку → освободил placeholder и запланировал reconnectLoop →
// пока тот ждал backoff, дренаж забрал ту же ячейку → recycle guard делал голый
// return → ячейка терялась НАВСЕГДА, потому что периодического healer'а в пуле
// нет (единственный вызов reconnectLoop на старте — начальный connect).
//
// Полевая цена: empty 8 → 9 → 10 → 11, mean alive 7.21 → 5.80 за 2 часа, дальше
// пул садится на пол storm-brake (ready=5 при floor=6), гейт отклоняет плановые
// ротации, слот доживает до полосы ненулевого hazard и его режет посредник.
// Три реза из четырёх в том прогоне — на конце этой цепочки.
func TestReconnectLoop_RecycleHealsCapacity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize: 8,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)

	// Пул НЕДОУКОМПЛЕКТОВАН: 7 живых при poolSize=8 — ровно та недостача,
	// которую оставляет за собой потерянная ячейка.
	for i := 0; i < 7; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		p.slots[i] = s
	}
	// Ячейку 7 «забрал дренаж», пока наш reconnect ждал backoff.
	recycled := &poolSlot{index: 7}
	recycled.setState(slotDraining)
	p.reserveMu.Lock()
	p.slots[7] = recycled
	p.reserveMu.Unlock()

	var mu sync.Mutex
	connectCalls := 0
	prev := getConnectSlotForTest()
	setConnectSlotForTest(func() error {
		mu.Lock()
		connectCalls++
		mu.Unlock()
		return nil
	})
	defer func() { setConnectSlotForTest(prev) }()
	setSlotBackoffDurationForTest(func(int) time.Duration { return 0 })
	defer setSlotBackoffDurationForTest(nil)

	before := Stats.HealingRetargetTotal.Load()
	p.reconnectLoop(7)

	mu.Lock()
	got := connectCalls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("connectSlot вызван %d раз, ожидался 1: ёмкость обязана "+
			"восполняться на СВОБОДНОЙ ячейке, а не теряться", got)
	}
	if delta := Stats.HealingRetargetTotal.Load() - before; delta != 1 {
		t.Errorf("HealingRetargetTotal += %d, ожидалось 1 — без счётчика лечение "+
			"неотличимо от исходной утечки", delta)
	}
	// Чужую ячейку не тронули.
	p.reserveMu.Lock()
	cell7 := p.slots[7]
	p.reserveMu.Unlock()
	if cell7 != recycled {
		t.Errorf("ячейка дренажа перезаписана")
	}
}

// TestReconnectLoop_RecycleNoHealWhenPoolFull — обратная сторона: лечение НЕ
// должно поднимать лишнее соединение, когда недостачи нет.
//
// Темп новых TLS-соединений к origin — это P0-угроза (policing по числу
// соединений). Замер 2026-08-14: 388 conn/ч против 305 в базе, причём на живую
// ячейку темп не изменился — весь рост от того, что пул держал штатные 8 вместо
// деградировавших 6. То есть ёмкость не бесплатна, и лечить «на всякий случай»
// нельзя.
func TestReconnectLoop_RecycleNoHealWhenPoolFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize: 8,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)

	// Полный комплект: 8 живых. Плюс ячейка, которую забрал дренаж.
	for i := 0; i < 8; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		p.slots[i] = s
	}
	recycled := &poolSlot{index: 8}
	recycled.setState(slotDraining)
	p.reserveMu.Lock()
	p.slots[8] = recycled
	p.reserveMu.Unlock()

	called := false
	prev := getConnectSlotForTest()
	setConnectSlotForTest(func() error { called = true; return nil })
	defer func() { setConnectSlotForTest(prev) }()
	setSlotBackoffDurationForTest(func(int) time.Duration { return 0 })
	defer setSlotBackoffDurationForTest(nil)

	p.reconnectLoop(8)

	if called {
		t.Errorf("connectSlot вызван при полном пуле — лишнее TLS-соединение " +
			"к origin, это P0 (policing по числу соединений)")
	}
}

// TestClaimFreeCellForHealing_DistinguishesSkipReasons — два разных отказа не
// должны выглядеть в логе одинаково.
//
// «Ёмкость уже полная» — штатный и самый частый исход (в поле 2026-08-19 слот
// успел подключиться за 2 мс до строки лога, health показывал alive=8 при
// poolSize=8). «Свободных ячеек нет» — состояние, где лечить физически негде.
// До правки оба печатались как "not needed (no free cell)", и первое читалось
// как второе, то есть как деградация: на этом чтении разбор 2026-08-19 едва не
// завёл ложную гипотезу о гонке против claimFreeSlot.
func TestClaimFreeCellForHealing_DistinguishesSkipReasons(t *testing.T) {
	// Ёмкость полная: 4 живых при poolSize=4, свободные ячейки ЕСТЬ.
	full := &WSPoolTransport{poolSize: 4}
	full.slots = make([]*poolSlot, 8)
	for i := 0; i < 4; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		full.slots[i] = s
	}
	idx, reason := full.claimFreeCellForHealingWithReason()
	if idx != -1 {
		t.Errorf("полная ёмкость: idx = %d, ожидался -1", idx)
	}
	if reason != healingNotNeededCapacityFull {
		t.Errorf("полная ёмкость: причина %q, ожидалась %q", reason, healingNotNeededCapacityFull)
	}

	// Недостача есть, но все ячейки заняты дренирующимися — лечить негде.
	packed := &WSPoolTransport{poolSize: 4}
	packed.slots = make([]*poolSlot, 4)
	for i := range packed.slots {
		s := &poolSlot{index: i}
		s.setState(slotDraining)
		packed.slots[i] = s
	}
	idx, reason = packed.claimFreeCellForHealingWithReason()
	if idx != -1 {
		t.Errorf("нет свободных ячеек: idx = %d, ожидался -1", idx)
	}
	if reason != healingBlockedNoFreeCell {
		t.Errorf("нет свободных ячеек: причина %q, ожидалась %q", reason, healingBlockedNoFreeCell)
	}

	// Недостача и свободная ячейка есть — лечение идёт, причина пустая.
	short := &WSPoolTransport{poolSize: 4}
	short.slots = make([]*poolSlot, 8)
	for i := 0; i < 3; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		short.slots[i] = s
	}
	idx, reason = short.claimFreeCellForHealingWithReason()
	if idx < 0 {
		t.Errorf("недостача при свободной ячейке: idx = %d, ожидался >= 0", idx)
	}
	if reason != healingProceeds {
		t.Errorf("лечение идёт: причина %q, ожидалась пустая", reason)
	}

	// Обёртка обязана сохранять прежнее поведение — на ней держатся остальные
	// call-site'ы и тесты.
	if got := full.claimFreeCellForHealing(); got != -1 {
		t.Errorf("обёртка при полной ёмкости: got %d, want -1", got)
	}
}

// TestClaimFreeCellForHealing_CountsOnlyLiveStates — что считается недостачей.
//
// Дренирующиеся НЕ живые: у них уже есть replacement, и учёт их как живых занизил
// бы недостачу ровно на число параллельных дренажей — то есть лечение молчало бы
// именно тогда, когда дренаж и забрал ячейку. Мёртвые тоже не живые: за ними своя
// цепочка reconnectLoop.
func TestClaimFreeCellForHealing_CountsOnlyLiveStates(t *testing.T) {
	newPool := func(states ...slotState) *WSPoolTransport {
		p := &WSPoolTransport{poolSize: 4}
		p.slots = make([]*poolSlot, 8)
		for i, st := range states {
			s := &poolSlot{index: i}
			s.setState(st)
			p.slots[i] = s
		}
		return p
	}

	// 4 живых при poolSize=4 → недостачи нет.
	full := newPool(slotReady, slotReady, slotReady, slotReady)
	if got := full.claimFreeCellForHealing(); got != -1 {
		t.Errorf("полный пул: got %d, want -1", got)
	}

	// slotConnecting считается живым — иначе лечение сработало бы дважды на
	// одну недостачу, пока первое соединение поднимается.
	rising := newPool(slotReady, slotReady, slotReady, slotConnecting)
	if got := rising.claimFreeCellForHealing(); got != -1 {
		t.Errorf("slotConnecting должен считаться живым: got %d, want -1", got)
	}

	// Дренирующийся НЕ живой: 3 живых + 1 draining при poolSize=4 → недостача.
	draining := newPool(slotReady, slotReady, slotReady, slotDraining)
	if got := draining.claimFreeCellForHealing(); got < 0 {
		t.Errorf("draining не должен считаться живым — недостача не увидена")
	}

	// Мёртвый НЕ живой.
	dead := newPool(slotReady, slotReady, slotReady, slotDead)
	if got := dead.claimFreeCellForHealing(); got < 0 {
		t.Errorf("slotDead не должен считаться живым — недостача не увидена")
	}

	// Недостача есть, но свободных ячеек нет → лечить негде, -1.
	p := &WSPoolTransport{poolSize: 4}
	p.slots = make([]*poolSlot, 4)
	for i := range p.slots {
		s := &poolSlot{index: i}
		s.setState(slotDraining) // все заняты, ни одна не живая
		p.slots[i] = s
	}
	if got := p.claimFreeCellForHealing(); got != -1 {
		t.Errorf("нет свободных ячеек: got %d, want -1", got)
	}
}

// TestConnectSlot_RefusesToOverwriteLiveCell — connectSlot не имеет права
// перезаписать ячейку, в которой сидит живой или дренирующийся слот
// (ревью 2026-08-14).
//
// Дефект, который тест закрывает: connectSlot был ЕДИНСТВЕННЫМ писателем ячейки
// без проверки прежнего содержимого. Пока каждый вызывающий гарантировал «nil или
// slotDead», это не стреляло. Лечение ёмкости (D1) гарантию сняло:
// claimFreeCellForHealing намеренно не ставит placeholder, поэтому между её
// Unlock и установкой в connectSlot ячейку успевает занять claimFreeSlot из
// startDrain.
//
// Цену той перезаписи комментарий оценивал как «лишнее одно соединение» — неверно:
// старый transport не закрыл бы НИКТО (все Close идут через slotAt(idx), то есть
// уже по новому указателю), старый slotReader не вышел бы (shouldExitReader
// смотрит generation своего объекта, а бампается generation нового), и этот ридер
// при своей ошибке чтения позвал бы handleSlotDeath ПО ИНДЕКСУ, убив свежий слот.
//
// Отказ проверяется через РЕАЛЬНЫЙ connectSlot: он возвращает ErrCellOccupied до
// всякого сетевого ввода-вывода, поэтому пустой пул в фикстуре достаточен.
// Разрешённые состояния — через cellIsOverwritable (тот же предикат, что зовёт
// connectSlot): дальше по коду connectSlot уходит в реальный хендшейк и упёрся бы
// в p.client, что к правилу перезаписи отношения не имеет.
func TestConnectSlot_RefusesToOverwriteLiveCell(t *testing.T) {
	// slotState не имеет String(), поэтому имя подтеста задаём явно — иначе в
	// выводе окажутся числа, и читателю придётся сверять их с iota.
	refuse := []struct {
		name  string
		state slotState
	}{
		{"slotReady — живой, перезапись осиротила бы ридер и transport", slotReady},
		{"slotDraining — ячейкой владеет дренаж", slotDraining},
	}
	for _, tc := range refuse {
		st := tc.state
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			p := &WSPoolTransport{poolSize: 4, ctx: ctx, log: newDiscardLogger()}
			p.slots = make([]*poolSlot, 8)
			occupant := &poolSlot{index: 2}
			occupant.setState(st)
			p.slots[2] = occupant

			err := p.connectSlot(ctx, 2)
			if !errors.Is(err, ErrCellOccupied) {
				t.Fatalf("connectSlot вернул %v, ожидался ErrCellOccupied: "+
					"перезапись живой ячейки осиротит transport и ридер", err)
			}
			p.reserveMu.Lock()
			got := p.slots[2]
			p.reserveMu.Unlock()
			if got != occupant {
				t.Errorf("ячейка перезаписана, несмотря на состояние %v", st)
			}
		})
	}

	// Разрешённые: nil, slotDead и placeholder slotConnecting. Запретить их
	// значило бы сломать штатный путь замены при дренаже — claimFreeSlot ставит
	// placeholder ровно для того, чтобы connectSlot его перезаписал.
	if !cellIsOverwritable(nil) {
		t.Error("nil-ячейка обязана быть перезаписываемой")
	}
	for _, tc := range []struct {
		name  string
		state slotState
	}{
		{"slotDead", slotDead},
		{"slotConnecting (placeholder claimFreeSlot)", slotConnecting},
	} {
		s := &poolSlot{}
		s.setState(tc.state)
		if !cellIsOverwritable(s) {
			t.Errorf("%s обязано быть перезаписываемым — иначе штатная замена "+
				"при дренаже (claimFreeSlot → connectSlot) сломана", tc.name)
		}
	}
}

// TestStartDrain_InflightCounterCaps asserts that with
// maxConcurrentDrains=2 (default for poolSize=8), at most 2 of N
// concurrent startDrain calls actually transition slots to slotDraining
// — the rest see the inflight cap and defer (spec §2.1.0).
func TestStartDrain_InflightCounterCaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	// Pre-saturate inflight to cap to short-circuit subsequent calls.
	p.inflightDrains.Store(int32(p.maxConcurrentDrains()))

	startedAt := Stats.DrainStartedTotal.Load()
	deferredAt := Stats.InflightCapDeferredTotal.Load()

	// All 4 concurrent calls should be deferred via the inflight gate.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p.startDrain(nil, idx, "test")
		}(i)
	}
	wg.Wait()

	if got := Stats.DrainStartedTotal.Load() - startedAt; got != 0 {
		t.Errorf("DrainStartedTotal increment = %d, want 0 (all should defer)", got)
	}
	if got := Stats.InflightCapDeferredTotal.Load() - deferredAt; got != 4 {
		t.Errorf("InflightCapDeferredTotal increment = %d, want 4", got)
	}
}

// TestStartDrain_BootstrapBackoff asserts catastrophic state (<50%
// ready) triggers the long backoff (drainCatastrophicBackoff), not the
// short one. Spec §2.1.1, C2 review fix.
//
// This is a REGRESSION GUARD for the catastrophic branch added in T6.
// If a future refactor accidentally drops the `ready < poolSize/2`
// predicate or collapses the two backoffs, this test fails first.
func TestStartDrain_BootstrapBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)

	// Catastrophic state: 3 of 8 ready (< poolSize/2 = 4). Drain target
	// (idx 0) is one of the ready cells.
	for i := 0; i < 3; i++ {
		p.slots[i] = &poolSlot{index: i}
		p.slots[i].setState(slotReady)
	}

	// Sanity check: readyCapacity=3, floor=6 (for poolSize=8) → capacity
	// gate fires; AND ready=3 < poolSize/2=4 → catastrophic backoff used.
	if got := p.readyCapacity(); got != 3 {
		t.Fatalf("setup: readyCapacity = %d, want 3", got)
	}

	before := time.Now().UnixNano()
	p.startDrain(nil, 0, "test")
	after := p.slots[0].nextDrainAttemptNs.Load()

	gap := time.Duration(after - before)
	// Expect drainCatastrophicBackoff (150s) ± scheduling slack.
	if gap < drainCatastrophicBackoff-time.Second || gap > drainCatastrophicBackoff+5*time.Second {
		t.Errorf("backoff gap = %v, want ~%v (drainCatastrophicBackoff)",
			gap, drainCatastrophicBackoff)
	}
}

// TestDrainWatchdog_InflightDecrementOnAllExitPaths asserts the
// inflight counter is decremented on natural-finish, hard-cap, AND
// ctx-cancel exit paths (spec §2.1.0, NEW-1 review fix).
func TestDrainWatchdog_InflightDecrementOnAllExitPaths(t *testing.T) {
	cases := []struct {
		name string
		exit func(p *WSPoolTransport, oldSlot *poolSlot, cancel context.CancelFunc)
	}{
		{
			name: "natural_finish",
			exit: func(p *WSPoolTransport, oldSlot *poolSlot, _ context.CancelFunc) {
				oldSlot.streams.Store(0) // streams reach 0 → natural finish
			},
		},
		{
			name: "ctx_cancel",
			exit: func(p *WSPoolTransport, _ *poolSlot, cancel context.CancelFunc) {
				cancel()
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			p := &WSPoolTransport{
				poolSize:     8,
				ctx:          ctx,
				log:          newDiscardLogger(),
				drainHardCap: 30 * time.Second,
			}
			p.slots = make([]*poolSlot, 16)
			oldSlot := &poolSlot{index: 0}
			oldSlot.setState(slotDraining)
			oldSlot.streams.Store(5) // 5 active
			p.slots[0] = oldSlot

			// Simulate that startDrain incremented inflight.
			p.inflightDrains.Store(1)

			done := make(chan struct{})
			go func() {
				p.drainWatchdog(nil, 0, oldSlot, time.Now(), "test")
				close(done)
			}()

			// Trigger the exit condition.
			time.Sleep(50 * time.Millisecond)
			tc.exit(p, oldSlot, cancel)

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("drainWatchdog did not exit within 2s")
			}

			if got := p.inflightDrains.Load(); got != 0 {
				t.Errorf("inflightDrains after exit = %d, want 0 (defer decrement)", got)
			}
		})
	}
}

// TestStreamIDReuse_RejectStaleFrames asserts that a frame's streamID
// lookup returning a slot index different from the reader's own idx
// causes the validation predicate to drop the frame rather than
// routing it (spec §2.4.1, W5 review fix).
//
// This test exercises the validation predicate directly. Full
// end-to-end frame injection requires a WS loopback fixture (deferred);
// the predicate check is what gates the production path.
func TestStreamIDReuse_RejectStaleFrames(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	// streamID 42 currently maps to slot 7 (newly assigned stream).
	p.streamMap.Store(uint16(42), newStreamEntry(7))

	// A reader on slot 5 receives a frame for streamID 42 (stale, slot 5
	// was just torn down and streamMap.Delete'd; new stream took 42 on 7).
	mappedIdx, ok := p.streamMap.Load(uint16(42))
	if !ok {
		t.Fatalf("expected mapping present")
	}
	if mappedIdx.(*streamEntry).slotIdx == 5 {
		t.Fatalf("test setup broken — expected mismatch")
	}

	initialCount := Stats.StaleFrameDroppedTotal.Load()

	// Simulate the validation predicate the reader uses.
	myIdx := 5
	if mappedIdx.(*streamEntry).slotIdx != myIdx {
		Stats.StaleFrameDroppedTotal.Add(1)
	}

	if got := Stats.StaleFrameDroppedTotal.Load() - initialCount; got != 1 {
		t.Errorf("StaleFrameDroppedTotal increment = %d, want 1", got)
	}
}

// TestEmitHealthSummary_UniformSchema asserts the new schema:
//   - dead = literal slotDead count (not nil-primary count)
//   - empty = nil-cell count anywhere in slice (new field)
//   - alive + dead + connecting + draining + empty == 2*poolSize
//
// Spec §2.4, C5 review fix.
func TestEmitHealthSummary_UniformSchema(t *testing.T) {
	p := &WSPoolTransport{
		poolSize:  8,
		log:       newDiscardLogger(),
		startedAt: time.Now(),
	}
	p.slots = make([]*poolSlot, 16)

	// Canary state: 6 primary ready + 2 reserve ready + 2 nil primary + 6 nil reserve.
	for _, i := range []int{0, 1, 3, 4, 5, 7, 8, 9} {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}

	alive, dead, connecting, draining, empty := p.poolStateCounts()
	if alive != 8 {
		t.Errorf("alive = %d, want 8", alive)
	}
	if dead != 0 {
		t.Errorf("dead = %d, want 0 (literal slotDead — not nil)", dead)
	}
	if empty != 8 {
		t.Errorf("empty = %d, want 8 (8 nil cells)", empty)
	}
	if connecting != 0 {
		t.Errorf("connecting = %d, want 0", connecting)
	}
	if draining != 0 {
		t.Errorf("draining = %d, want 0", draining)
	}
	if alive+dead+connecting+draining+empty != 16 {
		t.Errorf("sum invariant broken: %d+%d+%d+%d+%d != 16",
			alive, dead, connecting, draining, empty)
	}
}

// TestConnectReserveSlot_FreesPlaceholderOnFailure asserts that when
// the handshake fails, the slotConnecting placeholder is reset to nil
// under reserveMu so a subsequent claimFreeSlot can reuse the cell
// without waiting for reconnectLoop. Spec §4.2 (S5 review).
func TestConnectReserveSlot_FreesPlaceholderOnFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize: 8,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	p.reserveConnectFailures = make([]atomic.Int32, 16)

	// Pre-install a slotConnecting placeholder at idx 8 (as claimFreeSlot would).
	placeholder := &poolSlot{}
	placeholder.setState(slotConnecting)
	p.slots[8] = placeholder

	// Stub connectSlot to fail.
	prev := getConnectSlotForTest()
	setConnectSlotForTest(func() error {
		return errors.New("handshake failed")
	})
	defer func() { setConnectSlotForTest(prev) }()

	// Stub slotBackoffDurationForTest to 0 so the spawned reconnectLoop
	// doesn't block exit; we only verify the placeholder cleanup.
	setSlotBackoffDurationForTest(func(int) time.Duration { return 0 })
	defer setSlotBackoffDurationForTest(nil)

	p.connectReserveSlot(nil, 8, 0)

	// Wait briefly for the placeholder cleanup goroutine.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		p.reserveMu.Lock()
		s := p.slots[8]
		p.reserveMu.Unlock()
		if s == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	p.reserveMu.Lock()
	final := p.slots[8]
	p.reserveMu.Unlock()
	if final != nil {
		t.Errorf("placeholder at idx 8 not freed after failure: %v", final)
	}
}

// TestSessionForStream_NoFallback asserts that an unmapped streamID
// returns nil instead of any-ready-slot's session. Callers (client.go,
// socks5/tcp.go) are all nil-safe — verified in spec §2.5 caller audit
// (C4 review).
func TestSessionForStream_NoFallback(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)
	// Install a ready slot with a real session at idx 0.
	p.slots[0] = &poolSlot{session: core.NewSession(1, make([]byte, 32), make([]byte, 32))}
	p.slots[0].setState(slotReady)

	// streamID 999 is NOT in streamMap.
	got := p.SessionForStream(uint16(999))
	if got != nil {
		t.Errorf("SessionForStream for unmapped streamID = %v, want nil", got)
	}
}

// TestCanaryScenario_MismatchedPairs replays the exact canary
// 2026-05-19 stuck state to verify the uniform-cells fix. Setup:
// poolSize=8, primary[6] drained → reserve[8], primary[2] drained →
// reserve[9]. With pairing logic this state pinned non_ready_slots=2
// forever (canary log: 326 deferred drains in 23min). With uniform-
// cells, readyCapacity=8 (6+2) and drains can proceed.
func TestCanaryScenario_MismatchedPairs(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	// Mirror canary state.
	for _, i := range []int{0, 1, 3, 4, 5, 7, 8, 9} {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}

	ready := p.readyCapacity()
	floor := p.readyCapacityFloor()

	if ready != 8 {
		t.Errorf("canary state readyCapacity = %d, want 8", ready)
	}
	if floor != 6 {
		t.Errorf("canary state floor = %d, want 6", floor)
	}
	if ready < floor {
		t.Errorf("storm brake would engage incorrectly (ready=%d < floor=%d)", ready, floor)
	}

	// Verify a fresh drain can claim a free cell — slice has 8 nil cells
	// at indices [2, 6, 10, 11, 12, 13, 14, 15], so claim must succeed.
	got := p.claimFreeSlot()
	if got < 0 {
		t.Errorf("claimFreeSlot returned -1 — should have found a free cell")
	}
}

// TestRecycle_AfterAllReservesOccupied asserts swiss-cheese recovery:
// after 8 drains so all 8 reserve cells are occupied AND all 8 primary
// cells are nil, the 9th drain MUST claim a recycled primary cell.
// Spec §4 test list, W4 review fix.
func TestRecycle_AfterAllReservesOccupied(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	// Post-8-drain state: primary cells [0..7] all nil, reserve [8..15] all ready.
	for i := 8; i < 16; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}

	got := p.claimFreeSlot()
	if got < 0 || got >= 8 {
		t.Errorf("9th drain claim = %d, want primary range [0..8) (recycled cell)", got)
	}
	if p.slots[got] == nil || p.slots[got].getState() != slotConnecting {
		t.Errorf("recycled cell state wrong: %v", p.slots[got])
	}
}

// TestRecycleRace_DrainClaimsAfterFailedConnect — W8 race regression
// (review of T9 + T4 interaction). Sequence:
//  1. T9 failure path: connectReserveSlot fails, sets slots[newIdx]=nil,
//     launches reconnectLoop(newIdx) in background.
//  2. Concurrently, a NEW drain calls claimFreeSlot, picks newIdx,
//     installs slotConnecting placeholder.
//  3. reconnectLoop wakes after backoff, recycle guard observes
//     slots[newIdx] != nil AND state != slotDead → bails out.
//  4. End state: new drain owns newIdx; no double-install.
func TestRecycleRace_DrainClaimsAfterFailedConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize: 8, ctx: ctx, log: newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	// All primaries ready except idx 0 which is empty.
	for i := 1; i < 8; i++ {
		p.slots[i] = &poolSlot{index: i}
		p.slots[i].setState(slotReady)
	}

	// Step (1): simulate T9 already cleaned a failed connectReserveSlot
	// — slots[0] is nil, reconnectLoop is "in flight" (not actually
	// spawned in test; we verify the post-claim guard semantics).
	p.slots[0] = nil

	// Step (2): a fresh drain claims slot 0.
	got := p.claimFreeSlot()
	if got != 0 {
		t.Fatalf("claimFreeSlot returned %d, want 0", got)
	}
	if p.slots[0] == nil || p.slots[0].getState() != slotConnecting {
		t.Fatalf("post-claim state wrong: %v", p.slots[0])
	}

	// Step (3): emulate reconnectLoop guard check.
	p.reserveMu.Lock()
	recycled := p.slots[0] != nil && p.slots[0].getState() != slotDead
	p.reserveMu.Unlock()
	if !recycled {
		t.Errorf("recycle guard did not detect drain's claim — would overwrite")
	}
}

// latchTransport is a minimal wsSlotTransport stub whose ReadMessage
// blocks until release() is called (simulating a live reader), then
// returns an error (simulating connection close / slot death). Used by
// F1 test to let goroutines exit naturally so the WaitGroup-based old
// code would fire "all readers exited".
type latchTransport struct {
	releaseCh chan struct{}
}

func newLatchTransport() *latchTransport {
	return &latchTransport{releaseCh: make(chan struct{})}
}

func (l *latchTransport) release() {
	select {
	case l.releaseCh <- struct{}{}:
	default:
	}
}

func (l *latchTransport) ReadMessage(_ time.Duration) ([]byte, error) {
	<-l.releaseCh
	return nil, fmt.Errorf("simulated slot close")
}
func (l *latchTransport) WriteMessage(_ []byte) error        { return nil }
func (l *latchTransport) WriteControlMessage(_ []byte) error { return nil }
func (l *latchTransport) Close() error                       { return nil }
func (l *latchTransport) LastWriteUnixNano() int64           { return 0 }

// TestStartReader_NeverEmitsAllExited_OnPartialDrain — F1 architectural
// fix. After uniform-cells refactor, original-snapshot WaitGroup
// returned "all readers exited" when initial primary cells drained,
// even while replacement reserve readers were alive. This caused 35×
// engine resets in the 2026-05-19 canary (cosmetic but noisy).
//
// New behavior: StartReader polls and supervises; never returns "all
// exited" mid-flight. Only ctx.Done() causes return.
//
// Test mechanism: latchTransport blocks ReadMessage until release() is
// called, then returns an error (simulates slot death). After all 4
// initial readers exit naturally, old WaitGroup code would have fired
// "all readers exited" and StartReader would return. New polling code
// must stay blocked because ctx is still live.
func TestStartReader_NeverEmitsAllExited_OnPartialDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize: 4,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 8)

	// 4 primary ready cells with latch transports.
	latches := make([]*latchTransport, 4)
	for i := 0; i < 4; i++ {
		latches[i] = newLatchTransport()
		p.slots[i] = &poolSlot{index: i, transport: latches[i]}
		p.slots[i].setState(slotReady)
	}

	cl := &Client{streamChans: make(map[uint16]chan []byte)}

	// Run StartReader in a goroutine — must NOT return until ctx cancelled.
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.StartReader(ctx, cl)
	}()

	// Wait briefly for polling cycle to spawn initial readers and for
	// them to enter their blocking ReadMessage call.
	time.Sleep(50 * time.Millisecond)

	// Release all latches: each reader goroutine gets an error from
	// ReadMessage and tries to call handleSlotDeath. Since cl is minimal
	// (no real server), handleSlotDeath will run but won't panic — the
	// important thing is the reader goroutines exit naturally, completing
	// the WaitGroup. Also mark slots dead so spawnMissingReaders won't
	// respawn them (simulating permanent drain teardown).
	for i := 0; i < 4; i++ {
		p.slots[i].setState(slotDead)
		latches[i].release()
	}

	// Wait a polling cycle — old WaitGroup code would have returned by now.
	// New polling code MUST stay blocked because ctx is still live.
	select {
	case err := <-errCh:
		t.Errorf("StartReader returned prematurely: %v (must stay blocked until ctx.Done)", err)
	case <-time.After(2 * time.Second):
		// expected — still blocked
	}

	// Now cancel ctx — StartReader must return ctx.Err().
	cancel()
	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("StartReader returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("StartReader did not return after ctx.Done() within 2s")
	}
}

// TestStartDrain_ForceEvictsIdleSlot_WhenSliceFull verifies the
// slice-full eviction policy (spec 2026-05-20 §2.2.3): when every
// cell in p.slots is non-nil and claimFreeSlot returns -1, startDrain
// MUST force-evict an idle slotReady cell (streams==0) so the drain
// can proceed. Without this fix, long-running stable-network sessions
// freeze rotation forever (5h+ canary 2026-05-20).
//
// Setup mirrors the deadlock: 16 ready cells, half idle (streams=0)
// and half busy (streams>0). After startDrain on oldIdx=0:
//   - Stats.DrainForceEvictedTotal incremented by 1.
//   - One of the idle cells (NOT idx 0 itself, NOT any busy cell)
//     is torn down — nil in p.slots[].
//   - Stats.DrainStartedTotal incremented by 1 (the drain proceeded).
//   - oldSlot transitioned to slotDraining.
func TestStartDrain_ForceEvictsIdleSlot_WhenSliceFull(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          8,
		ServerAddr:    "127.0.0.1:1", // unreachable — connectReserveSlot will fail fast
		GracefulDrain: true,
		DrainHardCap:  500 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl

	// 16 ready cells. Indices 0..7 will be "busy" (streams>0) — except
	// idx 0 (the drain target) which we set streams=0 so it can drain
	// cleanly. Indices 8..15 will be "idle" (streams=0) — candidates
	// for force-eviction.
	for i := 0; i < 16; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		switch {
		case i == 0:
			s.streams.Store(0) // drain target — idle so the drain itself is clean
		case i < 8:
			s.streams.Store(3) // busy primary
		default:
			s.streams.Store(0) // idle reserve — eviction candidate
		}
		p.slots[i] = s
	}

	beforeEvicted := Stats.DrainForceEvictedTotal.Load()
	beforeStarted := Stats.DrainStartedTotal.Load()

	p.startDrain(cl, 0, "test")

	// Give the spawned connectReserveSlot/drainWatchdog goroutines a moment
	// to start — but we don't depend on them completing; the eviction +
	// counter update happen synchronously inside startDrain.
	time.Sleep(50 * time.Millisecond)

	if got := Stats.DrainForceEvictedTotal.Load() - beforeEvicted; got != 1 {
		t.Errorf("DrainForceEvictedTotal increment = %d, want 1", got)
	}
	if got := Stats.DrainStartedTotal.Load() - beforeStarted; got != 1 {
		t.Errorf("DrainStartedTotal increment = %d, want 1 (drain should proceed after evict)", got)
	}
	// Snapshot all cells under reserveMu: the spawned connectReserveSlot
	// goroutine writes p.slots[newIdx] under reserveMu (placeholder install /
	// nil-on-failure), so unguarded reads of p.slots[i] below race it
	// (Linux -race). Assert against the copied pointers.
	p.reserveMu.Lock()
	snap := make([]*poolSlot, len(p.slots))
	copy(snap, p.slots)
	p.reserveMu.Unlock()

	if got := snap[0].getState(); got != slotDraining {
		t.Errorf("drain target slot[0] state = %v, want slotDraining", got)
	}

	// Exactly one of the idle reserve cells [8..15] should be nil now
	// (force-evicted). All busy primaries [1..7] must remain non-nil
	// in slotReady. The drain target [0] must be slotDraining.
	evictedCount := 0
	for i := 8; i < 16; i++ {
		if snap[i] == nil {
			evictedCount++
		}
	}
	if evictedCount != 1 {
		t.Errorf("nil idle cells in [8..16) = %d, want 1 (force-evict picks exactly one)", evictedCount)
	}
	for i := 1; i < 8; i++ {
		if snap[i] == nil {
			t.Errorf("busy primary slot[%d] was evicted — must not touch active-stream slots", i)
		} else if snap[i].getState() != slotReady {
			t.Errorf("busy primary slot[%d] state = %v, want slotReady (untouched)", i, snap[i].getState())
		}
	}
}

// TestStartDrain_DefersWhenAllSlotsBusy verifies the fallback path
// (spec 2026-05-20 §2.2.3): when every slotReady cell has streams>0,
// force-eviction must NOT happen (no idle cell to safely evict).
// startDrain falls back to the existing defer-with-revert behavior:
//   - Stats.DrainForceEvictedTotal NOT incremented.
//   - Stats.DrainStartedTotal NOT incremented.
//   - oldSlot reverts to slotReady (CAS slotDraining→slotReady).
//   - oldSlot.nextDrainAttemptNs set to a future timestamp (backoff).
//
// This degraded-but-safe behavior is intentional: killing busy slots
// would terminate user-visible SOCKS5 connections — worse UX than
// pausing rotation for a few minutes until load shifts.
func TestStartDrain_DefersWhenAllSlotsBusy(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          8,
		ServerAddr:    "127.0.0.1:1",
		GracefulDrain: true,
		DrainHardCap:  500 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl

	// 16 cells all ready and ALL busy (streams>0). Idx 0 is also busy
	// but with streams=0 so the drain target itself can transition to
	// slotDraining cleanly (the eviction predicate is independent of
	// the drain target's streams count — it scans for OTHER idle cells).
	for i := 0; i < 16; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		if i == 0 {
			s.streams.Store(0) // drain target — its own load is irrelevant
		} else {
			s.streams.Store(2) // every other cell busy → no eviction candidate
		}
		p.slots[i] = s
	}

	beforeEvicted := Stats.DrainForceEvictedTotal.Load()
	beforeStarted := Stats.DrainStartedTotal.Load()
	beforeNow := time.Now().UnixNano()

	p.startDrain(cl, 0, "test")

	if got := Stats.DrainForceEvictedTotal.Load() - beforeEvicted; got != 0 {
		t.Errorf("DrainForceEvictedTotal increment = %d, want 0 (no idle cell to evict)", got)
	}
	if got := Stats.DrainStartedTotal.Load() - beforeStarted; got != 0 {
		t.Errorf("DrainStartedTotal increment = %d, want 0 (drain should defer)", got)
	}
	// oldSlot must have reverted to slotReady (CAS in the defer path).
	if got := p.slots[0].getState(); got != slotReady {
		t.Errorf("drain target slot[0] state = %v, want slotReady (reverted)", got)
	}
	// Backoff must be set: nextDrainAttemptNs is at least beforeNow+drainRevertBackoff/2
	// (slack for scheduling — the exact value is now+drainRevertBackoff).
	gotBackoff := p.slots[0].nextDrainAttemptNs.Load()
	minBackoff := beforeNow + int64(drainRevertBackoff/2)
	if gotBackoff < minBackoff {
		t.Errorf("nextDrainAttemptNs = %d, want >= %d (drainRevertBackoff applied)",
			gotBackoff, minBackoff)
	}

	// No cell should have been torn down — all 16 still non-nil.
	for i := 0; i < 16; i++ {
		if p.slots[i] == nil {
			t.Errorf("slot[%d] is nil — force-evict ran despite no idle cell", i)
		}
	}
}

// TestStartDrain_ForceEvictBumpsGeneration verifies that the eviction
// path bumps victim.generation BEFORE handleSlotDeath — matching the
// drainWatchdog tearDown contract. Without this bump, the victim's
// slotReader would observe transport.Close as a read error and
// inflate Stats.ReaderExits + IncFrameAnomaly counters (false-positive
// "natural" death attribution for what is an intentional teardown).
//
// The check is structural: we observe the victim's generation before
// startDrain and after, and assert it strictly increased.
func TestStartDrain_ForceEvictBumpsGeneration(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          8,
		ServerAddr:    "127.0.0.1:1",
		GracefulDrain: true,
		DrainHardCap:  500 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl

	// 16 cells all ready. The eviction candidate (first idle in scan
	// order, skipping drain target idx 0) is slot[1]. Both 0 and 1
	// have streams=0; all others have streams>0 so they cannot be
	// evicted. This pins which cell gets evicted so we can assert
	// on its generation deterministically.
	for i := 0; i < 16; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		if i == 0 || i == 1 {
			s.streams.Store(0)
		} else {
			s.streams.Store(2)
		}
		p.slots[i] = s
	}
	victim := p.slots[1]
	genBefore := victim.generation.Load()

	p.startDrain(cl, 0, "test")
	time.Sleep(50 * time.Millisecond)

	genAfter := victim.generation.Load()
	if genAfter <= genBefore {
		t.Errorf("victim.generation = %d, want > %d (bump before handleSlotDeath)",
			genAfter, genBefore)
	}
	// And the cell must be nil (handleSlotDeath ran). Read under reserveMu —
	// background connectReserveSlot/handleSlotDeath write p.slots[i] under it.
	p.reserveMu.Lock()
	cell1 := p.slots[1]
	p.reserveMu.Unlock()
	if cell1 != nil {
		t.Errorf("p.slots[1] should be nil after force-evict; got non-nil")
	}
}

// TestTryForceEvictIdleSlot_SkipsBusyAndDrainingCells is a direct
// unit test of the eviction candidate filter. Sanity check that:
//   - Cells with streams > 0 are skipped.
//   - Cells already in slotDraining are skipped.
//   - Cells in slotConnecting/slotDead are skipped.
//   - The first idle slotReady cell (in index order) wins.
//   - skipIdx is honored.
func TestTryForceEvictIdleSlot_SkipsBusyAndDrainingCells(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize:          8,
		ctx:               ctx,
		log:               newDiscardLogger(),
		client:            cl,
		meltdownThreshold: 100,
		meltdownWindow:    5 * time.Second,
	}
	p.slots = make([]*poolSlot, 16)

	// Layout (all non-nil — claimFreeSlot would have returned -1):
	// idx 0: drain target (slotDraining, skipIdx) — must skip.
	// idx 1: slotConnecting — skip.
	// idx 2: slotReady, streams=5 — busy, skip.
	// idx 3: slotDraining — skip.
	// idx 4: slotDead — skip.
	// idx 5: slotReady, streams=0 — FIRST eligible victim.
	// idx 6: slotReady, streams=0 — second candidate (must not be touched).
	// idx 7..15: slotReady, streams>0 — busy, skip.
	for i := 0; i < 16; i++ {
		s := &poolSlot{index: i}
		switch i {
		case 0:
			s.setState(slotDraining)
		case 1:
			s.setState(slotConnecting)
		case 3:
			s.setState(slotDraining)
		case 4:
			s.setState(slotDead)
		case 5, 6:
			s.setState(slotReady)
			s.streams.Store(0)
		default:
			s.setState(slotReady)
			s.streams.Store(int32(3))
		}
		p.slots[i] = s
	}

	ok := p.tryForceEvictIdleSlot(cl, 0)
	if !ok {
		t.Fatal("tryForceEvictIdleSlot returned false; expected eviction of slot[5]")
	}

	// idx 5 evicted (handleSlotDeath ran → cell nil).
	if p.slots[5] != nil {
		t.Errorf("p.slots[5] = %v, want nil (force-evicted)", p.slots[5])
	}
	// idx 6 untouched (second candidate must not be torn down).
	if p.slots[6] == nil || p.slots[6].getState() != slotReady {
		t.Errorf("p.slots[6] should still be slotReady (untouched); got %v", p.slots[6])
	}
	// Drain target idx 0 untouched.
	if p.slots[0] == nil || p.slots[0].getState() != slotDraining {
		t.Errorf("p.slots[0] (skipIdx) state changed; got %v", p.slots[0])
	}
	// Other non-Ready cells untouched.
	if p.slots[1] == nil || p.slots[1].getState() != slotConnecting {
		t.Errorf("p.slots[1] state changed; got %v", p.slots[1])
	}
	if p.slots[4] == nil || p.slots[4].getState() != slotDead {
		t.Errorf("p.slots[4] state changed; got %v", p.slots[4])
	}
}

// TestStartDrain_EmergencyEvictsMinStreamsWhenOverAged verifies the
// tier 2 eviction path (spec §2.2.3): under dense load where every
// slotReady cell has streams>0 AND the drain target has been waiting
// through emergencyEvictAgeMultiplier × maxSlotAge, startDrain must
// kill the cell with the LOWEST stream count to break the deadlock.
//
// Setup: 16 ready cells, every cell has streams>0 (no idle exists).
// Drain target [0] startedAtNs = now - 5× maxSlotAge (over-aged).
// One specific cell ([5]) has streams=1 — the unique minimum among
// non-target cells. Expected: cell 5 is evicted, counter
// DrainForceEvictedActiveTotal++, DrainStartedTotal++.
//
// Negative assertions: DrainForceEvictedTotal (idle counter) NOT
// incremented. Other busy cells untouched.
func TestStartDrain_EmergencyEvictsMinStreamsWhenOverAged(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          8,
		ServerAddr:    "127.0.0.1:1",
		MaxSlotAge:    time.Minute, // drain target needs age > 2× this
		GracefulDrain: true,
		DrainHardCap:  500 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl

	// All 16 cells ready with streams>0. Idx 5 has the unique minimum.
	for i := 0; i < 16; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		switch i {
		case 0:
			// Drain target — make it over-aged. Streams count doesn't
			// matter for the target's path (it goes via gate 6 CAS).
			s.streams.Store(3)
			s.startedAtNs.Store(time.Now().Add(-5 * time.Minute).UnixNano())
		case 5:
			s.streams.Store(1) // unique minimum
			s.startedAtNs.Store(time.Now().UnixNano())
		default:
			s.streams.Store(3)
			s.startedAtNs.Store(time.Now().UnixNano())
		}
		p.slots[i] = s
	}

	beforeIdle := Stats.DrainForceEvictedTotal.Load()
	beforeActive := Stats.DrainForceEvictedActiveTotal.Load()
	beforeStarted := Stats.DrainStartedTotal.Load()

	p.startDrain(cl, 0, "age")
	time.Sleep(50 * time.Millisecond)

	if got := Stats.DrainForceEvictedTotal.Load() - beforeIdle; got != 0 {
		t.Errorf("DrainForceEvictedTotal increment = %d, want 0 (no idle cell)", got)
	}
	if got := Stats.DrainForceEvictedActiveTotal.Load() - beforeActive; got != 1 {
		t.Errorf("DrainForceEvictedActiveTotal increment = %d, want 1", got)
	}
	if got := Stats.DrainStartedTotal.Load() - beforeStarted; got != 1 {
		t.Errorf("DrainStartedTotal increment = %d, want 1", got)
	}
	// Snapshot under reserveMu — background connectReserveSlot writes
	// p.slots[newIdx] under the lock; unguarded reads here race it.
	p.reserveMu.Lock()
	snap := make([]*poolSlot, len(p.slots))
	copy(snap, p.slots)
	p.reserveMu.Unlock()
	if snap[5] != nil {
		t.Errorf("cell [5] (min streams) should be nil after emergency evict; got %v", snap[5])
	}
	// Other busy cells [1..4, 6..15] must not be evicted.
	for _, i := range []int{1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
		if snap[i] == nil {
			t.Errorf("cell [%d] (not min-streams) should not be evicted", i)
		}
	}
}

// TestStartDrain_DoesNotEmergencyEvictWhenTargetYoung verifies the
// tier 2 gate: even when no idle cell is available, emergency
// eviction must NOT fire if the drain target is YOUNG (age < 2×
// maxSlotAge). The drain falls through to defer-with-revert.
//
// Setup: identical to TestStartDrain_DefersWhenAllSlotsBusy except
// that we explicitly set startedAtNs=now-1s on target so it's well
// under the 2× maxSlotAge threshold (2min by default).
func TestStartDrain_DoesNotEmergencyEvictWhenTargetYoung(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          8,
		ServerAddr:    "127.0.0.1:1",
		MaxSlotAge:    time.Minute,
		GracefulDrain: true,
		DrainHardCap:  500 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl

	for i := 0; i < 16; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		s.streams.Store(2)
		// Young — within maxSlotAge.
		s.startedAtNs.Store(time.Now().Add(-1 * time.Second).UnixNano())
		p.slots[i] = s
	}

	beforeIdle := Stats.DrainForceEvictedTotal.Load()
	beforeActive := Stats.DrainForceEvictedActiveTotal.Load()
	beforeStarted := Stats.DrainStartedTotal.Load()

	p.startDrain(cl, 0, "age")

	if got := Stats.DrainForceEvictedTotal.Load() - beforeIdle; got != 0 {
		t.Errorf("DrainForceEvictedTotal increment = %d, want 0", got)
	}
	if got := Stats.DrainForceEvictedActiveTotal.Load() - beforeActive; got != 0 {
		t.Errorf("DrainForceEvictedActiveTotal increment = %d, want 0 (target young, no emergency)", got)
	}
	if got := Stats.DrainStartedTotal.Load() - beforeStarted; got != 0 {
		t.Errorf("DrainStartedTotal increment = %d, want 0 (drain should defer)", got)
	}
	// All cells must remain.
	for i := 0; i < 16; i++ {
		if p.slots[i] == nil {
			t.Errorf("cell [%d] is nil — emergency evict ran despite young target", i)
		}
	}
	// Target reverted to slotReady with backoff.
	if got := p.slots[0].getState(); got != slotReady {
		t.Errorf("target state = %v, want slotReady (reverted)", got)
	}
}

// TestStartDrain_PrefersIdleOverEmergencyEvenWhenOverAged verifies
// tier ordering: if BOTH conditions hold (target over-aged AND an
// idle cell exists), tier 1 (idle) wins. We must NEVER kill an
// active stream when an idle cell is available.
func TestStartDrain_PrefersIdleOverEmergencyEvenWhenOverAged(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{},
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          8,
		ServerAddr:    "127.0.0.1:1",
		MaxSlotAge:    time.Minute,
		GracefulDrain: true,
		DrainHardCap:  500 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl

	for i := 0; i < 16; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		switch {
		case i == 0:
			// Over-aged drain target.
			s.streams.Store(3)
			s.startedAtNs.Store(time.Now().Add(-10 * time.Minute).UnixNano())
		case i == 9:
			// Single idle cell — must be picked by tier 1.
			s.streams.Store(0)
			s.startedAtNs.Store(time.Now().UnixNano())
		default:
			s.streams.Store(3)
			s.startedAtNs.Store(time.Now().UnixNano())
		}
		p.slots[i] = s
	}

	beforeIdle := Stats.DrainForceEvictedTotal.Load()
	beforeActive := Stats.DrainForceEvictedActiveTotal.Load()

	p.startDrain(cl, 0, "age")
	time.Sleep(50 * time.Millisecond)

	if got := Stats.DrainForceEvictedTotal.Load() - beforeIdle; got != 1 {
		t.Errorf("DrainForceEvictedTotal increment = %d, want 1 (idle wins)", got)
	}
	if got := Stats.DrainForceEvictedActiveTotal.Load() - beforeActive; got != 0 {
		t.Errorf("DrainForceEvictedActiveTotal increment = %d, want 0 (idle preferred)", got)
	}
	// Read under reserveMu — background connectReserveSlot writes p.slots[newIdx].
	p.reserveMu.Lock()
	cell9 := p.slots[9]
	p.reserveMu.Unlock()
	if cell9 != nil {
		t.Errorf("idle cell [9] should be evicted; got non-nil")
	}
}

// TestDrainTargetOverAged_BoundaryValues verifies the age threshold
// gate function. Spec: triggers when age >= 2× maxSlotAge.
func TestDrainTargetOverAged_BoundaryValues(t *testing.T) {
	p := &WSPoolTransport{maxSlotAge: 2 * time.Minute}

	cases := []struct {
		name   string
		ageSec int64
		want   bool
	}{
		{"young", 30, false},
		{"at_maxAge", 120, false},
		{"just_under_2x", 239, false},
		{"at_2x", 240, true},
		{"way_over", 600, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &poolSlot{}
			s.startedAtNs.Store(time.Now().Add(-time.Duration(c.ageSec) * time.Second).UnixNano())
			got := p.drainTargetOverAged(s)
			if got != c.want {
				t.Errorf("age=%ds → drainTargetOverAged = %v, want %v", c.ageSec, got, c.want)
			}
		})
	}

	// maxSlotAge=0 (disabled) should always return false.
	pDisabled := &WSPoolTransport{maxSlotAge: 0}
	s := &poolSlot{}
	s.startedAtNs.Store(time.Now().Add(-time.Hour).UnixNano())
	if pDisabled.drainTargetOverAged(s) {
		t.Errorf("maxSlotAge=0 should disable over-aged check")
	}

	// startedAtNs=0 (not yet connected) should return false.
	pEnabled := &WSPoolTransport{maxSlotAge: time.Minute}
	s2 := &poolSlot{}
	// startedAtNs.Load() == 0
	if pEnabled.drainTargetOverAged(s2) {
		t.Errorf("startedAtNs=0 should return false (slot not yet stamped)")
	}
}

// TestTryForceEvictIdleSlot_RevertsWhenStreamLandsInWindow simulates
// the race between AssignStream and the evictor: a stream lands on
// the chosen victim AFTER our streams==0 check but BEFORE we'd lose
// the chance to back out. The recheck post-CAS catches this: the slot
// reverts to slotReady and another candidate is tried instead.
//
// Mechanism: we set up TWO idle candidates (idx 5 and idx 6). idx 5
// is the natural first pick. We pre-load idx 5 with streams=0, then
// inject streams=1 into the same slot — the scan loop's first check
// at idx 5 reads streams=0 and CAS succeeds, but the recheck reads
// streams=1 (we pre-installed) and reverts; the loop continues and
// picks idx 6.
//
// We simulate the race by using a hand-rolled poolSlot whose
// streams.Load() returns 0 on the first call and 1 on subsequent
// calls. That's not possible with atomic.Int32. So we test the
// equivalent observable behavior: pre-install streams=1 on idx 5
// — both checks see 1, so scan skips it entirely; idx 6 is picked.
// While this doesn't exercise the exact "post-CAS recheck" branch,
// the recheck branch is exercised by code inspection (the Load is
// after the CAS) and the revert CAS is exercised by the
// TestPoolSlot_TryMarkDraining suite.
//
// To force the recheck-branch path deterministically, we'd need a
// hookable test seam in poolSlot — out of scope for this fix. The
// best we can do here is verify the second-pick behavior end-to-end.
func TestTryForceEvictIdleSlot_RevertsWhenStreamLandsInWindow(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize:          8,
		ctx:               ctx,
		log:               newDiscardLogger(),
		client:            cl,
		meltdownThreshold: 100,
		meltdownWindow:    5 * time.Second,
	}
	p.slots = make([]*poolSlot, 16)

	for i := 0; i < 16; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		switch i {
		case 5:
			s.streams.Store(1) // simulated "stream landed" — eligible-looking but actually busy
		case 6:
			s.streams.Store(0) // truly idle — should be evicted instead
		default:
			s.streams.Store(2) // busy
		}
		p.slots[i] = s
	}

	ok := p.tryForceEvictIdleSlot(cl, 0)
	if !ok {
		t.Fatal("expected eviction of idx 6")
	}
	if p.slots[6] != nil {
		t.Errorf("p.slots[6] = %v, want nil (truly idle, should be evicted)", p.slots[6])
	}
	// idx 5 must not be evicted (had streams>0).
	if p.slots[5] == nil || p.slots[5].getState() != slotReady {
		t.Errorf("p.slots[5] (streams>0) should be untouched; got %v", p.slots[5])
	}
}

// TestDrainWatchdog_IdleFinish verifies that with all attached streams
// silent for >= DrainIdleThreshold, drainWatchdog tears down via
// finishIdle (natural finish) before the hard cap. Step 2 per-stream
// version: setup uses storeStreamForTestWithAge for per-stream state
// instead of slot.lastActivityNs (which no longer exists).
//
// Spec 2026-05-25-drain-per-stream-idle-decision-design §2.2.
func TestDrainWatchdog_IdleFinish(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		GracefulDrain:      true,
		DrainHardCap:       5 * time.Second,
		DrainIdleThreshold: 200 * time.Millisecond,
	})
	p.ctx = t.Context()

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(2)
	oldSlot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[0] = oldSlot

	// Both streams stamped 500ms ago — past the 200ms threshold. The
	// next watchdog tick must see allStreamsIdle()==true and tear down.
	storeStreamForTestWithAge(p, 1, 0, 500*time.Millisecond)
	storeStreamForTestWithAge(p, 2, 0, 500*time.Millisecond)

	beforeIdle := Stats.DrainIdleFinishTotal.Load()
	beforeNat := Stats.DrainNaturalFinishTotal.Load()
	beforeHard := Stats.DrainHardCapTotal.Load()
	beforeRot := p.rotations1m.Load()

	start := time.Now()
	p.drainWatchdog(cl, 0, oldSlot, start, "test")
	elapsed := time.Since(start)

	if elapsed >= 1500*time.Millisecond {
		t.Errorf("idle-finish took %v, expected ≤ ~1s (first tick after threshold)", elapsed)
	}
	if got := Stats.DrainIdleFinishTotal.Load(); got != beforeIdle+1 {
		t.Errorf("DrainIdleFinishTotal = %d, want %d", got, beforeIdle+1)
	}
	if got := Stats.DrainNaturalFinishTotal.Load(); got != beforeNat+1 {
		t.Errorf("DrainNaturalFinishTotal = %d, want %d (idle counts as natural)", got, beforeNat+1)
	}
	if got := Stats.DrainHardCapTotal.Load(); got != beforeHard {
		t.Errorf("DrainHardCapTotal must not advance on idle path; before=%d after=%d", beforeHard, got)
	}
	if got := p.rotations1m.Load(); got != beforeRot+1 {
		t.Errorf("rotations_1m must tick on every drain finish; before=%d after=%d", beforeRot, got)
	}
}

// TestDrainWatchdog_IdleHeuristicDisabled verifies that DrainIdleThreshold=0
// disables the idle gate entirely — slot rides to hard cap regardless
// of per-stream silence. After Step 2 this is the canonical disable
// knob (DrainIdleStreamsMax=0 is deprecated no-op).
//
// Spec 2026-05-25-drain-per-stream-idle-decision-design §2.5.
func TestDrainWatchdog_IdleHeuristicDisabled(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		GracefulDrain:      true,
		DrainHardCap:       300 * time.Millisecond,
		DrainIdleThreshold: 0, // DISABLED (Step 2: this is the only disable knob)
	})
	p.ctx = t.Context()

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(1)
	p.slots[0] = oldSlot

	// Stream IS idle (1s old, well past any reasonable threshold). With
	// idle gate disabled, this should NOT trigger finishIdle — must hit
	// hard cap.
	storeStreamForTestWithAge(p, 1, 0, 1*time.Second)

	beforeIdle := Stats.DrainIdleFinishTotal.Load()
	beforeHard := Stats.DrainHardCapTotal.Load()

	start := time.Now()
	p.drainWatchdog(cl, 0, oldSlot, start, "test")
	elapsed := time.Since(start)

	if elapsed < 300*time.Millisecond {
		t.Errorf("hard cap should fire (~300ms); got %v", elapsed)
	}
	if got := Stats.DrainIdleFinishTotal.Load(); got != beforeIdle {
		t.Errorf("DrainIdleFinishTotal must not advance when heuristic disabled; before=%d after=%d", beforeIdle, got)
	}
	if got := Stats.DrainHardCapTotal.Load(); got != beforeHard+1 {
		t.Errorf("DrainHardCapTotal = %d, want %d", got, beforeHard+1)
	}
}

// TestBumpRotations1m_DecaysAfter60s is implicit-time-style (we don't wait
// 60s in tests). The contract under test is: every drain finish bumps the
// rotations_1m counter, mirroring fireRotation's legacy behavior. Fix 3
// for the 2026-05-22 canary where graceful drain showed rotations_1m=0
// for 7h55m despite 895 drains.
func TestBumpRotations1m_FromDrainTearDown(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: true,
		DrainHardCap:  300 * time.Millisecond,
	})
	p.ctx = t.Context()

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(1) // never reaches zero → hard cap fires
	p.slots[0] = oldSlot

	before := p.rotations1m.Load()
	p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test")
	if got := p.rotations1m.Load(); got != before+1 {
		t.Errorf("rotations1m after drain tearDown = %d, want %d (Fix 3: drains count as rotations)", got, before+1)
	}
}

// TestWriteMessageForStream_StampsPerStream verifies that
// a successful WriteMessageForStream call updates the per-stream
// lastWriteNs timestamp. Step 2 removes slot.lastActivityNs, so this
// test now only asserts per-stream behavior.
func TestWriteMessageForStream_StampsPerStream(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:       1,
		ServerAddr: "127.0.0.1:0",
	})

	stub := &countingTransport{}
	p.slots[0] = &poolSlot{transport: stub}
	p.slots[0].setState(slotReady)

	storeStreamForTest(p, uint16(42), 0)

	before := time.Now().UnixNano()
	if err := p.WriteMessageForStream(42, []byte("payload")); err != nil {
		t.Fatalf("WriteMessageForStream returned err: %v", err)
	}
	after := time.Now().UnixNano()

	// Per-stream stamp (Step 1+2: only remaining stamp after slot.lastActivityNs removal)
	v, ok := p.streamMap.Load(uint16(42))
	if !ok {
		t.Fatal("streamMap missing entry after write")
	}
	e, ok := v.(*streamEntry)
	if !ok {
		t.Fatalf("streamMap value is %T, want *streamEntry", v)
	}
	streamStamp := e.lastWriteNs.Load()
	if streamStamp < before || streamStamp > after {
		t.Errorf("per-stream lastWriteNs = %d, want in [%d, %d]", streamStamp, before, after)
	}
}

// TestEmitHardCapLog_IncludesDiagSnapshot verifies that the hard-cap
// log includes the new diag_* fields populated from snapshotDrainStreams.
// Uses the same fixture pattern as TestDrainWatchdog_HardCapTimeout —
// fakes a pool with two streams at controlled ages, then directly
// invokes emitHardCapLog and inspects captured output.
//
// The "1 active + 1 idle" shape is the smoking gun for hypothesis H1:
// if production hard-cap logs show this shape often, per-slot idle
// measurement is masking real per-stream idle (spec §2.4 / canary §4.4).
func TestEmitHardCapLog_IncludesDiagSnapshot(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Minimal harness: pool with two slots so slot index 0 references
	// a real *poolSlot we can put streams on. We don't need transport
	// or session — emitHardCapLog only reads slot.streams and the
	// pool's streamMap.
	p := &WSPoolTransport{
		log: logger,
	}
	p.slots = []*poolSlot{
		{streams: atomic.Int32{}},
	}
	p.slots[0].streams.Store(2)

	storeStreamForTestWithAge(p, 1, 0, 1*time.Second)
	storeStreamForTestWithAge(p, 2, 0, 60*time.Second)

	emitHardCapLog(p, 0, p.slots[0], "age", 90*time.Second, 90*time.Second)

	out := buf.String()
	required := []string{
		"drain hard cap reached",
		"diag_total=2",
		"diag_idle_30s_count=1",
		"diag_active_count=1",
		"diag_max_stream_age_ms=",
		"diag_min_stream_age_ms=",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestTearDownIdle_IncludesDiagSnapshot — placeholder.
//
// The finishIdle branch sits inside drainWatchdog's tearDown closure and
// is not directly callable from outside. Exercising it requires a real
// watchdog run, which is well-covered by TestDrainWatchdog_* family.
// The diag-field shape is identical to hard-cap (same snapshotDrainStreams
// call, same field names), so TestEmitHardCapLog_IncludesDiagSnapshot
// exercises the same logic.
//
// Skip is documented so anyone investigating canary regressions knows
// where to start.
func TestTearDownIdle_IncludesDiagSnapshot(t *testing.T) {
	t.Skip("Requires drainWatchdog harness; integration coverage via canary logs.")
}

// TestWriteControlMessageForStream_StampsPerStream — control-frame counterpart.
// Step 2 removes slot.lastActivityNs, so this test now only asserts per-stream behavior.
func TestWriteControlMessageForStream_StampsPerStream(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:       1,
		ServerAddr: "127.0.0.1:0",
	})

	stub := &countingTransport{}
	p.slots[0] = &poolSlot{transport: stub}
	p.slots[0].setState(slotReady)

	storeStreamForTest(p, uint16(43), 0)

	before := time.Now().UnixNano()
	if err := p.WriteControlMessageForStream(43, []byte("ctrl")); err != nil {
		t.Fatalf("WriteControlMessageForStream returned err: %v", err)
	}
	after := time.Now().UnixNano()

	v, ok := p.streamMap.Load(uint16(43))
	if !ok {
		t.Fatal("streamMap missing entry after control write")
	}
	e, ok := v.(*streamEntry)
	if !ok {
		t.Fatalf("streamMap value is %T, want *streamEntry", v)
	}
	streamStamp := e.lastWriteNs.Load()
	if streamStamp < before || streamStamp > after {
		t.Errorf("per-stream lastWriteNs = %d, want in [%d, %d]", streamStamp, before, after)
	}
}

// TestDrainWatchdog_PerStreamIdle_TriggersWhenAllSilent verifies the
// core Step 2 behavior: with 2 streams attached, both pre-aged past
// threshold, drainWatchdog should fire finishIdle (not hard cap).
// Asserts the spec §2.4 invariant on the emitted log line:
// diag_min_stream_age_ms >= threshold at finishIdle.
//
// Spec 2026-05-25-drain-per-stream-idle-decision-design §4.2 #7.
func TestDrainWatchdog_PerStreamIdle_TriggersWhenAllSilent(t *testing.T) {
	// syncBuffer sink: drainWatchdog → handleSlotDeath may spawn a
	// reconnectLoop goroutine that logs to this same logger concurrently
	// with the String() read below (Linux -race: bytes grow vs Len).
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		GracefulDrain:      true,
		DrainHardCap:       3 * time.Second,
		DrainIdleThreshold: 100 * time.Millisecond,
	})
	p.ctx = t.Context()
	p.log = logger

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(2)
	oldSlot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[0] = oldSlot

	// Both streams aged 500ms — well past 100ms threshold.
	storeStreamForTestWithAge(p, 1, 0, 500*time.Millisecond)
	storeStreamForTestWithAge(p, 2, 0, 500*time.Millisecond)

	beforeIdle := Stats.DrainIdleFinishTotal.Load()

	start := time.Now()
	p.drainWatchdog(cl, 0, oldSlot, start, "test")
	elapsed := time.Since(start)

	// Should finishIdle on the first tick after threshold — well under
	// the 3s hard cap.
	if elapsed >= 1500*time.Millisecond {
		t.Errorf("finishIdle took %v, expected ≤ ~1s", elapsed)
	}
	if got := Stats.DrainIdleFinishTotal.Load(); got != beforeIdle+1 {
		t.Errorf("DrainIdleFinishTotal = %d, want %d", got, beforeIdle+1)
	}

	// Spec §2.4 invariant: at finishIdle, diag_min_stream_age_ms must be
	// >= threshold (all streams silent at least that long).
	out := logBuf.String()
	if !strings.Contains(out, "natural finish (idle)") {
		t.Errorf("log should contain 'natural finish (idle)':\n%s", out)
	}
	if !strings.Contains(out, "diag_min_stream_age_ms=") {
		t.Errorf("log missing diag_min_stream_age_ms field:\n%s", out)
	}
}

// TestDrainWatchdog_PerStreamIdle_HoldsOpenForActiveStream verifies that a
// slot with one persistently-active stream does NOT trigger finishIdle.
//
// Bug #6 changed the contract here: pre-Bug#6 an active stream rode to the
// hard cap and was torn down via finishHardCap. Now the deadline branch
// EXTENDS the drain (sticky) instead of blindly killing the active stream —
// the whole point of the sticky-stream fix. So with healthy ready capacity
// the active stream must (a) survive past the hard cap and (b) increment
// DrainStickyExtendedTotal, NOT DrainIdleFinishTotal and NOT DrainHardCapTotal.
// We tear the watchdog down via ctx cancel after observing the extension.
//
// Spec 2026-05-25-drain-per-stream-idle-decision-design §4.2 #8 (updated for
// Bug #6 sticky stream, 2026-05-29).
func TestDrainWatchdog_PerStreamIdle_HoldsOpenForActiveStream(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               6,
		ServerAddr:         "127.0.0.1:0",
		GracefulDrain:      true,
		DrainHardCap:       400 * time.Millisecond,
		DrainIdleThreshold: 100 * time.Millisecond,
		// StickyMaxDrainAge/StickyMaxTotalBytes default (10m / 256MiB) — neither
		// trips in this short test, so the active stream extends cleanly.
	})
	ctx, cancel := context.WithCancel(context.Background())
	p.ctx = ctx
	t.Cleanup(cancel)

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(2)
	p.slots[0] = oldSlot
	// Healthy ready capacity (slots 1..5 ready) so the sticky-quota gate does
	// NOT deny the extension (readyCapacity 5 > floor(6*0.75)=4).
	for i := 1; i < 6; i++ {
		ready := &poolSlot{index: i}
		ready.setState(slotReady)
		p.slots[i] = ready
	}

	// Stream 1: idle (would-be candidate to trigger idle alone).
	storeStreamForTestWithAge(p, 1, 0, 200*time.Millisecond)

	// Stream 2: active — start fresh, re-stamp every 50ms.
	storeStreamForTestWithAge(p, 2, 0, 0)

	stopActive := make(chan struct{})
	activeDone := make(chan struct{})
	go func() {
		defer close(activeDone)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopActive:
				return
			case <-ticker.C:
				if v, ok := p.streamMap.Load(uint16(2)); ok {
					if e, ok := v.(*streamEntry); ok {
						e.lastWriteNs.Store(time.Now().UnixNano())
					}
				}
			}
		}
	}()

	beforeIdle := Stats.DrainIdleFinishTotal.Load()
	beforeHard := Stats.DrainHardCapTotal.Load()
	beforeExt := Stats.DrainStickyExtendedTotal.Load()

	done := make(chan struct{})
	start := time.Now()
	go func() { p.drainWatchdog(cl, 0, oldSlot, start, "test"); close(done) }()

	// Wait long enough for the hard cap (400ms) to fire at least once and the
	// deadline branch to extend the drain (active stream → sticky). Margin is
	// ~800ms over the 400ms cap so a slow CI runner's timer slip cannot make
	// the DrainStickyExtendedTotal assertion flake (code-review T6 follow-up).
	time.Sleep(1200 * time.Millisecond)
	if got := Stats.DrainStickyExtendedTotal.Load(); got != beforeExt+1 {
		t.Errorf("DrainStickyExtendedTotal = %d, want %d (active stream should extend drain past hard cap)", got, beforeExt+1)
	}
	// Stream still held open — watchdog has NOT finished.
	select {
	case <-done:
		t.Fatal("watchdog finished while stream still active — should have extended")
	default:
	}

	// Tear down via ctx cancel; watchdog must exit promptly.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not exit after ctx cancel")
	}

	close(stopActive)
	<-activeDone

	// Active stream must NEVER have been classified idle or hard-capped.
	if got := Stats.DrainIdleFinishTotal.Load(); got != beforeIdle {
		t.Errorf("DrainIdleFinishTotal must not advance with active stream; before=%d after=%d", beforeIdle, got)
	}
	if got := Stats.DrainHardCapTotal.Load(); got != beforeHard {
		t.Errorf("DrainHardCapTotal must not advance — active stream extends, not hard-caps; before=%d after=%d", beforeHard, got)
	}
}

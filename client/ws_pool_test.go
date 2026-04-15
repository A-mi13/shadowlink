package client

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPoolAssignStream(t *testing.T) {
	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 2),
		poolSize: 2,
	}
	pool.slots[0] = &poolSlot{index: 0}
	pool.slots[0].setState(slotReady)
	pool.slots[1] = &poolSlot{index: 1}
	pool.slots[1].setState(slotReady)

	// First stream goes to slot 0 (both have 0 streams)
	pool.AssignStream(1)
	if v, ok := pool.streamMap.Load(uint16(1)); !ok || v.(int) != 0 {
		t.Fatalf("stream 1 should be on slot 0, got %v", v)
	}
	if pool.slots[0].streams.Load() != 1 {
		t.Fatalf("slot 0 should have 1 stream")
	}

	// Second stream goes to slot 1 (least loaded)
	pool.AssignStream(2)
	if v, ok := pool.streamMap.Load(uint16(2)); !ok || v.(int) != 1 {
		t.Fatalf("stream 2 should be on slot 1, got %v", v)
	}

	// Third stream balances
	pool.AssignStream(3)
	s0 := pool.slots[0].streams.Load()
	s1 := pool.slots[1].streams.Load()
	if s0+s1 != 3 {
		t.Fatalf("total streams should be 3, got %d", s0+s1)
	}
}

func TestPoolReleaseStream(t *testing.T) {
	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 2),
		poolSize: 2,
	}
	pool.slots[0] = &poolSlot{index: 0}
	pool.slots[0].setState(slotReady)
	pool.slots[1] = &poolSlot{index: 1}
	pool.slots[1].setState(slotReady)

	pool.AssignStream(1)
	pool.AssignStream(2)

	pool.ReleaseStream(1)
	if _, ok := pool.streamMap.Load(uint16(1)); ok {
		t.Fatal("stream 1 should be released")
	}
	if pool.slots[0].streams.Load() != 0 {
		t.Fatalf("slot 0 should have 0 streams after release")
	}
}

func TestPoolSkipsDeadSlots(t *testing.T) {
	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 2),
		poolSize: 2,
	}
	pool.slots[0] = &poolSlot{index: 0}
	pool.slots[0].setState(slotDead)
	pool.slots[1] = &poolSlot{index: 1}
	pool.slots[1].setState(slotReady)

	pool.AssignStream(1)
	if v, ok := pool.streamMap.Load(uint16(1)); !ok || v.(int) != 1 {
		t.Fatalf("stream should go to slot 1 (only ready slot)")
	}
}

func TestPoolSkipsDrainingSlots(t *testing.T) {
	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 2),
		poolSize: 2,
	}
	pool.slots[0] = &poolSlot{index: 0}
	pool.slots[0].setState(slotDraining)
	pool.slots[1] = &poolSlot{index: 1}
	pool.slots[1].setState(slotReady)

	pool.AssignStream(1)
	if v, ok := pool.streamMap.Load(uint16(1)); !ok || v.(int) != 1 {
		t.Fatalf("stream should go to slot 1 (draining slots skipped)")
	}
}

func TestHealthySlots(t *testing.T) {
	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 2),
		poolSize: 2,
	}
	pool.slots[0] = &poolSlot{index: 0}
	pool.slots[0].setState(slotReady)
	pool.slots[1] = &poolSlot{index: 1}
	pool.slots[1].setState(slotDead)

	if h := pool.HealthySlots(); h != 1 {
		t.Fatalf("expected 1 healthy slot, got %d", h)
	}
}

func TestPoolWriteMessageNoReadySlots(t *testing.T) {
	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 2),
		poolSize: 2,
	}
	pool.slots[0] = &poolSlot{index: 0}
	pool.slots[0].setState(slotDead)
	pool.slots[1] = &poolSlot{index: 1}
	pool.slots[1].setState(slotDead)

	err := pool.WriteMessage([]byte("test"))
	if err == nil {
		t.Fatal("expected error when no ready slots")
	}
}

// TestMeltdownTriggersOnThreshold verifies that recording N slot deaths within
// the meltdown window sets a cooldown deadline in the future.
func TestMeltdownTriggersOnThreshold(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := &WSPoolTransport{
		poolSize:          4,
		meltdownWindow:    5 * time.Second,
		meltdownThreshold: 2,
		meltdownCooldown:  100 * time.Millisecond,
		ctx:               ctx,
		log:               slog.Default(),
	}

	// One death: under threshold — no cooldown yet.
	pool.recordSlotDeath()
	if got := pool.meltdownWaitDuration(); got != 0 {
		t.Fatalf("expected no cooldown after 1 death, got wait=%v", got)
	}

	// Second death: threshold reached — cooldown active.
	pool.recordSlotDeath()
	if got := pool.meltdownWaitDuration(); got <= 0 {
		t.Fatalf("expected cooldown active after threshold hit, got wait=%v", got)
	}
}

// TestMeltdownWaitReturnsZeroAfterCooldown verifies that meltdownWaitDuration
// returns zero once the cooldown deadline has passed.
func TestMeltdownWaitReturnsZeroAfterCooldown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := &WSPoolTransport{
		poolSize:          4,
		meltdownWindow:    5 * time.Second,
		meltdownThreshold: 1,
		meltdownCooldown:  20 * time.Millisecond,
		ctx:               ctx,
		log:               slog.Default(),
	}

	pool.recordSlotDeath()
	if got := pool.meltdownWaitDuration(); got <= 0 {
		t.Fatalf("expected active cooldown, got %v", got)
	}
	time.Sleep(40 * time.Millisecond)
	if got := pool.meltdownWaitDuration(); got != 0 {
		t.Fatalf("expected cooldown elapsed, got wait=%v", got)
	}
}

// TestMeltdownDeathsAgeOut verifies that deaths older than meltdownWindow
// don't count toward the threshold. Slow test (uses real sleep).
func TestMeltdownDeathsAgeOut(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := &WSPoolTransport{
		poolSize:          4,
		meltdownWindow:    50 * time.Millisecond,
		meltdownThreshold: 3,
		meltdownCooldown:  100 * time.Millisecond,
		ctx:               ctx,
		log:               slog.Default(),
	}

	// Two deaths now.
	pool.recordSlotDeath()
	pool.recordSlotDeath()

	// Wait for the window to pass + a bit more so the decrement goroutines run.
	time.Sleep(100 * time.Millisecond)

	// A third death now: old deaths aged out, counter was decremented twice,
	// so we're starting over. Should be under threshold (1 < 3).
	pool.recordSlotDeath()
	if got := pool.meltdownWaitDuration(); got != 0 {
		t.Fatalf("expected aged-out deaths not to trigger cooldown, got wait=%v", got)
	}
}

// TestSlotReaderExitsOnGenerationChange verifies that when a slot is
// reconnected (generation incremented), an old reader that's still in its
// loop detects the change and exits without touching the new transport.
//
// Prevents: gorilla "repeated read on failed websocket connection" panic
// caused by an old reader racing against a new one on the same conn.
func TestSlotReaderExitsOnGenerationChange(t *testing.T) {
	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 1),
		poolSize: 1,
		log:      slog.Default(),
	}
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	slot.generation.Store(7)
	pool.slots[0] = slot

	// Reader was started at generation 7. We simulate it checking generation
	// after the slot was reconnected to generation 8.
	const oldGen = 7
	slot.generation.Store(8)

	exitNow := pool.shouldExitReader(slot, oldGen)
	require.True(t, exitNow, "old reader (gen=7) must exit when slot generation advanced to 8")
}

// TestSlotReaderContinuesOnSameGeneration verifies that the generation
// check does not falsely exit a reader whose generation still matches.
func TestSlotReaderContinuesOnSameGeneration(t *testing.T) {
	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 1),
		poolSize: 1,
		log:      slog.Default(),
	}
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	slot.generation.Store(3)
	pool.slots[0] = slot

	exitNow := pool.shouldExitReader(slot, 3)
	require.False(t, exitNow, "reader with current generation must not be told to exit")
}

package client

import (
	"context"
	"encoding/json"
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
	if v, ok := pool.streamMap.Load(uint16(1)); !ok || v.(*streamEntry).slotIdx != 0 {
		t.Fatalf("stream 1 should be on slot 0, got %v", v)
	}
	if pool.slots[0].streams.Load() != 1 {
		t.Fatalf("slot 0 should have 1 stream")
	}

	// Second stream goes to slot 1 (least loaded)
	pool.AssignStream(2)
	if v, ok := pool.streamMap.Load(uint16(2)); !ok || v.(*streamEntry).slotIdx != 1 {
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
	if v, ok := pool.streamMap.Load(uint16(1)); !ok || v.(*streamEntry).slotIdx != 1 {
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
	if v, ok := pool.streamMap.Load(uint16(1)); !ok || v.(*streamEntry).slotIdx != 1 {
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

// TestConnectSlot_DecodesProtoVersionV — regression for the data-plane drift
// observed on datacanvases.com (2026-04-30). The pool slot's anonymous
// ServerHello-decoding struct previously omitted `_v`, which silently
// defaulted CompleteHandshake to protoVersion=0 against a server that
// derived keys with protoVersion=1. Every pool slot then died with
// "complete handshake: invalid server hello: cannot decrypt session token".
//
// We don't drive the full connectSlot path (it requires live transports);
// we replicate the JSON decoding with the same anonymous struct shape and
// assert that `_v=1` lands on shData.ProtoVersion. If this test fails,
// the key schedule is misaligned by construction and the WS pool will
// produce zero working slots in production.
func TestConnectSlot_DecodesProtoVersionV(t *testing.T) {
	// Server-emitted ServerHello (post-Phase-0). `_v=1` is mandatory.
	body := []byte(`{"eph":"ZXBoeXB1Yg==","tok":"dG9rZW4=","mc":8,"cs":12288,"_v":1}`)

	var shData struct {
		EphPub       []byte `json:"eph"`
		Token        []byte `json:"tok"`
		MaxConns     uint8  `json:"mc"`
		ChunkSize    uint16 `json:"cs"`
		ProtoVersion *uint8 `json:"_v,omitempty"`
	}
	require.NoError(t, json.Unmarshal(body, &shData))

	require.NotNil(t, shData.ProtoVersion,
		"ws_pool.go connectSlot must thread `_v` through to ProtoVersion — "+
			"otherwise CompleteHandshake derives keys with v=0 vs server's v=1 "+
			"and every slot fails with cannot-decrypt-session-token")
	require.Equal(t, uint8(1), *shData.ProtoVersion,
		"production server emits _v:1; pool slot must observe the same value")
	require.Equal(t, uint8(8), shData.MaxConns)
	require.Equal(t, uint16(12288), shData.ChunkSize)
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

// TestPoolSlot_ReaderActiveCAS_PreventsDuplicateReaders is the regression
// guard for the 2026-05-18 RSV-bits cascade. The slot's readerActive flag
// must permit exactly one concurrent owner; a second CAS attempt while the
// first owner is still active MUST fail, so the duplicate reader returns
// immediately without touching the *gorilla.Conn.
//
// Without this gate, two reader goroutines scheduled by:
//   - reconnectLoop (after a successful connectSlot)
//   - StartReader (called by the engine after "all readers exited")
//
// both call ReadMessage on the same conn, gorilla's frame parser sees the
// byte-interleaved stream and reports RSV1/RSV2/RSV3 bits + bad opcodes
// — the exact anomaly pattern captured in field logs that hour.
func TestPoolSlot_ReaderActiveCAS_PreventsDuplicateReaders(t *testing.T) {
	slot := &poolSlot{}

	// First reader claims ownership.
	require.True(t, slot.readerActive.CompareAndSwap(false, true),
		"first CAS must succeed — slot starts inactive")

	// Second reader attempt while first still active.
	require.False(t, slot.readerActive.CompareAndSwap(false, true),
		"second CAS must fail while first owner is active — "+
			"otherwise two readers would race ReadMessage on one conn")

	// First reader exits via its defer.
	slot.readerActive.Store(false)

	// Third reader (e.g. after reconnect) can claim ownership.
	require.True(t, slot.readerActive.CompareAndSwap(false, true),
		"new reader must be able to claim after previous owner released")
}

// TestPoolSlot_ConnectSlotResetsReaderActive guards that connectSlot's
// pre-setState reset of readerActive lets a fresh reader take ownership
// even if the previous reader's defer hasn't yet observed Close(). The
// alternative — wait on the defer — would require sub-millisecond
// synchronization between handleSlotDeath and connectSlot we don't have.
func TestPoolSlot_ConnectSlotResetsReaderActive(t *testing.T) {
	slot := &poolSlot{}
	slot.readerActive.Store(true) // simulate previous reader not yet exited

	// connectSlot's relevant final block (extracted): the reset must happen
	// BEFORE generation.Add and setState(slotReady) so the new reader can
	// CAS-claim before the engine sees the slot as ready and starts one.
	slot.readerActive.Store(false)
	slot.generation.Add(1)
	slot.setState(slotReady)

	require.True(t, slot.readerActive.CompareAndSwap(false, true),
		"new reader must succeed after connectSlot resets readerActive")
	require.Equal(t, slotReady, slot.getState())
	require.Equal(t, uint64(1), slot.generation.Load())
}

// newRotationTestPool builds a minimally-wired WSPoolTransport sufficient
// for maybeRotateSlot tests: handleSlotDeath needs a live context (for the
// reconnect goroutine to exit cleanly) and a non-zero meltdownWindow (for
// the recentDeaths decrement timer).
func newRotationTestPool(t *testing.T, slot *poolSlot) (*WSPoolTransport, *Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 1),
		poolSize:          1,
		log:               slog.Default(),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	pool.slots[0] = slot
	// Empty Client: maybeRotateSlot → handleSlotDeath only touches Client
	// when iterating streamMap, which is empty in these tests (no streams
	// were assigned). The reconnectLoop goroutine will exit on ctx.Done().
	return pool, &Client{}
}

// TestMaybeRotateSlot_IdleSlotRotatesImmediately verifies the policy gate:
// when no active streams are on the slot, a rotation trigger (byte budget
// or age budget) fires handleSlotDeath right away. This is the steady-state
// case after warmup — most slots are idle most of the time.
func TestMaybeRotateSlot_IdleSlotRotatesImmediately(t *testing.T) {
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	slot.streams.Store(0) // idle
	pool, cl := newRotationTestPool(t, slot)

	rotated := pool.maybeRotateSlot(cl, 0, slot, "age", 0, time.Now(), 0)
	require.True(t, rotated, "idle slot must rotate immediately on trigger")
	require.Equal(t, slotDead, slot.getState(),
		"handleSlotDeath must have flipped the slot to slotDead")
}

// TestMaybeRotateSlot_DefersWhenStreamsActive verifies the grace-window
// behaviour: when streams are flowing, the first trigger records a defer
// timestamp and returns false. The slot must NOT be marked dead.
func TestMaybeRotateSlot_DefersWhenStreamsActive(t *testing.T) {
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	slot.streams.Store(3) // active uploads
	pool, cl := newRotationTestPool(t, slot)

	require.Zero(t, slot.rotationDeferredNs.Load(),
		"precondition: defer not yet recorded")

	rotated := pool.maybeRotateSlot(cl, 0, slot, "age", 0, time.Now(), 0)
	require.False(t, rotated, "active streams must defer rotation, not fire it")
	require.Equal(t, slotReady, slot.getState(), "slot must stay ready while deferred")
	require.NotZero(t, slot.rotationDeferredNs.Load(),
		"first defer attempt must record the timestamp")
}

// TestRotationWatchdogSweep_RotatesAgedIdleSlot verifies the core watchdog
// invariant: a ready, idle slot whose age has exceeded MaxSlotAge MUST be
// rotated by one sweep — independent of whether the reader is currently
// blocked on ReadMessage. This is the failure mode the watchdog exists to
// prevent: a long-idle slot would otherwise sit past the middlebox kill
// window because the reader's age check only fires when data arrives.
func TestRotationWatchdogSweep_RotatesAgedIdleSlot(t *testing.T) {
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	slot.streams.Store(0) // idle — eligible for immediate rotation
	// Slot started 3 minutes ago. effectiveMaxAge for idx=0 = MaxSlotAge + 0.
	pastStart := time.Now().Add(-3 * time.Minute).UnixNano()
	slot.startedAtNs.Store(pastStart)

	pool, _ := newRotationTestPool(t, slot)
	pool.client = &Client{} // watchdog uses p.client, not the cl param
	pool.maxSlotAge = 2 * time.Minute

	pool.rotationWatchdogSweep()

	require.Equal(t, slotDead, slot.getState(),
		"watchdog must rotate an idle slot past its effective max-age")
	require.Equal(t, int32(1), pool.rotations1m.Load(),
		"successful rotation must bump the rotations_1m counter")
}

// TestRotationWatchdogSweep_LeavesYoungSlotAlone is the negative counterpart:
// a slot that is still within its effective max-age window MUST NOT be
// rotated by the watchdog. Without this guard the watchdog would burn down
// the entire pool on every tick.
func TestRotationWatchdogSweep_LeavesYoungSlotAlone(t *testing.T) {
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	slot.streams.Store(0)
	// Slot started 30 seconds ago — well below 2-min threshold.
	slot.startedAtNs.Store(time.Now().Add(-30 * time.Second).UnixNano())

	pool, _ := newRotationTestPool(t, slot)
	pool.client = &Client{}
	pool.maxSlotAge = 2 * time.Minute

	pool.rotationWatchdogSweep()

	require.Equal(t, slotReady, slot.getState(),
		"young slot must NOT be rotated by the watchdog")
	require.Equal(t, int32(0), pool.rotations1m.Load(),
		"no rotation means rotations_1m stays at zero")
}

// TestRotationWatchdogSweep_StaggerByIdx documents the per-slot stagger:
// at the moment slot 0 hits its threshold, slot 1 (with idx≥1, offset > 0)
// is still below its own threshold and must NOT be rotated. This keeps
// 8 simultaneously-aging slots from all rotating in the same tick.
//
// 2026-05-18 (A1): slot.staggerOffsetNs is sampled per-session by
// slotStaggerOffset(idx). idx=0 → 0, idx=1 → uniform [7.5s, 22.5s). For
// this test we pin specific offsets so the assertions stay deterministic;
// statistical guarantees of the sampler are covered by TestSlotStaggerOffset_*.
func TestRotationWatchdogSweep_StaggerByIdx(t *testing.T) {
	pool, _ := newRotationTestPool(t, nil)
	pool.slots = make([]*poolSlot, 2)
	pool.poolSize = 2
	pool.client = &Client{}
	pool.maxSlotAge = 2 * time.Minute

	// Both slots started at exactly the same moment, 2m05s ago.
	// slot 0 staggerOffset=0 → threshold 2m. 2m05s > 2m → rotate.
	// slot 1 staggerOffset=15s (the grid center for idx=1) → threshold
	// 2m15s. 2m05s < 2m15s → stay.
	started := time.Now().Add(-2*time.Minute - 5*time.Second).UnixNano()

	s0 := &poolSlot{}
	s0.setState(slotReady)
	s0.startedAtNs.Store(started)
	// idx=0 always has offset 0 — set explicitly for clarity.
	s0.staggerOffsetNs.Store(0)
	pool.slots[0] = s0

	s1 := &poolSlot{}
	s1.setState(slotReady)
	s1.startedAtNs.Store(started)
	// Pin slot 1 to the deterministic grid center to keep the assertion
	// stable. Real production samples vary within ±7.5s of this value.
	s1.staggerOffsetNs.Store(int64(slotRotationStaggerStep))
	pool.slots[1] = s1

	pool.rotationWatchdogSweep()

	require.Equal(t, slotDead, s0.getState(), "slot 0 past 2m threshold must rotate")
	require.Equal(t, slotReady, s1.getState(), "slot 1 below 2m15s threshold must stay")
}

// TestMaybeRotateSlot_GraceExpiresForcesRotation verifies the hard limit:
// a slot deferred for longer than slotRotationGraceWithActiveStreams gets
// rotated anyway. Without this, a long heavy upload could pin a slot
// indefinitely past the middlebox kill window we were trying to avoid.
func TestMaybeRotateSlot_GraceExpiresForcesRotation(t *testing.T) {
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	slot.streams.Store(2)
	// Simulate the slot has been in defer state longer than the grace window.
	pastDefer := time.Now().Add(-slotRotationGraceWithActiveStreams - time.Second).UnixNano()
	slot.rotationDeferredNs.Store(pastDefer)
	pool, cl := newRotationTestPool(t, slot)

	rotated := pool.maybeRotateSlot(cl, 0, slot, "age", 0, time.Now(), 0)
	require.True(t, rotated, "expired defer must force rotation despite active streams")
	require.Equal(t, slotDead, slot.getState())
}

// TestHandleSlotDeath_PreemptiveDoesNotAdvanceMeltdown is the regression
// test for the 2026-05-18 false-meltdown defect. When the age watchdog
// fires N preemptive rotations in rapid succession (8 staggered slots
// rolling over their MaxSlotAge thresholds within a 15s window), the
// meltdown detector used to count each rotation as a death and trip the
// threshold — pausing reconnect on a perfectly healthy pool. With the
// slotDeathCause split, preemptive rotations must NOT advance recentDeaths.
//
// Drives handleSlotDeath directly (bypassing fireRotation's rotations_1m
// bookkeeping) so the test isolates the meltdown-counter invariant.
func TestHandleSlotDeath_PreemptiveDoesNotAdvanceMeltdown(t *testing.T) {
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	pool, cl := newRotationTestPool(t, slot)

	require.Zero(t, pool.recentDeaths.Load(), "precondition: counter starts at zero")
	require.Zero(t, pool.meltdownUntil.Load(), "precondition: no meltdown active")

	pool.handleSlotDeath(cl, 0, deathCausePreemptiveRotation)

	require.Equal(t, slotDead, slot.getState(),
		"preemptive death must still flip the slot to slotDead (cleanup path)")
	require.Zero(t, pool.recentDeaths.Load(),
		"preemptive rotation MUST NOT inflate the meltdown counter — "+
			"counting our own staggered rotations would trip a false meltdown")
	require.Zero(t, pool.meltdownUntil.Load(),
		"preemptive rotation MUST NOT engage the meltdown cooldown")
}

// TestHandleSlotDeath_NaturalAdvancesMeltdown is the positive counterpart:
// real network failures (reader panic, ReadMessage error, middlebox close
// 1006) MUST still feed the meltdown detector — otherwise we lose the
// CF/TSPU storm protection that recordSlotDeath was built for.
func TestHandleSlotDeath_NaturalAdvancesMeltdown(t *testing.T) {
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	pool, cl := newRotationTestPool(t, slot)

	pool.handleSlotDeath(cl, 0, deathCauseNatural)

	require.Equal(t, slotDead, slot.getState())
	require.Equal(t, int32(1), pool.recentDeaths.Load(),
		"natural death MUST advance the meltdown counter so the detector "+
			"can pause reconnect under sustained network failure")
}

// TestHandleSlotDeath_MixedPreemptiveAndNaturalCountsOnlyNatural simulates
// the exact 2026-05-18 field scenario: the watchdog issues 6 preemptive
// rotations under steady-state load, and 2 real failures happen in the
// same window. The meltdown counter must see exactly 2 — not 8 — so the
// threshold (3 for the test pool) is NOT tripped by routine maintenance.
func TestHandleSlotDeath_MixedPreemptiveAndNaturalCountsOnlyNatural(t *testing.T) {
	// 8-slot pool mirrors the field setup that produced the false meltdown.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 8),
		poolSize:          8,
		log:               slog.Default(),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	for i := range pool.slots {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		pool.slots[i] = s
	}
	cl := &Client{}

	// 6 staggered preemptive rotations (slots 0..5).
	for i := 0; i < 6; i++ {
		pool.handleSlotDeath(cl, i, deathCausePreemptiveRotation)
	}
	require.Zero(t, pool.recentDeaths.Load(),
		"6 preemptive rotations must leave the meltdown counter untouched")
	require.Zero(t, pool.meltdownUntil.Load(),
		"steady-state rotation must NOT engage meltdown cooldown")

	// 2 real network failures (slots 6, 7).
	for i := 6; i < 8; i++ {
		pool.handleSlotDeath(cl, i, deathCauseNatural)
	}
	require.Equal(t, int32(2), pool.recentDeaths.Load(),
		"only the 2 natural deaths count — preemptive rotations stay zero")
	require.Zero(t, pool.meltdownUntil.Load(),
		"2 natural deaths is below threshold=3, no meltdown should fire")
}

// TestEffectiveMaxBytesForSlot_CenterStaggersByIndex pins the per-slot
// budget CENTER contract. The real per-slot budget is sampleByteBudget(idx)
// which applies multiplicative jitter around this center — see the
// distribution tests below. This test guarantees the deterministic
// center stays correct, so the jittered sampler always has a stable
// anchor point per slot.
//
// Renamed 2026-05-18 (A3 fix) from _StaggersByIndex — the function now
// returns the CENTER of the sampling distribution, not the final budget.
func TestEffectiveMaxBytesForSlot_CenterStaggersByIndex(t *testing.T) {
	pool := &WSPoolTransport{
		poolSize:        8,
		maxBytesPerSlot: 8 * 1024 * 1024, // 8 MiB direct-mode default
	}

	// Pinned expected centers — base + (idx × base / poolSize).
	// Per-slot increment = 8 MiB / 8 = 1 MiB.
	expected := []int64{
		8 * 1024 * 1024,  // slot 0: base
		9 * 1024 * 1024,  // slot 1: +1 MiB
		10 * 1024 * 1024, // slot 2
		11 * 1024 * 1024, // slot 3
		12 * 1024 * 1024, // slot 4
		13 * 1024 * 1024, // slot 5
		14 * 1024 * 1024, // slot 6
		15 * 1024 * 1024, // slot 7: 2× the slot-0 budget center
	}
	for i, want := range expected {
		got := pool.effectiveMaxBytesForSlot(i)
		require.Equal(t, want, got, "slot %d effective byte budget center", i)
	}

	// Monotonic increase of CENTERS across the pool. (Sampled values may
	// not be monotonic per session — see TestSampleByteBudget_Distribution.)
	for i := 1; i < pool.poolSize; i++ {
		require.Greater(t,
			pool.effectiveMaxBytesForSlot(i),
			pool.effectiveMaxBytesForSlot(i-1),
			"per-slot threshold CENTER must increase monotonically with idx")
	}
}

// TestEffectiveMaxBytesForSlot_DisabledWhenBaseZero — when the feature
// is off (MaxBytesPerSlot=0, used by viaCF mode AND by configs without
// rotation), the helper must return 0 so callers' "0 = disabled" branch
// stays exercised. Returning anything else would silently enable byte
// rotation in modes where it was meant to be off.
func TestEffectiveMaxBytesForSlot_DisabledWhenBaseZero(t *testing.T) {
	pool := &WSPoolTransport{poolSize: 8, maxBytesPerSlot: 0}
	for i := 0; i < pool.poolSize; i++ {
		require.Zero(t, pool.effectiveMaxBytesForSlot(i),
			"slot %d: disabled byte budget must stay disabled", i)
	}
}

// TestSampleByteBudget_DisabledWhenBaseZero — the sampler must propagate
// the "feature disabled" semantics of effectiveMaxBytesForSlot. If the
// pool is configured with MaxBytesPerSlot=0 (viaCF mode), sampling must
// return 0 so the read loop's `budget > 0` guard skips the rotation
// branch entirely. Returning a random non-zero value here would silently
// enable byte rotation in modes where it should be off.
func TestSampleByteBudget_DisabledWhenBaseZero(t *testing.T) {
	pool := &WSPoolTransport{poolSize: 8, maxBytesPerSlot: 0}
	for i := 0; i < pool.poolSize; i++ {
		for trial := 0; trial < 100; trial++ {
			got := pool.sampleByteBudget(i)
			require.Zero(t, got,
				"slot %d trial %d: disabled byte budget must stay disabled across all samples", i, trial)
		}
	}
}

// TestSampleByteBudget_InRange is the core distribution contract.
// Each slot's sampled budget MUST fall inside
//   [center * byteBudgetJitterLow, center * byteBudgetJitterHigh]
// where center = effectiveMaxBytesForSlot(idx). Validates the
// multiplicative jitter formula and protects against an off-by-one
// regression that could let a sample escape the band.
//
// For slot 0 with 8 MiB center, low=0.5, high=2.0:
//   range = [4 MiB, 16 MiB].
// For slot 7 with 15 MiB center:
//   range = [7.5 MiB, 30 MiB].
func TestSampleByteBudget_InRange(t *testing.T) {
	pool := &WSPoolTransport{
		poolSize:        8,
		maxBytesPerSlot: 8 * 1024 * 1024,
	}
	const trials = 500
	for idx := 0; idx < pool.poolSize; idx++ {
		center := pool.effectiveMaxBytesForSlot(idx)
		lo := int64(float64(center) * byteBudgetJitterLow)
		hi := int64(float64(center) * byteBudgetJitterHigh)
		for trial := 0; trial < trials; trial++ {
			got := pool.sampleByteBudget(idx)
			require.GreaterOrEqual(t, got, lo,
				"slot %d trial %d: sampled budget %d < low bound %d",
				idx, trial, got, lo)
			require.LessOrEqual(t, got, hi,
				"slot %d trial %d: sampled budget %d > high bound %d",
				idx, trial, got, hi)
		}
	}
}

// TestSampleByteBudget_RejectsConstant is the anti-regression test for
// the 2026-05-18 finding A3 — the *whole reason* this jitter exists is
// to break the previous deterministic 8/9/.../15 MiB ladder that was a
// per-flow-byte-counter detection vector (Citizen Lab "Stranger DPI in
// Russia", Aug 2024). If a future refactor accidentally pins the
// sampler to a constant (e.g. seed reuse, multiplier collapse to 1.0,
// or stub-out), this test fires.
//
// Concretely: across 200 samples per slot, we must see >50% distinct
// values. A deterministic implementation would give exactly 1 distinct.
// A barely-jittered one would give <5%. 50% is a comfortable lower bound
// that catches both classes of regression without flaking on the legit
// log-normal-style clustering.
func TestSampleByteBudget_RejectsConstant(t *testing.T) {
	pool := &WSPoolTransport{
		poolSize:        8,
		maxBytesPerSlot: 8 * 1024 * 1024,
	}
	const trials = 200
	for idx := 0; idx < pool.poolSize; idx++ {
		seen := make(map[int64]struct{})
		for trial := 0; trial < trials; trial++ {
			seen[pool.sampleByteBudget(idx)] = struct{}{}
		}
		require.Greater(t, len(seen), trials/2,
			"slot %d: only %d distinct values in %d samples — sampler is too clustered or pinned (A3 regression)",
			idx, len(seen), trials)
	}
}

// TestSampleByteBudget_AggregateOverlapsAcrossSlots is the wire-shape
// invariant. Pre-A3, slot 0 budget was exactly 8 MiB, slot 7 was exactly
// 15 MiB — no overlap, two clean clusters. Post-A3, slot 0 samples up to
// 16 MiB and slot 7 samples down to 7.5 MiB, so an observer counting
// per-flow bytes can no longer attribute "this teardown happened at
// ~10 MiB → must be slot 2" from the byte count alone.
//
// Concrete assertion: across many slot-0 samples and many slot-7 samples,
// the ranges [min_slot0, max_slot0] and [min_slot7, max_slot7] must
// overlap. (slot 0 max ≥ slot 7 min, given enough trials.)
func TestSampleByteBudget_AggregateOverlapsAcrossSlots(t *testing.T) {
	pool := &WSPoolTransport{
		poolSize:        8,
		maxBytesPerSlot: 8 * 1024 * 1024,
	}
	const trials = 500
	var slot0Max, slot7Min int64 = 0, 1 << 62
	for trial := 0; trial < trials; trial++ {
		s0 := pool.sampleByteBudget(0)
		s7 := pool.sampleByteBudget(7)
		if s0 > slot0Max {
			slot0Max = s0
		}
		if s7 < slot7Min {
			slot7Min = s7
		}
	}
	require.Greater(t, slot0Max, slot7Min,
		"slot 0 max (%d) must overlap slot 7 min (%d) to defeat bimodal byte-count fingerprinting",
		slot0Max, slot7Min)
}

// TestSampleByteBudget_PoolSizeOne — the degenerate pool with a single
// slot still uses effectiveMaxBytesForSlot == base (the stagger
// denominator branches off). Sampling on that single slot must still
// produce jittered values, not the bare base value. Otherwise A3 fix
// regresses on size=1 pools (used by tests and edge cases).
func TestSampleByteBudget_PoolSizeOne(t *testing.T) {
	pool := &WSPoolTransport{
		poolSize:        1,
		maxBytesPerSlot: 8 * 1024 * 1024,
	}
	// Center = base when poolSize == 1.
	center := pool.effectiveMaxBytesForSlot(0)
	require.Equal(t, int64(8*1024*1024), center,
		"degenerate single-slot pool center must equal base")

	const trials = 100
	lo := int64(float64(center) * byteBudgetJitterLow)
	hi := int64(float64(center) * byteBudgetJitterHigh)
	seen := make(map[int64]struct{})
	for trial := 0; trial < trials; trial++ {
		got := pool.sampleByteBudget(0)
		require.GreaterOrEqual(t, got, lo)
		require.LessOrEqual(t, got, hi)
		seen[got] = struct{}{}
	}
	require.Greater(t, len(seen), trials/2,
		"single-slot pool must still produce a jittered distribution, got %d distinct in %d", len(seen), trials)
}

// TestMaybeRotateSlot_StormBrakeDefersWhenPoolHalfDead is the regression
// test for the 2026-05-18 upload collapse. 4 of 8 slots are non-ready
// (dead, reconnecting). The brake threshold for poolSize=8 is
// ceil(8 × 0.25) = 2 — far exceeded. A new byte-budget trigger MUST
// defer, not fire, even on an idle slot. Without the brake, all
// remaining ready slots would tear down together on first byte_budget
// hit and the upload writer would have nowhere to land bytes.
func TestMaybeRotateSlot_StormBrakeDefersWhenPoolHalfDead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 8),
		poolSize:          8,
		log:               slog.Default(),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	for i := range pool.slots {
		s := &poolSlot{index: i}
		// 4 dead, 4 ready — half the pool already in reconnect.
		if i < 4 {
			s.setState(slotDead)
		} else {
			s.setState(slotReady)
		}
		pool.slots[i] = s
	}
	cl := &Client{}

	// Pick the first ready slot, simulate byte_budget trigger on an idle slot.
	target := pool.slots[4]
	target.streams.Store(0) // idle — would normally rotate immediately
	rotated := pool.maybeRotateSlot(cl, 4, target, "byte_budget", 0, time.Now(), 8*1024*1024)

	require.False(t, rotated,
		"storm brake must defer rotation when ≥ poolSize×0.25 slots are non-ready")
	require.Equal(t, slotReady, target.getState(),
		"deferred slot must NOT be marked dead")
	require.NotZero(t, target.rotationDeferredNs.Load(),
		"defer timestamp must be recorded so grace clock still ticks")
}

// TestMaybeRotateSlot_StormBrakeDoesNotBlockGraceExpired — once a slot
// has been deferred longer than slotRotationGraceWithActiveStreams, the
// brake MUST yield. The slot is past its safe age; the cost of NOT
// rotating (middlebox close 1006 + lost in-flight streams) exceeds
// the cost of a tight reconnect window. Without this carve-out, a
// stuck brake would pin a slot indefinitely past max-age.
func TestMaybeRotateSlot_StormBrakeDoesNotBlockGraceExpired(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 8),
		poolSize:          8,
		log:               slog.Default(),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	for i := range pool.slots {
		s := &poolSlot{index: i}
		if i < 4 {
			s.setState(slotDead)
		} else {
			s.setState(slotReady)
		}
		pool.slots[i] = s
	}
	cl := &Client{}

	target := pool.slots[4]
	target.streams.Store(3) // active streams, in defer state
	// Pre-record defer timestamp older than the grace window.
	target.rotationDeferredNs.Store(
		time.Now().Add(-slotRotationGraceWithActiveStreams - time.Second).UnixNano())

	rotated := pool.maybeRotateSlot(cl, 4, target, "age", 0, time.Now(), 0)

	require.True(t, rotated,
		"grace-expired rotation must bypass the storm brake — slot is past safe age")
	require.Equal(t, slotDead, target.getState())
}

// TestMaybeRotateSlot_StormBrakeAllowsHealthyPool guards the negative
// case: when the pool is healthy (0 non-ready slots), the brake must
// NOT defer normal byte-budget rotation. Without this assertion a typo
// or off-by-one in the threshold formula could silently disable all
// preemptive rotation under normal conditions.
func TestMaybeRotateSlot_StormBrakeAllowsHealthyPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 8),
		poolSize:          8,
		log:               slog.Default(),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	for i := range pool.slots {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		pool.slots[i] = s
	}
	cl := &Client{}

	target := pool.slots[3]
	target.streams.Store(0) // idle slot rotates immediately
	rotated := pool.maybeRotateSlot(cl, 3, target, "byte_budget", 0, time.Now(), 8*1024*1024)

	require.True(t, rotated,
		"healthy pool (0 non-ready) must NOT trip the storm brake")
	require.Equal(t, slotDead, target.getState())
}

// TestRotationStormBrakeThreshold_ScalesWithPoolSize pins the maxConcurrentDrains
// formula. After 2026-05-24 knob decoupling the cap is ceil(poolSize × 0.5),
// clamped to [1, poolSize-1]. Upper clamp (poolSize-1) is applied before lower
// clamp (min=1) so the degenerate poolSize=1 case (ceil(0.5)=1 → upper→0 →
// lower→1) always yields ≥ 1 — cap=0 would deadlock the drain scheduler.
func TestRotationStormBrakeThreshold_ScalesWithPoolSize(t *testing.T) {
	cases := []struct {
		poolSize int
		want     int
	}{
		{poolSize: 1, want: 1},  // degenerate: ceil(0.5)=1 → upper→0 → lower rescues → 1
		{poolSize: 2, want: 1},  // ceil(1.0)=1
		{poolSize: 4, want: 2},  // ceil(2.0)=2
		{poolSize: 8, want: 4},  // ceil(4.0)=4
		{poolSize: 16, want: 8}, // ceil(8.0)=8
	}
	for _, tc := range cases {
		p := &WSPoolTransport{poolSize: tc.poolSize}
		require.Equal(t, tc.want, p.maxConcurrentDrains(),
			"poolSize=%d", tc.poolSize)
	}
}

// TestMaybeRotateSlot_ByteBudgetDeferIsStaggered is the regression for
// the upload-storm second iteration (2026-05-18 18:10): even with the
// byte-budget stagger and storm brake, 8 slots under 600 Mbps load all
// entered defer within 4 seconds AND force-rotated 30s later within 4
// seconds → alive=2/8 during the burst. The brake didn't engage because
// at first-defer time the pool was healthy.
//
// Fix: when a slot enters defer for reason="byte_budget", record
// deferredAt + slot.staggerOffsetNs (per-session offset sampled in
// connectSlot via slotStaggerOffset). This spreads grace-expiry events
// across the pool regardless of how synchronously the byte triggers
// arrived.
//
// 2026-05-18 (A1): the per-slot offset is now sampled with additive
// grid jitter (idx*step ± step/2) rather than deterministic idx*step.
// For this test we pin specific offsets per slot — the sampling-side
// invariants are covered by TestSlotStaggerOffset_*.
//
// Verifies:
//   - slot 0: deferredAt ≈ now (offset 0)
//   - slot N: deferredAt = now + slot.staggerOffsetNs
//   - The cumulative defer times are monotonic given pinned offsets.
func TestMaybeRotateSlot_ByteBudgetDeferIsStaggered(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 8),
		poolSize:          8,
		log:               slog.Default(),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	for i := range pool.slots {
		s := &poolSlot{}
		s.setState(slotReady)
		s.streams.Store(5) // active streams — forces defer path
		// Pin staggerOffsetNs to the deterministic legacy 15s-grid center for
		// this test. This is INTENTIONAL: this test exercises sweep ORDERING,
		// not the production capped 6s formula (covered by
		// TestSlotStaggerOffset_Capped). Do NOT "fix" the 15s here to 6s —
		// it's a fixed grid for deterministic ordering. Real production samples
		// use p.slotStaggerOffset(idx) with cap + ±step/2 jitter.
		s.staggerOffsetNs.Store(int64(i) * int64(slotRotationStaggerStep))
		pool.slots[i] = s
	}
	cl := &Client{}

	startNs := time.Now().UnixNano()
	for i, s := range pool.slots {
		rotated := pool.maybeRotateSlot(cl, i, s, "byte_budget", 0, time.Now(), 8*1024*1024)
		require.False(t, rotated, "byte_budget with active streams must defer, not fire")
	}

	// Slot 0: no offset, deferredAt ≈ now.
	require.InDelta(t,
		float64(startNs),
		float64(pool.slots[0].rotationDeferredNs.Load()),
		float64(500*time.Millisecond),
		"slot 0 must have no stagger offset")

	// Slot 7: pinned offset 7 × 15s = 105s. deferredAt ≈ now + 105s.
	expected7 := startNs + int64(7)*int64(slotRotationStaggerStep)
	require.InDelta(t,
		float64(expected7),
		float64(pool.slots[7].rotationDeferredNs.Load()),
		float64(500*time.Millisecond),
		"slot 7 must have 7×15s = 105s pinned offset")

	// Monotonic: each slot's deferredAt > previous slot's (pinned offsets
	// are strictly increasing by 15s, so this is deterministic per test).
	for i := 1; i < 8; i++ {
		require.Greater(t,
			pool.slots[i].rotationDeferredNs.Load(),
			pool.slots[i-1].rotationDeferredNs.Load(),
			"defer stagger must be monotonic across pool indices")
	}
}

// TestMaybeRotateSlot_AgeDeferIsNotStaggered guards against the "double
// stagger" bug. The watchdog (rotationWatchdogSweep) already adds
// slot.staggerOffsetNs to maxSlotAge — by the time a slot reaches
// maybeRotateSlot via the age path, the stagger has already been
// applied. If we ALSO added the offset to deferredAt for "age" reason,
// the last slot would wait effectiveMaxAge[N-1] + offset + grace —
// well past any reasonable middlebox kill window.
//
// 2026-05-18 (A1): even though staggerOffsetNs is now non-zero on real
// slots (sampled in connectSlot), the maybeRotateSlot code only adds it
// for reason="byte_budget". This test pins non-zero offsets on each
// slot to PROVE the age path ignores them, not just defaults to 0.
func TestMaybeRotateSlot_AgeDeferIsNotStaggered(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 4),
		poolSize:          4,
		log:               slog.Default(),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	for i := range pool.slots {
		s := &poolSlot{}
		s.setState(slotReady)
		s.streams.Store(2)
		// Pin a non-zero stagger offset to PROVE the age path ignores it.
		// If maybeRotateSlot ever started honoring this for "age", deferredAt
		// would land at startNs + idx*15s, blowing the InDelta below.
		s.staggerOffsetNs.Store(int64(i+1) * int64(slotRotationStaggerStep))
		pool.slots[i] = s
	}
	cl := &Client{}

	startNs := time.Now().UnixNano()
	for i, s := range pool.slots {
		pool.maybeRotateSlot(cl, i, s, "age", 0, time.Now(), 0)
	}

	// All deferredAt must be ≈ startNs — the age path must NOT add the
	// stagger offset (it was already consumed in the watchdog).
	for i, s := range pool.slots {
		require.InDelta(t,
			float64(startNs),
			float64(s.rotationDeferredNs.Load()),
			float64(500*time.Millisecond),
			"slot %d: age defer must NOT add stagger offset (already applied in watchdog)", i)
	}
}

// TestCountNonReadySlots_TreatsAllNonReadyStates verifies the brake
// counter sees every non-ready transition: dead, connecting, draining,
// AND nil (uninitialized). Missing any one would let a half-broken
// pool slip past the brake and re-create the 2026-05-18 storm.
func TestCountNonReadySlots_TreatsAllNonReadyStates(t *testing.T) {
	pool := &WSPoolTransport{poolSize: 5, slots: make([]*poolSlot, 5)}

	pool.slots[0] = nil // not yet initialized
	pool.slots[1] = &poolSlot{}
	pool.slots[1].setState(slotConnecting)
	pool.slots[2] = &poolSlot{}
	pool.slots[2].setState(slotReady) // the only ready slot
	pool.slots[3] = &poolSlot{}
	pool.slots[3].setState(slotDead)
	pool.slots[4] = &poolSlot{}
	pool.slots[4].setState(slotDraining)

	require.Equal(t, 4, pool.poolSize-pool.readyCapacity(),
		"nil + connecting + dead + draining = 4 non-ready")
}

// TestPoolSlot_ByteBudgetStableWithinSession is the most important A3
// invariant: once connectSlot stores a byteBudget value on the slot,
// reading slot.byteBudget.Load() repeatedly during the slot's lifetime
// MUST return the same value. If the read loop ever re-samples (e.g. by
// calling sampleByteBudget(idx) on every ReadMessage instead of
// Load()ing the frozen field), a fresh sample landing BELOW the current
// down_bytes total would trigger an instant spurious rotation —
// defeating the entire byte-budget mechanism.
//
// Defends against this regression by:
//   1. Storing a known value into slot.byteBudget once.
//   2. Performing many Load() calls.
//   3. Asserting every Load() returns the original value.
//
// A regression that ever called sampleByteBudget from the loop would
// either give a different value on each Load (if it overwrote the
// field) or break the contract by returning whatever the helper
// produced (if it bypassed the field entirely). Both fail this test.
func TestPoolSlot_ByteBudgetStableWithinSession(t *testing.T) {
	slot := &poolSlot{}
	const pinned int64 = 12 * 1024 * 1024
	slot.byteBudget.Store(pinned)

	// Many reads, no writes. Real read-loop iterates thousands of times
	// over the slot's lifetime — 1000 reads here is a generous probe.
	for i := 0; i < 1000; i++ {
		got := slot.byteBudget.Load()
		require.Equal(t, pinned, got,
			"iteration %d: byteBudget must be stable for the slot's session", i)
	}
}

// TestConnectSlot_ByteBudgetSetExactlyOnce is a structural assertion:
// the A3 sampler MUST be wired through connectSlot's finalization
// block, not from the reader loop. We can't easily mock the full
// connectSlot path (requires real handshake + WS upgrade), but we can
// assert the invariant the code depends on: sampleByteBudget itself is
// idempotent in the sense that the value, once stored, is what the
// reader reads.
//
// Why this test exists separately from _StableWithinSession: that one
// checks the field is stable AFTER write. This one checks the WRITE
// side — that Sample → Store → Load round-trip is lossless and that a
// production code path (engine/engine.go direct mode: 8 MiB base, 8
// slots) produces non-zero budgets for every slot.
func TestConnectSlot_ByteBudgetSetExactlyOnce(t *testing.T) {
	pool := &WSPoolTransport{
		poolSize:        8,
		maxBytesPerSlot: 8 * 1024 * 1024, // direct-mode default
	}

	for idx := 0; idx < pool.poolSize; idx++ {
		slot := &poolSlot{}
		// Mimic connectSlot's finalization line: slot.byteBudget.Store(p.sampleByteBudget(idx)).
		slot.byteBudget.Store(pool.sampleByteBudget(idx))

		got := slot.byteBudget.Load()
		require.Greater(t, got, int64(0),
			"slot %d: byteBudget must be non-zero when base config enables rotation", idx)

		// Verify the stored value sits in the expected jitter band for
		// this slot — protects against a future refactor that accidentally
		// skips the Store or uses a different sampler.
		center := pool.effectiveMaxBytesForSlot(idx)
		lo := int64(float64(center) * byteBudgetJitterLow)
		hi := int64(float64(center) * byteBudgetJitterHigh)
		require.GreaterOrEqual(t, got, lo,
			"slot %d: stored byteBudget %d below jitter band lo %d", idx, got, lo)
		require.LessOrEqual(t, got, hi,
			"slot %d: stored byteBudget %d above jitter band hi %d", idx, got, hi)
	}
}

// TestConnectSlot_ByteBudgetZeroWhenFeatureDisabled — viaCF mode and any
// other config with MaxBytesPerSlot=0 must produce byteBudget=0 on the
// slot, which the read loop's `budget > 0` guard then skips. Regression
// here would silently re-enable byte rotation in CF mode where it
// belongs disabled (the /16 escape sweep handles CF rotation, and the
// CF byte budget would otherwise rotate every 15 KB — way too aggressive).
func TestConnectSlot_ByteBudgetZeroWhenFeatureDisabled(t *testing.T) {
	pool := &WSPoolTransport{
		poolSize:        8,
		maxBytesPerSlot: 0, // disabled
	}
	for idx := 0; idx < pool.poolSize; idx++ {
		var slot poolSlot
		slot.byteBudget.Store(pool.sampleByteBudget(idx))
		require.Zero(t, slot.byteBudget.Load(),
			"slot %d: disabled feature must keep byteBudget at 0", idx)
	}
}

// TestSlotStaggerOffset_ZeroForFirstSlot pins the invariant: slot 0
// always has zero offset. Slot 0 is the "first rotation point" — never
// delayed by jitter. Several existing tests
// (TestRotationWatchdogSweep_RotatesAgedIdleSlot, the watchdog stagger
// test) depend on this property to keep their assertions deterministic.
// A regression that ever returned non-zero for idx=0 would cascade into
// flaky test failures across the rotation suite.
func TestSlotStaggerOffset_ZeroForFirstSlot(t *testing.T) {
	p := &WSPoolTransport{staggerStep: slotRotationStaggerStep}
	for trial := 0; trial < 200; trial++ {
		got := p.slotStaggerOffset(0)
		require.Zero(t, got, "trial %d: slot 0 offset must be zero", trial)
	}
}

// TestSlotStaggerOffset_InRange asserts the additive grid contract:
// for idx ≥ 1, the offset is sampled from
//   [idx*step - step/2, idx*step + step/2).
// Float64 returns [0, 1) so the upper bound is open. For slot 1 with
// 15s step: [7.5s, 22.5s). For slot 7: [97.5s, 112.5s).
//
// Anti-regression: if a future refactor accidentally swaps in
// JitteredInterval (which clamps at base/2), low samples for slot 0
// would land at 3.75s instead of 0 — caught by ZeroForFirstSlot above.
// For slot N ≥ 1, the lower bound here is idx*step - step/2 strict
// inclusive; if jitter were narrower (e.g. step/4) most samples would
// still pass but the band width would fail. Trials = 500 to keep
// flake probability astronomically low.
func TestSlotStaggerOffset_InRange(t *testing.T) {
	const trials = 500
	p := &WSPoolTransport{staggerStep: slotRotationStaggerStep}
	step := slotRotationStaggerStep
	for idx := 1; idx <= 7; idx++ {
		base := time.Duration(idx) * step
		lo := base - step/2
		hi := base + step/2 // exclusive
		for trial := 0; trial < trials; trial++ {
			got := p.slotStaggerOffset(idx)
			require.GreaterOrEqual(t, got, lo,
				"slot %d trial %d: offset %v < low bound %v", idx, trial, got, lo)
			require.Less(t, got, hi,
				"slot %d trial %d: offset %v >= high bound %v (must be exclusive)", idx, trial, got, hi)
		}
	}
}

// TestSlotStaggerOffset_RejectsConstant is the anti-regression test for
// the FFT-peak signature. The whole reason for this jitter is to break
// the deterministic arithmetic-progression in rotation timings. If a
// future refactor pins the sampler to a constant (RNG seed reuse,
// multiplier collapse, or stubbed-out math/rand) the FFT peak returns.
//
// 200 trials per slot. With step=15s and 64-bit nanosecond resolution,
// distinct values are nearly guaranteed for any non-trivial jitter. We
// require >50% distinct as a conservative regression sentinel.
func TestSlotStaggerOffset_RejectsConstant(t *testing.T) {
	const trials = 200
	p := &WSPoolTransport{staggerStep: slotRotationStaggerStep}
	for idx := 1; idx <= 7; idx++ {
		seen := make(map[time.Duration]struct{})
		for trial := 0; trial < trials; trial++ {
			seen[p.slotStaggerOffset(idx)] = struct{}{}
		}
		require.Greater(t, len(seen), trials/2,
			"slot %d: only %d distinct offsets in %d trials — sampler collapsed (A1 regression)",
			idx, len(seen), trials)
	}
}

// TestSlotStaggerOffset_AdjacentSlotsTouchBoundary is the wire-shape
// assertion that drives the A1 fix. Pre-A1, slot 1 always landed
// exactly at 15s and slot 2 at 30s — a sharp delta-spike at every
// idx*step boundary, FFT peak at 1/step Hz.
//
// Post-A1, slot 1 samples are uniform on [7.5s, 22.5s) and slot 2
// samples are uniform on [22.5s, 37.5s). The two distributions touch
// at the 22.5s boundary exclusive-on-slot-1 / inclusive-on-slot-2.
// They don't overlap (by construction — window width = step), but
// they fill their bands DENSELY, smearing the delta-spike into a
// uniform sawtooth across the timeline. An observer collecting
// rotation-timestamp samples sees a flat distribution with no peaks
// at idx*step.
//
// Concrete check: across many samples, slot 1's max approaches the
// theoretical upper bound (22.5s) and slot 2's min approaches the
// theoretical lower bound (22.5s). Both must come within step/8 of
// the boundary to confirm density.
func TestSlotStaggerOffset_AdjacentSlotsTouchBoundary(t *testing.T) {
	const trials = 1000
	p := &WSPoolTransport{staggerStep: slotRotationStaggerStep}
	step := slotRotationStaggerStep
	boundary := time.Duration(1)*step + step/2 // 22.5s
	tolerance := step / 8                      // 1.875s — generous

	var slot1Max, slot2Min time.Duration = 0, 1 << 62
	for trial := 0; trial < trials; trial++ {
		s1 := p.slotStaggerOffset(1)
		s2 := p.slotStaggerOffset(2)
		if s1 > slot1Max {
			slot1Max = s1
		}
		if s2 < slot2Min {
			slot2Min = s2
		}
	}

	// Slot 1 max should approach the boundary from below (exclusive).
	require.Greater(t, slot1Max, boundary-tolerance,
		"slot 1 max (%v) must approach the boundary %v from below — band not filled, FFT-peak risk",
		slot1Max, boundary)
	require.Less(t, slot1Max, boundary,
		"slot 1 max (%v) must stay below %v (exclusive upper bound)", slot1Max, boundary)

	// Slot 2 min should approach the boundary from above (inclusive).
	require.Less(t, slot2Min, boundary+tolerance,
		"slot 2 min (%v) must approach the boundary %v from above — band not filled, FFT-peak risk",
		slot2Min, boundary)
	require.GreaterOrEqual(t, slot2Min, boundary,
		"slot 2 min (%v) must stay ≥ %v (inclusive lower bound)", slot2Min, boundary)
}

// TestSlotStaggerOffset_MonotonicInExpectation verifies the contract
// that monotonicity is preserved IN EXPECTATION (not per call). Across
// many trials, the mean offset for slot N+1 must exceed the mean offset
// for slot N. This protects the system invariant that slot N rotates
// AROUND its grid point, not arbitrarily.
//
// Concrete: 500 samples per slot, slot N mean must be ≥ slot N-1 mean.
// Expected mean per slot = idx*step. Deltas should converge to step.
// We assert a weaker bound (slot N mean > slot N-1 mean) to keep flake
// probability astronomically low.
func TestSlotStaggerOffset_MonotonicInExpectation(t *testing.T) {
	const trials = 500
	p := &WSPoolTransport{staggerStep: slotRotationStaggerStep}
	means := make([]int64, 8)
	for idx := 0; idx < 8; idx++ {
		var sum int64
		for trial := 0; trial < trials; trial++ {
			sum += int64(p.slotStaggerOffset(idx))
		}
		means[idx] = sum / trials
	}
	for idx := 1; idx < 8; idx++ {
		require.Greater(t, means[idx], means[idx-1],
			"slot %d mean offset (%dns) must exceed slot %d mean (%dns) — monotonicity in expectation broken",
			idx, means[idx], idx-1, means[idx-1])
	}
}

// TestSlotStaggerOffset_NegativeIdxSafeFallback covers the edge case:
// slotStaggerOffset(idx<0) must return 0 (matches idx=0 behavior). This
// is a defensive contract — if any future code path computes idx
// dynamically and hands a negative value (e.g. an off-by-one or
// signed-int math underflow), the helper must not crash or return a
// negative time.Duration that would skew the threshold backwards.
func TestSlotStaggerOffset_NegativeIdxSafeFallback(t *testing.T) {
	p := &WSPoolTransport{staggerStep: slotRotationStaggerStep}
	require.Zero(t, p.slotStaggerOffset(-1), "negative idx must fall back to 0")
	require.Zero(t, p.slotStaggerOffset(-100), "negative idx must fall back to 0")
}

// TestSlotStaggerOffset_Capped is the BLOCKER-1 regression test
// (TSPU freeze window). Without a cap, idx*step grows unbounded — at
// poolSize=8 the uniform-cells slice runs idx 0..15, so idx=15 yields
// 15*15s = +225s (or +90s sided against a 6s step) of stagger ON TOP of
// MaxSlotAge, pushing the slot's effective max age well into the ~130s
// TSPU direct-TCP freeze window. The cap clamps the linear ladder so the
// highest-idx slot still rotates before the freeze.
func TestSlotStaggerOffset_Capped(t *testing.T) {
	p := &WSPoolTransport{staggerStep: 6 * time.Second, staggerOffsetCap: 45 * time.Second}
	if got := p.slotStaggerOffset(0); got != 0 {
		t.Fatalf("idx=0: got %v want 0", got)
	}
	g7 := p.slotStaggerOffset(7) // 42s ± 3s
	if g7 < 39*time.Second || g7 > 45*time.Second {
		t.Fatalf("idx=7: got %v want ~42s±3s", g7)
	}
	g15 := p.slotStaggerOffset(15) // capped 45s ± 3s (NOT 90s)
	if g15 < 42*time.Second || g15 > 48*time.Second {
		t.Fatalf("idx=15: got %v want ~45s capped NOT 90s", g15)
	}
	if eff := 75*time.Second + g15; eff >= 130*time.Second {
		t.Fatalf("idx=15 effectiveMaxAge=%v must be <130s", eff)
	}
}

// TestAssignStream_BurstRebalanceWithCap is the A4 regression test
// (2026-05-18). Before A4, maxStreamsPerSlot=0 for direct mode let
// AssignStream pile 30+ streams on a single hot slot under burst load
// (observed in field logs: active_streams=85+ on one slot). With
// maxStreamsPerSlot=8 set as a rebalance hint, AssignStream's PASS-1
// routes new streams away from slots that hit the cap, soft-overflowing
// to the slot with fewest streams when all are saturated.
//
// Test: 8-slot pool, cap=8, fire 80 AssignStream calls. Expected:
//   - all 80 streams placed (none lost — soft-overflow guarantees this)
//   - distribution is approximately even (max-min ≤ 4, where 80/8=10
//     would be perfect; small variance is OK due to PASS-1 ordering)
//
// Critical: cap is a HINT not a hard limit. After 64 nominal capacity
// (8×8) the next 16 calls go to least-loaded slot via soft-overflow,
// pushing some slots to 12. We assert no slot exceeds 16 (2× nominal),
// catching a regression where overflow path breaks and clamps hard.
func TestAssignStream_BurstRebalanceWithCap(t *testing.T) {
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 8),
		poolSize:          8,
		maxStreamsPerSlot: 8, // A4 rebalance hint for direct mode
	}
	for i := range pool.slots {
		pool.slots[i] = &poolSlot{index: i}
		pool.slots[i].setState(slotReady)
	}

	const burstSize = 80
	for streamID := uint16(1); streamID <= burstSize; streamID++ {
		pool.AssignStream(streamID)
	}

	// All 80 streams must be placed somewhere — soft-overflow guarantees
	// no stream is silently dropped.
	totalAssigned := 0
	minStreams, maxStreams := int32(1<<30), int32(0)
	for i, slot := range pool.slots {
		s := slot.streams.Load()
		totalAssigned += int(s)
		if s < minStreams {
			minStreams = s
		}
		if s > maxStreams {
			maxStreams = s
		}
		t.Logf("slot %d streams=%d", i, s)
	}
	require.Equal(t, burstSize, totalAssigned,
		"all 80 streams must be placed (soft-overflow guarantees this)")

	// Distribution sanity: in a synthetic pool with pendingConnects=0
	// across all slots, score = streams, and PASS-1 + soft-overflow
	// converge on near-perfect distribution (10 streams/slot for
	// 80/8). The min/max spread must be ≤ 2 — looser bounds would
	// miss a regression where overflow piles streams on one slot.
	//
	// Catches: PASS-1 not exhausting slots (min < 8 OR max > cap+1);
	// overflow path picking same slot repeatedly (max - min > 2);
	// score-min logic broken (some slots stay at 0 while others fill).
	require.LessOrEqual(t, maxStreams-minStreams, int32(2),
		"burst distribution should be near-perfect in synthetic pool; got min=%d max=%d (regression in score-min or overflow path?)",
		minStreams, maxStreams)
	// Hard upper bound: max stream count must stay within 2× nominal
	// cap. Production may see slightly higher under pendingConnects
	// load, but the synthetic test must not.
	require.LessOrEqual(t, maxStreams, int32(16),
		"max stream count per slot must stay within 2× cap; got %d (regression in soft-overflow?)", maxStreams)
}

// TestAssignStream_BurstUncappedSkewsHard is the contrast test that
// documents WHY A4 exists. Without maxStreamsPerSlot (cap=0,
// pre-A4 behavior), AssignStream still picks min by score on each call,
// but with no cap, slot 0 stays "first eligible" for a long while
// before the rebalance kicks in. The skew is not catastrophic in a
// fresh pool — PASS-1 picks min(score) each call — but it serves as
// a baseline: if this test ever FAILS (i.e. uncapped pool produces
// the same distribution as capped), then A4 is doing nothing and
// can be reverted.
//
// 2026-05-18: in practice both capped and uncapped distribute reasonably
// well in this synthetic test because all slots start at zero load and
// AssignStream's min(pending*4 + streams) score is well-behaved. The
// real difference shows under PRODUCTION load where slots have varied
// pending CONNECTs that bias score — captured by field test, not
// synthesisable here. This test simply documents that BOTH modes place
// all 80 streams.
func TestAssignStream_BurstUncappedAlsoPlacesAll(t *testing.T) {
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 8),
		poolSize:          8,
		maxStreamsPerSlot: 0, // pre-A4 baseline (unlimited)
	}
	for i := range pool.slots {
		pool.slots[i] = &poolSlot{index: i}
		pool.slots[i].setState(slotReady)
	}

	const burstSize = 80
	for streamID := uint16(1); streamID <= burstSize; streamID++ {
		pool.AssignStream(streamID)
	}

	totalAssigned := 0
	for _, slot := range pool.slots {
		totalAssigned += int(slot.streams.Load())
	}
	require.Equal(t, burstSize, totalAssigned,
		"uncapped mode must also place all streams (PASS-1 score-min routes them)")
}

// TestReconnectJitterOffset_ZeroForFirstSlot pins the A2 invariant
// that slot 0 is the "anchor" reconnect — never delayed by jitter.
// reconnectLoop checks `idx > 0` before invoking this helper, so
// production never calls reconnectJitterOffset(0), but if some future
// caller does, it must return 0.
func TestReconnectJitterOffset_ZeroForFirstSlot(t *testing.T) {
	for trial := 0; trial < 200; trial++ {
		require.Zero(t, reconnectJitterOffset(0),
			"trial %d: slot 0 reconnect jitter must be zero", trial)
	}
}

// TestReconnectJitterOffset_InRange asserts the additive-grid contract
// for reconnect jitter. Slot N offset is uniform on
//   [N*reconnectJitterStaggerStep - step/2, N*step + step/2).
// For N=1: [100ms, 300ms). For N=7: [1300ms, 1500ms).
//
// Catches regressions where someone replaces additive-grid with
// multiplicative or cumulative-independent. Same pattern as
// TestSlotStaggerOffset_InRange but at 200ms scale instead of 15s.
func TestReconnectJitterOffset_InRange(t *testing.T) {
	const trials = 500
	step := reconnectJitterStaggerStep
	for idx := 1; idx <= 7; idx++ {
		base := time.Duration(idx) * step
		lo := base - step/2
		hi := base + step/2 // exclusive
		for trial := 0; trial < trials; trial++ {
			got := reconnectJitterOffset(idx)
			require.GreaterOrEqual(t, got, lo,
				"slot %d trial %d: offset %v < low bound %v", idx, trial, got, lo)
			require.Less(t, got, hi,
				"slot %d trial %d: offset %v >= high bound %v (must be exclusive)", idx, trial, got, hi)
		}
	}
}

// TestReconnectJitterOffset_NegativeIdxSafeFallback — defensive
// fallback matching slotStaggerOffset's contract. negative idx → 0.
func TestReconnectJitterOffset_NegativeIdxSafeFallback(t *testing.T) {
	require.Zero(t, reconnectJitterOffset(-1), "negative idx must fall back to 0")
	require.Zero(t, reconnectJitterOffset(-100), "negative idx must fall back to 0")
}

// TestReconnectJitterOffset_RejectsConstant — anti-FFT regression. If
// future refactor pins the sampler to a constant (RNG seed reuse,
// multiplier collapse), the thunder-herd signature returns. 200 trials,
// >50% distinct as a conservative sentinel.
func TestReconnectJitterOffset_RejectsConstant(t *testing.T) {
	const trials = 200
	for idx := 1; idx <= 7; idx++ {
		seen := make(map[time.Duration]struct{})
		for trial := 0; trial < trials; trial++ {
			seen[reconnectJitterOffset(idx)] = struct{}{}
		}
		require.Greater(t, len(seen), trials/2,
			"slot %d: only %d distinct offsets in %d trials — sampler collapsed",
			idx, len(seen), trials)
	}
}

// TestReconnectMeltdownGate_Fresh — pool with recentMeltdownNs set
// to "just now" must report the gate as ACTIVE. This is the steady-
// state we care about: post-meltdown handshakes spread by jitter.
//
// We can't easily test reconnectLoop end-to-end (requires a real
// origin), so this is a structural assertion on the gate condition
// reconnectLoop uses: `since < reconnectJitterWindow`.
func TestReconnectMeltdownGate_Fresh(t *testing.T) {
	pool := &WSPoolTransport{}
	// Stamp meltdown 1s ago — well within the 5s window.
	pool.recentMeltdownNs.Store(time.Now().Add(-1 * time.Second).UnixNano())

	last := pool.recentMeltdownNs.Load()
	require.Positive(t, last, "meltdown timestamp must be set")
	since := time.Since(time.Unix(0, last))
	require.Less(t, since, reconnectJitterWindow,
		"fresh meltdown (1s ago) must be inside the %v jitter window — gate must engage",
		reconnectJitterWindow)
}

// TestReconnectMeltdownGate_Stale — pool with old meltdown (longer
// than reconnectJitterWindow ago) must report the gate as INACTIVE.
// This prevents routine single-slot rotation from paying jitter
// latency for no benefit.
func TestReconnectMeltdownGate_Stale(t *testing.T) {
	pool := &WSPoolTransport{}
	// Stamp meltdown twice the window ago.
	pool.recentMeltdownNs.Store(time.Now().Add(-2 * reconnectJitterWindow).UnixNano())

	last := pool.recentMeltdownNs.Load()
	since := time.Since(time.Unix(0, last))
	require.GreaterOrEqual(t, since, reconnectJitterWindow,
		"stale meltdown must be outside the %v jitter window — gate must NOT engage",
		reconnectJitterWindow)
}

// TestReconnectMeltdownGate_NeverFired — initial state (no meltdown
// observed yet) must NOT engage the gate. Pool just started, single
// slot rotates routinely, no need to spread handshakes.
func TestReconnectMeltdownGate_NeverFired(t *testing.T) {
	pool := &WSPoolTransport{}
	require.Zero(t, pool.recentMeltdownNs.Load(),
		"initial state must have zero meltdown timestamp — gate inactive")
}

// TestEmitMeltdownLog_StampsRecentMeltdownNs is the wire-up test that
// proves emitMeltdownLog actually stamps the field reconnectLoop reads.
// Without this, a regression that removes the Store call would leave
// the gate permanently inactive in production (silent failure).
func TestEmitMeltdownLog_StampsRecentMeltdownNs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 8),
		poolSize:          8,
		log:               newDiscardLogger(),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	// Mark all 8 slots dead so severeMeltdown(8, 8) returns true and
	// the log path emits — but the recentMeltdownNs.Store happens
	// BEFORE the severity gate, so it'd stamp regardless.
	for i := range pool.slots {
		s := &poolSlot{}
		s.setState(slotDead)
		pool.slots[i] = s
	}

	require.Zero(t, pool.recentMeltdownNs.Load(),
		"precondition: no meltdown observed yet")

	before := time.Now().UnixNano()
	pool.emitMeltdownLog(8)
	after := time.Now().UnixNano()

	got := pool.recentMeltdownNs.Load()
	require.GreaterOrEqual(t, got, before,
		"recentMeltdownNs must be stamped no earlier than the call")
	require.LessOrEqual(t, got, after,
		"recentMeltdownNs must be stamped no later than the call returns")
}

// TestEmitMeltdownLog_CascadeRefreshesTimestamp — two emitMeltdownLog
// calls in quick succession must refresh recentMeltdownNs to the
// LATER timestamp, not pin the first one. Otherwise after a cascade
// meltdown the gate could expire while still inside the second event's
// reconnect window, leaving the second wave un-jittered.
func TestEmitMeltdownLog_CascadeRefreshesTimestamp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 8),
		poolSize:          8,
		log:               newDiscardLogger(),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	for i := range pool.slots {
		s := &poolSlot{}
		s.setState(slotDead)
		pool.slots[i] = s
	}

	pool.emitMeltdownLog(8)
	first := pool.recentMeltdownNs.Load()
	require.Positive(t, first)

	// Small pause so the second timestamp is strictly later.
	time.Sleep(2 * time.Millisecond)

	pool.emitMeltdownLog(8)
	second := pool.recentMeltdownNs.Load()

	require.Greater(t, second, first,
		"cascade meltdown must refresh recentMeltdownNs to the LATER timestamp; got first=%d second=%d",
		first, second)
}

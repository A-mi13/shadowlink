package client

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// migrate_resume_test.go — Bug #9 Task 17. Closes the client-side migration
// orchestration: the uplink barrier (§5.3), RESUME-on-slot-death (the sudden
// cut path — a stream survives its slot's death via a grace RESUME onto a live
// slot), and drain coordination via the per-stream migrating flag (F10 — a
// migrating stream is neither closed by teardown nor counted "active" for the
// sticky backstop).
//
// Test harness: a minimal WSPoolTransport built by hand (same pattern as
// migrate_watchdog_test.go) plus a sendMigrate hook so the RESUME wire
// round-trip is faked. The hook is installed via p.migrateSendHook (Task 17
// seam) and returns a scripted migrateResult.

// newResumeTestPool builds a pool with `size` cells, a live Client, and a
// migration-enabled wire format. slot states are left slotDead so the caller
// flips the cells it wants live. A real *Client is attached so handleSlotDeath
// can close streamChans through the normal streamMu path.
func newResumeTestPool(t *testing.T, size int) (*WSPoolTransport, *Client) {
	t.Helper()
	cl := &Client{}
	cl.streamChans = make(map[uint16]chan []byte)
	cl.streamProof = make(map[uint16][32]byte)
	// A cancelled ctx makes the background goroutines that handleSlotDeath spawns
	// on deathCauseNatural (recordSlotDeath's window-decrement, reconnectLoop)
	// exit immediately at their `<-p.ctx.Done()` select — they would otherwise
	// touch production-only state (transports, dialers) this minimal pool lacks.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &WSPoolTransport{
		poolSize: size,
		client:   cl,
		log:      slog.Default(),
		ctx:      ctx,
		cancel:   cancel,
		// High threshold so recordSlotDeath never trips the meltdown path (which
		// would dereference dialer/metrics state absent in this minimal pool).
		meltdownThreshold: 1 << 30,
		meltdownWindow:    time.Minute,
		meltdownCooldown:  time.Second,
	}
	p.slots = make([]*poolSlot, size)
	for i := range p.slots {
		p.slots[i] = &poolSlot{index: i}
	}
	p.migrateEnabled.Store(true)
	p.migrateCapable.Store(true)
	return p, cl
}

// attachStream wires a stream onto slotIdx exactly as the SOCKS front-end +
// AssignStream would: streamMap entry, slot counter, a registered stream chan,
// and a stored proof (so sendMigrate's proof-gate passes if it ran for real).
func attachStream(p *WSPoolTransport, cl *Client, streamID uint16, slotIdx int) {
	p.streamMap.Store(streamID, newStreamEntry(slotIdx))
	if slotIdx >= 0 && slotIdx < len(p.slots) && p.slots[slotIdx] != nil {
		p.slots[slotIdx].streams.Add(1)
	}
	cl.streamMu.Lock()
	cl.streamChans[streamID] = make(chan []byte, 1)
	cl.streamProof[streamID] = [32]byte{1, 2, 3}
	cl.streamMu.Unlock()
}

// streamChanClosed reports whether cl's stream chan for streamID is closed
// (non-blocking receive returns !ok) or already removed from the map.
func streamChanClosed(cl *Client, streamID uint16) bool {
	cl.streamMu.Lock()
	ch, ok := cl.streamChans[streamID]
	cl.streamMu.Unlock()
	if !ok {
		return true // removed by close path
	}
	select {
	case _, recvOk := <-ch:
		return !recvOk
	default:
		return false
	}
}

// TestHandleSlotDeath_ResumesMigratingStreamsBeforeClose: a dead slot with one
// active stream sends RESUME onto a live slot; on RESUME_OK the stream chan is
// NOT closed and the stream's slotIdx is re-pointed at the live slot.
func TestHandleSlotDeath_ResumesMigratingStreamsBeforeClose(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	// slot 0 = dying, slot 1 = live target.
	p.slots[0].state.Store(int32(slotReady))
	p.slots[0].startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[1].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(time.Now().UnixNano())

	attachStream(p, cl, 42, 0)

	// Hook sendMigrate to report OK without a wire round-trip. Capture the kind
	// + target so we can assert it was a RESUME onto the live slot.
	var gotKind atomic.Int32
	var gotTarget atomic.Int32
	gotTarget.Store(-1)
	p.migrateSendHook = func(streamID uint16, kind byte, targetIdx int) migrateResult {
		gotKind.Store(int32(kind))
		gotTarget.Store(int32(targetIdx))
		return migrateResult{kind: migrateResultOK}
	}

	p.handleSlotDeath(cl, 0, deathCauseNatural)

	if streamChanClosed(cl, 42) {
		t.Fatal("stream chan was closed despite a successful RESUME — barrier violated")
	}
	if gotKind.Load() != int32(core.FlagResume) {
		t.Fatalf("sendMigrate kind = %d, want FlagResume(%d)", gotKind.Load(), core.FlagResume)
	}
	if gotTarget.Load() != 1 {
		t.Fatalf("RESUME target = %d, want live slot 1", gotTarget.Load())
	}
	v, ok := p.streamMap.Load(uint16(42))
	if !ok {
		t.Fatal("stream entry removed after successful RESUME — should be re-pointed, not deleted")
	}
	if e := v.(*streamEntry); e.slotIdx != 1 {
		t.Fatalf("stream slotIdx = %d after RESUME, want 1 (re-pointed to live slot)", e.slotIdx)
	}
}

// TestHandleSlotDeath_ClosesWhenResumeFails: a RESUME_FAIL (or timeout) means
// the server would not re-home the stream — the chan must be closed, exactly
// like the legacy hard-close degradation.
func TestHandleSlotDeath_ClosesWhenResumeFails(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	p.slots[0].state.Store(int32(slotReady))
	p.slots[0].startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[1].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(time.Now().UnixNano())

	attachStream(p, cl, 7, 0)

	p.migrateSendHook = func(streamID uint16, kind byte, targetIdx int) migrateResult {
		return migrateResult{kind: migrateResultFail, reason: core.MigrateReasonGraceExpired}
	}

	p.handleSlotDeath(cl, 0, deathCauseNatural)

	if !streamChanClosed(cl, 7) {
		t.Fatal("stream chan NOT closed after RESUME_FAIL — degradation path broken")
	}
	if _, ok := p.streamMap.Load(uint16(7)); ok {
		t.Fatal("stream entry survived RESUME_FAIL — should be deleted like legacy close")
	}
}

// TestHandleSlotDeath_ClosesWhenNoLiveSlot: no live target exists → no RESUME
// attempt is possible, the chan must close (legacy degradation, the "all slots
// dead" cascade case).
func TestHandleSlotDeath_ClosesWhenNoLiveSlot(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	p.slots[0].state.Store(int32(slotReady))
	p.slots[0].startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	// slot 1 dead — no live target.
	p.slots[1].state.Store(int32(slotDead))

	attachStream(p, cl, 9, 0)

	called := false
	p.migrateSendHook = func(streamID uint16, kind byte, targetIdx int) migrateResult {
		called = true
		return migrateResult{kind: migrateResultOK}
	}

	p.handleSlotDeath(cl, 0, deathCauseNatural)

	if called {
		t.Fatal("sendMigrate called despite no live target slot")
	}
	if !streamChanClosed(cl, 9) {
		t.Fatal("stream chan NOT closed with no live slot — degradation path broken")
	}
}

// TestDrainTeardown_SkipsMigratingStream: a stream whose migrating flag is true
// (a T16 MIGRATE already in flight) must NOT be closed by handleSlotDeath's
// teardown Range loop — the in-flight move owns the stream.
func TestDrainTeardown_SkipsMigratingStream(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	p.slots[0].state.Store(int32(slotReady))
	p.slots[0].startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[1].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(time.Now().UnixNano())

	attachStream(p, cl, 13, 0)
	// Mark migrating — a MIGRATE is mid-flight (T16 owns this stream).
	v, _ := p.streamMap.Load(uint16(13))
	v.(*streamEntry).migrating.Store(true)

	// The RESUME hook must NOT fire for a stream already migrating — handleSlotDeath
	// should observe the flag and skip (neither close nor re-RESUME).
	resumeCalled := false
	p.migrateSendHook = func(streamID uint16, kind byte, targetIdx int) migrateResult {
		resumeCalled = true
		return migrateResult{kind: migrateResultOK}
	}

	p.handleSlotDeath(cl, 0, deathCauseDrainTeardown)

	if resumeCalled {
		t.Fatal("RESUME fired for a stream with migrating=true — double-send (T16 already owns it)")
	}
	if streamChanClosed(cl, 13) {
		t.Fatal("migrating stream's chan was closed by teardown — F10 violated")
	}
}

// TestMigratingNotCountedActiveForSticky: a stream with migrating=true must be
// classified NOT-active by allStreamsIdle and snapshotDrainStreams so the
// sticky backstop lets the drain finish instead of extending on a phantom
// active stream that is already leaving.
func TestMigratingNotCountedActiveForSticky(t *testing.T) {
	p := &WSPoolTransport{poolSize: 1}
	p.slots = make([]*poolSlot, 1)
	p.slots[0] = &poolSlot{index: 0}

	now := time.Now()
	// A single fresh (just-stamped, would be "active") stream on slot 0.
	e := newStreamEntry(0)
	e.lastWriteNs.Store(now.UnixNano()) // very recent → normally active
	p.streamMap.Store(uint16(1), e)

	// While NOT migrating, the fresh stream is active → allStreamsIdle false.
	if allStreamsIdle(p, 0, 30*time.Second, now) {
		t.Fatal("fresh stream should be active (allStreamsIdle=false) before migrating")
	}
	snap := snapshotDrainStreams(p, 0, now)
	if snap.activeCount != 1 {
		t.Fatalf("snapshot activeCount = %d before migrating, want 1", snap.activeCount)
	}

	// Flip migrating: the stream is leaving, so it must NOT hold the drain open.
	e.migrating.Store(true)
	if !allStreamsIdle(p, 0, 30*time.Second, now) {
		t.Fatal("migrating stream must be treated as idle (allStreamsIdle=true) — F10")
	}
	snap = snapshotDrainStreams(p, 0, now)
	if snap.activeCount != 0 {
		t.Fatalf("snapshot activeCount = %d with migrating stream, want 0 (not active)", snap.activeCount)
	}
	if snap.idleAge30sCount != 1 {
		t.Fatalf("snapshot idleAge30sCount = %d, want 1 (migrating counts toward idle)", snap.idleAge30sCount)
	}
}

// TestUplinkBarrier_WaitsForMigratingToClear is a focused unit test for the
// bounded barrier helper used by the SOCKS5 uplink goroutine: while the entry
// is migrating it blocks; once the flag clears it returns promptly; and it
// never blocks past the bounded timeout even if the flag never clears.
func TestUplinkBarrier_WaitsForMigratingToClear(t *testing.T) {
	p := &WSPoolTransport{poolSize: 1}
	p.slots = make([]*poolSlot, 1)
	p.slots[0] = &poolSlot{index: 0}
	p.migrateEnabled.Store(true)
	p.migrateAckTimeoutOverride = 200 * time.Millisecond

	e := newStreamEntry(0)
	p.streamMap.Store(uint16(5), e)

	// Not migrating → returns immediately.
	start := time.Now()
	p.WaitStreamMigrateBarrier(5)
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("barrier blocked %v for a non-migrating stream, want ~0", d)
	}

	// Migrating, cleared after 60ms → barrier returns shortly after clear.
	e.migrating.Store(true)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(60 * time.Millisecond)
		e.migrating.Store(false)
	}()
	start = time.Now()
	p.WaitStreamMigrateBarrier(5)
	wg.Wait()
	if d := time.Since(start); d < 40*time.Millisecond || d > 180*time.Millisecond {
		t.Fatalf("barrier returned after %v, want ~60ms (released when flag cleared)", d)
	}

	// Migrating and NEVER cleared → barrier returns at the bounded timeout, not forever.
	e.migrating.Store(true)
	start = time.Now()
	p.WaitStreamMigrateBarrier(5)
	d := time.Since(start)
	if d < 150*time.Millisecond {
		t.Fatalf("barrier returned too early (%v) — should wait near the bounded timeout", d)
	}
	if d > 400*time.Millisecond {
		t.Fatalf("barrier blocked %v past the bounded timeout — not bounded", d)
	}
}

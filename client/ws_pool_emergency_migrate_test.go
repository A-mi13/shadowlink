package client

import (
	"sync/atomic"
	"testing"
	"time"
)

// ws_pool_emergency_migrate_test.go — spec 2026-06-01 emergency-evict-migrate.
//
// Tier-2 emergency eviction (tryEmergencyEvictMinStreamsSlot) must migrate a
// victim cell's active streams off the cell BEFORE tearing it down, instead of
// killing them unconditionally. Reuses the Bug#9 MIGRATE primitive
// (migrateStream) via the migrateSendHook seam. Eviction ALWAYS completes (the
// cell is always reclaimed) — streams that cannot be migrated die with the cell,
// exactly the pre-change behavior, so worst-case is never worse.
//
// Harness: newResumeTestPool + attachStream + migrateSendHook (migrate_resume_test.go).

// TestEmergencyEvict_MigratesActiveStreamsBeforeKill — victim with 2 active
// streams and a younger slotReady target. Hook returns OK. Both streams move
// OFF the victim; Migrated+=2, Killed+=0; victim torn down.
func TestEmergencyEvict_MigratesActiveStreamsBeforeKill(t *testing.T) {
	p, cl := newResumeTestPool(t, 3)
	// slot 0 = drain target (skipIdx). slot 1 = victim (min streams).
	// slot 2 = younger live migration target.
	now := time.Now()
	p.slots[0].state.Store(int32(slotReady))
	p.slots[0].startedAtNs.Store(now.Add(-5 * time.Minute).UnixNano())
	p.slots[0].streams.Store(5)
	p.slots[1].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(now.Add(-3 * time.Minute).UnixNano())
	p.slots[2].state.Store(int32(slotReady))
	p.slots[2].startedAtNs.Store(now.UnixNano()) // youngest → migration target
	// Target carries a high stream count so the victim (slot 1, 2 streams) is the
	// unique MIN among non-skip cells; selectYoungTargetSlot ignores streams and
	// still picks slot 2 as youngest live target.
	p.slots[2].streams.Store(9)

	attachStream(p, cl, 100, 1)
	attachStream(p, cl, 101, 1)

	p.migrateSendHook = func(streamID uint16, kind byte, targetIdx int) migrateResult {
		return migrateResult{kind: migrateResultOK}
	}

	beforeMig := Stats.EmergencyEvictMigratedTotal.Load()
	beforeActive := Stats.DrainForceEvictedActiveTotal.Load()

	ok := p.tryEmergencyEvictMinStreamsSlot(cl, 0)
	if !ok {
		t.Fatal("tryEmergencyEvictMinStreamsSlot returned false; expected eviction of victim slot 1")
	}

	if got := Stats.EmergencyEvictMigratedTotal.Load() - beforeMig; got != 2 {
		t.Errorf("EmergencyEvictMigratedTotal increment = %d, want 2", got)
	}
	// Both streams must now be bound to the target slot 2, not the victim.
	for _, sid := range []uint16{100, 101} {
		v, ok := p.streamMap.Load(sid)
		if !ok {
			t.Errorf("stream %d missing from streamMap after migration", sid)
			continue
		}
		if e := v.(*streamEntry); e.slotIdx == 1 {
			t.Errorf("stream %d still bound to victim slot 1 after migration", sid)
		}
	}
	// DrainForceEvictedActiveTotal is incremented by the startDrain caller, not
	// by tryEmergencyEvictMinStreamsSlot itself — assert it did NOT move here.
	if got := Stats.DrainForceEvictedActiveTotal.Load() - beforeActive; got != 0 {
		t.Errorf("DrainForceEvictedActiveTotal moved inside tryEmergencyEvict = %d, want 0 (caller owns it)", got)
	}
	// Victim cell torn down.
	p.reserveMu.Lock()
	victim := p.slots[1]
	p.reserveMu.Unlock()
	if victim != nil {
		t.Errorf("victim slot 1 should be nil after eviction; got %v", victim)
	}
}

// TestEmergencyEvict_UnmigratableStreamsFallThroughToTeardown — victim has
// active streams but NO younger target (the only other ready cell is the drain
// target skipIdx, already slotDraining, which selectYoungTargetSlot excludes).
// The preemptive pass migrates nothing (Migrated+=0); the streams fall through
// to handleSlotDeath, whose RESUME-on-death ALSO finds no target and closes
// them. Victim STILL torn down; returns true. No separate "killed" counter — the
// teardown owns the residual's fate.
func TestEmergencyEvict_UnmigratableStreamsFallThroughToTeardown(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	now := time.Now()
	// slot 0 = drain target (skipIdx). In the real startDrain flow the drain
	// target is ALREADY slotDraining (gate-6 CAS) by the time tier-2 eviction
	// runs, so selectYoungTargetSlot (slotReady-only) excludes it. Reproduce
	// that here so the victim's streams have NO live target to move onto.
	// slot 1 = victim. No other live slot exists.
	p.slots[0].state.Store(int32(slotDraining))
	p.slots[0].startedAtNs.Store(now.Add(-5 * time.Minute).UnixNano())
	p.slots[0].streams.Store(5)
	p.slots[1].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(now.Add(-3 * time.Minute).UnixNano())

	attachStream(p, cl, 200, 1)
	attachStream(p, cl, 201, 1)

	hookCalls := atomic.Int32{}
	p.migrateSendHook = func(streamID uint16, kind byte, targetIdx int) migrateResult {
		hookCalls.Add(1)
		return migrateResult{kind: migrateResultOK}
	}

	beforeMig := Stats.EmergencyEvictMigratedTotal.Load()

	ok := p.tryEmergencyEvictMinStreamsSlot(cl, 0)
	if !ok {
		t.Fatal("eviction must complete even when streams can't migrate; got false")
	}

	// No younger target anywhere → neither the preemptive migrateStream nor the
	// teardown's RESUME reaches sendMigrateOrHook (both bail at selectYoungTargetSlot).
	if hookCalls.Load() != 0 {
		t.Errorf("migrate hook called %d times; want 0 (no younger target)", hookCalls.Load())
	}
	if got := Stats.EmergencyEvictMigratedTotal.Load() - beforeMig; got != 0 {
		t.Errorf("EmergencyEvictMigratedTotal increment = %d, want 0", got)
	}
	// The residual streams were closed by handleSlotDeath's teardown.
	for _, sid := range []uint16{200, 201} {
		if !streamChanClosed(cl, sid) {
			t.Errorf("stream %d should be closed after eviction with no migration target", sid)
		}
	}
	p.reserveMu.Lock()
	victim := p.slots[1]
	p.reserveMu.Unlock()
	if victim != nil {
		t.Errorf("victim slot 1 should be nil after eviction; got %v", victim)
	}
}

// TestEmergencyEvict_PartialMigration — two streams, hook moves one (OK) and
// fails the other (FAIL) on BOTH the preemptive MIGRATE and the teardown RESUME.
// EmergencyEvictMigratedTotal counts only the one moved by the preemptive pass
// (300); the failed one (301) falls through to teardown and is closed there.
// Eviction completes.
func TestEmergencyEvict_PartialMigration(t *testing.T) {
	p, cl := newResumeTestPool(t, 3)
	now := time.Now()
	p.slots[0].state.Store(int32(slotReady))
	p.slots[0].startedAtNs.Store(now.Add(-5 * time.Minute).UnixNano())
	p.slots[0].streams.Store(5)
	p.slots[1].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(now.Add(-3 * time.Minute).UnixNano())
	p.slots[2].state.Store(int32(slotReady))
	p.slots[2].startedAtNs.Store(now.UnixNano())
	p.slots[2].streams.Store(9) // keep victim (slot 1) the unique MIN

	attachStream(p, cl, 300, 1) // will succeed
	attachStream(p, cl, 301, 1) // will fail

	p.migrateSendHook = func(streamID uint16, kind byte, targetIdx int) migrateResult {
		if streamID == 300 {
			return migrateResult{kind: migrateResultOK}
		}
		return migrateResult{kind: migrateResultFail}
	}

	beforeMig := Stats.EmergencyEvictMigratedTotal.Load()

	ok := p.tryEmergencyEvictMinStreamsSlot(cl, 0)
	if !ok {
		t.Fatal("eviction must complete; got false")
	}

	if got := Stats.EmergencyEvictMigratedTotal.Load() - beforeMig; got != 1 {
		t.Errorf("EmergencyEvictMigratedTotal increment = %d, want 1 (only stream 300 moved by preemptive pass)", got)
	}
	// Stream 300 migrated off the victim (re-pointed, chan kept open).
	if v, ok := p.streamMap.Load(uint16(300)); ok {
		if e := v.(*streamEntry); e.slotIdx == 1 {
			t.Error("stream 300 should have migrated off victim slot 1")
		}
	} else {
		t.Error("stream 300 missing from streamMap; should be re-pointed to live slot")
	}
	// Stream 301 failed both MIGRATE and RESUME → closed by teardown.
	if !streamChanClosed(cl, 301) {
		t.Error("stream 301 should be closed (failed migration + failed resume)")
	}
}

// TestEmergencyEvict_SkippedWhenMigrationIncapable — MigrateCapable() false
// (wire format not negotiated). No preemptive migration AND no teardown RESUME
// (handleSlotDeath gates RESUME on the same migrateEnabled flag). All streams
// closed; eviction still completes. Guards the no-flag fallback (== pre-2026-06-01
// unconditional kill).
func TestEmergencyEvict_SkippedWhenMigrationIncapable(t *testing.T) {
	p, cl := newResumeTestPool(t, 3)
	p.migrateEnabled.Store(false) // not negotiated → MigrateCapable() == false
	now := time.Now()
	p.slots[0].state.Store(int32(slotReady))
	p.slots[0].startedAtNs.Store(now.Add(-5 * time.Minute).UnixNano())
	p.slots[0].streams.Store(5)
	p.slots[1].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(now.Add(-3 * time.Minute).UnixNano())
	p.slots[2].state.Store(int32(slotReady))
	p.slots[2].startedAtNs.Store(now.UnixNano())
	p.slots[2].streams.Store(9) // keep victim (slot 1) the unique MIN

	attachStream(p, cl, 400, 1)
	attachStream(p, cl, 401, 1)

	hookCalls := atomic.Int32{}
	p.migrateSendHook = func(streamID uint16, kind byte, targetIdx int) migrateResult {
		hookCalls.Add(1)
		return migrateResult{kind: migrateResultOK}
	}

	beforeMig := Stats.EmergencyEvictMigratedTotal.Load()

	ok := p.tryEmergencyEvictMinStreamsSlot(cl, 0)
	if !ok {
		t.Fatal("eviction must complete; got false")
	}

	if hookCalls.Load() != 0 {
		t.Errorf("migrate hook called %d times; want 0 (migration incapable)", hookCalls.Load())
	}
	if got := Stats.EmergencyEvictMigratedTotal.Load() - beforeMig; got != 0 {
		t.Errorf("EmergencyEvictMigratedTotal increment = %d, want 0", got)
	}
	// All streams closed (no migration capability → pre-2026-06-01 behavior).
	for _, sid := range []uint16{400, 401} {
		if !streamChanClosed(cl, sid) {
			t.Errorf("stream %d should be closed when migration incapable", sid)
		}
	}
}

// TestEmergencyEvict_VictimMarkedDrainingDuringMigration — the victim must be in
// slotDraining when the migrate hook fires, proving (a) selectYoungTargetSlot
// can't pick the victim as a self-target and (b) AssignStream is fenced off the
// victim before its streams move.
func TestEmergencyEvict_VictimMarkedDrainingDuringMigration(t *testing.T) {
	p, cl := newResumeTestPool(t, 3)
	now := time.Now()
	p.slots[0].state.Store(int32(slotReady))
	p.slots[0].startedAtNs.Store(now.Add(-5 * time.Minute).UnixNano())
	p.slots[0].streams.Store(5)
	p.slots[1].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(now.Add(-3 * time.Minute).UnixNano())
	p.slots[2].state.Store(int32(slotReady))
	p.slots[2].startedAtNs.Store(now.UnixNano())
	p.slots[2].streams.Store(9) // keep victim (slot 1) the unique MIN

	attachStream(p, cl, 500, 1)

	var victimStateAtHook atomic.Int32
	victimStateAtHook.Store(-1)
	p.migrateSendHook = func(streamID uint16, kind byte, targetIdx int) migrateResult {
		victimStateAtHook.Store(int32(p.slots[1].getState()))
		return migrateResult{kind: migrateResultOK}
	}

	p.tryEmergencyEvictMinStreamsSlot(cl, 0)

	if got := slotState(victimStateAtHook.Load()); got != slotDraining {
		t.Errorf("victim state during migration = %v, want slotDraining (fenced before migrating its streams)", got)
	}
}

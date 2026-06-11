package client

import (
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// migrate_watchdog.go — Bug #9 Task 16. The "WHEN to migrate" trigger that
// rides the existing rotation watchdog (Tasks 7–15 built the "HOW").
//
// When a ready slot crosses its per-session migration threshold (age × jitter)
// AND the pool is MigrateCapable AND the slot has active streams, the watchdog
// schedules a preemptive MIGRATE of EACH active stream onto a younger live
// slot. The migrations are NOT fired as a synchronized burst — each stream's
// MIGRATE is delayed by an independent U(0,spread) offset so a middlebox does
// not observe "slot A goes quiet + slot B lights up" at the same instant
// (F7 §5.6). The aging slot keeps serving until its normal age/byte rotation
// or its streams drain — migration is ADDITIVE to the existing lifecycle, it
// does not replace rotation.
//
// Anti-DPI properties:
//   - Per-slot threshold = base × U(0.7,1.0): slots don't all start migrating
//     at the same offset-from-connect (no FFT periodicity at 1/threshold).
//   - Per-stream spread = U(0,8s): the streams of one slot scatter their moves
//     instead of clustering at one tick (no "synchronized handoff" signature).
//   - Effective threshold ≤ base (45s) < idx=0 age-cut (75s) < observed TSPU
//     freeze window (~130s): streams migrate while the aging TCP is still
//     healthy, with margin before the slot rotates.

const (
	// migrationThresholdDefault is the base slot age at which preemptive stream
	// migration begins. 45s leaves a 30s margin below the idx=0 age-cut at 75s
	// (SHADOWLINK_MAX_SLOT_AGE) so streams migrate off a slot before it rotates,
	// and stays well below the observed ~130s TSPU freeze window even at the
	// high end of the jitter band.
	migrationThresholdDefault = 45 * time.Second

	// migrationThresholdJitterLow is the low multiplier of the per-slot
	// threshold jitter band U(migrationThresholdJitterLow, 1.0).
	migrationThresholdJitterLow = 0.7

	// migrationSpreadDefault is the width of the per-stream U(0,spread) delay
	// applied when scheduling a slot's active streams for migration.
	migrationSpreadDefault = 8 * time.Second
)

// migrationThresholdBase resolves the base migration threshold from
// SHADOWLINK_MIGRATE_THRESHOLD (a Go duration string, e.g. "45s", "2m").
// Empty/unset or unparseable → migrationThresholdDefault. Non-positive →
// default (a zero/negative base would migrate immediately on connect).
func migrationThresholdBase() time.Duration {
	v := strings.TrimSpace(os.Getenv("SHADOWLINK_MIGRATE_THRESHOLD"))
	if v == "" {
		return migrationThresholdDefault
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return migrationThresholdDefault
	}
	return d
}

// migrationSpread resolves the per-stream migration spread from
// SHADOWLINK_MIGRATE_SPREAD (a Go duration string). Empty/unset or
// unparseable → migrationSpreadDefault. Non-positive → default.
func migrationSpread() time.Duration {
	v := strings.TrimSpace(os.Getenv("SHADOWLINK_MIGRATE_SPREAD"))
	if v == "" {
		return migrationSpreadDefault
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return migrationSpreadDefault
	}
	return d
}

// sampleMigrationThreshold draws the per-slot migration threshold in
// nanoseconds: base × U(migrationThresholdJitterLow, 1.0). Sampled ONCE per
// (re)connect in connectSlot and frozen in poolSlot.migrationThresholdNs —
// re-sampling per watchdog tick would let a slot near its threshold oscillate
// in/out of eligibility, the same anti-pattern slotStaggerOffset documents.
// base<=0 → 0 (migration trigger disabled for the slot).
//
// math/rand/v2's package Float64 is concurrent-safe and allocation-free.
func sampleMigrationThreshold(base time.Duration) int64 {
	if base <= 0 {
		return 0
	}
	span := 1.0 - migrationThresholdJitterLow
	multiplier := migrationThresholdJitterLow + rand.Float64()*span
	return int64(float64(base) * multiplier)
}

// sampleMigrationOffset draws a per-stream migration delay uniformly on
// [0, spread). Each active stream of an aging slot gets an independent draw so
// the migrations scatter across the spread window instead of firing as one
// synchronized burst (F7 §5.6). spread<=0 → 0 (fire immediately).
func sampleMigrationOffset(spread time.Duration) time.Duration {
	if spread <= 0 {
		return 0
	}
	return time.Duration(rand.Float64() * float64(spread))
}

// effectiveMigrationSpread returns the test override when set, else the
// env-resolved spread.
func (p *WSPoolTransport) effectiveMigrationSpread() time.Duration {
	if p.migrateSpreadOverride > 0 {
		return p.migrateSpreadOverride
	}
	return migrationSpread()
}

// selectYoungTargetSlot picks the migration target for a stream leaving the
// aging slot agingIdx: the YOUNGEST (largest startedAtNs) slot that is
// slotReady and != agingIdx. Returns (idx, true) on success, (0, false) when
// no eligible slot exists (the stream then stays on the aging slot and either
// migrates on a later tick or breaks when the slot dies — Task 17).
//
// Why youngest: migrating onto a slot that is itself about to cross its own
// migration/rotation threshold would just chain another move shortly after.
// The freshest slot has the most runway before its next lifecycle event.
//
// Lock-free: startedAtNs and state are atomics; a slot transitioning out of
// slotReady concurrently is simply not selected (or sendMigrate's
// slotForMigrate re-validates the target state at send time).
func (p *WSPoolTransport) selectYoungTargetSlot(agingIdx int) (int, bool) {
	best := -1
	var bestStart int64
	// Audit H1 (2026-06-11): iterate a reserveMu snapshot rather than indexing
	// p.slots live; sendMigrate's slotForMigrate re-validates the target at
	// send time, so a snapshot going stale here is harmless.
	for idx, slot := range p.snapshotSlots() {
		if idx == agingIdx {
			continue
		}
		if slot == nil || slot.getState() != slotReady {
			continue
		}
		started := slot.startedAtNs.Load()
		if started == 0 {
			continue // ready but never stamped — defensive, skip
		}
		if best == -1 || started > bestStart {
			best = idx
			bestStart = started
		}
	}
	if best == -1 {
		return 0, false
	}
	return best, true
}

// scheduleSlotMigration arms a per-stream migration timer for every active
// stream currently attached to the aging slot that has NOT yet been scheduled.
// Each stream's MIGRATE is delayed by an independent U(0,spread) offset (NOT a
// burst). Returns true if >=1 NEW stream was scheduled on this pass.
//
// Per-stream gate (replaces the old per-slot slot.migrationScheduled CAS). The
// watchdog re-invokes this every 5s while the slot is above threshold; each
// pass arms a timer only for streams not yet scheduled (per-stream CAS) and not
// already migrating. This covers streams that attached to the aging slot AFTER
// the first pass — the per-slot gate left them unscheduled.
//
// Concurrency: streamMap.Range visits each entry at most once (sync.Map
// contract). A stream released concurrently may or may not appear — a missing
// stream is simply not migrated (fine); a stale-slot entry is filtered by the
// e.slotIdx == agingIdx check. The AfterFunc closures capture streamID by value.
func (p *WSPoolTransport) scheduleSlotMigration(agingIdx int, slot *poolSlot) bool {
	if slot == nil {
		return false
	}
	spread := p.effectiveMigrationSpread()
	scheduled := 0
	p.streamMap.Range(func(key, value any) bool {
		e, ok := value.(*streamEntry)
		if !ok || e.slotIdx != agingIdx {
			return true
		}
		streamID, ok := key.(uint16)
		if !ok {
			return true
		}
		// Skip streams already migrating: an in-flight move owns the stream; a
		// second timer would short-circuit on the migrating CAS in migrateStream.
		if e.migrating.Load() {
			return true
		}
		// Per-stream single-winner: arm exactly one timer per stream per slot life.
		// The type-assert above is done BEFORE this CAS so a (theoretically
		// impossible) non-uint16 key never burns migrationScheduled and strands
		// the stream un-armed.
		if !e.migrationScheduled.CompareAndSwap(false, true) {
			return true
		}
		offset := sampleMigrationOffset(spread)
		time.AfterFunc(offset, func() {
			if p.migrateStreamHook != nil {
				p.migrateStreamHook(streamID)
				return
			}
			p.migrateStream(streamID)
		})
		scheduled++
		return true
	})

	if scheduled == 0 {
		return false
	}
	Stats.MigrateScheduled.Add(uint64(scheduled))
	return true
}

// migrateStream performs the actual preemptive MIGRATE for one stream: pick a
// young target slot, send a FlagMigrate, and on success re-bind the stream's
// streamMap entry to the target slot. On FAIL / timeout / no-send the stream is
// left on its current slot — it will be retried on a later watchdog tick or
// break naturally when the aging slot dies (graceful degradation, Task 17 adds
// the slot-death RESUME path).
//
// Called from the per-stream AfterFunc timers armed by scheduleSlotMigration,
// so it runs on its own goroutine and may block on sendMigrate's ack window.
func (p *WSPoolTransport) migrateStream(streamID uint16) {
	if !p.MigrateCapable() {
		return
	}
	v, ok := p.streamMap.Load(streamID)
	if !ok {
		return // stream already released
	}
	e, ok := v.(*streamEntry)
	if !ok {
		return
	}

	// Bug #9 Task 17, F10 single-winner gate: claim the move via CAS false→true.
	// If the flag is already set, another goroutine (a second watchdog timer, or
	// the slot-death RESUME path) owns this stream's move — stand down to avoid a
	// double MIGRATE/double counter-transfer. The uplink barrier (§5.3) keys off
	// this flag, so it raises the moment we win the CAS and falls the moment we
	// resolve the outcome below.
	if !e.migrating.CompareAndSwap(false, true) {
		return
	}
	// Clear on FAIL/timeout/no-send (stream stays put). On OK the rebind below
	// replaces the entry with a fresh one (migrating=false by default), so we
	// only need to clear on the not-OK paths — guarded so a successful rebind
	// does not resurrect a stale flag on the old entry.
	moved := false
	defer func() {
		if !moved {
			e.migrating.Store(false)
		}
	}()

	agingIdx := e.slotIdx

	targetIdx, ok := p.selectYoungTargetSlot(agingIdx)
	if !ok {
		return // no younger slot to move onto — leave the stream put
	}

	res := p.sendMigrateOrHook(streamID, core.FlagMigrate, targetIdx)
	if res.kind != migrateResultOK {
		// FAIL / timeout / no-send → degrade gracefully, stream stays on agingIdx.
		return
	}

	// Server accepted the move: re-bind the stream to the target slot AND
	// transfer the per-slot active-stream counter so the aging slot frees
	// cleanly. See rebindStreamToSlot for the counter-transfer invariant.
	// rebindStreamToSlot Stores a fresh streamEntry(targetIdx) with
	// migrating=false — the move is done, the uplink barrier on the OLD entry is
	// released and subsequent writes route to the new slot.
	p.rebindStreamToSlot(streamID, targetIdx)
	moved = true
}

// rebindStreamToSlot moves streamID's streamMap binding onto targetIdx and
// transfers the per-slot active-stream counter (poolSlot.streams) from the
// stream's CURRENT slot to targetIdx, preserving the strict Assign(+1)/
// Release(-1) invariant that AssignStream/ReleaseStream maintain (ws_pool.go
// §2451/§2538). Without the counter transfer the aging slot stays "occupied"
// (streams.Load()>0) after the stream has left — maybeRotateSlot/startDrain
// then keep deferring its rotation on phantom active streams (the opposite of
// what migration is for), and the target slot is undercounted so a later
// ReleaseStream of the migrated stream decrements without a paired increment
// and can drive its counter negative.
//
// Counter-transfer ordering (no window where the stream is "nowhere" or
// "double-counted long"):
//  1. inc target  — target is accounted before we publish the new binding,
//     so a concurrent snapshot never sees the moved stream on a slot whose
//     counter is still 0.
//  2. Store(newStreamEntry(targetIdx)) — re-bind. newStreamEntry stamps
//     lastWriteNs=now (the MIGRATE round-trip just had wire activity).
//  3. dec source — only AFTER the re-bind. Between (1) and (3) the stream is
//     transiently counted on both slots (over-count by one for ~ns), never
//     under-counted; over-counting cannot trip a negative or a premature
//     free, whereas a momentary 0 on the target could.
//
// Edge cases:
//   - Stream already gone (concurrent slot death / ReleaseStream): the Load
//     misses → no-op, we never touch a counter we didn't own.
//   - Stream already on targetIdx (race / repeat migration): no-op, so we
//     never double-increment the target or decrement a foreign slot.
//   - Source decrement uses the slotIdx read from the live streamMap entry
//     (NOT the agingIdx the watchdog planned against) — between scheduling
//     the AfterFunc and this call the stream may have migrated again or moved,
//     so we decrement exactly the slot the stream is leaving.
//   - handleSlotDeath does streams.Store(0) on death and Deletes the entry
//     first; if it ran concurrently our Load would miss (entry gone) → no-op,
//     so our Add never fights its Store.
func (p *WSPoolTransport) rebindStreamToSlot(streamID uint16, targetIdx int) {
	v, ok := p.streamMap.Load(streamID)
	if !ok {
		return // stream already released / slot died — nothing to transfer
	}
	e, ok := v.(*streamEntry)
	if !ok {
		return
	}
	srcIdx := e.slotIdx
	if srcIdx == targetIdx {
		return // already bound to target (race / repeat) — avoid double-count
	}

	// Spec 2026-06-01 (counter-leak fix, F1): capture BOTH slot pointers up
	// front under reserveMu — the same lock connectSlot holds when it swaps
	// p.slots[idx] with a fresh *poolSlot after a death. Mutating BY INDEX
	// (the old code) let a close-1006 reconnect replace the object at srcIdx
	// BETWEEN the inc and the dec, so the dec landed on the new zeroed object
	// while the inc stranded on the live target with no pairing dec → the
	// active_streams sum drifted upward (observed 1397 vs max 80). Capturing
	// pointers binds inc and dec to the SAME objects regardless of any
	// concurrent index re-occupation: if a captured object is later retired,
	// its counter no longer feeds the health sum, so a residual count on it is
	// inert.
	p.reserveMu.Lock()
	var srcSlot, dstSlot *poolSlot
	if targetIdx >= 0 && targetIdx < len(p.slots) {
		dstSlot = p.slots[targetIdx]
	}
	if srcIdx >= 0 && srcIdx < len(p.slots) {
		srcSlot = p.slots[srcIdx]
	}
	p.reserveMu.Unlock()

	// (1) inc target before publishing the binding.
	if dstSlot != nil {
		dstSlot.streams.Add(1)
	}
	// (2) re-bind so subsequent uplink writes / routing target the new slot.
	p.streamMap.Store(streamID, newStreamEntry(targetIdx))
	// (3) dec the captured src object — floor-clamped so a historical mismatch
	// can never drive it negative.
	if srcSlot != nil {
		decStreamsFloor(srcSlot)
	}
}

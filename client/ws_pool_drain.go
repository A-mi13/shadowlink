package client

import (
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/client/slotobs"
)

const (
	// drainPollInterval — drainWatchdog tick rate when checking if active
	// streams have drained naturally.
	drainPollInterval = 500 * time.Millisecond

	// stickyRecheckInterval is how often the deadline branch re-evaluates an
	// extended (sticky) drain (Bug #6). Must be >= drainPollInterval so the ticker
	// idle/streams-zero branch catches natural finish between rechecks (spec L3).
	// 5s keeps lifetime overshoot small vs the 10m age backstop.
	stickyRecheckInterval = 5 * time.Second

	// drainRevertBackoff — backoff after startDrain failed because
	// claimFreeSlot returned -1 (slice fully occupied). Genuine resource
	// exhaustion, retry slowly.
	drainRevertBackoff = 30 * time.Second

	// drainStormBrakeBackoff — backoff after storm-brake deferral in
	// non-catastrophic state (readyCapacity >= poolSize/2). Equal to one
	// rotation watchdog tick (currently 5s — verified at T7) so the next
	// sweep re-evaluates immediately. Cheap to retry: readyCapacity() is
	// O(2*poolSize) integer compare. Spec 2026-05-20 §2.4.2 (W6 review
	// fix). If the watchdog interval changes in the future, update this
	// constant to match.
	drainStormBrakeBackoff = 5 * time.Second

	// drainCatastrophicBackoff — backoff when readyCapacity dropped below
	// poolSize/2 (more than half the pool is dead/connecting). Long
	// backoff to let reconnectLoop heal capacity without tight retry
	// loops that would just spin against the storm brake. Spec 2026-05-20
	// §2.1.1 (C2 review fix). 5x drainRevertBackoff is the spec-mandated
	// multiplier — see §2.1.1.
	drainCatastrophicBackoff = 150 * time.Second

	// drainDeferredLogInterval — minimum wall-clock gap between two
	// consecutive INFO emissions of "drain deferred" for the SAME gate.
	// Counters always increment; only the human-readable log is
	// rate-limited. 30s chosen to surface temporal trends (peaks/valleys)
	// without log spam — the 2026-05-24 session (12326 deferrals over
	// 4h52m) would have produced ~10 INFO lines per gate.
	// Spec 2026-05-24 (drain-diagnostics-counter-split).
	drainDeferredLogInterval = 30 * time.Second

	// hardCapWarnThreshold — minimum remaining_streams for a hard-cap
	// teardown to log at WARN level. Below this threshold the teardown
	// logs INFO.
	//
	// Rationale: hard cap with remaining_streams=1-2 is expected
	// steady-state behaviour under long-lived SOCKS sessions (uplinks
	// of 4-10min seen regularly in real traffic). Session 2026-05-24
	// distribution (272 hard-cap events, disjoint buckets):
	//   remaining=1:   96 (35.3%)
	//   remaining=2:   153 (56.3%)
	//   remaining=3-4: 17 (6.3%)
	//   remaining>=5:  6 (2.2%)
	// Threshold=5 keeps ~98% at INFO, surfacing only outliers as WARN.
	// Spec 2026-05-24 (drain-diagnostics-counter-split) §4.
	hardCapWarnThreshold int32 = 5

	// reserveConnectInitialBackoff — first delay after connectReserveSlot
	// fails, before spawning reconnectLoop. Doubled on each consecutive
	// failure up to reserveConnectMaxBackoff. Spec 2026-05-24
	// (concurrency-lift-and-backoff) §2.
	reserveConnectInitialBackoff = 500 * time.Millisecond

	// reserveConnectMaxBackoff — ceiling for connectReserveSlot
	// exponential backoff. Equal to drainRevertBackoff (30s) for symmetry
	// with the existing "slice full" retry timeline. Spec 2026-05-24.
	reserveConnectMaxBackoff = 30 * time.Second

	// reserveConnectBackoffJitterFraction — ±20% jitter applied to the
	// computed backoff to avoid thundering herd when multiple slots fail
	// simultaneously (e.g. cascade TIME_WAIT exhaustion under upload
	// load). Spec 2026-05-24.
	reserveConnectBackoffJitterFraction = 0.2
)

// shouldLogDeferred returns true if at least drainDeferredLogInterval has
// elapsed since the last INFO log for the gate represented by `last`.
// Atomic CAS guarantees at-most-one-winner semantics under concurrent
// calls — no mutex needed. The `now` parameter is passed explicitly so
// tests can inject deterministic timestamps without monkey-patching
// time.Now() globally.
//
// Returns true ≤1 time per drainDeferredLogInterval per `last`; counters
// are NOT touched here and must increment unconditionally at the call
// site (see spec §2). The returned bool gates ONLY the log call.
//
// Spec 2026-05-24 (drain-diagnostics-counter-split).
func shouldLogDeferred(last *atomic.Int64, now time.Time) bool {
	prev := last.Load()
	threshold := now.Add(-drainDeferredLogInterval).UnixNano()
	if prev > threshold {
		return false
	}
	return last.CompareAndSwap(prev, now.UnixNano())
}

// computeReserveBackoff returns an exponential backoff delay for the
// connectReserveSlot retry path, capped at reserveConnectMaxBackoff and
// jittered ±20% to break synchrony across cells.
//
// failures: consecutive failure count for this cell (1-based — 1 means
// "first failure", 2 means "second failure", etc.). Caller passes the
// value AFTER incrementing the counter, so failures=1 produces the
// initial backoff (500ms ± jitter), failures=2 produces 1s ± jitter,
// and so on, doubling until the 30s ceiling.
//
// The rng parameter returns float64 in [0.0, 1.0); production passes
// rand.Float64 (math/rand/v2). Tests pass a deterministic function to
// pin the jitter value.
//
// Spec 2026-05-24 (concurrency-lift-and-backoff) §2.
func computeReserveBackoff(failures int32, rng func() float64) time.Duration {
	if failures < 1 {
		failures = 1
	}
	// Cap shift to avoid int64 overflow at very high failure counts.
	// At failures=31 (shift=30) we have 500ms<<30 = 5.36e17ns, still
	// well below MaxInt64 = 9.22e18, but the >max check kicks in earlier.
	const maxShift = 30
	shift := failures - 1
	if shift > maxShift {
		shift = maxShift
	}
	delay := reserveConnectInitialBackoff << shift
	// `delay > reserveConnectMaxBackoff` is the hot path that caps the
	// ladder. `delay <= 0` is currently unreachable: maxShift=30 gives at
	// most 500ms<<30 = 5.36e17ns < MaxInt64. Kept as defence against
	// future changes to maxShift, reserveConnectInitialBackoff, or the
	// underlying time.Duration int64 width.
	if delay > reserveConnectMaxBackoff || delay <= 0 {
		delay = reserveConnectMaxBackoff
	}
	// Apply ±20% jitter. rng returns [0.0, 1.0); map to [-0.2, +0.2).
	jitterFrac := (rng() - 0.5) * 2 * reserveConnectBackoffJitterFraction
	jittered := time.Duration(float64(delay) * (1.0 + jitterFrac))
	if jittered < 0 {
		jittered = 0
	}
	return jittered
}

// claimFreeSlot atomically reserves the first nil cell anywhere in
// p.slots (uniform-cells design — spec 2026-05-20 §2.2). Returns the
// claimed index, or -1 if no nil cell exists.
//
// Under p.reserveMu so concurrent startDrain calls cannot pick the
// same idx. The critical section is tiny (linear scan + 2 atomic
// writes); contention is bounded by inflightDrains cap.
//
// connectReserveSlot's subsequent connectSlot call will overwrite the
// placeholder *poolSlot installed here. Scan starts at index 0 so
// post-teardown primary cells are recyclable as drain replacements
// (replaces old [poolSize, 2*poolSize) reserve-range scan).
func (p *WSPoolTransport) claimFreeSlot() int {
	p.reserveMu.Lock()
	defer p.reserveMu.Unlock()
	for i := 0; i < len(p.slots); i++ {
		if p.slots[i] == nil {
			slot := &poolSlot{}
			slot.setState(slotConnecting)
			p.slots[i] = slot
			return i
		}
	}
	return -1
}

// emergencyEvictAgeMultiplier — the drain target's age threshold for
// authorizing an emergency eviction of an active-stream cell. When the
// drain target has been waiting through 2× its maxSlotAge (≈ 4 min
// at default 2-min maxSlotAge), the anti-fingerprint cost of further
// delay exceeds the UX cost of killing one stream's worth of SOCKS5
// flows. Spec 2026-05-20 §2.2.3 (emergency eviction).
const emergencyEvictAgeMultiplier = 2

// emergencyEvictMigrateBudget bounds the TOTAL time spent migrating an
// emergency-eviction victim's streams before its forced teardown
// (spec 2026-06-01 emergency-evict-migrate). startDrain runs the eviction
// synchronously, so an unbounded per-stream ack sum could stall the rotation
// watchdog; this caps the whole victim-migration pass. One migrateAckTimeout
// covers the common 1-3 streams/victim (tier-2 picks the MIN-streams cell);
// streams not moved within the budget die with the cell — exactly the
// pre-2026-06-01 behavior, so worst-case is never worse than the status quo.
const emergencyEvictMigrateBudget = migrateAckTimeout

// tryForceEvictIdleSlot scans the slice for a slotReady cell with
// streams.Load() == 0 and, if found, force-tears it down via
// handleSlotDeath(deathCauseDrainTeardown) — freeing the cell for the
// next claimFreeSlot call. Skips skipIdx (the drain target; usually
// already slotDraining, defensive). Returns true if a cell was evicted.
//
// Rationale (spec 2026-05-20 §2.2.3): in long-running sessions with
// stable network, all 2*poolSize cells stay alive past natural
// rotation — claimFreeSlot starves indefinitely and anti-fingerprint
// rotation freezes. Force-evicting an idle cell breaks the deadlock
// without disturbing active streams.
//
// Idle-only policy: a slot with active streams hosts live SOCKS5
// flows. Evicting it would close their streamChans uniformly,
// terminating user-visible connections. Better to defer the drain
// than to kill active streams.
//
// Race-vs-AssignStream: AssignStream does NOT take reserveMu — it
// filters on slotReady state then calls streams.Add(1) unlocked. To
// prevent killing a stream that arrived between our streams==0 read
// and CAS, we (a) CAS to slotDraining first (so AssignStream's next
// pass excludes the slot), then (b) re-load streams.Load() — if a
// stream landed in the CAS window, revert the slot to slotReady and
// bail. The recheck closes the race without taking AssignStream's
// hot path under a lock.
//
// generation.Add(1) before handleSlotDeath: matches drainWatchdog's
// tearDown contract — the victim's slotReader sees gen mismatch and
// exits silently via shouldExitReader, avoiding false-positive
// ReaderExits / FrameAnomaly counter inflation when handleSlotDeath
// closes the transport (which would otherwise surface as a "natural"
// read error).
func (p *WSPoolTransport) tryForceEvictIdleSlot(cl *Client, skipIdx int) bool {
	// Audit H1/L3 (2026-06-11): scan a snapshot taken under reserveMu rather
	// than indexing p.slots live (which raced the lifecycle writers). The CAS
	// on the captured slot below is the authoritative claim; a cell nilled
	// after the snapshot simply loses the CAS or is skipped on the next tick.
	for i, s := range p.snapshotSlots() {
		if i == skipIdx {
			continue
		}
		if s == nil {
			continue
		}
		if s.getState() != slotReady {
			continue
		}
		if s.streams.Load() != 0 {
			continue
		}
		// Try to claim this victim via CAS slotReady→slotDraining. Lost
		// races (concurrent evictor or drain on this same cell) skip to
		// the next candidate.
		if !s.tryMarkDraining() {
			continue
		}
		// Recheck streams under the post-CAS happens-before edge: any
		// AssignStream that observed slotReady before our CAS would have
		// completed streams.Add(1) by now if its picker chose this slot.
		// If we see a non-zero count, revert and try another candidate
		// (do NOT evict an active-stream slot).
		if s.streams.Load() != 0 {
			// Revert via CAS — drainWatchdog or another evictor may have
			// raced us to slotDead; only revert if we still own slotDraining.
			s.state.CompareAndSwap(int32(slotDraining), int32(slotReady))
			continue
		}

		p.log.Info("WS pool drain force-evicted idle slot",
			"evicted_slot", i,
			"for_drain_of", skipIdx)

		// Bump generation so the victim's slotReader exits silently
		// via shouldExitReader when transport.Close in handleSlotDeath
		// surfaces as a read error.
		s.generation.Add(1)
		// Наша смена слота — в выборку плановых, как и дренаж (см.
		// recordPlannedRotation). Пропуск занижал бы знаменатель hazard и
		// завышал Rate.
		p.recordPlannedRotation(s)
		// handleSlotDeath takes reserveMu internally to nil the cell.
		p.handleSlotDeath(cl, i, deathCauseDrainTeardown)
		return true
	}
	return false
}

// tryEmergencyEvictMinStreamsSlot is the second-tier eviction path
// invoked when (a) tryForceEvictIdleSlot found no idle candidate AND
// (b) the drain target's slot age exceeds emergencyEvictAgeMultiplier
// × maxSlotAge. Under those two conditions, the pool has been stuck
// long enough that further delay damages the anti-fingerprint goal
// more than the UX cost of killing one cell's worth of streams.
//
// Selection: scan the slice for slotReady cells, pick the one with
// the lowest streams.Load() (minimizes collateral damage). Skip
// skipIdx. If multiple cells share the min, the first one wins
// (deterministic, slice-order).
//
// CAS + generation bump + handleSlotDeath mirror the idle path;
// the only difference is we do NOT recheck streams.Load() after CAS
// because we explicitly accept evicting active streams here.
//
// Returns true if a cell was evicted. Returns false only if no
// slotReady cell exists at all (rare; usually means pool is in
// catastrophic state and capacity-floor gate should have fired
// already).
func (p *WSPoolTransport) tryEmergencyEvictMinStreamsSlot(cl *Client, skipIdx int) bool {
	bestIdx := -1
	var victim *poolSlot
	bestStreams := int32(1<<31 - 1)
	// Audit H1/L3 (2026-06-11): scan a reserveMu snapshot and capture the
	// winning *poolSlot from that snapshot rather than re-reading
	// p.slots[bestIdx] live afterwards (which raced the lifecycle writers and
	// could return a different object than the one we scored).
	for i, s := range p.snapshotSlots() {
		if i == skipIdx {
			continue
		}
		if s == nil {
			continue
		}
		if s.getState() != slotReady {
			continue
		}
		st := s.streams.Load()
		if st < bestStreams {
			bestStreams = st
			bestIdx = i
			victim = s
		}
	}
	if bestIdx < 0 || victim == nil {
		return false
	}

	if !victim.tryMarkDraining() {
		// Lost the race — pick may have been claimed by a concurrent
		// startDrain. Caller will defer; the next watchdog tick re-tries.
		return false
	}

	streamsAtEvict := victim.streams.Load()

	// Spec 2026-06-01: before tearing the victim down, PREEMPTIVELY migrate its
	// active streams onto a live slot while the victim's TCP is still healthy.
	// The victim is already slotDraining (tryMarkDraining above), so
	// selectYoungTargetSlot — which only returns slotReady slots — can never pick
	// it as a self-target, and AssignStream is fenced off it. Gated by
	// MigrateCapable(): when migration is unavailable (not negotiated /
	// hysteresis-disabled) this is skipped and behavior is identical to the
	// pre-2026-06-01 unconditional kill.
	//
	// Why this is NOT redundant with the RESUME-on-death below: handleSlotDeath
	// (deathCauseDrainTeardown) already attempts a grace RESUME for each surviving
	// stream — but only AFTER transport.Close(), relying on the server's orphan
	// grace window. The preemptive MIGRATE here moves the stream while the aging
	// TCP is still up, eliminating the close→RESUME gap and the grace-window
	// dependency for streams that have a younger slot to move onto NOW. Whatever
	// this pass does not move falls through to handleSlotDeath's RESUME attempt
	// (counted there as MigrateResumeOnDeathOK/Fail) — so we deliberately do NOT
	// emit a separate "killed" counter here, which would double-count streams the
	// teardown's RESUME still rescues.
	migrated := 0
	if p.MigrateCapable() {
		migrated = p.migrateVictimStreams(bestIdx)
	}
	if migrated > 0 {
		Stats.EmergencyEvictMigratedTotal.Add(uint64(migrated))
	}
	// remaining = streams still on the victim after the preemptive pass; their
	// fate (RESUME survive vs close) is decided by handleSlotDeath below.
	remaining := victim.streams.Load()
	if remaining < 0 {
		remaining = 0 // defensive — counter never legitimately goes negative
	}

	p.log.Warn("WS pool drain emergency-evicted slot with active streams",
		"evicted_slot", bestIdx,
		"for_drain_of", skipIdx,
		"streams_at_evict", streamsAtEvict,
		"migrated", migrated,
		"remaining", remaining)

	victim.generation.Add(1)
	// Наша смена слота — в выборку плановых (см. recordPlannedRotation).
	p.recordPlannedRotation(victim)
	p.handleSlotDeath(cl, bestIdx, deathCauseDrainTeardown)
	return true
}

// migrateVictimStreams attempts to migrate every active stream currently bound
// to the emergency-eviction victim cell (victimIdx) onto a live slot, reusing
// the Bug#9 migrateStream primitive. It runs synchronously under a single
// emergencyEvictMigrateBudget deadline so the caller (startDrain, on its own
// goroutine) is never stalled by a slow/silent server. Returns the number of
// streams that actually left the victim (a successful rebind).
//
// Why count by binding-departure (not migrateStream's outcome): migrateStream
// has no return value and may stand down on its single-winner CAS when the
// preemptive watchdog already armed the same stream's move — in that case the
// stream still legitimately leaves the victim and must count as saved. So we
// snapshot each stream's pre-migration slotIdx and re-read it after: a binding
// that no longer names victimIdx is a save.
//
// Snapshot-then-migrate: we collect the victim's stream IDs first (a single
// streamMap.Range), then migrate outside the Range — migrateStream mutates the
// streamMap (rebind), which must not happen mid-Range. Streams that release
// concurrently between snapshot and migrate are handled by migrateStream's
// own Load-miss (no-op) and by the post-read finding the entry gone (not
// counted as migrated, not counted as killed beyond the victim's live counter).
func (p *WSPoolTransport) migrateVictimStreams(victimIdx int) int {
	var victimIDs []uint16
	p.streamMap.Range(func(key, value any) bool {
		e, ok := value.(*streamEntry)
		if !ok || e.slotIdx != victimIdx {
			return true
		}
		if sid, ok := key.(uint16); ok {
			victimIDs = append(victimIDs, sid)
		}
		return true
	})

	deadline := time.Now().Add(emergencyEvictMigrateBudget)
	migrated := 0
	for _, sid := range victimIDs {
		if time.Now().After(deadline) {
			break // bounded — do not stall startDrain on the remaining streams
		}
		p.migrateStream(sid)
		// Did the binding actually leave the victim?
		v, ok := p.streamMap.Load(sid)
		if !ok {
			continue // stream released concurrently — not a migration we own
		}
		e, ok := v.(*streamEntry)
		if !ok {
			continue
		}
		if e.slotIdx != victimIdx {
			migrated++
		}
	}
	return migrated
}

// drainTargetOverAged returns true when oldSlot's age exceeds
// emergencyEvictAgeMultiplier × maxSlotAge. Used to gate the
// emergency-eviction path.
func (p *WSPoolTransport) drainTargetOverAged(oldSlot *poolSlot) bool {
	if p.maxSlotAge <= 0 {
		return false
	}
	started := oldSlot.startedAtNs.Load()
	if started == 0 {
		return false
	}
	age := time.Now().UnixNano() - started
	threshold := int64(emergencyEvictAgeMultiplier) * p.maxSlotAge.Nanoseconds()
	return age >= threshold
}

// startDrain transitions p.slots[oldIdx] from slotReady to slotDraining
// and spawns parallel connect-replacement + drain-watchdog goroutines.
//
// Gate ordering (spec 2026-05-20 §2.1, §2.1.0):
//  1. Feature flag off → no-op.
//  2. oldIdx out of range → no-op.
//  3. oldSlot nil → no-op.
//  4. Inflight cap gate (atomic): increment, check, hand off on success
//     OR back out + defer on failure.
//  5. Capacity floor gate (secondary, catches catastrophic state).
//  6. tryMarkDraining CAS.
//  7. claimFreeSlot.
//  8. Spawn connectReserveSlot + drainWatchdog.
//
// `reason`: "age", "byte_budget", or "anti_fingerprint".
func (p *WSPoolTransport) startDrain(cl *Client, oldIdx int, reason string) {
	if !p.gracefulDrain {
		return
	}
	if oldIdx < 0 || oldIdx >= len(p.slots) {
		return
	}
	// Audit H1 (2026-06-11): capture under reserveMu via slotAt rather than an
	// unguarded p.slots[oldIdx] read that races the lifecycle writers.
	oldSlot := p.slotAt(oldIdx)
	if oldSlot == nil {
		return
	}

	// Gate 4: inflight cap (atomic — see spec §2.1.0). Increment FIRST so
	// concurrent triggers cannot all observe the same low count.
	inflight := p.inflightDrains.Add(1)
	committed := false
	defer func() {
		if !committed {
			p.inflightDrains.Add(-1)
		}
	}()
	if int(inflight) > p.maxConcurrentDrains() {
		Stats.InflightCapDeferredTotal.Add(1)
		p.bumpDrainDeferrals1m()
		// INFO with per-gate 30s rate-limit (spec 2026-05-24). Counters
		// above always increment; only the log line is rate-limited so
		// production logs stay readable. total_count in the log line
		// gives readers the real rate via delta between successive INFOs.
		if shouldLogDeferred(&p.lastInflightCapLogNs, time.Now()) {
			p.log.Info("WS pool slot drain deferred (inflight cap)",
				"slot", oldIdx, "reason", reason,
				"inflight", inflight,
				"max_concurrent", p.maxConcurrentDrains(),
				"total_count", Stats.InflightCapDeferredTotal.Load(),
				"deferred_1m", p.drainDeferrals1m.Load())
		}
		// Storm-brake-only deferral — fast retry.
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainStormBrakeBackoff).UnixNano())
		return
	}

	// Gate 5: capacity floor (catches natural-death depletion that
	// inflightDrains doesn't track).
	ready := p.readyCapacity()
	floor := p.readyCapacityFloor()
	if ready < floor {
		Stats.CapacityFloorDeferredTotal.Add(1)
		p.bumpDrainDeferrals1m()
		// Catastrophic state (less than half pool ready) → longer backoff
		// so reconnectLoop has time to heal capacity (spec §2.1.1).
		backoff := drainStormBrakeBackoff
		if ready < p.poolSize/2 {
			backoff = drainCatastrophicBackoff
		}
		// INFO with per-gate 30s rate-limit (spec 2026-05-24). See
		// inflight-cap branch above for rationale.
		if shouldLogDeferred(&p.lastCapacityFloorLogNs, time.Now()) {
			p.log.Info("WS pool slot drain deferred (capacity floor)",
				"slot", oldIdx, "reason", reason,
				"ready_capacity", ready,
				"floor", floor,
				"backoff", backoff,
				"total_count", Stats.CapacityFloorDeferredTotal.Load(),
				"deferred_1m", p.drainDeferrals1m.Load())
		}
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(backoff).UnixNano())
		return
	}

	// Gate 6: CAS slotReady → slotDraining.
	if !oldSlot.tryMarkDraining() {
		return
	}

	// Gate 7: claim a free cell ANYWHERE in the slice.
	newIdx := p.claimFreeSlot()
	if newIdx < 0 {
		// Slice fully occupied — under stable-network long-running
		// sessions this is the deadlock state: no reader errors to
		// trigger natural cell teardown, no free cell for the next
		// drain. Spec 2026-05-20 §2.2.3 (slice-full eviction policy).
		//
		// Two-tier eviction policy:
		//
		// Tier 1 (always tried) — force-evict an idle slotReady cell
		// (streams==0). Active streams on a slot would die uniformly
		// via closed streamChans if we evict, so the idle path never
		// disrupts user-visible flows.
		//
		// Tier 2 (only when drain target is over-aged) — emergency
		// eviction of the cell with the LOWEST active stream count,
		// even if non-zero. Triggered when oldSlot has been waiting
		// through 2× maxSlotAge: at that point the anti-fingerprint
		// cost of further delay (TSPU ML window) exceeds the UX cost
		// of killing one cell's worth of streams. Field canary
		// 2026-05-20 second run (174716): under dense load (5+ streams/
		// slot avg) tier 1 finds no idle and tier 2 must bypass.
		if evicted := p.tryForceEvictIdleSlot(cl, oldIdx); evicted {
			Stats.DrainForceEvictedTotal.Add(1)
			newIdx = p.claimFreeSlot()
		} else if p.drainTargetOverAged(oldSlot) {
			if evicted := p.tryEmergencyEvictMinStreamsSlot(cl, oldIdx); evicted {
				Stats.DrainForceEvictedActiveTotal.Add(1)
				newIdx = p.claimFreeSlot()
			}
		}
	}
	if newIdx < 0 {
		p.log.Warn("WS pool drain skipped — no free cell",
			"slot", oldIdx, "reason", reason)
		if !oldSlot.state.CompareAndSwap(int32(slotDraining), int32(slotReady)) {
			p.log.Debug("WS pool revert CAS failed — slot died concurrently",
				"slot", oldIdx)
		}
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainRevertBackoff).UnixNano())
		return
	}

	// All gates passed — hand off inflight ownership to drainWatchdog.
	committed = true

	Stats.DrainStartedTotal.Add(1)
	drainStart := time.Now()
	activeAtStart := oldSlot.streams.Load()

	p.log.Info("WS pool slot drain started",
		"slot", oldIdx,
		"replacement_slot", newIdx,
		"reason", reason,
		"active_streams", activeAtStart,
		"hard_cap", p.drainHardCap,
		"inflight", inflight,
	)

	go p.connectReserveSlot(cl, newIdx, oldIdx)
	go p.drainWatchdog(cl, oldIdx, oldSlot, drainStart, reason)
}

// connectReserveSlot runs the standard connect path at newIdx. On
// success, AssignStream picks it up via its slotReady filter. On
// failure, drops the placeholder back to nil under reserveMu so a
// fresh drain can immediately reuse the cell, then schedules
// reconnectLoop (which short-circuits via §2.2.2 recycle guard if a
// drain claimed the cell in the meantime).
//
// Spec 2026-05-20 §4.2 (S5 review).
func (p *WSPoolTransport) connectReserveSlot(cl *Client, newIdx, oldIdx int) {
	if newIdx < 0 || newIdx >= len(p.slots) {
		return
	}

	var err error
	if hook := getConnectSlotForTest(); hook != nil {
		err = hook()
	} else {
		err = p.connectSlot(p.ctx, newIdx)
	}

	if err != nil {
		// Pool-level counter (indexed by cell) survives slot recycle —
		// see spec §2 and opus review H2. Atomic Add is race-safe
		// under concurrent connectReserveSlot calls for the same cell
		// (possible during cascade failures).
		failures := p.reserveConnectFailures[newIdx].Add(1)
		Stats.ReserveConnectFailuresTotal.Add(1)

		p.reserveMu.Lock()
		if p.slots[newIdx] != nil && p.slots[newIdx].getState() != slotReady {
			p.slots[newIdx] = nil // free for next claim
		}
		p.reserveMu.Unlock()

		backoff := computeReserveBackoff(failures, rand.Float64)
		p.log.Warn("WS pool reserve slot connect failed — placeholder freed",
			"slot", newIdx, "for_drain_of", oldIdx,
			"err", err,
			"consecutive_failures", failures,
			"reconnect_backoff", backoff.Truncate(time.Millisecond))

		go func() {
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(backoff):
			}
			p.reconnectLoop(newIdx)
		}()
		return
	}

	// Success — reset the failure counter for this cell. Pool-level
	// storage means this reset persists across cell recycle.
	p.reserveConnectFailures[newIdx].Store(0)
	// Резервный слот подключился — это такое же доказательство «origin
	// отвечает», как и успех в reconnectLoopInner, и в полевом
	// восстановлении 2026-08-11 путь через резерв был активным. Без
	// сигнала отсюда половина успехов не будила бы слоты в паузе.
	p.signalNetworkRevival()
	go p.slotReader(newIdx)
}

// recordPlannedRotation пишет НАШУ смену слота в отдельный ринг slotobs.
//
// Единственная точка записи плановых наблюдений: три копии этого кода (дренаж +
// два evict-пути) разъехались бы при первой правке полей Observation, а
// расхождение здесь означает расхождение знаменателя в CutShare/Hazard.
//
// Зовётся из ВСЕХ путей, где смену слота инициируем мы:
//   - drainWatchdog.tearDown — плановый дренаж, sticky, hard cap, фантом;
//   - tryForceEvictIdleSlot — вытеснение простаивающей ячейки;
//   - tryEmergencyEvictMinStreamsSlot — аварийное вытеснение.
//
// Почему полнота важна именно здесь (ревью 2026-08-12): пропуск выживших
// ЗАНИЖАЕТ знаменатель hazard и ЗАВЫШАЕТ Rate — смещение, противоположное по
// знаку цензурированию внутри полосы (HazardBand.CensoredIn). Два смещения
// разных знаков дают суммарную ошибку, непредсказуемую по направлению, и это
// хуже одного известного смещения. Вытеснения происходят, когда пул забит и
// ротация застряла, то есть в самых интересных для анализа условиях.
//
// НЕ покрывает: ctx.Done() в drainWatchdog (остановка клиента — по одному
// наблюдению на слот за прогон) и legacy fireRotation при
// SHADOWLINK_GRACEFUL_DRAIN=0. Второе осознанно: при бисекции по этому флагу
// ринг плановых останется пустым, и CutShare вернёт 1.0 — что честно означает
// «наблюдений о плановых ротациях нет», а не «всё срезал цензор». Читать
// CutShare без graceful drain нельзя, и это сказано в его докстринге.
func (p *WSPoolTransport) recordPlannedRotation(slot *poolSlot) {
	if p.slotDeaths == nil || slot == nil {
		return
	}
	var ageMs int64
	if started := slot.startedAtNs.Load(); started > 0 {
		ageMs = time.Since(time.Unix(0, started)).Milliseconds()
	}
	p.slotDeaths.RecordPlanned(slotobs.Observation{
		AgeMs:     ageMs,
		DownBytes: slot.downBytes.Load(),
	})
}

// drainWatchdog polls oldSlot.streams every drainPollInterval until
// either count reaches 0 (natural finish) or drainHardCap elapses
// (hard cap). In both cases:
//   - Bumps oldSlot.generation BEFORE handleSlotDeath so any concurrent
//     slotReader exits silently via shouldExitReader (no false
//     ReaderExits++ or frame-anomaly counter inflation).
//   - Calls handleSlotDeath with deathCauseDrainTeardown so the slot
//     is torn down without advancing the meltdown counter and the
//     cell is freed for reserve reuse.
func (p *WSPoolTransport) drainWatchdog(cl *Client, oldIdx int, oldSlot *poolSlot,
	drainStart time.Time, reason string) {

	// Inflight ownership was transferred from startDrain via committed=true.
	// Guarantee decrement on every exit path (natural finish, hard cap,
	// ctx cancel, panic) — spec §2.1.0 NEW-1.
	defer p.inflightDrains.Add(-1)

	// Bug #6: free this slot's sticky extension on EVERY watchdog exit path
	// (tearDown→return, ctx.Done, panic). Operates on the captured oldSlot
	// pointer — safe across cell recycle (spec H2). Idempotent if never sticky.
	defer p.releaseSticky(oldSlot)

	ticker := time.NewTicker(drainPollInterval)
	defer ticker.Stop()
	deadline := time.NewTimer(p.drainHardCap)
	defer deadline.Stop()

	// finishCause distinguishes the path that drove the natural-finish
	// decision so the log line carries useful diagnostics.
	type finishCause int
	const (
		finishStreamsZero finishCause = iota
		finishIdle
		finishHardCap
		finishStickyAgeBackstop   // Bug #6: активный стрим, достигнут возрастной предел дренажа
		finishStickyBytesBackstop // Bug #6: активный стрим, достигнут объёмный предел TCP
		finishStickyQuotaDenied   // Bug #6: активный стрим, но sticky-квота/ёмкость не позволяют
		// finishPhantom — счётчик слота разошёлся с streamMap, рвём по карте.
		// Отдельно от finishStreamsZero намеренно: это НЕ natural finish.
		// Стримы не завершились сами — мы порвали слот по расхождению, и
		// смешивать эти события в DrainNaturalFinishTotal значит скачком
		// «улучшить» долю штатных дренажей (в поле 408 событий из 431) без
		// изменения реальности.
		finishPhantom
	)

	tearDown := func(cause finishCause) {
		duration := time.Since(drainStart)
		switch cause {
		case finishHardCap:
			emitHardCapLog(p, oldIdx, oldSlot, reason, duration)
		case finishStickyAgeBackstop:
			Stats.DrainStickyBackstopAgeTotal.Add(1)
			emitStickyTeardownLog(p, oldIdx, oldSlot, reason, duration, "age_backstop")
		case finishStickyBytesBackstop:
			Stats.DrainStickyBackstopBytesTotal.Add(1)
			emitStickyTeardownLog(p, oldIdx, oldSlot, reason, duration, "bytes_backstop")
		case finishStickyQuotaDenied:
			Stats.DrainStickyQuotaDeniedTotal.Add(1)
			emitStickyTeardownLog(p, oldIdx, oldSlot, reason, duration, "quota_denied")
		case finishPhantom:
			// Только своя метрика: в natural finish это не входит (см.
			// докстринг finishPhantom). Лог пишется в logPhantom на месте
			// обнаружения — там доступна величина, по которой принято
			// решение.
			Stats.DrainPhantomCounterTotal.Add(1)
		case finishIdle:
			Stats.DrainNaturalFinishTotal.Add(1)
			Stats.DrainIdleFinishTotal.Add(1)
			snap := snapshotDrainStreams(p, oldIdx, time.Now())
			p.log.Info("WS pool slot drain natural finish (idle)",
				"slot", oldIdx, "reason", reason,
				"remaining_streams", oldSlot.streams.Load(),
				"drain_duration", duration.Truncate(time.Second),
				"diag_total", snap.total,
				"diag_idle_30s_count", snap.idleAge30sCount,
				"diag_active_count", snap.activeCount,
				"diag_max_stream_age_ms", snap.maxStreamAgeMs,
				"diag_min_stream_age_ms", snap.minStreamAgeMs,
			)
		default: // finishStreamsZero
			Stats.DrainNaturalFinishTotal.Add(1)
			p.log.Info("WS pool slot drain natural finish",
				"slot", oldIdx, "reason", reason,
				"drain_duration", duration.Truncate(time.Second))
		}
		Stats.DrainDurationSeconds.Observe(duration.Seconds())

		// Плановая смена слота — в ОТДЕЛЬНУЮ выборку slotobs (2026-08-12).
		//
		// Зачем: до сих пор Record звался только из ветки ошибки чтения, поэтому
		// выборка была цензурирована — слоты, снятые нашей же ротацией, в неё не
		// попадали. Полевой прогон 20260812-110200 показал цену: 8 наблюдений за
		// 1ч58м против порога инференса 12, контур наблюдаемости молчал весь
		// прогон, адаптация порога не исполнялась. Плюс без знаменателя
		// перцентили по резам вводят в заблуждение (survivorship bias: p50 по 7
		// точкам дал 85с против 97.6с по 222 — прочитано как «окно сжалось», хотя
		// до 100с в том прогоне почти ничего не доезжало).
		//
		// Вызов стоит на ОБЩЕМ пути, после switch по причине: sticky-teardown,
		// hard cap и фантомный разрыв — тоже инициированные нами смены слота, и
		// они тоже дожили до своего возраста. Ставить вызов внутрь конкретной
		// ветки значило бы потерять часть выходов молча.
		//
		// RecordPlanned, НЕ Record: ринг резов трогать нельзя, иначе порог был бы
		// выведен из нашего же порога (тавтология).
		p.recordPlannedRotation(oldSlot)

		// Graceful drain is still a rotation we initiated — surface it in
		// the rolling 1-minute counter that pool-health logs read. Before
		// this change, drain-only sessions showed rotations_1m=0 even with
		// hundreds of drains/hour (2026-05-22 canary).
		p.bumpRotations1m()

		oldSlot.generation.Add(1)
		p.handleSlotDeath(cl, oldIdx, deathCauseDrainTeardown)
	}

	// Step 2: idle heuristic now uses per-stream measurement via
	// allStreamsIdle (defined in stream_entry.go). The disable knob is
	// SHADOWLINK_DRAIN_IDLE_THRESHOLD=0 — SHADOWLINK_DRAIN_IDLE_STREAMS_MAX
	// is deprecated and ignored in the decision (BREAKING CHANGE doc'd
	// in spec §2.5; startup WARN emitted in cmd-layer if env set).
	idleThreshold := p.drainIdleThreshold
	idleEnabled := idleThreshold > 0

	// isPhantomCounter: счётчик слота держит стримы, которых в streamMap нет.
	//
	// Карта здесь ground truth, счётчик — производное от неё. При расхождении
	// верить надо карте: она перечисляет привязки поимённо, счётчик же лишь
	// суммирует инкременты, и утёкший декремент делает его монотонно неверным
	// до конца жизни слота.
	//
	// Без этой проверки закрыты ОБЕ ранние ветки выхода:
	//   - `streams.Load() == 0` ложно (счётчик протёк);
	//   - `allStreamsIdle` возвращает `found && allIdle`, а при пустой карте
	//     found=false → тоже ложно.
	// Слот доезжает до sticky-дедлайна и держит ячейку весь teardown_cap.
	//
	// Замер 2026-08-11 (3ч38м): 408 из 431 sticky-teardown с таким
	// расхождением, 396 из них ровно по 25s. Ни один natural finish (0 из
	// 158) расхождения не имел — корреляция полная. Воспроизводится во всех
	// пяти сохранённых прогонах с 08-07.
	//
	// Чинится ПОСЛЕДСТВИЕ. Причина утечки (путь, которым запись уходит из
	// streamMap мимо декремента) не найдена и требует -race на сервере:
	// Windows-dev гонки не ловит (CLAUDE.md hard rule 6). Поэтому расхождение
	// логируется, а не молча исправляется — иначе причину не найдут никогда.
	// ⚠ Требуется ДВА наблюдения подряд, а не одно. Одного недостаточно:
	// AssignStream поднимает счётчик ПЕРЕД публикацией записи в streamMap
	// («streams.Add MUST precede streamMap.Store», ws_pool.go, spec §2.5), и
	// в этом окне здоровый новый стрим неотличим от фантома — счётчик>0,
	// карта пуста. Порвав слот там, мы бы не закрыли канал ещё не
	// опубликованного стрима (handleSlotDeath обходит streamMap, а записи в
	// ней нет): соединение повисло бы на мёртвом транспорте до таймаута.
	//
	// Отличие во времени, и оно на порядки: утёкший декремент необратим и
	// держится до конца жизни слота, окно inc→Store живёт наносекунды.
	// Два тика (>=500ms) гонку не переживают, а фантом переживает.
	// Цена — полтика задержки против 25s удержания сейчас, то есть выигрыш
	// сохраняется целиком.
	//
	// Тот же race для allStreamsIdle разобран в stream_entry.go и назван
	// консервативным — и там это верно: found=false → «не рвать». Здесь
	// знак противоположный, поэтому консервативность надо добавлять руками.
	var phantomSeenAt time.Time
	// phantomStreams: величина, по которой принято решение. Отдаётся в лог,
	// чтобы там стояло измеренное число, а не перечитанное позже другое.
	var phantomStreams int32

	// isPhantomCounter возвращает true, только когда расхождение подтверждено
	// вторым наблюдением. Первое лишь запоминает момент.
	isPhantomCounter := func(now time.Time) bool {
		counter := oldSlot.streams.Load()
		if counter <= 0 {
			phantomSeenAt = time.Time{}
			return false // обычный пустой слот — им занимается finishStreamsZero
		}
		if snapshotDrainStreams(p, oldIdx, now).total != 0 {
			phantomSeenAt = time.Time{} // карта не пуста — расхождения нет
			return false
		}
		if phantomSeenAt.IsZero() {
			phantomSeenAt = now
			return false // первое наблюдение — ждём подтверждения
		}
		if now.Sub(phantomSeenAt) < drainPollInterval {
			return false
		}
		phantomStreams = counter
		return true
	}

	// Счётчик бампает tearDown(finishPhantom) — здесь только лог, иначе
	// событие посчиталось бы дважды.
	logPhantom := func(duration time.Duration) {
		p.log.Warn("WS pool slot drain: phantom stream counter — torn down by map, not counter",
			"slot", oldIdx, "reason", reason,
			"counter_streams", phantomStreams,
			"map_streams", 0,
			"confirmed_after", drainPollInterval,
			"drain_duration", duration.Truncate(time.Second),
		)
	}

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-deadline.C:
			// Bug #6: осознанное решение вместо слепого hard-cap teardown.
			// Kill switch (StickyMaxDrainAge<=0) → ведём себя как раньше.
			//
			// idle-детекция выключена (DrainIdleThreshold==0) → нельзя
			// безопасно отличить активный стрим от простаивающего, поэтому
			// sticky НЕ активируется и deadline рвёт слепо по hard-cap, как
			// до Bug #6 (spec §3.1 / урок L2). Без этого гейта !idleEnabled
			// провалился бы в idle-ветку switch'а и поехал бы в finishIdle —
			// неверно классифицируя hard-cap teardown как natural-finish.
			if p.stickyMaxDrainAge <= 0 || !idleEnabled {
				tearDown(finishHardCap)
				return
			}
			now := time.Now()
			idle := allStreamsIdle(p, oldIdx, idleThreshold, now)
			drainAge := now.Sub(drainStart) // монотонные часы
			drainBytes := oldSlot.downBytes.Load()
			switch {
			case isPhantomCounter(now):
				// Счётчик врёт, привязок нет — рвём по карте, не оплачивая
				// sticky-предел. Проверка стоит ПЕРВОЙ: ниже каждая ветка
				// так или иначе доверяет счётчику.
				logPhantom(time.Since(drainStart))
				tearDown(finishPhantom)
				return
			case oldSlot.streams.Load() == 0:
				// последний стрим закрылся между ticker-тиком и deadline.C —
				// рвём как пустой слот (симметрично ticker-ветке). Без этого
				// case'а allStreamsIdle({}) возвращает false (found==false), и
				// пустой слот ушёл бы в default→extend на лишние 5s (spec M-2).
				tearDown(finishStreamsZero)
				return
			case idle:
				// стрим простаивает → natural-finish (НЕ hard-cap метрика, spec M5)
				tearDown(finishIdle)
				return
			case drainAge >= p.stickyMaxDrainAge:
				tearDown(finishStickyAgeBackstop)
				return
			case drainBytes >= p.stickyMaxTotalBytes:
				tearDown(finishStickyBytesBackstop)
				return
			case oldSlot.isSticky.Load() && p.readyCapacity() <= p.readyCapacityFloor():
				// уже-sticky слот при просадке ёмкости → досрочно рвём (spec H4:
				// приоритет ротация > UX одной закачки, клинч саморазрешается).
				tearDown(finishStickyQuotaDenied)
				return
			case !p.stickyQuotaAvailable(oldSlot):
				tearDown(finishStickyQuotaDenied)
				return
			default:
				// активная закачка, в пределах backstop, квота есть → продлеваем.
				p.markSticky(oldSlot)
				Stats.DrainStickyExtendedTotal.Add(1)
				deadline.Reset(stickyRecheckInterval)
			}
		case <-ticker.C:
			streams := oldSlot.streams.Load()
			if streams == 0 {
				tearDown(finishStreamsZero)
				return
			}
			// Фантом ловим на тике, а не только на дедлайне: иначе слот всё
			// равно ждал бы hard_cap впустую, просто рвался бы потом быстрее.
			if now := time.Now(); isPhantomCounter(now) {
				logPhantom(time.Since(drainStart))
				tearDown(finishPhantom)
				return
			}
			if idleEnabled && allStreamsIdle(p, oldIdx, idleThreshold, time.Now()) {
				tearDown(finishIdle)
				return
			}
		}
	}
}

// emitHardCapLog records a hard-cap teardown event: increments
// Stats.DrainHardCapTotal and emits a structured log line at INFO or
// WARN level depending on whether `slot.streams.Load() >=
// hardCapWarnThreshold`. Below threshold (the expected steady-state
// case for long-lived SOCKS sessions) logs INFO; outliers log WARN.
//
// Extracted from drainWatchdog.tearDown for testability — tests can
// drive this directly without orchestrating a full drain.
//
// Spec 2026-05-24 (drain-diagnostics-counter-split) §4.
func emitHardCapLog(p *WSPoolTransport, oldIdx int, slot *poolSlot, reason string, duration time.Duration) {
	Stats.DrainHardCapTotal.Add(1)
	remaining := slot.streams.Load()
	snap := snapshotDrainStreams(p, oldIdx, time.Now())

	logFn := p.log.Info
	if remaining >= hardCapWarnThreshold {
		logFn = p.log.Warn
	}
	logFn("WS pool slot drain hard cap reached",
		"slot", oldIdx, "reason", reason,
		"remaining_streams", remaining,
		"drain_duration", duration.Truncate(time.Second),
		"diag_total", snap.total,
		"diag_idle_30s_count", snap.idleAge30sCount,
		"diag_active_count", snap.activeCount,
		"diag_max_stream_age_ms", snap.maxStreamAgeMs,
		"diag_min_stream_age_ms", snap.minStreamAgeMs,
	)
}

// emitStickyTeardownLog records a Bug #6 sticky-backstop teardown: an active
// stream was finally torn down because a backstop (age/bytes) or quota gate
// fired. outcome ∈ {age_backstop, bytes_backstop, quota_denied}. Mirrors
// emitHardCapLog's diag fields so operators see WHY an active download was cut.
func emitStickyTeardownLog(p *WSPoolTransport, oldIdx int, slot *poolSlot,
	reason string, duration time.Duration, outcome string) {
	snap := snapshotDrainStreams(p, oldIdx, time.Now())
	p.log.Info("WS pool slot drain sticky backstop teardown",
		"slot", oldIdx, "reason", reason,
		"sticky_outcome", outcome,
		"remaining_streams", slot.streams.Load(),
		"down_bytes", slot.downBytes.Load(),
		"drain_duration", duration.Truncate(time.Second),
		"diag_total", snap.total,
		"diag_active_count", snap.activeCount,
		"diag_max_stream_age_ms", snap.maxStreamAgeMs,
	)
	// NB: bumpRotations1m is called by tearDown for ALL finish causes (incl.
	// sticky backstops) — do NOT bump here, or sticky teardowns would
	// double-count rotations_1m vs hard-cap/idle paths (final review H-1).
}

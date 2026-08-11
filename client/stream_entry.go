package client

import (
	"sync/atomic"
	"time"
)

// streamEntry tracks per-stream state required for both routing
// (which slot owns the stream) and diagnostics (when this stream
// last had wire activity).
//
// Stored as *streamEntry in WSPoolTransport.streamMap (sync.Map);
// pointer storage avoids re-Store on lastWriteNs updates.
//
// Concurrency: slotIdx is set once at construction by newStreamEntry
// and never mutated thereafter — safe for unlocked reads. lastWriteNs
// is updated and read exclusively through its atomic.Int64 methods.
type streamEntry struct {
	slotIdx     int
	lastWriteNs atomic.Int64

	// migrating coordinates Bug #9 stream migration (Task 17, F10). Set true
	// (CAS false→true) by the single owner of a move — either the preemptive
	// MIGRATE watchdog (migrateStream, T16) or the reactive RESUME-on-slot-death
	// path (resumeStreamOnDeath, T17) — and cleared on the move's outcome
	// (OK / FAIL / timeout / no-send).
	//
	// Three consumers read it:
	//   - The SOCKS5 uplink goroutine (proxy/socks5/tcp.go) holds an uplink
	//     barrier (§5.3): while migrating it stops writing to the old slot so
	//     no uplink data races ahead of the MIGRATE/RESUME and de-syncs the
	//     server's per-stream sequence. The write resumes once the flag clears
	//     (the binding now points at the new slot) or the bounded timeout
	//     elapses.
	//   - drain teardown / handleSlotDeath skip the stream-chan close for a
	//     migrating stream — the in-flight move owns the stream's fate.
	//   - allStreamsIdle / snapshotDrainStreams classify a migrating stream as
	//     NOT active, so the sticky backstop does not extend a drain on a
	//     stream that is already leaving the slot.
	//
	// CAS false→true is the single-winner gate: if migrateStream and
	// handleSlotDeath both target the same stream, exactly one wins the CAS and
	// performs the wire send; the loser observes migrating==true and stands down
	// (no double-send, no close of a stream another goroutine is moving).
	migrating atomic.Bool

	// migrationScheduled gates preemptive migration scheduling PER STREAM. The
	// watchdog re-invokes scheduleSlotMigration every 5s while a slot is above
	// its migration threshold; this per-stream CAS arms exactly ONE migration
	// timer per stream over its life on a slot, so a stream that attached to the
	// aging slot AFTER the first scheduling pass still gets scheduled on a later
	// tick. A fresh entry from newStreamEntry has it false (zero value); a rebind
	// to a new slot installs a fresh entry, re-arming on the next slot's aging.
	migrationScheduled atomic.Bool
}

// newStreamEntry constructs a fully-initialized entry: slotIdx pinned,
// lastWriteNs pre-stamped to time.Now() so snapshot logic never sees
// a zero clock.
func newStreamEntry(slotIdx int) *streamEntry {
	e := &streamEntry{slotIdx: slotIdx}
	e.lastWriteNs.Store(time.Now().UnixNano())
	return e
}

// drainStreamSnapshot aggregates per-stream activity for one slot
// at drain teardown. Populated by snapshotDrainStreams; consumed
// only by drain log emission.
type drainStreamSnapshot struct {
	total           int
	idleAge30sCount int
	activeCount     int
	maxStreamAgeMs  int64 // max age (ms) среди ВСЕХ attached streams (regardless of active/idle classification). 0 if total==0.
	minStreamAgeMs  int64 // min age (ms) среди ВСЕХ attached streams. 0 if total==0.
}

// snapshotDrainStreams scans the pool's streamMap once and aggregates
// per-stream activity for streams currently attached to slotIdx.
//
// Concurrency contract:
//   - lastWriteNs is read via atomic.Int64.Load() — no torn reads.
//   - sync.Map.Range visits each entry at most once; entries removed
//     concurrently by ReleaseStream may or may not appear in iteration,
//     per sync.Map's documented contract. No partial-entry exposure.
//   - All age math operates on local copies — race-free by construction.
//   - lastWriteNs is guaranteed >0 for every entry (newStreamEntry stamps
//     at construction); no zero-clock special case.
//
// Cost: O(N) where N is the total number of active streams across all
// slots in the pool (sync.Map.Range cannot pre-filter). Typical N is
// 50–100; iteration takes <10 µs.
//
// Since 2026-08-11 this also runs on every drainWatchdog tick (phantom
// counter detection, ws_pool_drain.go), not only at teardown. Still not a
// hot path: drainPollInterval is 500 ms and inflight drains are 0–2 in the
// field, so ~4 scans/s. At the observed peak (active_streams=274 in log
// nixavpn-DEBUG-20260811-145918) that is ~1100 entry visits per second.
func snapshotDrainStreams(p *WSPoolTransport, slotIdx int, now time.Time) drainStreamSnapshot {
	nowNs := now.UnixNano()
	const idleThresholdMs = 30_000

	var snap drainStreamSnapshot
	p.streamMap.Range(func(_, value any) bool {
		e, ok := value.(*streamEntry)
		if !ok || e.slotIdx != slotIdx {
			return true
		}
		snap.total++

		ageMs := (nowNs - e.lastWriteNs.Load()) / int64(time.Millisecond)
		if ageMs < 0 {
			// Clock regressed (NTP adjust on Windows, ~100ns scale).
			// Clamp to 0 and bump telemetry so persistent negatives are
			// observable rather than silently masked.
			Stats.SnapshotNegativeAgeTotal.Add(1)
			ageMs = 0
		}

		// Bug #9 F10: a migrating stream is leaving this slot via an in-flight
		// MIGRATE/RESUME, so it must not count as active — otherwise the sticky
		// backstop would extend the drain on a stream that is already moving
		// off. Classify it with the idle bucket regardless of wire age.
		if ageMs >= idleThresholdMs || e.migrating.Load() {
			snap.idleAge30sCount++
		} else {
			snap.activeCount++
		}
		if snap.total == 1 || ageMs > snap.maxStreamAgeMs {
			snap.maxStreamAgeMs = ageMs
		}
		if snap.total == 1 || ageMs < snap.minStreamAgeMs {
			snap.minStreamAgeMs = ageMs
		}
		return true
	})
	return snap
}

// allStreamsIdle returns true iff every stream attached to slotIdx has
// been silent for at least threshold. Returns false if there are no
// streams attached to slotIdx (caller should have already handled the
// streams.Load()==0 case via finishStreamsZero) — defensive against
// edge case where streams counter and streamMap diverge.
//
// Early-exits on first active stream found (most ticks during a drain
// have at least one active heartbeat-stream, so typical path is fast).
//
// Concurrency:
//   - lastWriteNs read via atomic.Int64.Load — no torn reads.
//   - sync.Map.Range visits each entry at most once; entries removed by
//     concurrent ReleaseStream may or may not appear, per sync.Map
//     contract. No partial state.
//   - Race with new AssignStream: newStreamEntry stamps lastWriteNs=now,
//     so fresh entries appear as active → conservative (no premature
//     teardown). False negative for idle on at most one tick (500ms).
//   - Race with ReleaseStream (spec §2.3.1 fix flips order: streams.Add(-1)
//     BEFORE Delete): window where snapshot sees decremented counter
//     but entry still present — entry's lastWriteNs is read, either
//     correctly active (no premature teardown) or correctly idle
//     (teardown safe).
//
// Cost: O(N) sync.Map scan, N = total active streams across pool.
// Called only from drainWatchdog tick (500ms cadence). Typical N=50-100,
// early-exit path <1µs, full-scan path ~5-10µs. Not a hot path.
func allStreamsIdle(p *WSPoolTransport, slotIdx int, threshold time.Duration, now time.Time) bool {
	nowNs := now.UnixNano()
	thresholdNs := threshold.Nanoseconds()
	found := false
	allIdle := true
	p.streamMap.Range(func(_, value any) bool {
		e, ok := value.(*streamEntry)
		if !ok || e.slotIdx != slotIdx {
			return true
		}
		found = true
		// Bug #9 F10: a migrating stream is leaving this slot — do NOT let it
		// hold the drain open. Skip it from the active check (treat as idle) so
		// allStreamsIdle can return true once every remaining stream is either
		// truly idle or migrating away.
		if e.migrating.Load() {
			return true
		}
		age := nowNs - e.lastWriteNs.Load()
		// Clock-skew handling (spec §2.1 R2-L4): age < 0 means clock
		// regressed. Conservative — treat as active. No telemetry
		// bump here (decision path is silent; snapshot path handles
		// telemetry for the same condition in Step 1).
		if age < thresholdNs {
			allIdle = false
			return false // early exit
		}
		return true
	})
	return found && allIdle
}

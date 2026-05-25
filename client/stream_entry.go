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
// 50–100; iteration takes <10 µs and runs only at drain teardown — not
// in any hot path.
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

		if ageMs >= idleThresholdMs {
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

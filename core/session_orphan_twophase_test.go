package core

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCleanupNewbornOrphans_TwoPhase_NoLockHeldDuringIO locks in P2-3
// (final audit 2026-05-03). Pre-fix: CleanupNewbornOrphans held
// sm.mu.Lock() (write lock) for the entire scan — under handshake-abuse
// DoS that fills the orphan pool with 10k+ sessions, every other
// SessionManager operation (Get / Create / Remove / Count / ForEach)
// stalled for the duration of the sweep, amplifying the DoS.
//
// Post-fix: two-phase. Phase 1 collects candidate IDs under RLock
// (read lock) — concurrent readers proceed without blocking. Phase 2
// per-candidate write-lock window — each acquisition is bounded by a
// single map lookup + the per-session zero work, allowing concurrent
// Create/Remove operations to interleave between candidates.
//
// Test strategy: pre-populate the manager with 10000 sessions whose
// CreatedAt is well in the past (so all are eviction candidates).
// Drive a concurrent reader (Get) that records the maximum gap
// between consecutive successful acquisitions during the sweep.
// With the legacy single-write-lock implementation the reader would
// stall for the entire sweep (potentially hundreds of milliseconds);
// with two-phase the reader sees only per-candidate-window stalls.
//
// Concurrency rationale (memory ordering):
//   - Phase 1 RLock pairs with Create's Lock via sync.RWMutex's
//     happens-before — every published session is observed; the
//     iteration of sm.sessions is safe (no concurrent writer).
//   - AttachedAt is sync/atomic.Int64; Load gives acquire ordering
//     with respect to authenticateFirstFrame's Store. A session
//     that attaches between Phase 1 and Phase 2 is correctly
//     skipped because Phase 2 re-Loads AttachedAt under sm.mu.Lock().
//   - CreatedAt is set once in NewSession before publication into
//     sm.sessions. The write-lock-protected map publish in Create
//     synchronizes-with every reader (RLock + atomic load on the
//     pointer), so CreatedAt is safely readable from Phase 1.
func TestCleanupNewbornOrphans_TwoPhase_NoLockHeldDuringIO(t *testing.T) {
	const N = 10000
	sm := NewSessionManager(time.Hour)

	// Pre-populate N orphan sessions with old CreatedAt so all are evictable.
	for i := 0; i < N; i++ {
		_, err := sm.Create(make([]byte, 32), make([]byte, 32))
		require.NoError(t, err)
	}

	// Backdate every session's CreatedAt to 31s ago.
	sm.mu.Lock()
	now := time.Now()
	for _, s := range sm.sessions {
		s.CreatedAt = now.Add(-31 * time.Second)
	}
	// Snapshot one ID for the concurrent reader probe.
	var probeID uint32
	for id := range sm.sessions {
		probeID = id
		break
	}
	sm.mu.Unlock()

	// Reader goroutine: hammer Get(probeID) and record max-stall.
	var stop atomic.Bool
	var maxStall int64 // nanoseconds
	var probeReads atomic.Int64
	var wg sync.WaitGroup
	// readerStarted closes after the reader has completed its first Get(),
	// proving the Go scheduler has actually run the goroutine. Without this
	// barrier, on a fully CPU-saturated host the reader can fail to get a
	// single time slice before the (sub-10ms) sweep finishes and stop is set,
	// yielding probeReads=0 — a test artifact (scheduler starvation), NOT the
	// legacy lock-held regression. The barrier guarantees the reader is live
	// and interleaving with the sweep. It does not mask the legacy bug: under
	// the single-write-lock implementation the reader still completes this
	// first Get() before the sweep grabs the write lock, then blocks inside
	// Get() for the whole sweep, so its read count stays O(1).
	readerStarted := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		last := time.Now()
		first := true
		for !stop.Load() {
			_, _ = sm.Get(probeID)
			probeReads.Add(1)
			cur := time.Now()
			if d := cur.Sub(last).Nanoseconds(); d > maxStall {
				atomic.StoreInt64(&maxStall, d)
			}
			last = cur
			if first {
				first = false
				close(readerStarted)
			}
		}
	}()
	<-readerStarted

	// Run cleanup. With two-phase fix this should NOT stall the reader
	// for hundreds of ms even with N=10000 candidates.
	sweepStart := time.Now()
	evicted := sm.CleanupNewbornOrphans(now, 30*time.Second)
	sweepElapsed := time.Since(sweepStart)
	stop.Store(true)
	wg.Wait()

	require.Len(t, evicted, N, "all %d orphan sessions must be evicted", N)
	require.Equal(t, 0, sm.Count(), "manager must be empty after sweep")

	// Soft assertion: the reader observed >0 stalls (any concurrent
	// access to the manager during the sweep is allowed). The hard
	// assertion is that the maximum stall is bounded — pre-fix, with
	// a single write-lock holding the whole sweep, the reader would
	// stall for ~sweepElapsed itself. Post-fix, per-candidate windows
	// are O(microseconds) so max-stall stays well below sweep elapsed.
	t.Logf("sweep elapsed=%v, evicted=%d, probe reads during sweep=%d, max reader stall=%v",
		sweepElapsed, len(evicted), probeReads.Load(), time.Duration(maxStall))

	// The two-phase invariant we lock in is STRUCTURAL (reader throughput),
	// not wall-clock (max stall). Rationale for dropping the timing assert:
	//
	//   The original `maxStall < sweepElapsed/2` check was inherently flaky.
	//   maxStall records the largest gap between two consecutive Get() calls,
	//   and that gap captures ANY pause of the reader goroutine — most often
	//   OS scheduler preemption (observed 4-10ms stalls on a loaded host),
	//   which has nothing to do with lock contention. Critically, the whole
	//   sweep of 10000 sessions completes in only single-digit milliseconds
	//   (measured 3.7-12ms), so a single scheduler preemption is the SAME
	//   order of magnitude as the entire sweep. No fixed fraction of
	//   sweepElapsed can separate "lock held across the sweep" (the legacy
	//   bug) from "reader was briefly descheduled" (benign jitter) when both
	//   live in the same few-millisecond band — even `maxStall < sweepElapsed`
	//   false-fails when the reader's final post-sweep gap happens to equal
	//   the sweep duration. Wall-clock timing is the wrong instrument here.
	//
	// The honest, jitter-immune invariant is reader THROUGHPUT. Under the
	// two-phase fix the write lock is released between every one of the 10000
	// candidates, so the reader interleaves tens of thousands of Get() calls
	// (measured 21000-33000). Under the legacy single-write-lock bug the
	// reader is pinned for the ENTIRE sweep and can complete only O(1) Get()
	// calls — one just before the sweep grabs the lock, one just after it
	// releases. We require >> N/10 (= 1000) reads: that floor sits orders of
	// magnitude above the legacy O(1) ceiling, so it still catches the
	// regression, yet it is unaffected by CPU load — once scheduled, the
	// reader races through Get() far faster than the sweep deletes sessions,
	// so the read count stays in the tens of thousands regardless of timing.
	require.Greater(t, probeReads.Load(), int64(N/10),
		"reader made only %d reads during the sweep of %d candidates — "+
			"under two-phase the reader should interleave tens of thousands of "+
			"Get() calls; a count this low means the write lock was held across "+
			"the entire scan (legacy single-lock regression)",
		probeReads.Load(), N)
}

// TestCleanupNewbornOrphans_TwoPhase_RaceFreeAttachBetweenPhases verifies
// that a session which attaches AFTER Phase 1 collected it as a
// candidate but BEFORE Phase 2 reaches it is correctly skipped (NOT
// evicted). This is the primary correctness-preserving invariant for
// the two-phase split.
func TestCleanupNewbornOrphans_TwoPhase_RaceFreeAttachBetweenPhases(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	s, err := sm.Create(make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)

	// Backdate to 31s old → eligible for Phase 1.
	now := time.Now()
	s.CreatedAt = now.Add(-31 * time.Second)

	// Simulate "attach between phases" by stamping AttachedAt after
	// the session is technically eligible. With re-validation in
	// Phase 2, this session must NOT be evicted.
	s.AttachedAt.Store(now.UnixNano())

	evicted := sm.CleanupNewbornOrphans(now, 30*time.Second)
	require.Empty(t, evicted, "session that attached must not be evicted by orphan fast path")

	got, ok := sm.Get(s.ID)
	require.True(t, ok)
	require.Equal(t, s.ID, got.ID)
}

// TestCleanupNewbornOrphans_TwoPhase_RaceFreeRemoveBetweenPhases verifies
// that a session which is Removed by another path (Cleanup, Remove,
// Destroy) AFTER Phase 1 collected it but BEFORE Phase 2 acquires the
// write lock is correctly skipped — no double-delete, no panic.
func TestCleanupNewbornOrphans_TwoPhase_RaceFreeRemoveBetweenPhases(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	a, err := sm.Create(make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)
	b, err := sm.Create(make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)

	// Both backdated to 31s — both eligible.
	now := time.Now()
	a.CreatedAt = now.Add(-31 * time.Second)
	b.CreatedAt = now.Add(-31 * time.Second)

	// Pre-remove `a` directly; the cleanup must still succeed (skip the
	// missing entry, evict `b`).
	sm.Remove(a.ID)

	evicted := sm.CleanupNewbornOrphans(now, 30*time.Second)
	require.Len(t, evicted, 1, "exactly one session must be evicted (the live one)")
	require.Equal(t, b.ID, evicted[0])

	_, okA := sm.Get(a.ID)
	_, okB := sm.Get(b.ID)
	require.False(t, okA)
	require.False(t, okB)
}

// TestCleanupNewbornOrphans_ConcurrentCreate_NotEvicted verifies the
// key correctness property of the two-phase design: a session created
// AFTER Phase 1 collected its candidate snapshot must NOT be evicted
// by the ongoing sweep (Review 2 M-5, 2026-05-05).
//
// Strategy:
//  1. Pre-populate N=1000 "ancient" sessions (CreatedAt 60s in the past,
//     AttachedAt=0) that are all legitimate eviction targets.
//  2. Launch CleanupNewbornOrphans in a goroutine.
//  3. Concurrently create 100 "fresh" sessions DURING the sweep.
//     Because Phase 1 collected candidates under RLock before the new
//     sessions existed, their IDs cannot be in `candidates`. Phase 2
//     must therefore never touch them.
//  4. After the sweep completes, assert all 1000 ancient sessions are
//     gone and all 100 fresh sessions survive.
//
// Race-detection note: run with -race to surface any unsynchronised
// access to session fields written by Create and read by the sweep.
func TestCleanupNewbornOrphans_ConcurrentCreate_NotEvicted(t *testing.T) {
	const ancient = 1000
	const fresh = 100

	sm := NewSessionManager(time.Hour)

	// Pre-populate ancient orphans — backdated well beyond maxAge.
	ancientIDs := make([]uint32, 0, ancient)
	for i := 0; i < ancient; i++ {
		s, err := sm.Create(make([]byte, 32), make([]byte, 32))
		require.NoError(t, err)
		ancientIDs = append(ancientIDs, s.ID)
	}
	now := time.Now()
	sm.mu.Lock()
	for _, id := range ancientIDs {
		if s, ok := sm.sessions[id]; ok {
			s.CreatedAt = now.Add(-61 * time.Second)
		}
	}
	sm.mu.Unlock()

	// Channel to synchronise: sweep goroutine signals when it has completed
	// Phase 1 (or is mid-sweep). We can't hook into the internals, so we
	// simply start Create immediately — concurrent Create racing against
	// both phases is the intended scenario.
	sweepDone := make(chan []uint32, 1)
	go func() {
		evicted := sm.CleanupNewbornOrphans(now, 30*time.Second)
		sweepDone <- evicted
	}()

	// Give Phase 1 a head start (in practice, both goroutines race).
	time.Sleep(time.Microsecond)

	// Create fresh sessions concurrently with the running sweep.
	freshIDs := make([]uint32, 0, fresh)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < fresh; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := sm.Create(make([]byte, 32), make([]byte, 32))
			if err != nil {
				return
			}
			mu.Lock()
			freshIDs = append(freshIDs, s.ID)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Wait for the sweep to finish.
	evicted := <-sweepDone

	// All ancient sessions must be evicted.
	require.Len(t, evicted, ancient,
		"all %d ancient sessions must be evicted (got %d)", ancient, len(evicted))

	// All fresh sessions must survive — none of their IDs appear in evicted.
	evictedSet := make(map[uint32]struct{}, len(evicted))
	for _, id := range evicted {
		evictedSet[id] = struct{}{}
	}
	for _, id := range freshIDs {
		_, wasEvicted := evictedSet[id]
		require.False(t, wasEvicted,
			"fresh session %d was incorrectly evicted by the concurrent sweep", id)
		// Also verify still present in the manager.
		_, ok := sm.Get(id)
		require.True(t, ok,
			"fresh session %d was removed from manager by concurrent sweep", id)
	}
	require.Len(t, freshIDs, fresh,
		"all %d Create calls must have succeeded (got %d)", fresh, len(freshIDs))
}

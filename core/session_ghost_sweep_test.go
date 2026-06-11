package core

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Server ghost-sweep (spec 2026-06-01-pool-capacity-dip-fix-design.md, server
// ghost-sweep section — REPLACES the crypto-impossible client FIN-via-sibling).
//
// When a slot's WS reader exits (TSPU age-cut → close 1006 / io_timeout /
// peer_eof) the bound session's transport is dead, but the *Session lingers in
// the manager until the coarse idle timeout — accumulating ghosts
// (active_clients=18 after the client disconnected). CleanupDetachedGhosts
// reclaims a detached session after a SHORT grace, gated so it never evicts a
// session a stream is migrating onto (Bug#9 orphan window).
// ---------------------------------------------------------------------------

func newGhostTestManager(t *testing.T) *SessionManager {
	t.Helper()
	// 5-minute idle timeout (production default scale) so the regular Cleanup
	// never interferes with the short-grace ghost sweep under test.
	return NewSessionManager(5 * time.Minute)
}

func mustCreateSession(t *testing.T, sm *SessionManager) *Session {
	t.Helper()
	key := make([]byte, 32) // AES-256
	s, err := sm.Create(key, key)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	return s
}

// TestCleanupDetachedGhosts_SweepsAfterReaderExit: a session that attached and
// then detached (WS reader exited) more than `grace` ago is reclaimed.
func TestCleanupDetachedGhosts_SweepsAfterReaderExit(t *testing.T) {
	sm := newGhostTestManager(t)
	s := mustCreateSession(t, sm)
	now := time.Now()

	// Attached (handshake completed) then detached (reader exited) 10s ago.
	s.AttachedAt.Store(now.Add(-60 * time.Second).UnixNano())
	s.DetachedAt.Store(now.Add(-10 * time.Second).UnixNano())

	// Gate allows eviction (no orphan relay, no live transport).
	gate := func(id uint32) bool { return true }

	swept := sm.CleanupDetachedGhosts(now, 5*time.Second, gate)
	if len(swept) != 1 || swept[0] != s.ID {
		t.Fatalf("expected session %d swept, got %v", s.ID, swept)
	}
	if _, ok := sm.Get(s.ID); ok {
		t.Fatal("swept session must be removed from the manager")
	}
}

// TestCleanupDetachedGhosts_RespectsGrace: a session detached LESS than `grace`
// ago is NOT swept (allows a RESUME/MIGRATE to re-adopt it).
func TestCleanupDetachedGhosts_RespectsGrace(t *testing.T) {
	sm := newGhostTestManager(t)
	s := mustCreateSession(t, sm)
	now := time.Now()

	s.AttachedAt.Store(now.Add(-60 * time.Second).UnixNano())
	s.DetachedAt.Store(now.Add(-2 * time.Second).UnixNano()) // only 2s ago

	swept := sm.CleanupDetachedGhosts(now, 8*time.Second, func(uint32) bool { return true })
	if len(swept) != 0 {
		t.Fatalf("session within grace must NOT be swept, got %v", swept)
	}
	if _, ok := sm.Get(s.ID); !ok {
		t.Fatal("session within grace must survive")
	}
}

// TestCleanupDetachedGhosts_SkipsGated: a session past grace but whose gate
// returns false (a stream is migrating onto it — orphan relay still live) is
// NOT swept. This is the critical Bug#9-coexistence constraint.
func TestCleanupDetachedGhosts_SkipsGated(t *testing.T) {
	sm := newGhostTestManager(t)
	s := mustCreateSession(t, sm)
	now := time.Now()

	s.AttachedAt.Store(now.Add(-60 * time.Second).UnixNano())
	s.DetachedAt.Store(now.Add(-30 * time.Second).UnixNano()) // well past grace

	// Gate refuses — simulate an active orphan relay mid-migration for this id.
	gate := func(id uint32) bool { return false }

	swept := sm.CleanupDetachedGhosts(now, 8*time.Second, gate)
	if len(swept) != 0 {
		t.Fatalf("a gated session (mid-migration) must NOT be swept, got %v", swept)
	}
	if _, ok := sm.Get(s.ID); !ok {
		t.Fatal("a gated session must survive the sweep (RESUME may re-adopt it)")
	}
}

// TestCleanupDetachedGhosts_SkipsNeverDetached: a session still attached
// (DetachedAt==0 — live transport) is never a ghost.
func TestCleanupDetachedGhosts_SkipsNeverDetached(t *testing.T) {
	sm := newGhostTestManager(t)
	s := mustCreateSession(t, sm)
	now := time.Now()

	s.AttachedAt.Store(now.Add(-60 * time.Second).UnixNano())
	// DetachedAt stays 0 — transport currently attached.

	swept := sm.CleanupDetachedGhosts(now, 8*time.Second, func(uint32) bool { return true })
	if len(swept) != 0 {
		t.Fatalf("a still-attached session must NOT be swept, got %v", swept)
	}
}

// TestCleanupDetachedGhosts_ReattachClearsDetach: a session that detached and
// then RE-ATTACHED (reconnect re-adopted it: DetachedAt reset to 0) must not be
// swept even long after the original detach.
func TestCleanupDetachedGhosts_ReattachClearsDetach(t *testing.T) {
	sm := newGhostTestManager(t)
	s := mustCreateSession(t, sm)
	now := time.Now()

	s.AttachedAt.Store(now.Add(-120 * time.Second).UnixNano())
	s.DetachedAt.Store(now.Add(-60 * time.Second).UnixNano())
	// Reconnect re-adopted the session — DetachedAt cleared.
	s.DetachedAt.Store(0)

	swept := sm.CleanupDetachedGhosts(now, 8*time.Second, func(uint32) bool { return true })
	if len(swept) != 0 {
		t.Fatalf("a re-attached session must NOT be swept, got %v", swept)
	}
}

// TestReattachClearDetached_ClearsLiveSession: the happy path — a still-present
// session has its DetachedAt cleared and the commit reports success.
func TestReattachClearDetached_ClearsLiveSession(t *testing.T) {
	sm := newGhostTestManager(t)
	s := mustCreateSession(t, sm)
	s.AttachedAt.Store(time.Now().Add(-60 * time.Second).UnixNano())
	s.DetachedAt.Store(time.Now().Add(-30 * time.Second).UnixNano())

	if !sm.ReattachClearDetached(s.ID) {
		t.Fatal("ReattachClearDetached must succeed for a present session")
	}
	if s.DetachedAt.Load() != 0 {
		t.Fatalf("DetachedAt must be cleared to 0, got %d", s.DetachedAt.Load())
	}
}

// TestReattachClearDetached_FailsForSweptSession: if the sweep already removed
// the session, the commit reports false so the caller aborts the attach.
func TestReattachClearDetached_FailsForSweptSession(t *testing.T) {
	sm := newGhostTestManager(t)
	s := mustCreateSession(t, sm)
	sm.Remove(s.ID) // sweep won the race and deleted it

	if sm.ReattachClearDetached(s.ID) {
		t.Fatal("ReattachClearDetached must report false for an already-removed session")
	}
}

// TestCleanupDetachedGhosts_TOCTOU_ReattachBeforeSweepDelete is the HIGH-4 /
// H-S3 regression for the WINNING-RECONNECT ordering. It pins the contract that
// closes the TOCTOU window deterministically:
//
// The race is between a pool reconnect (websocket.go: WSAttached CAS-win →
// clear DetachedAt) and the sweep's Phase-2 critical section (re-read
// DetachedAt under sm.mu → delete). The fix routes the reconnect's clear
// through ReattachClearDetached, which holds the SAME sm.mu the sweep's delete
// holds. The two are therefore mutually exclusive; the only two real orderings
// are:
//
//	(1) reconnect's lock-held clear runs first  → sweep's lock-held DetachedAt
//	    re-read sees 0 → session SURVIVES (this test).
//	(2) sweep's lock-held delete runs first      → ReattachClearDetached's
//	    lookup misses → returns false → caller aborts the attach
//	    (TestReattachClearDetached_FailsForSweptSession + the
//	    websocket.go undo-latch path).
//
// A bare `DetachedAt.Store(0)` (the pre-fix code) is NOT serialized with the
// delete, so a reconnect could clear AFTER the sweep's lock-held re-read but
// the session would already be gone, or the delete could land between the
// reader's last check and the Store — deleting a live, just-attached session.
//
// Here we drive ordering (1) directly: the reconnect commits via the real
// serialized path, THEN the sweep runs. The session must survive.
//
// NOTE for CI: true concurrent interleaving is exercised under `go test -race`
// on Linux (no cgo/-race on the Windows dev box). This test forces the
// adversarial ordering so it is deterministic regardless of -race.
func TestCleanupDetachedGhosts_TOCTOU_ReattachBeforeSweepDelete(t *testing.T) {
	sm := newGhostTestManager(t)
	s := mustCreateSession(t, sm)
	now := time.Now()

	// Eligible ghost as the sweep's Phase 1 collected it: attached long ago,
	// detached well past grace, and a gate that (mirroring the audit window)
	// observed WSAttached==false and so still answers "eligible".
	s.AttachedAt.Store(now.Add(-120 * time.Second).UnixNano())
	s.DetachedAt.Store(now.Add(-30 * time.Second).UnixNano())
	gate := func(uint32) bool { return true }

	// The reconnect wins the WSAttached CAS and commits the re-attach via the
	// sm.mu-serialized path — ordered BEFORE the sweep's lock-held delete.
	if !sm.ReattachClearDetached(s.ID) {
		t.Fatal("reconnect commit must succeed — the session is still present")
	}

	// The sweep now takes sm.mu and re-reads DetachedAt: it is 0, so the
	// just-reattached live session MUST be skipped, not deleted.
	swept := sm.CleanupDetachedGhosts(now, 8*time.Second, gate)

	if len(swept) != 0 {
		t.Fatalf("session re-attached in the race window MUST NOT be swept, got %v", swept)
	}
	if _, ok := sm.Get(s.ID); !ok {
		t.Fatal("the freshly re-attached session must survive the sweep")
	}
	if s.DetachedAt.Load() != 0 {
		t.Fatalf("re-attach must have cleared DetachedAt, got %d", s.DetachedAt.Load())
	}
}

// TestCleanupDetachedGhosts_TOCTOU_ConcurrentReattach exercises the genuinely
// concurrent interleaving: a sweep goroutine and a reconnect goroutine race on
// the same session with no enforced ordering. The invariant under test is the
// SAFETY one: the session is never left in a torn state — either it survives
// with DetachedAt==0 (reconnect's clear serialized before the delete) or it is
// swept AND the reconnect's commit reported false (delete serialized first).
// It must NEVER be the case that the reconnect's commit reported success yet
// the session was swept (that is the HIGH-4 spurious teardown).
//
// Run under `go test -race` on Linux/CI to catch ordering violations the
// Windows dev box (no -race) cannot. Repeated to widen the interleaving net.
func TestCleanupDetachedGhosts_TOCTOU_ConcurrentReattach(t *testing.T) {
	gate := func(uint32) bool { return true }
	for i := 0; i < 200; i++ {
		sm := newGhostTestManager(t)
		s := mustCreateSession(t, sm)
		now := time.Now()
		s.AttachedAt.Store(now.Add(-120 * time.Second).UnixNano())
		s.DetachedAt.Store(now.Add(-30 * time.Second).UnixNano())

		var swept []uint32
		var commitOK bool
		start := make(chan struct{})
		done := make(chan struct{}, 2)

		go func() {
			<-start
			swept = sm.CleanupDetachedGhosts(now, 8*time.Second, gate)
			done <- struct{}{}
		}()
		go func() {
			<-start
			commitOK = sm.ReattachClearDetached(s.ID)
			done <- struct{}{}
		}()
		close(start)
		<-done
		<-done

		_, present := sm.Get(s.ID)
		wasSwept := len(swept) == 1 && swept[0] == s.ID

		// The forbidden state: the reconnect believed it succeeded but the
		// session was swept out from under it.
		if commitOK && wasSwept {
			t.Fatalf("iter %d: HIGH-4 violation — reconnect committed OK yet session was swept", i)
		}
		// Mutually consistent outcomes only.
		if wasSwept && present {
			t.Fatalf("iter %d: session reported swept but still present", i)
		}
		if commitOK && !present {
			t.Fatalf("iter %d: commit reported OK but session is gone", i)
		}
	}
}

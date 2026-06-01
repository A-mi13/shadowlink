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

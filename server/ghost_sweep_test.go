package server

import (
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Server ghost-sweep gate (spec 2026-06-01-pool-capacity-dip-fix-design.md,
// server ghost-sweep section). The gate (ghostSweepEligible) is where the
// Bug#9-coexistence constraint lives: a detached session a stream is migrating
// onto (orphaned relay still bound) MUST NOT be reclaimed mid-RESUME.
// ---------------------------------------------------------------------------

// ghostSweepSession creates a session in the handler's manager and a matching
// tunnel, stamped attached-then-detached `detachAgo` in the past.
func ghostSweepSession(t *testing.T, h *Handler, clientID string, detachAgo time.Duration) *core.Session {
	t.Helper()
	key := make([]byte, 32)
	s, err := h.sessions.Create(key, key)
	require.NoError(t, err)
	now := time.Now()
	s.AttachedAt.Store(now.Add(-2 * time.Minute).UnixNano())
	s.DetachedAt.Store(now.Add(-detachAgo).UnixNano())

	tun := &Tunnel{SessionID: s.ID, ClientID: clientID}
	tun.WSAttached.Store(false) // reader exited
	h.tunnelsMu.Lock()
	h.tunnels[s.ID] = tun
	h.tunnelsMu.Unlock()
	return s
}

// TestGhostSweepEligible_NoRelayDetached: an attached-then-detached session
// with no bound relay and no live transport is eligible to sweep.
func TestGhostSweepEligible_NoRelayDetached(t *testing.T) {
	h, _ := setupTestHandler(t)
	s := ghostSweepSession(t, h, "user-1:devA", 30*time.Second)

	require.True(t, h.ghostSweepEligible(s.ID),
		"a detached session with no bound relay and no live transport is a sweepable ghost")
}

// TestGhostSweepEligible_LiveTransportBlocks: a session whose WSAttached latch
// is set (a transport re-attached) is NOT eligible.
func TestGhostSweepEligible_LiveTransportBlocks(t *testing.T) {
	h, _ := setupTestHandler(t)
	s := ghostSweepSession(t, h, "user-1:devA", 30*time.Second)

	h.tunnelsMu.RLock()
	h.tunnels[s.ID].WSAttached.Store(true)
	h.tunnelsMu.RUnlock()

	require.False(t, h.ghostSweepEligible(s.ID),
		"a session with a live attached transport must NOT be swept")
}

// TestGhostSweepEligible_BoundOrphanRelayBlocks: the critical Bug#9 constraint —
// a detached session with an orphaned relay STILL BOUND to it (a stream is
// mid-RESUME in the grace window) must NOT be swept.
func TestGhostSweepEligible_BoundOrphanRelayBlocks(t *testing.T) {
	h, _ := setupTestHandler(t)
	s := ghostSweepSession(t, h, "user-1:devA", 30*time.Second)

	// Register a relay still bound to this session (an orphaned relay whose
	// binding has not yet moved to a new slot — a RESUME may re-adopt it).
	e := &relayEntry{originClientID: "user-1:devA", globalStreamID: 7}
	e.bound.Store(&binding{session: s})
	h.relayRegistry.add("user-1:devA", 7, e)

	require.False(t, h.ghostSweepEligible(s.ID),
		"a session with an orphaned relay still bound to it must NOT be swept "+
			"(a stream may RESUME onto it in the migration grace window)")

	// Once the relay moves away (binding points elsewhere) / is removed, the
	// session becomes a sweepable ghost.
	h.relayRegistry.remove("user-1:devA", 7)
	require.True(t, h.ghostSweepEligible(s.ID),
		"after the orphaned relay is gone, the detached session is a sweepable ghost")
}

// TestGhostSweepEligible_RelayMigratedAwayIsSweepable: a relay that was
// preemptively migrated to ANOTHER live slot has its binding pointing at a
// different session — it is no longer bound to the dying session, so the dying
// session IS a sweepable ghost (the migrated stream keeps running elsewhere).
// This pins that the gate keys on binding identity, not mere clientID presence.
func TestGhostSweepEligible_RelayMigratedAwayIsSweepable(t *testing.T) {
	h, _ := setupTestHandler(t)
	dying := ghostSweepSession(t, h, "user-1:devA", 30*time.Second)

	// A relay under the same clientID, but bound to a DIFFERENT (live) session —
	// it migrated to another slot and no longer references `dying`.
	otherKey := make([]byte, 32)
	otherSess, err := h.sessions.Create(otherKey, otherKey)
	require.NoError(t, err)
	e := &relayEntry{originClientID: "user-1:devA", globalStreamID: 11}
	e.bound.Store(&binding{session: otherSess})
	h.relayRegistry.add("user-1:devA", 11, e)

	require.True(t, h.ghostSweepEligible(dying.ID),
		"a session whose relay migrated AWAY (binding points elsewhere) is a "+
			"sweepable ghost — the gate keys on binding identity, not clientID presence")
}

// TestCleanupDetachedGhosts_HandlerGate_EndToEnd: drives the real
// CleanupDetachedGhosts with the handler gate. A bound-relay session survives;
// a no-relay session past grace is swept.
func TestCleanupDetachedGhosts_HandlerGate_EndToEnd(t *testing.T) {
	h, _ := setupTestHandler(t)

	// Ghost: detached 30s ago, no relay → should be swept.
	ghost := ghostSweepSession(t, h, "user-ghost:devA", 30*time.Second)
	// Migrating: detached 30s ago but an orphaned relay is still bound → survive.
	migrating := ghostSweepSession(t, h, "user-mig:devB", 30*time.Second)
	e := &relayEntry{originClientID: "user-mig:devB", globalStreamID: 9}
	e.bound.Store(&binding{session: migrating})
	h.relayRegistry.add("user-mig:devB", 9, e)

	swept := h.sessions.CleanupDetachedGhosts(time.Now(), detachedGhostGrace, h.ghostSweepEligible)

	require.Contains(t, swept, ghost.ID, "the no-relay detached ghost must be swept")
	require.NotContains(t, swept, migrating.ID,
		"the mid-migration session (bound orphan relay) must NOT be swept")

	_, ghostStillThere := h.sessions.Get(ghost.ID)
	require.False(t, ghostStillThere, "swept ghost is removed from the manager")
	_, migStillThere := h.sessions.Get(migrating.ID)
	require.True(t, migStillThere, "mid-migration session survives the sweep")
}

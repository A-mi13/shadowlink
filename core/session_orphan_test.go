package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSession_NewbornNotAttached_CleanedAfter30s exercises Plan §C10 M2
// (May 2026 audit). A session whose AttachedAt remains zero for longer
// than the grace window must be evicted by CleanupNewbornOrphans.
func TestSession_NewbornNotAttached_CleanedAfter30s(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	s, err := sm.Create(make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)

	// Mock time: pretend the session was created 31 seconds ago by passing
	// a now() that is 31s ahead. Avoids real sleeps.
	now := s.CreatedAt.Add(31 * time.Second)
	evicted := sm.CleanupNewbornOrphans(now, 30*time.Second)

	require.Len(t, evicted, 1)
	require.Equal(t, s.ID, evicted[0])

	_, ok := sm.Get(s.ID)
	require.False(t, ok, "evicted session must be gone from manager")
}

// TestSession_NewbornNotAttached_NotCleanedWithinGrace verifies that
// sessions younger than the grace window are NOT evicted — the orphan
// fast path must not race the legitimate WS upgrade window.
func TestSession_NewbornNotAttached_NotCleanedWithinGrace(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	s, err := sm.Create(make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)

	// 10s old — well within the 30s grace window.
	now := s.CreatedAt.Add(10 * time.Second)
	evicted := sm.CleanupNewbornOrphans(now, 30*time.Second)
	require.Empty(t, evicted, "session within grace window must not be evicted")

	got, ok := sm.Get(s.ID)
	require.True(t, ok)
	require.Equal(t, s.ID, got.ID)
}

// TestSession_Attached_NotCleanedAt30s verifies sessions with a non-zero
// AttachedAt are skipped — they fall under the regular idle-timeout
// policy, not the newborn fast path.
func TestSession_Attached_NotCleanedAt30s(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	s, err := sm.Create(make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)

	// Simulate WS first-frame auth: stamp AttachedAt to "right after
	// CreatedAt". Then advance now() well past the grace window — the
	// regular Cleanup() (called separately) handles idle timeout.
	s.AttachedAt.Store(s.CreatedAt.Add(100 * time.Millisecond).UnixNano())

	now := s.CreatedAt.Add(31 * time.Second)
	evicted := sm.CleanupNewbornOrphans(now, 30*time.Second)
	require.Empty(t, evicted, "attached session must not be evicted by orphan fast path")

	_, ok := sm.Get(s.ID)
	require.True(t, ok)
}

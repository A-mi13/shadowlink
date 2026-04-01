package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUserID(t *testing.T) {
	tests := []struct {
		clientID string
		expected string
	}{
		{"u42:d1", "u42"},
		{"u108:d2", "u108"},
		{"nocolon", "nocolon"},
		{"u1:d1:extra", "u1"},  // only first colon matters
		{":leading", ""},       // edge case: empty userID
		{"trailing:", "trailing"},
	}

	for _, tc := range tests {
		t.Run(tc.clientID, func(t *testing.T) {
			got := parseUserID(tc.clientID)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestClientAuthDeviceLimit(t *testing.T) {
	// Default limit is 3, so with defaultMax=2 we test with 2.
	// Create auth with 3 clients for user "u1".
	ca := NewClientAuth([]string{"u1:d1", "u1:d2", "u1:d3"})
	// Override default limit to 2 for this test.
	ca.defaultMax = 2

	// No sessions yet — should allow device.
	assert.True(t, ca.CheckDeviceLimit("u1:d1"), "first device should be allowed")

	// Create session for d1.
	ca.OnSessionCreated("u1:d1", 100)
	assert.Equal(t, 1, ca.ActiveSessionCount("u1"))

	// Second device should still be allowed.
	assert.True(t, ca.CheckDeviceLimit("u1:d2"), "second device should be allowed")
	ca.OnSessionCreated("u1:d2", 200)
	assert.Equal(t, 2, ca.ActiveSessionCount("u1"))

	// Third device should be blocked (limit=2).
	assert.False(t, ca.CheckDeviceLimit("u1:d3"), "third device should be blocked with limit=2")

	// Destroy one session — third should now pass.
	ca.OnSessionDestroyed("u1:d1", 100)
	assert.Equal(t, 1, ca.ActiveSessionCount("u1"))
	assert.True(t, ca.CheckDeviceLimit("u1:d3"), "third device should be allowed after destroying one")
}

func TestClientAuthDeviceLimitOpenMode(t *testing.T) {
	// Open mode: all clients allowed, no device limit checks.
	ca := NewClientAuth(nil)
	assert.True(t, ca.openMode)
	assert.True(t, ca.CheckDeviceLimit("anyuser:anydevice"), "open mode should always allow")
}

func TestClientAuthSetUserLimit(t *testing.T) {
	ca := NewClientAuth([]string{"u5:d1", "u5:d2", "u5:d3", "u5:d4"})
	// Default max is 3.
	require.Equal(t, 3, ca.defaultMax)

	// Create 3 sessions — should hit default limit.
	ca.OnSessionCreated("u5:d1", 1)
	ca.OnSessionCreated("u5:d2", 2)
	ca.OnSessionCreated("u5:d3", 3)
	assert.False(t, ca.CheckDeviceLimit("u5:d4"), "should be blocked at default limit=3")

	// Increase limit for u5 to 5.
	ca.SetUserLimit("u5", 5)
	assert.True(t, ca.CheckDeviceLimit("u5:d4"), "should be allowed after SetUserLimit(5)")
}

func TestClientAuthSyncClients(t *testing.T) {
	// Start with some clients.
	ca := NewClientAuth([]string{"u1:d1", "u2:d1"})
	assert.True(t, ca.IsAuthorized("u1:d1"))
	assert.True(t, ca.IsAuthorized("u2:d1"))

	// Create a session for u1:d1.
	ca.OnSessionCreated("u1:d1", 100)

	// Sync: replace with new set, u1:d1 removed, u3:d1 added.
	newClients := []string{"u2:d1", "u3:d1"}
	limits := map[string]int{"u2": 5, "u3": 2}
	ca.SyncClients(newClients, limits)

	// Old client removed.
	assert.False(t, ca.IsAuthorized("u1:d1"), "u1:d1 should be removed after sync")
	// New clients present.
	assert.True(t, ca.IsAuthorized("u2:d1"), "u2:d1 should remain after sync")
	assert.True(t, ca.IsAuthorized("u3:d1"), "u3:d1 should be added after sync")

	// Open mode should be false.
	assert.False(t, ca.openMode, "openMode should be false after sync with clients")

	// Limits should be applied.
	ca.OnSessionCreated("u3:d1", 300)
	ca.OnSessionCreated("u3:d2", 301) // not authorized, but session tracking is separate
	assert.False(t, ca.CheckDeviceLimit("u3:d3"), "u3 limit=2, should block 3rd")

	// Old sessions for removed user should be cleaned up.
	assert.Equal(t, 0, ca.ActiveSessionCount("u1"), "u1 sessions should be cleaned after sync")
}

func TestClientAuthOnSessionDestroyedIdempotent(t *testing.T) {
	ca := NewClientAuth([]string{"u1:d1"})
	ca.OnSessionCreated("u1:d1", 100)
	assert.Equal(t, 1, ca.ActiveSessionCount("u1"))

	// Destroy twice — should not panic or go negative.
	ca.OnSessionDestroyed("u1:d1", 100)
	ca.OnSessionDestroyed("u1:d1", 100)
	assert.Equal(t, 0, ca.ActiveSessionCount("u1"))
}

func TestClientAuthCheckDeviceLimitExistingSession(t *testing.T) {
	// A client that already has an active session should always be allowed
	// (they're reconnecting, not a new device).
	ca := NewClientAuth([]string{"u1:d1", "u1:d2"})
	ca.defaultMax = 1

	ca.OnSessionCreated("u1:d1", 100)
	// u1 is at limit (1), but d1 already has a session — should pass.
	assert.True(t, ca.CheckDeviceLimit("u1:d1"), "reconnecting client should be allowed")
	// d2 is genuinely new — should be blocked.
	assert.False(t, ca.CheckDeviceLimit("u1:d2"), "new device should be blocked at limit")
}

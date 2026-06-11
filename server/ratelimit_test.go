package server

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/nixavpn/shadowlink/core"
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
		{"u1:d1:extra", "u1"}, // only first colon matters
		{":leading", ""},      // edge case: empty userID
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

func TestClientAuth_IsOpenMode(t *testing.T) {
	open := NewClientAuth(nil)
	assert.True(t, open.IsOpenMode())

	closed := NewClientAuth([]string{"u1:d1"})
	assert.False(t, closed.IsOpenMode())
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

// TestNewHandlerHandshakeRateLimitFromConfig verifies that the handler's
// rate limiter respects Config.HandshakeRateLimitPerMin so we can raise the
// cap above the legacy 50/min hardcode that was breaking pool reconnect.
func TestNewHandlerHandshakeRateLimitFromConfig(t *testing.T) {
	// Force legacy path: test exercises h.rateLimiters.Handshake.Allow directly.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig()
	cfg.HandshakeRateLimitPerMin = 100

	h := NewHandler(serverKey, cfg, "")

	// First 100 attempts from one IP must be allowed.
	for i := 0; i < 100; i++ {
		require.True(t, h.rateLimiters.Handshake.Allow("203.0.113.10"),
			"attempt %d/100 must pass under configured limit", i+1)
	}
	// 101st must be blocked.
	require.False(t, h.rateLimiters.Handshake.Allow("203.0.113.10"),
		"attempt 101 must be rate-limited")
}

// TestNewHandlerHandshakeRateLimitDefaultRaised verifies the new default
// (300/min) replaces the legacy hardcoded 50/min that throttled legitimate
// pool reconnect bursts. Pool of 4 slots × cascade reconnects can easily
// generate 30+ handshakes/min from one IP — we must allow this.
func TestNewHandlerHandshakeRateLimitDefaultRaised(t *testing.T) {
	// Force legacy path: test exercises h.rateLimiters.Handshake.Allow directly.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig() // does not set HandshakeRateLimitPerMin
	h := NewHandler(serverKey, cfg, "")

	// At least 100 attempts must pass under default — well above old 50.
	allowed := 0
	for i := 0; i < 100; i++ {
		if h.rateLimiters.Handshake.Allow("203.0.113.20") {
			allowed++
		}
	}
	require.GreaterOrEqual(t, allowed, 100,
		"default rate limit must allow >=100 handshakes/min for pool reconnect; got %d", allowed)
}

// TestRateLimitersSplit_IndependentBudgets confirms the Phase B split: a
// handshake burst that exhausts the Handshake limiter must NOT affect the
// Data limiter from the same IP. The isolation is the whole point — a DoSing
// attacker flooding handshakes cannot starve an active session's data path.
func TestRateLimitersSplit_IndependentBudgets(t *testing.T) {
	// Force legacy path: test exercises the legacy .Allow() methods directly on
	// individual limiter fields to verify budget isolation.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig()
	cfg.HandshakeRateLimitPerMin = 10 // easy to exhaust
	h := NewHandler(serverKey, cfg, "")

	ip := "203.0.113.30"
	// Exhaust handshake budget.
	for range 10 {
		require.True(t, h.rateLimiters.Handshake.Allow(ip))
	}
	require.False(t, h.rateLimiters.Handshake.Allow(ip), "handshake must be capped at 10")

	// Data limiter must still accept traffic on the same IP.
	require.True(t, h.rateLimiters.Data.Allow(ip), "data limiter must be independent of handshake")
	require.True(t, h.rateLimiters.WSUpgrade.Allow(ip), "ws-upgrade limiter must be independent")
}

// TestHandshake_RateLimit_BucketPath verifies that when SHADOWLINK_RL_TOKENBUCKET
// is active (default-on), draining the HandshakeBucket directly causes the HTTP
// handleHandshakeNew path to return a decoy 200 (rate-limited). This exercises
// the TokenBucket dispatch branch in AllowHandshake.
func TestHandshake_RateLimit_BucketPath(t *testing.T) {
	// Bucket path is the default; no env override needed. We ensure it explicitly.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "1")

	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig()
	cfg.HandshakeRateLimitPerMin = 300
	h := NewHandler(serverKey, cfg, "")

	require.True(t, h.rateLimiters.UseBucket, "UseBucket must be true when token bucket path is on")
	require.NotNil(t, h.rateLimiters.HandshakeBucket)

	// Replace the production-sized bucket (burst=50) with a 1-token bucket so
	// the test exhausts via the HTTP wire path itself. This proves the
	// AllowHandshake → HandshakeBucket dispatch is wired AND that the IP key
	// extracted by ClientIPFromRequest matches the bucket's key — without it,
	// the test could pass while a future IP-extraction regression silently
	// bypassed the bucket dispatch (review finding 2026-05-02).
	h.rateLimiters.HandshakeBucket = NewTokenBucket(1, 0.0001, 10)

	ip := "203.0.113.55"
	// First HTTP request consumes the only token via AllowHandshake → bucket.
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/a", bytes.NewReader([]byte("{}")))
	req1.RemoteAddr = ip + ":55555"
	h.handleHandshakeNew(rec1, req1, []byte("eph"), []byte("enc"))
	require.Empty(t, rec1.Header().Get("X-SL-RL"),
		"first request must NOT be rate-limited (bucket has 1 token, no sentinel)")

	// Second request hits an empty bucket and must take the rate-limit
	// branch — proving the wire path consumes from the same bucket. C5 verbose
	// format is "bucket=handshake,burst_left=...,refill_in=...s,exempt=0";
	// burst_left/refill_in are bucket-state-dependent, so we substring-match
	// the stable prefix instead of pinning the exact numeric values.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/a", bytes.NewReader([]byte("{}")))
	req2.RemoteAddr = ip + ":55555"
	h.handleHandshakeNew(rec2, req2, []byte("eph"), []byte("enc"))
	got := rec2.Header().Get("X-SL-RL")
	require.Contains(t, got, "bucket=handshake",
		"second request must emit verbose X-SL-RL sentinel (bucket exhausted via HTTP); got=%q", got)
	require.Contains(t, got, "exempt=0",
		"sentinel must include exempt field; got=%q", got)
}

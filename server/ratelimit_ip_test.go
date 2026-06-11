package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nixavpn/shadowlink/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTrustedProxies(t *testing.T) {
	set, err := parseTrustedProxies([]string{"10.0.0.0/8", "192.168.1.5", "::1"})
	require.NoError(t, err)

	// Loopback is always implicitly trusted, even if not listed.
	assert.True(t, set.contains("127.0.0.1"), "127.0.0.1 must be implicitly trusted")
	assert.True(t, set.contains("::1"), "::1 must be trusted")
	// Explicit CIDR.
	assert.True(t, set.contains("10.5.6.7"), "10.0.0.0/8 must match")
	// Bare IP normalized to /32.
	assert.True(t, set.contains("192.168.1.5"))
	assert.False(t, set.contains("192.168.1.6"), "outside the /32")
	// Public client IP is not trusted.
	assert.False(t, set.contains("203.0.113.9"))
}

func TestParseTrustedProxies_Invalid(t *testing.T) {
	_, err := parseTrustedProxies([]string{"not-a-cidr"})
	require.Error(t, err)
}

func TestTrustedProxySet_Nil(t *testing.T) {
	// nil/empty set still trusts loopback (default nginx-on-localhost case).
	set, err := parseTrustedProxies(nil)
	require.NoError(t, err)
	assert.True(t, set.contains("127.0.0.1"))
	assert.False(t, set.contains("8.8.8.8"))
}

func TestClientIP_DirectModeIgnoresXFF(t *testing.T) {
	// BehindProxy=false → XFF ignored, RemoteAddr only. Unchanged behaviour.
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	set, _ := parseTrustedProxies(nil)
	assert.Equal(t, "203.0.113.9", clientIPFromRequest(req, false, set))
}

func TestClientIP_OneHopNginx(t *testing.T) {
	// nginx on localhost appended the real client to XFF; RemoteAddr is loopback.
	set, _ := parseTrustedProxies(nil) // loopback-only trust
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	assert.Equal(t, "203.0.113.9", clientIPFromRequest(req, true, set))
}

func TestClientIP_SpoofedLeftmostRejected(t *testing.T) {
	// Attacker prepends a fake leftmost IP; nginx appends the REAL client to the
	// right. The rightmost-untrusted walk must return the appended real client,
	// NOT the spoofed leftmost.
	set, _ := parseTrustedProxies(nil)
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 203.0.113.9")
	assert.Equal(t, "203.0.113.9", clientIPFromRequest(req, true, set))
}

func TestClientIP_TwoHopCDN(t *testing.T) {
	// CDN egress 198.51.100.0/24 trusted; chain: client, cdn-edge. RemoteAddr loopback.
	set, _ := parseTrustedProxies([]string{"198.51.100.0/24"})
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
	assert.Equal(t, "203.0.113.9", clientIPFromRequest(req, true, set))
}

func TestClientIP_AllTrustedFallsBackToLeftmost(t *testing.T) {
	// Degenerate: every hop trusted → fall back to leftmost XFF token.
	set, _ := parseTrustedProxies([]string{"10.0.0.0/8"})
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	req.Header.Set("X-Forwarded-For", "10.1.1.1, 10.2.2.2")
	assert.Equal(t, "10.1.1.1", clientIPFromRequest(req, true, set))
}

func TestClientIP_NoXFFUsesRemoteAddr(t *testing.T) {
	set, _ := parseTrustedProxies(nil)
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	assert.Equal(t, "203.0.113.9", clientIPFromRequest(req, true, set))
}

// TestHandshakeBucket_NotBypassedBySpoofedXFF proves the end-to-end wire path:
// a spoofed leftmost XFF token cannot mint a fresh per-IP handshake bucket key.
// The rightmost-untrusted walk pins the bucket key to the real client appended
// on the right by nginx, so two requests with different spoofed leftmosts but
// the SAME real client share one bucket and the second is rate-limited. HIGH-1.
func TestHandshakeBucket_NotBypassedBySpoofedXFF(t *testing.T) {
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig()
	cfg.BehindProxy = true
	cfg.TrustedProxies = nil // loopback-only; RemoteAddr will be loopback
	h := NewHandler(serverKey, cfg, "")
	require.True(t, h.rateLimiters.UseBucket)

	// 1-token bucket so the second request from the SAME real client trips it.
	h.rateLimiters.HandshakeBucket = NewTokenBucket(1, 0.0001, 10)

	makeReq := func(spoofLeftmost string) *http.Request {
		req := httptest.NewRequest("POST", "/a", bytes.NewReader([]byte("{}")))
		req.RemoteAddr = "127.0.0.1:55555" // nginx on localhost
		// Attacker rotates the leftmost; nginx appends the SAME real client right.
		req.Header.Set("X-Forwarded-For", spoofLeftmost+", 203.0.113.9")
		return req
	}

	rec1 := httptest.NewRecorder()
	h.handleHandshakeNew(rec1, makeReq("9.9.9.9"), []byte("eph"), []byte("enc"))
	require.Empty(t, rec1.Header().Get("X-SL-RL"), "first request: bucket has the token")

	// Different spoofed leftmost, SAME real client → must hit the SAME bucket key
	// (203.0.113.9) and be rate-limited. Pre-fix this would bypass (fresh key).
	rec2 := httptest.NewRecorder()
	h.handleHandshakeNew(rec2, makeReq("8.8.8.8"), []byte("eph"), []byte("enc"))
	require.Contains(t, rec2.Header().Get("X-SL-RL"), "bucket=handshake",
		"spoofed leftmost must NOT mint a fresh bucket key; real client is rate-limited")
}

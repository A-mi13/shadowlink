package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveECHConfig_CloudflareDomain(t *testing.T) {
	config, err := ResolveECHConfig("crypto.cloudflare.com")
	if err != nil {
		t.Skipf("ECH resolution failed (network?): %v", err)
	}
	assert.NotEmpty(t, config)
	assert.GreaterOrEqual(t, len(config), 4)
}

func TestResolveECHConfig_NonExistentDomain(t *testing.T) {
	_, err := ResolveECHConfig("this-domain-does-not-exist-12345.invalid")
	assert.Error(t, err)
}

func TestResolveECHConfig_NoDNSHTTPS(t *testing.T) {
	_, err := ResolveECHConfig("example.com")
	// Should return error (no ECH), not panic
	if err == nil {
		t.Log("example.com has ECH config (unexpected but ok)")
	}
}

func TestECHConfig_IsExpired(t *testing.T) {
	var ec *ECHConfig
	assert.True(t, ec.IsExpired(), "nil config should be expired")

	ec = &ECHConfig{}
	assert.True(t, ec.IsExpired(), "empty config should be expired")
}

// TestNewDoHClient_UsesUTLSTransport verifies that the DoH HTTP client used by
// ResolveECHConfig is wired through the uTLS dialer (DialTLSContext set),
// not the Go stdlib's default TLS roundtripper.
//
// A2-MED-1 (2026-04 audit): the previous implementation built `&http.Client{}`
// inline and called `httpClient.Post("https://1.1.1.1/dns-query", ...)`. That
// emits the canonical Go-stdlib JA3 from the same client IP that minutes later
// speaks Chrome/Safari/Firefox JA3 over the data path — a free fingerprint
// inconsistency for any passive observer who can co-locate the DoH and
// ShadowLink flows. This test pins the fix: the DoH client MUST go through
// buildUTLSHTTPClient (which sets DialTLSContext on the underlying Transport).
func TestNewDoHClient_UsesUTLSTransport(t *testing.T) {
	c := newDoHClient()
	require.NotNil(t, c, "newDoHClient must return non-nil *http.Client")

	tr, ok := c.Transport.(*http.Transport)
	require.True(t, ok, "DoH client Transport must be *http.Transport (got %T)", c.Transport)
	require.NotNil(t, tr.DialTLSContext, "DialTLSContext must be set — proves uTLS routing (A2-MED-1)")
	// DisableKeepAlives matches buildUTLSHTTPClient's cold-path posture
	// (each DoH request gets a fresh TCP+TLS handshake, no JA3 leak via
	// long-lived connection).
	assert.True(t, tr.DisableKeepAlives, "DoH client must disable keepalives (cold-path JA3 hygiene)")
}

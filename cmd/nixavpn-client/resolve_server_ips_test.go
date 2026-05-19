package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestResolveServerIPs_OriginOverrideExclusive verifies the 2026-05-18 fix
// for the origin-bypass leak: when ?origin=<IP> is set, the function must
// return ONLY that IP, NOT the full DNS lookup of the CDN domain. Without
// this short-circuit, escape routes covered CF edge IPs (104.21.x.x,
// 172.67.x.x) in addition to the origin, letting reconnect-handshake POSTs
// silently route through CF when the resolver picked a CF answer.
func TestResolveServerIPs_OriginOverrideExclusive(t *testing.T) {
	cfg := &Config{
		ShadowLink: &ShadowLinkConfig{
			Server: "datacanvases.com:443",
			CDN:    "datacanvases.com",
			Origin: "104.222.177.67",
		},
	}

	ips := resolveServerIPs("shadowlink", cfg)
	assert.Equal(t, []string{"104.222.177.67"}, ips,
		"origin override must yield exactly [Origin] — no CDN DNS lookup, "+
			"no extra IPs. Adding CF edge IPs would re-open the bypass leak.")
}

// TestResolveServerIPs_OriginOverride_IgnoredWhenNotIPv4 — config sanity
// regression: if Origin is malformed (not parseable IPv4), we must fall
// back to normal CDN resolution AND warn (the Warn slog call is observable
// indirectly by the lack of early return). The test asserts that we do
// NOT return the malformed string — which would crash the route-add path.
func TestResolveServerIPs_OriginOverride_IgnoredWhenNotIPv4(t *testing.T) {
	cfg := &Config{
		ShadowLink: &ShadowLinkConfig{
			Server: "127.0.0.1:443", // use a literal so we don't hit DNS
			Origin: "not-an-ip",
		},
	}

	ips := resolveServerIPs("shadowlink", cfg)
	// Server is a literal IP, so the rest of the function returns it.
	// What we care about is that "not-an-ip" is NOT in the result.
	for _, ip := range ips {
		assert.NotEqual(t, "not-an-ip", ip, "malformed origin must not leak into escape routes")
	}
}

// TestResolveServerIPs_NoOriginUsesCDN — when no Origin is set, the
// pre-2026-05-18 behavior is preserved: CDN domain is resolved and the
// IPs returned drive the /16 sweep. This is intentional for CDN-mode
// operation. We can't make a real DNS call in unit tests, so we drive
// it with a literal in Server and verify the fallback path returns it
// without injecting unexpected IPs.
func TestResolveServerIPs_NoOriginUsesServerLiteral(t *testing.T) {
	cfg := &Config{
		ShadowLink: &ShadowLinkConfig{
			Server: "203.0.113.5:443", // TEST-NET-3, safe literal
		},
	}

	ips := resolveServerIPs("shadowlink", cfg)
	assert.Equal(t, []string{"203.0.113.5"}, ips,
		"without origin override, IP literal in Server must pass through")
}

package server

import (
	"strings"
	"testing"
)

func TestIsAllowedWSPath_AllPoolPathsAccepted(t *testing.T) {
	paths := AllWSPaths()
	if len(paths) == 0 {
		t.Fatal("AllWSPaths() returned empty pool — at least one path expected")
	}
	if len(paths) < 6 {
		t.Errorf("AllWSPaths() returned only %d paths — pool should have at least 6 to defeat single-path probing (CRIT-4)", len(paths))
	}
	for _, p := range paths {
		// For pool entries that include a query string, IsAllowedWSPath should
		// also accept the bare-path form (since http.Request.URL.Path drops the
		// query). Verify both forms work.
		if !IsAllowedWSPath(p) {
			t.Errorf("pool path %q rejected by IsAllowedWSPath", p)
		}
		if i := strings.IndexByte(p, '?'); i > 0 {
			bare := p[:i]
			if !IsAllowedWSPath(bare) {
				t.Errorf("pool entry %q has bare path %q which IsAllowedWSPath rejected", p, bare)
			}
		}
	}
}

func TestIsAllowedWSPath_NonPoolRejected(t *testing.T) {
	cases := []string{
		"",
		"/",
		"/random/path/not/in/pool",
		"/ws", // CRIT-4: legacy single path no longer accepted
		"/wss",
		"/ws/",
		"/ws?query=1",
		"/api/v2/events", // upload-pool path, not a WS path
		"/SOCKET.IO/",    // case-sensitive check
		"/socket.io",     // missing trailing slash
	}
	for _, p := range cases {
		if IsAllowedWSPath(p) {
			t.Errorf("non-pool path %q unexpectedly accepted", p)
		}
	}
}

func TestAllWSPaths_ReturnsCopy(t *testing.T) {
	a := AllWSPaths()
	if len(a) == 0 {
		t.Fatal("AllWSPaths returned empty")
	}
	orig := a[0]
	a[0] = "/mutated-sentinel"

	b := AllWSPaths()
	if b[0] != orig {
		t.Errorf("AllWSPaths returned shared slice — caller mutation leaked: got %q want %q", b[0], orig)
	}
}

// TestWSURLPool_NoDevEndpoints (Wave 2.1, 2026-05-17) guards the cleanup
// of dev-only / vendor-specific endpoints from the active pool:
//   - /_next/webpack-hmr — Next.js HMR is a development-time only WS endpoint,
//     production deploys never serve it. Including it created a "developer
//     preview deploy" tell.
//   - /track/realtime — vendor-specific public tracking endpoint shape; not
//     a realtime SaaS pattern that mimics general analytics behavior.
// Both paths remain accepted by IsAllowedWSPath via legacyAcceptedWSPaths
// for backward-compat with already-installed clients (see TestIsAllowedWSPath_BackwardCompat).
func TestWSURLPool_NoDevEndpoints(t *testing.T) {
	for _, p := range wsURLPool {
		if strings.Contains(p, "webpack-hmr") || strings.Contains(p, "/_next") || strings.Contains(p, "/__webpack") {
			t.Errorf("WS pool contains dev-only endpoint: %s", p)
		}
		if strings.HasPrefix(p, "/track/") {
			t.Errorf("WS pool contains vendor-track endpoint: %s", p)
		}
	}
	if len(wsURLPool) < 5 {
		t.Errorf("WS pool too small: %d (need >= 5)", len(wsURLPool))
	}
}

// TestIsAllowedWSPath_BackwardCompat (Wave 2.1, 2026-05-17) verifies that the
// retired paths /_next/webpack-hmr and /track/realtime are still accepted by
// the server-side whitelist even after their removal from the active pool.
// Already-installed clients hashed a path at install time and continue to use
// it across the upgrade — rejecting them would force a redeploy. Counter
// Metrics.WSPathLegacyHits tracks how often these are hit, enabling a
// data-driven cutoff decision (when rate < 0.01/s for 2 weeks → safe to drop).
func TestIsAllowedWSPath_BackwardCompat(t *testing.T) {
	if !IsAllowedWSPath("/_next/webpack-hmr") {
		t.Error("legacy /_next/webpack-hmr must still be allowed during transition")
	}
	if !IsAllowedWSPath("/track/realtime") {
		t.Error("legacy /track/realtime must still be allowed during transition")
	}
}

// TestWSPool_NoFingerprintLeak guards CRIT-4: the pool must not contain any
// path that gives away the project ("shadowlink", "vpn", "proxy", etc.). It
// also ensures that "/ws" — the fingerprint we are removing — is not in the
// pool (so an automated regression cannot reintroduce it).
func TestWSPool_NoFingerprintLeak(t *testing.T) {
	forbiddenSubstrings := []string{"shadowlink", "vpn", "proxy", "tunnel"}
	paths := AllWSPaths()
	for _, p := range paths {
		lower := strings.ToLower(p)
		for _, bad := range forbiddenSubstrings {
			if strings.Contains(lower, bad) {
				t.Errorf("pool path %q contains forbidden substring %q (project fingerprint leak)", p, bad)
			}
		}
		if p == "/ws" {
			t.Errorf("pool contains literal %q — this is exactly the CRIT-4 single-path fingerprint we are removing", p)
		}
	}
}

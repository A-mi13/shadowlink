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

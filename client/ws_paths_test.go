package client

import (
	"sort"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/server"
)

// TestWSURLPool_MirrorsServer guards CRIT-4: the client and server pools must
// be byte-identical, otherwise some random-pick attempt by the client will
// land on a path the server's IsAllowedWSPath rejects (silent decoy fall-
// through, looks like a network error to the user).
func TestWSURLPool_MirrorsServer(t *testing.T) {
	clientPool := allWSPaths()
	serverPool := server.AllWSPaths()

	if len(clientPool) != len(serverPool) {
		t.Fatalf("pool size mismatch: client=%d server=%d", len(clientPool), len(serverPool))
	}

	cs := append([]string(nil), clientPool...)
	ss := append([]string(nil), serverPool...)
	sort.Strings(cs)
	sort.Strings(ss)
	for i := range cs {
		if cs[i] != ss[i] {
			t.Errorf("pool entry %d differs: client=%q server=%q", i, cs[i], ss[i])
		}
	}
}

// TestPickWSPath_AllPathsReachable runs many picks and asserts that every
// member of the pool is selected at least once. With N=12 entries and a
// uniform random pick, 5000 trials gives roughly each member selected ~417
// times; missing any one is statistically impossible (P < 1e-300) absent a
// bug.
func TestPickWSPath_AllPathsReachable(t *testing.T) {
	const trials = 5000
	seen := make(map[string]int, len(wsURLPool))
	for i := 0; i < trials; i++ {
		seen[pickWSPath()]++
	}
	for _, p := range wsURLPool {
		if seen[p] == 0 {
			t.Errorf("path %q was never picked across %d trials — pickWSPath is not uniform", p, trials)
		}
	}
	if len(seen) != len(wsURLPool) {
		t.Errorf("picked %d distinct paths, want %d", len(seen), len(wsURLPool))
	}
}

// TestPickWSPath_AcceptedByServer is the CRIT-4 cross-package sanity check:
// every path the client picks must be accepted by the server's
// IsAllowedWSPath. If the two pools ever drift apart, this test fires before
// the WS dial fails on a real user.
func TestPickWSPath_AcceptedByServer(t *testing.T) {
	for i := 0; i < 1000; i++ {
		p := pickWSPath()
		// IsAllowedWSPath compares against r.URL.Path which has the query
		// string stripped. Mirror that here.
		bare := p
		if idx := strings.IndexByte(bare, '?'); idx > 0 {
			bare = bare[:idx]
		}
		if !server.IsAllowedWSPath(bare) {
			t.Fatalf("client pool produced path %q (bare=%q) which the server's IsAllowedWSPath rejected", p, bare)
		}
	}
}

// TestPickWSPath_NoFingerprintLeak guards against accidentally putting a
// project-identifying string into the client pool. Mirrors the equivalent
// server-side test.
func TestPickWSPath_NoFingerprintLeak(t *testing.T) {
	forbidden := []string{"shadowlink", "vpn", "proxy", "tunnel"}
	for _, p := range wsURLPool {
		lower := strings.ToLower(p)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Errorf("client pool path %q contains forbidden substring %q", p, bad)
			}
		}
		if p == "/ws" {
			t.Errorf("client pool contains literal %q — exactly the CRIT-4 fingerprint we removed", p)
		}
	}
}

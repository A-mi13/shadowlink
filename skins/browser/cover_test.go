package browser

import "testing"

// TestDefaultCoverPaths_PoolSize pins the pool size at 10 entries (Wave
// 2.4, 2026-05-17 — 6 Mixpanel/SDK telemetry paths + 4 static asset paths
// for multi-resource decoy mimicry). The chooseWarmupCount cap (≤4 via
// `min(4, len(pool))` in `client/ws_transport.go`) and the
// `ws_transport_warmup_test.go` order-entropy expectations both rely on
// the pool being large enough to permit shuffled prefixes; growing the
// pool only widens that space.
//
// If you change pool size, refit callers — at minimum re-audit:
//   - `chooseWarmupCount` cap behavior in `client/ws_transport.go`
//   - `TestWarmupRequests_OrderEntropy` distinct-tuple threshold
func TestDefaultCoverPaths_PoolSize(t *testing.T) {
	if got := len(defaultCoverPaths); got != 10 {
		t.Fatalf("defaultCoverPaths size = %d, want 10", got)
	}
}

// TestDefaultCoverPaths_ExportedCopy guards against callers mutating the
// internal slice via the exported helper.
func TestDefaultCoverPaths_ExportedCopy(t *testing.T) {
	got := DefaultCoverPaths()
	if len(got) != len(defaultCoverPaths) {
		t.Fatalf("len mismatch: got %d, want %d", len(got), len(defaultCoverPaths))
	}
	got[0] = "/poisoned"
	if defaultCoverPaths[0] == "/poisoned" {
		t.Fatal("DefaultCoverPaths returned the underlying slice")
	}
}

// TestDefaultCoverPaths_IncludesAssetPaths guards Wave 2.4 closure
// (multi-resource decoy mimicry, 2026-05-17): real SPAs request a mix of
// SDK telemetry endpoints AND static page assets (CSS / JS bundle / hero
// image / favicon) before opening a long-lived socket. A pool consisting
// solely of telemetry paths is itself a fingerprintable shape — adding
// static-asset paths broadens the prefix distribution observed by a
// passive logger.
func TestDefaultCoverPaths_IncludesAssetPaths(t *testing.T) {
	want := []string{"/assets/main.css", "/assets/app.js", "/favicon.ico", "/assets/hero.webp"}
	for _, p := range want {
		found := false
		for _, have := range defaultCoverPaths {
			if have == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("defaultCoverPaths missing %q", p)
		}
	}
}

// TestCoverPathsPool_Combines guards the Task 3.1 closure (Wave 3,
// 2026-05-17): CoverPathsPool() returns defaultCoverPaths +
// dynamicCoverPaths (generated from an HTML snapshot of the decoy origin
// via tools/extract_cover_paths). Mutating the returned slice must not
// leak back into either underlying pool.
func TestCoverPathsPool_Combines(t *testing.T) {
	pool := CoverPathsPool()
	wantLen := len(defaultCoverPaths) + len(dynamicCoverPaths)
	if len(pool) != wantLen {
		t.Errorf("CoverPathsPool len = %d, want %d", len(pool), wantLen)
	}
	if len(dynamicCoverPaths) == 0 {
		t.Fatal("dynamicCoverPaths is empty — extract_cover_paths generator regression")
	}
	// Defensive copy guard.
	origDefault0 := defaultCoverPaths[0]
	origDynamic0 := dynamicCoverPaths[0]
	pool[0] = "/poisoned-default"
	pool[len(defaultCoverPaths)] = "/poisoned-dynamic"
	if defaultCoverPaths[0] != origDefault0 {
		t.Fatal("CoverPathsPool exposed defaultCoverPaths backing array")
	}
	if dynamicCoverPaths[0] != origDynamic0 {
		t.Fatal("CoverPathsPool exposed dynamicCoverPaths backing array")
	}
}

// TestDefaultCoverPaths_NoNonMixpanelPaths guards C1 closure (may-audit,
// 2026-05-02): `/health` and `/api/v2/feature-flags` are NOT Mixpanel SDK
// paths and would be detectable via correlation analysis against a Mixpanel
// reference fixture. Regression here means someone re-added a non-Mixpanel
// shape into the warmup pool.
func TestDefaultCoverPaths_NoNonMixpanelPaths(t *testing.T) {
	forbidden := map[string]bool{
		"/health":               true,
		"/api/v2/feature-flags": true,
	}
	for _, p := range defaultCoverPaths {
		if forbidden[p] {
			t.Errorf("defaultCoverPaths contains forbidden non-Mixpanel path %q", p)
		}
	}
}

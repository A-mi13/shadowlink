package browser

import "testing"

// TestDefaultCoverPaths_PoolSize pins the pool size at 6 entries — the
// chooseWarmupCount cap (≤4) and ws_transport_warmup_test.go entropy
// expectations assume the pool is large enough to allow shuffled prefixes.
// If you change pool size, refit those callers.
func TestDefaultCoverPaths_PoolSize(t *testing.T) {
	if got := len(defaultCoverPaths); got != 6 {
		t.Fatalf("defaultCoverPaths size = %d, want 6", got)
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

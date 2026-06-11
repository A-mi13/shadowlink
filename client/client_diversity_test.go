package client

import (
	"testing"

	"github.com/nixavpn/shadowlink/skins/browser"
)

func TestNewClient_DefaultWeightsProduceDiversity(t *testing.T) {
	// SHADOWLINK_FP_POOL не должен форсить chrome133.
	t.Setenv("SHADOWLINK_FP_POOL", "")
	// FPCacheDir разный на каждой итерации → fresh resample.
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		c := NewClient(ClientConfig{
			ClientID:   make([]byte, 16),
			FPCacheDir: t.TempDir(),
			ServerAddr: "127.0.0.1:1",
		})
		seen[c.selectedProfileName]++
	}
	if len(seen) < 2 {
		t.Fatalf("NewClient monoculture across 200 instances: %v", seen)
	}
	// Все — chrome-family.
	for name := range seen {
		if !browser.IsChromeFamily(name) {
			t.Errorf("non-chrome-family selected: %q", name)
		}
	}
}

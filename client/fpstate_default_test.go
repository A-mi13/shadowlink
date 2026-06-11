package client

import (
	"testing"

	"github.com/nixavpn/shadowlink/skins/browser"
)

func TestResolveProfile_NilWeightsUsesDefaults(t *testing.T) {
	// weights == nil (пустой серверный YAML) → дефолты из кода, НЕ "chrome" 100%.
	seen := map[string]int{}
	for s := uint64(0); s < 1000; s++ {
		name, _ := ResolveProfile(t.TempDir(), nil, s)
		seen[name]++
	}
	// Должны встретиться как минимум два разных chrome-major (разброс),
	// и все они — chrome-family.
	if len(seen) < 2 {
		t.Fatalf("nil weights produced monoculture: %v", seen)
	}
	for name := range seen {
		if !browser.IsChromeFamily(name) {
			t.Errorf("resolved non-chrome-family profile %q from default weights", name)
		}
	}
}

func TestLookupProfile_LegacyChromeAlias(t *testing.T) {
	p, ok := browser.LookupProfile(browser.ProfileChrome) // "chrome"
	if !ok {
		t.Fatal("legacy alias chrome did not resolve")
	}
	if p.Name != browser.ProfileChrome133 {
		t.Errorf("legacy chrome resolved to %q, want chrome133", p.Name)
	}
}

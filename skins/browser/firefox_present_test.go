//go:build sl_firefox

package browser

import "testing"

func TestFirefox_PresentInTaggedBuild(t *testing.T) {
	p, ok := LookupProfile("firefox")
	if !ok {
		t.Fatal("firefox must be present when built with sl_firefox tag")
	}
	if p.Family != FamilyFirefox {
		t.Errorf("firefox Family = %q, want firefox", p.Family)
	}
	if IsChromeFamily("firefox") {
		t.Error("firefox must not be chrome-family")
	}
}

package bypassroute

import (
	"net/netip"
	"testing"
)

func TestLoader_EmbeddedOnly(t *testing.T) {
	tr, err := Load(Source{Embedded: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tr.Size() < 5000 {
		t.Errorf("embedded size = %d, want > 5000 (RIPE RU snapshot)", tr.Size())
	}
}

func TestLoader_OverrideAdds(t *testing.T) {
	override := AdminOverride{
		Adds: []netip.Prefix{netip.MustParsePrefix("100.99.99.0/24")},
	}
	tr, err := Load(Source{Embedded: false, Override: &override})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !tr.Match(netip.MustParseAddr("100.99.99.5")) {
		t.Fatal("override Adds not applied")
	}
}

func TestLoader_OverrideExcludes(t *testing.T) {
	// Setup: embedded carries 213.180.193.0/24. Override excludes 213.180.193.128/25.
	override := AdminOverride{
		Excludes: []netip.Prefix{netip.MustParsePrefix("213.180.193.128/25")},
	}
	tr, err := Load(Source{Embedded: true, Override: &override})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !tr.Match(netip.MustParseAddr("213.180.193.50")) {
		t.Error("non-excluded portion of /24 should still match")
	}
	if tr.Match(netip.MustParseAddr("213.180.193.200")) {
		t.Error("excluded /25 portion should NOT match")
	}
}

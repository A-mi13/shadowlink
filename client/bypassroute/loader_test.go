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

func TestSnapshotPrefixes_ReturnsIncludeMinusExclude(t *testing.T) {
	r, err := Load(Source{Embedded: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ps := SnapshotPrefixes(r)
	if len(ps) == 0 {
		t.Fatalf("expected RU prefixes")
	}
	for _, p := range ps {
		if !p.Addr().Is4() {
			t.Fatalf("v4 only, got %s", p)
		}
	}
}

func TestSnapshotPrefixes_DropsExcluded(t *testing.T) {
	override := AdminOverride{
		Adds:     []netip.Prefix{netip.MustParsePrefix("100.99.99.0/24")},
		Excludes: []netip.Prefix{netip.MustParsePrefix("100.99.99.0/24")},
	}
	r, err := Load(Source{Embedded: false, Override: &override})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, p := range SnapshotPrefixes(r) {
		if p == netip.MustParsePrefix("100.99.99.0/24") {
			t.Fatalf("excluded prefix must not appear in snapshot")
		}
	}
}

func TestSnapshotPrefixes_NilSafe(t *testing.T) {
	if ps := SnapshotPrefixes(nil); ps != nil {
		t.Fatalf("nil Resolved → nil snapshot, got %v", ps)
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

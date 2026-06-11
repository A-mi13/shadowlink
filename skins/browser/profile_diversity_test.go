package browser

import "testing"

func TestRegistry_HasThreeChromeProfiles(t *testing.T) {
	want := map[string]int{
		ProfileChrome120: 120,
		ProfileChrome131: 131,
		ProfileChrome133: 133,
	}
	for name, major := range want {
		p, ok := LookupProfile(name)
		if !ok {
			t.Fatalf("profile %q not in registry", name)
		}
		if p.Major != major {
			t.Errorf("%q Major = %d, want %d", name, p.Major, major)
		}
		if p.Family != FamilyChrome {
			t.Errorf("%q Family = %q, want chrome", name, p.Family)
		}
	}
}

func TestRegistry_PQKeyShareFlags(t *testing.T) {
	// 131/133 несут MLKEM; 120 — нет.
	cases := map[string]bool{
		ProfileChrome120: false,
		ProfileChrome131: true,
		ProfileChrome133: true,
	}
	for name, want := range cases {
		p, _ := LookupProfile(name)
		if p.PQKeyShare != want {
			t.Errorf("%q PQKeyShare = %v, want %v", name, p.PQKeyShare, want)
		}
	}
}

func TestDefaultFPWeights_ChromeOnly(t *testing.T) {
	w := DefaultFPWeights()
	if len(w) == 0 {
		t.Fatal("DefaultFPWeights empty")
	}
	for name := range w {
		if !IsChromeFamily(name) {
			t.Errorf("DefaultFPWeights contains non-chrome-family key %q", name)
		}
	}
	// Все три major присутствуют.
	for _, n := range []string{ProfileChrome120, ProfileChrome131, ProfileChrome133} {
		if w[n] <= 0 {
			t.Errorf("DefaultFPWeights missing positive weight for %q", n)
		}
	}
}

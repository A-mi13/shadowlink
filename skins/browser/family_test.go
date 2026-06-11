package browser

import "testing"

func TestIsChromeFamily(t *testing.T) {
	// Все три chrome-профиля — chrome-family.
	for _, n := range []string{ProfileChrome120, ProfileChrome131, ProfileChrome133} {
		if !IsChromeFamily(n) {
			t.Errorf("IsChromeFamily(%q) = false, want true", n)
		}
	}
	// Неизвестное имя — не chrome-family (не паникует).
	if IsChromeFamily("netscape") {
		t.Error("IsChromeFamily(netscape) = true, want false")
	}
	// Legacy-алиас "chrome" должен резолвиться в chrome-family (см. Task 6).
	if !IsChromeFamily(ProfileChrome) {
		t.Errorf("IsChromeFamily(%q) = false, want true (legacy alias)", ProfileChrome)
	}
}

func TestProfileFamilyField(t *testing.T) {
	p, ok := LookupProfile(ProfileChrome133)
	if !ok {
		t.Fatal("chrome133 not in registry")
	}
	if p.Family != FamilyChrome {
		t.Errorf("chrome133.Family = %q, want %q", p.Family, FamilyChrome)
	}
}

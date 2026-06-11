package client

import (
	"testing"

	"github.com/nixavpn/shadowlink/skins/browser"
)

func TestIsValidUAForProfile_Chrome131(t *testing.T) {
	ua := browser.ChromeUAForMajor(131)
	if !isValidUAForProfile(ua, browser.ProfileChrome131) {
		t.Error("valid chrome131 UA rejected")
	}
	// Chrome 120 UA для chrome131-профиля — mismatch (major).
	if isValidUAForProfile(browser.ChromeUAForMajor(120), browser.ProfileChrome131) {
		t.Error("chrome120 UA accepted for chrome131 profile")
	}
}

func TestWeightsLookExtreme_FamilyBased(t *testing.T) {
	// Все три chrome-профиля → non-chrome-family доля 0 → не extreme.
	w := map[string]int{
		browser.ProfileChrome133: 60,
		browser.ProfileChrome131: 30,
		browser.ProfileChrome120: 10,
	}
	if weightsLookExtreme(w) {
		t.Error("all-chrome weights flagged as extreme")
	}
}

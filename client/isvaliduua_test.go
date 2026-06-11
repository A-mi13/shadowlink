package client

import (
	"testing"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// TestLockedChromeUA_PassesProfileValidator — the canonical UA returned by
// browser.LockedChromeUA() must always pass the per-profile validator for the
// default Chrome133 profile. Without this guard, a future bump to
// LockedChromeMajor would silently break the wire lockstep contract.
//
// H-2 (2026-06-11): retargeted from the deleted isValidUA onto
// isValidUAForProfile — the live validator wired in applyServerHello.
func TestLockedChromeUA_PassesProfileValidator(t *testing.T) {
	locked := browser.LockedChromeUA()
	if !isValidUAForProfile(locked, browser.ProfileChrome133) {
		t.Fatalf("LockedChromeUA() = %q failed isValidUAForProfile(chrome133) — lockstep regression", locked)
	}
}

// TestIsAllowedUAKey — the closed enum is now driven by the profile registry.
//
// C3 2026-06-09: расширено с жёсткого {chrome} до имён реестра профилей.
// "safari", "edge" и прочие не-реестровые ключи отвергаются.
// Binary-control-char keys также дропаются до value-validator (T1 §219).
func TestIsAllowedUAKey(t *testing.T) {
	type tc struct {
		key  string
		want bool
	}
	// chrome and firefox are registered profiles; all others are not.
	_, firefoxRegistered := browser.LookupProfile("firefox")
	cases := []tc{
		{key: "chrome", want: true},
		{key: "firefox", want: firefoxRegistered}, // true if firefox is in registry
		{key: "safari", want: false},
		{key: "Chrome", want: false}, // case-sensitive
		{key: "edge", want: false},
		{key: "", want: false},
		{key: "x\x00y", want: false},
		{key: "chrome\n", want: false},
	}
	for _, c := range cases {
		t.Run("key="+c.key, func(t *testing.T) {
			if got := isAllowedUAKey(c.key); got != c.want {
				t.Fatalf("isAllowedUAKey(%q) = %v, want %v", c.key, got, c.want)
			}
		})
	}
}

func TestIsValidUAForProfile_Chrome(t *testing.T) {
	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
	if !isValidUAForProfile(chromeUA, "chrome") {
		t.Error("valid chrome UA must pass for chrome profile")
	}
	ffUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"
	if isValidUAForProfile(ffUA, "chrome") {
		t.Error("firefox UA must NOT pass for chrome profile (cross-layer guard)")
	}
}

func TestIsValidUAForProfile_Firefox(t *testing.T) {
	ffUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"
	_, registered := browser.LookupProfile("firefox")
	got := isValidUAForProfile(ffUA, "firefox")
	if registered && !got {
		t.Error("valid firefox UA must pass for firefox profile when registered")
	}
	if !registered && got {
		t.Error("firefox UA must NOT pass when firefox not in registry")
	}
	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
	if isValidUAForProfile(chromeUA, "firefox") {
		t.Error("chrome UA must NOT pass for firefox profile")
	}
}

func TestIsAllowedUAKey_RegistryProfiles(t *testing.T) {
	if !isAllowedUAKey("chrome") {
		t.Error("chrome must be allowed UA key")
	}
	if isAllowedUAKey("netscape") {
		t.Error("unknown profile must not be allowed UA key")
	}
}

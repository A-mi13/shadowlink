package browser

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/refraction-networking/utls"
)

// TestLockedChromeMajor_PinnedAt133 documents the upstream constraint that
// caps the Chrome major lockstep at 133 (utls v1.8.3 has no HelloChrome_135+).
// Bumping the constant requires a coordinated upstream catch-up — this test
// fails on accidental bump so the contract is explicit.
func TestLockedChromeMajor_PinnedAt133(t *testing.T) {
	if LockedChromeMajor != 133 {
		t.Fatalf("LockedChromeMajor=%d; expected 133 (utls v1.8.3 cap)", LockedChromeMajor)
	}
	if LockedChromeMajorString != "133" {
		t.Fatalf("LockedChromeMajorString=%q; expected \"133\"", LockedChromeMajorString)
	}
}

// TestLockedUTLSChromeID_Returns133 verifies the cold-path uTLS dialer
// pulls HelloChrome_133 — the highest non-PSK ID utls upstream exposes.
func TestLockedUTLSChromeID_Returns133(t *testing.T) {
	got := LockedUTLSChromeID()
	if got.Client != utls.HelloChrome_133.Client || got.Version != utls.HelloChrome_133.Version {
		t.Fatalf("LockedUTLSChromeID()=%v; expected utls.HelloChrome_133", got)
	}
}

// TestLockedBogdanfinnChromeProfile_Returns133 verifies the bogdanfinn
// hot-path uses Chrome_133 lockstep with uTLS.
func TestLockedBogdanfinnChromeProfile_Returns133(t *testing.T) {
	got := LockedBogdanfinnChromeProfile()
	if got.GetClientHelloStr() != profiles.Chrome_133.GetClientHelloStr() {
		t.Fatalf("LockedBogdanfinnChromeProfile()=%s; expected Chrome_133",
			got.GetClientHelloStr())
	}
}

// TestLockedChromeUA_Contains133 verifies UA string carries Chrome major 133
// so JA4 / H2 SETTINGS / UA all agree on the same major.
func TestLockedChromeUA_Contains133(t *testing.T) {
	ua := LockedChromeUA()
	if !strings.Contains(ua, "Chrome/133.") {
		t.Fatalf("LockedChromeUA()=%q; expected substring \"Chrome/133.\"", ua)
	}
	// Sanity: it should not also contain other Chrome majors or Edge brand.
	for _, banned := range []string{"Chrome/134.", "Chrome/146.", "Chrome/131.", "Edg/"} {
		if strings.Contains(ua, banned) {
			t.Errorf("LockedChromeUA() leaks %q: %s", banned, ua)
		}
	}
}

// TestChromeUA_MirrorsLockedUA documents that the package-level chromeUA
// var (used by NewFingerprint(ProfileChrome)) is initialized from
// LockedChromeUA(). UpdateUserAgents from server can override at runtime —
// the test only pins the cold-start invariant, not the runtime override.
func TestChromeUA_MirrorsLockedUA(t *testing.T) {
	uaMu.RLock()
	defer uaMu.RUnlock()
	if chromeUA != LockedChromeUA() {
		t.Fatalf("cold-start chromeUA=%q != LockedChromeUA()=%q",
			chromeUA, LockedChromeUA())
	}
}

// TestDefaultUserAgent_ColdStartEqualsLockedUA verifies the DirectTransport
// fallback (NEW-3 fix) uses the locked Chrome major instead of the legacy
// UserAgents[0] which carried Chrome/131 — a hidden fourth Chrome major in
// the wire surface count.
//
// After UpdateUserAgents (server-driven runtime override), defaultUserAgent
// intentionally diverges from chromeUA — that is by design (defaultUserAgent
// is a cold-start fallback, chromeUA is the live profile UA). This test
// pins only the cold-start equality.
func TestDefaultUserAgent_ColdStartEqualsLockedUA(t *testing.T) {
	if defaultUserAgent != LockedChromeUA() {
		t.Fatalf("defaultUserAgent=%q != LockedChromeUA()=%q",
			defaultUserAgent, LockedChromeUA())
	}
}

// TestLockedChromeCHUA_HasMajor133 verifies the sec-ch-ua header value
// references Chrome 133. NEW-2: real Chrome 90+ unconditionally emits
// these headers; missing them on a Chrome JA4 connection is a
// browser-class contradiction.
func TestLockedChromeCHUA_HasMajor133(t *testing.T) {
	pairs := LockedChromeCHUA()
	if len(pairs) != 3 {
		t.Fatalf("LockedChromeCHUA() returned %d pairs; expected 3", len(pairs))
	}
	wantKeys := []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}
	for i, want := range wantKeys {
		if pairs[i][0] != want {
			t.Errorf("pair %d key=%q; expected %q", i, pairs[i][0], want)
		}
	}
	if !strings.Contains(pairs[0][1], `v="133"`) {
		t.Errorf("sec-ch-ua value=%q; expected substring v=\"133\"", pairs[0][1])
	}
	if pairs[1][1] != "?0" {
		t.Errorf("sec-ch-ua-mobile=%q; expected \"?0\"", pairs[1][1])
	}
	if pairs[2][1] != `"Windows"` {
		t.Errorf("sec-ch-ua-platform=%q; expected \"Windows\"", pairs[2][1])
	}
}

// TestApplyChromeCHUAForUA_Chrome verifies headers are written when the UA
// is a Chrome-family string.
func TestApplyChromeCHUAForUA_Chrome(t *testing.T) {
	h := http.Header{}
	ApplyChromeCHUAForUA(h, LockedChromeUA())
	if v := h.Get("sec-ch-ua"); !strings.Contains(v, `v="133"`) {
		t.Errorf("sec-ch-ua=%q; expected substring v=\"133\"", v)
	}
	if v := h.Get("sec-ch-ua-mobile"); v != "?0" {
		t.Errorf("sec-ch-ua-mobile=%q; expected \"?0\"", v)
	}
	if v := h.Get("sec-ch-ua-platform"); v != `"Windows"` {
		t.Errorf("sec-ch-ua-platform=%q; expected \"Windows\"", v)
	}
}

// TestApplyChromeCHUAForUA_NonChromiumUA verifies UAs that do not contain
// "Chrome/" (e.g. legacy Safari / Firefox UA strings, or any future non-
// Chromium client) do NOT receive sec-ch-ua headers — adding them to
// non-Chromium UAs would itself be a cross-browser inconsistency.
//
// 2026-05-05: non-Chrome fingerprints retired in the client pool, но
// helper всё ещё используется для defensive UA-detection (любая UA без
// "Chrome/" — внешний caller / runtime override / legacy state-файл).
func TestApplyChromeCHUAForUA_NonChromiumUA(t *testing.T) {
	for _, ua := range []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
	} {
		t.Run(ua[:30], func(t *testing.T) {
			h := http.Header{}
			ApplyChromeCHUAForUA(h, ua)
			if h.Get("sec-ch-ua") != "" {
				t.Errorf("non-Chromium UA leaked sec-ch-ua: %q", h.Get("sec-ch-ua"))
			}
			if h.Get("sec-ch-ua-mobile") != "" {
				t.Errorf("non-Chromium UA leaked sec-ch-ua-mobile")
			}
			if h.Get("sec-ch-ua-platform") != "" {
				t.Errorf("non-Chromium UA leaked sec-ch-ua-platform")
			}
		})
	}
}

// TestApplyChromeCHUAForFingerprint_OnlyChrome verifies the Fingerprint-typed
// helper writes sec-ch-ua only for ProfileChrome and is a silent no-op
// otherwise (nil или unknown name — defensive guard, не должно случаться
// после ретайра non-Chrome 2026-05-05, но контракт сохранён).
func TestApplyChromeCHUAForFingerprint_OnlyChrome(t *testing.T) {
	chrome := NewFingerprint(ProfileChrome)

	hChrome := http.Header{}
	ApplyChromeCHUAForFingerprint(hChrome, chrome)
	if hChrome.Get("sec-ch-ua") == "" {
		t.Error("Chrome fingerprint should produce sec-ch-ua header")
	}

	// nil safety
	h := http.Header{}
	ApplyChromeCHUAForFingerprint(h, nil)
	if h.Get("sec-ch-ua") != "" {
		t.Error("nil Fingerprint should be silent no-op")
	}

	// Defensive: synthetic Fingerprint с unknown name (не должен случиться,
	// но сохраняем контракт «name != ProfileChrome → no-op»).
	bogus := &Fingerprint{name: "synthetic-non-chrome"}
	h2 := http.Header{}
	ApplyChromeCHUAForFingerprint(h2, bogus)
	if h2.Get("sec-ch-ua") != "" {
		t.Error("non-Chrome name should be silent no-op")
	}
}

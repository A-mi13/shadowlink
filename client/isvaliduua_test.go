package client

import (
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// TestIsValidUA_PinsToLockedChromeMajor — Chrome-family UAs are accepted
// only when they carry the locked Chrome major. A UA carrying any other
// major (older or newer) is rejected so a compromised server cannot
// re-fingerprint the client fleet via the ServerHello UA mechanism.
//
// Final-audit-2026-05-03 P2-2 (T1 §154).
func TestIsValidUA_PinsToLockedChromeMajor(t *testing.T) {
	locked := browser.LockedChromeMajorString // "133" today

	type tc struct {
		name string
		ua   string
		want bool
	}
	cases := []tc{
		{
			name: "locked-major Chrome accepted",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/" + locked + ".0.0.0 Safari/537.36",
			want: true,
		},
		{
			name: "older Chrome rejected (re-fingerprint vector)",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			want: false,
		},
		{
			name: "newer Chrome rejected (out-of-lockstep with uTLS/bogdanfinn)",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/199.0.0.0 Safari/537.36",
			want: false,
		},
		{
			// Длиной >80 чтобы валидация падала именно на substring-spoofing,
			// а не на length-bound (Opus review M-5).
			name: "Chrome/<major> without trailing dot rejected (substring spoofing)",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/" + locked + "abc Safari/537.36",
			want: false,
		},
		{
			// 2026-05-05: non-Chrome fingerprints retired — standalone Safari
			// (без Chrome/ в UA) теперь отвергается.
			name: "standalone Safari rejected (non-Chrome retired 2026-05-05)",
			ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 " +
				"(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
			want: false,
		},
		{
			// 2026-05-05: Firefox UA жёстко отвергается (TSPU блокирует
			// non-Chrome fp). Hard-reject на substring "Firefox/".
			name: "Firefox rejected (non-Chrome retired 2026-05-05)",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:128.0) Gecko/20100101 Firefox/128.0 padding-padding-padding-padding-padding",
			want: false,
		},
		{
			// Защита от server-side UA-injection: Chrome-family UA, в которую
			// сервер попытался впихнуть Firefox/ substring. Hard-reject.
			name: "Chrome UA contaminated with Firefox/ rejected",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/" + locked + ".0.0.0 Firefox/0 Safari/537.36",
			want: false,
		},
		{
			name: "no Mozilla/ rejected",
			ua:   "Definitely not a UA Chrome/" + locked + ".0",
			want: false,
		},
		{
			name: "no browser family rejected",
			ua:   "Mozilla/5.0 (Linux x86_64)",
			want: false,
		},
		{
			name: "non-printable ASCII rejected",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) \x01 Chrome/" + locked + ".0 Safari/537.36",
			want: false,
		},
		{
			name: "high-bit byte rejected (UTF-8 multi-byte)",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) \xc3\xa9 Chrome/" + locked + ".0 Safari/537.36",
			want: false,
		},
		{
			name: "less-than rejected (HTML injection vector)",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) <Chrome/" + locked + ".0 Safari/537.36",
			want: false,
		},
		{
			name: "greater-than rejected",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/" + locked + ".0> Safari/537.36",
			want: false,
		},
		{
			name: "newline rejected",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/" + locked + ".0\n Safari/537.36",
			want: false,
		},
		{
			name: "CR rejected",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/" + locked + ".0\r Safari/537.36",
			want: false,
		},
		{
			name: "NUL rejected",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/" + locked + ".0\x00 Safari/537.36",
			want: false,
		},
		{
			name: "too short rejected",
			ua:   "Mozilla/5",
			want: false,
		},
		{
			name: "too long rejected (>200 bytes — Opus M-5)",
			ua:   "Mozilla/5.0 Chrome/" + locked + ".0 Safari/537.36 " + strings.Repeat("x", 200),
			want: false,
		},
		{
			name: "too short rejected (<80 bytes — Opus M-5)",
			ua:   "Mozilla/5.0 Chrome/" + locked + ".0",
			want: false,
		},
		{
			name: "empty rejected",
			ua:   "",
			want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isValidUA(c.ua)
			if got != c.want {
				t.Fatalf("isValidUA(%q) = %v, want %v", c.ua, got, c.want)
			}
		})
	}
}

// TestIsValidUA_BackwardCompatLockedDefault — the canonical UA returned by
// browser.LockedChromeUA() must always pass isValidUA. Without this guard,
// a future bump to LockedChromeMajor would silently break the wire
// lockstep contract and the F2 followup tests would not catch it
// because the stock check earlier in the function passes anything
// containing "Chrome/".
func TestIsValidUA_BackwardCompatLockedDefault(t *testing.T) {
	locked := browser.LockedChromeUA()
	if !isValidUA(locked) {
		t.Fatalf("LockedChromeUA() = %q failed isValidUA — F2 lockstep regression", locked)
	}
}

// TestIsAllowedUAKey — the closed enum is now {chrome} only.
//
// 2026-05-05: non-Chrome fingerprints retired (TSPU блокирует Safari/Firefox/
// Edge). "safari"/"firefox" из ServerHello теперь отбрасываются.
// Binary-control-char keys также дропаются до value-validator (T1 §219).
func TestIsAllowedUAKey(t *testing.T) {
	type tc struct {
		key  string
		want bool
	}
	cases := []tc{
		{key: "chrome", want: true},
		{key: "safari", want: false},  // 2026-05-05: retired
		{key: "firefox", want: false}, // 2026-05-05: retired
		{key: "Chrome", want: false},  // case-sensitive
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

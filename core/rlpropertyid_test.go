package core

import (
	"regexp"
	"strings"
	"testing"
)

// TestDeriveRLPropertyID_Deterministic is the contract the whole design rests
// on: server and client derive independently, exchanging nothing but the host
// they already both know.
func TestDeriveRLPropertyID_Deterministic(t *testing.T) {
	for _, host := range []string{"datacanvases.com", "example.org", "a.b.c.example"} {
		first := DeriveRLPropertyID(host)
		for i := 0; i < 100; i++ {
			if got := DeriveRLPropertyID(host); got != first {
				t.Fatalf("DeriveRLPropertyID(%q) not deterministic: %q then %q", host, first, got)
			}
		}
	}
}

// TestDeriveRLPropertyID_HostFormsAgree covers the actual client/server split:
// the client holds a dial address with a port, the server sees a bare Host
// header. Both must land on the same identifier or the carrier silently stops
// matching — a failure that looks exactly like "the server never rate-limits".
func TestDeriveRLPropertyID_HostFormsAgree(t *testing.T) {
	cases := [][]string{
		{"datacanvases.com", "datacanvases.com:443", "DataCanvases.com", "datacanvases.com."},
		{"example.org", "example.org:8443", "EXAMPLE.ORG", " example.org "},
		{"::1", "[::1]:443", "[::1]"},
	}
	for _, group := range cases {
		want := DeriveRLPropertyID(group[0])
		for _, variant := range group[1:] {
			if got := DeriveRLPropertyID(variant); got != want {
				t.Errorf("host forms disagree: %q→%q but %q→%q", group[0], want, variant, got)
			}
		}
	}
}

// TestDeriveRLPropertyID_DiffersAcrossHosts is the property the change exists
// for. If distinct hosts collide, a single scan hit still enumerates the fleet.
func TestDeriveRLPropertyID_DiffersAcrossHosts(t *testing.T) {
	hosts := []string{
		"datacanvases.com", "example.com", "example.org", "example.net",
		"a.example.com", "b.example.com", "c.example.com",
		"shop.test", "cdn.test", "api.test", "www.test", "m.test",
		"1.2.3.4", "5.6.7.8", "9.10.11.12",
	}
	seen := make(map[string]string, len(hosts))
	collisions := 0
	for _, h := range hosts {
		id := DeriveRLPropertyID(h)
		if prev, dup := seen[id]; dup {
			t.Logf("collision: %q and %q both derive %q", prev, h, id)
			collisions++
			continue
		}
		seen[id] = h
	}
	// The output space is deliberately small (12 shapes × ≤1000) so values stay
	// plausible, which makes some collision inevitable at scale — that is an
	// accepted trade, not a defect. What must not happen is wholesale collapse.
	if collisions > len(hosts)/4 {
		t.Errorf("collisions=%d over %d hosts — derivation is not spreading",
			collisions, len(hosts))
	}
}

// TestDeriveRLPropertyID_ShapeIsPlausible guards the risk that made hex
// unacceptable: an identifier nobody else would emit is itself the signal.
// The output must read as catalogue metadata, not as a hash.
func TestDeriveRLPropertyID_ShapeIsPlausible(t *testing.T) {
	// Word prefix, hyphen, short digit run. Nothing else.
	shape := regexp.MustCompile(`^[a-z]{3,7}-[0-9]{2,3}$`)
	hexish := regexp.MustCompile(`[0-9a-f]{6,}`)

	for _, host := range []string{
		"datacanvases.com", "example.com", "a.example.org", "1.2.3.4",
		"very-long-subdomain.example.co.uk", "x.y", "::1",
	} {
		id := DeriveRLPropertyID(host)
		if !shape.MatchString(id) {
			t.Errorf("DeriveRLPropertyID(%q) = %q — does not read as a vendor identifier", host, id)
		}
		if hexish.MatchString(id) {
			t.Errorf("DeriveRLPropertyID(%q) = %q — looks like a digest, which is the tell we are avoiding", host, id)
		}
		if strings.Contains(id, LegacyRLPropertyID) {
			t.Errorf("DeriveRLPropertyID(%q) = %q — leaks the legacy literal", host, id)
		}
	}
}

// TestDeriveRLPropertyID_EmptyHostFallsBackToLegacy pins the degradation path.
// Returning "" would produce a JSON-LD block with an empty propertyID, which
// is both invalid-looking and unmatched by any carrier.
func TestDeriveRLPropertyID_EmptyHostFallsBackToLegacy(t *testing.T) {
	for _, h := range []string{"", "   ", "."} {
		if got := DeriveRLPropertyID(h); got != LegacyRLPropertyID {
			t.Errorf("DeriveRLPropertyID(%q) = %q, want legacy %q", h, got, LegacyRLPropertyID)
		}
	}
}

// TestSignalHost covers the asymmetry that shipped broken in the first cut:
// WebSocketTransport derived the host inline, DirectTransport left it empty
// whenever no SNI override was configured. An empty host silently restricts a
// client to the legacy fleet-wide marker — it keeps working today only because
// no server emits a derived one yet, and would have started dropping signals
// the moment one did.
func TestSignalHost(t *testing.T) {
	cases := []struct {
		name        string
		sniOverride string
		dialAddr    string
		want        string
	}{
		{"sni override wins", "datacanvases.com", "104.222.177.67:443", "datacanvases.com"},
		{"sni override with odd port", "datacanvases.com", "104.222.177.67:8443", "datacanvases.com"},
		{"no sni falls back to dial host", "", "datacanvases.com:443", "datacanvases.com"},
		{"no sni, bare host", "", "datacanvases.com", "datacanvases.com"},
		{"no sni, ip literal", "", "104.222.177.67:443", "104.222.177.67"},
		{"no sni, ipv6 with port", "", "[2001:db8::1]:443", "2001:db8::1"},
		{"nothing known", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SignalHost(tc.sniOverride, tc.dialAddr); got != tc.want {
				t.Errorf("SignalHost(%q, %q) = %q, want %q",
					tc.sniOverride, tc.dialAddr, got, tc.want)
			}
		})
	}
}

// TestSignalHost_FeedsDerivationConsistently ties the two functions together:
// whichever form a transport holds, the derived ID must be the one the server
// baked into its template from the same domain.
func TestSignalHost_FeedsDerivationConsistently(t *testing.T) {
	const domain = "datacanvases.com"
	want := DeriveRLPropertyID(domain)

	for _, tc := range []struct{ sni, dial string }{
		{domain, "104.222.177.67:443"},           // origin-IP dialling, SNI domain — prod mode
		{"", domain + ":443"},                    // plain direct, port present
		{"", domain},                             // plain direct, bare
		{strings.ToUpper(domain), "1.2.3.4:443"}, // case must not matter
	} {
		if got := DeriveRLPropertyID(SignalHost(tc.sni, tc.dial)); got != want {
			t.Errorf("sni=%q dial=%q derived %q, want %q", tc.sni, tc.dial, got, want)
		}
	}
}

func TestNormalizeRLHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM":     "example.com",
		"example.com:443": "example.com",
		"example.com.":    "example.com",
		"  example.com  ": "example.com",
		"[::1]:443":       "::1",
		"[2001:db8::1]":   "2001:db8::1",
		"2001:db8::1":     "2001:db8::1", // bare IPv6 must not lose a group
		"1.2.3.4:8443":    "1.2.3.4",
		"":                "",
	}
	for in, want := range cases {
		if got := NormalizeRLHost(in); got != want {
			t.Errorf("NormalizeRLHost(%q) = %q, want %q", in, got, want)
		}
	}
}

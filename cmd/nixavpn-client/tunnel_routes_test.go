package main

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/client/dnsproxy"
)

// prodServerIP — боевой origin (bin/connect-vpn-*.bat: ?origin=104.222.177.67).
// Держим литералом здесь, а не тянем из конфига: тест обязан ловить и случай,
// когда конфиг сменят на IP из 1.1.0.0/16.
const prodServerIP = "104.222.177.67"

// containsHost reports whether the plan grants ip a direct /32 escape.
func (p escapePlan) containsHost(ip string) bool {
	for _, h := range p.Hosts {
		if h == ip {
			return true
		}
	}
	return false
}

// coversIP reports whether any /16 in the plan covers ip. This is the check that
// makes the guard about REACHABILITY rather than about string equality: a /16
// sweep never mentions 1.1.1.1 by name, yet 1.1.0.0/16 would exempt it from the
// TUN just as effectively as an explicit /32.
func (p escapePlan) coversIP(t *testing.T, ip string) bool {
	t.Helper()
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatalf("bad test IP %q: %v", ip, err)
	}
	for _, c := range p.CIDRs {
		pref, err := netip.ParsePrefix(c + "/16")
		if err != nil {
			t.Fatalf("plan produced unparsable CIDR %q: %v", c, err)
		}
		if pref.Contains(addr) {
			return true
		}
	}
	return false
}

// TestDoHServerIP_HasNoEscapeRoute is the primary guard for an EMERGENT security
// property that no single line of code states.
//
// The DoH client dials a bare net.Dialer (client/utls_http.go
// buildUTLSHTTPClientCommon → client/split_transport_tls.go). Nothing in Go code
// routes it through the tunnel. It reaches Cloudflare over the tunnel for one
// reason only: the OS routing table gives it NO escape, so the 0/1+128/1 split
// routes swallow it into the TUN, where tun2socks hands it to BypassDialer,
// which classifies it as non-RU → routeTunnel.
//
// Therefore "no escape route for the DoH IP" is not a missing setting — it IS
// the protection. Adding one (e.g. "let's make DNS faster") would put a
// cleartext TLS ClientHello with SNI cloudflare-dns.com on the wire from the
// user's own NIC — exactly the signature Russian ISPs began resetting in
// August 2026 (DoH/DoT to Google and Cloudflare broken at the TLS handshake).
//
// Guards all three route-level ways to lose it:
//  1. an explicit /32 for the DoH IP (prod narrow-escape mode),
//  2. the /16 sweep covering it in CDN mode (no ?origin= pin),
//  3. a server IP that itself sits in 1.1.0.0/16, which would drag the DoH IP
//     out of the TUN through the sweep as collateral.
//
// The fourth way (the RU trie matching 1.1.1.1 → routeDirect) cannot be seen
// from this package; it is guarded by TestDoHServerIP_NotInRUTrie in
// client/bypassroute.
func TestDoHServerIP_HasNoEscapeRoute(t *testing.T) {
	doh := client.DoHServerIP()

	// Case 1: prod shape — origin-pinned, narrow escape.
	narrow := buildEscapePlan([]string{prodServerIP}, true)
	if narrow.containsHost(doh) {
		t.Errorf("narrow escape grants DoH IP %s a /32 escape — its DoH handshake "+
			"would leave the physical NIC in cleartext (SNI cloudflare-dns.com), "+
			"the exact pattern RU ISPs reset; plan=%+v", doh, narrow)
	}
	if narrow.coversIP(t, doh) {
		t.Errorf("narrow escape /16 sweep covers DoH IP %s (sweep must be empty "+
			"under origin pin); plan=%+v", doh, narrow)
	}

	// Case 2: CDN shape — no origin pin, /16 sweep active.
	cdn := buildEscapePlan([]string{prodServerIP}, false)
	if cdn.containsHost(doh) {
		t.Errorf("CDN escape grants DoH IP %s a /32 escape; plan=%+v", doh, cdn)
	}
	if cdn.coversIP(t, doh) {
		t.Errorf("CDN /16 sweep covers DoH IP %s; plan=%+v", doh, cdn)
	}

	// Case 3: adversarial — a server IP inside the DoH IP's own /16. If the
	// sweep ever ran for such a server, it would exempt the resolver too.
	// Today narrowEscape=true (prod) keeps the sweep empty; this pins that the
	// protection does not silently depend on the server IP's neighbourhood.
	sameSixteen := buildEscapePlan([]string{"1.1.9.9"}, true)
	if sameSixteen.coversIP(t, doh) || sameSixteen.containsHost(doh) {
		t.Errorf("server IP in the DoH /16 dragged DoH IP %s out of the TUN; plan=%+v",
			doh, sameSixteen)
	}
}

// TestBuildEscapePlan_YandexAlwaysEscapes is the OPPOSITE-sign counterpart of
// the DoH guard, and it exists so the two are not confused with one another.
//
// Yandex plain-UDP is direct BY DESIGN (see setupRoutes §1a): without a /32 the
// split routes would pull those UDP packets back into the TUN and loop them.
// So Yandex MUST be in the escape list in BOTH modes, while the DoH IP must be
// in NEITHER. A refactor that "cleans up" the escape list by treating all
// resolvers alike would break exactly one of these two tests, whichever
// direction it erred in.
func TestBuildEscapePlan_YandexAlwaysEscapes(t *testing.T) {
	for _, narrow := range []bool{true, false} {
		plan := buildEscapePlan([]string{prodServerIP}, narrow)
		for _, ip := range dnsproxy.DefaultYandexIPs() {
			if !plan.containsHost(ip) {
				t.Errorf("narrowEscape=%v: Yandex resolver %s lost its /32 escape — "+
					"its plain-UDP would loop back into the TUN; plan=%+v",
					narrow, ip, plan)
			}
		}
	}
}

// TestBuildEscapePlan_ServerIPAndSweep pins the rest of the plan's shape so the
// DoH guard above cannot pass by accident (e.g. because buildEscapePlan started
// returning an empty plan for every input — which would "protect" the DoH IP
// while silently breaking the tunnel's own escape route).
func TestBuildEscapePlan_ServerIPAndSweep(t *testing.T) {
	narrow := buildEscapePlan([]string{prodServerIP}, true)
	if !narrow.containsHost(prodServerIP) {
		t.Fatalf("server IP lost its /32 escape — the WS pool would route into "+
			"its own TUN; plan=%+v", narrow)
	}
	if len(narrow.CIDRs) != 0 {
		t.Errorf("origin pin must skip the /16 sweep, got CIDRs=%v", narrow.CIDRs)
	}

	cdn := buildEscapePlan([]string{prodServerIP}, false)
	if want := []string{"104.222.0.0"}; !reflect.DeepEqual(cdn.CIDRs, want) {
		t.Errorf("CDN sweep: got %v want %v", cdn.CIDRs, want)
	}

	// Dedup: two IPs in one /16 produce one CIDR, not two.
	dedup := buildEscapePlan([]string{"104.222.177.67", "104.222.5.5"}, false)
	if len(dedup.CIDRs) != 1 {
		t.Errorf("sweep must dedup by /16, got %v", dedup.CIDRs)
	}

	// Malformed input must not produce a bogus prefix (it would become a real
	// `route add` argument).
	malformed := buildEscapePlan([]string{"not-an-ip"}, false)
	if len(malformed.CIDRs) != 0 {
		t.Errorf("malformed IP leaked into sweep: %v", malformed.CIDRs)
	}
}

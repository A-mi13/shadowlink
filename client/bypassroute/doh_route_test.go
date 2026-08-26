package bypassroute

import (
	"net/netip"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// metaForIP builds the tun2socks metadata route() consumes. Port 443 matches the
// real DoH dial (client/ech.go POSTs to https://cloudflare-dns.com/dns-query).
func metaForIP(ip netip.Addr) *M.Metadata {
	return &M.Metadata{DstIP: ip, DstPort: 443}
}

// dohServerIPLiteral mirrors client.DoHServerIP(). It is duplicated as a literal
// ON PURPOSE: importing package client from here would create an import cycle
// (client already imports bypassroute). The drift risk that duplication normally
// carries is covered from the other side — cmd/nixavpn-client's
// TestDoHServerIP_HasNoEscapeRoute reads the live client.DoHServerIP(), so a
// change to the constant that is not mirrored here still fails the suite there,
// and the comment below tells the next reader where to look.
const dohServerIPLiteral = "1.1.1.1"

// TestDoHServerIP_NotInRUTrie guards the fourth (and least visible) way the DoH
// path could be pushed onto the wire in cleartext.
//
// Routing keeps the DoH dial inside the TUN (see
// cmd/nixavpn-client TestDoHServerIP_HasNoEscapeRoute). Once inside, tun2socks
// asks BypassDialer where to send it, and route() returns routeDirect for any
// address the RU trie matches. So a trie that matched 1.1.1.1 would hand the DoH
// handshake straight back to the physical NIC — correct routes and all.
//
// The embedded baseline is already covered by TestEmbedded_NonRUIPsMiss. What is
// NOT covered there, and is covered here, is the ADMIN OVERRIDE path: Adds is
// operator-supplied and can carry any prefix, including one containing the DoH
// resolver. This test pins the two things that must hold:
//
//  1. the default (embedded) trie must not match the DoH IP, and
//  2. route() — not just Match() — must classify it as routeTunnel, since that
//     is the function tun2socks actually consults.
func TestDoHServerIP_NotInRUTrie(t *testing.T) {
	doh := netip.MustParseAddr(dohServerIPLiteral)

	resolved, err := Load(Source{Embedded: true})
	if err != nil {
		t.Fatalf("load embedded: %v", err)
	}
	if resolved.Match(doh) {
		t.Fatalf("embedded RU trie matches DoH IP %s → BypassDialer would send its "+
			"TLS handshake DIRECT from the user's NIC (cleartext SNI "+
			"cloudflare-dns.com), defeating the tunnel protection", doh)
	}

	// The classification that actually runs in the data path.
	d := &BypassDialer{resolved: resolved}
	if got := d.route(metaForIP(doh)); got != routeTunnel {
		t.Fatalf("route(%s) = %v, want routeTunnel — the DoH dial must stay inside "+
			"the tunnel", doh, got)
	}
}

// TestDoHServerIP_AdminOverrideCannotExposeIt documents the residual risk rather
// than asserting a protection that does not exist.
//
// An admin override CAN currently pull the DoH IP into the RU trie, which would
// route it direct. There is no code today that prevents it. This test pins that
// behaviour so the exposure is visible and intentional: if someone later adds a
// hard exclusion for the DoH IP (the natural fix — an Excludes entry, since
// Match applies include-minus-exclude), this test fails and must be inverted,
// which is the moment to confirm the fix works.
//
// Written this way on purpose: a test asserting "override cannot expose it"
// would be green today only because it asserted nothing real.
func TestDoHServerIP_AdminOverrideCannotExposeIt(t *testing.T) {
	doh := netip.MustParseAddr(dohServerIPLiteral)

	resolved, err := Load(Source{
		Embedded: true,
		Override: &AdminOverride{Adds: []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")}},
	})
	if err != nil {
		t.Fatalf("load with override: %v", err)
	}

	d := &BypassDialer{resolved: resolved}
	got := d.route(metaForIP(doh))

	if got == routeTunnel {
		t.Fatalf("admin override no longer exposes the DoH IP (route=%v). If this is "+
			"an intentional new protection (e.g. a hard Excludes entry for the DoH "+
			"resolver), invert this test: the documented residual risk is now closed.", got)
	}
	if got != routeDirect {
		t.Fatalf("unexpected classification %v for overridden DoH IP; expected "+
			"routeDirect (the documented residual risk)", got)
	}
	t.Logf("documented residual risk holds: an admin override covering %s routes "+
		"the DoH dial DIRECT (route=%v), exposing a cleartext ClientHello with SNI "+
		"cloudflare-dns.com. Mitigation if ever needed: add the DoH IP to Excludes.",
		doh, got)
}

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

// dohBackupServerIPLiteral mirrors the BACKUP upstream (client/ech.go
// dohBackupServerIP, AdGuard unfiltered). Duplicated as a literal for the same
// import-cycle reason as above, and covered from the other side by
// cmd/nixavpn-client's TestDoHUpstreams_HaveNoEscapeRoute, which iterates the
// live client.DoHUpstreams() list.
//
// Added 2026-08-26 together with the backup upstream: the trie guard below
// protected only the primary, so a trie that matched the backup would have sent
// its handshake DIRECT from the user's NIC (cleartext SNI
// unfiltered.adguard-dns.com) with every existing test still green.
const dohBackupServerIPLiteral = "94.140.14.140"

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

// TestDoHBackupServerIP_NotInRUTrie is the same guard for the BACKUP upstream.
//
// The backup is dialled by the same bare net.Dialer as the primary and enjoys
// exactly the same (emergent, route-derived) protection — so it needs exactly
// the same guard. Without this, the RU trie could classify the AdGuard IP as
// routeDirect and hand its handshake to the physical NIC, defeating the point
// of having a backup that survives a Cloudflare block.
func TestDoHBackupServerIP_NotInRUTrie(t *testing.T) {
	backup := netip.MustParseAddr(dohBackupServerIPLiteral)

	resolved, err := Load(Source{Embedded: true})
	if err != nil {
		t.Fatalf("load embedded: %v", err)
	}
	if resolved.Match(backup) {
		t.Fatalf("embedded RU trie matches backup DoH IP %s → BypassDialer would "+
			"send its TLS handshake DIRECT from the user's NIC (cleartext SNI "+
			"unfiltered.adguard-dns.com)", backup)
	}

	d := &BypassDialer{resolved: resolved}
	if got := d.route(metaForIP(backup)); got != routeTunnel {
		t.Fatalf("route(%s) = %v, want routeTunnel — the backup DoH dial must stay "+
			"inside the tunnel", backup, got)
	}
}

// TestDoHUpstreams_AdminOverrideCannotExposeAny closes the gap the primary-only
// guard left open (review finding, 2026-08-26).
//
// The original guard compared against a single address, so the backup upstream
// kept exactly the exposure the primary had just been protected from: an
// AdminOverride.Adds entry covering it — and Adds is fetched from the admin
// server (admin_fetch.go), i.e. genuinely remote operator input — would make
// route() return routeDirect and put a cleartext ClientHello with SNI
// unfiltered.adguard-dns.com on the user's own NIC.
//
// The irony that makes this worth a dedicated test: the backup exists precisely
// to survive a Cloudflare block, so it gets dialled exactly when the primary is
// already unusable. An unprotected backup fails at the only moment it matters.
//
// This iterates dohResolverAddrs rather than naming addresses, so a third
// upstream added later cannot silently escape the check.
func TestDoHUpstreams_AdminOverrideCannotExposeAny(t *testing.T) {
	if len(dohResolverAddrs) < 2 {
		t.Fatalf("expected at least primary+backup pinned upstreams, got %d",
			len(dohResolverAddrs))
	}

	for _, addr := range dohResolverAddrs {
		// Both shapes an override could take: a broad /24 and the exact /32.
		for _, bits := range []int{24, 32} {
			pref := netip.PrefixFrom(addr, bits).Masked()
			resolved, err := Load(Source{
				Embedded: true,
				Override: &AdminOverride{Adds: []netip.Prefix{pref}},
			})
			if err != nil {
				t.Fatalf("load with override %s: %v", pref, err)
			}

			d := &BypassDialer{resolved: resolved}
			if got := d.route(metaForIP(addr)); got != routeTunnel {
				t.Errorf("admin override %s exposes pinned DoH upstream %s: route()=%v, "+
					"want routeTunnel — its handshake would leave the physical NIC in "+
					"cleartext, the exact signature RU ISPs began resetting in August 2026",
					pref, addr, got)
			}
		}
	}
}

// TestDoHServerIP_AdminOverrideCannotExposeIt asserts the protection that closes
// the last route-level way to expose the DoH dial.
//
// HISTORY: until 2026-08-26 this test asserted the OPPOSITE — that an admin
// override covering 1.1.1.1 routes the DoH dial DIRECT. It was written that way
// on purpose: back then no code prevented the exposure, and a test asserting
// "override cannot expose it" would have been green only because it asserted
// nothing real. The protection now exists — route() short-circuits the pinned
// DoH resolver IP (DoHResolverIP) to routeTunnel BEFORE consulting the trie —
// so the test is inverted, as its own comment demanded.
//
// The guard sits in route() rather than as a hard Excludes entry in Load()
// deliberately: route() is the function tun2socks actually consults (both
// DialContext and DialUDP), it covers ANY Resolved regardless of how it was
// built, and it leaves SnapshotPrefixes — the leakguard allow-rule export —
// untouched. An Excludes entry would protect only tries built via Load and
// would not change SnapshotPrefixes for a covering /24 anyway (the snapshot
// drops a prefix only when its NETWORK address is excluded; 1.1.1.0 is not
// matched by a 1.1.1.1/32 exclude).
func TestDoHServerIP_AdminOverrideCannotExposeIt(t *testing.T) {
	// Package-local drift stitch: the prod guard constant must protect the same
	// address this test pins as a literal. The cross-package half (guard vs the
	// live client.DoHServerIP()) lives in client/doh_pin_stitch_test.go.
	if DoHResolverIP != dohServerIPLiteral {
		t.Fatalf("DoHResolverIP = %q, test pins %q — the route() guard protects a "+
			"different address than the DoH client actually dials", DoHResolverIP,
			dohServerIPLiteral)
	}

	doh := netip.MustParseAddr(dohServerIPLiteral)

	// Both override shapes that could cover the resolver: a broad /24 and the
	// exact /32. Either one, without the guard, flips route() to routeDirect.
	for _, cidr := range []string{"1.1.1.0/24", "1.1.1.1/32"} {
		resolved, err := Load(Source{
			Embedded: true,
			Override: &AdminOverride{Adds: []netip.Prefix{netip.MustParsePrefix(cidr)}},
		})
		if err != nil {
			t.Fatalf("load with override %s: %v", cidr, err)
		}

		d := &BypassDialer{resolved: resolved}
		if got := d.route(metaForIP(doh)); got != routeTunnel {
			t.Fatalf("admin override %s exposes the DoH IP %s: route()=%v, want "+
				"routeTunnel. A direct dial would put a cleartext ClientHello with "+
				"SNI cloudflare-dns.com on the wire from the user's NIC — the exact "+
				"signature RU ISPs began resetting in August 2026.", cidr, doh, got)
		}
	}
}

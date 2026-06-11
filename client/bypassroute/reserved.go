package bypassroute

import (
	"net/netip"
	"sync"
)

// Reserved IPv4 ranges that MUST NEVER traverse the VPN tunnel.
//
// These belong to the local network stack or cloud-provider metadata
// endpoints. Sending them through ShadowLink causes two failure modes:
//   - WS CONNECT_FAIL noise: the server tries to dial an address that is
//     either invalid (link-local, multicast) or simply does not exist
//     from its vantage point (cloud metadata IPs are per-VM-local).
//   - Loss of legitimate local functionality (e.g. Windows DHCP discovery
//     leak through the tunnel, cloud-init metadata fetch on bring-up).
//
// The 8h canary 2026-05-22 logged 141 CONNECT_FAIL on 169.254.169.254 —
// AWS metadata being tunneled out from the user's laptop. Per RFC 3927
// the entire 169.254.0.0/16 is IPv4 link-local; cloud metadata (AWS, GCP
// IMDSv1, Azure IMDS, OpenStack, DigitalOcean) all carve out the same
// /16 because the spec mandates it. Excluding the whole block covers all
// future cloud providers in one shot.
//
// Adding a new range: declare it as a named `reservedRange` below. The
// `init()` block parses every entry once at startup and panics if a CIDR
// is malformed — that contract is locked by `TestReservedRanges_AllParse`.
// drop classifies a reserved range by physical reachability via the host's
// direct (physical-NIC) dialer, splitting Bug #7's two failure modes:
//
//   - drop=false (DIRECT): RFC1918 LAN ranges. Real machines on the user's
//     LAN — router, NAS, printer. Physically reachable via the NIC; the
//     BypassDialer routes them through proxy.NewDirect() so they keep working
//     outside the tunnel.
//   - drop=true (DROP): ranges that have NO listener on the user's machine and
//     are unreachable by a physical-NIC dial. Routing them to proxy.NewDirect()
//     opens a real OS socket against a host that never answers; on Windows each
//     failed dial leaks an ephemeral port until "Only one usage of each socket
//     address" — which then breaks every other connection (downloads included).
//     The canonical offender is 169.254.169.254 (cloud metadata) on a non-cloud
//     laptop. These are rejected WITHOUT opening a socket.
type reservedRange struct {
	cidr string
	why  string
	drop bool
}

var reservedRanges = []reservedRange{
	{"0.0.0.0/8", "RFC 1122 §3.2.1.3 — \"this network\"; no real listener, drop", true},
	{"10.0.0.0/8", "RFC 1918 — private network; user's LAN, reachable via NIC", false},
	{"127.0.0.0/8", "RFC 1122 — loopback; never via physical NIC, drop", true},
	{"169.254.0.0/16", "RFC 3927 — IPv4 link-local; cloud metadata (169.254.169.254) unreachable on non-cloud host, drop", true},
	{"172.16.0.0/12", "RFC 1918 — private network; user's LAN, reachable via NIC", false},
	{"192.168.0.0/16", "RFC 1918 — private network; user's LAN, reachable via NIC", false},
	{"224.0.0.0/4", "RFC 5771 — multicast; no unicast listener via NIC, drop", true},
	{"240.0.0.0/4", "RFC 1112 — reserved future use / 255.255.255.255 broadcast, drop", true},
}

// Reserved IPv6 ranges — the v6 mirror of reservedRanges (C2, audit 2026-06-11).
//
// The Trie above is IPv4-only (it stores 4-byte keys and silently skips v6), so
// IPv6 classification is done by linear netip.Prefix.Contains over this small,
// fixed list. The drop/direct split mirrors the IPv4 reasoning exactly:
//
//   - drop=true (DROP): addresses with no listener reachable via the physical
//     NIC. Routing them to proxy.NewDirect() opens a socket against a host that
//     never answers — the Bug #7 ephemeral-port-exhaustion / CONNECT_FAIL path,
//     now on IPv6. Covers loopback (::1), link-local (fe80::/10), multicast
//     (ff00::/8), the unspecified address (::/128), and IPv6 cloud metadata
//     (fd00:ec2::254 — AWS IMDS over IPv6).
//   - drop=false (DIRECT): ULA fc00::/7 — the v6 analogue of RFC1918 LAN. Real
//     local machines reachable via the NIC; keep them outside the tunnel.
//
// Order matters: fd00:ec2::254/128 is itself inside fc00::/7 (ULA), so the
// metadata /128 MUST be classified before the ULA /7. isUnreachableReservedIPv6
// checks the drop subset first, which guarantees that precedence.
var reservedRangesV6 = []reservedRange{
	{"::1/128", "RFC 4291 — loopback; never via physical NIC, drop", true},
	{"::/128", "RFC 4291 — unspecified address; no real destination, drop", true},
	{"fe80::/10", "RFC 4291 — link-local; not reachable as unicast dst via NIC, drop", true},
	{"ff00::/8", "RFC 4291 — multicast; no unicast listener via NIC, drop", true},
	{"fd00:ec2::254/128", "AWS IMDS IPv6 metadata endpoint; per-VM-local, unreachable on non-cloud host, drop", true},
	{"fc00::/7", "RFC 4193 — unique local address (ULA); user's LAN, reachable via NIC", false},
}

var (
	reservedV6Once     sync.Once
	reservedPrefixesV6 []netip.Prefix // all reservedRangesV6 (drop + direct)
	unreachablePfxV6   []netip.Prefix // subset with drop=true
)

func buildReservedV6() {
	for _, r := range reservedRangesV6 {
		p, err := netip.ParsePrefix(r.cidr)
		if err != nil {
			panic("bypassroute: malformed reserved IPv6 CIDR " + r.cidr + ": " + err.Error())
		}
		p = p.Masked()
		reservedPrefixesV6 = append(reservedPrefixesV6, p)
		if r.drop {
			unreachablePfxV6 = append(unreachablePfxV6, p)
		}
	}
}

var (
	reservedTrieOnce sync.Once
	reservedTrie     *Trie // all reserved ranges
	unreachableTrie  *Trie // subset with drop=true (unreachable via physical NIC)
)

// reservedTrieInstance returns a lazily-built singleton trie of reservedRanges.
// It is safe for concurrent reads; the trie is read-only after init. The same
// Do also builds unreachableTrie (the drop=true subset) so the two stay in
// lockstep with reservedRanges.
func reservedTrieInstance() *Trie {
	reservedTrieOnce.Do(buildReservedTries)
	return reservedTrie
}

// unreachableTrieInstance returns the lazily-built singleton trie of the
// drop=true subset of reservedRanges (unreachable via the physical NIC).
func unreachableTrieInstance() *Trie {
	reservedTrieOnce.Do(buildReservedTries)
	return unreachableTrie
}

func buildReservedTries() {
	all := New()
	drop := New()
	for _, r := range reservedRanges {
		p, err := netip.ParsePrefix(r.cidr)
		if err != nil {
			panic("bypassroute: malformed reserved CIDR " + r.cidr + ": " + err.Error())
		}
		all.Insert(p)
		if r.drop {
			drop.Insert(p)
		}
	}
	reservedTrie = all
	unreachableTrie = drop
}

// isReservedIPv4 reports whether addr is in any reservedRanges entry. addr
// MUST already be Unmap'd to IPv4 by the caller; non-v4 addresses return
// false (IPv6 reserved-range coverage is a future task — see Active state).
func isReservedIPv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	return reservedTrieInstance().Match(addr)
}

// isUnreachableReserved reports whether addr is in a reserved range marked
// drop=true — i.e. a host that cannot be reached by a physical-NIC dial and
// must be DROPPED rather than handed to the direct dialer (Bug #7). addr MUST
// already be Unmap'd to IPv4; non-v4 returns false.
func isUnreachableReserved(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	return unreachableTrieInstance().Match(addr)
}

// isReservedIPv6 reports whether addr matches any reservedRangesV6 entry (drop
// or direct). addr MUST already be Unmap'd by the caller; non-v6 returns false.
// IPv4-mapped v6 is handled on the IPv4 path after Unmap, not here.
func isReservedIPv6(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	reservedV6Once.Do(buildReservedV6)
	for _, p := range reservedPrefixesV6 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// isUnreachableReservedIPv6 reports whether addr is in an IPv6 reserved range
// marked drop=true — a host unreachable via the physical NIC that must be
// DROPPED rather than handed to the direct dialer (the v6 mirror of Bug #7).
// addr MUST already be Unmap'd; non-v6 returns false. The drop subset is checked
// independently of the direct set so that the metadata /128 (which lives inside
// the ULA /7) is correctly classified as DROP regardless of list order.
func isUnreachableReservedIPv6(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	reservedV6Once.Do(buildReservedV6)
	for _, p := range unreachablePfxV6 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

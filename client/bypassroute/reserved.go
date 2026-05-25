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
type reservedRange struct {
	cidr string
	why  string
}

var reservedRanges = []reservedRange{
	{"0.0.0.0/8", "RFC 1122 §3.2.1.3 — \"this network\" / DHCP source before lease"},
	{"10.0.0.0/8", "RFC 1918 — private network; user's LAN, must not tunnel"},
	{"127.0.0.0/8", "RFC 1122 — loopback; local-only by definition"},
	{"169.254.0.0/16", "RFC 3927 — IPv4 link-local; covers AWS/GCP/Azure/OpenStack metadata (169.254.169.254 etc.)"},
	{"172.16.0.0/12", "RFC 1918 — private network; user's LAN, must not tunnel"},
	{"192.168.0.0/16", "RFC 1918 — private network; user's LAN, must not tunnel"},
	{"224.0.0.0/4", "RFC 5771 — multicast; not meaningful through a unicast tunnel"},
	{"240.0.0.0/4", "RFC 1112 — reserved future use / 255.255.255.255 broadcast"},
}

var (
	reservedTrieOnce sync.Once
	reservedTrie     *Trie
)

// reservedTrieInstance returns a lazily-built singleton trie of reservedRanges.
// It is safe for concurrent reads; the trie is read-only after init.
func reservedTrieInstance() *Trie {
	reservedTrieOnce.Do(func() {
		t := New()
		for _, r := range reservedRanges {
			p, err := netip.ParsePrefix(r.cidr)
			if err != nil {
				panic("bypassroute: malformed reserved CIDR " + r.cidr + ": " + err.Error())
			}
			t.Insert(p)
		}
		reservedTrie = t
	})
	return reservedTrie
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

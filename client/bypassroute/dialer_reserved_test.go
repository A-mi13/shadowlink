package bypassroute

import (
	"context"
	"net/netip"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// AWS/GCP/Azure metadata endpoints must short-circuit to direct even when the
// bypass trie is empty (RIPE-RU snapshot unloaded / admin override only).
// This is the regression bound for the 141 CONNECT_FAIL spew on
// 169.254.169.254 observed in the 2026-05-22 canary log.
func TestBypassDialer_LinkLocalAlwaysDirect(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	for _, ip := range []string{
		"169.254.169.254", // AWS / GCP IMDSv1 / Azure IMDS / OpenStack
		"127.0.0.1",       // loopback
		"10.20.30.40",     // RFC1918 /8
		"192.168.1.1",     // RFC1918 /16
		"224.0.0.251",     // mDNS multicast
		"255.255.255.255", // limited broadcast
	} {
		direct.called, inner.called = false, false
		m := &M.Metadata{DstIP: netip.MustParseAddr(ip), DstPort: 80}
		_, _ = d.DialContext(context.Background(), m)
		if !direct.called || inner.called {
			t.Errorf("reserved IP %s: direct=%v inner=%v, want direct only", ip, direct.called, inner.called)
		}
	}
}

// Even with a nil Resolved (worst case: bypass disabled), reserved IPs MUST
// still take the direct path. The dialer is the last line of defense for
// local-stack traffic.
func TestBypassDialer_LinkLocalWhenResolvedNil(t *testing.T) {
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, nil)

	m := &M.Metadata{DstIP: netip.MustParseAddr("169.254.169.254"), DstPort: 80}
	_, _ = d.DialContext(context.Background(), m)
	if !direct.called || inner.called {
		t.Fatalf("with resolved=nil, link-local must still go direct (direct=%v inner=%v)", direct.called, inner.called)
	}
}

// UDP path mirrors TCP — DHCP, mDNS, etc. all use UDP and would otherwise
// leak into the tunnel.
func TestBypassDialer_LinkLocalUDP(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	m := &M.Metadata{DstIP: netip.MustParseAddr("169.254.169.254"), DstPort: 80}
	_, _ = d.DialUDP(m)
	if !direct.called || inner.called {
		t.Fatalf("UDP to link-local must go direct (direct=%v inner=%v)", direct.called, inner.called)
	}
}

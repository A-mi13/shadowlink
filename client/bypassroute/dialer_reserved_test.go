package bypassroute

import (
	"context"
	"net/netip"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// Reserved IPs must NEVER traverse the tunnel. Bug #7 split the outcome by
// physical reachability: RFC1918 LAN → DIRECT (reachable local machines);
// unreachable-by-design (link-local/metadata, loopback, multicast, broadcast)
// → DROP (rejected without a socket, so the direct dialer cannot leak ephemeral
// ports against a host that does not exist on this machine). This test pins the
// classification: NEITHER class is ever tunneled (inner is never called).
func TestBypassDialer_ReservedNeverTunneled(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	for _, ip := range []string{
		"169.254.169.254", // metadata — DROP
		"127.0.0.1",       // loopback — DROP
		"224.0.0.251",     // mDNS multicast — DROP
		"255.255.255.255", // limited broadcast — DROP
		"10.20.30.40",     // RFC1918 /8 — DIRECT
		"192.168.1.1",     // RFC1918 /16 — DIRECT
	} {
		direct.called, inner.called = false, false
		m := &M.Metadata{DstIP: netip.MustParseAddr(ip), DstPort: 80}
		_, _ = d.DialContext(context.Background(), m)
		if inner.called {
			t.Errorf("reserved IP %s MUST NOT be tunneled (inner called)", ip)
		}
	}
}

// Even with a nil Resolved (worst case: bypass disabled), reserved IPs MUST
// still be handled by the dialer (drop or direct), never tunneled. The dialer
// is the last line of defense for local-stack traffic.
func TestBypassDialer_ReservedWhenResolvedNil(t *testing.T) {
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, nil)

	// metadata → DROP (no dialer touched, error returned)
	m := &M.Metadata{DstIP: netip.MustParseAddr("169.254.169.254"), DstPort: 80}
	_, err := d.DialContext(context.Background(), m)
	if err == nil {
		t.Fatal("with resolved=nil, metadata must be dropped (error)")
	}
	if direct.called || inner.called {
		t.Fatalf("metadata drop must touch no dialer (direct=%v inner=%v)", direct.called, inner.called)
	}

	// LAN → DIRECT even with nil resolved
	direct.called, inner.called = false, false
	m2 := &M.Metadata{DstIP: netip.MustParseAddr("192.168.1.1"), DstPort: 80}
	_, _ = d.DialContext(context.Background(), m2)
	if !direct.called || inner.called {
		t.Fatalf("with resolved=nil, LAN must go direct (direct=%v inner=%v)", direct.called, inner.called)
	}
}

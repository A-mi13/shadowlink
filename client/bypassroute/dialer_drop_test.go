package bypassroute

import (
	"context"
	"net/netip"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// Bug #7: unreachable-by-design reserved ranges (cloud-metadata link-local,
// multicast, this-network, future-reserved, loopback) MUST be DROPPED (rejected
// without opening an OS socket), not sent to the direct dialer. Routing them to
// proxy.NewDirect() binds a real socket to a physically-unreachable host
// (169.254.169.254 has no listener on a non-cloud laptop), and each failed dial
// leaks an ephemeral port until Windows reports "Only one usage of each socket
// address" — which then breaks every other connection, including downloads.
//
// Field log 2026-05-29 16:16-16:20: repeated
//   "[TCP] dial 169.254.169.254:80: bind: ... lacked sufficient buffer space"
//   "[TCP] dial 169.254.169.254:80: connectex: Only one usage of each socket address"
func TestBypassDialer_UnreachableReservedDropped(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	dropped := []string{
		"169.254.169.254", // AWS/GCP/Azure/OpenStack metadata
		"169.254.10.20",   // any link-local
		"127.0.0.1",       // loopback — never via physical NIC
		"224.0.0.251",     // mDNS multicast
		"255.255.255.255", // limited broadcast (240/4)
		"0.0.0.0",         // this-network (0/8)
	}
	for _, ip := range dropped {
		direct.called, inner.called = false, false
		m := &M.Metadata{DstIP: netip.MustParseAddr(ip), DstPort: 80}
		conn, err := d.DialContext(context.Background(), m)
		if err == nil {
			t.Errorf("unreachable reserved %s: expected DROP error, got nil err", ip)
		}
		if conn != nil {
			t.Errorf("unreachable reserved %s: expected nil conn on drop", ip)
		}
		if direct.called || inner.called {
			t.Errorf("unreachable reserved %s: must DROP (no dialer); direct=%v inner=%v",
				ip, direct.called, inner.called)
		}
	}
}

// RFC1918 LAN ranges remain DIRECT — they are real machines on the user's LAN
// (router, NAS, printer) that are physically reachable via the host's NIC and
// must NOT be dropped or tunneled.
func TestBypassDialer_LANReservedStaysDirect(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	lan := []string{
		"10.20.30.40",  // RFC1918 /8
		"172.16.5.5",   // RFC1918 /12
		"192.168.1.1",  // RFC1918 /16
	}
	for _, ip := range lan {
		direct.called, inner.called = false, false
		m := &M.Metadata{DstIP: netip.MustParseAddr(ip), DstPort: 80}
		_, _ = d.DialContext(context.Background(), m)
		if !direct.called || inner.called {
			t.Errorf("LAN reserved %s: must stay DIRECT; direct=%v inner=%v",
				ip, direct.called, inner.called)
		}
	}
}

// UDP path mirrors TCP: unreachable reserved dropped, LAN stays direct.
func TestBypassDialer_UnreachableReservedDroppedUDP(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	m := &M.Metadata{DstIP: netip.MustParseAddr("169.254.169.254"), DstPort: 80}
	pc, err := d.DialUDP(m)
	if err == nil {
		t.Error("UDP to metadata: expected DROP error, got nil")
	}
	if pc != nil {
		t.Error("UDP to metadata: expected nil PacketConn on drop")
	}
	if direct.called || inner.called {
		t.Errorf("UDP to metadata: must DROP; direct=%v inner=%v", direct.called, inner.called)
	}

	direct.called, inner.called = false, false
	m2 := &M.Metadata{DstIP: netip.MustParseAddr("192.168.1.1"), DstPort: 53}
	_, _ = d.DialUDP(m2)
	if !direct.called || inner.called {
		t.Errorf("UDP to LAN: must stay DIRECT; direct=%v inner=%v", direct.called, inner.called)
	}
}

// isUnreachableReserved unit coverage — the classification itself.
func TestIsUnreachableReserved(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"169.254.169.254", true},  // link-local / metadata
		{"169.254.0.1", true},      // link-local
		{"127.0.0.1", true},        // loopback
		{"224.0.0.251", true},      // multicast
		{"239.1.2.3", true},        // multicast
		{"255.255.255.255", true},  // 240/4 broadcast
		{"240.0.0.1", true},        // 240/4 reserved
		{"0.0.0.0", true},          // 0/8 this-network
		{"10.20.30.40", false},     // RFC1918 — reachable LAN
		{"172.16.5.5", false},      // RFC1918
		{"192.168.1.1", false},     // RFC1918
		{"8.8.8.8", false},         // public
	}
	for _, c := range cases {
		got := isUnreachableReserved(netip.MustParseAddr(c.ip))
		if got != c.want {
			t.Errorf("isUnreachableReserved(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

package bypassroute

import (
	"context"
	"net/netip"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// C2 (audit 2026-06-11): IPv6 reserved/link-local/cloud-metadata leaked into the
// tunnel because route() returned routeTunnel unconditionally for !addr.Is4().
// This mirrors the Bug #7 IPv4 classification onto IPv6:
//   - DROP (unreachable-by-design): loopback ::1, link-local fe80::/10,
//     multicast ff00::/8, unspecified ::, IPv6 cloud-metadata fd00:ec2::254.
//   - DIRECT (reachable LAN): ULA fc00::/7.
//   - TUNNEL: everything public (e.g. 2001:db8::1).

// IPv6 unreachable-by-design ranges MUST be DROPPED (no socket opened) — same
// ephemeral-port-exhaustion / CONNECT_FAIL reasoning as Bug #7 on IPv4.
func TestBypassDialer_UnreachableReservedDroppedIPv6(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	dropped := []string{
		"::1",             // loopback
		"fe80::1",         // link-local
		"fe80::dead:beef", // link-local
		"ff02::fb",        // mDNS multicast (link-local scope)
		"ff00::1",         // multicast base
		"::",              // unspecified
		"fd00:ec2::254",   // AWS IMDS IPv6 metadata
	}
	for _, ip := range dropped {
		direct.called, inner.called = false, false
		m := &M.Metadata{DstIP: netip.MustParseAddr(ip), DstPort: 80}
		conn, err := d.DialContext(context.Background(), m)
		if err == nil {
			t.Errorf("unreachable IPv6 %s: expected DROP error, got nil err", ip)
		}
		if conn != nil {
			t.Errorf("unreachable IPv6 %s: expected nil conn on drop", ip)
		}
		if direct.called || inner.called {
			t.Errorf("unreachable IPv6 %s: must DROP (no dialer); direct=%v inner=%v",
				ip, direct.called, inner.called)
		}
	}
}

// IPv6 ULA (fc00::/7) is the v6 analogue of RFC1918 LAN — reachable local
// machines that must stay DIRECT, never tunneled or dropped.
func TestBypassDialer_ULAReservedStaysDirectIPv6(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	ula := []string{
		"fc00::1",                              // fc00::/8 half of /7
		"fd12:3456:789a:1::1",                  // fd00::/8 half of /7 (common ULA)
		"fdff:ffff:ffff:ffff:ffff:ffff:ffff:1", // upper ULA
	}
	for _, ip := range ula {
		direct.called, inner.called = false, false
		m := &M.Metadata{DstIP: netip.MustParseAddr(ip), DstPort: 80}
		_, _ = d.DialContext(context.Background(), m)
		if !direct.called || inner.called {
			t.Errorf("ULA %s: must stay DIRECT; direct=%v inner=%v",
				ip, direct.called, inner.called)
		}
	}
}

// Public (GUA) IPv6 still tunnels — the C2 fix must not break normal v6 egress.
func TestBypassDialer_PublicIPv6Tunnels(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	public := []string{
		"2001:db8::1",          // documentation/global
		"2606:4700:4700::1111", // Cloudflare DNS v6
		"2620:fe::fe",          // Quad9 v6
	}
	for _, ip := range public {
		direct.called, inner.called = false, false
		m := &M.Metadata{DstIP: netip.MustParseAddr(ip), DstPort: 443}
		_, _ = d.DialContext(context.Background(), m)
		if direct.called || !inner.called {
			t.Errorf("public IPv6 %s: must TUNNEL; direct=%v inner=%v",
				ip, direct.called, inner.called)
		}
	}
}

// UDP path mirrors TCP for IPv6: unreachable dropped, ULA direct, public tunnel.
func TestBypassDialer_IPv6PathsUDP(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	// unspecified-scope mDNS multicast → DROP
	m := &M.Metadata{DstIP: netip.MustParseAddr("ff02::fb"), DstPort: 5353}
	pc, err := d.DialUDP(m)
	if err == nil {
		t.Error("UDP to IPv6 multicast: expected DROP error, got nil")
	}
	if pc != nil {
		t.Error("UDP to IPv6 multicast: expected nil PacketConn on drop")
	}
	if direct.called || inner.called {
		t.Errorf("UDP to IPv6 multicast: must DROP; direct=%v inner=%v", direct.called, inner.called)
	}

	// ULA → DIRECT
	direct.called, inner.called = false, false
	m2 := &M.Metadata{DstIP: netip.MustParseAddr("fd12::1"), DstPort: 53}
	_, _ = d.DialUDP(m2)
	if !direct.called || inner.called {
		t.Errorf("UDP to ULA: must stay DIRECT; direct=%v inner=%v", direct.called, inner.called)
	}

	// public → TUNNEL
	direct.called, inner.called = false, false
	m3 := &M.Metadata{DstIP: netip.MustParseAddr("2001:db8::53"), DstPort: 53}
	_, _ = d.DialUDP(m3)
	if direct.called || !inner.called {
		t.Errorf("UDP to public IPv6: must TUNNEL; direct=%v inner=%v", direct.called, inner.called)
	}
}

// Even with nil Resolved (bypass disabled), reserved IPv6 must still be handled
// by the dialer (drop or direct), never tunneled. Mirrors the IPv4 nil-resolved
// guarantee.
func TestBypassDialer_ReservedIPv6WhenResolvedNil(t *testing.T) {
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, nil)

	// metadata → DROP
	m := &M.Metadata{DstIP: netip.MustParseAddr("fd00:ec2::254"), DstPort: 80}
	_, err := d.DialContext(context.Background(), m)
	if err == nil {
		t.Fatal("with resolved=nil, IPv6 metadata must be dropped (error)")
	}
	if direct.called || inner.called {
		t.Fatalf("IPv6 metadata drop must touch no dialer (direct=%v inner=%v)", direct.called, inner.called)
	}

	// ULA → DIRECT even with nil resolved
	direct.called, inner.called = false, false
	m2 := &M.Metadata{DstIP: netip.MustParseAddr("fd12::1"), DstPort: 80}
	_, _ = d.DialContext(context.Background(), m2)
	if !direct.called || inner.called {
		t.Fatalf("with resolved=nil, ULA must go direct (direct=%v inner=%v)", direct.called, inner.called)
	}

	// public → TUNNEL even with nil resolved
	direct.called, inner.called = false, false
	m3 := &M.Metadata{DstIP: netip.MustParseAddr("2001:db8::1"), DstPort: 80}
	_, _ = d.DialContext(context.Background(), m3)
	if direct.called || !inner.called {
		t.Fatalf("with resolved=nil, public IPv6 must tunnel (direct=%v inner=%v)", direct.called, inner.called)
	}
}

// Classification unit coverage for IPv6.
func TestIsUnreachableReservedIPv6(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"::1", true},              // loopback
		{"fe80::1", true},          // link-local
		{"fe80::abcd", true},       // link-local
		{"ff02::fb", true},         // multicast
		{"ff00::1", true},          // multicast base
		{"::", true},               // unspecified
		{"fd00:ec2::254", true},    // AWS IMDS v6
		{"fc00::1", false},         // ULA — reachable LAN
		{"fd12::1", false},         // ULA — reachable LAN
		{"2001:db8::1", false},     // public
		{"2606:4700::1111", false}, // public Cloudflare
	}
	for _, c := range cases {
		got := isUnreachableReservedIPv6(netip.MustParseAddr(c.ip))
		if got != c.want {
			t.Errorf("isUnreachableReservedIPv6(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestIsReservedIPv6(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"::1", true},              // loopback (drop class, still reserved)
		{"fe80::1", true},          // link-local
		{"ff02::fb", true},         // multicast
		{"fd00:ec2::254", true},    // metadata
		{"fc00::1", true},          // ULA (direct class, reserved)
		{"fd12::1", true},          // ULA
		{"::", true},               // unspecified
		{"2001:db8::1", false},     // public
		{"2606:4700::1111", false}, // public
	}
	for _, c := range cases {
		got := isReservedIPv6(netip.MustParseAddr(c.ip))
		if got != c.want {
			t.Errorf("isReservedIPv6(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

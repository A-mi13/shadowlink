package bypassroute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

type stubDialer struct {
	called bool
	tag    string
}

func (s *stubDialer) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	s.called = true
	return nil, errors.New("stub:" + s.tag)
}

func (s *stubDialer) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	s.called = true
	return nil, errors.New("stub-udp:" + s.tag)
}

func TestBypassDialer_RoutesByTrie(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("213.180.193.0/24"))
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	m := &M.Metadata{DstIP: netip.MustParseAddr("213.180.193.5"), DstPort: 443}
	_, err := d.DialContext(context.Background(), m)
	if err == nil || err.Error() != "stub:direct" {
		t.Fatalf("expected direct dialer hit, got err=%v", err)
	}
	if !direct.called || inner.called {
		t.Fatalf("called direct=%v inner=%v, want direct only", direct.called, inner.called)
	}

	direct.called, inner.called = false, false

	m2 := &M.Metadata{DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 443}
	_, err = d.DialContext(context.Background(), m2)
	if err == nil || err.Error() != "stub:inner" {
		t.Fatalf("expected inner dialer hit, got err=%v", err)
	}
	if direct.called || !inner.called {
		t.Fatalf("called direct=%v inner=%v, want inner only", direct.called, inner.called)
	}
}

func TestBypassDialer_IPv6FallthroughToInner(t *testing.T) {
	tr := New()
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	v6 := netip.MustParseAddr("2001:db8::1")
	m := &M.Metadata{DstIP: v6, DstPort: 443}
	_, _ = d.DialContext(context.Background(), m)
	if direct.called || !inner.called {
		t.Fatalf("v6 should go via inner, got direct=%v inner=%v", direct.called, inner.called)
	}
}

func TestBypassDialer_UnmapsV4MappedV6(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("8.8.8.0/24"))
	resolved := &Resolved{include: tr, exclude: New()}
	inner := &stubDialer{tag: "inner"}
	direct := &stubDialer{tag: "direct"}
	d := newDialerWithDirect(inner, direct, resolved)

	v4mapped := netip.MustParseAddr("::ffff:8.8.8.8")
	m := &M.Metadata{DstIP: v4mapped, DstPort: 443}
	_, _ = d.DialContext(context.Background(), m)
	if !direct.called {
		t.Fatal("v4-mapped v6 should be unmapped and matched against trie")
	}
}

package bypassroute

import (
	"context"
	"net"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

// BypassDialer wraps a default proxy.Dialer (e.g. SOCKS5 to ShadowLink) and
// short-circuits dials whose destination IP matches a Resolved trie — those
// go through a "direct" dialer (proxy.NewDirect) instead, which dials via the
// system's physical interface, bypassing the TUN.
type BypassDialer struct {
	inner    proxy.Dialer
	direct   proxy.Dialer
	resolved *Resolved
	onMatch  func()
	onMiss   func()
}

// NewBypassDialer constructs a BypassDialer around an inner SOCKS5 dialer.
// The "direct" dialer is built from proxy.NewDirect() — dials use system
// default route unconfigured by the TUN.
func NewBypassDialer(inner proxy.Dialer, resolved *Resolved) *BypassDialer {
	return newDialerWithDirect(inner, proxy.NewDirect(), resolved)
}

func newDialerWithDirect(inner, direct proxy.Dialer, resolved *Resolved) *BypassDialer {
	return &BypassDialer{
		inner:    inner,
		direct:   direct,
		resolved: resolved,
	}
}

// WithMetrics attaches counters incremented on each dial decision.
func (d *BypassDialer) WithMetrics(onMatch, onMiss func()) *BypassDialer {
	d.onMatch = onMatch
	d.onMiss = onMiss
	return d
}

func (d *BypassDialer) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	if d.shouldBypass(m) {
		if d.onMatch != nil {
			d.onMatch()
		}
		return d.direct.DialContext(ctx, m)
	}
	if d.onMiss != nil {
		d.onMiss()
	}
	return d.inner.DialContext(ctx, m)
}

func (d *BypassDialer) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	if d.shouldBypass(m) {
		if d.onMatch != nil {
			d.onMatch()
		}
		return d.direct.DialUDP(m)
	}
	if d.onMiss != nil {
		d.onMiss()
	}
	return d.inner.DialUDP(m)
}

func (d *BypassDialer) shouldBypass(m *M.Metadata) bool {
	if m == nil {
		return false
	}
	addr := m.DstIP
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	// Reserved IPv4 ranges (link-local, loopback, RFC1918, multicast, …) must
	// never traverse the tunnel — they're local-stack traffic that the server
	// can't reach from its vantage point. See reserved.go for the why.
	if isReservedIPv4(addr) {
		return true
	}
	if d.resolved == nil {
		return false
	}
	return d.resolved.Match(addr)
}

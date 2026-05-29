package bypassroute

import (
	"context"
	"fmt"
	"net"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

// errDropUnreachable is returned for dials to unreachable-by-design reserved
// addresses (cloud metadata, loopback, multicast, broadcast). Rejecting here —
// before any OS socket is opened — is the Bug #7 fix: routing these to the
// direct dialer leaked an ephemeral port per failed dial until Windows hit
// "Only one usage of each socket address" and broke all connections.
var errDropUnreachable = fmt.Errorf("bypassroute: destination is an unreachable reserved address (dropped)")

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

// route is the per-dial decision: drop (reject, no socket), direct (physical
// NIC, bypass tunnel), or tunnel (through inner / ShadowLink).
type route int

const (
	routeTunnel route = iota
	routeDirect
	routeDrop
)

func (d *BypassDialer) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	switch d.route(m) {
	case routeDrop:
		if d.onMatch != nil {
			d.onMatch()
		}
		return nil, errDropUnreachable
	case routeDirect:
		if d.onMatch != nil {
			d.onMatch()
		}
		return d.direct.DialContext(ctx, m)
	default:
		if d.onMiss != nil {
			d.onMiss()
		}
		return d.inner.DialContext(ctx, m)
	}
}

func (d *BypassDialer) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	switch d.route(m) {
	case routeDrop:
		if d.onMatch != nil {
			d.onMatch()
		}
		return nil, errDropUnreachable
	case routeDirect:
		if d.onMatch != nil {
			d.onMatch()
		}
		return d.direct.DialUDP(m)
	default:
		if d.onMiss != nil {
			d.onMiss()
		}
		return d.inner.DialUDP(m)
	}
}

// route classifies a destination into drop / direct / tunnel. Order matters:
//   1. unreachable-by-design reserved (cloud metadata, loopback, multicast,
//      broadcast) → DROP (Bug #7 — never open a socket, else ephemeral-port
//      exhaustion against a non-existent host).
//   2. other reserved (RFC1918 LAN) → DIRECT (reachable local machines).
//   3. RIPE-RU / admin-override trie match → DIRECT (bypass tunnel for .ru).
//   4. everything else → TUNNEL.
func (d *BypassDialer) route(m *M.Metadata) route {
	if m == nil {
		return routeTunnel
	}
	addr := m.DstIP
	if !addr.IsValid() {
		return routeTunnel
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return routeTunnel
	}
	if isUnreachableReserved(addr) {
		return routeDrop
	}
	if isReservedIPv4(addr) {
		return routeDirect
	}
	if d.resolved == nil {
		return routeTunnel
	}
	if d.resolved.Match(addr) {
		return routeDirect
	}
	return routeTunnel
}

package socks5

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

// inprocess.go — in-process tun2socks Dialer (Bug #5). Eliminates the loopback
// SOCKS5 socket on the system-VPN data path: instead of tun2socks opening a
// fresh 127.0.0.1:PORT TCP connection per app flow (which exhausts Windows
// ephemeral ports at high throughput), we hand tun2socks a buffered in-memory
// net.Conn (memConn) and run the WS tunnel relay directly in-process.
//
// Routing note (review BLOCKER-1): this dialer does NOT call router.Decide.
// Routing (RU-bypass / reserved / block) is the BypassDialer's responsibility
// one layer up, and tun2socks metadata carries only a concrete IP (no hostname),
// so the dialer only ever receives tunnel-bound destinations.

// inProcessDialer implements tun2socks proxy.Dialer by relaying through the
// shared WS transport in-process. It is stateless beyond its references; safe
// for concurrent DialContext calls from many tun2socks goroutines.
type inProcessDialer struct {
	// engineCtx is the long-lived engine context. Relay goroutines derive their
	// lifetime from THIS, never from the per-dial ctx (which tun2socks bounds to
	// 5s — review HIGH-5). Cancelled on engine shutdown.
	engineCtx context.Context

	// srv carries the WS transport (srv.WST), the client (srv.Client) and the
	// CONNECT semaphore. Reused from the loopback SOCKS5 server so behavior is
	// identical between front-ends.
	srv *Server

	// runRelay tunnels conn↔WS for destAddr. Defaults to the production relay
	// (tunnelTCPStream); overridable in tests. ctx is the relay lifetime ctx.
	runRelay func(ctx context.Context, conn net.Conn, destAddr string)
}

// newInProcessDialer builds the production in-process dialer bound to a Server
// (its WST/Client/semaphore) and the engine context.
func newInProcessDialer(engineCtx context.Context, srv *Server) *inProcessDialer {
	d := &inProcessDialer{engineCtx: engineCtx, srv: srv}
	d.runRelay = func(ctx context.Context, conn net.Conn, destAddr string) {
		// socks5Replies=false: tun2socks established the flow itself and expects
		// the memConn to carry ONLY raw application bytes. Writing SOCKS5 reply
		// framing here would prepend `05 00 00 01 ...` to the downlink and
		// corrupt the first read (tls handshake / garbage). A failed CONNECT is
		// instead signalled by the relay returning → memConn close → app EOF.
		tunnelTCPStream(ctx, conn, srv.Client, srv.WST, destAddr, srv, false)
	}
	return d
}

// DialContext returns the app end of a buffered in-memory pipe and spawns the
// WS tunnel relay on the engine context. The per-dial ctx is intentionally NOT
// propagated to the relay (HIGH-5).
func (d *inProcessDialer) DialContext(_ context.Context, m *M.Metadata) (net.Conn, error) {
	if d.runRelay == nil {
		return nil, fmt.Errorf("in-process dialer: relay not configured")
	}
	dst := m.DestinationAddress()

	appConn, ourConn := newMemPipe()

	// Relay lifetime is the engine ctx, not the 5s dial ctx (HIGH-5). The relay
	// owns ourConn and closes it on exit; tun2socks owns appConn.
	relayCtx := d.engineCtx
	if relayCtx == nil {
		relayCtx = context.Background()
	}
	go func() {
		defer ourConn.Close()
		d.runRelay(relayCtx, ourConn, dst)
	}()

	return appConn, nil
}

// DialUDP returns an in-process PacketConn for one UDP 5-tuple. tun2socks
// drives it via WriteTo (outbound datagram) / ReadFrom (inbound). The
// PacketConn registers a stream on first use and tears it down (FIN +
// UnregisterStream) on Close — critical under DNS bursts where many short-lived
// 5-tuples would otherwise leak server stream slots (review HIGH-3).
func (d *inProcessDialer) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	if d.srv == nil || d.srv.Client == nil || d.srv.WST == nil {
		return nil, fmt.Errorf("in-process dialer: transport not ready")
	}
	cl := d.srv.Client
	wst := d.srv.WST

	// PoolReadiness gate (review HIGH-3 / CLAUDE.md C12 F6): refuse UDP when the
	// WS pool has too few ready slots, so a UDP stream doesn't bind to a slot
	// that may never recover during a cascade. Single-WS transports don't
	// implement PoolReadiness and pass through.
	if pr, ok := wst.(client.PoolReadiness); ok {
		if ready := pr.ReadyCount(); ready < udpMinReadySlots {
			return nil, fmt.Errorf("in-process dialer: UDP refused, only %d ready slots (<%d)", ready, udpMinReadySlots)
		}
	}

	session := cl.Session()
	if session == nil {
		return nil, fmt.Errorf("in-process dialer: no session for UDP")
	}

	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		return nil, fmt.Errorf("in-process dialer: UDP stream register: %w", regErr)
	}

	dst := m.DestinationAddrPort()

	send := func(targetAddr string, data []byte) error {
		chunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, data)
		enc, err := session.EncryptChunk(chunk)
		if err != nil {
			return err
		}
		return wst.WriteMessage(enc)
	}
	cleanup := func() {
		// Send a per-stream FIN so the server frees the slot immediately, then
		// unregister locally. Mirrors HandleUDPAssociateWS teardown.
		cl.CloseStream(streamID, wst)
	}

	return newStreamPacketConn(dst, incomingCh, send, cleanup), nil
}

// streamPacketConn is an in-process net.PacketConn for one UDP 5-tuple. It maps
// tun2socks WriteTo/ReadFrom onto the ShadowLink UDP chunk protocol.
//
// HIGH-2: ReadFrom ALWAYS returns from == dst (the dial destination), never the
// addr embedded in the server's UDP chunk — tun2socks' symmetricNATPacketConn
// drops any datagram whose from-addr != dst.
type streamPacketConn struct {
	dst        netip.AddrPort
	dstUDPAddr *net.UDPAddr
	incoming   <-chan []byte
	send       func(targetAddr string, data []byte) error
	cleanup    func()

	mu        sync.Mutex
	rdeadline time.Time
	closed    chan struct{}
	closeOnce sync.Once
}

func newStreamPacketConn(dst netip.AddrPort, incoming <-chan []byte, send func(string, []byte) error, cleanup func()) *streamPacketConn {
	return &streamPacketConn{
		dst:        dst,
		dstUDPAddr: net.UDPAddrFromAddrPort(dst),
		incoming:   incoming,
		send:       send,
		cleanup:    cleanup,
		closed:     make(chan struct{}),
	}
}

// WriteTo encodes an outbound datagram as a UDP chunk and sends it. The target
// address is the datagram's destination (addr), which for tun2socks equals dst.
func (p *streamPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	if err := p.send(addr.String(), b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom blocks until an inbound datagram arrives on the stream channel, the
// read deadline fires, or the conn is closed. Returns from == dst (HIGH-2).
func (p *streamPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		dl := p.rdeadline
		p.mu.Unlock()

		var timer *time.Timer
		var timerC <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, timeoutError{}
			}
			timer = time.NewTimer(d)
			timerC = timer.C
		}

		select {
		case <-p.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-timerC:
			return 0, nil, timeoutError{}
		case payload, ok := <-p.incoming:
			if timer != nil {
				timer.Stop()
			}
			if !ok || payload == nil {
				return 0, nil, net.ErrClosed
			}
			// payload is the full FlagUDP chunk payload WITH the 2-byte StreamID
			// prefix (demux contract differs from TCP). ParseUDPChunk expects it.
			_, _, data, err := core.ParseUDPChunk(payload)
			if err != nil || len(data) == 0 {
				continue // skip malformed/empty, keep waiting
			}
			n := copy(b, data)
			// HIGH-2: return dst, NOT the chunk's embedded addr.
			return n, p.dstUDPAddr, nil
		}
	}
}

func (p *streamPacketConn) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		if p.cleanup != nil {
			p.cleanup()
		}
	})
	return nil
}

func (p *streamPacketConn) LocalAddr() net.Addr { return p.dstUDPAddr }

func (p *streamPacketConn) SetDeadline(t time.Time) error {
	return p.SetReadDeadline(t)
}
func (p *streamPacketConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.rdeadline = t
	p.mu.Unlock()
	return nil
}
func (p *streamPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.PacketConn = (*streamPacketConn)(nil)

// compile-time check: inProcessDialer implements proxy.Dialer.
var _ proxy.Dialer = (*inProcessDialer)(nil)

// NewInProcessDialer is the exported constructor used by the engine wiring
// (Bug #5 P4). Returns a proxy.Dialer ready to install as BypassDialer.inner.
func NewInProcessDialer(engineCtx context.Context, srv *Server) proxy.Dialer {
	return newInProcessDialer(engineCtx, srv)
}

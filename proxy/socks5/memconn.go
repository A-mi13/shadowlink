package socks5

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// memconn.go — buffered in-memory net.Conn pair used by the in-process
// tun2socks dialer (Bug #5). Replaces the loopback SOCKS5 socket on the
// system-VPN data path so no ephemeral OS port is consumed per app connection
// (Windows port exhaustion at high throughput).
//
// Why not net.Pipe: net.Pipe is fully synchronous — every Write blocks until a
// matching Read consumes it. At 460 Mbit/s tun2socks io.CopyBuffer (20KB chunks)
// would be ping-ponged on every chunk. memConn gives each direction a bounded
// in-memory buffer so writes return immediately while space remains, applying
// backpressure (block) only when the buffer is full — never dropping data.
//
// Contract required by tun2socks v2.6.0 (tunnel/tcp.go unidirectionalStream):
//   - CloseRead() / CloseWrite() for TCP half-close.
//   - SetReadDeadline honored (60s half-close drain timeout).
//   - Close on either end unblocks a peer blocked in Read.
//   - LocalAddr()/RemoteAddr() parse as host:port (tun2socks parseNetAddr).

// memPipeBufferSize bounds each direction's in-memory buffer. 256 KiB ≈ 8×
// tun2socks' 20KB relay chunk: enough to decouple the fast TUN side from a
// slower WS/CF write without unbounded RAM. Backpressure (blocking Write) kicks
// in past this, which is correct — it throttles the producer instead of buffering
// without limit. Tunable if field benchmarks show it throttles real WS throughput.
const memPipeBufferSize = 256 * 1024

// memBuffer is a single-direction byte buffer with blocking semantics and
// deadline support, shared by the writer end and the reader end of one
// direction. Guarded by mu; cond signals both space-available (to writers) and
// data-available/closed (to readers).
type memBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	max    int
	closed bool // write side done (CloseWrite or Close) — reader drains then EOF

	rdeadline time.Time
	wdeadline time.Time
	// deadlineCh is closed and recreated whenever a deadline changes, so a
	// blocked Read/Write goroutine wakes to re-evaluate. A dedicated timer
	// goroutine broadcasts on the cond when a deadline expires.
}

func newMemBuffer(max int) *memBuffer {
	b := &memBuffer{max: max}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *memBuffer) timedOut(deadline time.Time) bool {
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

// write appends p, blocking while the buffer is full. Returns number written
// and an error (timeout or closed).
func (b *memBuffer) write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	total := 0
	for len(p) > 0 {
		for !b.closed && len(b.buf) >= b.max && !b.timedOut(b.wdeadline) {
			b.startDeadlineTimerLocked(b.wdeadline)
			b.cond.Wait()
		}
		if b.closed {
			return total, io.ErrClosedPipe
		}
		if b.timedOut(b.wdeadline) {
			return total, timeoutError{}
		}
		space := b.max - len(b.buf)
		n := min(len(p), space)
		b.buf = append(b.buf, p[:n]...)
		p = p[n:]
		total += n
		b.cond.Broadcast() // wake readers
	}
	return total, nil
}

// read pulls up to len(p) bytes, blocking until data is available, the buffer
// is closed (then drains remaining, finally io.EOF), or the read deadline fires.
func (b *memBuffer) read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if len(b.buf) > 0 {
			n := copy(p, b.buf)
			b.buf = b.buf[n:]
			b.cond.Broadcast() // wake writers (space freed)
			return n, nil
		}
		if b.closed {
			return 0, io.EOF
		}
		if b.timedOut(b.rdeadline) {
			return 0, timeoutError{}
		}
		b.startDeadlineTimerLocked(b.rdeadline)
		b.cond.Wait()
	}
}

// close marks the write side done; readers drain remaining bytes then see EOF.
func (b *memBuffer) close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		b.cond.Broadcast()
	}
	b.mu.Unlock()
}

// isClosed reports whether the write side of this direction has been closed
// (via CloseWrite or Close). Used by the in-process relay to distinguish a
// half-close (only the uplink direction d1 closed) from a full close (both
// directions closed by appConn.Close).
func (b *memBuffer) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

func (b *memBuffer) setReadDeadline(t time.Time) {
	b.mu.Lock()
	b.rdeadline = t
	b.startDeadlineTimerLocked(t)
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *memBuffer) setWriteDeadline(t time.Time) {
	b.mu.Lock()
	b.wdeadline = t
	b.startDeadlineTimerLocked(t)
	b.cond.Broadcast()
	b.mu.Unlock()
}

// startDeadlineTimerLocked schedules a broadcast at deadline t so blocked
// goroutines re-evaluate timedOut. Called under b.mu. Cheap: one goroutine per
// future deadline; they coalesce on the shared cond. No-op for zero/past times
// (past is caught by the timedOut check on the next loop iteration anyway).
func (b *memBuffer) startDeadlineTimerLocked(t time.Time) {
	if t.IsZero() {
		return
	}
	d := time.Until(t)
	if d <= 0 {
		b.cond.Broadcast()
		return
	}
	time.AfterFunc(d, func() {
		b.mu.Lock()
		b.cond.Broadcast()
		b.mu.Unlock()
	})
}

// memConn is one end of the pair. rd is the direction it reads from, wr the
// direction it writes to. The peer has them swapped.
//
// peerFullClose is a channel SHARED by both ends, closed exactly once when the
// *app* end performs a full Close (real FIN) — never on CloseWrite (half-close).
// The relay's ourConn selects on PeerFullCloseSignal() so a full Close that
// arrives AFTER an earlier half-close (when the uplink goroutine has already
// returned) still tears the downlink goroutine down — closing the only leak
// window left once idle-grace is removed from the in-process path.
//
// isAppEnd marks which memConn is handed to tun2socks (the app). Only the app
// end's Close fires peerFullClose; the relay's ourConn.Close (cleanup on relay
// exit) does not, so it cannot self-signal a false FIN.
type memConn struct {
	rd            *memBuffer
	wr            *memBuffer
	localAddr     net.Addr
	closeOnce     sync.Once
	isAppEnd      bool
	peerFullClose chan struct{}
	fullCloseOnce *sync.Once

	// downlinkDeadlineImmune is set on the APP end when tun2socks half-closes the
	// uplink (CloseWrite). While set (and full Close has not happened), the app's
	// downlink Read ignores any read-deadline: a long-poll / SSE response that goes
	// quiet for >tun2socks tcpWaitTimeout (60s) is legitimate and must NOT be torn
	// down. tun2socks calls CloseWrite() THEN SetReadDeadline(now+60s) in sequence
	// (vendored tunnel/tcp.go:68→72), so both CloseWrite (clears the live deadline)
	// and SetReadDeadline (becomes a no-op) must honor this flag. Full Close still
	// tears down via rd.close()/peerFullClose — immune does not affect that.
	downlinkDeadlineImmune atomic.Bool
}

// newMemPipe returns a connected pair of buffered in-memory net.Conns. The
// first return value (a) is the app end handed to tun2socks; the second (b) is
// the relay end (ourConn).
func newMemPipe() (net.Conn, net.Conn) {
	d1 := newMemBuffer(memPipeBufferSize) // a writes → b reads
	d2 := newMemBuffer(memPipeBufferSize) // b writes → a reads
	fc := make(chan struct{})
	var fcOnce sync.Once
	a := &memConn{rd: d2, wr: d1, localAddr: memAddr("127.0.0.1:0"), isAppEnd: true, peerFullClose: fc, fullCloseOnce: &fcOnce}
	b := &memConn{rd: d1, wr: d2, localAddr: memAddr("127.0.0.1:0"), isAppEnd: false, peerFullClose: fc, fullCloseOnce: &fcOnce}
	return a, b
}

func (c *memConn) Read(p []byte) (int, error)  { return c.rd.read(p) }
func (c *memConn) Write(p []byte) (int, error) { return c.wr.write(p) }

// PeerFullCloseSignal returns a channel closed when the app end performs a full
// Close (real FIN). Used by the in-process relay to tear down the downlink
// goroutine even when a full Close follows an earlier half-close.
func (c *memConn) PeerFullCloseSignal() <-chan struct{} { return c.peerFullClose }

// Close shuts both directions: stop reading (peer's writes will error) and
// signal EOF to the peer's reader. Idempotent. When called on the app end it
// also fires peerFullClose so the relay distinguishes this real FIN from a
// half-close.
func (c *memConn) Close() error {
	c.closeOnce.Do(func() {
		c.wr.close() // peer's Read sees EOF after draining
		c.rd.close() // unblock our own blocked Read
		if c.isAppEnd {
			c.fullCloseOnce.Do(func() { close(c.peerFullClose) })
		}
	})
	return nil
}

// CloseWrite half-closes the write direction: the peer's Read drains buffered
// data then returns io.EOF. Our Read side stays open. [tun2socks half-close]
//
// On the APP end this is the tun2socks half-close signal (uplink done). We mark
// the downlink deadline-immune and clear any already-armed read-deadline so a
// quiet long-poll downlink is not torn down by the 60s tcpWaitTimeout that
// tun2socks arms on the very next line (vendored tunnel/tcp.go:72).
func (c *memConn) CloseWrite() error {
	c.wr.close()
	if c.isAppEnd {
		c.downlinkDeadlineImmune.Store(true)
		c.rd.setReadDeadline(time.Time{}) // clear any deadline armed before CloseWrite
	}
	return nil
}

// CloseRead half-closes the read direction: we stop consuming; the peer's
// writes will eventually block/err. [tun2socks half-close]
func (c *memConn) CloseRead() error {
	c.rd.close()
	return nil
}

// writeClosed reports whether our write direction has been closed by the peer's
// full Close. For the relay's ourConn this distinguishes the two ways the peer
// (tun2socks' appConn) can signal uplink EOF:
//
//   - appConn.CloseWrite() (TCP half-close): closes only the uplink direction
//     d1 → ourConn.Read sees io.EOF, but ourConn.wr (downlink d2) stays open →
//     writeClosed() == false. Downlink is still live (HTTP keep-alive: app sent
//     its request and waits for the response / further responses).
//   - appConn.Close() (full close, real FIN): closes BOTH d1 and d2 →
//     ourConn.Read sees io.EOF AND ourConn.wr is closed → writeClosed() == true.
//     The stream must be torn down.
//
// memConn satisfies the unexported writeCloseDetector interface in tcp.go so the
// in-process relay can branch on this without importing concrete types.
func (c *memConn) writeClosed() bool { return c.wr.isClosed() }

func (c *memConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *memConn) RemoteAddr() net.Addr { return c.localAddr }

func (c *memConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t) // honors the half-close immune guard
	c.wr.setWriteDeadline(t)
	return nil
}
func (c *memConn) SetReadDeadline(t time.Time) error {
	// After a half-close on the app end, ignore read-deadlines on the downlink:
	// tun2socks arms a 60s deadline right after CloseWrite, which would otherwise
	// kill a legitimately-quiet long-poll/SSE response.
	if c.isAppEnd && c.downlinkDeadlineImmune.Load() {
		return nil
	}
	c.rd.setReadDeadline(t)
	return nil
}
func (c *memConn) SetWriteDeadline(t time.Time) error { c.wr.setWriteDeadline(t); return nil }

// memAddr is a synthetic net.Addr that parses as host:port for tun2socks'
// parseNetAddr (which reads conn.LocalAddr()).
type memAddr string

func (a memAddr) Network() string { return "mem" }
func (a memAddr) String() string  { return string(a) }

// timeoutError satisfies net.Error with Timeout()==true so callers (and
// tun2socks) treat memConn deadline expiry like a real socket timeout.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

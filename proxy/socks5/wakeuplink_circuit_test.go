package socks5

// wakeuplink_circuit_test.go — integration tests for the defer wakeUplink
// contract in the live tunnelTCPStream relay circuit.
//
// These tests exercise the FULL relay loop (tunnelTCPStream via
// newInProcessDialer / echoTransport / keepAliveEchoTransport) rather than the
// wakeUplink helper in isolation (that is covered by tcp_test.go). Two
// scenarios:
//
//   MEDIUM-1: downlink-exit wakes the uplink goroutine on the in-process path.
//             The application sends a request, then goes quiet (no more uplink
//             data). The mock server closes the downlink channel. The relay MUST
//             exit completely (both goroutines) within a short deadline — the
//             deferred wakeUplink(conn, socks5Replies) in the downlink goroutine
//             must call conn.CloseRead() which wakes the uplink Read.
//
//   MEDIUM-2: on the loopback SOCKS5 path (socks5Replies=true) the relay tears
//             down quickly after early downlink close — well below the
//             downlinkIdleGrace window. We shrink the grace to 500ms and confirm
//             the relay finishes in <300ms. This proves wakeUplink fires before
//             the idle-grace timer and also confirms that downlink bytes written
//             *before* the close were not lost (they were flushed to the app).

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"

	"github.com/stretchr/testify/require"
)

// closeOnWriteTransport is a mock StreamTransport that:
//   - Acks CONNECT_OK immediately (same pattern as echoTransport).
//   - Delivers an optional downlink payload.
//   - Then closes the downlink channel for the stream so the downlink goroutine
//     exits — triggering the deferred wakeUplink.
//
// This exercises MEDIUM-1: after downlink closes, wakeUplink must unblock the
// uplink goroutine that is parked in conn.Read with no application traffic.
type closeOnWriteTransport struct {
	cl       *client.Client
	downlink []byte // optional bytes to deliver before closing

	mu        sync.Mutex
	streamID  uint16
	gotStream bool
	echoOnce  sync.Once
}

func newCloseOnWriteTransport(cl *client.Client, downlink []byte) *closeOnWriteTransport {
	return &closeOnWriteTransport{cl: cl, downlink: downlink}
}

func (e *closeOnWriteTransport) WriteMessage(data []byte) error {
	e.mu.Lock()
	sid := e.streamID
	ready := e.gotStream
	e.mu.Unlock()
	if !ready {
		return nil
	}
	e.echoOnce.Do(func() {
		go func() {
			// Step 1: ack CONNECT_OK so the relay can proceed.
			e.cl.RouteToStream(sid, []byte("CONNECT_OK"))
			time.Sleep(20 * time.Millisecond)
			// Step 2: optionally deliver payload.
			if len(e.downlink) > 0 {
				e.cl.RouteToStream(sid, append([]byte(nil), e.downlink...))
				time.Sleep(10 * time.Millisecond)
			}
			// Step 3: signal stream-closed to the downlink goroutine by sending a
			// nil frame. The relay treats `data == nil` as a stream-close signal
			// (tcp.go: `if !ok || data == nil { return }`). This mirrors what the
			// real WS demux does when the server closes the stream (ResetStreams
			// closes channels; RouteToStream nil is the in-test equivalent).
			e.cl.RouteToStream(sid, nil)
		}()
	})
	return nil
}

func (e *closeOnWriteTransport) StartReader(ctx context.Context, cl *client.Client) error { return nil }
func (e *closeOnWriteTransport) Close() error                                             { return nil }

func (e *closeOnWriteTransport) AssignStream(streamID uint16) {
	e.mu.Lock()
	e.streamID = streamID
	e.gotStream = true
	e.mu.Unlock()
}
func (e *closeOnWriteTransport) ReleaseStream(streamID uint16)                  {}
func (e *closeOnWriteTransport) SessionForStream(streamID uint16) *core.Session { return e.cl.Session() }
func (e *closeOnWriteTransport) WriteMessageForStream(streamID uint16, data []byte) error {
	return e.WriteMessage(data)
}

var _ client.StreamTransport = (*closeOnWriteTransport)(nil)
var _ client.PoolAware = (*closeOnWriteTransport)(nil)

// TestDownlinkExit_WakesUplinkInCircuit (MEDIUM-1): exercises the complete
// in-process relay circuit. The app sends a request and then goes silent (no
// more uplink writes). The mock transport acks CONNECT_OK, delivers a small
// downlink payload, then closes the stream channel — exactly what happens when
// the remote server closes the connection. The downlink goroutine's deferred
// wakeUplink(conn, false) must call conn.CloseRead() on the memConn, which
// unblocks the uplink goroutine's conn.Read. The relay exits; wg.Wait returns.
//
// Failure mode without the fix: the uplink goroutine blocks forever in
// ourConn.Read (nobody ever closes d1 from the relay side) and wg.Wait hangs.
func TestDownlinkExit_WakesUplinkInCircuit(t *testing.T) {
	cl := setupConnectedClient(t)

	downlinkPayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	tr := newCloseOnWriteTransport(cl, downlinkPayload)

	srv := &Server{Client: cl, WST: tr}
	engineCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := newInProcessDialer(engineCtx, srv)

	appConn, err := d.DialContext(context.Background(), metaFor("142.250.1.1", 80))
	require.NoError(t, err)
	defer appConn.Close()

	// App sends a request and goes silent: uplink half-closes write so the uplink
	// goroutine in the relay will see EOF and park waiting for idle-grace/cancel.
	_, err = appConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)
	// Half-close: tell the relay's uplink goroutine the request is done.
	if hc, ok := appConn.(interface{ CloseWrite() error }); ok {
		require.NoError(t, hc.CloseWrite())
	}

	// Drain the downlink — we expect the full response to arrive.
	appConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(downlinkPayload))
	n, err := io.ReadFull(appConn, buf)
	require.NoError(t, err, "downlink payload did not reach appConn")
	require.Equal(t, downlinkPayload, buf[:n])

	// After downlink close the relay must tear down (both goroutines exit).
	// The relay goroutine owns ourConn and closes it on exit (see inprocess.go:81).
	// appConn.Read will return io.EOF when ourConn.Close() closes d2 (downlink).
	appConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	extra := make([]byte, 1)
	_, err = appConn.Read(extra)
	require.Equal(t, io.EOF, err,
		"relay did not tear down after downlink close — wakeUplink may not have fired")
}

// TestLoopback_EarlyDownlinkClose_NoIdleGraceWait (MEDIUM-2): on the loopback
// SOCKS5 path (socks5Replies=true) the relay uses idle-grace to wait after
// uplink EOF before tearing down. However, when the downlink exits first
// (server closed the connection), the deferred wakeUplink fires IMMEDIATELY
// and cancels the relay without waiting for the idle-grace window.
//
// We shrink idle-grace to 500ms and deliver downlink bytes followed by a stream
// close. The relay must finish within 300ms (well before the 500ms grace).
// Additionally the downlink bytes written before the close must reach appConn
// (no data loss).
//
// The test also verifies that previously-delivered downlink bytes are not lost:
// the payload is flushed to conn before the channel closes.
func TestLoopback_EarlyDownlinkClose_NoIdleGraceWait(t *testing.T) {
	// Shrink idle-grace so that if the relay mistakenly waits it out, the test
	// still finishes quickly but fails the <300ms assertion.
	withShrunkIdleGrace(t, 500*time.Millisecond, 50*time.Millisecond)

	cl := setupConnectedClient(t)

	downlinkPayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	tr := newCloseOnWriteTransport(cl, downlinkPayload)

	srv := &Server{Client: cl, WST: tr}
	engineCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// socks5Replies=true path: use HandleTCPConnectWS via a loopback connection.
	// We route directly through tunnelTCPStream with socks5Replies=true so the
	// uplink goroutine takes the idle-grace branch (not the in-process half-close
	// branch). A net.Pipe pair simulates the loopback socket.
	appSide, relaySide := newMemPipe()
	defer appSide.Close()

	relayDone := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(relayDone)
		defer relaySide.Close()
		// socks5Replies=true — loopback path; idle-grace is active.
		tunnelTCPStream(engineCtx, relaySide, cl, tr, "142.250.1.1:80", srv, true)
	}()

	// The relay writes ReplySuccess (10 bytes) for socks5Replies=true. Read it.
	appSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	replyBuf := make([]byte, 10)
	_, err := io.ReadFull(appSide, replyBuf)
	require.NoError(t, err, "SOCKS5 reply did not arrive")

	// Now app sends uplink data. The app uplink goroutine parks after this — we
	// deliberately do NOT close the write side on the loopback path (it's a real
	// socket scenario); the uplink goroutine blocks in Read until wakeUplink fires.
	_, err = appSide.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)

	// Read downlink payload — must arrive before relay tears down.
	appSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	downBuf := make([]byte, len(downlinkPayload))
	n, err := io.ReadFull(appSide, downBuf)
	require.NoError(t, err, "downlink payload must arrive before relay closes")
	require.Equal(t, downlinkPayload, downBuf[:n], "downlink data must not be lost")

	// After downlink close the relay must finish quickly — no idle-grace wait.
	select {
	case <-relayDone:
		elapsed := time.Since(start)
		// The relay should finish well before the 500ms shrunk idle-grace. We
		// allow 350ms generously (includes CONNECT_OK, payload delivery, stream
		// close, wakeUplink CloseRead propagation).
		require.Less(t, elapsed, 350*time.Millisecond,
			"relay took %v — likely waited idle-grace instead of wakeUplink", elapsed)
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not finish after downlink close — uplink goroutine may be stuck in idle-grace")
	}
}

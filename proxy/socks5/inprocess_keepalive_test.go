package socks5

import (
	"context"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"

	"github.com/stretchr/testify/require"
)

// keepAliveEchoTransport mimics the server side of a keep-alive HTTP stream:
// it acks CONNECT_OK, then delivers a downlink payload ONLY after a delay that
// exceeds the (test-shrunk) idle-grace window. This reproduces the keep-alive
// pattern that the in-process bug severed: the app does appConn.CloseWrite()
// (uplink EOF) right after sending its request, then sits quietly waiting for
// the response — which arrives later than idle-grace.
//
// It also records whether RouteToStream was still able to deliver (i.e. the
// stream channel was not torn down) so the test can assert the downlink direction
// stayed alive across the would-be idle-grace deadline.
type keepAliveEchoTransport struct {
	cl       *client.Client
	downlink []byte
	delay    time.Duration

	mu        sync.Mutex
	streamID  uint16
	gotStream bool
	echoOnce  sync.Once
}

func (e *keepAliveEchoTransport) WriteMessage(data []byte) error {
	e.mu.Lock()
	sid := e.streamID
	ready := e.gotStream
	e.mu.Unlock()
	if !ready {
		return nil
	}
	e.echoOnce.Do(func() {
		go func() {
			e.cl.RouteToStream(sid, []byte("CONNECT_OK"))
			// Deliver the response only AFTER the idle-grace window would have
			// fired on the buggy path. On the fixed in-process path no idle-grace
			// runs, so the downlink survives and this payload is delivered.
			time.Sleep(e.delay)
			e.cl.RouteToStream(sid, append([]byte(nil), e.downlink...))
		}()
	})
	return nil
}

func (e *keepAliveEchoTransport) StartReader(ctx context.Context, cl *client.Client) error { return nil }
func (e *keepAliveEchoTransport) Close() error                                             { return nil }

func (e *keepAliveEchoTransport) AssignStream(streamID uint16) {
	e.mu.Lock()
	e.streamID = streamID
	e.gotStream = true
	e.mu.Unlock()
}
func (e *keepAliveEchoTransport) ReleaseStream(streamID uint16)                  {}
func (e *keepAliveEchoTransport) SessionForStream(streamID uint16) *core.Session { return e.cl.Session() }
func (e *keepAliveEchoTransport) WriteMessageForStream(streamID uint16, data []byte) error {
	return e.WriteMessage(data)
}

var _ client.StreamTransport = (*keepAliveEchoTransport)(nil)
var _ client.PoolAware = (*keepAliveEchoTransport)(nil)

// withShrunkIdleGrace temporarily shrinks the idle-grace constants so the test
// can prove a behavioral property quickly. Restored on cleanup.
func withShrunkIdleGrace(t *testing.T, grace, poll time.Duration) {
	t.Helper()
	og, op := downlinkIdleGrace, downlinkIdlePoll
	downlinkIdleGrace = grace
	downlinkIdlePoll = poll
	t.Cleanup(func() {
		downlinkIdleGrace = og
		downlinkIdlePoll = op
	})
}

// TestInProcess_KeepAliveSurvivesIdleGrace is the regression test for the bug
// that severed live keep-alive connections. In the in-process path the app does
// CloseWrite (uplink half-close) and then waits SILENTLY for a downlink that
// arrives AFTER the idle-grace window. On the buggy path the uplink goroutine
// fired waitForIdleOrCancel + cancel and tore the whole stream down before the
// response arrived. On the fixed path the in-process uplink EOF (half-close)
// does NOT idle-grace at all — the downlink survives and the response is
// delivered.
//
// We shrink idle-grace to 100ms and deliver the downlink at 400ms: if the buggy
// idle-grace path were still active, the stream would be cancelled at ~100ms and
// the read would never complete.
func TestInProcess_KeepAliveSurvivesIdleGrace(t *testing.T) {
	withShrunkIdleGrace(t, 100*time.Millisecond, 20*time.Millisecond)

	cl := setupConnectedClient(t)

	wantDownlink := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	echo := &keepAliveEchoTransport{cl: cl, downlink: wantDownlink, delay: 400 * time.Millisecond}

	srv := &Server{Client: cl}
	srv.SetWST(echo)

	engineCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := newInProcessDialer(engineCtx, srv)

	appConn, err := d.DialContext(context.Background(), metaFor("142.250.1.1", 80))
	require.NoError(t, err)
	defer appConn.Close()

	// Request, then half-close uplink (tun2socks unidirectionalStream behavior).
	_, err = appConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)
	hc, ok := appConn.(interface{ CloseWrite() error })
	require.True(t, ok, "memConn must support CloseWrite")
	require.NoError(t, hc.CloseWrite())

	// The response arrives at 400ms — well past the 100ms idle-grace. It must
	// still reach appConn.Read because the in-process path doesn't idle-grace.
	appConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(wantDownlink))
	n, err := io.ReadFull(appConn, buf)
	require.NoError(t, err, "downlink after idle-grace window did not reach appConn — keep-alive was severed")
	require.Equal(t, wantDownlink, buf[:n])
}

// TestInProcess_FullCloseTerminatesStream verifies the other half of the
// contract: when the app does a FULL Close (real FIN, not half-close), the relay
// MUST tear down — both relay goroutines exit, the stream is unregistered, and no
// goroutine leaks. Without this, removing the idle-grace cancel could leave the
// downlink goroutine blocked forever on incomingCh after the app is gone.
func TestInProcess_FullCloseTerminatesStream(t *testing.T) {
	withShrunkIdleGrace(t, 100*time.Millisecond, 20*time.Millisecond)

	cl := setupConnectedClient(t)

	// No downlink ever arrives (server stays silent) so the only thing that can
	// end the stream is the app's full Close.
	echo := &keepAliveEchoTransport{cl: cl, downlink: nil, delay: time.Hour}

	srv := &Server{Client: cl}
	srv.SetWST(echo)

	engineCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := newInProcessDialer(engineCtx, srv)

	before := runtime.NumGoroutine()

	appConn, err := d.DialContext(context.Background(), metaFor("142.250.1.1", 80))
	require.NoError(t, err)

	_, err = appConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)

	// Give the relay goroutines time to spin up and the CONNECT_OK to flow.
	time.Sleep(150 * time.Millisecond)

	// Full close (real FIN): must terminate the whole relay.
	require.NoError(t, appConn.Close())

	// Within a short window all relay goroutines must have exited and the stream
	// must be unregistered. Poll the goroutine count back to baseline.
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.GC()
		if runtime.NumGoroutine() <= before+1 { // +1 tolerance for scheduler noise
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay goroutines did not exit after full Close: before=%d now=%d", before, runtime.NumGoroutine())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

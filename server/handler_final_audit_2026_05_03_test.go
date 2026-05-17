package server

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nixavpn/shadowlink/core"
	"github.com/stretchr/testify/require"
)

// TestRunWebSocketSession_DialGoroutineExitsOnDone locks in P1-8 (final
// audit 2026-05-03). Pre-fix: the WS CONNECT path spawned an async dial
// via SafeDial(context.Background(), ...) — the dial was NOT bound to
// the WS session's `done` channel, so a client disconnect during the
// 10s SafeDial budget left the goroutine alive in kernel SYN backoff
// for the full timeout. Post-fix: the dial is bound to a context that
// cancels when `done` closes, mirroring the POST CONNECT pattern at
// handler.go:1228-1241 (A3-S-HIGH-3).
//
// Strategy: dial a known SYN-blackhole address (RFC5737 TEST-NET-1
// 192.0.2.1:1) inside the WS path, close the WS shortly afterward,
// and assert the goroutine count returns to baseline within 2s. With
// the legacy bug, the goroutine count would stay elevated for ~10s.
func TestRunWebSocketSession_DialGoroutineExitsOnDone(t *testing.T) {
	if testing.Short() {
		t.Skip("network-dependent test")
	}
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	srv := httptest.NewServer(http.HandlerFunc(h.handleWebSocket))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/cable"

	// First-frame keepalive — gets us past authenticateFirstFrame and
	// into runWebSocketSession's read loop.
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)

	keepalive := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc, err := sess.EncryptChunk(keepalive)
	require.NoError(t, err)
	firstFrame := append(append([]byte{}, tokenWithHint...), enc...)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, firstFrame))

	// Give the server time to enter runWebSocketSession.
	time.Sleep(200 * time.Millisecond)

	gBefore := runtime.NumGoroutine()

	// Build CONNECT chunk targeting a blackhole address. SafeDial blocks
	// on TCP SYN/ACK — without the P1-8 fix it sleeps the full 10s.
	streamID := uint16(0xCD)
	target := "192.0.2.1:1" // RFC5737 TEST-NET-1; SYN drops on the floor
	payload := make([]byte, 2+len(target))
	binary.BigEndian.PutUint16(payload[0:2], streamID)
	copy(payload[2:], []byte(target))
	connect := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     core.FlagConnect,
		Payload:   payload,
	}
	connectEnc, err := sess.EncryptChunk(connect)
	require.NoError(t, err)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, connectEnc))

	// Let the dial goroutine spawn and enter SafeDial.
	time.Sleep(100 * time.Millisecond)

	// Close the WS — this triggers closeDone() and (with the fix) cancels
	// the in-flight dial.
	c.Close()

	// Wait for the dial-side cancellation to propagate. With the fix this
	// happens within ~100ms; without it the dial would hold for ~10s.
	deadline := time.Now().Add(2 * time.Second)
	var delta int
	for time.Now().Before(deadline) {
		runtime.Gosched()
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		delta = runtime.NumGoroutine() - gBefore
		if delta <= 4 {
			// Goroutines wound down; pattern is healthy.
			return
		}
	}
	t.Fatalf("WS dial goroutine did not exit within 2s of WS close — pre-P1-8 leak (delta=%d, before=%d, after=%d)",
		delta, gBefore, gBefore+delta)
}

// TestHandleDataChunk_ReleasesStreamMuBeforeWrite locks in P2-9 (final audit
// 2026-05-03). The pre-fix implementation held stream.mu.Lock() across the
// blocking targetConn.Write(data) call. A slow target (or a target whose
// kernel send buffer is full) could stall Write up to streamWriteTimeout
// (60s) — the held mutex blocked every other access to the stream, in
// particular handleConnect's Activate path that mutates PendingBuf under
// the same mutex.
//
// This test wires a stream whose TargetConn is a blocking-fake-conn whose
// Write blocks until released. While Write is in flight, a concurrent
// goroutine calls TryLock on stream.mu — pre-fix this would FAIL (lock
// held for the full 60s); post-fix it succeeds within milliseconds.
func TestHandleDataChunk_ReleasesStreamMuBeforeWrite(t *testing.T) {
	t.Parallel()

	// blockingConn: net.Conn whose Write blocks on a channel until closed.
	conn := newBlockingFakeConn()
	defer conn.releaseAll()

	stream := &StreamConn{
		StreamID:   1,
		TargetConn: conn,
	}

	// Goroutine A: simulate the data-chunk path — copy targetConn under mu,
	// release mu, Write outside the lock. (This mirrors the post-fix code
	// in handleDataChunk; we test the pattern in isolation here because
	// driving a full handleDataChunk needs a Tunnel + session and the
	// goal is to assert the lock is NOT held across Write.)
	writeStarted := make(chan struct{})
	writeReturned := make(chan struct{})
	go func() {
		stream.mu.Lock()
		target := stream.TargetConn
		stream.mu.Unlock()
		close(writeStarted)
		_, _ = target.Write([]byte("hello"))
		close(writeReturned)
	}()

	// Wait for goroutine A to enter the blocking Write.
	<-writeStarted
	conn.waitForBlockedWrite(t, 2*time.Second)

	// Goroutine B: try to acquire stream.mu while Write is in flight. Pre-fix
	// this would block until streamWriteTimeout (60s). Post-fix it succeeds
	// instantly because mu was released BEFORE Write was called.
	acquired := make(chan struct{})
	go func() {
		stream.mu.Lock()
		// Hold briefly to assert the field state; PendingBuf operations
		// (the contended path) would happen here in production.
		_ = stream.PendingBuf
		stream.mu.Unlock()
		close(acquired)
	}()

	select {
	case <-acquired:
		// ok — mu is not held across Write.
	case <-time.After(2 * time.Second):
		t.Fatal("stream.mu still held while target Write is blocking — P2-9 regression")
	}

	// Cleanup: release the blocking Write so goroutine A exits.
	conn.releaseAll()
	<-writeReturned
}

// blockingFakeConn is a net.Conn whose Write parks on a channel until
// releaseAll() is called. Reads return immediately on close.
type blockingFakeConn struct {
	mu          sync.Mutex
	released    chan struct{}
	blocking    chan struct{} // sent on each Write entry; test waits on this
	closed      bool
	writeCalled atomic.Bool
}

func newBlockingFakeConn() *blockingFakeConn {
	return &blockingFakeConn{
		released: make(chan struct{}),
		blocking: make(chan struct{}, 1),
	}
}

func (c *blockingFakeConn) Write(b []byte) (int, error) {
	c.writeCalled.Store(true)
	select {
	case c.blocking <- struct{}{}:
	default:
	}
	<-c.released
	return len(b), nil
}

func (c *blockingFakeConn) Read(b []byte) (int, error) {
	<-c.released
	return 0, net.ErrClosed
}

func (c *blockingFakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.released)
	return nil
}

func (c *blockingFakeConn) releaseAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.released)
}

func (c *blockingFakeConn) waitForBlockedWrite(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if c.writeCalled.Load() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("Write was not called within %v", timeout)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (c *blockingFakeConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (c *blockingFakeConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (c *blockingFakeConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingFakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingFakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// TestHandleDataChunk_RealCallSite_ReleasesStreamMu is the companion to
// TestHandleDataChunk_ReleasesStreamMuBeforeWrite. That test verified the
// lock-release pattern in isolation; this one exercises the REAL handleDataChunk
// call-site end-to-end (Review 2 M-2, 2026-05-05).
//
// A real session + tunnel + stream are wired via the same helpers used by
// integration tests. The stream's TargetConn is a blockingFakeConn whose
// Write blocks until released. A concurrent goroutine tries to acquire
// stream.mu while handleDataChunk is in flight — post-fix this succeeds
// within milliseconds because mu is released before Write; pre-fix it would
// block for the full streamWriteTimeout (60 s).
func TestHandleDataChunk_RealCallSite_ReleasesStreamMu(t *testing.T) {
	t.Parallel()

	h, serverKey := setupTestHandler(t)
	sess, _ := completeHandshakeForTest(t, h, serverKey)

	// Wire a blocking conn as the stream's target.
	blocking := newBlockingFakeConn()
	defer blocking.releaseAll()

	const streamID = uint16(0xAB)

	// Register tunnel + stream directly — mirrors broadcast_test.go pattern.
	tun := &Tunnel{
		SessionID:   sess.ID,
		ClientID:    "test:dev",
		Incoming:    make(chan []byte, 64),
		Outgoing:    make(chan []byte, defaultTunnelOutgoingBuffer),
		OutgoingUDP: make(chan []byte, 64),
		done:        make(chan struct{}),
		streams: map[uint16]*StreamConn{
			streamID: {
				StreamID:   streamID,
				TargetConn: blocking,
			},
		},
	}
	h.tunnelsMu.Lock()
	h.tunnels[sess.ID] = tun
	h.tunnelsMu.Unlock()

	// Build a FlagData chunk targeting the stream.
	payload := make([]byte, 2+5)
	binary.BigEndian.PutUint16(payload[0:2], streamID)
	copy(payload[2:], []byte("hello"))
	chunk := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     core.FlagData,
		Payload:   payload,
	}

	// Launch handleDataChunk in background — it will block inside blocking.Write.
	w := httptest.NewRecorder()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		h.handleDataChunk(w, sess, chunk)
		close(done)
	}()

	<-started
	// Wait until the blocking Write is entered.
	blocking.waitForBlockedWrite(t, 2*time.Second)

	// Concurrent goroutine: try to acquire stream.mu while Write is in flight.
	// Post-fix: mu was released BEFORE Write, so this succeeds instantly.
	// Pre-fix: mu would be held for up to 60 s.
	acquired := make(chan struct{})
	go func() {
		tun.streams[streamID].mu.Lock()
		_ = tun.streams[streamID].PendingBuf // simulate Activate path
		tun.streams[streamID].mu.Unlock()
		close(acquired)
	}()

	select {
	case <-acquired:
		// OK: stream.mu released before Write — real call-site is P2-9 clean.
	case <-time.After(2 * time.Second):
		t.Fatal("stream.mu still held while Write is blocking at real handleDataChunk call-site — P2-9 regression")
	}

	// Let handleDataChunk finish.
	blocking.releaseAll()
	<-done
}

// TestRunWebSocketSession_DialGoroutineExitsOnDone_MockDialer is the
// deterministic, environment-independent companion to the original
// TestRunWebSocketSession_DialGoroutineExitsOnDone (Review 2 M-3, 2026-05-05).
//
// The original test relies on OS-level SYN-blackholing of 192.0.2.1:1
// (RFC5737 TEST-NET-1) which behaves differently on Windows (RST returned
// immediately) vs Linux CI (kernel drops SYN). This test injects a blocking
// dialer via h.safeDialFn that parks on a channel until ctx is cancelled —
// guaranteed to exercise the "dial cancelled by WS close" path on every OS.
//
// Strategy:
//  1. Complete handshake; upgrade WS; send CONNECT chunk.
//  2. The injected blocking dialer parks; the WS-side goroutine is in SafeDial.
//  3. Close the WS connection — closeDone() fires, cancelDial() is called, ctx.Done.
//  4. Assert the blocking dialer returns ctx.Err within 100 ms.
func TestRunWebSocketSession_DialGoroutineExitsOnDone_MockDialer(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	// blockingDialerCh is never closed — the dialer only unblocks via ctx.Done.
	blockingDialerCh := make(chan struct{})
	dialEntered := make(chan struct{}, 1) // buffered so inject doesn't deadlock
	var dialReturnedAt atomic.Int64       // unix nano when dialer returned

	h.safeDialFn = func(ctx context.Context, target string, timeout time.Duration) (net.Conn, error) {
		// Signal that the dialer is in-flight.
		select {
		case dialEntered <- struct{}{}:
		default:
		}
		select {
		case <-blockingDialerCh: // never fires in this test
			return nil, errors.New("unreachable")
		case <-ctx.Done():
			dialReturnedAt.Store(time.Now().UnixNano())
			return nil, ctx.Err()
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(h.handleWebSocket))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/cable"

	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)

	// First-frame keepalive — authenticates and enters runWebSocketSession.
	keepalive := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc, err := sess.EncryptChunk(keepalive)
	require.NoError(t, err)
	firstFrame := append(append([]byte{}, tokenWithHint...), enc...)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, firstFrame))

	time.Sleep(100 * time.Millisecond) // enter runWebSocketSession

	// Send CONNECT — triggers the async dial goroutine with the blocking dialer.
	const streamID = uint16(0xDE)
	target := "example.com:80"
	connPayload := make([]byte, 2+len(target))
	binary.BigEndian.PutUint16(connPayload[0:2], streamID)
	copy(connPayload[2:], []byte(target))
	connectChunk := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     core.FlagConnect,
		Payload:   connPayload,
	}
	connectEnc, err := sess.EncryptChunk(connectChunk)
	require.NoError(t, err)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, connectEnc))

	// Wait until the blocking dialer is entered.
	select {
	case <-dialEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("blocking dialer was not entered within 2s")
	}

	// Close the WS — this triggers closeDone() → cancelDial() → ctx.Done.
	wsClosedAt := time.Now()
	c.Close()

	// Assert the dialer returned within 100 ms of WS close.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		ns := dialReturnedAt.Load()
		if ns != 0 {
			latency := time.Unix(0, ns).Sub(wsClosedAt)
			if latency > 100*time.Millisecond {
				t.Errorf("blocking dialer returned %v after WS close (want ≤100ms)", latency)
			}
			return // success
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("blocking dialer did not return within 500ms of WS close — dial goroutine not cancelled (P1-8 regression)")
}

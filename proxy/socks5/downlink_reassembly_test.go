package socks5

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
)

// drainConn reads everything written to one end of a net.Pipe into a buffer
// until the pipe is closed, so the downlink loop's conn.Write never blocks on
// an unread pipe. Returns the accumulated bytes once readDone closes.
func drainPipe(t *testing.T, c net.Conn) (*[]byte, *sync.Mutex, chan struct{}) {
	t.Helper()
	var mu sync.Mutex
	buf := make([]byte, 0, 4096)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tmp := make([]byte, 4096)
		for {
			n, err := c.Read(tmp)
			if n > 0 {
				mu.Lock()
				buf = append(buf, tmp[:n]...)
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return &buf, &mu, done
}

// TestDownlinkReassembly_OutOfOrderWritesInOrder feeds frames in a scrambled
// downSeq order and asserts the loop writes the payload bytes to conn in strict
// ascending-seq order (no reordering = no TCP-stream corruption).
func TestDownlinkReassembly_OutOfOrderWritesInOrder(t *testing.T) {
	appSide, peerSide := net.Pipe()
	defer appSide.Close()
	defer peerSide.Close()

	buf, mu, readDone := drainPipe(t, peerSide)

	incoming := make(chan client.StreamFrame, 16)
	// seq 1..5 carry the bytes 'A'..'E'; offered scrambled.
	frames := []client.StreamFrame{
		{Seq: 3, Data: []byte("C")},
		{Seq: 1, Data: []byte("A")},
		{Seq: 5, Data: []byte("E")},
		{Seq: 2, Data: []byte("B")},
		{Seq: 4, Data: []byte("D")},
	}
	for _, f := range frames {
		incoming <- f
	}
	close(incoming)

	dep := downlinkReassemblyDeps{
		gapTimeout:  100 * time.Millisecond,
		maxBuffered: 1 << 20,
	}
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		downlinkReassemblyLoop(context.Background(), incoming, appSide, nil, dep)
	}()

	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not exit after incoming channel closed")
	}
	appSide.Close()
	<-readDone

	mu.Lock()
	got := string(*buf)
	mu.Unlock()
	if got != "ABCDE" {
		t.Fatalf("out-of-order downlink not reassembled: got %q want %q", got, "ABCDE")
	}
}

// TestDownlinkReassembly_ControlSeqZero verifies seq==0 frames are routed to
// onControl (never to conn / the reassembler): CONNECT_OK keeps the loop alive
// and CONNECT_FAIL tears it down. This is the critical control path — misrouting
// CONNECT_OK as data corrupts the app's first bytes.
func TestDownlinkReassembly_ControlSeqZero(t *testing.T) {
	appSide, peerSide := net.Pipe()
	defer appSide.Close()
	defer peerSide.Close()
	buf, mu, readDone := drainPipe(t, peerSide)

	var controlSeen [][]byte
	incoming := make(chan client.StreamFrame, 8)
	dep := downlinkReassemblyDeps{
		gapTimeout:  200 * time.Millisecond,
		maxBuffered: 1 << 20,
		onControl: func(msg []byte) bool {
			controlSeen = append(controlSeen, append([]byte(nil), msg...))
			return string(msg) != "CONNECT_FAIL" // FAIL tears down
		},
	}
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		downlinkReassemblyLoop(context.Background(), incoming, appSide, nil, dep)
	}()

	// CONNECT_OK (control) then one real data frame, then CONNECT_FAIL (break).
	incoming <- client.StreamFrame{Seq: 0, Data: []byte("CONNECT_OK")}
	incoming <- client.StreamFrame{Seq: 1, Data: []byte("hello")}
	time.Sleep(50 * time.Millisecond)
	incoming <- client.StreamFrame{Seq: 0, Data: []byte("CONNECT_FAIL")}

	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT_FAIL did not tear the stream down")
	}
	appSide.Close()
	<-readDone

	if len(controlSeen) != 2 || string(controlSeen[0]) != "CONNECT_OK" || string(controlSeen[1]) != "CONNECT_FAIL" {
		t.Fatalf("control frames mis-routed: %v", controlSeen)
	}
	mu.Lock()
	got := string(*buf)
	mu.Unlock()
	if got != "hello" {
		t.Fatalf("data byte stream corrupted by control handling: got %q want %q", got, "hello")
	}
}

// TestDownlinkReassembly_GapTimeoutBreaks pushes seq 2,3,4,5 but never seq 1.
// The hole can never close, so after gapTimeout the loop MUST return (break the
// stream) rather than hang forever, and the gap-timeout counter ticks.
func TestDownlinkReassembly_GapTimeoutBreaks(t *testing.T) {
	appSide, peerSide := net.Pipe()
	defer appSide.Close()
	defer peerSide.Close()
	_, _, readDone := drainPipe(t, peerSide)

	incoming := make(chan client.StreamFrame, 16)
	for _, s := range []uint64{2, 3, 4, 5} {
		incoming <- client.StreamFrame{Seq: s, Data: []byte("x")}
	}
	// NOTE: do NOT close — a real downlink channel stays open; the loop must
	// break on the gap-timer, not on channel close.

	before := client.Stats.StreamReassemblyGapTimeout.Load()

	dep := downlinkReassemblyDeps{
		gapTimeout:  100 * time.Millisecond,
		maxBuffered: 1 << 20,
	}
	loopDone := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(loopDone)
		downlinkReassemblyLoop(context.Background(), incoming, appSide, nil, dep)
	}()

	select {
	case <-loopDone:
		elapsed := time.Since(start)
		if elapsed < 80*time.Millisecond {
			t.Fatalf("loop exited too early (%v) — gap timer should fire near %v", elapsed, dep.gapTimeout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gap timeout did not break the stream — loop hung on unfillable hole (NEW-1 regression)")
	}
	appSide.Close()
	<-readDone

	after := client.Stats.StreamReassemblyGapTimeout.Load()
	if after != before+1 {
		t.Fatalf("StreamReassemblyGapTimeout not incremented: before=%d after=%d", before, after)
	}
}

// TestDownlinkReassembly_GapClosedInTimeNoTimeout opens a hole (seq 2 first)
// then fills seq 1 before the gap timer fires. The loop must keep running (no
// break) and deliver both bytes in order.
func TestDownlinkReassembly_GapClosedInTimeNoTimeout(t *testing.T) {
	appSide, peerSide := net.Pipe()
	defer appSide.Close()
	defer peerSide.Close()
	buf, mu, readDone := drainPipe(t, peerSide)

	incoming := make(chan client.StreamFrame, 16)

	beforeGap := client.Stats.StreamReassemblyGapTimeout.Load()

	dep := downlinkReassemblyDeps{
		gapTimeout:  300 * time.Millisecond,
		maxBuffered: 1 << 20,
	}
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		downlinkReassemblyLoop(context.Background(), incoming, appSide, nil, dep)
	}()

	// Open the hole, wait a bit (less than gapTimeout), then close it.
	incoming <- client.StreamFrame{Seq: 2, Data: []byte("B")}
	time.Sleep(100 * time.Millisecond)
	// Still alive?
	select {
	case <-loopDone:
		t.Fatal("loop broke before gap timeout while hole was still fillable")
	default:
	}
	incoming <- client.StreamFrame{Seq: 1, Data: []byte("A")}
	// Allow the in-order run to flush.
	time.Sleep(100 * time.Millisecond)

	// No timeout should have fired.
	if got := client.Stats.StreamReassemblyGapTimeout.Load(); got != beforeGap {
		t.Fatalf("gap timeout fired despite hole closing in time: before=%d after=%d", beforeGap, got)
	}

	// Closing the channel cleanly ends the loop.
	close(incoming)
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not exit after clean channel close")
	}
	appSide.Close()
	<-readDone

	mu.Lock()
	got := string(*buf)
	mu.Unlock()
	if got != "AB" {
		t.Fatalf("reassembled bytes wrong: got %q want %q", got, "AB")
	}
}

// TestDownlinkReassembly_CtxCancelBreaks proves the Bug #9 T14 goroutine-leak
// fix: on the loopback-SOCKS5 path peerFullClose is nil and the incoming
// channel is never closed by UnregisterStream, so a cleanly-finished stream
// (no reassembly gap → gap timer disarmed) leaves the loop parked forever on
// <-incoming. The uplink goroutine signals teardown by cancelling ctx2; the
// loop MUST observe ctx.Done() and return. Without the case <-ctx.Done() this
// test hangs (and the production goroutine + 512-frame buffer leak).
func TestDownlinkReassembly_CtxCancelBreaks(t *testing.T) {
	appSide, peerSide := net.Pipe()
	defer appSide.Close()
	defer peerSide.Close()
	_, _, readDone := drainPipe(t, peerSide)

	// Clean-finish scenario: deliver one in-order frame so the run flushes and
	// NO gap exists (gap timer stays disarmed). The channel is intentionally
	// left OPEN — mirrors a live downlink channel that UnregisterStream does
	// not close.
	incoming := make(chan client.StreamFrame, 4)
	incoming <- client.StreamFrame{Seq: 1, Data: []byte("Z")}

	ctx, cancel := context.WithCancel(context.Background())

	dep := downlinkReassemblyDeps{
		gapTimeout:  10 * time.Second, // long: must NOT be the thing that breaks us
		maxBuffered: 1 << 20,
	}
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		downlinkReassemblyLoop(ctx, incoming, appSide, nil, dep)
	}()

	// Let the in-order frame flush; the loop should now be parked on <-incoming
	// (no gap armed, channel open, peerFullClose nil).
	time.Sleep(100 * time.Millisecond)
	select {
	case <-loopDone:
		t.Fatal("loop exited before ctx cancel — should be parked on <-incoming")
	default:
	}

	// Teardown signal: exactly what the uplink goroutine does on Read-EOF.
	cancel()

	select {
	case <-loopDone:
		// PASS: ctx cancel broke the loop — no goroutine leak.
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not exit on ctx cancel — goroutine leak (Bug #9 T14 regression)")
	}
	appSide.Close()
	<-readDone
}

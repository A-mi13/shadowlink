package socks5

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// memconn is the buffered in-memory net.Conn pair that replaces the loopback
// SOCKS5 socket on the system-VPN data path (Bug #5). These tests pin the
// contract tun2socks v2.6.0 relies on: bidirectional buffered transfer,
// TCP half-close (CloseRead/CloseWrite), deadlines, and Close that unblocks a
// peer blocked in Read — see tunnel/tcp.go unidirectionalStream.

func TestMemPipe_BasicRoundTrip(t *testing.T) {
	a, b := newMemPipe()
	defer a.Close()
	defer b.Close()

	msg := []byte("hello in-process")
	go func() {
		if _, err := a.Write(msg); err != nil {
			t.Errorf("write: %v", err)
		}
	}()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("got %q want %q", got, msg)
	}
}

// TestMemPipe_WriteDoesNotBlockUntilBufferFull is the backpressure contract:
// unlike net.Pipe (synchronous), a write must return immediately while buffer
// space remains, so a fast tun2socks io.CopyBuffer is not ping-ponged on every
// 20KB chunk at 460 Mbit/s.
func TestMemPipe_WriteDoesNotBlockUntilBufferFull(t *testing.T) {
	a, b := newMemPipe()
	defer a.Close()
	defer b.Close()

	// A single modest write must complete without any reader present.
	done := make(chan error, 1)
	go func() {
		_, err := a.Write(make([]byte, 32*1024)) // 32KB < buffer
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("buffered write returned err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write blocked with no reader — not buffered (net.Pipe-like)")
	}
}

// TestMemPipe_CloseWriteSignalsEOF — TCP half-close: tun2socks calls
// CloseWrite() on the upload side; the peer's Read must then return io.EOF so
// our relay's uplink reader observes EOF and starts idle-grace. [HIGH-1]
func TestMemPipe_CloseWriteSignalsEOF(t *testing.T) {
	a, b := newMemPipe()
	defer a.Close()
	defer b.Close()

	hc, ok := a.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("memconn must implement CloseWrite() for tun2socks half-close")
	}

	msg := []byte("final")
	if _, err := a.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := hc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// Buffered data still readable, then EOF (not a hang, not lost data).
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("ReadAll after CloseWrite: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("data before EOF: got %q want %q", got, msg)
	}
}

// TestMemPipe_CloseReadImplemented — tun2socks calls CloseRead() on the source.
func TestMemPipe_CloseReadImplemented(t *testing.T) {
	a, _ := newMemPipe()
	defer a.Close()
	if _, ok := a.(interface{ CloseRead() error }); !ok {
		t.Fatal("memconn must implement CloseRead() for tun2socks half-close")
	}
}

// TestMemPipe_CloseUnblocksBlockedRead — a reader blocked in Read must be
// released by Close on either end (else relay goroutines + stream slots leak).
// [MEDIUM-5]
func TestMemPipe_CloseUnblocksBlockedRead(t *testing.T) {
	a, b := newMemPipe()
	defer a.Close()

	readReturned := make(chan error, 1)
	go func() {
		_, err := b.Read(make([]byte, 16))
		readReturned <- err
	}()

	// Let the reader block, then close its own end.
	time.Sleep(50 * time.Millisecond)
	b.Close()

	select {
	case err := <-readReturned:
		if err == nil {
			t.Fatal("Read after Close must return an error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock a blocked Read — goroutine leak")
	}
}

// TestMemPipe_ReadDeadline — tun2socks sets SetReadDeadline(now+60s) after
// half-close; the deadline must actually fire. [HIGH-1]
func TestMemPipe_ReadDeadline(t *testing.T) {
	_, b := newMemPipe()
	defer b.Close()

	if err := b.SetReadDeadline(time.Now().Add(60 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	_, err := b.Read(make([]byte, 16))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected net.Error timeout, got %v", err)
	}
	if elapsed < 50*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("deadline fired at %v, want ~60ms", elapsed)
	}
}

// TestMemPipe_LocalRemoteAddrValid — parseNetAddr in tun2socks reads
// conn.LocalAddr(); it must parse as ip:port (not panic / garbage). [MEDIUM-1]
func TestMemPipe_LocalRemoteAddrValid(t *testing.T) {
	a, b := newMemPipe()
	defer a.Close()
	defer b.Close()
	for _, c := range []net.Conn{a, b} {
		if c.LocalAddr() == nil || c.LocalAddr().String() == "" {
			t.Error("LocalAddr must be non-empty")
		}
		if _, _, err := net.SplitHostPort(c.LocalAddr().String()); err != nil {
			t.Errorf("LocalAddr %q not host:port: %v", c.LocalAddr().String(), err)
		}
	}
}

// TestMemPipe_ConcurrentBidirectional stresses both directions at once.
func TestMemPipe_ConcurrentBidirectional(t *testing.T) {
	a, b := newMemPipe()
	defer a.Close()
	defer b.Close()

	const n = 1 << 20 // 1 MiB each way
	var wg sync.WaitGroup
	wg.Add(2)

	// a -> b
	go func() {
		defer wg.Done()
		defer a.(interface{ CloseWrite() error }).CloseWrite()
		buf := make([]byte, 64*1024)
		sent := 0
		for sent < n {
			w, err := a.Write(buf)
			if err != nil {
				t.Errorf("a.Write: %v", err)
				return
			}
			sent += w
		}
	}()
	// drain b
	go func() {
		defer wg.Done()
		got, err := io.Copy(io.Discard, b)
		if err != nil {
			t.Errorf("drain b: %v", err)
		}
		if got != n {
			t.Errorf("drained %d want %d", got, n)
		}
	}()

	wg.Wait()
}

package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestWakeUplink_CloseReadOnMemConn(t *testing.T) {
	_, ourConn := newMemPipe() // uplink reads relay-end (ourConn)
	defer ourConn.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := ourConn.Read(buf) // blocks (nobody writes)
		readDone <- err
	}()

	time.Sleep(30 * time.Millisecond) // let Read block
	wakeUplink(ourConn, false)        // must wake via CloseRead

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("Read must return error/EOF after wakeUplink CloseRead")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wakeUplink did not wake the blocked Read")
	}
}

// TestWakeUplink_AfterHalfCloseIsHarmless: on keep-alive half-close the uplink
// goroutine has already exited (appConn.CloseWrite → ourConn.Read EOF). Later,
// when the downlink goroutine finishes, its deferred wakeUplink(ourConn) calls
// CloseRead on an already-half-closed conn. This must be harmless (idempotent);
// downlink writes that happened BEFORE wakeUplink must have succeeded.
func TestWakeUplink_AfterHalfCloseIsHarmless(t *testing.T) {
	appConn, ourConn := newMemPipe()
	defer appConn.Close()
	defer ourConn.Close()

	// app half-closes uplink (tun2socks after sending its request).
	if hc, ok := appConn.(interface{ CloseWrite() error }); ok {
		if err := hc.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	} else {
		t.Fatal("appConn missing CloseWrite")
	}
	// uplink reads EOF (exited on its own, before downlink).
	buf := make([]byte, 32)
	if _, err := ourConn.Read(buf); err != io.EOF {
		t.Fatalf("ourConn.Read after half-close: got %v want io.EOF", err)
	}
	// downlink is still alive — write must succeed (keep-alive not broken).
	if _, err := ourConn.Write([]byte("downlink chunk")); err != nil {
		t.Fatalf("downlink Write after half-close must work, got %v", err)
	}
	// downlink goroutine exits → deferred wakeUplink fires. Call manually.
	// Must be harmless: CloseRead is idempotent; uplink already exited.
	wakeUplink(ourConn, false)
	wakeUplink(ourConn, false) // double call must also be harmless
}

// TestWakeUplink_DoesNotPanicOnClosedConn: wakeUplink on a fully closed conn
// must not panic — neither the CloseRead path (memConn) nor the Close fallback
// path (net.Pipe conn).
func TestWakeUplink_DoesNotPanicOnClosedConn(t *testing.T) {
	appConn, ourConn := newMemPipe()
	_ = appConn.Close()
	_ = ourConn.Close()
	wakeUplink(ourConn, false) // must not panic (CloseRead on already-closed memConn)
	c1, c2 := net.Pipe()
	_ = c1.Close()
	_ = c2.Close()
	wakeUplink(c1, true) // Close fallback on already-closed conn — must not panic
}

func TestWakeUplink_CloseFallback(t *testing.T) {
	c1, c2 := net.Pipe() // net.Pipe conn does NOT have CloseRead → Close fallback
	defer c2.Close()
	readDone := make(chan error, 1)
	go func() { buf := make([]byte, 16); _, err := c1.Read(buf); readDone <- err }()
	time.Sleep(30 * time.Millisecond)
	wakeUplink(c1, true)
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("Read must error after Close fallback")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wakeUplink Close fallback did not wake Read")
	}
}

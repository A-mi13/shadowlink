package socks5

import (
	"io"
	"testing"
)

// TestMemConn_HalfCloseKeepsDownlinkAlive reproduces the Bug #8 field symptom:
// after tun2socks does appConn.CloseWrite() (TCP half-close — the app finished
// sending its HTTP request), the relay MUST still be able to write the download
// response into the downlink direction. The field log shows the opposite: an
// active 13.7 MB download (connectConfirmed=true, fullClose=false) gets
// "io: read/write on closed pipe" on the relay's downlink conn.Write right
// after the uplink goroutine saw EOF (half-close).
//
// memConn pairing (newMemPipe):
//   appConn (a): rd=d2, wr=d1   — handed to tun2socks
//   ourConn (b): rd=d1, wr=d2   — the relay (tunnelTCPStream conn)
// Uplink   = app→server = d1 (appConn.Write / ourConn.Read)
// Downlink = server→app = d2 (ourConn.Write / appConn.Read)
func TestMemConn_HalfCloseKeepsDownlinkAlive(t *testing.T) {
	appConn, ourConn := newMemPipe()

	// tun2socks half-close after the app sent its request: it calls
	// appConn.CloseWrite() on the uplink direction.
	if hc, ok := appConn.(interface{ CloseWrite() error }); ok {
		if err := hc.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	} else {
		t.Fatal("appConn missing CloseWrite")
	}

	// The relay's uplink goroutine reads ourConn until EOF (uplink direction d1
	// now closed) — this is the expected half-close signal.
	buf := make([]byte, 64)
	if _, err := ourConn.Read(buf); err != io.EOF {
		t.Fatalf("ourConn.Read after appConn.CloseWrite: got %v, want io.EOF", err)
	}

	// CRITICAL: the relay must STILL be able to write downlink (server→app).
	// This is what tunnelTCPStream's downlink goroutine does on every chunk.
	if _, err := ourConn.Write([]byte("downlink response chunk")); err != nil {
		t.Fatalf("downlink ourConn.Write after half-close FAILED: %v "+
			"(this is the Bug #8 'closed pipe' — half-close killed downlink)", err)
	}

	// And the app must be able to read it.
	n, err := appConn.Read(buf)
	if err != nil {
		t.Fatalf("appConn.Read downlink after half-close: %v", err)
	}
	if string(buf[:n]) != "downlink response chunk" {
		t.Fatalf("downlink payload mismatch: %q", buf[:n])
	}
}

// TestMemConn_CloseReadKillsDownlink documents what happens if tun2socks calls
// appConn.CloseRead() (which it does on the downlink goroutine's exit):
// appConn.rd = d2 = the downlink direction. Closing it makes the relay's
// ourConn.Write(d2) return ErrClosedPipe. This test pins that behavior so the
// fix (and its rationale) is explicit.
func TestMemConn_CloseReadKillsDownlink(t *testing.T) {
	appConn, ourConn := newMemPipe()

	if hc, ok := appConn.(interface{ CloseRead() error }); ok {
		if err := hc.CloseRead(); err != nil {
			t.Fatalf("CloseRead: %v", err)
		}
	} else {
		t.Fatal("appConn missing CloseRead")
	}

	// After appConn.CloseRead(), the relay writing downlink hits a closed pipe.
	_, err := ourConn.Write([]byte("downlink"))
	if err == nil {
		t.Fatal("expected downlink write to fail after appConn.CloseRead (d2 closed)")
	}
	t.Logf("downlink write after appConn.CloseRead → %v (expected: closed pipe)", err)
}

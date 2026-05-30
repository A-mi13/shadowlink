package socks5

import (
	"testing"
)

// TestHalfClose_DownlinkCreditPathSurvives documents the Bug #8 invariant
// (spec §8): after the app does CloseWrite (TCP half-close — it finished
// sending its request), the relay's downlink side stays alive. That downlink
// side is exactly where tunnelTCPStream calls cl.OnStreamConsumed after a
// successful conn.Write — so the flow-control credit path keeps working through
// a half-close (HTTP keep-alive download continuing after the request was sent).
//
// memConn semantics: appConn.CloseWrite() closes only the uplink direction d1;
// ourConn.Write (downlink d2) still succeeds, and appConn.Read receives it.
func TestHalfClose_DownlinkCreditPathSurvives(t *testing.T) {
	appConn, ourConn := newMemPipe()

	if hc, ok := appConn.(interface{ CloseWrite() error }); ok {
		if err := hc.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	} else {
		t.Fatal("appConn missing CloseWrite")
	}

	// Downlink write must still succeed — this is where tunnelTCPStream's
	// downlink goroutine writes the response and then credits OnStreamConsumed.
	const payload = "response after half-close"
	if _, err := ourConn.Write([]byte(payload)); err != nil {
		t.Fatalf("downlink write after half-close failed: %v "+
			"(credit path would be dead — Bug #8)", err)
	}
	buf := make([]byte, 64)
	n, err := appConn.Read(buf)
	if err != nil {
		t.Fatalf("appConn.Read after half-close: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("downlink payload mismatch: got %q want %q", buf[:n], payload)
	}
}

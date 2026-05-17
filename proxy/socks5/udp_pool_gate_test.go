package socks5

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
)

// stubStarvedTransport implements client.StreamTransport AND
// client.PoolReadiness, reporting `ready` as the pool's ready-slot count.
// HandleUDPAssociateWS only consults ReadyCount before any WS work, so the
// other StreamTransport methods never get called in these tests — they
// return errors for safety.
type stubStarvedTransport struct {
	ready int
}

func (s *stubStarvedTransport) WriteMessage(data []byte) error { return errStubUnused }
func (s *stubStarvedTransport) StartReader(ctx context.Context, cl *client.Client) error {
	return errStubUnused
}
func (s *stubStarvedTransport) Close() error { return nil }

// ReadyCount makes the stub satisfy client.PoolReadiness.
func (s *stubStarvedTransport) ReadyCount() int { return s.ready }

var errStubUnused = stubError("stub: should not be called when pool is starved")

type stubError string

func (e stubError) Error() string { return string(e) }

// connPipe wraps net.Pipe to give the SOCKS5 handler something to write the
// reply byte stream to. We capture written bytes for assertion.
type connPipe struct {
	net.Conn
	written *bytes.Buffer
}

func newConnPipe() (*connPipe, net.Conn) {
	a, b := net.Pipe()
	cp := &connPipe{Conn: a, written: &bytes.Buffer{}}
	return cp, b
}

func (c *connPipe) Write(p []byte) (int, error) {
	c.written.Write(p)
	return c.Conn.Write(p)
}

// TestUDPAssociate_FailsWhenPoolStarved: when the pool transport reports
// ReadyCount=0 (well below udpMinReadySlots=2), HandleUDPAssociateWS must
// emit a SOCKS5 0x03 (network unreachable) reply and return without opening
// any UDP socket.
func TestUDPAssociate_FailsWhenPoolStarved(t *testing.T) {
	stub := &stubStarvedTransport{ready: 0}
	cp, peer := newConnPipe()
	defer cp.Close()
	defer peer.Close()

	// Drain peer side so handler's Write doesn't block.
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// cl, router can be nil because the gate fires before they're touched.
		HandleUDPAssociateWS(context.Background(), cp, nil, stub, nil)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleUDPAssociateWS did not return on starved pool")
	}

	got := cp.written.Bytes()
	if len(got) == 0 {
		t.Fatal("no SOCKS5 reply written")
	}
	if got[0] != 0x05 {
		t.Errorf("expected SOCKS5 version 0x05, got 0x%02x", got[0])
	}
	// REP field is at index 1: [VER(0), REP(1), RSV(2), ATYP(3), ...]
	if got[1] != 0x03 {
		t.Errorf("expected REP=0x03 (network unreachable), got 0x%02x; full: %x",
			got[1], got)
	}
}

// TestUDPAssociate_FailsAtBoundary: ReadyCount == udpMinReadySlots-1 must
// still reject. Confirms the boundary is inclusive on the rejection side.
func TestUDPAssociate_FailsAtBoundary(t *testing.T) {
	stub := &stubStarvedTransport{ready: udpMinReadySlots - 1}
	cp, peer := newConnPipe()
	defer cp.Close()
	defer peer.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		HandleUDPAssociateWS(context.Background(), cp, nil, stub, nil)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleUDPAssociateWS did not return")
	}

	got := cp.written.Bytes()
	if len(got) < 2 || got[1] != 0x03 {
		t.Errorf("expected REP=0x03 at boundary, got %x", got)
	}
}

// stubAcceptedTransport: ReadyCount >= threshold; the handler will proceed
// past the gate and call WriteMessage / StartReader on the stub. We don't
// drive it past the SOCKS5 success reply — once that reply is written, the
// test stops. This proves the gate itself does not reject.
type stubAcceptedTransport struct {
	ready    int
	writeErr error
}

func (s *stubAcceptedTransport) ReadyCount() int { return s.ready }
func (s *stubAcceptedTransport) WriteMessage(data []byte) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	return nil
}
func (s *stubAcceptedTransport) StartReader(ctx context.Context, cl *client.Client) error {
	<-ctx.Done()
	return ctx.Err()
}
func (s *stubAcceptedTransport) Close() error { return nil }

// TestUDPAssociate_AcceptsWhenPoolReady: ReadyCount >= udpMinReadySlots →
// gate passes; the handler proceeds far enough to write a SOCKS5 success
// reply (REP=0x00). We then close the conn to unblock and check the reply.
//
// Note: the handler also goes on to register a stream against a nil
// *client.Client which would NPE — to avoid that, we construct a Client
// instance via reflection-free means. cl.NextStreamID needs streamMu and
// streamChans; cl.RegisterStream needs streamChans. Both are zero-value
// safe on a fresh struct.
func TestUDPAssociate_AcceptsWhenPoolReady(t *testing.T) {
	stub := &stubAcceptedTransport{ready: udpMinReadySlots}
	cp, peer := newConnPipe()
	defer cp.Close()
	defer peer.Close()

	// Drain peer; close it after a short delay so the handler's
	// blocking conn.Read on the wait-buf path returns and the handler exits.
	peerClosed := make(chan struct{})
	go func() {
		defer close(peerClosed)
		buf := make([]byte, 64)
		// Read once to consume the SOCKS5 reply, then close to unblock the
		// handler's "wait for TCP close" sentinel read.
		_, _ = peer.Read(buf)
		time.Sleep(50 * time.Millisecond)
		peer.Close()
	}()

	cl := &client.Client{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		HandleUDPAssociateWS(context.Background(), cp, cl, stub, nil)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleUDPAssociateWS did not return after peer close")
	}

	got := cp.written.Bytes()
	if len(got) < 10 {
		t.Fatalf("SOCKS5 reply truncated: %x", got)
	}
	// REP=0x00 means success (gate passed and the handler proceeded to bind).
	if got[1] != 0x00 {
		t.Errorf("expected REP=0x00 (success) when pool is ready, got 0x%02x; full: %x",
			got[1], got)
	}
}

package socks5

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
)

// Companion defects found alongside the sing-box multiplexing bug (2026-09-01).
// All three are cases where the association's lifecycle disagrees with what a
// real SOCKS5 client may legitimately do.

// TestUDPAssociateWS_SurvivesControlChannelTraffic guards the second defect:
// the handler treated ANY byte arriving on the control TCP as "the association
// is over". RFC 1928 ends the association when the control connection CLOSES,
// not when it carries a byte. The old code was `conn.Read(waitBuf)` with the
// return values discarded, so a client that sends a keepalive byte down the
// control channel — a documented pattern for keeping NAT state alive — tore
// down its own relay instantly.
func TestUDPAssociateWS_SurvivesControlChannelTraffic(t *testing.T) {
	stub := newMultiportStub(0x99999999)

	key := make([]byte, 32)
	cl := client.NewTestClientWithSession(core.NewSession(0xAAAAAAAA, key, key))

	stub.onUplink = func(streamID uint16, frame []byte) {
		tokenLen := len(cl.Token())
		if len(frame) <= tokenLen {
			return
		}
		chunk, err := stub.slotSession.DecryptChunkSafe(frame[tokenLen:])
		if err != nil {
			return
		}
		_, addr, data, err := core.ParseUDPChunk(chunk.Payload)
		if err != nil {
			return
		}
		cl.RouteToStream(streamID, core.BuildUDPChunkPayload(streamID, addr, data))
	}

	cp, peer := newConnPipe()
	defer cp.Close()
	defer peer.Close()

	replyCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 32)
		n, err := peer.Read(buf)
		if err != nil {
			replyCh <- nil
			return
		}
		replyCh <- buf[:n]
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		HandleUDPAssociateWS(context.Background(), cp, cl, stub, nil)
	}()

	var reply []byte
	select {
	case reply = <-replyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("no SOCKS5 reply")
	}
	if len(reply) < 10 || reply[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE refused: %x", reply)
	}
	port := int(binary.BigEndian.Uint16(reply[8:10]))

	// The client sends a keepalive byte on the control channel — legal, and
	// fatal under the old code.
	if _, err := peer.Write([]byte{0x00}); err != nil {
		t.Fatalf("write keepalive: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("association torn down by a byte on the control TCP — RFC 1928 " +
			"ends it on CLOSE, not on traffic. A client sending keepalives kills " +
			"its own relay")
	default:
	}

	// And the relay must still work afterwards, not merely be un-torn-down.
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sock.Close()

	relayAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	if _, err := sock.WriteToUDP(udpRequest("after-keepalive"), relayAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readEcho(t, sock); got != "after-keepalive" {
		t.Errorf("relay dead after control-channel keepalive: got %q", got)
	}

	// Closing the control TCP must still end the association.
	peer.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("association did not end when the control TCP closed — the " +
			"teardown signal must still be CLOSE")
	}
}

// noSessionStub accepts the readiness gate but never yields a session, standing
// in for a pool that lost every ready slot between the gate and the assignment.
type noSessionStub struct{ multiportStub }

func (s *noSessionStub) SessionForStream(streamID uint16) *core.Session { return nil }

// TestUDPAssociateWS_NoSuccessReplyWithoutSession guards the third defect: the
// success reply (REP=0x00) was written before the session was resolved, so a
// client could be told its association was up while the relay was already dead.
// It then waited out its own timeout instead of failing over — which inflates
// exactly the kind of failure rate the field team measured.
func TestUDPAssociateWS_NoSuccessReplyWithoutSession(t *testing.T) {
	stub := &noSessionStub{multiportStub: *newMultiportStub(0xBBBBBBBB)}

	key := make([]byte, 32)
	cl := client.NewTestClientWithSession(core.NewSession(0xCCCCCCCC, key, key))

	cp, peer := newConnPipe()
	defer cp.Close()
	defer peer.Close()

	replyCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 32)
		n, err := peer.Read(buf)
		if err != nil {
			replyCh <- nil
			return
		}
		replyCh <- buf[:n]
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		HandleUDPAssociateWS(context.Background(), cp, cl, stub, nil)
	}()

	var reply []byte
	select {
	case reply = <-replyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler neither replied nor returned")
	}

	if len(reply) < 2 {
		t.Fatalf("truncated reply: %x", reply)
	}
	if reply[1] == 0x00 {
		t.Error("handler replied SUCCESS while no session could be resolved — " +
			"the client believes the association is up and blocks until its own " +
			"timeout instead of failing over")
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("handler did not return after failing to resolve a session")
	}
}

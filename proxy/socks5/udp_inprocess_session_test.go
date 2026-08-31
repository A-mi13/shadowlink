package socks5

import (
	"context"
	"net/netip"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
)

// The tun2socks UDP path (inProcessDialer.DialUDP) carried the same defect as
// HandleUDPAssociateWS: it sealed frames with cl.Session() — the global
// handshake session — while the server decrypts a pooled WS with that slot's
// own session and silently drops anything else (server/websocket.go:917-919).
//
// This is the path the desktop TUN mode uses, so it needs its own guard: the
// SOCKS5 guard in udp_pool_session_test.go does not cover it.

// TestDialUDP_SealsWithSlotSessionNotGlobal drives DialUDP and inspects the
// frame the returned PacketConn puts on the transport.
func TestDialUDP_SealsWithSlotSessionNotGlobal(t *testing.T) {
	stub := newPoolSessionStub(0x55555555)

	globalKey := make([]byte, 32)
	for i := range globalKey {
		globalKey[i] = 0xCD
	}
	globalSession := core.NewSession(0x66666666, globalKey, globalKey)
	cl := client.NewTestClientWithSession(globalSession)

	srv := &Server{Client: cl}
	srv.SetWST(stub)

	d := &inProcessDialer{engineCtx: context.Background(), srv: srv}

	pc, err := d.DialUDP(&M.Metadata{
		Network: M.UDP,
		DstIP:   netip.MustParseAddr("8.8.8.8"),
		DstPort: 53,
	})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer pc.Close()

	if _, err := pc.WriteTo([]byte("query"), udpAddr("8.8.8.8", 53)); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	frame, viaStreamPath := stub.sentFrame()
	if frame == nil {
		t.Fatal("no frame reached the transport")
	}

	// cl has no token here, so the frame is the bare encrypted chunk.
	tokenLen := len(cl.Token())

	if frameDecryptsWith(t, globalSession, frame, tokenLen) {
		t.Error("DialUDP sealed with the GLOBAL session — the server would drop " +
			"this frame silently (server/websocket.go:917-919)")
	}
	if !frameDecryptsWith(t, stub.slotSession, frame, tokenLen) {
		t.Error("frame does not decrypt with the slot session — DialUDP must use " +
			"client.StreamSession(wst, cl, streamID)")
	}
	if !viaStreamPath {
		t.Error("frame went out via WriteMessage; a stream-bound datagram must " +
			"use StreamWrite to land on the slot owning its session")
	}
	if !stub.wasEverAssigned() {
		t.Error("DialUDP never called AssignStream — SessionForStream is keyed on " +
			"the pool's streamMap and would return nil")
	}
}

// TestDialUDP_ReleasesStreamOnClose: the binding must not outlive the flow, or
// the slot's stream counter stays inflated and blocks its rotation. DNS bursts
// make this a leak of many short-lived 5-tuples.
func TestDialUDP_ReleasesStreamOnClose(t *testing.T) {
	stub := newPoolSessionStub(0x77777777)

	key := make([]byte, 32)
	cl := client.NewTestClientWithSession(core.NewSession(0x88888888, key, key))

	srv := &Server{Client: cl}
	srv.SetWST(stub)

	d := &inProcessDialer{engineCtx: context.Background(), srv: srv}

	pc, err := d.DialUDP(&M.Metadata{
		Network: M.UDP,
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 53,
	})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	if !stub.wasEverAssigned() {
		t.Fatal("stream was never assigned — nothing to release")
	}

	if err := pc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if stub.stillAssigned() {
		t.Error("stream still assigned after Close — the slot's stream counter " +
			"stays inflated and its rotation is blocked")
	}
}

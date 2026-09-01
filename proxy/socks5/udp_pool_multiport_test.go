package socks5

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
)

// Field report 2026-09-01 (NixaVPN client team, iOS/macOS): DNS over the tunnel
// resolved 8/8 when driven by a hand-run client, but only 33% (242 ok / 485
// fail) when driven by sing-box. They attributed it to sing-box's ASSOCIATE
// handling and asked us to look at their side. It is ours.
//
// A SOCKS5 UDP ASSOCIATE is one control TCP connection plus one relay socket,
// and a client is free to multiplex several UDP flows over it from DIFFERENT
// source ports — sing-box does exactly that, one source port per query in
// flight. The relay pinned the first datagram's full address (IP *and* port)
// and sent every response back to it, while accepting uplink from any port of
// the same IP. Replies for every flow after the first went to the wrong port
// and vanished.
//
// A single-socket client (dig, curl, a hand-rolled probe) uses one source port
// for everything, so it can never observe this: the pin and the real address
// coincide. That is why the manual check passed 8/8 and is structurally unable
// to catch the defect — the test below drives two ports on purpose.

// multiportStub is a StreamTransport that echoes each uplink datagram back into
// the client's stream channel, so the association's receive path runs for real.
// It keeps the crypto honest by sealing with the same slot session the handler
// resolves, mirroring what the server does on the way back.
type multiportStub struct {
	mu sync.Mutex

	slotSession *core.Session
	assigned    map[uint16]bool

	// downlink is handed the frames to feed back; set by the test.
	onUplink func(streamID uint16, frame []byte)
}

func newMultiportStub(slotSessionID uint32) *multiportStub {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x5A
	}
	return &multiportStub{
		slotSession: core.NewSession(slotSessionID, key, key),
		assigned:    make(map[uint16]bool),
	}
}

func (s *multiportStub) ReadyCount() int { return udpMinReadySlots }

func (s *multiportStub) WriteMessage(data []byte) error { return nil }

func (s *multiportStub) WriteMessageForStream(streamID uint16, data []byte) error {
	s.mu.Lock()
	cb := s.onUplink
	s.mu.Unlock()
	if cb != nil {
		cb(streamID, append([]byte(nil), data...))
	}
	return nil
}

func (s *multiportStub) AssignStream(streamID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assigned[streamID] = true
}

func (s *multiportStub) ReleaseStream(streamID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.assigned, streamID)
}

func (s *multiportStub) SessionForStream(streamID uint16) *core.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.assigned[streamID] {
		return nil
	}
	return s.slotSession
}

func (s *multiportStub) StartReader(ctx context.Context, cl *client.Client) error {
	<-ctx.Done()
	return ctx.Err()
}

func (s *multiportStub) Close() error { return nil }

// startAssociation runs HandleUDPAssociateWS and returns the relay port plus a
// teardown func. It leaves the control TCP open so the caller can drive several
// datagrams through the live association.
func startAssociation(t *testing.T, cl *client.Client, wst client.StreamTransport) (relayPort int, stop func()) {
	t.Helper()

	cp, peer := newConnPipe()

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
		HandleUDPAssociateWS(context.Background(), cp, cl, wst, nil)
	}()

	var reply []byte
	select {
	case reply = <-replyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("no SOCKS5 reply from HandleUDPAssociateWS")
	}
	if len(reply) < 10 || reply[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE refused: %x", reply)
	}

	return int(binary.BigEndian.Uint16(reply[8:10])), func() {
		peer.Close()
		cp.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("HandleUDPAssociateWS did not return after control TCP close")
		}
	}
}

// udpRequest builds a SOCKS5 UDP datagram for 1.1.1.1:53 carrying payload.
func udpRequest(payload string) []byte {
	d := []byte{0, 0, 0, 0x01, 1, 1, 1, 1, 0x00, 0x35}
	return append(d, payload...)
}

// TestUDPAssociateWS_RepliesToSenderPortNotFirstPort is the regression guard for
// the sing-box 33% defect. Two sockets share one association; each must get its
// own reply back. Before the fix socket B received nothing: the relay had pinned
// socket A's port at the first datagram and never updated it.
func TestUDPAssociateWS_RepliesToSenderPortNotFirstPort(t *testing.T) {
	stub := newMultiportStub(0x77777777)

	key := make([]byte, 32)
	cl := client.NewTestClientWithSession(core.NewSession(0x88888888, key, key))

	// Echo every uplink datagram back down the stream, exactly as the server
	// would relay a DNS answer.
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
		// Feed the response back through the client's stream router, which is
		// what WSPoolTransport does for an inbound UDP frame.
		cl.RouteToStream(streamID, core.BuildUDPChunkPayload(streamID, addr, data))
	}

	port, stop := startAssociation(t, cl, stub)
	defer stop()

	relayAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}

	sockA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer sockA.Close()

	sockB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer sockB.Close()

	// Socket A goes first and becomes the pinned address under the old code.
	if _, err := sockA.WriteToUDP(udpRequest("query-A"), relayAddr); err != nil {
		t.Fatalf("write A: %v", err)
	}
	if got := readEcho(t, sockA); got != "query-A" {
		t.Fatalf("socket A got %q, want its own reply", got)
	}

	// Socket B is the one the old code stranded: its uplink was accepted (same
	// IP, any port) but its reply went to A's port.
	if _, err := sockB.WriteToUDP(udpRequest("query-B"), relayAddr); err != nil {
		t.Fatalf("write B: %v", err)
	}
	got := readEcho(t, sockB)
	if got == "" {
		t.Fatal("socket B received NO reply — the relay answered the first " +
			"datagram's port instead of the sender's. This is the sing-box 33% " +
			"defect: a multiplexing client loses every flow after the first, " +
			"while a single-socket probe (dig/curl) cannot observe it at all")
	}
	if got != "query-B" {
		t.Fatalf("socket B got %q, want %q", got, "query-B")
	}

	// A must still work afterwards: the fix must track the sender per datagram,
	// not simply move the pin to whoever spoke last and strand A instead.
	if _, err := sockA.WriteToUDP(udpRequest("query-A2"), relayAddr); err != nil {
		t.Fatalf("write A2: %v", err)
	}
	if got := readEcho(t, sockA); got != "query-A2" {
		t.Fatalf("socket A got %q after B spoke, want %q — replies must follow "+
			"the sender, not a single moving pin", got, "query-A2")
	}
}

// readEcho reads one SOCKS5 UDP response and returns its payload, or "" on
// timeout.
func readEcho(t *testing.T, sock *net.UDPConn) string {
	t.Helper()
	sock.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := sock.ReadFromUDP(buf)
	if err != nil {
		return ""
	}
	// [RSV(2) FRAG(1) ATYP(1) ADDR PORT(2)] + data
	_, off, ok := ParseSOCKS5UDPHeader(buf, n)
	if !ok {
		t.Fatalf("malformed SOCKS5 UDP response: %x", buf[:n])
	}
	return string(buf[off:n])
}

// TestUDPAssociateWS_RejectsForeignIP keeps the other half of the invariant: the
// fix must widen the reply target per sender, NOT drop the same-IP restriction
// that stops a foreign localhost process from stealing someone else's stream.
// Only loopback is reachable here, so this asserts the predicate directly.
func TestUDPAssociateWS_RejectsForeignIP(t *testing.T) {
	var senders udpSenderSet

	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	sameIPOtherPort := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}
	foreignIP := &net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 40000}

	if !senders.accept(first, "1.1.1.1:53") {
		t.Fatal("first datagram must be accepted and pin the IP")
	}
	if !senders.accept(sameIPOtherPort, "8.8.8.8:53") {
		t.Error("same IP, different port must be accepted — that is exactly the " +
			"multiplexing client we are fixing for")
	}
	if senders.accept(foreignIP, "1.1.1.1:53") {
		t.Error("a different source IP must still be rejected: a foreign local " +
			"process must not be able to smuggle traffic through another " +
			"client's association (H4, 2026-06-11)")
	}
}

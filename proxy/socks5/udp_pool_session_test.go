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

// UDP over the WS pool must encrypt with the session of the slot the stream is
// assigned to — never with cl.Session(), the global handshake session that no
// pooled WS connection is authenticated against.
//
// Field report 2026-08-31 (NixaVPN client team, iOS/macOS): UDP ASSOCIATE hung
// until the tunnel dropped — zero DNS resolutions over UDP — while TCP through
// the same pool worked. Root cause: udp.go took cl.Session(). The server binds
// one session per WS connection at upgrade (server/websocket.go:159 resolves the
// hint ONCE) and every later frame is decrypted with that slot's session only,
// so a frame sealed with the global session fails AES-GCM and is dropped by
// `continue` (server/websocket.go:917-919) — no log line, no metric.
//
// The mobile facade hardwires WSPool: true (mobile/config.go:196), so this path
// is the only one it ever takes.
//
// These tests assert on the SessionID carried in the frame rather than on which
// transport method was called: the defect is "wrong crypto session", and a test
// that checks the method name would still pass if a future refactor picked the
// wrong session through the right method.

// poolSessionStub implements client.StreamTransport, client.PoolReadiness and
// client.PoolAware with one distinct session per assigned stream, mirroring the
// real pool where each slot completes its own handshake.
type poolSessionStub struct {
	mu sync.Mutex

	slotSession *core.Session // the "slot" session, as SessionForStream reports it
	assigned    map[uint16]bool
	// everAssigned survives ReleaseStream. Asserting on `assigned` after the
	// handler returns would always fail: the handler releases the stream on the
	// way out, so the live map measures teardown, not binding.
	everAssigned map[uint16]bool

	// frames captured per entry point so a test can tell which path was used.
	viaStream []byte // WriteMessageForStream
	viaBroad  []byte // WriteMessage (the buggy path)
}

func newPoolSessionStub(slotSessionID uint32) *poolSessionStub {
	return &poolSessionStub{
		slotSession:  core.NewSession(slotSessionID, make([]byte, 32), make([]byte, 32)),
		assigned:     make(map[uint16]bool),
		everAssigned: make(map[uint16]bool),
	}
}

func (s *poolSessionStub) ReadyCount() int { return udpMinReadySlots }

func (s *poolSessionStub) WriteMessage(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.viaBroad == nil {
		s.viaBroad = append([]byte(nil), data...)
	}
	return nil
}

func (s *poolSessionStub) WriteMessageForStream(streamID uint16, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.viaStream == nil {
		s.viaStream = append([]byte(nil), data...)
	}
	return nil
}

func (s *poolSessionStub) AssignStream(streamID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assigned[streamID] = true
	s.everAssigned[streamID] = true
}

func (s *poolSessionStub) ReleaseStream(streamID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.assigned, streamID)
}

// SessionForStream mirrors WSPoolTransport: nil until the stream is assigned to
// a slot (ws_pool.go:4367 looks the stream up in streamMap first). This is why
// AssignStream must run BEFORE the session is resolved.
func (s *poolSessionStub) SessionForStream(streamID uint16) *core.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.assigned[streamID] {
		return nil
	}
	return s.slotSession
}

func (s *poolSessionStub) StartReader(ctx context.Context, cl *client.Client) error {
	<-ctx.Done()
	return ctx.Err()
}

func (s *poolSessionStub) Close() error { return nil }

func (s *poolSessionStub) sentFrame() (frame []byte, viaStreamPath bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.viaStream != nil {
		return s.viaStream, true
	}
	return s.viaBroad, false
}

func (s *poolSessionStub) wasEverAssigned() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.everAssigned) > 0
}

// stillAssigned reports whether any stream is left bound after teardown — a
// leaked binding would keep the slot's stream count inflated forever.
func (s *poolSessionStub) stillAssigned() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.assigned) > 0
}

// sessionIDOfFrame reads the SessionID a frame was sealed under. The encrypted
// chunk is prefixed by the token; core.Chunk carries SessionID inside the AEAD
// plaintext, so we cannot read it without the key. Instead we decrypt with the
// candidate session: success identifies the session that sealed it.
func frameDecryptsWith(t *testing.T, sess *core.Session, frame []byte, tokenLen int) bool {
	t.Helper()
	if len(frame) <= tokenLen {
		return false
	}
	_, err := sess.DecryptChunkSafe(frame[tokenLen:])
	return err == nil
}

// runUDPAssociate drives HandleUDPAssociateWS far enough to send exactly one
// datagram through the tunnel, then tears the association down.
func runUDPAssociate(t *testing.T, cl *client.Client, wst client.StreamTransport) {
	t.Helper()

	cp, peer := newConnPipe()
	defer cp.Close()
	defer peer.Close()

	// The handler writes the SOCKS5 reply, then blocks on conn.Read until the
	// control TCP closes. Read the reply to learn the bound UDP port.
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

	// reply = [VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)]
	port := int(binary.BigEndian.Uint16(reply[8:10]))
	relay, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer relay.Close()

	// SOCKS5 UDP request: [RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2)] + data
	dgram := []byte{0, 0, 0, 0x01, 1, 1, 1, 1, 0x00, 0x35, 'p', 'i', 'n', 'g'}
	if _, err := relay.Write(dgram); err != nil {
		t.Fatalf("write datagram: %v", err)
	}

	// Give the send goroutine a moment to seal and hand off the frame.
	time.Sleep(300 * time.Millisecond)

	peer.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleUDPAssociateWS did not return after control TCP close")
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// TestUDPAssociateWS_SealsWithSlotSessionNotGlobal is the regression guard for
// the field defect: the frame must decrypt with the slot session and must NOT
// decrypt with the global client session.
func TestUDPAssociateWS_SealsWithSlotSessionNotGlobal(t *testing.T) {
	const (
		globalID = uint32(0x11111111)
		slotID   = uint32(0x22222222)
	)

	stub := newPoolSessionStub(slotID)

	// Global session with a DIFFERENT key, exactly as in the pool: the initial
	// handshake session shares nothing with any slot.
	globalKey := make([]byte, 32)
	for i := range globalKey {
		globalKey[i] = 0xAB
	}
	globalSession := core.NewSession(globalID, globalKey, globalKey)

	cl := client.NewTestClientWithSession(globalSession)

	runUDPAssociate(t, cl, stub)

	frame, viaStreamPath := stub.sentFrame()
	if frame == nil {
		t.Fatal("no frame reached the transport — the datagram was never sent")
	}

	tokenLen := len(cl.Token())

	if frameDecryptsWith(t, globalSession, frame, tokenLen) {
		t.Error("frame was sealed with the GLOBAL session — the server binds one " +
			"session per WS connection and would drop this frame silently " +
			"(server/websocket.go:917-919)")
	}
	if !frameDecryptsWith(t, stub.slotSession, frame, tokenLen) {
		t.Error("frame does not decrypt with the slot session — UDP must use " +
			"client.StreamSession(wst, cl, streamID)")
	}
	if !viaStreamPath {
		t.Error("frame went out via WriteMessage (any ready slot); a stream-bound " +
			"datagram must use StreamWrite so it lands on the slot that owns its session")
	}
}

// TestUDPAssociateWS_AssignsStreamToSlot guards the ordering dependency:
// SessionForStream returns nil until the stream is in the pool's streamMap, so
// AssignStream has to happen before the session is resolved. Without it the
// pool also treats the slot as empty and tears it down mid-association
// (ws_pool_drain.go:1256).
func TestUDPAssociateWS_AssignsStreamToSlot(t *testing.T) {
	stub := newPoolSessionStub(0x33333333)

	key := make([]byte, 32)
	cl := client.NewTestClientWithSession(core.NewSession(0x44444444, key, key))

	runUDPAssociate(t, cl, stub)

	if !stub.wasEverAssigned() {
		t.Error("UDP ASSOCIATE never called AssignStream — the pool cannot route " +
			"the stream's session or account it against a slot")
	}
	// The other half of the invariant: a binding that outlives the association
	// would keep the slot's stream counter above zero and block its rotation.
	if stub.stillAssigned() {
		t.Error("stream still assigned after teardown — AssignStream must be " +
			"paired with ReleaseStream")
	}
}

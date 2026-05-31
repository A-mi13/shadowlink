package client

import (
	"testing"

	"github.com/nixavpn/shadowlink/core"
)

// newTestSlotSession builds a real *core.Session usable for encrypting a FIN
// chunk in tests. Both directions use the same 32-byte key — the client only
// needs the send direction to encrypt outbound, and the server is not involved
// in these unit tests.
func newTestSlotSession(t *testing.T, id uint32) *core.Session {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	sm := core.NewSessionManager(0)
	s, err := sm.Create(key, key)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return s
}

// TestSendSlotSessionFIN_EmitsControlFrame is the regression test for the
// ghost-session accumulation bug (2026-05-29).
//
// Field evidence: pl1 served `decoy reason=max_clients` because the WS pool
// closed slots (rotation / drain teardown) WITHOUT telling the server, so each
// retired slot left a session on the server that lingered until the idle
// timeout. With max_conns=8 and graceful-drain rotation every 30-90s, sessions
// accumulated faster than they idled out and breached max_clients.
//
// The fix: before tearing down a slot we control (our own rotation), send a
// session-wide FIN over the still-live transport so the server's handleFin can
// release the session immediately. This test pins that sendSlotSessionFIN emits
// exactly one control frame on the slot's transport.
func TestSendSlotSessionFIN_EmitsControlFrame(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 1, ServerAddr: "127.0.0.1:0"})

	stub := &countingTransport{}
	slot := &poolSlot{
		transport: stub,
		session:   newTestSlotSession(t, 7),
	}
	slot.setState(slotReady)
	p.slots[0] = slot

	p.sendSlotSessionFIN(slot)

	if stub.controlWrites != 1 {
		t.Fatalf("expected exactly 1 control frame (session FIN), got %d", stub.controlWrites)
	}
}

// TestSendSlotSessionFIN_NilSafe verifies the helper is a no-op (no panic) when
// the slot has no session or no transport — e.g. a slot that died from a real
// network failure (transport already gone) must not crash the teardown path.
func TestSendSlotSessionFIN_NilSafe(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 1, ServerAddr: "127.0.0.1:0"})

	// nil session
	p.sendSlotSessionFIN(&poolSlot{transport: &countingTransport{}})
	// nil transport
	p.sendSlotSessionFIN(&poolSlot{session: newTestSlotSession(t, 9)})
	// nil slot
	p.sendSlotSessionFIN(nil)
}

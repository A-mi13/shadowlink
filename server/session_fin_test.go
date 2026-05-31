package server

import (
	"crypto/rand"
	"net/http/httptest"
	"testing"

	"github.com/nixavpn/shadowlink/core"
)

// newFinTestTunnel creates a session + attached tunnel and returns the session
// so a test can drive handleFinChunk against it.
func newFinTestTunnel(t *testing.T, h *Handler) *core.Session {
	t.Helper()
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)
	if _, err := rand.Read(sendKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(recvKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sess, err := h.sessions.Create(sendKey, recvKey)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}
	tun := &Tunnel{
		SessionID:   sess.ID,
		ClientID:    "test:dev",
		Incoming:    make(chan []byte, 64),
		Outgoing:    make(chan []byte, defaultTunnelOutgoingBuffer),
		OutgoingUDP: make(chan []byte, 64),
		done:        make(chan struct{}),
	}
	h.tunnelsMu.Lock()
	h.tunnels[sess.ID] = tun
	h.tunnelsMu.Unlock()
	return sess
}

// TestHandleFinChunk_SessionWideReleasesSession is the server-side contract for
// the ghost-session fix (2026-05-29): a session-wide FIN (empty payload) must
// remove the session from the SessionManager immediately, so a single
// legitimate client's pool rotation cannot accumulate sessions toward
// MaxClients. Before the fix the only "session FIN" the client could build was
// NewStreamFinChunk(...,0) — a 2-byte payload that routed to handleStreamFin and
// left the session alive until idle timeout.
func TestHandleFinChunk_SessionWideReleasesSession(t *testing.T) {
	h, _ := setupTestHandler(t)
	sess := newFinTestTunnel(t, h)

	before := h.sessions.Count()
	if before == 0 {
		t.Fatal("precondition: session must exist before FIN")
	}

	// Session-wide FIN: empty payload (NewSessionFinChunk).
	finChunk := core.NewSessionFinChunk(sess.ID, sess.NextSeqNum())
	rec := httptest.NewRecorder()
	h.handleFinChunk(rec, sess, finChunk)

	if _, ok := h.sessions.Get(sess.ID); ok {
		t.Fatal("session-wide FIN must remove the session from SessionManager")
	}
	if after := h.sessions.Count(); after != before-1 {
		t.Fatalf("session count: got %d, want %d (session-wide FIN must release exactly one)", after, before-1)
	}
}

// TestHandleFinChunk_PerStreamKeepsSession is the complementary guard: a
// per-stream FIN (2-byte streamID payload) must NOT remove the session — it only
// closes that one stream. This pins the distinction the bug violated.
func TestHandleFinChunk_PerStreamKeepsSession(t *testing.T) {
	h, _ := setupTestHandler(t)
	sess := newFinTestTunnel(t, h)

	before := h.sessions.Count()

	// Per-stream FIN for stream 5: 2-byte payload.
	finChunk := core.NewStreamFinChunk(sess.ID, sess.NextSeqNum(), 5)
	rec := httptest.NewRecorder()
	h.handleFinChunk(rec, sess, finChunk)

	if _, ok := h.sessions.Get(sess.ID); !ok {
		t.Fatal("per-stream FIN must NOT remove the session")
	}
	if after := h.sessions.Count(); after != before {
		t.Fatalf("session count changed on per-stream FIN: got %d, want %d", after, before)
	}
}

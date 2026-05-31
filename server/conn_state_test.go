package server

import (
	"net"
	"net/http"
	"testing"

	"github.com/nixavpn/shadowlink/core"
)

// fakeConn is a throwaway net.Conn used only as a distinct map key for the
// per-connection state tracking in connStateHook. None of its I/O methods are
// called by the hook.
type fakeConn struct{ net.Conn }

func newConnStateTestServer(t *testing.T) *Server {
	t.Helper()
	key, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	s, err := New(TestConfig(), key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// TestConnStateHook_NeverIdleDoesNotGoNegative is the regression test for the
// IdleConnections gauge going deeply negative (-1178 observed on pl1).
//
// A connection that never reaches StateIdle (New → Active → Closed — e.g. a
// single handshake POST that completes and closes) used to emit a -1 on
// StateActive and another on StateClosed with no matching +1, dragging the
// gauge below zero. Correct accounting must only decrement when leaving the
// Idle state, so a never-idle connection nets zero.
func TestConnStateHook_NeverIdleDoesNotGoNegative(t *testing.T) {
	s := newConnStateTestServer(t)

	// 100 connections that handshake and close without ever idling.
	for i := 0; i < 100; i++ {
		c := &fakeConn{}
		s.connStateHook(c, http.StateNew)
		s.connStateHook(c, http.StateActive)
		s.connStateHook(c, http.StateClosed)
	}

	if got := s.handler.metrics.IdleConnections.Load(); got != 0 {
		t.Fatalf("IdleConnections after 100 never-idle conns: got %d, want 0", got)
	}
}

// TestConnStateHook_IdleLifecycleBalances verifies the gauge tracks real idle
// connections: entering Idle is +1, leaving Idle (Active or Closed) is -1, and a
// full lifecycle nets zero.
func TestConnStateHook_IdleLifecycleBalances(t *testing.T) {
	s := newConnStateTestServer(t)

	c1 := &fakeConn{}
	c2 := &fakeConn{}

	// c1 and c2 both become idle → gauge = 2.
	s.connStateHook(c1, http.StateNew)
	s.connStateHook(c1, http.StateActive)
	s.connStateHook(c1, http.StateIdle)
	s.connStateHook(c2, http.StateNew)
	s.connStateHook(c2, http.StateActive)
	s.connStateHook(c2, http.StateIdle)

	if got := s.handler.metrics.IdleConnections.Load(); got != 2 {
		t.Fatalf("after 2 idle conns: got %d, want 2", got)
	}

	// c1 goes active again (leaves idle) → gauge = 1.
	s.connStateHook(c1, http.StateActive)
	if got := s.handler.metrics.IdleConnections.Load(); got != 1 {
		t.Fatalf("after c1 leaves idle: got %d, want 1", got)
	}

	// c1 idles again → 2; both close → 0.
	s.connStateHook(c1, http.StateIdle)
	s.connStateHook(c1, http.StateClosed)
	s.connStateHook(c2, http.StateClosed)
	if got := s.handler.metrics.IdleConnections.Load(); got != 0 {
		t.Fatalf("after both closed: got %d, want 0", got)
	}
}

// TestConnStateHook_DoubleIdleNotDoubleCounted guards against a connection that
// somehow reports Idle twice in a row inflating the gauge — only the first
// transition into Idle counts.
func TestConnStateHook_DoubleIdleNotDoubleCounted(t *testing.T) {
	s := newConnStateTestServer(t)
	c := &fakeConn{}
	s.connStateHook(c, http.StateIdle)
	s.connStateHook(c, http.StateIdle) // duplicate — must not double count
	if got := s.handler.metrics.IdleConnections.Load(); got != 1 {
		t.Fatalf("double idle: got %d, want 1", got)
	}
}

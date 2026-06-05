package client

import (
	"testing"
)

// TestHandleStreamClose_ClosesStreamAndMap verifies that handleStreamClose
// (Bug #10) deletes the stream from streamMap and closes its channel.
func TestHandleStreamClose_ClosesStreamAndMap(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	const sid = uint16(42)

	// Register a stream on slot 0.
	attachStream(p, cl, sid, 0)

	// Pre-condition: stream is live.
	if _, ok := p.streamMap.Load(sid); !ok {
		t.Fatal("precondition: stream not in streamMap")
	}
	if streamChanClosed(cl, sid) {
		t.Fatal("precondition: stream chan should be open")
	}

	// Call the method under test.
	p.handleStreamClose(cl, sid)

	// streamMap entry must be gone.
	if _, ok := p.streamMap.Load(sid); ok {
		t.Error("streamMap entry still present after handleStreamClose")
	}

	// Stream channel must be closed (receive returns !ok immediately).
	if !streamChanClosed(cl, sid) {
		t.Error("stream chan not closed after handleStreamClose")
	}
}

// TestHandleStreamClose_IgnoresUnknownStream checks that calling
// handleStreamClose for a stream that does not exist in streamChans is a
// safe no-op (no panic, no corruption).
func TestHandleStreamClose_IgnoresUnknownStream(t *testing.T) {
	p, cl := newResumeTestPool(t, 1)
	const unknownSID = uint16(99)

	// Must not panic even when the stream is not registered.
	p.handleStreamClose(cl, unknownSID)

	if _, ok := p.streamMap.Load(unknownSID); ok {
		t.Error("unknown streamID must not be created in streamMap")
	}
}

// TestHandleStreamClose_BypassesW5Guard verifies that handleStreamClose works
// correctly when the stream's slotIdx differs from the slot that delivered
// the frame (exactly the RESUME-fallback scenario where the FlagStreamClose
// may arrive on slot B while the streamMap still points at slot A).
//
// This is the core safety property of Bug #10: FlagStreamClose is handled
// BEFORE the W5 stale-frame guard, so even a cross-slot delivery tears the
// stream down instead of silently dropping the frame.
func TestHandleStreamClose_BypassesW5Guard(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	const sid = uint16(7)

	// Stream is registered on slot 0 but the FlagStreamClose arrives on slot 1
	// (RESUME-fallback scenario).
	attachStream(p, cl, sid, 0 /* slotIdx = 0 */)

	// Simulate demux running on slot 1 (idx=1) delivering the FlagStreamClose.
	// The W5 guard would drop this frame because e.slotIdx (0) != idx (1).
	// handleStreamClose must still close the stream regardless.
	p.handleStreamClose(cl, sid)

	if _, ok := p.streamMap.Load(sid); ok {
		t.Error("streamMap entry still present; W5-bypass path did not close the stream")
	}
	if !streamChanClosed(cl, sid) {
		t.Error("stream chan not closed; W5-bypass path did not signal EOF to reader")
	}
}

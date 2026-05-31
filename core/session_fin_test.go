package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewSessionFinChunk_PayloadRoutesSessionWide pins the wire contract that
// distinguishes a session-wide FIN from a per-stream FIN.
//
// The server's handleFinChunk routes by payload length:
//   - len(payload) >= 2 → per-stream FIN (streamID = payload[0:2])
//   - len(payload) <  2 → session-wide FIN (tears the whole session down)
//
// NewStreamFinChunk always writes a 2-byte streamID, so even streamID=0 lands
// on the per-stream branch and never releases the session. NewSessionFinChunk
// must therefore emit a payload shorter than 2 bytes so it routes to the
// session-wide branch. This is the fix for the ghost-session accumulation bug
// (2026-05-29): retired pool slots / failed WS upgrades must release their
// server session immediately, which only happens via the session-wide branch.
func TestNewSessionFinChunk_PayloadRoutesSessionWide(t *testing.T) {
	chunk := NewSessionFinChunk(42, 7)

	assert.Equal(t, FlagFin, chunk.Flags)
	assert.Equal(t, uint32(42), chunk.SessionID)
	assert.Equal(t, uint32(7), chunk.SeqNum)
	// CRITICAL: payload MUST be shorter than 2 bytes so the server routes it to
	// the session-wide handleFin branch, not handleStreamFin.
	assert.Less(t, len(chunk.Payload), 2,
		"session FIN payload must be <2 bytes to route session-wide, got len=%d", len(chunk.Payload))
}

// TestNewStreamFinChunk_StaysPerStream is a guard so the existing per-stream FIN
// constructor is not accidentally changed to also route session-wide — they
// must remain distinct.
func TestNewStreamFinChunk_StaysPerStream(t *testing.T) {
	chunk := NewStreamFinChunk(42, 7, 0)
	assert.Equal(t, FlagFin, chunk.Flags)
	assert.GreaterOrEqual(t, len(chunk.Payload), 2,
		"per-stream FIN must carry a 2-byte streamID (routes to handleStreamFin)")
}

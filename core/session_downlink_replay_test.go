package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// M1 (2026-06-11): downlink anti-replay invariant on core.Session. The client
// ws_pool / direct downlink paths drive this method as a drop filter before
// routing bytes into a stream — a replayed (already-seen) chunk.SeqNum must be
// rejected so an on-path injector cannot duplicate bytes in the proxied TCP
// stream. AEAD proves authenticity but NOT freshness; this sliding window adds
// freshness, mirroring what the server already runs on uplink.
func TestDownlinkReplay_SecondSameSeqRejected(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.True(t, s.AcceptSeqNum(5), "first seq=5 accepted")
	assert.False(t, s.AcceptSeqNum(5), "replay seq=5 rejected")
	assert.True(t, s.AcceptSeqNum(6), "new seq=6 accepted")
}

// Out-of-order delivery (WS multiplex) within the window is still accepted —
// the filter must not reject legitimate reordering, only true duplicates.
func TestDownlinkReplay_OutOfOrderWithinWindowAccepted(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.True(t, s.AcceptSeqNum(10))
	assert.True(t, s.AcceptSeqNum(8), "older-but-unseen seq within window accepted")
	assert.False(t, s.AcceptSeqNum(8), "now a replay → rejected")
	assert.True(t, s.AcceptSeqNum(9))
}

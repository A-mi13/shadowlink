package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// L5 (2026-06-11): a seq jump >= WindowSize forces a full bitmap reset, which
// re-admits previously-seen seqs in the old range. Only an authentic peer can
// produce a valid frame so it is not externally exploitable, but a buggy
// duplicate-heavy peer could slip dupes through — surface it via a counter.
func TestAcceptSeqNum_LargeJumpIncrementsResetCounter(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.True(t, s.AcceptSeqNum(1))
	before := s.WindowResetCount()
	assert.True(t, s.AcceptSeqNum(1+WindowSize+10)) // jump > window → full reset
	assert.Equal(t, before+1, s.WindowResetCount())
}

// A small in-window advance must NOT increment the reset counter.
func TestAcceptSeqNum_SmallAdvanceNoReset(t *testing.T) {
	s := NewSession(2, make([]byte, 32), make([]byte, 32))
	assert.True(t, s.AcceptSeqNum(1))
	before := s.WindowResetCount()
	assert.True(t, s.AcceptSeqNum(5))
	assert.Equal(t, before, s.WindowResetCount(), "in-window advance must not reset")
}

package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// After InitSendEpoch a client session must encrypt via a counter-nonce
// (deterministic) rather than the random-nonce fallback. Verify the first two
// nonces are counter 0 and 1 in 8 BE, and that the peer decrypts (wire-compat).
func TestInitSendEpoch_SwitchesToCounterNonce(t *testing.T) {
	sendKey := make([]byte, 32)
	sendKey[0] = 0xA1
	recvKey := make([]byte, 32)
	recvKey[0] = 0xB2

	s := NewSession(7, sendKey, recvKey)
	require.Nil(t, s.sendEpochPtr.Load(), "newborn client session has no epoch")

	require.NoError(t, s.InitSendEpoch())
	require.NotNil(t, s.sendEpochPtr.Load(), "epoch installed")

	c0 := NewDataChunk(7, 0, []byte("a"))
	enc0, err := s.EncryptChunk(c0)
	require.NoError(t, err)
	// nonce[:8] = counter 0
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, enc0[:8])

	c1 := NewDataChunk(7, 1, []byte("b"))
	enc1, err := s.EncryptChunk(c1)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, enc1[:8])

	// Receiver with the same key decrypts (wire-compat).
	dec, err := DecryptChunk(enc0, sendKey)
	require.NoError(t, err)
	assert.Equal(t, []byte("a"), dec.Payload)
}

// Idempotence: a second call must NOT reset the counter (would reopen nonce 0).
func TestInitSendEpoch_IdempotentNoCounterReset(t *testing.T) {
	s := NewSession(9, make([]byte, 32), make([]byte, 32))
	require.NoError(t, s.InitSendEpoch())
	_, _ = s.EncryptChunk(NewDataChunk(9, 0, []byte("x"))) // counter→1
	require.NoError(t, s.InitSendEpoch())                  // second call — no-op
	enc, err := s.EncryptChunk(NewDataChunk(9, 1, []byte("y")))
	require.NoError(t, err)
	// If the re-call reset the epoch, the counter would be 0 again → nonce reuse.
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, enc[:8], "counter must not reset")
}

// A session built via Create (server) already has an epoch — InitSendEpoch no-op.
func TestInitSendEpoch_NoopWhenAlreadyCached(t *testing.T) {
	sm := NewSessionManager(0)
	s, err := sm.Create(make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)
	before := s.sendEpochPtr.Load()
	require.NoError(t, s.InitSendEpoch())
	assert.Same(t, before, s.sendEpochPtr.Load(), "must not replace server epoch")
}

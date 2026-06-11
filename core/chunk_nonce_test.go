package core

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// L1 (2026-06-11): EncryptWith nonce must be pure counter(8 BE) ‖ zero(4) —
// the former random 4-byte tail added no per-key uniqueness over the monotonic
// counter and cost a crypto/rand syscall on the hot path.
func TestEncryptWith_NonceIsPureCounterNoRandomTail(t *testing.T) {
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	c := &Chunk{SessionID: 1, SeqNum: 0, Flags: FlagData, Payload: []byte("z")}
	out, err := c.EncryptWith(gcm, 0x0102030405060708)
	require.NoError(t, err)
	// nonce[:8] = counter BE
	assert.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, out[:8])
	// nonce[8:12] = zero (was random)
	assert.Equal(t, []byte{0, 0, 0, 0}, out[8:12])

	// Wire-compat: the same key decrypts.
	dec, err := DecryptChunk(out, key)
	require.NoError(t, err)
	assert.Equal(t, []byte("z"), dec.Payload)
}

// Two distinct counters under the same key must produce distinct nonces (the
// uniqueness guarantee the random tail used to be wrongly credited with).
func TestEncryptWith_DistinctCountersDistinctNonces(t *testing.T) {
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	c := &Chunk{SessionID: 1, SeqNum: 0, Flags: FlagData, Payload: []byte("p")}
	a, err := c.EncryptWith(gcm, 41)
	require.NoError(t, err)
	b, err := c.EncryptWith(gcm, 42)
	require.NoError(t, err)
	assert.NotEqual(t, a[:NonceSize], b[:NonceSize], "distinct counters → distinct nonces")
}

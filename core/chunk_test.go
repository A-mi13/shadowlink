package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestChunkRoundtrip(t *testing.T) {
	key := makeKey(t)
	chunk := &Chunk{
		SessionID: 42,
		SeqNum:    1,
		Flags:     FlagData,
		Payload:   []byte("hello shadowlink"),
	}

	encrypted, err := chunk.Encrypt(key)
	require.NoError(t, err)

	decoded, err := DecryptChunk(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, chunk.SessionID, decoded.SessionID)
	assert.Equal(t, chunk.SeqNum, decoded.SeqNum)
	assert.Equal(t, chunk.Flags, decoded.Flags)
	assert.Equal(t, chunk.Payload, decoded.Payload)
}

func TestChunkEmptyPayload(t *testing.T) {
	key := makeKey(t)
	chunk := NewKeepaliveChunk(1, 0)

	encrypted, err := chunk.Encrypt(key)
	require.NoError(t, err)

	decoded, err := DecryptChunk(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, FlagKeepalive, decoded.Flags)
	assert.Empty(t, decoded.Payload)
}

func TestChunkLargePayload(t *testing.T) {
	key := makeKey(t)
	payload := make([]byte, 9000) // typical max useful data per chunk
	rand.Read(payload)

	chunk := NewDataChunk(100, 999, payload)
	encrypted, err := chunk.Encrypt(key)
	require.NoError(t, err)

	decoded, err := DecryptChunk(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, payload, decoded.Payload)
}

func TestChunkTamperedCiphertext(t *testing.T) {
	key := makeKey(t)
	chunk := NewDataChunk(1, 1, []byte("secret data"))

	encrypted, err := chunk.Encrypt(key)
	require.NoError(t, err)

	// Flip a byte in the ciphertext
	encrypted[NonceSize+5] ^= 0xff

	_, err = DecryptChunk(encrypted, key)
	assert.Error(t, err, "tampered chunk must fail decryption")
}

func TestChunkWrongKey(t *testing.T) {
	key1 := makeKey(t)
	key2 := makeKey(t)

	chunk := NewDataChunk(1, 1, []byte("data"))
	encrypted, err := chunk.Encrypt(key1)
	require.NoError(t, err)

	_, err = DecryptChunk(encrypted, key2)
	assert.Error(t, err, "wrong key must fail")
}

func TestChunkCrossSessionReplay(t *testing.T) {
	key1 := makeKey(t)
	key2 := makeKey(t)

	// Encrypt with session 1's key
	chunk := NewDataChunk(1, 1, []byte("data"))
	encrypted, err := chunk.Encrypt(key1)
	require.NoError(t, err)

	// Try to decrypt with session 2's key — must fail
	_, err = DecryptChunk(encrypted, key2)
	assert.Error(t, err, "cross-session replay must fail — different session keys")
}

func TestChunkTooShort(t *testing.T) {
	key := makeKey(t)
	_, err := DecryptChunk([]byte{1, 2, 3}, key)
	assert.Error(t, err)
}

func TestChunkAllFlags(t *testing.T) {
	key := makeKey(t)
	flags := []byte{FlagData, FlagAck, FlagPadding, FlagKeepalive, FlagFin, FlagControl, FlagConnect, FlagUDP}

	for _, f := range flags {
		chunk := &Chunk{SessionID: 1, SeqNum: 0, Flags: f, Payload: []byte("x")}
		enc, err := chunk.Encrypt(key)
		require.NoError(t, err)

		dec, err := DecryptChunk(enc, key)
		require.NoError(t, err)
		assert.Equal(t, f, dec.Flags)
	}
}

func TestNewPaddingChunk(t *testing.T) {
	chunk, err := NewPaddingChunk(1, 0, 100)
	require.NoError(t, err)
	assert.Equal(t, FlagPadding, chunk.Flags)
	assert.Len(t, chunk.Payload, 100)
}

func makeGCM(t testing.TB, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return gcm
}

func TestEncryptWithDecryptWith(t *testing.T) {
	key := makeKey(t)
	gcm := makeGCM(t, key)

	chunk := &Chunk{
		SessionID: 42,
		SeqNum:    7,
		Flags:     FlagData,
		Payload:   []byte("hello encrypted world"),
	}

	encrypted, err := chunk.EncryptWith(gcm, 1)
	require.NoError(t, err)

	decoded, err := DecryptWith(encrypted, gcm)
	require.NoError(t, err)
	assert.Equal(t, chunk.SessionID, decoded.SessionID)
	assert.Equal(t, chunk.SeqNum, decoded.SeqNum)
	assert.Equal(t, chunk.Flags, decoded.Flags)
	assert.Equal(t, chunk.Payload, decoded.Payload)
}

func TestEncryptWithEmptyPayload(t *testing.T) {
	key := makeKey(t)
	gcm := makeGCM(t, key)

	chunk := NewKeepaliveChunk(1, 0)
	encrypted, err := chunk.EncryptWith(gcm, 0)
	require.NoError(t, err)

	decoded, err := DecryptWith(encrypted, gcm)
	require.NoError(t, err)
	assert.Equal(t, FlagKeepalive, decoded.Flags)
	assert.Empty(t, decoded.Payload)
}

func TestEncryptWithLargePayload(t *testing.T) {
	key := makeKey(t)
	gcm := makeGCM(t, key)

	payload := make([]byte, 9000)
	rand.Read(payload)

	chunk := NewDataChunk(100, 999, payload)
	encrypted, err := chunk.EncryptWith(gcm, 42)
	require.NoError(t, err)

	decoded, err := DecryptWith(encrypted, gcm)
	require.NoError(t, err)
	assert.Equal(t, payload, decoded.Payload)
}

func TestEncryptWithCrossCompatibility(t *testing.T) {
	key := makeKey(t)
	gcm := makeGCM(t, key)

	chunk := &Chunk{
		SessionID: 55,
		SeqNum:    123,
		Flags:     FlagData,
		Payload:   []byte("cross compat test"),
	}

	// EncryptWith -> DecryptChunk (old API with raw key)
	encrypted, err := chunk.EncryptWith(gcm, 100)
	require.NoError(t, err)

	decoded, err := DecryptChunk(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, chunk.SessionID, decoded.SessionID)
	assert.Equal(t, chunk.SeqNum, decoded.SeqNum)
	assert.Equal(t, chunk.Flags, decoded.Flags)
	assert.Equal(t, chunk.Payload, decoded.Payload)

	// Encrypt (old API) -> DecryptWith (new API with cached GCM)
	encrypted2, err := chunk.Encrypt(key)
	require.NoError(t, err)

	decoded2, err := DecryptWith(encrypted2, gcm)
	require.NoError(t, err)
	assert.Equal(t, chunk.SessionID, decoded2.SessionID)
	assert.Equal(t, chunk.SeqNum, decoded2.SeqNum)
	assert.Equal(t, chunk.Flags, decoded2.Flags)
	assert.Equal(t, chunk.Payload, decoded2.Payload)
}

func TestEncryptWithTamperedCiphertext(t *testing.T) {
	key := makeKey(t)
	gcm := makeGCM(t, key)

	chunk := NewDataChunk(1, 1, []byte("secret data"))
	encrypted, err := chunk.EncryptWith(gcm, 1)
	require.NoError(t, err)

	// Flip a byte in the ciphertext
	encrypted[NonceSize+5] ^= 0xff

	_, err = DecryptWith(encrypted, gcm)
	assert.Error(t, err, "tampered chunk must fail decryption")
}

func TestDecryptWithTooShort(t *testing.T) {
	key := makeKey(t)
	gcm := makeGCM(t, key)

	_, err := DecryptWith([]byte{1, 2, 3}, gcm)
	assert.Error(t, err)
}

func TestEncryptWithFlagUDP(t *testing.T) {
	key := makeKey(t)
	gcm := makeGCM(t, key)

	// Build a UDP chunk: StreamID(2) + UDP data
	payload := make([]byte, 2+100)
	binary.BigEndian.PutUint16(payload[0:2], 42)
	copy(payload[2:], make([]byte, 100))

	chunk := &Chunk{SessionID: 1, SeqNum: 0, Flags: FlagUDP, Payload: payload}
	encrypted, err := chunk.EncryptWith(gcm, 0)
	require.NoError(t, err)

	decoded, err := DecryptWith(encrypted, gcm)
	require.NoError(t, err)
	assert.Equal(t, FlagUDP, decoded.Flags)

	streamID, data := ParseStreamID(decoded.Payload)
	assert.Equal(t, uint16(42), streamID)
	assert.Len(t, data, 100)
}

func TestNewUDPDataChunkRoundtrip(t *testing.T) {
	chunk := NewUDPDataChunk(1, 0, 42, "8.8.8.8:53", []byte("dns query"))

	assert.Equal(t, FlagUDP, chunk.Flags)

	streamID, addr, data, err := ParseUDPChunk(chunk.Payload)
	require.NoError(t, err)
	assert.Equal(t, uint16(42), streamID)
	assert.Equal(t, "8.8.8.8:53", addr)
	assert.Equal(t, []byte("dns query"), data)
}

func TestNewUDPDataChunkEmptyData(t *testing.T) {
	chunk := NewUDPDataChunk(1, 0, 1, "127.0.0.1:1234", nil)

	streamID, addr, data, err := ParseUDPChunk(chunk.Payload)
	require.NoError(t, err)
	assert.Equal(t, uint16(1), streamID)
	assert.Equal(t, "127.0.0.1:1234", addr)
	assert.Empty(t, data)
}

func TestParseUDPChunkTooShort(t *testing.T) {
	_, _, _, err := ParseUDPChunk([]byte{0x00})
	assert.Error(t, err)

	_, _, _, err = ParseUDPChunk(nil)
	assert.Error(t, err)
}

func TestParseUDPChunkTruncatedAddr(t *testing.T) {
	// Claim addr is 100 bytes but only provide 2 bytes
	payload := []byte{0x00, 0x01, 0x00, 100, 'a', 'b'}
	_, _, _, err := ParseUDPChunk(payload)
	assert.Error(t, err)
}

func TestNewUDPDataChunkEncryptDecrypt(t *testing.T) {
	key := makeKey(t)
	gcm := makeGCM(t, key)

	chunk := NewUDPDataChunk(99, 7, 500, "example.com:443", []byte("payload data here"))

	encrypted, err := chunk.EncryptWith(gcm, 1)
	require.NoError(t, err)

	decoded, err := DecryptWith(encrypted, gcm)
	require.NoError(t, err)
	assert.Equal(t, FlagUDP, decoded.Flags)

	streamID, addr, data, err := ParseUDPChunk(decoded.Payload)
	require.NoError(t, err)
	assert.Equal(t, uint16(500), streamID)
	assert.Equal(t, "example.com:443", addr)
	assert.Equal(t, []byte("payload data here"), data)
}

func BenchmarkChunkEncrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	payload := make([]byte, 9000)
	rand.Read(payload)
	chunk := NewDataChunk(1, 0, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chunk.SeqNum = uint32(i)
		chunk.Encrypt(key)
	}
}

func BenchmarkChunkDecrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	payload := make([]byte, 9000)
	rand.Read(payload)
	chunk := NewDataChunk(1, 0, payload)
	encrypted, _ := chunk.Encrypt(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptChunk(encrypted, key)
	}
}

func BenchmarkEncryptWith(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	payload := make([]byte, 9000)
	rand.Read(payload)
	chunk := NewDataChunk(1, 0, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chunk.SeqNum = uint32(i)
		chunk.EncryptWith(gcm, uint64(i))
	}
}

func TestWindowUpdateChunk_RoundTrip(t *testing.T) {
	c := NewWindowUpdateChunk(0x11223344, 7, 0xABCD, 0x0010FFFF)
	if c.Flags != FlagWindowUpdate {
		t.Fatalf("Flags = %#x, want %#x", c.Flags, FlagWindowUpdate)
	}
	sid, delta, err := ParseWindowUpdate(c.Payload)
	if err != nil {
		t.Fatalf("ParseWindowUpdate: %v", err)
	}
	if sid != 0xABCD || delta != 0x0010FFFF {
		t.Fatalf("got sid=%#x delta=%#x, want 0xABCD/0x0010FFFF", sid, delta)
	}
}

func TestParseWindowUpdate_TooShort(t *testing.T) {
	if _, _, err := ParseWindowUpdate([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("expected error for <6-byte payload, got nil")
	}
}

func BenchmarkDecryptWith(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	payload := make([]byte, 9000)
	rand.Read(payload)
	chunk := NewDataChunk(1, 0, payload)
	encrypted, _ := chunk.EncryptWith(gcm, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptWith(encrypted, gcm)
	}
}

func TestFlagStreamOpenValue(t *testing.T) {
	if FlagStreamOpen != 0x09 {
		t.Errorf("FlagStreamOpen = 0x%02x, want 0x09", FlagStreamOpen)
	}
	all := []byte{FlagData, FlagAck, FlagPadding, FlagKeepalive, FlagFin, FlagControl, FlagConnect, FlagUDP, FlagStreamOpen}
	seen := map[byte]bool{}
	for _, f := range all {
		if seen[f] {
			t.Errorf("flag collision at 0x%02x", f)
		}
		seen[f] = true
	}
}

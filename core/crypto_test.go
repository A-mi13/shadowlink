package core

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)
	assert.Len(t, kp.Public, 32)
	assert.Len(t, kp.Private, 32)
	assert.NotEqual(t, kp.Public, kp.Private)
}

func TestGenerateKeyPairUniqueness(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	assert.NotEqual(t, kp1.Public, kp2.Public)
	assert.NotEqual(t, kp1.Private, kp2.Private)
}

func TestKeyPairFromPrivate(t *testing.T) {
	kp1, err := GenerateKeyPair()
	require.NoError(t, err)

	kp2, err := KeyPairFromPrivate(kp1.Private)
	require.NoError(t, err)
	assert.Equal(t, kp1.Public, kp2.Public)
	assert.Equal(t, kp1.Private, kp2.Private)
}

func TestECDHSharedSecret(t *testing.T) {
	client, _ := GenerateKeyPair()
	server, _ := GenerateKeyPair()

	s1, err := ComputeSharedSecret(client, server.Public)
	require.NoError(t, err)
	s2, err := ComputeSharedSecret(server, client.Public)
	require.NoError(t, err)

	assert.Equal(t, s1, s2)
	assert.Len(t, s1, 32)
}

func TestDeriveSessionKeys(t *testing.T) {
	shared := make([]byte, 32)
	rand.Read(shared)
	clientPub := make([]byte, 32)
	rand.Read(clientPub)
	serverPub := make([]byte, 32)
	rand.Read(serverPub)
	clientID := []byte("test-client-001")

	k1, err := DeriveSessionKeys(shared, clientPub, serverPub, clientID, 0)
	require.NoError(t, err)
	k2, err := DeriveSessionKeys(shared, clientPub, serverPub, clientID, 0)
	require.NoError(t, err)

	assert.Equal(t, k1.SendKey, k2.SendKey, "deterministic")
	assert.Equal(t, k1.RecvKey, k2.RecvKey, "deterministic")
	assert.NotEqual(t, k1.SendKey, k1.RecvKey, "different directions")
	assert.Len(t, k1.SendKey, 32, "AES-256 key size")
	assert.Len(t, k1.RecvKey, 32, "AES-256 key size")
}

func TestDeriveSessionKeysDoesNotMutateInputs(t *testing.T) {
	shared := make([]byte, 32)
	rand.Read(shared)
	clientPub := make([]byte, 32)
	rand.Read(clientPub)
	serverPub := make([]byte, 32)
	rand.Read(serverPub)
	clientID := []byte("test-client")

	clientPubCopy := make([]byte, 32)
	copy(clientPubCopy, clientPub)
	clientIDCopy := make([]byte, len(clientID))
	copy(clientIDCopy, clientID)

	DeriveSessionKeys(shared, clientPub, serverPub, clientID, 0) //nolint:errcheck // test only

	assert.Equal(t, clientPubCopy, clientPub, "clientPub must not be mutated")
	assert.Equal(t, clientIDCopy, clientID, "clientID must not be mutated")
}

func TestNaclBoxEncryptDecrypt(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	// 16-byte UUID-shaped ID — the only length the protocol accepts post A1-M4.
	clientID := []byte("client-1234567_X")

	encrypted, err := EncryptClientID(clientID, receiver.Public, sender)
	require.NoError(t, err)

	decrypted, err := DecryptClientID(encrypted, sender.Public, receiver)
	require.NoError(t, err)
	assert.Equal(t, clientID, decrypted)
}

func TestNaclBoxFixedSize(t *testing.T) {
	// EncryptClientID output is now deterministic in size — random padding moved to the wire
	// format layer (trailing bytes after the fixed-size encClientID field). This ensures
	// ParseHandshakePayload can delimit fields without a length prefix.
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	clientID := []byte("client-1234567_X") // 16 bytes (UUID size)

	expectedSize := 24 + 8 + 1 + len(clientID) + 16 // nonce + ts + len_prefix + plaintext + MAC
	for i := 0; i < 30; i++ {
		enc, err := EncryptClientID(clientID, receiver.Public, sender)
		require.NoError(t, err)
		assert.Equal(t, expectedSize, len(enc), "EncryptClientID must produce deterministic-size output")
	}
}

func TestNaclBoxWrongKey(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	wrong, _ := GenerateKeyPair()
	clientID := []byte("client-1234567_X") // 16 bytes (UUID size)

	encrypted, err := EncryptClientID(clientID, receiver.Public, sender)
	require.NoError(t, err)

	_, err = DecryptClientID(encrypted, sender.Public, wrong)
	assert.Error(t, err, "decryption with wrong key should fail")
}

func TestNaclBoxClientIDTooLong(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	longID := make([]byte, 256)

	_, err := EncryptClientID(longID, receiver.Public, sender)
	assert.Error(t, err, "client_id > 255 bytes should be rejected")
}

// TestDecryptClientID_RejectsNonSixteenSize asserts the A1-M4 decode-side
// invariant: any ciphertext whose embedded clientID length byte != 16 is
// rejected even if box.Open succeeds. The encoder is permissive (accepts
// 0..16) for historical reasons, so this gap is closed at the decoder.
//
// 2026-05-03 T1 P3: with the new outer-length check (`len(encrypted) !=
// EncryptedClientIDSize`), encoding a non-16-byte ID now yields a frame whose
// outer length differs from 65 — so the boundary check rejects it BEFORE the
// AEAD primitive runs. The error string therefore reads "invalid encrypted
// clientID size" (outer) rather than "invalid clientID size" (inner). Both
// assertions are valid: any non-canonical encoding is rejected somewhere in
// the decode path. We match on the substring "size" common to both.
func TestDecryptClientID_RejectsNonSixteenSize(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()

	// 0-byte ID — encoder accepts, decoder must reject.
	enc, err := EncryptClientID([]byte{}, receiver.Public, sender)
	require.NoError(t, err)
	_, err = DecryptClientID(enc, sender.Public, receiver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size")

	// 10-byte ID — same.
	enc, err = EncryptClientID([]byte("client-123"), receiver.Public, sender)
	require.NoError(t, err)
	_, err = DecryptClientID(enc, sender.Public, receiver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size")

	// 15-byte ID (one short of canonical) — same.
	enc, err = EncryptClientID([]byte("0123456789abcde"), receiver.Public, sender)
	require.NoError(t, err)
	_, err = DecryptClientID(enc, sender.Public, receiver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size")
}

// TestDecryptClientID_RejectsWrongOuterLength asserts the final-audit
// 2026-05-03 T1 P3 fix: any wire frame whose ciphertext length differs from
// EncryptedClientIDSize is rejected at the size-check boundary before the
// AEAD primitive runs. Closes the asymmetry where encode strict-bounded the
// payload but decode only checked `idLen != 16` post-Open.
func TestDecryptClientID_RejectsWrongOuterLength(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	require.NoError(t, err)

	canonical, err := EncryptClientID(uuid, receiver.Public, sender)
	require.NoError(t, err)
	require.Len(t, canonical, EncryptedClientIDSize, "encode invariant: 16-byte UUID → EncryptedClientIDSize")

	// One byte short of canonical — must reject at the boundary.
	short := canonical[:len(canonical)-1]
	_, err = DecryptClientID(short, sender.Public, receiver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid encrypted clientID size")

	// One byte longer — pad with arbitrary trailing byte; reject same path.
	long := append([]byte{}, canonical...)
	long = append(long, 0xAA)
	_, err = DecryptClientID(long, sender.Public, receiver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid encrypted clientID size")

	// Far too short (less than 24-byte nonce) — same boundary owns it now,
	// not the previous "ciphertext too short" check.
	_, err = DecryptClientID([]byte{1, 2, 3}, sender.Public, receiver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid encrypted clientID size")

	// Sanity: canonical-length frame still round-trips.
	dec, err := DecryptClientID(canonical, sender.Public, receiver)
	require.NoError(t, err)
	assert.Equal(t, uuid, dec)
}

// TestEncryptedClientIDSize_RoundtripInvariant pins the wire-format invariant
// recommended by final audit 2026-05-03 T1 P3: encoding a canonical 16-byte
// UUID must yield exactly EncryptedClientIDSize bytes; decode must accept it
// and recover the original. A future contributor that bumps the constant or
// changes the encoder format in one place will fail this single assertion
// loudly instead of leaving the parser slot (handshake.go) and decode idLen
// check drifting silently.
func TestEncryptedClientIDSize_RoundtripInvariant(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()

	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	require.NoError(t, err)

	enc, err := EncryptClientID(uuid, receiver.Public, sender)
	require.NoError(t, err)
	require.Equal(t, EncryptedClientIDSize, len(enc),
		"wire invariant: 16-byte UUID encodes to exactly EncryptedClientIDSize=%d bytes",
		EncryptedClientIDSize)

	dec, err := DecryptClientID(enc, sender.Public, receiver)
	require.NoError(t, err)
	require.Equal(t, uuid, dec, "round-trip must recover the original UUID")
	require.Equal(t, 16, len(dec), "decoded clientID must be canonical 16-byte UUID")
}

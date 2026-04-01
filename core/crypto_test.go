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

	k1, err := DeriveSessionKeys(shared, clientPub, serverPub, clientID)
	require.NoError(t, err)
	k2, err := DeriveSessionKeys(shared, clientPub, serverPub, clientID)
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

	DeriveSessionKeys(shared, clientPub, serverPub, clientID) //nolint:errcheck // test only

	assert.Equal(t, clientPubCopy, clientPub, "clientPub must not be mutated")
	assert.Equal(t, clientIDCopy, clientID, "clientID must not be mutated")
}

func TestNaclBoxEncryptDecrypt(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	clientID := []byte("client-123")

	encrypted, err := EncryptClientID(clientID, receiver.Public, sender)
	require.NoError(t, err)

	decrypted, err := DecryptClientID(encrypted, sender.Public, receiver)
	require.NoError(t, err)
	assert.Equal(t, clientID, decrypted)
}

func TestNaclBoxVariesSize(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	clientID := []byte("client-123")

	sizes := map[int]bool{}
	for i := 0; i < 30; i++ {
		enc, err := EncryptClientID(clientID, receiver.Public, sender)
		require.NoError(t, err)
		sizes[len(enc)] = true
	}
	assert.Greater(t, len(sizes), 1, "random padding should vary ciphertext size")
}

func TestNaclBoxWrongKey(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	wrong, _ := GenerateKeyPair()
	clientID := []byte("client-123")

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

func TestNaclBoxEmptyClientID(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()

	encrypted, err := EncryptClientID([]byte{}, receiver.Public, sender)
	require.NoError(t, err)

	decrypted, err := DecryptClientID(encrypted, sender.Public, receiver)
	require.NoError(t, err)
	assert.Equal(t, []byte{}, decrypted)
}

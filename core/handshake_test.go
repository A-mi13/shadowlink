package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeRoundtrip(t *testing.T) {
	serverStatic, err := GenerateKeyPair()
	require.NoError(t, err)
	clientID := []byte("test-client")
	sm := NewSessionManager(5 * time.Minute)

	// Client creates ClientHello
	clientHello, clientState, err := NewClientHello(clientID, serverStatic.Public)
	require.NoError(t, err)
	assert.Len(t, clientHello.EphemeralPub, 32)
	assert.NotEmpty(t, clientHello.EncryptedClientID)

	// Server handles ClientHello
	serverHello, serverSession, _, err := HandleClientHello(clientHello, serverStatic, 8, 12288, sm)
	require.NoError(t, err)
	assert.Len(t, serverHello.EphemeralPub, 32)
	assert.NotEmpty(t, serverHello.EncryptedSessionToken)
	assert.NotNil(t, serverSession)
	assert.Equal(t, uint8(8), serverHello.MaxConnsPerClient)
	assert.Equal(t, uint16(12288), serverHello.ChunkSize)

	// Client completes handshake
	clientSession, err := CompleteHandshake(clientState, serverHello)
	require.NoError(t, err)

	// Both sides should derive compatible keys
	assert.Equal(t, clientSession.SendKey, serverSession.RecvKey, "client send = server recv")
	assert.Equal(t, clientSession.RecvKey, serverSession.SendKey, "client recv = server send")
	assert.Equal(t, clientSession.ID, serverSession.ID, "same session ID")
}

func TestHandshakeWrongServerKey(t *testing.T) {
	serverStatic, _ := GenerateKeyPair()
	wrongServer, _ := GenerateKeyPair()
	clientID := []byte("test-client")
	sm := NewSessionManager(5 * time.Minute)

	clientHello, _, _ := NewClientHello(clientID, wrongServer.Public)

	// Server with different key can't decrypt client_id
	_, _, _, err := HandleClientHello(clientHello, serverStatic, 8, 12288, sm) //nolint
	assert.Error(t, err)
}

func TestHandshakeDataTransfer(t *testing.T) {
	serverStatic, _ := GenerateKeyPair()
	clientID := []byte("user-42")
	sm := NewSessionManager(5 * time.Minute)

	clientHello, clientState, _ := NewClientHello(clientID, serverStatic.Public)
	serverHello, serverSession, _, _ := HandleClientHello(clientHello, serverStatic, 8, 12288, sm)
	clientSession, _ := CompleteHandshake(clientState, serverHello)

	// Client encrypts a data chunk
	payload := []byte("hello from client")
	chunk := NewDataChunk(clientSession.ID, clientSession.NextSeqNum(), payload)
	encrypted, err := chunk.Encrypt(clientSession.SendKey)
	require.NoError(t, err)

	// Server decrypts it
	decoded, err := DecryptChunk(encrypted, serverSession.RecvKey)
	require.NoError(t, err)
	assert.Equal(t, payload, decoded.Payload)
	assert.Equal(t, FlagData, decoded.Flags)

	// Server responds
	response := []byte("hello from server")
	respChunk := NewDataChunk(serverSession.ID, serverSession.NextSeqNum(), response)
	respEncrypted, err := respChunk.Encrypt(serverSession.SendKey)
	require.NoError(t, err)

	// Client decrypts response
	respDecoded, err := DecryptChunk(respEncrypted, clientSession.RecvKey)
	require.NoError(t, err)
	assert.Equal(t, response, respDecoded.Payload)
}

func TestHandshakeMultipleSessions(t *testing.T) {
	serverStatic, _ := GenerateKeyPair()
	sm := NewSessionManager(5 * time.Minute)

	// Create 10 sessions
	sessions := make([]*Session, 10)
	for i := range 10 {
		clientID := []byte("client-" + string(rune('A'+i)))
		ch, cs, _ := NewClientHello(clientID, serverStatic.Public)
		sh, _, _, _ := HandleClientHello(ch, serverStatic, 8, 12288, sm)
		sess, _ := CompleteHandshake(cs, sh)
		sessions[i] = sess
	}

	// All sessions should have unique IDs and keys
	ids := map[uint32]bool{}
	for _, s := range sessions {
		assert.False(t, ids[s.ID], "duplicate session ID")
		ids[s.ID] = true
	}
	assert.Equal(t, 10, sm.Count())
}

func TestHandshakeTamperedClientHello(t *testing.T) {
	serverStatic, _ := GenerateKeyPair()
	clientID := []byte("client")
	sm := NewSessionManager(5 * time.Minute)

	hello, _, _ := NewClientHello(clientID, serverStatic.Public)

	// Tamper with encrypted client ID
	hello.EncryptedClientID[len(hello.EncryptedClientID)-1] ^= 0xff

	_, _, _, err := HandleClientHello(hello, serverStatic, 8, 12288, sm)
	assert.Error(t, err)
}

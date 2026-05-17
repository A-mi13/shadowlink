package core

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeRoundtrip(t *testing.T) {
	serverStatic, err := GenerateKeyPair()
	require.NoError(t, err)
	clientID := []byte("test-client-uuid") // 16-byte UUID-shaped ID required post A1-M4
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
	clientID := []byte("test-client-uuid") // 16 bytes
	sm := NewSessionManager(5 * time.Minute)

	clientHello, _, _ := NewClientHello(clientID, wrongServer.Public)

	// Server with different key can't decrypt client_id
	_, _, _, err := HandleClientHello(clientHello, serverStatic, 8, 12288, sm) //nolint
	assert.Error(t, err)
}

func TestHandshakeDataTransfer(t *testing.T) {
	serverStatic, _ := GenerateKeyPair()
	clientID := []byte("user-42-paddingX") // 16 bytes
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
		// 16-byte UUID-shaped ID with per-session distinguishing rune (post A1-M4).
		clientID := []byte("client-" + string(rune('A'+i)) + "-padding")
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
	clientID := []byte("client-paddingXY") // 16 bytes
	sm := NewSessionManager(5 * time.Minute)

	hello, _, _ := NewClientHello(clientID, serverStatic.Public)

	// Tamper with encrypted client ID
	hello.EncryptedClientID[len(hello.EncryptedClientID)-1] ^= 0xff

	_, _, _, err := HandleClientHello(hello, serverStatic, 8, 12288, sm)
	assert.Error(t, err)
}

func TestServerHelloProtoVersionField(t *testing.T) {
	v := uint8(1)
	sh := &ServerHello{ProtoVersion: &v}
	if sh.ProtoVersion == nil {
		t.Fatal("ProtoVersion not assignable")
	}
	if *sh.ProtoVersion != 1 {
		t.Fatalf("ProtoVersion = %d, want 1", *sh.ProtoVersion)
	}
	// nil case — pointer must distinguish "absent" from "=0"
	sh2 := &ServerHello{}
	if sh2.ProtoVersion != nil {
		t.Fatal("nil ProtoVersion should be distinguishable from zero")
	}
}

func TestDeriveSessionKeys_VersionBinding(t *testing.T) {
	shared := bytes.Repeat([]byte{0xAB}, 32)
	clientEph := bytes.Repeat([]byte{0x01}, 32)
	serverEph := bytes.Repeat([]byte{0x02}, 32)
	clientID := []byte("test-client-id-0")

	keysV0, err := DeriveSessionKeys(shared, clientEph, serverEph, clientID, 0)
	if err != nil {
		t.Fatal(err)
	}
	keysV1, err := DeriveSessionKeys(shared, clientEph, serverEph, clientID, 1)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(keysV0.SendKey, keysV1.SendKey) {
		t.Error("SendKey identical across versions — HKDF binding missing")
	}
	if bytes.Equal(keysV0.RecvKey, keysV1.RecvKey) {
		t.Error("RecvKey identical across versions — HKDF binding missing")
	}
}

func TestEncryptedClientIDSize(t *testing.T) {
	serverStatic, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientID := make([]byte, 16) // UUID-size plaintext
	if _, err := rand.Read(clientID); err != nil {
		t.Fatal(err)
	}

	enc, err := EncryptClientID(clientID, serverStatic.Public, ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != EncryptedClientIDSize {
		t.Errorf("EncryptedClientIDSize = %d, got actual %d — update constant or fix encryption", EncryptedClientIDSize, len(enc))
	}
}

func TestEncryptClientID_RoundTripWithTimestamp(t *testing.T) {
	ss, _ := GenerateKeyPair()
	eph, _ := GenerateKeyPair()
	clientID := []byte("id-0123456789abc")

	enc, err := EncryptClientID(clientID, ss.Public, eph)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptClientID(enc, eph.Public, ss)
	if err != nil {
		t.Fatalf("fresh decrypt: %v", err)
	}
	if !bytes.Equal(dec, clientID) {
		t.Errorf("round-trip mismatch: got %q want %q", dec, clientID)
	}
}

func TestDecryptClientID_RejectsExpiredTimestamp(t *testing.T) {
	ss, _ := GenerateKeyPair()
	eph, _ := GenerateKeyPair()
	clientID := []byte("id-0123456789abc")

	origNow := timeNow
	defer func() { timeNow = origNow }()
	// Freeze time 301 seconds in the past — just outside the 5-minute window
	timeNow = func() int64 { return origNow() - 301 }

	enc, err := EncryptClientID(clientID, ss.Public, eph)
	if err != nil {
		t.Fatal(err)
	}

	// Restore clock for decrypt
	timeNow = origNow

	_, err = DecryptClientID(enc, eph.Public, ss)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected timestamp expired error, got %v", err)
	}
}

func TestDecryptClientID_AcceptsWithinWindow(t *testing.T) {
	ss, _ := GenerateKeyPair()
	eph, _ := GenerateKeyPair()
	clientID := []byte("id-0123456789abc")

	origNow := timeNow
	defer func() { timeNow = origNow }()
	// Freeze 60 seconds in the past — well within window
	timeNow = func() int64 { return origNow() - 60 }

	enc, err := EncryptClientID(clientID, ss.Public, eph)
	if err != nil {
		t.Fatal(err)
	}

	timeNow = origNow
	dec, err := DecryptClientID(enc, eph.Public, ss)
	if err != nil {
		t.Fatalf("within window should pass: %v", err)
	}
	if !bytes.Equal(dec, clientID) {
		t.Error("round-trip mismatch")
	}
}

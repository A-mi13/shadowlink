package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// ClientHello is the first message from client to server during handshake.
type ClientHello struct {
	EphemeralPub      []byte // 32 bytes X25519
	EncryptedClientID []byte // NaCl Box encrypted (with random padding)
}

// ServerHello is the server's response to ClientHello.
type ServerHello struct {
	EphemeralPub          []byte // 32 bytes X25519
	EncryptedSessionToken []byte // encrypted with derived session key
	SessionID             uint32
	MaxConnsPerClient     uint8
	ChunkSize             uint16
}

// HandshakeClientState holds client-side state during handshake.
type HandshakeClientState struct {
	Ephemeral *KeyPair
	ClientID  []byte
	ServerPub []byte // server static public key
}

// NewClientHello creates a ClientHello message.
// clientID is encrypted to the server's static public key via NaCl Box.
func NewClientHello(clientID, serverStaticPub []byte) (*ClientHello, *HandshakeClientState, error) {
	ephemeral, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	encClientID, err := EncryptClientID(clientID, serverStaticPub, ephemeral)
	if err != nil {
		return nil, nil, err
	}

	hello := &ClientHello{
		EphemeralPub:      ephemeral.Public,
		EncryptedClientID: encClientID,
	}

	state := &HandshakeClientState{
		Ephemeral: ephemeral,
		ClientID:  clientID,
		ServerPub: serverStaticPub,
	}

	return hello, state, nil
}

// HandleClientHello processes a ClientHello on the server side.
// Returns ServerHello and a new Session with derived keys.
func HandleClientHello(hello *ClientHello, serverStatic *KeyPair, maxConns uint8, chunkSize uint16, sm *SessionManager) (*ServerHello, *Session, []byte, error) {
	// Decrypt client_id
	clientID, err := DecryptClientID(hello.EncryptedClientID, hello.EphemeralPub, serverStatic)
	if err != nil {
		return nil, nil, nil, errors.New("invalid client hello: cannot decrypt client_id")
	}

	// Generate server ephemeral key
	serverEph, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}

	// Compute shared secret
	shared, err := ComputeSharedSecret(serverEph, hello.EphemeralPub)
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive keys — server sends with RecvKey, receives with SendKey (reversed from client)
	keys, err := DeriveSessionKeys(shared, hello.EphemeralPub, serverEph.Public, clientID)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create session (server uses reversed keys: client's send = server's recv)
	session, err := sm.Create(keys.RecvKey, keys.SendKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create session token = encrypted session ID (so client can reference it)
	sessionToken, err := encryptSessionToken(session.ID, keys.SendKey)
	if err != nil {
		return nil, nil, nil, err
	}

	serverHello := &ServerHello{
		EphemeralPub:          serverEph.Public,
		EncryptedSessionToken: sessionToken,
		SessionID:             session.ID,
		MaxConnsPerClient:     maxConns,
		ChunkSize:             chunkSize,
	}

	return serverHello, session, clientID, nil
}

// CompleteHandshake finishes the handshake on the client side.
// Returns a Session with derived keys.
func CompleteHandshake(state *HandshakeClientState, hello *ServerHello) (*Session, error) {
	// Compute shared secret
	shared, err := ComputeSharedSecret(state.Ephemeral, hello.EphemeralPub)
	if err != nil {
		return nil, err
	}

	// Derive keys
	keys, err := DeriveSessionKeys(shared, state.Ephemeral.Public, hello.EphemeralPub, state.ClientID)
	if err != nil {
		return nil, err
	}

	// Decrypt session token to get session ID.
	// Session ID is ONLY in the encrypted token — never sent in plaintext. (Audit C1 fix)
	sessID, err := decryptSessionToken(hello.EncryptedSessionToken, keys.SendKey)
	if err != nil {
		return nil, errors.New("invalid server hello: cannot decrypt session token")
	}

	return NewSession(sessID, keys.SendKey, keys.RecvKey), nil
}

// encryptSessionToken encrypts a session ID using AES-GCM.
func encryptSessionToken(sessionID uint32, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, 4)
	binary.BigEndian.PutUint32(plaintext, sessionID)

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptSessionToken decrypts a session ID.
func decryptSessionToken(data, key []byte) (uint32, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize+4+gcm.Overhead() {
		return 0, errors.New("session token too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	if len(plaintext) < 4 {
		return 0, errors.New("invalid session token")
	}

	return binary.BigEndian.Uint32(plaintext[:4]), nil
}

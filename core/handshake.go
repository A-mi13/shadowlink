package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// EncryptedClientIDSize is the protocol-fixed size of EncryptClientID() output for a 16-byte UUID.
// Composition: nonce(24) + ts(8) + len_prefix(1) + UUID(16) + NaCl Poly1305 MAC(16) = 65 bytes.
// Wire format: ephemeralPub[32] || encClientID[EncryptedClientIDSize] || randomPadding.
// Parser uses this constant to delimit the field — no length prefix in the frame per DPI-evasion design.
// Changing this value requires a ServerHello._v bump and a per-version size map in parsers.
const EncryptedClientIDSize = 65

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
	ProtoVersion          *uint8         // nil = legacy (Bearer header), non-nil = new body-prefix format version
	FingerprintWeights    map[string]int // имя профиля → относительный вес (nil = дефолт chrome 100%)
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

// HandleClientHello processes a ClientHello on the server side (legacy path,
// protoVersion=0). Preserved as a shim over HandleClientHelloWithVersion so
// existing callers in the Bearer-header path keep v0 key derivation.
// Returns ServerHello and a new Session with derived keys.
func HandleClientHello(hello *ClientHello, serverStatic *KeyPair, maxConns uint8, chunkSize uint16, sm *SessionManager) (*ServerHello, *Session, []byte, error) {
	return HandleClientHelloWithVersion(hello, serverStatic, maxConns, chunkSize, sm, 0)
}

// HandleClientHelloWithVersion is the protocol-version-aware server handshake.
// protoVersion is threaded into DeriveSessionKeys so v0 (legacy Bearer header)
// and v1 (body-prefix) sessions derive byte-different keys from the same X25519
// share — a rollback attacker cannot downgrade a v1 client to v0 and reuse any
// cryptographic material.
func HandleClientHelloWithVersion(hello *ClientHello, serverStatic *KeyPair, maxConns uint8, chunkSize uint16, sm *SessionManager, protoVersion uint8) (*ServerHello, *Session, []byte, error) {
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

	// Derive keys — server sends with RecvKey, receives with SendKey (reversed from client).
	// protoVersion binds the key schedule to the wire format (downgrade defense).
	keys, err := DeriveSessionKeys(shared, hello.EphemeralPub, serverEph.Public, clientID, protoVersion)
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

// CompleteHandshake finishes the handshake on the client side, mapping ServerHello.ProtoVersion
// (`_v` JSON field) into the v0/v1 key schedule for DeriveSessionKeys.
//
// A1-L8 audit recommendation called for an explicit "reject nil" or "explicit default" instead
// of silent-mapping nil → 0. Resolution: nil maps to **explicit default v0** (legacy Bearer-path
// keys) with the rationale that:
//
//   - After Phase 0 Bearer retire (2026-04-26), the production server always emits `_v=1`, so a
//     `nil` ProtoVersion only occurs in legacy unit tests exercising HandleClientHello (v0 wrapper).
//   - The previous behaviour was correct: tests legitimately exercise the v0 path with nil _v.
//     Rejecting nil here would break those tests without closing any production attack surface
//     (the production server cannot emit nil _v).
//
// The comment below makes the default explicit (no longer silent). Callers that need to require
// `_v` strictly should inspect `hello.ProtoVersion == nil` themselves before calling.
func CompleteHandshake(state *HandshakeClientState, hello *ServerHello) (*Session, error) {
	if hello == nil {
		return nil, errors.New("ShadowLink: ServerHello = nil")
	}
	// Explicit-default semantics (A1-L8): nil → v0 (legacy). Documented, not silent.
	pv := uint8(0)
	if hello.ProtoVersion != nil {
		pv = *hello.ProtoVersion
	}
	return CompleteHandshakeWithVersion(state, hello, pv)
}

// CompleteHandshakeWithVersion finishes the handshake with an explicit
// protoVersion for DeriveSessionKeys — symmetric counterpart of
// HandleClientHelloWithVersion on the server side. The client pins the version
// based on `_v` in ServerHello: absent → 0 (legacy), 1 → new body-prefix path.
func CompleteHandshakeWithVersion(state *HandshakeClientState, hello *ServerHello, protoVersion uint8) (*Session, error) {
	// Compute shared secret
	shared, err := ComputeSharedSecret(state.Ephemeral, hello.EphemeralPub)
	if err != nil {
		return nil, err
	}

	// Derive keys — protoVersion binds the key schedule (downgrade defense).
	keys, err := DeriveSessionKeys(shared, state.Ephemeral.Public, hello.EphemeralPub, state.ClientID, protoVersion)
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

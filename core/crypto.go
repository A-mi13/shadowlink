package core

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
)

// ZeroBytes securely zeroes a byte slice (for key material cleanup).
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// KeyPair holds an X25519 key pair for ECDH key exchange.
type KeyPair struct {
	Public  []byte
	Private []byte
	private *ecdh.PrivateKey
}

// GenerateKeyPair creates a new random X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Public:  priv.PublicKey().Bytes(),
		Private: priv.Bytes(),
		private: priv,
	}, nil
}

// KeyPairFromPrivate reconstructs a KeyPair from a 32-byte private key.
func KeyPairFromPrivate(privBytes []byte) (*KeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Public:  priv.PublicKey().Bytes(),
		Private: priv.Bytes(),
		private: priv,
	}, nil
}

// ComputeSharedSecret performs X25519 ECDH and returns the shared secret.
func ComputeSharedSecret(local *KeyPair, remotePub []byte) ([]byte, error) {
	curve := ecdh.X25519()
	remote, err := curve.NewPublicKey(remotePub)
	if err != nil {
		return nil, err
	}
	return local.private.ECDH(remote)
}

// SessionKeys holds derived encryption keys for one direction of communication.
type SessionKeys struct {
	SendKey []byte // 32 bytes, AES-256-GCM
	RecvKey []byte // 32 bytes, AES-256-GCM
}

// DeriveSessionKeys uses HKDF-SHA256 to derive send and receive keys from a shared secret.
// Parameters follow spec section 3:
//
//	IKM:  ECDH shared secret
//	salt: clientPub || serverPub
//	info: "ShadowLink-v1" || clientID
func DeriveSessionKeys(sharedSecret, clientPub, serverPub, clientID []byte) (*SessionKeys, error) {
	// Safe concat — never mutate input slices
	salt := make([]byte, 0, len(clientPub)+len(serverPub))
	salt = append(salt, clientPub...)
	salt = append(salt, serverPub...)

	info := make([]byte, 0, len("ShadowLink-v1")+len(clientID))
	info = append(info, []byte("ShadowLink-v1")...)
	info = append(info, clientID...)

	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sendKey); err != nil {
		return nil, fmt.Errorf("HKDF derive send key: %w", err)
	}
	if _, err := io.ReadFull(hkdfReader, recvKey); err != nil {
		return nil, fmt.Errorf("HKDF derive recv key: %w", err)
	}

	return &SessionKeys{SendKey: sendKey, RecvKey: recvKey}, nil
}

// EncryptClientID encrypts a client ID using NaCl Box (X25519+XSalsa20+Poly1305).
// Random padding (16-64 bytes) is added to vary ciphertext size and prevent DPI fingerprinting.
func EncryptClientID(clientID, receiverPub []byte, sender *KeyPair) ([]byte, error) {
	if len(clientID) > 255 {
		return nil, errors.New("client_id exceeds 255 bytes")
	}

	// Random padding length using crypto/rand
	var padLenBuf [1]byte
	if _, err := rand.Read(padLenBuf[:]); err != nil {
		return nil, err
	}
	padLen := 16 + int(padLenBuf[0])%49 // 16..64

	padded := make([]byte, 1+len(clientID)+padLen)
	padded[0] = byte(len(clientID))
	copy(padded[1:], clientID)
	if _, err := rand.Read(padded[1+len(clientID):]); err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	var pubKey, privKey [32]byte
	copy(pubKey[:], receiverPub)
	copy(privKey[:], sender.Private)

	encrypted := box.Seal(nonce[:], padded, &nonce, &pubKey, &privKey)
	return encrypted, nil
}

// DecryptClientID decrypts a client ID encrypted with EncryptClientID.
func DecryptClientID(encrypted, senderPub []byte, receiver *KeyPair) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, errors.New("ciphertext too short")
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	var pubKey, privKey [32]byte
	copy(pubKey[:], senderPub)
	copy(privKey[:], receiver.Private)

	decrypted, ok := box.Open(nil, encrypted[24:], &nonce, &pubKey, &privKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	if len(decrypted) < 1 {
		return nil, errors.New("invalid plaintext")
	}

	idLen := int(decrypted[0])
	if idLen > len(decrypted)-1 {
		return nil, errors.New("invalid padding")
	}
	return decrypted[1 : 1+idLen], nil
}

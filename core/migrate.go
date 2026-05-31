package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

// migrateHKDFSalt domain-separates the migration KDF from any other use of the
// server master key. §4.1.
var migrateHKDFSalt = []byte("shadowlink-migrate-v1")

// DeriveServerPerClientKey derives a 32-byte per-client key from the server
// master key via HKDF-SHA256 (salt fixed, info = clientID). Deterministic and
// stateless — the server recomputes it on the fly, storing no per-client
// secret (§4.1, F2).
func DeriveServerPerClientKey(serverMasterKey []byte, clientID string) []byte {
	r := hkdf.New(sha256.New, serverMasterKey, migrateHKDFSalt, []byte(clientID))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF-Expand over SHA-256 for 32 bytes cannot fail in practice; return
		// zeros so a downstream VerifyStreamProof fails closed rather than panic.
		return make([]byte, 32)
	}
	return out
}

// ComputeStreamProof = HMAC-SHA256(perClientKey, clientID ‖ globalStreamID(2 BE)
// ‖ session_nonce(16)). This is the 32-byte proofToken the client presents in
// MIGRATE/RESUME (§3.3, §4.1).
func ComputeStreamProof(perClientKey []byte, clientID string, globalStreamID uint16, nonce [16]byte) [32]byte {
	mac := hmac.New(sha256.New, perClientKey)
	mac.Write([]byte(clientID))
	var idBuf [2]byte
	binary.BigEndian.PutUint16(idBuf[:], globalStreamID)
	mac.Write(idBuf[:])
	mac.Write(nonce[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// VerifyStreamProof recomputes the proof and compares in constant time
// (crypto/hmac.Equal — F12; NEVER bytes.Equal).
func VerifyStreamProof(received [32]byte, perClientKey []byte, clientID string, globalStreamID uint16, nonce [16]byte) bool {
	expected := ComputeStreamProof(perClientKey, clientID, globalStreamID, nonce)
	return hmac.Equal(received[:], expected[:])
}

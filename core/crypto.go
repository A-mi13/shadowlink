package core

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
)

// timeNow is swappable for deterministic testing.
var timeNow = func() int64 { return time.Now().Unix() }

// TimeNowUnix returns the current Unix timestamp via the same indirection as the
// encryption path. Exposed for callers in other packages (e.g. ReplayCache users
// in server/handler.go) so tests can consistently freeze time across the codebase.
func TimeNowUnix() int64 { return timeNow() }

// HandshakeDriftWindowSecs is the allowed |now - ts| wall-clock skew for a
// ClientHello timestamp (operational freshness, NOT anti-replay by itself —
// replay is enforced by ReplayCache). M3 (2026-06-11): named so the server boot
// validation can require ReplayCacheWindow >= this window (replay defence is only
// as wide as min(drift, cache-window) AND requires the cache entry to survive the
// whole drift window). Value 300s is the current production window and is
// DELIBERATELY KEPT (owner decision 2026-06-11) — this change only extracts the
// former hardcoded 300 into a named constant so the boot enforcement (T7) and the
// replay-cache window are bound to one source of truth. No behaviour change: a
// client with up to 5 min clock drift still authenticates.
const HandshakeDriftWindowSecs int64 = 300

// ZeroBytes securely zeroes a byte slice (for key material cleanup).
// A1-H3 fix: runtime.KeepAlive prevents the compiler from eliminating the zeroing
// loop as a dead store (the slice is "used" after the loop from the compiler's perspective).
// Mirrors the bufpool.PutBufferZero pattern.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(&b)
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
//	info: "shadowlink-v" || protoVersion || clientEph || serverEph || clientID
//
// The protoVersion byte is included in HKDF info so that v0 and v1 keys byte-differ,
// defeating downgrade attacks: if a MITM strips _v from ServerHello, client and server
// end up with different keys — first post-handshake chunk fails decrypt, session dies
// without leaking the session token.
func DeriveSessionKeys(sharedSecret, clientPub, serverPub, clientID []byte, protoVersion uint8) (*SessionKeys, error) {
	// Safe concat — never mutate input slices
	salt := make([]byte, 0, len(clientPub)+len(serverPub))
	salt = append(salt, clientPub...)
	salt = append(salt, serverPub...)

	// info binds the proto version so v0 and v1 produce byte-different keys (spec §3.5 HKDF binding)
	prefix := []byte("shadowlink-v")
	info := make([]byte, 0, len(prefix)+1+len(clientPub)+len(serverPub)+len(clientID))
	info = append(info, prefix...)
	info = append(info, protoVersion)
	info = append(info, clientPub...)
	info = append(info, serverPub...)
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
// Output is deterministic in size: nonce(24) + ts(8) + len_prefix(1) + clientID(≤255) + MAC(16).
// For UUID-sized (16-byte) client IDs this yields exactly EncryptedClientIDSize bytes.
// Caller-level random padding is added in the wire format after this ciphertext (no length prefix
// in the frame — per DPI-evasion design; parser uses EncryptedClientIDSize to delimit the field).
//
// A1-M4 fix: rejects clientID lengths > 16 to prevent silent decryption failures.
// `EncryptedClientIDSize=65` is sized for a 16-byte UUID; longer IDs overflow the slot,
// causing ParseHandshakePayload to truncate the ciphertext and fail box.Open with an
// opaque "decryption failed" error. Production clientID format `user_<id>` fits within
// 16 bytes for any 10-digit user_id and remains supported.
func EncryptClientID(clientID, receiverPub []byte, sender *KeyPair) ([]byte, error) {
	if len(clientID) > 16 {
		return nil, fmt.Errorf("ShadowLink: client_id не должен превышать 16 байт, получено %d", len(clientID))
	}

	// plaintext = ts(8 BE) || 1-byte length prefix || clientID
	plaintext := make([]byte, 8+1+len(clientID))
	// A1-M3 fix: zero plaintext copy after box.Seal — it contained the unencrypted clientID
	// and timestamp, which qualify as sensitive metadata.
	defer ZeroBytes(plaintext)
	binary.BigEndian.PutUint64(plaintext[0:8], uint64(timeNow()))
	plaintext[8] = byte(len(clientID))
	copy(plaintext[9:], clientID)

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	var pubKey, privKey [32]byte
	copy(pubKey[:], receiverPub)
	copy(privKey[:], sender.Private)

	encrypted := box.Seal(nonce[:], plaintext, &nonce, &pubKey, &privKey)
	return encrypted, nil
}

// DecryptClientID decrypts a client ID encrypted with EncryptClientID.
// Rejects handshakes where |now - ts| > ±300s (HandshakeDriftWindowSecs) —
// operational freshness, not anti-replay by itself (replay protection).
//
// Wall-clock dependency (final audit 2026-05-03 T1 P3): the 300s drift check
// uses `time.Now().Unix()` on both client and server. This is wall-clock,
// NOT monotonic — `time.Now().Unix()` strips the monotonic component by
// design (it must produce a "seconds since epoch" value comparable across
// hosts). Operational implications:
//
//   - If the server wall clock jumps backwards (NTP step, container snapshot
//     restore, virt-host pause/resume), recently-issued legitimate handshakes
//     may fall outside the window and be rejected with "handshake timestamp
//     expired".
//   - If the client wall clock drifts >5min from the server, every handshake
//     fails with the same error.
//   - This is NOT an active-attack vector — replay protection is enforced
//     separately by `ReplayCache.Accept(encClientID, ts)` in
//     server/handler.go; the 300s window is operational expiry, not anti-
//     replay-by-itself.
//
// Ops runbook should pin chrony / require NTP sync on both server and client
// hosts. A monotonic-clock alternative is not viable here because the
// timestamp travels across the wire and is compared between two hosts —
// monotonic clocks are only meaningful within a single process.
func DecryptClientID(encrypted, senderPub []byte, receiver *KeyPair) ([]byte, error) {
	// Final audit 2026-05-03 T1 P3 fix: enforce wire-frozen ciphertext slot
	// size on decode. EncryptedClientIDSize=65 is the protocol-fixed length
	// (nonce(24) + ts(8) + len_prefix(1) + UUID(16) + Poly1305 MAC(16)). Encode
	// rejects clientID > 16 (line 139), but decode previously only checked
	// `idLen != 16` after box.Open succeeded. A malformed wire frame whose
	// ciphertext happens to round-trip to a 16-byte payload but whose outer
	// length differs from 65 would slip past — closing the asymmetry here at
	// the boundary, before invoking the AEAD primitive.
	if len(encrypted) != EncryptedClientIDSize {
		return nil, errors.New("invalid encrypted clientID size")
	}
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

	if len(decrypted) < 9 {
		return nil, errors.New("invalid plaintext: too short")
	}

	ts := int64(binary.BigEndian.Uint64(decrypted[0:8]))
	if diff := timeNow() - ts; diff > HandshakeDriftWindowSecs || diff < -HandshakeDriftWindowSecs {
		return nil, errors.New("handshake timestamp expired")
	}

	idLen := int(decrypted[8])
	// A1-M4 fix (decode side): reject ciphertexts whose embedded length byte
	// disagrees with the protocol-fixed 16-byte UUID. Encode rejects len > 16
	// (line 139), but the prior decode accepted any idLen ≤ len(decrypted)-9
	// — leaving an asymmetry where a malformed/truncated frame could decode
	// to a non-canonical clientID. EncryptedClientIDSize=65 is sized exactly
	// for a 16-byte payload (handshake.go:11-16); any other length means the
	// wire was tampered with or the encoder dropped its own invariant.
	if idLen != 16 {
		return nil, errors.New("invalid clientID size")
	}
	if idLen > len(decrypted)-9 {
		return nil, errors.New("invalid padding")
	}
	return decrypted[9 : 9+idLen], nil
}

package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// Chunk flags per spec section 3.
const (
	FlagData       byte = 0x01
	FlagAck        byte = 0x02
	FlagPadding    byte = 0x03
	FlagKeepalive  byte = 0x04
	FlagFin        byte = 0x05
	FlagControl    byte = 0x06
	FlagConnect    byte = 0x07 // payload = target address "host:port"
	FlagUDP        byte = 0x08 // payload = [StreamID(2)] + [UDP data]
	FlagStreamOpen   byte = 0x09 // client requests a streaming POST response (server→client download channel)
	FlagWindowUpdate byte = 0x0A // payload = [StreamID(2)] + [delta(4)] per-stream flow-control credit
)

const (
	NonceSize  = 12        // AES-GCM nonce
	HeaderSize = 4 + 4 + 1 // sess_id(4) + seq_num(4) + flags(1)
	TagSize    = 16        // AES-GCM authentication tag
	MinChunk   = NonceSize + HeaderSize + TagSize
)

// Chunk is the unified wire format for ShadowLink.
// Entire chunk (including sess_id, seq_num) is encrypted with AES-256-GCM.
// sess_id is encrypted in the plaintext; different sessions use different keys, making AAD unnecessary.
type Chunk struct {
	SessionID uint32
	SeqNum    uint32
	Flags     byte
	Payload   []byte
}

// Encrypt serializes and encrypts the chunk using AES-256-GCM.
// Nonce = random(12).
// Returns: nonce(12) + ciphertext_with_tag.
func (c *Chunk) Encrypt(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Build plaintext: sess_id(4) + seq_num(4) + flags(1) + payload
	plaintext := make([]byte, HeaderSize+len(c.Payload))
	binary.BigEndian.PutUint32(plaintext[0:4], c.SessionID)
	binary.BigEndian.PutUint32(plaintext[4:8], c.SeqNum)
	plaintext[8] = c.Flags
	copy(plaintext[HeaderSize:], c.Payload)

	// Nonce: fully random 12 bytes — no metadata in cleartext.
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// No AAD — the session key itself provides session binding.
	// Different sessions have different keys, so cross-session replay
	// is impossible. This avoids leaking any metadata in cleartext.
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Output: nonce(12) + ciphertext_with_tag
	out := make([]byte, NonceSize+len(ciphertext))
	copy(out[:NonceSize], nonce)
	copy(out[NonceSize:], ciphertext)
	return out, nil
}

// EncryptWith serializes and encrypts the chunk using a pre-cached AES-256-GCM cipher.
// This avoids re-creating aes.NewCipher + cipher.NewGCM on every call.
// Nonce format: counter(8 bytes big-endian) + random(4 bytes).
// Returns: nonce(12) + ciphertext_with_tag.
func (c *Chunk) EncryptWith(gcm cipher.AEAD, nonceCounter uint64) ([]byte, error) {
	// Build plaintext: sess_id(4) + seq_num(4) + flags(1) + payload
	ptSize := HeaderSize + len(c.Payload)
	// Use pooled buffer for common sizes; fall back to heap for oversized chunks.
	var ptBuf []byte
	if ptSize <= tierSizes[len(tierSizes)-1] {
		ptBuf = GetBuffer(ptSize) // cap == tier size, safe to slice to ptSize
	} else {
		ptBuf = make([]byte, ptSize)
	}
	plaintext := ptBuf[:ptSize]
	binary.BigEndian.PutUint32(plaintext[0:4], c.SessionID)
	binary.BigEndian.PutUint32(plaintext[4:8], c.SeqNum)
	plaintext[8] = c.Flags
	copy(plaintext[HeaderSize:], c.Payload)

	// Nonce: counter(8 bytes big-endian) + random(4 bytes) — stack-allocated.
	var nonce [NonceSize]byte
	binary.BigEndian.PutUint64(nonce[:8], nonceCounter)
	if _, err := rand.Read(nonce[8:]); err != nil {
		PutBufferZero(ptBuf)
		return nil, err
	}

	out := make([]byte, NonceSize, NonceSize+ptSize+gcm.Overhead())
	copy(out, nonce[:])
	out = gcm.Seal(out, nonce[:], plaintext, nil)

	// Zero and return plaintext buffer (contained unencrypted data).
	PutBufferZero(ptBuf)
	return out, nil
}

// DecryptWith decrypts and deserializes an encrypted chunk using a pre-cached GCM cipher.
// Wire format is the same as DecryptChunk: nonce(12) + ciphertext_with_tag.
func DecryptWith(data []byte, gcm cipher.AEAD) (*Chunk, error) {
	if len(data) < MinChunk {
		return nil, fmt.Errorf("chunk too short: %d < %d", len(data), MinChunk)
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if len(plaintext) < HeaderSize {
		return nil, errors.New("plaintext too short")
	}

	return &Chunk{
		SessionID: binary.BigEndian.Uint32(plaintext[0:4]),
		SeqNum:    binary.BigEndian.Uint32(plaintext[4:8]),
		Flags:     plaintext[8],
		Payload:   plaintext[HeaderSize:],
	}, nil
}

// DecryptChunk decrypts and deserializes an encrypted chunk.
func DecryptChunk(data, key []byte) (*Chunk, error) {
	if len(data) < MinChunk {
		return nil, errors.New("chunk too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if len(plaintext) < HeaderSize {
		return nil, errors.New("plaintext too short")
	}

	return &Chunk{
		SessionID: binary.BigEndian.Uint32(plaintext[0:4]),
		SeqNum:    binary.BigEndian.Uint32(plaintext[4:8]),
		Flags:     plaintext[8],
		Payload:   plaintext[HeaderSize:],
	}, nil
}

// NewDataChunk creates a data chunk with the given payload (StreamID=0, legacy).
func NewDataChunk(sessID, seq uint32, payload []byte) *Chunk {
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagData, Payload: payload}
}

// NewStreamDataChunk creates a data chunk for a specific stream.
// Payload format: [StreamID(2 bytes)] + [actual data]
//
// The returned Chunk.Payload uses a pooled backing array. After encrypting
// the chunk, callers MUST release it with core.PutBuffer(chunk.Payload).
// cap(chunk.Payload) is a pool tier size, which PutBuffer requires.
func NewStreamDataChunk(sessID, seq uint32, streamID uint16, payload []byte) *Chunk {
	pSize := 2 + len(payload)
	pBuf := GetBuffer(pSize) // cap == tier size (512/4096/16384/65536)
	p := pBuf[:pSize]        // correct length; cap still == tier size
	binary.BigEndian.PutUint16(p[0:2], streamID)
	copy(p[2:], payload)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagData, Payload: p}
}

// NewStreamConnectChunk creates a CONNECT chunk for a specific stream.
// Payload format: [StreamID(2 bytes)] + [target "host:port"]
func NewStreamConnectChunk(sessID, seq uint32, streamID uint16, target string) *Chunk {
	p := make([]byte, 2+len(target))
	binary.BigEndian.PutUint16(p[0:2], streamID)
	copy(p[2:], target)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagConnect, Payload: p}
}

// NewStreamFinChunk creates a FIN chunk to close a specific stream.
func NewStreamFinChunk(sessID, seq uint32, streamID uint16) *Chunk {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p[0:2], streamID)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagFin, Payload: p}
}

// NewSessionFinChunk creates a session-wide FIN chunk that tears down the whole
// session, not a single stream.
//
// Wire contract: the server's handleFinChunk routes by payload length —
// len(payload) >= 2 is a per-stream FIN (streamID = payload[0:2]); a shorter
// payload is session-wide. We therefore emit an EMPTY payload so the server
// runs handleFin (Remove session + ActiveClients--) immediately rather than
// handleStreamFin (which would only close stream 0 and leave the session to
// linger until its idle timeout). This is the constructor that actually
// releases a server session — NewStreamFinChunk(...,0) does NOT, because its
// 2-byte streamID lands on the per-stream branch.
func NewSessionFinChunk(sessID, seq uint32) *Chunk {
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagFin, Payload: nil}
}

// ParseStreamID extracts StreamID from payload (first 2 bytes).
// Returns streamID=0 if payload too short (legacy chunks).
func ParseStreamID(payload []byte) (streamID uint16, data []byte) {
	if len(payload) < 2 {
		return 0, payload
	}
	return binary.BigEndian.Uint16(payload[0:2]), payload[2:]
}

// NewWindowUpdateChunk creates a per-stream flow-control credit update.
// Payload format: [StreamID(2 BE)] + [delta(4 BE)]. delta is the additive
// number of bytes the receiver has consumed since its last update (HTTP/2
// WINDOW_UPDATE semantics — always positive, never absolute).
func NewWindowUpdateChunk(sessID, seq uint32, streamID uint16, delta uint32) *Chunk {
	p := make([]byte, 6)
	binary.BigEndian.PutUint16(p[0:2], streamID)
	binary.BigEndian.PutUint32(p[2:6], delta)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagWindowUpdate, Payload: p}
}

// ParseWindowUpdate extracts stream ID and credit delta from a window-update
// payload. Returns an error (never panics) on a payload shorter than 6 bytes.
func ParseWindowUpdate(payload []byte) (streamID uint16, delta uint32, err error) {
	if len(payload) < 6 {
		return 0, 0, fmt.Errorf("window update payload too short: %d < 6", len(payload))
	}
	streamID = binary.BigEndian.Uint16(payload[0:2])
	delta = binary.BigEndian.Uint32(payload[2:6])
	return streamID, delta, nil
}

// NewUDPDataChunk creates a UDP data chunk.
// Payload format: [StreamID(2)] + [AddrLen(2)] + [Addr(var)] + [Data]
func NewUDPDataChunk(sessID, seq uint32, streamID uint16, addr string, data []byte) *Chunk {
	addrBytes := []byte(addr)
	p := make([]byte, 2+2+len(addrBytes)+len(data))
	binary.BigEndian.PutUint16(p[0:2], streamID)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(addrBytes)))
	copy(p[4:4+len(addrBytes)], addrBytes)
	copy(p[4+len(addrBytes):], data)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagUDP, Payload: p}
}

// BuildUDPChunkPayload builds the raw payload for a UDP data chunk (no Chunk wrapper).
// Format: [StreamID(2)] + [AddrLen(2)] + [Addr(var)] + [Data]
// Used by SplitHTTP download stream where the Chunk wrapper + encryption is done later.
func BuildUDPChunkPayload(streamID uint16, addr string, data []byte) []byte {
	addrBytes := []byte(addr)
	p := make([]byte, 2+2+len(addrBytes)+len(data))
	binary.BigEndian.PutUint16(p[0:2], streamID)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(addrBytes)))
	copy(p[4:4+len(addrBytes)], addrBytes)
	copy(p[4+len(addrBytes):], data)
	return p
}

// ParseUDPChunk extracts stream ID, target address, and data from a UDP chunk payload.
func ParseUDPChunk(payload []byte) (streamID uint16, addr string, data []byte, err error) {
	if len(payload) < 4 {
		return 0, "", nil, errors.New("UDP chunk payload too short")
	}
	streamID = binary.BigEndian.Uint16(payload[0:2])
	addrLen := binary.BigEndian.Uint16(payload[2:4])
	if len(payload) < int(4+addrLen) {
		return 0, "", nil, fmt.Errorf("UDP chunk payload truncated: need %d, have %d", 4+addrLen, len(payload))
	}
	addr = string(payload[4 : 4+addrLen])
	data = payload[4+addrLen:]
	return streamID, addr, data, nil
}

// NewPaddingChunk creates a padding chunk with random data of the given size.
func NewPaddingChunk(sessID, seq uint32, size int) (*Chunk, error) {
	padding := make([]byte, size)
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagPadding, Payload: padding}, nil
}

// NewKeepaliveChunk creates a keepalive (heartbeat) chunk.
func NewKeepaliveChunk(sessID, seq uint32) *Chunk {
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagKeepalive, Payload: nil}
}

// NewConnectChunk creates a connect chunk (legacy, StreamID=0).
// Delegates to NewStreamConnectChunk so the payload format matches
// ParseStreamID expectations on the server side.
func NewConnectChunk(sessID, seq uint32, target string) *Chunk {
	return NewStreamConnectChunk(sessID, seq, 0, target)
}

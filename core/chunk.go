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
	FlagData         byte = 0x01
	FlagAck          byte = 0x02
	FlagPadding      byte = 0x03
	FlagKeepalive    byte = 0x04
	FlagFin          byte = 0x05
	FlagControl      byte = 0x06
	FlagConnect      byte = 0x07 // payload = target address "host:port"
	FlagUDP          byte = 0x08 // payload = [StreamID(2)] + [UDP data]
	FlagStreamOpen   byte = 0x09 // client requests a streaming POST response (server→client download channel)
	FlagWindowUpdate byte = 0x0A // payload = [StreamID(2)] + [delta(4)] per-stream flow-control credit
	FlagMigrate      byte = 0x0B // payload = [globalStreamID(2 BE)] + [proof(32)] — preemptive migration (§3.2)
	FlagResume       byte = 0x0C // payload = [globalStreamID(2 BE)] + [proof(32)] — reactive resume from grace
	FlagStreamAck    byte = 0x0D // payload = [globalStreamID(2 BE)] + [ackedDownSeq(8 BE)] — reassembler barrier (§3.3)
	FlagStreamClose  byte = 0x0E // payload = [globalStreamID(2 BE)] — origin закрылся, стрим завершён (Bug #10)
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

// EncryptWith serializes and encrypts the chunk using a pre-cached AES-256-GCM
// cipher with NO associated data (the legacy v0/v1 contract). This avoids
// re-creating aes.NewCipher + cipher.NewGCM on every call.
// Nonce format: counter(8 BE) ‖ zero(4). Returns: nonce(12) + ciphertext_with_tag.
func (c *Chunk) EncryptWith(gcm cipher.AEAD, nonceCounter uint64) ([]byte, error) {
	return c.EncryptWithAAD(gcm, nonceCounter, nil)
}

// EncryptWithAAD is EncryptWith with explicit associated data (M2, 2026-06-11,
// GATED). aad==nil reproduces the legacy wire/AEAD context byte-for-byte
// (EncryptWith delegates here with nil). A non-nil aad — produced by buildAEAD
// for protoVersion>=2 — binds the chunk to its direction+version so it cannot be
// reflected across the send/recv boundary; the AAD is authenticated but NOT
// transmitted, so the wire size is unchanged. The peer MUST Open with the
// identical aad or gcm.Open fails.
func (c *Chunk) EncryptWithAAD(gcm cipher.AEAD, nonceCounter uint64, aad []byte) ([]byte, error) {
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

	// Nonce: counter(8 BE) ‖ zero(4). L1 (2026-06-11): a monotonic 64-bit counter
	// already guarantees per-key uniqueness (rekey at ~2^32 well before wrap);
	// the former random 4-byte tail added no uniqueness and cost a crypto/rand
	// syscall on the hot path. Deterministic 12-byte nonce, trivially auditable.
	// WIRE-COMPAT: receiver reads 12 bytes regardless.
	var nonce [NonceSize]byte
	binary.BigEndian.PutUint64(nonce[:8], nonceCounter)
	// nonce[8:12] stays zero — no rand.Read.

	out := make([]byte, NonceSize, NonceSize+ptSize+gcm.Overhead())
	copy(out, nonce[:])
	out = gcm.Seal(out, nonce[:], plaintext, aad)

	// Zero and return plaintext buffer (contained unencrypted data).
	PutBufferZero(ptBuf)
	return out, nil
}

// DecryptWith decrypts and deserializes an encrypted chunk using a pre-cached GCM
// cipher with NO associated data (legacy v0/v1). Wire format is the same as
// DecryptChunk: nonce(12) + ciphertext_with_tag.
func DecryptWith(data []byte, gcm cipher.AEAD) (*Chunk, error) {
	return DecryptWithAAD(data, gcm, nil)
}

// DecryptWithAAD is DecryptWith with explicit associated data (M2, 2026-06-11,
// GATED). aad==nil reproduces the legacy contract (DecryptWith delegates here
// with nil). The aad MUST match what the sender passed to EncryptWithAAD or
// gcm.Open fails — that is the mechanism that makes the direction+version bind
// cryptographic for protoVersion>=2.
func DecryptWithAAD(data []byte, gcm cipher.AEAD, aad []byte) (*Chunk, error) {
	if len(data) < MinChunk {
		return nil, fmt.Errorf("chunk too short: %d < %d", len(data), MinChunk)
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
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

// NewStreamDataChunkSeq creates a data chunk carrying a per-stream monotonic
// downlink sequence number (Bug #9 §3.1, F1). Payload format:
//   [StreamID(2 BE)] + [downSeq(8 BE)] + [data]
//
// downSeq is assigned by the SERVER relay-loop (relayEntry.downSeqCounter,
// §5.1) and survives slot migration — it is the ordering key the client-side
// reassembler uses (§5.4). downSeq==0 is RESERVED for control chunks
// (CONNECT_OK/FAIL) which use the legacy NewStreamDataChunk; the first real
// data chunk is downSeq==1 (NEW-2).
//
// Like NewStreamDataChunk the returned Payload uses a pooled backing array;
// callers MUST release it via core.PutBuffer(chunk.Payload) after encrypting.
func NewStreamDataChunkSeq(sessID, seq uint32, streamID uint16, downSeq uint64, payload []byte) *Chunk {
	pSize := 2 + 8 + len(payload)
	pBuf := GetBuffer(pSize)
	p := pBuf[:pSize]
	binary.BigEndian.PutUint16(p[0:2], streamID)
	binary.BigEndian.PutUint64(p[2:10], downSeq)
	copy(p[10:], payload)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagData, Payload: p}
}

// ParseStreamDataSeq extracts streamID, downSeq and data from a seq-format
// data payload (§3.1). Errors (never panics) on payload shorter than 10 bytes
// — the client guard MUST reject such frames rather than misparse them as the
// legacy [StreamID(2)]+[data] format (NEW-2, see ws_pool guard <10).
func ParseStreamDataSeq(payload []byte) (streamID uint16, downSeq uint64, data []byte, err error) {
	if len(payload) < 10 {
		return 0, 0, nil, fmt.Errorf("seq data payload too short: %d < 10", len(payload))
	}
	streamID = binary.BigEndian.Uint16(payload[0:2])
	downSeq = binary.BigEndian.Uint64(payload[2:10])
	return streamID, downSeq, payload[10:], nil
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

// BuildMigrateFrame builds the payload for a FlagMigrate / FlagResume control
// chunk: [globalStreamID(2 BE)] + [proof(32)]. proof is an opaque HMAC token
// (see core/migrate.go); this function does not interpret it. §3.3.
func BuildMigrateFrame(streamID uint16, proof [32]byte) []byte {
	p := make([]byte, 2+32)
	binary.BigEndian.PutUint16(p[0:2], streamID)
	copy(p[2:], proof[:])
	return p
}

// ParseMigrateFrame extracts streamID and proof from a FlagMigrate/FlagResume
// payload. Errors (never panics) on payload shorter than 34 bytes.
func ParseMigrateFrame(payload []byte) (streamID uint16, proof [32]byte, err error) {
	if len(payload) < 34 {
		return 0, proof, fmt.Errorf("migrate frame too short: %d < 34", len(payload))
	}
	streamID = binary.BigEndian.Uint16(payload[0:2])
	copy(proof[:], payload[2:34])
	return streamID, proof, nil
}

// BuildStreamAckFrame builds the payload for a FlagStreamAck chunk:
// [globalStreamID(2 BE)] + [ackedDownSeq(8 BE)]. §3.3.
func BuildStreamAckFrame(streamID uint16, ackedDownSeq uint64) []byte {
	p := make([]byte, 2+8)
	binary.BigEndian.PutUint16(p[0:2], streamID)
	binary.BigEndian.PutUint64(p[2:10], ackedDownSeq)
	return p
}

// ParseStreamAckFrame extracts streamID and ackedDownSeq from a FlagStreamAck
// payload. Errors (never panics) on payload shorter than 10 bytes.
func ParseStreamAckFrame(payload []byte) (streamID uint16, ackedDownSeq uint64, err error) {
	if len(payload) < 10 {
		return 0, 0, fmt.Errorf("stream ack frame too short: %d < 10", len(payload))
	}
	streamID = binary.BigEndian.Uint16(payload[0:2])
	ackedDownSeq = binary.BigEndian.Uint64(payload[2:10])
	return streamID, ackedDownSeq, nil
}

// NewStreamCloseChunk creates a per-stream close control chunk (Bug #10): the
// origin (server↔destination TCP) for this stream died, so the stream is over.
// Payload format: [globalStreamID(2 BE)]. The client tears the stream down and
// hands EOF to the app (which then retries). NOT session-wide (unlike FlagFin).
func NewStreamCloseChunk(sessID, seq uint32, streamID uint16) *Chunk {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p[0:2], streamID)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagStreamClose, Payload: p}
}

// ParseStreamCloseFrame extracts the globalStreamID from a FlagStreamClose
// payload. Errors (never panics) on payload shorter than 2 bytes.
func ParseStreamCloseFrame(payload []byte) (streamID uint16, err error) {
	if len(payload) < 2 {
		return 0, fmt.Errorf("stream close frame too short: %d < 2", len(payload))
	}
	return binary.BigEndian.Uint16(payload[0:2]), nil
}

// ───────────────────────────────────────────────────────────────────────────
// MIGRATE/RESUME server reply convention (§3.4, Bug #9 Task 11).
//
// The server replies to a client MIGRATE/RESUME on the NEW slot using the SAME
// flag it received (FlagMigrate → MIGRATE_OK/FAIL, FlagResume → RESUME_OK/FAIL).
// The reply payload's FIRST byte is a status discriminator so the client can
// tell OK from FAIL without a second flag:
//
//	OK   : [status=0x01][globalStreamID(2 BE)][resumeDownSeq(8 BE)]   (11 bytes)
//	FAIL : [status=0x00][globalStreamID(2 BE)][reasonCode(1)]         (4 bytes)
//
// resumeDownSeq is the highest downSeq the server assigned BEFORE the binding
// switched — the client waits for the old slot's in-flight tail up to this seq,
// then accepts data from the new slot as continuous (§3.4). The client parser
// (Task 15) reads byte 0 to branch. RESUME_OK's bufferedFromSeq (§3.4) is folded
// into resumeDownSeq here for v1 — Task 15 may split it if the reassembler needs
// it separately; documented so the convention is unambiguous now.
const (
	MigrateReplyFail byte = 0x00
	MigrateReplyOK   byte = 0x01
)

// MIGRATE/RESUME failure reason codes (§3.4). Short codes keep the reply
// indistinguishable in length across reasons and feed the metric/log labels.
const (
	MigrateReasonNotFound     byte = 0x01
	MigrateReasonBadProof     byte = 0x02
	MigrateReasonGraceExpired byte = 0x03
	MigrateReasonLimit        byte = 0x04
	MigrateReasonDestClosed   byte = 0x05
)

// BuildMigrateOK builds the OK reply payload: [0x01][streamID(2)][resumeDownSeq(8)].
func BuildMigrateOK(streamID uint16, resumeDownSeq uint64) []byte {
	p := make([]byte, 1+2+8)
	p[0] = MigrateReplyOK
	binary.BigEndian.PutUint16(p[1:3], streamID)
	binary.BigEndian.PutUint64(p[3:11], resumeDownSeq)
	return p
}

// BuildMigrateFail builds the FAIL reply payload: [0x00][streamID(2)][reason(1)].
func BuildMigrateFail(streamID uint16, reason byte) []byte {
	p := make([]byte, 1+2+1)
	p[0] = MigrateReplyFail
	binary.BigEndian.PutUint16(p[1:3], streamID)
	p[3] = reason
	return p
}

// ParseMigrateReply parses a MIGRATE/RESUME reply payload. ok reports the
// status byte; on ok it returns streamID + resumeDownSeq; on !ok it returns
// streamID + reason in the resumeDownSeq's low byte position via reason.
// Errors (never panics) on a malformed/short payload.
func ParseMigrateReply(payload []byte) (ok bool, streamID uint16, resumeDownSeq uint64, reason byte, err error) {
	if len(payload) < 4 {
		return false, 0, 0, 0, fmt.Errorf("migrate reply too short: %d < 4", len(payload))
	}
	switch payload[0] {
	case MigrateReplyOK:
		if len(payload) < 11 {
			return false, 0, 0, 0, fmt.Errorf("migrate OK reply too short: %d < 11", len(payload))
		}
		streamID = binary.BigEndian.Uint16(payload[1:3])
		resumeDownSeq = binary.BigEndian.Uint64(payload[3:11])
		return true, streamID, resumeDownSeq, 0, nil
	case MigrateReplyFail:
		streamID = binary.BigEndian.Uint16(payload[1:3])
		return false, streamID, 0, payload[3], nil
	default:
		return false, 0, 0, 0, fmt.Errorf("migrate reply: unknown status byte 0x%02x", payload[0])
	}
}

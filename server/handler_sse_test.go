package server

import (
	"encoding/base64"
	"encoding/binary"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// testSessionPair creates a sender+receiver session pair for encrypt/decrypt roundtrip.
func testSessionPair(t *testing.T) (sender *core.Session, receiver *core.Session) {
	t.Helper()
	sm := core.NewSessionManager(5 * time.Minute)
	sendKey := make([]byte, 32)
	sendKey[0] = 0xAA
	recvKey := make([]byte, 32)
	recvKey[0] = 0xBB

	sender, err := sm.Create(sendKey, recvKey)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err = sm.Create(recvKey, sendKey)
	if err != nil {
		t.Fatal(err)
	}
	return sender, receiver
}

// TestWriteFrameBinaryRoundtrip verifies the length-prefixed binary frame
// format used by the SplitHTTP download stream:
//
//	[4-byte big-endian length][encrypted chunk bytes]
//
// The reader in client/split_transport.go parses exactly this shape. The
// test used to expect an SSE framing (data: <base64>\n\n), but the transport
// moved to the binary XHTTP pattern so CF CDN passes frames through without
// applying SSE line-based buffering.
func TestWriteFrameBinaryRoundtrip(t *testing.T) {
	sender, receiver := testSessionPair(t)
	rec := httptest.NewRecorder()
	frameBuf := make([]byte, 4+32*1024)

	payload := []byte("hello world test data")
	if err := writeFrame(rec, rec, sender, core.FlagData, payload, frameBuf); err != nil {
		t.Fatalf("writeFrame failed: %v", err)
	}

	body := rec.Body.Bytes()
	if len(body) < 4 {
		t.Fatalf("body too short: %d bytes", len(body))
	}
	frameLen := binary.BigEndian.Uint32(body[:4])
	if int(frameLen) != len(body)-4 {
		t.Fatalf("length prefix %d does not match body payload %d", frameLen, len(body)-4)
	}

	chunk, err := receiver.DecryptChunkSafe(body[4:])
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if chunk.Flags != core.FlagData {
		t.Errorf("expected FlagData, got %d", chunk.Flags)
	}
	if string(chunk.Payload) != string(payload) {
		t.Errorf("payload mismatch: got %q, want %q", chunk.Payload, payload)
	}
}

// TestWriteFrameBinaryLargePayload verifies frames with a full-chunk payload
// still fit in a single write with a length prefix, and that the prefix
// precisely describes the encrypted body so the reader never over- or
// under-reads.
func TestWriteFrameBinaryLargePayload(t *testing.T) {
	sender, receiver := testSessionPair(t)
	rec := httptest.NewRecorder()
	frameBuf := make([]byte, 4+32*1024)

	payload := make([]byte, 12288)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	if err := writeFrame(rec, rec, sender, core.FlagData, payload, frameBuf); err != nil {
		t.Fatal(err)
	}

	body := rec.Body.Bytes()
	if len(body) < 4 {
		t.Fatalf("body too short: %d", len(body))
	}
	frameLen := int(binary.BigEndian.Uint32(body[:4]))
	if frameLen != len(body)-4 {
		t.Fatalf("length prefix %d vs body payload %d", frameLen, len(body)-4)
	}
	// Encrypted chunk carries AES-GCM nonce (12) + ciphertext (plaintext + 9 header) + tag (16).
	// No SSE wrapper, no base64 — the reader consumes raw bytes.
	chunk, err := receiver.DecryptChunkSafe(body[4 : 4+frameLen])
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if len(chunk.Payload) != len(payload) {
		t.Errorf("payload length mismatch: got %d, want %d", len(chunk.Payload), len(payload))
	}
}

// _ keeps the base64 import used by adjacent tests in the package — removing
// it would break them if this file were compiled in isolation.
var _ = base64.RawStdEncoding

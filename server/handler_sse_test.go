package server

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
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

func TestWriteFrameSSE(t *testing.T) {
	sender, receiver := testSessionPair(t)

	rec := httptest.NewRecorder()

	payload := []byte("hello world test data")
	b64Buf := make([]byte, base64.RawStdEncoding.EncodedLen(32*1024))

	err := writeFrameSSE(rec, rec, sender, core.FlagData, payload, b64Buf)
	if err != nil {
		t.Fatalf("writeFrameSSE failed: %v", err)
	}

	body := rec.Body.String()

	if !strings.HasPrefix(body, "data: ") {
		t.Errorf("SSE frame must start with 'data: ', got: %q", body[:min(len(body), 20)])
	}
	if !strings.HasSuffix(body, "\n\n") {
		t.Errorf("SSE frame must end with '\\n\\n', got suffix: %q", body[max(0, len(body)-10):])
	}

	b64str := strings.TrimPrefix(body, "data: ")
	b64str = strings.TrimSuffix(b64str, "\n\n")

	encrypted, err := base64.RawStdEncoding.DecodeString(b64str)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	chunk, err := receiver.DecryptChunkSafe(encrypted)
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

func TestWriteFrameSSENoNewlines(t *testing.T) {
	sender, _ := testSessionPair(t)
	rec := httptest.NewRecorder()
	b64Buf := make([]byte, base64.RawStdEncoding.EncodedLen(32*1024))

	payload := make([]byte, 12288)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	err := writeFrameSSE(rec, rec, sender, core.FlagData, payload, b64Buf)
	if err != nil {
		t.Fatal(err)
	}

	body := rec.Body.String()
	lines := strings.Split(body, "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines (data + 2 empty), got %d: %v", len(lines), lines)
	}
}

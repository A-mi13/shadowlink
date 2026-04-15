package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// testSessionPair creates sender+receiver sessions for encrypt/decrypt roundtrip.
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

// mockSSEStream builds an SSE byte stream from encrypted frames.
func mockSSEStream(session *core.Session, payloads [][]byte) []byte {
	var buf bytes.Buffer
	for _, payload := range payloads {
		chunk := &core.Chunk{
			SessionID: session.ID,
			SeqNum:    session.NextSeqNum(),
			Flags:     core.FlagData,
			Payload:   payload,
		}
		encrypted, err := session.EncryptChunk(chunk)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(&buf, "data: %s\n\n", base64.RawStdEncoding.EncodeToString(encrypted))
	}
	return buf.Bytes()
}

func TestParseSSEFrames(t *testing.T) {
	sender, receiver := testSessionPair(t)

	// StreamID 1, payload "hello"
	payload1 := append([]byte{0, 1}, []byte("hello")...)
	// StreamID 2, payload "world"
	payload2 := append([]byte{0, 2}, []byte("world")...)

	stream := mockSSEStream(sender, [][]byte{payload1, payload2})

	// Parse using the same logic as StartReader (receiver decrypts sender's frames)
	frames := parseSSEFrames(t, receiver, bytes.NewReader(stream))
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}

	if frames[0].streamID != 1 || string(frames[0].data) != "hello" {
		t.Errorf("frame 0: streamID=%d data=%q", frames[0].streamID, frames[0].data)
	}
	if frames[1].streamID != 2 || string(frames[1].data) != "world" {
		t.Errorf("frame 1: streamID=%d data=%q", frames[1].streamID, frames[1].data)
	}
}

func TestParseSSEWithKeepalive(t *testing.T) {
	sender, receiver := testSessionPair(t)

	var buf bytes.Buffer

	// ACK frame (no meaningful payload)
	ack := &core.Chunk{SessionID: sender.ID, SeqNum: sender.NextSeqNum(), Flags: core.FlagAck}
	encrypted, _ := sender.EncryptChunk(ack)
	fmt.Fprintf(&buf, "data: %s\n\n", base64.RawStdEncoding.EncodeToString(encrypted))

	// SSE comment (should be ignored)
	buf.WriteString(": keepalive\n\n")

	// Real data frame
	payload := append([]byte{0, 5}, []byte("data")...)
	dataChunk := &core.Chunk{SessionID: sender.ID, SeqNum: sender.NextSeqNum(), Flags: core.FlagData, Payload: payload}
	enc2, _ := sender.EncryptChunk(dataChunk)
	fmt.Fprintf(&buf, "data: %s\n\n", base64.RawStdEncoding.EncodeToString(enc2))

	frames := parseSSEFrames(t, receiver, bytes.NewReader(buf.Bytes()))
	if len(frames) != 1 {
		t.Fatalf("expected 1 data frame (ACK skipped), got %d", len(frames))
	}
	if frames[0].streamID != 5 {
		t.Errorf("expected streamID=5, got %d", frames[0].streamID)
	}
}

type parsedFrame struct {
	streamID uint16
	data     []byte
	flags    byte
}

// parseSSEFrames extracts decrypted frames from an SSE byte stream for testing.
func parseSSEFrames(t *testing.T, receiver *core.Session, r io.Reader) []parsedFrame {
	t.Helper()
	var frames []parsedFrame
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		b64data := line[6:]
		encrypted, err := base64.RawStdEncoding.DecodeString(b64data)
		if err != nil {
			continue
		}
		chunk, err := receiver.DecryptChunkSafe(encrypted)
		if err != nil {
			continue
		}
		if len(chunk.Payload) < 2 {
			continue
		}
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])
		frames = append(frames, parsedFrame{
			streamID: streamID,
			data:     chunk.Payload[2:],
			flags:    chunk.Flags,
		})
	}
	return frames
}

// Ensure context import is used (referenced by StartReader signature).
var _ = context.Background

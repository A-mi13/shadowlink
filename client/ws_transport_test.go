package client

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// TestUpgradeToWS_NoAuthHeader guards the D3 migration: the WebSocket upgrade
// request must not carry an Authorization header, and instead the client must
// immediately send a binary first frame whose base64-decoded payload starts
// with the session token.
func TestUpgradeToWS_NoAuthHeader(t *testing.T) {
	var gotAuth string
	firstFrameCh := make(chan []byte, 1)
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade failed: %v", err)
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		mt, frame, err := c.ReadMessage()
		if err != nil {
			t.Logf("read first frame: %v", err)
			firstFrameCh <- nil
			return
		}
		if mt != websocket.BinaryMessage {
			t.Logf("first frame not binary: mt=%d", mt)
		}
		firstFrameCh <- frame
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	wst := NewWebSocketTransport(addr, false, true)

	// Fake but self-consistent session: its own keys make EncryptChunk work.
	token := make([]byte, 36)
	for i := range token {
		token[i] = byte(i + 1)
	}
	session := core.NewSession(11, make([]byte, 32), make([]byte, 32))

	if err := wst.UpgradeToWS(token, session); err != nil {
		t.Fatalf("UpgradeToWS: %v", err)
	}
	defer wst.Close()

	select {
	case frame := <-firstFrameCh:
		if frame == nil {
			t.Fatal("server failed to read first frame")
		}
		if !bytes.HasPrefix(frame, token) {
			t.Errorf("first frame does not start with session token; got prefix %x", frame[:minInt(len(frame), len(token))])
		}
		if len(frame) <= len(token) {
			t.Errorf("first frame has no encrypted chunk after token (len=%d)", len(frame))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for first frame on server")
	}

	if gotAuth != "" {
		t.Errorf("upgrade request still carries Authorization header: %q", gotAuth)
	}
}

// TestUpgradeToWS_NilSessionErrors guards the fast-fail path added in D3.
func TestUpgradeToWS_NilSessionErrors(t *testing.T) {
	wst := NewWebSocketTransport("127.0.0.1:1", false, true)
	err := wst.UpgradeToWS(make([]byte, 36), nil)
	if err == nil {
		t.Fatal("expected error when session is nil")
	}
}

// TestBuildFirstFramePayload_Shape verifies the wire format of the first-frame
// payload: [token][encrypted FlagKeepalive chunk], consumable by ParseDataPayload.
func TestBuildFirstFramePayload_Shape(t *testing.T) {
	wst := NewWebSocketTransport("127.0.0.1:1", false, true)
	token := make([]byte, 36)
	for i := range token {
		token[i] = byte(42 + i)
	}
	session := core.NewSession(7, make([]byte, 32), make([]byte, 32))

	payload, err := wst.buildFirstFramePayload(token, session, 0)
	if err != nil {
		t.Fatalf("buildFirstFramePayload: %v", err)
	}
	gotToken, gotChunk, err := browser.ParseDataPayload(payload, len(token))
	if err != nil {
		t.Fatalf("ParseDataPayload: %v", err)
	}
	if !bytes.Equal(gotToken, token) {
		t.Errorf("token mismatch")
	}
	if len(gotChunk) == 0 {
		t.Errorf("encrypted chunk is empty")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestHandler(t *testing.T) (*Handler, *core.KeyPair) {
	t.Helper()
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	config := TestConfig()
	h := NewHandler(serverKey, config, "")
	return h, serverKey
}

func TestUnauthenticatedGETReturnsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(w, r)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "under construction")
	assert.Equal(t, "nginx/1.27.3", w.Header().Get("Server"))
}

func TestUnauthenticatedPOSTNonJSONReturnsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "text/plain")
	h.ServeHTTP(w, r)

	// Decoy serves the root page (under construction) or 404 for non-root
	assert.Less(t, w.Code, 500, "should not return server error")
}

func TestInvalidJSONReturnsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events",
		bytes.NewReader([]byte(`{"invalid":"not shadowlink format"}`)))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	// Should return decoy, not error
	assert.Less(t, w.Code, 500)
}

func TestHandshakeCreatesSession(t *testing.T) {
	h, serverKey := setupTestHandler(t)

	// Build ClientHello
	clientHello, _, err := core.NewClientHello([]byte("test-client"), serverKey.Public)
	require.NoError(t, err)

	// Encode as "encrypted chunk": ephPub(32) + encClientID
	payload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "init", "ts": 1234, "data": encodedPayload},
		},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	// No Authorization header = handshake
	h.ServeHTTP(w, r)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, 1, h.SessionCount())

	// Response should be valid JSON with ServerHello data
	var resp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp["status"])
}

func TestHandshakeWrongKeyReturnsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	// Use wrong server key for ClientHello
	wrongKey, _ := core.GenerateKeyPair()
	clientHello, _, _ := core.NewClientHello([]byte("client"), wrongKey.Public)

	payload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "init", "ts": 1234, "data": encodedPayload},
		},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	// Should look like decoy, not reveal we're a proxy
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, 0, h.SessionCount())
}

func TestCoverTrafficTreatedAsNormalChunk(t *testing.T) {
	h, _ := setupTestHandler(t)

	// C3 fix: cover traffic now carries encrypted padding, indistinguishable from data.
	// Without a valid session, it falls through to decoy (like any invalid chunk).
	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "session_ping", "ts": 1234, "data": "ZW5jcnlwdGVkLXBhZGRpbmc"},
		},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString([]byte("some-token-value")))
	h.ServeHTTP(w, r)

	// Without valid session token, server returns decoy (not crash)
	assert.Less(t, w.Code, 500)
}

func TestMaxClientsEnforced(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	h.config.MaxClients = 2

	// Create 2 sessions
	for i := range 2 {
		clientHello, _, _ := core.NewClientHello([]byte(fmt.Sprintf("client-%d", i)), serverKey.Public)
		payload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
		encoded := base64.RawURLEncoding.EncodeToString(payload)

		body, _ := json.Marshal(map[string]any{
			"events": []map[string]any{{"type": "init", "ts": 1234, "data": encoded}},
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)
		assert.Equal(t, 200, w.Code)
	}
	assert.Equal(t, 2, h.SessionCount())

	// 3rd should be rejected
	clientHello, _, _ := core.NewClientHello([]byte("client-overflow"), serverKey.Public)
	payload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encoded := base64.RawURLEncoding.EncodeToString(payload)

	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "init", "ts": 1234, "data": encoded}},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	// I6 fix: return decoy (200) instead of 503 to avoid revealing capacity limits
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, 2, h.SessionCount(), "3rd client should NOT create a session")
}

func TestFullHandshakeAndDataTransfer(t *testing.T) {
	h, serverKey := setupTestHandler(t)

	// === HANDSHAKE ===
	clientHello, clientState, err := core.NewClientHello([]byte("user-42"), serverKey.Public)
	require.NoError(t, err)

	helloPayload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encoded := base64.RawURLEncoding.EncodeToString(helloPayload)

	helloBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "init", "ts": 1234, "data": encoded}},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(helloBody))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, 200, w.Code)

	// Parse ServerHello from response
	respData, _, err := browser.ParseDownloadResponse(w.Body.Bytes())
	require.NoError(t, err)

	var shData struct {
		EphPub    []byte `json:"eph"`
		Token     []byte `json:"tok"`
		MaxConns  uint8  `json:"mc"`
		ChunkSize uint16 `json:"cs"`
	}
	require.NoError(t, json.Unmarshal(respData, &shData))

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
	}

	// Complete handshake on client side
	clientSession, err := core.CompleteHandshake(clientState, serverHello)
	require.NoError(t, err)

	// === DATA TRANSFER ===
	// Put some data into the tunnel's outgoing channel (simulating server-side app)
	tunnel, ok := h.GetTunnel(clientSession.ID)
	require.True(t, ok)
	go func() {
		tunnel.Outgoing <- []byte("hello from server tunnel")
	}()

	// Client sends encrypted data chunk
	vpnPayload := []byte("hello from client vpn")
	dataChunk := core.NewDataChunk(clientSession.ID, clientSession.NextSeqNum(), vpnPayload)
	encChunk, err := dataChunk.Encrypt(clientSession.SendKey)
	require.NoError(t, err)

	// Build HTTP request — use EncryptedSessionToken as Bearer token
	// (this is what findSession will try to AES-decrypt with each session's key)
	encChunkB64 := base64.RawURLEncoding.EncodeToString(encChunk)
	dataBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "data", "ts": 1234, "data": encChunkB64},
		},
	})
	dataReq := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(dataBody))
	dataReq.Header.Set("Content-Type", "application/json")
	dataReq.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(shData.Token))
	dataReq.Header.Set("X-Request-ID", fmt.Sprintf("%08x", dataChunk.SeqNum))

	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, dataReq)
	assert.Equal(t, 200, w2.Code)

	// Check client received server data in the response
	respEncrypted, _, err := browser.ParseDownloadResponse(w2.Body.Bytes())
	require.NoError(t, err)

	respChunk, err := core.DecryptChunk(respEncrypted, clientSession.RecvKey)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello from server tunnel"), respChunk.Payload)

	// Check server received client data via tunnel
	select {
	case received := <-tunnel.Incoming:
		assert.Equal(t, vpnPayload, received)
	default:
		t.Fatal("expected data in tunnel incoming channel")
	}
}

func TestActiveProbeGetsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	// Simulate various active probing techniques

	// 1. curl
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "curl/8.7.1")
	h.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "html")

	// 2. Random POST with JSON but wrong format
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/v2/events",
		bytes.NewReader([]byte(`{"test":true}`)))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	assert.Less(t, w.Code, 500)

	// 3. HEAD request
	w = httptest.NewRecorder()
	r = httptest.NewRequest("HEAD", "/", nil)
	h.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Code)

	// 4. Request to random path
	for _, path := range []string{"/robots.txt", "/favicon.ico", "/.env", "/wp-admin"} {
		w = httptest.NewRecorder()
		r = httptest.NewRequest("GET", path, nil)
		h.ServeHTTP(w, r)
		assert.Less(t, w.Code, 500, "path %s should not cause 5xx", path)
	}
}

func TestHandlerServeHTTPContentTypeCheck(t *testing.T) {
	h, _ := setupTestHandler(t)

	// POST with application/x-www-form-urlencoded → decoy
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/contact", bytes.NewReader([]byte("name=test")))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(w, r)
	// Should not crash, should serve decoy
	assert.Less(t, w.Code, 500)
}

// Helper to build a proper ShadowLink upload request body
func buildShadowLinkBody(t *testing.T, chunk []byte) io.Reader {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString(chunk)
	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "data", "ts": 1234, "data": encoded},
		},
	})
	return bytes.NewReader(body)
}

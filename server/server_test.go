package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startTestServer(t *testing.T) (*Server, *core.KeyPair) {
	t.Helper()
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	config := TestConfig()
	srv, err := New(config, serverKey)
	require.NoError(t, err)

	_, err = srv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { srv.Stop() })

	return srv, serverKey
}

func TestServerStartsAndResponds(t *testing.T) {
	srv, _ := startTestServer(t)

	// GET to root should return decoy
	resp, err := http.Get("http://" + srv.Addr() + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "under construction")
	assert.Equal(t, "nginx/1.27.3", resp.Header.Get("Server"))
}

func TestServerDecoyForMultiplePaths(t *testing.T) {
	srv, _ := startTestServer(t)

	paths := []string{"/", "/about", "/robots.txt", "/favicon.ico"}
	for _, path := range paths {
		resp, err := http.Get("http://" + srv.Addr() + path)
		require.NoError(t, err, "path: %s", path)
		resp.Body.Close()
		assert.Less(t, resp.StatusCode, 500, "path %s should not return 5xx", path)
	}
}

func TestServerHandshakeOverHTTP(t *testing.T) {
	srv, serverKey := startTestServer(t)

	clientHello, _, err := core.NewClientHello([]byte("integration-test"), serverKey.Public)
	require.NoError(t, err)

	payload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encoded := base64.RawURLEncoding.EncodeToString(payload)

	reqBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "init", "ts": time.Now().UnixMilli(), "data": encoded},
		},
	})

	resp, err := http.Post("http://"+srv.Addr()+"/api/v2/events",
		"application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, 1, srv.SessionCount())

	body, _ := io.ReadAll(resp.Body)
	var respJSON map[string]any
	require.NoError(t, json.Unmarshal(body, &respJSON))
	assert.Equal(t, "ok", respJSON["status"])
}

func TestServerFullCycle(t *testing.T) {
	srv, serverKey := startTestServer(t)
	baseURL := "http://" + srv.Addr()

	// === HANDSHAKE ===
	clientHello, clientState, err := core.NewClientHello([]byte("full-cycle-test!"), serverKey.Public)
	require.NoError(t, err)

	helloPayload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encoded := base64.RawURLEncoding.EncodeToString(helloPayload)

	helloBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "init", "ts": 1234, "data": encoded}},
	})

	resp, err := http.Post(baseURL+"/api/v2/events", "application/json", bytes.NewReader(helloBody))
	require.NoError(t, err)
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	// Parse ServerHello
	respData, _, err := browser.ParseDownloadResponse(respBody)
	require.NoError(t, err)

	var shData struct {
		EphPub       []byte `json:"eph"`
		Token        []byte `json:"tok"`
		MaxConns     uint8  `json:"mc"`
		ChunkSize    uint16 `json:"cs"`
		ProtoVersion *uint8 `json:"_v"`
	}
	require.NoError(t, json.Unmarshal(respData, &shData))

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		ProtoVersion:          shData.ProtoVersion,
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
	}

	clientSession, err := core.CompleteHandshake(clientState, serverHello)
	require.NoError(t, err)

	// === SEND DATA ===
	// Put data in server tunnel outgoing
	tunnel, ok := srv.Handler().GetTunnel(clientSession.ID)
	require.True(t, ok)
	go func() {
		tunnel.Outgoing <- []byte("server-response-data")
	}()

	// Client sends data chunk
	vpnData := []byte("client-vpn-packet-12345")
	chunk := core.NewDataChunk(clientSession.ID, clientSession.NextSeqNum(), vpnData)
	encChunk, err := chunk.Encrypt(clientSession.SendKey)
	require.NoError(t, err)

	// Body-prefix wire format: pack token-with-hint + encrypted chunk into body.
	tokenWithHint := browser.EncodeTokenWithHint(clientSession.ID, shData.Token)
	dataPayload := browser.BuildDataPayload(tokenWithHint, encChunk)
	encB64 := base64.RawURLEncoding.EncodeToString(dataPayload)
	dataBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "data", "ts": 1234, "data": encB64}},
	})

	req, _ := http.NewRequest("POST", baseURL+"/api/v2/events", bytes.NewReader(dataBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", fmt.Sprintf("%08x", chunk.SeqNum))

	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp2Body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	require.Equal(t, 200, resp2.StatusCode)

	// Decrypt server response
	respEncrypted, _, err := browser.ParseDownloadResponse(resp2Body)
	require.NoError(t, err)

	respChunk, err := core.DecryptChunk(respEncrypted, clientSession.RecvKey)
	require.NoError(t, err)
	assert.Equal(t, []byte("server-response-data"), respChunk.Payload)

	// Verify server received client data
	select {
	case received := <-tunnel.Incoming:
		assert.Equal(t, vpnData, received)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for client data in tunnel")
	}
}

func TestServerGracefulShutdown(t *testing.T) {
	serverKey, _ := core.GenerateKeyPair()
	config := TestConfig()
	srv, err := New(config, serverKey)
	require.NoError(t, err)

	_, err = srv.Start()
	require.NoError(t, err)
	addr := srv.Addr()

	// Verify it's responding
	resp, err := http.Get("http://" + addr + "/")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	// Shutdown
	err = srv.Stop()
	require.NoError(t, err)

	// Should no longer respond
	_, err = http.Get("http://" + addr + "/")
	assert.Error(t, err)
}

// TestServer_DefaultMaxDevices_AppliedWithoutMgmt covers A3-S-MED-4 closure:
// when the operator sets DefaultMaxDevices but NOT ManagementPort, the value
// must still propagate into clientAuth.defaultMax. Earlier the override was
// gated behind the management API config, which silently dropped the limit.
func TestServer_DefaultMaxDevices_AppliedWithoutMgmt(t *testing.T) {
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig()
	cfg.ManagementPort = 0 // mgmt API disabled
	cfg.ManagementKey = ""
	cfg.DefaultMaxDevices = 5

	srv, err := New(cfg, serverKey)
	require.NoError(t, err)

	_, err = srv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { srv.Stop() })

	assert.Equal(t, 5, srv.Handler().clientAuth.defaultMax,
		"DefaultMaxDevices must apply regardless of management API state (A3-S-MED-4)")
}

func TestServerMaxClientsOverHTTP(t *testing.T) {
	srv, serverKey := startTestServer(t)
	srv.config.MaxClients = 1
	// Need to set it on the handler too
	srv.Handler().config.MaxClients = 1

	baseURL := "http://" + srv.Addr()

	// First handshake — ok
	ch1, _, _ := core.NewClientHello([]byte("c1-uuid-padding!"), serverKey.Public)
	p1 := append(ch1.EphemeralPub, ch1.EncryptedClientID...)
	b1, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "init", "ts": 1, "data": base64.RawURLEncoding.EncodeToString(p1)}},
	})
	resp1, _ := http.Post(baseURL+"/api/v2/events", "application/json", bytes.NewReader(b1))
	resp1.Body.Close()
	assert.Equal(t, 200, resp1.StatusCode)

	// Second handshake — should be 503
	ch2, _, _ := core.NewClientHello([]byte("c2-uuid-padding!"), serverKey.Public)
	p2 := append(ch2.EphemeralPub, ch2.EncryptedClientID...)
	b2, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "init", "ts": 1, "data": base64.RawURLEncoding.EncodeToString(p2)}},
	})
	resp2, _ := http.Post(baseURL+"/api/v2/events", "application/json", bytes.NewReader(b2))
	resp2.Body.Close()
	// I6 fix: decoy (200) instead of 503 to avoid revealing capacity
	assert.Equal(t, 200, resp2.StatusCode)
}

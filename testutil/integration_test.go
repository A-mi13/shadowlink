package testutil

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupE2E(t *testing.T) (*server.Server, *client.Client) {
	t.Helper()
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	config := server.TestConfig()
	srv, err := server.New(config, serverKey)
	require.NoError(t, err)
	_, err = srv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { srv.Stop() })

	cl := client.NewClient(client.ClientConfig{
		ServerAddr:   srv.Addr(),
		ServerPubKey: serverKey.Public,
		ClientID:     []byte("e2e-test"),
		UseTLS:       false,
	})
	t.Cleanup(func() { cl.Close() })

	err = cl.Connect(context.Background())
	require.NoError(t, err)

	return srv, cl
}

// T1.1
func TestE2E_HandshakeCompletes(t *testing.T) {
	_, cl := setupE2E(t)
	assert.True(t, cl.Connected())
	assert.NotEqual(t, uint32(0), cl.SessionID())
}

// T1.2
func TestE2E_DataTransfer100Chunks(t *testing.T) {
	srv, cl := setupE2E(t)
	tunnel, ok := srv.Handler().GetTunnel(cl.SessionID())
	require.True(t, ok)

	for i := range 100 {
		payload := make([]byte, 1024)
		for j := range payload {
			payload[j] = byte(i + j)
		}

		go func() { tunnel.Outgoing <- []byte("ack") }()
		resp, err := cl.Send(context.Background(), payload)
		require.NoError(t, err, "chunk %d", i)
		assert.Equal(t, []byte("ack"), resp)

		received := <-tunnel.Incoming
		assert.Equal(t, payload, received, "chunk %d mismatch", i)
	}
}

// T1.3
func TestE2E_ChunksCorrectOrder(t *testing.T) {
	srv, cl := setupE2E(t)
	tunnel, _ := srv.Handler().GetTunnel(cl.SessionID())

	for i := range 50 {
		data := []byte{byte(i)}
		go func(v byte) { tunnel.Outgoing <- []byte{v} }(byte(i))
		resp, err := cl.Send(context.Background(), data)
		require.NoError(t, err)
		assert.Equal(t, data, (<-tunnel.Incoming), "chunk %d", i)
		assert.Equal(t, []byte{byte(i)}, resp)
	}
}

// T1.5
func TestE2E_Keepalive(t *testing.T) {
	_, cl := setupE2E(t)
	for range 5 {
		ok, err := cl.SendKeepalive(context.Background())
		require.NoError(t, err)
		assert.True(t, ok)
	}
}

// T1.8
func TestE2E_DecoyForUnauthenticated(t *testing.T) {
	srv, _ := setupE2E(t)
	resp, err := http.Get("http://" + srv.Addr() + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "under construction")
	assert.Equal(t, "nginx/1.27.3", resp.Header.Get("Server"))
}

// T2.4
func TestE2E_DPI16KBThreshold(t *testing.T) {
	serverKey, _ := core.GenerateKeyPair()
	srvConfig := server.TestConfig()
	srv, _ := server.New(srvConfig, serverKey)
	srv.Start()
	defer srv.Stop()

	dpi := NewDPIEmulator("127.0.0.1:0", srv.Addr())
	dpi.ByteLimit = 16384
	dpiAddr, err := dpi.Start()
	require.NoError(t, err)
	defer dpi.Stop()

	cl := client.NewClient(client.ClientConfig{
		ServerAddr:   dpiAddr,
		ServerPubKey: serverKey.Public,
		ClientID:     []byte("dpi-test"),
		UseTLS:       false,
	})
	defer cl.Close()

	err = cl.Connect(context.Background())
	require.NoError(t, err, "handshake should pass (< 16KB)")

	tunnel, ok := srv.Handler().GetTunnel(cl.SessionID())
	require.True(t, ok)

	successCount := 0
	for i := range 20 {
		go func() { tunnel.Outgoing <- []byte("ok") }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := cl.Send(ctx, []byte("small"))
		cancel()
		if err == nil {
			successCount++
		} else {
			t.Logf("chunk %d failed: %v", i, err)
		}
	}

	assert.GreaterOrEqual(t, successCount, 10,
		"most chunks should pass (each conn < 16KB)")
	t.Logf("DPI: conns=%d frozen=%d", dpi.TotalConns.Load(), dpi.FrozenConns.Load())
}

// Destination routing: ConnectToStream to public server
func TestE2E_DestinationRouting(t *testing.T) {
	serverKey, _ := core.GenerateKeyPair()
	srvConfig := server.TestConfig()
	srv, _ := server.New(srvConfig, serverKey)
	srv.Start()
	defer srv.Stop()

	cl := client.NewClient(client.ClientConfig{
		ServerAddr:   srv.Addr(),
		ServerPubKey: serverKey.Public,
		ClientID:     []byte("routing-test"),
		UseTLS:       false,
	})
	defer cl.Close()
	err := cl.Connect(context.Background())
	require.NoError(t, err)

	// Register stream and connect to a public HTTP server (example.com:80)
	var streamID uint16 = 1
	ch, err := cl.RegisterStream(streamID)
	require.NoError(t, err)
	defer cl.UnregisterStream(streamID)

	err = cl.ConnectToStream(context.Background(), streamID, "93.184.216.34:80")
	if err != nil {
		t.Skipf("cannot reach external server: %v", err)
	}

	// Send HTTP request through tunnel via stream API
	httpReq := []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
	err = cl.SendStream(context.Background(), streamID, httpReq)
	require.NoError(t, err)

	// Poll for response — server returns data only when it has arrived from target.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			cl.PollStreams(ctx)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Read response from stream channel
	select {
	case resp := <-ch:
		assert.Contains(t, string(resp), "HTTP/1.", "should get HTTP response from example.com")
	case <-ctx.Done():
		t.Skip("timeout reaching example.com — network may be unavailable")
	}
}

// Destination routing: SSRF protection blocks localhost
func TestE2E_DestinationRoutingSSRFBlocked(t *testing.T) {
	serverKey, _ := core.GenerateKeyPair()
	srvConfig := server.TestConfig()
	srv, _ := server.New(srvConfig, serverKey)
	srv.Start()
	defer srv.Stop()

	cl := client.NewClient(client.ClientConfig{
		ServerAddr:   srv.Addr(),
		ServerPubKey: serverKey.Public,
		ClientID:     []byte("ssrf-test"),
		UseTLS:       false,
	})
	defer cl.Close()
	cl.Connect(context.Background())

	// SSRF: try to connect to localhost — should be BLOCKED
	err := cl.ConnectTo(context.Background(), "127.0.0.1:5432")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONNECT_FAIL")

	// SSRF: try AWS metadata
	err = cl.ConnectTo(context.Background(), "169.254.169.254:80")
	require.Error(t, err)

	// SSRF: try private network
	err = cl.ConnectTo(context.Background(), "10.0.0.1:22")
	require.Error(t, err)
}

// Destination routing: connect to invalid target
func TestE2E_DestinationRoutingBadTarget(t *testing.T) {
	serverKey, _ := core.GenerateKeyPair()
	srvConfig := server.TestConfig()
	srv, _ := server.New(srvConfig, serverKey)
	srv.Start()
	defer srv.Stop()

	cl := client.NewClient(client.ClientConfig{
		ServerAddr:   srv.Addr(),
		ServerPubKey: serverKey.Public,
		ClientID:     []byte("bad-target-test"),
		UseTLS:       false,
	})
	defer cl.Close()
	cl.Connect(context.Background())

	// Connect to non-existent target
	err := cl.ConnectTo(context.Background(), "127.0.0.1:1")
	assert.Error(t, err, "should fail connecting to closed port")
	assert.Contains(t, err.Error(), "CONNECT_FAIL")
}

// T2.10
func TestE2E_EntropyIsBase64Range(t *testing.T) {
	encrypted := make([]byte, 1000)
	for i := range encrypted {
		encrypted[i] = byte(i * 7)
	}
	b64 := []byte(base64.RawURLEncoding.EncodeToString(encrypted))
	entropy := AnalyzeEntropy(b64)
	t.Logf("base64 entropy: %.2f bits/byte", entropy)
	assert.Greater(t, entropy, 5.0)
	assert.Less(t, entropy, 7.0)
}

// T2.14
func TestE2E_CurlGetsDecoy(t *testing.T) {
	srv, _ := setupE2E(t)
	resp, err := http.Get("http://" + srv.Addr() + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "html")
	assert.NotContains(t, string(body), "shadowlink")
}

// T2.16
func TestE2E_InvalidTokenGetsNonError(t *testing.T) {
	srv, _ := setupE2E(t)
	reqBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "data", "ts": 1234, "data": base64.RawURLEncoding.EncodeToString([]byte("fake"))},
		},
	})
	req, _ := http.NewRequest("POST", "http://"+srv.Addr()+"/api/v2/events",
		bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid-token")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Less(t, resp.StatusCode, 500, "should not return 5xx")
}

// DPI emulator unit tests

func TestDPIEmulatorProxy(t *testing.T) {
	echoLn := startEchoServer(t)
	dpi := NewDPIEmulator("127.0.0.1:0", echoLn.Addr().String())
	dpiAddr, err := dpi.Start()
	require.NoError(t, err)
	defer dpi.Stop()

	conn, err := net.DialTimeout("tcp", dpiAddr, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	conn.Write([]byte("hello"))
	buf := make([]byte, 100)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	assert.Equal(t, "hello", string(buf[:n]))

	assert.Greater(t, dpi.TotalConns.Load(), int64(0))
}

func TestAnalyzeEntropy(t *testing.T) {
	same := make([]byte, 100)
	assert.InDelta(t, 0.0, AnalyzeEntropy(same), 0.01)

	varied := make([]byte, 256)
	for i := range varied {
		varied[i] = byte(i)
	}
	assert.Greater(t, AnalyzeEntropy(varied), 7.0)

	assert.Equal(t, 0.0, AnalyzeEntropy(nil))
}

func TestComputeSizeStats(t *testing.T) {
	stats := ComputeSizeStats([]int{100, 200, 300, 400, 500})
	assert.Equal(t, 100, stats.Min)
	assert.Equal(t, 500, stats.Max)
	assert.InDelta(t, 300.0, stats.Mean, 0.1)
	assert.Equal(t, 0, ComputeSizeStats(nil).Count)
}

// --- helpers ---

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln
}

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/server"
	"github.com/nixavpn/shadowlink/skins/browser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startServer(t *testing.T) (*server.Server, *core.KeyPair) {
	t.Helper()
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	config := server.TestConfig()
	srv, err := server.New(config, serverKey)
	require.NoError(t, err)

	_, err = srv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { srv.Stop() })

	return srv, serverKey
}

func TestDirectTransportHandshake(t *testing.T) {
	srv, serverKey := startServer(t)
	transport := NewDirectTransport(srv.Addr(), false, false)
	defer transport.Close()

	clientHello, clientState, err := core.NewClientHello([]byte("transport-test"), serverKey.Public)
	require.NoError(t, err)

	respBody, err := transport.SendHandshake(context.Background(), clientHello)
	require.NoError(t, err)

	// Parse ServerHello from response
	respData, _, err := browser.ParseDownloadResponse(respBody)
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

	// Client should be able to complete handshake
	session, err := core.CompleteHandshake(clientState, serverHello)
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.NotEqual(t, uint32(0), session.ID)
}

func TestDirectTransportSendChunk(t *testing.T) {
	srv, serverKey := startServer(t)
	transport := NewDirectTransport(srv.Addr(), false, false)
	defer transport.Close()

	// Handshake first
	clientHello, clientState, _ := core.NewClientHello([]byte("chunk-test"), serverKey.Public)
	respBody, err := transport.SendHandshake(context.Background(), clientHello)
	require.NoError(t, err)

	respData, _, _ := browser.ParseDownloadResponse(respBody)
	var shData struct {
		EphPub    []byte `json:"eph"`
		Token     []byte `json:"tok"`
		MaxConns  uint8  `json:"mc"`
		ChunkSize uint16 `json:"cs"`
	}
	json.Unmarshal(respData, &shData)

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		
	}
	clientSession, _ := core.CompleteHandshake(clientState, serverHello)

	// Put data in server's outgoing tunnel
	tunnel, _ := srv.Handler().GetTunnel(clientSession.ID)
	go func() { tunnel.Outgoing <- []byte("server-data") }()

	// Send encrypted chunk
	chunk := core.NewDataChunk(clientSession.ID, clientSession.NextSeqNum(), []byte("client-data"))
	encChunk, _ := chunk.Encrypt(clientSession.SendKey)

	encResp, err := transport.SendChunk(context.Background(), encChunk, shData.Token, chunk.SeqNum)
	require.NoError(t, err)

	// Decrypt response
	respChunk, err := core.DecryptChunk(encResp, clientSession.RecvKey)
	require.NoError(t, err)
	assert.Equal(t, []byte("server-data"), respChunk.Payload)

	// Verify server got client data
	select {
	case data := <-tunnel.Incoming:
		assert.Equal(t, []byte("client-data"), data)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for data")
	}
}

func TestDirectTransportName(t *testing.T) {
	tr := NewDirectTransport("localhost:443", false, false)
	assert.Equal(t, "direct", tr.Name())
	tr.Close()
}

func TestCDNTransportName(t *testing.T) {
	tr := NewCDNTransport("api.example.com")
	assert.Equal(t, "cdn", tr.Name())
	tr.Close()
}

func TestDirectTransportWrongServer(t *testing.T) {
	transport := NewDirectTransport("127.0.0.1:1", false, false)
	defer transport.Close()

	kp, _ := core.GenerateKeyPair()
	hello, _, _ := core.NewClientHello([]byte("test"), kp.Public)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := transport.SendHandshake(ctx, hello)
	assert.Error(t, err, "connecting to closed port should fail")
}

// Helper to test that handshake result is valid
func completeHandshake(t *testing.T, respBody []byte, clientState *core.HandshakeClientState) (*core.Session, []byte) {
	t.Helper()
	respData, _, err := browser.ParseDownloadResponse(respBody)
	require.NoError(t, err)

	var shData struct {
		EphPub    []byte `json:"eph"`
		Token     []byte `json:"tok"`
	}
	require.NoError(t, json.Unmarshal(respData, &shData))

	session, err := core.CompleteHandshake(clientState, &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		
	})
	require.NoError(t, err)

	return session, shData.Token
}

func TestDirectTransportMultipleChunks(t *testing.T) {
	srv, serverKey := startServer(t)
	transport := NewDirectTransport(srv.Addr(), false, false)
	defer transport.Close()

	hello, state, _ := core.NewClientHello([]byte("multi"), serverKey.Public)
	respBody, _ := transport.SendHandshake(context.Background(), hello)
	session, token := completeHandshake(t, respBody, state)

	// Send 10 chunks
	for i := range 10 {
		chunk := core.NewDataChunk(session.ID, session.NextSeqNum(), []byte("data"))
		enc, _ := chunk.Encrypt(session.SendKey)

		_, err := transport.SendChunk(context.Background(), enc, token, chunk.SeqNum)
		require.NoError(t, err, "chunk %d", i)
	}
	_ = base64.RawURLEncoding // keep import used
}

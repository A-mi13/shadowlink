package client

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupClientTest(t *testing.T) (*server.Server, *core.KeyPair, *Client) {
	t.Helper()
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	config := server.TestConfig()
	srv, err := server.New(config, serverKey)
	require.NoError(t, err)

	_, err = srv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { srv.Stop() })

	// D4: ShadowLink Phase B expects UUID-sized (16 B) clientID on the new
	// body-prefix handshake path — non-UUID IDs only land on the pre-migration
	// legacy Bearer path, which the new client no longer uses by default.
	cl := NewClient(ClientConfig{
		ServerAddr:   srv.Addr(),
		ServerPubKey: serverKey.Public,
		ClientID:     []byte("test-client-uuid"), // 16 bytes
		UseTLS:       false,
	})
	t.Cleanup(func() { cl.Close() })

	return srv, serverKey, cl
}

func TestClientConnect(t *testing.T) {
	_, _, cl := setupClientTest(t)

	assert.False(t, cl.Connected())
	assert.Equal(t, uint32(0), cl.SessionID())

	err := cl.Connect(context.Background())
	require.NoError(t, err)

	assert.True(t, cl.Connected())
	assert.NotEqual(t, uint32(0), cl.SessionID())
	assert.Equal(t, "direct", cl.TransportName())
}

func TestClientSendReceive(t *testing.T) {
	srv, _, cl := setupClientTest(t)

	err := cl.Connect(context.Background())
	require.NoError(t, err)

	// Put data in server tunnel for client to receive
	tunnel, ok := srv.Handler().GetTunnel(cl.SessionID())
	require.True(t, ok)
	go func() {
		tunnel.Outgoing <- []byte("hello from server")
	}()

	// Client sends and receives in one round-trip
	resp, err := cl.Send(context.Background(), []byte("hello from client"))
	require.NoError(t, err)
	assert.Equal(t, []byte("hello from server"), resp)

	// Server should have received client data
	select {
	case data := <-tunnel.Incoming:
		assert.Equal(t, []byte("hello from client"), data)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for client data")
	}
}

func TestClientMultipleRoundTrips(t *testing.T) {
	srv, _, cl := setupClientTest(t)

	err := cl.Connect(context.Background())
	require.NoError(t, err)

	tunnel, _ := srv.Handler().GetTunnel(cl.SessionID())

	for i := range 10 {
		serverMsg := []byte(fmt.Sprintf("server-%d", i))
		go func() { tunnel.Outgoing <- serverMsg }()

		clientMsg := []byte(fmt.Sprintf("client-%d", i))
		resp, err := cl.Send(context.Background(), clientMsg)
		require.NoError(t, err, "round %d", i)
		assert.Equal(t, serverMsg, resp, "round %d", i)

		received := <-tunnel.Incoming
		assert.Equal(t, clientMsg, received, "round %d", i)
	}
}

func TestClientKeepalive(t *testing.T) {
	_, _, cl := setupClientTest(t)

	err := cl.Connect(context.Background())
	require.NoError(t, err)

	ok, err := cl.SendKeepalive(context.Background())
	require.NoError(t, err)
	assert.True(t, ok, "keepalive should be acknowledged")
}

func TestClientSendWithoutConnect(t *testing.T) {
	_, _, cl := setupClientTest(t)

	_, err := cl.Send(context.Background(), []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestClientClose(t *testing.T) {
	_, _, cl := setupClientTest(t)

	cl.Connect(context.Background())
	assert.True(t, cl.Connected())

	cl.Close()
	assert.False(t, cl.Connected())
}

func TestClientConnectWrongKey(t *testing.T) {
	serverKey, _ := core.GenerateKeyPair()
	wrongKey, _ := core.GenerateKeyPair()

	config := server.TestConfig()
	srv, _ := server.New(config, serverKey)
	srv.Start()
	defer srv.Stop()

	cl := NewClient(ClientConfig{
		ServerAddr:   srv.Addr(),
		ServerPubKey: wrongKey.Public, // wrong key!
		ClientID:     []byte("test"),
		UseTLS:       false,
	})
	defer cl.Close()

	err := cl.Connect(context.Background())
	assert.Error(t, err, "should fail with wrong server key")
}

// TestClientSnapshot_AtomicTokenSessionPair guards the H4 review finding:
// Snapshot must return a consistent (token, session) pair under a single
// c.mu acquisition — a caller MUST NOT observe token=set + session=nil or
// vice versa partway through Close().
func TestClientSnapshot_AtomicTokenSessionPair(t *testing.T) {
	_, _, cl := setupClientTest(t)

	// Pre-connect: both must be nil.
	tok, sess := cl.Snapshot()
	assert.Nil(t, tok, "pre-connect token must be nil")
	assert.Nil(t, sess, "pre-connect session must be nil")

	require.NoError(t, cl.Connect(context.Background()))

	// Post-connect: both must be non-nil and consistent.
	tok, sess = cl.Snapshot()
	require.NotNil(t, tok, "post-connect token must be non-nil")
	require.NotNil(t, sess, "post-connect session must be non-nil")
	assert.Equal(t, cl.SessionID(), sess.ID, "Snapshot session.ID must match Client.SessionID")
	assert.Equal(t, cl.Token(), tok, "Snapshot token must match Client.Token")
}

func TestClientWithCustomTransport(t *testing.T) {
	srv, serverKey := startServer(t)

	transport := NewDirectTransport(srv.Addr(), false, false)
	// D4: Phase B body-prefix path requires a UUID-sized clientID.
	cl := NewClientWithTransport(transport, serverKey.Public, []byte("custom-uuid-16!!"))
	defer cl.Close()

	err := cl.Connect(context.Background())
	require.NoError(t, err)
	assert.True(t, cl.Connected())
}

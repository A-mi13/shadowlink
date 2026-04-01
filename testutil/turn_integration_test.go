package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2E_TURNRelay_Handshake(t *testing.T) {
	// 1. Start ShadowLink server with UDP enabled
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	config := server.TestConfig()
	config.EnableUDP = true
	config.UDPListenAddr = "127.0.0.1:0"
	srv, err := server.New(config, serverKey)
	require.NoError(t, err)
	_, err = srv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { srv.Stop() })

	udpAddr := srv.UDPAddr()
	require.NotEmpty(t, udpAddr, "UDP listener should be running")
	t.Logf("ShadowLink UDP: %s", udpAddr)

	// 2. Start embedded TURN server
	turnSrv, err := NewTestTURNServer("127.0.0.1:0", "testuser", "testpass")
	require.NoError(t, err)
	t.Cleanup(func() { turnSrv.Close() })
	t.Logf("TURN server: %s", turnSrv.Addr())

	// 3. Create CallSkinTransport
	transport, err := client.NewCallSkinTransport(client.CallSkinConfig{
		TURNServer:    turnSrv.Addr(),
		TURNUsername:  "testuser",
		TURNPassword:  "testpass",
		ServerUDPAddr: udpAddr,
	})
	require.NoError(t, err)
	defer transport.Close()

	// 4. Connect client through TURN
	cl := client.NewClientWithTransport(transport, serverKey.Public, []byte("turn-test"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = cl.Connect(ctx)
	require.NoError(t, err, "handshake through TURN should succeed")

	assert.True(t, cl.Connected())
	assert.NotEqual(t, uint32(0), cl.SessionID())
	assert.Equal(t, "call_skin", cl.TransportName())
	t.Logf("Connected via TURN, session: %d", cl.SessionID())
}

func TestE2E_TURNRelay_DataTransfer(t *testing.T) {
	// Setup server + TURN
	serverKey, _ := core.GenerateKeyPair()
	config := server.TestConfig()
	config.EnableUDP = true
	config.UDPListenAddr = "127.0.0.1:0"
	srv, _ := server.New(config, serverKey)
	srv.Start()
	t.Cleanup(func() { srv.Stop() })

	turnSrv, _ := NewTestTURNServer("127.0.0.1:0", "test", "test")
	t.Cleanup(func() { turnSrv.Close() })

	transport, _ := client.NewCallSkinTransport(client.CallSkinConfig{
		TURNServer:    turnSrv.Addr(),
		TURNUsername:  "test",
		TURNPassword:  "test",
		ServerUDPAddr: srv.UDPAddr(),
	})
	defer transport.Close()

	cl := client.NewClientWithTransport(transport, serverKey.Public, []byte("data-test"))
	ctx := context.Background()
	require.NoError(t, cl.Connect(ctx))

	// Put data in server tunnel for response
	tunnel, ok := srv.Handler().GetTunnel(cl.SessionID())
	require.True(t, ok, "tunnel should exist")
	go func() { tunnel.Outgoing <- []byte("hello-from-server-via-turn") }()

	// Send data chunk
	resp, err := cl.Send(ctx, []byte("hello-from-client-via-turn"))
	require.NoError(t, err)
	assert.Equal(t, []byte("hello-from-server-via-turn"), resp)

	// Verify server received client data
	select {
	case data := <-tunnel.Incoming:
		assert.Equal(t, []byte("hello-from-client-via-turn"), data)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for client data in tunnel")
	}
}

func TestE2E_TURNRelay_Keepalive(t *testing.T) {
	serverKey, _ := core.GenerateKeyPair()
	config := server.TestConfig()
	config.EnableUDP = true
	config.UDPListenAddr = "127.0.0.1:0"
	srv, _ := server.New(config, serverKey)
	srv.Start()
	t.Cleanup(func() { srv.Stop() })

	turnSrv, _ := NewTestTURNServer("127.0.0.1:0", "test", "test")
	t.Cleanup(func() { turnSrv.Close() })

	transport, _ := client.NewCallSkinTransport(client.CallSkinConfig{
		TURNServer:    turnSrv.Addr(),
		TURNUsername:  "test",
		TURNPassword:  "test",
		ServerUDPAddr: srv.UDPAddr(),
	})
	defer transport.Close()

	cl := client.NewClientWithTransport(transport, serverKey.Public, []byte("keepalive-test"))
	require.NoError(t, cl.Connect(context.Background()))

	ok, err := cl.SendKeepalive(context.Background())
	require.NoError(t, err)
	assert.True(t, ok, "keepalive should return ACK")
}

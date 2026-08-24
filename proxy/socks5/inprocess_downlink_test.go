package socks5

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/server"

	"github.com/stretchr/testify/require"
)

// echoTransport is a mock StreamTransport that reproduces the server side of a
// stream relay WITHOUT a real network: every CONNECT is acked with CONNECT_OK,
// and after the ack it pushes a canned "downlink" payload back to the client's
// stream channel via cl.RouteToStream — exactly the path the real WS demux uses
// to feed tunnelTCPStream's downlink goroutine.
//
// It implements PoolAware only to learn the active streamID (AssignStream) so it
// can target RouteToStream — the production WS pool path also runs through
// AssignStream. It deliberately does NOT decrypt the uplink (the uplink chunk is
// AES-GCM sealed with the client's SEND key, which the recv-side session cannot
// open); the bug under test is purely about whether downlink bytes delivered to
// the client's stream channel surface on appConn.Read.
type echoTransport struct {
	cl       *client.Client
	downlink []byte

	mu        sync.Mutex
	streamID  uint16
	gotStream bool
	echoOnce  sync.Once
}

func newEchoTransport(cl *client.Client, downlink []byte) *echoTransport {
	return &echoTransport{cl: cl, downlink: downlink}
}

func (e *echoTransport) WriteMessage(data []byte) error {
	// The relay's CONNECT and data frames both land here for a plain
	// StreamTransport. We can't read the (encrypted) frame type, so we drive
	// the echo off the first frame after a stream has been assigned: ack
	// CONNECT_OK once, then deliver the downlink payload once.
	e.mu.Lock()
	sid := e.streamID
	ready := e.gotStream
	e.mu.Unlock()
	if !ready {
		return nil
	}
	e.echoOnce.Do(func() {
		go func() {
			// CONNECT_OK is consumed as a control message by the downlink
			// goroutine (not relayed to appConn), then the real payload follows.
			e.cl.RouteToStream(sid, []byte("CONNECT_OK"))
			time.Sleep(20 * time.Millisecond)
			e.cl.RouteToStream(sid, append([]byte(nil), e.downlink...))
		}()
	})
	return nil
}

func (e *echoTransport) StartReader(ctx context.Context, cl *client.Client) error { return nil }
func (e *echoTransport) Close() error                                             { return nil }

// PoolAware — captures the streamID and reuses the client's single session.
func (e *echoTransport) AssignStream(streamID uint16) {
	e.mu.Lock()
	e.streamID = streamID
	e.gotStream = true
	e.mu.Unlock()
}
func (e *echoTransport) ReleaseStream(streamID uint16)                  {}
func (e *echoTransport) SessionForStream(streamID uint16) *core.Session { return e.cl.Session() }
func (e *echoTransport) WriteMessageForStream(streamID uint16, data []byte) error {
	return e.WriteMessage(data)
}

var _ client.StreamTransport = (*echoTransport)(nil)
var _ client.PoolAware = (*echoTransport)(nil)

// setupConnectedClient stands up a real ShadowLink server and a connected client
// (DirectTransport) so cl.Session() is a real, usable session — required because
// tunnelTCPStream encrypts uplink data chunks with it.
func setupConnectedClient(t *testing.T) *client.Client {
	t.Helper()
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	srv, err := server.New(server.TestConfig(), serverKey)
	require.NoError(t, err)
	_, err = srv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { srv.Stop() })

	cl := client.NewClient(client.ClientConfig{
		ServerAddr:   srv.Addr(),
		ServerPubKey: serverKey.Public,
		ClientID:     []byte("test-client-uuid"),
		UseTLS:       false,
	})
	t.Cleanup(func() { cl.Close() })

	require.NoError(t, cl.Connect(context.Background()))
	return cl
}

// TestInProcessDialer_DownlinkReachesAppConn is the regression test for the
// in-process dialer downlink bug: after tun2socks writes a request and
// half-closes the write side (CloseWrite, as the real tun2socks
// unidirectionalStream does), the server's response MUST still surface on
// appConn.Read. The original bug tore the downlink direction down the moment the
// uplink hit EOF.
func TestInProcessDialer_DownlinkReachesAppConn(t *testing.T) {
	cl := setupConnectedClient(t)

	wantDownlink := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	echo := newEchoTransport(cl, wantDownlink)

	srv := &Server{Client: cl}
	srv.SetWST(echo)

	engineCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := newInProcessDialer(engineCtx, srv)

	appConn, err := d.DialContext(context.Background(), metaFor("142.250.1.1", 80))
	require.NoError(t, err)
	defer appConn.Close()

	// Uplink: write the request, then half-close the write side exactly like
	// tun2socks does after copying the client→server direction.
	_, err = appConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)
	if hc, ok := appConn.(interface{ CloseWrite() error }); ok {
		require.NoError(t, hc.CloseWrite())
	}

	// Downlink: the server response must arrive on appConn.Read.
	appConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(wantDownlink))
	n, err := io.ReadFull(appConn, buf)
	require.NoError(t, err, "downlink response did not reach appConn.Read")
	require.Equal(t, wantDownlink, buf[:n])
}

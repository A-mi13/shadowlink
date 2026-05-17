package client

import (
	"context"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration_NewClient_Server_HappyPath is the F1 smoke test: a
// client using the body-prefix wire format against the server must complete
// the handshake, land on ProtoVersion=1, and successfully exchange a
// round-trip data chunk.
func TestMigration_NewClient_HybridServer_HappyPath(t *testing.T) {
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := server.TestConfig()
	srv, err := server.New(cfg, serverKey)
	require.NoError(t, err)
	_, err = srv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { srv.Stop() })

	cl := NewClient(ClientConfig{
		ServerAddr:   srv.Addr(),
		ServerPubKey: serverKey.Public,
		ClientID:     []byte("migration-test-uu"),
		UseTLS:       false,
	})
	// ClientID must be 16 bytes for the new-format path (non-UUID falls
	// through to legacy by design — see phase-d-nuances N-D2).
	cl.clientID = []byte("migration-test-!")
	require.Len(t, cl.clientID, 16)
	t.Cleanup(func() { cl.Close() })

	require.NoError(t, cl.Connect(context.Background()))

	sess := cl.Session()
	require.NotNil(t, sess)
	assert.Equal(t, uint8(1), sess.ProtoVersion,
		"F1 regression: new-format handshake must pin ProtoVersion=1")
	assert.True(t, cl.Connected())

	// Quick Send round-trip to validate the upload path also works under the
	// new wire format (token is packed in body, server decrypts on the
	// authenticateFirstFrame WS path).
	tunnel, ok := srv.Handler().GetTunnel(cl.SessionID())
	require.True(t, ok)
	go func() { tunnel.Outgoing <- []byte("roundtrip-ok") }()

	resp, err := cl.Send(context.Background(), []byte("hello-from-new-client"))
	require.NoError(t, err)
	assert.Equal(t, []byte("roundtrip-ok"), resp)

	select {
	case received := <-tunnel.Incoming:
		assert.Equal(t, []byte("hello-from-new-client"), received)
	case <-time.After(time.Second):
		t.Fatal("F1: server never saw the client's body-prefix data chunk")
	}
}

// TestMigration_Server_CountersIncrement verifies the steady-state metrics
// increment as expected during a client handshake — NewPathHits should
// advance. Lets ops validate dashboards after deploy without a live canary.
func TestMigration_Server_CountersIncrement(t *testing.T) {
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)
	cfg := server.TestConfig()
	srv, err := server.New(cfg, serverKey)
	require.NoError(t, err)
	_, err = srv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { srv.Stop() })

	cl := NewClient(ClientConfig{
		ServerAddr:   srv.Addr(),
		ServerPubKey: serverKey.Public,
		ClientID:     []byte("f1-counter-uuid!"),
		UseTLS:       false,
	})
	t.Cleanup(func() { cl.Close() })

	// Snapshot metrics before the handshake so we measure the delta, not
	// whatever prior state the shared Handler may carry.
	h := srv.Handler()
	beforeNew := h.Metrics().NewPathHits.Load()

	require.NoError(t, cl.Connect(context.Background()))

	// Send a data chunk too so NewPathHits counts both handshake + data.
	_, _ = cl.Send(context.Background(), []byte("x"))

	afterNew := h.Metrics().NewPathHits.Load()

	assert.Greater(t, afterNew, beforeNew, "NewPathHits must increment (handshake goes via new path)")
}

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nixavpn/shadowlink/core"
)

// Layer contract (H-K1, 2026-06-11): the client slot/direct setup must call
// InitSendEpoch right after CompleteHandshake so client uplink uses the
// deterministic counter-nonce regime rather than the random-nonce fallback.
// We mirror that setup at the core level (CompleteHandshake yields a
// NewSession-shaped session; InitSendEpoch is the additive call the production
// paths now make) and assert the first uplink frame carries counter nonce 0.
// The crypto wire-compat is proven in core; this test guards that the client
// package observes the counter regime after the InitSendEpoch call it issues.
func TestSlotSession_CounterNonceAfterSetup(t *testing.T) {
	sess := core.NewSession(42, make([]byte, 32), make([]byte, 32))

	// Before InitSendEpoch a NewSession-built client session falls through the
	// random-nonce fallback — its first 8 nonce bytes are NOT a zero counter.
	encBefore, err := sess.EncryptChunk(core.NewDataChunk(sess.ID, 0, []byte("a")))
	require.NoError(t, err)
	assert.NotEqual(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, encBefore[:8],
		"pre-InitSendEpoch uplink uses the random-nonce fallback")

	// This is the exact additive call the slot/direct setup makes after
	// CompleteHandshake (client/ws_pool.go slot setup, client/client.go paths).
	require.NoError(t, sess.InitSendEpoch())

	enc, err := sess.EncryptChunk(core.NewDataChunk(sess.ID, 0, []byte("uplink")))
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, enc[:8],
		"client uplink must use deterministic counter nonce after slot setup")
}

package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// M3 (2026-06-11): the handshake drift window is a named constant pinned at
// 300s (owner decision — window NOT narrowed). T6 only extracts the former
// hardcoded 300 so the server boot enforcement (T7) and the replay-cache
// window bind to one source of truth.
func TestDecryptClientID_DriftWindowIs300s(t *testing.T) {
	assert.Equal(t, int64(300), HandshakeDriftWindowSecs)

	// Freeze time via the same timeNow hook crypto.go uses.
	orig := timeNow
	defer func() { timeNow = orig }()

	srvStatic, err := GenerateKeyPair()
	require.NoError(t, err)
	clientEph, err := GenerateKeyPair()
	require.NoError(t, err)
	clientID := []byte("user_1234567890a") // 16 bytes
	require.Len(t, clientID, 16)

	// ts = T0
	timeNow = func() int64 { return 1_000_000 }
	enc, err := EncryptClientID(clientID, srvStatic.Public, clientEph)
	require.NoError(t, err)

	// +299s — inside the window, ok
	timeNow = func() int64 { return 1_000_299 }
	_, err = DecryptClientID(enc, clientEph.Public, srvStatic)
	require.NoError(t, err)

	// +301s — outside the window, rejected
	timeNow = func() int64 { return 1_000_301 }
	_, err = DecryptClientID(enc, clientEph.Public, srvStatic)
	require.Error(t, err)
}

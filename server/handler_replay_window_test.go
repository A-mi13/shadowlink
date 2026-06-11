package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nixavpn/shadowlink/core"
)

// M3 (2026-06-11): a ReplayCacheWindow shorter than the handshake drift window
// leaves a [cacheWindow, driftWindow] gap where a captured ClientHello — still
// inside its drift window — re-decrypts AND has no surviving cache entry, so it
// is accepted as fresh. NewHandler must clamp the window UP to the drift window
// at boot so a misconfiguration cannot silently reopen the replay window.
func TestNewHandler_ReplayWindowClampedToDrift(t *testing.T) {
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig()
	cfg.ReplayCacheWindow = 30 * time.Second // < 300s drift window
	h := NewHandler(serverKey, cfg, "")

	driftWindow := time.Duration(core.HandshakeDriftWindowSecs) * time.Second
	assert.GreaterOrEqual(t, h.replayCacheWindow, driftWindow,
		"replay window must cover the drift window after boot validation")
}

// The zero-value default (5m) already covers the 300s drift window, so it must
// pass through unchanged.
func TestNewHandler_ReplayWindowDefaultUnchanged(t *testing.T) {
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig()
	// ReplayCacheWindow=0 → default 5m, which >= 300s drift → not clamped.
	h := NewHandler(serverKey, cfg, "")
	assert.Equal(t, 5*time.Minute, h.replayCacheWindow)
}

// A window already >= the drift window (but custom) must be preserved.
func TestNewHandler_ReplayWindowAboveDriftPreserved(t *testing.T) {
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig()
	cfg.ReplayCacheWindow = 10 * time.Minute // > 300s drift → kept as-is
	h := NewHandler(serverKey, cfg, "")
	assert.Equal(t, 10*time.Minute, h.replayCacheWindow)
}

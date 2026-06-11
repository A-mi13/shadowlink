package core

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// M2 (2026-06-11, GATED default-OFF): legacy protocol versions (v0/v1) must pass
// nil AAD so the wire/AEAD context is unchanged — backwards compat. AAD is only
// emitted for protoVersion >= 2, which is NOT the default and requires a lockstep
// client+server upgrade plus a two-client smoke before any default-on.
func TestAEAD_DisabledForLegacyVersions(t *testing.T) {
	assert.Nil(t, buildAEAD(0, aeadDirClientToServer))
	assert.Nil(t, buildAEAD(1, aeadDirServerToClient))
}

func TestAEAD_V2LayoutIsDirAndVersion(t *testing.T) {
	assert.Equal(t, []byte{aeadDirClientToServer, 2}, buildAEAD(2, aeadDirClientToServer))
	assert.Equal(t, []byte{aeadDirServerToClient, 3}, buildAEAD(3, aeadDirServerToClient))
}

// Under v2 AAD a chunk sealed with one direction must NOT open with the opposite
// direction — even when the AEAD key is symmetric (the test suite's common case).
// This makes direction-binding cryptographic (not by-convention) and closes the
// reflection channel.
func TestAEAD_V2DirectionMismatchFailsOpen(t *testing.T) {
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	c := &Chunk{SessionID: 1, SeqNum: 0, Flags: FlagData, Payload: []byte("p")}
	// Seal with client-direction AAD (v2).
	out, err := c.EncryptWithAAD(gcm, 0, buildAEAD(2, aeadDirClientToServer))
	require.NoError(t, err)

	// Open with the same direction — ok.
	dec, err := DecryptWithAAD(out, gcm, buildAEAD(2, aeadDirClientToServer))
	require.NoError(t, err)
	assert.Equal(t, []byte("p"), dec.Payload)

	// Open with the OPPOSITE direction (symmetric key!) — must fail (reflection
	// blocked cryptographically).
	_, err = DecryptWithAAD(out, gcm, buildAEAD(2, aeadDirServerToClient))
	assert.Error(t, err, "cross-direction reflection must fail to open under AAD")
}

// The legacy nil-AAD helpers must remain interoperable: EncryptWith == seal with
// nil AAD, and a frame sealed via EncryptWith opens via DecryptWith (regression
// guard that the *AAD delegation preserved the v0/v1 wire contract).
func TestAEAD_NilAADMatchesLegacyHelpers(t *testing.T) {
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	c := &Chunk{SessionID: 9, SeqNum: 7, Flags: FlagData, Payload: []byte("legacy")}

	legacy, err := c.EncryptWith(gcm, 5)
	require.NoError(t, err)
	viaAAD, err := c.EncryptWithAAD(gcm, 5, buildAEAD(1, aeadDirClientToServer)) // v1 → nil AAD
	require.NoError(t, err)

	// Both decrypt via the legacy DecryptWith (nil AAD).
	d1, err := DecryptWith(legacy, gcm)
	require.NoError(t, err)
	assert.Equal(t, []byte("legacy"), d1.Payload)
	d2, err := DecryptWith(viaAAD, gcm)
	require.NoError(t, err)
	assert.Equal(t, []byte("legacy"), d2.Payload)
}

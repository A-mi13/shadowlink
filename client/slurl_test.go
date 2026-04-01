package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSLURL_BasicValid(t *testing.T) {
	raw := "sl://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@example.com:8443?tls=1&ws=1&auto=1&cdn=cdn.example.com&socks=127.0.0.1:9050&ech=1&id=my-client-42"

	cfg, err := ParseSLURL(raw)
	require.NoError(t, err)

	assert.Equal(t, "example.com:8443", cfg.Server)
	assert.Equal(t, "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233", cfg.PubKey)
	assert.Equal(t, true, cfg.TLS)
	assert.Equal(t, true, cfg.WebSocket)
	assert.Equal(t, true, cfg.Auto)
	assert.Equal(t, "cdn.example.com", cfg.CDN)
	assert.Equal(t, "127.0.0.1:9050", cfg.Socks)
	assert.Equal(t, true, cfg.ECH)
	assert.Equal(t, "my-client-42", cfg.ClientID)
}

func TestParseSLURL_DefaultPort(t *testing.T) {
	raw := "sl://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@vpn.example.com?tls=1"

	cfg, err := ParseSLURL(raw)
	require.NoError(t, err)

	assert.Equal(t, "vpn.example.com:443", cfg.Server)
	assert.Equal(t, true, cfg.TLS)
	// defaults
	assert.Equal(t, "127.0.0.1:1080", cfg.Socks)
	assert.Equal(t, false, cfg.WebSocket)
	assert.Equal(t, false, cfg.Auto)
	assert.Equal(t, false, cfg.ECH)
	assert.Equal(t, "", cfg.CDN)
	assert.Equal(t, "", cfg.ClientID)
}

func TestParseSLURL_WithCDN(t *testing.T) {
	raw := "sl://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@vpn.example.com:443?cdn=cloudflare.example.com&ech=1"

	cfg, err := ParseSLURL(raw)
	require.NoError(t, err)

	assert.Equal(t, "cloudflare.example.com", cfg.CDN)
	assert.Equal(t, true, cfg.ECH)
	assert.Equal(t, "vpn.example.com:443", cfg.Server)
}

func TestParseSLURL_WithSocks(t *testing.T) {
	raw := "sl://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@vpn.example.com:443?socks=192.168.1.100:5555"

	cfg, err := ParseSLURL(raw)
	require.NoError(t, err)

	assert.Equal(t, "192.168.1.100:5555", cfg.Socks)
}

func TestParseSLURL_InvalidPubkeyTooShort(t *testing.T) {
	raw := "sl://aabbccdd@vpn.example.com:443"

	_, err := ParseSLURL(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pubkey")
}

func TestParseSLURL_InvalidPubkeyUppercase(t *testing.T) {
	raw := "sl://AABBCCDD00112233AABBCCDD00112233AABBCCDD00112233AABBCCDD00112233@vpn.example.com:443"

	_, err := ParseSLURL(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pubkey")
}

func TestParseSLURL_InvalidScheme(t *testing.T) {
	raw := "https://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@vpn.example.com:443"

	_, err := ParseSLURL(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sl://")
}

func TestParseSLURL_MalformedDoubleAt(t *testing.T) {
	raw := "sl://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@host@evil.com:443"

	_, err := ParseSLURL(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "@")
}

func TestBuildSLURL_Roundtrip(t *testing.T) {
	original := &ClientFileConfig{
		Server:    "vpn.example.com:8443",
		PubKey:    "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
		ClientID:  "device-1",
		Socks:     "127.0.0.1:1080",
		TLS:       true,
		WebSocket: true,
		Auto:      true,
		CDN:       "cdn.example.com",
		ECH:       true,
	}

	url := BuildSLURL(original)
	assert.True(t, len(url) > 0, "BuildSLURL should return non-empty string")
	assert.Contains(t, url, "sl://")

	parsed, err := ParseSLURL(url)
	require.NoError(t, err)

	assert.Equal(t, original.Server, parsed.Server)
	assert.Equal(t, original.PubKey, parsed.PubKey)
	assert.Equal(t, original.ClientID, parsed.ClientID)
	assert.Equal(t, original.TLS, parsed.TLS)
	assert.Equal(t, original.WebSocket, parsed.WebSocket)
	assert.Equal(t, original.Auto, parsed.Auto)
	assert.Equal(t, original.CDN, parsed.CDN)
	assert.Equal(t, original.ECH, parsed.ECH)
	// Socks is default, so BuildSLURL may omit it, but ParseSLURL sets default
	assert.Equal(t, original.Socks, parsed.Socks)
}

func TestBuildSLURL_OmitsDefaults(t *testing.T) {
	cfg := &ClientFileConfig{
		Server: "vpn.example.com:443",
		PubKey: "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
		Socks:  "127.0.0.1:1080",
		TLS:    true,
	}

	url := BuildSLURL(cfg)
	// Should not contain socks param (it's the default)
	assert.NotContains(t, url, "socks=")
	// Should not contain ws, auto, ech, cdn, id params (all zero/empty)
	assert.NotContains(t, url, "ws=")
	assert.NotContains(t, url, "auto=")
	assert.NotContains(t, url, "ech=")
	assert.NotContains(t, url, "cdn=")
	assert.NotContains(t, url, "id=")
	// Should contain tls
	assert.Contains(t, url, "tls=1")
}

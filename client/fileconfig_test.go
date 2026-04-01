package client

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadClientConfig(t *testing.T) {
	yamlContent := `
server: "vpn.example.com:443"
pubkey: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
client_id: "my-device-001"
socks: "127.0.0.1:1080"
tls: true
skip_verify: false
cdn: "cdn.example.com"
websocket: true
auto: false
routing:
  bypass:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
  force:
    - "blocked.site"
  block:
    - "ads.example.com"
warmup: true
`
	f, err := os.CreateTemp("", "sl-client-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.WriteString(yamlContent)
	require.NoError(t, err)
	f.Close()

	cc, err := LoadClientConfig(f.Name())
	require.NoError(t, err)

	assert.Equal(t, "vpn.example.com:443", cc.Server)
	assert.Equal(t, "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", cc.PubKey)
	assert.Equal(t, "my-device-001", cc.ClientID)
	assert.Equal(t, "127.0.0.1:1080", cc.Socks)
	assert.True(t, cc.TLS)
	assert.False(t, cc.SkipVerify)
	assert.Equal(t, "cdn.example.com", cc.CDN)
	assert.True(t, cc.WebSocket)
	assert.False(t, cc.Auto)

	assert.Equal(t, 2, len(cc.Routing.Bypass))
	assert.Equal(t, "192.168.0.0/16", cc.Routing.Bypass[0])
	assert.Equal(t, "10.0.0.0/8", cc.Routing.Bypass[1])
	assert.Equal(t, 1, len(cc.Routing.Force))
	assert.Equal(t, "blocked.site", cc.Routing.Force[0])
	assert.Equal(t, 1, len(cc.Routing.Block))
	assert.Equal(t, "ads.example.com", cc.Routing.Block[0])

	assert.NotNil(t, cc.Warmup)
	assert.True(t, *cc.Warmup)
}

func TestLoadClientConfig_Empty(t *testing.T) {
	f, err := os.CreateTemp("", "sl-client-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.Close()

	cc, err := LoadClientConfig(f.Name())
	require.NoError(t, err)

	assert.Empty(t, cc.Server)
	assert.Empty(t, cc.PubKey)
	assert.Nil(t, cc.Warmup)
	assert.Empty(t, cc.Routing.Bypass)
	assert.Empty(t, cc.Routing.Force)
	assert.Empty(t, cc.Routing.Block)
}

func TestLoadClientConfig_NotFound(t *testing.T) {
	_, err := LoadClientConfig("/nonexistent/client.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read client config")
}

func TestLoadClientConfig_InvalidYAML(t *testing.T) {
	f, err := os.CreateTemp("", "sl-client-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.WriteString("server: :::bad\n\t\t[[[")
	f.Close()

	_, err = LoadClientConfig(f.Name())
	assert.Error(t, err)
}

func TestLoadClientConfig_RoutingOnly(t *testing.T) {
	yamlContent := `
routing:
  bypass:
    - "127.0.0.0/8"
  block:
    - "malware.example"
`
	f, err := os.CreateTemp("", "sl-client-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.WriteString(yamlContent)
	f.Close()

	cc, err := LoadClientConfig(f.Name())
	require.NoError(t, err)

	assert.Equal(t, 1, len(cc.Routing.Bypass))
	assert.Equal(t, "127.0.0.0/8", cc.Routing.Bypass[0])
	assert.Empty(t, cc.Routing.Force)
	assert.Equal(t, 1, len(cc.Routing.Block))
}

package client

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testValidPubkey = "0000000000000000000000000000000000000000000000000000000000000001"

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
	// ech=1 в этом URL присутствует намеренно: он больше не парсится (ECH-ветка
	// удалена), и его наличие не должно ломать разбор остальных параметров.
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
	assert.Equal(t, "", cfg.CDN)
	assert.Equal(t, "", cfg.ClientID)
}

func TestParseSLURL_WithCDN(t *testing.T) {
	raw := "sl://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@vpn.example.com:443?cdn=cloudflare.example.com&ech=1"

	cfg, err := ParseSLURL(raw)
	require.NoError(t, err)

	assert.Equal(t, "cloudflare.example.com", cfg.CDN)
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
	// Should not contain ws, auto, cdn, id params (all zero/empty); ech= не
	// эмитится никогда — поле удалено вместе с ECH-веткой.
	assert.NotContains(t, url, "ws=")
	assert.NotContains(t, url, "auto=")
	assert.NotContains(t, url, "ech=")
	assert.NotContains(t, url, "cdn=")
	assert.NotContains(t, url, "id=")
	// Should contain tls
	assert.Contains(t, url, "tls=1")
}

// TestParseSLURL_FullDirectSNI verifies the full-direct URL form:
// IP as host + sni=domain parameter. Used to bypass CF entirely while
// keeping the CF-protected domain in TLS SNI so nginx server_name matches.
func TestParseSLURL_FullDirectSNI(t *testing.T) {
	raw := "sl://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@104.222.177.67:443?tls=1&sni=datacanvases.com"

	cfg, err := ParseSLURL(raw)
	require.NoError(t, err)

	assert.Equal(t, "104.222.177.67:443", cfg.Server)
	assert.Equal(t, "datacanvases.com", cfg.SNI)
	assert.Equal(t, "", cfg.CDN, "full-direct must not set CDN")
	assert.Equal(t, "", cfg.Origin, "full-direct uses Server as origin, no separate Origin")
	assert.Equal(t, true, cfg.TLS)
}

// TestBuildSLURL_FullDirectRoundtrip verifies BuildSLURL preserves sni= and origin=
// so full-direct and hybrid configs can be serialized and re-parsed without loss.
func TestBuildSLURL_FullDirectRoundtrip(t *testing.T) {
	orig := &ClientFileConfig{
		Server: "104.222.177.67:443",
		PubKey: "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
		TLS:    true,
		SNI:    "datacanvases.com",
	}
	built := BuildSLURL(orig)
	assert.Contains(t, built, "sni=datacanvases.com")

	roundtripped, err := ParseSLURL(built)
	require.NoError(t, err)
	assert.Equal(t, orig.Server, roundtripped.Server)
	assert.Equal(t, orig.SNI, roundtripped.SNI)
	assert.Equal(t, orig.TLS, roundtripped.TLS)
}

// TestParseSLURL_BackupServers verifies the backup= parameter produces a list
// of fallback servers. Used when the primary CF domain gets blocked by ТСПУ.
func TestParseSLURL_BackupServers(t *testing.T) {
	raw := "sl://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@primary.com:443?tls=1&cdn=primary.com&backup=fallback1.com,fallback2.com:8443"

	cfg, err := ParseSLURL(raw)
	require.NoError(t, err)

	assert.Equal(t, "primary.com:443", cfg.Server)
	require.Len(t, cfg.BackupServers, 2, "expected 2 backup servers")
	assert.Equal(t, "fallback1.com:443", cfg.BackupServers[0], "backup without :port should default to :443")
	assert.Equal(t, "fallback2.com:8443", cfg.BackupServers[1], "backup with explicit :port should be preserved")
}

// TestParseSLURL_NoBackupBackwardCompat verifies that existing URLs without
// backup= continue to parse to an empty BackupServers slice (no breaking change).
func TestParseSLURL_NoBackupBackwardCompat(t *testing.T) {
	raw := "sl://aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233@primary.com:443?tls=1&cdn=primary.com"

	cfg, err := ParseSLURL(raw)
	require.NoError(t, err)

	assert.Empty(t, cfg.BackupServers, "no backup param must produce empty slice")
}

// TestBuildSLURL_BackupRoundtrip verifies BuildSLURL preserves backup servers
// so configs can be exported and re-imported.
func TestBuildSLURL_BackupRoundtrip(t *testing.T) {
	orig := &ClientFileConfig{
		Server:        "primary.com:443",
		PubKey:        "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
		TLS:           true,
		CDN:           "primary.com",
		BackupServers: []string{"fallback1.com:443", "fallback2.com:8443"},
	}

	built := BuildSLURL(orig)
	assert.Contains(t, built, "backup=")

	roundtripped, err := ParseSLURL(built)
	require.NoError(t, err)
	assert.Equal(t, orig.BackupServers, roundtripped.BackupServers)
}

func TestParseSLURL_CDNsPool(t *testing.T) {
	url := "sl://" + testValidPubkey + "@example.com:443?tls=1&ws=1&cdns=a.com,b.com,c.com"
	cfg, err := ParseSLURL(url)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"a.com", "b.com", "c.com"}
	if !reflect.DeepEqual(cfg.CDNs, want) {
		t.Errorf("CDNs = %v, want %v", cfg.CDNs, want)
	}
}

func TestParseSLURL_CDNsAbsent_Empty(t *testing.T) {
	url := "sl://" + testValidPubkey + "@example.com:443?tls=1&ws=1"
	cfg, _ := ParseSLURL(url)
	if len(cfg.CDNs) != 0 {
		t.Errorf("CDNs should be empty when absent, got %v", cfg.CDNs)
	}
}

func TestParseSLURL_CDNs_TooMany(t *testing.T) {
	parts := make([]string, 9)
	for i := range parts {
		parts[i] = fmt.Sprintf("x%d.com", i)
	}
	url := "sl://" + testValidPubkey + "@example.com:443?cdns=" + strings.Join(parts, ",")
	_, err := ParseSLURL(url)
	if err == nil {
		t.Error("expected error for > 8 cdns entries")
	}
}

func TestParseSLURL_CDNs_InvalidHostname(t *testing.T) {
	url := "sl://" + testValidPubkey + "@example.com:443?cdns=ok.com,not%20a%20valid%20host"
	_, err := ParseSLURL(url)
	if err == nil {
		t.Error("expected error for invalid hostname in cdns")
	}
}

func TestBuildSLURL_RoundtripCDNs(t *testing.T) {
	original := &ClientFileConfig{
		Server:    "example.com:443",
		PubKey:    testValidPubkey,
		TLS:       true,
		WebSocket: true,
		CDNs:      []string{"a.com", "b.com"},
	}
	url := BuildSLURL(original)
	parsed, err := ParseSLURL(url)
	if err != nil {
		t.Fatalf("roundtrip parse: %v", err)
	}
	if !reflect.DeepEqual(parsed.CDNs, original.CDNs) {
		t.Errorf("roundtrip CDNs: got %v, want %v", parsed.CDNs, original.CDNs)
	}
}

func TestBuildSLURL_HybridRoundtrip(t *testing.T) {
	orig := &ClientFileConfig{
		Server: "datacanvases.com:443",
		PubKey: "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
		TLS:    true,
		CDN:    "datacanvases.com",
		Origin: "104.222.177.67",
	}
	built := BuildSLURL(orig)
	assert.Contains(t, built, "cdn=datacanvases.com")
	assert.Contains(t, built, "origin=104.222.177.67")

	roundtripped, err := ParseSLURL(built)
	require.NoError(t, err)
	assert.Equal(t, orig.Server, roundtripped.Server)
	assert.Equal(t, orig.CDN, roundtripped.CDN)
	assert.Equal(t, orig.Origin, roundtripped.Origin)
	assert.Equal(t, "", roundtripped.SNI, "hybrid must not set SNI")
}

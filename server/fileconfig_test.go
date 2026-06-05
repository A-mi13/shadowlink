package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigFile(t *testing.T) {
	yamlContent := `
listen: ":9443"
cert: /etc/ssl/cert.pem
key: /etc/ssl/key.pem
server_key: /etc/shadowlink/server.key
decoy: /var/www/decoy
max_clients: 200
behind_proxy: true
management:
  port: 9100
  bind: "127.0.0.1"
  key: "secret-key"
  default_max_devices: 5
mimicry:
  cover_traffic: true
  inflation: false
block_domains:
  - "illegal.com"
  - "bad-site.org"
`
	f, err := os.CreateTemp("", "sl-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.WriteString(yamlContent)
	require.NoError(t, err)
	f.Close()

	fc, err := LoadConfigFile(f.Name())
	require.NoError(t, err)

	assert.Equal(t, ":9443", fc.Listen)
	assert.Equal(t, "/etc/ssl/cert.pem", fc.Cert)
	assert.Equal(t, "/etc/ssl/key.pem", fc.Key)
	assert.Equal(t, "/etc/shadowlink/server.key", fc.ServerKey)
	assert.Equal(t, "/var/www/decoy", fc.Decoy)

	assert.NotNil(t, fc.MaxClients)
	assert.Equal(t, 200, *fc.MaxClients)

	assert.NotNil(t, fc.BehindProxy)
	assert.True(t, *fc.BehindProxy)

	assert.NotNil(t, fc.Management)
	assert.NotNil(t, fc.Management.Port)
	assert.Equal(t, 9100, *fc.Management.Port)
	assert.Equal(t, "127.0.0.1", fc.Management.Bind)
	assert.Equal(t, "secret-key", fc.Management.Key)
	assert.NotNil(t, fc.Management.DefaultMaxDevices)
	assert.Equal(t, 5, *fc.Management.DefaultMaxDevices)

	assert.NotNil(t, fc.Mimicry)
	assert.NotNil(t, fc.Mimicry.CoverTraffic)
	assert.True(t, *fc.Mimicry.CoverTraffic)
	assert.NotNil(t, fc.Mimicry.Inflation)
	assert.False(t, *fc.Mimicry.Inflation)

	assert.Equal(t, 2, len(fc.BlockDomains))
	assert.Equal(t, "illegal.com", fc.BlockDomains[0])
	assert.Equal(t, "bad-site.org", fc.BlockDomains[1])
}

func TestLoadConfigFile_Empty(t *testing.T) {
	f, err := os.CreateTemp("", "sl-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.Close()

	fc, err := LoadConfigFile(f.Name())
	require.NoError(t, err)

	assert.Nil(t, fc.MaxClients)
	assert.Nil(t, fc.BehindProxy)
	assert.Nil(t, fc.Management)
	assert.Nil(t, fc.Mimicry)
	assert.Empty(t, fc.Listen)
}

func TestLoadConfigFile_NotFound(t *testing.T) {
	_, err := LoadConfigFile("/nonexistent/path/config.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read config")
}

func TestLoadConfigFile_InvalidYAML(t *testing.T) {
	f, err := os.CreateTemp("", "sl-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.WriteString("listen: :::bad yaml\n\t\t[[[")
	f.Close()

	_, err = LoadConfigFile(f.Name())
	assert.Error(t, err)
}

func TestApplyTo(t *testing.T) {
	mc := 200
	bp := true
	fc := &FileConfig{
		Listen:      ":9443",
		MaxClients:  &mc,
		BehindProxy: &bp,
	}
	cfg := Config{ListenAddr: ":443", MaxClients: 100}
	fc.ApplyTo(&cfg)
	assert.Equal(t, ":9443", cfg.ListenAddr)
	assert.Equal(t, 200, cfg.MaxClients)
	assert.True(t, cfg.BehindProxy)
}

func TestApplyTo_OriginDeathTeardown(t *testing.T) {
	// Bug #10: YAML origin_death_teardown propagates as a pointer (nil-preserving).
	on := true
	fc := &FileConfig{OriginDeathTeardown: &on}
	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)
	if cfg.OriginDeathTeardown == nil || !*cfg.OriginDeathTeardown {
		t.Fatal("origin_death_teardown: true must propagate as *true")
	}
	if !cfg.originDeathTeardownEnabledOrDefault() {
		t.Fatal("resolved gate must be ON when YAML set true")
	}

	// Absent YAML key → pointer stays nil → default OFF.
	fcNil := &FileConfig{}
	cfgNil := DefaultConfig()
	fcNil.ApplyTo(&cfgNil)
	if cfgNil.OriginDeathTeardown != nil {
		t.Fatal("absent YAML key must leave OriginDeathTeardown nil")
	}
	if cfgNil.originDeathTeardownEnabledOrDefault() {
		t.Fatal("nil must resolve to default OFF")
	}
}

func TestApplyTo_PartialOverride(t *testing.T) {
	// Only listen is set — other fields should remain at defaults
	fc := &FileConfig{
		Listen: ":9443",
	}
	cfg := DefaultConfig()
	original := cfg
	fc.ApplyTo(&cfg)

	assert.Equal(t, ":9443", cfg.ListenAddr)
	assert.Equal(t, original.MaxClients, cfg.MaxClients)
	assert.Equal(t, original.ChunkSize, cfg.ChunkSize)
	assert.Equal(t, original.ManagementBind, cfg.ManagementBind)
}

func TestApplyTo_Management(t *testing.T) {
	port := 9100
	maxDev := 5
	fc := &FileConfig{
		Management: &MgmtConfig{
			Port:              &port,
			Bind:              "0.0.0.0",
			Key:               "my-secret",
			DefaultMaxDevices: &maxDev,
		},
	}
	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)

	assert.Equal(t, 9100, cfg.ManagementPort)
	assert.Equal(t, "0.0.0.0", cfg.ManagementBind)
	assert.Equal(t, "my-secret", cfg.ManagementKey)
	assert.Equal(t, 5, cfg.DefaultMaxDevices)
}

func TestApplyTo_ZeroValuesNotOverridden(t *testing.T) {
	// Empty FileConfig should not change any defaults — with the exception of
	// UseInflatedResponses which ApplyTo unconditionally sets to true (Wave 1.1
	// default-on; overridden only by explicit mimicry.inflation: false in YAML).
	fc := &FileConfig{}
	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)

	assert.Equal(t, ":443", cfg.ListenAddr)
	// 2026-05-17 incident retrospective: bumped 100 → 500.
	assert.Equal(t, 500, cfg.MaxClients)
	assert.Equal(t, 8, cfg.MaxConnsPerClient)
	assert.Equal(t, 12288, cfg.ChunkSize)
	assert.Equal(t, "127.0.0.1", cfg.ManagementBind)
	assert.Equal(t, 3, cfg.DefaultMaxDevices)
	// Wave 1.1: UseInflatedResponses defaults to true after ApplyTo.
	assert.True(t, cfg.UseInflatedResponses)
}

// helperLoadConfig is a test-local convenience: load YAML and apply to DefaultConfig.
func helperLoadConfig(t *testing.T, content string) Config {
	t.Helper()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)
	return cfg
}

// TestLoad_InflationDefaultsTrue verifies that UseInflatedResponses is true
// when the mimicry section is absent from YAML (Wave 1.1 default-on change).
func TestLoad_InflationDefaultsTrue(t *testing.T) {
	content := `listen: ":443"
cert: "/tmp/cert"
key: "/tmp/key"
server_key: "0000000000000000000000000000000000000000000000000000000000000000"
decoy: "/tmp/decoy"
`
	cfg := helperLoadConfig(t, content)
	if !cfg.UseInflatedResponses {
		t.Error("UseInflatedResponses must default to true when mimicry section absent (Wave 1.1)")
	}
}

// TestLoad_InflationExplicitFalseRespected verifies that an explicit
// mimicry.inflation: false override is honoured.
func TestLoad_InflationExplicitFalseRespected(t *testing.T) {
	content := `listen: ":443"
cert: "/tmp/cert"
key: "/tmp/key"
server_key: "0000000000000000000000000000000000000000000000000000000000000000"
decoy: "/tmp/decoy"
mimicry:
  inflation: false
`
	cfg := helperLoadConfig(t, content)
	if cfg.UseInflatedResponses {
		t.Error("UseInflatedResponses must respect explicit mimicry.inflation: false override")
	}
}

// writeAndLoadExpectError writes YAML content to a temp file and expects
// LoadConfigFile to return an error containing wantSubstr.
func writeAndLoadExpectError(t *testing.T, content, wantSubstr string) {
	t.Helper()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfigFile(cfgPath)
	if err == nil {
		t.Fatalf("expected fail-fast error containing %q, got nil", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Errorf("error should mention %q: %v", wantSubstr, err)
	}
}

// --- Phase G (decoy behavioral coverage): per-host {directory, persona} ---

func TestFileConfig_DomainDecoyMap_NewFormat(t *testing.T) {
	yamlData := `listen: ":443"
domain_decoy_map:
  "datacanvases.com":
    directory: "/var/www/saas-landing"
    persona: "saas"
  "myblog.io":
    directory: "/var/www/tech-blog"
    persona: "blog"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yamlData), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if got := cfg.DomainDecoyMap["datacanvases.com"]; got != "/var/www/saas-landing" {
		t.Errorf("datacanvases.com dir = %q, want /var/www/saas-landing", got)
	}
	if got := cfg.DomainPersonaMap["datacanvases.com"]; got != "saas" {
		t.Errorf("datacanvases.com persona = %q, want saas", got)
	}
	if got := cfg.DomainPersonaMap["myblog.io"]; got != "blog" {
		t.Errorf("myblog.io persona = %q, want blog", got)
	}
}

func TestFileConfig_DomainDecoyMap_LegacyFormat(t *testing.T) {
	yamlData := `listen: ":443"
domain_decoy_map:
  "host1": "/var/www/saas-landing"
  "host2": "/var/www/tech-blog"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yamlData), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if got := cfg.DomainDecoyMap["host1"]; got != "/var/www/saas-landing" {
		t.Errorf("legacy: host1 dir = %q, want /var/www/saas-landing", got)
	}
	if len(cfg.DomainPersonaMap) > 0 {
		t.Errorf("legacy format must not populate DomainPersonaMap, got %v", cfg.DomainPersonaMap)
	}
}

// TestFileConfig_ApplyTo_PropagatesPersonaMap is the wire-up guard for the
// Phase G end-to-end YAML→handler path. Without ApplyTo copying
// DomainPersonaMap into Config, NewDecoyHandlerV2 in handler.go would receive
// nil DomainPersona for every host and silently fall back to the default
// persona — defeating the whole new-YAML-format change. This test fails fast
// if the ApplyTo copy is ever dropped.
func TestFileConfig_ApplyTo_PropagatesPersonaMap(t *testing.T) {
	fc := &FileConfig{
		DomainDecoyMap: map[string]string{
			"saas.example.com": "/var/www/saas-landing",
			"blog.example.com": "/var/www/tech-blog",
		},
		DomainPersonaMap: map[string]string{
			"saas.example.com": "saas",
			"blog.example.com": "blog",
		},
	}
	cfg := &Config{}
	fc.ApplyTo(cfg)

	if got := cfg.DomainPersonaMap["saas.example.com"]; got != "saas" {
		t.Errorf("Config.DomainPersonaMap[\"saas.example.com\"] = %q, want %q", got, "saas")
	}
	if got := cfg.DomainPersonaMap["blog.example.com"]; got != "blog" {
		t.Errorf("Config.DomainPersonaMap[\"blog.example.com\"] = %q, want %q", got, "blog")
	}
	if len(cfg.DomainPersonaMap) != 2 {
		t.Errorf("Config.DomainPersonaMap size = %d, want 2", len(cfg.DomainPersonaMap))
	}
}

// TestLoad_InvalidWSPoolSize_FailsFast verifies out-of-range ws_pool_size
// causes Load to fail fast with the field name in the error.
func TestLoad_InvalidWSPoolSize_FailsFast(t *testing.T) {
	content := `listen: ":443"
cert: "/tmp/c"
key: "/tmp/k"
server_key: "0000000000000000000000000000000000000000000000000000000000000000"
decoy: "/tmp/d"
mimicry:
  ws_pool_size: 100
`
	writeAndLoadExpectError(t, content, "ws_pool_size")
}

// TestLoad_InvalidDecoyBurstMs_FailsFast verifies decoy_get_interval_burst_ms
// below floor 100 fails.
func TestLoad_InvalidDecoyBurstMs_FailsFast(t *testing.T) {
	content := `listen: ":443"
cert: "/tmp/c"
key: "/tmp/k"
server_key: "0000000000000000000000000000000000000000000000000000000000000000"
decoy: "/tmp/d"
mimicry:
  decoy_get_interval_burst_ms: 50
`
	writeAndLoadExpectError(t, content, "decoy_get_interval_burst_ms")
}

// TestLoad_InvalidDecoyQuietSec_FailsFast verifies decoy_get_interval_quiet_sec
// above ceiling 300 fails.
func TestLoad_InvalidDecoyQuietSec_FailsFast(t *testing.T) {
	content := `listen: ":443"
cert: "/tmp/c"
key: "/tmp/k"
server_key: "0000000000000000000000000000000000000000000000000000000000000000"
decoy: "/tmp/d"
mimicry:
  decoy_get_interval_quiet_sec: 500
`
	writeAndLoadExpectError(t, content, "decoy_get_interval_quiet_sec")
}

// TestLoad_PreambleMinExceedsMax_FailsFast verifies the cross-field
// invariant preamble_count_min <= preamble_count_max.
func TestLoad_PreambleMinExceedsMax_FailsFast(t *testing.T) {
	content := `listen: ":443"
cert: "/tmp/c"
key: "/tmp/k"
server_key: "0000000000000000000000000000000000000000000000000000000000000000"
decoy: "/tmp/d"
mimicry:
  preamble_count_min: 5
  preamble_count_max: 3
`
	writeAndLoadExpectError(t, content, "preamble_count_min")
}

// TestLoad_InvalidPreambleMax_FailsFast verifies preamble_count_max above
// ceiling 15 fails.
func TestLoad_InvalidPreambleMax_FailsFast(t *testing.T) {
	content := `listen: ":443"
cert: "/tmp/c"
key: "/tmp/k"
server_key: "0000000000000000000000000000000000000000000000000000000000000000"
decoy: "/tmp/d"
mimicry:
  preamble_count_max: 50
`
	writeAndLoadExpectError(t, content, "preamble_count_max")
}

// TestLoad_InvalidIdleTimeout_FailsFast verifies idle_timeout_sec below
// floor 60 fails.
func TestLoad_InvalidIdleTimeout_FailsFast(t *testing.T) {
	content := `listen: ":443"
cert: "/tmp/c"
key: "/tmp/k"
server_key: "0000000000000000000000000000000000000000000000000000000000000000"
decoy: "/tmp/d"
idle_timeout_sec: 10
`
	writeAndLoadExpectError(t, content, "idle_timeout_sec")
}

// TestLoad_ValidAllFields_NoError verifies that a config with all new
// mimicry + root fields set to valid in-range values loads cleanly.
func TestLoad_ValidAllFields_NoError(t *testing.T) {
	content := `listen: ":443"
cert: "/tmp/c"
key: "/tmp/k"
server_key: "0000000000000000000000000000000000000000000000000000000000000000"
decoy: "/tmp/d"
idle_timeout_sec: 240
server_header: "nginx/1.24.0"
mimicry:
  inflation: true
  ws_pool_size: 6
  decoy_get_interval_burst_ms: 250
  decoy_get_interval_quiet_sec: 60
  preamble_count_min: 3
  preamble_count_max: 7
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfigFile returned error on valid config: %v", err)
	}

	require.NotNil(t, fc.IdleTimeoutSec)
	assert.Equal(t, 240, *fc.IdleTimeoutSec)
	require.NotNil(t, fc.ServerHeader)
	assert.Equal(t, "nginx/1.24.0", *fc.ServerHeader)

	require.NotNil(t, fc.Mimicry)
	require.NotNil(t, fc.Mimicry.WSPoolSize)
	assert.Equal(t, 6, *fc.Mimicry.WSPoolSize)
	require.NotNil(t, fc.Mimicry.DecoyGetIntervalBurstMs)
	assert.Equal(t, 250, *fc.Mimicry.DecoyGetIntervalBurstMs)
	require.NotNil(t, fc.Mimicry.DecoyGetIntervalQuietSec)
	assert.Equal(t, 60, *fc.Mimicry.DecoyGetIntervalQuietSec)
	require.NotNil(t, fc.Mimicry.PreambleCountMin)
	assert.Equal(t, 3, *fc.Mimicry.PreambleCountMin)
	require.NotNil(t, fc.Mimicry.PreambleCountMax)
	assert.Equal(t, 7, *fc.Mimicry.PreambleCountMax)
}

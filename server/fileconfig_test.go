package server

import (
	"os"
	"testing"
	"time"

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
	// Empty FileConfig should not change any defaults
	fc := &FileConfig{}
	cfg := DefaultConfig()
	original := cfg
	fc.ApplyTo(&cfg)

	assert.Equal(t, original, cfg)
}

func TestLoadConfigFile_LiveBlog(t *testing.T) {
	yamlContent := `
live_blog:
  enabled: true
  upstream: "https://example.com"
  cache_ttl: "30m"
`
	f, err := os.CreateTemp("", "sl-liveblog-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.WriteString(yamlContent)
	require.NoError(t, err)
	f.Close()

	fc, err := LoadConfigFile(f.Name())
	require.NoError(t, err)

	require.NotNil(t, fc.LiveBlog)
	require.NotNil(t, fc.LiveBlog.Enabled)
	assert.True(t, *fc.LiveBlog.Enabled)
	assert.Equal(t, "https://example.com", fc.LiveBlog.Upstream)
	assert.Equal(t, "30m", fc.LiveBlog.CacheTTL)

	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)

	assert.True(t, cfg.LiveBlog.Enabled)
	assert.Equal(t, "https://example.com", cfg.LiveBlog.Upstream)
	assert.Equal(t, 30*time.Minute, cfg.LiveBlog.CacheTTL)
}

func TestApplyTo_LiveBlogPartialOverride(t *testing.T) {
	// Only Enabled set — other fields stay at zero (caller applies defaults separately)
	enabled := true
	fc := &FileConfig{
		LiveBlog: &FileLiveBlogConfig{
			Enabled: &enabled,
		},
	}
	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)

	assert.True(t, cfg.LiveBlog.Enabled)
	// Fields not set in YAML remain zero (DefaultConfig has zero LiveBlog)
	assert.Equal(t, "", cfg.LiveBlog.Upstream)
}

func TestApplyTo_LiveBlogDurationParsing(t *testing.T) {
	enabled := false
	rps := 2.5
	burst := 10
	maxBody := 1024 * 1024
	cdnBody := 8 * 1024 * 1024
	maxEntries := 200
	fc := &FileConfig{
		LiveBlog: &FileLiveBlogConfig{
			Enabled:           &enabled,
			CacheTTL:          "2h",
			CacheStaleGrace:   "48h",
			UpstreamTimeout:   "5s",
			CanaryInterval:    "10m",
			UpstreamRPS:       &rps,
			UpstreamBurst:     &burst,
			MaxBodyBytes:      &maxBody,
			CDNMaxBodyBytes:   &cdnBody,
			CacheMaxEntries:   &maxEntries,
			TargetBrand:       "MyBrand",
			TargetLogoPath:    "/logo.svg",
			TargetTitleSuffix: " — MyBrand",
			CanaryArticleID:   "123456",
			CDNUpstream:       "https://cdn.example.com",
		},
	}
	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)

	assert.False(t, cfg.LiveBlog.Enabled)
	assert.Equal(t, 2*time.Hour, cfg.LiveBlog.CacheTTL)
	assert.Equal(t, 48*time.Hour, cfg.LiveBlog.CacheStaleGrace)
	assert.Equal(t, 5*time.Second, cfg.LiveBlog.UpstreamTimeout)
	assert.Equal(t, 10*time.Minute, cfg.LiveBlog.CanaryInterval)
	assert.Equal(t, 2.5, cfg.LiveBlog.UpstreamRPS)
	assert.Equal(t, 10, cfg.LiveBlog.UpstreamBurst)
	assert.Equal(t, 1024*1024, cfg.LiveBlog.MaxBodyBytes)
	assert.Equal(t, 8*1024*1024, cfg.LiveBlog.CDNMaxBodyBytes)
	assert.Equal(t, 200, cfg.LiveBlog.CacheMaxEntries)
	assert.Equal(t, "MyBrand", cfg.LiveBlog.TargetBrand)
	assert.Equal(t, "/logo.svg", cfg.LiveBlog.TargetLogoPath)
	assert.Equal(t, " — MyBrand", cfg.LiveBlog.TargetTitleSuffix)
	assert.Equal(t, "123456", cfg.LiveBlog.CanaryArticleID)
	assert.Equal(t, "https://cdn.example.com", cfg.LiveBlog.CDNUpstream)
}

func TestApplyTo_LiveBlogInvalidDurationIgnored(t *testing.T) {
	// Invalid duration strings must be silently ignored — field stays zero
	enabled := true
	fc := &FileConfig{
		LiveBlog: &FileLiveBlogConfig{
			Enabled:  &enabled,
			CacheTTL: "not-a-duration",
		},
	}
	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)

	assert.True(t, cfg.LiveBlog.Enabled)
	assert.Equal(t, time.Duration(0), cfg.LiveBlog.CacheTTL) // zero — not overridden
}

package server

import "time"

// Config holds all server configuration.
type Config struct {
	// ListenAddr is the address to listen on (e.g., ":443").
	ListenAddr string

	// TLS certificate and key paths (Let's Encrypt or self-signed for testing).
	CertFile string
	KeyFile  string

	// ServerKeyFile is the path to the ShadowLink static private key (32 bytes, hex or base64).
	// This key is used for NaCl Box decryption of client_id in handshake.
	ServerKeyFile string

	// DecoyDir is the path to the static site served to unauthenticated requests.
	// Active probes from TSPU see a real website.
	DecoyDir string

	// DomainDecoyMap maps Host header → decoy directory path for multi-domain serving.
	// Empty/nil → use DecoyDir for all hosts (legacy behaviour).
	// Sub-phase B (Domain Diversity): orchestrator populates this from per-domain
	// decoy_template_id assignments at deploy time.
	DomainDecoyMap map[string]string `yaml:"domain_decoy_map,omitempty"`

	// MaxClients is the maximum number of concurrent client sessions.
	// Configurable per-server in NixaVPN admin panel.
	MaxClients int

	// MaxConnsPerClient is the max concurrent HTTP connections per client session.
	// Advertised to client in ServerHello. Reduced under memory pressure.
	MaxConnsPerClient int

	// ChunkSize is the max chunk payload size in bytes.
	// Default 12288 (12 KB) — below TSPU 16 KB threshold.
	ChunkSize int

	// SessionTimeout is how long to keep idle sessions before cleanup.
	SessionTimeout time.Duration

	// CleanupInterval is how often to run session cleanup.
	CleanupInterval time.Duration

	// AuthorizedClients is a list of allowed client IDs.
	// Empty = open mode (all clients allowed, for testing).
	AuthorizedClients []string

	// BehindProxy indicates the server is behind a reverse proxy (CDN).
	// When true, X-Forwarded-For is trusted for client IP extraction.
	// When false (direct mode), only RemoteAddr is used — prevents XFF spoofing.
	BehindProxy bool

	// ManagementPort is the port for the Management API (0 = disabled).
	ManagementPort int
	// ManagementBind is the bind address for the Management API (default "127.0.0.1").
	ManagementBind string
	// ManagementKey is the API key for the Management API (X-Management-Key header).
	ManagementKey string
	// DefaultMaxDevices is the default device limit per user (default 3).
	DefaultMaxDevices int

	// BlockDomains is a list of domain suffixes/exact names the server refuses to dial.
	BlockDomains []string

	// UseInflatedResponses enables BuildInflatedDownloadResponse (extra JSON
	// fields + body-size variance for DPI evasion).
	//
	// Default: true (changed 2026-05-17 — audit found flag absent in pl1 config
	// → all T2.4 mimicry distributions dead code in production).
	//
	// Throughput cost: ~2-3x per Phase 3 Plan A § 4.4 (T2.4 documentation).
	// A/B perf-measure required before broad rollout (see plan Wave 1.1 Step 11).
	// If regression > 30% in real traffic — consider "inflate small only" (<8KB).
	//
	// Override via `mimicry.inflation: false` in YAML.
	UseInflatedResponses bool

	// ReplayCacheMaxSize caps the LRU size of the handshake replay cache.
	// Zero/unset → 10000 (covers ~33 accepts/sec at 5min window before
	// LRU evicts). For ≥1k-client deployments document the scaling
	// threshold and bump this. See audit A1-L6 (2026-04-25).
	ReplayCacheMaxSize int `yaml:"replay_cache_max_size"`

	// ReplayCacheWindow is the timestamp-bucket size for replay rejection.
	// Zero/unset → 5*time.Minute. Larger windows rebuke replays for longer
	// at the cost of LRU pressure (see ReplayCacheMaxSize).
	ReplayCacheWindow time.Duration `yaml:"replay_cache_window"`

	// HandshakeRateLimitPerMin caps new handshakes per minute per client IP.
	// 0 = use safe default (300). The legacy hardcoded value (50) was sized
	// for one-handshake-per-CONNECT clients and broke pool reconnect: 4 slots
	// × cascade death easily produces 30+ handshakes/min from one IP, hitting
	// the limit and falling through to the decoy (HTTP 404 / HTML responses).
	HandshakeRateLimitPerMin int

	// LiveBlog configures the /blog/* and /_cdn/* live reverse-proxy decoy paths.
	// Zero value has Enabled=false — no behaviour change when not set.
	LiveBlog LiveBlogConfig `yaml:"live_blog"`

	// RateLimit configures per-bucket rate-limit specs (handshake, ws_upgrade)
	// and the ClientID exemption cache. Zero values fall through to safe
	// defaults applied at handler construction (NewHandler) so existing
	// deployments without YAML overrides keep working unchanged. Plan §C6
	// (May audit, 2026-05-02).
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitBucketSpec defines a single token-bucket: burst (max tokens) and
// refill rate per minute. Zero values trigger per-bucket defaults inside
// NewHandler (handshake: burst=50/refill=300, ws_upgrade: burst=18/refill=30).
type RateLimitBucketSpec struct {
	Burst        int `yaml:"burst"`
	RefillPerMin int `yaml:"refill_per_min"`
}

// RateLimitConfig groups per-bucket rate-limit specs and the ClientID
// exemption cache parameters. All fields are optional — zero values trigger
// defaults at NewHandler construction time.
type RateLimitConfig struct {
	WSUpgrade RateLimitBucketSpec `yaml:"ws_upgrade"`
	Handshake RateLimitBucketSpec `yaml:"handshake"`
	// ClientIDLruSize caps the LRU of recently-seen authenticated clientIDs.
	// Zero → 10000.
	ClientIDLruSize int `yaml:"client_id_lru_size"`
	// ClientIDTTLMin is the per-clientID exemption TTL (minutes). Zero → 60.
	ClientIDTTLMin int `yaml:"client_id_ttl_min"`
	// ClientIDSoftLimit is the per-clientID per-window soft cap that prevents
	// one trusted clientID from monopolizing the bucket-bypass path. Zero → 60.
	ClientIDSoftLimit int `yaml:"client_id_soft_limit"`
	// ClientIDSoftWindowSec sliding window for the soft limit (seconds).
	// Zero → 60.
	ClientIDSoftWindowSec int `yaml:"client_id_soft_window_sec"`
}

// DefaultConfig returns production-ready defaults for a 2 vCPU / 2 GB RAM VPS.
//
// 2026-05-17 incident retrospective: prior defaults (MaxClients=100,
// SessionTimeout=5m, CleanupInterval=30s) were too tight для современного
// reconnect-storm pattern. При 8-slot WS pool и одном клиенте ghost-сессий
// от EOF reader exit'ов накапливалось 50-100 за окно SessionTimeout — пробит
// MaxClients → decoy lockout. Новые defaults дают 5× запас по слотам и 3×
// быстрее освобождают idle сессии.
//
// Override: операционные ключи в /etc/shadowlink/config.yaml имеют приоритет.
func DefaultConfig() Config {
	return Config{
		ListenAddr:        ":443",
		MaxClients:        500,
		MaxConnsPerClient: 8,
		ChunkSize:         12288,
		SessionTimeout:    90 * time.Second,
		CleanupInterval:   10 * time.Second,
		ManagementBind:    "127.0.0.1",
		DefaultMaxDevices: 3,
	}
}

// TestConfig returns config suitable for testing (no TLS, localhost).
func TestConfig() Config {
	return Config{
		ListenAddr:        "127.0.0.1:0", // random port
		MaxClients:        10,
		MaxConnsPerClient: 4,
		ChunkSize:         12288,
		SessionTimeout:    1 * time.Minute,
		CleanupInterval:   5 * time.Second,
	}
}

// LiveBlogConfig configures the /blog/* and /_cdn/* reverse-proxy decoy paths.
// Default Enabled=false — zero regression when omitted from YAML.
// See docs/superpowers/specs/2026-04-23-t13-live-decoy-design.md.
type LiveBlogConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Upstream          string        `yaml:"upstream"`            // e.g. "https://habr.com"
	CDNUpstream       string        `yaml:"cdn_upstream"`        // e.g. "https://dr.habracdn.net"
	CacheTTL          time.Duration `yaml:"cache_ttl"`           // fresh cache window, default 1h
	CacheMaxEntries   int           `yaml:"cache_max_entries"`   // LRU cap, default 500
	CacheStaleGrace   time.Duration `yaml:"cache_stale_grace"`   // serve-stale window on fetch fail, default 24h
	UpstreamRPS       float64       `yaml:"upstream_rps"`        // rate.Limiter RPS, default 1.0
	UpstreamBurst     int           `yaml:"upstream_burst"`      // rate.Limiter burst, default 5
	UpstreamTimeout   time.Duration `yaml:"upstream_timeout"`    // http.Client.Timeout, default 10s
	MaxBodyBytes      int           `yaml:"max_body_bytes"`      // /blog/* body cap, default 2 MiB
	CDNMaxBodyBytes   int           `yaml:"cdn_max_body_bytes"`  // /_cdn/* body cap, default 16 MiB
	CanaryArticleID   string        `yaml:"canary_article_id"`   // digit-only habr article ID
	CanaryInterval    time.Duration `yaml:"canary_interval"`     // canary loop period, default 15m
	TargetBrand       string        `yaml:"target_brand"`        // replaces visible "Хабр" text
	TargetLogoPath    string        `yaml:"target_logo_path"`    // e.g. "/assets/logo.svg"
	TargetTitleSuffix string        `yaml:"target_title_suffix"` // appended to <title>
	FallbackLatencyMs int           `yaml:"fallback_latency_ms"` // fail/limit path target latency, default 150
	FallbackJitterMs  int           `yaml:"fallback_jitter_ms"`  // jitter ±ms around latency, default 20
}

// DefaultLiveBlogConfig returns the built-in defaults. Applied when a YAML key
// is present but empty, or when filling missing keys on a loaded config.
func DefaultLiveBlogConfig() LiveBlogConfig {
	return LiveBlogConfig{
		Enabled:           false,
		Upstream:          "https://habr.com",
		CDNUpstream:       "https://dr.habracdn.net",
		CacheTTL:          time.Hour,
		CacheMaxEntries:   500,
		CacheStaleGrace:   24 * time.Hour,
		UpstreamRPS:       1.0,
		UpstreamBurst:     5,
		UpstreamTimeout:   10 * time.Second,
		MaxBodyBytes:      2 * 1024 * 1024,
		CDNMaxBodyBytes:   16 * 1024 * 1024,
		CanaryArticleID:   "723128",
		CanaryInterval:    15 * time.Minute,
		TargetBrand:       "DataCanvases",
		TargetLogoPath:    "/assets/logo.svg",
		TargetTitleSuffix: " — DataCanvases Research",
		FallbackLatencyMs: 150,
		FallbackJitterMs:  20,
	}
}

// applyLiveBlogDefaults fills zero-valued fields in c with defaults. Called
// after YAML load so operators can override only the values they care about.
func applyLiveBlogDefaults(c *LiveBlogConfig) {
	d := DefaultLiveBlogConfig()
	if c.Upstream == "" {
		c.Upstream = d.Upstream
	}
	if c.CDNUpstream == "" {
		c.CDNUpstream = d.CDNUpstream
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = d.CacheTTL
	}
	if c.CacheMaxEntries == 0 {
		c.CacheMaxEntries = d.CacheMaxEntries
	}
	if c.CacheStaleGrace == 0 {
		c.CacheStaleGrace = d.CacheStaleGrace
	}
	if c.UpstreamRPS == 0 {
		c.UpstreamRPS = d.UpstreamRPS
	}
	if c.UpstreamBurst == 0 {
		c.UpstreamBurst = d.UpstreamBurst
	}
	if c.UpstreamTimeout == 0 {
		c.UpstreamTimeout = d.UpstreamTimeout
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = d.MaxBodyBytes
	}
	if c.CDNMaxBodyBytes == 0 {
		c.CDNMaxBodyBytes = d.CDNMaxBodyBytes
	}
	if c.CanaryArticleID == "" {
		c.CanaryArticleID = d.CanaryArticleID
	}
	if c.CanaryInterval == 0 {
		c.CanaryInterval = d.CanaryInterval
	}
	if c.TargetBrand == "" {
		c.TargetBrand = d.TargetBrand
	}
	if c.TargetLogoPath == "" {
		c.TargetLogoPath = d.TargetLogoPath
	}
	if c.TargetTitleSuffix == "" {
		c.TargetTitleSuffix = d.TargetTitleSuffix
	}
	if c.FallbackLatencyMs <= 0 {
		c.FallbackLatencyMs = d.FallbackLatencyMs
	}
	if c.FallbackJitterMs < 0 {
		c.FallbackJitterMs = d.FallbackJitterMs
	}
}

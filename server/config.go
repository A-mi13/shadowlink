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

	// UDPListenAddr for TURN-relayed traffic (Phase 2 Call Skin). Default ":56000".
	UDPListenAddr string
	// EnableUDP enables the UDP listener.
	EnableUDP bool

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

	// UseInflatedResponses enables BuildInflatedDownloadResponse (extra JSON fields for DPI evasion).
	// Disabled by default — adds overhead that reduces throughput ~2-3x.
	// Enable via mimicry.inflation: true in YAML config.
	UseInflatedResponses bool

	// HandshakeRateLimitPerMin caps new handshakes per minute per client IP.
	// 0 = use safe default (300). The legacy hardcoded value (50) was sized
	// for one-handshake-per-CONNECT clients and broke pool reconnect: 4 slots
	// × cascade death easily produces 30+ handshakes/min from one IP, hitting
	// the limit and falling through to the decoy (HTTP 404 / HTML responses).
	HandshakeRateLimitPerMin int
}

// DefaultConfig returns production-ready defaults for a 2 vCPU / 2 GB RAM VPS.
func DefaultConfig() Config {
	return Config{
		ListenAddr:        ":443",
		MaxClients:        100,
		MaxConnsPerClient: 8,
		ChunkSize:         12288,
		SessionTimeout:    5 * time.Minute,
		CleanupInterval:   30 * time.Second,
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

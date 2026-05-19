package client

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"gopkg.in/yaml.v3"
)

// ClientFileConfig holds client configuration fields from a YAML file.
// Pointer fields distinguish "not set" from zero value, allowing CLI flags to override.
type ClientFileConfig struct {
	Server     string        `yaml:"server"`
	PubKey     string        `yaml:"pubkey"`
	ClientID   string        `yaml:"client_id"`
	Socks      string        `yaml:"socks"`
	TLS        bool          `yaml:"tls"`
	SkipVerify bool          `yaml:"skip_verify"`
	CDN        string        `yaml:"cdn"`
	WebSocket  bool          `yaml:"websocket"`
	Auto       bool          `yaml:"auto"`
	Routing    RoutingConfig `yaml:"routing"`
	Warmup     *bool         `yaml:"warmup"`
	ECH        bool          `yaml:"ech"`
	Origin     string        `yaml:"origin"` // Origin IP for direct WS (bypass CF CDN)
	SNI        string        `yaml:"sni"`    // TLS ServerName override when connecting to IP directly (full-direct mode)
	CFIP       string        `yaml:"cfip"`   // Specific Cloudflare edge IP (bypass DNS, keep domain as TLS SNI)
	// BackupServers is a list of fallback "host:port" endpoints. When the
	// primary Server fails to handshake (e.g. ТСПУ blocks the CF domain by
	// SNI), the client tries each backup in order. Each backup must point
	// to the same underlying ShadowLink server (same X25519 pubkey) but via
	// a different CF domain (or IP).
	BackupServers []string `yaml:"backup_servers,omitempty"`
	// CDNs is the SNI rotation pool. Distinct from BackupServers (alternative
	// host:port endpoints). Max 8 entries. When non-empty, DomainPool rotates
	// SNI per reconnect against this list.
	CDNs []string `yaml:"cdns,omitempty"`
}

// RoutingConfig holds per-domain routing rules from the YAML file.
type RoutingConfig struct {
	Bypass []string `yaml:"bypass"`
	Force  []string `yaml:"force"`
	Block  []string `yaml:"block"`
}

// LoadClientConfig reads and parses a YAML client config file.
// C-1 fix: warns if file permissions are too open on Unix systems.
func LoadClientConfig(path string) (*ClientFileConfig, error) {
	warnClientConfigPermissions(path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config: %w", err)
	}
	var cc ClientFileConfig
	if err := yaml.Unmarshal(data, &cc); err != nil {
		return nil, fmt.Errorf("parse client config: %w", err)
	}
	return &cc, nil
}

// warnClientConfigPermissions logs a warning if the config file is readable by
// group or others. Skipped on Windows.
func warnClientConfigPermissions(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		slog.Warn("client config file has insecure permissions — should be 0600",
			"path", path, "mode", fmt.Sprintf("%04o", mode))
	}
}

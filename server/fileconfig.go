package server

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileConfig holds all server configuration fields from a YAML file.
// Pointer fields distinguish "not set" from zero value, allowing CLI flags to override.
type FileConfig struct {
	Listen       string         `yaml:"listen"`
	Cert         string         `yaml:"cert"`
	Key          string         `yaml:"key"`
	ServerKey    string         `yaml:"server_key"`
	Decoy        string         `yaml:"decoy"`
	MaxClients   *int           `yaml:"max_clients"`
	MaxConns     *int           `yaml:"max_conns"`
	ChunkSize    *int           `yaml:"chunk_size"`
	BehindProxy  *bool          `yaml:"behind_proxy"`
	EnableUDP    *bool          `yaml:"enable_udp"`
	UDPListen    string         `yaml:"udp_listen"`
	Management   *MgmtConfig    `yaml:"management"`
	Mimicry      *MimicryConfig `yaml:"mimicry"`
	BlockDomains      []string  `yaml:"block_domains"`
	AuthorizedClients []string  `yaml:"authorized_clients"`
}

// MgmtConfig holds management API configuration from the YAML file.
type MgmtConfig struct {
	Port              *int   `yaml:"port"`
	Bind              string `yaml:"bind"`
	Key               string `yaml:"key"`
	DefaultMaxDevices *int   `yaml:"default_max_devices"`
}

// MimicryConfig holds mimicry engine feature flags from the YAML file.
type MimicryConfig struct {
	CoverTraffic *bool `yaml:"cover_traffic"`
	Inflation    *bool `yaml:"inflation"`
}

// LoadConfigFile reads and parses a YAML config file into FileConfig.
// C-1 fix: warns if file permissions are too open on Unix systems.
// C-2 fix: expands ${ENV_VAR} references in sensitive fields after parsing.
func LoadConfigFile(path string) (*FileConfig, error) {
	warnInsecurePermissions(path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// C-2: expand env vars in sensitive fields
	if fc.Management != nil {
		fc.Management.Key = expandEnv(fc.Management.Key)
	}
	fc.ServerKey = expandEnv(fc.ServerKey)

	return &fc, nil
}

// warnInsecurePermissions logs a warning if the config file is readable by
// group or others. Skipped on Windows (no POSIX permission model).
func warnInsecurePermissions(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		slog.Warn("config file has insecure permissions — should be 0600",
			"path", path, "mode", fmt.Sprintf("%04o", mode))
	}
}

// expandEnv expands ${ENV_VAR} references in a string value.
// Returns the original string if not an env reference or env is not set.
func expandEnv(s string) string {
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		envKey := s[2 : len(s)-1]
		if val := os.Getenv(envKey); val != "" {
			return val
		}
		slog.Warn("env var referenced but not set", "var", envKey)
	}
	return s
}

// ApplyTo copies non-zero FileConfig values into cfg.
// Only fields that were explicitly set in the YAML (non-zero / non-nil) override cfg.
// CLI flags applied after this call will win because main() only calls ApplyTo before
// processing flag overrides.
func (fc *FileConfig) ApplyTo(cfg *Config) {
	if fc.Listen != "" {
		cfg.ListenAddr = fc.Listen
	}
	if fc.Cert != "" {
		cfg.CertFile = fc.Cert
	}
	if fc.Key != "" {
		cfg.KeyFile = fc.Key
	}
	if fc.ServerKey != "" {
		cfg.ServerKeyFile = fc.ServerKey
	}
	if fc.Decoy != "" {
		cfg.DecoyDir = fc.Decoy
	}
	if fc.MaxClients != nil {
		cfg.MaxClients = *fc.MaxClients
	}
	if fc.MaxConns != nil {
		cfg.MaxConnsPerClient = *fc.MaxConns
	}
	if fc.ChunkSize != nil {
		cfg.ChunkSize = *fc.ChunkSize
	}
	if fc.BehindProxy != nil {
		cfg.BehindProxy = *fc.BehindProxy
	}
	if fc.EnableUDP != nil {
		cfg.EnableUDP = *fc.EnableUDP
	}
	if fc.UDPListen != "" {
		cfg.UDPListenAddr = fc.UDPListen
	}
	if fc.Management != nil {
		if fc.Management.Port != nil {
			cfg.ManagementPort = *fc.Management.Port
		}
		if fc.Management.Bind != "" {
			cfg.ManagementBind = fc.Management.Bind
		}
		if fc.Management.Key != "" {
			cfg.ManagementKey = fc.Management.Key
		}
		if fc.Management.DefaultMaxDevices != nil {
			cfg.DefaultMaxDevices = *fc.Management.DefaultMaxDevices
		}
	}
	if len(fc.BlockDomains) > 0 {
		cfg.BlockDomains = fc.BlockDomains
	}
	if len(fc.AuthorizedClients) > 0 {
		cfg.AuthorizedClients = fc.AuthorizedClients
	}
	if fc.Mimicry != nil {
		if fc.Mimicry.Inflation != nil {
			cfg.UseInflatedResponses = *fc.Mimicry.Inflation
		}
	}
}

package server

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FileConfig holds all server configuration fields from a YAML file.
// Pointer fields distinguish "not set" from zero value, allowing CLI flags to override.
type FileConfig struct {
	Listen            string               `yaml:"listen"`
	Cert              string               `yaml:"cert"`
	Key               string               `yaml:"key"`
	ServerKey         string               `yaml:"server_key"`
	Decoy             string               `yaml:"decoy"`
	DomainDecoyMap    map[string]string    `yaml:"domain_decoy_map,omitempty"`
	MaxClients        *int                 `yaml:"max_clients"`
	MaxConns          *int                 `yaml:"max_conns"`
	ChunkSize         *int                 `yaml:"chunk_size"`
	BehindProxy       *bool                `yaml:"behind_proxy"`
	Management        *MgmtConfig          `yaml:"management"`
	Mimicry           *MimicryConfig       `yaml:"mimicry"`
	LiveBlog          *FileLiveBlogConfig  `yaml:"live_blog"`
	BlockDomains      []string             `yaml:"block_domains"`
	AuthorizedClients []string             `yaml:"authorized_clients"`
	RateLimit         *FileRateLimitConfig `yaml:"rate_limit"`

	// IdleTimeoutSec is the HTTP server IdleTimeout in seconds.
	// Valid range: [60, 600]. Default (when nil): 300 (Wave 2.3 hardcoded).
	// Task 5.1 (2026-05-17): exposed via YAML for ops tuning. Wiring through
	// to httpSrv.IdleTimeout is deferred — for now Load() validates the value
	// but startup keeps the 300s hardcode.
	IdleTimeoutSec *int `yaml:"idle_timeout_sec"`

	// ServerHeader overrides the HTTP `Server:` response header for masquerade
	// (e.g. "nginx/1.24.0"). Default (nil): no override — Go's default is used
	// (or omitted when responding from the embedded handler). Wiring deferred
	// to Wave 2.4 — Load() accepts the value but it is not yet emitted.
	ServerHeader *string `yaml:"server_header"`
}

// FileRateLimitConfig is the YAML representation of RateLimitConfig.
// All fields are pointers so "absent" is distinguishable from "zero" — only
// explicitly-set values override the defaults applied at NewHandler.
// Plan §C6 (May audit, 2026-05-02).
type FileRateLimitConfig struct {
	WSUpgrade             *FileRateLimitBucketSpec `yaml:"ws_upgrade"`
	Handshake             *FileRateLimitBucketSpec `yaml:"handshake"`
	ClientIDLruSize       *int                     `yaml:"client_id_lru_size"`
	ClientIDTTLMin        *int                     `yaml:"client_id_ttl_min"`
	ClientIDSoftLimit     *int                     `yaml:"client_id_soft_limit"`
	ClientIDSoftWindowSec *int                     `yaml:"client_id_soft_window_sec"`
}

// FileRateLimitBucketSpec is the YAML representation of RateLimitBucketSpec.
type FileRateLimitBucketSpec struct {
	Burst        *int `yaml:"burst"`
	RefillPerMin *int `yaml:"refill_per_min"`
}

// FileLiveBlogConfig holds live-blog decoy settings from YAML.
// Duration fields are strings because YAML time.Duration parsing is awkward —
// they are converted via time.ParseDuration in ApplyTo.
// Pointer fields distinguish "not set" from zero value.
type FileLiveBlogConfig struct {
	Enabled           *bool    `yaml:"enabled"`
	Upstream          string   `yaml:"upstream"`
	CDNUpstream       string   `yaml:"cdn_upstream"`
	CacheTTL          string   `yaml:"cache_ttl"`
	CacheMaxEntries   *int     `yaml:"cache_max_entries"`
	CacheStaleGrace   string   `yaml:"cache_stale_grace"`
	UpstreamRPS       *float64 `yaml:"upstream_rps"`
	UpstreamBurst     *int     `yaml:"upstream_burst"`
	UpstreamTimeout   string   `yaml:"upstream_timeout"`
	MaxBodyBytes      *int     `yaml:"max_body_bytes"`
	CDNMaxBodyBytes   *int     `yaml:"cdn_max_body_bytes"`
	CanaryArticleID   string   `yaml:"canary_article_id"`
	CanaryInterval    string   `yaml:"canary_interval"`
	TargetBrand       string   `yaml:"target_brand"`
	TargetLogoPath    string   `yaml:"target_logo_path"`
	TargetTitleSuffix string   `yaml:"target_title_suffix"`
}

// MgmtConfig holds management API configuration from the YAML file.
type MgmtConfig struct {
	Port              *int   `yaml:"port"`
	Bind              string `yaml:"bind"`
	Key               string `yaml:"key"`
	DefaultMaxDevices *int   `yaml:"default_max_devices"`
}

// MimicryConfig holds mimicry engine feature flags from the YAML file.
//
// Task 5.1 (2026-05-17): extended with tuning knobs for the WS pool size,
// decoy GET cadence, and preamble count range. All new fields are pointers
// so absent-in-YAML is distinguishable from explicit zero. Validation is
// performed in LoadConfigFile; runtime wiring is deferred — only Inflation
// is honored today. Logged at startup for ops verification.
type MimicryConfig struct {
	CoverTraffic *bool `yaml:"cover_traffic"`
	Inflation    *bool `yaml:"inflation"`

	// WSPoolSize is the target WebSocket pool size. Valid range: [1, 8].
	// Default (when nil): 6 (current hardcode in ws_ready_pool). Wiring
	// deferred until pool-size spike.
	WSPoolSize *int `yaml:"ws_pool_size"`

	// DecoyGetIntervalBurstMs is the decoy GET inter-arrival during burst
	// phase, in milliseconds. Valid range: [100, 1000]. Default 250.
	DecoyGetIntervalBurstMs *int `yaml:"decoy_get_interval_burst_ms"`

	// DecoyGetIntervalQuietSec is the decoy GET inter-arrival during quiet
	// phase, in seconds. Valid range: [15, 300]. Default 60.
	DecoyGetIntervalQuietSec *int `yaml:"decoy_get_interval_quiet_sec"`

	// PreambleCountMin is the lower bound of the WarmupRequests preamble
	// count distribution. Valid range: [1, 5]. Default 3.
	PreambleCountMin *int `yaml:"preamble_count_min"`

	// PreambleCountMax is the upper bound of the WarmupRequests preamble
	// count distribution. Valid range: [3, 15]. Default 7. Must be
	// >= PreambleCountMin.
	PreambleCountMax *int `yaml:"preamble_count_max"`
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

	// Task 5.1 (2026-05-17): fail-fast range validation for mimicry tuning
	// knobs + root idle_timeout_sec. Each field is independently optional —
	// only validated when explicitly set in YAML. Out-of-range values abort
	// startup with the field name + observed value in the error, so the
	// operator can fix the config rather than silently shipping defaults.
	if err := validateMimicryRanges(&fc); err != nil {
		return nil, err
	}

	return &fc, nil
}

// validateMimicryRanges enforces the fail-fast invariants declared on
// MimicryConfig pointer fields and FileConfig.IdleTimeoutSec. Returns nil
// when every set field is in range; otherwise returns an error naming the
// offending field. Cross-field constraint:
// PreambleCountMin <= PreambleCountMax.
func validateMimicryRanges(fc *FileConfig) error {
	if fc.Mimicry != nil {
		if fc.Mimicry.WSPoolSize != nil {
			v := *fc.Mimicry.WSPoolSize
			if v < 1 || v > 8 {
				return fmt.Errorf("ws_pool_size must be in [1,8], got %d", v)
			}
		}
		if fc.Mimicry.DecoyGetIntervalBurstMs != nil {
			v := *fc.Mimicry.DecoyGetIntervalBurstMs
			if v < 100 || v > 1000 {
				return fmt.Errorf("decoy_get_interval_burst_ms must be in [100,1000], got %d", v)
			}
		}
		if fc.Mimicry.DecoyGetIntervalQuietSec != nil {
			v := *fc.Mimicry.DecoyGetIntervalQuietSec
			if v < 15 || v > 300 {
				return fmt.Errorf("decoy_get_interval_quiet_sec must be in [15,300], got %d", v)
			}
		}
		if fc.Mimicry.PreambleCountMin != nil {
			v := *fc.Mimicry.PreambleCountMin
			if v < 1 || v > 5 {
				return fmt.Errorf("preamble_count_min must be in [1,5], got %d", v)
			}
		}
		if fc.Mimicry.PreambleCountMax != nil {
			v := *fc.Mimicry.PreambleCountMax
			if v < 3 || v > 15 {
				return fmt.Errorf("preamble_count_max must be in [3,15], got %d", v)
			}
		}
		if fc.Mimicry.PreambleCountMin != nil && fc.Mimicry.PreambleCountMax != nil {
			lo, hi := *fc.Mimicry.PreambleCountMin, *fc.Mimicry.PreambleCountMax
			if lo > hi {
				return fmt.Errorf("preamble_count_min (%d) > preamble_count_max (%d)", lo, hi)
			}
		}
	}
	if fc.IdleTimeoutSec != nil {
		v := *fc.IdleTimeoutSec
		if v < 60 || v > 600 {
			return fmt.Errorf("idle_timeout_sec must be in [60,600], got %d", v)
		}
	}
	return nil
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
	if len(fc.DomainDecoyMap) > 0 {
		cfg.DomainDecoyMap = fc.DomainDecoyMap
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
	// Default-on per Wave 1.1 (audit 2026-05-17 found flag absent in pl1 config →
	// all T2.4 mimicry distributions dead code in prod). A/B perf-measure on
	// pl1-canary required before broad rollout — see
	// docs/superpowers/plans/2026-05-17-pl1-ab-perf-measure.md
	cfg.UseInflatedResponses = true
	if fc.Mimicry != nil && fc.Mimicry.Inflation != nil {
		cfg.UseInflatedResponses = *fc.Mimicry.Inflation
	}
	if fc.LiveBlog != nil {
		lb := &cfg.LiveBlog
		if fc.LiveBlog.Enabled != nil {
			lb.Enabled = *fc.LiveBlog.Enabled
		}
		if fc.LiveBlog.Upstream != "" {
			lb.Upstream = fc.LiveBlog.Upstream
		}
		if fc.LiveBlog.CDNUpstream != "" {
			lb.CDNUpstream = fc.LiveBlog.CDNUpstream
		}
		if fc.LiveBlog.CacheTTL != "" {
			if d, err := time.ParseDuration(fc.LiveBlog.CacheTTL); err == nil {
				lb.CacheTTL = d
			}
		}
		if fc.LiveBlog.CacheMaxEntries != nil {
			lb.CacheMaxEntries = *fc.LiveBlog.CacheMaxEntries
		}
		if fc.LiveBlog.CacheStaleGrace != "" {
			if d, err := time.ParseDuration(fc.LiveBlog.CacheStaleGrace); err == nil {
				lb.CacheStaleGrace = d
			}
		}
		if fc.LiveBlog.UpstreamRPS != nil {
			lb.UpstreamRPS = *fc.LiveBlog.UpstreamRPS
		}
		if fc.LiveBlog.UpstreamBurst != nil {
			lb.UpstreamBurst = *fc.LiveBlog.UpstreamBurst
		}
		if fc.LiveBlog.UpstreamTimeout != "" {
			if d, err := time.ParseDuration(fc.LiveBlog.UpstreamTimeout); err == nil {
				lb.UpstreamTimeout = d
			}
		}
		if fc.LiveBlog.MaxBodyBytes != nil {
			lb.MaxBodyBytes = *fc.LiveBlog.MaxBodyBytes
		}
		if fc.LiveBlog.CDNMaxBodyBytes != nil {
			lb.CDNMaxBodyBytes = *fc.LiveBlog.CDNMaxBodyBytes
		}
		if fc.LiveBlog.CanaryArticleID != "" {
			lb.CanaryArticleID = fc.LiveBlog.CanaryArticleID
		}
		if fc.LiveBlog.CanaryInterval != "" {
			if d, err := time.ParseDuration(fc.LiveBlog.CanaryInterval); err == nil {
				lb.CanaryInterval = d
			}
		}
		if fc.LiveBlog.TargetBrand != "" {
			lb.TargetBrand = fc.LiveBlog.TargetBrand
		}
		if fc.LiveBlog.TargetLogoPath != "" {
			lb.TargetLogoPath = fc.LiveBlog.TargetLogoPath
		}
		if fc.LiveBlog.TargetTitleSuffix != "" {
			lb.TargetTitleSuffix = fc.LiveBlog.TargetTitleSuffix
		}
	}
	if fc.RateLimit != nil {
		rl := &cfg.RateLimit
		if fc.RateLimit.WSUpgrade != nil {
			if fc.RateLimit.WSUpgrade.Burst != nil {
				rl.WSUpgrade.Burst = *fc.RateLimit.WSUpgrade.Burst
			}
			if fc.RateLimit.WSUpgrade.RefillPerMin != nil {
				rl.WSUpgrade.RefillPerMin = *fc.RateLimit.WSUpgrade.RefillPerMin
			}
		}
		if fc.RateLimit.Handshake != nil {
			if fc.RateLimit.Handshake.Burst != nil {
				rl.Handshake.Burst = *fc.RateLimit.Handshake.Burst
			}
			if fc.RateLimit.Handshake.RefillPerMin != nil {
				rl.Handshake.RefillPerMin = *fc.RateLimit.Handshake.RefillPerMin
			}
		}
		if fc.RateLimit.ClientIDLruSize != nil {
			rl.ClientIDLruSize = *fc.RateLimit.ClientIDLruSize
		}
		if fc.RateLimit.ClientIDTTLMin != nil {
			rl.ClientIDTTLMin = *fc.RateLimit.ClientIDTTLMin
		}
		if fc.RateLimit.ClientIDSoftLimit != nil {
			rl.ClientIDSoftLimit = *fc.RateLimit.ClientIDSoftLimit
		}
		if fc.RateLimit.ClientIDSoftWindowSec != nil {
			rl.ClientIDSoftWindowSec = *fc.RateLimit.ClientIDSoftWindowSec
		}
	}
}

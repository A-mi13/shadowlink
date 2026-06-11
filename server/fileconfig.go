package server

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// domainDecoyEntry — новый YAML формат per-host (Phase G, spec §8.2):
//
//	domain_decoy_map:
//	  "host.example.com":
//	    directory: "/var/www/saas-landing"
//	    persona: "saas"
//
// Поле раскрывается в `FileConfig.DomainDecoyMap` (host→directory) и
// `FileConfig.DomainPersonaMap` (host→persona). Legacy формат
// (`host: directory` строкой) тоже поддерживается — см. LoadConfigFile.
type domainDecoyEntry struct {
	Directory string `yaml:"directory"`
	Persona   string `yaml:"persona"`
}

// FileConfig holds all server configuration fields from a YAML file.
// Pointer fields distinguish "not set" from zero value, allowing CLI flags to override.
type FileConfig struct {
	Listen    string `yaml:"listen"`
	Cert      string `yaml:"cert"`
	Key       string `yaml:"key"`
	ServerKey string `yaml:"server_key"`
	Decoy     string `yaml:"decoy"`

	// DomainDecoyMap — host→directory map, заполняется в LoadConfigFile из
	// RawDomainDecoyMap. Поддерживается ОБА YAML формата: legacy single-line
	// (`"host": "/dir"`) и Phase G v2 (`"host": {directory, persona}`).
	DomainDecoyMap map[string]string `yaml:"-"`

	// DomainPersonaMap — host→persona map. Заполняется ТОЛЬКО для нового
	// формата; для legacy format остаётся nil. Phase G (spec §8.2).
	DomainPersonaMap map[string]string `yaml:"-"`

	// RawDomainDecoyMap — сырой узел YAML под ключом `domain_decoy_map`.
	// LoadConfigFile делает try-new-then-legacy decode и наполняет два поля
	// выше. Здесь хранится для интероп: пустой узел = поле отсутствует.
	RawDomainDecoyMap yaml.Node `yaml:"domain_decoy_map,omitempty"`

	MaxClients        *int                 `yaml:"max_clients"`
	MaxConns          *int                 `yaml:"max_conns"`
	ChunkSize         *int                 `yaml:"chunk_size"`
	BehindProxy       *bool                `yaml:"behind_proxy"`
	Management        *MgmtConfig          `yaml:"management"`
	Mimicry           *MimicryConfig       `yaml:"mimicry"`
	BlockDomains      []string             `yaml:"block_domains"`
	AuthorizedClients []string             `yaml:"authorized_clients"`
	RateLimit         *FileRateLimitConfig `yaml:"rate_limit"`

	// OriginDeathTeardown (Bug #10) gates the origin-death → FlagStreamClose
	// signal. nil → leaves Config.OriginDeathTeardown untouched (default OFF via
	// originDeathTeardownEnabledOrDefault). A YAML `origin_death_teardown: true`
	// turns it on; this pointer is propagated (not deref'd) so absence stays nil.
	OriginDeathTeardown *bool `yaml:"origin_death_teardown,omitempty"`

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

	// FingerprintWeights defines relative weights for browser TLS fingerprint
	// profiles used in population mimicry (C2, FP-mimicry feature).
	// Keys are profile names (e.g. "chrome", "firefox"); values are relative
	// weights. Absent section → nil map → client defaults to chrome 100%.
	//
	// fingerprint_weights: относительные веса browser-профилей для популяционной
	// мимикрии. Веса ДОЛЖНЫ отражать реальную популяцию браузеров целевого региона.
	// Для РФ Firefox ≲ 10-15% — нереалистичная пропорция (напр. 50% Firefox) сама
	// становится детектируемой аномалией. Отсутствие секции → chrome 100% (дефолт).
	// fingerprint_weights:
	//   chrome: 100
	//   firefox: 0
	FingerprintWeights map[string]int `yaml:"fingerprint_weights,omitempty"`
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

// hasNewFormatEntry возвращает true, если хотя бы одна запись содержит
// non-empty Directory — индикатор нового Phase G формата. Legacy формат
// (`"host": "/dir"` плоской строкой) при попытке decode в map[string]domainDecoyEntry
// либо сразу падает (тип mismatch), либо даёт все-пустые struct'ы.
func hasNewFormatEntry(m map[string]domainDecoyEntry) bool {
	for _, v := range m {
		if v.Directory != "" {
			return true
		}
	}
	return false
}

// LoadConfigFile reads and parses a YAML config file into FileConfig.
// C-1 fix: warns if file permissions are too open on Unix systems.
// C-2 fix: expands ${ENV_VAR} references in sensitive fields after parsing.
//
// Phase G (spec §8.2): `domain_decoy_map` декодируется через RawDomainDecoyMap
// (yaml.Node) — пробуем новый формат `{directory, persona}` per host, fallback
// на legacy `host: directory`. Backwards compat: оба формата поддерживаются;
// сосуществовать в одном файле нельзя — выбирается тот, который успешно
// декодируется первым (новый, если хоть одна запись имеет non-empty
// `directory`).
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

	// Phase G post-process: domain_decoy_map — try new-format first, legacy fallback.
	if fc.RawDomainDecoyMap.Kind != 0 {
		newFmt := make(map[string]domainDecoyEntry)
		if err := fc.RawDomainDecoyMap.Decode(&newFmt); err == nil && hasNewFormatEntry(newFmt) {
			fc.DomainDecoyMap = make(map[string]string, len(newFmt))
			fc.DomainPersonaMap = make(map[string]string, len(newFmt))
			for host, entry := range newFmt {
				fc.DomainDecoyMap[host] = entry.Directory
				if entry.Persona != "" {
					fc.DomainPersonaMap[host] = entry.Persona
				}
			}
		} else {
			oldFmt := make(map[string]string)
			if err := fc.RawDomainDecoyMap.Decode(&oldFmt); err != nil {
				return nil, fmt.Errorf("parse domain_decoy_map (tried new and legacy formats): %w", err)
			}
			fc.DomainDecoyMap = oldFmt
			fc.DomainPersonaMap = nil
		}
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
	// Phase G — propagate persona map so NewDecoyHandlerV2 in handler.go can
	// route per-host responses through the right persona setters. Without this
	// copy the YAML parser populates DomainPersonaMap but the handler never sees
	// it — silent fallback to default persona for every host.
	if len(fc.DomainPersonaMap) > 0 {
		cfg.DomainPersonaMap = fc.DomainPersonaMap
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
	// Bug #10: propagate the pointer (not the value) so an absent YAML key leaves
	// Config.OriginDeathTeardown nil (→ default OFF). A CLI -origin-death-teardown
	// flag still wins over this in main.go (applied after ApplyTo).
	if fc.OriginDeathTeardown != nil {
		cfg.OriginDeathTeardown = fc.OriginDeathTeardown
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
	// C2 (FP-mimicry): propagate fingerprint_weights from YAML into Config so the
	// handler can embed them in ServerHello. Only copied when explicitly set in
	// YAML (len > 0) — absent section keeps Config.FingerprintWeights nil, which
	// the client interprets as "chrome 100%".
	if len(fc.FingerprintWeights) > 0 {
		cfg.FingerprintWeights = fc.FingerprintWeights
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

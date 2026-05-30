// ShadowLink server entry point.
//
// # Phase B deploy order (bearer→body-prefix migration)
//
// This server supports BOTH the legacy Bearer-header client contract and the
// new body-prefix contract. Hybrid dispatch routes requests by Authorization
// header presence. During migration:
//
//  1. Deploy the updated CLIENT first (client/client.go reads `_v` from
//     ServerHello). Old binaries that ignore `_v` won't decrypt session
//     tokens when the server chooses v1 keys for a handshake that lands in
//     the new-path router (97-byte UUID-sized payload with no Authorization).
//  2. Then deploy this SERVER. UUID-sized legacy clients without the `_v`
//     reader fix will fail handshake (~30-60s breakage window) until they
//     pick up the new client binary.
//  3. Monitor `handshakes_new_total / handshakes_total` (migration ratio)
//     and `v0_fallback_from_new_path` (legacy clients entering via new
//     path — helps size the migration tail).
//  4. Monitor `dual_auth_detected` — fires when a v1-migrated client still
//     sends the Authorization header; indicates a client rollout bug.
//
// See docs/superpowers/specs/2026-04-20-bearer-body-prefix-migration.md for
// the full protocol spec.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/server"
)

func main() {
	// Subcommand dispatch — must be before flag.Parse() so the global flagset
	// does not consume subcommand-specific flags.
	if len(os.Args) > 1 && os.Args[1] == "export-client-config" {
		runExportClientConfig(os.Args[2:])
		return
	}

	configFile := flag.String("config", "", "Path to YAML config file")
	listen := flag.String("listen", ":443", "Listen address (e.g., :443 or 0.0.0.0:8443)")
	cert := flag.String("cert", "", "TLS certificate file path")
	key := flag.String("key", "", "TLS private key file path")
	serverKeyFile := flag.String("server-key", "", "ShadowLink static key file (64 hex chars)")
	decoyDir := flag.String("decoy", "", "Decoy site directory (static files)")
	maxClients := flag.Int("max-clients", 500, "Maximum concurrent client sessions")
	maxConns := flag.Int("max-conns", 8, "Maximum connections per client")
	chunkSize := flag.Int("chunk-size", 12288, "Max chunk payload size in bytes")
	behindProxy := flag.Bool("behind-proxy", false, "Trust X-Forwarded-For (when behind nginx/CDN)")
	mgmtPort := flag.Int("mgmt-port", 0, "Management API port (0=disabled)")
	mgmtBind := flag.String("mgmt-bind", "127.0.0.1", "Management API bind address")
	mgmtKey := flag.String("mgmt-key", "", "Management API key")
	defaultMaxDevices := flag.Int("default-max-devices", 3, "Default device limit per user")
	genKey := flag.Bool("gen-key", false, "Generate a new server key and exit")
	validateConfig := flag.String("validate-config", "", "parse YAML config file at PATH, exit 0 if OK / non-zero on error; no server starts")
	decoySnapshotPaths := flag.String("decoy-snapshot-paths", "index.html", "comma-separated paths (relative to -decoy dir) of decoy HTML files to pre-bake for SentinelEmitter dual-carrier rate-limit responses")
	decoySnapshotStrict := flag.Bool("decoy-snapshot-strict", false,
		"if true, fail-fast on decoy snapshot loading errors (default: warn and continue header-only)")
	flowMaxWindow := flag.Int("flow-max-window", 1048576, "Bug #8: max per-stream flow-control window (bytes) the server grants; 0 disables flow control")
	flag.Parse()

	if *validateConfig != "" {
		if err := validateConfigAndExit(*validateConfig); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("OK")
		os.Exit(0)
	}

	if *genKey {
		kp, err := core.GenerateKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Private key: %s\n", hex.EncodeToString(kp.Private))
		fmt.Printf("Public key:  %s\n", hex.EncodeToString(kp.Public))
		fmt.Println("\nSave private key to a file and use --server-key <file>")
		fmt.Println("Share public key with clients for handshake authentication.")
		return
	}

	// Start from production defaults, then apply YAML file (if provided),
	// then let explicitly-passed CLI flags win.
	config := server.DefaultConfig()
	config.SessionTimeout = 5 * time.Minute
	config.CleanupInterval = 30 * time.Second

	if *configFile != "" {
		fc, err := server.LoadConfigFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
			os.Exit(1)
		}
		fc.ApplyTo(&config)
		// Task 5.1 (2026-05-17): surface mimicry config in startup logs for ops
		// verification. Only `inflation` is currently wired through to runtime
		// behavior (UseInflatedResponses); the other knobs (ws_pool_size, decoy
		// GET cadence, preamble range, idle_timeout_sec, server_header) are
		// validated by LoadConfigFile but wiring is deferred — see Task 5.1
		// docs/superpowers/plans/2026-05-17-shadowlink-improvements.md.
		logMimicryConfig(fc, &config)
	}

	// Track which flags were explicitly set by the user so YAML values are not
	// silently overridden by flag defaults.
	explicitly := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { explicitly[f.Name] = true })

	if explicitly["listen"] {
		config.ListenAddr = *listen
	}
	if explicitly["cert"] {
		config.CertFile = *cert
	}
	if explicitly["key"] {
		config.KeyFile = *key
	}
	if explicitly["server-key"] {
		config.ServerKeyFile = *serverKeyFile
	}
	if explicitly["decoy"] {
		config.DecoyDir = *decoyDir
	}
	if explicitly["max-clients"] {
		config.MaxClients = *maxClients
	}
	if explicitly["max-conns"] {
		config.MaxConnsPerClient = *maxConns
	}
	if explicitly["chunk-size"] {
		config.ChunkSize = *chunkSize
	}
	if explicitly["behind-proxy"] {
		config.BehindProxy = *behindProxy
	}
	if explicitly["mgmt-port"] {
		config.ManagementPort = *mgmtPort
	}
	if explicitly["mgmt-bind"] {
		config.ManagementBind = *mgmtBind
	}
	if explicitly["mgmt-key"] {
		config.ManagementKey = *mgmtKey
	}
	if explicitly["default-max-devices"] {
		config.DefaultMaxDevices = *defaultMaxDevices
	}
	// Always apply flow-max-window: flag default (1048576) applies when not
	// explicitly set; explicit 0 disables flow control on the server.
	config.FlowMaxWindow = uint64(*flowMaxWindow)
	srv, err := server.New(config, nil)
	if err != nil {
		slog.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	// Phase 1 (2026-05-14): pre-bake decoy snapshots for SentinelEmitter
	// (dual-carrier rate-limit: Schema.org body marker + X-SL-RL).
	//
	// Snapshot paths are read from -decoy-snapshot-paths (comma-separated,
	// relative to -decoy dir). On failure, default mode is graceful degradation
	// (header-only); use -decoy-snapshot-strict=true for fail-fast (CI/staging).
	//
	// If no decoy dir is set (e.g., Telegraph-proxy deploy without static files),
	// SentinelEmitter is left nil and rate-limit branches fall back to the legacy
	// writeRateLimitSentinelV2 header-only path.
	if config.DecoyDir != "" {
		snapshotPaths := strings.Split(*decoySnapshotPaths, ",")
		// Graceful degradation: if snapshot loading fails (e.g., templates not
		// yet updated with Schema.org baseline), log a clear warning and continue
		// without the body-marker carrier. Header carrier (X-SL-RL) still works
		// via the legacy path in failClosedToDecoyRateLimitedV2. This prevents
		// pl1 outage during rollout when templates may be partial.
		//
		// To force fail-fast (e.g., in CI/staging where missing baseline is
		// definitely a bug), set -decoy-snapshot-strict=true.
		snapshots, snapErr := server.LoadDecoySnapshots(config.DecoyDir, snapshotPaths)
		if snapErr != nil {
			if *decoySnapshotStrict {
				slog.Error("decoy snapshot loading failed (strict mode)", "err", snapErr)
				os.Exit(1)
			}
			slog.Warn("decoy snapshot loading failed; body-marker carrier disabled, header-only mode active",
				"err", snapErr,
				"hint", "update decoy templates with Schema.org rl-state baseline, then restart")
			snapshots = nil // SentinelEmitter handles nil → header-only path
		}
		srv.SetSentinelEmitter(server.NewSentinelEmitter(snapshots, srv.Metrics()))
		slog.Info("SentinelEmitter initialized", "snapshot_count", len(snapshots))
	} else {
		slog.Info("no decoy dir configured — SentinelEmitter disabled, using header-only rate-limit fallback")
	}

	addr, err := srv.Start()
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	slog.Info("ShadowLink server running", "addr", addr)

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("received shutdown signal")
	if err := srv.Stop(); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	slog.Info("server stopped")
}

// validateConfigAndExit loads the YAML file at path and applies it to a
// baseline server.Config. Returns non-nil error on any parse problem.
//
// Used by deploy scripts (shadowlink-apply-config.sh) for pre-flight validation
// before systemd restart — if this returns non-zero, the deploy aborts without
// touching the running server.
func validateConfigAndExit(path string) error {
	fcfg, err := server.LoadConfigFile(path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	baseline := server.DefaultConfig()
	fcfg.ApplyTo(&baseline)
	return nil
}

// logMimicryConfig surfaces the active mimicry config in the startup log so
// ops can verify the YAML→runtime mapping (Task 5.1, 2026-05-17). Wired
// fields are logged with their effective Config value; deferred-wiring
// fields are logged with the raw FileConfig pointer (or "default" when nil)
// to flag that the operator's choice is currently inert.
func logMimicryConfig(fc *server.FileConfig, cfg *server.Config) {
	attrs := []any{
		"inflation_wired", cfg.UseInflatedResponses,
		"idle_timeout_sec_runtime", 300, // Wave 2.3 hardcoded; wiring deferred
	}

	if fc.IdleTimeoutSec != nil {
		attrs = append(attrs, "idle_timeout_sec_yaml", *fc.IdleTimeoutSec, "idle_timeout_wired", false)
	}
	if fc.ServerHeader != nil {
		attrs = append(attrs, "server_header_yaml", *fc.ServerHeader, "server_header_wired", false)
	}

	if fc.Mimicry != nil {
		if fc.Mimicry.WSPoolSize != nil {
			attrs = append(attrs, "ws_pool_size_yaml", *fc.Mimicry.WSPoolSize, "ws_pool_size_wired", false)
		}
		if fc.Mimicry.DecoyGetIntervalBurstMs != nil {
			attrs = append(attrs, "decoy_get_interval_burst_ms_yaml", *fc.Mimicry.DecoyGetIntervalBurstMs, "decoy_burst_wired", false)
		}
		if fc.Mimicry.DecoyGetIntervalQuietSec != nil {
			attrs = append(attrs, "decoy_get_interval_quiet_sec_yaml", *fc.Mimicry.DecoyGetIntervalQuietSec, "decoy_quiet_wired", false)
		}
		if fc.Mimicry.PreambleCountMin != nil {
			attrs = append(attrs, "preamble_count_min_yaml", *fc.Mimicry.PreambleCountMin, "preamble_min_wired", false)
		}
		if fc.Mimicry.PreambleCountMax != nil {
			attrs = append(attrs, "preamble_count_max_yaml", *fc.Mimicry.PreambleCountMax, "preamble_max_wired", false)
		}
	}

	slog.Info("mimicry config", attrs...)
}

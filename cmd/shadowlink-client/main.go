package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/client/dnsrouter"
	"github.com/nixavpn/shadowlink/client/leakguard"
	"github.com/nixavpn/shadowlink/proxy/socks5"
	"github.com/nixavpn/shadowlink/skins/browser"
	"gopkg.in/yaml.v3"
)

func main() {
	configFile := flag.String("config", "", "Path to YAML config file")
	serverAddr := flag.String("server", "", "ShadowLink server address (host:port)")
	pubKey := flag.String("pubkey", "", "Server public key (64 hex chars)")
	clientID := flag.String("id", "shadowlink-client", "Client identifier")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 proxy address")
	useTLS := flag.Bool("tls", false, "Enable TLS (use for production)")
	skipVerify := flag.Bool("skip-verify", false, "Skip TLS certificate verification (testing)")
	cdnDomain := flag.String("cdn", "", "Cloudflare CDN domain (enables CDN mode)")
	useWS := flag.Bool("ws", false, "Use WebSocket for full-duplex relay (recommended)")
	autoProbe := flag.Bool("auto", false, "Auto-detect network and select transport")
	echEnabled := flag.Bool("ech", false, "Enable ECH (Encrypted Client Hello) for CDN mode")
	importURL := flag.String("import", "", "Import config from sl:// URL")
	saveConfig := flag.String("save", "", "Save imported config to YAML file")
	systemVPN := flag.Bool("system-vpn", false, "System VPN mode: kill switch + DNS/IPv6 leak protection")
	checkIP := flag.Bool("check-ip", false, "Check exit IP through tunnel and warn on datacenter/timezone mismatch")
	forceTransport := flag.String("transport", "", "Force transport: direct, cdn, wb_turn, call_skin (skip auto-detect)")
	dnsBypass := flag.Bool("dns-bypass", false, "Start local DNS proxy for domain-based bypass routing (use with TUN)")
	flag.Parse()

	// Track which flags were explicitly set by the user.
	explicitly := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { explicitly[f.Name] = true })

	// Handle --import: parse sl:// URL into config, optionally save
	var loadedConfig *client.ClientFileConfig
	if *importURL != "" {
		imported, err := client.ParseSLURL(*importURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing import URL: %v\n", err)
			os.Exit(1)
		}
		if *saveConfig != "" {
			yamlBytes, err := yaml.Marshal(imported)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling config: %v\n", err)
				os.Exit(1)
			}
			if err := os.WriteFile(*saveConfig, yamlBytes, 0600); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing config file: %v\n", err)
				os.Exit(1)
			}
			slog.Info("config saved", "path", *saveConfig)
		}
		loadedConfig = imported
		if !explicitly["server"] && imported.Server != "" {
			*serverAddr = imported.Server
		}
		if !explicitly["pubkey"] && imported.PubKey != "" {
			*pubKey = imported.PubKey
		}
		if !explicitly["id"] && imported.ClientID != "" {
			*clientID = imported.ClientID
		}
		if !explicitly["socks"] && imported.Socks != "" {
			*socksAddr = imported.Socks
		}
		if !explicitly["tls"] && imported.TLS {
			*useTLS = imported.TLS
		}
		if !explicitly["skip-verify"] && imported.SkipVerify {
			*skipVerify = imported.SkipVerify
		}
		if !explicitly["cdn"] && imported.CDN != "" {
			*cdnDomain = imported.CDN
		}
		if !explicitly["ws"] && imported.WebSocket {
			*useWS = imported.WebSocket
		}
		if !explicitly["auto"] && imported.Auto {
			*autoProbe = imported.Auto
		}
		if !explicitly["ech"] && imported.ECH {
			*echEnabled = imported.ECH
		}
	}

	// Load YAML config file if provided; its values become defaults that CLI flags override.
	if *configFile != "" {
		cc, err := client.LoadClientConfig(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
			os.Exit(1)
		}
		loadedConfig = cc
		// Apply file values only when the corresponding CLI flag was not explicitly set.
		if !explicitly["server"] && cc.Server != "" {
			*serverAddr = cc.Server
		}
		if !explicitly["pubkey"] && cc.PubKey != "" {
			*pubKey = cc.PubKey
		}
		if !explicitly["id"] && cc.ClientID != "" {
			*clientID = cc.ClientID
		}
		if !explicitly["socks"] && cc.Socks != "" {
			*socksAddr = cc.Socks
		}
		if !explicitly["tls"] && cc.TLS {
			*useTLS = cc.TLS
		}
		if !explicitly["skip-verify"] && cc.SkipVerify {
			*skipVerify = cc.SkipVerify
		}
		if !explicitly["cdn"] && cc.CDN != "" {
			*cdnDomain = cc.CDN
		}
		if !explicitly["ws"] && cc.WebSocket {
			*useWS = cc.WebSocket
		}
		if !explicitly["auto"] && cc.Auto {
			*autoProbe = cc.Auto
		}
		if !explicitly["ech"] && cc.ECH {
			*echEnabled = cc.ECH
		}
	}

	if *serverAddr == "" || *pubKey == "" {
		fmt.Fprintln(os.Stderr, "Usage: shadowlink-client -server HOST:PORT -pubkey HEX_KEY")
		fmt.Fprintln(os.Stderr, "   or: shadowlink-client --import sl://PUBKEY@HOST:PORT?params")
		fmt.Fprintln(os.Stderr, "   or: shadowlink-client --config client.yaml")
		fmt.Fprintln(os.Stderr, "\nRequired (one of):")
		fmt.Fprintln(os.Stderr, "  -server + -pubkey  Server address and public key")
		fmt.Fprintln(os.Stderr, "  --import           Import from sl:// URL")
		fmt.Fprintln(os.Stderr, "  --config           Load from YAML config file")
		fmt.Fprintln(os.Stderr, "\nOptional:")
		fmt.Fprintln(os.Stderr, "  --save     Save imported config to YAML file")
		fmt.Fprintln(os.Stderr, "  -socks     Local SOCKS5 address (default 127.0.0.1:1080)")
		fmt.Fprintln(os.Stderr, "  -tls       Enable TLS")
		fmt.Fprintln(os.Stderr, "  -cdn       Cloudflare domain for CDN mode")
		fmt.Fprintln(os.Stderr, "  -auto      Auto-detect network conditions")
		os.Exit(1)
	}

	pubKeyBytes, err := hex.DecodeString(*pubKey)
	if err != nil || len(pubKeyBytes) != 32 {
		fmt.Fprintln(os.Stderr, "Error: pubkey must be 64 hex characters (32 bytes)")
		os.Exit(1)
	}

	// ECH only makes sense in CDN mode (requires TLS + CDN domain for SNI protection).
	if *echEnabled && *cdnDomain == "" {
		slog.Warn("--ech has no effect without --cdn: ECH hides the SNI in CDN mode only")
	}

	// Build router from file config (or empty rules = tunnel everything by default)
	var router *client.Router
	if loadedConfig != nil {
		router = client.NewRouter(loadedConfig.Routing)
	} else {
		router = client.NewRouter(client.RoutingConfig{})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cl *client.Client

	if *forceTransport == "wb_turn" {
		// WB TURN mode: launch wbturn.exe as child process for KCP/yamux tunnel
		// ShadowLink polling over TURN is too slow; KCP/yamux gives 70-145 Mbps
		serverHost, _, _ := net.SplitHostPort(*serverAddr)
		wbturnAddr := serverHost + ":56000"
		slog.Info("WB TURN mode: launching wbturn proxy", "server", wbturnAddr)

		// Find wbturn binary
		wbturnBin := findWBTurnBinary()
		if wbturnBin == "" {
			slog.Error("wbturn binary not found — place wbturn.exe next to shadowlink-client")
			os.Exit(1)
		}

		// Launch wbturn as child process with same SOCKS5 address
		// Password: first 16 chars of hex pubkey (shared secret for KCP)
		kcpPass := *pubKey
		if len(kcpPass) > 16 {
			kcpPass = kcpPass[:16]
		}
		cmd := exec.Command(wbturnBin,
			"--server-addr", wbturnAddr,
			"--password", kcpPass,
			"--socks", *socksAddr)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			slog.Error("failed to start wbturn", "error", err)
			os.Exit(1)
		}
		slog.Info("wbturn started", "pid", cmd.Process.Pid)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutting down wbturn...")
		cmd.Process.Kill()
		return
	} else if *forceTransport == "call_skin" {
		// Force VK TURN (Call Skin) transport
		slog.Info("forcing VK TURN (Call Skin) transport")
		slog.Error("VK TURN requires manual TURN config — use --auto instead")
		os.Exit(1)
	} else if *autoProbe {
		// Auto-detect network and connect
		wbturnOn := loadedConfig != nil && loadedConfig.WBTurn
		config := client.ClientConfig{
			ServerAddr:    *serverAddr,
			ServerPubKey:  pubKeyBytes,
			ClientID:      []byte(*clientID),
			UseTLS:        *useTLS,
			SkipVerify:    *skipVerify,
			CDNDomain:     *cdnDomain,
			ECHEnabled:    *echEnabled,
			WBTurnEnabled: wbturnOn,
		}
		probeConfig := client.DefaultProbeConfig(*serverAddr, *cdnDomain)

		cl, err = client.AutoConnect(ctx, config, probeConfig)
		if err != nil {
			slog.Error("auto-connect failed", "error", err)
			os.Exit(1)
		}
	} else {
		config := client.ClientConfig{
			ServerAddr:   *serverAddr,
			ServerPubKey: pubKeyBytes,
			ClientID:     []byte(*clientID),
			UseTLS:       *useTLS,
			SkipVerify:   *skipVerify,
			CDNDomain:    *cdnDomain,
			ECHEnabled:   *echEnabled,
		}
		cl = client.NewClient(config)
		if err := cl.Connect(ctx); err != nil {
			slog.Error("connect failed", "error", err)
			os.Exit(1)
		}
	}
	defer cl.Close()

	slog.Info("connected",
		"transport", cl.TransportName())

	// Load persistent fingerprint lease (per-user, weekly rotation).
	// Used for both HTTP (tls-client) and WebSocket (uTLS) — consistent JA3.
	homeDir, _ := os.UserHomeDir()
	fpStateDir := homeDir + "/.shadowlink"
	fpLease := browser.LoadOrCreateLease(fpStateDir)
	lockedFP := fpLease.ToFingerprint()

	// Upgrade to WebSocket if requested (skip for TURN transports — they use UDP, not TCP WebSocket)
	// R-2 fix: use atomic.Pointer to avoid data race between reconnect goroutine and SOCKS5 accept loop
	var wstPtr atomic.Pointer[client.WebSocketTransport]
	isTurnTransport := cl.TransportName() == "wb_turn" || cl.TransportName() == "call_skin"
	if *useWS && !isTurnTransport {
		initialWst, wsErr := cl.UpgradeToWebSocket(*serverAddr, *useTLS, *skipVerify, lockedFP)
		if wsErr != nil {
			slog.Error("websocket upgrade failed", "error", wsErr)
			os.Exit(1)
		}
		wstPtr.Store(initialWst)
		defer initialWst.Close()
		slog.Info("upgraded to websocket — full-duplex mode")

		// Start WS background reader with reconnect
		readerCtx, readerCancel := context.WithCancel(ctx)
		defer readerCancel()
		go func() {
			for {
				currentWst := wstPtr.Load()
				if currentWst == nil {
					return
				}
				err := currentWst.StartReader(readerCtx, cl)
				if readerCtx.Err() != nil {
					return // shutting down
				}
				slog.Warn("ws reader stopped, reconnecting", "error", err)
				cl.ResetStreams()
				if err := cl.ConnectWithRetry(readerCtx); err != nil {
					return
				}
				// Re-upgrade to WebSocket after reconnect
				newWst, err := cl.UpgradeToWebSocket(*serverAddr, *useTLS, *skipVerify, lockedFP)
				if err != nil {
					slog.Error("ws upgrade failed after reconnect", "error", err)
					continue
				}
				// R-3 fix: close old wst before assigning new one to prevent leak
				oldWst := wstPtr.Swap(newWst)
				if oldWst != nil {
					oldWst.Close()
				}
			}
		}()
	}

	// Start SOCKS5 proxy via extracted package.
	// CDN mode: per-stream WS (1 WS per TCP stream, like VLESS+WS).
	// Direct/single-WS mode: shared WS (pool or single).
	srv := &socks5.Server{
		Client: cl,
		Router: router,
		Addr:   *socksAddr,
	}
	isCDN := *cdnDomain != "" && wstPtr.Load() != nil
	if isCDN {
		sniHost := ""
		h, _, _ := net.SplitHostPort(*serverAddr)
		if h != "" {
			sniHost = h
		}
		srv.PerStreamWS = &socks5.PerStreamWSConfig{
			ServerAddr: *serverAddr,
			UseTLS:     *useTLS,
			SkipVerify: *skipVerify,
			LockedFP:   lockedFP,
			SNIHost:    sniHost,
		}
		slog.Info("CDN mode: per-stream WS (VLESS-like)")
	}
	fmt.Printf("\nShadowLink connected! Configure your apps to use SOCKS5 proxy:\n")
	fmt.Printf("  Address: %s\n\n", *socksAddr)

	// LeakGuard: system VPN mode with DNS/IPv6/kill-switch protection
	var guard leakguard.LeakGuard
	if *systemVPN {
		homeDir, _ := os.UserHomeDir()
		stateDir := homeDir + "/.shadowlink"
		os.MkdirAll(stateDir, 0700)
		statePath := stateDir + "/leakguard-state.json"

		// New() handles crash recovery internally (checks state.json, cleans stale rules).
		var err error
		guard, err = leakguard.New(statePath)
		if err != nil {
			slog.Error("failed to create leakguard", "error", err)
			os.Exit(1)
		}

		// Resolve server IP for escape route
		serverHost, serverPortStr, _ := net.SplitHostPort(*serverAddr)
		serverPort := 443
		fmt.Sscanf(serverPortStr, "%d", &serverPort)

		ips, err := net.LookupIP(serverHost)
		if err != nil || len(ips) == 0 {
			slog.Error("cannot resolve server IP for kill switch", "host", serverHost, "error", err)
			os.Exit(1)
		}

		guardCfg := leakguard.LeakGuardConfig{
			ServerIP:   ips[0],
			ServerPort: serverPort,
			TunName:    "ShadowLink",
			TunGateway: net.ParseIP("10.0.85.1"),
		}

		// WB TURN escape route: resolve TURN relay IPs so they bypass TUN
		if *forceTransport == "wb_turn" || *autoProbe {
			turnHosts := []string{
				"wb-stream-turn-1.wb.ru",
				"wb-stream-turn-2.wb.ru",
				"wbstream01-el.wb.ru",
				"stream.wb.ru",
			}
			for _, h := range turnHosts {
				if resolved, err := net.LookupIP(h); err == nil {
					for _, rip := range resolved {
						if rip.To4() != nil {
							guardCfg.ExtraEscapeIPs = append(guardCfg.ExtraEscapeIPs, rip)
						}
					}
				}
			}
			// Also add known WB TURN subnet 185.62.200.0/24 endpoints
			for i := 1; i <= 10; i++ {
				guardCfg.ExtraEscapeIPs = append(guardCfg.ExtraEscapeIPs, net.ParseIP(fmt.Sprintf("185.62.200.%d", i)))
			}
			if len(guardCfg.ExtraEscapeIPs) > 0 {
				slog.Info("leakguard: added TURN escape IPs", "count", len(guardCfg.ExtraEscapeIPs))
			}
		}

		if err := guard.Enable(guardCfg); err != nil {
			slog.Error("failed to enable leakguard", "error", err)
			os.Exit(1)
		}
		slog.Info("system VPN mode: leak protection active")
	}

	// DNS Router: domain-based bypass routing for system VPN mode
	// Starts local DNS proxy on 127.0.0.1:53. For bypass domains (*.ru),
	// adds host routes through real gateway so traffic goes direct.
	var dnsRouter *dnsrouter.Router
	if (*systemVPN || *dnsBypass) && loadedConfig != nil && len(loadedConfig.Routing.Bypass) > 0 {
		// Detect real gateway for bypass routes
		gw := detectRealGateway()
		if gw != "" {
			dnsRouter = dnsrouter.New(dnsrouter.Config{
				ListenAddr: "127.0.0.1:53",
				Upstream:   "1.1.1.1:53",
				Gateway:    gw,
				Bypass:     loadedConfig.Routing.Bypass,
			})
			if err := dnsRouter.Start(); err != nil {
				slog.Warn("DNS router failed to start, bypass routing disabled", "error", err)
				dnsRouter = nil
			} else {
				slog.Info("DNS bypass router active", "patterns", len(loadedConfig.Routing.Bypass), "gateway", gw)
			}
		} else {
			slog.Warn("cannot detect real gateway, bypass routing disabled")
		}
	}

	// IP check (runs AFTER tunnel + leakguard are active)
	if *checkIP {
		go func() {
			time.Sleep(2 * time.Second)
			info, err := leakguard.CheckIP(*socksAddr)
			if err != nil {
				slog.Warn("IP check failed", "error", err)
			} else {
				fmt.Printf("\n  Exit IP: %s (%s, %s)\n\n", info.IP, info.Country, info.Org)
			}
		}()
	}

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// R-2 fix: SOCKS5 server reads wst atomically via the pointer.
	// We launch a goroutine that keeps srv.WST in sync with the atomic pointer.
	socksCtx, socksCancel := context.WithCancel(ctx)
	go func() {
		// Update WST pointer on srv for each accepted connection.
		// The socks5.Server reads WST once per handleConn call.
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-socksCtx.Done():
				return
			case <-ticker.C:
				srv.WST = wstPtr.Load()
			}
		}
	}()

	go srv.ListenAndServe(socksCtx)

	<-sigCh
	slog.Info("shutting down...")
	if dnsRouter != nil {
		dnsRouter.Stop()
	}
	if guard != nil {
		if err := guard.Disable(); err != nil {
			slog.Error("leakguard disable error", "error", err)
		}
	}
	cancel()
	socksCancel()
	srv.Close()
	slog.Info("goodbye")
}

// findWBTurnBinary finds wbturn executable next to current binary or in current dir.
func findWBTurnBinary() string {
	names := []string{"wbturn.exe", "wbturn"}
	// Check next to current executable
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, name := range names {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	// Check current directory
	for _, name := range names {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	return ""
}

// detectRealGateway finds the default gateway, filtering out TUN gateway (10.0.85.x).
func detectRealGateway() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("netstat", "-rn").CombinedOutput()
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				gw := fields[2]
				if !strings.HasPrefix(gw, "10.0.85.") && !strings.HasPrefix(gw, "127.") {
					return gw
				}
			}
		}
	case "darwin":
		// Method 1: route -n get default
		out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "gateway:") {
					gw := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
					// Filter out link#N and TUN gateway
					if len(gw) > 0 && gw[0] >= '0' && gw[0] <= '9' && strings.Contains(gw, ".") && !strings.HasPrefix(gw, "10.0.85.") {
						return gw
					}
				}
			}
		}
		// Method 2: netstat -rn
		out, err = exec.Command("netstat", "-rn").CombinedOutput()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] == "default" && strings.Contains(fields[1], ".") && !strings.HasPrefix(fields[1], "10.0.85.") {
					return fields[1]
				}
			}
		}
		// Method 3: derive from own IP (assume .1 gateway)
		out, _ = exec.Command("ipconfig", "getifaddr", "en0").CombinedOutput()
		ip := strings.TrimSpace(string(out))
		if strings.Contains(ip, ".") {
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				return parts[0] + "." + parts[1] + "." + parts[2] + ".1"
			}
		}
	default: // linux
		out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
		if err != nil {
			return ""
		}
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				gw := fields[i+1]
				if !strings.HasPrefix(gw, "10.0.85.") {
					return gw
				}
			}
		}
	}
	return ""
}

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/client/dnsrouter"
	"github.com/nixavpn/shadowlink/client/leakguard"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
	"gopkg.in/yaml.v3"
)

// Global config for per-connection sessions in SOCKS5 handler
var (
	globalServerAddr string
	globalServerPub  []byte
	globalUseTLS     bool
	globalSkipVerify bool
	globalRouter     *client.Router
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

	// Set globals for per-connection SOCKS5 sessions
	globalServerAddr = *serverAddr
	globalServerPub = pubKeyBytes
	globalUseTLS = *useTLS
	globalSkipVerify = *skipVerify

	// Build router from file config (or empty rules = tunnel everything by default)
	if loadedConfig != nil {
		globalRouter = client.NewRouter(loadedConfig.Routing)
	} else {
		globalRouter = client.NewRouter(client.RoutingConfig{})
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
				newWst, err := cl.UpgradeToWebSocket(globalServerAddr, globalUseTLS, globalSkipVerify, lockedFP)
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

	// Start SOCKS5 proxy
	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		slog.Error("failed to start SOCKS5 listener", "addr", *socksAddr, "error", err)
		os.Exit(1)
	}
	defer ln.Close()

	slog.Info("SOCKS5 proxy listening", "addr", ln.Addr().String())
	fmt.Printf("\nShadowLink connected! Configure your apps to use SOCKS5 proxy:\n")
	fmt.Printf("  Address: %s\n\n", ln.Addr().String())

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

	var wg sync.WaitGroup

	// Accept SOCKS5 connections
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				// R-2 fix: read wst atomically to avoid data race with reconnect goroutine
				wst := wstPtr.Load()
				if wst != nil {
					handleSOCKS5WS(ctx, conn, cl, wst)
				} else {
					handleSOCKS5(ctx, conn, cl)
				}
			}()
		}
	}()

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
	ln.Close()
	wg.Wait()
	slog.Info("goodbye")
}

// handleSOCKS5 handles a SOCKS5 connection (minimal implementation).
// Supports CONNECT command only (TCP tunneling).
func handleSOCKS5(ctx context.Context, conn net.Conn, cl *client.Client) {
	defer conn.Close()

	// SOCKS5 handshake
	buf := make([]byte, 256)

	// Read greeting: version(1) + nmethods(1) + methods(n)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// Reply: no auth required
	conn.Write([]byte{0x05, 0x00})

	// MED-7 fix: use ReadAtLeast to handle TCP fragmentation.
	// SOCKS5 request minimum: ver(1) + cmd(1) + rsv(1) + atyp(1) + addr(1+) + port(2) = 7 bytes
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = io.ReadAtLeast(conn, buf, 7)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n < 7 {
		return
	}

	switch buf[1] {
	case 0x01: // CONNECT — continue below
	case 0x03: // UDP ASSOCIATE
		handleUDPAssociate(ctx, conn, cl, buf[:n])
		return
	default:
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		return
	}

	// Parse destination
	var destAddr string
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		destAddr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		domain := string(buf[5 : 5+domainLen])
		port := int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
		destAddr = fmt.Sprintf("%s:%d", domain, port)
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		ip := net.IP(buf[4:20])
		port := int(buf[20])<<8 | int(buf[21])
		destAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // address type not supported
		return
	}

	slog.Debug("SOCKS5 CONNECT", "dest", destAddr)

	// Apply routing rules: block / direct / tunnel
	switch globalRouter.Decide(destAddr) {
	case client.ActionBlock:
		conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	case client.ActionDirect:
		// SEC-H1 fix: SSRF protection — resolve and check for private IPs before direct dial
		host, _, _ := net.SplitHostPort(destAddr)
		if host == "" {
			host = destAddr
		}
		if ips, lookupErr := net.LookupIP(host); lookupErr == nil {
			for _, ip := range ips {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
					conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
			}
		}
		target, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
		if err != nil {
			conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer target.Close()
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		go io.Copy(target, conn)
		io.Copy(conn, target)
		return
	}

	// Multiplexed: allocate a stream within the shared session
	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded", "error", regErr)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer cl.UnregisterStream(streamID)

	if err := cl.ConnectToStream(ctx, streamID, destAddr); err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Two goroutines: uplink (SOCKS→server) + downlink (server→SOCKS)
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// Uplink: read from SOCKS client → send as stream data
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 16384)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if err := cl.SendStream(ctx2, streamID, buf[:n]); err != nil {
				return
			}
		}
	}()

	// Downlink: poll server for data → route to SOCKS client
	// Also serves as the poll loop (fetches data for ALL streams)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		pollTicker := time.NewTicker(20 * time.Millisecond)
		defer pollTicker.Stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-pollTicker.C:
			}
			// Poll sends empty data, gets back server responses for any stream
			cl.PollStreams(ctx2)
			// Check if we got data for our stream
			select {
			case data, ok := <-incomingCh:
				if !ok || data == nil {
					return // HIGH-2 fix: channel closed by ResetStreams
				}
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(data); err != nil {
					return
				}
				// Drain more data if available
				draining := true
				for draining {
					select {
					case more, moreOk := <-incomingCh:
						if !moreOk || more == nil {
							return
						}
						if _, err := conn.Write(more); err != nil {
							return
						}
					default:
						draining = false
					}
				}
			case <-ctx2.Done():
				return
			default:
				// No data yet — ticker prevents busy-loop
			}
		}
	}()

	wg.Wait()
}

// handleSOCKS5WS handles SOCKS5 over WebSocket — true full-duplex with stream mux.
// Each SOCKS5 CONNECT gets a StreamID. All streams share one WS connection.
// Server pushes data instantly — no polling.
func handleSOCKS5WS(ctx context.Context, conn net.Conn, cl *client.Client, wst *client.WebSocketTransport) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in handleSOCKS5WS", "error", r)
		}
	}()

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	conn.Write([]byte{0x05, 0x00})

	// MED-7 fix: ReadAtLeast for TCP fragmentation
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = io.ReadAtLeast(conn, buf, 7)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n < 7 {
		return
	}
	switch buf[1] {
	case 0x01: // CONNECT — continue below
	case 0x03: // UDP ASSOCIATE
		handleUDPAssociateWS(ctx, conn, cl, wst, buf[:n])
		return
	default:
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var destAddr string
	switch buf[3] {
	case 0x01:
		if n < 10 { return }
		destAddr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
	case 0x03:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 { return }
		domain := string(buf[5 : 5+domainLen])
		port := int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
		destAddr = fmt.Sprintf("%s:%d", domain, port)
	case 0x04:
		if n < 22 { return }
		ip := net.IP(buf[4:20])
		port := int(buf[20])<<8 | int(buf[21])
		destAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Apply routing rules: block / direct / tunnel
	switch globalRouter.Decide(destAddr) {
	case client.ActionBlock:
		conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	case client.ActionDirect:
		// SEC-H1 fix: SSRF protection — resolve and check for private IPs before direct dial
		host, _, _ := net.SplitHostPort(destAddr)
		if host == "" {
			host = destAddr
		}
		if ips, lookupErr := net.LookupIP(host); lookupErr == nil {
			for _, ip := range ips {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
					conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
			}
		}
		target, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
		if err != nil {
			conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer target.Close()
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		go io.Copy(target, conn)
		io.Copy(conn, target)
		return
	}

	// Allocate stream + register for incoming data
	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded", "error", regErr)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer cl.UnregisterStream(streamID)

	// Send CONNECT via WS with StreamID
	session := cl.Session()
	if session == nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	connectChunk := core.NewStreamConnectChunk(session.ID, session.NextSeqNum(), streamID, destAddr)
	encrypted, err := session.EncryptChunk(connectChunk)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if err := wst.WriteMessage(encrypted); err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Wait for CONNECT_OK response
	select {
	case resp, ok := <-incomingCh:
		if !ok || string(resp) != "CONNECT_OK" {
			conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	case <-time.After(10 * time.Second):
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Full-duplex relay — no polling!
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup

	// Uplink: SOCKS client → encrypt → WS → server (no Nagle, no delay)
	// Read whatever OS TCP stack has buffered, encrypt, send immediately.
	// TCP already does its own Nagle. Adding artificial delay kills upload on Windows.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 32768) // large buffer — let OS batch
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			chunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, buf[:n])
			enc, encErr := session.EncryptChunk(chunk)
			core.PutBuffer(chunk.Payload) // release pooled payload after encryption
			if encErr != nil {
				return
			}
			if err := wst.WriteMessage(enc); err != nil {
				return
			}
		}
	}()

	// Downlink: incoming channel ← WS demux (background reader fills this)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			select {
			case data, ok := <-incomingCh:
				if !ok || data == nil {
					return // HIGH-2 fix: channel closed by ResetStreams
				}
				if _, err := conn.Write(data); err != nil {
					return
				}
			case <-ctx2.Done():
				return
			}
		}
	}()

	wg.Wait()
}

// handleUDPAssociateWS handles SOCKS5 UDP ASSOCIATE over WebSocket transport.
// Opens a local UDP listener, relays datagrams through the encrypted WS tunnel.
func handleUDPAssociateWS(ctx context.Context, conn net.Conn, cl *client.Client, wst *client.WebSocketTransport, socksReq []byte) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in handleUDPAssociateWS", "error", r)
		}
	}()

	// Open local UDP listener on loopback
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpConn.Close()

	// Get bound address for SOCKS5 reply
	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	ip4 := boundAddr.IP.To4()
	if ip4 == nil {
		ip4 = []byte{127, 0, 0, 1}
	}

	// Reply: success with BND.ADDR = local UDP address
	reply := []byte{0x05, 0x00, 0x00, 0x01,
		ip4[0], ip4[1], ip4[2], ip4[3],
		byte(boundAddr.Port >> 8), byte(boundAddr.Port & 0xff)}
	conn.Write(reply)

	slog.Debug("SOCKS5 UDP ASSOCIATE", "udp_addr", boundAddr.String())

	// Allocate stream for this UDP association
	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded for UDP", "error", regErr)
		return
	}
	defer cl.UnregisterStream(streamID)

	session := cl.Session()
	if session == nil {
		return
	}

	// Track last client address for sending responses back
	var lastClientAddr atomic.Pointer[net.UDPAddr]

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup

	// Goroutine 1 (send): Read UDP datagrams from SOCKS5 client → encrypt → send via WS
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 65535)
		for {
			udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, clientAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 4 {
				continue // too short for SOCKS5 UDP header
			}

			lastClientAddr.Store(clientAddr)

			// Parse SOCKS5 UDP request header:
			// RSV(2) + FRAG(1) + ATYP(1) + ADDR(var) + PORT(2) + DATA
			frag := buf[2]
			if frag != 0 {
				continue // fragmentation not supported
			}
			atyp := buf[3]
			var targetAddr string
			var dataOffset int

			switch atyp {
			case 0x01: // IPv4
				if n < 10 {
					continue
				}
				targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
					buf[4], buf[5], buf[6], buf[7],
					int(buf[8])<<8|int(buf[9]))
				dataOffset = 10
			case 0x03: // Domain
				if n < 5 {
					continue
				}
				domainLen := int(buf[4])
				if n < 5+domainLen+2 {
					continue
				}
				domain := string(buf[5 : 5+domainLen])
				port := int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
				targetAddr = fmt.Sprintf("%s:%d", domain, port)
				dataOffset = 5 + domainLen + 2
			case 0x04: // IPv6
				if n < 22 {
					continue
				}
				ip := net.IP(buf[4:20])
				port := int(buf[20])<<8 | int(buf[21])
				targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
				dataOffset = 22
			default:
				continue
			}

			data := buf[dataOffset:n]
			if len(data) == 0 {
				continue
			}

			// Create UDP chunk and send via WS
			chunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, data)
			enc, err := session.EncryptChunk(chunk)
			if err != nil {
				return
			}
			if err := wst.WriteMessage(enc); err != nil {
				return
			}
		}
	}()

	// Goroutine 2 (receive): Read from stream channel → parse UDP response → send to SOCKS5 client
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			select {
			case payload, ok := <-incomingCh:
				if !ok || payload == nil {
					return // HIGH-2 fix: channel closed by ResetStreams
				}
				// payload is full UDP chunk payload: [StreamID(2)][AddrLen(2)][Addr][Data]
				_, addr, data, err := core.ParseUDPChunk(payload)
				if err != nil || len(data) == 0 {
					continue
				}

				// Build SOCKS5 UDP response header
				udpResp := buildSOCKS5UDPHeader(addr, data)
				if udpResp == nil {
					continue
				}

				ca := lastClientAddr.Load()
				if ca != nil {
					udpConn.WriteToUDP(udpResp, ca)
				}
			case <-ctx2.Done():
				return
			}
		}
	}()

	// Main: wait for TCP connection to close (signals end of UDP ASSOCIATE per RFC 1928)
	waitBuf := make([]byte, 1)
	conn.Read(waitBuf) // blocks until TCP closes
	cancel()
	udpConn.Close() // unblock ReadFromUDP
	wg.Wait()
}

// handleUDPAssociate handles SOCKS5 UDP ASSOCIATE over poll-based (HTTP) transport.
// Same logic as handleUDPAssociateWS but uses poll-based sending.
func handleUDPAssociate(ctx context.Context, conn net.Conn, cl *client.Client, socksReq []byte) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in handleUDPAssociate", "error", r)
		}
	}()

	// Open local UDP listener on loopback
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpConn.Close()

	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	ip4 := boundAddr.IP.To4()
	if ip4 == nil {
		ip4 = []byte{127, 0, 0, 1}
	}

	reply := []byte{0x05, 0x00, 0x00, 0x01,
		ip4[0], ip4[1], ip4[2], ip4[3],
		byte(boundAddr.Port >> 8), byte(boundAddr.Port & 0xff)}
	conn.Write(reply)

	slog.Debug("SOCKS5 UDP ASSOCIATE (poll)", "udp_addr", boundAddr.String())

	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded for UDP poll", "error", regErr)
		return
	}
	defer cl.UnregisterStream(streamID)

	session := cl.Session()
	if session == nil {
		return
	}

	var lastClientAddr atomic.Pointer[net.UDPAddr]

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup

	// Send: UDP client → encrypt → HTTP poll
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 65535)
		for {
			udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, clientAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 4 {
				continue
			}
			lastClientAddr.Store(clientAddr)

			frag := buf[2]
			if frag != 0 {
				continue
			}
			atyp := buf[3]
			var targetAddr string
			var dataOffset int
			switch atyp {
			case 0x01:
				if n < 10 {
					continue
				}
				targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
					buf[4], buf[5], buf[6], buf[7],
					int(buf[8])<<8|int(buf[9]))
				dataOffset = 10
			case 0x03:
				if n < 5 {
					continue
				}
				domainLen := int(buf[4])
				if n < 5+domainLen+2 {
					continue
				}
				domain := string(buf[5 : 5+domainLen])
				port := int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
				targetAddr = fmt.Sprintf("%s:%d", domain, port)
				dataOffset = 5 + domainLen + 2
			case 0x04:
				if n < 22 {
					continue
				}
				ip := net.IP(buf[4:20])
				port := int(buf[20])<<8 | int(buf[21])
				targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
				dataOffset = 22
			default:
				continue
			}
			data := buf[dataOffset:n]
			if len(data) == 0 {
				continue
			}

			// Send via HTTP poll transport (use SendStream which handles encrypt+send+demux)
			udpChunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, data)
			encrypted, err := session.EncryptChunk(udpChunk)
			if err != nil {
				return
			}

			token := cl.SessionToken()
			if _, err := cl.SendChunkRaw(ctx2, encrypted, token, udpChunk.SeqNum); err != nil {
				return
			}
		}
	}()

	// Receive: incoming channel → parse → send to SOCKS5 client
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			select {
			case payload, ok := <-incomingCh:
				if !ok || payload == nil {
					return // HIGH-2 fix: channel closed by ResetStreams
				}
				_, addr, data, err := core.ParseUDPChunk(payload)
				if err != nil || len(data) == 0 {
					continue
				}
				udpResp := buildSOCKS5UDPHeader(addr, data)
				if udpResp == nil {
					continue
				}
				ca := lastClientAddr.Load()
				if ca != nil {
					udpConn.WriteToUDP(udpResp, ca)
				}
			case <-ctx2.Done():
				return
			}
		}
	}()

	// Poll loop for receiving UDP responses in poll mode
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		pollTicker := time.NewTicker(20 * time.Millisecond)
		defer pollTicker.Stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-pollTicker.C:
			}
			cl.PollStreams(ctx2)
		}
	}()

	waitBuf := make([]byte, 1)
	conn.Read(waitBuf)
	cancel()
	udpConn.Close()
	wg.Wait()
}

// buildSOCKS5UDPHeader builds a SOCKS5 UDP response: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT(2) + DATA
func buildSOCKS5UDPHeader(addr string, data []byte) []byte {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}

	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	ip := net.ParseIP(host)

	var hdr []byte
	if ip != nil && ip.To4() != nil {
		// IPv4
		ip4 := ip.To4()
		hdr = make([]byte, 10+len(data))
		// RSV + FRAG
		hdr[0], hdr[1], hdr[2] = 0, 0, 0
		hdr[3] = 0x01 // ATYP IPv4
		copy(hdr[4:8], ip4)
		hdr[8] = byte(port >> 8)
		hdr[9] = byte(port & 0xff)
		copy(hdr[10:], data)
	} else if ip != nil {
		// IPv6
		ip6 := ip.To16()
		hdr = make([]byte, 22+len(data))
		hdr[0], hdr[1], hdr[2] = 0, 0, 0
		hdr[3] = 0x04 // ATYP IPv6
		copy(hdr[4:20], ip6)
		hdr[20] = byte(port >> 8)
		hdr[21] = byte(port & 0xff)
		copy(hdr[22:], data)
	} else {
		// Domain
		domainBytes := []byte(host)
		hdr = make([]byte, 5+len(domainBytes)+2+len(data))
		hdr[0], hdr[1], hdr[2] = 0, 0, 0
		hdr[3] = 0x03 // ATYP domain
		hdr[4] = byte(len(domainBytes))
		copy(hdr[5:5+len(domainBytes)], domainBytes)
		hdr[5+len(domainBytes)] = byte(port >> 8)
		hdr[5+len(domainBytes)+1] = byte(port & 0xff)
		copy(hdr[5+len(domainBytes)+2:], data)
	}
	return hdr
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
		out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "gateway:") {
				gw := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
				if !strings.HasPrefix(gw, "10.0.85.") {
					return gw
				}
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

// Package main is the entry point for the NixaVPN unified client CLI.
// It embeds both ShadowLink and VLESS+Reality protocols via xray-core,
// and uses tun2socks for system VPN (TUN interface) mode.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	// xray-core: provides VLESS+Reality as embedded Go library
	_ "github.com/xtls/xray-core/core"
	// tun2socks: provides system VPN (TUN interface) as embedded Go library
	_ "github.com/xjasonlyu/tun2socks/v2/engine"

	"github.com/nixavpn/shadowlink/client/bypassroute"
	"github.com/nixavpn/shadowlink/client/leakguard"
)

const version = "0.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("nixavpn-client %s\n", version)
			return
		case "check-ip":
			ip, err := checkExitIP()
			if err != nil {
				fmt.Fprintf(os.Stderr, "ошибка проверки IP: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(ip)
			return
		case "connect":
			// Subcommand explicitly specified — shift args.
			os.Args = append(os.Args[:1], os.Args[2:]...)
		}
	}

	// Parse flags for connect subcommand.
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	importURL := fs.String("import", "", "import config from vless:// or sl:// URL")
	configFile := fs.String("config", "", "path to YAML config file")
	apiURL := fs.String("api", "", "NixaVPN API base URL (e.g. https://nixavpn.com)")
	apiToken := fs.String("token", "", "NixaVPN API auth token")
	protocol := fs.String("protocol", "auto", "protocol: auto | shadowlink | vless")
	socksAddr := fs.String("socks", "", "SOCKS5 listen address (overrides config, default 127.0.0.1:1080)")
	systemVPN := fs.Bool("system-vpn", false, "enable system VPN mode (TUN interface + LeakGuard)")
	doCheckIP := fs.Bool("check-ip", false, "print exit IP after connecting")
	verbose := fs.Bool("verbose", false, "(deprecated) verbose logging — use -log=debug instead")
	logFlag := fs.String("log", "info", "log level: quiet | info | debug | trace")
	logFile := fs.String("log-file", "", "if set, also write logs to this file (appended)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка разбора флагов: %v\n", err)
		os.Exit(1)
	}

	// Configure logging. -verbose maps to debug for backwards compatibility
	// with existing bat-scripts; -log takes precedence when both are passed.
	levelStr := *logFlag
	if *verbose && *logFlag == "info" {
		levelStr = "debug"
	}
	parsedLevel, parseErr := parseLogLevel(levelStr)
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", parseErr)
		os.Exit(1)
	}
	logCloser, logErr := configureLogging(logSpec{level: parsedLevel, file: *logFile})
	if logErr != nil {
		fmt.Fprintf(os.Stderr, "ошибка настройки логирования: %v\n", logErr)
		os.Exit(1)
	}
	defer logCloser.Close()
	if *verbose {
		slog.Warn("-verbose флаг устарел — используйте -log=debug")
	}

	// Load config from one of the three sources.
	cfg, err := loadConfig(*importURL, *configFile, *apiURL, *apiToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка загрузки конфига: %v\n", err)
		os.Exit(1)
	}

	// SOCKS address: CLI flag > YAML config > random port.
	// Рандомный порт по умолчанию — порт 1080 есть в методичке РКН для обнаружения прокси.
	if *socksAddr != "" {
		cfg.SOCKS = *socksAddr
	} else {
		cfg.SOCKS = randomSOCKSAddr()
	}

	// Защита: запретить bind на 0.0.0.0 (доступ из сети).
	if host, port, err := net.SplitHostPort(cfg.SOCKS); err == nil {
		if host == "0.0.0.0" || host == "::" || host == "" {
			slog.Warn("SOCKS5 на 0.0.0.0 небезопасно — принудительно 127.0.0.1")
			cfg.SOCKS = "127.0.0.1:" + port
		}
	}

	// Генерируем случайные credentials для SOCKS5 — защита от локального IP-leak.
	proxyUser, proxyPass := generateProxyCredentials()
	cfg.ProxyUser = proxyUser
	cfg.ProxyPass = proxyPass
	// W1: don't log password even at debug level.
	slog.Debug("SOCKS5 auth", "user", proxyUser, "passLen", len(proxyPass))

	// Override system VPN flag.
	if *systemVPN {
		cfg.SystemVPN = true
	}

	// Resolve protocol.
	resolvedProtocol := resolveProtocol(*protocol, cfg)
	slog.Info("выбран протокол", "protocol", resolvedProtocol)

	// Create engine.
	eng, err := NewEngine(resolvedProtocol, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка создания engine: %v\n", err)
		os.Exit(1)
	}

	// Context with cancellation for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect engine.
	if err := eng.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка подключения: %v\n", err)
		os.Exit(1)
	}
	slog.Info("подключено", "protocol", eng.Name(), "socks", eng.SOCKSAddr())

	// System VPN mode: TUN tunnel + LeakGuard.
	var tun *Tunnel
	var lg leakguard.LeakGuard

	if cfg.SystemVPN {
		serverIPs := resolveServerIPs(resolvedProtocol, cfg)
		if len(serverIPs) == 0 {
			fmt.Fprintf(os.Stderr, "ошибка: не удалось определить IP сервера для escape-маршрута\n")
			_ = eng.Close()
			os.Exit(1)
		}

		bypassOn := bypassEnabledFromEnv()
		slog.Info("bypass routing", "enabled", bypassOn)

		// Fetch admin-managed CIDR override list (B7).
		// Server publishes signed override; client persists per-user cache.
		// HMAC key MUST come from SHADOWLINK_BYPASS_HMAC_KEY env (out-of-band).
		// SHADOWLINK_ADMIN_OVERRIDE=0/false/no/off (spec §10) skips the
		// network fetch and uses only the on-disk cache (which itself can be
		// empty → embedded baseline only).
		var override *bypassroute.AdminOverride
		if bypassOn {
			hmacKey, hmacOK := loadBypassHMACKey()
			if hmacOK && cfg.API != nil && cfg.API.URL != "" && cfg.API.Token != "" {
				cacheDir := userBypassCacheDir()
				cached, _ := bypassroute.LoadCachedOverride(cacheDir, hmacKey)

				if !adminOverrideEnabled() {
					slog.Info("bypass admin override disabled by env, using cache only")
					override = cached
				} else {
					cachedEtag := ""
					cachedSigVersion := ""
					if cached != nil {
						cachedEtag = cached.Etag
						cachedSigVersion = cached.SigVersion
					}

					httpClient := &http.Client{Timeout: 5 * time.Second}
					// previousSigVersion=cachedSigVersion enforces sticky-v2:
					// once a client has accepted a v2 reply from this server,
					// any later v1 reply is treated as a downgrade and rejected.
					fresh, ferr := bypassroute.FetchAdminOverride(httpClient, cfg.API.URL, cfg.API.Token, cachedEtag, hmacKey, cachedSigVersion)
					switch {
					case ferr != nil:
						slog.Warn("bypass override fetch failed, using cached", "err", ferr)
						override = cached
					case fresh == nil:
						// 304 Not Modified — кэш актуален.
						override = cached
					default:
						if perr := bypassroute.PersistOverride(cacheDir, fresh, hmacKey); perr != nil {
							slog.Warn("bypass override cache persist failed", "err", perr)
						}
						override = fresh
					}
				}
				if override != nil {
					slog.Info("bypass override loaded", "adds", len(override.Adds), "excludes", len(override.Excludes), "etag", override.Etag)
				}
			}
		}

		// narrowEscape: enable /32-only escape when origin is pinned. resolveServerIPs
		// already returns ONLY the origin IP in that case, so /16 sweep would have
		// nothing legitimate to cover anyway. F-5 (2026-06-13): gate on the SHARED
		// originPinned predicate (valid IPv4), not mere non-emptiness — an invalid
		// ?origin= is effectively CDN mode and must keep the /16 sweep.
		narrowEscape := originPinned(cfg)
		splitDNS := splitDNSEnabledFromEnv(bypassOn)
		slog.Info("split-DNS forwarder", "enabled", splitDNS)
		tun = NewTunnel(eng.SOCKSAddr(), cfg.ProxyUser, cfg.ProxyPass, serverIPs).
			WithBypass(bypassOn, override).
			WithNarrowEscape(narrowEscape).
			WithSplitDNS(splitDNS)
		// INT-H2 (2026-06-12): bootstrap-whitelist для split-DNS forwarder'а —
		// серверный домен (CDN-режим) должен резолвиться по Yandex-only, когда
		// CF-нога DoH мертва вместе с туннелем, иначе reconnect не может
		// зарезолвить сервер и туннель не восстанавливается. Пусто при
		// origin-pin / IP-литералах (DNS не участвует) — тогда не передаём.
		if d := serverBootstrapDomain(resolvedProtocol, cfg); d != "" {
			tun = tun.WithBootstrapDomains(d)
			slog.Info("split-DNS bootstrap-домен сервера", "domain", d)
		}
		// Bug #5: prefer the engine's in-process dialer (no loopback socket per
		// flow → no Windows ephemeral port exhaustion). Optional interface —
		// only ShadowLink implements it; VLESS falls back to loopback SOCKS5.
		if p, ok := eng.(InProcessDialerProvider); ok {
			if d := p.InProcessDialer(); d != nil {
				tun = tun.WithInProcessDialer(d)
			}
		}

		// H1/C3-b: create LeakGuard BEFORE tun.Start() so its crash-recovery
		// (Windows New() → removeKillSwitch + policy restore + WFP
		// DeleteByProvider) clears any stale SL-* rules / blockoutbound default
		// policy / WFP filters left by a previous crash BEFORE any network
		// activity — otherwise a leftover block could deadlock startup.
		lg, err = leakguard.New(leakguardStatePath())
		if err != nil {
			slog.Warn("не удалось создать LeakGuard", "err", err)
			lg = nil
		}

		// Build the LeakGuard config (incl. explicit split-tunnel) up front so
		// PreLock and Enable share it.
		tunName := tunDeviceName()
		tunName = strings.TrimPrefix(tunName, "tun://")
		// Parse ALL resolved server IPs for firewall rules. CDN returns multiple
		// IPs — kill switch must allow ALL of them or download stream ACKs to the
		// "other" IP get blocked.
		var parsedIPs []net.IP
		for _, ipStr := range serverIPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				parsedIPs = append(parsedIPs, ip)
			}
		}

		// C3: explicit split-tunnel (default OFF = fail-secure). When ON and
		// bypass is enabled, export the RU CIDR snapshot so the kill switch
		// allows bypass ranges past it (LAN always; RU via WFP/nft/pf). This
		// traffic is NOT protected by the kill switch — log a clear WARN.
		splitTunnel := splitTunnelEnabledFromEnv()
		var bypassRanges []netip.Prefix
		if bypassOn && splitTunnel {
			// NB (I1, 2026-06-11): this bypassroute.Load is used ONLY to derive the
			// kill-switch firewall BypassRanges (the WFP/nft/pf ranges allowed past
			// the LeakGuard). It is NOT the split-DNS arbitration snapshot and does
			// not break the "one Load for arbitration" invariant: the split-DNS
			// Forwarder shares Tunnel.resolved, whose single Load lives in
			// tunnel.go installBypassDialer. These two snapshots serve different
			// subsystems (firewall vs DNS arbitration) and are intentionally separate.
			if resolved, rerr := bypassroute.Load(bypassroute.Source{Embedded: true, Override: override}); rerr == nil {
				bypassRanges = bypassroute.SnapshotPrefixes(resolved)
			} else {
				slog.Warn("split-tunnel: не удалось загрузить bypass-диапазоны", "err", rerr)
			}
			slog.Warn("split-tunnel ВКЛЮЧЁН — bypass-трафик (RU CIDR + LAN) идёт МИМО kill-switch и НЕ защищён им",
				"ranges", len(bypassRanges))
		}

		var lgCfg leakguard.LeakGuardConfig
		if len(parsedIPs) > 0 {
			lgCfg = leakguard.LeakGuardConfig{
				TunName:      tunName,
				ServerPort:   resolveServerPort(resolvedProtocol, cfg),
				ServerIP:     parsedIPs[0],
				ServerIPs:    parsedIPs,
				SplitTunnel:  splitTunnel,
				BypassRanges: bypassRanges,
			}
		}

		// H2: pre-lock DNS+IPv6 BEFORE tun.Start() — closes the leak window
		// between tun.Start() and the kill switch. PreLock is idempotent;
		// Enable later installs the kill switch without redoing DNS/IPv6.
		if lg != nil && len(parsedIPs) > 0 {
			if err := lg.PreLock(lgCfg); err != nil {
				slog.Warn("LeakGuard pre-lock не удался — продолжаем, Enable попробует снова", "err", err)
			}
		}

		if err := tun.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "ошибка запуска TUN-туннеля: %v\n", err)
			// tun.Stop здесь не нужен: setTUNDNS — ПОСЛЕДНИЙ шаг Start, на
			// упавшем Start туннель DNS не трогал, а остальное откатил
			// rollbackStart внутри Start. lg.Disable откатывает PreLock —
			// порядок-инвариант shutdownTunnelAndGuard не нарушается.
			if lg != nil {
				_ = lg.Disable() // roll back PreLock DNS/IPv6
			}
			_ = eng.Close()
			os.Exit(1)
		}

		if lg != nil && len(parsedIPs) > 0 {
			if err := lg.Enable(lgCfg); err != nil {
				slog.Error("LeakGuard НЕ включён — VPN работает БЕЗ kill-switch/DNS-защиты", "err", err)
				fmt.Fprintln(os.Stderr, "ВНИМАНИЕ: LeakGuard не активирован — защита от утечек ВЫКЛЮЧЕНА. "+
					"По умолчанию запуск прерывается (fail-secure). Запустите с "+
					"SHADOWLINK_LEAKGUARD_STRICT=0, только если осознанно принимаете риск утечки реального IP.")
				if leakguardStrictFromEnv() {
					// tun.Stop ПЕРЕД lg.Disable — тот же инвариант, что и в
					// shutdownTunnelAndGuard (LeakGuard восстанавливает истинный DNS последним).
					shutdownTunnelAndGuard(tun, lg)
					_ = eng.Close()
					os.Exit(1)
				}
				// H2: НЕ обнуляем lg — сохраняем для гарантированного Disable() в
				// shutdown, чтобы откатить частично применённые PreLock-настройки.
			} else {
				slog.Info("LeakGuard включён")
			}
		}
	}

	// Optionally check and print exit IP (с retry — DNS может не сразу заработать после TUN).
	if *doCheckIP {
		go func() {
			for i := 0; i < 3; i++ {
				time.Sleep(time.Duration(2+i*2) * time.Second)
				ip, err := checkExitIP()
				if err != nil {
					if i < 2 {
						continue
					}
					slog.Warn("проверка IP не удалась", "err", err)
					return
				}
				fmt.Printf("выходной IP: %s\n", ip)
				return
			}
		}()
	}

	fmt.Printf("NixaVPN подключён (%s). SOCKS5: %s (auth: on)\nНажмите Ctrl+C для отключения.\n",
		eng.Name(), eng.SOCKSAddr())

	// Wait for termination signal or engine fatal error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// W8: also watch for engine crash (WS reconnect exhausted, SOCKS5 died, etc.)
	var engineErr <-chan error
	if sig, ok := eng.(ErrorSignaller); ok {
		engineErr = sig.ErrorCh()
	}

	select {
	case <-sigCh:
		fmt.Println("\nОтключение...")
	case err := <-engineErr:
		fmt.Printf("\nEngine упал: %v\nОтключение...\n", err)
	}

	// Graceful shutdown: tun.Stop ПЕРЕД lg.Disable (см. shutdownTunnelAndGuard).
	var ts tunStopper
	if tun != nil {
		ts = tun
	}
	shutdownTunnelAndGuard(ts, lg)

	cancel()
	if err := eng.Close(); err != nil {
		slog.Warn("ошибка закрытия engine", "err", err)
	}

	slog.Info("отключено")
}

// tunStopper / lgDisabler — минимальные seam-интерфейсы, чтобы инвариант
// порядка shutdown был unit-тестируемым (main_shutdown_order_test.go).
type tunStopper interface{ Stop() error }
type lgDisabler interface{ Disable() error }

// shutdownTunnelAndGuard tears down the tunnel and LeakGuard in the REQUIRED
// order: tun.Stop() BEFORE lg.Disable().
//
// Инвариант: LeakGuard владеет ИСТИННЫМ оригинальным DNS — его PreLock снял
// бэкап ДО того, как туннель вообще трогал DNS. Поэтому restore LeakGuard'а
// должен лечь ПОСЛЕДНИМ: tun.Stop восстанавливает свой бэкап (darwin: это
// LOCK-значения 1.1.1.1/8.8.8.8, снятые setTUNDNS уже ПОСЛЕ PreLock), затем
// lg.Disable поверх возвращает настоящие пользовательские значения
// (DHCP/automatic). Обратный порядок навсегда оставлял хост на lock-значениях.
// Когда lg==nil, PreLock не выполнялся → бэкап туннеля хранит истинные
// значения, и tun.Stop одного достаточно.
//
// Окно между Stop и Disable (forwarder уже мёртв, kill-switch ещё жив) — это
// краткий DNS-dead на shutdown: приемлемо и fail-secure. Сеть для Stop не
// нужна — он выполняет только локальные exec (netsh/route/networksetup/
// файловые операции resolv.conf), поэтому работающий kill-switch ему не мешает
// (windows и darwin — одинаковое рассуждение).
//
// Оба шага best-effort: ошибка одного не пропускает другой.
func shutdownTunnelAndGuard(tun tunStopper, lg lgDisabler) {
	if tun != nil {
		if err := tun.Stop(); err != nil {
			slog.Warn("ошибка остановки TUN-туннеля", "err", err)
		}
	}
	if lg != nil {
		if err := lg.Disable(); err != nil {
			slog.Warn("ошибка отключения LeakGuard", "err", err)
		}
	}
}

// loadConfig загружает конфиг из одного из трёх источников:
// 1. Import URL (--import)
// 2. Config file (--config)
// 3. NixaVPN API (--api + --token)
func loadConfig(importURL, configFile, apiURL, apiToken string) (*Config, error) {
	switch {
	case importURL != "":
		slog.Info("загрузка конфига из URL", "url", importURL)
		return ParseImportURL(importURL)

	case configFile != "":
		slog.Info("загрузка конфига из файла", "path", configFile)
		return LoadConfigFile(configFile)

	case apiURL != "":
		slog.Info("загрузка конфига из API", "api", apiURL)
		return FetchConfigFromAPI(apiURL, apiToken)

	default:
		// Try default config file locations.
		for _, path := range defaultConfigPaths() {
			if _, err := os.Stat(path); err == nil {
				slog.Info("найден конфиг по умолчанию", "path", path)
				return LoadConfigFile(path)
			}
		}
		return nil, fmt.Errorf("не задан источник конфига: используйте --import, --config или --api")
	}
}

// defaultConfigPaths returns OS-appropriate default config file paths.
func defaultConfigPaths() []string {
	return []string{
		"nixavpn.yaml",
		"nixavpn.yml",
	}
}

// resolveProtocol выбирает конкретный протокол из "auto" или возвращает указанный.
// При "auto": предпочитает VLESS если доступен, иначе ShadowLink.
func resolveProtocol(protocol string, cfg *Config) string {
	if protocol != "auto" {
		return protocol
	}
	if cfg.Protocol != "" && cfg.Protocol != "auto" {
		return cfg.Protocol
	}
	// Auto selection: prefer VLESS if config section is present, else ShadowLink.
	if cfg.VLESS != nil {
		return "vless"
	}
	if cfg.ShadowLink != nil {
		return "shadowlink"
	}
	// Fallback.
	return "shadowlink"
}

// resolveServerIPs returns the VPN server's IP addresses for the given protocol.
// Used for escape routing (server traffic must bypass the TUN interface).
// If the host is a domain name, resolves it to IPs via DNS.
// For CDN mode, resolves the CDN domain (Cloudflare IPs).
// Only returns IPv4 addresses (escape routes use IPv4 syntax).
func resolveServerIPs(protocol string, cfg *Config) []string {
	var host string
	switch protocol {
	case "vless":
		if cfg.VLESS != nil {
			host = cfg.VLESS.Address
		}
	case "shadowlink":
		if cfg.ShadowLink != nil {
			// Origin override has the highest priority. When ?origin=<IP> is set
			// the data path is forced to dial that IP directly (see
			// engine_shadowlink.go::full-direct activation). Returning ONLY the
			// origin IP here ensures the TUN escape list does NOT include any
			// CF edge IP — without this, a reconnect-handshake that for any
			// reason resolved through DNS would still have a usable escape route
			// and silently leak through CF. We make the leak path unroutable.
			// F-5 (2026-06-13): gate on the SHARED originPinned predicate so the
			// short-circuit here, narrowEscape and serverBootstrapDomain agree on
			// exactly what counts as a pinned origin (valid IPv4).
			if originPinned(cfg) {
				slog.Info("сервер резолвлен для escape-маршрута (origin override)",
					"origin", cfg.ShadowLink.Origin)
				return []string{cfg.ShadowLink.Origin}
			}
			if cfg.ShadowLink.Origin != "" {
				// Origin is set but not a valid IPv4 — fall through to normal
				// resolution; log so the operator notices the config error.
				slog.Warn("origin= задан, но не IPv4 — игнорируем, escape через DNS",
					"origin", cfg.ShadowLink.Origin)
			}

			// In CDN mode (no origin override), the actual connection goes to
			// the CDN domain (Cloudflare). We need an escape route for the CDN IP.
			if cfg.ShadowLink.CDN != "" {
				host = cfg.ShadowLink.CDN
			} else {
				h, _, err := net.SplitHostPort(cfg.ShadowLink.Server)
				if err == nil {
					host = h
				} else {
					host = cfg.ShadowLink.Server
				}
			}
		}
	}

	if host == "" {
		return nil
	}

	// If already an IP, return as-is.
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return []string{host}
		}
		return nil // skip IPv6-only
	}

	// Resolve domain to IPs for escape routing.
	// Резолв до старта split-DNS forwarder — намеренно через системный резолвер:
	// нужен реальный IP сервера для escape-маршрута, не split-DNS арбитраж.
	// resolveServerIPs вызывается при инициализации, ДО tun.Start (forwarder ещё
	// не слушает), поэтому net.LookupHost здесь не может уйти через split-DNS.
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		slog.Error("не удалось резолвить сервер для escape-маршрута", "host", host, "err", err)
		return nil
	}

	// Filter IPv4 only — escape routes use IPv4 route add syntax.
	var ipv4s []string
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			ipv4s = append(ipv4s, ip)
		}
	}

	// C5: limit escape routes to 8 max (CDN can return many IPs).
	if len(ipv4s) > 8 {
		ipv4s = ipv4s[:8]
	}

	// If a specific CF edge IP is pinned via ?cfip=<IP>, add to escape routes.
	// Origin override is NOT processed here — it short-circuits at the top of
	// this function and returns [Origin] alone, so by construction we cannot
	// reach this point with cfg.ShadowLink.Origin set.
	if protocol == "shadowlink" && cfg.ShadowLink != nil && cfg.ShadowLink.CFIP != "" {
		extraIP := cfg.ShadowLink.CFIP
		if parsed := net.ParseIP(extraIP); parsed != nil && parsed.To4() != nil {
			found := false
			for _, ip := range ipv4s {
				if ip == extraIP {
					found = true
					break
				}
			}
			if !found {
				ipv4s = append(ipv4s, extraIP)
			}
		}
	}

	slog.Info("сервер резолвлен для escape-маршрута", "host", host, "ips", ipv4s)
	return ipv4s
}

// originPinned reports whether the ShadowLink data path is pinned to a literal
// origin IP — i.e. ?origin= holds a VALID IPv4. This is the SINGLE predicate
// (F-5, 2026-06-13, final batch review) feeding narrowEscape, resolveServerIPs'
// origin short-circuit, and serverBootstrapDomain. Previously narrowEscape keyed
// off mere non-emptiness of Origin while the other two required a valid IPv4 —
// so an INVALID ?origin= (config typo) silently disabled the /16 escape sweep in
// what is effectively CDN mode, leaving CF edge rotation unroutable. Now an
// invalid origin keeps the /16 sweep, consistent with the resolve/bootstrap
// fall-through. (resolveServerIPs still logs its own Warn on the invalid value.)
func originPinned(cfg *Config) bool {
	if cfg == nil || cfg.ShadowLink == nil || cfg.ShadowLink.Origin == "" {
		return false
	}
	parsed := net.ParseIP(cfg.ShadowLink.Origin)
	return parsed != nil && parsed.To4() != nil
}

// serverBootstrapDomain — INT-H2 (2026-06-12): чистый хелпер, вычисляющий
// серверный ДОМЕН для bootstrap-whitelist split-DNS forwarder'а. Выбор host'а
// зеркалит resolveServerIPs (origin short-circuit → CDN → Server), но вместо
// резолва возвращает само имя — и только когда это домен:
//   - origin-pin (валидный IPv4 в ?origin=) → "" — dial идёт по литеральному
//     IP, DNS в reconnect не участвует, bootstrap не нужен;
//   - IP-литерал (VLESS address / ShadowLink server) → "" — по той же причине;
//   - иначе → домен (CDN-режим / доменный server / VLESS-домен).
func serverBootstrapDomain(protocol string, cfg *Config) string {
	var host string
	switch protocol {
	case "vless":
		if cfg.VLESS != nil {
			host = cfg.VLESS.Address
		}
	case "shadowlink":
		if cfg.ShadowLink == nil {
			break
		}
		// Origin short-circuit — зеркало resolveServerIPs: валидный IPv4 в
		// origin пиннит data path к литеральному IP, DNS-bootstrap не нужен.
		// Невалидный origin (как и там) проваливается к обычному выбору host'а.
		if originPinned(cfg) {
			return ""
		}
		if cfg.ShadowLink.CDN != "" {
			host = cfg.ShadowLink.CDN
		} else if h, _, err := net.SplitHostPort(cfg.ShadowLink.Server); err == nil {
			host = h
		} else {
			host = cfg.ShadowLink.Server
		}
	}
	if host == "" || net.ParseIP(host) != nil {
		return "" // нет host'а либо IP-литерал — DNS-bootstrap не нужен
	}
	return host
}

// resolveServerPort returns the VPN server's port for LeakGuard config.
func resolveServerPort(protocol string, cfg *Config) int {
	switch protocol {
	case "vless":
		if cfg.VLESS != nil {
			return cfg.VLESS.Port
		}
	case "shadowlink":
		if cfg.ShadowLink != nil {
			_, portStr, err := net.SplitHostPort(cfg.ShadowLink.Server)
			if err == nil {
				port := 0
				fmt.Sscanf(portStr, "%d", &port)
				if port > 0 {
					return port
				}
			}
		}
	}
	return 443 // default
}

// leakguardStatePath returns the path for LeakGuard crash-recovery state file.
// W3: use absolute path so crash-recovery works regardless of CWD after reboot.
func leakguardStatePath() string {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		if appData != "" {
			dir := appData + "\\NixaVPN"
			os.MkdirAll(dir, 0700)
			return dir + "\\leakguard.state"
		}
	case "darwin":
		home := os.Getenv("HOME")
		if home != "" {
			dir := home + "/Library/Application Support/NixaVPN"
			os.MkdirAll(dir, 0700)
			return dir + "/leakguard.state"
		}
	}
	// Linux / fallback
	os.MkdirAll("/var/run/nixavpn", 0700)
	return "/var/run/nixavpn/leakguard.state"
}

// checkExitIP performs a request through the system HTTP stack to determine
// the current public exit IP address.
func checkExitIP() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", fmt.Errorf("запрос к ipify: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", fmt.Errorf("чтение ответа: %w", err)
	}

	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("неверный IP в ответе: %q", ip)
	}
	return ip, nil
}

// generateProxyCredentials создаёт случайные user/pass для SOCKS5 прокси.
// Новые credentials при каждом запуске — другие приложения не могут подключиться.
func generateProxyCredentials() (user, pass string) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "nix", hex.EncodeToString(b)
}

// bypassEnabledFromEnv reports whether bypass routing is enabled.
// Default is ON — set SHADOWLINK_BYPASS_ENABLED=0 (or "false"/"no"/"off")
// to disable. Mirrors the pqEnabled() semantics from client/utls_http.go.
func bypassEnabledFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_BYPASS_ENABLED"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// adminOverrideEnabled reports whether admin override network fetch is
// enabled (spec §10). Default ON; SHADOWLINK_ADMIN_OVERRIDE=0/false/no/off
// disables the network call so the client uses only the on-disk cache (which
// itself can be empty → embedded baseline only). Same semantics as
// bypassEnabledFromEnv() and the server-side useTokenBucket() flag.
func adminOverrideEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_ADMIN_OVERRIDE"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// splitTunnelEnabledFromEnv reports whether explicit split-tunnel is enabled.
// Default OFF (fail-secure): bypass ranges are NOT allowed past the kill switch
// unless the user explicitly opts in. Only "1"/"true"/"yes"/"on" enable it.
// Opt-IN semantics (opposite of bypassEnabledFromEnv) — safe value = off.
func splitTunnelEnabledFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_SPLIT_TUNNEL"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// splitDNSEnabledFromEnv reports whether the local split-DNS forwarder is
// enabled. Default follows bypass: ON when bypass is ON (the forwarder needs
// the shared RU snapshot to arbitrate), OFF when bypass is OFF. Explicit
// SHADOWLINK_SPLIT_DNS=0/false/no/off force-disables; =1/true/yes/on
// force-enables regardless of bypass. Mirrors bypassEnabledFromEnv semantics.
// LG-L3: an unrecognized value keeps the follow-bypass default but logs a
// Warn — a typo like "of" must be visible, not silently swallowed.
func splitDNSEnabledFromEnv(bypassOn bool) bool {
	raw := strings.TrimSpace(os.Getenv("SHADOWLINK_SPLIT_DNS"))
	switch strings.ToLower(raw) {
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return true
	case "":
		return bypassOn // unset: follow bypass
	default:
		slog.Warn("SHADOWLINK_SPLIT_DNS: нераспознанное значение — действует default (follow bypass)",
			"value", raw, "bypass", bypassOn)
		return bypassOn
	}
}

// leakguardStrictFromEnv reports whether a LeakGuard Enable failure should abort
// startup (os.Exit) instead of continuing without leak protection.
//
// Раунд 18 / C-3: default инвертирован на ON (fail-secure). Раньше строгий
// режим был opt-IN, поэтому при любом сбое Enable (нет прав администратора,
// WFP недоступен, netsh отказал, backup политики не прочитался) клиент писал
// WARN и продолжал работу с поднятым туннелем и БЕЗ kill-switch. При
// последующем обрыве туннеля трафик уходил через физический шлюз с реальным
// IP — то есть самый глубоко проработанный контур защиты по умолчанию не
// вставал именно тогда, когда он нужен.
//
// Теперь opt-OUT: "0"/"false"/"no"/"off" — явная аварийная ручка для случая
// «нужно поднять туннель на машине, где LeakGuard не работает, и я осознаю
// риск утечки». Всё прочее (включая пустое значение и мусор) → strict.
//
// Сравните с splitTunnelEnabledFromEnv: там opt-IN правилен, потому что
// безопасное значение = off. Здесь безопасное значение = on, поэтому и
// default обратный.
func leakguardStrictFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_LEAKGUARD_STRICT"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// loadBypassHMACKey reads the admin override HMAC key from
// SHADOWLINK_BYPASS_HMAC_KEY (hex-encoded). Returns the decoded bytes plus
// a flag indicating whether admin override fetching is enabled.
//
// The server derives this key from JWT_SECRET; the client cannot — so the
// key MUST be provisioned out-of-band. If the env is unset or invalid,
// fetching is disabled and the caller proceeds with nil override.
func loadBypassHMACKey() ([]byte, bool) {
	raw := strings.TrimSpace(os.Getenv("SHADOWLINK_BYPASS_HMAC_KEY"))
	if raw == "" {
		slog.Info("admin bypass override disabled — SHADOWLINK_BYPASS_HMAC_KEY not set")
		return nil, false
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		slog.Warn("admin bypass override disabled — SHADOWLINK_BYPASS_HMAC_KEY hex decode failed", "err", err)
		return nil, false
	}
	if len(key) < 16 {
		slog.Warn("admin bypass override disabled — SHADOWLINK_BYPASS_HMAC_KEY too short", "bytes", len(key), "min", 16)
		return nil, false
	}
	return key, true
}

// userBypassCacheDir returns the per-user cache directory used to persist
// the signed admin bypass override blob. Falls back to a relative dir if
// os.UserConfigDir() is unavailable.
func userBypassCacheDir() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ".nixavpn-cache"
	}
	return filepath.Join(d, "nixavpn", "bypass")
}

// randomSOCKSAddr выбирает случайный порт в диапазоне 10000-60000.
// Не используем стандартный 1080 — он в методичке РКН для обнаружения прокси.
func randomSOCKSAddr() string {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	port := 10000 + int(b[0])<<8 + int(b[1])
	if port > 60000 {
		port = 10000 + port%50000
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

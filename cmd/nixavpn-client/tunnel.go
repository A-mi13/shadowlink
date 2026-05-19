package main

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	tunsdialer "github.com/xjasonlyu/tun2socks/v2/dialer"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	t2tunnel "github.com/xjasonlyu/tun2socks/v2/tunnel"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/client/bypassroute"
)

// Tunnel управляет TUN-интерфейсом для системного VPN-режима.
// Использует tun2socks v2 как встроенную Go-библиотеку.
// Трафик с TUN-интерфейса перенаправляется в SOCKS5-прокси.
type Tunnel struct {
	socksAddr string
	proxyUser string
	proxyPass string
	serverIPs []string // one or more IPs for escape routes

	// narrowEscape: when true, setupRoutes skips the /16 CIDR sweep used to
	// catch CF Anycast rotation. This is correct ONLY when the data path is
	// pinned to a known origin IP (URL has ?origin=) — in that case the WS
	// dial target never moves, so the broader /16 escape is unnecessary AND
	// harmful (it lets ~65k unrelated IPs bypass the TUN, including any
	// neighbour service on the same /16 the user might want routed through
	// the VPN). For CDN-mode (no origin) we keep the /16 sweep.
	narrowEscape bool

	bypassEnabled  bool
	bypassOverride *bypassroute.AdminOverride

	mu      sync.Mutex
	started bool

	// nicWatcherStop signals the NIC-switching watcher (started in Start)
	// to exit. Closed by Stop. Nil when bypass is disabled or determination
	// failed at Start.
	nicWatcherStop chan struct{}
}

// WithNarrowEscape disables the /16 CIDR escape sweep, leaving only /32
// host routes for each server IP. Call this when the data path is locked
// to a specific origin IP (URL has ?origin=). Default (false) preserves
// the CDN-friendly /16 sweep that catches CF Anycast rotation.
func (t *Tunnel) WithNarrowEscape(narrow bool) *Tunnel {
	t.narrowEscape = narrow
	return t
}

// WithBypass настраивает bypass-маршрутизацию для Tunnel. Когда включено,
// dial-вызовы к IP-адресам из встроенного RU CIDR-снапшота (плюс опциональный
// admin override) идут через физическую сеть, а не через SOCKS5 + ShadowLink.
// Phase B будет наполнять override через admin API; пока передаём nil.
func (t *Tunnel) WithBypass(enabled bool, override *bypassroute.AdminOverride) *Tunnel {
	t.bypassEnabled = enabled
	t.bypassOverride = override
	return t
}

// NewTunnel создаёт Tunnel.
// socksAddr — адрес SOCKS5-прокси (например "127.0.0.1:12345").
// proxyUser/proxyPass — credentials для аутентификации на SOCKS5.
// serverIPs — IP-адреса VPN-сервера для escape-маршрутов через реальный шлюз.
func NewTunnel(socksAddr, proxyUser, proxyPass string, serverIPs []string) *Tunnel {
	return &Tunnel{
		socksAddr: socksAddr,
		proxyUser: proxyUser,
		proxyPass: proxyPass,
		serverIPs: serverIPs,
	}
}

// Start создаёт TUN-интерфейс, запускает tun2socks и настраивает маршруты.
// Использует split-routing (0.0.0.0/1 + 128.0.0.0/1), чтобы не заменять
// дефолтный маршрут целиком.
func (t *Tunnel) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.started {
		return fmt.Errorf("tunnel уже запущен")
	}

	device := tunDeviceName()

	// Linux: TUN-устройство нужно создать явно перед запуском tun2socks.
	if runtime.GOOS == "linux" {
		if err := createTUNLinux(device); err != nil {
			return fmt.Errorf("создание TUN-устройства: %w", err)
		}
	}

	// Determine physical interface BEFORE tun2socks publishes its TUN-bound
	// DefaultDialer. We set `dialer.DefaultDialer.InterfaceName/Index.Store(...)`
	// directly here instead of via `engine.Key.Interface` to close the
	// TOCTOU window where tun2socks `general()` would re-resolve the iface
	// name and `log.Fatalf` (→ os.Exit(1)) on a transient
	// `net.InterfaceByName` failure (Wi-Fi suspend, USB-Ethernet unplug).
	// We resolve once here, log a warn on failure, and continue without
	// bypass binding. Opus review I-1 (final-audit-2026-05-05).
	//
	// Effect: `proxy.NewDirect()` (used by BypassDialer) binds each socket
	// to the physical interface via IP_BOUND_IF / SO_BINDTODEVICE /
	// IP_UNICAST_IF. Without it, direct dials fall through default routing
	// and the split-routes (0.0.0.0/1 + 128.0.0.0/1) re-capture the packets
	// back into the TUN — bypass routing silently no-ops and ALL traffic
	// (including RU CIDR matches) exits through the VPN. Loopback dials for
	// our local SOCKS5 (127.0.0.1:port) are skipped by the per-platform
	// `IsGlobalUnicast()` guard in sockopt_*.go, so SOCKS5 keeps working.
	physicalIface := determinePhysicalInterface()
	physicalIfaceIdx := 0
	if physicalIface != "" {
		if iface, err := net.InterfaceByName(physicalIface); err == nil {
			tunsdialer.DefaultDialer.InterfaceName.Store(iface.Name)
			tunsdialer.DefaultDialer.InterfaceIndex.Store(int32(iface.Index))
			physicalIfaceIdx = iface.Index
			slog.Info("физический интерфейс для bypass определён",
				"name", iface.Name, "index", iface.Index)
		} else {
			slog.Warn("net.InterfaceByName fail для bypass — продолжаем без bind",
				"name", physicalIface, "err", err)
			physicalIface = ""
		}
	} else {
		slog.Warn("физический интерфейс не определён — bypass routing будет no-op")
	}

	// Загружаем конфиг tun2socks и запускаем движок.
	// Proxy URL включает credentials: socks5://user:pass@host:port
	proxyURL := fmt.Sprintf("socks5://%s:%s@%s", t.proxyUser, t.proxyPass, t.socksAddr)
	// W7: MTU 1400 to account for ShadowLink encryption + WebSocket + TLS overhead.
	// `Interface` НЕ устанавливаем — tun2socks general() сделал бы повторный
	// `net.InterfaceByName` (TOCTOU). DefaultDialer уже выставлен выше.
	key := &engine.Key{
		Device:     device,
		Proxy:      proxyURL,
		LogLevel:   "warn",
		MTU:        1400,
		UDPTimeout: 30 * time.Second,
	}
	engine.Insert(key)

	// engine.Start() блокирует выполнение — запускаем в горутине.
	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("tun2socks паника: %v", r)
			}
		}()
		engine.Start()
		errCh <- nil
	}()

	// Небольшая синхронизация: если tun2socks немедленно упал — вернуть ошибку.
	// Успешный запуск блокируется внутри engine.Start(), поэтому просто
	// настраиваем маршруты сразу после отправки команды.
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("запуск tun2socks: %w", err)
		}
	default:
		// tun2socks ещё работает (нормальный путь) — продолжаем.
	}

	// C3: wait for TUN interface to be fully ready on all platforms.
	if err := waitForTUNReady(device, 15*time.Second); err != nil {
		engine.Stop()
		return fmt.Errorf("TUN-интерфейс не готов: %w", err)
	}

	// Устанавливаем bypass dialer, если включён. При любой ошибке шага —
	// логируем warning и продолжаем: VPN работает и без bypass.
	if t.bypassEnabled {
		if err := t.installBypassDialer(); err != nil {
			slog.Warn("bypass dialer не активирован", "err", err)
		}
		// NIC-switching watcher: Wi-Fi → Ethernet (док-станция, suspend/resume,
		// USB-NIC замена) меняет default route. DefaultDialer.InterfaceIndex
		// без обновления указывает на down-адаптер → bypass dial fails с
		// ENETDOWN/ENETUNREACH. Раз в 30s проверяем gw + iface, при изменении
		// атомарно Store. Opus review I-2 (final-audit-2026-05-05).
		if physicalIface != "" {
			t.nicWatcherStop = make(chan struct{})
			go t.runNICWatcher(physicalIfaceIdx)
		}
	}

	// W4: route setup failure is fatal — without routes, TUN is useless
	// and LeakGuard kill switch would block all traffic.
	if err := setupRoutes(device, t.serverIPs, t.narrowEscape); err != nil {
		engine.Stop()
		return fmt.Errorf("не удалось настроить маршруты: %w", err)
	}

	t.started = true
	slog.Info("TUN-туннель запущен", "device", device, "proxy", t.socksAddr)
	return nil
}

// Stop останавливает tun2socks и убирает маршруты.
func (t *Tunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.started {
		return nil
	}

	// Сигнализируем NIC watcher'у завершиться. Закрытие канала идемпотентно
	// под mu (повторный Stop short-circuit'ит на !t.started выше).
	if t.nicWatcherStop != nil {
		close(t.nicWatcherStop)
		t.nicWatcherStop = nil
	}

	device := tunDeviceName()

	if err := cleanupRoutes(device, t.serverIPs); err != nil {
		slog.Warn("не удалось убрать маршруты", "err", err)
	}

	engine.Stop()

	t.started = false
	slog.Info("TUN-туннель остановлен")
	return nil
}

// nicWatchInterval — как часто перепроверять физический интерфейс.
// 30s — компромисс между responsiveness (Wi-Fi → Ethernet swap) и
// нагрузкой на `route print 0.0.0.0` (Windows exec несколько ms).
const nicWatchInterval = 30 * time.Second

// runNICWatcher следит за сменой физического интерфейса (Wi-Fi → Ethernet,
// suspend/resume, USB-NIC unplug). При изменении переписывает
// `tunsdialer.DefaultDialer.InterfaceName/Index.Store(...)` атомарно —
// все последующие direct-dials уходят через новый NIC.
//
// initialIdx — индекс, выставленный при Start. Используется как baseline
// для сравнения. Если getDefaultGateway() / getInterfaceForGateway падают,
// сохраняем старое значение (избегаем "флапа на nil-iface" во время
// transient outage).
func (t *Tunnel) runNICWatcher(initialIdx int) {
	currentIdx := initialIdx
	ticker := time.NewTicker(nicWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.nicWatcherStop:
			slog.Debug("NIC watcher остановлен")
			return
		case <-ticker.C:
			gw, err := getDefaultGateway()
			if err != nil {
				slog.Debug("NIC watcher: gw lookup fail", "err", err)
				continue
			}
			name, err := getInterfaceForGateway(gw)
			if err != nil {
				slog.Debug("NIC watcher: iface lookup fail", "gw", gw, "err", err)
				continue
			}
			iface, err := net.InterfaceByName(name)
			if err != nil {
				slog.Debug("NIC watcher: InterfaceByName fail", "name", name, "err", err)
				continue
			}
			if iface.Index == currentIdx {
				continue // unchanged
			}
			tunsdialer.DefaultDialer.InterfaceName.Store(iface.Name)
			tunsdialer.DefaultDialer.InterfaceIndex.Store(int32(iface.Index))
			slog.Info("NIC switched, обновили DefaultDialer",
				"old_idx", currentIdx, "new_name", iface.Name, "new_idx", iface.Index)
			currentIdx = iface.Index
		}
	}
}

// installBypassDialer loads the RU CIDR trie and installs a BypassDialer as the
// active tun2socks dialer. Must be called after engine.Start() (tun2socks
// publishes its tunnel singleton during Start) and before setupRoutes so
// the dialer is in place before any packets flow through the TUN.
func (t *Tunnel) installBypassDialer() error {
	resolved, err := bypassroute.Load(bypassroute.Source{
		Embedded: true,
		Override: t.bypassOverride,
	})
	if err != nil {
		return fmt.Errorf("load bypass trie: %w", err)
	}
	socks, err := proxy.NewSocks5(t.socksAddr, t.proxyUser, t.proxyPass)
	if err != nil {
		return fmt.Errorf("build socks5 dialer: %w", err)
	}
	bypass := bypassroute.NewBypassDialer(socks, resolved).
		WithMetrics(client.Stats.IncBypassMatch, client.Stats.IncBypassMiss)
	t2tunnel.T().SetDialer(bypass)
	slog.Info("bypass routing активирован",
		"include", resolved.Size(),
		"exclude", resolved.Excludes())
	return nil
}

// tunDeviceName возвращает имя TUN-устройства для текущей платформы.
//
//   - darwin:  "utun99"
//   - windows: "tun://NixaVPN"  (Wintun через tun2socks)
//   - linux:   "tun0"
func tunDeviceName() string {
	switch runtime.GOOS {
	case "darwin":
		return "utun99"
	case "windows":
		return "tun://NixaVPN"
	default: // linux и прочие
		return "tun0"
	}
}

// createTUNLinux создаёт TUN-устройство на Linux с помощью iproute2.
// На Windows и macOS TUN создаётся автоматически (Wintun / utun).
func createTUNLinux(device string) error {
	// device может быть "tun0" — оставляем как есть.
	name := device
	out, err := exec.Command("ip", "tuntap", "add", "dev", name, "mode", "tun").CombinedOutput()
	if err != nil {
		// Устройство уже существует — не считаем ошибкой.
		if strings.Contains(string(out), "File exists") {
			return nil
		}
		return fmt.Errorf("ip tuntap add: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// Поднимаем интерфейс и назначаем адрес.
	if out, err = exec.Command("ip", "addr", "add", "198.18.0.1/15", "dev", name).CombinedOutput(); err != nil {
		return fmt.Errorf("ip addr add: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	if out, err = exec.Command("ip", "link", "set", name, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setupRoutes настраивает split-routing для системного VPN.
// Сначала добавляет escape-маршруты для каждого IP VPN-сервера через реальный шлюз,
// затем один раз добавляет split-маршруты (0.0.0.0/1 + 128.0.0.0/1) через TUN.
func setupRoutes(device string, serverIPs []string, narrowEscape bool) error {
	gw, err := getDefaultGateway()
	if err != nil {
		return fmt.Errorf("определение шлюза: %w", err)
	}

	// 1. Escape-маршруты для каждого IP сервера (/32).
	for _, ip := range serverIPs {
		if err := addEscapeRoute(ip, gw); err != nil {
			slog.Warn("escape route не добавлен", "ip", ip, "err", err)
		}
	}

	// 1b. Broader escape routes for CF Anycast: add /16 for each resolved IP.
	// CF CDN rotates Anycast IPs within the same datacenter. Without broader
	// routes, ConnManager rotation may resolve to a new CF IP not covered by
	// /32 escape routes, causing traffic to loop through TUN.
	//
	// SKIPPED in narrowEscape mode (URL has ?origin=). When the data path is
	// pinned to a known origin IP, the WS dial target never rotates, so the
	// /16 sweep adds no value AND is harmful: it covers ~65k unrelated IPs
	// (every neighbour on the same /16) and exempts them from the TUN. In
	// CDN mode (no origin pin) the /16 sweep is correct and kept.
	if !narrowEscape {
		addedCIDR := make(map[string]bool)
		for _, ip := range serverIPs {
			parts := strings.SplitN(ip, ".", 4)
			if len(parts) == 4 {
				cidr := parts[0] + "." + parts[1] + ".0.0"
				if !addedCIDR[cidr] {
					addedCIDR[cidr] = true
					if err := addEscapeRouteCIDR(cidr, "255.255.0.0", gw); err != nil {
						slog.Warn("escape CIDR route не добавлен", "cidr", cidr+"/16", "err", err)
					} else {
						slog.Info("escape CIDR route добавлен", "cidr", cidr+"/16")
					}
				}
			}
		}
	} else {
		slog.Info("narrow escape mode: /16 CIDR sweep skipped (origin pin)",
			"escape_ips", serverIPs)
	}

	// 2. Split-routing через TUN — один раз.
	return addSplitRoutes(device, gw)
}

// addEscapeRoute добавляет маршрут для конкретного IP через реальный шлюз (bypass TUN).
func addEscapeRoute(serverIP, gw string) error {
	if serverIP == "" {
		return nil
	}
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "add", serverIP, "via", gw).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("ip route add %s via %s: %w (%s)", serverIP, gw, err, strings.TrimSpace(string(out)))
		}
	case "darwin":
		out, err := exec.Command("route", "add", "-host", serverIP, gw).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "exists") {
			return fmt.Errorf("route add -host %s %s: %w (%s)", serverIP, gw, err, strings.TrimSpace(string(out)))
		}
	case "windows":
		out, err := exec.Command("route", "add", serverIP, "mask", "255.255.255.255", gw, "metric", "1").CombinedOutput()
		if err != nil {
			return fmt.Errorf("route add %s: %w (%s)", serverIP, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// addEscapeRouteCIDR adds a CIDR escape route (e.g., 104.21.0.0 mask 255.255.0.0) through the real gateway.
func addEscapeRouteCIDR(network, mask, gw string) error {
	switch runtime.GOOS {
	case "linux":
		cidr := network + "/16"
		out, err := exec.Command("ip", "route", "add", cidr, "via", gw).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("ip route add %s via %s: %w (%s)", cidr, gw, err, strings.TrimSpace(string(out)))
		}
	case "darwin":
		out, err := exec.Command("route", "add", "-net", network+"/16", gw).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "exists") {
			return fmt.Errorf("route add -net %s/16 %s: %w (%s)", network, gw, err, strings.TrimSpace(string(out)))
		}
	case "windows":
		out, err := exec.Command("route", "add", network, "mask", mask, gw, "metric", "1").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "already exists") {
			return fmt.Errorf("route add %s mask %s: %w (%s)", network, mask, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// addSplitRoutes добавляет split-routing (0.0.0.0/1 + 128.0.0.0/1) через TUN.
func addSplitRoutes(device, gw string) error {
	switch runtime.GOOS {
	case "linux":
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			out, err := exec.Command("ip", "route", "add", cidr, "dev", device).CombinedOutput()
			if err != nil && !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("split route %s: %w (%s)", cidr, err, strings.TrimSpace(string(out)))
			}
		}
	case "darwin":
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			out, err := exec.Command("route", "add", "-net", cidr, "-interface", device).CombinedOutput()
			if err != nil && !strings.Contains(string(out), "exists") {
				return fmt.Errorf("split route %s: %w (%s)", cidr, err, strings.TrimSpace(string(out)))
			}
		}
	case "windows":
		// DNS на TUN: используем Yandex DNS (RU) как primary + Cloudflare как
		// fallback. RU primary критично для bypass routing — DNS-запросы к
		// RU resolver'у возвращают geo-localized RU IP'ы для российских
		// сайтов (yandex.ru, mail.ru, vk.com, 2ip.ru), которые попадают в
		// embedded RU CIDR snapshot и идут direct через физический NIC.
		// Field-test 2026-05-05: с CF DNS (1.1.1.1) российские сайты
		// резолвились в global anycast IP'ы (не в RU snapshot) → весь
		// трафик уходил через VPN. С Yandex DNS bypass работает.
		//
		// Yandex DNS 77.88.8.8 / 77.88.8.1 — public RU resolver'ы, доступны
		// из любой сети, поддерживают как RU так и foreign домены, в RIPE-RU
		// snapshot включены (bypass match для самих DNS-пакетов работает).
		// Cloudflare 1.1.1.1 как secondary на случай Yandex DNS outage.
		tunName := strings.TrimPrefix(device, "tun://")
		if out, err := exec.Command("netsh", "interface", "ip", "set", "dns",
			tunName, "static", "77.88.8.8").CombinedOutput(); err != nil {
			slog.Warn("не удалось установить основной DNS на TUN", "err", err, "output", strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("netsh", "interface", "ip", "add", "dns",
			tunName, "77.88.8.1", "index=2").CombinedOutput(); err != nil {
			slog.Warn("не удалось установить вторичный DNS на TUN", "err", err, "output", strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("netsh", "interface", "ip", "add", "dns",
			tunName, "1.1.1.1", "index=3").CombinedOutput(); err != nil {
			slog.Warn("не удалось установить резервный DNS на TUN", "err", err, "output", strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("netsh", "interface", "ip", "set", "interface",
			tunName, "metric=1").CombinedOutput(); err != nil {
			slog.Warn("не удалось установить метрику TUN-интерфейса", "err", err, "output", strings.TrimSpace(string(out)))
		}
		exec.Command("ipconfig", "/flushdns").Run()
		slog.Info("DNS настроен на TUN", "primary", "77.88.8.8 (Yandex)", "secondary", "77.88.8.1", "fallback", "1.1.1.1", "metric", 1)

		// Split-routing через TUN-интерфейс.
		tunGW := "198.18.0.1"
		routes := []struct{ net, mask string }{
			{"0.0.0.0", "128.0.0.0"},
			{"128.0.0.0", "128.0.0.0"},
		}
		ifIdx, err := getWindowsInterfaceIndex(device)
		if err != nil {
			slog.Warn("не удалось получить индекс TUN, используем gateway", "err", err)
			for _, r := range routes {
				out, err2 := exec.Command("route", "add", r.net, "mask", r.mask, tunGW, "metric", "1").CombinedOutput()
				if err2 != nil {
					return fmt.Errorf("split route %s: %w (%s)", r.net, err2, strings.TrimSpace(string(out)))
				}
			}
			return nil
		}
		for _, r := range routes {
			out, err2 := exec.Command("route", "add", r.net, "mask", r.mask, tunGW, "metric", "1", "if", ifIdx).CombinedOutput()
			if err2 != nil {
				return fmt.Errorf("split route %s: %w (%s)", r.net, err2, strings.TrimSpace(string(out)))
			}
		}
	default:
		return fmt.Errorf("неподдерживаемая платформа: %s", runtime.GOOS)
	}
	return nil
}

// cleanupRoutes удаляет маршруты, добавленные в setupRoutes.
func cleanupRoutes(device string, serverIPs []string) error {
	gw, err := getDefaultGateway()
	if err != nil {
		slog.Warn("не удалось определить шлюз при очистке маршрутов", "err", err)
		gw = ""
	}

	// 1. Удаляем escape-маршруты.
	for _, ip := range serverIPs {
		removeEscapeRoute(ip, gw)
	}

	// 2. Удаляем split-routes.
	removeSplitRoutes(device)
	return nil
}

func removeEscapeRoute(serverIP, gw string) {
	if serverIP == "" || gw == "" {
		return
	}
	switch runtime.GOOS {
	case "linux":
		_ = exec.Command("ip", "route", "del", serverIP, "via", gw).Run()
	case "darwin":
		_ = exec.Command("route", "delete", "-host", serverIP, gw).Run()
	case "windows":
		_ = exec.Command("route", "delete", serverIP, "mask", "255.255.255.255", gw).Run()
	}
}

func removeSplitRoutes(device string) {
	switch runtime.GOOS {
	case "linux":
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			_ = exec.Command("ip", "route", "del", cidr, "dev", device).Run()
		}
		_ = exec.Command("ip", "link", "del", device).Run()
	case "darwin":
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			_ = exec.Command("route", "delete", "-net", cidr, "-interface", device).Run()
		}
	case "windows":
		for _, r := range []struct{ net, mask string }{
			{"0.0.0.0", "128.0.0.0"},
			{"128.0.0.0", "128.0.0.0"},
		} {
			_ = exec.Command("route", "delete", r.net, "mask", r.mask).Run()
		}
		_ = exec.Command("ipconfig", "/flushdns").Run()
	}
}

// getDefaultGateway возвращает IP-адрес дефолтного шлюза для текущей платформы.
func getDefaultGateway() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return getDefaultGatewayLinux()
	case "darwin":
		return getDefaultGatewayDarwin()
	case "windows":
		return getDefaultGatewayWindows()
	default:
		return "", fmt.Errorf("неподдерживаемая платформа: %s", runtime.GOOS)
	}
}

// getDefaultGatewayLinux парсит вывод `ip route show default`.
func getDefaultGatewayLinux() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("ip route show default: %w", err)
	}
	// Пример вывода: "default via 192.168.1.1 dev eth0 ..."
	return parseGatewayVia(string(out))
}

// getDefaultGatewayDarwin парсит вывод `route -n get default`.
func getDefaultGatewayDarwin() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", fmt.Errorf("route -n get default: %w", err)
	}
	// Пример вывода содержит строку "  gateway: 192.168.1.1"
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	return "", fmt.Errorf("шлюз не найден в выводе route -n get default")
}

// getDefaultGatewayWindows парсит вывод `route print 0.0.0.0`.
func getDefaultGatewayWindows() (string, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", fmt.Errorf("route print 0.0.0.0: %w", err)
	}
	// Ищем строку вида "  0.0.0.0    0.0.0.0    192.168.1.1    ..."
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			return fields[2], nil
		}
	}
	return "", fmt.Errorf("шлюз не найден в выводе route print")
}

// parseGatewayVia находит IP-адрес после ключевого слова "via" в строке маршрута.
// Используется для разбора вывода `ip route`.
func parseGatewayVia(routeOutput string) (string, error) {
	for _, line := range strings.Split(routeOutput, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("шлюз не найден в выводе ip route")
}

// waitForTUNReady waits for the TUN interface to be fully operational.
// On Windows: checks netsh for interface presence.
// On macOS/Linux: checks that the interface exists and has an IP.
func waitForTUNReady(device string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	switch runtime.GOOS {
	case "windows":
		tunName := strings.TrimPrefix(device, "tun://")
		for time.Now().Before(deadline) {
			out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
			if err == nil && strings.Contains(string(out), tunName) {
				slog.Debug("TUN-интерфейс обнаружен", "name", tunName)
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("интерфейс %q не появился за %v", tunName, timeout)

	case "darwin":
		for time.Now().Before(deadline) {
			out, err := exec.Command("ifconfig", device).Output()
			if err == nil && strings.Contains(string(out), "inet ") {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("интерфейс %q не готов за %v", device, timeout)

	case "linux":
		for time.Now().Before(deadline) {
			out, err := exec.Command("ip", "addr", "show", device).Output()
			if err == nil && strings.Contains(string(out), "inet ") {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("интерфейс %q не готов за %v", device, timeout)

	default:
		time.Sleep(2 * time.Second) // fallback: just wait
		return nil
	}
}

// determinePhysicalInterface returns the OS name of the network interface that
// owns the default-route gateway. We pass it to tun2socks via `engine.Key.Interface`
// so `dialer.DefaultDialer` (used by `proxy.NewDirect()` from the bypass path)
// binds outbound sockets to the physical NIC instead of letting the kernel
// route them through the freshly-installed TUN split-routes.
//
// Returns "" on any error — the caller logs a warning and continues without
// bypass binding (VPN itself still works, only RU bypass is no-op).
func determinePhysicalInterface() string {
	gw, err := getDefaultGateway()
	if err != nil {
		slog.Warn("не удалось определить шлюз для bypass", "err", err)
		return ""
	}
	name, err := getInterfaceForGateway(gw)
	if err != nil {
		slog.Warn("не удалось найти интерфейс шлюза", "gw", gw, "err", err)
		return ""
	}
	return name
}

// virtualIfacePrefixes is a Windows-centric list of name prefixes that
// almost always belong to virtualization / VPN / tunneling software, never
// to the physical NIC actually carrying internet traffic. When multiple
// interfaces' subnets contain the default gateway IP (rare but real — WSL
// + Hyper-V Default Switch may overlap with home subnets), preferring a
// non-virtual match avoids binding bypass dials to a dead-end virtual
// switch.
//
// Order matters only for log readability; matching is case-insensitive
// substring (not anchored prefix) so "vEthernet (WSL)" / "Hyper-V Virtual
// Ethernet Adapter" / "VMware Network Adapter VMnet1" all hit.
//
// Linux/macOS rarely need this filter (physical NICs have stable names
// like eth0/en0 and virtual ones come up later in the enumeration), but
// the heuristic does not harm them — it falls through to the first match
// when no name hits the blacklist.
var virtualIfacePrefixes = []string{
	"veth",       // Linux veth pairs
	"vethernet",  // Windows Hyper-V virtual switches
	"hyper-v",    // Windows Hyper-V
	"vmware",     // VMware adapters
	"virtualbox", // VirtualBox host-only / NAT
	"vbox",       // shorter VirtualBox naming
	"docker",     // Docker bridge / NAT
	"wsl",        // explicit WSL vEthernet
	"tap",        // OpenVPN / Tailscale TAP
	"tun",        // tun-based VPN devices (incl. our own NixaVPN if a previous run left one)
	"wireguard",  // WireGuard interfaces
	"openvpn",    // OpenVPN named interfaces
	"tailscale",  // Tailscale interface
	"nordlynx",   // NordVPN WireGuard
	"loopback",   // any "Loopback Pseudo-Interface" Windows variant
	"bluetooth",  // Bluetooth PAN
}

func isVirtualIface(name string) bool {
	low := strings.ToLower(name)
	for _, p := range virtualIfacePrefixes {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

// getInterfaceForGateway returns the name of the up, non-loopback interface
// whose subnet contains the supplied gateway IP. This works on Windows, Linux
// and macOS without parsing per-platform `route` / `ip` text output beyond
// the gateway itself.
//
// Multiple-match selection (Opus review I-3, 2026-05-05): when more than
// one up interface's subnet contains gw (e.g. WSL/Hyper-V vEthernet adapter
// with same /24 as the home router), prefer the first NON-virtual match —
// see virtualIfacePrefixes. Falls back to the first match overall if every
// candidate is virtual (unusual but graceful).
func getInterfaceForGateway(gw string) (string, error) {
	gwIP := net.ParseIP(gw)
	if gwIP == nil {
		return "", fmt.Errorf("неверный IP шлюза: %s", gw)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("net.Interfaces: %w", err)
	}
	var (
		firstMatch        string
		firstNonVirtMatch string
		matchCount        int
	)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if !ipnet.Contains(gwIP) {
				continue
			}
			matchCount++
			if firstMatch == "" {
				firstMatch = iface.Name
			}
			if firstNonVirtMatch == "" && !isVirtualIface(iface.Name) {
				firstNonVirtMatch = iface.Name
			}
			break // one match per iface is enough
		}
	}
	switch {
	case firstNonVirtMatch != "":
		if matchCount > 1 {
			slog.Info("несколько интерфейсов содержат шлюз, выбран физический",
				"chosen", firstNonVirtMatch, "candidates", matchCount, "gw", gw)
		}
		return firstNonVirtMatch, nil
	case firstMatch != "":
		slog.Warn("только virtual-интерфейсы содержат шлюз, использую первый",
			"chosen", firstMatch, "gw", gw)
		return firstMatch, nil
	}
	return "", fmt.Errorf("не найден интерфейс с подсетью шлюза %s", gw)
}

// getWindowsInterfaceIndex возвращает числовой индекс TUN-интерфейса Windows
// через `netsh interface show interface`. Используется при добавлении маршрутов.
func getWindowsInterfaceIndex(device string) (string, error) {
	// Убираем tun:// префикс — нам нужно только имя.
	name := strings.TrimPrefix(device, "tun://")

	out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
	if err != nil {
		return "", fmt.Errorf("netsh interface show: %w", err)
	}
	// Формат вывода: "  Idx  Met  MTU   Status   Name"
	//               "   15   25 1500   connected  NixaVPN"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, name) {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				return fields[0], nil
			}
		}
	}
	return "", fmt.Errorf("интерфейс %q не найден в netsh output", name)
}

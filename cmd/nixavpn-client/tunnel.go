package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	tunsdialer "github.com/xjasonlyu/tun2socks/v2/dialer"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	t2tunnel "github.com/xjasonlyu/tun2socks/v2/tunnel"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/client/bypassroute"
	"github.com/nixavpn/shadowlink/client/dnsproxy"
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

	// resolved is the single RU CIDR snapshot, loaded once in installBypassDialer
	// and shared between the BypassDialer and the split-DNS Forwarder. Sharing one
	// *Resolved is critical: two independent snapshots could drift (different load
	// times → different admin overrides), which would re-introduce the Yandex
	// censorship bug the Forwarder fixes (an IP classified RU by the dialer but
	// foreign by the Forwarder, or vice versa). Nil until installBypassDialer runs.
	resolved *bypassroute.Resolved

	// splitDNSEnabled gates the local split-DNS Forwarder (Yandex-vs-Cloudflare
	// arbitration). When false, the TUN keeps the legacy static Yandex DNS.
	splitDNSEnabled bool
	// bootstrapDomains — INT-H2 (2026-06-12): серверные домены, передаваемые в
	// split-DNS forwarder как bootstrap-whitelist (Yandex-only fallback при
	// недоступном CF). Лечит deadlock CDN-режима: все WS-слоты мертвы → DoH
	// через туннель мёртв → reconnect не может зарезолвить серверный домен →
	// туннель не восстанавливается. Пусто при origin-pin / IP-литералах
	// (DNS-bootstrap не нужен) — поведение forwarder'а тогда без изменений.
	bootstrapDomains []string
	// dnsFwd is the running split-DNS Forwarder (nil when split-DNS is disabled
	// or failed to start). Set in Start, stopped in Stop.
	dnsFwd *dnsproxy.Forwarder
	// dnsListenIP is the IP (no port) the Forwarder bound to — "198.18.0.1"
	// (TUN gateway) or "127.0.0.1" (loopback fallback). Pushed onto the TUN as
	// its sole DNS via setTUNDNS when split-DNS is active.
	dnsListenIP string

	// inProcessDialer, when set, replaces the loopback SOCKS5 dialer as the
	// tunnel-bound inner dialer (Bug #5) — TUN traffic relays through the WS
	// transport in-process, with no loopback socket per flow (no Windows
	// ephemeral port exhaustion). Nil → fall back to proxy.NewSocks5 (loopback).
	inProcessDialer proxy.Dialer

	// onNetworkChange, when set, is invoked by runNICWatcher when the default
	// interface changes (Wi-Fi↔Ethernet, dock, wake-from-sleep). It forces the
	// WS pool to tear down slots bound to the OLD local path and reconnect —
	// without it those sockets hang until the TCP timeout (P0, see
	// WSPoolTransport.NetworkChanged). Held as a plain func so tunnel.go does not
	// import client/ or engine/; the closure is wired in main.go from the engine's
	// NetworkChangeNotifier. Nil → the watcher only fixes the bypass dialer.
	onNetworkChange func()

	mu      sync.Mutex
	started bool

	// nicWatcherStop signals the NIC-switching watcher (started in Start)
	// to exit. Closed by Stop. Nil when bypass is disabled or determination
	// failed at Start. The watcher goroutine itself selects on a copy of this
	// channel captured by value at launch (same pattern as
	// dnsproxy.Forwarder.runBranchLog) — it never reads the field, so the
	// close+nil under mu in Stop/rollbackStart cannot race with it or leave it
	// blocked on a nil-channel receive. The field exists only for close/nil
	// under mu.
	nicWatcherStop chan struct{}

	// routesDirty is set (under mu) right before Start calls setupRoutes and
	// cleared by the teardown paths after cleanupRoutes runs. setupRoutes may
	// fail PARTIALLY: the /32 server escapes, /32 Yandex DNS escapes and the
	// /16 CIDR sweep are installed via the PHYSICAL gateway before
	// addSplitRoutes — on its failure those routes stay in the OS routing
	// table until reboot (they are NOT torn down with the engine), silently
	// exempting ~65k IPs from any future VPN. The flag tells rollbackStart
	// that route cleanup is required.
	routesDirty bool

	// resolvConfBackup holds the original /etc/resolv.conf state captured the
	// first time we overwrote it (linux only). It is restored in Stop so the
	// host keeps working DNS after the VPN is torn down — otherwise the host is
	// left pointing at the forwarder nameserver (e.g. 198.18.0.1) which is
	// unreachable outside the tunnel. Guarded by resolvConfTouched: backup/restore
	// only happen when we actually wrote resolv.conf. All three fields are touched
	// solely from setTUNDNS (under mu, during Start) and Stop (under mu) — no
	// concurrent access.
	resolvConfTouched     bool   // true once we have written /etc/resolv.conf
	resolvConfWasSymlink  bool   // original was a symlink (systemd-resolved stub)
	resolvConfSymlinkDest string // symlink target (valid only when wasSymlink)
	resolvConfBackup      []byte // original regular-file contents (valid when !wasSymlink)

	// darwinDNSBackup holds the per-service DNS captured BEFORE setTUNDNS
	// rewrote them via networksetup (darwin only). Symmetric to the linux
	// resolv.conf ownership model: the Tunnel must own (and restore in Stop)
	// what it changes. ВАЖНО про содержимое бэкапа:
	//   - lg != nil (обычный случай): lg.PreLock выставил всем сервисам
	//     1.1.1.1/8.8.8.8 ДО tun.Start → этот бэкап хранит LOCK-значения
	//     LeakGuard'а, НЕ пользовательские. Он лишь fallback; истинные
	//     оригиналы (DHCP/automatic) восстанавливает lg.Disable(), который в
	//     main.go обязан идти ПОСЛЕ tun.Stop() — иначе наш restore перетёр бы
	//     их обратно lock-значениями.
	//   - lg == nil (leakguard.New failed): PreLock не выполнялся → бэкап
	//     хранит ИСТИННЫЕ пользовательские значения, и restore Tunnel'а сам по
	//     себе корректен и достаточен.
	// Touched solely from setTUNDNS (under mu, during Start) and Stop (under mu).
	darwinDNSTouched bool
	darwinDNSBackup  []darwinDNSEntry
}

// darwinDNSEntry is one network service's pre-VPN DNS configuration.
// servers == nil means the service was on automatic/DHCP DNS ("There aren't
// any DNS Servers set" sentinel) — restored by passing the "Empty" keyword.
type darwinDNSEntry struct {
	service string
	servers []string
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

// WithSplitDNS enables the local split-DNS Forwarder. When enabled, Start brings
// up a dnsproxy.Forwarder (Yandex plain-UDP direct vs Cloudflare DoH over the
// tunnel, arbitrated against the RU CIDR snapshot) and points the TUN interface's
// DNS at it. When disabled (default), the TUN keeps the legacy static Yandex DNS.
// The Forwarder shares the same *bypassroute.Resolved as the bypass dialer, so
// split-DNS is only meaningful together with bypass — main.go (T7) gates this.
func (t *Tunnel) WithSplitDNS(enabled bool) *Tunnel {
	t.splitDNSEnabled = enabled
	return t
}

// WithBootstrapDomains задаёт серверные домены для bootstrap-whitelist
// split-DNS forwarder'а (INT-H2, 2026-06-12). Пустые строки отфильтровываются;
// без вызова (или с пустым итогом) forwarder ведёт себя как прежде. Имеет
// эффект только вместе с WithSplitDNS(true).
func (t *Tunnel) WithBootstrapDomains(domains ...string) *Tunnel {
	for _, d := range domains {
		if trimmed := strings.TrimSpace(d); trimmed != "" {
			t.bootstrapDomains = append(t.bootstrapDomains, trimmed)
		}
	}
	return t
}

// WithInProcessDialer sets the in-process tun2socks dialer (Bug #5). When set,
// installBypassDialer uses it as the tunnel-bound inner dialer instead of a
// loopback SOCKS5 dialer — eliminating Windows ephemeral port exhaustion. Pass
// nil (or don't call) to keep the loopback path.
func (t *Tunnel) WithInProcessDialer(d proxy.Dialer) *Tunnel {
	t.inProcessDialer = d
	return t
}

// WithNetworkChangeHook sets the callback runNICWatcher invokes when it detects a
// default-interface change. Wire it to the engine's NetworkChanged so the WS pool
// re-establishes slots promptly instead of hanging on the old path. Pass nil (or
// don't call) to keep the legacy behaviour (bypass-dialer fix only).
func (t *Tunnel) WithNetworkChangeHook(hook func()) *Tunnel {
	t.onNetworkChange = hook
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

	// Centralized rollback: every resource brought up below (engine, NIC
	// watcher, split-DNS forwarder) is created in-place; on ANY error path we
	// must tear them all down, otherwise a partial Start leaks the forwarder
	// goroutine + occupies :53 (and leaks the NIC watcher), while t.started
	// stays false so a later Stop short-circuits and never cleans up. Instead
	// of sprinkling per-resource cleanup at each error return, we flip `success`
	// only at the very end and let this single defer reverse a partial bring-up.
	// On the normal path success=true and the defer is a no-op — the resources
	// then belong to the Tunnel and are released by Stop().
	success := false
	defer func() {
		if success {
			return
		}
		t.rollbackStart()
	}()

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
	// On failure the deferred rollbackStart() stops the engine.
	if err := waitForTUNReady(device, 15*time.Second); err != nil {
		return fmt.Errorf("TUN-интерфейс не готов: %w", err)
	}

	// Windows: назначаем статический IP 198.18.0.1/24 на TUN-интерфейс. На Linux
	// адрес уже назначен в createTUNLinux (ip addr add 198.18.0.1/15); Wintun на
	// Windows сам IP не назначает — без этого интерфейс остаётся с APIPA
	// (169.254.x.x), bind split-DNS forwarder'а на 198.18.0.1:53 падает
	// ("address is not valid in its context"), forwarder откатывается на
	// loopback (127.0.0.1:53), а Windows DNS Client ненадёжно ходит к loopback
	// как iface-DNS → резолвит мимо forwarder'а (РКН-заглушка). Назначаем ДО
	// startSplitDNS, чтобы 198.18.0.1:53 был доступен. Не fatal: при ошибке
	// forwarder деградирует на loopback (старое поведение). Darwin (utun) —
	// отдельный случай, loopback fallback там приемлем (TODO: статический IP на
	// utun через ifconfig, если потребуется надёжный split-DNS на macOS).
	if runtime.GOOS == "windows" {
		if err := assignTUNAddrWindows(device); err != nil {
			slog.Warn("не удалось назначить IP на TUN (Windows) — split-DNS отступит на loopback", "err", err)
		} else {
			slog.Info("IP назначен на TUN (Windows)", "addr", tunStaticAddr+"/24")
		}
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
		// The stop channel is passed by value: the goroutine must keep
		// selecting on THIS channel even after Stop/rollbackStart nils the
		// field (see the nicWatcherStop field doc).
		if physicalIface != "" {
			stop := make(chan struct{})
			t.nicWatcherStop = stop
			go t.runNICWatcher(physicalIfaceIdx, stop)
		}
	}

	// Split-DNS forwarder: поднимаем ДО setupRoutes (split-маршруты заберут
	// весь :53 трафик в TUN — forwarder должен уже слушать). При ошибке —
	// продолжаем без split-DNS (VPN работает, TUN ниже получит legacy Yandex
	// static DNS через setTUNDNS). t.resolved шарится с BypassDialer; при nil
	// (bypass off) forwarder работает в безопасном режиме «всё на Cloudflare».
	if t.splitDNSEnabled {
		if t.resolved == nil {
			slog.Info("split-DNS: RU snapshot пуст (bypass off) — арбитраж уйдёт на Cloudflare")
		}
		t.dnsFwd, t.dnsListenIP = startSplitDNS(t.resolved, t.bootstrapDomains)
		if t.dnsFwd == nil {
			slog.Warn("split-DNS forwarder не запущен — продолжаем без split-DNS")
		} else {
			slog.Info("split-DNS forwarder запущен", "listen", t.dnsListenIP+":53")
		}
	}

	// W4: route setup failure is fatal — without routes, TUN is useless
	// and LeakGuard kill switch would block all traffic. On failure the
	// deferred rollbackStart() stops the forwarder, NIC watcher and engine,
	// and (via routesDirty, set BEFORE the call) removes whatever escape
	// routes a partially-failed setupRoutes already installed via the
	// physical gateway — those live in the OS routing table until reboot
	// and are not torn down with the engine.
	t.routesDirty = true
	if err := setupRoutes(device, t.serverIPs, t.narrowEscape); err != nil {
		return fmt.Errorf("не удалось настроить маршруты: %w", err)
	}

	// DNS на TUN. Split-DNS ON → единственный DNS = forwarder (t.dnsListenIP).
	// Split-DNS OFF (или forwarder не поднялся) → legacy Yandex static DNS
	// (primary 77.88.8.8 + 77.88.8.1 + 1.1.1.1 fallback) на Windows/darwin;
	// на Linux в legacy-режиме resolv.conf НЕ трогаем вовсе — до split-DNS
	// интеграции Linux хостовый DNS не менял, и перезапись единственным Yandex
	// молча лишала хост failover'а (INT-L2). Решение о наборе DNS вынесено в
	// чистую tunDNSPlan — инвариант закреплён тестами.
	splitActive := t.dnsFwd != nil
	if dnsIPs := tunDNSPlan(splitActive, runtime.GOOS, t.dnsListenIP); dnsIPs == nil {
		slog.Info("legacy-режим: хостовый DNS не трогаем (linux, split-DNS off)")
	} else if err := t.setTUNDNS(device, dnsIPs...); err != nil {
		if splitActive {
			// INT-M3: честный лог — forwarder слушает, но TUN на него не
			// указывает; запросы уйдут мимо арбитража (лечение цензуры мертво).
			slog.Error("split-DNS активен, но TUN DNS не установлен — арбитраж не работает, запросы пойдут мимо forwarder",
				"err", err)
		} else {
			slog.Warn("не удалось установить DNS на TUN (legacy)", "err", err)
		}
	}

	t.started = true
	success = true // ownership transfers to Tunnel; Stop() now releases resources
	slog.Info("TUN-туннель запущен", "device", device, "proxy", t.socksAddr)
	return nil
}

// stopForwarderAndWatcher releases the split-DNS forwarder and the NIC watcher
// — the teardown steps shared by Stop and rollbackStart (single canonical
// order so the two paths never drift): forwarder first, so we stop answering
// DNS before anything underneath it changes, then the watcher. Must be called
// under t.mu. Idempotent and nil-safe: both resources are nil'd after release,
// so a second call is a no-op and the channel is never double-closed; the
// watcher goroutine holds its own by-value copy of the channel and exits on
// the close regardless of the field being nil'd here.
func (t *Tunnel) stopForwarderAndWatcher() {
	if t.dnsFwd != nil {
		if err := t.dnsFwd.Stop(); err != nil {
			slog.Warn("split-DNS forwarder не остановлен чисто", "err", err)
		}
		t.dnsFwd = nil
	}
	if t.nicWatcherStop != nil {
		close(t.nicWatcherStop)
		t.nicWatcherStop = nil
	}
}

// cleanupRoutesFn is an indirection over cleanupRoutes so tests can observe
// the teardown decision ("routes attempted ⇒ cleanup invoked") without
// exec'ing real `route delete` commands on the host.
var cleanupRoutesFn = cleanupRoutes

// rollbackStart tears down any resources a partial Start() brought up:
// forwarder first, then NIC watcher, routes, and the engine last. It is
// the single teardown point shared by every error path of Start (via the
// deferred guard) — covering the split-DNS forwarder leak (goroutine +
// occupied :53), the NIC-watcher goroutine leak, escape-route pollution of the
// OS routing table, and the running tun2socks engine in one place.
//
// Idempotent and nil-safe: each step is guarded so a path that never created a
// given resource is a no-op, and calling it twice does not panic (channels are
// nil'd after close, pointers after Stop, flags cleared after consumption,
// engine.Stop is itself idempotent). DNS (linux resolv.conf, darwin
// networksetup) is untouched — setTUNDNS is the LAST Start step (no failure
// path can run after it), so on a failed Start it has not run yet; its
// restore belongs to Stop.
func (t *Tunnel) rollbackStart() {
	// 1+2. Split-DNS forwarder, then NIC watcher — shared with Stop.
	t.stopForwarderAndWatcher()

	// 3. Routes — only when Start reached setupRoutes (routesDirty). A partial
	//    setupRoutes failure leaves the /32 server escapes, /32 Yandex DNS
	//    escapes and the /16 CIDR sweep installed via the PHYSICAL gateway;
	//    they are NOT torn down with the engine and would silently bypass any
	//    future VPN until reboot (on Linux the persistent tun0 from
	//    createTUNLinux lingers too — cleanupRoutes deletes it). cleanupRoutes
	//    is idempotent and best-effort. On Linux this may delete tun0 while the
	//    engine still holds its fd — kernel-safe (the device dies with the fd)
	//    and mirrors Stop's historical order.
	if t.routesDirty {
		t.routesDirty = false
		if err := cleanupRoutesFn(tunDeviceName(), t.serverIPs); err != nil {
			slog.Warn("rollback: не удалось убрать маршруты", "err", err)
		}
	}

	// 4. tun2socks engine — idempotent (engine.stop nil-checks device/stack).
	engine.Stop()
}

// Stop останавливает tun2socks и убирает маршруты.
func (t *Tunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.started {
		return nil
	}

	// Останавливаем split-DNS forwarder (ДО engine.Stop — перестаём отвечать
	// на DNS прежде, чем рушим туннель: CF DoH-ветка идёт через него) и
	// сигнализируем NIC watcher'у завершиться. Общий с rollbackStart helper —
	// идемпотентно под mu (повторный Stop short-circuit'ит на !t.started выше).
	t.stopForwarderAndWatcher()

	device := tunDeviceName()

	t.routesDirty = false
	if err := cleanupRoutesFn(device, t.serverIPs); err != nil {
		slog.Warn("не удалось убрать маршруты", "err", err)
	}

	engine.Stop()

	// Linux: восстанавливаем оригинальный /etc/resolv.conf (симлинк или
	// regular-файл), если мы его перезаписывали в Start. Без этого хост остаётся
	// с forwarder-nameserver'ом (напр. 198.18.0.1), недоступным вне туннеля →
	// нет резолвинга после отключения VPN. Best-effort, no-op на не-linux и
	// когда resolv.conf не трогали. Windows TUN DNS снимается вместе с
	// интерфейсом — не дублируем здесь.
	t.restoreResolvConfLinux()

	// Darwin: восстанавливаем DNS физических сервисов (Wi-Fi/Ethernet/...),
	// которые setTUNDNS переписал на forwarder/legacy значения. INT-M2: Tunnel
	// владеет своими изменениями и не зависит от LeakGuard.Disable() (lg может
	// быть nil или его бэкап мог не сняться). ВАЖНО: при lg != nil наш бэкап
	// хранит LOCK-значения PreLock'а (1.1.1.1/8.8.8.8), а не пользовательские —
	// main.go вызывает tun.Stop() ПЕРЕД lg.Disable(), чтобы restore истинных
	// оригиналов LeakGuard'ом лёг ПОСЛЕДНИМ (см. doc darwinDNSBackup).
	t.restoreDarwinDNS()

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
//
// stop — dedicated stop channel captured by value (same pattern as
// dnsproxy.Forwarder.runBranchLog): Stop/rollbackStart do
// `close(ch); t.nicWatcherStop = nil` under mu, and re-reading the field here
// would both race with that write and, once nil'd, block this select forever
// on a nil-channel receive — leaking the goroutine to keep exec'ing
// getDefaultGateway every 30s and overwrite tunsdialer.DefaultDialer after
// tunnel stop (clobbering a subsequent Start's state).
func (t *Tunnel) runNICWatcher(initialIdx int, stop chan struct{}) {
	currentIdx := initialIdx
	ticker := time.NewTicker(nicWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
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
			// Помимо bypass-диалера (выше) дёргаем WS-пул: его слоты держат TCP со
			// СТАРОГО адреса и без этого зависли бы до TCP-таймаута (P0, см.
			// WSPoolTransport.NetworkChanged). Вызов синхронный, но метод не
			// блокирует (teardown best-effort, реконнекты уходят в горутины) —
			// 30-секундный цикл вотчера он не задерживает.
			if t.onNetworkChange != nil {
				t.onNetworkChange()
			}
		}
	}
}

// installBypassDialer loads the RU CIDR trie and installs a BypassDialer as the
// active tun2socks dialer. Must be called after engine.Start() (tun2socks
// publishes its tunnel singleton during Start) and before setupRoutes so
// the dialer is in place before any packets flow through the TUN.
func (t *Tunnel) installBypassDialer() error {
	// Load the RU CIDR snapshot once into t.resolved and reuse it on any
	// subsequent call. The same snapshot is later handed to the split-DNS
	// Forwarder (Start) — one snapshot = one source of truth shared with the
	// BypassDialer (see the resolved field doc).
	if t.resolved == nil {
		r, err := bypassroute.Load(bypassroute.Source{
			Embedded: true,
			Override: t.bypassOverride,
		})
		if err != nil {
			return fmt.Errorf("load bypass trie: %w", err)
		}
		t.resolved = r
	}
	resolved := t.resolved
	// Inner (tunnel-bound) dialer: in-process when available (Bug #5 — no
	// loopback socket per flow → no Windows ephemeral port exhaustion),
	// otherwise the legacy loopback SOCKS5 dialer.
	var inner proxy.Dialer
	if t.inProcessDialer != nil {
		inner = t.inProcessDialer
		slog.Info("in-process dialer активирован (без loopback SOCKS5 на data-path)")
	} else {
		socks, err := proxy.NewSocks5(t.socksAddr, t.proxyUser, t.proxyPass)
		if err != nil {
			return fmt.Errorf("build socks5 dialer: %w", err)
		}
		inner = socks
	}
	bypass := bypassroute.NewBypassDialer(inner, resolved).
		WithMetrics(client.Stats.IncBypassMatch, client.Stats.IncBypassMiss)
	t2tunnel.T().SetDialer(bypass)
	slog.Info("bypass routing активирован",
		"include", resolved.Size(),
		"exclude", resolved.Excludes())
	return nil
}

// splitDNSCandidates — адреса listener'а для split-DNS forwarder, в порядке
// предпочтения. Сначала TUN gateway (198.18.0.1) — DNS-пакеты тогда видны как
// «к шлюзу TUN», естественно для split-режима; при ошибке bind — loopback.
var splitDNSCandidates = []struct{ ip, addr string }{
	{"198.18.0.1", "198.18.0.1:53"},
	{"127.0.0.1", "127.0.0.1:53"},
}

// splitDNSBindRetryDelay — пауза между попытками bind на TUN-gateway-адрес,
// пока Windows регистрирует только что назначенный (assignTUNAddrWindows) IP в
// IP-стеке. Это и есть шаг condition-based-waiting: каждая пауза — между двумя
// реальными bind-пробами, а сам успешный bind является условием готовности
// адреса (не угаданный фиксированный sleep).
const splitDNSBindRetryDelay = 500 * time.Millisecond

// splitDNSBindAttempts возвращает число попыток bind для listener-адреса. TUN
// gateway (tunStaticAddr) получает много попыток: на Windows адрес после netsh
// set address регистрируется в IP-стеке АСИНХРОННО и дольше прежнего окна (~до
// нескольких секунд — поле подтвердило, что ~через минуту bind на 198.18.0.1:53
// проходит, но первые секунды падают с "address is not valid in its context").
// 20 попыток × 500мс = окно ожидания до ~10с (поллинг с дедлайном) — этого
// заведомо достаточно для регистрации адреса, и Start блокируется не дольше ~10с
// в худшем (аномальном) случае. Loopback и любой другой адрес — 1 попытка (он
// доступен сразу, ретраить нечего; loopback — крайний деградационный fallback).
// Чистая функция (без сна/exec) — число попыток unit-тестируемо.
func splitDNSBindAttempts(ip string) int {
	if ip == tunStaticAddr {
		return 20
	}
	return 1
}

// startSplitDNS создаёт и запускает dnsproxy.Forwarder, перебирая listener-адреса
// (TUN gateway → loopback) до первого успешного Start. Возвращает запущенный
// forwarder и его listen-IP (без порта), либо (nil, "") если ни один адрес не
// поднялся. Выбран вариант «пере-Start» (а не TOCTOU-проба net.ListenPacket с
// последующим закрытием): forwarder сам биндит сокет в Start, поэтому реальный
// bind на этом же адресе — единственный достоверный сигнал доступности, без окна
// гонки между пробой и фактическим биндом.
//
// Condition-based-waiting: для TUN-gateway-кандидата (tunStaticAddr) bind
// поллится до фактического успеха (splitDNSBindAttempts попыток × паузу
// splitDNSBindRetryDelay = окно до ~10с). На Windows адрес после netsh set address
// регистрируется в IP-стеке АСИНХРОННО — первые попытки падают с "address is not
// valid in its context", пока адрес не появился. Условие готовности = успешный
// bind (он атомарно проверяет «адрес есть И порт свободен»), поэтому мы не спим
// фиксированный таймаут и не парсим netsh show addresses — просто ретраим реальный
// bind. Как только проходит — возвращаемся на 198.18.0.1 (INFO). Если за всё окно
// (~10с) адрес так и не зарегистрировался (аномалия окружения) — переходим к
// loopback-кандидату (1 попытка) как крайнему деградационному fallback с WARN.
//
// bootstrapDomains — INT-H2 (2026-06-12): серверные домены для bootstrap-
// whitelist forwarder'а (Yandex-only fallback при недоступном CF); пустой
// список не меняет поведение forwarder'а.
func startSplitDNS(snapshot *bypassroute.Resolved, bootstrapDomains []string) (*dnsproxy.Forwarder, string) {
	for _, c := range splitDNSCandidates {
		attempts := splitDNSBindAttempts(c.ip)
		for attempt := 1; attempt <= attempts; attempt++ {
			fwd := dnsproxy.NewForwarder(c.addr, snapshot,
				dnsproxy.WithBootstrapDomains(bootstrapDomains...))
			if err := fwd.Start(); err != nil {
				_ = fwd.Stop() // оборонительный идемпотентный no-op: при fail Start сервер не присвоен, освобождать нечего
				if attempt < attempts {
					// Промежуточные попытки — Debug (адрес ещё регистрируется
					// Windows-стеком); не спамим INFO на ~20 строк за старт.
					slog.Debug("split-DNS bind не удался, ждём регистрации адреса",
						"addr", c.addr, "attempt", attempt, "of", attempts, "err", err)
					time.Sleep(splitDNSBindRetryDelay)
					continue
				}
				slog.Warn("split-DNS bind не удался за всё окно ожидания, пробуем следующий адрес",
					"addr", c.addr, "attempts", attempts, "err", err)
				break // следующий кандидат
			}
			// Итог. Успех на TUN gateway — норма (INFO). Успех на loopback —
			// деградация: Windows DNS Client (Dnscache, им ходит браузер) ненадёжно
			// резолвит через loopback-iface-DNS → может пойти мимо forwarder'а
			// (РКН-заглушка). Логируем явный WARN, чтобы деградация была видна.
			if c.ip == tunStaticAddr {
				slog.Info("split-DNS forwarder bind на TUN gateway", "addr", c.addr, "attempt", attempt)
			} else {
				slog.Warn("split-DNS на loopback — Windows DNS Client может резолвить мимо forwarder; ожидался "+tunStaticAddr,
					"addr", c.addr)
			}
			return fwd, c.ip
		}
	}
	return nil, ""
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

// tunStaticAddr — статический IPv4-адрес самого TUN-интерфейса (он же gateway-хак
// split-маршрутов и предпочтительный listen-IP split-DNS forwarder'а). На Linux
// он назначается с маской /15 в createTUNLinux; на Windows — с /24 (достаточно
// для адреса интерфейса, 198.18.0.1 остаётся on-link для route add ... 198.18.0.1).
const tunStaticAddr = "198.18.0.1"

// buildWindowsSetTUNAddrCommand строит argv для назначения статического IPv4
// на Windows TUN-интерфейс через netsh. Используется форма `set address ...
// static <ip> <mask>` (без gateway) — set заменяет конфигурацию (надёжнее, чем
// add address поверх APIPA), а отсутствие gateway корректно для on-link
// gateway-хака split-маршрутов. Чистая (без exec) — argv unit-тестируем.
func buildWindowsSetTUNAddrCommand(tunName string) []string {
	return []string{"netsh", "interface", "ip", "set", "address",
		"name=" + tunName, "static", tunStaticAddr, "255.255.255.0"}
}

// assignTUNAddrWindows назначает статический IP tunStaticAddr/24 на TUN-интерфейс
// Windows через netsh (см. buildWindowsSetTUNAddrCommand). Wintun сам адрес не
// назначает, поэтому без этого интерфейс остаётся с APIPA. Best-effort на уровне
// вызова (Start логирует Warn и продолжает), но саму ошибку netsh пробрасываем
// наверх для лога. Требует админ-прав (клиент запускается от админа).
func assignTUNAddrWindows(device string) error {
	tunName := strings.TrimPrefix(device, "tun://")
	cmd := buildWindowsSetTUNAddrCommand(tunName)
	out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set address %s: %w (%s)", tunName, err, strings.TrimSpace(string(out)))
	}
	return nil
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

// yandexDNSIPs — Yandex DNS resolver'ы, которым нужен прямой /32 escape через
// физический шлюз (см. setupRoutes §1a).
//
// N2 (2026-06-11): выводится из ЕДИНОГО источника истины dnsproxy.DefaultYandexIPs()
// — те же bare IP, что dnsproxy навешивает порт и использует как plain-UDP
// резолверы. Раньше это были два независимых литерала, связанные только
// комментарием: добавление третьего Yandex-резолвера в dnsproxy молча не дало бы
// ему escape-маршрут → его UDP-пакеты утянулись бы split-маршрутами обратно в TUN
// и зациклились. Теперь источник один. legacy static DNS в setTUNDNS (Start) тоже
// должен совпадать — сторожится TestYandexDNSIPs_MatchResolvers.
var yandexDNSIPs = dnsproxy.DefaultYandexIPs()

// escapePlan — полный набор адресов/сетей, которые setupRoutes выводит из TUN
// через физический шлюз. Всё, чего здесь НЕТ, попадает под split-маршруты
// 0/1+128/1 и уходит в туннель.
//
// Вынесено в чистую функцию (buildEscapePlan) ровно по той же причине, что и
// buildWindowsSetDNSCommands: escape-список — это политика безопасности, а не
// деталь исполнения, и она должна быть проверяема без exec/админских прав.
// Пустой escape для DoH-IP — не отсутствие настройки, а сама защита; сторож
// TestDoHServerIP_HasNoEscapeRoute держит этот инвариант.
type escapePlan struct {
	Hosts []string // /32 (или /128) escape через физ. шлюз
	CIDRs []string // /16 sweep, только в CDN-режиме (без origin-pin)
}

// buildEscapePlan строит escape-план. Чистая: без exec, без сети, без gateway.
// narrowEscape=true (URL содержит ?origin=) выключает /16 sweep.
func buildEscapePlan(serverIPs []string, narrowEscape bool) escapePlan {
	plan := escapePlan{}
	plan.Hosts = append(plan.Hosts, serverIPs...)
	plan.Hosts = append(plan.Hosts, yandexDNSIPs...)

	if narrowEscape {
		return plan
	}
	added := make(map[string]bool)
	for _, ip := range serverIPs {
		parts := strings.SplitN(ip, ".", 4)
		if len(parts) != 4 {
			continue
		}
		cidr := parts[0] + "." + parts[1] + ".0.0"
		if !added[cidr] {
			added[cidr] = true
			plan.CIDRs = append(plan.CIDRs, cidr)
		}
	}
	return plan
}

// setupRoutes настраивает split-routing для системного VPN.
// Сначала добавляет escape-маршруты для каждого IP VPN-сервера через реальный шлюз,
// затем один раз добавляет split-маршруты (0.0.0.0/1 + 128.0.0.0/1) через TUN.
func setupRoutes(device string, serverIPs []string, narrowEscape bool) error {
	gw, err := getDefaultGateway()
	if err != nil {
		return fmt.Errorf("определение шлюза: %w", err)
	}

	// План escape-маршрутов (чистая функция — сторожится в tunnel_routes_test.go).
	// 1/1a. /32 для каждого IP сервера и для Yandex DNS (77.88.8.8 / 77.88.8.1).
	// Yandex — БЕЗУСЛОВНО (не зависит от split-DNS): он резолвится напрямую в
	// обоих режимах. С forwarder'ом: тот шлёт Yandex plain-UDP DIRECT — без
	// escape split-маршруты 0/1+128/1 утянули бы эти UDP-пакеты обратно в TUN
	// и зациклили. Без forwarder'а (legacy): TUN DNS = Yandex напрямую — те же
	// пакеты тоже должны идти мимо TUN.
	plan := buildEscapePlan(serverIPs, narrowEscape)
	for _, ip := range plan.Hosts {
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
	// (every neighbour on the same /16) and exempts them from the TUN — including,
	// if a server IP ever landed in 1.1.0.0/16, the pinned DoH resolver itself.
	// In CDN mode (no origin pin) the /16 sweep is correct and kept.
	if len(plan.CIDRs) > 0 {
		for _, cidr := range plan.CIDRs {
			if err := addEscapeRouteCIDR(cidr, "255.255.0.0", gw); err != nil {
				slog.Warn("escape CIDR route не добавлен", "cidr", cidr+"/16", "err", err)
			} else {
				slog.Info("escape CIDR route добавлен", "cidr", cidr+"/16")
			}
		}
	} else if narrowEscape {
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
		// DNS на TUN вынесен в setTUNDNS (кроссплатформенно, variadic) —
		// вызывается из Start после старта split-DNS forwarder. Здесь только
		// split-маршруты через TUN-интерфейс.

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

// tunDNSPlan is the PURE decision of which DNS list setTUNDNS must receive.
// Returns nil when the platform must not be touched at all in this mode.
//
//   - split-DNS ON  → exactly [dnsListenIP] on every platform (the forwarder is
//     the sole resolver; arbitration happens behind it).
//   - split-DNS OFF, linux → nil: before the split-DNS integration Linux never
//     touched the host resolv.conf — overwriting it with a single Yandex
//     resolver silently dropped failover and widened the INT-H3 blast radius
//     in a mode where the feature is off (INT-L2). Keep hands off.
//   - split-DNS OFF, windows/darwin → the historical Yandex-primary +
//     Cloudflare-fallback triple, derived from the same single source of truth
//     as the escape routes (yandexDNSIPs, invariant N2).
func tunDNSPlan(splitDNSActive bool, goos, dnsListenIP string) []string {
	if splitDNSActive {
		return []string{dnsListenIP}
	}
	if goos == "linux" {
		return nil
	}
	return append(append([]string{}, yandexDNSIPs...), "1.1.1.1")
}

// execTUNDNSCmd is the exec seam for the DNS-related platform commands (netsh /
// ipconfig on Windows, networksetup on darwin). argv[0] is the binary. Tests
// stub it to drive the full backup→set→restore cycle without touching the host.
var execTUNDNSCmd = func(argv []string) (string, error) {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	return string(out), err
}

// setTUNDNS sets dnsIPs as the DNS resolvers on the TUN interface, cross-platform.
// The first IP is the primary (set static / sole nameserver); the rest are added
// as ordered secondaries (Windows index=2,3,…). Callers decide the dnsIPs set via
// tunDNSPlan (split-DNS ON → sole forwarder IP; OFF → legacy triple, linux skipped).
//
// On Windows it also re-applies the TUN interface metric=1 and flushes the DNS
// cache (both previously inlined in addSplitRoutes). The PRIMARY `set dns` step
// failure is returned as an error (INT-M3) — without it the forwarder listens
// uselessly; secondary/metric steps stay best-effort.
//
// On Linux the original /etc/resolv.conf is backed up into the Tunnel before the
// first overwrite (see backupResolvConf) so Stop can restore it — otherwise the
// host is left pointing at the forwarder nameserver, which is unreachable once
// the tunnel is down. On darwin the per-service DNS is symmetrically backed up
// into the Tunnel before networksetup rewrites it (INT-M2). This is a *method*
// (not a free func) for that reason: the linux/darwin branches record backup
// state on the receiver.
func (t *Tunnel) setTUNDNS(device string, dnsIPs ...string) error {
	if len(dnsIPs) == 0 {
		return fmt.Errorf("setTUNDNS: пустой список DNS")
	}
	switch runtime.GOOS {
	case "windows":
		tunName := strings.TrimPrefix(device, "tun://")
		if err := setWindowsTUNDNS(tunName, dnsIPs); err != nil {
			return err
		}
		slog.Info("DNS настроен на TUN", "dns", dnsIPs, "metric", 1)
		return nil

	case "linux":
		// Перезаписываем /etc/resolv.conf нашими nameserver-строками (ВСЕ
		// переданные IP) с маркером владения первой строкой — это единственное
		// место, где мы трогаем хостовый resolv.conf на Linux. ПЕРЕД записью
		// сохраняем оригинал (regular-файл или systemd-resolved симлинк) в поля
		// Tunnel — Stop восстановит, иначе хост останется с nameserver'ом
		// forwarder'а (напр. 198.18.0.1), недоступным вне туннеля.
		t.writeResolvConf(dnsIPs)
		return nil

	case "darwin":
		// networksetup требует имя network service, не device. Сервисы
		// перечисляем через -listallnetworkservices (как LeakGuard), а не
		// hardcoded пару Wi-Fi/Ethernet; текущий DNS каждого сервиса бэкапится
		// в Tunnel и восстанавливается в Stop (INT-M2).
		if t.setDarwinDNS(dnsIPs) {
			slog.Info("DNS настроен на TUN (networksetup, с бэкапом)", "dns", dnsIPs)
		} else {
			slog.Warn("darwin DNS: не применён ни к одному сервису — TUN без forwarder DNS", "dns", dnsIPs)
		}
		return nil

	default:
		return fmt.Errorf("setTUNDNS: неподдерживаемая платформа: %s", runtime.GOOS)
	}
}

// setWindowsTUNDNS runs the netsh command sequence pinning dnsIPs onto the TUN.
// Platform-independent core (exec goes through the seam) so the error contract
// is testable everywhere. Step 0 — the primary `set dns ... static <ip>` — is
// load-bearing: if it fails (corp policy, stopped DNS Client service, iface
// recreation race) the TUN keeps no/old DNS and the split-DNS forwarder is
// bypassed entirely, so its error is RETURNED (INT-M3). The remaining steps
// (secondary resolvers, metric, flushdns) stay best-effort Warn.
func setWindowsTUNDNS(tunName string, dnsIPs []string) error {
	for i, cmd := range buildWindowsSetDNSCommands(tunName, dnsIPs) {
		out, err := execTUNDNSCmd(cmd)
		if err != nil {
			if i == 0 {
				return fmt.Errorf("netsh set dns (primary) не выполнен: %w (%s)",
					err, strings.TrimSpace(out))
			}
			slog.Warn("netsh set dns шаг не выполнен",
				"step", i, "args", strings.Join(cmd, " "),
				"err", err, "output", strings.TrimSpace(out))
		}
	}
	_, _ = execTUNDNSCmd([]string{"ipconfig", "/flushdns"})
	return nil
}

// ---------- darwin DNS ownership (INT-M2) ----------

// parseDarwinNetworkServices extracts service names from `networksetup
// -listallnetworkservices` output: the header line is skipped, and services
// disabled by hardware (prefixed with *) are skipped — we must not enable-by-
// side-effect or restore DNS onto a service the user turned off.
func parseDarwinNetworkServices(out string) []string {
	var services []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services
}

// parseDarwinDNSServers parses `networksetup -getdnsservers <svc>` output.
// The "There aren't any DNS Servers set" sentinel means automatic/DHCP →
// nil (restored later via the "Empty" keyword).
func parseDarwinDNSServers(out string) []string {
	text := strings.TrimSpace(out)
	if strings.Contains(text, "There aren't any") {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(text, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			servers = append(servers, s)
		}
	}
	return servers
}

// buildDarwinSetDNSArgs builds the networksetup argv that applies `servers`
// to a service; empty servers → the "Empty" keyword (back to automatic/DHCP).
// Pure (no exec) — argv unit-tested.
func buildDarwinSetDNSArgs(service string, servers []string) []string {
	if len(servers) == 0 {
		return []string{"networksetup", "-setdnsservers", service, "Empty"}
	}
	return append([]string{"networksetup", "-setdnsservers", service}, servers...)
}

// setDarwinDNS enumerates the enabled network services, backs up each one's
// current DNS into t.darwinDNSBackup, then applies dnsIPs. Ownership rules:
//   - enumeration failed → change NOTHING (we cannot restore what we cannot list);
//   - per-service backup failed → skip SETTING that service (never change what
//     we cannot restore).
//
// Best-effort beyond that: set failures are logged, not fatal (matches the
// historical darwin behaviour). Restore lives in restoreDarwinDNSState (Stop).
//
// Returns true when dnsIPs were applied to at least one service — the caller
// must not log success otherwise (recheck NIT: «DNS настроен» on an
// enumeration failure was a lie).
func (t *Tunnel) setDarwinDNS(dnsIPs []string) bool {
	out, err := execTUNDNSCmd([]string{"networksetup", "-listallnetworkservices"})
	if err != nil {
		slog.Warn("darwin DNS: -listallnetworkservices не удался — DNS сервисов не трогаем (нечего будет восстанавливать)",
			"err", err)
		return false
	}
	services := parseDarwinNetworkServices(out)
	if len(services) == 0 {
		slog.Warn("darwin DNS: список network services пуст — DNS не трогаем")
		return false
	}
	applied := false
	for _, svc := range services {
		if !t.darwinHasDNSBackup(svc) {
			gout, gerr := execTUNDNSCmd([]string{"networksetup", "-getdnsservers", svc})
			if gerr != nil {
				slog.Warn("darwin DNS: бэкап DNS сервиса не снят — сервис пропущен (не меняем то, что не восстановим)",
					"service", svc, "err", gerr)
				continue
			}
			t.darwinDNSBackup = append(t.darwinDNSBackup, darwinDNSEntry{
				service: svc,
				servers: parseDarwinDNSServers(gout),
			})
			t.darwinDNSTouched = true
		}
		if sout, serr := execTUNDNSCmd(buildDarwinSetDNSArgs(svc, dnsIPs)); serr != nil {
			slog.Warn("darwin DNS: setdnsservers не удался",
				"service", svc, "err", serr, "output", strings.TrimSpace(sout))
		} else {
			applied = true
		}
	}
	return applied
}

// darwinHasDNSBackup reports whether a backup entry for svc already exists.
func (t *Tunnel) darwinHasDNSBackup(svc string) bool {
	for _, e := range t.darwinDNSBackup {
		if e.service == svc {
			return true
		}
	}
	return false
}

// restoreDarwinDNS is the GOOS-gated Stop entry point for restoreDarwinDNSState.
func (t *Tunnel) restoreDarwinDNS() {
	if runtime.GOOS != "darwin" {
		return
	}
	t.restoreDarwinDNSState()
}

// restoreDarwinDNSState reverts every service's DNS to its backed-up value
// ("Empty" for services that were on automatic/DHCP). Platform-independent
// core (exec seam) so the cycle is testable everywhere. Best-effort: failures
// are logged, never fatal. Clears the backup state afterwards so a second Stop
// is a no-op. Когда lg.PreLock выполнялся, бэкап хранит LOCK-значения
// LeakGuard'а (см. doc darwinDNSBackup) — поэтому в main.go tun.Stop() обязан
// идти ПЕРЕД lg.Disable(): restore истинных оригиналов LeakGuard'ом ложится
// ПОВЕРХ нашего. Смысл метода — Tunnel не ЗАВИСИТ от lg != nil: при lg==nil
// бэкап и есть истинные пользовательские значения.
func (t *Tunnel) restoreDarwinDNSState() {
	if !t.darwinDNSTouched {
		return
	}
	defer func() {
		t.darwinDNSTouched = false
		t.darwinDNSBackup = nil
	}()
	for _, e := range t.darwinDNSBackup {
		if out, err := execTUNDNSCmd(buildDarwinSetDNSArgs(e.service, e.servers)); err != nil {
			slog.Warn("darwin DNS: restore setdnsservers не удался",
				"service", e.service, "err", err, "output", strings.TrimSpace(out))
		}
	}
	slog.Info("darwin DNS восстановлен из бэкапа Tunnel", "services", len(t.darwinDNSBackup))
}

// ---------- linux resolv.conf ownership (INT-H3) ----------

// resolvConfPath is a package var (not const) so the backup/restore state
// machine is testable against a tempdir on any platform (INT-L3a).
var resolvConfPath = "/etc/resolv.conf"

// systemdStubResolvConf is the conventional systemd-resolved stub that
// /etc/resolv.conf symlinks to on most modern distros. Used by the no-backup
// restore branch to recover a sane host resolver. Package var for tests.
var systemdStubResolvConf = "/run/systemd/resolve/stub-resolv.conf"

// resolvConfMarker is the ownership marker written as the FIRST line of every
// resolv.conf we create. INT-H3: without it, a session started after a crash
// (SIGKILL/panic — Stop never ran) would Lstat a regular file containing our
// forwarder IP, back it up as the "original", and Stop would then "restore"
// the poison — breaking host DNS permanently and re-poisoning every later
// Start/Stop cycle. With the marker, backupResolvConf recognizes our own
// leftover and refuses to treat it as the original.
const resolvConfMarker = "# nixavpn-managed"

// buildResolvConfContent renders the resolv.conf we own: the marker line, then
// one nameserver line per IP (ALL entries, not just the primary — INT-L2).
func buildResolvConfContent(dnsIPs []string) string {
	var b strings.Builder
	b.WriteString(resolvConfMarker + "\n")
	for _, ip := range dnsIPs {
		b.WriteString("nameserver " + ip + "\n")
	}
	return b.String()
}

// isNixaManagedResolvConf reports whether data is a resolv.conf WE wrote
// (carries the ownership marker as its first line).
func isNixaManagedResolvConf(data []byte) bool {
	return strings.HasPrefix(string(data), resolvConfMarker)
}

// writeResolvConf backs up the current resolv.conf (first call only) and
// replaces it with our marker + nameserver lines. Platform-independent core
// of the setTUNDNS linux branch (testable everywhere via resolvConfPath).
//
// Recheck HIGH: resolv.conf is REMOVED before the write. open(2) follows
// symlinks — on a systemd-resolved host (/etc/resolv.conf →
// /run/systemd/resolve/stub-resolv.conf) a plain os.WriteFile would overwrite
// the STUB FILE ITSELF with our forwarder IP, and restore would then recreate
// the symlink pointing at the poisoned stub → host DNS broken after Stop.
// Remove-then-write replaces the symlink with our regular file; the target
// stays untouched, and restoreResolvConf recreates the symlink from backup.
func (t *Tunnel) writeResolvConf(dnsIPs []string) {
	t.backupResolvConf()
	if err := os.Remove(resolvConfPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("не удалось удалить resolv.conf перед записью", "path", resolvConfPath, "err", err)
	}
	content := buildResolvConfContent(dnsIPs)
	if err := os.WriteFile(resolvConfPath, []byte(content), 0644); err != nil {
		slog.Warn("не удалось записать resolv.conf", "path", resolvConfPath, "err", err)
		return // best-effort, не fatal
	}
	slog.Info("DNS настроен на TUN (resolv.conf)", "dns", dnsIPs)
}

// backupResolvConf captures the current resolv.conf state the first time it is
// called per Tunnel, before we overwrite it. It records either the symlink
// target (systemd-resolved typically symlinks resolv.conf to
// /run/systemd/resolve/stub-resolv.conf) or the regular-file contents. The
// resolvConfTouched flag gates restore in Stop: once set, restoreResolvConf
// will undo our write. Subsequent calls are no-ops (we keep the FIRST, pre-VPN
// state). Best-effort: a backup failure still lets us proceed, but we mark
// touched so restore at least removes our write.
//
// INT-H3: a regular file carrying our ownership marker is a leftover from a
// crashed session (Stop never ran) — it is NOT the original and is NOT backed
// up. The backup stays empty so restore falls to the no-backup recovery branch
// (remove our file, re-point at the systemd stub when present).
func (t *Tunnel) backupResolvConf() {
	if t.resolvConfTouched {
		return
	}
	t.resolvConfTouched = true

	fi, err := os.Lstat(resolvConfPath)
	if err != nil {
		// Файла нет (или не прочесть) — нечего бэкапить. touched уже выставлен;
		// restore тогда просто удалит наш файл, вернув отсутствие resolv.conf.
		slog.Warn("backup resolv.conf: Lstat не удался", "err", err)
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		dest, lerr := os.Readlink(resolvConfPath)
		if lerr != nil {
			slog.Warn("backup resolv.conf: Readlink не удался", "err", lerr)
			return
		}
		t.resolvConfWasSymlink = true
		t.resolvConfSymlinkDest = dest
		slog.Info("resolv.conf backup (symlink)", "target", dest)
		return
	}
	data, rerr := os.ReadFile(resolvConfPath)
	if rerr != nil {
		slog.Warn("backup resolv.conf: ReadFile не удался", "err", rerr)
		return
	}
	if isNixaManagedResolvConf(data) {
		// INT-H3: это НАШ файл, оставшийся от упавшей сессии — не оригинал.
		// Бэкап не снимаем; restore уйдёт в recovery-ветку (удалить + symlink
		// на systemd stub, если он есть).
		slog.Warn("backup resolv.conf: найден наш маркер от предыдущей (упавшей) сессии — НЕ считаем оригиналом")
		return
	}
	t.resolvConfBackup = data
	slog.Info("resolv.conf backup (regular)", "bytes", len(data))
}

// restoreResolvConf reverts the resolv.conf overwrite performed during Start.
// It runs from Stop when resolvConfTouched is set. Best-effort: failures are
// logged at Warn, never fatal. After running it clears the backup state so a
// second Stop is a no-op. Platform-independent core (testable everywhere).
//
// Recovery semantics:
//   - original was a symlink → remove our regular file and recreate the symlink.
//   - original was a regular file → write the saved contents back.
//   - no backup (original absent/unreadable, or it was our own marker file left
//     by a crashed session — INT-H3):
//     -- the current file does NOT carry our marker → someone else rewrote it
//     after us; it is not ours to delete — leave it untouched;
//     -- otherwise remove our file, and if the systemd-resolved stub exists,
//     restore the conventional /etc/resolv.conf → stub symlink (working
//     resolver on systemd-resolved distros); else just remove and Warn
//     (host returns to "no resolv.conf", strictly better than keeping a
//     dead forwarder IP).
func (t *Tunnel) restoreResolvConf() {
	if !t.resolvConfTouched {
		return
	}
	// Сбрасываем состояние в конце вне зависимости от исхода — повторный Stop no-op.
	defer func() {
		t.resolvConfTouched = false
		t.resolvConfWasSymlink = false
		t.resolvConfSymlinkDest = ""
		t.resolvConfBackup = nil
	}()

	switch {
	case t.resolvConfWasSymlink:
		// Удаляем наш regular-файл и пересоздаём оригинальный симлинк.
		if err := os.Remove(resolvConfPath); err != nil && !os.IsNotExist(err) {
			slog.Warn("restore resolv.conf: Remove перед symlink не удался", "err", err)
		}
		if err := os.Symlink(t.resolvConfSymlinkDest, resolvConfPath); err != nil {
			slog.Warn("restore resolv.conf: Symlink не восстановлен",
				"target", t.resolvConfSymlinkDest, "err", err)
			return
		}
		slog.Info("resolv.conf восстановлен (symlink)", "target", t.resolvConfSymlinkDest)
	case t.resolvConfBackup != nil:
		if err := os.WriteFile(resolvConfPath, t.resolvConfBackup, 0644); err != nil {
			slog.Warn("restore resolv.conf: WriteFile оригинала не удался", "err", err)
			return
		}
		slog.Info("resolv.conf восстановлен (regular)", "bytes", len(t.resolvConfBackup))
	default:
		// Бэкап не снят: оригинала не было/не прочёлся ЛИБО там был наш маркер
		// от упавшей сессии (INT-H3). Удаляем только СВОЙ файл (по маркеру) —
		// чужую запись (NetworkManager/пользователь поверх нас) не трогаем.
		data, rerr := os.ReadFile(resolvConfPath)
		if rerr == nil && !isNixaManagedResolvConf(data) {
			slog.Warn("restore resolv.conf: файл перезаписан не нами (нет маркера) — оставляем как есть")
			return
		}
		if err := os.Remove(resolvConfPath); err != nil && !os.IsNotExist(err) {
			slog.Warn("restore resolv.conf: Remove нашего файла не удался", "err", err)
			return
		}
		// Попытка вернуть хосту рабочий резолвер: конвенциональный симлинк на
		// systemd-resolved stub, если он существует.
		if _, serr := os.Stat(systemdStubResolvConf); serr == nil {
			if err := os.Symlink(systemdStubResolvConf, resolvConfPath); err != nil {
				slog.Warn("restore resolv.conf: symlink на systemd stub не создан",
					"target", systemdStubResolvConf, "err", err)
				return
			}
			slog.Info("resolv.conf восстановлен symlink'ом на systemd stub (оригинал неизвестен)",
				"target", systemdStubResolvConf)
			return
		}
		slog.Warn("resolv.conf удалён без восстановления — оригинал неизвестен, systemd stub отсутствует")
	}
}

// restoreResolvConfLinux is the GOOS-gated wrapper called from Stop.
func (t *Tunnel) restoreResolvConfLinux() {
	if runtime.GOOS != "linux" {
		return
	}
	t.restoreResolvConf()
}

// buildWindowsSetDNSCommands builds the ordered netsh command argv list for
// pinning dnsIPs onto tunName: a `set dns ... static <primary>`, then
// `add dns ... <ip> index=N` for each secondary, then `set interface ... metric=1`.
// Pure (no exec) so the argument construction is unit-testable.
func buildWindowsSetDNSCommands(tunName string, dnsIPs []string) [][]string {
	cmds := make([][]string, 0, len(dnsIPs)+1)
	cmds = append(cmds, []string{"netsh", "interface", "ip", "set", "dns", tunName, "static", dnsIPs[0]})
	for i := 1; i < len(dnsIPs); i++ {
		cmds = append(cmds, []string{"netsh", "interface", "ip", "add", "dns",
			tunName, dnsIPs[i], fmt.Sprintf("index=%d", i+1)})
	}
	cmds = append(cmds, []string{"netsh", "interface", "ip", "set", "interface", tunName, "metric=1"})
	return cmds
}

// cleanupRoutes удаляет маршруты, добавленные в setupRoutes.
func cleanupRoutes(device string, serverIPs []string) error {
	gw, err := getDefaultGateway()
	if err != nil {
		slog.Warn("не удалось определить шлюз при очистке маршрутов", "err", err)
		gw = ""
	}

	// 1. Удаляем escape-маршруты (серверные + Yandex DNS — симметрично setupRoutes).
	for _, ip := range serverIPs {
		removeEscapeRoute(ip, gw)
	}
	for _, ip := range yandexDNSIPs {
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

// winDefaultRoute is one parsed `0.0.0.0/0` entry from `route print`: the
// gateway IP and the interface IP that owns the route. Windows lists one such
// row per active default route — with a second VPN/tunnel up (sing-tun,
// WireGuard, …) there are several, and the lowest-metric one (listed first)
// is frequently the tunnel, not the physical NIC.
type winDefaultRoute struct {
	gateway string // 3-я колонка "Адрес шлюза"
	ifaceIP string // 4-я колонка "Интерфейс" (IP интерфейса, через который идёт маршрут)
}

// getDefaultGatewayWindows возвращает шлюз ФИЗИЧЕСКОГО default-маршрута.
//
// Раньше бралась первая строка `0.0.0.0/0` (лучшая метрика). При параллельно
// поднятом стороннем туннеле (sing-tun/WireGuard) его маршрут идёт с метрикой 0
// и побеждал — bypass-дилер садился на чужой туннель, и весь direct-трафик
// (RU-сайты мимо нашего VPN) уходил в тупик → ERR_CONNECTION_RESET. Теперь мы
// разбираем ВСЕ default-маршруты и выбираем тот, чей интерфейс физический
// (его IP не принадлежит виртуальному адаптеру). Туннельные маршруты
// отбрасываются.
func getDefaultGatewayWindows() (string, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", fmt.Errorf("route print 0.0.0.0: %w", err)
	}
	routes := parseWindowsDefaultRoutes(string(out))
	if len(routes) == 0 {
		return "", fmt.Errorf("шлюз не найден в выводе route print")
	}
	return pickPhysicalGateway(routes, ifaceNameForIP), nil
}

// parseWindowsDefaultRoutes извлекает все строки default-маршрута
// ("0.0.0.0  0.0.0.0  <gateway>  <iface-ip>  <metric>") из вывода
// `route print`. Чистая функция — тестируется без сети. Строка On-link
// (half-default нашего TUN: "0.0.0.0 128.0.0.0 On-link …") сюда не попадает:
// маска не 0.0.0.0.
func parseWindowsDefaultRoutes(routeOutput string) []winDefaultRoute {
	var routes []winDefaultRoute
	for _, line := range strings.Split(routeOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			routes = append(routes, winDefaultRoute{gateway: fields[2], ifaceIP: fields[3]})
		}
	}
	return routes
}

// pickPhysicalGateway выбирает шлюз маршрута, чей интерфейс физический.
// nameForIP мапит IP интерфейса в имя адаптера (в проде — ifaceNameForIP, в
// тестах — синтетическая мапа). Если имя интерфейса определить нельзя
// (адаптер не найден) — маршрут считается кандидатом, но уступает явно
// физическому. Если все кандидаты виртуальные ИЛИ имя ни для кого не
// определилось — возвращаем шлюз первого маршрута (graceful fallback,
// прежнее поведение).
func pickPhysicalGateway(routes []winDefaultRoute, nameForIP func(string) string) string {
	var firstUnknown string
	for _, r := range routes {
		name := nameForIP(r.ifaceIP)
		if name != "" && !isVirtualIface(name) {
			return r.gateway // физический интерфейс — берём сразу
		}
		if name == "" && firstUnknown == "" {
			firstUnknown = r.gateway // интерфейс не опознан — запасной вариант
		}
	}
	if firstUnknown != "" {
		return firstUnknown
	}
	return routes[0].gateway
}

// ifaceNameForIP возвращает имя up-интерфейса, которому назначен данный IP,
// либо "" если такого нет. Используется для классификации default-маршрутов
// (физический vs туннельный) по их интерфейсному IP.
func ifaceNameForIP(ip string) string {
	target := net.ParseIP(ip)
	if target == nil {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
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
			if ipnet.IP.Equal(target) {
				return iface.Name
			}
		}
	}
	return ""
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
			if err == nil {
				// INT-L1: exact Name-column match — substring "NixaVPN" would
				// report readiness on a stale "NixaVPN 2" adapter.
				if _, found := findNetshInterfaceIndex(string(out), tunName); found {
					slog.Debug("TUN-интерфейс обнаружен", "name", tunName)
					return nil
				}
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
		// Только виртуальный интерфейс владеет подсетью шлюза → сам шлюз
		// принадлежит чужому туннелю (sing-tun/WireGuard/…). Привязка bypass к
		// нему кладёт direct-трафик в тупик (ERR_CONNECTION_RESET на RU-сайтах).
		// Возвращаем ошибку: caller (determinePhysicalInterface) логирует и
		// продолжает БЕЗ bypass-привязки — RU-трафик пойдёт через наш туннель
		// (медленнее, но живой), а не в чужой.
		return "", fmt.Errorf("подсеть шлюза %s принадлежит только virtual-интерфейсу %q (вероятно сторонний туннель) — bypass не активирован", gw, firstMatch)
	}
	return "", fmt.Errorf("не найден интерфейс с подсетью шлюза %s", gw)
}

// findNetshInterfaceIndex scans `netsh interface ipv4 show interfaces` output
// for the row whose Name column EXACTLY equals name, returning that row's Idx.
//
// Row format: "  Idx  Met  MTU   State   Name" — the Name is the LAST column
// and may contain spaces ("Loopback Pseudo-Interface 1"), so we reconstruct it
// as the join of fields[4:]. Header/separator lines are rejected by the
// numeric-Idx check. INT-L1: the previous strings.Contains(line, name) let
// "NixaVPN" match a stale "NixaVPN 2" adapter left by an unclosed Wintun →
// wrong ifIdx for the split routes and false TUN readiness. Pure (no exec).
func findNetshInterfaceIndex(out, name string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue // header / separator row
		}
		if strings.Join(fields[4:], " ") == name {
			return fields[0], true
		}
	}
	return "", false
}

// getWindowsInterfaceIndex возвращает числовой индекс TUN-интерфейса Windows
// через `netsh interface ipv4 show interfaces`. Используется при добавлении
// маршрутов. Имя матчится ТОЧНО по колонке Name (см. findNetshInterfaceIndex).
func getWindowsInterfaceIndex(device string) (string, error) {
	// Убираем tun:// префикс — нам нужно только имя.
	name := strings.TrimPrefix(device, "tun://")

	out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
	if err != nil {
		return "", fmt.Errorf("netsh interface show: %w", err)
	}
	if idx, ok := findNetshInterfaceIndex(string(out), name); ok {
		return idx, nil
	}
	return "", fmt.Errorf("интерфейс %q не найден в netsh output", name)
}

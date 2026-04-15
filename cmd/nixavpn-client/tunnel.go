package main

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// Tunnel управляет TUN-интерфейсом для системного VPN-режима.
// Использует tun2socks v2 как встроенную Go-библиотеку.
// Трафик с TUN-интерфейса перенаправляется в SOCKS5-прокси.
type Tunnel struct {
	socksAddr string
	proxyUser string
	proxyPass string
	serverIPs []string // one or more IPs for escape routes

	mu      sync.Mutex
	started bool
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

	// Загружаем конфиг tun2socks и запускаем движок.
	// Proxy URL включает credentials: socks5://user:pass@host:port
	proxyURL := fmt.Sprintf("socks5://%s:%s@%s", t.proxyUser, t.proxyPass, t.socksAddr)
	// W7: MTU 1400 to account for ShadowLink encryption + WebSocket + TLS overhead.
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

	// W4: route setup failure is fatal — without routes, TUN is useless
	// and LeakGuard kill switch would block all traffic.
	if err := setupRoutes(device, t.serverIPs); err != nil {
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

	device := tunDeviceName()

	if err := cleanupRoutes(device, t.serverIPs); err != nil {
		slog.Warn("не удалось убрать маршруты", "err", err)
	}

	engine.Stop()

	t.started = false
	slog.Info("TUN-туннель остановлен")
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
func setupRoutes(device string, serverIPs []string) error {
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
	// CF CDN rotates Anycast IPs within the same datacenter. Without broader routes,
	// ConnManager rotation may resolve to a new CF IP not covered by /32 escape routes,
	// causing traffic to loop through TUN.
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
		// DNS: задать DNS на TUN-интерфейсе чтобы приложения резолвили через VPN.
		tunName := strings.TrimPrefix(device, "tun://")
		if out, err := exec.Command("netsh", "interface", "ip", "set", "dns",
			tunName, "static", "1.1.1.1").CombinedOutput(); err != nil {
			slog.Warn("не удалось установить основной DNS на TUN", "err", err, "output", strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("netsh", "interface", "ip", "add", "dns",
			tunName, "8.8.8.8", "index=2").CombinedOutput(); err != nil {
			slog.Warn("не удалось установить резервный DNS на TUN", "err", err, "output", strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("netsh", "interface", "ip", "set", "interface",
			tunName, "metric=1").CombinedOutput(); err != nil {
			slog.Warn("не удалось установить метрику TUN-интерфейса", "err", err, "output", strings.TrimSpace(string(out)))
		}
		exec.Command("ipconfig", "/flushdns").Run()
		slog.Info("DNS настроен на TUN", "dns1", "1.1.1.1", "dns2", "8.8.8.8", "metric", 1)

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

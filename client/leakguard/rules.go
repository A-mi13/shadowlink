package leakguard

import (
	"net/netip"

	"github.com/nixavpn/shadowlink/client/dnsproxy"
)

// LANRanges возвращает RFC1918 LAN-диапазоны, разрешаемые при split-tunnel.
// Источник истины дублирует bypassroute drop==false reserved, НО держим
// локальную копию чтобы leakguard не импортировал bypassroute (избегаем
// цикла client→leakguard и оставляем leakguard листовым пакетом).
func LANRanges() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
}

// dedupV4Prefixes отбрасывает не-IPv4 и дубликаты, сохраняя порядок первого
// появления (стабильный порядок — важно для детерминизма тестов и WFP-bulk).
func dedupV4Prefixes(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.Addr().Is4() {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// KillSwitchPlan — платформо-нейтральное описание того, что должен сделать
// kill-switch. OS-обёртки переводят его в netsh/nft/pfctl/WFP. Чистая
// структура, сериализуема, тестируема без exec.
type KillSwitchPlan struct {
	ServerIPs   []string       // allow к серверу (все CDN IP)
	ServerPort  int            // порт сервера
	TunName     string         // имя TUN-интерфейса
	Loopback    bool           // allow loopback
	DHCP        bool           // allow DHCP (udp 68→67)
	ExtraEscape []string       // ExtraEscapeIPs (udp)
	SplitTunnel bool           // явный split-tunnel включён
	LANAllow    []netip.Prefix // RFC1918 при split-tunnel
	RUAllow     []netip.Prefix // RU CIDR при split-tunnel (если OS поддерживает)

	// DNSAllow — резолверы, которым нужен plain-UDP/53 МИМО туннеля.
	//
	// H-13 (раунд 18): правило существовало только в rules_windows.go, где IP
	// брались напрямую из dnsproxy.DefaultYandexIPs(). Linux и Darwin его не
	// имели ВООБЩЕ, при этом setupRoutes (tunnel.go) ставит /32 escape-маршруты
	// для Yandex БЕЗУСЛОВНО на всех платформах: пакеты уходили мимо TUN и
	// упирались в финальный `drop` (nft/iptables) / `block out all` (pf).
	// Итог — Yandex-нога арбитража мертва при поднятом kill-switch, dnsproxy
	// всегда получал !yOK и деградировал в CF-only. Направление fail-secure (не
	// утечка), но анти-цензурная функция не работала на двух платформах из трёх.
	//
	// Поле в плане, а не обращение к dnsproxy внутри каждого генератора: ровно
	// тот «единый источник истины», который декларировал комментарий
	// Windows-правила. Паритет сторожится TestKillSwitchPlan_DNSAllow* в
	// rules_test.go — кросс-платформенном файле БЕЗ build-тега, потому что
	// per-platform тесты под тегами и были причиной, по которой дрейф не
	// замечали (§7.4).
	DNSAllow []string
}

// BuildKillSwitchPlan детерминированно строит план из config + флага поддержки
// RU-split на данной ОС. ruBypassSupported=true на ВСЕХ ОС (Windows — через
// WFP, Linux — nft set/ipset, Darwin — pf table; см. spec §4.4). На
// Linux-iptables-без-ipset обёртка передаёт ruBypassSupported по факту
// доступности ipset.
func BuildKillSwitchPlan(cfg LeakGuardConfig, ruBypassSupported bool) KillSwitchPlan {
	plan := KillSwitchPlan{
		ServerPort:  cfg.ServerPort,
		TunName:     cfg.TunName,
		Loopback:    true,
		DHCP:        true,
		SplitTunnel: cfg.SplitTunnel,
	}
	for _, ip := range cfg.AllServerIPs() {
		plan.ServerIPs = append(plan.ServerIPs, ip.String())
	}
	for _, ip := range cfg.ExtraEscapeIPs {
		plan.ExtraEscape = append(plan.ExtraEscape, ip.String())
	}
	// H-13: единый источник истины для DNS-резолверов, идущих plain-UDP мимо
	// туннеля. Те же IP, что dnsproxy использует как plain-UDP цели и для
	// которых tunnel.go ставит /32 escape-маршруты. Заполняется на ВСЕХ
	// платформах — раньше правило было только в netsh-генераторе Windows.
	plan.DNSAllow = append(plan.DNSAllow, dnsproxy.DefaultYandexIPs()...)
	if cfg.SplitTunnel {
		plan.LANAllow = LANRanges()
		if ruBypassSupported {
			plan.RUAllow = dedupV4Prefixes(cfg.BypassRanges)
		}
	}
	return plan
}

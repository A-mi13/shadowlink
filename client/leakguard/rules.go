package leakguard

import "net/netip"

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
	if cfg.SplitTunnel {
		plan.LANAllow = LANRanges()
		if ruBypassSupported {
			plan.RUAllow = dedupV4Prefixes(cfg.BypassRanges)
		}
	}
	return plan
}

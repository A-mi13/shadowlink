//go:build linux

package leakguard

import "fmt"

// linuxNFTCommands is the PURE generator of nft commands for the kill switch.
// Order invariant: the final `drop` rule is ALWAYS last so accepts precede it.
func linuxNFTCommands(plan KillSwitchPlan) [][]string {
	port := fmt.Sprintf("%d", plan.ServerPort)
	cmds := [][]string{
		{"nft", "add", "table", "inet", "shadowlink"},
		{"nft", "add", "chain", "inet", "shadowlink", "output",
			"{ type filter hook output priority 0 ; policy accept ; }"},
		{"nft", "add", "rule", "inet", "shadowlink", "output", "oifname", plan.TunName, "accept"},
	}
	for _, ip := range plan.ServerIPs {
		cmds = append(cmds,
			[]string{"nft", "add", "rule", "inet", "shadowlink", "output", "ip", "daddr", ip, "tcp", "dport", port, "accept"},
			[]string{"nft", "add", "rule", "inet", "shadowlink", "output", "ip", "daddr", ip, "udp", "dport", port, "accept"},
		)
	}
	if plan.Loopback {
		cmds = append(cmds, []string{"nft", "add", "rule", "inet", "shadowlink", "output", "oifname", "lo", "accept"})
	}
	if plan.DHCP {
		cmds = append(cmds, []string{"nft", "add", "rule", "inet", "shadowlink", "output",
			"udp", "sport", "68", "udp", "dport", "67", "accept"})
	}
	for _, eip := range plan.ExtraEscape {
		cmds = append(cmds, []string{"nft", "add", "rule", "inet", "shadowlink", "output", "ip", "daddr", eip, "udp", "accept"})
	}

	// Split-tunnel: LAN accepts + RU set (named interval set scales to thousands).
	if plan.SplitTunnel {
		for _, p := range plan.LANAllow {
			cmds = append(cmds, []string{"nft", "add", "rule", "inet", "shadowlink", "output", "ip", "daddr", p.String(), "accept"})
		}
		if len(plan.RUAllow) > 0 {
			cmds = append(cmds, []string{"nft", "add", "set", "inet", "shadowlink", "sl_ru",
				"{ type ipv4_addr ; flags interval ; }"})
			elems := make([]string, 0, len(plan.RUAllow))
			for _, p := range plan.RUAllow {
				elems = append(elems, p.String())
			}
			cmds = append(cmds, []string{"nft", "add", "element", "inet", "shadowlink", "sl_ru",
				"{ " + joinComma(elems) + " }"})
			cmds = append(cmds, []string{"nft", "add", "rule", "inet", "shadowlink", "output", "ip", "daddr", "@sl_ru", "accept"})
		}
	}

	// Final drop ALWAYS last.
	cmds = append(cmds, []string{"nft", "add", "rule", "inet", "shadowlink", "output", "drop"})
	return cmds
}

// linuxIPTablesCommands is the PURE generator of iptables commands. RU split
// requires ipset; when ipsetAvailable is false the RU ranges are omitted
// (degradation to LAN-only, fail-secure: RU goes through TUN).
func linuxIPTablesCommands(plan KillSwitchPlan, ipsetAvailable bool) [][]string {
	port := fmt.Sprintf("%d", plan.ServerPort)
	var cmds [][]string

	// ipset for RU (created before chain rules reference it).
	if plan.SplitTunnel && len(plan.RUAllow) > 0 && ipsetAvailable {
		cmds = append(cmds, []string{"ipset", "create", "sl_ru", "hash:net", "-exist"})
		for _, p := range plan.RUAllow {
			cmds = append(cmds, []string{"ipset", "add", "sl_ru", p.String(), "-exist"})
		}
	}

	cmds = append(cmds,
		[]string{"iptables", "-N", "SHADOWLINK-KS"},
		[]string{"iptables", "-I", "OUTPUT", "-j", "SHADOWLINK-KS"},
		[]string{"iptables", "-A", "SHADOWLINK-KS", "-o", plan.TunName, "-j", "ACCEPT"},
	)
	for _, ip := range plan.ServerIPs {
		cmds = append(cmds,
			[]string{"iptables", "-A", "SHADOWLINK-KS", "-d", ip, "-p", "tcp", "--dport", port, "-j", "ACCEPT"},
			[]string{"iptables", "-A", "SHADOWLINK-KS", "-d", ip, "-p", "udp", "--dport", port, "-j", "ACCEPT"},
		)
	}
	if plan.Loopback {
		cmds = append(cmds, []string{"iptables", "-A", "SHADOWLINK-KS", "-o", "lo", "-j", "ACCEPT"})
	}
	if plan.DHCP {
		cmds = append(cmds, []string{"iptables", "-A", "SHADOWLINK-KS", "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"})
	}
	for _, eip := range plan.ExtraEscape {
		cmds = append(cmds, []string{"iptables", "-A", "SHADOWLINK-KS", "-d", eip, "-p", "udp", "-j", "ACCEPT"})
	}

	if plan.SplitTunnel {
		for _, p := range plan.LANAllow {
			cmds = append(cmds, []string{"iptables", "-A", "SHADOWLINK-KS", "-d", p.String(), "-j", "ACCEPT"})
		}
		if len(plan.RUAllow) > 0 && ipsetAvailable {
			cmds = append(cmds, []string{"iptables", "-A", "SHADOWLINK-KS", "-m", "set", "--match-set", "sl_ru", "dst", "-j", "ACCEPT"})
		}
	}

	// Final drop ALWAYS last.
	cmds = append(cmds, []string{"iptables", "-A", "SHADOWLINK-KS", "-j", "DROP"})
	return cmds
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// ipv6DisableSysctlKeys returns the sysctl keys to disable IPv6: the global
// `all` and `default` plus a per-interface key for each iface (M3).
func ipv6DisableSysctlKeys(ifaces []string) []string {
	keys := []string{
		"net.ipv6.conf.all.disable_ipv6",
		"net.ipv6.conf.default.disable_ipv6",
	}
	for _, ifc := range ifaces {
		if ifc == "" {
			continue
		}
		keys = append(keys, fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", ifc))
	}
	return keys
}

// resolvConfPlan describes how setDNS should write DNS when /etc/resolv.conf
// is (or is not) a symlink managed by systemd-resolved / NetworkManager (M2/L5).
type resolvConfPlan struct {
	overwrite     bool   // safe to write the file directly
	useResolvectl bool   // managed → use resolvectl/nmcli instead
	target        string // symlink target (for restore)
}

// resolvConfWritePlan decides whether to overwrite /etc/resolv.conf or defer to
// resolvectl. A symlink means it is managed → never clobber the target.
func resolvConfWritePlan(isSymlink bool, target string) resolvConfPlan {
	if isSymlink {
		return resolvConfPlan{overwrite: false, useResolvectl: true, target: target}
	}
	return resolvConfPlan{overwrite: true, useResolvectl: false}
}

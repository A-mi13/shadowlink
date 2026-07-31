//go:build darwin

package leakguard

import (
	"fmt"
	"path/filepath"
	"strings"
)

// darwinPFRules is the PURE generator of pf rules from a KillSwitchPlan.
// Order: pass-quick rules first (server, lo, dhcp, escape, split, tun), then
// `block out all` ALWAYS last (with `quick` order is fixed regardless, but we
// keep block last for clarity and to satisfy the order invariant).
func darwinPFRules(plan KillSwitchPlan) []string {
	var rules []string
	for _, ip := range plan.ServerIPs {
		rules = append(rules, fmt.Sprintf("pass out quick proto {tcp, udp} to %s port %d", ip, plan.ServerPort))
	}
	if plan.Loopback {
		rules = append(rules, "pass out quick on lo0 all")
	}
	if plan.DHCP {
		rules = append(rules, "pass out quick proto udp from any port 68 to any port 67")
	}
	for _, eip := range plan.ExtraEscape {
		rules = append(rules, fmt.Sprintf("pass out quick proto udp to %s", eip))
	}
	// H-13: plain-UDP/53 к RU-резолверам идёт DIRECT мимо TUN by design
	// (escape /32 через физический шлюз). Без этого pass пакеты упирались в
	// `block out all` → Yandex-нога split-DNS не работала на macOS.
	for _, dip := range plan.DNSAllow {
		rules = append(rules, fmt.Sprintf("pass out quick proto udp to %s port 53", dip))
	}

	if plan.SplitTunnel {
		for _, p := range plan.LANAllow {
			rules = append(rules, fmt.Sprintf("pass out quick to %s", p.String()))
		}
		if len(plan.RUAllow) > 0 {
			elems := make([]string, 0, len(plan.RUAllow))
			for _, p := range plan.RUAllow {
				elems = append(elems, p.String())
			}
			rules = append(rules, fmt.Sprintf("table <sl_ru> { %s }", strings.Join(elems, " ")))
			rules = append(rules, "pass out quick to <sl_ru>")
		}
	}

	if plan.TunName != "" {
		rules = append(rules, fmt.Sprintf("pass out quick on %s all", plan.TunName))
	}
	rules = append(rules, "block out all")
	return rules
}

// parsePFEnabled reports whether `pfctl -s info` shows pf as enabled (M4).
func parsePFEnabled(infoOutput string) bool {
	for _, line := range strings.Split(infoOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Status:") {
			return strings.Contains(line, "Enabled")
		}
	}
	return false
}

// pfRulesPath returns the pf rules file path inside the app directory rather
// than world-writable /tmp (M5). appDir is the directory of the state file.
func pfRulesPath(appDir string) string {
	if appDir == "" {
		appDir = "."
	}
	return filepath.Join(appDir, "shadowlink-pf.rules")
}

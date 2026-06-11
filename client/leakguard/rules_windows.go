//go:build windows

package leakguard

import (
	"fmt"
	"strconv"
	"strings"
)

// firewallRule is a netsh advfirewall rule: a name plus the args passed to netsh.
type firewallRule struct {
	name string
	args []string
}

// windowsFirewallRules is the PURE generator of netsh advfirewall rules from a
// KillSwitchPlan. It does NOT touch the network — OS wrapper applies each rule.
//
// RU CIDR split is NOT represented here: on Windows it goes through WFP (see
// wfp_windows.go / buildWFPConds), not netsh. Only LAN split (3 RFC1918 ranges)
// is expressed as a netsh rule because netsh handles a handful of prefixes.
func windowsFirewallRules(plan KillSwitchPlan) []firewallRule {
	serverIPList := strings.Join(plan.ServerIPs, ",")
	port := strconv.Itoa(plan.ServerPort)

	rules := []firewallRule{
		{
			name: "SL-Block-All",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Block-All", "dir=out", "action=block"},
		},
		{
			name: "SL-Allow-TUN",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-TUN", "dir=out", "action=allow",
				"localip=198.18.0.0/15"},
		},
		{
			name: "SL-Allow-Server-TCP",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-Server-TCP", "dir=out", "action=allow",
				fmt.Sprintf("remoteip=%s", serverIPList),
				fmt.Sprintf("remoteport=%s", port),
				"protocol=tcp"},
		},
		{
			name: "SL-Allow-Server-UDP",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-Server-UDP", "dir=out", "action=allow",
				fmt.Sprintf("remoteip=%s", serverIPList),
				fmt.Sprintf("remoteport=%s", port),
				"protocol=udp"},
		},
	}

	if plan.Loopback {
		rules = append(rules, firewallRule{
			name: "SL-Allow-Loopback",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-Loopback", "dir=out", "action=allow",
				"remoteip=127.0.0.0/8"},
		})
	}

	if plan.DHCP {
		rules = append(rules, firewallRule{
			name: "SL-Allow-DHCP",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-DHCP", "dir=out", "action=allow",
				"protocol=udp", "localport=68", "remoteport=67"},
		})
	}

	// Optional escape route for extra UDP destinations (e.g. TURN relays).
	if len(plan.ExtraEscape) > 0 {
		rules = append(rules, firewallRule{
			name: "SL-Allow-Escape-UDP",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-Escape-UDP", "dir=out", "action=allow",
				fmt.Sprintf("remoteip=%s", strings.Join(plan.ExtraEscape, ",")),
				"protocol=udp"},
		})
	}

	// Split-tunnel LAN allow (RFC1918) — netsh handles the 3 ranges trivially.
	if plan.SplitTunnel && len(plan.LANAllow) > 0 {
		lanList := make([]string, 0, len(plan.LANAllow))
		for _, p := range plan.LANAllow {
			lanList = append(lanList, p.String())
		}
		rules = append(rules, firewallRule{
			name: "SL-Allow-LAN",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-LAN", "dir=out", "action=allow",
				fmt.Sprintf("remoteip=%s", strings.Join(lanList, ","))},
		})
	}

	return rules
}

// windowsFirewallRuleNames returns the names of all rules a plan would create,
// used for state persistence and cleanup.
func windowsFirewallRuleNames(plan KillSwitchPlan) []string {
	rules := windowsFirewallRules(plan)
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.name)
	}
	return names
}

//go:build windows

package leakguard

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nixavpn/shadowlink/client/dnsproxy"
)

// firewallRule is a netsh advfirewall rule: a name plus the args passed to netsh.
type firewallRule struct {
	name string
	args []string
}

// windowsFirewallRules is the PURE generator of netsh advfirewall rules from a
// KillSwitchPlan. It does NOT touch the network — OS wrapper applies each rule.
//
// LG-H1: there is deliberately NO explicit block rule here. Windows Firewall
// evaluates explicit block rules BEFORE allow rules, so a block-all rule would
// always beat the allows below and cut the tunnel itself. Deny-by-default is
// provided by flipping the DEFAULT OUTBOUND POLICY to Block instead (see
// fwpolicy_windows.go / setKillSwitchFirewallPolicy) — the default action only
// applies when no rule matches, so the allow rules work as designed.
//
// RU CIDR split is NOT represented here: on Windows it goes through WFP (see
// wfp_windows.go / buildWFPConds), not netsh. Only LAN split (3 RFC1918 ranges)
// is expressed as a netsh rule because netsh handles a handful of prefixes.
//
// LG-L2 invariant — IPv6 over the TUN is blocked DELIBERATELY: SL-Allow-TUN is
// an IPv4 localip rule (198.18.0.0/15), no v6 permit exists, and disableIPv6
// exempting the TUN does not imply v6 is allowed through it — the
// deny-by-default outbound policy drops it (fail-secure). When enabling v6
// transport, add SL-Allow-TUN-v6 here AND a v6 DNS backup in lockstep (see
// guard_windows.go disableIPv6 / backupDNS, which are IPv4-only today).
func windowsFirewallRules(plan KillSwitchPlan) []firewallRule {
	serverIPList := strings.Join(plan.ServerIPs, ",")
	port := strconv.Itoa(plan.ServerPort)

	rules := []firewallRule{
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
		// LG-H2: the split-DNS forwarder's Yandex branch goes DIRECT off-TUN by
		// design (escape /32 routes via the physical gateway, src = physical NIC
		// IP), so neither SL-Allow-TUN (localip 198.18/15) nor SL-Allow-Server-UDP
		// (server IP:port) permits it. Scope is minimal: udp/53 to the exact
		// resolver IPs from dnsproxy.DefaultYandexIPs() — the single source of
		// truth shared with the resolver targets and tunnel.go escape routes
		// (never duplicate the literals). Plaintext DNS to Yandex off-tunnel is
		// the split-DNS design itself, not a leak.
		{
			name: "SL-Allow-DNS-RU",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-DNS-RU", "dir=out", "action=allow",
				"protocol=udp", "remoteport=53",
				fmt.Sprintf("remoteip=%s", strings.Join(dnsproxy.DefaultYandexIPs(), ","))},
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

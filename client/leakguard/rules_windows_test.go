//go:build windows

package leakguard

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/client/dnsproxy"
)

// ---------------------------------------------------------------------------
// Task 6 — Windows firewall formatter (LAN via netsh + RU via WFP)
// ---------------------------------------------------------------------------

func ruleNames(rules []firewallRule) []string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.name)
	}
	return names
}

func mustHave(t *testing.T, names []string, want ...string) {
	t.Helper()
	for _, w := range want {
		found := false
		for _, n := range names {
			if n == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing rule %q in %v", w, names)
		}
	}
}

func mustNotHave(t *testing.T, names []string, banned ...string) {
	t.Helper()
	for _, b := range banned {
		for _, n := range names {
			if n == b {
				t.Errorf("rule %q must NOT be present in %v", b, names)
			}
		}
	}
}

func findRule(t *testing.T, rules []firewallRule, name string) firewallRule {
	t.Helper()
	for _, r := range rules {
		if r.name == name {
			return r
		}
	}
	t.Fatalf("rule %q not found", name)
	return firewallRule{}
}

func mustContainArg(t *testing.T, args []string, want string) {
	t.Helper()
	for _, a := range args {
		if a == want {
			return
		}
	}
	t.Errorf("expected arg %q in %v", want, args)
}

func TestWindowsRules_FailSecure_NoBypassAllow(t *testing.T) {
	rules := windowsFirewallRules(BuildKillSwitchPlan(baseCfg(), true)) // SplitTunnel=false
	names := ruleNames(rules)
	mustHave(t, names, "SL-Allow-TUN", "SL-Allow-Server-TCP", "SL-Allow-Loopback", "SL-Allow-DHCP", "SL-Allow-DNS-RU")
	mustNotHave(t, names, "SL-Allow-LAN")
}

// LG-H1 — Windows Firewall evaluates explicit block rules BEFORE allow rules,
// so an explicit block-all rule would always beat our allows and cut the
// tunnel itself. The deny-by-default semantics must come from the default
// outbound POLICY (set by the guard), never from a block rule.
func TestWindowsRules_NoExplicitBlockRule(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = true
	cfg.BypassRanges = []netip.Prefix{netip.MustParsePrefix("77.88.0.0/18")}
	rules := windowsFirewallRules(BuildKillSwitchPlan(cfg, true))
	mustNotHave(t, ruleNames(rules), "SL-Block-All")
	for _, r := range rules {
		for _, a := range r.args {
			if a == "action=block" {
				t.Errorf("rule %q uses action=block — explicit block rules override allow rules", r.name)
			}
		}
	}
}

// LG-H2 — the split-DNS forwarder's Yandex branch goes DIRECT off-TUN
// (src = physical NIC IP), so the kill switch needs a minimal udp/53 permit
// to exactly the resolver IPs from the dnsproxy single source of truth.
func TestWindowsRules_DNSRU_ExactYandexIPs(t *testing.T) {
	rules := windowsFirewallRules(BuildKillSwitchPlan(baseCfg(), true))
	r := findRule(t, rules, "SL-Allow-DNS-RU")
	mustContainArg(t, r.args, "dir=out")
	mustContainArg(t, r.args, "action=allow")
	mustContainArg(t, r.args, "protocol=udp")
	mustContainArg(t, r.args, "remoteport=53")
	mustContainArg(t, r.args, "remoteip="+strings.Join(dnsproxy.DefaultYandexIPs(), ","))
}

// SL-Allow-DNS-RU must be in the well-known crash-recovery name list so a
// stale rule is removed even when the state file is lost.
func TestKillSwitchRuleNames_ContainsDNSRU(t *testing.T) {
	found := false
	for _, n := range killSwitchRuleNames {
		if n == "SL-Allow-DNS-RU" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SL-Allow-DNS-RU missing from killSwitchRuleNames: %v", killSwitchRuleNames)
	}
}

func TestWindowsRules_Split_AddsLANAllow(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = true
	cfg.BypassRanges = []netip.Prefix{netip.MustParsePrefix("77.88.0.0/18")}
	rules := windowsFirewallRules(BuildKillSwitchPlan(cfg, true))
	r := findRule(t, rules, "SL-Allow-LAN")
	mustContainArg(t, r.args, "remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
}

// RU split на Windows идёт через WFP, а не netsh-правила.
func TestWindowsRules_Split_AddsRUViaWFP(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = true
	cfg.BypassRanges = []netip.Prefix{
		netip.MustParsePrefix("77.88.0.0/18"),
		netip.MustParsePrefix("5.45.192.0/18"),
	}
	plan := BuildKillSwitchPlan(cfg, true) // ruBypassSupported=true (WFP)
	if len(plan.RUAllow) != 2 {
		t.Fatalf("RU split must be in plan on Windows (WFP): %v", plan.RUAllow)
	}
	// netsh-правила RU НЕ содержат (RU идёт мимо netsh, через WFP)
	mustNotHave(t, ruleNames(windowsFirewallRules(plan)), "SL-Allow-RU")
	// чистая WFP-функция мапит оба префикса в условия
	conds := buildWFPConds(plan.RUAllow)
	if len(conds) != 2 {
		t.Fatalf("buildWFPConds len=%d want 2", len(conds))
	}
	// 77.88.0.0/18 → mask 0xFFFFC000, addr 77.88.0.0
	if conds[0].Mask != 0xFFFFC000 {
		t.Errorf("mask=%#x want 0xFFFFC000", conds[0].Mask)
	}
	if conds[0].Addr != (77<<24 | 88<<16) {
		t.Errorf("addr=%#x want 77.88.0.0", conds[0].Addr)
	}
}

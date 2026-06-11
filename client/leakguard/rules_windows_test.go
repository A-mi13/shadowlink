//go:build windows

package leakguard

import (
	"net/netip"
	"testing"
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
	mustHave(t, names, "SL-Block-All", "SL-Allow-TUN", "SL-Allow-Server-TCP", "SL-Allow-Loopback", "SL-Allow-DHCP")
	mustNotHave(t, names, "SL-Allow-LAN")
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

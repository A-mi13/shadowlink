//go:build darwin

package leakguard

import (
	"net/netip"
	"strings"
	"testing"
)

func joinRules(rules []string) string { return strings.Join(rules, "\n") }

func assertLastRule(t *testing.T, rules []string, want string) {
	t.Helper()
	if len(rules) == 0 {
		t.Fatal("no rules")
	}
	if rules[len(rules)-1] != want {
		t.Fatalf("last rule = %q want %q", rules[len(rules)-1], want)
	}
}

// ---------------------------------------------------------------------------
// Task 5 — Darwin pf formatter
// ---------------------------------------------------------------------------

func TestDarwinPF_FailSecure_PassBeforeBlock_NoBypass(t *testing.T) {
	rules := darwinPFRules(BuildKillSwitchPlan(baseCfg(), true)) // no split
	joined := joinRules(rules)
	mustContain(t, joined, "pass out quick proto {tcp, udp} to 104.222.177.67 port 443")
	mustContain(t, joined, "pass out quick on tun0 all")
	assertLastRule(t, rules, "block out all")
	mustNotContain(t, joined, "10.0.0.0/8")
	mustNotContain(t, joined, "<sl_ru>")
}

func TestDarwinPF_Split_TableBeforeBlock(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = true
	cfg.BypassRanges = []netip.Prefix{netip.MustParsePrefix("77.88.0.0/18")}
	rules := darwinPFRules(BuildKillSwitchPlan(cfg, true))
	joined := joinRules(rules)
	mustContain(t, joined, "table <sl_ru> { 77.88.0.0/18 }")
	mustContain(t, joined, "pass out quick to <sl_ru>")
	mustContain(t, joined, "pass out quick to 10.0.0.0/8")
	assertLastRule(t, rules, "block out all")
}

// ---------------------------------------------------------------------------
// Task 10 — pf-enabled check + pfRulesPath in app-dir
// ---------------------------------------------------------------------------

func TestParsePFEnabled(t *testing.T) {
	if !parsePFEnabled("Status: Enabled for 0 days 00:01:23\n  ...") {
		t.Fatal("expected Enabled → true")
	}
	if parsePFEnabled("Status: Disabled") {
		t.Fatal("expected Disabled → false")
	}
}

func TestDarwinPFRulesPath_NotInTmp(t *testing.T) {
	p := pfRulesPath("/Users/x/Library/Application Support/NixaVPN")
	if strings.HasPrefix(p, "/tmp") {
		t.Fatalf("must not be /tmp (M5): %s", p)
	}
}

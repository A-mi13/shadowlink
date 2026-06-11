package leakguard

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Task 1 — LANRanges + dedupV4Prefixes
// ---------------------------------------------------------------------------

func TestLANRanges_AreRFC1918(t *testing.T) {
	got := LANRanges()
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d", len(got), len(want))
	}
	for i, p := range got {
		if p.String() != want[i] {
			t.Errorf("[%d]=%s want %s", i, p, want[i])
		}
		if !p.Addr().Is4() {
			t.Errorf("[%d] not IPv4", i)
		}
	}
}

func TestDedupV4Prefixes_DropsV6AndDups(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("5.45.192.0/18"),
		netip.MustParsePrefix("5.45.192.0/18"),  // dup
		netip.MustParsePrefix("2a00:1450::/32"), // v6 → drop
		netip.MustParsePrefix("77.88.0.0/18"),
	}
	got := dedupV4Prefixes(in)
	if len(got) != 2 {
		t.Fatalf("len=%d want 2 (%v)", len(got), got)
	}
	// stable order: first-seen wins
	if got[0].String() != "5.45.192.0/18" || got[1].String() != "77.88.0.0/18" {
		t.Errorf("order not stable: %v", got)
	}
}

// ---------------------------------------------------------------------------
// Task 2 — BuildKillSwitchPlan (fail-secure decision)
// ---------------------------------------------------------------------------

func baseCfg() LeakGuardConfig {
	return LeakGuardConfig{
		ServerIPs:  []net.IP{net.ParseIP("104.222.177.67")},
		ServerPort: 443, TunName: "tun0",
	}
}

func TestBuildPlan_NoSplit_NoBypassAllow(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = false
	cfg.BypassRanges = []netip.Prefix{netip.MustParsePrefix("77.88.0.0/18")}
	plan := BuildKillSwitchPlan(cfg, true)
	if len(plan.LANAllow) != 0 || len(plan.RUAllow) != 0 {
		t.Fatalf("fail-secure violated: LAN=%v RU=%v", plan.LANAllow, plan.RUAllow)
	}
	if len(plan.ServerIPs) != 1 {
		t.Fatalf("server allow missing")
	}
}

func TestBuildPlan_Split_AddsLANAndRU(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = true
	cfg.BypassRanges = []netip.Prefix{netip.MustParsePrefix("77.88.0.0/18")}
	plan := BuildKillSwitchPlan(cfg, true)
	if len(plan.LANAllow) != 3 {
		t.Fatalf("LAN allow missing")
	}
	if len(plan.RUAllow) != 1 {
		t.Fatalf("RU allow missing")
	}
}

// ruBypassSupported=false возникает ТОЛЬКО на Linux-iptables-без-ipset
// (Windows = WFP → true, Linux-nft → true, Darwin = pf table → true).
func TestBuildPlan_Split_RUUnsupported_LANStillApplies(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = true
	cfg.BypassRanges = []netip.Prefix{netip.MustParsePrefix("77.88.0.0/18")}
	plan := BuildKillSwitchPlan(cfg, false) // ruBypassSupported=false (iptables без ipset)
	if len(plan.LANAllow) != 3 {
		t.Fatalf("LAN allow must still apply (fail-secure)")
	}
	if len(plan.RUAllow) != 0 {
		t.Fatalf("RU split must be empty when backend cannot scale (degradation)")
	}
}

// ---------------------------------------------------------------------------
// shared test helpers (used by per-OS formatter tests under build tags)
// ---------------------------------------------------------------------------

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected to contain %q in:\n%s", needle, haystack)
	}
}

func mustNotContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("expected NOT to contain %q in:\n%s", needle, haystack)
	}
}

func mustContainOnce(t *testing.T, haystack, needle string) {
	t.Helper()
	if n := strings.Count(haystack, needle); n != 1 {
		t.Errorf("expected exactly one %q, got %d in:\n%s", needle, n, haystack)
	}
}

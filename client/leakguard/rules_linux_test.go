//go:build linux

package leakguard

import (
	"net/netip"
	"strings"
	"testing"
)

func joinCmds(cmds [][]string) string {
	var b strings.Builder
	for _, c := range cmds {
		b.WriteString(strings.Join(c, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// assertDropIsLast verifies the final command is the drop rule.
func assertDropIsLast(t *testing.T, cmds [][]string) {
	t.Helper()
	if len(cmds) == 0 {
		t.Fatal("no commands")
	}
	last := strings.Join(cmds[len(cmds)-1], " ")
	if !strings.HasSuffix(last, "drop") && !strings.HasSuffix(last, "DROP") {
		t.Fatalf("last cmd is not drop: %q", last)
	}
	// No accept after the drop.
	for i, c := range cmds {
		joined := strings.Join(c, " ")
		if (strings.HasSuffix(joined, "drop") || strings.HasSuffix(joined, "DROP")) && i != len(cmds)-1 {
			t.Fatalf("drop at index %d is not last (%d cmds)", i, len(cmds))
		}
	}
}

// ---------------------------------------------------------------------------
// Task 3 — Linux nft formatter
// ---------------------------------------------------------------------------

func TestLinuxNFT_FailSecure_HasDropNoBypass(t *testing.T) {
	plan := BuildKillSwitchPlan(baseCfg(), true) // SplitTunnel=false
	cmds := linuxNFTCommands(plan)
	joined := joinCmds(cmds)
	mustContain(t, joined, "oifname tun0 accept")
	mustContain(t, joined, "ip daddr 104.222.177.67 tcp dport 443 accept")
	mustContainOnce(t, joined, "output drop")
	mustNotContain(t, joined, "10.0.0.0/8")
	mustNotContain(t, joined, "@sl_ru")
	assertDropIsLast(t, cmds)
}

func TestLinuxNFT_Split_AddsLANAndRUSet(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = true
	cfg.BypassRanges = []netip.Prefix{netip.MustParsePrefix("77.88.0.0/18")}
	cmds := linuxNFTCommands(BuildKillSwitchPlan(cfg, true))
	joined := joinCmds(cmds)
	mustContain(t, joined, "add set inet shadowlink sl_ru")
	mustContain(t, joined, "77.88.0.0/18")
	mustContain(t, joined, "ip daddr 10.0.0.0/8 accept")
	mustContain(t, joined, "ip daddr @sl_ru accept")
	assertDropIsLast(t, cmds)
}

// ---------------------------------------------------------------------------
// Task 4 — Linux iptables formatter (ipset degradation)
// ---------------------------------------------------------------------------

func TestLinuxIPTables_Split_NoIpset_DegradesToLANOnly(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = true
	cfg.BypassRanges = []netip.Prefix{netip.MustParsePrefix("77.88.0.0/18")}
	cmds := linuxIPTablesCommands(BuildKillSwitchPlan(cfg, true), false /*ipsetAvailable*/)
	joined := joinCmds(cmds)
	mustContain(t, joined, "192.168.0.0/16")  // LAN still allowed
	mustNotContain(t, joined, "77.88.0.0/18") // RU dropped (no ipset)
	assertDropIsLast(t, cmds)
}

func TestLinuxIPTables_Split_WithIpset_UsesMatchSet(t *testing.T) {
	cfg := baseCfg()
	cfg.SplitTunnel = true
	cfg.BypassRanges = []netip.Prefix{netip.MustParsePrefix("77.88.0.0/18")}
	cmds := linuxIPTablesCommands(BuildKillSwitchPlan(cfg, true), true)
	joined := joinCmds(cmds)
	mustContain(t, joined, "match-set sl_ru dst")
	mustContain(t, joined, "77.88.0.0/18")
	assertDropIsLast(t, cmds)
}

// ---------------------------------------------------------------------------
// Task 9 — Linux IPv6 default/per-iface + resolv.conf symlink awareness
// ---------------------------------------------------------------------------

func TestLinuxIPv6Sysctls_CoversAllAndDefault(t *testing.T) {
	keys := ipv6DisableSysctlKeys([]string{"eth0", "wlan0"})
	joined := strings.Join(keys, "\n")
	mustContain(t, joined, "net.ipv6.conf.all.disable_ipv6")
	mustContain(t, joined, "net.ipv6.conf.default.disable_ipv6")
	mustContain(t, joined, "net.ipv6.conf.eth0.disable_ipv6")
	mustContain(t, joined, "net.ipv6.conf.wlan0.disable_ipv6")
}

func TestResolvConfPlan_Symlink_DoesNotOverwriteTarget(t *testing.T) {
	plan := resolvConfWritePlan(true /*isSymlink*/, "/run/systemd/resolve/stub-resolv.conf")
	if plan.overwrite {
		t.Fatalf("must NOT overwrite symlink target")
	}
	if !plan.useResolvectl {
		t.Fatalf("symlink → managed by resolved/NM, use resolvectl")
	}
}

func TestResolvConfPlan_RegularFile_Overwrites(t *testing.T) {
	plan := resolvConfWritePlan(false, "")
	if !plan.overwrite {
		t.Fatalf("regular file must be overwritable")
	}
	if plan.useResolvectl {
		t.Fatalf("regular file → write directly, not resolvectl")
	}
}

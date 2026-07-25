//go:build windows

package leakguard

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureLogs redirects the default slog logger into a buffer for the duration
// of the test so Warn/Debug paths can be asserted.
func captureLogs(t *testing.T) *strings.Builder {
	t.Helper()
	var sb strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&sb, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &sb
}

// fastTunRetries shrinks the LG-M1 retry pause so tests stay instant.
func fastTunRetries(t *testing.T) {
	t.Helper()
	prev := tunResolveRetryDelay
	tunResolveRetryDelay = 0
	t.Cleanup(func() { tunResolveRetryDelay = prev })
}

// psDNSCSVPair mimics Get-DnsClientServerAddress output with one static and
// one DHCP interface.
const psDNSCSVPair = "\"InterfaceIndex\",\"ServerAddresses\"\r\n" +
	"\"12\",\"{10.0.0.1}\"\r\n" +
	"\"23\",\"{}\"\r\n"

// ---------------------------------------------------------------------------
// LG-M1 — transient net.InterfaceByName failure must not clobber the TUN DNS
// ---------------------------------------------------------------------------

// A transient resolve failure (Wintun rename race) recovers via retries: the
// TUN index is found on a later attempt and the TUN is still skipped.
func TestSetDNS_TransientResolveFail_RetriesAndSkipsTun(t *testing.T) {
	fastTunRetries(t)
	fake := &fakeRunner{}
	calls := 0
	g := &windowsGuard{runner: fake, ifaceByName: func(name string) (*net.Interface, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("transient: interface renaming")
		}
		return &net.Interface{Index: 23, Name: name}, nil
	}}
	backup := DNSBackup{Entries: []DNSEntry{
		{InterfaceName: "12"},
		{InterfaceName: "23"},
	}}
	g.setDNS(backup, "NixaVPN", true)

	if calls != 3 {
		t.Fatalf("expected 3 resolve attempts, got %d", calls)
	}
	got := fake.dnsSetIfaces()
	for _, idx := range got {
		if idx == "23" {
			t.Fatalf("TUN iface 23 must NOT be forced after transient-fail-then-success; got=%v", got)
		}
	}
	if len(got) != 1 || got[0] != "12" {
		t.Fatalf("physical NIC 12 must be the only forced iface; got=%v", got)
	}
}

// A permanent resolve failure keeps the fail-secure behaviour (force DNS on
// ALL interfaces — we cannot identify the TUN) but must be LOUD: a Warn, not
// the old silent Debug-only path.
func TestSetDNS_PermanentResolveFail_ForcesAllAndWarns(t *testing.T) {
	fastTunRetries(t)
	logs := captureLogs(t)
	fake := &fakeRunner{}
	calls := 0
	g := &windowsGuard{runner: fake, ifaceByName: func(string) (*net.Interface, error) {
		calls++
		return nil, errors.New("permanent failure")
	}}
	backup := DNSBackup{Entries: []DNSEntry{
		{InterfaceName: "12"},
		{InterfaceName: "23"},
	}}
	g.setDNS(backup, "NixaVPN", true)

	if calls != tunResolveAttempts {
		t.Fatalf("expected %d resolve attempts, got %d", tunResolveAttempts, calls)
	}
	got := fake.dnsSetIfaces()
	if len(got) != 2 {
		t.Fatalf("fail-secure: ALL ifaces must be forced when the TUN cannot be identified; got=%v", got)
	}
	out := logs.String()
	if !strings.Contains(out, "WARN") || !strings.Contains(out, "NixaVPN") {
		t.Fatalf("permanent TUN resolve failure must log a Warn naming the TUN; logs=%q", out)
	}
}

// PreLock path (expectTun=false): the TUN is known not to exist yet — a single
// resolve attempt, no retries, no Warn (expected condition, not a failure).
func TestSetDNS_NotExpectTun_SingleAttemptNoWarn(t *testing.T) {
	fastTunRetries(t)
	logs := captureLogs(t)
	fake := &fakeRunner{}
	calls := 0
	g := &windowsGuard{runner: fake, ifaceByName: func(string) (*net.Interface, error) {
		calls++
		return nil, errors.New("no such interface")
	}}
	g.setDNS(DNSBackup{Entries: []DNSEntry{{InterfaceName: "12"}}}, "NixaVPN", false)

	if calls != 1 {
		t.Fatalf("PreLock path must resolve exactly once, got %d attempts", calls)
	}
	if strings.Contains(logs.String(), "WARN") {
		t.Fatalf("PreLock path must not Warn on the expected pre-TUN resolve failure; logs=%q", logs.String())
	}
}

// ---------------------------------------------------------------------------
// LG-M2 — preLocked Enable must never touch DNS (forwarder protection)
// ---------------------------------------------------------------------------

// In production main.go always calls PreLock first; Enable's preLocked branch
// is what protects the split-DNS forwarder's TUN DNS. Pin it: ZERO DNS reads
// or writes during a preLocked Enable.
func TestEnable_PreLocked_DoesNotTouchDNS(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leakguard.state")
	prevBackup := DNSBackup{Entries: []DNSEntry{{InterfaceName: "12", Servers: []string{"10.0.0.1"}}}}
	if err := SaveState(statePath, &State{
		Platform:   "windows",
		DNSBackup:  prevBackup,
		IPv6Backup: IPv6Backup{DisabledInterfaces: []string{"14"}},
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	fake := &fakeRunner{outputs: map[string]string{"Get-NetFirewallProfile": fwProfilesCSV}}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}, preLocked: true}
	if err := g.Enable(baseCfg()); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	for _, c := range fake.calls {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "Set-DnsClientServerAddress") {
			t.Fatalf("preLocked Enable must NOT write DNS (forwarder protection); call=%q", joined)
		}
		if strings.Contains(joined, "Get-DnsClientServerAddress") {
			t.Fatalf("preLocked Enable must NOT re-read DNS (backups come from PreLock state); call=%q", joined)
		}
	}

	// The PreLock backups must be carried into the persisted state (both the
	// mid-way checkpoint and the final save use the same state value).
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(state.DNSBackup.Entries) != 1 || state.DNSBackup.Entries[0].InterfaceName != "12" {
		t.Fatalf("PreLock DNS backup must be preserved; got=%+v", state.DNSBackup)
	}
	if len(state.IPv6Backup.DisabledInterfaces) != 1 || state.IPv6Backup.DisabledInterfaces[0] != "14" {
		t.Fatalf("PreLock IPv6 backup must be preserved; got=%+v", state.IPv6Backup)
	}
}

// Symmetric pin: a NON-preLocked Enable DOES force DNS — but skips the TUN
// index (shouldSkipDNSIface) so even the hypothetical direct-Enable path
// cannot clobber the forwarder.
func TestEnable_NotPreLocked_ForcesDNSButSkipsTun(t *testing.T) {
	fastTunRetries(t)
	statePath := filepath.Join(t.TempDir(), "leakguard.state")
	fake := &fakeRunner{outputs: map[string]string{
		"Get-NetFirewallProfile":     fwProfilesCSV,
		"Get-DnsClientServerAddress": psDNSCSVPair,
	}}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{},
		ifaceByName: func(name string) (*net.Interface, error) {
			return &net.Interface{Index: 23, Name: name}, nil
		}}
	if err := g.Enable(baseCfg()); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	if !fake.called("Get-DnsClientServerAddress") {
		t.Fatalf("non-preLocked Enable must back up DNS; calls=%v", fake.calls)
	}
	got := fake.dnsSetIfaces()
	if len(got) != 1 || got[0] != "12" {
		t.Fatalf("non-preLocked Enable must force the physical NIC 12 and skip TUN 23; got=%v", got)
	}
}

// ---------------------------------------------------------------------------
// LG-M3 — preLocked Enable with a corrupt state file must not persist empty
// backups (permanent stuck-at-1.1.1.1 damage)
// ---------------------------------------------------------------------------

// ipv6ShowOutput mimics `netsh interface ipv6 show interface` (3 header lines).
const ipv6ShowOutput = "Idx     Met         MTU          State                Name\r\n" +
	"---  ----------  ----------  ------------  ---------------------------\r\n" +
	"\r\n" +
	"  1          75  4294967295  connected     Loopback Pseudo-Interface 1\r\n" +
	" 14          25        1500  connected     Ethernet\r\n"

// psDNSCSVPostPreLock is what Get-DnsClientServerAddress returns AFTER PreLock
// already forced the safe DNS: iface 12 carries our forced pair (original
// value unrecoverable), iface 30 carries a value PreLock never touched.
const psDNSCSVPostPreLock = "\"InterfaceIndex\",\"ServerAddresses\"\r\n" +
	"\"12\",\"{1.1.1.1, 8.8.8.8}\"\r\n" +
	"\"30\",\"{192.168.1.1}\"\r\n"

func TestEnable_PreLocked_CorruptState_RebuildsBackupsNotEmpty(t *testing.T) {
	logs := captureLogs(t)
	statePath := filepath.Join(t.TempDir(), "leakguard.state")
	if err := os.WriteFile(statePath, []byte("not json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	fake := &fakeRunner{outputs: map[string]string{
		"Get-NetFirewallProfile":     fwProfilesCSV,
		"Get-DnsClientServerAddress": psDNSCSVPostPreLock,
		"ipv6 show interface":        ipv6ShowOutput,
	}}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}, preLocked: true}
	if err := g.Enable(baseCfg()); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	if !strings.Contains(logs.String(), "WARN") {
		t.Fatalf("losing the PreLock backups must be LOUD; logs=%q", logs.String())
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(state.DNSBackup.Entries) == 0 {
		t.Fatalf("state file must NOT be overwritten with an empty DNS backup")
	}
	byIdx := map[string][]string{}
	for _, e := range state.DNSBackup.Entries {
		byIdx[e.InterfaceName] = e.Servers
	}
	// Iface 12 read back our own forced pair — keeping it as "backup" would pin
	// 1.1.1.1 forever; it must be blanked so restore resets to DHCP.
	if servers, ok := byIdx["12"]; !ok || len(servers) != 0 {
		t.Fatalf("forced-pair entry must be blanked to DHCP-reset semantics; got=%v", byIdx)
	}
	// Iface 30 was never forced — its current value IS the original, keep it.
	if servers := byIdx["30"]; len(servers) != 1 || servers[0] != "192.168.1.1" {
		t.Fatalf("untouched entry must be preserved verbatim; got=%v", byIdx)
	}
	// IPv6 list rebuilt via the idempotent re-disable.
	if len(state.IPv6Backup.DisabledInterfaces) != 1 || state.IPv6Backup.DisabledInterfaces[0] != "14" {
		t.Fatalf("IPv6 backup must be rebuilt (Ethernet idx 14); got=%+v", state.IPv6Backup)
	}
}

// Pure-function pin for the recovery sanitiser.
func TestSanitizeRecoveryDNSBackup(t *testing.T) {
	in := DNSBackup{Entries: []DNSEntry{
		{InterfaceName: "12", Servers: []string{"1.1.1.1", "8.8.8.8"}}, // our force → blank
		{InterfaceName: "30", Servers: []string{"192.168.1.1"}},        // untouched → keep
		{InterfaceName: "31"},                                          // DHCP → keep empty
		{InterfaceName: "32", Servers: []string{"1.1.1.1"}},            // partial ≠ force → keep
	}}
	out := sanitizeRecoveryDNSBackup(in)
	if len(out.Entries) != 4 {
		t.Fatalf("entry count must be preserved; got=%+v", out)
	}
	if len(out.Entries[0].Servers) != 0 {
		t.Fatalf("forced pair must be blanked; got=%v", out.Entries[0].Servers)
	}
	if len(out.Entries[1].Servers) != 1 || out.Entries[1].Servers[0] != "192.168.1.1" {
		t.Fatalf("untouched servers must be kept; got=%v", out.Entries[1].Servers)
	}
	if len(out.Entries[3].Servers) != 1 || out.Entries[3].Servers[0] != "1.1.1.1" {
		t.Fatalf("non-exact match must be kept verbatim; got=%v", out.Entries[3].Servers)
	}
}

// ---------------------------------------------------------------------------
// LG-L1 — restoreDNS must not push forwarder-range servers onto a (possibly
// foreign) adapter: Windows reuses interface indices
// ---------------------------------------------------------------------------

func TestRestoreDNS_SkipsForwarderRangeEntries(t *testing.T) {
	logs := captureLogs(t)
	fake := &fakeRunner{}
	g := &windowsGuard{runner: fake}
	g.restoreDNS(DNSBackup{Entries: []DNSEntry{
		{InterfaceName: "7", Servers: []string{"198.18.0.1"}},             // forwarder → skip
		{InterfaceName: "8", Servers: []string{"198.19.0.5"}},             // /15 upper half → skip
		{InterfaceName: "9", Servers: []string{"8.8.8.8"}},                // restore
		{InterfaceName: "11"},                                             // DHCP → reset
		{InterfaceName: "12", Servers: []string{"198.18.0.1", "8.8.8.8"}}, // mixed → restore (not ⊆ range)
	}})

	for _, c := range fake.calls {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "-InterfaceIndex 7 ") || strings.HasSuffix(joined, "-InterfaceIndex 7") {
			t.Fatalf("forwarder-range entry 7 must be skipped; call=%q", joined)
		}
		if strings.Contains(joined, "-InterfaceIndex 8 ") || strings.HasSuffix(joined, "-InterfaceIndex 8") {
			t.Fatalf("forwarder-range entry 8 must be skipped; call=%q", joined)
		}
	}
	if !fake.called("Set-DnsClientServerAddress -InterfaceIndex 9 -ServerAddresses 8.8.8.8") {
		t.Fatalf("normal entry 9 must be restored; calls=%v", fake.calls)
	}
	if !fake.called("Set-DnsClientServerAddress -InterfaceIndex 11 -ResetServerAddresses") {
		t.Fatalf("DHCP entry 11 must be reset; calls=%v", fake.calls)
	}
	if !fake.called("Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses 198.18.0.1,8.8.8.8") {
		t.Fatalf("mixed entry 12 must be restored verbatim; calls=%v", fake.calls)
	}
	if !strings.Contains(logs.String(), "WARN") {
		t.Fatalf("skipping a forwarder-range entry must Warn; logs=%q", logs.String())
	}
}

func TestIsForwarderOnlyDNSEntry(t *testing.T) {
	cases := []struct {
		servers []string
		want    bool
	}{
		{[]string{"198.18.0.1"}, true},
		{[]string{"198.19.255.254"}, true},
		{[]string{"198.18.0.1", "198.18.0.2"}, true},
		{[]string{"198.20.0.1"}, false}, // outside /15
		{[]string{"8.8.8.8"}, false},
		{[]string{"198.18.0.1", "8.8.8.8"}, false}, // mixed → not forwarder-only
		{nil, false},                               // empty = DHCP, not forwarder
		{[]string{"garbage"}, false},               // unparseable → restore as-is
	}
	for _, tc := range cases {
		if got := isForwarderOnlyDNSEntry(tc.servers); got != tc.want {
			t.Errorf("isForwarderOnlyDNSEntry(%v)=%v want %v", tc.servers, got, tc.want)
		}
	}
}

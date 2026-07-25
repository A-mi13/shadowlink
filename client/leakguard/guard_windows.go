//go:build windows

package leakguard

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// cmdRunner abstracts external command execution so guard logic can be mocked.
type cmdRunner interface {
	run(name string, args ...string) (string, error)
}

// realRunner executes commands for real.
type realRunner struct{}

func (realRunner) run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// windowsGuard implements LeakGuard for Windows using netsh, PowerShell DNS,
// Windows Firewall (deny-by-default outbound policy + allow rules, LG-H1) and
// WFP (RU CIDR split-tunnel).
type windowsGuard struct {
	statePath string
	runner    cmdRunner
	wfp       wfpEngine
	preLocked bool // PreLock already applied DNS+IPv6 → Enable must not redo them

	// ifaceByName is the LG-M1 test seam for TUN interface resolution.
	// nil → net.InterfaceByName.
	ifaceByName func(name string) (*net.Interface, error)
}

// New returns a platform-specific LeakGuard implementation.
// statePath is used for crash-recovery state persistence.
//
// C3-b/H1: New() performs crash recovery (remove SL-* rules + WFP filters,
// restore the default firewall policy and DNS/IPv6) BEFORE returning, so a
// previous crash with an active kill switch does not leave the system
// offline / deadlocked on startup.
func New(statePath string) (LeakGuard, error) {
	g := &windowsGuard{statePath: statePath, runner: realRunner{}, wfp: newWFPEngine()}
	if StateExists(statePath) {
		slog.Warn("leakguard: found stale state file, performing crash recovery", "path", statePath)
		if err := g.crashRecover(); err != nil {
			slog.Error("leakguard: crash recovery failed", "err", err)
		}
	}
	return g, nil
}

// PreLock applies DNS + IPv6 protection BEFORE the TUN comes up (H2), closing
// the leak window between tun.Start() and Enable(). Idempotent.
func (g *windowsGuard) PreLock(cfg LeakGuardConfig) error {
	if g.preLocked {
		return nil
	}
	var state State
	state.EnabledAt = time.Now().UTC()
	state.Platform = "windows"

	dnsBackup, err := g.backupDNS()
	if err != nil {
		slog.Warn("leakguard: pre-lock DNS backup failed, continuing", "error", err)
	}
	state.DNSBackup = dnsBackup
	// expectTun=false: PreLock runs before tun.Start — the TUN does not exist
	// yet, an unresolvable name is normal (no retries, no Warn).
	g.setDNS(dnsBackup, cfg.TunName, false)

	ipv6Backup, err := g.disableIPv6(cfg.TunName)
	if err != nil {
		slog.Warn("leakguard: pre-lock disable IPv6 failed", "error", err)
	}
	state.IPv6Backup = ipv6Backup

	// Persist partial state so a crash between PreLock and Enable is recoverable.
	if err := SaveState(g.statePath, &state); err != nil {
		slog.Warn("leakguard: pre-lock save state failed", "error", err)
	}
	g.preLocked = true
	slog.Info("leakguard: pre-lock applied (DNS+IPv6)")
	return nil
}

// Enable activates DNS, IPv6 and kill-switch protection.
func (g *windowsGuard) Enable(cfg LeakGuardConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	var state State
	state.EnabledAt = time.Now().UTC()
	state.Platform = "windows"
	state.SplitTunnel = cfg.SplitTunnel

	if g.preLocked {
		// PreLock already applied DNS+IPv6 and saved their backups — reuse them.
		if prev, err := LoadState(g.statePath); err == nil {
			state.DNSBackup = prev.DNSBackup
			state.IPv6Backup = prev.IPv6Backup
		} else {
			// LG-M3: the PreLock backups are LOST (state file corrupted/deleted
			// between PreLock and Enable). Silently continuing with empty backups
			// would let the SaveState below overwrite the state file with nothing
			// to restore — physical NICs pinned to 1.1.1.1,8.8.8.8 and IPv6
			// disabled FOREVER after Disable/crashRecover. Rebuild least-bad
			// backups instead:
			//   DNS — fresh read, sanitized: entries showing our own forced pair
			//   are blanked (→ DHCP reset on restore; the true original is gone),
			//   anything else is kept verbatim (PreLock didn't touch it).
			//   IPv6 — re-run the idempotent disable to recapture the interface
			//   list (same semantics as the PreLock pass).
			slog.Warn("leakguard: PreLock state unreadable — original DNS/IPv6 backups lost; rebuilding least-bad recovery backups (forced DNS will restore to DHCP)",
				"error", err)
			dnsBackup, derr := g.backupDNS()
			if derr != nil {
				slog.Warn("leakguard: recovery DNS backup failed", "error", derr)
			}
			state.DNSBackup = sanitizeRecoveryDNSBackup(dnsBackup)
			ipv6Backup, ierr := g.disableIPv6(cfg.TunName)
			if ierr != nil {
				slog.Warn("leakguard: recovery IPv6 re-disable failed", "error", ierr)
			}
			state.IPv6Backup = ipv6Backup
		}
	} else {
		dnsBackup, err := g.backupDNS()
		if err != nil {
			slog.Warn("leakguard: failed to backup DNS, continuing", "error", err)
		}
		state.DNSBackup = dnsBackup
		// expectTun=true: Enable runs after tun.Start — the TUN must resolve;
		// LG-M1 retries + loud Warn protect the split-DNS forwarder's TUN DNS.
		g.setDNS(dnsBackup, cfg.TunName, true)

		ipv6Backup, err := g.disableIPv6(cfg.TunName)
		if err != nil {
			slog.Warn("leakguard: failed to disable IPv6", "error", err)
		}
		state.IPv6Backup = ipv6Backup
	}

	// Kill switch (netsh allow rules + blockoutbound default policy) + WFP
	// (RU split). enableKillSwitch persists a CHECKPOINT state (rules + policy
	// backup) BEFORE arming the policy, so a crash inside the arming window is
	// always recoverable; the final SaveState below only refreshes WFPActive.
	if err := g.enableKillSwitch(cfg, &state); err != nil {
		slog.Error("leakguard: kill switch failed, rolling back", "error", err)
		_ = g.wfp.DeleteByProvider()
		g.restoreIPv6(state.IPv6Backup)
		g.restoreDNS(state.DNSBackup)
		g.flushDNS()
		return fmt.Errorf("leakguard: enable kill switch: %w", err)
	}

	if err := SaveState(g.statePath, &state); err != nil {
		// Non-fatal: the pre-arm checkpoint already carries the rules and the
		// policy backup; only WFPActive may be stale, and crash recovery calls
		// wfp.DeleteByProvider unconditionally anyway.
		slog.Warn("leakguard: failed to save state", "error", err)
	}

	slog.Info("leakguard enabled", "split_tunnel", cfg.SplitTunnel, "wfp", state.WFPActive)
	return nil
}

// Disable removes all protections and restores original settings.
func (g *windowsGuard) Disable() error {
	if !StateExists(g.statePath) {
		slog.Warn("leakguard: no state file, attempting cleanup by rule names")
		g.removeKillSwitchByName()
		// No backup available — un-stick a possibly armed blockoutbound policy
		// via the factory default (Warn inside; never leave the network dead).
		g.restoreFirewallPolicy(nil)
		_ = g.wfp.DeleteByProvider()
		return nil
	}

	state, err := LoadState(g.statePath)
	if err != nil {
		slog.Warn("leakguard: corrupt state file, attempting cleanup by rule names", "error", err)
		g.removeKillSwitchByName()
		g.restoreFirewallPolicy(nil)
		_ = g.wfp.DeleteByProvider()
		_ = DeleteState(g.statePath)
		return nil
	}

	g.removeKillSwitchRules(state.KillSwitch.Rules)
	g.restorePolicyFromState(state)
	_ = g.wfp.DeleteByProvider()
	g.restoreIPv6(state.IPv6Backup)
	g.restoreDNS(state.DNSBackup)
	g.flushDNS()

	if err := DeleteState(g.statePath); err != nil {
		slog.Warn("leakguard: failed to delete state", "error", err)
	}

	slog.Info("leakguard disabled")
	return nil
}

// crashRecover removes a stale kill switch (netsh SL-* + WFP) and restores
// DNS/IPv6 BEFORE any network activity. C3-b/H1.
func (g *windowsGuard) crashRecover() error {
	state, err := LoadState(g.statePath)
	if err != nil {
		// Corrupt/unreadable: best-effort blind cleanup by names + WFP provider.
		// The policy may still be blockoutbound from before the crash — without
		// a backup, fall back to the factory default (never leave it stuck).
		g.removeKillSwitchByName()
		g.restoreFirewallPolicy(nil)
		_ = g.wfp.DeleteByProvider()
		_ = DeleteState(g.statePath)
		return nil
	}
	g.removeKillSwitchRules(state.KillSwitch.Rules)
	g.removeKillSwitchByName() // подстраховка (netsh)
	g.restorePolicyFromState(state)
	_ = g.wfp.DeleteByProvider()
	g.restoreIPv6(state.IPv6Backup)
	g.restoreDNS(state.DNSBackup)
	g.flushDNS()
	_ = DeleteState(g.statePath)
	return nil
}

// ---------------------------------------------------------------------------
// DNS helpers — locale-independent via PowerShell (L1) + DHCP ifaces (L2)
// ---------------------------------------------------------------------------

// backupDNS captures current DNS servers per interface via PowerShell so it is
// locale-independent (numeric InterfaceIndex). Includes DHCP interfaces (empty
// Servers) so they are restored to DHCP later.
func (g *windowsGuard) backupDNS() (DNSBackup, error) {
	out, err := g.runner.run("powershell", "-NoProfile", "-Command",
		"Get-DnsClientServerAddress -AddressFamily IPv4 | "+
			"Select-Object InterfaceIndex,ServerAddresses | "+
			"ConvertTo-Csv -NoTypeInformation")
	if err == nil {
		entries := parsePSGetDns(out)
		if len(entries) > 0 {
			return DNSBackup{Entries: entries}, nil
		}
	}
	// Fallback: legacy netsh parser (best-effort; should not happen on modern Windows).
	slog.Warn("leakguard: PowerShell DNS backup unavailable, falling back to netsh", "error", err)
	return g.backupDNSNetshFallback()
}

// shouldSkipDNSIface reports whether the interface identified by entryIdx must
// be excluded from the safe-DNS force. The TUN interface is owned by the
// split-DNS forwarder (its address is set as the TUN DNS server); forcing
// 1.1.1.1/8.8.8.8 onto it would clobber the forwarder and break split-DNS.
// An empty tunIdx (TUN not yet resolvable) means "skip nothing" — see setDNS.
func shouldSkipDNSIface(entryIdx, tunIdx string) bool {
	return tunIdx != "" && entryIdx == tunIdx
}

// safeDNSServerList is the safe-DNS pair setDNS pins on every non-TUN
// interface. Single source of truth: sanitizeRecoveryDNSBackup compares
// against the exact same value to recognise "this read-back is our own force,
// not the user's original".
const safeDNSServerList = "1.1.1.1,8.8.8.8"

// LG-M1: TUN resolve retry budget. A transient net.InterfaceByName failure
// (Wintun rename race — same TOCTOU precedent as tun2socks/tunnel.go) must not
// silently degrade into "skip nothing" and clobber the forwarder's TUN DNS.
const tunResolveAttempts = 3

// Var (not const) so tests can shrink the pause.
var tunResolveRetryDelay = 250 * time.Millisecond

// resolveTunIndex resolves the TUN interface name to its numeric index.
//
// expectTun=true (Enable after tun.Start): the TUN MUST exist — a resolve
// failure is retried (short pauses, mirrors the startSplitDNS bind-retry
// pattern) and a permanent failure is LOUD (Warn): the caller will fall back
// to forcing safe DNS on ALL interfaces, which keeps the kill-switch
// fail-secure but kills split-DNS arbitration (plaintext DNS shows on the
// exit node) — over-block beats fail-functional, but it must be visible.
//
// expectTun=false (PreLock, before tun.Start): the TUN is known not to exist
// yet; a single attempt, Debug only — forcing the (future) TUN is moot since
// the forwarder is not up yet.
//
// Hook for a stronger fix: callers that already know the TUN interface index
// (main.go resolves the adapter right after tun.Start) could thread it into
// LeakGuardConfig and bypass the by-name resolve entirely; not done in this
// block to keep the config surface stable.
func (g *windowsGuard) resolveTunIndex(tunName string, expectTun bool) string {
	if tunName == "" {
		return ""
	}
	resolve := g.ifaceByName
	if resolve == nil {
		resolve = net.InterfaceByName
	}
	attempts := 1
	if expectTun {
		attempts = tunResolveAttempts
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(tunResolveRetryDelay)
		}
		iface, err := resolve(tunName)
		if err == nil {
			return strconv.Itoa(iface.Index)
		}
		lastErr = err
	}
	if expectTun {
		slog.Warn("leakguard: TUN interface resolve failed — forcing safe DNS on ALL interfaces (fail-secure; split-DNS forwarder DNS on the TUN will be clobbered)",
			"tun", tunName, "attempts", attempts, "error", lastErr)
	} else {
		slog.Debug("leakguard: TUN not resolvable (expected before tun.Start)", "tun", tunName, "error", lastErr)
	}
	return ""
}

// setDNS sets safe DNS on ALL active IPv4 interfaces by numeric index (incl.
// DHCP interfaces — L2 fix), EXCEPT the TUN interface when it is resolvable.
//
// The TUN interface is skipped because the split-DNS forwarder installs its
// own address as the TUN DNS server; forcing 1.1.1.1/8.8.8.8 there would
// overwrite the forwarder and break split-DNS resolution. Physical NICs are
// still forced — their DNS queries are captured by the 0/1+128/1 split route
// into the tunnel and reach the forwarder (or the server) via TUN, so they do
// not break the forwarder.
//
// expectTun communicates whether the TUN is supposed to exist at this point:
// PreLock passes false (runs before tun.Start — empty tunIdx is normal, no
// skip, harmless because the forwarder is not up yet); a direct Enable passes
// true (TUN must resolve → LG-M1 retries + loud Warn on permanent failure).
func (g *windowsGuard) setDNS(backup DNSBackup, tunName string, expectTun bool) {
	tunIdx := g.resolveTunIndex(tunName, expectTun)
	for _, entry := range backup.Entries {
		idx := entry.InterfaceName
		if idx == "" {
			continue
		}
		if shouldSkipDNSIface(idx, tunIdx) {
			slog.Debug("leakguard: skip TUN iface in setDNS (split-DNS forwarder owns it)", "idx", tunIdx)
			continue
		}
		if _, err := g.runner.run("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddresses %s", idx, safeDNSServerList)); err != nil {
			// A physical NIC that keeps its original (ISP) DNS under the armed
			// guard is a potential plaintext-DNS signal — loud, not Debug.
			slog.Warn("leakguard: set dns failed", "iface", idx, "error", err)
		}
	}
	g.flushDNS()
}

// forwarderDNSRange is the split-DNS forwarder address space (matches the TUN
// subnet / SL-Allow-TUN localip). A backup entry whose servers all live here
// was captured on a TUN interface, not a physical NIC.
var forwarderDNSRange = netip.MustParsePrefix("198.18.0.0/15")

// isForwarderOnlyDNSEntry reports whether ALL servers of a backup entry lie in
// 198.18.0.0/15 — i.e. the entry is our own forwarder address captured on a
// TUN that no longer exists. Empty/unparseable servers → false (restore as-is:
// empty means DHCP reset, unparseable means "not provably ours").
func isForwarderOnlyDNSEntry(servers []string) bool {
	if len(servers) == 0 {
		return false
	}
	for _, s := range servers {
		addr, err := netip.ParseAddr(s)
		if err != nil || !forwarderDNSRange.Contains(addr) {
			return false
		}
	}
	return true
}

// sanitizeRecoveryDNSBackup converts a FRESH post-PreLock DNS read into the
// least-bad restorable backup for the LG-M3 recovery path (preLocked Enable
// lost the real PreLock backup to a corrupt/missing state file):
//
//   - an entry that reads back exactly our safe-DNS force (1.1.1.1,8.8.8.8)
//     is our own pin — keeping it as "backup" would restore the pin forever
//     (stuck at 1.1.1.1). The true original is unrecoverable, so the servers
//     are blanked: restoreDNS turns empty Servers into -ResetServerAddresses
//     (DHCP). Static-DNS originals are lost, but the host is never stuck.
//   - any other value means PreLock did not touch the interface (or the user
//     changed it since) — its current value IS the best original we have:
//     keep it verbatim.
func sanitizeRecoveryDNSBackup(b DNSBackup) DNSBackup {
	out := DNSBackup{Entries: make([]DNSEntry, 0, len(b.Entries))}
	for _, e := range b.Entries {
		if isSafeDNSForcePair(e.Servers) {
			e.Servers = nil
		}
		out.Entries = append(out.Entries, e)
	}
	return out
}

// isSafeDNSForcePair reports whether servers is exactly the safe-DNS force
// pair, in any order — PowerShell does not guarantee enumeration order, and an
// order-sensitive compare would let our own pin survive as a "backup".
func isSafeDNSForcePair(servers []string) bool {
	if len(servers) != 2 {
		return false
	}
	want := strings.Split(safeDNSServerList, ",")
	return (servers[0] == want[0] && servers[1] == want[1]) ||
		(servers[0] == want[1] && servers[1] == want[0])
}

// restoreDNS restores DNS from backup: empty Servers → reset to DHCP, else set
// the recorded servers. Targets numeric InterfaceIndex (locale-independent).
//
// LG-L1: entries whose servers all lie in 198.18.0.0/15 are skipped with a
// Warn — that is our forwarder address captured on a TUN interface that no
// longer exists, and Windows reuses interface indices: pushing it onto
// whatever adapter now owns that index would break a foreign NIC's DNS.
//
// Empty-BACKUP semantics (LG-M3 decision): a backup with zero entries restores
// nothing — deliberately. setDNS forces exactly the interfaces listed in the
// backup it is given, so an empty backup means nothing was forced and a no-op
// restore is correct. The dangerous case (backups lost AFTER a force) is
// handled upstream: the preLocked Enable recovery branch always persists a
// non-empty sanitized backup (see sanitizeRecoveryDNSBackup), never an empty
// one. Blanket-resetting all interfaces here on an empty backup would clobber
// user static DNS in the common "we never touched DNS" case.
func (g *windowsGuard) restoreDNS(backup DNSBackup) {
	for _, entry := range backup.Entries {
		idx := entry.InterfaceName
		if idx == "" {
			continue
		}
		if isForwarderOnlyDNSEntry(entry.Servers) {
			slog.Warn("leakguard: skip DNS restore for forwarder-range entry — stale TUN index, Windows reuses indices (restoring could hit a foreign adapter)",
				"iface", idx, "servers", entry.Servers)
			continue
		}
		var cmd string
		if len(entry.Servers) == 0 {
			cmd = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %s -ResetServerAddresses", idx)
		} else {
			cmd = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddresses %s",
				idx, strings.Join(entry.Servers, ","))
		}
		if _, err := g.runner.run("powershell", "-NoProfile", "-Command", cmd); err != nil {
			slog.Warn("leakguard: restore dns failed", "iface", idx, "error", err)
		}
	}
}

// flushDNS runs ipconfig /flushdns.
func (g *windowsGuard) flushDNS() {
	if _, err := g.runner.run("ipconfig", "/flushdns"); err != nil {
		slog.Warn("leakguard: flush dns failed", "error", err)
	}
}

// backupDNSNetshFallback is the legacy locale-dependent parser, kept only as a
// last-resort fallback when PowerShell is unavailable.
func (g *windowsGuard) backupDNSNetshFallback() (DNSBackup, error) {
	out, err := g.runner.run("netsh", "interface", "ip", "show", "dns")
	if err != nil {
		return DNSBackup{}, fmt.Errorf("netsh show dns: %w: %s", err, out)
	}
	var backup DNSBackup
	var current *DNSEntry
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Configuration for interface") {
			if current != nil && len(current.Servers) > 0 {
				backup.Entries = append(backup.Entries, *current)
			}
			name := extractQuoted(line)
			if name != "" {
				current = &DNSEntry{InterfaceName: name}
			} else {
				current = nil
			}
			continue
		}
		if current == nil {
			continue
		}
		if strings.Contains(line, "DNS") && strings.Contains(line, "configured") {
			continue
		}
		if ip := extractIP(line); ip != "" {
			current.Servers = append(current.Servers, ip)
		}
	}
	if current != nil && len(current.Servers) > 0 {
		backup.Entries = append(backup.Entries, *current)
	}
	return backup, nil
}

// ---------------------------------------------------------------------------
// IPv6 helpers
// ---------------------------------------------------------------------------

// disableIPv6 disables IPv6 on all interfaces except the TUN and Loopback.
//
// LG-L2 invariant — deliberate IPv6 asymmetry: the TUN is exempted from the
// disable, but NO firewall permit covers v6-over-TUN (SL-Allow-TUN is an IPv4
// localip rule, 198.18.0.0/15) and backupDNS is IPv4-only. v6 through the TUN
// is therefore blocked by the deny-by-default outbound policy — fail-secure by
// design. If v6 transport is ever enabled, add an SL-Allow-TUN-v6 permit AND
// an IPv6 DNS backup/restore path in lockstep (see windowsFirewallRules).
func (g *windowsGuard) disableIPv6(tunName string) (IPv6Backup, error) {
	var backup IPv6Backup
	out, err := g.runner.run("netsh", "interface", "ipv6", "show", "interface")
	if err != nil {
		return backup, fmt.Errorf("netsh ipv6 show interface: %w: %s", err, out)
	}
	indices := parseIPv6Interfaces(out, tunName)
	for _, idx := range indices {
		if out, err := g.runner.run("netsh", "interface", "ipv6", "set", "interface", idx, "disabled"); err != nil {
			slog.Warn("leakguard: disable ipv6 failed", "index", idx, "error", err, "output", out)
			continue
		}
		backup.DisabledInterfaces = append(backup.DisabledInterfaces, idx)
	}
	return backup, nil
}

// restoreIPv6 re-enables IPv6 on previously disabled interfaces.
func (g *windowsGuard) restoreIPv6(backup IPv6Backup) {
	for _, idx := range backup.DisabledInterfaces {
		if out, err := g.runner.run("netsh", "interface", "ipv6", "set", "interface", idx, "enabled"); err != nil {
			slog.Warn("leakguard: restore ipv6 failed", "index", idx, "error", err, "output", out)
		}
	}
}

// parseIPv6Interfaces extracts interface indices from netsh output,
// skipping Loopback and the TUN interface.
func parseIPv6Interfaces(output, tunName string) []string {
	var indices []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for i := 0; i < 3 && scanner.Scan(); i++ {
		// consume header lines
	}
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		idx := fields[0]
		if _, err := strconv.Atoi(idx); err != nil {
			continue
		}
		name := strings.Join(fields[4:], " ")
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, "loopback") {
			continue
		}
		if tunName != "" && strings.EqualFold(name, tunName) {
			continue
		}
		indices = append(indices, idx)
	}
	return indices
}

// ---------------------------------------------------------------------------
// Kill Switch helpers
// ---------------------------------------------------------------------------

// killSwitchRuleNames are the well-known rule names used for crash recovery.
// SL-Block-All is no longer created (LG-H1: block rules beat allow rules —
// deny-by-default now comes from the outbound policy) but stays listed so
// blind cleanup removes stale rules left by pre-LG-H1 binaries.
var killSwitchRuleNames = []string{
	"SL-Block-All",
	"SL-Allow-TUN",
	"SL-Allow-Server-TCP",
	"SL-Allow-Server-UDP",
	"SL-Allow-Loopback",
	"SL-Allow-DHCP",
	"SL-Allow-Escape-UDP",
	"SL-Allow-LAN",
	"SL-Allow-DNS-RU",
}

// enableKillSwitch applies netsh advfirewall allow rules from the pure
// formatter, persists a CHECKPOINT of state (rules + policy backup), then
// arms deny-by-default by flipping the default outbound policy to Block
// (LG-H1 — an explicit block rule would always beat the allows) and, when
// split-tunnel + RU ranges are present, installs WFP permit filters for the
// RU CIDR snapshot. Mutates state: KillSwitch, FirewallPolicyBackup,
// WFPActive.
//
// Crash-safety contract (BLOCKER 2): the on-disk state ALWAYS carries the
// policy backup and the applied rule names BEFORE the policy is armed, so a
// crash anywhere inside the arming window is recovered by crashRecover
// (state with a policy backup ⇒ "policy may be armed → restore it"). If the
// checkpoint save fails, the policy is NOT armed and an error is returned —
// fail-secure but recoverable: rules removed, policy untouched.
func (g *windowsGuard) enableKillSwitch(cfg LeakGuardConfig, state *State) error {
	plan := BuildKillSwitchPlan(cfg, true /*ruBypassSupported via WFP*/)
	rules := windowsFirewallRules(plan)

	// Backup the default policy BEFORE changing it. A failed backup is not
	// fatal (over-block is acceptable): enable proceeds, restore will fall
	// back to the Windows factory default. reconcilePolicyBackup defends
	// against persisting a poisoned (already-armed) read after a crash.
	policyBackup, err := g.backupFirewallPolicy()
	if err != nil {
		slog.Warn("leakguard: firewall policy backup failed, proceeding (restore will use factory default)", "error", err)
		policyBackup = nil
	}
	policyBackup = g.reconcilePolicyBackup(policyBackup)

	var added []string
	for _, r := range rules {
		if out, err := g.runner.run("netsh", r.args...); err != nil {
			slog.Error("leakguard: add firewall rule failed", "rule", r.name, "error", err, "output", out)
			g.removeKillSwitchRules(added)
			return fmt.Errorf("add rule %s: %w: %s", r.name, err, out)
		}
		added = append(added, r.name)
	}

	state.KillSwitch = KillSwitchState{
		Rules:      added,
		ServerIP:   strings.Join(plan.ServerIPs, ","),
		ServerPort: cfg.ServerPort,
		TunName:    cfg.TunName,
		Backend:    "netsh-advfirewall",
	}
	state.FirewallPolicyBackup = policyBackup

	// CHECKPOINT: persist everything crash recovery needs BEFORE arming the
	// policy. Without this, a crash between the policy SET and the final
	// SaveState would leave a state that looks "policy untouched" — and the
	// next enable would back up our own blockoutbound as the thing to
	// "restore" (stuck-broken-host). If the save fails, do NOT arm.
	if err := SaveState(g.statePath, state); err != nil {
		slog.Error("leakguard: checkpoint state save failed — NOT arming the kill-switch policy", "error", err)
		g.removeKillSwitchRules(added)
		return fmt.Errorf("save checkpoint state: %w", err)
	}

	// Arm deny-by-default LAST: the allow rules are inert under the original
	// allow-outbound policy, so the switch to blockoutbound is atomic. A
	// failure here means the kill switch is NOT armed — that MUST surface as
	// an error (strict mode relies on it), with rules and policy rolled back.
	if err := g.setKillSwitchFirewallPolicy(); err != nil {
		slog.Error("leakguard: set default outbound policy failed — kill switch NOT armed", "error", err)
		if policyBackup != nil {
			// Re-assert the backed-up policy. This always issues the netsh
			// restore commands; that is harmless when the failed SET changed
			// nothing and curative if it partially applied. A nil backup
			// (backup read failed) is left alone — blindly forcing the
			// factory default could clobber an untouched custom policy.
			g.restoreFirewallPolicy(policyBackup)
		}
		g.removeKillSwitchRules(added)
		// The checkpoint state intentionally stays on disk: a later Disable
		// or crashRecover re-asserts the same backup, which is idempotent.
		return fmt.Errorf("set firewall policy: %w", err)
	}

	wfpActive := false
	if plan.SplitTunnel && len(plan.RUAllow) > 0 {
		conds := buildWFPConds(plan.RUAllow)
		if err := g.wfp.ApplyRU(conds); err != nil {
			// WFP failure is non-fatal for the kill switch itself (deny-by-default
			// outbound policy is already up); RU bypass simply won't work →
			// fail-secure (RU via TUN).
			slog.Warn("leakguard: WFP RU split-tunnel apply failed — RU bypass inactive (fail-secure)", "error", err)
		} else {
			wfpActive = true
			slog.Info("leakguard: WFP RU split-tunnel applied", "prefixes", len(conds))
		}
	}
	state.WFPActive = wfpActive
	return nil
}

// removeKillSwitchRules deletes the listed firewall rules by name.
func (g *windowsGuard) removeKillSwitchRules(rules []string) {
	for _, name := range rules {
		if out, err := g.runner.run("netsh", "advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf("name=%s", name)); err != nil {
			slog.Warn("leakguard: delete firewall rule failed", "rule", name, "error", err, "output", out)
		}
	}
}

// removeKillSwitchByName tries to remove all well-known SL- rules.
// Used for crash recovery when the state file is missing or corrupt.
func (g *windowsGuard) removeKillSwitchByName() {
	for _, name := range killSwitchRuleNames {
		if out, err := g.runner.run("netsh", "advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf("name=%s", name)); err != nil {
			slog.Debug("leakguard: cleanup rule not found", "rule", name, "error", err, "output", out)
		}
	}
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

// extractQuoted returns the first double-quoted substring from s.
func extractQuoted(s string) string {
	start := strings.IndexByte(s, '"')
	if start < 0 {
		return ""
	}
	end := strings.IndexByte(s[start+1:], '"')
	if end < 0 {
		return ""
	}
	return s[start+1 : start+1+end]
}

// extractIP returns the first token that looks like an IPv4 address.
func extractIP(line string) string {
	for _, tok := range strings.Fields(line) {
		parts := strings.Split(tok, ".")
		if len(parts) != 4 {
			continue
		}
		valid := true
		for _, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				valid = false
				break
			}
		}
		if valid {
			return tok
		}
	}
	return ""
}

// Ensure windowsGuard satisfies the interface at compile time.
var _ LeakGuard = (*windowsGuard)(nil)

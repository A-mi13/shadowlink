//go:build windows

package leakguard

import (
	"bufio"
	"fmt"
	"log/slog"
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
// Windows Firewall (block-all + LAN) and WFP (RU CIDR split-tunnel).
type windowsGuard struct {
	statePath string
	runner    cmdRunner
	wfp       wfpEngine
	preLocked bool // PreLock already applied DNS+IPv6 → Enable must not redo them
}

// New returns a platform-specific LeakGuard implementation.
// statePath is used for crash-recovery state persistence.
//
// C3-b/H1: New() performs crash recovery (remove SL-Block-All + WFP filters,
// restore DNS/IPv6) BEFORE returning, so a previous crash with an active
// kill switch does not leave the system offline / deadlocked on startup.
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
	g.setDNS(dnsBackup)

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
		}
	} else {
		dnsBackup, err := g.backupDNS()
		if err != nil {
			slog.Warn("leakguard: failed to backup DNS, continuing", "error", err)
		}
		state.DNSBackup = dnsBackup
		g.setDNS(dnsBackup)

		ipv6Backup, err := g.disableIPv6(cfg.TunName)
		if err != nil {
			slog.Warn("leakguard: failed to disable IPv6", "error", err)
		}
		state.IPv6Backup = ipv6Backup
	}

	// Kill switch (netsh block-all + LAN) + WFP (RU split).
	ks, wfpActive, err := g.enableKillSwitch(cfg)
	if err != nil {
		slog.Error("leakguard: kill switch failed, rolling back", "error", err)
		_ = g.wfp.DeleteByProvider()
		g.restoreIPv6(state.IPv6Backup)
		g.restoreDNS(state.DNSBackup)
		g.flushDNS()
		return fmt.Errorf("leakguard: enable kill switch: %w", err)
	}
	state.KillSwitch = ks
	state.WFPActive = wfpActive

	if err := SaveState(g.statePath, &state); err != nil {
		slog.Warn("leakguard: failed to save state", "error", err)
	}

	slog.Info("leakguard enabled", "split_tunnel", cfg.SplitTunnel, "wfp", wfpActive)
	return nil
}

// Disable removes all protections and restores original settings.
func (g *windowsGuard) Disable() error {
	if !StateExists(g.statePath) {
		slog.Warn("leakguard: no state file, attempting cleanup by rule names")
		g.removeKillSwitchByName()
		_ = g.wfp.DeleteByProvider()
		return nil
	}

	state, err := LoadState(g.statePath)
	if err != nil {
		slog.Warn("leakguard: corrupt state file, attempting cleanup by rule names", "error", err)
		g.removeKillSwitchByName()
		_ = g.wfp.DeleteByProvider()
		_ = DeleteState(g.statePath)
		return nil
	}

	g.removeKillSwitchRules(state.KillSwitch.Rules)
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
		g.removeKillSwitchByName()
		_ = g.wfp.DeleteByProvider()
		_ = DeleteState(g.statePath)
		return nil
	}
	g.removeKillSwitchRules(state.KillSwitch.Rules)
	g.removeKillSwitchByName() // подстраховка (netsh)
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

// setDNS sets safe DNS on ALL active IPv4 interfaces by numeric index (incl.
// DHCP interfaces — L2 fix).
func (g *windowsGuard) setDNS(backup DNSBackup) {
	for _, entry := range backup.Entries {
		idx := entry.InterfaceName
		if idx == "" {
			continue
		}
		if _, err := g.runner.run("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddresses 1.1.1.1,8.8.8.8", idx)); err != nil {
			slog.Debug("leakguard: set dns failed", "iface", idx, "error", err)
		}
	}
	g.flushDNS()
}

// restoreDNS restores DNS from backup: empty Servers → reset to DHCP, else set
// the recorded servers. Targets numeric InterfaceIndex (locale-independent).
func (g *windowsGuard) restoreDNS(backup DNSBackup) {
	for _, entry := range backup.Entries {
		idx := entry.InterfaceName
		if idx == "" {
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
var killSwitchRuleNames = []string{
	"SL-Block-All",
	"SL-Allow-TUN",
	"SL-Allow-Server-TCP",
	"SL-Allow-Server-UDP",
	"SL-Allow-Loopback",
	"SL-Allow-DHCP",
	"SL-Allow-Escape-UDP",
	"SL-Allow-LAN",
}

// enableKillSwitch applies netsh advfirewall rules (block-all + LAN) from the
// pure formatter and, when split-tunnel + RU ranges are present, installs WFP
// permit filters for the RU CIDR snapshot. Returns the kill-switch state and
// whether WFP filters were installed.
func (g *windowsGuard) enableKillSwitch(cfg LeakGuardConfig) (KillSwitchState, bool, error) {
	plan := BuildKillSwitchPlan(cfg, true /*ruBypassSupported via WFP*/)
	rules := windowsFirewallRules(plan)

	var added []string
	for _, r := range rules {
		if out, err := g.runner.run("netsh", r.args...); err != nil {
			slog.Error("leakguard: add firewall rule failed", "rule", r.name, "error", err, "output", out)
			g.removeKillSwitchRules(added)
			return KillSwitchState{}, false, fmt.Errorf("add rule %s: %w: %s", r.name, err, out)
		}
		added = append(added, r.name)
	}

	wfpActive := false
	if plan.SplitTunnel && len(plan.RUAllow) > 0 {
		conds := buildWFPConds(plan.RUAllow)
		if err := g.wfp.ApplyRU(conds); err != nil {
			// WFP failure is non-fatal for the kill switch itself (block-all is
			// already up); RU bypass simply won't work → fail-secure (RU via TUN).
			slog.Warn("leakguard: WFP RU split-tunnel apply failed — RU bypass inactive (fail-secure)", "error", err)
		} else {
			wfpActive = true
			slog.Info("leakguard: WFP RU split-tunnel applied", "prefixes", len(conds))
		}
	}

	return KillSwitchState{
		Rules:      added,
		ServerIP:   strings.Join(plan.ServerIPs, ","),
		ServerPort: cfg.ServerPort,
		TunName:    cfg.TunName,
		Backend:    "netsh-advfirewall",
	}, wfpActive, nil
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

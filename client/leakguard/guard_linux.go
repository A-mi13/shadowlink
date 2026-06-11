//go:build linux

package leakguard

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// linuxGuard implements LeakGuard for Linux using iptables/nftables,
// resolv.conf/systemd-resolved for DNS, and sysctl for IPv6.
type linuxGuard struct {
	statePath     string
	backend       string // "iptables" or "nftables"
	preLocked     bool   // PreLock applied DNS+IPv6 → Enable must not redo them
	wasSymlink    bool   // /etc/resolv.conf was a symlink at backup time (M2)
	symlinkTarget string // resolved symlink target (for restore)
}

// New returns a platform-specific LeakGuard implementation.
// statePath is used for crash-recovery state persistence.
func New(statePath string) (LeakGuard, error) {
	g := &linuxGuard{statePath: statePath}

	// If a stale state file exists from a previous crash, clean up immediately.
	if StateExists(statePath) {
		slog.Warn("leakguard: found stale state file, performing crash recovery", "path", statePath)
		if err := g.crashRecover(); err != nil {
			slog.Error("leakguard: crash recovery failed", "err", err)
		}
	}

	return g, nil
}

// PreLock applies DNS+IPv6 protection BEFORE the TUN comes up (H2). Idempotent.
func (g *linuxGuard) PreLock(cfg LeakGuardConfig) error {
	if g.preLocked {
		return nil
	}
	state := &State{EnabledAt: time.Now(), Platform: "linux"}

	dnsBackup, err := g.backupDNS()
	if err != nil {
		slog.Warn("leakguard: pre-lock dns backup failed, continuing", "err", err)
	} else {
		state.DNSBackup = dnsBackup
		state.ResolvConfWasSymlink = g.wasSymlink
		state.ResolvConfTarget = g.symlinkTarget
	}
	if err := g.setDNS(); err != nil {
		slog.Warn("leakguard: pre-lock set dns failed, continuing", "err", err)
	}

	ipv6Backup, err := g.backupIPv6()
	if err != nil {
		slog.Warn("leakguard: pre-lock ipv6 backup failed, continuing", "err", err)
	} else {
		state.IPv6Backup = ipv6Backup
	}
	if err := g.disableIPv6(); err != nil {
		slog.Warn("leakguard: pre-lock disable ipv6 failed, continuing", "err", err)
	}

	if err := SaveState(g.statePath, state); err != nil {
		slog.Warn("leakguard: pre-lock save state failed", "err", err)
	}
	g.preLocked = true
	slog.Info("leakguard: pre-lock applied (DNS+IPv6)")
	return nil
}

// Enable activates DNS leak protection, IPv6 disable, and kill switch.
func (g *linuxGuard) Enable(cfg LeakGuardConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	g.backend = detectBackend()
	slog.Info("leakguard: enabling", "backend", g.backend, "tun", cfg.TunName,
		"server", cfg.ServerIP, "port", cfg.ServerPort, "split_tunnel", cfg.SplitTunnel)

	state := &State{
		EnabledAt:   time.Now(),
		Platform:    "linux",
		SplitTunnel: cfg.SplitTunnel,
		KillSwitch: KillSwitchState{
			ServerIP:   cfg.ServerIP.String(),
			ServerPort: cfg.ServerPort,
			TunName:    cfg.TunName,
			Backend:    g.backend,
		},
	}

	if g.preLocked {
		// Reuse DNS/IPv6 backups captured by PreLock.
		if prev, err := LoadState(g.statePath); err == nil {
			state.DNSBackup = prev.DNSBackup
			state.IPv6Backup = prev.IPv6Backup
			state.ResolvConfWasSymlink = prev.ResolvConfWasSymlink
			state.ResolvConfTarget = prev.ResolvConfTarget
		}
	} else {
		dnsBackup, err := g.backupDNS()
		if err != nil {
			slog.Warn("leakguard: dns backup failed, continuing", "err", err)
		} else {
			state.DNSBackup = dnsBackup
			state.ResolvConfWasSymlink = g.wasSymlink
			state.ResolvConfTarget = g.symlinkTarget
		}
		if err := g.setDNS(); err != nil {
			slog.Warn("leakguard: set dns failed, continuing", "err", err)
		}

		ipv6Backup, err := g.backupIPv6()
		if err != nil {
			slog.Warn("leakguard: ipv6 backup failed, continuing", "err", err)
		} else {
			state.IPv6Backup = ipv6Backup
		}
		if err := g.disableIPv6(); err != nil {
			slog.Warn("leakguard: disable ipv6 failed, continuing", "err", err)
		}
	}

	// Enable kill switch.
	rules, err := g.enableKillSwitch(cfg)
	if err != nil {
		// Kill switch failure is critical — roll back what we did.
		_ = g.restoreDNS(state.DNSBackup)
		_ = g.restoreIPv6(state.IPv6Backup)
		return fmt.Errorf("leakguard: enable kill switch: %w", err)
	}
	state.KillSwitch.Rules = rules

	if err := SaveState(g.statePath, state); err != nil {
		return fmt.Errorf("leakguard: save state: %w", err)
	}

	slog.Info("leakguard: enabled successfully")
	return nil
}

// Disable removes all leak-prevention rules and restores original settings.
func (g *linuxGuard) Disable() error {
	state, err := LoadState(g.statePath)
	if err != nil {
		// No state file — try both backends as a best effort.
		slog.Warn("leakguard: no state file, attempting blind cleanup")
		g.blindCleanup()
		return nil
	}

	g.backend = state.KillSwitch.Backend
	g.wasSymlink = state.ResolvConfWasSymlink
	g.symlinkTarget = state.ResolvConfTarget

	var errs []string

	// 1. Remove kill switch.
	if err := g.disableKillSwitch(); err != nil {
		errs = append(errs, fmt.Sprintf("kill switch: %v", err))
	}

	// 2. Restore DNS.
	if err := g.restoreDNS(state.DNSBackup); err != nil {
		errs = append(errs, fmt.Sprintf("dns restore: %v", err))
	}

	// 3. Restore IPv6.
	if err := g.restoreIPv6(state.IPv6Backup); err != nil {
		errs = append(errs, fmt.Sprintf("ipv6 restore: %v", err))
	}

	// 4. Remove state file.
	if err := DeleteState(g.statePath); err != nil {
		errs = append(errs, fmt.Sprintf("delete state: %v", err))
	}

	if len(errs) > 0 {
		slog.Warn("leakguard: disable completed with errors", "errors", strings.Join(errs, "; "))
		return fmt.Errorf("leakguard: disable: %s", strings.Join(errs, "; "))
	}

	slog.Info("leakguard: disabled successfully")
	return nil
}

// ---------------------------------------------------------------------------
// Backend detection
// ---------------------------------------------------------------------------

// detectBackend determines whether to use nftables or iptables.
func detectBackend() string {
	out, err := exec.Command("iptables", "-V").CombinedOutput()
	if err == nil && strings.Contains(string(out), "nf_tables") {
		if _, err := exec.LookPath("nft"); err == nil {
			return "nftables"
		}
	}
	return "iptables"
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

const resolvConfPath = "/etc/resolv.conf"

// backupDNS reads /etc/resolv.conf, recording whether it is a symlink (managed
// by systemd-resolved / NetworkManager — M2) so restore re-creates the link
// instead of clobbering a regular file in its place.
func (g *linuxGuard) backupDNS() (DNSBackup, error) {
	g.wasSymlink = false
	g.symlinkTarget = ""
	if fi, err := os.Lstat(resolvConfPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		g.wasSymlink = true
		if tgt, lerr := os.Readlink(resolvConfPath); lerr == nil {
			g.symlinkTarget = tgt
		}
	}
	data, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return DNSBackup{}, fmt.Errorf("read resolv.conf: %w", err)
	}
	return DNSBackup{
		Entries: []DNSEntry{
			{
				InterfaceName: "resolv.conf",
				Servers:       []string{string(data)},
			},
		},
	}, nil
}

// setDNS configures safe DNS servers. When resolv.conf is a symlink or
// systemd-resolved/NetworkManager are managing DNS, it defers to the manager
// (resolvectl) instead of overwriting the (managed) file (M2/L5).
func (g *linuxGuard) setDNS() error {
	plan := resolvConfWritePlan(g.wasSymlink, g.symlinkTarget)
	if plan.useResolvectl || isSystemdResolvedActive() || isNetworkManagerActive() {
		return runCmd("resolvectl", "dns", "1.1.1.1", "8.8.8.8")
	}
	content := "# Set by ShadowLink LeakGuard\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"
	return os.WriteFile(resolvConfPath, []byte(content), 0644)
}

// restoreDNS writes back the original resolv.conf content. If the file was a
// symlink, it re-creates the symlink rather than leaving a regular file.
func (g *linuxGuard) restoreDNS(backup DNSBackup) error {
	if len(backup.Entries) == 0 || len(backup.Entries[0].Servers) == 0 {
		return nil
	}
	original := backup.Entries[0].Servers[0]
	if original == "" {
		return nil
	}

	if isSystemdResolvedActive() || isNetworkManagerActive() {
		var servers []string
		for _, line := range strings.Split(original, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver ") {
				servers = append(servers, strings.TrimPrefix(line, "nameserver "))
			}
		}
		if len(servers) > 0 {
			args := append([]string{"dns"}, servers...)
			return runCmd("resolvectl", args...)
		}
		return nil
	}

	// If the original was a symlink, re-create the link (M2). Best-effort.
	if g.wasSymlink && g.symlinkTarget != "" {
		_ = os.Remove(resolvConfPath)
		if err := os.Symlink(g.symlinkTarget, resolvConfPath); err == nil {
			return nil
		}
		// Fall through to writing the backed-up content if symlink fails.
	}
	return os.WriteFile(resolvConfPath, []byte(original), 0644)
}

// isSystemdResolvedActive checks if systemd-resolved is running.
func isSystemdResolvedActive() bool {
	err := exec.Command("systemctl", "is-active", "systemd-resolved").Run()
	return err == nil
}

// isNetworkManagerActive checks if NetworkManager is managing DNS (M2).
func isNetworkManagerActive() bool {
	err := exec.Command("systemctl", "is-active", "NetworkManager").Run()
	return err == nil
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

// backupIPv6 records the original disable_ipv6 value for `all` (used as the
// restore baseline). DisabledInterfaces holds the full set of sysctl keys we
// will disable so restore re-enables exactly what we touched (M3).
func (g *linuxGuard) backupIPv6() (IPv6Backup, error) {
	out, err := exec.Command("sysctl", "-n", "net.ipv6.conf.all.disable_ipv6").CombinedOutput()
	if err != nil {
		return IPv6Backup{}, fmt.Errorf("sysctl read ipv6: %w", err)
	}
	keys := ipv6DisableSysctlKeys(listIPv6Interfaces())
	return IPv6Backup{
		DisabledInterfaces: keys,
		OriginalSysctl:     strings.TrimSpace(string(out)),
	}, nil
}

// disableIPv6 sets disable_ipv6=1 on all/default + every detected interface (M3).
func (g *linuxGuard) disableIPv6() error {
	keys := ipv6DisableSysctlKeys(listIPv6Interfaces())
	var firstErr error
	for _, k := range keys {
		if err := runCmd("sysctl", "-w", k+"=1"); err != nil {
			slog.Warn("leakguard: disable ipv6 key failed", "key", k, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// restoreIPv6 restores disable_ipv6 to its original value on every key we set.
func (g *linuxGuard) restoreIPv6(backup IPv6Backup) error {
	val := backup.OriginalSysctl
	if val == "" {
		val = "0"
	}
	keys := backup.DisabledInterfaces
	if len(keys) == 0 {
		keys = []string{"net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"}
	}
	for _, k := range keys {
		_ = runCmd("sysctl", "-w", k+"="+val)
	}
	return nil
}

// listIPv6Interfaces enumerates non-loopback network interfaces for per-iface
// IPv6 disable. Best-effort; returns nil on error (all/default still covered).
func listIPv6Interfaces() []string {
	out, err := exec.Command("ls", "/proc/sys/net/ipv6/conf").CombinedOutput()
	if err != nil {
		return nil
	}
	var ifaces []string
	for _, f := range strings.Fields(string(out)) {
		switch f {
		case "all", "default", "lo":
			continue
		}
		ifaces = append(ifaces, f)
	}
	return ifaces
}

// ---------------------------------------------------------------------------
// Kill Switch — iptables
// ---------------------------------------------------------------------------

func (g *linuxGuard) enableKillSwitchIPTables(cfg LeakGuardConfig) ([]string, error) {
	ipsetAvailable := false
	if _, err := exec.LookPath("ipset"); err == nil {
		ipsetAvailable = true
	}
	plan := BuildKillSwitchPlan(cfg, ipsetAvailable)
	if cfg.SplitTunnel && len(cfg.BypassRanges) > 0 && !ipsetAvailable {
		slog.Warn("leakguard: ipset unavailable — RU split-tunnel degraded to LAN-only (RU via TUN, fail-secure)")
	}
	cmds := linuxIPTablesCommands(plan, ipsetAvailable)

	var rules []string
	for _, args := range cmds {
		if err := runCmd(args[0], args[1:]...); err != nil {
			// Best-effort rollback of what we already added.
			_ = g.cleanupIPTables()
			return nil, fmt.Errorf("iptables %v: %w", args, err)
		}
		rules = append(rules, strings.Join(args, " "))
	}
	return rules, nil
}

func (g *linuxGuard) cleanupIPTables() error {
	// Ignore errors — chain may not exist.
	_ = runCmd("iptables", "-D", "OUTPUT", "-j", "SHADOWLINK-KS")
	_ = runCmd("iptables", "-F", "SHADOWLINK-KS")
	_ = runCmd("iptables", "-X", "SHADOWLINK-KS")
	// Destroy the RU ipset if it exists (split-tunnel cleanup).
	_ = runCmd("ipset", "destroy", "sl_ru")
	return nil
}

// ---------------------------------------------------------------------------
// Kill Switch — nftables
// ---------------------------------------------------------------------------

func (g *linuxGuard) enableKillSwitchNFTables(cfg LeakGuardConfig) ([]string, error) {
	// nft sets scale to thousands of prefixes → RU split always supported.
	cmds := linuxNFTCommands(BuildKillSwitchPlan(cfg, true))

	var rules []string
	for _, args := range cmds {
		if err := runCmd(args[0], args[1:]...); err != nil {
			_ = g.cleanupNFTables()
			return nil, fmt.Errorf("nft %v: %w", args, err)
		}
		rules = append(rules, strings.Join(args, " "))
	}
	return rules, nil
}

func (g *linuxGuard) cleanupNFTables() error {
	_ = runCmd("nft", "delete", "table", "inet", "shadowlink")
	return nil
}

// ---------------------------------------------------------------------------
// Kill Switch — unified interface
// ---------------------------------------------------------------------------

func (g *linuxGuard) enableKillSwitch(cfg LeakGuardConfig) ([]string, error) {
	if g.backend == "nftables" {
		return g.enableKillSwitchNFTables(cfg)
	}
	return g.enableKillSwitchIPTables(cfg)
}

func (g *linuxGuard) disableKillSwitch() error {
	if g.backend == "nftables" {
		return g.cleanupNFTables()
	}
	return g.cleanupIPTables()
}

// ---------------------------------------------------------------------------
// Crash recovery
// ---------------------------------------------------------------------------

// crashRecover is called when a state file exists at startup, meaning
// the previous process crashed without calling Disable().
func (g *linuxGuard) crashRecover() error {
	state, err := LoadState(g.statePath)
	if err != nil {
		// State file is corrupt or unreadable — try both backends.
		slog.Warn("leakguard: cannot load state for recovery, blind cleanup")
		g.blindCleanup()
		_ = DeleteState(g.statePath)
		return nil
	}

	g.backend = state.KillSwitch.Backend
	g.wasSymlink = state.ResolvConfWasSymlink
	g.symlinkTarget = state.ResolvConfTarget

	var errs []string

	if err := g.disableKillSwitch(); err != nil {
		errs = append(errs, fmt.Sprintf("kill switch: %v", err))
	}
	if err := g.restoreDNS(state.DNSBackup); err != nil {
		errs = append(errs, fmt.Sprintf("dns: %v", err))
	}
	if err := g.restoreIPv6(state.IPv6Backup); err != nil {
		errs = append(errs, fmt.Sprintf("ipv6: %v", err))
	}

	_ = DeleteState(g.statePath)

	if len(errs) > 0 {
		return fmt.Errorf("crash recovery partial: %s", strings.Join(errs, "; "))
	}
	return nil
}

// blindCleanup tries both iptables and nftables cleanup when no state is available.
func (g *linuxGuard) blindCleanup() {
	slog.Info("leakguard: blind cleanup — trying both iptables and nftables")
	g.cleanupIPTables()
	g.cleanupNFTables()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// runCmd executes a command and returns an error with combined output on failure.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Ensure linuxGuard satisfies the interface at compile time.
var _ LeakGuard = (*linuxGuard)(nil)

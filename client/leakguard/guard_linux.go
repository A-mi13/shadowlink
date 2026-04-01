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
	statePath string
	backend   string // "iptables" or "nftables"
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

// Enable activates DNS leak protection, IPv6 disable, and kill switch.
func (g *linuxGuard) Enable(cfg LeakGuardConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	g.backend = detectBackend()
	slog.Info("leakguard: enabling", "backend", g.backend, "tun", cfg.TunName,
		"server", cfg.ServerIP, "port", cfg.ServerPort)

	state := &State{
		EnabledAt: time.Now(),
		Platform:  "linux",
		KillSwitch: KillSwitchState{
			ServerIP:   cfg.ServerIP.String(),
			ServerPort: cfg.ServerPort,
			TunName:    cfg.TunName,
			Backend:    g.backend,
		},
	}

	// 1. Backup and set DNS.
	dnsBackup, err := g.backupDNS()
	if err != nil {
		slog.Warn("leakguard: dns backup failed, continuing", "err", err)
	} else {
		state.DNSBackup = dnsBackup
	}

	if err := g.setDNS(); err != nil {
		slog.Warn("leakguard: set dns failed, continuing", "err", err)
	}

	// 2. Backup and disable IPv6.
	ipv6Backup, err := g.backupIPv6()
	if err != nil {
		slog.Warn("leakguard: ipv6 backup failed, continuing", "err", err)
	} else {
		state.IPv6Backup = ipv6Backup
	}

	if err := g.disableIPv6(); err != nil {
		slog.Warn("leakguard: disable ipv6 failed, continuing", "err", err)
	}

	// 3. Enable kill switch.
	rules, err := g.enableKillSwitch(cfg)
	if err != nil {
		// Kill switch failure is critical — roll back what we did.
		_ = g.restoreDNS(state.DNSBackup)
		_ = g.restoreIPv6(state.IPv6Backup)
		return fmt.Errorf("leakguard: enable kill switch: %w", err)
	}
	state.KillSwitch.Rules = rules

	// 4. Persist state for crash recovery.
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

// backupDNS reads /etc/resolv.conf and stores its full content.
func (g *linuxGuard) backupDNS() (DNSBackup, error) {
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

// setDNS configures safe DNS servers. Uses systemd-resolved if active,
// otherwise writes directly to /etc/resolv.conf.
func (g *linuxGuard) setDNS() error {
	if isSystemdResolvedActive() {
		return runCmd("resolvectl", "dns", "1.1.1.1", "8.8.8.8")
	}
	content := "# Set by ShadowLink LeakGuard\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"
	return os.WriteFile(resolvConfPath, []byte(content), 0644)
}

// restoreDNS writes back the original resolv.conf content.
func (g *linuxGuard) restoreDNS(backup DNSBackup) error {
	if len(backup.Entries) == 0 || len(backup.Entries[0].Servers) == 0 {
		return nil
	}
	original := backup.Entries[0].Servers[0]
	if original == "" {
		return nil
	}

	if isSystemdResolvedActive() {
		// Extract nameserver lines from the original content and pass to resolvectl.
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

	return os.WriteFile(resolvConfPath, []byte(original), 0644)
}

// isSystemdResolvedActive checks if systemd-resolved is running.
func isSystemdResolvedActive() bool {
	err := exec.Command("systemctl", "is-active", "systemd-resolved").Run()
	return err == nil
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

// backupIPv6 reads the current IPv6 disable sysctl value.
func (g *linuxGuard) backupIPv6() (IPv6Backup, error) {
	out, err := exec.Command("sysctl", "-n", "net.ipv6.conf.all.disable_ipv6").CombinedOutput()
	if err != nil {
		return IPv6Backup{}, fmt.Errorf("sysctl read ipv6: %w", err)
	}
	return IPv6Backup{
		DisabledInterfaces: []string{"all"},
		OriginalSysctl:     strings.TrimSpace(string(out)),
	}, nil
}

// disableIPv6 sets net.ipv6.conf.all.disable_ipv6=1.
func (g *linuxGuard) disableIPv6() error {
	return runCmd("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1")
}

// restoreIPv6 restores the original sysctl value for IPv6.
func (g *linuxGuard) restoreIPv6(backup IPv6Backup) error {
	if backup.OriginalSysctl == "" {
		return nil
	}
	return runCmd("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6="+backup.OriginalSysctl)
}

// ---------------------------------------------------------------------------
// Kill Switch — iptables
// ---------------------------------------------------------------------------

func (g *linuxGuard) enableKillSwitchIPTables(cfg LeakGuardConfig) ([]string, error) {
	ip := cfg.ServerIP.String()
	port := fmt.Sprintf("%d", cfg.ServerPort)
	tun := cfg.TunName

	cmds := [][]string{
		{"iptables", "-N", "SHADOWLINK-KS"},
		{"iptables", "-I", "OUTPUT", "-j", "SHADOWLINK-KS"},
		{"iptables", "-A", "SHADOWLINK-KS", "-o", tun, "-j", "ACCEPT"},
		{"iptables", "-A", "SHADOWLINK-KS", "-d", ip, "-p", "tcp", "--dport", port, "-j", "ACCEPT"},
		{"iptables", "-A", "SHADOWLINK-KS", "-d", ip, "-p", "udp", "--dport", port, "-j", "ACCEPT"},
		{"iptables", "-A", "SHADOWLINK-KS", "-o", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", "SHADOWLINK-KS", "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"},
	}
	// Allow UDP to TURN relay IPs (WB TURN escape route)
	for _, eip := range cfg.ExtraEscapeIPs {
		cmds = append(cmds, []string{"iptables", "-A", "SHADOWLINK-KS", "-d", eip.String(), "-p", "udp", "-j", "ACCEPT"})
	}
	cmds = append(cmds, []string{"iptables", "-A", "SHADOWLINK-KS", "-j", "DROP"})

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
	return nil
}

// ---------------------------------------------------------------------------
// Kill Switch — nftables
// ---------------------------------------------------------------------------

func (g *linuxGuard) enableKillSwitchNFTables(cfg LeakGuardConfig) ([]string, error) {
	ip := cfg.ServerIP.String()
	port := fmt.Sprintf("%d", cfg.ServerPort)
	tun := cfg.TunName

	cmds := [][]string{
		{"nft", "add", "table", "inet", "shadowlink"},
		{"nft", "add", "chain", "inet", "shadowlink", "output",
			"{ type filter hook output priority 0 ; policy accept ; }"},
		{"nft", "add", "rule", "inet", "shadowlink", "output",
			"oifname", tun, "accept"},
		{"nft", "add", "rule", "inet", "shadowlink", "output",
			"ip", "daddr", ip, "tcp", "dport", port, "accept"},
		{"nft", "add", "rule", "inet", "shadowlink", "output",
			"ip", "daddr", ip, "udp", "dport", port, "accept"},
		{"nft", "add", "rule", "inet", "shadowlink", "output",
			"oifname", "lo", "accept"},
		{"nft", "add", "rule", "inet", "shadowlink", "output",
			"udp", "sport", "68", "udp", "dport", "67", "accept"},
	}
	// Allow UDP to TURN relay IPs (WB TURN escape route)
	for _, eip := range cfg.ExtraEscapeIPs {
		cmds = append(cmds, []string{"nft", "add", "rule", "inet", "shadowlink", "output",
			"ip", "daddr", eip.String(), "udp", "accept"})
	}
	cmds = append(cmds, []string{"nft", "add", "rule", "inet", "shadowlink", "output", "drop"})

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

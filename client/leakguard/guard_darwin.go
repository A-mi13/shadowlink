//go:build darwin

package leakguard

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const pfAnchor = "shadowlink"

// darwinGuard implements LeakGuard for macOS using networksetup and pf.
type darwinGuard struct {
	statePath   string
	preLocked   bool // PreLock applied DNS+IPv6 → Enable must not redo them
	pfRulesPath string
}

// appDir returns the directory used for the pf rules file (state-file dir).
func (g *darwinGuard) appDir() string {
	return filepath.Dir(g.statePath)
}

// New returns a platform-specific LeakGuard implementation.
// statePath is used for crash-recovery state persistence.
func New(statePath string) (LeakGuard, error) {
	g := &darwinGuard{statePath: statePath, pfRulesPath: pfRulesPath(filepath.Dir(statePath))}

	// If a previous state file exists, we may have crashed — try to restore.
	if StateExists(statePath) {
		slog.Warn("leakguard: found stale state file, attempting crash recovery",
			"path", statePath)
		if err := g.Disable(); err != nil {
			slog.Error("leakguard: crash recovery failed, manual cleanup may be needed",
				"error", err)
		}
	}

	return g, nil
}

// PreLock applies DNS+IPv6 protection BEFORE the TUN comes up (H2). Idempotent.
func (g *darwinGuard) PreLock(cfg LeakGuardConfig) error {
	if g.preLocked {
		return nil
	}
	state := &State{EnabledAt: time.Now(), Platform: "darwin"}

	dnsBackup, err := g.backupDNS()
	if err != nil {
		slog.Warn("leakguard: pre-lock DNS backup failed, continuing", "error", err)
	} else {
		state.DNSBackup = dnsBackup
	}
	if err := g.setDNS([]string{"1.1.1.1", "8.8.8.8"}); err != nil {
		slog.Warn("leakguard: pre-lock set DNS failed, continuing", "error", err)
	}
	_ = g.flushDNS()

	ipv6Backup, err := g.disableIPv6()
	if err != nil {
		slog.Warn("leakguard: pre-lock disable IPv6 failed, continuing", "error", err)
	}
	state.IPv6Backup = ipv6Backup

	if err := SaveState(g.statePath, state); err != nil {
		slog.Warn("leakguard: pre-lock save state failed", "error", err)
	}
	g.preLocked = true
	slog.Info("leakguard: pre-lock applied (DNS+IPv6)")
	return nil
}

// Enable activates DNS leak protection, disables IPv6, and installs pf kill-switch rules.
func (g *darwinGuard) Enable(cfg LeakGuardConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	slog.Info("leakguard: enabling macOS leak protection",
		"server", cfg.ServerIP, "port", cfg.ServerPort, "tun", cfg.TunName)

	state := &State{
		EnabledAt:   time.Now(),
		Platform:    "darwin",
		SplitTunnel: cfg.SplitTunnel,
	}

	if g.preLocked {
		if prev, perr := LoadState(g.statePath); perr == nil {
			state.DNSBackup = prev.DNSBackup
			state.IPv6Backup = prev.IPv6Backup
		}
	} else {
		// --- DNS ---
		dnsBackup, err := g.backupDNS()
		if err != nil {
			return fmt.Errorf("leakguard: backup DNS: %w", err)
		}
		state.DNSBackup = dnsBackup

		if err := g.setDNS([]string{"1.1.1.1", "8.8.8.8"}); err != nil {
			slog.Warn("leakguard: failed to set DNS servers, continuing", "error", err)
		}
		if err := g.flushDNS(); err != nil {
			slog.Warn("leakguard: failed to flush DNS cache", "error", err)
		}

		// --- IPv6 ---
		ipv6Backup, err := g.disableIPv6()
		if err != nil {
			slog.Warn("leakguard: failed to disable IPv6, continuing", "error", err)
		}
		state.IPv6Backup = ipv6Backup
	}

	// --- Kill Switch (pf) ---
	ksState, pfEnabledByUs, err := g.enableKillSwitch(cfg)
	if err != nil {
		// Kill switch is critical — roll back and return error.
		slog.Error("leakguard: kill switch failed, rolling back", "error", err)
		g.restoreDNS(state.DNSBackup)
		g.restoreIPv6(state.IPv6Backup)
		return fmt.Errorf("leakguard: enable kill switch: %w", err)
	}
	state.KillSwitch = ksState
	state.PFEnabledByUs = pfEnabledByUs
	state.PFRulesPath = g.pfRulesPath

	// Persist state for crash recovery.
	if err := SaveState(g.statePath, state); err != nil {
		slog.Warn("leakguard: failed to save state file", "error", err)
	}

	slog.Info("leakguard: macOS leak protection enabled")
	return nil
}

// Disable removes all leak protection rules and restores original settings.
func (g *darwinGuard) Disable() error {
	slog.Info("leakguard: disabling macOS leak protection")

	var state *State
	if StateExists(g.statePath) {
		var err error
		state, err = LoadState(g.statePath)
		if err != nil {
			slog.Warn("leakguard: failed to load state, doing best-effort cleanup", "error", err)
		}
	}

	var firstErr error

	// --- Kill Switch ---
	pfEnabledByUs := false
	rulesPath := g.pfRulesPath
	if state != nil {
		pfEnabledByUs = state.PFEnabledByUs
		if state.PFRulesPath != "" {
			rulesPath = state.PFRulesPath
		}
	}
	if err := g.disableKillSwitch(pfEnabledByUs, rulesPath); err != nil {
		slog.Warn("leakguard: failed to disable kill switch", "error", err)
		if firstErr == nil {
			firstErr = err
		}
	}

	// --- DNS ---
	if state != nil {
		if err := g.restoreDNS(state.DNSBackup); err != nil {
			slog.Warn("leakguard: failed to restore DNS", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
		if err := g.flushDNS(); err != nil {
			slog.Warn("leakguard: failed to flush DNS cache on disable", "error", err)
		}
	}

	// --- IPv6 ---
	if state != nil {
		if err := g.restoreIPv6(state.IPv6Backup); err != nil {
			slog.Warn("leakguard: failed to restore IPv6", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Clean up state file.
	if err := DeleteState(g.statePath); err != nil {
		slog.Warn("leakguard: failed to delete state file", "error", err)
	}

	slog.Info("leakguard: macOS leak protection disabled")
	return firstErr
}

// ---------- DNS helpers ----------

// listNetworkServices returns all non-hardware-port network services.
func (g *darwinGuard) listNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("listallnetworkservices: %w", err)
	}

	var services []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		// First line is a header like "An asterisk (*) denotes..."
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		// Services disabled by hardware have a leading asterisk.
		line = strings.TrimPrefix(line, "*")
		line = strings.TrimSpace(line)
		if line != "" {
			services = append(services, line)
		}
	}
	return services, nil
}

// backupDNS reads current DNS servers from all network services.
func (g *darwinGuard) backupDNS() (DNSBackup, error) {
	services, err := g.listNetworkServices()
	if err != nil {
		return DNSBackup{}, err
	}

	var entries []DNSEntry
	for _, svc := range services {
		out, err := exec.Command("networksetup", "-getdnsservers", svc).Output()
		if err != nil {
			slog.Warn("leakguard: cannot read DNS for service", "service", svc, "error", err)
			continue
		}

		text := strings.TrimSpace(string(out))
		var servers []string

		// "There aren't any DNS Servers set on ..." means DHCP/automatic.
		if strings.Contains(text, "There aren't any") {
			servers = nil // empty = was automatic
		} else {
			for _, line := range strings.Split(text, "\n") {
				s := strings.TrimSpace(line)
				if s != "" {
					servers = append(servers, s)
				}
			}
		}

		entries = append(entries, DNSEntry{
			InterfaceName: svc,
			Servers:       servers,
		})
	}

	return DNSBackup{Entries: entries}, nil
}

// setDNS overrides DNS servers on all network services.
func (g *darwinGuard) setDNS(servers []string) error {
	services, err := g.listNetworkServices()
	if err != nil {
		return err
	}

	for _, svc := range services {
		args := append([]string{"-setdnsservers", svc}, servers...)
		if out, err := exec.Command("networksetup", args...).CombinedOutput(); err != nil {
			slog.Warn("leakguard: failed to set DNS for service",
				"service", svc, "error", err, "output", string(out))
		}
	}
	return nil
}

// restoreDNS restores original DNS settings from backup.
func (g *darwinGuard) restoreDNS(backup DNSBackup) error {
	for _, entry := range backup.Entries {
		var args []string
		if len(entry.Servers) == 0 {
			// Original was automatic/DHCP — pass "Empty" to clear.
			args = []string{"-setdnsservers", entry.InterfaceName, "Empty"}
		} else {
			args = append([]string{"-setdnsservers", entry.InterfaceName}, entry.Servers...)
		}

		if out, err := exec.Command("networksetup", args...).CombinedOutput(); err != nil {
			slog.Warn("leakguard: failed to restore DNS for service",
				"service", entry.InterfaceName, "error", err, "output", string(out))
		}
	}
	return nil
}

// flushDNS clears the macOS DNS cache.
func (g *darwinGuard) flushDNS() error {
	if out, err := exec.Command("dscacheutil", "-flushcache").CombinedOutput(); err != nil {
		slog.Warn("leakguard: dscacheutil -flushcache failed", "error", err, "output", string(out))
	}
	if out, err := exec.Command("killall", "-HUP", "mDNSResponder").CombinedOutput(); err != nil {
		slog.Warn("leakguard: killall -HUP mDNSResponder failed", "error", err, "output", string(out))
	}
	return nil
}

// ---------- IPv6 helpers ----------

// disableIPv6 turns off IPv6 on all network services and returns a backup.
func (g *darwinGuard) disableIPv6() (IPv6Backup, error) {
	services, err := g.listNetworkServices()
	if err != nil {
		return IPv6Backup{}, err
	}

	var disabled []string
	for _, svc := range services {
		if out, err := exec.Command("networksetup", "-setv6off", svc).CombinedOutput(); err != nil {
			slog.Warn("leakguard: failed to disable IPv6 for service",
				"service", svc, "error", err, "output", string(out))
			continue
		}
		disabled = append(disabled, svc)
	}

	return IPv6Backup{
		DisabledInterfaces: disabled,
	}, nil
}

// restoreIPv6 re-enables IPv6 on all services that were previously disabled.
func (g *darwinGuard) restoreIPv6(backup IPv6Backup) error {
	for _, svc := range backup.DisabledInterfaces {
		if out, err := exec.Command("networksetup", "-setv6automatic", svc).CombinedOutput(); err != nil {
			slog.Warn("leakguard: failed to restore IPv6 for service",
				"service", svc, "error", err, "output", string(out))
		}
	}
	return nil
}

// ---------- Kill Switch (pf) helpers ----------

// enableKillSwitch writes pf anchor rules (from the pure formatter) and loads
// them. It verifies pf is enabled (M4); if disabled it runs `pfctl -E` and
// records that we did so (PFEnabledByUs) for rollback on Disable. The rules
// file lives in the app dir, not /tmp (M5). Returns the kill-switch state and
// whether we enabled pf ourselves.
func (g *darwinGuard) enableKillSwitch(cfg LeakGuardConfig) (KillSwitchState, bool, error) {
	plan := BuildKillSwitchPlan(cfg, true /*pf table scales*/)
	rules := darwinPFRules(plan)

	rulesPath := g.pfRulesPath
	content := strings.Join(rules, "\n") + "\n"
	if err := os.WriteFile(rulesPath, []byte(content), 0600); err != nil {
		return KillSwitchState{}, false, fmt.Errorf("write pf rules to %s: %w", rulesPath, err)
	}

	// Load rules into the shadowlink anchor.
	out, err := exec.Command("pfctl", "-a", pfAnchor, "-f", rulesPath).CombinedOutput()
	if err != nil {
		os.Remove(rulesPath)
		return KillSwitchState{}, false, fmt.Errorf("pfctl load anchor: %w (output: %s)", err, string(out))
	}

	// M4: verify pf is actually enabled; if not, enable it ourselves and record.
	pfEnabledByUs := false
	info, _ := exec.Command("pfctl", "-s", "info").CombinedOutput()
	if !parsePFEnabled(string(info)) {
		if eout, eerr := exec.Command("pfctl", "-E").CombinedOutput(); eerr != nil {
			slog.Warn("leakguard: pf is disabled and `pfctl -E` failed — kill switch may be inactive",
				"error", eerr, "output", string(eout))
		} else {
			pfEnabledByUs = true
			slog.Info("leakguard: pf was disabled, enabled by LeakGuard (will disable on cleanup)")
		}
	}

	slog.Info("leakguard: pf kill switch enabled",
		"anchor", pfAnchor, "tun", cfg.TunName, "split_tunnel", cfg.SplitTunnel)

	return KillSwitchState{
		Rules:      rules,
		ServerIP:   strings.Join(plan.ServerIPs, ","),
		ServerPort: cfg.ServerPort,
		TunName:    cfg.TunName,
		Backend:    "pf",
	}, pfEnabledByUs, nil
}

// disableKillSwitch flushes the pf anchor, optionally disables pf if we enabled
// it, and removes the rules file.
func (g *darwinGuard) disableKillSwitch(pfEnabledByUs bool, rulesPath string) error {
	out, err := exec.Command("pfctl", "-a", pfAnchor, "-F", "all").CombinedOutput()
	if err != nil {
		slog.Warn("leakguard: pfctl flush anchor failed",
			"error", err, "output", string(out))
	}

	if pfEnabledByUs {
		if dout, derr := exec.Command("pfctl", "-d").CombinedOutput(); derr != nil {
			slog.Warn("leakguard: pfctl -d (restore disabled) failed", "error", derr, "output", string(dout))
		}
	}

	if rulesPath == "" {
		rulesPath = g.pfRulesPath
	}
	if err := os.Remove(rulesPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("leakguard: failed to remove pf rules file",
			"path", rulesPath, "error", err)
	}

	slog.Info("leakguard: pf kill switch disabled")
	return nil
}

// Ensure darwinGuard satisfies the interface at compile time.
var _ LeakGuard = (*darwinGuard)(nil)

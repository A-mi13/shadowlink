//go:build darwin

package leakguard

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	pfRulesPath = "/tmp/shadowlink-pf.rules"
	pfAnchor    = "shadowlink"
)

// darwinGuard implements LeakGuard for macOS using networksetup and pf.
type darwinGuard struct {
	statePath string
}

// New returns a platform-specific LeakGuard implementation.
// statePath is used for crash-recovery state persistence.
func New(statePath string) (LeakGuard, error) {
	g := &darwinGuard{statePath: statePath}

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

// Enable activates DNS leak protection, disables IPv6, and installs pf kill-switch rules.
func (g *darwinGuard) Enable(cfg LeakGuardConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	slog.Info("leakguard: enabling macOS leak protection",
		"server", cfg.ServerIP, "port", cfg.ServerPort, "tun", cfg.TunName)

	state := &State{
		EnabledAt: time.Now(),
		Platform:  "darwin",
	}

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

	// --- Kill Switch (pf) ---
	serverIP := cfg.ServerIP.String()
	ksState, err := g.enableKillSwitch(serverIP, cfg.ServerPort, cfg.TunName, cfg.ExtraEscapeIPs)
	if err != nil {
		// Kill switch is critical — roll back and return error.
		slog.Error("leakguard: kill switch failed, rolling back", "error", err)
		g.restoreDNS(state.DNSBackup)
		g.restoreIPv6(state.IPv6Backup)
		return fmt.Errorf("leakguard: enable kill switch: %w", err)
	}
	state.KillSwitch = ksState

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
	if err := g.disableKillSwitch(); err != nil {
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

// enableKillSwitch writes pf anchor rules and loads them.
func (g *darwinGuard) enableKillSwitch(serverIP string, serverPort int, tunName string, extraIPs []net.IP) (KillSwitchState, error) {
	// Order matters with "quick": first matching rule wins.
	// pass rules MUST come before block, otherwise server escape route is blocked.
	rules := []string{
		fmt.Sprintf("pass out quick proto {tcp, udp} to %s port %d", serverIP, serverPort),
		"pass out quick on lo0 all",
		"pass out quick proto udp from any port 68 to any port 67",
	}
	// Allow UDP to TURN relay IPs (WB TURN escape route)
	for _, ip := range extraIPs {
		rules = append(rules, fmt.Sprintf("pass out quick proto udp to %s", ip.String()))
	}
	rules = append(rules,
		fmt.Sprintf("pass out quick on %s all", tunName),
		"block out all",
	)

	content := strings.Join(rules, "\n") + "\n"
	if err := os.WriteFile(pfRulesPath, []byte(content), 0600); err != nil {
		return KillSwitchState{}, fmt.Errorf("write pf rules to %s: %w", pfRulesPath, err)
	}

	// Load rules into the shadowlink anchor.
	// We intentionally do NOT run "pfctl -e" because pf is already enabled on macOS 10.15+.
	out, err := exec.Command("pfctl", "-a", pfAnchor, "-f", pfRulesPath).CombinedOutput()
	if err != nil {
		// Clean up the temp file on failure.
		os.Remove(pfRulesPath)
		return KillSwitchState{}, fmt.Errorf("pfctl load anchor: %w (output: %s)", err, string(out))
	}

	slog.Info("leakguard: pf kill switch enabled",
		"anchor", pfAnchor, "tun", tunName, "server", serverIP)

	return KillSwitchState{
		Rules:      rules,
		ServerIP:   serverIP,
		ServerPort: serverPort,
		TunName:    tunName,
		Backend:    "pf",
	}, nil
}

// disableKillSwitch flushes the pf anchor and removes the temp rules file.
func (g *darwinGuard) disableKillSwitch() error {
	out, err := exec.Command("pfctl", "-a", pfAnchor, "-F", "all").CombinedOutput()
	if err != nil {
		slog.Warn("leakguard: pfctl flush anchor failed",
			"error", err, "output", string(out))
	}

	if err := os.Remove(pfRulesPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("leakguard: failed to remove pf rules file",
			"path", pfRulesPath, "error", err)
	}

	slog.Info("leakguard: pf kill switch disabled")
	return nil
}

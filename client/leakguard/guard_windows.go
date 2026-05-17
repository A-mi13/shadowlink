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

// windowsGuard implements LeakGuard for Windows using netsh and Windows Firewall.
type windowsGuard struct {
	statePath string
}

// New returns a platform-specific LeakGuard implementation.
// statePath is used for crash-recovery state persistence.
func New(statePath string) (LeakGuard, error) {
	return &windowsGuard{statePath: statePath}, nil
}

// Enable activates DNS, IPv6 and kill-switch protection.
func (g *windowsGuard) Enable(cfg LeakGuardConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	var state State
	state.EnabledAt = time.Now().UTC()
	state.Platform = "windows"

	// 1. Backup DNS.
	dnsBackup, err := g.backupDNS()
	if err != nil {
		slog.Warn("leakguard: failed to backup DNS, continuing", "error", err)
	}
	state.DNSBackup = dnsBackup

	// 2. Set DNS to Cloudflare + Google.
	g.setDNS(dnsBackup)

	// 3. Disable IPv6 on non-TUN interfaces.
	ipv6Backup, err := g.disableIPv6(cfg.TunName)
	if err != nil {
		slog.Warn("leakguard: failed to disable IPv6", "error", err)
	}
	state.IPv6Backup = ipv6Backup

	// 4. Enable kill switch rules.
	ks, err := g.enableKillSwitch(cfg)
	if err != nil {
		// Kill switch is critical — roll back everything.
		slog.Error("leakguard: kill switch failed, rolling back", "error", err)
		g.restoreIPv6(state.IPv6Backup)
		g.restoreDNS(state.DNSBackup)
		g.flushDNS()
		return fmt.Errorf("leakguard: enable kill switch: %w", err)
	}
	state.KillSwitch = ks

	// 5. Save state.
	if err := SaveState(g.statePath, &state); err != nil {
		slog.Warn("leakguard: failed to save state", "error", err)
	}

	slog.Info("leakguard enabled")
	return nil
}

// Disable removes all protections and restores original settings.
func (g *windowsGuard) Disable() error {
	if !StateExists(g.statePath) {
		slog.Warn("leakguard: no state file, attempting cleanup by rule names")
		g.removeKillSwitchByName()
		return nil
	}

	state, err := LoadState(g.statePath)
	if err != nil {
		slog.Warn("leakguard: corrupt state file, attempting cleanup by rule names", "error", err)
		g.removeKillSwitchByName()
		_ = DeleteState(g.statePath)
		return nil
	}

	// 1. Remove kill switch rules.
	g.removeKillSwitchRules(state.KillSwitch.Rules)

	// 2. Restore IPv6.
	g.restoreIPv6(state.IPv6Backup)

	// 3. Restore DNS.
	g.restoreDNS(state.DNSBackup)

	// 4. Flush DNS cache.
	g.flushDNS()

	// 5. Delete state file.
	if err := DeleteState(g.statePath); err != nil {
		slog.Warn("leakguard: failed to delete state", "error", err)
	}

	slog.Info("leakguard disabled")
	return nil
}

// ---------------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------------

// backupDNS parses "netsh interface ip show dns" to capture current DNS servers.
func (g *windowsGuard) backupDNS() (DNSBackup, error) {
	out, err := exec.Command("netsh", "interface", "ip", "show", "dns").CombinedOutput()
	if err != nil {
		return DNSBackup{}, fmt.Errorf("netsh show dns: %w: %s", err, out)
	}

	var backup DNSBackup
	var current *DNSEntry

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Lines like:
		//   Configuration for interface "Wi-Fi"
		//   Configuration for interface "Ethernet"
		if strings.HasPrefix(line, "Configuration for interface") {
			// Save previous entry if it had servers.
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

		// DNS servers statically configured / DHCP-configured lines contain IPs.
		// Look for lines that contain an IP-like value.
		if strings.Contains(line, "DNS") && strings.Contains(line, "configured") {
			// Header line, skip.
			continue
		}
		if ip := extractIP(line); ip != "" {
			current.Servers = append(current.Servers, ip)
		}
	}
	// Flush last entry.
	if current != nil && len(current.Servers) > 0 {
		backup.Entries = append(backup.Entries, *current)
	}

	return backup, nil
}

// setDNS sets DNS on common network interfaces to 1.1.1.1 and 8.8.8.8.
func (g *windowsGuard) setDNS(backup DNSBackup) {
	// Use interfaces discovered by backup instead of hardcoded list.
	for _, entry := range backup.Entries {
		iface := entry.InterfaceName
		if iface == "" {
			continue
		}
		out, err := exec.Command("netsh", "interface", "ip", "set", "dns",
			iface, "static", "1.1.1.1").CombinedOutput()
		if err != nil {
			slog.Debug("leakguard: set dns primary failed", "interface", iface, "error", err, "output", string(out))
			continue
		}
		out, err = exec.Command("netsh", "interface", "ip", "add", "dns",
			iface, "8.8.8.8", "index=2").CombinedOutput()
		if err != nil {
			slog.Debug("leakguard: add dns secondary failed", "interface", iface, "error", err, "output", string(out))
		}
	}
	g.flushDNS()
}

// restoreDNS restores DNS settings from the backup.
func (g *windowsGuard) restoreDNS(backup DNSBackup) {
	for _, entry := range backup.Entries {
		if len(entry.Servers) == 0 {
			// No servers means DHCP was used — reset to DHCP.
			out, err := exec.Command("netsh", "interface", "ip", "set", "dns",
				entry.InterfaceName, "dhcp").CombinedOutput()
			if err != nil {
				slog.Warn("leakguard: restore dns dhcp failed", "interface", entry.InterfaceName, "error", err, "output", string(out))
			}
			continue
		}
		// Restore first server as static.
		out, err := exec.Command("netsh", "interface", "ip", "set", "dns",
			entry.InterfaceName, "static", entry.Servers[0]).CombinedOutput()
		if err != nil {
			slog.Warn("leakguard: restore dns primary failed", "interface", entry.InterfaceName, "error", err, "output", string(out))
			continue
		}
		// Add remaining servers.
		for i := 1; i < len(entry.Servers); i++ {
			out, err = exec.Command("netsh", "interface", "ip", "add", "dns",
				entry.InterfaceName, entry.Servers[i], fmt.Sprintf("index=%d", i+1)).CombinedOutput()
			if err != nil {
				slog.Warn("leakguard: restore dns secondary failed", "interface", entry.InterfaceName, "server", entry.Servers[i], "error", err, "output", string(out))
			}
		}
	}
}

// flushDNS runs ipconfig /flushdns.
func (g *windowsGuard) flushDNS() {
	out, err := exec.Command("ipconfig", "/flushdns").CombinedOutput()
	if err != nil {
		slog.Warn("leakguard: flush dns failed", "error", err, "output", string(out))
	}
}

// ---------------------------------------------------------------------------
// IPv6 helpers
// ---------------------------------------------------------------------------

// disableIPv6 disables IPv6 on all interfaces except the TUN and Loopback.
func (g *windowsGuard) disableIPv6(tunName string) (IPv6Backup, error) {
	var backup IPv6Backup

	out, err := exec.Command("netsh", "interface", "ipv6", "show", "interface").CombinedOutput()
	if err != nil {
		return backup, fmt.Errorf("netsh ipv6 show interface: %w: %s", err, out)
	}

	indices := parseIPv6Interfaces(string(out), tunName)

	for _, idx := range indices {
		out, err := exec.Command("netsh", "interface", "ipv6", "set", "interface",
			idx, "disabled").CombinedOutput()
		if err != nil {
			slog.Warn("leakguard: disable ipv6 failed", "index", idx, "error", err, "output", string(out))
			continue
		}
		backup.DisabledInterfaces = append(backup.DisabledInterfaces, idx)
	}

	return backup, nil
}

// restoreIPv6 re-enables IPv6 on previously disabled interfaces.
func (g *windowsGuard) restoreIPv6(backup IPv6Backup) {
	for _, idx := range backup.DisabledInterfaces {
		out, err := exec.Command("netsh", "interface", "ipv6", "set", "interface",
			idx, "enabled").CombinedOutput()
		if err != nil {
			slog.Warn("leakguard: restore ipv6 failed", "index", idx, "error", err, "output", string(out))
		}
	}
}

// parseIPv6Interfaces extracts interface indices from netsh output,
// skipping Loopback and the TUN interface.
func parseIPv6Interfaces(output, tunName string) []string {
	var indices []string
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip header lines (first 3 lines are headers + separator).
	for i := 0; i < 3 && scanner.Scan(); i++ {
		// consume
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		// Format: Idx  Met  MTU   State        Name
		// e.g.:   1    75   ...   Connected    Loopback Pseudo-Interface 1
		if len(fields) < 5 {
			continue
		}

		idx := fields[0]
		if _, err := strconv.Atoi(idx); err != nil {
			continue // not a valid index line
		}

		// Reconstruct the name from remaining fields (fields[4:]).
		name := strings.Join(fields[4:], " ")

		// Skip loopback and TUN.
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
	"SL-Allow-Escape-UDP", // optional escape route for extra UDP destinations
}

// enableKillSwitch adds Windows Firewall rules that block all traffic except
// through the VPN tunnel.
func (g *windowsGuard) enableKillSwitch(cfg LeakGuardConfig) (KillSwitchState, error) {
	// Build comma-separated list of ALL server IPs for firewall rules.
	// CDN (Cloudflare) returns multiple IPs — ALL must be allowed or
	// the kill switch blocks download stream ACKs to the "other" IP.
	allIPs := cfg.AllServerIPs()
	var ipStrs []string
	for _, ip := range allIPs {
		ipStrs = append(ipStrs, ip.String())
	}
	serverIPList := strings.Join(ipStrs, ",")
	port := strconv.Itoa(cfg.ServerPort)

	rules := []struct {
		name string
		args []string
	}{
		{
			name: "SL-Block-All",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Block-All", "dir=out", "action=block"},
		},
		{
			name: "SL-Allow-TUN",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-TUN", "dir=out", "action=allow",
				"localip=198.18.0.0/15"},
		},
		{
			name: "SL-Allow-Server-TCP",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-Server-TCP", "dir=out", "action=allow",
				fmt.Sprintf("remoteip=%s", serverIPList),
				fmt.Sprintf("remoteport=%s", port),
				"protocol=tcp"},
		},
		{
			name: "SL-Allow-Server-UDP",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-Server-UDP", "dir=out", "action=allow",
				fmt.Sprintf("remoteip=%s", serverIPList),
				fmt.Sprintf("remoteport=%s", port),
				"protocol=udp"},
		},
		{
			name: "SL-Allow-Loopback",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-Loopback", "dir=out", "action=allow",
				"remoteip=127.0.0.0/8"},
		},
		{
			name: "SL-Allow-DHCP",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-DHCP", "dir=out", "action=allow",
				"protocol=udp", "localport=68", "remoteport=67"},
		},
	}

	// Add escape rules for extra IPs (optional UDP relays bypassing the TUN).
	if len(cfg.ExtraEscapeIPs) > 0 {
		var escapeIPs []string
		for _, ip := range cfg.ExtraEscapeIPs {
			escapeIPs = append(escapeIPs, ip.String())
		}
		rules = append(rules, struct {
			name string
			args []string
		}{
			name: "SL-Allow-Escape-UDP",
			args: []string{"advfirewall", "firewall", "add", "rule",
				"name=SL-Allow-Escape-UDP", "dir=out", "action=allow",
				fmt.Sprintf("remoteip=%s", strings.Join(escapeIPs, ",")),
				"protocol=udp"},
		})
	}

	var added []string
	for _, r := range rules {
		out, err := exec.Command("netsh", r.args...).CombinedOutput()
		if err != nil {
			slog.Error("leakguard: add firewall rule failed", "rule", r.name, "error", err, "output", string(out))
			// Rollback already-added rules.
			g.removeKillSwitchRules(added)
			return KillSwitchState{}, fmt.Errorf("add rule %s: %w: %s", r.name, err, out)
		}
		added = append(added, r.name)
	}

	return KillSwitchState{
		Rules:      added,
		ServerIP:   serverIPList,
		ServerPort: cfg.ServerPort,
		TunName:    cfg.TunName,
		Backend:    "netsh-advfirewall",
	}, nil
}

// removeKillSwitchRules deletes the listed firewall rules by name.
func (g *windowsGuard) removeKillSwitchRules(rules []string) {
	for _, name := range rules {
		out, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf("name=%s", name)).CombinedOutput()
		if err != nil {
			slog.Warn("leakguard: delete firewall rule failed", "rule", name, "error", err, "output", string(out))
		}
	}
}

// removeKillSwitchByName tries to remove all well-known SL- rules.
// Used for crash recovery when the state file is missing or corrupt.
func (g *windowsGuard) removeKillSwitchByName() {
	for _, name := range killSwitchRuleNames {
		out, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf("name=%s", name)).CombinedOutput()
		if err != nil {
			// This is expected if rules don't exist — debug level.
			slog.Debug("leakguard: cleanup rule not found", "rule", name, "error", err, "output", string(out))
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

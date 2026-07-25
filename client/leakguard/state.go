package leakguard

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// State holds everything LeakGuard needs to undo its changes after a crash.
type State struct {
	EnabledAt  time.Time       `json:"enabled_at"`
	Platform   string          `json:"platform"`
	DNSBackup  DNSBackup       `json:"dns_backup"`
	IPv6Backup IPv6Backup      `json:"ipv6_backup"`
	KillSwitch KillSwitchState `json:"kill_switch"`

	// SplitTunnel records whether explicit split-tunnel was active so restore
	// is honest about what was applied.
	SplitTunnel bool `json:"split_tunnel,omitempty"`
	// FirewallPolicyBackup (Windows) stores the per-profile default firewall
	// actions captured BEFORE the kill switch flipped the default outbound
	// policy to Block (LG-H1), so Disable/crash recovery can restore them
	// verbatim. Empty while KillSwitch.Rules is non-empty = backup read failed
	// at enable → restore falls back to the Windows factory default.
	FirewallPolicyBackup []FirewallProfilePolicy `json:"firewall_policy_backup,omitempty"`
	// WFPActive (Windows) is true when RU CIDR WFP filters were installed under
	// our provider GUID and must be removed via DeleteByProvider on cleanup.
	WFPActive bool `json:"wfp_active,omitempty"`
	// PFEnabledByUs (Darwin) is true when we ran `pfctl -E` ourselves and must
	// run `pfctl -d` on disable to restore the prior disabled state.
	PFEnabledByUs bool `json:"pf_enabled_by_us,omitempty"`
	// PFRulesPath (Darwin) is the on-disk pf rules file path (app-dir, not /tmp)
	// to clean up.
	PFRulesPath string `json:"pf_rules_path,omitempty"`
	// ResolvConfWasSymlink (Linux) records that /etc/resolv.conf was a symlink
	// (managed by resolved/NM) so restore re-creates it instead of writing.
	ResolvConfWasSymlink bool   `json:"resolv_conf_was_symlink,omitempty"`
	ResolvConfTarget     string `json:"resolv_conf_target,omitempty"`
}

// DNSBackup stores original DNS settings so they can be restored.
type DNSBackup struct {
	Entries []DNSEntry `json:"entries"`
}

// DNSEntry represents DNS servers configured on a single network interface.
type DNSEntry struct {
	InterfaceName string   `json:"interface_name"`
	Servers       []string `json:"servers"`
}

// IPv6Backup stores the list of interfaces where IPv6 was disabled
// and (on Linux) the original sysctl value.
type IPv6Backup struct {
	DisabledInterfaces []string `json:"disabled_interfaces"`
	OriginalSysctl     string   `json:"original_sysctl,omitempty"`
}

// FirewallProfilePolicy records the default in/outbound actions of a single
// Windows Firewall profile (Domain/Private/Public) as reported by PowerShell
// Get-NetFirewallProfile (locale-independent enum names: Allow / Block /
// NotConfigured). Stored verbatim so restore reproduces the exact original.
type FirewallProfilePolicy struct {
	Name     string `json:"name"`
	Inbound  string `json:"inbound"`
	Outbound string `json:"outbound"`
}

// KillSwitchState stores firewall rules so they can be removed on cleanup.
type KillSwitchState struct {
	Rules      []string `json:"rules"`
	ServerIP   string   `json:"server_ip"`
	ServerPort int      `json:"server_port"`
	TunName    string   `json:"tun_name"`
	Backend    string   `json:"backend"`
}

// SaveState serialises state to a JSON file with restricted permissions.
func SaveState(path string, s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("leakguard: marshal state: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("leakguard: write state %s: %w", path, err)
	}
	return nil
}

// LoadState reads a previously saved state file.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("leakguard: read state %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("leakguard: unmarshal state %s: %w", path, err)
	}
	return &s, nil
}

// StateExists returns true when a state file is present on disk.
func StateExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DeleteState removes the state file.
func DeleteState(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("leakguard: delete state %s: %w", path, err)
	}
	return nil
}

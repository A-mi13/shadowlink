//go:build windows

package leakguard

import (
	"fmt"
	"log/slog"
	"strings"
)

// LG-H1: Windows Defender Firewall evaluates explicit BLOCK rules before
// ALLOW rules — an explicit block-all rule always beats our allow rules and
// would cut the tunnel itself. Deny-by-default must therefore come from the
// DEFAULT OUTBOUND POLICY (firewallpolicy blockoutbound), which only applies
// when no rule matches — exactly the deny-by-default + allow-exceptions
// semantics the ruleset was designed for. This file owns the policy
// backup/set/restore lifecycle.

// factoryDefaultFirewallPolicy is the out-of-the-box Windows policy, used as
// the restore fallback when no backup is available. Never leave blockoutbound
// stuck — a dead network after a lost state file is worse than restoring the
// stock default on an exotic setup. The per-direction constants are also the
// EFFECTIVE defaults a NotConfigured profile resolves to at runtime.
const (
	factoryDefaultInbound        = "blockinbound"
	factoryDefaultOutbound       = "allowoutbound"
	factoryDefaultFirewallPolicy = factoryDefaultInbound + "," + factoryDefaultOutbound
)

// backupFirewallPolicy captures the per-profile default in/outbound actions
// via PowerShell so it is locale-independent (same approach as backupDNS —
// netsh text output is translated on RU-localized Windows).
func (g *windowsGuard) backupFirewallPolicy() ([]FirewallProfilePolicy, error) {
	out, err := g.runner.run("powershell", "-NoProfile", "-Command",
		"Get-NetFirewallProfile | "+
			"Select-Object Name,DefaultInboundAction,DefaultOutboundAction | "+
			"ConvertTo-Csv -NoTypeInformation")
	if err != nil {
		return nil, fmt.Errorf("get firewall profiles: %w: %s", err, out)
	}
	profiles := parsePSFirewallProfiles(out)
	if len(profiles) == 0 {
		return nil, fmt.Errorf("get firewall profiles: no parsable profiles in output: %s", out)
	}
	return profiles, nil
}

// parsePSFirewallProfiles parses the CSV produced by:
//
//	Get-NetFirewallProfile |
//	  Select-Object Name,DefaultInboundAction,DefaultOutboundAction |
//	  ConvertTo-Csv -NoTypeInformation
//
// Profile names (Domain/Private/Public) and action enum names (Allow/Block/
// NotConfigured) are emitted in English regardless of the system locale.
// Rows that do not have exactly three fields are skipped.
//
// NOTE: the parser relies on quote-all CSV output, which Windows PowerShell
// 5.1 ConvertTo-Csv always produces. pwsh 7+ quotes only when needed — if the
// backup command ever moves to pwsh, it must add `-UseQuotes Always`.
func parsePSFirewallProfiles(csv string) []FirewallProfilePolicy {
	var profiles []FirewallProfilePolicy
	for _, raw := range strings.Split(csv, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		// PowerShell may emit a UTF-8 BOM at stream start.
		line = strings.TrimPrefix(line, "\ufeff")
		if line == "" {
			continue
		}
		// Skip the header row by CONTENT, not by index — a BOM or a leading
		// blank line must not let the header parse as a profile {Name:"Name"}.
		if isFWProfilesCSVHeader(line) {
			continue
		}
		trimmed := strings.TrimPrefix(line, `"`)
		trimmed = strings.TrimSuffix(trimmed, `"`)
		parts := strings.Split(trimmed, `","`)
		if len(parts) != 3 {
			continue
		}
		profiles = append(profiles, FirewallProfilePolicy{
			Name:     strings.TrimSpace(parts[0]),
			Inbound:  strings.TrimSpace(parts[1]),
			Outbound: strings.TrimSpace(parts[2]),
		})
	}
	return profiles
}

// isFWProfilesCSVHeader reports whether a CSV line is the ConvertTo-Csv
// header row of the Get-NetFirewallProfile pipeline.
func isFWProfilesCSVHeader(line string) bool {
	l := strings.ToLower(line)
	return strings.Contains(l, `"name"`) && strings.Contains(l, `"defaultinboundaction"`)
}

// isKillSwitchPolicy reports whether the profile set reads Block/Block on
// EVERY profile — i.e. it equals the armed kill-switch policy.
func isKillSwitchPolicy(profiles []FirewallProfilePolicy) bool {
	if len(profiles) == 0 {
		return false
	}
	for _, p := range profiles {
		if !strings.EqualFold(strings.TrimSpace(p.Inbound), "Block") ||
			!strings.EqualFold(strings.TrimSpace(p.Outbound), "Block") {
			return false
		}
	}
	return true
}

// reconcilePolicyBackup defends the policy backup against poisoning after a
// crash inside the arming window (BLOCKER 2): if the freshly read policy
// equals the armed kill-switch policy (Block/Block on every profile) AND a
// persisted state carries an older non-poisoned backup, prefer the persisted
// backup — the fresh read is almost certainly our own blockoutbound left over
// from a crashed Enable, and persisting it would make a later legitimate
// Disable "restore" blockoutbound forever (stuck-broken-host).
//
// Simplest-correct-variant trade-off (documented intentionally): a host whose
// admin deliberately runs Block/Block on all profiles AND has a stale
// leakguard state gets the persisted backup instead of Block/Block. Restoring
// a too-permissive default is recoverable by the admin; a self-inflicted
// permanent blockoutbound is not.
// A failed fresh read (empty) is treated the same way: a persisted non-poisoned
// backup is better than overwriting it with nothing (which would degrade a
// later restore to the factory default).
func (g *windowsGuard) reconcilePolicyBackup(fresh []FirewallProfilePolicy) []FirewallProfilePolicy {
	if len(fresh) > 0 && !isKillSwitchPolicy(fresh) {
		return fresh
	}
	prev, err := LoadState(g.statePath)
	if err != nil || len(prev.FirewallPolicyBackup) == 0 || isKillSwitchPolicy(prev.FirewallPolicyBackup) {
		return fresh
	}
	if len(fresh) == 0 {
		slog.Warn("leakguard: fresh firewall policy read failed — reusing the persisted backup")
	} else {
		slog.Warn("leakguard: fresh firewall policy backup equals the armed kill-switch policy — " +
			"preferring the persisted backup (a previous enable likely crashed after arming)")
	}
	return prev.FirewallPolicyBackup
}

// setKillSwitchFirewallPolicy flips the default policy of ALL profiles to
// blockinbound,blockoutbound — arming the kill switch. blockinbound matches
// the normal Windows default; the per-profile backup covers exotic setups on
// restore. A failure here means the kill switch is NOT armed and MUST be
// surfaced as an Enable error (silent fail-open is unacceptable).
func (g *windowsGuard) setKillSwitchFirewallPolicy() error {
	out, err := g.runner.run("netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "blockinbound,blockoutbound")
	if err != nil {
		return fmt.Errorf("set firewallpolicy blockoutbound: %w: %s", err, out)
	}
	return nil
}

// netshProfileToken maps a PowerShell profile name to its netsh counterpart.
// Returns "" for unknown names.
func netshProfileToken(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "domain":
		return "domainprofile"
	case "private":
		return "privateprofile"
	case "public":
		return "publicprofile"
	default:
		return ""
	}
}

// netshActionToken maps a Get-NetFirewallProfile action enum name to the
// netsh firewallpolicy keyword for the given direction. Returns "" for
// unknown values.
func netshActionToken(action string, inbound bool) string {
	dir := "outbound"
	if inbound {
		dir = "inbound"
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow":
		return "allow" + dir
	case "block":
		return "block" + dir
	case "notconfigured":
		// netsh rejects "notconfigured" for the LOCAL policy store (it is
		// valid only for the Group Policy store), and NotConfigured/
		// NotConfigured is the stock state of Get-NetFirewallProfile on a
		// normal machine. Restore the EFFECTIVE direction default instead:
		// an unconfigured profile behaves as inbound=Block, outbound=Allow.
		if inbound {
			return factoryDefaultInbound
		}
		return factoryDefaultOutbound
	default:
		return ""
	}
}

// restoreFirewallPolicy restores the per-profile default policy from backup.
// Fail-secure restore semantics: anything unmappable or missing falls back to
// the Windows factory default (blockinbound,allowoutbound) with a Warn, and a
// failed per-profile netsh restore is RETRIED with the factory default for
// that profile — blockoutbound must never be left stuck after the guard is
// gone, on any profile.
func (g *windowsGuard) restoreFirewallPolicy(backup []FirewallProfilePolicy) {
	restored := 0
	for _, p := range backup {
		profile := netshProfileToken(p.Name)
		if profile == "" {
			slog.Warn("leakguard: unknown firewall profile in backup, skipping", "profile", p.Name)
			continue
		}
		in := netshActionToken(p.Inbound, true)
		out := netshActionToken(p.Outbound, false)
		if in == "" || out == "" {
			slog.Warn("leakguard: unmappable firewall actions in backup, using factory default for profile",
				"profile", p.Name, "inbound", p.Inbound, "outbound", p.Outbound)
			in, out = factoryDefaultInbound, factoryDefaultOutbound
		}
		policy := in + "," + out
		if outStr, err := g.runner.run("netsh", "advfirewall", "set", profile,
			"firewallpolicy", policy); err != nil {
			slog.Warn("leakguard: restore firewall policy failed, retrying with factory default",
				"profile", profile, "policy", policy, "error", err, "output", outStr)
			if policy == factoryDefaultFirewallPolicy {
				continue // a retry would be the identical command
			}
			// Fail-secure: never leave this profile possibly stuck on
			// blockoutbound just because its exact restore command errored.
			if outStr, err := g.runner.run("netsh", "advfirewall", "set", profile,
				"firewallpolicy", factoryDefaultFirewallPolicy); err != nil {
				slog.Warn("leakguard: factory default retry failed for profile",
					"profile", profile, "error", err, "output", outStr)
				continue
			}
		}
		restored++
	}
	if restored == 0 {
		slog.Warn("leakguard: no firewall policy backup restorable, falling back to Windows factory default",
			"policy", factoryDefaultFirewallPolicy)
		if out, err := g.runner.run("netsh", "advfirewall", "set", "allprofiles",
			"firewallpolicy", factoryDefaultFirewallPolicy); err != nil {
			slog.Warn("leakguard: factory default firewall policy restore failed", "error", err, "output", out)
		}
	}
}

// restorePolicyFromState restores the default firewall policy recorded in
// state. A state with no kill-switch rules AND no policy backup is a
// PreLock-only state — the policy was never touched, so nothing is restored.
// A state WITH a policy backup or rules may be a pre-arm CHECKPOINT (persisted
// by enableKillSwitch immediately before the policy SET — BLOCKER 2): the
// policy may or may not be armed, so it is restored either way; re-asserting
// an unchanged policy is harmless. An armed state without a backup (backup
// read failed at enable) falls back to the factory default inside
// restoreFirewallPolicy.
func (g *windowsGuard) restorePolicyFromState(state *State) {
	if len(state.KillSwitch.Rules) == 0 && len(state.FirewallPolicyBackup) == 0 {
		return
	}
	g.restoreFirewallPolicy(state.FirewallPolicyBackup)
}

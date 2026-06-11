package leakguard

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
)

// tunNameRe validates TUN interface names — only safe chars to prevent command injection.
var tunNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// LeakGuardConfig holds the parameters needed to set up leak protection.
type LeakGuardConfig struct {
	ServerIP       net.IP   // Primary server IP (backward compat)
	ServerIPs      []net.IP // All resolved server IPs (CDN returns multiple — ALL must be allowed)
	ServerPort     int
	TunName        string
	TunGateway     net.IP
	ExtraEscapeIPs []net.IP // Additional IPs that must bypass TUN (e.g. TURN relay servers)

	// SplitTunnel, если true, добавляет allow-правила для BypassRanges и
	// LAN-диапазонов — bypass-трафик идёт мимо TUN И мимо kill-switch.
	// Default false = fail-secure (bypass-дилы режутся kill-switch, leak нет).
	SplitTunnel bool
	// BypassRanges — RU CIDR snapshot (+ admin override) для split-tunnel allow.
	// Игнорируется при SplitTunnel=false. Пустой = только LAN-split.
	BypassRanges []netip.Prefix
}

// AllServerIPs returns all server IPs to allow in firewall rules.
func (c LeakGuardConfig) AllServerIPs() []net.IP {
	if len(c.ServerIPs) > 0 {
		return c.ServerIPs
	}
	if c.ServerIP != nil {
		return []net.IP{c.ServerIP}
	}
	return nil
}

// Validate checks that all config fields are safe and non-empty.
func (c LeakGuardConfig) Validate() error {
	if len(c.AllServerIPs()) == 0 {
		return fmt.Errorf("leakguard: no server IPs configured")
	}
	if c.ServerPort <= 0 || c.ServerPort > 65535 {
		return fmt.Errorf("leakguard: ServerPort %d out of range", c.ServerPort)
	}
	if !tunNameRe.MatchString(c.TunName) {
		return fmt.Errorf("leakguard: TunName %q contains unsafe characters", c.TunName)
	}
	return nil
}

// LeakGuard prevents DNS, IPv6 and traffic leaks while the VPN tunnel is active.
type LeakGuard interface {
	// PreLock применяет DNS + IPv6-disable ДО поднятия TUN, закрывая
	// leak-окно (H2). Идемпотентен; Enable позже доустанавливает kill-switch.
	// Возврат ошибки НЕ фатален сам по себе — caller решает (см. main.go).
	PreLock(cfg LeakGuardConfig) error
	Enable(cfg LeakGuardConfig) error
	Disable() error
}

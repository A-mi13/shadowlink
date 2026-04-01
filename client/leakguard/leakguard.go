package leakguard

import (
	"fmt"
	"net"
	"regexp"
)

// tunNameRe validates TUN interface names — only safe chars to prevent command injection.
var tunNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// LeakGuardConfig holds the parameters needed to set up leak protection.
type LeakGuardConfig struct {
	ServerIP       net.IP
	ServerPort     int
	TunName        string
	TunGateway     net.IP
	ExtraEscapeIPs []net.IP // Additional IPs that must bypass TUN (e.g. TURN relay servers)
}

// Validate checks that all config fields are safe and non-empty.
func (c LeakGuardConfig) Validate() error {
	if c.ServerIP == nil || c.ServerIP.IsUnspecified() {
		return fmt.Errorf("leakguard: ServerIP is nil or unspecified")
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
	Enable(cfg LeakGuardConfig) error
	Disable() error
}

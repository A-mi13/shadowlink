package client

import (
	"net"
	"strings"
)

// Action represents the routing decision for a destination host.
type Action int

const (
	ActionTunnel Action = iota // send through ShadowLink tunnel (default)
	ActionDirect               // connect directly, bypassing the tunnel
	ActionBlock                // refuse the connection entirely
)

type matcher struct {
	pattern string
	cidr    *net.IPNet
}

func newMatcher(pattern string) matcher {
	_, cidr, err := net.ParseCIDR(pattern)
	if err == nil {
		return matcher{cidr: cidr}
	}
	return matcher{pattern: strings.ToLower(pattern)}
}

func (m matcher) matches(host string) bool {
	host = strings.ToLower(host)
	if m.cidr != nil {
		ip := net.ParseIP(host)
		return ip != nil && m.cidr.Contains(ip)
	}
	p := m.pattern
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:] // ".ru"
		return strings.HasSuffix(host, suffix)
	}
	return host == p || strings.HasSuffix(host, "."+p)
}

// Router evaluates routing rules (block / force-tunnel / bypass) for destination hosts.
// Priority: block > force > bypass > default (tunnel).
type Router struct {
	block  []matcher
	force  []matcher
	bypass []matcher
}

// NewRouter creates a Router from a RoutingConfig.
func NewRouter(cfg RoutingConfig) *Router {
	r := &Router{}
	for _, p := range cfg.Block {
		r.block = append(r.block, newMatcher(p))
	}
	for _, p := range cfg.Force {
		r.force = append(r.force, newMatcher(p))
	}
	for _, p := range cfg.Bypass {
		r.bypass = append(r.bypass, newMatcher(p))
	}
	return r
}

// Decide returns the routing Action for the given host or host:port address.
func (r *Router) Decide(host string) Action {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, m := range r.block {
		if m.matches(host) {
			return ActionBlock
		}
	}
	for _, m := range r.force {
		if m.matches(host) {
			return ActionTunnel
		}
	}
	for _, m := range r.bypass {
		if m.matches(host) {
			return ActionDirect
		}
	}
	return ActionTunnel
}

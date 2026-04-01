package server

import (
	"context"
	"fmt"
	"net"
	"time"
)

// privateCIDRs are IP ranges that must never be dialed via CONNECT.
// Prevents SSRF to internal services (PostgreSQL, Redis, AWS metadata, etc.)
var privateCIDRs = []string{
	"127.0.0.0/8",    // loopback
	"10.0.0.0/8",     // RFC 1918
	"172.16.0.0/12",  // RFC 1918
	"192.168.0.0/16", // RFC 1918
	"169.254.0.0/16", // link-local
	"::1/128",        // IPv6 loopback
	"fc00::/7",       // IPv6 unique local
	"fe80::/10",      // IPv6 link-local
	"100.64.0.0/10",  // carrier-grade NAT
	"0.0.0.0/8",      // "this" network
}

var privateNets []*net.IPNet

func init() {
	for _, cidr := range privateCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid CIDR in privateCIDRs: " + cidr)
		}
		privateNets = append(privateNets, network)
	}
}

// isPrivateIP checks if an IP belongs to a private/reserved range.
func isPrivateIP(ip net.IP) bool {
	for _, network := range privateNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// SafeDial resolves the target hostname and connects to it,
// rejecting connections to private/reserved IP ranges.
// This prevents SSRF attacks via the CONNECT handler.
func SafeDial(ctx context.Context, target string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	// Validate port
	if port == "" {
		return nil, fmt.Errorf("missing port in target")
	}

	// Resolve hostname to IP (DNS rebinding protection: check IP AFTER resolution)
	resolver := &net.Resolver{}
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		// If host is already an IP, parse it directly
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("cannot resolve target: %w", err)
		}
		if isPrivateIP(ip) {
			return nil, fmt.Errorf("target IP is in private range")
		}
		// Connect to the raw IP
		dialer := &net.Dialer{Timeout: timeout}
		return dialer.DialContext(ctx, "tcp", target)
	}

	// Check ALL resolved IPs — reject if ANY is private (DNS rebinding defense)
	var validIP net.IP
	for _, ipAddr := range ips {
		if isPrivateIP(ipAddr.IP) {
			return nil, fmt.Errorf("target resolves to private IP")
		}
		if validIP == nil {
			validIP = ipAddr.IP
		}
	}

	if validIP == nil {
		return nil, fmt.Errorf("target resolved to no valid IPs")
	}

	// Connect to the resolved IP (not the hostname — prevents TOCTOU DNS rebinding)
	dialTarget := net.JoinHostPort(validIP.String(), port)
	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", dialTarget)
}

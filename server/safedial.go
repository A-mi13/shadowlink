package server

import (
	"context"
	"fmt"
	"net"
	"time"
)

// privateCIDRs are IP ranges that must never be dialed via CONNECT.
// Prevents SSRF to internal services (PostgreSQL, Redis, AWS metadata, etc.)
//
// H-12 (раунд 18): the IPv6 transition ranges below were missing, and with them
// `[::]` — dialing the unspecified address lands on loopback on Linux, so
// `FlagConnect` to `[::]:6379` reached local Redis/PostgreSQL/admin APIs on the
// same VPS. The IPv4 form was already covered (0.0.0.0/8), the IPv6 form was not:
// a pure asymmetry. NAT64/6to4/Teredo matter because they EMBED an IPv4 address —
// `64:ff9b::7f00:1` and `2002:7f00:1::` both route to 127.0.0.1 on a host with
// the corresponding translation configured, so filtering only the native IPv4
// forms leaves an equivalent path open.
//
// Note: unspecified/multicast are matched via net.IP methods in isPrivateIP
// rather than CIDR, mirroring proxy/socks5/direct.go's isUnsafeDirectIP — the
// client-side guard has used the method form (and covered IsUnspecified) all
// along; this list was the one lagging behind.
var privateCIDRs = []string{
	"127.0.0.0/8",    // loopback
	"10.0.0.0/8",     // RFC 1918
	"172.16.0.0/12",  // RFC 1918
	"192.168.0.0/16", // RFC 1918
	"169.254.0.0/16", // link-local (incl. cloud metadata 169.254.169.254)
	"::1/128",        // IPv6 loopback
	"fc00::/7",       // IPv6 unique local
	"fe80::/10",      // IPv6 link-local
	"100.64.0.0/10",  // carrier-grade NAT
	"0.0.0.0/8",      // "this" network

	// H-12 additions.
	"64:ff9b::/96",       // NAT64 well-known prefix (RFC 6052) — embeds IPv4
	"64:ff9b:1::/48",     // local-use NAT64 (RFC 8215)
	"2002::/16",          // 6to4 (RFC 3056) — embeds IPv4
	"2001::/32",          // Teredo (RFC 4380) — embeds IPv4
	"100::/64",           // discard-only (RFC 6666)
	"198.18.0.0/15",      // benchmark (RFC 2544); overlaps our own TUN → loop
	"255.255.255.255/32", // limited broadcast
}

// Deliberately NOT blocked: the TEST-NET documentation ranges (192.0.2.0/24,
// 198.51.100.0/24, 203.0.113.0/24, RFC 5737). They are reserved, but reserved is
// not the criterion — reaching a local service is. TEST-NET addresses route
// nowhere on a normal host, so blocking them widens the perimeter without
// closing a vector, and 203.0.113.1 is used as a stand-in for a public IP by the
// server's own tests and decoy fixtures.

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
//
// The method-based checks come first: they are cheap, and they cover the two
// classes where a CIDR entry alone would miss a form. `IsUnspecified` catches
// both `0.0.0.0` and `::` (H-12 — the latter used to pass); the multicast
// checks catch 224.0.0.0/4 and ff00::/8 including IPv4-mapped variants, which
// Go normalizes into the 4-byte form that a v6 CIDR would not match.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true // fail closed: an unparseable target is never safe to dial
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() {
		return true
	}
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

package socks5

import (
	"context"
	"io"
	"net"
	"time"
)

// lookupIPFunc resolves a host to its IP addresses. It is a package var so
// tests can inject a mock resolver (DNS-rebind / empty-lookup scenarios)
// without real network access. Production uses net.DefaultResolver.
var lookupIPFunc = func(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// isUnsafeDirectIP reports whether dialing this IP directly would be an SSRF
// vector: loopback, RFC1918/ULA private, link-local (incl. cloud metadata
// 169.254.169.254 / fe80::), or the unspecified address. Mirrors the server-
// side guard in server/safedial.go.
func isUnsafeDirectIP(ip net.IP) bool {
	return ip == nil ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

// DirectDial connects directly to destAddr with SSRF protection.
//
// SEC-H3 fix (2026-06-11): the previous implementation resolved the host
// twice — once via LookupIP for the safety check and again implicitly inside
// net.DialTimeout(destAddr) — opening a TOCTOU/DNS-rebind window where an
// attacker-controlled resolver could return a public IP for the check and a
// private IP for the dial. It also SKIPPED the check entirely when LookupIP
// errored. This version resolves ONCE, rejects if ANY resolved IP is unsafe,
// fails closed on resolve error, and dials the validated IP literal directly
// (never the hostname), so the IP that was checked is the IP that is dialed.
// Approach mirrors the TOCTOU-safe server/safedial.go.
//
// On success, relays data bidirectionally between conn and the target.
func DirectDial(conn net.Conn, destAddr string) {
	host, port, err := net.SplitHostPort(destAddr)
	if err != nil || host == "" || port == "" {
		conn.Write(ReplyHostUnreachable)
		return
	}

	// If host is already an IP literal, validate it directly — no DNS needed.
	if literal := net.ParseIP(host); literal != nil {
		if isUnsafeDirectIP(literal) {
			conn.Write(ReplyNotAllowed)
			return
		}
		dialAndRelay(conn, net.JoinHostPort(literal.String(), port))
		return
	}

	// Resolve ONCE. Fail closed on error — never dial an unresolved/unchecked
	// host (the old code's silent fall-through was the SSRF hole).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, lookupErr := lookupIPFunc(ctx, host)
	if lookupErr != nil || len(ips) == 0 {
		conn.Write(ReplyHostUnreachable)
		return
	}

	// Reject if ANY resolved IP is unsafe (DNS-rebind defense); pick the first
	// safe one to dial by literal.
	var safeIP net.IP
	for _, ip := range ips {
		if isUnsafeDirectIP(ip) {
			conn.Write(ReplyNotAllowed)
			return
		}
		if safeIP == nil {
			safeIP = ip
		}
	}
	if safeIP == nil {
		conn.Write(ReplyHostUnreachable)
		return
	}

	// Dial the validated IP literal — NOT the hostname — so no second
	// resolution can substitute a different (private) IP.
	dialAndRelay(conn, net.JoinHostPort(safeIP.String(), port))
}

// dialAndRelay dials the already-validated IP:port target and, on success,
// writes the SOCKS5 success reply and relays bidirectionally.
func dialAndRelay(conn net.Conn, ipTarget string) {
	target, err := net.DialTimeout("tcp", ipTarget, 10*time.Second)
	if err != nil {
		conn.Write(ReplyHostUnreachable)
		return
	}
	defer target.Close()
	conn.Write(ReplySuccess)
	go io.Copy(target, conn)
	io.Copy(conn, target)
}

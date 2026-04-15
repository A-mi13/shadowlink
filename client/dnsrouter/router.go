// Package dnsrouter implements a local DNS proxy that enables domain-based
// split routing in system VPN (TUN) mode. For bypass domains (e.g. *.ru),
// resolved IPs get a host route through the real gateway, so traffic goes
// direct instead of through the VPN tunnel.
package dnsrouter

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Config for the DNS router.
type Config struct {
	ListenAddr string   // local DNS listen address (default "127.0.0.1:53")
	Upstream   string   // upstream DNS server (default "1.1.1.1:53")
	Gateway    string   // real gateway IP for bypass routes
	Bypass     []string // domain patterns: "*.ru", "vk.com", etc.
}

// Router is a DNS proxy that adds bypass routes for matched domains.
type Router struct {
	config   Config
	conn     *net.UDPConn
	patterns []pattern
	routes   sync.Map // track added routes for cleanup: IP string → true
	done     chan struct{}
}

type pattern struct {
	suffix string // ".ru" for "*.ru", "" for exact match
	exact  string // "vk.com" for exact match
}

// New creates a DNS router.
func New(cfg Config) *Router {
	if cfg.ListenAddr == "" {
		// Try port 53 first, fall back to 5353 if permission denied (macOS non-root)
		cfg.ListenAddr = "127.0.0.1:53"
	}
	if cfg.Upstream == "" {
		cfg.Upstream = "1.1.1.1:53"
	}

	r := &Router{
		config: cfg,
		done:   make(chan struct{}),
	}

	for _, b := range cfg.Bypass {
		b = strings.TrimSpace(strings.ToLower(b))
		if b == "" {
			continue
		}
		if strings.HasPrefix(b, "*.") {
			r.patterns = append(r.patterns, pattern{suffix: b[1:]}) // "*.ru" → ".ru"
		} else {
			r.patterns = append(r.patterns, pattern{exact: b})
		}
	}

	slog.Info("dnsrouter: configured", "bypass_patterns", len(r.patterns), "upstream", cfg.Upstream, "gateway", cfg.Gateway)
	return r
}

// Start begins listening for DNS queries.
// Falls back to port 5353 if port 53 requires root.
func (r *Router) Start() error {
	addr, err := net.ResolveUDPAddr("udp", r.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("dnsrouter: resolve listen addr: %w", err)
	}

	r.conn, err = net.ListenUDP("udp", addr)
	if err != nil && r.config.ListenAddr == "127.0.0.1:53" {
		// Port 53 needs root on macOS/Linux — fall back to 5353
		slog.Info("dnsrouter: port 53 unavailable, trying 5353")
		r.config.ListenAddr = "127.0.0.1:5353"
		addr, _ = net.ResolveUDPAddr("udp", r.config.ListenAddr)
		r.conn, err = net.ListenUDP("udp", addr)
	}
	if err != nil {
		return fmt.Errorf("dnsrouter: listen %s: %w", r.config.ListenAddr, err)
	}

	slog.Info("dnsrouter: listening", "addr", r.config.ListenAddr)

	go r.serve()
	return nil
}

// Addr returns the actual listen address (may differ from config if fallback was used).
func (r *Router) Addr() string { return r.config.ListenAddr }

// Stop shuts down the DNS router and cleans up added routes.
func (r *Router) Stop() {
	close(r.done)
	if r.conn != nil {
		r.conn.Close()
	}
	r.cleanupRoutes()
}

func (r *Router) serve() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-r.done:
			return
		default:
		}

		r.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-r.done:
				return
			default:
			}
			continue
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		go r.handleQuery(query, clientAddr)
	}
}

func (r *Router) handleQuery(query []byte, clientAddr *net.UDPAddr) {
	// Extract domain from DNS query
	domain := extractQueryDomain(query)

	// Forward to upstream
	upstream, err := net.ResolveUDPAddr("udp", r.config.Upstream)
	if err != nil {
		return
	}

	upConn, err := net.DialUDP("udp", nil, upstream)
	if err != nil {
		return
	}
	defer upConn.Close()

	upConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := upConn.Write(query); err != nil {
		return
	}

	resp := make([]byte, 4096)
	n, err := upConn.Read(resp)
	if err != nil {
		return
	}
	resp = resp[:n]

	// Check if domain matches bypass patterns
	if domain != "" && r.shouldBypass(domain) {
		// Extract A record IPs from response and add bypass routes
		ips := extractARecords(resp)
		for _, ip := range ips {
			r.addBypassRoute(ip)
		}
	}

	// Send response back to client
	r.conn.WriteToUDP(resp, clientAddr)
}

// shouldBypass checks if a domain matches any bypass pattern.
func (r *Router) shouldBypass(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, p := range r.patterns {
		if p.exact != "" && domain == p.exact {
			return true
		}
		if p.suffix != "" && (strings.HasSuffix(domain, p.suffix) || domain == p.suffix[1:]) {
			return true
		}
	}
	return false
}

// addBypassRoute adds a host route for the IP through the real gateway.
func (r *Router) addBypassRoute(ip net.IP) {
	ipStr := ip.String()
	if _, loaded := r.routes.LoadOrStore(ipStr, true); loaded {
		return // already added
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("route", "add", ipStr, "mask", "255.255.255.255", r.config.Gateway, "metric", "5")
	case "darwin":
		cmd = exec.Command("route", "-n", "add", "-host", ipStr, r.config.Gateway)
	default: // linux
		cmd = exec.Command("ip", "route", "add", ipStr+"/32", "via", r.config.Gateway)
	}

	if err := cmd.Run(); err != nil {
		// Route may already exist — not an error
		slog.Debug("dnsrouter: route add", "ip", ipStr, "error", err)
	} else {
		slog.Debug("dnsrouter: bypass route added", "ip", ipStr, "gw", r.config.Gateway)
	}
}

// cleanupRoutes removes all bypass routes we added.
func (r *Router) cleanupRoutes() {
	r.routes.Range(func(key, _ any) bool {
		ipStr := key.(string)
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			cmd = exec.Command("route", "delete", ipStr)
		case "darwin":
			cmd = exec.Command("route", "-n", "delete", "-host", ipStr)
		default:
			cmd = exec.Command("ip", "route", "del", ipStr+"/32")
		}
		cmd.Run()
		return true
	})
}

// --- Minimal DNS packet parsing (no external deps) ---

// extractQueryDomain extracts the first question domain from a DNS query packet.
func extractQueryDomain(pkt []byte) string {
	if len(pkt) < 12 {
		return ""
	}
	// Skip header (12 bytes), parse question section
	pos := 12
	var labels []string
	for pos < len(pkt) {
		length := int(pkt[pos])
		if length == 0 {
			break
		}
		if length >= 64 { // compression pointer
			break
		}
		pos++
		if pos+length > len(pkt) {
			break
		}
		labels = append(labels, string(pkt[pos:pos+length]))
		pos += length
	}
	return strings.Join(labels, ".")
}

// extractARecords extracts IPv4 addresses from DNS response A records.
func extractARecords(pkt []byte) []net.IP {
	if len(pkt) < 12 {
		return nil
	}

	// Header: ID(2) + Flags(2) + QDCount(2) + ANCount(2) + NSCount(2) + ARCount(2)
	anCount := int(pkt[6])<<8 | int(pkt[7])
	if anCount == 0 {
		return nil
	}

	// Skip questions section
	pos := 12
	qdCount := int(pkt[4])<<8 | int(pkt[5])
	for i := 0; i < qdCount && pos < len(pkt); i++ {
		pos = skipDNSName(pkt, pos)
		pos += 4 // QTYPE(2) + QCLASS(2)
	}

	// Parse answer records
	var ips []net.IP
	for i := 0; i < anCount && pos < len(pkt); i++ {
		pos = skipDNSName(pkt, pos) // NAME
		if pos+10 > len(pkt) {
			break
		}
		rtype := int(pkt[pos])<<8 | int(pkt[pos+1])
		rdLength := int(pkt[pos+8])<<8 | int(pkt[pos+9])
		pos += 10 // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

		if rtype == 1 && rdLength == 4 && pos+4 <= len(pkt) { // A record
			ip := net.IPv4(pkt[pos], pkt[pos+1], pkt[pos+2], pkt[pos+3])
			if !ip.IsLoopback() && !ip.IsPrivate() {
				ips = append(ips, ip)
			}
		}
		pos += rdLength
	}

	return ips
}

// skipDNSName advances past a DNS name (handling compression pointers).
func skipDNSName(pkt []byte, pos int) int {
	for pos < len(pkt) {
		length := int(pkt[pos])
		if length == 0 {
			return pos + 1
		}
		if length >= 192 { // compression pointer (2 bytes)
			return pos + 2
		}
		pos += 1 + length
	}
	return pos
}

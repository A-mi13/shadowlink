package client

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// pubkeyRe matches exactly 64 lowercase hex characters.
var pubkeyRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// hostnameRe matches a permissive DNS-name shape (letters, digits, dots, hyphens).
// Strict RFC 1123 validation deferred — the pool is admin-configured server-side
// via SQL, so input is trusted; this regex blocks shell/URL injection shapes only.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`)

const defaultSocksAddr = "127.0.0.1:1080"

// maxCDNs caps the SNI rotation pool size carried in `cdns=` query param.
// Same limit applied in ParseSLURL (rejects oversized URLs) and BuildSLURL
// (truncates programmatic callers to preserve roundtrip safety).
const maxCDNs = 8

// ParseSLURL parses an sl:// URL into a ClientFileConfig.
//
// Format: sl://PUBKEY@HOST:PORT?tls=1&ws=1&auto=1&cdn=DOMAIN&sni=DOMAIN&origin=IP&socks=ADDR&ech=1&id=CLIENT_ID
//
// Modes:
//   - Full-CF:     @DOMAIN:443?tls=1&cdn=DOMAIN                       — all traffic via CF
//   - Hybrid:      @DOMAIN:443?tls=1&cdn=DOMAIN&origin=IP              — handshake via CF, WS direct to origin
//   - Full-direct: @IP:443?tls=1&sni=DOMAIN                            — all traffic direct, TLS SNI = DOMAIN
//
// Security:
//   - Pubkey must be exactly 64 lowercase hex characters.
//   - Hostname must not contain '@' (prevents SSRF via sl://key@host@evil.com).
func ParseSLURL(rawURL string) (*ClientFileConfig, error) {
	if !strings.HasPrefix(rawURL, "sl://") {
		return nil, fmt.Errorf("invalid scheme: URL must start with sl://")
	}

	// Replace sl:// with https:// so net/url can parse it correctly.
	httpsURL := "https://" + rawURL[len("sl://"):]

	u, err := url.Parse(httpsURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	// Security: reject hostname containing '@' (SSRF protection).
	// Must check BEFORE extracting pubkey, because url.Parse treats
	// everything before the last '@' as userinfo, masking the attack.
	authority := rawURL[len("sl://"):]
	if qIdx := strings.Index(authority, "?"); qIdx != -1 {
		authority = authority[:qIdx]
	}
	if pIdx := strings.Index(authority, "/"); pIdx != -1 {
		authority = authority[:pIdx]
	}
	if strings.Count(authority, "@") > 1 {
		return nil, fmt.Errorf("invalid URL: hostname must not contain '@'")
	}

	// Extract pubkey from userinfo section.
	pubkey := ""
	if u.User != nil {
		pubkey = u.User.Username()
	}
	if pubkey == "" {
		return nil, fmt.Errorf("missing pubkey in URL")
	}
	if !pubkeyRe.MatchString(pubkey) {
		return nil, fmt.Errorf("invalid pubkey: must be exactly 64 lowercase hex chars")
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	server := host + ":" + port

	q := u.Query()
	cfg := &ClientFileConfig{
		Server:    server,
		PubKey:    pubkey,
		ClientID:  q.Get("id"),
		Socks:     q.Get("socks"),
		TLS:       q.Get("tls") == "1",
		WebSocket: q.Get("ws") == "1",
		Auto:      q.Get("auto") == "1",
		ECH:       q.Get("ech") == "1",
		CDN:       q.Get("cdn"),
		Origin:    q.Get("origin"),
		SNI:       q.Get("sni"),
		CFIP:      q.Get("cfip"),
	}

	// Parse comma-separated backup= list; each entry may omit :port (defaults to 443).
	if raw := q.Get("backup"); raw != "" {
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(entry); err != nil {
				entry = entry + ":443"
			}
			cfg.BackupServers = append(cfg.BackupServers, entry)
		}
	}

	if raw := q.Get("cdns"); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !hostnameRe.MatchString(p) {
				return nil, fmt.Errorf("cdns: invalid hostname %q", p)
			}
			cfg.CDNs = append(cfg.CDNs, p)
		}
		if len(cfg.CDNs) > maxCDNs {
			return nil, fmt.Errorf("cdns: max %d entries, got %d", maxCDNs, len(cfg.CDNs))
		}
	}

	if cfg.Socks == "" {
		cfg.Socks = defaultSocksAddr
	}

	return cfg, nil
}

// BuildSLURL serialises a ClientFileConfig into an sl:// URL.
// Only non-default parameters are included in the query string.
//
// Roundtrip guarantee: ParseSLURL(BuildSLURL(cfg)) produces an equivalent config.
func BuildSLURL(cfg *ClientFileConfig) string {
	// Split host:port from Server field. Use net.SplitHostPort for IPv6 safety.
	host, port, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		host = cfg.Server
		port = "443"
	}

	var b strings.Builder
	b.WriteString("sl://")
	b.WriteString(cfg.PubKey)
	b.WriteString("@")
	b.WriteString(host)
	if port != "" {
		b.WriteString(":")
		b.WriteString(port)
	}

	// Build query params — only include non-defaults.
	params := url.Values{}
	if cfg.TLS {
		params.Set("tls", "1")
	}
	if cfg.WebSocket {
		params.Set("ws", "1")
	}
	if cfg.Auto {
		params.Set("auto", "1")
	}
	if cfg.ECH {
		params.Set("ech", "1")
	}
	if cfg.CDN != "" {
		params.Set("cdn", cfg.CDN)
	}
	if cfg.Origin != "" {
		params.Set("origin", cfg.Origin)
	}
	if cfg.SNI != "" {
		params.Set("sni", cfg.SNI)
	}
	if cfg.CFIP != "" {
		params.Set("cfip", cfg.CFIP)
	}
	if len(cfg.BackupServers) > 0 {
		params.Set("backup", strings.Join(cfg.BackupServers, ","))
	}
	if len(cfg.CDNs) > 0 {
		// Truncate to maxCDNs so ParseSLURL(BuildSLURL(cfg)) round-trips even
		// when programmatic callers exceed the limit. Validation lives in
		// ParseSLURL — emit silently truncates rather than panicking here.
		cdns := cfg.CDNs
		if len(cdns) > maxCDNs {
			cdns = cdns[:maxCDNs]
		}
		params.Set("cdns", strings.Join(cdns, ","))
	}
	if cfg.Socks != "" && cfg.Socks != defaultSocksAddr {
		params.Set("socks", cfg.Socks)
	}
	if cfg.ClientID != "" {
		params.Set("id", cfg.ClientID)
	}

	encoded := params.Encode()
	if encoded != "" {
		b.WriteString("?")
		b.WriteString(encoded)
	}

	return b.String()
}

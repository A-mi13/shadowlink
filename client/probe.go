package client

import (
	"context"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// defaultRuCheckURLs is the rotation pool used by ProbeEngine when the caller
// does not supply RuCheckURLs explicitly. A2-MED-8 (2026-04 audit) closure:
// the previous single hardcoded ya.ru meant every cold start emitted a
// deterministic HTTPS HEAD to the same RU domain — a startup signal a passive
// observer can use to flag the client. We rotate across the top-7 RU sites
// that any normal Russian browser would hit organically. All entries are
// HTTPS-only to keep the JA3 emission consistent across rounds.
var defaultRuCheckURLs = []string{
	"https://yandex.ru",
	"https://mail.ru",
	"https://vk.com",
	"https://ok.ru",
	"https://dzen.ru",
	"https://gosuslugi.ru",
	"https://ria.ru",
}

// newHTTPRequestHEAD builds a HEAD request with a browser User-Agent. Local
// helper for probe.go's CRIT-3 fix — keeps the HEAD construction identical
// across probe targets (CDN domain, ya.ru, etc.).
//
// 2026-05-02 wire-trigger followup NEW-2: when ua is Chrome-family, attach
// the sec-ch-ua header set so the cold-path probe HEAD looks like a real
// Chrome request (Chrome 90+ emits these unconditionally).
func newHTTPRequestHEAD(ctx context.Context, target, ua string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return nil, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
		browser.ApplyChromeCHUAForUA(req.Header, ua)
	}
	req.Header.Set("Accept", "*/*")
	return req, nil
}

// NetworkType classifies the current network environment.
type NetworkType int

const (
	NetworkOpen     NetworkType = iota // Direct access to server works
	NetworkDPIBlock                    // Server IP blocked, but CDN/global IPs work
	NetworkOffline                     // No internet at all
)

func (n NetworkType) String() string {
	switch n {
	case NetworkOpen:
		return "OPEN"
	case NetworkDPIBlock:
		return "DPI_BLOCK"
	case NetworkOffline:
		return "OFFLINE"
	default:
		return "UNKNOWN"
	}
}

// ProbeConfig controls the Probe Engine behavior.
//
// RuCheckURLs is a rotation pool — each Probe round picks one entry at random.
// A nil/empty slice falls back to defaultRuCheckURLs so callers that don't
// care about the pool still get the cold-path-safe behavior.
type ProbeConfig struct {
	ServerAddr  string        // direct server "host:port"
	CDNDomain   string        // Cloudflare domain (optional)
	RuCheckURLs []string      // RU rotation pool (nil/empty → defaultRuCheckURLs)
	Timeout     time.Duration // probe timeout (default: 3s)
}

// DefaultProbeConfig returns spec-compliant defaults.
func DefaultProbeConfig(serverAddr, cdnDomain string) ProbeConfig {
	// Copy the package-level default so callers can mutate the slice without
	// affecting other engines.
	pool := make([]string, len(defaultRuCheckURLs))
	copy(pool, defaultRuCheckURLs)
	return ProbeConfig{
		ServerAddr:  serverAddr,
		CDNDomain:   cdnDomain,
		RuCheckURLs: pool,
		Timeout:     3 * time.Second,
	}
}

// ProbeResults holds the raw results of parallel probes.
type ProbeResults struct {
	DirectOK bool // TCP connect to server succeeded
	CDNOK    bool // HTTPS to CDN domain succeeded
	RuOK     bool // HTTPS to Russian site succeeded
	DNSOK    bool // DNS resolution of server succeeded
}

// Classify determines the network type from probe results.
// Per spec section 8.
func Classify(r ProbeResults) NetworkType {
	if r.DirectOK {
		return NetworkOpen
	}
	if r.CDNOK {
		return NetworkDPIBlock
	}
	return NetworkOffline
}

// ProbeEngine detects network conditions and selects the best transport.
type ProbeEngine struct {
	config    ProbeConfig
	lastType  NetworkType
	lastProbe time.Time
	mu        sync.Mutex
}

// NewProbeEngine creates a probe engine with the given config.
func NewProbeEngine(config ProbeConfig) *ProbeEngine {
	return &ProbeEngine{
		config:   config,
		lastType: NetworkOffline,
	}
}

// Probe runs parallel network probes and returns the classified network type.
// Completes within config.Timeout (default 3 seconds).
func (p *ProbeEngine) Probe(ctx context.Context) (NetworkType, ProbeResults) {
	probeCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	var results ProbeResults
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Pick one fingerprint for the whole probe round so the CDN HEAD and the
	// ya.ru HEAD share a JA3 — independent picks would let an observer
	// correlate "client did 2 HTTPS HEADs at startup with 2 different
	// fingerprints" which is itself a behavioral signal. CRIT-3 fix.
	probeFP := browser.NewFingerprintPool().Next()

	// Probe A: TCP connect to server
	wg.Add(1)
	go func() {
		defer wg.Done()
		ok := probeTCP(probeCtx, p.config.ServerAddr)
		mu.Lock()
		results.DirectOK = ok
		mu.Unlock()
	}()

	// Probe B: HTTPS to CDN domain
	if p.config.CDNDomain != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := probeHTTPS(probeCtx, "https://"+p.config.CDNDomain, probeFP)
			mu.Lock()
			results.CDNOK = ok
			mu.Unlock()
		}()
	}

	// Probe C: HTTPS to Russian site (rotated across the pool per round, A2-MED-8).
	ruTarget := pickRuTarget(p.config.RuCheckURLs)
	if ruTarget != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := probeHTTPS(probeCtx, ruTarget, probeFP)
			mu.Lock()
			results.RuOK = ok
			mu.Unlock()
		}()
	}

	// Probe D: DNS resolve
	wg.Add(1)
	go func() {
		defer wg.Done()
		host, _, _ := net.SplitHostPort(p.config.ServerAddr)
		if host == "" {
			host = p.config.ServerAddr
		}
		ok := probeDNS(probeCtx, host)
		mu.Lock()
		results.DNSOK = ok
		mu.Unlock()
	}()

	wg.Wait()

	netType := Classify(results)

	p.mu.Lock()
	p.lastType = netType
	p.lastProbe = time.Now()
	p.mu.Unlock()

	slog.Debug("probe complete",
		"type", netType.String(),
		"direct", results.DirectOK,
		"cdn", results.CDNOK,
		"ru", results.RuOK,
		"dns", results.DNSOK)

	return netType, results
}

// LastResult returns the last probe result (for warm start).
func (p *ProbeEngine) LastResult() (NetworkType, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastType, p.lastProbe
}

// SelectTransport returns the recommended transport name for the given network type.
func SelectTransport(netType NetworkType) string {
	switch netType {
	case NetworkOpen:
		return "direct"
	case NetworkDPIBlock:
		return "cdn"
	default:
		return ""
	}
}

// pickRuTarget chooses a random URL from the configured pool. Empty/nil pool
// falls back to defaultRuCheckURLs. Returns "" only if both are empty (which
// shouldn't happen since defaultRuCheckURLs is a const-like package var).
func pickRuTarget(pool []string) string {
	if len(pool) == 0 {
		pool = defaultRuCheckURLs
	}
	if len(pool) == 0 {
		return ""
	}
	if len(pool) == 1 {
		return pool[0]
	}
	return pool[mathrand.IntN(len(pool))]
}

// probeTCP attempts a TCP connection to addr.
func probeTCP(ctx context.Context, addr string) bool {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeHTTPS makes a HEAD request to a URL via uTLS.
//
// CRIT-3 (2026-04 audit): the previous implementation built a vanilla
// `&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
// InsecureSkipVerify: true}}}` — Go-stdlib JA3 + skipped cert verification on
// **ya.ru** and on the project's CF domain at every startup. That JA3 is the
// canonical "Go proxy" fingerprint and TSPU's connection-based TLS policing
// (bbs#546, 2025-11) cross-correlates such cold-path emissions with later
// CF-domain hits. The fix routes probes through the same uTLS dialer family
// used on the data path (Chrome/Safari/Firefox) and drops InsecureSkipVerify
// — both ya.ru and the CF domain serve real certs that validate normally.
func probeHTTPS(ctx context.Context, target string, fp *browser.Fingerprint) bool {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return false
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	dialAddr := net.JoinHostPort(host, port)

	var client *http.Client
	if parsed.Scheme == "https" {
		client = buildUTLSHTTPClient(dialAddr, host, fp, false, 3*time.Second, "http/1.1")
	} else {
		// Plaintext fallback — only used by unit tests against httptest.NewServer
		// (which is http://). No JA3 to worry about on plain HTTP.
		client = &http.Client{Timeout: 3 * time.Second}
	}
	defer client.CloseIdleConnections()

	req, err := newHTTPRequestHEAD(ctx, target, fp.UserAgent())
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

// probeDNS resolves a hostname.
func probeDNS(ctx context.Context, host string) bool {
	// If it's already an IP, skip DNS
	if net.ParseIP(host) != nil {
		return true
	}
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, host)
	return err == nil && len(addrs) > 0
}

// AutoConnect probes the network and connects using the best transport.
// This is the high-level "just connect" function.
func AutoConnect(ctx context.Context, config ClientConfig, probeConfig ProbeConfig) (*Client, error) {
	engine := NewProbeEngine(probeConfig)
	netType, _ := engine.Probe(ctx)

	switch netType {
	case NetworkOpen:
		slog.Info("network: OPEN — using direct transport")
		config.CDNDomain = ""
		cl := NewClient(config)
		if err := cl.Connect(ctx); err != nil {
			return nil, fmt.Errorf("direct connect: %w", err)
		}
		return cl, nil

	case NetworkDPIBlock:
		if config.CDNDomain == "" {
			return nil, fmt.Errorf("server IP blocked and no CDN domain configured")
		}
		slog.Info("network: DPI_BLOCK — using CDN transport", "domain", config.CDNDomain)
		cl := NewClient(config) // CDNDomain is set, will use CDN transport
		if err := cl.Connect(ctx); err != nil {
			return nil, fmt.Errorf("CDN connect: %w", err)
		}
		return cl, nil

	default:
		return nil, fmt.Errorf("network offline — no connectivity detected")
	}
}

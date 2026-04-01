package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// NetworkType classifies the current network environment.
type NetworkType int

const (
	NetworkOpen     NetworkType = iota // Direct access to server works
	NetworkDPIBlock                    // Server IP blocked, but CDN/global IPs work
	NetworkWhitelist                   // Only Russian IPs accessible
	NetworkOffline                     // No internet at all
)

func (n NetworkType) String() string {
	switch n {
	case NetworkOpen:
		return "OPEN"
	case NetworkDPIBlock:
		return "DPI_BLOCK"
	case NetworkWhitelist:
		return "WHITELIST"
	case NetworkOffline:
		return "OFFLINE"
	default:
		return "UNKNOWN"
	}
}

// ProbeConfig controls the Probe Engine behavior.
type ProbeConfig struct {
	ServerAddr  string        // direct server "host:port"
	CDNDomain   string        // Cloudflare domain (optional)
	RuCheckURL  string        // Russian URL for whitelist detection (default: ya.ru)
	Timeout     time.Duration // probe timeout (default: 3s)
}

// DefaultProbeConfig returns spec-compliant defaults.
func DefaultProbeConfig(serverAddr, cdnDomain string) ProbeConfig {
	return ProbeConfig{
		ServerAddr: serverAddr,
		CDNDomain:  cdnDomain,
		RuCheckURL: "https://ya.ru",
		Timeout:    3 * time.Second,
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
	if r.RuOK {
		return NetworkWhitelist
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
			ok := probeHTTPS(probeCtx, "https://"+p.config.CDNDomain)
			mu.Lock()
			results.CDNOK = ok
			mu.Unlock()
		}()
	}

	// Probe C: HTTPS to Russian site
	wg.Add(1)
	go func() {
		defer wg.Done()
		ok := probeHTTPS(probeCtx, p.config.RuCheckURL)
		mu.Lock()
		results.RuOK = ok
		mu.Unlock()
	}()

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
	case NetworkWhitelist:
		return "cloud_relay" // Yandex Cloud Functions or VK TURN
	default:
		return ""
	}
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

// probeHTTPS makes a HEAD request to a URL.
func probeHTTPS(ctx context.Context, url string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true, // prevent connection leak
		},
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
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

	case NetworkWhitelist:
		// Cascade: WB TURN (fast, no account needed) → VK TURN (fallback)
		if config.ServerUDPAddr != "" && config.WBTurnEnabled {
			slog.Info("network: WHITELIST — trying WB TURN transport first")
			wbt, err := NewWBTurnTransport(config.ServerUDPAddr)
			if err == nil {
				cl := NewClientWithTransport(wbt, config.ServerPubKey, config.ClientID)
				if err := cl.Connect(ctx); err != nil {
					wbt.Close()
					slog.Warn("WB TURN connect failed, trying VK TURN", "error", err)
				} else {
					return cl, nil
				}
			} else {
				slog.Warn("WB TURN transport failed, trying VK TURN", "error", err)
			}
		}

		// Fallback: VK TURN (Call Skin)
		if config.TURNServer == "" {
			return nil, fmt.Errorf("whitelist mode — no TURN server configured and WB TURN failed")
		}
		slog.Info("network: WHITELIST — using VK TURN (Call Skin) transport", "turn", config.TURNServer)
		callTransport, err := NewCallSkinTransport(CallSkinConfig{
			TURNServer:    config.TURNServer,
			TURNUsername:  config.TURNUsername,
			TURNPassword:  config.TURNPassword,
			ServerUDPAddr: config.ServerUDPAddr,
		})
		if err != nil {
			return nil, fmt.Errorf("call skin transport: %w", err)
		}
		cl := NewClientWithTransport(callTransport, config.ServerPubKey, config.ClientID)
		if err := cl.Connect(ctx); err != nil {
			callTransport.Close()
			return nil, fmt.Errorf("call skin connect: %w", err)
		}
		return cl, nil

	default:
		return nil, fmt.Errorf("network offline — no connectivity detected")
	}
}

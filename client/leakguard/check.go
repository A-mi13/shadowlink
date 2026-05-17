package leakguard

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IPInfo holds the response from ipinfo.io/json.
type IPInfo struct {
	IP       string `json:"ip"`
	Org      string `json:"org"`
	Country  string `json:"country"`
	Timezone string `json:"timezone"`
	City     string `json:"city"`
}

// chromeUserAgent matches the locked Chrome 133 string used by the rest of
// the shadowlink client (skins/browser/fingerprint.go pool). Sending the Go
// stdlib default `Go-http-client/1.1` from CheckIP was a passive cold-path
// signal — A2-MED-2 (2026-04 audit). All client-originated HTTPS calls
// MUST emit a browser-class UA. Constant kept inline (no browser import)
// to avoid a cycle from the leakguard subpackage.
const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

// ipinfoEndpoint is overridable from tests so they can point CheckIP at a
// httptest.NewServer without touching the real ipinfo.io.
var ipinfoEndpoint = "https://ipinfo.io/json"

// buildProxy is overridable from tests. Production code resolves the SOCKS5
// address; tests can return (nil, nil) to bypass the proxy when targeting a
// loopback test server.
var buildProxy = parseSOCKS5URL

// CheckIP queries ipinfo.io through the SOCKS5 proxy (tunnel) and logs warnings
// about datacenter IPs or timezone mismatches.
//
// Cold-path note (A2-MED-2, 2026-04 audit): the request MUST carry a
// browser-class User-Agent. Otherwise a passive observer sees a Go-default
// UA originating from the client IP minutes after the same client emitted
// Chrome JA3 over the data path — an unmistakable inconsistency. We do not
// route this call through uTLS because (a) leakguard is a child package and
// importing the parent client package for a single helper would balloon the
// dependency graph, and (b) ipinfo.io is fronted by Cloudflare which already
// terminates TLS — the JA3 leak from a stdlib HTTPS client is a real but
// secondary concern next to the missing UA. Future work: route via uTLS once
// the client-package helper is exported into a leaf package.
func CheckIP(socksAddr string) (*IPInfo, error) {
	// Create HTTP client that routes through SOCKS5 proxy (= through tunnel).
	// In tests the buildProxy hook can return (nil, nil) to bypass the proxy.
	proxyURL, err := buildProxy(socksAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 address: %w", err)
	}
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, ipinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build ipinfo request: %w", err)
	}
	// Browser-class headers — match the Chrome profile used by the data path
	// uTLS dialer in client/utls_http.go. ipinfo.io accepts both Accept:
	// application/json and the generic */*; we send the latter to match the
	// browser fetch pattern more closely.
	req.Header.Set("User-Agent", chromeUserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query ipinfo.io: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var info IPInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	slog.Info("exit IP check",
		"ip", info.IP,
		"org", info.Org,
		"country", info.Country,
		"city", info.City,
		"timezone", info.Timezone)

	// Warn on datacenter IP
	orgLower := strings.ToLower(info.Org)
	dcKeywords := []string{"hosting", "datacenter", "data center", "cloud", "vps",
		"server", "hetzner", "ovh", "digitalocean", "linode", "vultr"}
	for _, kw := range dcKeywords {
		if strings.Contains(orgLower, kw) {
			slog.Warn("exit IP appears to be a datacenter/hosting IP — may be detected as VPN",
				"org", info.Org, "ip", info.IP)
			break
		}
	}

	// Warn on timezone mismatch — compare UTC offsets, not abbreviations.
	// ipinfo.io returns IANA timezone ("Europe/Moscow"), Go Zone() returns abbreviation ("MSK").
	if info.Timezone != "" {
		if exitLoc, err := time.LoadLocation(info.Timezone); err == nil {
			_, localOffset := time.Now().Zone()
			_, exitOffset := time.Now().In(exitLoc).Zone()
			if localOffset != exitOffset {
				slog.Warn("timezone mismatch: local OS timezone differs from exit IP timezone",
					"local_offset_h", localOffset/3600, "exit_tz", info.Timezone, "exit_offset_h", exitOffset/3600)
			}
		}
	}

	return &info, nil
}

func parseSOCKS5URL(addr string) (*url.URL, error) {
	if addr == "" {
		return nil, fmt.Errorf("empty SOCKS5 address")
	}
	return url.Parse("socks5://" + addr)
}

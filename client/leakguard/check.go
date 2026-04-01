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

// CheckIP queries ipinfo.io through the SOCKS5 proxy (tunnel) and logs warnings
// about datacenter IPs or timezone mismatches.
func CheckIP(socksAddr string) (*IPInfo, error) {
	// Create HTTP client that routes through SOCKS5 proxy (= through tunnel)
	proxyURL, err := parseSOCKS5URL(socksAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 address: %w", err)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			Proxy:       http.ProxyURL(proxyURL),
		},
		Timeout: 15 * time.Second,
	}

	resp, err := httpClient.Get("https://ipinfo.io/json")
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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for the NixaVPN unified client.
type Config struct {
	Protocol   string            `yaml:"protocol"` // auto | shadowlink | vless
	SOCKS      string            `yaml:"socks"`    // "127.0.0.1:1080"
	SystemVPN  bool              `yaml:"system_vpn"`
	ShadowLink *ShadowLinkConfig `yaml:"shadowlink,omitempty"`
	VLESS      *VLESSConfig      `yaml:"vless,omitempty"`
	API        *APIConfig        `yaml:"api,omitempty"`

	// ProxyUser/ProxyPass — случайные credentials для SOCKS5 прокси.
	// Генерируются при каждом запуске, защищают от local proxy IP leak.
	ProxyUser string `yaml:"-"`
	ProxyPass string `yaml:"-"`
}

// ShadowLinkConfig holds ShadowLink protocol connection settings.
type ShadowLinkConfig struct {
	Server     string                `yaml:"server"`
	PubKey     string                `yaml:"pubkey"`
	WebSocket  bool                  `yaml:"websocket"`
	TLS        bool                  `yaml:"tls"`
	Auto       bool                  `yaml:"auto"`
	CDN        string                `yaml:"cdn,omitempty"`
	ECH        bool                  `yaml:"ech,omitempty"`
	Routing    *client.RoutingConfig `yaml:"routing,omitempty"`
	Origin     string                `yaml:"origin,omitempty"`       // origin IP for direct WS (bypass CF CDN)
	SNI        string                `yaml:"sni,omitempty"`          // TLS ServerName override for full-direct mode (IP host + domain SNI)
	CFIP       string                `yaml:"cfip,omitempty"`         // specific Cloudflare edge IP (bypass DNS for WS)
	WSPool     bool                  `yaml:"ws_pool,omitempty"`      // enable WS pool (default true for CDN+WS)
	WSPoolSize int                   `yaml:"ws_pool_size,omitempty"` // pool size (default 6)
	// BackupServers are fallback "host:port" endpoints tried in order when
	// the primary Server handshake fails (ТСПУ blocks the CF SNI, DNS
	// poisoning, etc.). Must share the same X25519 pubkey.
	BackupServers []string `yaml:"backup_servers,omitempty"`
	// CDNs is the SNI rotation pool (DomainPool). Distinct from BackupServers
	// (alternative host:port endpoints). When non-empty, the engine installs a
	// DomainPool on the transport's ConnManager and rotates SNI per reconnect
	// against this list. Max enforced by client.maxCDNs (=8) on URL parsing.
	CDNs []string `yaml:"cdns,omitempty"`
}

// VLESSConfig holds VLESS+Reality connection settings.
type VLESSConfig struct {
	Address       string `yaml:"address"`
	Port          int    `yaml:"port"`
	UUID          string `yaml:"uuid"`
	PublicKey     string `yaml:"public_key"`
	ShortID       string `yaml:"short_id"`
	SNI           string `yaml:"sni"`
	Fingerprint   string `yaml:"fingerprint"`
	Flow          string `yaml:"flow"`
	Encryption    string `yaml:"encryption,omitempty"`     // VLESS encryption (mlkem768x25519plus...); пусто = "none"
	Mldsa65Verify string `yaml:"mldsa65_verify,omitempty"` // ML-DSA-65 client verify (base64url); пусто = не передаётся
}

// APIConfig holds NixaVPN API connection settings for remote config fetch.
type APIConfig struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

// LoadConfigFile reads and parses a YAML config file into a Config struct.
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return &cfg, nil
}

// ParseVLESSURL parses a vless:// URL into a VLESSConfig.
//
// Format: vless://UUID@HOST:PORT?security=reality&sni=SNI&fp=FP&pbk=KEY&sid=SID&flow=FLOW#REMARK
func ParseVLESSURL(rawURL string) (*VLESSConfig, error) {
	if !strings.HasPrefix(rawURL, "vless://") {
		return nil, fmt.Errorf("invalid scheme: URL must start with vless://")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse vless URL: %w", err)
	}

	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	if uuid == "" {
		return nil, fmt.Errorf("missing UUID in vless URL")
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in vless URL")
	}

	portStr := u.Port()
	port := 443
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
		}
	}

	q := u.Query()
	cfg := &VLESSConfig{
		Address:     host,
		Port:        port,
		UUID:        uuid,
		SNI:         q.Get("sni"),
		Fingerprint: q.Get("fp"),
		PublicKey:   q.Get("pbk"),
		ShortID:     q.Get("sid"),
		Flow:        q.Get("flow"),
	}

	return cfg, nil
}

// parseSLURL wraps client.ParseSLURL and maps the result to ShadowLinkConfig.
func parseSLURL(rawURL string) (*ShadowLinkConfig, error) {
	cfc, err := client.ParseSLURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse sl URL: %w", err)
	}

	sl := &ShadowLinkConfig{
		Server:        cfc.Server,
		PubKey:        cfc.PubKey,
		WebSocket:     cfc.WebSocket,
		TLS:           cfc.TLS,
		Auto:          cfc.Auto,
		CDN:           cfc.CDN,
		ECH:           cfc.ECH,
		Origin:        cfc.Origin,
		SNI:           cfc.SNI,
		CFIP:          cfc.CFIP,
		BackupServers: cfc.BackupServers,
		CDNs:          cfc.CDNs,
	}

	// Map RoutingConfig only if non-empty (avoid allocating empty pointer).
	if len(cfc.Routing.Bypass) > 0 || len(cfc.Routing.Force) > 0 || len(cfc.Routing.Block) > 0 {
		sl.Routing = &client.RoutingConfig{
			Bypass: cfc.Routing.Bypass,
			Force:  cfc.Routing.Force,
			Block:  cfc.Routing.Block,
		}
	}

	return sl, nil
}

// ParseImportURL dispatches to the correct parser based on URL scheme.
// Supported schemes: vless://, sl://
func ParseImportURL(rawURL string) (*Config, error) {
	switch {
	case strings.HasPrefix(rawURL, "vless://"):
		vlCfg, err := ParseVLESSURL(rawURL)
		if err != nil {
			return nil, err
		}
		return &Config{
			Protocol: "vless",
			SOCKS:    "127.0.0.1:1080",
			VLESS:    vlCfg,
		}, nil

	case strings.HasPrefix(rawURL, "sl://"):
		slCfg, err := parseSLURL(rawURL)
		if err != nil {
			return nil, err
		}
		return &Config{
			Protocol:   "shadowlink",
			SOCKS:      "127.0.0.1:1080",
			ShadowLink: slCfg,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported URL scheme: %q (supported: vless://, sl://)", rawURL)
	}
}

// apiConfigResponse is the JSON structure returned by the NixaVPN config API.
type apiConfigResponse struct {
	Protocol   string          `json:"protocol"`
	VLESS      json.RawMessage `json:"vless,omitempty"`
	ShadowLink json.RawMessage `json:"shadowlink,omitempty"`
}

// apiVLESSResponse is the VLESS section returned by /api/v1/client/full-config?protocol=vless.
type apiVLESSResponse struct {
	Link string `json:"link"` // vless:// URL
}

// apiSLResponse is the ShadowLink section returned by /api/v1/client/full-config?protocol=shadowlink.
type apiSLResponse struct {
	Link string `json:"link"` // sl:// URL
}

// FetchConfigFromAPI fetches configuration from the NixaVPN API.
// It makes two requests:
//
//	GET /api/v1/client/full-config?protocol=vless
//	GET /api/v1/client/full-config?protocol=shadowlink
//
// The resulting Config has Protocol="auto" and both sections populated when available.
func FetchConfigFromAPI(apiURL, token string) (*Config, error) {
	httpClient := &http.Client{Timeout: 15 * time.Second}

	cfg := &Config{
		Protocol: "auto",
		SOCKS:    "127.0.0.1:1080",
	}

	// Fetch VLESS config.
	vlessLink, err := fetchProtocolLink(httpClient, apiURL, token, "vless")
	if err != nil {
		return nil, fmt.Errorf("fetch vless config: %w", err)
	}
	if vlessLink != "" {
		vlCfg, err := ParseVLESSURL(vlessLink)
		if err != nil {
			return nil, fmt.Errorf("parse vless link from API: %w", err)
		}
		cfg.VLESS = vlCfg
	}

	// Fetch ShadowLink config.
	slLink, err := fetchProtocolLink(httpClient, apiURL, token, "shadowlink")
	if err != nil {
		return nil, fmt.Errorf("fetch shadowlink config: %w", err)
	}
	if slLink != "" {
		slCfg, err := parseSLURL(slLink)
		if err != nil {
			return nil, fmt.Errorf("parse shadowlink link from API: %w", err)
		}
		cfg.ShadowLink = slCfg
	}

	if cfg.VLESS == nil && cfg.ShadowLink == nil {
		return nil, fmt.Errorf("API returned no usable config for any protocol")
	}

	return cfg, nil
}

// fetchProtocolLink performs a single GET /api/v1/client/full-config?protocol=<proto>
// and returns the link string from the response JSON.
func fetchProtocolLink(httpClient *http.Client, apiURL, token, proto string) (string, error) {
	endpoint := strings.TrimRight(apiURL, "/") + "/api/v1/client/full-config?protocol=" + proto

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Protocol not available on this server — not an error.
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	var result struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse response JSON: %w", err)
	}

	return result.Link, nil
}

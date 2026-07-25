package main

// INT-H2 (2026-06-12): serverBootstrapDomain — чистый хелпер, вычисляющий
// серверный домен для bootstrap-whitelist split-DNS forwarder'а тем же путём,
// что resolveServerIPs выбирает host. Возвращает "" когда DNS-bootstrap не
// нужен: origin-pin (dial по литеральному IP, DNS не участвует) и IP-литералы.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServerBootstrapDomain_OriginPin_Empty(t *testing.T) {
	cfg := &Config{
		ShadowLink: &ShadowLinkConfig{
			Server: "datacanvases.com:443",
			CDN:    "datacanvases.com",
			Origin: "104.222.177.67",
		},
	}
	assert.Equal(t, "", serverBootstrapDomain("shadowlink", cfg),
		"origin-pin: dial идёт по литеральному IP — DNS-bootstrap не нужен")
}

func TestServerBootstrapDomain_CDNDomain(t *testing.T) {
	cfg := &Config{
		ShadowLink: &ShadowLinkConfig{
			Server: "datacanvases.com:443",
			CDN:    "cdn.example.com",
		},
	}
	assert.Equal(t, "cdn.example.com", serverBootstrapDomain("shadowlink", cfg))
}

func TestServerBootstrapDomain_ServerHostDomain(t *testing.T) {
	cfg := &Config{
		ShadowLink: &ShadowLinkConfig{Server: "example.com:443"},
	}
	assert.Equal(t, "example.com", serverBootstrapDomain("shadowlink", cfg))
}

func TestServerBootstrapDomain_ServerIPLiteral_Empty(t *testing.T) {
	cfg := &Config{
		ShadowLink: &ShadowLinkConfig{Server: "203.0.113.5:443"},
	}
	assert.Equal(t, "", serverBootstrapDomain("shadowlink", cfg),
		"IP-литерал не требует DNS-bootstrap")
}

func TestServerBootstrapDomain_VLESSDomain(t *testing.T) {
	cfg := &Config{
		VLESS: &VLESSConfig{Address: "vless.example.com"},
	}
	assert.Equal(t, "vless.example.com", serverBootstrapDomain("vless", cfg))
}

func TestServerBootstrapDomain_VLESSIPLiteral_Empty(t *testing.T) {
	cfg := &Config{
		VLESS: &VLESSConfig{Address: "203.0.113.5"},
	}
	assert.Equal(t, "", serverBootstrapDomain("vless", cfg))
}

// Невалидный origin (не IPv4) → fall-through к CDN, зеркально resolveServerIPs.
func TestServerBootstrapDomain_OriginInvalid_FallsThroughToCDN(t *testing.T) {
	cfg := &Config{
		ShadowLink: &ShadowLinkConfig{
			Server: "example.com:443",
			CDN:    "cdn.example.com",
			Origin: "not-an-ip",
		},
	}
	assert.Equal(t, "cdn.example.com", serverBootstrapDomain("shadowlink", cfg))
}

func TestServerBootstrapDomain_NilSections_Empty(t *testing.T) {
	assert.Equal(t, "", serverBootstrapDomain("shadowlink", &Config{}))
	assert.Equal(t, "", serverBootstrapDomain("vless", &Config{}))
}

// Builder-опция Tunnel сохраняет домены для передачи в startSplitDNS.
func TestTunnel_WithBootstrapDomains_StoresValue(t *testing.T) {
	tun := NewTunnel("127.0.0.1:1080", "u", "p", []string{"1.2.3.4"}).
		WithBootstrapDomains("cdn.example.com")
	assert.Equal(t, []string{"cdn.example.com"}, tun.bootstrapDomains)
}

// F-5 (2026-06-13): единый предикат originPinned — валидный IPv4 в ?origin=.
// Гейтит narrowEscape, origin short-circuit resolveServerIPs и
// serverBootstrapDomain согласованно. Невалидный origin (typo) → НЕ pinned →
// /16 sweep сохраняется (фактически CDN-режим).
func TestOriginPinned(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{"valid IPv4", &Config{ShadowLink: &ShadowLinkConfig{Origin: "104.222.177.67"}}, true},
		{"invalid origin (typo)", &Config{ShadowLink: &ShadowLinkConfig{Origin: "not-an-ip"}}, false},
		{"IPv6 origin (escape uses IPv4)", &Config{ShadowLink: &ShadowLinkConfig{Origin: "2001:db8::1"}}, false},
		{"empty origin", &Config{ShadowLink: &ShadowLinkConfig{Origin: ""}}, false},
		{"nil ShadowLink", &Config{}, false},
		{"nil cfg", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, originPinned(tc.cfg))
		})
	}
}

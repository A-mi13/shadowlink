package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// dohServerAddr — Cloudflare 1.1.1.1 DoH endpoint. Pinned IP avoids plaintext
// DNS resolution of the resolver itself (would defeat the point of DoH).
const dohServerAddr = "1.1.1.1:443"

// dohSNI — the ServerName presented in the TLS handshake. Cloudflare's 1.1.1.1
// DoH endpoint serves a cert valid for `cloudflare-dns.com` and `one.one.one.one`;
// we use `cloudflare-dns.com` because it's the canonical public name.
const dohSNI = "cloudflare-dns.com"

// newDoHClient constructs the HTTP client used for DNS-over-HTTPS queries to
// Cloudflare's 1.1.1.1 endpoint.
//
// A2-MED-1 (2026-04 audit) cure: the previous implementation built a vanilla
// `&http.Client{Timeout: 5 * time.Second}` and POSTed to `https://1.1.1.1/dns-query`,
// emitting the canonical Go-stdlib JA3 from the same client IP that minutes
// later spoke Chrome/Safari/Firefox JA3 over the ShadowLink data path. Even
// though 1.1.1.1 itself is benign, the JA3 inconsistency is a passive
// fingerprint signal for any observer who can co-locate the DoH and VPN flows.
//
// This unifies the DoH client onto the same uTLS dialer used by the data path
// (see buildUTLSHTTPClient + ws_transport / split_transport).
func newDoHClient() *http.Client {
	// Pick a Chrome fingerprint for DoH. Chrome is the most common browser
	// fingerprint, so a Chrome JA3 hitting 1.1.1.1 is the highest-volume
	// background traffic to blend into.
	fp := browser.NewFingerprint(browser.ProfileChrome)
	return buildUTLSHTTPClient(dohServerAddr, dohSNI, fp, false, 5*time.Second, "http/1.1")
}

// ResolveECHConfig queries DNS HTTPS record (type 65) for domain
// and extracts ECHConfigList from the ech= SvcParam.
// Uses DNS-over-HTTPS (DoH) to prevent plaintext DNS leaking the target domain.
func ResolveECHConfig(domain string) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	m.RecursionDesired = true

	// Pack the DNS message for DoH POST
	packed, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("dns pack failed: %w", err)
	}

	// Send via DNS-over-HTTPS to Cloudflare (encrypted, no plaintext domain leak).
	// uTLS-routed (A2-MED-1 fix) — see newDoHClient godoc.
	//
	// 2026-05-02 wire-trigger followup NEW-2: build the request manually so we
	// can attach the Chrome User-Agent + sec-ch-ua header set. Stdlib
	// http.Client.Post sends no UA, leaving a uTLS Chrome ClientHello followed
	// by a UA-less POST — internally inconsistent.
	httpClient := newDoHClient()
	defer httpClient.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodPost, "https://"+dohSNI+"/dns-query", bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("doh build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", browser.LockedChromeUA())
	browser.ApplyChromeCHUA(req.Header)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh query returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("doh read failed: %w", err)
	}

	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, fmt.Errorf("dns unpack failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query returned %s", dns.RcodeToString[r.Rcode])
	}

	for _, ans := range r.Answer {
		https, ok := ans.(*dns.HTTPS)
		if !ok {
			continue
		}
		for _, v := range https.Value {
			if v.Key() == dns.SVCB_ECHCONFIG {
				echVal, ok := v.(*dns.SVCBECHConfig)
				if !ok {
					continue
				}
				if len(echVal.ECH) > 0 {
					return echVal.ECH, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no ECH config found in DNS HTTPS record for %s", domain)
}

// ECHConfig holds cached ECH configuration with TTL.
type ECHConfig struct {
	ConfigList []byte
	ResolvedAt time.Time
	TTL        time.Duration
}

// IsExpired returns true if the cached ECH config has expired.
func (e *ECHConfig) IsExpired() bool {
	if e == nil || len(e.ConfigList) == 0 {
		return true
	}
	return time.Since(e.ResolvedAt) > e.TTL
}

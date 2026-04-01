package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

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

	// Send via DNS-over-HTTPS to Cloudflare (encrypted, no plaintext domain leak)
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Post(
		"https://1.1.1.1/dns-query",
		"application/dns-message",
		bytes.NewReader(packed),
	)
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

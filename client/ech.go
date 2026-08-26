package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// dohServerIP — Cloudflare 1.1.1.1 DoH endpoint IP. The DoH client dials this
// literal IP (no DNS) so resolving the resolver's own name can never happen.
//
// B1 (2026-06-11 split-DNS final review): this is now a HARD pin, not a hint.
// Previously buildUTLSHTTPClient ignored its first arg (cfIP="") and dialed
// whatever host the request URL pointed at — `cloudflare-dns.com` — via DNS.
// In the split-DNS forwarder that name lookup re-enters the forwarder (TUN-DNS
// is the forwarder once setTUNDNS runs) → Cloudflare branch → DoHQuery → resolve
// `cloudflare-dns.com` → loop (cascade timeouts → SERVFAIL). Pinning the dial to
// the literal 1.1.1.1 removes the DNS step entirely.
//
// ⚠ HOW this connect reaches CF, stated precisely (the earlier wording said
// "routed through the tunnel by BypassDialer" and misled a 2026-08-26 review
// into believing the Go code routes it): the dialer here is a BARE net.Dialer
// (utls_http.go buildUTLSHTTPClientCommon) — no BypassDialer, no tun2socks in
// this call path. Reaching CF over the tunnel is a property of the OS ROUTING
// TABLE, not of this code, and only in TUN/SystemVPN mode:
//   - no /32 escape route exists for this IP (tunnel.go buildEscapePlan), and
//   - the /16 sweep is skipped under origin-pin,
//
// so the 0/1+128/1 split routes swallow the packet into the TUN, where
// tun2socks hands it to BypassDialer, which classifies non-RU → routeTunnel.
// In plain SOCKS5 mode (no TUN) there are no split routes and this dial goes
// DIRECT from the physical NIC, putting a cleartext ClientHello with SNI
// cloudflare-dns.com on the wire. Same for the ECH cold-start caller, which
// runs before routes exist. Guards: TestDoHServerIP_HasNoEscapeRoute
// (cmd/nixavpn-client) and TestDoHServerIP_NotInRUTrie (client/bypassroute).
const dohServerIP = "1.1.1.1"

// dohSNI — the ServerName presented in the TLS handshake. Cloudflare's 1.1.1.1
// DoH endpoint serves a cert valid for `cloudflare-dns.com` and `one.one.one.one`;
// we use `cloudflare-dns.com` because it's the canonical public name.
const dohSNI = "cloudflare-dns.com"

// DoHServerIP exposes the pinned DoH dial target to other packages so route- and
// trie-level guards can assert against the LIVE constant instead of a parallel
// literal. Same single-source-of-truth role dnsproxy.DefaultYandexIPs() plays for
// the Yandex escape routes (invariant N2) — but with the OPPOSITE sign: Yandex
// MUST have a /32 escape (plain UDP, direct by design), while this IP must have
// NONE, because its protection is that it falls through to the tunnel.
//
// Why an accessor is needed at all: the DoH dialer is a bare net.Dialer
// (utls_http.go buildUTLSHTTPClientCommon) — nothing in Go code routes it. It
// reaches CF through the tunnel only because the OS routing table has no escape
// for it, so the 0/1+128/1 split routes swallow it into the TUN. That protection
// is emergent from three independent decisions and is not visible at this call
// site; see TestDoHServerIP_HasNoEscapeRoute (cmd/nixavpn-client) and
// TestDoHServerIP_NotInRUTrie (client/bypassroute) for the guards.
func DoHServerIP() string { return dohServerIP }

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
//
// B1 (2026-06-11): the client now dials the LITERAL 1.1.1.1 via
// buildUTLSHTTPClientPinned — no DNS lookup of `cloudflare-dns.com`. This is
// the cure for the split-DNS forwarder loop (see dohServerIP doc) and is also
// correct for the ECH cold-start caller (1.1.1.1 is the right edge for the
// cloudflare-dns.com cert, so pinning never hurts).
func newDoHClient() *http.Client {
	// Pick a Chrome fingerprint for DoH. Chrome is the most common browser
	// fingerprint, so a Chrome JA3 hitting 1.1.1.1 is the highest-volume
	// background traffic to blend into.
	fp := browser.NewFingerprint(browser.ProfileChrome)
	return buildUTLSHTTPClientPinned(dohServerIP, dohSNI, fp, false, 5*time.Second, "http/1.1")
}

// NewDoHKeepAliveClient возвращает долгоживущий DoH-клиент с ВКЛЮЧЁННЫМ
// keep-alive для dnsproxy-форвардера. DNS-M6 (2026-06-12): one-shot клиент на
// каждый DNS-запрос = полный TCP+uTLS хендшейк к 1.1.1.1 через туннель на
// КАЖДОЕ имя страницы (шторм Chrome-ClientHello по пулу слотов) и поведенчески
// неправдоподобен — реальный браузер держит одно DoH-соединение. Вызывающий
// держит ОДИН инстанс на весь свой lifecycle и обязан звать
// CloseIdleConnections при остановке (Forwarder.Stop → dohResolver.Close).
// Тот же IP-пин 1.1.1.1 и тот же Chrome-fingerprint, что у newDoHClient;
// ECH bootstrap путь (DoHQueryRaw → newDoHClient) НЕ переводится и остаётся
// one-shot, как был.
func NewDoHKeepAliveClient() *http.Client {
	fp := browser.NewFingerprint(browser.ProfileChrome)
	return buildUTLSHTTPClientPinnedKeepAlive(dohServerIP, dohSNI, fp, false, 5*time.Second, "http/1.1")
}

// DoHQueryRaw sends an arbitrary DNS message over DNS-over-HTTPS to Cloudflare
// (1.1.1.1) and returns the parsed response dns.Msg regardless of its Rcode.
// The query is routed via the uTLS DoH client — see newDoHClient.
//
// DNS-H1 (2026-06-12): the dnsproxy forwarder needs NXDOMAIN / NOERROR-NODATA
// back as valid *dns.Msg responses (to propagate and negative-cache them), so
// the Rcode check lives in the DoHQuery wrapper below, NOT here. An error from
// DoHQueryRaw means transport/protocol failure only (HTTP error, unpack
// failure) — a parsed DNS answer with any Rcode is a success at this layer.
//
// NEW-2: the request is assembled by hand (not http.Client.Post) so that the
// Chrome User-Agent + sec-ch-ua header set can be attached; stdlib Post sends
// no UA, which would leave a uTLS Chrome ClientHello followed by a UA-less POST.
func DoHQueryRaw(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// One-shot клиент per-call — поведение ECH bootstrap пути сохранено как
	// есть (DNS-M6 меняет только dnsproxy-путь через DoHQueryRawWith).
	httpClient := newDoHClient()
	defer httpClient.CloseIdleConnections()
	return DoHQueryRawWith(ctx, m, httpClient)
}

// DoHQueryRawWith — тело DoHQueryRaw с клиентом от вызывающего. DNS-M6
// (2026-06-12): dnsproxy-форвардер передаёт сюда свой ЕДИНСТВЕННЫЙ
// долгоживущий keep-alive клиент (NewDoHKeepAliveClient) — соединение к
// 1.1.1.1 переиспользуется между запросами вместо хендшейка на каждый.
// CloseIdleConnections здесь НЕ вызывается — lifecycle клиента принадлежит
// вызывающему. http.Client безопасен для конкурентного использования;
// uTLS-дайлер под ним создаёт всё состояние per-dial (см. buildUTLSDialTLS).
func DoHQueryRawWith(ctx context.Context, m *dns.Msg, httpClient *http.Client) (*dns.Msg, error) {
	// Pack the DNS message for DoH POST
	packed, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("dns pack failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+dohSNI+"/dns-query", bytes.NewReader(packed))
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

	return r, nil
}

// DoHQuery is DoHQueryRaw plus the strict-success contract: a non-Success
// Rcode is treated as an error. Used by ResolveECHConfig (TypeHTTPS), which
// expects a failed resolve in that case. Callers that must distinguish
// NXDOMAIN/NODATA from transport failure (the dnsproxy forwarder) use
// DoHQueryRaw directly.
func DoHQuery(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	r, err := DoHQueryRaw(ctx, m)
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query returned %s", dns.RcodeToString[r.Rcode])
	}

	return r, nil
}

// ResolveECHConfig queries DNS HTTPS record (type 65) for domain
// and extracts ECHConfigList from the ech= SvcParam.
// Uses DNS-over-HTTPS (DoH) to prevent plaintext DNS leaking the target domain.
func ResolveECHConfig(domain string) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	m.RecursionDesired = true

	r, err := DoHQuery(context.Background(), m)
	if err != nil {
		return nil, fmt.Errorf("resolve ech for %s: %w", domain, err)
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

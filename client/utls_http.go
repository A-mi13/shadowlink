package client

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// pqClientHelloSpec returns a ClientHelloSpec derived from the supplied helloID
// with X25519MLKEM768 ensured-present in BOTH the SupportedCurvesExtension
// (a.k.a. supported_groups, RFC 8446 §4.2.7) and the KeyShareExtension (RFC 8446
// §4.2.8). For current utls (Chrome_133 spec already includes MLKEM at index 1
// after a GREASE placeholder at index 0) this is effectively a no-op safety
// check — but it acts as a bridge if upstream ever drops MLKEM from the base
// spec or we move to an older HelloChromeID without it.
//
// T1.1 (Phase 2, 2026-04-26): wire-visible PQ readiness. Real Chrome 135+ in
// the field has GREASE first followed by X25519MLKEM768 (per RFC 8701) in both
// extensions; passive DPI fingerprints the first non-GREASE key_share group
// as the "preferred" curve, so MLKEM presence (not strictly position 0) is
// what matters. We must NOT blindly prepend on every call: doing so produces
// a duplicate MLKEM keyshare (~2.4KB extra ClientHello bytes) AND moves
// MLKEM in front of GREASE, breaking the wire-order convention.
//
// utls v1.8.3+ supports MLKEM in MarshalClientHello: a KeyShare entry with
// Group=X25519MLKEM768 and Data=nil triggers the parrots path to generate the
// hybrid encapsulation key + x25519 ephemeral key automatically (see
// u_parrots.go ApplyPreset branch on curveID == X25519MLKEM768).
//
// T1 §P1-2 (May 2026 audit, 2026-05-03): utls.UTLSIdToSpec does NOT guarantee
// a fresh allocation per call — extensions point into a package-level
// descriptor table that is shared across goroutines. Mutating the returned
// spec in place (e.g. `v.Curves = append(...)`) would race with concurrent
// cold-path handshakes (split_transport, ws warmup, probeHTTPS, ECH DoH).
// This is currently a latent bug because Chrome_133 already has MLKEM in
// position 1 — the append branch never fires — but an utls upstream bump
// that drops MLKEM from the canonical spec would silently turn it into a
// data-race + ClientHello corruption.
//
// Fix: deep-copy spec.Extensions and the two extension structs we touch
// before mutating. Cost is ~200 ns per cold-path handshake — invisible.
//
// C4 cold-path lockstep (2026-06-09): helloID is now a parameter rather than
// a hardcoded HelloChrome_133. The spec is derived from the SELECTED browser
// profile's ClientHelloID. The MLKEM ensure-present injection is idempotent:
// if the derived spec already carries X25519MLKEM768 in supported_groups /
// key_share (true for current Chrome_133 and Firefox_148 specs), the append
// branch never fires and the returned spec equals the stock profile spec.
// NOTE: this helper applies a Chrome-shaped MLKEM placement (prepend ahead of
// the existing list) and must only be called for Chrome-family profiles —
// non-Chrome cold paths use the stock UTLSIdToSpec(helloID) directly so the
// browser's own native key_share layout is preserved (see callers).
func pqClientHelloSpec(helloID utls.ClientHelloID) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		return utls.ClientHelloSpec{}, fmt.Errorf("pq: derive %v spec: %w", helloID, err)
	}

	// Defensive deep-copy of the Extensions slice. Without this the for-loops
	// below would write through pointers that utls returned from a shared
	// descriptor table — concurrent dialers calling this function (or any
	// other code path that uses HelloChrome_133's spec) would race.
	//
	// We only need to clone the slice header + the two pointer-extensions we
	// mutate (SupportedCurvesExtension, KeyShareExtension). Other extensions
	// stay aliased — we never mutate them, and shared aliasing of read-only
	// extension structs is safe.
	extsCopy := make([]utls.TLSExtension, len(spec.Extensions))
	copy(extsCopy, spec.Extensions)
	for i, ext := range extsCopy {
		switch v := ext.(type) {
		case *utls.SupportedCurvesExtension:
			cloned := &utls.SupportedCurvesExtension{
				Curves: append([]utls.CurveID(nil), v.Curves...),
			}
			extsCopy[i] = cloned
		case *utls.KeyShareExtension:
			cloned := &utls.KeyShareExtension{
				KeyShares: append([]utls.KeyShare(nil), v.KeyShares...),
			}
			extsCopy[i] = cloned
		}
	}
	spec.Extensions = extsCopy

	for _, ext := range spec.Extensions {
		if v, ok := ext.(*utls.SupportedCurvesExtension); ok {
			hasMLKEM := false
			for _, c := range v.Curves {
				if c == utls.X25519MLKEM768 {
					hasMLKEM = true
					break
				}
			}
			if !hasMLKEM {
				v.Curves = append([]utls.CurveID{utls.X25519MLKEM768}, v.Curves...)
			}
			break
		}
	}

	for _, ext := range spec.Extensions {
		if v, ok := ext.(*utls.KeyShareExtension); ok {
			hasMLKEM := false
			for _, ks := range v.KeyShares {
				if ks.Group == utls.X25519MLKEM768 {
					hasMLKEM = true
					break
				}
			}
			if !hasMLKEM {
				v.KeyShares = append(
					[]utls.KeyShare{{Group: utls.X25519MLKEM768}},
					v.KeyShares...,
				)
			}
			break
		}
	}

	return spec, nil
}

// pqEnabled reports whether the PQ ClientHello path is active. Default ON
// since 2026-04-28 (Phase 2 closure flip after cold-path JA3 propagation
// closed the WS-vs-cold-path mismatch — see phase-2-closure-done.md). On
// utls v1.8.3 the wire effect is ≈ no-op because HelloChrome_133 already
// includes MLKEM768 in the right position; pqClientHelloSpec() acts as a
// safety bridge if upstream removes it.
//
// Set SHADOWLINK_TLS_PQ=0 (or "false"/"no"/"off") for emergency disable —
// restores stock HelloChrome_133 spec via UTLSIdToSpec without the safety
// bridge derive step. Mirrors SHADOWLINK_DATAPATH_BODYPREFIX semantics.
func pqEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_TLS_PQ"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// buildUTLSHTTPClient returns a stdlib *http.Client whose TLS handshake goes
// through refraction-networking/utls with a browser-identical ClientHello.
//
// Cold-path cure (2026-04 audit CRIT-1/2/3): WebSocketTransport.SendHandshake,
// WebSocketTransport.WarmupRequests, and probe.probeHTTPS used to construct a
// vanilla `&http.Client{}` for their pre-WS / startup HTTPS calls. That leaked
// Go stdlib's JA3 from the same client IP that minutes later spoke Chrome JA3
// over the WS upgrade or the CDN data path — a single passive observer can
// flag the inconsistency. This helper unifies all client-originated HTTPS
// traffic on the same uTLS profile already used by ws_transport.UpgradeToWS
// and split_transport.
//
// Arguments:
//   - serverAddr: dial target "host:port" — drives DNS lookup if cfIP is empty.
//   - sni: TLS ServerName — must match the cert (commonly equal to host of serverAddr).
//   - fp: browser fingerprint whose ClientHelloID we mimic (Chrome 133, Safari 16, Firefox auto).
//   - skipVerify: trust any cert. MUST be false for production probes against
//     real domains; the only legitimate use is local self-signed test fixtures.
//   - timeout: total request timeout (Client.Timeout). 0 disables it.
//   - nextProto: pinned ALPN — pass "http/1.1" for HTTP/1.1-only Transports.
//
// The returned client has DisableKeepAlives=true so each request is a fresh
// TCP+TLS handshake (matches the cold-path call sites which fire one HEAD/POST
// then drop the connection — keep-alive would just leak the JA3 longer).
func buildUTLSHTTPClient(
	serverAddr, sni string,
	fp *browser.Fingerprint,
	skipVerify bool,
	timeout time.Duration,
	nextProto string,
) *http.Client {
	// cfIP="" — the helper resolves whatever host the request URL points at via
	// DNS; cold-path callers don't need CF edge pinning the way SplitTransport
	// does. sni is set to the cert domain so verification succeeds.
	return buildUTLSHTTPClientCommon("", sni, fp, skipVerify, timeout, nextProto, true)
}

// buildUTLSHTTPClientPinned is the IP-pinned sibling of buildUTLSHTTPClient: it
// dials the literal cfIP (no DNS) while presenting sni as the TLS ServerName,
// so the cert still validates against the canonical domain.
//
// B1 (2026-06-11 split-DNS final review): the forwarder's DoH path must NOT
// resolve `cloudflare-dns.com` via DNS — once setTUNDNS points the TUN at the
// forwarder, that lookup re-enters the forwarder's own Cloudflare branch, which
// calls DoHQuery again → resolve `cloudflare-dns.com` → … (cascade of timeouts
// → SERVFAIL). Pinning the dial target to the literal 1.1.1.1 breaks the loop:
// the TCP connect goes straight to the edge IP (which is not in the RU snapshot,
// so BypassDialer routes it through the tunnel to the exit server → out to CF),
// with zero DNS involvement.
//
// cfIP MUST be a bare IP (no port) — buildUTLSDialTLS re-joins it with the port
// taken from the request URL.
func buildUTLSHTTPClientPinned(
	cfIP, sni string,
	fp *browser.Fingerprint,
	skipVerify bool,
	timeout time.Duration,
	nextProto string,
) *http.Client {
	return buildUTLSHTTPClientCommon(cfIP, sni, fp, skipVerify, timeout, nextProto, true)
}

// buildUTLSHTTPClientPinnedKeepAlive — IP-пиннутый клиент с ВКЛЮЧЁННЫМ
// keep-alive. DNS-M6 (2026-06-12): dnsproxy-форвардер шлёт DoH-запросы на
// каждое DNS-имя страницы — one-shot клиент превращал это в шторм
// Chrome-ClientHello к 1.1.1.1 через пул слотов (и поведенчески неправдоподобен:
// реальный браузер держит ОДНО DoH-соединение). Этот вариант предназначен для
// одного долгоживущего клиента на весь lifecycle вызывающего; вызывающий обязан
// звать CloseIdleConnections при остановке, чтобы сокеты не утекали.
// Существующие one-shot вызыватели (ECH bootstrap, cold-path probes) НЕ
// переводятся — их поведение не меняется.
func buildUTLSHTTPClientPinnedKeepAlive(
	cfIP, sni string,
	fp *browser.Fingerprint,
	skipVerify bool,
	timeout time.Duration,
	nextProto string,
) *http.Client {
	return buildUTLSHTTPClientCommon(cfIP, sni, fp, skipVerify, timeout, nextProto, false)
}

// buildUTLSHTTPClientCommon is the shared body of buildUTLSHTTPClient (cfIP="")
// and buildUTLSHTTPClientPinned (cfIP=literal edge IP). cfIP empty → resolve the
// request URL host via DNS; cfIP set → dial that literal IP, keeping sni as the
// TLS ServerName so cert verification still succeeds. disableKeepAlives=true
// keeps the historical one-shot behavior; false enables connection reuse for
// long-lived callers (DNS-M6 — see buildUTLSHTTPClientPinnedKeepAlive).
func buildUTLSHTTPClientCommon(
	cfIP, sni string,
	fp *browser.Fingerprint,
	skipVerify bool,
	timeout time.Duration,
	nextProto string,
	disableKeepAlives bool,
) *http.Client {
	if nextProto == "" {
		nextProto = "http/1.1"
	}

	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	dialTLS := buildUTLSDialTLS(cfIP, sni, fp, dialer, skipVerify, nextProto)

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext:     dialTLS,
			DisableCompression: false,
			DisableKeepAlives:  disableKeepAlives,
			ForceAttemptHTTP2:  false,
			// IdleConnTimeout matters only when keep-alives are enabled
			// (pooled idle conns are dropped after this); mirrors the
			// stdlib DefaultTransport value. No-op for one-shot clients.
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
}

package client

import (
	"context"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// buildUTLSDialTLS returns a DialTLSContext suitable for stdhttp.Transport that
// performs the TLS handshake via refraction-networking/utls with a browser-
// identical ClientHello.
//
// 2026-04 DPI audit P0.5: split_transport previously delegated TLS to the Go
// stdlib (crypto/tls.Config on Transport.TLSClientConfig). That leaked the Go
// JA3/JA4 fingerprint on every CDN upload POST, which is the main ShadowLink
// data path. ws_transport already used uTLS for the same reason; this helper
// lifts that pattern into split_transport so both paths share the same
// defensive posture.
//
// Arguments:
//   - cfIP: optional pinned Cloudflare edge IP (empty = resolve via DNS)
//   - sni: TLS ServerName — MUST be the cert domain, not the IP
//   - fp: browser fingerprint whose ClientHelloID we mimic
//   - dialer: TCP dialer (carries connect timeout, keep-alive config)
//   - skipVerify: trust any cert — only safe for self-signed test environments
//   - nextProto: single ALPN value the Transport expects (h2 or http/1.1).
//     Go's net/http compares the negotiated ALPN against Transport config; an
//     http/1.1-only transport cannot read an h2 connection, so we pin the
//     ClientHello's ALPN extension to exactly this protocol.
func buildUTLSDialTLS(
	cfIP, sni string,
	fp *browser.Fingerprint,
	dialer *net.Dialer,
	skipVerify bool,
	nextProto string,
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	helloID := utlsProfileForFingerprint(fp)

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// cfIP override: swap addr host for the scanned edge while keeping
		// the port. TLS SNI stays as sni (the domain) so the cert validates.
		dialAddr := addr
		if cfIP != "" {
			if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
				dialAddr = net.JoinHostPort(cfIP, port)
			}
		}

		tcpConn, err := dialer.DialContext(ctx, network, dialAddr)
		if err != nil {
			return nil, err
		}

		// PQ cold-path branch (Phase 2 closure 2026-04-28): SHADOWLINK_TLS_PQ=1
		// enables MLKEM-prepended ClientHello on every cold-path HTTPS call
		// (SendHandshake POST, WarmupRequests, cover GET, SplitTransport CDN
		// upload). Without this, flipping the flag default-on would re-create
		// the JA3 mismatch CRIT-1/2/3 of the 2026-04 audit because the WS
		// upgrade would speak MLKEM while same-IP same-session cold-path
		// requests kept the stock HelloChrome_133 spec.
		usePQ := pqEnabled()
		var spec utls.ClientHelloSpec
		pqApplied := false
		pqFellBack := false
		if usePQ {
			if pqSpec, pqErr := pqClientHelloSpec(); pqErr == nil {
				spec = pqSpec
				pqApplied = true
			} else {
				pqFellBack = true
				hsSpec, specErr := utls.UTLSIdToSpec(helloID)
				if specErr != nil {
					tcpConn.Close()
					Stats.PQHandshakeError.Add(1)
					return nil, fmt.Errorf("uTLS spec: %w", specErr)
				}
				spec = hsSpec
			}
		} else {
			hsSpec, specErr := utls.UTLSIdToSpec(helloID)
			if specErr != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("uTLS spec: %w", specErr)
			}
			spec = hsSpec
		}

		// Force the ALPN extension to the single protocol the Transport
		// will speak. Chrome profiles advertise h2,http/1.1 by default; if
		// the peer picks h2 but our Transport is HTTP/1.1-only (ForceAttemptHTTP2:
		// false + empty TLSNextProto map), Go treats the negotiated ALPN as
		// a protocol error and returns "tls: server selected unadvertised ALPN
		// protocol" or silently fails the next write.
		for i, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{nextProto}
				spec.Extensions[i] = alpn
			}
		}

		uConfig := &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: skipVerify,
			NextProtos:         []string{nextProto},
		}
		tlsConn := utls.UClient(tcpConn, uConfig, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(&spec); err != nil {
			tcpConn.Close()
			if usePQ {
				Stats.PQHandshakeError.Add(1)
			}
			return nil, fmt.Errorf("uTLS apply: %w", err)
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			if usePQ {
				Stats.PQHandshakeError.Add(1)
			}
			return nil, fmt.Errorf("uTLS handshake: %w", err)
		}
		// PQ counter accounting: only ticks when usePQ is true so the
		// counter stays at zero in default builds.
		if usePQ {
			switch {
			case pqApplied:
				Stats.PQHandshakeSuccess.Add(1)
			case pqFellBack:
				Stats.PQHandshakeFallback.Add(1)
			}
		}
		return tlsConn, nil
	}
}

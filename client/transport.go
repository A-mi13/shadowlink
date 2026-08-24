package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// Transport sends encrypted chunks to a ShadowLink server and returns responses.
type Transport interface {
	// SendChunk sends an encrypted chunk and returns the encrypted response.
	SendChunk(ctx context.Context, data []byte, sessionToken []byte, seqNum uint32) ([]byte, error)
	// SendHandshake sends a ClientHello and returns raw response body.
	SendHandshake(ctx context.Context, clientHello *core.ClientHello) ([]byte, error)
	// Name returns the transport name (for logging).
	Name() string
	// Close cleans up resources.
	Close() error
}

// SessionAware is implemented by transports that need session data for cover traffic.
type SessionAware interface {
	SetSession(s *core.Session)
	SetSessionToken(token []byte)
}

// HandshakeRawSender is the optional capability used by the D4 probe flow:
// it posts an arbitrary raw handshake payload (padded/BuildHandshakePayload)
// through the transport's ConnManager and returns the server body. Transports
// without this capability fall back to the legacy path only.
type HandshakeRawSender interface {
	// SendHandshakeRaw wraps the payload in the analytics envelope and POSTs it
	// as the first request (no Authorization), returning the raw response body.
	// Returns an error whose Error() starts with "HTTP 4xx: " / "HTTP 200-garbage: "
	// so the D4 probe can classify fallback cases.
	SendHandshakeRaw(ctx context.Context, payload []byte) ([]byte, error)
}

// Compile-time assertions: both transports must implement SessionAware.
var (
	_ SessionAware = (*DirectTransport)(nil)
	_ SessionAware = (*CDNTransport)(nil)
)

// Phase 2.2 (2026-05-14) compile-time assertion: fhttp.Header (bogdanfinn/fhttp)
// and stdhttp.Header (net/http) MUST both be `map[string][]string`.
// SendHandshake / SendHandshakeRaw cast resp.Header via stdhttp.Header(resp.Header)
// to feed the RateLimitDetector. The cast is zero-cost IFF both types share the
// same underlying type. If bogdanfinn/fhttp ever changes its Header definition
// (e.g., to a struct), this block will fail to compile rather than silently
// corrupt response-header parsing.
var (
	_ = (stdhttp.Header)(http.Header{}) // fhttp.Header → stdhttp.Header
	_ = (http.Header)(stdhttp.Header{}) // stdhttp.Header → fhttp.Header (symmetric)
)

// DirectTransport connects directly to the ShadowLink server.
// Uses bogdanfinn/tls-client for browser-identical TLS + HTTP/2 fingerprinting.
type DirectTransport struct {
	baseURL     string // scheme://DIAL_HOST:PORT — drives DNS/dial + default SNI
	publicURL   string // scheme://VISIBLE_HOST:PORT — used in Origin/Referer headers
	publicHost  string // VISIBLE_HOST used as HTTP Host header (== sniOverride when set, else dial host)
	// signalHost is the host fed to core.DeriveRLPropertyID for the per-host
	// rate-limit marker. Distinct from publicHost, which is deliberately empty
	// when there is no SNI override (the Host header is then left to the URL).
	// Reusing publicHost here would have restricted the no-SNI path to the
	// legacy fleet-wide marker without any visible failure.
	signalHost string
	urlPool     *browser.URLPool
	connManager *ConnManager

	// rlDetector — Phase 2.2 (2026-05-14): dual-carrier rate-limit detector chain
	// (body marker → header → lifeline fallback). Replaces the old header-only
	// X-SL-RL detection that failed when CF stripped the header in production
	// (log 2026-05-14, sticky reconnect loop).
	rlDetector *RateLimitDetector

	rc           *browser.RatioController
	session      *core.Session
	sessionToken []byte
	coverMu      sync.Mutex
	stopCover    chan struct{}

	// dataPathBodyPrefix — эффективный per-instance выбор формата data-path,
	// снятый на конструировании (дефолт из env либо явное поле ClientConfig).
	// Заменяет чтение пакетной переменной в SendChunk/SendChunkRawBody: глобал
	// недоступен мобильному фасаду, у которого нет env до импорта пакета.
	dataPathBodyPrefix bool
}

// NewDirectTransport creates a transport that connects directly to the server.
// serverAddr is "host:port" (e.g., "example.com:443").
// useTLS enables TLS with browser-identical fingerprinting. skipVerify for testing.
func NewDirectTransport(serverAddr string, useTLS bool, skipVerify bool) *DirectTransport {
	return newDirectTransportFull(serverAddr, useTLS, skipVerify, false, "", "", defaultDataPathBodyPrefix)
}

// newDirectTransportBP — как NewDirectTransport, но с явным выбором формата
// data-path (bodyPrefix). Используется NewClient для проброса
// ClientConfig.DataPathBodyPrefix; при nil-поле NewClient передаёт сюда дефолт.
func newDirectTransportBP(serverAddr string, useTLS, skipVerify, bodyPrefix bool) *DirectTransport {
	return newDirectTransportFull(serverAddr, useTLS, skipVerify, false, "", "", bodyPrefix)
}

// NewDirectTransportWithSNI creates a direct transport that dials serverAddr (IP:port)
// but presents sniDomain as the TLS ServerName. This is the full-direct mode: the
// client contacts the origin IP without going through CF, but the TLS handshake
// still uses the CF-protected domain so nginx server_name matching and certificate
// presentation work normally.
//
// Implementation uses tls-client's WithServerNameOverwrite, which requires
// InsecureSkipVerify. This is acceptable because ShadowLink pins the server's
// X25519 public key at the protocol layer — TLS here is only for steganographic
// packet shape, not for authentication.
func NewDirectTransportWithSNI(serverAddr, sniDomain string, useTLS bool) *DirectTransport {
	return newDirectTransportFull(serverAddr, useTLS, false, false, "", sniDomain, defaultDataPathBodyPrefix)
}

// newDirectTransportWithSNIBP — как NewDirectTransportWithSNI, но с явным
// bodyPrefix (проброс ClientConfig.DataPathBodyPrefix из NewClient).
func newDirectTransportWithSNIBP(serverAddr, sniDomain string, useTLS, bodyPrefix bool) *DirectTransport {
	return newDirectTransportFull(serverAddr, useTLS, false, false, "", sniDomain, bodyPrefix)
}

// newDirectTransportECH is kept for backward compatibility with existing callers.
func newDirectTransportECH(serverAddr string, useTLS bool, skipVerify bool, echEnabled bool, echDomain string) *DirectTransport {
	return newDirectTransportFull(serverAddr, useTLS, skipVerify, echEnabled, echDomain, "", defaultDataPathBodyPrefix)
}

// newDirectTransportFull is the unified internal constructor. bodyPrefix — уже
// разрешённый эффективный выбор формата data-path (снимок дефолта либо явное
// поле конфига), потому что глобал недоступен мобильному фасаду.
func newDirectTransportFull(serverAddr string, useTLS bool, skipVerify bool, echEnabled bool, echDomain, sniOverride string, bodyPrefix bool) *DirectTransport {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	// Full-direct mode: tls-client's WithServerNameOverwrite requires
	// InsecureSkipVerify. This is acceptable because ShadowLink authenticates
	// the server via X25519 pubkey pin inside the encrypted payload — TLS
	// certificate validation here is cosmetic (for steganographic shape only).
	effSkipVerify := skipVerify
	if sniOverride != "" {
		effSkipVerify = true
	}

	fpPool := browser.NewFingerprintPool()
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr:  serverAddr,
		UseTLS:      useTLS,
		SkipVerify:  effSkipVerify,
		FPPool:      fpPool,
		MinRotation: 5 * time.Minute,
		MaxRotation: 10 * time.Minute,
		ECHEnabled:  echEnabled,
		ECHDomain:   echDomain,
		SNIOverride: sniOverride,
	})

	baseURL := fmt.Sprintf("%s://%s", scheme, serverAddr)
	publicURL := baseURL
	publicHost := ""
	if sniOverride != "" {
		// Host header and Origin/Referer must use the public (CF-protected)
		// domain, not the origin IP. Otherwise nginx server_name won't match
		// and the request looks anomalous (IP in Host header).
		_, port, splitErr := net.SplitHostPort(serverAddr)
		if splitErr != nil {
			port = "443"
		}
		if port == "443" || port == "" {
			publicURL = fmt.Sprintf("%s://%s", scheme, sniOverride)
			publicHost = sniOverride
		} else {
			publicURL = fmt.Sprintf("%s://%s:%s", scheme, sniOverride, port)
			publicHost = fmt.Sprintf("%s:%s", sniOverride, port)
		}
	}

	t := &DirectTransport{
		baseURL:            baseURL,
		publicURL:          publicURL,
		publicHost:         publicHost,
		signalHost:         core.SignalHost(sniOverride, serverAddr),
		urlPool:            browser.NewURLPool(),
		connManager:        cm,
		rlDetector:         DefaultDetector(&Stats),
		rc:                 browser.NewRatioController(2.5, 3.5),
		stopCover:          make(chan struct{}),
		dataPathBodyPrefix: bodyPrefix,
	}
	t.startCoverTraffic()
	return t
}

func (t *DirectTransport) Name() string { return "direct" }

// ConnManager returns the underlying ConnManager (for DomainPool wire-up by
// the engine and for testability). May be nil for transports constructed in
// degenerate states; callers MUST nil-check.
func (t *DirectTransport) ConnManager() *ConnManager { return t.connManager }

func (t *DirectTransport) Close() error {
	select {
	case <-t.stopCover:
	default:
		close(t.stopCover)
	}
	return t.connManager.Close()
}

// SetSession stores the active session and token so the cover traffic goroutine can use them.
func (t *DirectTransport) SetSession(s *core.Session) {
	t.coverMu.Lock()
	defer t.coverMu.Unlock()
	t.session = s
}

// SetSessionToken stores the session token for cover traffic requests.
func (t *DirectTransport) SetSessionToken(token []byte) {
	t.coverMu.Lock()
	defer t.coverMu.Unlock()
	t.sessionToken = token
}

// startCoverTraffic runs a background goroutine that checks CoverBudget at a
// jittered ~5s cadence and sends encrypted FlagPadding chunks to balance the
// upload/download ratio. The ratio controller is reset at a jittered ~30s
// cadence to prevent stale counters from accumulating after long idle
// periods (M-3 fix).
//
// NEW-4 fix: both tickers are jittered. Final-audit-2026-05-03 P1-3:
// switched to log-normal sampling (heavy-tailed) to defeat ML classifiers
// that detect the flat power spectrum + sharp band edges of uniform
// jitter via KS-test against a log-normal reference. Both tickers are
// recurring/periodic so they qualify for the heavy-tailed sampler. Two
// timers live alongside the main select to preserve the
// independent-cadence semantics of the original ticker pair.
//
// Final-audit-2026-05-03 P2-5 (Periodic cover budget reset ~30s introduces
// secondary FFT line) — closed by P1-3 above. The 30s `resetTimer` was
// previously `JitteredInterval(30s, 0.2)` (uniform ±20%) which still left
// a coherent first-moment around 30s in long captures. P1-3 swapped both
// timers to JitteredIntervalLogNormal with sigma=0.5 (truncation rails
// [base/2, base*2] = [15s, 60s]). Heavy-tailed log-normal eliminates the
// boxy uniform histogram that the FFT secondary-line detector relied on.
// Sigma=0.5 (moderate) was preferred over the milder sigma=0.3 because
// the same value is used by the 5s coverTimer above — keeping both
// timers on identical sampler shape removes a potential cross-period
// correlation signal where the same client uses heavier jitter on cover
// emit and lighter jitter on ratio reset.
func (t *DirectTransport) startCoverTraffic() {
	go func() {
		coverTimer := time.NewTimer(JitteredIntervalLogNormal(5*time.Second, 0.5))
		defer coverTimer.Stop()
		resetTimer := time.NewTimer(JitteredIntervalLogNormal(30*time.Second, 0.5))
		defer resetTimer.Stop()
		for {
			select {
			case <-t.stopCover:
				return
			case <-resetTimer.C:
				t.rc.Reset()
				resetTimer.Reset(JitteredIntervalLogNormal(30*time.Second, 0.5))
			case <-coverTimer.C:
				// Re-arm immediately so the body's continue/error paths
				// don't leave the timer disarmed. Reset on a stopped
				// timer is safe because we just consumed C.
				coverTimer.Reset(JitteredIntervalLogNormal(5*time.Second, 0.5))
				budget := t.rc.CoverBudget()
				if budget <= 0 {
					continue
				}

				t.coverMu.Lock()
				sess := t.session
				token := t.sessionToken
				t.coverMu.Unlock()
				if sess == nil || len(token) == 0 {
					continue
				}

				// Build a FlagPadding chunk of the budget size
				padChunk := &core.Chunk{
					SessionID: sess.ID,
					SeqNum:    sess.NextSeqNum(),
					Flags:     core.FlagPadding,
					Payload:   make([]byte, budget),
				}
				encrypted, err := sess.EncryptChunk(padChunk)
				if err != nil {
					continue
				}

				// Body-prefix wire format (D1/B2 migration, 2026-04): token
				// is packed at the start of the envelope data field via
				// buildDataEnvelope — no `Authorization: Bearer` header.
				// Headers from buildDataPostHeaders MUST remain byte-identical
				// across cover and real data POSTs (W4 invariant). Any edit
				// to either helper is a wire-visible change.
				ua := t.connManager.ActiveFingerprint().UserAgent()
				coverBody, err := buildDataEnvelope(token, encrypted)
				if err != nil {
					continue
				}

				coverURL := t.baseURL + t.urlPool.NextUploadPath()
				req, err := http.NewRequest("POST", coverURL, bytes.NewReader(coverBody))
				if err != nil {
					continue
				}
				if t.publicHost != "" {
					req.Host = t.publicHost
				}
				req.Header = buildDataPostHeaders(ua, t.publicURL)

				resp, err := t.connManager.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()

				t.rc.RecordUpload(len(encrypted))
				Stats.CoverPosts.Add(1)
			}
		}
	}()
}

// SendHandshake sends a ClientHello as the first request (no session token).
func (t *DirectTransport) SendHandshake(ctx context.Context, hello *core.ClientHello) ([]byte, error) {
	payload := make([]byte, 0, len(hello.EphemeralPub)+len(hello.EncryptedClientID))
	payload = append(payload, hello.EphemeralPub...)
	payload = append(payload, hello.EncryptedClientID...)

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	// F4 fix: use struct to control JSON key order (type,ts,data — like JS insertion order)
	type evt struct {
		Type string `json:"type"`
		TS   int64  `json:"ts"`
		Data string `json:"data"`
	}
	type envelope struct {
		Events []evt `json:"events"`
	}
	body, _ := json.Marshal(envelope{Events: []evt{{
		Type: "init", TS: time.Now().UnixMilli(), Data: encoded,
	}}})

	url := t.baseURL + t.urlPool.NextUploadPath()
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if t.publicHost != "" {
		req.Host = t.publicHost
	}

	ua := t.connManager.ActiveFingerprint().UserAgent()
	req.Header = http.Header{
		"content-type":    {"application/json"},
		"user-agent":      {ua},
		"accept":          {"application/json"},
		"accept-encoding": {"gzip, deflate, br"},
		"accept-language": {"en-US,en;q=0.9"},
		"origin":          {t.publicURL},
		"referer":         {t.publicURL + "/"},
		"cache-control":   {"no-cache"},
		http.HeaderOrderKey: {
			"content-type",
			"user-agent",
			"accept",
			"accept-encoding",
			"accept-language",
			"origin",
			"referer",
			"cache-control",
		},
	}

	resp, err := t.connManager.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Phase 2.2 (2026-05-14): read body first so BodyMarkerCarrier can inspect
	// the Schema.org JSON-LD marker — needed when CF strips the X-SL-RL header.
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	// Run the marker-only detector chain: body marker → header. No HTML
	// lifeline fallback here.
	//
	// Rationale (2026-05-29 false-positive fix): the lifeline ("HTML body +
	// no X-SL-RL → assume rate-limited, 90s cooldown") cannot tell a genuine
	// rate-limit decoy from a PLAIN decoy. The server emits plain decoys for
	// max_clients / protocol_unknown / auth_fail with NO X-SL-RL header and NO
	// Schema.org rl-state marker (failClosedToDecoyWithReason), identical on
	// the wire to a real decoy page. Only a true rate-limit decoy carries an
	// explicit marker (failClosedToDecoyRateLimitedV2 sets X-SL-RL + body
	// marker). Field data (pl1, 14.6h): server rejected 0 handshakes / emitted
	// 0 sentinels, yet the lifeline fired 48× on max_clients decoys, each a 90s
	// self-imposed cooldown that degraded the pool. DetectCarriersOnly mirrors
	// the WS path (ws_transport.go), which dropped the lifeline for the same
	// reason. A real server-directed rate-limit (explicit marker) is still
	// detected; a markerless decoy now surfaces as a regular network error.
	// fhttp.Header is map[string][]string identical in layout to net/http.Header;
	// the DetectionContext only reads the "X-SL-RL" header, so a shallow copy suffices.
	stdResp := &stdhttp.Response{Header: stdhttp.Header(resp.Header)}
	detCtx := &DetectionContext{Response: stdResp, BodyHead: respBytes, Path: "handshake", Host: t.signalHost}
	if sig := t.rlDetector.DetectCarriersOnly(detCtx); sig != nil {
		IncHandshakeDecoyReceived()
		return nil, &RateLimitError{Signal: sig}
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("handshake failed: HTTP %d, body: %s", resp.StatusCode, string(respBytes[:min(200, len(respBytes))]))
	}

	// Note: the old `respBytes[0] == '<'` HTML guard has been removed.
	// The detector's lifeline carrier (isHTMLBody + no X-SL-RL) handles all
	// CF-strip scenarios where a decoy HTML body is returned without markers.
	// If we somehow reach this point with an HTML body it means Detect returned
	// nil — that's a detector bug to fix, not a defensive check here.

	// Warmup delay after first handshake (mimics SDK init, not applied on reconnect)
	t.connManager.WarmupDelay()

	return respBytes, nil
}

// SendHandshakeRaw posts the given raw payload bytes as the first request
// (no Authorization), returning the server body. Used by the D4 probe flow
// to send a padded handshake via BuildHandshakePayload — transport here only
// cares about wrapping it in the analytics envelope.
//
// Error shape: when the server answers with HTTP >= 400 or with HTTP 200 +
// clearly non-JSON (e.g. an HTML decoy), SendHandshakeRaw returns a typed
// `*httpStatusError` (Status >= 400 for HTTP errors, Status == 200 for
// non-JSON bodies). The D4 probe uses `errors.As` on that type to decide
// whether to fall back to the legacy path or hard-fail on suspected MITM.
// Transports that wrap this error with `fmt.Errorf(..., %w, err)` stay
// compatible — `errors.As` walks the wrap chain.
func (t *DirectTransport) SendHandshakeRaw(ctx context.Context, payload []byte) ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	type evt struct {
		Type string `json:"type"`
		TS   int64  `json:"ts"`
		Data string `json:"data"`
	}
	type envelope struct {
		Events []evt `json:"events"`
	}
	body, _ := json.Marshal(envelope{Events: []evt{{
		Type: "init", TS: time.Now().UnixMilli(), Data: encoded,
	}}})

	url := t.baseURL + t.urlPool.NextUploadPath()
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if t.publicHost != "" {
		req.Host = t.publicHost
	}

	ua := t.connManager.ActiveFingerprint().UserAgent()
	req.Header = http.Header{
		"content-type":    {"application/json"},
		"user-agent":      {ua},
		"accept":          {"application/json"},
		"accept-encoding": {"gzip, deflate, br"},
		"accept-language": {"en-US,en;q=0.9"},
		"origin":          {t.publicURL},
		"referer":         {t.publicURL + "/"},
		"cache-control":   {"no-cache"},
		http.HeaderOrderKey: {
			"content-type",
			"user-agent",
			"accept",
			"accept-encoding",
			"accept-language",
			"origin",
			"referer",
			"cache-control",
		},
	}

	resp, err := t.connManager.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, &httpStatusError{
			Status: resp.StatusCode,
			Body:   fmt.Sprintf("HTTP %d, body: %s", resp.StatusCode, string(respBytes[:min(200, len(respBytes))])),
		}
	}
	if resp.StatusCode != 200 {
		return nil, &httpStatusError{
			Status: resp.StatusCode,
			Body:   fmt.Sprintf("handshake unexpected status: HTTP %d", resp.StatusCode),
		}
	}

	// Phase 2.2 (2026-05-14): check for rate-limit signal via the marker-only
	// detector chain before the HTML body guard, so a rl-state marker in the
	// decoy body is surfaced as ErrRateLimited rather than a generic
	// httpStatusError. SendHandshakeRaw is used by the D4 probe flow.
	//
	// 2026-05-29: switched Detect → DetectCarriersOnly (drop HTML lifeline).
	// Here the lifeline was doubly wrong: a markerless HTML decoy is exactly the
	// MITM/decoy case the explicit isHTMLBody guard below is designed to catch
	// (Status=200 → probe MITM hard-fail). Letting the lifeline pre-empt it as
	// rate-limit hid genuine decoy/MITM responses behind a 90s cooldown. Only a
	// real rate-limit decoy (explicit X-SL-RL or body marker) is reported as
	// ErrRateLimited; a markerless decoy falls through to the HTML guard.
	// fhttp.Header is map[string][]string; DetectionContext only reads "X-SL-RL".
	stdRespRaw := &stdhttp.Response{Header: stdhttp.Header(resp.Header)}
	detCtx := &DetectionContext{Response: stdRespRaw, BodyHead: respBytes, Path: "handshake", Host: t.signalHost}
	if sig := t.rlDetector.DetectCarriersOnly(detCtx); sig != nil {
		IncHandshakeDecoyReceived()
		return nil, &RateLimitError{Signal: sig}
	}

	// HTML-ish body on 200 after detector passed — almost certainly a decoy-page
	// response from a server that didn't recognize the payload (or an on-path
	// adversary injecting a splash page). Flag with Status=200 so the probe
	// classifier routes to the MITM hard-fail branch, not fallback.
	if isHTMLBody(respBytes) {
		return nil, &httpStatusError{
			Status: 200,
			Body:   fmt.Sprintf("server returned HTML instead of JSON (first 200 bytes): %s", string(respBytes[:min(200, len(respBytes))])),
		}
	}

	t.connManager.WarmupDelay()
	return respBytes, nil
}

// SendChunk sends an encrypted data chunk.
//
// Transport behavior is gated on t.dataPathBodyPrefix (per-instance; дефолт из
// env SHADOWLINK_DATAPATH_BODYPREFIX, переопределяем ClientConfig.DataPathBodyPrefix):
//   - on  → body-prefix wire format, no Authorization header (Phase T1.4)
//   - off → legacy Authorization: Bearer header (pre-migration contract)
//
// The flag defaults ON since 2026-04-26 (Phase 0 T1.4 flip after canary soak).
// Set SHADOWLINK_DATAPATH_BODYPREFIX=0 for emergency disable.
//
// seqNum is accepted for API compatibility but is not transmitted at the
// transport layer — sequence numbering lives inside the encrypted core.Chunk
// payload (see Spec §Open risks #3).
func (t *DirectTransport) SendChunk(ctx context.Context, encryptedChunk []byte, sessionToken []byte, seqNum uint32) ([]byte, error) {
	ua := t.connManager.ActiveFingerprint().UserAgent()

	var evtBody []byte
	var headers http.Header
	if t.dataPathBodyPrefix {
		var err error
		evtBody, err = buildDataEnvelope(sessionToken, encryptedChunk)
		if err != nil {
			return nil, fmt.Errorf("build data envelope: %w", err)
		}
		headers = buildDataPostHeaders(ua, t.publicURL)
	} else {
		// Legacy Bearer contract. Preserved for flag=off clients during T1.4
		// canary; retired in Phase 3 once new / total ≥ 0.99 for 7 days
		// (see docs/superpowers/specs/2026-04-22-t14-direct-transport-v1-closure-design.md §Rollout plan and
		// shadowlink/docs/protocols/body-prefix-v1.md §"Phase 3 Legacy Retirement").
		payload := base64.RawURLEncoding.EncodeToString(encryptedChunk)
		type evt struct {
			Type string `json:"type"`
			TS   int64  `json:"ts"`
			Data string `json:"data"`
		}
		type envelope struct {
			Events []evt `json:"events"`
		}
		var err error
		evtBody, err = json.Marshal(envelope{Events: []evt{{
			Type: browser.RandomEventType(),
			TS:   time.Now().UnixMilli(),
			Data: payload,
		}}})
		if err != nil {
			return nil, fmt.Errorf("marshal legacy envelope: %w", err)
		}
		headers = http.Header{
			"content-type":    {"application/json"},
			"authorization":   {"Bearer " + base64.RawURLEncoding.EncodeToString(sessionToken)},
			"x-request-id":    {fmt.Sprintf("%08x", browser.RandomUint32())},
			"user-agent":      {ua},
			"accept":          {"application/json"},
			"accept-encoding": {"gzip, deflate, br"},
			"accept-language": {"en-US,en;q=0.9"},
			"origin":          {t.publicURL},
			"referer":         {t.publicURL + "/"},
			"cache-control":   {"no-cache"},
			http.HeaderOrderKey: {
				"content-type",
				"authorization",
				"x-request-id",
				"user-agent",
				"accept",
				"accept-encoding",
				"accept-language",
				"origin",
				"referer",
				"cache-control",
			},
		}
	}

	url := t.baseURL + t.urlPool.NextUploadPath()
	req, err := http.NewRequest("POST", url, bytes.NewReader(evtBody))
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if t.publicHost != "" {
		req.Host = t.publicHost
	}
	req.Header = headers

	resp, err := t.connManager.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if t.rc != nil {
		t.rc.RecordUpload(len(encryptedChunk))
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	if t.rc != nil {
		t.rc.RecordDownload(len(respBody))
	}

	encResp, _, err := browser.ParseDownloadResponse(respBody)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return encResp, nil
}

// SendChunkRawBody sends a chunk and returns the raw JSON response body (not parsed).
// Used by PollVia to handle multi-chunk server responses. Flag-gated identically
// to SendChunk — see that function's docstring for the semantics of
// t.dataPathBodyPrefix (per-instance; дефолт из env SHADOWLINK_DATAPATH_BODYPREFIX).
//
// seqNum is accepted for API compatibility but is not transmitted at the
// transport layer — sequence numbering lives inside the encrypted core.Chunk
// payload (see Spec §Open risks #3).
func (t *DirectTransport) SendChunkRawBody(ctx context.Context, encryptedChunk []byte, sessionToken []byte, seqNum uint32) ([]byte, error) {
	ua := t.connManager.ActiveFingerprint().UserAgent()

	var evtBody []byte
	var headers http.Header
	if t.dataPathBodyPrefix {
		var err error
		evtBody, err = buildDataEnvelope(sessionToken, encryptedChunk)
		if err != nil {
			return nil, fmt.Errorf("build data envelope: %w", err)
		}
		headers = buildDataPostHeaders(ua, t.publicURL)
	} else {
		// Legacy Bearer contract. Preserved for flag=off clients during T1.4
		// canary; retired in Phase 3 once new / total ≥ 0.99 for 7 days
		// (see docs/superpowers/specs/2026-04-22-t14-direct-transport-v1-closure-design.md §Rollout plan and
		// shadowlink/docs/protocols/body-prefix-v1.md §"Phase 3 Legacy Retirement").
		payload := base64.RawURLEncoding.EncodeToString(encryptedChunk)
		type evt struct {
			Type string `json:"type"`
			TS   int64  `json:"ts"`
			Data string `json:"data"`
		}
		type envelope struct {
			Events []evt `json:"events"`
		}
		var err error
		evtBody, err = json.Marshal(envelope{Events: []evt{{
			Type: browser.RandomEventType(),
			TS:   time.Now().UnixMilli(),
			Data: payload,
		}}})
		if err != nil {
			return nil, fmt.Errorf("marshal legacy envelope: %w", err)
		}
		headers = http.Header{
			"content-type":    {"application/json"},
			"authorization":   {"Bearer " + base64.RawURLEncoding.EncodeToString(sessionToken)},
			"x-request-id":    {fmt.Sprintf("%08x", browser.RandomUint32())},
			"user-agent":      {ua},
			"accept":          {"application/json"},
			"accept-encoding": {"gzip, deflate, br"},
			"accept-language": {"en-US,en;q=0.9"},
			"origin":          {t.publicURL},
			"referer":         {t.publicURL + "/"},
			"cache-control":   {"no-cache"},
			http.HeaderOrderKey: {
				"content-type",
				"authorization",
				"x-request-id",
				"user-agent",
				"accept",
				"accept-encoding",
				"accept-language",
				"origin",
				"referer",
				"cache-control",
			},
		}
	}

	url := t.baseURL + t.urlPool.NextUploadPath()
	req, err := http.NewRequest("POST", url, bytes.NewReader(evtBody))
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if t.publicHost != "" {
		req.Host = t.publicHost
	}
	req.Header = headers

	resp, err := t.connManager.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, respBody)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 128*1024))
}

// CDNTransport connects to the server via Cloudflare CDN (orange cloud).
type CDNTransport struct {
	direct *DirectTransport
}

// NewCDNTransport creates a transport through Cloudflare CDN.
func NewCDNTransport(cdnDomain string) *CDNTransport {
	direct := newDirectTransportECH(cdnDomain, true, false, false, "")
	return &CDNTransport{direct: direct}
}

// NewCDNTransportWithECH creates a CDN transport with optional ECH support.
// When echEnabled is true, the ConnManager will resolve and cache ECH config
// from DNS HTTPS records for the CDN domain, preparing for utls-level ECH injection.
func NewCDNTransportWithECH(cdnDomain string, echEnabled bool) *CDNTransport {
	direct := newDirectTransportECH(cdnDomain, true, false, echEnabled, cdnDomain)
	return &CDNTransport{direct: direct}
}

func (t *CDNTransport) Name() string { return "cdn" }
func (t *CDNTransport) Close() error { return t.direct.Close() }

// ConnManager proxies to the wrapped DirectTransport so callers can install a
// DomainPool on the underlying ConnManager.
func (t *CDNTransport) ConnManager() *ConnManager { return t.direct.ConnManager() }

func (t *CDNTransport) SendHandshake(ctx context.Context, hello *core.ClientHello) ([]byte, error) {
	return t.direct.SendHandshake(ctx, hello)
}

func (t *CDNTransport) SendHandshakeRaw(ctx context.Context, payload []byte) ([]byte, error) {
	return t.direct.SendHandshakeRaw(ctx, payload)
}

func (t *CDNTransport) SendChunk(ctx context.Context, data []byte, token []byte, seq uint32) ([]byte, error) {
	return t.direct.SendChunk(ctx, data, token, seq)
}

// SendChunkRawBody returns the raw response body for multi-chunk parsing.
func (t *CDNTransport) SendChunkRawBody(ctx context.Context, data []byte, token []byte, seq uint32) ([]byte, error) {
	return t.direct.SendChunkRawBody(ctx, data, token, seq)
}

func (t *CDNTransport) SetSession(s *core.Session) {
	t.direct.SetSession(s)
}

func (t *CDNTransport) SetSessionToken(token []byte) {
	t.direct.SetSessionToken(token)
}

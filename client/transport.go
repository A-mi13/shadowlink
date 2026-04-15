package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

// Compile-time assertions: both transports must implement SessionAware.
var (
	_ SessionAware = (*DirectTransport)(nil)
	_ SessionAware = (*CDNTransport)(nil)
)

// DirectTransport connects directly to the ShadowLink server.
// Uses bogdanfinn/tls-client for browser-identical TLS + HTTP/2 fingerprinting.
type DirectTransport struct {
	baseURL     string // scheme://DIAL_HOST:PORT — drives DNS/dial + default SNI
	publicURL   string // scheme://VISIBLE_HOST:PORT — used in Origin/Referer headers
	publicHost  string // VISIBLE_HOST used as HTTP Host header (== sniOverride when set, else dial host)
	urlPool     *browser.URLPool
	connManager *ConnManager

	rc           *browser.RatioController
	session      *core.Session
	sessionToken []byte
	coverMu      sync.Mutex
	stopCover    chan struct{}
}

// NewDirectTransport creates a transport that connects directly to the server.
// serverAddr is "host:port" (e.g., "example.com:443").
// useTLS enables TLS with browser-identical fingerprinting. skipVerify for testing.
func NewDirectTransport(serverAddr string, useTLS bool, skipVerify bool) *DirectTransport {
	return newDirectTransportFull(serverAddr, useTLS, skipVerify, false, "", "")
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
	return newDirectTransportFull(serverAddr, useTLS, false, false, "", sniDomain)
}

// newDirectTransportECH is kept for backward compatibility with existing callers.
func newDirectTransportECH(serverAddr string, useTLS bool, skipVerify bool, echEnabled bool, echDomain string) *DirectTransport {
	return newDirectTransportFull(serverAddr, useTLS, skipVerify, echEnabled, echDomain, "")
}

// newDirectTransportFull is the unified internal constructor.
func newDirectTransportFull(serverAddr string, useTLS bool, skipVerify bool, echEnabled bool, echDomain, sniOverride string) *DirectTransport {
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
		baseURL:     baseURL,
		publicURL:   publicURL,
		publicHost:  publicHost,
		urlPool:     browser.NewURLPool(),
		connManager: cm,
		rc:          browser.NewRatioController(2.5, 3.5),
		stopCover:   make(chan struct{}),
	}
	t.startCoverTraffic()
	return t
}

func (t *DirectTransport) Name() string { return "direct" }

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

// startCoverTraffic runs a background goroutine that checks CoverBudget every 5s
// and sends encrypted FlagPadding chunks to balance the upload/download ratio.
func (t *DirectTransport) startCoverTraffic() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		// M-3 fix: periodically reset ratio controller to prevent stale counters
		// from accumulating after long idle periods, which would cause a burst of cover traffic.
		resetTicker := time.NewTicker(30 * time.Second)
		defer resetTicker.Stop()
		for {
			select {
			case <-t.stopCover:
				return
			case <-resetTicker.C:
				t.rc.Reset()
			case <-ticker.C:
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

				// Build fhttp cover request (same structure as SendChunk but with FlagPadding payload)
				ua := t.connManager.ActiveFingerprint().UserAgent()
				coverPayload := base64.RawURLEncoding.EncodeToString(encrypted)
				type evt struct {
					Type string `json:"type"`
					TS   int64  `json:"ts"`
					Data string `json:"data"`
				}
				type envelope struct {
					Events []evt `json:"events"`
				}
				coverBody, _ := json.Marshal(envelope{Events: []evt{{
					Type: browser.RandomEventType(),
					TS:   time.Now().UnixMilli(),
					Data: coverPayload,
				}}})

				coverURL := t.baseURL + t.urlPool.NextUploadPath()
				req, err := http.NewRequest("POST", coverURL, bytes.NewReader(coverBody))
				if err != nil {
					continue
				}
				if t.publicHost != "" {
					req.Host = t.publicHost
				}
				req.Header = http.Header{
					"content-type":    {"application/json"},
					"authorization":   {"Bearer " + base64.RawURLEncoding.EncodeToString(token)},
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

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("handshake failed: HTTP %d, body: %s", resp.StatusCode, string(respBytes[:min(200, len(respBytes))]))
	}

	// Debug: check if response looks like JSON
	if len(respBytes) > 0 && respBytes[0] == '<' {
		return nil, fmt.Errorf("server returned HTML instead of JSON (first 200 bytes): %s", string(respBytes[:min(200, len(respBytes))]))
	}

	// Warmup delay after first handshake (mimics SDK init, not applied on reconnect)
	t.connManager.WarmupDelay()

	return respBytes, nil
}

// SendChunk sends an encrypted data chunk with session token.
func (t *DirectTransport) SendChunk(ctx context.Context, encryptedChunk []byte, sessionToken []byte, seqNum uint32) ([]byte, error) {
	ua := t.connManager.ActiveFingerprint().UserAgent()

	// F4 fix: struct-based JSON for browser-like key ordering (type,ts,data)
	payload := base64.RawURLEncoding.EncodeToString(encryptedChunk)
	type evt struct {
		Type string `json:"type"`
		TS   int64  `json:"ts"`
		Data string `json:"data"`
	}
	type envelope struct {
		Events []evt `json:"events"`
	}
	evtBody, _ := json.Marshal(envelope{Events: []evt{{
		Type: browser.RandomEventType(),
		TS:   time.Now().UnixMilli(),
		Data: payload,
	}}})

	url := t.baseURL + t.urlPool.NextUploadPath()
	req, err := http.NewRequest("POST", url, bytes.NewReader(evtBody))
	if err != nil {
		return nil, err
	}
	if t.publicHost != "" {
		req.Host = t.publicHost
	}

	req.Header = http.Header{
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

	// H5 fix: limit response size
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
// Used by PollVia to handle multi-chunk server responses.
func (t *DirectTransport) SendChunkRawBody(ctx context.Context, encryptedChunk []byte, sessionToken []byte, seqNum uint32) ([]byte, error) {
	ua := t.connManager.ActiveFingerprint().UserAgent()

	payload := base64.RawURLEncoding.EncodeToString(encryptedChunk)
	type evt struct {
		Type string `json:"type"`
		TS   int64  `json:"ts"`
		Data string `json:"data"`
	}
	type envelope struct {
		Events []evt `json:"events"`
	}
	evtBody, _ := json.Marshal(envelope{Events: []evt{{
		Type: browser.RandomEventType(),
		TS:   time.Now().UnixMilli(),
		Data: payload,
	}}})

	url := t.baseURL + t.urlPool.NextUploadPath()
	req, err := http.NewRequest("POST", url, bytes.NewReader(evtBody))
	if err != nil {
		return nil, err
	}
	if t.publicHost != "" {
		req.Host = t.publicHost
	}

	req.Header = http.Header{
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

func (t *CDNTransport) SendHandshake(ctx context.Context, hello *core.ClientHello) ([]byte, error) {
	return t.direct.SendHandshake(ctx, hello)
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

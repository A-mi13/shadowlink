package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

// DirectTransport connects directly to the ShadowLink server.
// Uses bogdanfinn/tls-client for browser-identical TLS + HTTP/2 fingerprinting.
type DirectTransport struct {
	baseURL     string
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
	return newDirectTransportECH(serverAddr, useTLS, skipVerify, false, "")
}

// newDirectTransportECH is the internal constructor that accepts ECH parameters.
func newDirectTransportECH(serverAddr string, useTLS bool, skipVerify bool, echEnabled bool, echDomain string) *DirectTransport {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	fpPool := browser.NewFingerprintPool()
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr:  serverAddr,
		UseTLS:      useTLS,
		SkipVerify:  skipVerify,
		FPPool:      fpPool,
		MinRotation: 5 * time.Minute,
		MaxRotation: 10 * time.Minute,
		ECHEnabled:  echEnabled,
		ECHDomain:   echDomain,
	})

	t := &DirectTransport{
		baseURL:     fmt.Sprintf("%s://%s", scheme, serverAddr),
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
				req.Header = http.Header{
					"content-type":    {"application/json"},
					"authorization":   {"Bearer " + base64.RawURLEncoding.EncodeToString(token)},
					"x-request-id":    {fmt.Sprintf("%08x", browser.RandomUint32())},
					"user-agent":      {ua},
					"accept":          {"application/json"},
					"accept-encoding": {"gzip, deflate, br"},
					"accept-language": {"en-US,en;q=0.9"},
					"origin":          {t.baseURL},
					"referer":         {t.baseURL + "/"},
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

	ua := t.connManager.ActiveFingerprint().UserAgent()
	req.Header = http.Header{
		"content-type":    {"application/json"},
		"user-agent":      {ua},
		"accept":          {"application/json"},
		"accept-encoding": {"gzip, deflate, br"},
		"accept-language": {"en-US,en;q=0.9"},
		"origin":          {t.baseURL},
		"referer":         {t.baseURL + "/"},
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

	req.Header = http.Header{
		"content-type":    {"application/json"},
		"authorization":   {"Bearer " + base64.RawURLEncoding.EncodeToString(sessionToken)},
		"x-request-id":    {fmt.Sprintf("%08x", browser.RandomUint32())},
		"user-agent":      {ua},
		"accept":          {"application/json"},
		"accept-encoding": {"gzip, deflate, br"},
		"accept-language": {"en-US,en;q=0.9"},
		"origin":          {t.baseURL},
		"referer":         {t.baseURL + "/"},
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

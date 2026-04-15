package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	stdhttp "net/http"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// StreamTransport is the interface shared by WebSocketTransport and SplitTransport.
// SOCKS5 handlers use this for bidirectional data relay.
type StreamTransport interface {
	WriteMessage(data []byte) error
	StartReader(ctx context.Context, cl *Client) error
	Close() error
}

// Compile-time assertions.
var (
	_ StreamTransport = (*WebSocketTransport)(nil)
	_ StreamTransport = (*SplitTransport)(nil)
	_ ControlWriter   = (*WebSocketTransport)(nil)
)

// PoolAware is implemented by pool transports that manage multiple WS connections.
// Each WS has its own crypto session — callers must use the correct session per stream.
type PoolAware interface {
	AssignStream(streamID uint16)
	ReleaseStream(streamID uint16)
	SessionForStream(streamID uint16) *core.Session
	WriteMessageForStream(streamID uint16, data []byte) error
}

// PendingTracker tracks in-flight CONNECT requests per slot for backpressure.
// Implemented by WSPoolTransport to distribute CONNECT load evenly across CF CDN connections.
type PendingTracker interface {
	IncrPending(streamID uint16)
	DecrPending(streamID uint16)
	AllSlotsAtMaxPending() bool
}

// ControlWriter is implemented by transports that support priority write channels.
// Control messages (CONNECT, FIN, keepalive) are drained before data messages.
type ControlWriter interface {
	WriteControlMessage(data []byte) error
}

// ControlPoolAware extends PoolAware with priority write per stream.
type ControlPoolAware interface {
	WriteControlMessageForStream(streamID uint16, data []byte) error
}

// StreamWrite sends a data frame via the correct slot if transport is pool-aware, else via WriteMessage.
func StreamWrite(wst StreamTransport, streamID uint16, data []byte) error {
	if pa, ok := wst.(PoolAware); ok {
		return pa.WriteMessageForStream(streamID, data)
	}
	return wst.WriteMessage(data)
}

// StreamWriteControl sends a control frame (CONNECT, FIN) with high priority.
// Falls back to StreamWrite if the transport doesn't support priority channels.
func StreamWriteControl(wst StreamTransport, streamID uint16, data []byte) error {
	// Pool-aware: route to correct slot's control channel.
	if cpa, ok := wst.(ControlPoolAware); ok {
		return cpa.WriteControlMessageForStream(streamID, data)
	}
	// Single WS: use control channel directly.
	if cw, ok := wst.(ControlWriter); ok {
		return cw.WriteControlMessage(data)
	}
	// Fallback: no priority support (SplitTransport, legacy).
	return StreamWrite(wst, streamID, data)
}

// StreamSession returns the session for a specific stream (pool-aware) or the client's global session.
func StreamSession(wst StreamTransport, cl *Client, streamID uint16) *core.Session {
	if pa, ok := wst.(PoolAware); ok {
		return pa.SessionForStream(streamID)
	}
	return cl.Session()
}

// SplitTransport provides SplitHTTP mode for CDN system VPN.
// Upload: HTTP POST via standard Go net/http (fresh TCP per request — immune to CF keep-alive kills).
// Download: persistent chunked GET response — server pushes data instantly.
// This replaces WebSocket which Cloudflare kills under load after ~30 seconds.
//
// Why standard net/http for uploads (not tls-client/bogdanfinn):
// - tls-client HTTP/1.1: CF kills keep-alive connections after ~20s → dead uploads
// - tls-client HTTP/2: internal stream retries duplicate seq_nums → server rejects
// - Standard Go net/http with DisableKeepAlives: fresh TCP per POST, proven stable (download stream uses it)
type SplitTransport struct {
	uploadClient   *stdhttp.Client             // standard Go HTTP client for uploads (fresh TCP per POST)
	streamMgr      *ConnManager                // for download stream (no timeout — persistent connection)
	downloadClient *stdhttp.Client             // standard Go HTTP client for download stream
	fpPool         *browser.FingerprintPool    // for User-Agent rotation
	serverAddr     string
	token          []byte
	urlPool        *browser.URLPool

	mu         sync.Mutex
	downloadRC io.ReadCloser // download stream response body

	// onResponse is called with encrypted response data from every upload POST.
	// This turns every upload into a download poll — no persistent stream dependency.
	onResponse func(encResp []byte)
}

// SetOnResponse sets a callback that receives encrypted download data from POST responses.
func (t *SplitTransport) SetOnResponse(fn func([]byte)) {
	t.onResponse = fn
}

// NewSplitTransport creates a SplitHTTP transport.
// Upload: standard Go net/http with DisableKeepAlives (fresh TCP per POST).
// Download: standard Go net/http with persistent chunked GET.
func NewSplitTransport(serverAddr string, token []byte) *SplitTransport {
	fpPool := browser.NewFingerprintPool()

	// Upload client: fresh TCP connection per POST request.
	// DisableKeepAlives prevents CF from killing idle connections (no keep-alive = no stale connections).
	// tls-client (bogdanfinn) is NOT used: it buffers responses (HTTP/1.1) and
	// duplicates requests via internal retries (HTTP/2), both breaking SplitHTTP.
	ulClient := &stdhttp.Client{
		Transport: &stdhttp.Transport{
			TLSClientConfig:    &tls.Config{},
			DisableCompression: true,
			DisableKeepAlives:  true, // fresh TCP per request — immune to CF keep-alive kills
			ForceAttemptHTTP2:  false,
			TLSNextProto:      make(map[string]func(string, *tls.Conn) stdhttp.RoundTripper),
		},
		Timeout: 25 * time.Second, // CF CDN round-trip can take 10-15s under load; 10s caused mass timeouts
	}

	// Separate ConnManager for download stream — no timeout for persistent chunked GET.
	streamCM := NewConnManager(ConnManagerConfig{
		ServerAddr:  serverAddr,
		UseTLS:      true,
		NoTimeout:   true,
		FPPool:      fpPool,
		MinRotation: 5 * time.Minute,
		MaxRotation: 10 * time.Minute,
	})

	// Download client: persistent chunked GET (same proven approach as before).
	dlClient := &stdhttp.Client{
		Transport: &stdhttp.Transport{
			TLSClientConfig:    &tls.Config{},
			DisableCompression: true,
			ForceAttemptHTTP2:  false,
			TLSNextProto:      make(map[string]func(string, *tls.Conn) stdhttp.RoundTripper),
		},
		Timeout: 0, // no timeout — persistent stream
	}

	return &SplitTransport{
		uploadClient:   ulClient,
		streamMgr:      streamCM,
		downloadClient: dlClient,
		fpPool:         fpPool,
		serverAddr:     serverAddr,
		token:          token,
		urlPool:        browser.NewURLPool(),
	}
}

// WriteMessage sends encrypted data via HTTP POST (upload direction).
// Uses standard Go net/http with fresh TCP per request (DisableKeepAlives).
// NO RETRY: each POST has a unique seq_num baked into the encrypted data.
// Retrying the same encrypted chunk causes seq_num duplicates on the server.
// With DisableKeepAlives, each request gets a fresh TCP — if it fails,
// the network is genuinely broken, retrying won't help.
func (t *SplitTransport) WriteMessage(data []byte) error {
	return t.doUpload(data)
}

// Poll sends an empty poll request to retrieve pending download data.
func (t *SplitTransport) Poll(session *core.Session) error {
	if session == nil {
		return fmt.Errorf("poll: nil session")
	}
	chunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), 0, nil)
	encrypted, err := session.EncryptChunk(chunk)
	core.PutBuffer(chunk.Payload)
	if err != nil {
		return fmt.Errorf("poll encrypt: %w", err)
	}
	return t.WriteMessage(encrypted)
}

// buildUploadRequest creates a standard net/http POST request with analytics JSON envelope.
func (t *SplitTransport) buildUploadRequest(data []byte) (*stdhttp.Request, error) {
	payload := base64.RawURLEncoding.EncodeToString(data)
	type evt struct {
		Type string `json:"type"`
		TS   int64  `json:"ts"`
		Data string `json:"data"`
	}
	type envelope struct {
		Events []evt `json:"events"`
	}
	body, _ := json.Marshal(envelope{Events: []evt{{
		Type: browser.RandomEventType(),
		TS:   time.Now().UnixMilli(),
		Data: payload,
	}}})

	baseURL := fmt.Sprintf("https://%s", t.serverAddr)
	url := baseURL + t.urlPool.NextUploadPath()
	req, err := stdhttp.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	ua := t.fpPool.Next().UserAgent()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(t.token))
	req.Header.Set("X-Request-Id", fmt.Sprintf("%08x", browser.RandomUint32()))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Cache-Control", "no-cache")
	return req, nil
}

// doUpload sends a single POST via standard Go net/http client.
func (t *SplitTransport) doUpload(data []byte) error {
	uploadStart := time.Now()

	req, err := t.buildUploadRequest(data)
	if err != nil {
		return err
	}

	resp, err := t.uploadClient.Do(req)
	elapsed := time.Since(uploadStart)
	if err != nil {
		slog.Warn("split upload FAIL", "elapsed", elapsed, "err", err)
		return fmt.Errorf("split upload: %w", err)
	}
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		slog.Warn("split upload HTTP error", "status", resp.StatusCode, "elapsed", elapsed)
		return fmt.Errorf("split upload: HTTP %d: %s", resp.StatusCode, respBody)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if t.onResponse != nil && len(respBody) > 0 {
		// Server batches multiple chunks per response (BuildDownloadResponseMulti).
		// Must process ALL chunks, not just the first — otherwise TLS handshake
		// data arrives incomplete and browsers show ERR_SSL_PROTOCOL_ERROR.
		encChunks, err := browser.ParseDownloadResponseMulti(respBody)
		if err == nil {
			for _, enc := range encChunks {
				t.onResponse(enc)
			}
		} else {
			// Fallback: single-chunk response (legacy/CONNECT results).
			encResp, _, err := browser.ParseDownloadResponse(respBody)
			if err == nil && len(encResp) > 0 {
				t.onResponse(encResp)
			}
		}
	}
	if elapsed > 3*time.Second {
		slog.Warn("split upload SLOW", "elapsed", elapsed, "bodyLen", len(data))
	}
	return nil
}

// SendChunkSync sends a POST and returns the parsed encrypted response.
// Used for CONNECT which needs synchronous request-response.
// NO RETRY: same reason as WriteMessage — encrypted chunk has baked-in seq_num.
func (t *SplitTransport) SendChunkSync(data []byte) ([]byte, error) {
	return t.doUploadSync(data)
}

// doUploadSync sends a POST and returns the encrypted response chunk directly.
func (t *SplitTransport) doUploadSync(data []byte) ([]byte, error) {
	uploadStart := time.Now()

	req, err := t.buildUploadRequest(data)
	if err != nil {
		return nil, err
	}

	resp, err := t.uploadClient.Do(req)
	elapsed := time.Since(uploadStart)
	if err != nil {
		return nil, fmt.Errorf("split sync upload: %w", err)
	}
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		return nil, fmt.Errorf("split sync upload: HTTP %d: %s", resp.StatusCode, respBody)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if elapsed > 3*time.Second {
		slog.Warn("split sync upload SLOW", "elapsed", elapsed, "bodyLen", len(data))
	}
	encResp, _, err := browser.ParseDownloadResponse(respBody)
	if err != nil {
		return nil, fmt.Errorf("split sync parse response: %w", err)
	}
	return encResp, nil
}

// OpenDownloadStream opens a persistent GET connection for receiving data.
// Server responds with chunked Transfer-Encoding, pushing encrypted frames.
// Uses standard Go net/http client — tls-client (bogdanfinn) buffers response
// bodies internally, breaking chunked streaming through CF CDN.
func (t *SplitTransport) OpenDownloadStream() (io.ReadCloser, error) {
	baseURL := fmt.Sprintf("https://%s", t.serverAddr)
	url := baseURL + t.urlPool.NextDownloadPath()

	req, err := stdhttp.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	ua := t.streamMgr.ActiveFingerprint().UserAgent()
	req.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(t.token))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := t.downloadClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("split download open: %w", err)
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("split download: HTTP %d", resp.StatusCode)
	}

	slog.Info("SplitHTTP download stream opened", "content-type", resp.Header.Get("Content-Type"))
	return resp.Body, nil
}

// StartReader reads length-prefixed binary frames from the download stream,
// decrypts them, and routes to the client's stream channels.
// Frame format: [4-byte big-endian length][encrypted chunk bytes].
// Same interface as WebSocketTransport.StartReader().
func (t *SplitTransport) StartReader(ctx context.Context, cl *Client) error {
	rc, err := t.OpenDownloadStream()
	if err != nil {
		return fmt.Errorf("open download stream: %w", err)
	}
	defer rc.Close()

	t.mu.Lock()
	t.downloadRC = rc
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.downloadRC = nil
		t.mu.Unlock()
	}()

	slog.Info("SplitHTTP StartReader started (binary mode)")
	lenBuf := make([]byte, 4)
	msgCount := 0

	// Read timeout must be > server keepalive interval (25s).
	const readTimeout = 45 * time.Second
	readWithTimeout := func(buf []byte) error {
		type result struct{ err error }
		ch := make(chan result, 1)
		go func() {
			_, err := io.ReadFull(rc, buf)
			ch <- result{err}
		}()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readTimeout):
			rc.Close()
			return fmt.Errorf("download stream read timeout (%s)", readTimeout)
		case r := <-ch:
			return r.err
		}
	}

	for {
		select {
		case <-ctx.Done():
			slog.Info("SplitHTTP StartReader stopped", "messages", msgCount)
			return ctx.Err()
		default:
		}

		if err := readWithTimeout(lenBuf); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("split read length: %w", err)
		}

		frameLen := binary.BigEndian.Uint32(lenBuf)
		if frameLen > 256*1024 {
			return fmt.Errorf("split frame too large: %d bytes", frameLen)
		}

		frameBuf := make([]byte, frameLen)
		if err := readWithTimeout(frameBuf); err != nil {
			return fmt.Errorf("split read frame: %w", err)
		}

		session := cl.Session()
		if session == nil {
			slog.Warn("SplitHTTP frame ignored: no session", "frameLen", frameLen)
			continue
		}

		chunk, err := session.DecryptChunkSafe(frameBuf)
		if err != nil {
			slog.Warn("SplitHTTP decrypt FAIL", "err", err, "frameLen", frameLen)
			continue
		}

		if len(chunk.Payload) < 2 {
			if chunk.Flags == core.FlagAck {
				slog.Debug("SplitHTTP keepalive ACK received")
			} else {
				slog.Debug("SplitHTTP frame: short payload", "flags", chunk.Flags, "len", len(chunk.Payload))
			}
			continue
		}

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		if chunk.Flags == core.FlagUDP {
			cl.RouteToStream(streamID, chunk.Payload)
		} else {
			cl.RouteToStream(streamID, chunk.Payload[2:])
		}

		if msgCount <= 20 || msgCount%50 == 0 {
			slog.Info("SplitHTTP download decrypt OK", "msg", msgCount, "stream", streamID,
				"payloadLen", len(chunk.Payload), "flags", chunk.Flags)
		}
	}
}

// Close closes the download stream and underlying connection manager.
func (t *SplitTransport) Close() error {
	t.mu.Lock()
	rc := t.downloadRC
	t.mu.Unlock()
	if rc != nil {
		rc.Close()
	}
	t.streamMgr.Close()
	t.uploadClient.CloseIdleConnections()
	return nil
}

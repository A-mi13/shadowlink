package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// TryControlPoolAware extends ControlPoolAware with a non-blocking priority
// write per stream. Used by the flow-control credit sender (Bug #8): a credit
// frame that can't be enqueued right now is simply retried on the next tick
// (the delta is additive), so the sender must never block.
type TryControlPoolAware interface {
	TryWriteControlMessageForStream(streamID uint16, data []byte) bool
}

// TryStreamWriteControl sends a control frame to the stream's slot without
// blocking. Returns true if enqueued, false if the channel was full / the
// transport doesn't support non-blocking control writes (caller keeps the
// pending delta to retry).
func TryStreamWriteControl(wst StreamTransport, streamID uint16, data []byte) bool {
	if tpa, ok := wst.(TryControlPoolAware); ok {
		return tpa.TryWriteControlMessageForStream(streamID, data)
	}
	return false
}

// PoolReadiness reports the live health of an underlying transport pool. Used
// by the SOCKS5 UDP ASSOCIATE handler (C12 F6, May audit) to fail-fast when
// the pool is starved of ready slots — without this gate, a UDP ASSOCIATE
// can permanently hang on a slot that never recovers.
//
// Single-WS transports (DirectTransport, SplitTransport, WebSocketTransport)
// do not implement this interface — callers must treat absence of the
// interface as "always ready" so non-pooled deployments are not penalised.
type PoolReadiness interface {
	// ReadyCount returns the number of slots currently in slotReady state.
	// Implementations MUST be safe to call concurrently with reconnects.
	ReadyCount() int
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
	uploadClient   *stdhttp.Client          // standard Go HTTP client for uploads (fresh TCP per POST)
	streamMgr      *ConnManager             // for download stream (no timeout — persistent connection)
	downloadClient *stdhttp.Client          // standard Go HTTP client for download stream
	fpPool         *browser.FingerprintPool // for User-Agent rotation
	serverAddr     string
	token          []byte
	urlPool        *browser.URLPool

	// uploadSem caps concurrent POSTs to prevent goroutine explosion. Under
	// active browsing, hundreds of streams close per second — each fires a
	// FIN POST which (with DisableKeepAlives + slow CF RTT) holds a goroutine
	// for seconds. Without a cap, they pile up into tens of thousands of
	// stuck goroutines. 16 concurrent POSTs is plenty for 30-50 Mbps.
	uploadSem chan struct{}

	mu         sync.Mutex
	downloadRC io.ReadCloser // download stream response body

	// onResponse is called with encrypted response data from every upload POST.
	// This turns every upload into a download poll — no persistent stream dependency.
	onResponse func(encResp []byte)

	// decoy emits fake GET requests to decoy paths while the session is
	// active, shifting the POST-only traffic profile toward a realistic
	// browser mix. See DPI audit vector V5.
	decoy *DecoyTraffic
}

// SetOnResponse sets a callback that receives encrypted download data from POST responses.
func (t *SplitTransport) SetOnResponse(fn func([]byte)) {
	t.onResponse = fn
}

// NewSplitTransport creates a SplitHTTP transport.
// Upload: standard Go net/http with DisableKeepAlives (fresh TCP per POST).
// Download: standard Go net/http with persistent chunked GET.
// If cfIP is non-empty, all TCP dials are pinned to cfIP:port (skipping DNS
// and the round-robin of bad CF edges), while TLS SNI stays the domain in
// serverAddr. Critical for Russia 2026 where CF DNS returns many blocked IPs.
//
// TLS handshake goes through refraction-networking/utls with a browser-
// identical ClientHello, not the Go stdlib (DPI audit P0.5, 2026-04).
// The fingerprint is fixed at construction so every POST in this session
// shares the same JA3 — rotating per request would itself be a signal and
// would also clash with the locked-per-user consistency posture.
//
// Optional lockedFP pins the fingerprint to a specific profile (for per-user
// JA3 consistency); without it, one is drawn from the pool at construction.
func NewSplitTransport(serverAddr string, token []byte, cfIP string, lockedFP ...*browser.Fingerprint) *SplitTransport {
	fpPool := browser.NewFingerprintPool()

	// Pin one fingerprint for the whole SplitTransport lifetime — real
	// users do not swap browsers mid-session, and rotating per-POST would
	// be detectable on its own.
	var fp *browser.Fingerprint
	if len(lockedFP) > 0 && lockedFP[0] != nil {
		fp = lockedFP[0]
	} else {
		fp = fpPool.Next()
	}

	// Custom dialer: apply a hard TCP connect timeout.
	// Without this, Go's net/http uses no default connect timeout (stuck
	// TCPs hang forever). cfIP pinning happens inside the uTLS dialer.
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// TLS config: ServerName must match the domain (cert matching) even
	// though TCP goes to cfIP. Extract domain from serverAddr.
	tlsServerName := serverAddr
	if h, _, err := net.SplitHostPort(serverAddr); err == nil {
		tlsServerName = h
	}

	// uTLS dial replaces stdlib TLSClientConfig: the Transport never sees
	// a crypto/tls handshake, and the ClientHello carries Chrome/Safari/
	// Firefox bytes (whichever fp picked) instead of Go's fingerprint.
	// nextProto pinned to http/1.1 — our Transport disables HTTP/2 anyway,
	// and the server is plain HTTP/1.1 behind nginx.
	dialTLS := buildUTLSDialTLS(cfIP, tlsServerName, fp, dialer, false, "http/1.1")

	// Upload client: fresh TCP connection per POST request, pinned to cfIP.
	// DisableKeepAlives prevents CF from killing idle connections (no keep-alive = no stale connections).
	ulClient := &stdhttp.Client{
		Transport: &stdhttp.Transport{
			DialTLSContext:      dialTLS,
			DisableCompression:  true,
			DisableKeepAlives:   true, // fresh TCP per request — immune to CF keep-alive kills
			ForceAttemptHTTP2:   false,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		// 8s timeout: TSPU 2026 freezes TCP after ~15-20KB downstream — stuck
		// POSTs give no signal except slow/no response. 8s is enough for a
		// healthy round-trip (Russia→Stockholm ~375ms) but kills frozen TCPs
		// fast so downstream streams don't hang 25s before failing over.
		Timeout: 8 * time.Second,
	}

	// Separate ConnManager for download stream — no timeout for persistent chunked GET.
	streamCM := NewConnManager(ConnManagerConfig{
		ServerAddr:    serverAddr,
		UseTLS:        true,
		NoTimeout:     true,
		FPPool:        fpPool,
		LockedProfile: fp, // keep download stream on the same uTLS profile as uploads
		MinRotation:   5 * time.Minute,
		MaxRotation:   10 * time.Minute,
	})

	// Download client: persistent chunked GET. Shares the same uTLS dialer
	// as uploads so download and upload TLS fingerprints stay identical.
	dlClient := &stdhttp.Client{
		Transport: &stdhttp.Transport{
			DialTLSContext:      dialTLS,
			DisableCompression:  true,
			ForceAttemptHTTP2:   false,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		Timeout: 0, // no timeout — persistent stream
	}

	t := &SplitTransport{
		uploadClient:   ulClient,
		streamMgr:      streamCM,
		downloadClient: dlClient,
		fpPool:         fpPool,
		serverAddr:     serverAddr,
		token:          token,
		urlPool:        browser.NewURLPool(),
		uploadSem:      make(chan struct{}, 32),
	}

	// V5: decoy generator is constructed but inert. The caller enables it
	// via StartDecoyTraffic() after a successful handshake so that a
	// failed session (handshake error, early abort) does not leak a live
	// goroutine that keeps hitting CF with fake GETs forever.
	baseURL := "https://" + serverAddr
	t.decoy = NewDecoyTraffic(baseURL, ulClient, fpPool)

	return t
}

// StartDecoyTraffic begins emitting fake GET requests to decoy paths. Call
// this once after a successful session handshake. Close() stops the generator.
// Calling more than once is a no-op.
func (t *SplitTransport) StartDecoyTraffic() {
	if t.decoy != nil {
		t.decoy.Start()
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
//
// D2 migration (2026-04): session token is packed into the body via BuildDataPayload
// instead of being sent as `Authorization: Bearer`. Wire format matches the new
// body-prefix dispatch path on the server (Phase B handleNewFormatPost).
func (t *SplitTransport) buildUploadRequest(data []byte) (*stdhttp.Request, error) {
	combined := browser.BuildDataPayload(t.token, data)
	payload := base64.RawURLEncoding.EncodeToString(combined)
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
	// D2: Authorization header removed — token travels inside the JSON body.
	req.Header.Set("X-Request-Id", fmt.Sprintf("%08x", browser.RandomUint32()))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Cache-Control", "no-cache")
	// 2026-05-02 wire-trigger followup NEW-2: Chrome-family UAs need the
	// sec-ch-ua header set to avoid a browser-class contradiction with the
	// JA4 fingerprint.
	browser.ApplyChromeCHUAForUA(req.Header, ua)
	return req, nil
}

// doUpload sends a single POST via standard Go net/http client.
func (t *SplitTransport) doUpload(data []byte) error {
	// Cap concurrent POSTs to prevent goroutine explosion under heavy browsing.
	// Each stream close fires a FIN POST — with DisableKeepAlives + slow CF RTT
	// these pile up into tens of thousands of stuck goroutines otherwise.
	select {
	case t.uploadSem <- struct{}{}:
		defer func() { <-t.uploadSem }()
	case <-time.After(2 * time.Second):
		return fmt.Errorf("split upload: semaphore timeout (too many concurrent POSTs)")
	}

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
	// Same concurrency cap as doUpload — CONNECTs share the pool of POSTs.
	select {
	case t.uploadSem <- struct{}{}:
		defer func() { <-t.uploadSem }()
	case <-time.After(2 * time.Second):
		return nil, fmt.Errorf("split sync upload: semaphore timeout")
	}

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

// OpenDownloadStream opens a persistent connection for receiving data from the server.
// Server responds with chunked Transfer-Encoding, pushing encrypted frames.
//
// D2 migration (2026-04): previously a bare GET with `Authorization: Bearer`.
// Now a POST whose JSON body carries [session token][encrypted FlagStreamOpen chunk]
// via BuildDataPayload, matching the body-prefix dispatch path on the server
// (handleDownloadStreamV2 in Phase B). The session is required to produce the
// encrypted FlagStreamOpen chunk — callers must pass the active session.
//
// Uses standard Go net/http client — tls-client (bogdanfinn) buffers response
// bodies internally, breaking chunked streaming through CF CDN.
func (t *SplitTransport) OpenDownloadStream(session *core.Session) (io.ReadCloser, error) {
	if session == nil {
		return nil, fmt.Errorf("split download open: nil session")
	}

	// Build an encrypted FlagStreamOpen chunk — tells the server this POST is
	// the streaming download channel, not a regular upload.
	streamOpenChunk := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     core.FlagStreamOpen,
	}
	encrypted, err := session.EncryptChunk(streamOpenChunk)
	if err != nil {
		return nil, fmt.Errorf("split download open: encrypt stream-open chunk: %w", err)
	}
	combined := browser.BuildDataPayload(t.token, encrypted)
	payload := base64.RawURLEncoding.EncodeToString(combined)

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
	url := baseURL + t.urlPool.NextDownloadPath()

	req, err := stdhttp.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	ua := t.streamMgr.ActiveFingerprint().UserAgent()
	// D2: Authorization header removed — token packed in body.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	browser.ApplyChromeCHUAForUA(req.Header, ua)

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
//
// Note on TSPU (Russia DPI, 2026): the persistent GET is one long TCP that
// eventually hits the 15-20KB freeze cliff. We previously tried preemptive
// rotation here but the server returns HTTP 404 on repeat opens under the
// same session. So we let the GET live its natural life — when TSPU freezes
// it, the read timeout fires, StartReader exits, poll workers take over via
// streamReaderLoop's downloadActive=false signal. POST responses also carry
// downstream data (onResponse callback), so downstream keeps flowing.
func (t *SplitTransport) StartReader(ctx context.Context, cl *Client) error {
	// D2: OpenDownloadStream now needs the session to encrypt the FlagStreamOpen
	// chunk that rides in the POST body (was a bare GET with Bearer header).
	session := cl.Session()
	if session == nil {
		return fmt.Errorf("open download stream: no session")
	}
	rc, err := t.OpenDownloadStream(session)
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

	// Read timeout: TSPU freezes TCPs after ~15-20KB with no signal. 20s is
	// short enough to escape a frozen GET fast (so poll workers take over)
	// while staying above server keepalive (25s is too close — use server
	// keepalive tuned to 15s to pair with this).
	const readTimeout = 20 * time.Second
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

		// M1 (2026-06-11): downlink anti-replay before routing bytes into a
		// stream (SplitHTTP download reader). A replayed authentic chunk would
		// duplicate bytes in the proxied TCP stream — drop it.
		if !session.AcceptSeqNum(chunk.SeqNum) {
			Stats.DownlinkReplayDroppedTotal.Add(1)
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
	if t.decoy != nil {
		t.decoy.Stop()
	}
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

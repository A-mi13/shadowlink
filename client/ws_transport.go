package client

import (
	"context"
	stdtls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// WebSocketTransport provides full-duplex bidirectional relay over WebSocket.
// After initial HTTP handshake, upgrades to WS for real-time data transfer.
// Eliminates polling pattern — data flows instantly in both directions.
type WebSocketTransport struct {
	baseURL     string
	wsURL       string
	serverAddr  string
	sniHost     string // override TLS ServerName (for origin IP with domain SNI)
	cfIP        string // specific CF edge IP (TCP dial override, domain stays as TLS SNI)
	useTLS      bool
	skipVerify  bool
	urlPool     *browser.URLPool
	connManager *ConnManager // for initial HTTP handshake
	pd          *browser.PayloadDistribution

	mu          sync.Mutex
	writeMu     sync.Mutex // only used by SendChunk (legacy single-WS fallback, not ws_pool hot path)
	conn        *websocket.Conn
	asyncWriter *core.WSAsyncWriter // async egress queue, used by WriteMessage (ws_pool hot path)

	// Per-frame write deadline. Zero → WSAsyncWriter default (30s). For viaCF
	// mode this should be 5-8s: CF-side stalls propagate to us as TCP
	// backpressure and the default 30s means the slot freezes for 30s before
	// the pool can route around the bad edge. Cross-check 2026-04-15 H6.
	writeTimeout time.Duration
}

// NewWebSocketTransport creates a transport that uses WebSocket for data relay.
// Initial handshake is done via HTTP, then upgraded to WS.
func NewWebSocketTransport(serverAddr string, useTLS bool, skipVerify bool, lockedFP ...*browser.Fingerprint) *WebSocketTransport {
	scheme := "http"
	wsScheme := "ws"
	if useTLS {
		scheme = "https"
		wsScheme = "wss"
	}

	fpPool := browser.NewFingerprintPool()
	var locked *browser.Fingerprint
	if len(lockedFP) > 0 && lockedFP[0] != nil {
		locked = lockedFP[0]
	}
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr:    serverAddr,
		UseTLS:        useTLS,
		SkipVerify:    skipVerify,
		FPPool:        fpPool,
		LockedProfile: locked,
		MinRotation:   5 * time.Minute,
		MaxRotation:   10 * time.Minute,
	})

	return &WebSocketTransport{
		baseURL:     fmt.Sprintf("%s://%s", scheme, serverAddr),
		wsURL:       fmt.Sprintf("%s://%s/ws", wsScheme, serverAddr),
		serverAddr:  serverAddr,
		useTLS:      useTLS,
		skipVerify:  skipVerify,
		urlPool:     browser.NewURLPool(),
		connManager: cm,
		pd:          browser.NewPayloadDistribution(),
	}
}

func (t *WebSocketTransport) Name() string { return "websocket" }

// SetSNIHost overrides TLS ServerName for origin IP with domain SNI.
func (t *WebSocketTransport) SetSNIHost(host string) { t.sniHost = host }

// SetCFIP sets a specific CF edge IP (bypass DNS, keep domain as TLS SNI).
func (t *WebSocketTransport) SetCFIP(ip string) { t.cfIP = ip }

// SetWriteTimeout overrides the per-frame write deadline used by the async
// writer. Must be called before UpgradeToWS. Zero keeps the WSAsyncWriter
// default (30s). For viaCF mode pass 5-8s to surface CF-side backpressure
// quickly instead of letting a stalled slot block traffic for 30s.
func (t *WebSocketTransport) SetWriteTimeout(d time.Duration) { t.writeTimeout = d }

// SendHandshake performs initial HTTP handshake (same as DirectTransport).
// After this, call UpgradeToWS() to switch to WebSocket.
func (t *WebSocketTransport) SendHandshake(ctx context.Context, hello *core.ClientHello) ([]byte, error) {
	// Same handshake as DirectTransport — via HTTP POST
	payload := make([]byte, 0, len(hello.EphemeralPub)+len(hello.EncryptedClientID))
	payload = append(payload, hello.EphemeralPub...)
	payload = append(payload, hello.EncryptedClientID...)

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

	// Use standard HTTP for handshake (before WS upgrade)
	httpClient := &http.Client{Timeout: 15 * time.Second}
	url := t.baseURL + t.urlPool.NextUploadPath()
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(io.Reader(newBytesReader(body)))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", t.connManager.ActiveFingerprint().UserAgent())
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("handshake failed: HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

// utlsProfileForFingerprint maps our browser fingerprint to a uTLS ClientHelloID.
// This ensures the WebSocket TLS handshake has the same JA3 fingerprint as the
// HTTP handshake (via tls-client). Without this, DPI sees "Chrome HTTP → Go WebSocket".
func utlsProfileForFingerprint(fp *browser.Fingerprint) utls.ClientHelloID {
	switch fp.Name() {
	case browser.ProfileChrome:
		return utls.HelloChrome_133
	case browser.ProfileSafari:
		return utls.HelloSafari_16_0
	case browser.ProfileFirefox:
		return utls.HelloFirefox_Auto // latest available (120)
	default:
		return utls.HelloChrome_133
	}
}

// WarmupRequests sends 2-3 GET requests to decoy pages before WebSocket upgrade.
// Mimics real browser behavior: user loads page, browses, THEN opens WebSocket.
// Without this, DPI sees: TLS connect → instant WS upgrade (suspicious).
// With this: TLS → GET / → GET /about → GET /api/config → WS upgrade (normal).
func (t *WebSocketTransport) WarmupRequests() {
	ua := t.connManager.ActiveFingerprint().UserAgent()

	// Decoy page paths that a real SPA would load
	paths := []string{
		"/",
		"/about",
		"/api/v1/config",
	}

	// Pick 2-3 random paths
	count := 2 + int(time.Now().UnixNano()%2) // 2 or 3
	if count > len(paths) {
		count = len(paths)
	}

	for i := 0; i < count; i++ {
		url := t.baseURL + paths[i]
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		// Read and discard body (like a real browser)
		io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		// Random delay between requests (200-600ms, like real browsing)
		delay := 200 + time.Duration(time.Now().UnixNano()%400)*time.Millisecond
		time.Sleep(delay)
	}
}

// UpgradeToWS establishes WebSocket connection with session token.
// Uses uTLS for TLS handshake to match browser fingerprint (fixes detection via JA3 mismatch).
func (t *WebSocketTransport) UpgradeToWS(token []byte) error {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(token))
	header.Set("User-Agent", t.connManager.ActiveFingerprint().UserAgent())

	fp := t.connManager.ActiveFingerprint()
	skipVerify := t.skipVerify
	serverAddr := t.serverAddr

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		WriteBufferSize:  65536,
		ReadBufferSize:   65536,
	}

	if t.useTLS {
		// Use uTLS for browser-identical TLS fingerprint on WebSocket connection.
		// gorilla/websocket's NetDialTLSContext bypasses crypto/tls entirely.
		helloID := utlsProfileForFingerprint(fp)
		originAddr := serverAddr // actual IP:port to connect to
		dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			if host == "" {
				host = addr
			}
			// SNI trick: use domain as TLS ServerName, but connect to origin IP.
			// addr comes from URL (domain → CF IP via DNS). Override with origin IP.
			if t.sniHost != "" {
				host = t.sniHost
				addr = originAddr // connect to origin IP, not DNS-resolved CF IP
			}
			// CF IP override: connect to specific CF edge IP, keep domain as TLS SNI.
			// This bypasses DNS resolution to pick a CF edge that doesn't aggressively kill WS.
			if t.cfIP != "" && t.sniHost == "" {
				// host stays as domain from URL (TLS SNI = CF domain)
				if port == "" {
					port = "443"
				}
				addr = net.JoinHostPort(t.cfIP, port)
			}

			tcpConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			uConfig := &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: skipVerify,
			}

			// Get browser spec, then patch ALPN to http/1.1 only.
			// WebSocket requires HTTP/1.1 — Chrome h2 ALPN makes nginx respond with HTTP/2 SETTINGS.
			spec, specErr := utls.UTLSIdToSpec(helloID)
			if specErr != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("uTLS spec: %w", specErr)
			}
			for i, ext := range spec.Extensions {
				switch v := ext.(type) {
				case *utls.ALPNExtension:
					v.AlpnProtocols = []string{"http/1.1"}
					spec.Extensions[i] = v
				}
			}

			tlsConn := utls.UClient(tcpConn, uConfig, utls.HelloCustom)
			if err := tlsConn.ApplyPreset(&spec); err != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("uTLS apply: %w", err)
			}
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("uTLS handshake: %w", err)
			}
			return tlsConn, nil
		}
	} else {
		dialer.TLSClientConfig = &stdtls.Config{InsecureSkipVerify: skipVerify}
	}

	_ = serverAddr // used for logging if needed

	// SNI trick: use domain URL so gorilla sets correct Host header.
	// gorilla/websocket ignores header.Set("Host") — it takes Host from the URL.
	// We use domain URL (wss://domain/ws) but NetDialTLSContext connects to origin IP.
	dialURL := t.wsURL
	if t.sniHost != "" {
		wsScheme := "ws"
		if t.useTLS {
			wsScheme = "wss"
		}
		dialURL = fmt.Sprintf("%s://%s/ws", wsScheme, t.sniHost)
	}

	conn, _, err := dialer.Dial(dialURL, header)
	if err != nil {
		return fmt.Errorf("ws upgrade: %w", err)
	}

	// Async writer with priority channels: CONNECT/FIN/keepalive use the
	// control channel (drained first), data relay uses the data channel.
	// This eliminates the writeMu bottleneck where 100 data goroutines
	// starved CONNECT requests for 5+ seconds.
	w := core.NewWSAsyncWriter(conn, 256) // 256 data frames, 64 control frames

	// Apply per-frame write deadline. Default (0) keeps WSAsyncWriter's own
	// default of 30s; viaCF mode sets this to 5-8s via SetWriteTimeout so a
	// CF-side stall kills this slot quickly and the pool can route around
	// the bad edge instead of freezing for 30s.
	if t.writeTimeout > 0 {
		w.SetWriteTimeout(t.writeTimeout)
	}

	// Custom ping handler: route pong through our async writer to avoid
	// gorilla's WriteControl concurrent write conflict. Without this, the
	// Run() goroutine's continuous WriteMessage calls set c.isWriting=true
	// inside gorilla, causing the default pong-via-WriteControl to fail
	// with errWriteTimeout. Failed pongs → server read deadline (60s)
	// expires → all WS connections die simultaneously.
	conn.SetPingHandler(func(appData string) error {
		return w.EnqueueControl(websocket.PongMessage, []byte(appData))
	})

	go func() {
		if err := w.Run(); err != nil {
			// Warn-level (was Debug) so writer-triggered slot deaths are
			// distinguishable from reader-triggered ones in the field logs.
			// Cross-check 2026-04-15 H6: the local write deadline is the
			// real first domino under CF backpressure — we need to see it.
			Stats.WriterExits.Add(1)
			slog.Warn("ws async writer exit", "err", err, "writeTimeout", t.writeTimeout)
			// Close the conn so the reader goroutine gets an error and exits
			// immediately instead of waiting up to 60s for the server's read
			// deadline to expire (zombie connection prevention).
			conn.Close()
		}
	}()

	t.mu.Lock()
	t.conn = conn
	t.asyncWriter = w
	t.mu.Unlock()

	return nil
}

// SendChunk sends an encrypted chunk over WebSocket and reads response.
// Small chunks (< 80 bytes) are padded to a distribution-realistic size to prevent
// length-based fingerprinting of control messages (FlagConnect, FlagFin).
func (t *WebSocketTransport) SendChunk(ctx context.Context, data []byte, sessionToken []byte, seqNum uint32) ([]byte, error) {
	t.mu.Lock()
	conn := t.conn
	w := t.asyncWriter
	t.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("websocket not connected")
	}
	// Guard: SendChunk writes directly to conn via writeMu. If the async
	// writer is active, its Run() goroutine also writes to conn — concurrent
	// writes corrupt WebSocket frames (RSV bits, continuation after FIN).
	if w != nil {
		return nil, fmt.Errorf("SendChunk unavailable in async mode — use WriteMessage")
	}

	// Pad small control chunks to defeat length-based DPI fingerprinting.
	// Chunks under 80 bytes are typically FlagConnect or FlagFin — pad to a
	// distribution-realistic upload size.
	if len(data) < 80 {
		data = browser.PadToSize(data, t.pd.UploadSize())
	}

	// MED-8 fix: serialize writes via writeMu (gorilla requires single writer)
	t.writeMu.Lock()
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	writeErr := conn.WriteMessage(websocket.BinaryMessage, data)
	t.writeMu.Unlock()
	if writeErr != nil {
		return nil, fmt.Errorf("ws write: %w", writeErr)
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, respData, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("ws read: %w", err)
	}

	return respData, nil
}

// ReadMessage reads the next message from the WebSocket (for server-initiated data).
func (t *WebSocketTransport) ReadMessage(timeout time.Duration) ([]byte, error) {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("websocket not connected")
	}

	if timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(timeout))
	} else {
		conn.SetReadDeadline(time.Time{}) // no deadline — block forever
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// WriteMessage enqueues a data frame (low priority) for writing.
// Data frames are written after all pending control frames are drained.
// Returns ErrWSWriterClosed if the async writer has stopped.
func (t *WebSocketTransport) WriteMessage(data []byte) error {
	t.mu.Lock()
	w := t.asyncWriter
	t.mu.Unlock()

	if w == nil {
		return fmt.Errorf("websocket not connected")
	}
	return w.Enqueue(websocket.BinaryMessage, data)
}

// WriteControlMessage enqueues a control frame (high priority) for writing.
// Control frames (CONNECT, FIN, keepalive) are always drained before data
// frames, preventing latency-sensitive operations from being starved by
// 100+ concurrent data relay goroutines.
func (t *WebSocketTransport) WriteControlMessage(data []byte) error {
	t.mu.Lock()
	w := t.asyncWriter
	t.mu.Unlock()

	if w == nil {
		return fmt.Errorf("websocket not connected")
	}
	return w.EnqueueControl(websocket.BinaryMessage, data)
}

// StartReader runs the background WS message reader.
// Dispatches decrypted chunks to the client's stream router.
// Returns on WS error (caller should reconnect).
func (t *WebSocketTransport) StartReader(ctx context.Context, cl *Client) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("ws reader panic: %v", r)
		}
	}()
	msgCount := 0
	errCount := 0
	slog.Info("WS StartReader started")
	for {
		select {
		case <-ctx.Done():
			slog.Info("WS StartReader stopped", "messages", msgCount, "errors", errCount)
			return ctx.Err()
		default:
		}

		// Use a 30s read deadline so we periodically check ctx.Done()
		// instead of blocking forever in ReadMessage.
		data, err := t.ReadMessage(30 * time.Second)
		if err != nil {
			// On timeout, check if context was cancelled — if so, return cleanly
			if ctx.Err() != nil {
				slog.Info("WS StartReader context done", "messages", msgCount, "errors", errCount)
				return ctx.Err()
			}
			// Check if this is a timeout — retry the read
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				continue
			}
			slog.Warn("WS StartReader fatal error", "err", err, "messages", msgCount)
			return fmt.Errorf("ws read: %w", err)
		}

		session := cl.Session()
		if session == nil {
			continue
		}

		chunk, err := session.DecryptChunkSafe(data)
		if err != nil {
			errCount++
			if errCount <= 3 {
				slog.Debug("WS decrypt error", "err", err, "dataLen", len(data))
			}
			continue
		}

		if len(chunk.Payload) < 2 {
			continue
		}

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		if chunk.Flags == core.FlagUDP {
			cl.RouteToStream(streamID, chunk.Payload)
		} else {
			cl.RouteToStream(streamID, chunk.Payload[2:])
		}
	}
}

func (t *WebSocketTransport) Close() error {
	t.mu.Lock()
	conn := t.conn
	t.conn = nil
	w := t.asyncWriter
	t.asyncWriter = nil
	t.mu.Unlock()

	if w != nil {
		w.Close()      // signal Run() to stop
		<-w.RunDone()  // wait for Run() to finish draining — prevents concurrent write with conn.Close()
	}
	if conn != nil {
		conn.Close()
	}
	return t.connManager.Close()
}

// bytesReader wraps []byte as io.Reader
type bytesReader struct{ data []byte; pos int }

func newBytesReader(data []byte) *bytesReader { return &bytesReader{data: data} }
func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) { return 0, io.EOF }
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

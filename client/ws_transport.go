package client

import (
	"context"
	stdtls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	useTLS      bool
	skipVerify  bool
	urlPool     *browser.URLPool
	connManager *ConnManager // for initial HTTP handshake
	pd          *browser.PayloadDistribution

	mu      sync.Mutex
	writeMu sync.Mutex     // serializes WS writes (gorilla requires single writer)
	conn    *websocket.Conn
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
		dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			if host == "" {
				host = addr
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

	conn, _, err := dialer.Dial(t.wsURL, header)
	if err != nil {
		return fmt.Errorf("ws upgrade: %w", err)
	}

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()

	return nil
}

// SendChunk sends an encrypted chunk over WebSocket and reads response.
// Small chunks (< 80 bytes) are padded to a distribution-realistic size to prevent
// length-based fingerprinting of control messages (FlagConnect, FlagFin).
func (t *WebSocketTransport) SendChunk(ctx context.Context, data []byte, sessionToken []byte, seqNum uint32) ([]byte, error) {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("websocket not connected")
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

// WriteMessage writes a message to the WebSocket (thread-safe).
func (t *WebSocketTransport) WriteMessage(data []byte) error {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("websocket not connected")
	}

	// Serialize all writes — gorilla/websocket requires single writer
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// StartReader runs the background WS message reader.
// Dispatches decrypted chunks to the client's stream router.
// Returns on WS error (caller should reconnect).
func (t *WebSocketTransport) StartReader(ctx context.Context, cl *Client) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Use a 30s read deadline so we periodically check ctx.Done()
		// instead of blocking forever in ReadMessage.
		data, err := t.ReadMessage(30 * time.Second)
		if err != nil {
			// On timeout, check if context was cancelled — if so, return cleanly
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Check if this is a timeout — retry the read
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("ws read: %w", err)
		}

		session := cl.Session()
		if session == nil {
			continue
		}

		chunk, err := session.DecryptChunkSafe(data)
		if err != nil {
			continue
		}

		if len(chunk.Payload) < 2 {
			continue
		}

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
	t.mu.Unlock()

	if conn != nil {
		// C2 fix: don't call WriteMessage here — it races with goroutine writes.
		// Just close the conn; the write goroutine will get an error on next write.
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

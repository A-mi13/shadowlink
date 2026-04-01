package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// Handler processes authenticated ShadowLink requests.
// Unauthenticated requests fall through to the decoy site.
type Handler struct {
	serverKey   *core.KeyPair
	sessions    *core.SessionManager
	decoy       *DecoyHandler
	config      Config
	metrics     *Metrics
	rateLimiter *RateLimiter
	clientAuth  *ClientAuth
	udpRelay    *UDPRelay

	// For each session, incoming data is buffered and can be read by the tunnel.
	tunnels   map[uint32]*Tunnel
	tunnelsMu sync.RWMutex
}

// StreamConn represents one multiplexed stream within a tunnel.
type StreamConn struct {
	StreamID   uint16
	TargetConn net.Conn
}

// Tunnel represents one client's bidirectional data channel with multiplexed streams.
type Tunnel struct {
	SessionID uint32
	ClientID  string // "userID:deviceID" — used for OnSessionDestroyed cleanup
	Incoming  chan []byte
	Outgoing  chan []byte
	done      chan struct{} // closed to signal all relays to stop
	closeOnce sync.Once

	mu      sync.Mutex
	streams map[uint16]*StreamConn

	targetConn net.Conn
	connected  bool
}

// closeTunnel safely closes channels and signals goroutines (idempotent).
func (t *Tunnel) closeTunnel() {
	t.closeOnce.Do(func() {
		close(t.done)
		close(t.Incoming)
		close(t.Outgoing)
	})
}

// NewHandler creates a ShadowLink request handler.
func NewHandler(serverKey *core.KeyPair, config Config, decoyDir string) *Handler {
	return &Handler{
		serverKey:   serverKey,
		sessions:    core.NewSessionManager(config.SessionTimeout),
		decoy:       NewDecoyHandler(decoyDir),
		config:      config,
		metrics:     NewMetrics(),
		rateLimiter: NewRateLimiter(50, time.Minute), // 50/min/IP — each SOCKS5 CONNECT = new session
		clientAuth:  NewClientAuth(config.AuthorizedClients),
		udpRelay:    NewUDPRelay(60 * time.Second),
		tunnels:     make(map[uint32]*Tunnel),
	}
}

// Metrics returns the handler's metrics tracker.
func (h *Handler) Metrics() *Metrics {
	return h.metrics
}

// setStandardHeaders sets response headers identical to the decoy handler.
// F2 fix: all responses (data, handshake, keepalive, control) must have the same
// headers as decoy to prevent oracle-based detection.
func setStandardHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "nginx/1.27.3")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// buildResponse wraps encrypted chunk in JSON. Uses inflated response if configured.
func (h *Handler) buildResponse(encrypted []byte, seqNum uint32) ([]byte, error) {
	if h.config.UseInflatedResponses {
		return browser.BuildInflatedDownloadResponse(encrypted, seqNum)
	}
	return browser.BuildDownloadResponse(encrypted, seqNum)
}

// ServeHTTP routes requests: authenticated → ShadowLink, unauthenticated → decoy.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// WebSocket upgrade for full-duplex relay (Phase 1b)
	if r.Header.Get("Upgrade") == "websocket" {
		h.handleWebSocket(w, r)
		return
	}

	// Only POST with JSON content type could be ShadowLink
	ct := r.Header.Get("Content-Type")
	if r.Method != "POST" || ct != "application/json" {
		// MED-3 fix: don't log headers (may contain Bearer token)
	slog.Info("decoy fallback", "method", r.Method, "path", r.URL.Path)
		h.decoy.ServeHTTP(w, r)
		return
	}
	slog.Info("ShadowLink request received", "path", r.URL.Path, "content-type", ct)

	// Try to extract session token
	_, tokenErr := browser.ExtractSessionToken(r)

	// Read body (limit to chunk size + overhead)
	// HIGH-3 fix: limit body to chunk size + JSON envelope overhead (not 2x chunk)
	body, err := browser.ReadBodyLimited(r.Body, int64(h.config.ChunkSize+1024))
	if err != nil {
		h.decoy.ServeHTTP(w, r)
		return
	}

	// C3 fix: cover traffic is now indistinguishable from data (encrypted FlagPadding).
	// Server processes it as a normal chunk and responds with FlagPadding → standard response.
	// No special IsCoverTraffic check needed.

	// Try to parse as ShadowLink upload
	encryptedChunk, err := browser.ParseUploadRequest(body)
	if err != nil {
		// Not a valid ShadowLink request → decoy
		h.decoy.ServeHTTP(w, r)
		return
	}

	// Check if this is a handshake (no existing session token) or data
	if tokenErr != nil {
		// No valid session token → try handshake
		h.handleHandshake(w, r, encryptedChunk)
		return
	}

	// Has session token → data transfer
	h.handleData(w, r, encryptedChunk)
}

// handleHandshake processes a ClientHello and creates a new session.
func (h *Handler) handleHandshake(w http.ResponseWriter, r *http.Request, encryptedPayload []byte) {
	// Rate limit per IP (M6: behindProxy controls XFF trust)
	clientIP := ClientIPFromRequest(r, h.config.BehindProxy)
	if !h.rateLimiter.Allow(clientIP) {
		slog.Warn("rate limited handshake", "ip", clientIP)
		h.decoy.ServeHTTP(w, r) // look like decoy, don't reveal rate limiting
		return
	}

	// Backpressure check — I6 fix: return decoy, not 503 (don't reveal capacity limits)
	_, rejectNew := h.metrics.BackpressureCheck(h.config.MaxConnsPerClient)
	if rejectNew {
		h.metrics.RejectedOverload.Add(1)
		slog.Warn("backpressure: rejecting new connection (high memory)")
		h.decoy.ServeHTTP(w, httpPlaceholderRequest())
		return
	}

	// Check client limit — I6 fix: return decoy, not 503
	if h.sessions.Count() >= h.config.MaxClients {
		h.metrics.RejectedOverload.Add(1)
		slog.Warn("max clients reached, rejecting handshake")
		h.decoy.ServeHTTP(w, httpPlaceholderRequest())
		return
	}

	// Decode ClientHello from the encrypted payload
	// In Browser Skin, the "encrypted chunk" for handshake IS the ClientHello data:
	// First 32 bytes = ephemeral pub, rest = encrypted client_id
	if len(encryptedPayload) < 33 {
		h.decoy.ServeHTTP(w, httpPlaceholderRequest())
		return
	}

	clientHello := &core.ClientHello{
		EphemeralPub:      encryptedPayload[:32],
		EncryptedClientID: encryptedPayload[32:],
	}

	serverHello, session, clientID, err := core.HandleClientHello(
		clientHello,
		h.serverKey,
		uint8(h.config.MaxConnsPerClient),
		uint16(h.config.ChunkSize),
		h.sessions,
	)
	if err != nil {
		h.metrics.HandshakesFailed.Add(1)
		slog.Debug("handshake failed", "error", err)
		// Failed handshake → look like decoy (don't reveal we're a proxy)
		h.decoy.ServeHTTP(w, httpPlaceholderRequest())
		return
	}

	// Check client authorization BEFORE creating tunnel (W7 fix: prevent tunnel leak)
	if !h.clientAuth.IsAuthorized(string(clientID)) {
		h.metrics.HandshakesFailed.Add(1)
		h.sessions.Remove(session.ID)
		slog.Warn("unauthorized handshake rejected")
		h.decoy.ServeHTTP(w, httpPlaceholderRequest())
		return
	}

	// Check per-user device limit (Task 4: Management API push model)
	if !h.clientAuth.CheckDeviceLimit(string(clientID)) {
		h.metrics.HandshakesFailed.Add(1)
		h.sessions.Remove(session.ID)
		slog.Warn("device limit exceeded")
		h.decoy.ServeHTTP(w, httpPlaceholderRequest())
		return
	}

	// Create tunnel for this session (after auth + device limit check)
	tunnel := &Tunnel{
		SessionID: session.ID,
		ClientID:  string(clientID),
		Incoming:  make(chan []byte, 64),
		Outgoing:  make(chan []byte, 64),
		done:      make(chan struct{}),
	}
	h.tunnelsMu.Lock()
	h.tunnels[session.ID] = tunnel
	h.tunnelsMu.Unlock()

	// Track session for device limit enforcement
	h.clientAuth.OnSessionCreated(string(clientID), session.ID)

	h.metrics.HandshakesTotal.Add(1)
	h.metrics.ActiveClients.Add(1)
	// H3 fix: don't log full session ID or client_id (forensic evidence)
	slog.Info("new session created")

	// Build response with ServerHello data
	responsePayload := encodeServerHello(serverHello)
	respBody, err := browser.BuildDownloadResponse(responsePayload, 0)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

// handleData processes an encrypted data chunk from an established session.
func (h *Handler) handleData(w http.ResponseWriter, r *http.Request, encryptedChunk []byte) {
	tokenBytes, _ := browser.ExtractSessionToken(r)

	// Find session by trying to decrypt the chunk with known sessions
	// The session token in the header helps us identify which session
	session := h.findSession(tokenBytes)
	if session == nil {
		h.decoy.ServeHTTP(w, r)
		return
	}

	// H1 fix: use safe method that holds session lock during key access
	chunk, err := session.DecryptChunkSafe(encryptedChunk)
	if err != nil {
		slog.Debug("chunk decryption failed")
		h.decoy.ServeHTTP(w, r)
		return
	}

	// Validate seq_num (replay protection)
	if !session.AcceptSeqNum(chunk.SeqNum) {
		slog.Debug("rejected seq_num")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	// Process by flag type
	switch chunk.Flags {
	case core.FlagData:
		h.handleDataChunk(w, session, chunk)
	case core.FlagPadding:
		// C3 fix: cover traffic is encrypted padding — respond with matching padding
		h.handleKeepalive(w, session) // same ACK response as keepalive
	case core.FlagKeepalive:
		h.handleKeepalive(w, session)
	case core.FlagConnect:
		h.handleConnect(w, session, chunk)
	case core.FlagUDP:
		h.handleUDPData(w, session, chunk)
	case core.FlagControl:
		h.handleControl(w, session, chunk)
	case core.FlagFin:
		h.handleFin(session)
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	default:
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}
}

func (h *Handler) handleDataChunk(w http.ResponseWriter, session *core.Session, chunk *core.Chunk) {
	h.tunnelsMu.RLock()
	tunnel, ok := h.tunnels[session.ID]
	h.tunnelsMu.RUnlock()

	h.metrics.ChunksReceived.Add(1)
	h.metrics.BytesReceived.Add(uint64(len(chunk.Payload)))

	if ok && len(chunk.Payload) > 0 {
		tunnel.mu.Lock()
		hasStreams := len(tunnel.streams) > 0
		legacyConn := tunnel.targetConn
		tunnel.mu.Unlock()

		if hasStreams {
			// Multiplexed mode: parse StreamID from payload
			streamID, data := core.ParseStreamID(chunk.Payload)
			tunnel.mu.Lock()
			stream := tunnel.streams[streamID]
			tunnel.mu.Unlock()
			if stream != nil && stream.TargetConn != nil && len(data) > 0 {
				stream.TargetConn.Write(data)
			}
		} else if legacyConn != nil {
			// Legacy mode: payload is raw data, no StreamID
			legacyConn.Write(chunk.Payload)
		} else {
			select {
			case tunnel.Incoming <- chunk.Payload:
			default:
			}
		}
	}

	// Collect outgoing data — accumulate pooled slices, free them after encrypt.
	var responsePayload []byte
	var pooledChunks [][]byte
	if ok {
		tunnel.mu.Lock()
		hasAnyConn := len(tunnel.streams) > 0 || tunnel.connected
		tunnel.mu.Unlock()

		waitTime := time.Duration(20+rand.IntN(50)) * time.Millisecond
		if hasAnyConn {
			waitTime = 2 * time.Second
		}

		// HIGH-1 fix: replace time.After with NewTimer to prevent timer leak
		timer := time.NewTimer(waitTime)
		select {
		case data := <-tunnel.Outgoing:
			timer.Stop()
			pooledChunks = append(pooledChunks, data)
			responsePayload = append(responsePayload, data...)
			draining := true
			for draining {
				select {
				case more := <-tunnel.Outgoing:
					pooledChunks = append(pooledChunks, more)
					responsePayload = append(responsePayload, more...)
				default:
					draining = false
				}
			}
		case <-timer.C:
		}
	}

	// Build encrypted response
	respChunk := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     core.FlagData,
		Payload:   responsePayload,
	}

	encrypted, err := session.EncryptChunk(respChunk)
	// Return pooled chunks now that payload has been encrypted.
	for _, pc := range pooledChunks {
		core.PutBuffer(pc)
	}
	if err != nil {
		w.WriteHeader(500)
		return
	}

	h.metrics.ChunksSent.Add(1)
	h.metrics.BytesSent.Add(uint64(len(responsePayload)))

	respBody, _ := h.buildResponse(encrypted, respChunk.SeqNum)
	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

func (h *Handler) handleKeepalive(w http.ResponseWriter, session *core.Session) {
	// Respond with ACK chunk
	ackChunk := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     core.FlagAck,
	}
	encrypted, _ := session.EncryptChunk(ackChunk)
	respBody, _ := h.buildResponse(encrypted, ackChunk.SeqNum)

	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

// isBlockedDomain reports whether host matches any entry in blockDomains.
// Each entry may be an exact domain ("illegal.com") or wildcard ("*.illegal.org").
// Matching is case-insensitive; exact entries also match all subdomains.
// D-1 fix: if host is an IP, performs reverse DNS lookup and checks those names too.
func isBlockedDomain(host string, blockDomains []string) bool {
	if matchesBlockList(host, blockDomains) {
		return true
	}

	// D-1: if host is an IP, try reverse DNS to catch IP-based bypass
	// MED-2 fix: 2s timeout to prevent goroutine starvation on slow DNS
	if ip := net.ParseIP(host); ip != nil {
		lookupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		names, err := net.DefaultResolver.LookupAddr(lookupCtx, host)
		if err == nil {
			for _, name := range names {
				name = strings.TrimSuffix(name, ".") // remove trailing dot from PTR
				if matchesBlockList(name, blockDomains) {
					return true
				}
			}
		}
	}
	return false
}

// matchesBlockList checks a single hostname against the block list patterns.
func matchesBlockList(host string, blockDomains []string) bool {
	host = strings.ToLower(host)
	for _, pattern := range blockDomains {
		p := strings.ToLower(pattern)
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".illegal.org"
			if strings.HasSuffix(host, suffix) {
				return true
			}
		} else {
			if host == p || strings.HasSuffix(host, "."+p) {
				return true
			}
		}
	}
	return false
}

// handleConnect opens a TCP connection to the target specified in the chunk payload.
// Supports multiplexed streams via StreamID in payload.
func (h *Handler) handleConnect(w http.ResponseWriter, session *core.Session, chunk *core.Chunk) {
	// Parse StreamID + target from payload
	streamID, targetBytes := core.ParseStreamID(chunk.Payload)
	target := string(targetBytes)
	if target == "" {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	h.tunnelsMu.RLock()
	tunnel, ok := h.tunnels[session.ID]
	h.tunnelsMu.RUnlock()
	if !ok {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	// Check server-side block list before dialing
	if len(h.config.BlockDomains) > 0 {
		blockHost := target
		if bh, _, err := net.SplitHostPort(target); err == nil {
			blockHost = bh
		}
		if isBlockedDomain(blockHost, h.config.BlockDomains) {
			slog.Debug("CONNECT blocked by server block-list", "target", target)
			errChunk := core.NewDataChunk(session.ID, session.NextSeqNum(), []byte("CONNECT_FAIL"))
			encrypted, _ := session.EncryptChunk(errChunk)
			respBody, _ := h.buildResponse(encrypted, errChunk.SeqNum)
			setStandardHeaders(w)
			w.WriteHeader(200)
			w.Write(respBody)
			return
		}
	}

	conn, err := SafeDial(context.Background(), target, 10*time.Second)
	if err != nil {
		errChunk := core.NewDataChunk(session.ID, session.NextSeqNum(), []byte("CONNECT_FAIL"))
		encrypted, _ := session.EncryptChunk(errChunk)
		respBody, _ := h.buildResponse(encrypted, errChunk.SeqNum)
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write(respBody)
		return
	}

	// HIGH-8 fix: check stream count limit before adding
	tunnel.mu.Lock()
	if tunnel.streams == nil {
		tunnel.streams = make(map[uint16]*StreamConn)
	}
	if len(tunnel.streams) >= maxStreamsPerSession {
		tunnel.mu.Unlock()
		conn.Close()
		errChunk := core.NewDataChunk(session.ID, session.NextSeqNum(), []byte("CONNECT_FAIL"))
		encrypted, _ := session.EncryptChunk(errChunk)
		respBody, _ := h.buildResponse(encrypted, errChunk.SeqNum)
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write(respBody)
		return
	}
	tunnel.streams[streamID] = &StreamConn{StreamID: streamID, TargetConn: conn}
	// Legacy compat
	if streamID == 0 {
		tunnel.targetConn = conn
	}
	tunnel.connected = true
	tunnel.mu.Unlock()

	// Per-stream relay: target → tunnel.Outgoing (tagged with StreamID)
	go h.relayStreamFromTarget(session, tunnel, streamID, conn)

	okChunk := core.NewDataChunk(session.ID, session.NextSeqNum(), []byte("CONNECT_OK"))
	encrypted, _ := session.EncryptChunk(okChunk)
	respBody, _ := h.buildResponse(encrypted, okChunk.SeqNum)
	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

// relayFromTarget reads from legacy single-target conn (StreamID=0).
func (h *Handler) relayFromTarget(session *core.Session, tunnel *Tunnel) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in relayFromTarget", "error", r)
		}
	}()
	buf := core.GetBuffer(16384)
	defer core.PutBuffer(buf)

	// CRIT-4 fix: snapshot targetConn under lock
	tunnel.mu.Lock()
	conn := tunnel.targetConn
	tunnel.mu.Unlock()
	if conn == nil {
		return
	}

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data := core.GetBuffer(n)
			data = data[:n]
			copy(data, buf[:n])
			select {
			case tunnel.Outgoing <- data:
			default:
				core.PutBuffer(data)
			}
		}
		if err != nil {
			return
		}
	}
}

// relayStreamFromTarget reads from a specific stream's target and tags data with StreamID.
func (h *Handler) relayStreamFromTarget(session *core.Session, tunnel *Tunnel, streamID uint16, conn net.Conn) {
	buf := core.GetBuffer(16384)
	defer core.PutBuffer(buf)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			tagged := core.GetBuffer(2 + n)
			tagged = tagged[:2+n]
			binary.BigEndian.PutUint16(tagged[0:2], streamID)
			copy(tagged[2:], buf[:n])
			select {
			case tunnel.Outgoing <- tagged:
			case <-tunnel.done:
				core.PutBuffer(tagged)
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (h *Handler) handleControl(w http.ResponseWriter, session *core.Session, chunk *core.Chunk) {
	// Control chunks handle rekeying, chunk_size negotiation, etc.
	// For now: just ACK
	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write([]byte(`{"status":"ok","type":"control_ack"}`))
}

// handleUDPData processes a FlagUDP chunk: relays UDP data to the target via UDPRelay.
func (h *Handler) handleUDPData(w http.ResponseWriter, session *core.Session, chunk *core.Chunk) {
	streamID, targetAddr, data, err := core.ParseUDPChunk(chunk.Payload)
	if err != nil {
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}
	if h.udpRelay == nil {
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	h.tunnelsMu.RLock()
	tunnel, ok := h.tunnels[session.ID]
	h.tunnelsMu.RUnlock()
	if !ok {
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	// X-2 fix: SSRF protection for UDP targets — resolve hostname first to prevent DNS rebinding
	udpHost := targetAddr
	if uh, _, err := net.SplitHostPort(targetAddr); err == nil {
		udpHost = uh
	}
	if isBlockedDomain(udpHost, h.config.BlockDomains) {
		slog.Debug("blocked domain UDP target", "addr", targetAddr)
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}
	// Resolve hostname to IP to prevent DNS rebinding bypassing isPrivateIP
	resolvedAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		slog.Debug("failed to resolve UDP target", "addr", targetAddr, "error", err)
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}
	if isPrivateIP(resolvedAddr.IP) {
		slog.Debug("blocked private UDP target", "addr", targetAddr, "resolved", resolvedAddr.IP)
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}
	// Use the resolved IP:port to prevent TOCTOU DNS rebinding
	resolvedTarget := resolvedAddr.String()

	h.udpRelay.Send(streamID, resolvedTarget, data, func(response []byte) {
		respChunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, response)
		encrypted, err := session.EncryptChunk(respChunk)
		if err != nil {
			return
		}
		select {
		case tunnel.Outgoing <- encrypted:
		default:
		}
	})

	// Collect any pending outgoing data (same pattern as handleDataChunk)
	var responsePayload []byte
	if ok {
		// HIGH-1 fix: replace time.After with NewTimer to prevent timer leak
		udpTimer := time.NewTimer(100 * time.Millisecond)
		select {
		case outData := <-tunnel.Outgoing:
			udpTimer.Stop()
			responsePayload = outData
		case <-udpTimer.C:
		}
	}

	respChunk := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     core.FlagData,
		Payload:   responsePayload,
	}
	encrypted, err := session.EncryptChunk(respChunk)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	respBody, _ := h.buildResponse(encrypted, respChunk.SeqNum)
	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

func (h *Handler) handleFin(session *core.Session) {
	h.tunnelsMu.Lock()
	if tunnel, ok := h.tunnels[session.ID]; ok {
		// Clean up device tracking
		if tunnel.ClientID != "" {
			h.clientAuth.OnSessionDestroyed(tunnel.ClientID, session.ID)
		}
		// Close all multiplexed stream connections + legacy targetConn under lock
		tunnel.mu.Lock()
		for _, sc := range tunnel.streams {
			if sc.TargetConn != nil {
				sc.TargetConn.Close()
			}
		}
		if tunnel.targetConn != nil {
			tunnel.targetConn.Close()
		}
		tunnel.mu.Unlock()
		tunnel.closeTunnel() // idempotent — sync.Once
		delete(h.tunnels, session.ID)
	}
	h.tunnelsMu.Unlock()
	h.sessions.Remove(session.ID)
	h.metrics.ActiveClients.Add(-1)
}

// findSession looks up a session from the encrypted session token.
// Supports two formats:
//   - With hint (new): [hint(4)] + [encrypted_token] — O(1) lookup
//   - Without hint (legacy): [encrypted_token] — O(N) fallback
func (h *Handler) findSession(tokenBytes []byte) *core.Session {
	if len(tokenBytes) < 16 {
		return nil
	}

	// Try O(1) lookup with hint (new format: 4-byte hint prefix)
	if len(tokenBytes) >= 20 {
		hint := tokenBytes[:4]
		token := tokenBytes[4:]
		if len(token) >= 4 {
			var xorMask [4]byte
			copy(xorMask[:], token[:4])
			sid := binary.BigEndian.Uint32(hint) ^ binary.BigEndian.Uint32(xorMask[:])

			if s, ok := h.sessions.Get(sid); ok {
				sk, rk := s.Keys() // copy keys under lock (use-after-destroy fix)
				if verifySessionToken(token, s.ID, rk) {
					return s
				}
				if verifySessionToken(token, s.ID, sk) {
					return s
				}
			}
		}
	}

	// Fallback: O(N) scan — try tokenBytes as-is (no hint prefix)
	var found *core.Session
	h.sessions.ForEach(func(s *core.Session) bool {
		sk, rk := s.Keys() // copy keys under lock
		if verifySessionToken(tokenBytes, s.ID, rk) {
			found = s
			return true
		}
		if verifySessionToken(tokenBytes, s.ID, sk) {
			found = s
			return true
		}
		return false
	})
	return found
}

// verifySessionToken checks if token decrypts to the expected session ID.
func verifySessionToken(token []byte, expectedID uint32, key []byte) bool {
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	nonceSize := gcm.NonceSize()
	if len(token) < nonceSize+4+gcm.Overhead() {
		return false
	}
	nonce := token[:nonceSize]
	ciphertext := token[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return false
	}
	if len(plaintext) < 4 {
		return false
	}
	id := binary.BigEndian.Uint32(plaintext[:4])
	return id == expectedID
}

// GetTunnel returns the tunnel for a given session ID.
func (h *Handler) GetTunnel(sessionID uint32) (*Tunnel, bool) {
	h.tunnelsMu.RLock()
	defer h.tunnelsMu.RUnlock()
	t, ok := h.tunnels[sessionID]
	return t, ok
}

// SessionCount returns the number of active sessions.
func (h *Handler) SessionCount() int {
	return h.sessions.Count()
}

// StartCleanup runs periodic session cleanup in the background.
func (h *Handler) StartCleanup(stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(h.config.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// M6 fix: clean up rate limiter map alongside sessions
				h.rateLimiter.Cleanup()

				removed := h.sessions.Cleanup()
				if removed > 0 {
					// Also clean up tunnels for removed sessions
					h.tunnelsMu.Lock()
					for id, tunnel := range h.tunnels {
						if _, ok := h.sessions.Get(id); !ok {
							// Clean up device tracking
							if tunnel.ClientID != "" {
								h.clientAuth.OnSessionDestroyed(tunnel.ClientID, id)
							}
							// Close all stream connections + channels
							tunnel.mu.Lock()
							for _, sc := range tunnel.streams {
								if sc.TargetConn != nil {
									sc.TargetConn.Close()
								}
							}
							if tunnel.targetConn != nil {
								tunnel.targetConn.Close()
							}
							tunnel.mu.Unlock()
							tunnel.closeTunnel()
							delete(h.tunnels, id)
							h.metrics.ActiveClients.Add(-1)
						}
					}
					h.tunnelsMu.Unlock()
					slog.Debug("session cleanup", "removed", removed)
				}
			case <-stop:
				return
			}
		}
	}()
}

// encodeServerHello serializes ServerHello into bytes for transmission.
// SessionID is NOT included in plaintext — it's only in the encrypted token.
// This prevents CDN (Cloudflare) from seeing the session ID. (Audit C1 fix)
func encodeServerHello(sh *core.ServerHello) []byte {
	// UA update mechanism: server sends current browser UA strings
	// so clients stay up-to-date without code changes.
	data, _ := json.Marshal(struct {
		EphPub    []byte            `json:"eph"`
		Token     []byte            `json:"tok"`
		MaxConns  uint8             `json:"mc"`
		ChunkSize uint16            `json:"cs"`
		UA        map[string]string `json:"ua,omitempty"`
	}{
		EphPub:    sh.EphemeralPub,
		Token:     sh.EncryptedSessionToken,
		MaxConns:  sh.MaxConnsPerClient,
		ChunkSize: sh.ChunkSize,
		UA: map[string]string{
			"chrome":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			"safari":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15",
			"firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
		},
	})
	return data
}

func httpPlaceholderRequest() *http.Request {
	r, _ := http.NewRequest("GET", "/", nil)
	return r
}

// Add ForEach to SessionManager (needed by findSession).
func init() {
	// ForEach is defined in session.go — verify it exists at compile time.
}

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

const maxClientStreams = 4096 // X-4 fix: bound client-side stream map (high for system VPN mode)

// isValidUA validates that a UA string matches known browser patterns.
// Prevents a malicious server from injecting arbitrary strings via the UA update mechanism.
// MED-6 fix: added length bounds and printable ASCII check.
func isValidUA(ua string) bool {
	if len(ua) < 10 || len(ua) > 256 {
		return false
	}
	for _, c := range ua {
		if c < 0x20 || c > 0x7E {
			return false // non-printable or non-ASCII
		}
	}
	return strings.Contains(ua, "Mozilla/") &&
		(strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/") || strings.Contains(ua, "Safari/"))
}

// Client is the main ShadowLink client API.
// Connect() performs handshake, then Send/Recv exchange data through the tunnel.
type Client struct {
	transport   Transport
	session     *core.Session
	token       []byte // encrypted session token for Authorization header
	serverPub   []byte // server static public key
	clientID    []byte
	maxConns    int
	chunkSize   int

	mu sync.Mutex

	// Stream multiplexing
	streamCounter uint16
	streamChans   map[uint16]chan []byte // StreamID → incoming data from server
	streamMu      sync.Mutex
}

// ClientConfig holds configuration for the client.
type ClientConfig struct {
	ServerAddr   string // "host:port"
	ServerPubKey []byte // 32 bytes X25519 public key
	ClientID     []byte // client identifier
	UseTLS       bool   // enable TLS (default true for production)
	SkipVerify   bool   // skip TLS cert verification (testing only)
	CDNDomain    string // if set, use CDN transport via this domain
	ECHEnabled   bool   // enable ECH (Encrypted Client Hello) for CDN mode
	SNIOverride  string // if set, TLS ServerName = SNIOverride (full-direct mode: IP host + domain SNI). Requires UseTLS=true.

	// Phase 2: TURN relay for whitelist bypass
	TURNServer    string // TURN server "host:port"
	TURNUsername  string
	TURNPassword  string
	ServerUDPAddr  string // ShadowLink server UDP "host:port" (default :56000)
	WBTurnEnabled  bool   // Enable WB TURN in auto-detect (feature flag)
}

// NewClient creates a client with the given config.
func NewClient(config ClientConfig) *Client {
	var transport Transport
	switch {
	case config.SNIOverride != "":
		// Full-direct: dial to ServerAddr (IP), TLS SNI = SNIOverride (domain).
		// Used when client knows the origin IP and wants to bypass CF entirely
		// while keeping the legitimate SNI so nginx server_name still matches.
		transport = NewDirectTransportWithSNI(config.ServerAddr, config.SNIOverride, config.UseTLS)
	case config.CDNDomain != "":
		transport = NewCDNTransportWithECH(config.CDNDomain, config.ECHEnabled)
	default:
		transport = NewDirectTransport(config.ServerAddr, config.UseTLS, config.SkipVerify)
	}

	return &Client{
		transport: transport,
		serverPub: config.ServerPubKey,
		clientID:  config.ClientID,
	}
}

// NewClientWithTransport creates a client with a custom transport (for testing).
func NewClientWithTransport(transport Transport, serverPubKey, clientID []byte) *Client {
	return &Client{
		transport: transport,
		serverPub: serverPubKey,
		clientID:  clientID,
	}
}

// Connect performs the ShadowLink handshake and establishes a session.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create ClientHello
	hello, clientState, err := core.NewClientHello(c.clientID, c.serverPub)
	if err != nil {
		return fmt.Errorf("create client hello: %w", err)
	}

	// Send via transport
	respBody, err := c.transport.SendHandshake(ctx, hello)
	if err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	// Parse ServerHello from response
	respData, _, err := browser.ParseDownloadResponse(respBody)
	if err != nil {
		return fmt.Errorf("parse server hello: %w", err)
	}

	var shData struct {
		EphPub    []byte            `json:"eph"`
		Token     []byte            `json:"tok"`
		MaxConns  uint8             `json:"mc"`
		ChunkSize uint16            `json:"cs"`
		UA        map[string]string `json:"ua,omitempty"` // server-provided UA updates
	}
	if err := json.Unmarshal(respData, &shData); err != nil {
		return fmt.Errorf("unmarshal server hello: %w", err)
	}

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
	}

	// Complete handshake — derive session keys
	session, err := core.CompleteHandshake(clientState, serverHello)
	if err != nil {
		return fmt.Errorf("complete handshake: %w", err)
	}

	c.session = session
	// Encode token with session_id hint for O(1) server-side lookup
	c.token = browser.EncodeTokenWithHint(session.ID, shData.Token)
	c.maxConns = int(shData.MaxConns)
	c.chunkSize = int(shData.ChunkSize)
	if c.chunkSize == 0 {
		c.chunkSize = 12288
	}

	// M-1 fix: pass session and token to transport so cover traffic can use them.
	// Works for both DirectTransport and CDNTransport (both implement SessionAware).
	if sa, ok := c.transport.(SessionAware); ok {
		sa.SetSession(c.session)
		sa.SetSessionToken(c.token)
	}

	// Apply server-provided UA updates (keeps client UAs fresh without code changes).
	// SEC-H4 fix: validate UA strings against known browser patterns to prevent
	// a compromised server from injecting arbitrary UA strings.
	if len(shData.UA) > 0 {
		validUAs := make(map[string]string, len(shData.UA))
		for profile, ua := range shData.UA {
			if isValidUA(ua) {
				validUAs[profile] = ua
			} else {
				slog.Warn("rejected invalid UA from server", "profile", profile)
			}
		}
		if len(validUAs) > 0 {
			browser.UpdateUserAgents(validUAs)
		}
	}

	slog.Info("connected to shadowlink server",
		"transport", c.transport.Name(),
		"max_conns", c.maxConns,
		"chunk_size", c.chunkSize)

	return nil
}

// Send encrypts and sends data to the server, returns decrypted response payload.
func (c *Client) Send(ctx context.Context, data []byte) ([]byte, error) {
	c.mu.Lock()
	session := c.session
	token := c.token
	c.mu.Unlock()

	if session == nil {
		return nil, errors.New("not connected — call Connect() first")
	}

	seq := session.NextSeqNum()
	chunk := core.NewDataChunk(session.ID, seq, data)
	encrypted, err := session.EncryptChunk(chunk) // safe: copies key under lock
	if err != nil {
		return nil, fmt.Errorf("encrypt chunk: %w", err)
	}

	encResp, err := c.transport.SendChunk(ctx, encrypted, token, seq)
	if err != nil {
		return nil, fmt.Errorf("send chunk: %w", err)
	}

	respChunk, err := session.DecryptChunkSafe(encResp) // safe: copies key under lock
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}

	return respChunk.Payload, nil
}

// ConnectTo tells the server to open a TCP connection to the target address.
// Returns "CONNECT_OK" on success or error details on failure.
func (c *Client) ConnectTo(ctx context.Context, target string) error {
	c.mu.Lock()
	session := c.session
	token := c.token
	c.mu.Unlock()

	if session == nil {
		return errors.New("not connected — call Connect() first")
	}

	seq := session.NextSeqNum()
	chunk := core.NewConnectChunk(session.ID, seq, target)
	encrypted, err := session.EncryptChunk(chunk)
	if err != nil {
		return fmt.Errorf("encrypt connect chunk: %w", err)
	}

	encResp, err := c.transport.SendChunk(ctx, encrypted, token, seq)
	if err != nil {
		return fmt.Errorf("send connect: %w", err)
	}

	respChunk, err := session.DecryptChunkSafe(encResp)
	if err != nil {
		return fmt.Errorf("decrypt connect response: %w", err)
	}

	resp := string(respChunk.Payload)
	if resp == "CONNECT_OK" {
		return nil
	}
	return fmt.Errorf("connect failed: %s", resp)
}

// SendKeepalive sends a heartbeat chunk and returns true if server responded.
func (c *Client) SendKeepalive(ctx context.Context) (bool, error) {
	c.mu.Lock()
	session := c.session
	token := c.token
	c.mu.Unlock()

	if session == nil {
		return false, errors.New("not connected")
	}

	seq := session.NextSeqNum()
	chunk := core.NewKeepaliveChunk(session.ID, seq)
	encrypted, err := session.EncryptChunk(chunk)
	if err != nil {
		return false, err
	}

	encResp, err := c.transport.SendChunk(ctx, encrypted, token, seq)
	if err != nil {
		return false, err
	}

	// Verify we got a valid response
	respChunk, err := session.DecryptChunkSafe(encResp)
	if err != nil {
		return false, err
	}

	return respChunk.Flags == core.FlagAck, nil
}

// UpgradeToWebSocket switches to WebSocket transport for full-duplex relay.
// Must be called after Connect() (needs session token).
// Returns a WebSocketTransport for direct frame read/write.
// Optional lockedFP sets a persistent browser fingerprint for uTLS (JA3 consistency).
func (c *Client) UpgradeToWebSocket(serverAddr string, useTLS, skipVerify bool, lockedFP ...*browser.Fingerprint) (*WebSocketTransport, error) {
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()

	if token == nil {
		return nil, errors.New("not connected — call Connect() first")
	}

	var fp *browser.Fingerprint
	if len(lockedFP) > 0 {
		fp = lockedFP[0]
	}
	wst := NewWebSocketTransport(serverAddr, useTLS, skipVerify, fp)

	// Signature packets: warmup GET requests to decoy pages before WS upgrade.
	// Real browser loads HTML/CSS/JS before opening WebSocket.
	// Without this, DPI sees instant TLS→WS upgrade (suspicious pattern).
	wst.WarmupRequests()

	if err := wst.UpgradeToWS(token); err != nil {
		return nil, err
	}
	return wst, nil
}

// NextStreamID allocates a new stream ID, skipping IDs still in use.
func (c *Client) NextStreamID() uint16 {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	for i := 0; i < 65535; i++ {
		c.streamCounter++
		if c.streamCounter == 0 {
			c.streamCounter = 1
		}
		if _, used := c.streamChans[c.streamCounter]; !used {
			return c.streamCounter
		}
	}
	return c.streamCounter // fallback — all IDs used (shouldn't happen)
}

// RegisterStream creates a channel for receiving data on a stream.
// X-4 fix: returns error if max concurrent streams exceeded.
func (c *Client) RegisterStream(streamID uint16) (chan []byte, error) {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	if c.streamChans == nil {
		c.streamChans = make(map[uint16]chan []byte)
	}
	if len(c.streamChans) >= maxClientStreams {
		return nil, errors.New("max streams exceeded")
	}
	ch := make(chan []byte, 512) // large buffer to avoid drops
	c.streamChans[streamID] = ch
	return ch, nil
}

// UnregisterStream removes a stream channel.
func (c *Client) UnregisterStream(streamID uint16) {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	delete(c.streamChans, streamID)
}

// CloseStream sends a per-stream FIN to the server and unregisters the stream locally.
// This tells the server to close the target connection and free the stream slot.
// Without this, streams leak on the server until maxStreamsPerSession is hit.
// FIN is best-effort with a 3s timeout — if it fails, server cleans up via idle timeout.
// Pool-aware: uses the slot's session and releases stream assignment.
func (c *Client) CloseStream(streamID uint16, wst StreamTransport) {
	c.UnregisterStream(streamID)

	// Pool-aware: use slot's session, then release stream assignment.
	session := StreamSession(wst, c, streamID)
	if pa, ok := wst.(PoolAware); ok {
		defer pa.ReleaseStream(streamID)
	}

	if session == nil {
		return
	}
	fin := core.NewStreamFinChunk(session.ID, session.NextSeqNum(), streamID)
	encrypted, err := session.EncryptChunk(fin)
	if err != nil {
		return
	}
	// Sync send with timeout — prevents fire-and-forget goroutine crash.
	done := make(chan error, 1)
	go func() { done <- StreamWriteControl(wst, streamID, encrypted) }()
	select {
	case <-time.After(3 * time.Second):
		slog.Debug("FIN send timeout", "stream", streamID)
	case err := <-done:
		if err != nil {
			slog.Debug("FIN send failed", "stream", streamID, "err", err)
		}
	}
}

// ConnectToStream sends CONNECT for a specific stream.
func (c *Client) ConnectToStream(ctx context.Context, streamID uint16, target string) error {
	c.mu.Lock()
	session := c.session
	token := c.token
	c.mu.Unlock()

	if session == nil {
		return errors.New("not connected")
	}

	seq := session.NextSeqNum()
	chunk := core.NewStreamConnectChunk(session.ID, seq, streamID, target)
	encrypted, err := session.EncryptChunk(chunk)
	if err != nil {
		return err
	}

	encResp, err := c.transport.SendChunk(ctx, encrypted, token, seq)
	if err != nil {
		return err
	}

	respChunk, err := session.DecryptChunkSafe(encResp)
	if err != nil {
		return err
	}

	resp := string(respChunk.Payload)
	if resp == "CONNECT_OK" {
		return nil
	}
	return fmt.Errorf("connect failed: %s", resp)
}

// SendStream sends data for a specific stream and returns response data.
// Response may contain data for ANY stream — it gets demuxed.
func (c *Client) SendStream(ctx context.Context, streamID uint16, data []byte) error {
	c.mu.Lock()
	session := c.session
	token := c.token
	c.mu.Unlock()

	if session == nil {
		return errors.New("not connected")
	}

	seq := session.NextSeqNum()
	chunk := core.NewStreamDataChunk(session.ID, seq, streamID, data)
	encrypted, err := session.EncryptChunk(chunk)
	core.PutBuffer(chunk.Payload) // release pooled payload after encryption
	if err != nil {
		return err
	}

	encResp, err := c.transport.SendChunk(ctx, encrypted, token, seq)
	if err != nil {
		return err
	}

	// Demux response — may contain data for any stream
	respChunk, err := session.DecryptChunkSafe(encResp)
	if err != nil {
		return nil // ignore decrypt errors on response
	}

	if len(respChunk.Payload) > 0 {
		respStreamID, respData := core.ParseStreamID(respChunk.Payload)
		if len(respData) > 0 {
			c.streamMu.Lock()
			ch := c.streamChans[respStreamID]
			c.streamMu.Unlock()
			if ch != nil {
				select {
				case ch <- respData:
				default:
					slog.Warn("stream buffer full in SendStream", "stream_id", respStreamID, "bytes", len(respData))
				}
			}
		}
	}

	return nil
}

// PollStreams sends an empty poll and demuxes any response to stream channels.
func (c *Client) PollStreams(ctx context.Context) error {
	return c.SendStream(ctx, 0, nil)
}

// RawBodySender is an optional interface for transports that can return raw response bodies.
// Used by PollVia for multi-chunk server responses.
type RawBodySender interface {
	SendChunkRawBody(ctx context.Context, data []byte, token []byte, seq uint32) ([]byte, error)
}

// PollVia sends a poll through a dedicated transport (not the client's main transport).
// This avoids contention with CONNECTs that saturate the main CDNTransport.
// Handles multi-chunk responses: server waits 300ms and batches up to 16 chunks.
// Only 1 goroutine should call this to ensure in-order delivery.
func (c *Client) PollVia(ctx context.Context, t Transport) error {
	c.mu.Lock()
	session := c.session
	token := c.token
	c.mu.Unlock()

	if session == nil {
		return errors.New("not connected")
	}

	seq := session.NextSeqNum()
	chunk := core.NewStreamDataChunk(session.ID, seq, 0, nil)
	encrypted, err := session.EncryptChunk(chunk)
	core.PutBuffer(chunk.Payload)
	if err != nil {
		return err
	}

	// Use raw body sender for multi-chunk support if available.
	if rs, ok := t.(RawBodySender); ok {
		rawBody, err := rs.SendChunkRawBody(ctx, encrypted, token, seq)
		if err != nil {
			return err
		}
		encChunks, err := browser.ParseDownloadResponseMulti(rawBody)
		if err != nil {
			return nil // no data this poll
		}
		for _, enc := range encChunks {
			respChunk, err := session.DecryptChunkSafe(enc)
			if err != nil || len(respChunk.Payload) < 2 {
				continue
			}
			streamID := uint16(respChunk.Payload[0])<<8 | uint16(respChunk.Payload[1])
			if respChunk.Flags == core.FlagUDP {
				c.RouteToStream(streamID, respChunk.Payload)
			} else {
				c.RouteToStream(streamID, respChunk.Payload[2:])
			}
		}
		return nil
	}

	// Fallback: single-chunk via standard SendChunk.
	encResp, err := t.SendChunk(ctx, encrypted, token, seq)
	if err != nil {
		return err
	}
	respChunk, err := session.DecryptChunkSafe(encResp)
	if err != nil {
		return nil
	}
	if len(respChunk.Payload) >= 2 {
		streamID := uint16(respChunk.Payload[0])<<8 | uint16(respChunk.Payload[1])
		if respChunk.Flags == core.FlagUDP {
			c.RouteToStream(streamID, respChunk.Payload)
		} else {
			c.RouteToStream(streamID, respChunk.Payload[2:])
		}
	}
	return nil
}

// HasStream returns true if a stream channel is registered for the given ID.
func (c *Client) HasStream(streamID uint16) bool {
	c.streamMu.Lock()
	_, ok := c.streamChans[streamID]
	c.streamMu.Unlock()
	return ok
}

// RouteToStream delivers data to a registered stream's channel.
// MED-5 fix: logs warning on buffer full instead of silent drop.
func (c *Client) RouteToStream(streamID uint16, data []byte) {
	c.streamMu.Lock()
	ch := c.streamChans[streamID]
	c.streamMu.Unlock()
	if ch != nil {
		select {
		case ch <- data:
		default:
			slog.Warn("stream buffer full, data dropped", "stream_id", streamID, "bytes", len(data))
		}
	}
}

// Session returns the current session (for direct WS relay). Nil if not connected.
func (c *Client) Session() *core.Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// Token returns the session token (for SplitHTTP transport).
func (c *Client) Token() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// Transport returns the underlying transport (for SplitHTTP to reuse for uploads).
func (c *Client) Transport() Transport {
	return c.transport
}

// Connected returns true if the client has an active session.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session != nil
}

// SessionID returns the current session ID (0 if not connected).
func (c *Client) SessionID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return 0
	}
	return c.session.ID
}

// NewStreamSession performs a lightweight handshake and returns an independent
// session+token for a per-stream WS. Each per-stream WS gets its own session
// to avoid seq_num conflicts when multiple streams share the crypto state.
// The caller owns the returned session and must call session.Destroy() when done.
func (c *Client) NewStreamSession(ctx context.Context) (*core.Session, []byte, error) {
	hello, clientState, err := core.NewClientHello(c.clientID, c.serverPub)
	if err != nil {
		return nil, nil, err
	}

	respBody, err := c.transport.SendHandshake(ctx, hello)
	if err != nil {
		return nil, nil, err
	}

	respData, _, err := browser.ParseDownloadResponse(respBody)
	if err != nil {
		return nil, nil, err
	}

	var shData struct {
		EphPub    []byte `json:"eph"`
		Token     []byte `json:"tok"`
		MaxConns  uint8  `json:"mc"`
		ChunkSize uint16 `json:"cs"`
	}
	if err := json.Unmarshal(respData, &shData); err != nil {
		return nil, nil, err
	}

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
	}

	session, err := core.CompleteHandshake(clientState, serverHello)
	if err != nil {
		return nil, nil, err
	}

	token := browser.EncodeTokenWithHint(session.ID, shData.Token)
	return session, token, nil
}

// Close disconnects and cleans up resources.
// H2 fix: zeroes key material before releasing session.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.session != nil {
		c.session.Destroy() // zero SendKey, RecvKey, oldRecvKey
	}
	c.session = nil
	core.ZeroBytes(c.token)
	c.token = nil
	c.mu.Unlock()
	return c.transport.Close()
}

// backoffDuration returns an exponentially increasing wait duration for reconnect attempts,
// capped at 60s and jittered ±25% to avoid thundering herd.
func backoffDuration(attempt int) time.Duration {
	base := float64(time.Second) * math.Pow(2, float64(attempt))
	if base > float64(60*time.Second) {
		base = float64(60 * time.Second)
	}
	jitter := 0.75 + rand.Float64()*0.5
	return time.Duration(base * jitter)
}

// ConnectWithRetry calls Connect in a loop with exponential backoff until it
// succeeds or ctx is cancelled. Suitable for use as the main client loop entry point.
func (c *Client) ConnectWithRetry(ctx context.Context) error {
	for attempt := 0; ; attempt++ {
		// Check cancellation before each attempt.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		err := c.Connect(ctx)
		if err == nil {
			if attempt > 0 {
				slog.Info("reconnected", "attempts", attempt+1)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		d := backoffDuration(attempt)
		slog.Warn("connect failed, retrying", "attempt", attempt+1, "backoff", d, "error", err)
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// ResetStreams closes all registered stream channels and detaches the session.
// R-1 fix: acquire streamMu for stream cleanup (streamChans is guarded by streamMu,
// not mu). Lock ordering: streamMu first, then mu — consistent with other code paths.
// R-4 fix: defer session.Destroy() by 5s so in-flight SOCKS5 handlers that already
// snapshotted the session can finish their encrypt/decrypt operations. New handlers
// will see session=nil and return "not connected" immediately.
func (c *Client) ResetStreams() {
	c.streamMu.Lock()
	for id, ch := range c.streamChans {
		close(ch)
		delete(c.streamChans, id)
	}
	c.streamMu.Unlock()

	c.mu.Lock()
	oldSession := c.session
	oldToken := c.token
	c.session = nil
	c.token = nil
	c.mu.Unlock()

	// R-4: defer key zeroing — in-flight handlers may still hold a reference
	if oldSession != nil || oldToken != nil {
		go func() {
			time.Sleep(5 * time.Second)
			if oldSession != nil {
				oldSession.Destroy()
			}
			if oldToken != nil {
				core.ZeroBytes(oldToken)
			}
		}()
	}
}

// TransportName returns the name of the current transport.
func (c *Client) TransportName() string {
	return c.transport.Name()
}

// SessionToken returns the encrypted session token (for direct chunk sending).
func (c *Client) SessionToken() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// SendChunkRaw sends a pre-encrypted chunk via the transport and returns the raw response.
// Used for UDP ASSOCIATE where the caller handles encryption/decryption directly.
func (c *Client) SendChunkRaw(ctx context.Context, encrypted []byte, token []byte, seqNum uint32) ([]byte, error) {
	return c.transport.SendChunk(ctx, encrypted, token, seqNum)
}

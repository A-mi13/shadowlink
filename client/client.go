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
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

const maxClientStreams = 4096 // X-4 fix: bound client-side stream map (high for system VPN mode)

// allowedUAKeys is the closed enum of profile keys the client will accept
// in the ServerHello UA map. Any other key is dropped before the value is
// even validated. Final-audit-2026-05-03 P2-2 (T1 §219): defensive
// hygiene against a compromised server emitting binary-control-char keys
// that propagate to UpdateUserAgents.
//
// 2026-05-05: non-Chrome fingerprints retired (TSPU блокирует Safari/Firefox/
// Edge). Только chrome допускается; "safari"/"firefox" из ServerHello теперь
// тихо отбрасываются isAllowedUAKey, server-side exportClientConfig также
// отправляет только chrome-key.
var allowedUAKeys = map[string]struct{}{
	browser.ProfileChrome: {},
}

// uaForbiddenChars are bytes a real browser UA never contains. Listed
// explicitly so the disallow set stays auditable even though every entry
// here is also caught by the printable-ASCII range check below — having
// the explicit deny-list documents intent and survives any future
// loosening of the range check.
var uaForbiddenChars = []byte{'<', '>', '\n', '\r', 0}

// isValidUA validates that a UA string matches the locked-Chrome contract.
// Prevents a malicious or compromised server from re-fingerprinting the
// client fleet via the ServerHello UA update mechanism (T1 §154).
//
// Acceptance rules:
//   - Length 80..200 bytes (Opus review M-5, final-audit-2026-05-05).
//     Real Chrome UA на разных платформах: Win 117-130, Mac 125-135,
//     Android 100-115. Старый bound 10..256 давал серверу 125 байт extra
//     room для UA-padding атак — tighter window закрывает это без
//     отказа легитимным браузерам.
//   - All bytes are printable ASCII (0x20..0x7E).
//   - No `<`, `>`, `\n`, `\r`, or NUL bytes (already covered by the
//     printable-ASCII range; double-check kept as defense-in-depth).
//   - Contains `"Mozilla/"` and `"Chrome/<LockedChromeMajor>."`.
//   - Hard-reject UAs that contain `"Firefox/"` or `"Safari/"` BEZ `"Chrome/"`.
//     Note: real Chrome UA содержит "Safari/537.36" в качестве AppleWebKit
//     legacy-tag (наследие WebKit, который Chromium до сих пор forks-ает),
//     поэтому проверка на standalone Safari условная — отвергаем только
//     UAs, где есть "Safari/" но нет "Chrome/" (т.е. настоящий Apple Safari).
//
// 2026-05-05: non-Chrome fingerprints retired (TSPU блокирует Safari/Firefox/
// Edge). Раньше функция принимала Firefox- и Safari-only UAs; теперь —
// только Chrome-family с залоченным major.
//
// On reject, the caller leaves the per-profile UA unchanged — `browser`
// retains its compile-time defaults sourced from LockedChromeUA(), so
// failure-to-update does not break wire fingerprint consistency.
//
// Final-audit-2026-05-03 P2-2 (T1 §154 + §219).
func isValidUA(ua string) bool {
	if len(ua) < 80 || len(ua) > 200 {
		return false
	}
	for i := 0; i < len(ua); i++ {
		c := ua[i]
		if c < 0x20 || c > 0x7E {
			return false // non-printable or non-ASCII
		}
	}
	for _, bad := range uaForbiddenChars {
		if strings.IndexByte(ua, bad) >= 0 {
			return false
		}
	}
	if !strings.Contains(ua, "Mozilla/") {
		return false
	}
	hasChrome := strings.Contains(ua, "Chrome/")
	if !hasChrome {
		// 2026-05-05: только Chrome-family UAs принимаются. Firefox-only
		// и standalone Safari (без Chrome/) отбрасываются.
		return false
	}
	// Hard-reject Firefox/ — реальный Chrome UA не содержит этого токена.
	if strings.Contains(ua, "Firefox/") {
		return false
	}
	needle := "Chrome/" + browser.LockedChromeMajorString + "."
	return strings.Contains(ua, needle)
}

// isAllowedUAKey reports whether the given map key is on the closed enum
// of profile keys the client will accept from a ServerHello UA map.
// Final-audit-2026-05-03 P2-2 (T1 §219).
func isAllowedUAKey(k string) bool {
	_, ok := allowedUAKeys[k]
	return ok
}

// Client is the main ShadowLink client API.
// Connect() performs handshake, then Send/Recv exchange data through the tunnel.
type Client struct {
	transport Transport
	session   *core.Session
	token     []byte // encrypted session token for Authorization header
	serverPub []byte // server static public key
	clientID  []byte
	maxConns  int
	chunkSize int

	// insecureSkipVerify is carried here so the D4 handshake probe can refuse
	// to fall back to the legacy Bearer path when TLS is not actually verified.
	// Without this guard, an on-path MITM could strip `_v` and force the client
	// down the pre-migration path without detection.
	insecureSkipVerify bool

	// handshakeOnce ensures performHandshake runs at most once per Client —
	// Connect() may be retried by callers, but the handshake is idempotent on
	// success and we must not replay the ClientHello payload on a second call.
	handshakeOnce sync.Once
	handshakeErr  error

	mu sync.Mutex

	// Stream multiplexing
	streamCounter uint16
	streamChans   map[uint16]chan []byte // StreamID → incoming data from server
	streamMu      sync.Mutex

	// Cold-start observability (Task D5, 2026-05-02 plan).
	//
	// connectStartUnixNano stores time.Now().UnixNano() at the start of
	// Connect() — written before performHandshake runs, read by
	// MarkFirstStream when the first SOCKS5 stream is attached so the
	// gauge measures the user-perceived "tunnel ready" interval. Stored as
	// atomic so the SOCKS5 dispatcher path can read without taking c.mu
	// (which is already held by some callers higher in the stack).
	//
	// firstStreamOnce guarantees the FirstStreamMS gauge is stamped at most
	// once per Connect() cycle — without it, every successful CONNECT
	// would overwrite the gauge with later (irrelevant) latencies. Reset
	// is wired into the ctx-error retry path in performHandshake so a
	// fresh Connect after a cancelled one starts measuring from scratch.
	connectStartUnixNano atomic.Int64
	firstStreamOnce      sync.Once
}

// serverHelloJSON is the unmarshalled ServerHello envelope. `_v` is a pointer so
// "absent" (legacy server) is distinguishable from "present but zero".
type serverHelloJSON struct {
	EphPub       []byte            `json:"eph"`
	Token        []byte            `json:"tok"`
	MaxConns     uint8             `json:"mc"`
	ChunkSize    uint16            `json:"cs"`
	ProtoVersion *uint8            `json:"_v,omitempty"`
	Deprecated   bool              `json:"_deprecated,omitempty"`
	UA           map[string]string `json:"ua,omitempty"`
}

// httpStatusError carries the HTTP status code from SendHandshakeRaw so the
// D4 probe can decide whether to fall back to the legacy path.
type httpStatusError struct {
	Status int
	Body   string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
}

// parseHandshakeError extracts an httpStatusError from a SendHandshakeRaw
// error, walking the wrap chain via errors.As. Returns nil for network errors
// and context cancellation — those should propagate without triggering the
// legacy fallback.
//
// All transport implementations (DirectTransport, CDNTransport, the synthesized
// error in handshakeNew when HandshakeRawSender is absent) emit *httpStatusError
// directly, so string-prefix matching is unnecessary. errors.As also handles
// `fmt.Errorf("foo: %w", statusErr)` wraps, keeping the classifier robust
// against future transport refactors.
func parseHandshakeError(err error) *httpStatusError {
	if err == nil {
		return nil
	}
	var he *httpStatusError
	if errors.As(err, &he) {
		return he
	}
	return nil
}

// ClientConfig holds configuration for the client.
type ClientConfig struct {
	ServerAddr   string // "host:port"
	ServerPubKey []byte // 32 bytes X25519 public key
	// ClientID identifies the client. Phase B pins EncryptedClientIDSize=65
	// bytes assuming a 16-byte UUID; non-UUID-sized IDs still work via the
	// server's v0 legacy-fallback path but forfeit the new-format keys.
	// Production SHOULD use UUID-sized (16 B) IDs.
	ClientID    []byte
	UseTLS      bool   // enable TLS (default true for production)
	SkipVerify  bool   // skip TLS cert verification (testing only)
	CDNDomain   string // if set, use CDN transport via this domain
	ECHEnabled  bool   // enable ECH (Encrypted Client Hello) for CDN mode
	SNIOverride string // if set, TLS ServerName = SNIOverride (full-direct mode: IP host + domain SNI). Requires UseTLS=true.
}

// NewClient creates a client with the given config.
//
// Warns (slog.Warn) when ClientID is not 16 bytes — prod callers should pass
// UUIDs so the handshake lands on the new-format keys. We don't hard-fail
// because short IDs still interoperate via the server's v0 fallback; the
// warning is a migration-canary for admin panels still issuing short strings.
func NewClient(config ClientConfig) *Client {
	if len(config.ClientID) != 16 {
		slog.Warn("shadowlink: non-UUID-sized ClientID — falling back to legacy v0 handshake path",
			"size", len(config.ClientID), "recommended", 16)
	}
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
		transport:          transport,
		serverPub:          config.ServerPubKey,
		clientID:           config.ClientID,
		insecureSkipVerify: config.SkipVerify,
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
// Internally idempotent via performHandshake's sync.Once — safe to call again
// after a successful first connect (a second call is a no-op).
func (c *Client) Connect(ctx context.Context) error {
	// Task D5: stamp the cold-start origin so MarkFirstStream can compute
	// the user-perceived "tunnel ready" interval. CompareAndSwap leaves the
	// existing value untouched on the no-op second-Connect path (sync.Once
	// already pinned the handshake outcome) so the gauge keeps measuring
	// from the original Connect, not the retry.
	c.connectStartUnixNano.CompareAndSwap(0, time.Now().UnixNano())
	return c.performHandshake(ctx)
}

// MarkFirstStream stamps the FirstStreamMS gauge with the elapsed duration
// since Connect() was called. The first SOCKS5 CONNECT to successfully send
// CONNECT_OK back to its caller wires this up. sync.Once gates so only the
// very first stream-attached event of the Connect cycle wins — subsequent
// CONNECTs and reconnects do not overwrite the gauge.
//
// No-op when connectStartUnixNano is zero (Connect was never called) so
// out-of-order callers do not write a meaningless "ms since Unix epoch".
//
// Snapshot of start+Once happens under c.mu so a concurrent ctx-error reset
// in performHandshake (which clears both fields under the same mutex) cannot
// race a stale start into a freshly-reset Once.Do — the gauge would otherwise
// stamp with a very large elapsed (since the cancelled Connect) on the next
// stream-attach event.
func (c *Client) MarkFirstStream() {
	c.mu.Lock()
	defer c.mu.Unlock()
	start := c.connectStartUnixNano.Load()
	if start == 0 {
		return
	}
	c.firstStreamOnce.Do(func() {
		SetFirstStreamMS(time.Since(time.Unix(0, start)))
	})
}

// performHandshake is the one-shot guarded entry point around the probe
// fallback. sync.Once pins the outcome so a retry after a successful connect
// doesn't replay the ClientHello (which would mint a new session) and a retry
// after a failed connect doesn't double-handshake either.
//
// Exception: context cancellation / deadline errors are transient — the caller
// typically passes a fresh context to retry (ConnectWithRetry loops on this).
// Caching those errors permanently would poison the Client forever after a
// single early cancel. We reset the Once when the previous outcome was purely
// a ctx error so the next caller gets a real handshake attempt.
func (c *Client) performHandshake(ctx context.Context) error {
	c.handshakeOnce.Do(func() {
		c.handshakeErr = c.runHandshakeSequence(ctx)
	})
	err := c.handshakeErr
	if err != nil && isContextError(err) {
		// Clear the cached ctx error under the same lock the handshake runs
		// under so a concurrent retry doesn't race with the reset.
		c.mu.Lock()
		c.handshakeOnce = sync.Once{}
		c.handshakeErr = nil
		// Task D5: cold-start gauge resets too, so the next Connect()
		// timestamps a fresh start and the next stream-attach stamps a
		// fresh interval (instead of measuring against a long-cancelled
		// Connect that never completed).
		c.connectStartUnixNano.Store(0)
		c.firstStreamOnce = sync.Once{}
		c.mu.Unlock()
	}
	return err
}

// isContextError reports whether the error is solely a context cancellation
// or deadline, possibly wrapped. Network errors unrelated to ctx (dial refused,
// TLS handshake failure, protocol parse failure) should NOT reset the Once —
// they indicate a stable problem the caller can't fix by retrying with a new
// context alone.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// runHandshakeSequence implements the D4 probe flow:
//
//  1. Try the new body-prefix handshake (padded payload via BuildHandshakePayload,
//     POST without Authorization).
//  2. On network error or context cancellation — propagate, do not fall back.
//  3. On HTTP 200 + body that isn't a valid ServerHello — hard-fail (MITM).
//  4. On HTTP 4xx — fall back to the legacy handshake path, UNLESS
//     InsecureSkipVerify is on (in which case a falling back would silently
//     land on the pre-migration Bearer path without TLS guarantees).
//  5. On success: require `_v` to be set; refuse `_v > 1` (server requires an
//     update we don't yet ship) and refuse `_v == nil` unless falling back to
//     legacy is permitted.
//  6. Pin session.ProtoVersion = 1 on the new path, 0 on the legacy path.
func (c *Client) runHandshakeSequence(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	hello, clientState, err := core.NewClientHello(c.clientID, c.serverPub)
	if err != nil {
		return fmt.Errorf("create client hello: %w", err)
	}

	// Non-UUID clientIDs produce a short EncryptedClientID that doesn't match
	// Phase B's fixed EncryptedClientIDSize — a hybrid server fail-closes to
	// decoy (HTML body) in that case, which would trip the 200-garbage MITM
	// guard. Skip the new-format probe entirely for these clients and go
	// straight to the legacy path (server still honors it via hybrid dispatch).
	// Production callers SHOULD pass 16-byte UUIDs; legacy is only for back-
	// compat with existing admin panels that still issue short IDs.
	if len(c.clientID) != 16 {
		return c.handshakeLegacy(ctx, hello, clientState)
	}

	// Attempt 1 — new format (padded, no Authorization).
	respBody, newErr := c.handshakeNew(ctx, hello)
	if newErr != nil {
		// Network/context errors — don't retry under a different format.
		if errors.Is(newErr, context.Canceled) || errors.Is(newErr, context.DeadlineExceeded) {
			return newErr
		}
		statusErr := parseHandshakeError(newErr)
		if statusErr == nil {
			// Non-HTTP error (dial failure, TLS handshake, etc). Don't fall back.
			return fmt.Errorf("handshake new: %w", newErr)
		}
		switch {
		case statusErr.Status == 200:
			// 200-garbage — likely MITM stripping the real body.
			return fmt.Errorf("handshake: invalid ServerHello (possible MITM): %w", newErr)
		case statusErr.Status >= 400 && statusErr.Status < 500:
			if c.insecureSkipVerify {
				return fmt.Errorf("handshake new failed and legacy fallback disabled (InsecureSkipVerify=true): %w", newErr)
			}
			return c.handshakeLegacy(ctx, hello, clientState)
		default:
			return fmt.Errorf("handshake new: %w", newErr)
		}
	}

	// New-format success — parse and validate ServerHello before pinning session.
	respData, _, err := browser.ParseDownloadResponse(respBody)
	if err != nil {
		return fmt.Errorf("handshake: invalid ServerHello (possible MITM): %w", err)
	}
	var sh serverHelloJSON
	if err := json.Unmarshal(respData, &sh); err != nil {
		return fmt.Errorf("handshake: invalid ServerHello (possible MITM): %w", err)
	}

	if sh.ProtoVersion == nil {
		// Server advertised legacy from the new path — surprising but possible
		// in the transitional window. Only fall back when TLS is verified.
		if c.insecureSkipVerify {
			return errors.New("handshake: legacy ServerHello received but fallback disabled (InsecureSkipVerify=true)")
		}
		return c.handshakeLegacy(ctx, hello, clientState)
	}
	if *sh.ProtoVersion > 1 {
		return fmt.Errorf("handshake: server requires proto v=%d, client supports v=1 (update required)", *sh.ProtoVersion)
	}

	return c.applyServerHello(clientState, &sh, 1)
}

// handshakeNew posts a padded ClientHello payload through the transport's raw
// handshake channel (D4). Returns the server body on 200 and a
// "HTTP Nxx:" / "HTTP 200-garbage:" error from the transport otherwise.
// Returns an error without side effects on Client state when the transport
// doesn't implement HandshakeRawSender — callers treat that as an HTTP 4xx
// and fall back to the legacy path.
func (c *Client) handshakeNew(ctx context.Context, hello *core.ClientHello) ([]byte, error) {
	raw, ok := c.transport.(HandshakeRawSender)
	if !ok {
		// Synthesize a 4xx so runHandshakeSequence triggers the fallback path.
		return nil, &httpStatusError{Status: 404, Body: "transport does not support raw handshake"}
	}
	pd := browser.NewPayloadDistribution()
	payload := browser.BuildHandshakePayload(hello.EphemeralPub, hello.EncryptedClientID, pd)
	return raw.SendHandshakeRaw(ctx, payload)
}

// handshakeLegacy sends the pre-migration handshake (no padding) and applies
// the resulting ServerHello with ProtoVersion pinned to 0.
func (c *Client) handshakeLegacy(ctx context.Context, hello *core.ClientHello, clientState *core.HandshakeClientState) error {
	respBody, err := c.transport.SendHandshake(ctx, hello)
	if err != nil {
		return fmt.Errorf("handshake legacy: %w", err)
	}
	respData, _, err := browser.ParseDownloadResponse(respBody)
	if err != nil {
		return fmt.Errorf("handshake legacy: invalid ServerHello (possible MITM): %w", err)
	}
	var sh serverHelloJSON
	if err := json.Unmarshal(respData, &sh); err != nil {
		return fmt.Errorf("handshake legacy: invalid ServerHello (possible MITM): %w", err)
	}
	// Legacy path ignores _v (may be absent or set by a hybrid server).
	return c.applyServerHello(clientState, &sh, 0)
}

// applyServerHello completes the crypto handshake, stores session+token on the
// Client, and pins ProtoVersion. protoVersion is the negotiated wire-format
// version — 1 for the new body-prefix path, 0 for legacy.
func (c *Client) applyServerHello(clientState *core.HandshakeClientState, sh *serverHelloJSON, protoVersion uint8) error {
	serverHello := &core.ServerHello{
		EphemeralPub:          sh.EphPub,
		EncryptedSessionToken: sh.Token,
		MaxConnsPerClient:     sh.MaxConns,
		ChunkSize:             sh.ChunkSize,
		// Thread `_v` through so CompleteHandshake picks the matching key schedule
		// (nil → v0, *v=1 → v1 body-prefix path).
		ProtoVersion: sh.ProtoVersion,
	}

	session, err := core.CompleteHandshake(clientState, serverHello)
	if err != nil {
		return fmt.Errorf("complete handshake: %w", err)
	}

	// D5: pin the negotiated wire version on the session itself so write-path
	// code can check Session.ProtoVersion without walking back to the client.
	session.ProtoVersion = protoVersion

	c.session = session
	c.token = browser.EncodeTokenWithHint(session.ID, sh.Token)
	c.maxConns = int(sh.MaxConns)
	c.chunkSize = int(sh.ChunkSize)
	if c.chunkSize == 0 {
		c.chunkSize = 12288
	}

	if sa, ok := c.transport.(SessionAware); ok {
		sa.SetSession(c.session)
		sa.SetSessionToken(c.token)
	}

	if len(sh.UA) > 0 {
		validUAs := make(map[string]string, len(sh.UA))
		for profile, ua := range sh.UA {
			if !isAllowedUAKey(profile) {
				// P2-2 T1 §219 — keys outside the closed enum are
				// dropped before value validation so binary-control-char
				// keys never reach UpdateUserAgents / log lines.
				slog.Warn("rejected UA from server: unknown profile key")
				continue
			}
			if !isValidUA(ua) {
				slog.Warn("rejected invalid UA from server", "profile", profile)
				continue
			}
			validUAs[profile] = ua
		}
		if len(validUAs) > 0 {
			browser.UpdateUserAgents(validUAs)
		}
	}

	slog.Info("connected to shadowlink server",
		"transport", c.transport.Name(),
		"max_conns", c.maxConns,
		"chunk_size", c.chunkSize,
		"proto_version", protoVersion)

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

	// D3 migration: UpgradeToWS now authenticates via a post-upgrade first
	// frame and needs the active session for encryption of that frame.
	session := c.Session()
	if session == nil {
		return nil, errors.New("not connected — call Connect() first")
	}
	if err := wst.UpgradeToWS(token, session); err != nil {
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

// Snapshot atomically returns the current token and session under a single
// c.mu acquisition. Use this when a caller needs both values consistent with
// each other — consecutive Token() / Session() calls would admit a race where
// Close() or the handshake reset nils one between the two loads, leaving the
// caller with a token referring to an already-destroyed session (H4, D4 review).
//
// Either return value may be nil on its own if the handshake hasn't completed
// yet; callers should check both. Callers MUST NOT retain the returned session
// pointer across a Close() or Reset call without independently validating it.
func (c *Client) Snapshot() (token []byte, session *core.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token, c.session
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

package client

import (
	"context"
	stdtls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
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
	wsScheme    string // "ws" or "wss" — used to rebuild dialURL per UpgradeToWS
	serverAddr  string
	sniHost     string // override TLS ServerName (for origin IP with domain SNI)
	cfIP        string // specific CF edge IP (TCP dial override, domain stays as TLS SNI)
	useTLS      bool
	skipVerify  bool
	urlPool     *browser.URLPool
	connManager *ConnManager // for initial HTTP handshake
	pd          *browser.PayloadDistribution

	// rlDetector — Phase 2.3 (2026-05-14): dual-carrier rate-limit detection
	// for WS upgrade response. Mirrors transport.go pattern — if CF strips
	// X-SL-RL header, body marker in the 200-decoy response still surfaces
	// the signal.
	//
	// NOTE: WS path uses `DetectCarriersOnly` (no lifeline) — any non-101
	// WS response returns HTML (CF middlebox, plain decoy, connection error),
	// so the HTML-body lifeline would fire on every generic failure causing
	// false-positive 90s cooldowns. Generic upgrade failures must surface
	// as ordinary errors with session-FIN, not as rate-limit. See
	// TestUpgradeToWS_NoXSLRLHeader_ReturnsGenericError for the invariant.
	rlDetector *RateLimitDetector

	mu          sync.Mutex
	writeMu     sync.Mutex // only used by SendChunk (legacy single-WS fallback, not ws_pool hot path)
	conn        *websocket.Conn
	asyncWriter *core.WSAsyncWriter // async egress queue, used by WriteMessage (ws_pool hot path)

	// Per-frame write deadline. Zero → WSAsyncWriter default (30s). For viaCF
	// mode this should be 5-8s: CF-side stalls propagate to us as TCP
	// backpressure and the default 30s means the slot freezes for 30s before
	// the pool can route around the bad edge. Cross-check 2026-04-15 H6.
	writeTimeout time.Duration

	// Bug #8 flow control negotiation (per-WS-conn). flowDesiredWindow > 0 means
	// the client advertises FLOWCTL in its first keepalive and synchronously
	// reads the server's ack in UpgradeToWS. flowControlEnabled/flowWindow are
	// set from that ack.
	flowDesiredWindow  uint32
	flowControlEnabled bool
	flowWindow         uint32

	// flowMigrateEnabled records whether Bug #9 stream migration was negotiated
	// for this WS connection (§3.5). It is set from the server's FLOWCTL-ack
	// (V2 marker, migrate bit) read synchronously in UpgradeToWS. False unless
	// BOTH sides advertised the capability — an old server that echoes a legacy
	// 11-byte marker (no migrate bit) leaves this false (backwards compat).
	flowMigrateEnabled bool
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
		wsScheme:    wsScheme,
		serverAddr:  serverAddr,
		useTLS:      useTLS,
		skipVerify:  skipVerify,
		urlPool:     browser.NewURLPool(),
		connManager: cm,
		pd:          browser.NewPayloadDistribution(),
		rlDetector:  DefaultDetector(&Stats),
	}
}

// pickDialURL builds the WS dial URL for one upgrade attempt. Call sites use
// this on every UpgradeToWS so reconnects do not reuse the previous path —
// that is the anti-correlation invariant from CRIT-4 in the 2026-04-25 audit.
//
// host argument: serverAddr by default; when sniHost is set we dial against
// the domain so gorilla emits the correct Host header (NetDialTLSContext
// then redirects the underlying TCP to the origin IP). The path comes from
// the shared compile-time pool (ws_paths.go).
func (t *WebSocketTransport) pickDialURL(host string) string {
	return fmt.Sprintf("%s://%s%s", t.wsScheme, host, pickWSPath())
}

// buildColdPathClient returns an *http.Client used for cold-path HTTPS
// (SendHandshake POST and WarmupRequests GETs). It shares the uTLS profile
// with UpgradeToWS so a passive observer sees a single JA3 across the
// pre-upgrade burst (CRIT-1/CRIT-2 in the 2026-04-25 audit).
//
// In useTLS=false mode (unit tests against an httptest server) we fall back
// to a stdlib client because there is no TLS to fingerprint.
// signalHost returns the host this transport presents to the server: the SNI
// override when set (origin-IP dialling with a domain SNI), otherwise the host
// part of the dial address.
//
// This is the value the server sees as its own Host, which is what both sides
// feed into core.DeriveRLPropertyID — so the per-host rate-limit marker only
// matches when this agrees with the server's view.
func (t *WebSocketTransport) signalHost() string {
	return core.SignalHost(t.sniHost, t.serverAddr)
}

func (t *WebSocketTransport) buildColdPathClient(fp *browser.Fingerprint, timeout time.Duration) *http.Client {
	if !t.useTLS {
		return &http.Client{Timeout: timeout}
	}
	return buildUTLSHTTPClient(t.serverAddr, t.signalHost(), fp, t.skipVerify, timeout, "http/1.1")
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

	// CRIT-1 (2026-04 audit): cold-path handshake POST must share the uTLS JA3
	// of the upcoming WS upgrade. Previously this used `&http.Client{}` (Go
	// stdlib JA3) seconds before UpgradeToWS sent Chrome 133 — a single passive
	// fingerprint logger could flag the inconsistency. Route through the same
	// uTLS dialer family used by UpgradeToWS / SplitTransport.
	fp := t.connManager.ActiveFingerprint()
	httpClient := t.buildColdPathClient(fp, 15*time.Second)
	defer httpClient.CloseIdleConnections()
	url := t.baseURL + t.urlPool.NextUploadPath()
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(io.Reader(newBytesReader(body)))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fp.UserAgent())
	req.Header.Set("Accept", "application/json")
	browser.ApplyChromeCHUAForFingerprint(req.Header, fp)

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
// This ensures the WebSocket TLS handshake (cold-path) has the same JA3
// fingerprint as the H2 SETTINGS handshake (hot-path, bogdanfinn).
//
// C4 (2026-06-09): now reads fp.Profile().UTLSHelloID so the cold-path
// ClientHello matches the selected browser profile. Prior to C4 this always
// returned LockedUTLSChromeID() — correct for Chrome-only fleets but wrong
// for any non-Chrome profile (Firefox UA + Chrome ClientHello = detectable
// cross-layer mismatch on the wire). Nil fingerprint falls back to Chrome 133.
func utlsProfileForFingerprint(fp *browser.Fingerprint) utls.ClientHelloID {
	if fp == nil {
		return browser.LockedUTLSChromeID()
	}
	return fp.Profile().UTLSHelloID
}

// chooseWarmupCount picks the warmup-burst length for a given RNG. Returns
// a value in [1, min(4, max)]. Exposed for ws_transport_warmup_test.go.
func chooseWarmupCount(rng *mrand.Rand, max int) int {
	if max <= 0 {
		return 0
	}
	cap := 4
	if max < cap {
		cap = max
	}
	return 1 + rng.Intn(cap)
}

// WarmupRequests sends 1-4 GET requests to cover paths before WebSocket
// upgrade. Mimics real browser behavior: user loads SDK assets / feature
// flags before opening WS. T1.6 randomizes both order (Fisher-Yates
// shuffle) and count so the burst signature varies across reconnects —
// without this, a passive observer sees the exact same 3-path GET burst
// every dial and fingerprints us by request order alone.
func (t *WebSocketTransport) WarmupRequests() {
	// CRIT-2 (2026-04 audit): warmup GETs are intended to look like a real
	// browser visiting the SPA before opening WS. Sending them with stdlib JA3
	// is *worse* than skipping warmup — the upcoming WS upgrade will use the
	// uTLS Chrome JA3, and the JA3 mismatch on the same flow is the cleanest
	// "this is not a real browser" signal a JA3 logger can capture. Pin the
	// uTLS dialer used by UpgradeToWS for these probes too.
	fp := t.connManager.ActiveFingerprint()
	ua := fp.UserAgent()
	client := t.buildColdPathClient(fp, 5*time.Second)
	defer client.CloseIdleConnections()

	// Shared cover/warmup pool — defaultCoverPaths (hand-curated SDK +
	// static-asset shapes) combined with dynamicCoverPaths (extracted
	// from a snapshot of the decoy origin via tools/extract_cover_paths).
	// Wave 3, 2026-05-17 (Task 3.1): broaden the prefix space and bring
	// it closer to NaiveProxy-style preambles where the warmup looks
	// indistinguishable from a real browser cold-start on that origin.
	paths := browser.CoverPathsPool()
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(paths), func(i, j int) { paths[i], paths[j] = paths[j], paths[i] })
	count := chooseWarmupCount(rng, len(paths))

	for i := 0; i < count; i++ {
		path := paths[i]
		url := t.baseURL + path
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		// Per-subresource Accept + Sec-Fetch-* set based on the path
		// extension (CSS/JS/image/fallback). MUST run before
		// ApplyChromeCHUAForFingerprint — the latter adds sec-ch-ua-*
		// but leaves Accept and Sec-Fetch-* untouched. Replaces the
		// previous one-size-fits-all `Accept: application/json,...`
		// which was a browser-class anomaly for the CSS/JS/image paths
		// the warmup pool draws from.
		applyChromeSubresourceHeaders(req, path)
		browser.ApplyChromeCHUAForFingerprint(req.Header, fp)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		// Read and discard body (like a real browser)
		io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		// Inter-request jitter: 50ms + rand[0..100]ms == [50ms, 150ms].
		// That's the spec's "100ms ± 50%" window expressed in linear form.
		delay := 50*time.Millisecond + time.Duration(rng.Intn(101))*time.Millisecond
		time.Sleep(delay)
	}
}

// UpgradeToWS establishes WebSocket connection and authenticates via a
// post-upgrade first-frame.
//
// D3 migration (2026-04): the session token used to ride in `Authorization:
// Bearer` on the upgrade request. Now the upgrade carries no auth-bearing
// header; instead, immediately after the 101 Switching Protocols response the
// client sends one binary frame containing [token][encrypted FlagKeepalive
// chunk] — the server's authenticateFirstFrame path (Phase C) validates it and
// completes the session.
//
// The session is required to produce the encrypted FlagKeepalive chunk that
// serves as the first frame.
//
// Uses uTLS for TLS handshake to match browser fingerprint (fixes detection
// via JA3 mismatch).
func (t *WebSocketTransport) UpgradeToWS(token []byte, session *core.Session) error {
	if session == nil {
		return fmt.Errorf("ws upgrade: nil session")
	}

	// Pre-compute the first frame BEFORE Dial so the WriteMessage fires within
	// a few ms of 101 — slow first frames are themselves a DPI signal and also
	// give the server's 1500ms auth timeout room to spare.
	firstFramePayload, err := t.buildFirstFramePayload(token, session, t.flowDesiredWindow)
	if err != nil {
		return fmt.Errorf("ws upgrade: first frame prep: %w", err)
	}

	fp := t.connManager.ActiveFingerprint()
	header := http.Header{}
	// D3: Authorization header removed — auth happens via the first WS frame.
	header.Set("User-Agent", fp.UserAgent())
	// 2026-05-02 wire-trigger followup NEW-2: Chrome WS Upgrade requests
	// emit sec-ch-ua headers same as regular HTTP. Their absence on a
	// connection that simultaneously presents a Chrome JA4 fingerprint is
	// a browser-class contradiction.
	browser.ApplyChromeCHUAForFingerprint(header, fp)

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
		// C4 cold-path lockstep (2026-06-11): MLKEM cold-path injection is gated
		// per-profile by PQKeyShare, not by family. chrome131/133 carry MLKEM
		// natively on both cold (utls) and hot (bogdanfinn) paths; chrome120 and
		// non-Chrome profiles keep their stock native key_share so cold stays
		// paired with hot.
		usePQ := pqEnabled() && fp != nil && fp.Profile().PQKeyShare
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

			// PQ branch (T1.1, Phase 2): when SHADOWLINK_TLS_PQ=1, derive a
			// custom spec with X25519MLKEM768 prepended into key_share +
			// supported_groups. Falls back to the helloID-based spec if the
			// PQ helper errors. Both branches end in the same ALPN patch +
			// ApplyPreset + Handshake. The fallback is also accounted for in
			// the prom counter so ops can spot a botched derive at scale.
			var spec utls.ClientHelloSpec
			pqApplied := false
			pqFellBack := false
			if usePQ {
				if pqSpec, pqErr := pqClientHelloSpec(helloID); pqErr == nil {
					spec = pqSpec
					pqApplied = true
				} else {
					pqFellBack = true
					hsSpec, specErr := utls.UTLSIdToSpec(helloID)
					if specErr != nil {
						tcpConn.Close()
						Stats.PQHandshakeError.Add(1)
						return nil, fmt.Errorf("uTLS spec: %w", specErr)
					}
					spec = hsSpec
				}
			} else {
				hsSpec, specErr := utls.UTLSIdToSpec(helloID)
				if specErr != nil {
					tcpConn.Close()
					return nil, fmt.Errorf("uTLS spec: %w", specErr)
				}
				spec = hsSpec
			}

			// Patch ALPN to http/1.1 only on whichever spec we picked.
			// WebSocket requires HTTP/1.1 — Chrome h2 ALPN makes nginx respond with HTTP/2 SETTINGS.
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
				if usePQ {
					Stats.PQHandshakeError.Add(1)
				}
				return nil, fmt.Errorf("uTLS apply: %w", err)
			}
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				tcpConn.Close()
				if usePQ {
					Stats.PQHandshakeError.Add(1)
				}
				return nil, fmt.Errorf("uTLS handshake: %w", err)
			}
			// PQ counter accounting: only ticks when usePQ is true so the
			// counter stays at zero in default builds.
			if usePQ {
				switch {
				case pqApplied:
					Stats.PQClientHelloSent.Add(1)
				case pqFellBack:
					Stats.PQHandshakeFallback.Add(1)
				}
			}
			return tlsConn, nil
		}
	} else {
		dialer.TLSClientConfig = &stdtls.Config{InsecureSkipVerify: skipVerify}
	}

	_ = serverAddr // used for logging if needed

	// SNI trick: use domain URL so gorilla sets correct Host header.
	// gorilla/websocket ignores header.Set("Host") — it takes Host from the URL.
	// NetDialTLSContext (above) redirects TCP to the origin IP regardless.
	//
	// CRIT-4 anti-correlation: the path component is drawn fresh from the
	// shared WS pool on every UpgradeToWS, including reconnects to the same
	// server. The pool entry is byte-identical to one of the server's
	// IsAllowedWSPath whitelist members; the server matches on r.URL.Path so
	// any query string in the chosen entry collapses to the bare path on
	// the receiving side.
	host := t.serverAddr
	if t.sniHost != "" {
		host = t.sniHost
	}
	dialURL := t.pickDialURL(host)

	conn, resp, err := dialer.Dial(dialURL, header)
	if err != nil {
		// Phase 2.3 (2026-05-14): dual-carrier rate-limit detection.
		// gorilla returns non-nil resp on non-101 status (rate-limit hit
		// produces 200+decoy). Try body marker → header carriers (no lifeline).
		// If CF stripped X-SL-RL but body has Schema.org marker, body carrier
		// catches it. Lifeline is intentionally skipped here: any rejected WS
		// upgrade returns a decoy HTML body; the lifeline would fire on every
		// CF middlebox / generic error, causing false-positive cooldowns. Only
		// genuine positive signals (Schema.org marker or X-SL-RL) trigger RL.
		// gorilla returns *net/http.Response directly — no type cast needed
		// (unlike transport.go which works with fhttp fork).
		if resp != nil {
			var bodyHead []byte
			if resp.Body != nil {
				bodyHead, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
			}
			detCtx := &DetectionContext{Response: resp, BodyHead: bodyHead, Path: "ws_upgrade", Host: t.signalHost()}
			if sig := t.rlDetector.DetectCarriersOnly(detCtx); sig != nil {
				// Counter increment lives in reconnectLoop (single decision
				// point) so upgrade-path + handshake-POST-path don't double-
				// count one event. No best-effort FIN here: server explicitly
				// told us to back off — cleanup happens via idle timeout.
				// Task D5 (cold-start metrics): tick decoy-received counter
				// at detection site — symmetric with transport.go SendHandshake.
				IncHandshakeDecoyReceived()
				return fmt.Errorf("ws upgrade: %w", &RateLimitError{Signal: sig})
			}
		}
		// C10 M5 (May audit, 2026-05-01): handshake POST already succeeded
		// (server has a session + tunnel attached), but the WS upgrade
		// failed mid-flight — without this signal the orphan session sits
		// for the full 5 min cleanup-loop window, and under cascade we
		// accumulate dozens of orphans per client. Fire-and-forget a
		// session-level FIN so the server can short-circuit cleanup.
		t.sendBestEffortSessionFIN(token, session)
		return fmt.Errorf("ws upgrade: %w", err)
	}

	// D3: send the authentication first frame immediately after 101 — target
	// <100ms. Server Phase C authenticateFirstFrame rejects anything that
	// doesn't arrive within its 1500ms timeout, so this write must not wait
	// on the async writer's queue.
	if err := conn.WriteMessage(websocket.BinaryMessage, firstFramePayload); err != nil {
		conn.Close()
		// C10 M5: same orphan-session theme as the Dial-fail branch above —
		// server-side authenticateFirstFrame won't complete the session, and
		// we'd otherwise leak it until the 5 min sweeper. Best-effort FIN.
		t.sendBestEffortSessionFIN(token, session)
		return fmt.Errorf("ws upgrade: first frame send: %w", err)
	}

	// Bug #8 §4.5: synchronously read the server's FLOWCTL-ack BEFORE starting
	// the async writer / slot reader. Only when we advertised a window — else
	// the wire path is unchanged. The slot reader starts only after UpgradeToWS
	// returns (connectSlot sets slotReady afterwards), so it won't race this read.
	if t.flowDesiredWindow > 0 {
		conn.SetReadDeadline(time.Now().Add(negotiationAckTimeout))
		ackType, ackData, ackErr := conn.ReadMessage()
		conn.SetReadDeadline(time.Time{})
		if ackErr == nil && ackType == websocket.BinaryMessage {
			if ackChunk, derr := session.DecryptChunkSafe(ackData); derr == nil && ackChunk.Flags == core.FlagAck {
				// Bug #9 §3.5: parse the V2 marker so we capture the server's
				// echoed migrate bit alongside the window. A legacy 11-byte ack
				// parses with migrate=false (backwards compat) — migration stays
				// off unless both sides agreed.
				if win, migrate, okFlow := core.ParseFlowCtlMarkerV2(ackChunk.Payload); okFlow {
					t.flowControlEnabled = true
					t.flowWindow = win
					t.flowMigrateEnabled = migrate
				}
			}
		}
		if !t.flowControlEnabled {
			Stats.FlowNegotiationTimeout.Add(1)
		}
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

// bestEffortSessionFINHook is a test seam: when non-nil it intercepts the
// fire-and-forget FIN POST in sendBestEffortSessionFIN. Production paths
// never assign this (it is checked but not set). Tests use it to observe
// the upgrade-fail FIN attempt without spinning up an HTTPS server.
var bestEffortSessionFINHook func(token []byte, session *core.Session, body []byte)

// bestEffortSessionFINTimeout caps the fire-and-forget POST. Two seconds is
// generous enough to cover one round-trip via CF CDN under healthy
// conditions, but short enough that a stuck POST does not pin a goroutine
// past the next reconnect attempt (reconnectLoop's slowest baseline is 5s).
const bestEffortSessionFINTimeout = 2 * time.Second

// negotiationAckTimeout is the deadline for reading the server's FLOWCTL-ack
// synchronously in UpgradeToWS. Kept short: if the server doesn't support
// flow control the read must not stall the upgrade path.
const negotiationAckTimeout = 500 * time.Millisecond

// migrateAckTimeout bounds how long the client waits for a MIGRATE_OK /
// RESUME_OK before degrading the stream to a hard break (F3 fail-safe,
// §3.5). Same order as the first-frame negotiation window so an old server
// that silently ignores FlagMigrate never hangs a stream.
const migrateAckTimeout = 1500 * time.Millisecond

// streamMigrationEnabledFromEnv resolves SHADOWLINK_STREAM_MIGRATION.
// Default ON; 0/false/no/off (case-insensitive) disables. Main kill-switch (§7).
func streamMigrationEnabledFromEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_STREAM_MIGRATION")))
	switch v {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// sendBestEffortSessionFIN fires a best-effort POST containing a FIN chunk
// for streamID=0 (session-level FIN semantic). C10 M5 (May audit,
// 2026-05-01): when the WS upgrade fails after a successful handshake POST,
// the server is left with an orphan session + tunnel until the 5 min
// cleanup loop sweeps it. Under reconnect cascade this accumulates dozens of
// orphans per client. Telling the server "this session will not attach"
// lets it cleanup immediately (or, on Group C M2 paths, fall back to a 30s
// timeout — either way better than 5 min).
//
// Contract:
//   - Fire-and-forget: returns immediately, dispatches in a fresh goroutine.
//   - Errors swallowed: server may reject (rate-limit, 404, decoy fall-through);
//     we log debug and move on. Reconnect flow MUST NOT block on this.
//   - Idempotent: if the encrypt/build path errors out, we silently drop.
//   - 2s timeout via context.WithTimeout — one round-trip cap.
//   - Test seam: bestEffortSessionFINHook intercepts the dispatch so unit
//     tests can observe the attempt without an HTTPS test server.
func (t *WebSocketTransport) sendBestEffortSessionFIN(token []byte, session *core.Session) {
	if session == nil || len(token) == 0 {
		return
	}

	// Build the FIN chunk synchronously so we capture the seq number BEFORE
	// returning to the caller — concurrent goroutines on the same session
	// must not collide on NextSeqNum() ordering.
	// Session-wide FIN (empty payload) so the server runs handleFin and releases
	// the session. NewStreamFinChunk(...,0) does NOT — its 2-byte streamID routes
	// to the per-stream branch and leaves the session to linger until idle
	// timeout (latent bug found alongside the pool ghost-session fix, 2026-05-29).
	fin := core.NewSessionFinChunk(session.ID, session.NextSeqNum())
	encrypted, err := session.EncryptChunk(fin)
	if err != nil {
		// Session may have been destroyed concurrently between handshake-OK
		// and WS-upgrade-fail (Close() zeros SendKey; sendEpochPtr.Load()
		// returns nil → fallback chunk.Encrypt sees empty key → AES-GCM
		// init fails). Soft-fail by contract: caller already accepted that
		// FIN may not arrive (server's 30s newborn-orphan sweeper handles
		// the fallback). Holistic review I-1 (2026-05-02 final P2 pack).
		slog.Debug("best-effort session FIN: encrypt failed (likely session destroyed)", "err", err)
		return
	}
	body, err := buildDataEnvelope(token, encrypted)
	if err != nil {
		slog.Debug("best-effort session FIN: envelope build failed", "err", err)
		return
	}

	// Test seam: intercept dispatch so the unit test can observe the POST
	// without standing up an HTTPS server keyed to the production uTLS
	// dialer. Production NEVER sets this — the variable stays nil.
	if hook := bestEffortSessionFINHook; hook != nil {
		hook(token, session, body)
		return
	}

	go t.dispatchBestEffortSessionFIN(body)
}

// dispatchBestEffortSessionFIN does the actual POST. Split out so tests
// that intercept via bestEffortSessionFINHook do not need to spin up a
// real cold-path client.
func (t *WebSocketTransport) dispatchBestEffortSessionFIN(body []byte) {
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("best-effort session FIN: dispatch panic", "panic", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), bestEffortSessionFINTimeout)
	defer cancel()

	fp := t.connManager.ActiveFingerprint()
	httpClient := t.buildColdPathClient(fp, bestEffortSessionFINTimeout)
	defer httpClient.CloseIdleConnections()

	url := t.baseURL + t.urlPool.NextUploadPath()
	req, err := http.NewRequestWithContext(ctx, "POST", url, newBytesReader(body))
	if err != nil {
		slog.Debug("best-effort session FIN: build request failed", "err", err)
		return
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fp.UserAgent())
	req.Header.Set("Accept", "application/json")
	browser.ApplyChromeCHUAForFingerprint(req.Header, fp)

	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Debug("best-effort session FIN: dispatch failed", "err", err)
		return
	}
	defer resp.Body.Close()
	// Drain (small) response body so the underlying TLS conn can be reused
	// or cleanly torn down — same etiquette as cover GET.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
	slog.Debug("best-effort session FIN sent", "status", resp.StatusCode)
}

// buildFirstFramePayload packs the session token followed by an encrypted
// FlagKeepalive chunk into the body-prefix wire format, which the server's
// authenticateFirstFrame path uses to validate the WS session post-upgrade.
// FlagKeepalive is chosen because it's semantically idempotent — the server
// rejects any other flag (Connect/Data/StreamOpen) on the first frame.
func (t *WebSocketTransport) buildFirstFramePayload(token []byte, session *core.Session, flowWindow uint32) ([]byte, error) {
	keepalive := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     core.FlagKeepalive,
	}
	if flowWindow > 0 {
		// Bug #9 §3.5: announce the migrate-capability bit in the same FLOWCTL
		// marker (V2). The extra byte is invisible to an old server's
		// ParseFlowCtlMarker (reads only the first 11 bytes), so this stays
		// backwards compatible. Migration is only ever negotiated alongside flow
		// control (the server echoes the bit in its FLOWCTL-ack).
		keepalive.Payload = core.BuildFlowCtlMarkerV2(flowWindow, streamMigrationEnabledFromEnv()) // inside AES-GCM (NH2)
	}
	encrypted, err := session.EncryptChunk(keepalive)
	if err != nil {
		return nil, err
	}
	return browser.BuildDataPayload(token, encrypted), nil
}

// parseFlowAckPayload reports whether a decrypted FlagAck chunk payload carries
// the server's FLOWCTL confirmation and returns the effective window.
func parseFlowAckPayload(payload []byte) (window uint32, ok bool) {
	return core.ParseFlowCtlMarker(payload)
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
	// distribution-realistic size.
	if len(data) < 80 {
		// A2-HIGH-7: padding distribution decoupled from PayloadDistribution
		// (independent log-normal in browser.SamplePaddingTarget). Do not re-couple.
		rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
		target := browser.SamplePaddingTarget(rng)
		data = browser.PadToSize(data, target)
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

// LastWriteUnixNano returns the wall-clock time (UnixNano) of the most recent
// successful frame write through the async writer, or zero if either no
// writer is active or no write has succeeded yet. Used by the slot reader's
// frame-anomaly diagnostic capture to compute `last_write_age_ms` so log
// reviewers can tell "read errored on an idle conn" from "read errored
// while writes were active".
func (t *WebSocketTransport) LastWriteUnixNano() int64 {
	t.mu.Lock()
	w := t.asyncWriter
	t.mu.Unlock()
	if w == nil {
		return 0
	}
	return w.LastWriteUnixNano()
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

// TryWriteControlMessage enqueues a control frame without blocking. Returns
// false if the async writer is absent or its control channel is full.
func (t *WebSocketTransport) TryWriteControlMessage(data []byte) bool {
	t.mu.Lock()
	w := t.asyncWriter
	t.mu.Unlock()
	if w == nil {
		return false
	}
	return w.TryEnqueueControl(websocket.BinaryMessage, data)
}

// StartReader runs the background WS message reader.
// Dispatches decrypted chunks to the client's stream router.
// Returns on WS error (caller should reconnect).
//
// C12 F5 (May audit, 2026-05-01): emits structured slog markers at every
// significant transition — enter, first-frame received, exit-with-reason —
// so a field log can answer "did the reader ever see traffic?" without
// invasive instrumentation. Counters live on the slot reader path
// (ws_pool.go); this function targets the single-WS / non-pooled fallback
// where ws_pool's diagnostics do not run.
//
// TODO(C12 F5 follow-up): under VPS throttle the WS reader can stall on
// `ReadMessage` even though the conn is half-alive. A poll-based fallback
// (open a separate GET stream and treat its bytes as a backup data path
// while keeping the WS open) would let us keep traffic flowing while the
// WS recovers. Plan §C12 F5 explicitly says trace-only for this milestone;
// implementing the fallback is deferred to a separate F-row.
func (t *WebSocketTransport) StartReader(ctx context.Context, cl *Client) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("ws reader panic: %v", r)
		}
	}()
	msgCount := 0
	errCount := 0
	startedAt := time.Now()
	var sessionID uint32
	if s := cl.Session(); s != nil {
		sessionID = s.ID
	}
	slog.Info("WS StartReader started",
		"sessionID", sessionID,
		"transport", "websocket",
	)
	for {
		select {
		case <-ctx.Done():
			slog.Info("WS StartReader stopped",
				"messages", msgCount,
				"errors", errCount,
				"reason", "ctx_done",
				"sessionAgeMs", time.Since(startedAt).Milliseconds(),
			)
			return ctx.Err()
		default:
		}

		// Use a 30s read deadline so we periodically check ctx.Done()
		// instead of blocking forever in ReadMessage.
		data, err := t.ReadMessage(30 * time.Second)
		if err != nil {
			// On timeout, check if context was cancelled — if so, return cleanly
			if ctx.Err() != nil {
				slog.Info("WS StartReader stopped",
					"messages", msgCount,
					"errors", errCount,
					"reason", "ctx_done_during_read",
					"sessionAgeMs", time.Since(startedAt).Milliseconds(),
				)
				return ctx.Err()
			}
			// Phase −1 hotfix mirror (2026-05-14): any read error is terminal.
			// Previously: on Timeout()==true we called continue, looping back to
			// ReadMessage. With gorilla/websocket v1.5.3 caching readErr (sticky),
			// this created a tight loop that triggered a defensive panic at ~1000
			// iterations. Same root cause as fixed in ws_pool.go (handleSlotDeath
			// path). Removing the `continue` lets the structured slog.Warn exit
			// path below handle all errors uniformly. Reader's caller will detect
			// the exit and trigger reconnect via existing transport-level logic.
			slog.Warn("WS StartReader stopped",
				"err", err,
				"messages", msgCount,
				"errors", errCount,
				"reason", "read_error",
				"sessionAgeMs", time.Since(startedAt).Milliseconds(),
			)
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

		// First-frame marker: useful in field logs to confirm the reader
		// is alive AND seeing real decrypted traffic, not just bytes that
		// failed decrypt. msgCount transitions 0→1 exactly once per reader
		// lifetime; later transitions are no-op.
		if msgCount == 0 {
			slog.Info("WS StartReader first frame",
				"sessionID", sessionID,
				"timeToFirstMs", time.Since(startedAt).Milliseconds(),
			)
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
		w.Close()     // signal Run() to stop
		<-w.RunDone() // wait for Run() to finish draining — prevents concurrent write with conn.Close()
	}
	if conn != nil {
		conn.Close()
	}
	return t.connManager.Close()
}

// bytesReader wraps []byte as io.Reader
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader { return &bytesReader{data: data} }
func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

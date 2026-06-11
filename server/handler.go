package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"math"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
	"golang.org/x/sync/errgroup"
)

// Handler processes authenticated ShadowLink requests.
// Unauthenticated requests fall through to the decoy site.
type Handler struct {
	serverKey    *core.KeyPair
	sessions     *core.SessionManager
	decoy        *DecoyHandler
	config       Config
	metrics      *Metrics
	rateLimiters *RateLimiters
	clientAuth   *ClientAuth
	udpRelay     *UDPRelay

	// flowMaxWindow caps the per-stream flow-control window the server grants
	// (Bug #8). 0 → server does not offer flow control. Default 1 MiB set in
	// NewHandler. Task 11 will expose this via Config.
	flowMaxWindow uint64

	// migrationEnabled gates Bug #9 stream migration server-side (§3.5). When
	// true the server echoes the client's advertised migrate capability back in
	// the FLOWCTL-ack (V2 marker) so both peers agree before any MIGRATE/RESUME
	// is attempted. Default true (set in NewHandler from Config.StreamMigrationEnabled
	// with a default-on fallback). The full env table lands in Task 18; for now
	// the field just carries the negotiated default. Read-only after construction.
	migrationEnabled bool

	// relayRegistry holds Bug #9 migratable per-stream relays keyed
	// (clientID, globalStreamID), living independently of any single WS
	// session so a relay survives slot migration (§5.1, F4). Constructed in
	// NewHandler; only populated on the migration CONNECT path. nil-safe is
	// NOT required — NewHandler always sets it.
	relayRegistry *relayRegistry

	// exemption caches recently-seen authenticated clientIDs and lets them
	// bypass the per-IP rate-limit bucket on the data path / subsequent
	// handshakes. Set once in NewHandler (default-on, opt out via
	// SHADOWLINK_RL_CLIENTID_EXEMPT=0/false/no/off); nil means feature
	// disabled. Read-only after construction — no mutex needed because
	// every handler-method dereference happens after the publish in
	// NewHandler returns. Plan §C4 (May audit, 2026-05-02).
	exemption *ClientIDExemption
	// replayCache rejects bit-for-bit handshake replays. Key is the entire
	// EncryptedClientID ciphertext (NaCl box nonce + sealed payload) — a
	// genuine replay reuses the captured ciphertext verbatim, so its 24-byte
	// CSPRNG nonce collides instantly. Legitimate parallel handshakes from
	// the same client (e.g., the WS pool minting fresh ClientHellos for each
	// of its 8 slots) generate distinct nonces, so they don't collide. Keying
	// on the decoded clientID — the previous design — silently broke the WS
	// pool because a 5-minute sliding window allowed only one handshake per
	// client. Used only by the new body-prefix handshake path.
	replayCache *core.ReplayCache

	// replayCacheMaxSize / replayCacheWindow expose the resolved replay-cache
	// parameters (Config.ReplayCacheMaxSize / Config.ReplayCacheWindow with
	// defaults applied) for diagnostics and tests. Audit A1-L6.
	replayCacheMaxSize int
	replayCacheWindow  time.Duration

	// For each session, incoming data is buffered and can be read by the tunnel.
	tunnels   map[uint32]*Tunnel
	tunnelsMu sync.RWMutex

	// safeDialFn is the dial function used by the WS CONNECT path.
	// Defaults to SafeDial; tests may inject a blocking or erroring dialer to
	// exercise cancel-on-done behaviour without touching the network.
	// Written once in NewHandler (or test setup) before any requests are
	// served — no synchronisation needed after publication.
	safeDialFn func(ctx context.Context, target string, timeout time.Duration) (net.Conn, error)

	// sentinelEmitter handles dual-carrier rate-limit responses (Schema.org
	// JSON-LD body marker + X-SL-RL header). Constructed at startup from
	// LoadDecoySnapshots; nil-safe — if nil, rate-limit branches degrade to
	// the legacy writeRateLimitSentinelV2 + failClosedToDecoy path.
	//
	// INVARIANT: Emit is called ONLY from the two rate-limit branches in
	// handleHandshakeNew and handleWebSocket. All other failClosedToDecoy
	// callers (auth_fail, replay_detected, malformed, max_clients, unauth_visitor)
	// must NOT use sentinelEmitter — Task 1.5 enforces this via test.
	//
	// Phase 1 (2026-05-14): set by Server.SetSentinelEmitter after construction.
	sentinelEmitter *SentinelEmitter
}

// StreamConn represents one multiplexed stream within a tunnel.
// Supports optimistic CONNECT: TargetConn may be nil while dial is in progress.
// Data arriving before dial completes is buffered in PendingBuf.
type StreamConn struct {
	StreamID   uint16
	TargetConn net.Conn
	mu         sync.Mutex
	PendingBuf [][]byte // data buffered while TargetConn==nil (optimistic CONNECT)
}

// Tunnel represents one client's bidirectional data channel with multiplexed streams.
type Tunnel struct {
	SessionID   uint32
	ClientID    string // "userID:deviceID" — used for OnSessionDestroyed cleanup
	Incoming    chan []byte
	Outgoing    chan []byte
	OutgoingUDP chan []byte   // UDP responses (separate to preserve FlagUDP in SplitHTTP download stream)
	done        chan struct{} // closed to signal all relays to stop
	closeOnce   sync.Once

	// HasDownloadStream is true when a SplitHTTP GET stream is active.
	// When true, handleDataChunk skips polling Outgoing (the download stream drains it).
	HasDownloadStream atomic.Bool

	// WSAttached is set via CAS by authenticateFirstFrame on the first WS
	// upgrade for this tunnel. A second WS attempt (regardless of token
	// validity) loses the CAS and is rejected via fakeAckAndClose. Audit
	// A3-S-HIGH-2 (2026-04-25): without this gate two transports can
	// race on the same session (POST + WS or WS + WS) and produce
	// non-deterministic CONNECT routing / seq-num exhaustion.
	WSAttached atomic.Bool

	mu      sync.Mutex
	streams map[uint16]*StreamConn

	targetConn net.Conn
	connected  bool
}

// closeTunnel signals all goroutines bound to this tunnel to exit.
// Idempotent (sync.Once-guarded). Audit A4-M5 (2026-04-25): closeTunnel
// historically also closed Incoming/Outgoing/OutgoingUDP, which races
// with concurrent senders that do `tunnel.Outgoing <- frame` in a
// select-arm — the runtime can pick the send-arm just as close() lands
// and panic with `send on closed channel`. The previous mitigation
// relied on `defer recover()` in every relay goroutine, which masks
// the symptom but still costs a stack unwind on every shutdown.
//
// Fix: only `done` is closed here. Senders are required to gate every
// `tunnel.Outgoing <- ...` with `<-tunnel.done` in a select; receivers
// either select on `tunnel.done` or rely on the data-path no longer
// producing once `done` fires. The data channels themselves drop into
// GC once all references are dropped — this is the standard Go idiom
// for "broadcast cancel" on multi-producer channels.
//
// See `safeSendToTunnel` in the test helpers for the canonical sender
// pattern; the structural race-detector test
// `TestConcurrentTunnelClose` (linux-only) exercises 32 producers
// against one closeTunnel call and asserts no panics.
func (t *Tunnel) closeTunnel() {
	t.closeOnce.Do(func() {
		close(t.done)
	})
}

// NewHandler creates a ShadowLink request handler.
func NewHandler(serverKey *core.KeyPair, config Config, decoyDir string) *Handler {
	// Handshake rate limit sized for WS pool reconnect bursts (pool=4-8 slots ×
	// cascade reconnects generate 20-50 handshakes/min per client IP). The old
	// 50/min cap forced the client into decoy fallback, so the default sits at
	// 300/min; the operator can override via Config.HandshakeRateLimitPerMin.
	// Data + WSUpgrade limits are protocol policy, set inside NewRateLimiters.
	//
	// Token-bucket path is active by default (SHADOWLINK_RL_TOKENBUCKET unset or
	// non-off). Opt out with SHADOWLINK_RL_TOKENBUCKET=0/false/no/off to fall
	// back to the legacy counter+window RateLimiter.
	//
	// A1-L6 (2026-04-25): ReplayCache size/window are operator-configurable.
	// Zero values fall back to the historical (10000, 5*time.Minute) tuning.
	replayMax := config.ReplayCacheMaxSize
	if replayMax <= 0 {
		replayMax = 10000
	}
	replayWindow := config.ReplayCacheWindow
	if replayWindow <= 0 {
		replayWindow = 5 * time.Minute
	}

	// Plan §C6 (May audit, 2026-05-02): rate-limit specs flow from
	// Config.RateLimit when set, with defensive defaults applied here so
	// existing deployments without YAML overrides keep working unchanged.
	// Handshake refill default falls back through Config.HandshakeRateLimitPerMin
	// (legacy field) before hitting the 300/min hardcode — preserves the
	// "raise the cap to 300" fix that NewRateLimiters originally encoded.
	hs := config.RateLimit.Handshake
	if hs.Burst <= 0 {
		hs.Burst = 50
	}
	if hs.RefillPerMin <= 0 {
		hs.RefillPerMin = config.HandshakeRateLimitPerMin
		if hs.RefillPerMin <= 0 {
			hs.RefillPerMin = 300
		}
	}
	ws := config.RateLimit.WSUpgrade
	if ws.Burst <= 0 {
		ws.Burst = 18
	}
	if ws.RefillPerMin <= 0 {
		ws.RefillPerMin = 30
	}

	// Plan §C4 (May audit, 2026-05-02): ClientID exemption. Default-on,
	// opt out via SHADOWLINK_RL_CLIENTID_EXEMPT=0. Cache parameters flow
	// from Config.RateLimit with the same zero-fallback pattern as the
	// rate-limit buckets above.
	var exempt *ClientIDExemption
	if useClientIDExemption() {
		exCap := config.RateLimit.ClientIDLruSize
		if exCap <= 0 {
			exCap = 10000
		}
		exTTL := time.Duration(config.RateLimit.ClientIDTTLMin) * time.Minute
		if exTTL <= 0 {
			exTTL = time.Hour
		}
		exSoft := config.RateLimit.ClientIDSoftLimit
		if exSoft <= 0 {
			exSoft = 60
		}
		exWin := time.Duration(config.RateLimit.ClientIDSoftWindowSec) * time.Second
		if exWin <= 0 {
			exWin = time.Minute
		}
		exempt = NewClientIDExemption(exCap, exTTL, exSoft, exWin)
	}

	h := &Handler{
		serverKey:          serverKey,
		sessions:           core.NewSessionManager(config.SessionTimeout),
		decoy: NewDecoyHandlerV2(DecoyHandlerConfig{
			DefaultDir:     decoyDir,
			DomainMap:      config.DomainDecoyMap,
			DomainPersona:  config.DomainPersonaMap,
			DefaultPersona: config.DefaultDecoyPersona,
		}),
		config:             config,
		metrics:            NewMetrics(),
		rateLimiters:       NewRateLimitersWithConfig(hs, ws, useTokenBucket()),
		clientAuth:         NewClientAuth(config.AuthorizedClients),
		udpRelay:           NewUDPRelay(60 * time.Second),
		replayCache:        core.NewReplayCache(replayMax, replayWindow),
		replayCacheMaxSize: replayMax,
		replayCacheWindow:  replayWindow,
		tunnels:            make(map[uint32]*Tunnel),
		exemption:          exempt,
		safeDialFn:         SafeDial,
		flowMaxWindow:      config.flowMaxWindowOrDefault(), // Bug #8 Task 11: from Config.FlowMaxWindow
		// migrationEnabled — Bug #9 §3.5: default-on, opt-out via Config/Task 18 env.
		migrationEnabled: config.streamMigrationEnabledOrDefault(),
		// relayRegistry — Bug #9 §5.1: holds migratable per-stream relays keyed
		// (clientID, globalStreamID) so they survive WS-slot migration (F4).
		relayRegistry: newRelayRegistry(),
	}

	// Bug #9 Task 12 (F5/F6) + Task 18 (§7): configure orphan DoS caps. An
	// orphaned relay holds a real egress socket through the grace window with no
	// WS behind it, so the caps bound that resource. Task 18 makes these
	// env/flag/YAML-tunable via Config (defaults 16 / 1024 from the §7 table);
	// Task 12 originally derived them from MaxConnsPerClient × MaxClients.
	//   per-client = Config.MaxOrphanedPerClient (default 16).
	//   total      = Config.MaxOrphanedTotal     (default 1024).
	//   fdBudget   = ~half the RLIMIT_NOFILE soft limit (orphans are transient;
	//     leave the other half for live sessions + listeners). On Windows dev
	//     readFDSoftLimit()==0 → fall back to `total` so the cap still applies.
	{
		perClient := config.maxOrphanedPerClientOrDefault()
		total := config.maxOrphanedTotalOrDefault()
		fdBudget := total
		if soft := readFDSoftLimit(); soft > 0 {
			fdBudget = int(soft / 2)
			if fdBudget < perClient {
				fdBudget = perClient // never below a single client's working set
			}
		}
		h.relayRegistry.setLimits(perClient, total, fdBudget)
	}
	h.relayRegistry.setOriginDeathTeardown(config.originDeathTeardownEnabledOrDefault())

	// Bug #9 Task 18 (§4.3): publish the registry to Metrics so the orphan series
	// (OrphanedRelaysActive gauge, orphan_fd_budget_rejected, orphaned_evicted_limit)
	// surface through the text/JSON exporters reading the registry's own counters —
	// a single source of truth, no duplicate count on the admit/evict hot paths.
	h.metrics.AttachRelayRegistry(h.relayRegistry)

	// CRIT-1 / LOW-4 (2026-06-11): wire nil-safe UDP-relay metric hooks. Set once
	// here, before StartCleanup/readLoop goroutines run, so the relay can read them
	// lock-free. onCapped ticks per amplification-cap drop; onReaped per idle reap.
	if h.udpRelay != nil {
		h.udpRelay.SetHooks(
			func() { h.metrics.UDPRespCapped.Add(1) },
			func() { h.metrics.UDPFlowsReaped.Add(1) },
		)
	}

	// Eagerly populate the asymmetric decoy fixture used by the
	// failClosedToDecoy timing pipeline so the first hot-path call does
	// not pay cold-RNG keypair-generation cost under sync.Once mutex —
	// final-audit-2026-05-05 Review 1 M-2.
	EnsureDecoyFixtureInitialized()

	return h
}

// Metrics returns the handler's metrics tracker.
func (h *Handler) Metrics() *Metrics {
	return h.metrics
}

// ackJitter returns a small randomized delay inserted before ACK-style responses
// (keepalive, padding, control, FIN ack, rejected seq_num). Rationale — 2026-04
// DPI audit V6: tunnel traffic shows a POST→<50ms ACK→POST pattern where the
// request-response graph is effectively deterministic. TSPU and ML-DPI use
// cross-layer timing (TLS vs TCP vs app) to fingerprint proxies even when the
// payload mimicry is good (Xue et al., NDSS 2025).
//
// Plan §C5 (P2, May 2026 audit, F7 finding): replaced hard 150ms cap + 18ms
// scale with 95%/5% mixture — exp(scale=7.21ms, median≈5ms, soft-cap 200ms)
// for the core + Pareto right-tail (α=2.0, xm=50ms, hard-ceil 1500ms) for the
// remaining 5%. The previous shape produced a point-mass at exactly 150ms
// (~5% of samples landed on the hard cap) — that's a unique p100 signature
// distinguishable from real CDN/nginx ACK distributions, which exhibit a
// heavy right tail well beyond 150ms but no hard ceiling.
//
// Calibration vs real CDN nginx ACK distribution deferred to Phase 5 / S5
// schema lock — current constants are best-guess preserving non-detectable
// shape (median in canonical p50 band, smooth body, heavy right tail).
//
// NOT applied to data-bearing responses (handleDataChunk has its own bimodal
// collection window — 10-30ms while idle, 300ms while a CDN poll fallback is
// active; see handler.go:885-890) or CONNECT results (latency-sensitive for
// SOCKS5 UX).
func ackJitter() time.Duration {
	// 5% → Pareto right-tail; 95% → exp core.
	if mathrand.Float64() < 0.05 {
		// Pareto inverse-CDF: xm * (1/U)^(1/α). xm=50ms, α=2.0 → median tail ≈ 70ms,
		// p99 ≈ 500ms, hard ceiling 1500ms. Cap U away from zero to avoid Inf.
		u := mathrand.Float64()
		if u < 1e-9 {
			u = 1e-9
		}
		d := time.Duration(50*math.Pow(1.0/u, 0.5)) * time.Millisecond
		if d > 1500*time.Millisecond {
			d = 1500 * time.Millisecond
		}
		return d
	}
	// Exp core: scale=7.21ms (median ≈ 5ms = 7.21·ln(2)).
	d := time.Duration(mathrand.ExpFloat64() * 7.21 * float64(time.Millisecond))
	if d > 200*time.Millisecond {
		d = 200 * time.Millisecond // soft cap on core; tail handled above
	}
	return d
}

// isJSONContentType reports whether the Content-Type header value identifies
// an `application/json` body, ignoring case and trailing parameters such as
// `; charset=utf-8`. Audit A3-S-HIGH-1 (2026-04-25): strict equality dropped
// charset-tagged or differently-cased variants to decoy and broke clients
// behind middleware that rewrites the header.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	// Strip parameters: take the part before ';'.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	// Trim whitespace inside the type/subtype slot (rare but RFC-allowed).
	ct = strings.TrimSpace(ct)
	return strings.EqualFold(ct, "application/json")
}

// setStandardHeaders sets response headers identical to the decoy handler.
// F2 fix: all responses (data, handshake, keepalive, control) must have the same
// headers as decoy to prevent oracle-based detection.
func setStandardHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// buildResponse wraps encrypted chunk in JSON. Uses inflated response if configured.
//
// T2.4 (Phase 3 Plan A § 4.4): when UseInflatedResponses is on, the inflated
// builder consults the session's sticky MimicrySession (Pareto next_poll
// lambda) to produce per-session-stable polling intervals. nil session →
// legacy uniform fallback inside BuildInflatedDownloadResponse.
func (h *Handler) buildResponse(session *core.Session, encrypted []byte, seqNum uint32) ([]byte, error) {
	if h.config.UseInflatedResponses {
		var mimicry *core.MimicrySession
		if session != nil {
			mimicry = session.MimicrySession
		}
		return browser.BuildInflatedDownloadResponse(encrypted, seqNum, mimicry)
	}
	return browser.BuildDownloadResponse(encrypted, seqNum)
}

// ServeHTTP routes requests after Phase A retire (2026-04-26):
//
//   - WebSocket upgrade           → handleWebSocket (first-frame auth)
//   - POST + application/json     → handleNewFormatPost (body-prefix only)
//   - everything else             → decoy
//
// Authorization-bearing requests (legacy Phase A clients) are no longer
// routed — they fall through to the same decoy timing/body distribution
// every other probe gets. There is no observable difference between
// "unauthenticated probe" and "stale legacy client" on the wire, which
// is the point: forcing a clean redeploy off legacy without leaking
// the migration seam to a passive observer.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// WebSocket upgrade for full-duplex relay (Phase 1b).
	if r.Header.Get("Upgrade") == "websocket" {
		h.handleWebSocket(w, r)
		return
	}

	// Non-POST / non-JSON → decoy. MED-3: don't log headers/paths — these
	// can accumulate forensic evidence on the hottest path on the server.
	//
	// A3-S-HIGH-1 (2026-04-25): match Content-Type by case-insensitive
	// prefix `application/json` so charset-tagged variants
	// ("application/json; charset=utf-8", "Application/JSON") reach the
	// dispatcher. Before this fix a CDN/middleware-rewritten Content-Type
	// would silently drop legit traffic to decoy. Anything that does NOT
	// look like JSON (text/plain, html, urlencoded, missing) still routes
	// to decoy without paying the failClosedToDecoy crypto cost.
	if r.Method != "POST" || !isJSONContentType(r.Header.Get("Content-Type")) {
		h.decoyWithTimingParity(w, r)
		return
	}

	// POST + JSON → body-prefix path. Authorization-bearing legacy POSTs
	// are not given a special branch; handleNewFormatPost rejects payloads
	// that don't match the body-prefix shape and falls back to decoy via
	// failClosedToDecoy (same timing/body shape as a probe).
	h.metrics.NewPathHits.Add(1)
	h.handleNewFormatPost(w, r)
}

// handshakeProfileFromUA derives a browser profile label ("chrome", "firefox",
// or "other") from a User-Agent string. Used for aggregate D2 (FP-mimicry)
// handshake-profile counters on the server — the label is derived locally from
// the request header and never stored in the session or any per-client LRU.
//
// Detection rules (order matters — Chrome UA strings also contain "Safari/"):
//   - "Chrome/" anywhere → "chrome"
//   - "Firefox/" anywhere → "firefox"
//   - anything else → "other"
func handshakeProfileFromUA(ua string) string {
	if strings.Contains(ua, "Chrome/") {
		return "chrome"
	}
	if strings.Contains(ua, "Firefox/") {
		return "firefox"
	}
	return "other"
}


// handleHandshakeNew serves a handshake on the Phase B body-prefix path.
// Phase 0 retire (2026-04-26): legacy 3-arg handleHandshake deleted.
// Differences from the retired legacy variant (history note):
//   - DeriveSessionKeys binds protoVersion=1 → v0 and v1 clients get
//     byte-different keys from the same ECDH share (downgrade defense).
//   - ReplayCache gates post-decrypt — a stolen captured handshake cannot be
//     re-submitted within the timestamp-bucket window.
//   - ServerHello carries ProtoVersion=1 (emitted as `_v`) so the client pins
//     the wire format for the session.
//
// Decoy fallbacks: all failure modes route through failClosedToDecoy so an
// attacker cannot distinguish rate-limit / backpressure / decrypt-failure /
// replay / auth failure from the wire.
func (h *Handler) handleHandshakeNew(w http.ResponseWriter, r *http.Request, ephPub, encClientID []byte) {
	// Rate limit per IP via the split Handshake limiter — sized for WS pool
	// reconnect bursts (see NewRateLimiters) so live sessions aren't starved
	// by an attacker flooding the handshake endpoint.
	clientIP := ClientIPFromRequest(r, h.config.BehindProxy)
	allow, remaining, retryAfter := h.rateLimiters.AllowHandshake(clientIP)
	// preCachedClientID carries the decrypted clientID across the escape-hatch
	// jump to `proceed:` so the normal-path DecryptClientID below is skipped
	// for exempt callers. Two motivations: (1) drop the redundant ~50µs op,
	// (2) keep the per-handshake decrypt count symmetric across exempt and
	// non-exempt paths (1 decrypt here + 1 inside HandleClientHelloWithVersion
	// either way) so timing-channel observers cannot fingerprint exemption
	// activity.
	var preCachedClientID []byte
	if allow {
		// Plan §C7 (May audit, 2026-05-02): gate returned true → token
		// actually withdrawn from the handshake bucket. Counted here so
		// the exemption fall-through below (which also reaches `proceed:`
		// without a token consume) does NOT double-count via this series.
		h.metrics.IncRatelimitBurstConsumed("handshake")
	}
	if !allow {
		// Plan §C4 (May audit, 2026-05-02): exemption escape hatch. Pay the
		// X25519 + box-decrypt cost (one shot) to recover a known clientID;
		// if it is in the exemption LRU, allow the subsequent handshake to
		// proceed without consuming a bucket token. This keeps WS-pool slot
		// reconnects flowing under cold-start cascades that would otherwise
		// trip the per-IP cap. First-handshake from a fresh clientID still
		// pays the bucket cost — exemption activates from the 2nd request
		// onward.
		if h.exemption != nil {
			if cid, dErr := core.DecryptClientID(encClientID, ephPub, h.serverKey); dErr == nil && h.exemption.IsExempt(cid) {
				if h.exemption.AllowExempted(cid) {
					h.metrics.IncRatelimitClientIDExempted()
					// Bucket bypass: cache the decrypted clientID so the
					// proceed path below skips the redundant decrypt. Wire
					// shape stays symmetric — both paths still feed exactly
					// one DecryptClientID call into HandleClientHelloWithVersion
					// downstream.
					preCachedClientID = cid
					goto proceed
				}
				// Soft-cap tripped: explicit "Exempt=1" sentinel.
				h.metrics.IncRatelimitClientIDSoftLimitRejected()
				h.failClosedToDecoyRateLimitedV2(w, r, RLSentinel{
					Bucket:    "handshake",
					BurstLeft: remaining,
					RefillIn:  retryAfter,
					Exempt:    1,
				})
				return
			}
		}
		slog.Warn("rate limited handshake (new)", "ip", clientIP)
		// Task A2 (May audit): rate-limit branch emits X-SL-RL sentinel so the
		// client applies a fixed per-bucket cool-down rather than the generic
		// exp backoff used for decrypt-fail / replay paths. C5 (2026-05-02)
		// upgraded the wire format to verbose key=value (bucket / burst_left /
		// refill_in / exempt). Exempt=0 here means the clientID was either
		// not exempt (first contact) or could not be decoded (malformed
		// ciphertext / wrong server key).
		//
		// Plan §C7 (May audit, 2026-05-02): true bucket-empty rejection —
		// counted here. Soft-cap branch above (exemption tried but tripped)
		// already owns its own series via IncRatelimitClientIDSoftLimitRejected.
		h.metrics.IncRatelimitBurstRejected("handshake")
		h.failClosedToDecoyRateLimitedV2(w, r, RLSentinel{
			Bucket:    "handshake",
			BurstLeft: remaining,
			RefillIn:  retryAfter,
			Exempt:    0,
		})
		return
	}
proceed:

	// Backpressure + max clients — identical gates to handleHandshake; decoy on reject.
	if _, rejectNew := h.metrics.BackpressureCheck(h.config.MaxConnsPerClient); rejectNew {
		h.metrics.RejectedOverload.Add(1)
		h.failClosedToDecoyWithReason(w, r, DecoyReasonBackpressure)
		return
	}
	if h.sessions.Count() >= h.config.MaxClients {
		h.metrics.RejectedOverload.Add(1)
		h.failClosedToDecoyWithReason(w, r, DecoyReasonMaxClients)
		return
	}

	// Decrypt client_id first (cheap in CPU terms; fails closed on tampered payloads).
	// Replay cache comes AFTER successful decrypt so random-bytes probes cannot
	// pollute the LRU — only real-looking handshakes consume a slot.
	//
	// Plan §C4 escape-hatch path already paid the decrypt cost above and stamped
	// preCachedClientID; reuse it instead of running the same NaCl-box op twice.
	// Decrypt failures on the exempt path are impossible here (we only stamped
	// the cache on dErr == nil), so the err-branch only runs for the normal
	// (non-exempt) path.
	clientHello := &core.ClientHello{EphemeralPub: ephPub, EncryptedClientID: encClientID}
	var clientID []byte
	if preCachedClientID != nil {
		clientID = preCachedClientID
	} else {
		var err error
		clientID, err = core.DecryptClientID(clientHello.EncryptedClientID, clientHello.EphemeralPub, h.serverKey)
		if err != nil {
			h.metrics.HandshakesFailed.Add(1)
			h.metrics.HandshakesAuthFailed.Add(1)
			h.failClosedToDecoyWithReason(w, r, DecoyReasonAuthFail)
			return
		}
	}

	// Key replay protection on the encrypted ClientID ciphertext, not the
	// decoded clientID. The 24-byte NaCl box nonce embedded in encClientID is
	// CSPRNG-fresh per handshake, so multiple legitimate handshakes from the
	// same client (WS pool warm-up) are accepted, while a captured-and-
	// resubmitted handshake reuses the exact ciphertext and is rejected.
	if !h.replayCache.Accept(encClientID, core.TimeNowUnix()) {
		h.metrics.HandshakesFailed.Add(1)
		h.metrics.HandshakesAuthFailed.Add(1)
		h.failClosedToDecoyWithReason(w, r, DecoyReasonReplayDetected)
		return
	}

	// A6 (2026-05-18): per-session chunk_size sampling. Pre-A6 every
	// session got the same chunk_size (12288 default) — data frames on
	// the wire formed a unimodal size distribution detectable as a
	// circumvention-tool signature. sampleChunkSize draws from
	// {6144, 8192, 10240, 12288} uniformly so the wire-shape histogram
	// gains four discrete peaks. Pinned per session via the ServerHello
	// response — client's connectSlot reads it into the slot transport.
	sampledChunkSize := sampleChunkSize(h.config.ChunkSize)
	serverHello, session, _, err := core.HandleClientHelloWithVersion(
		clientHello,
		h.serverKey,
		uint8(h.config.MaxConnsPerClient),
		sampledChunkSize,
		h.sessions,
		1, // protoVersion = 1 (new body-prefix format)
	)
	if err != nil {
		// Not AuthFailed: decrypt succeeded; failure is session-slot or internal error.
		h.metrics.HandshakesFailed.Add(1)
		h.failClosedToDecoyWithReason(w, r, DecoyReasonHandshakeFail)
		return
	}

	// Authz + device limit — mirror handleHandshake (W7 fix: destroy session on reject).
	if !h.clientAuth.IsAuthorized(string(clientID)) {
		h.metrics.HandshakesFailed.Add(1)
		h.metrics.HandshakesAuthFailed.Add(1)
		h.sessions.Remove(session.ID)
		h.failClosedToDecoyWithReason(w, r, DecoyReasonAuthFail)
		return
	}
	if !h.clientAuth.CheckDeviceLimit(string(clientID)) {
		// Not AuthFailed: authenticated client, rejected only by device quota.
		h.metrics.HandshakesFailed.Add(1)
		h.sessions.Remove(session.ID)
		h.failClosedToDecoyWithReason(w, r, DecoyReasonDeviceLimit)
		return
	}

	tunnel := &Tunnel{
		SessionID:   session.ID,
		ClientID:    string(clientID),
		Incoming:    make(chan []byte, 64),
		Outgoing:    make(chan []byte, defaultTunnelOutgoingBuffer),
		OutgoingUDP: make(chan []byte, 64),
		done:        make(chan struct{}),
	}
	h.tunnelsMu.Lock()
	h.tunnels[session.ID] = tunnel
	h.tunnelsMu.Unlock()

	h.clientAuth.OnSessionCreated(string(clientID), session.ID)
	// Plan §C4 (May audit, 2026-05-02): record this clientID in the
	// exemption LRU AFTER X25519 decrypt + auth + device-limit checks
	// pass. First handshake from a fresh clientID still pays the per-IP
	// bucket cost; subsequent data-path POSTs and reconnect handshakes
	// can bypass via IsExempt + AllowExempted (see exemption dance in
	// handleNewFormatPost / handleHandshakeNew bucket gate).
	if h.exemption != nil {
		h.exemption.MarkSeen(clientID)
	}
	h.metrics.HandshakesTotal.Add(1)
	h.metrics.HandshakesOK.Add(1)
	h.metrics.HandshakesNewTotal.Add(1)
	// D2 (FP-mimicry): aggregate handshake count by browser profile.
	// Profile derived locally from User-Agent header — NOT stored in session
	// or any per-client structure (privacy invariant).
	h.metrics.IncHandshakeProfile(handshakeProfileFromUA(r.Header.Get("User-Agent")))
	// MimicrySession is populated inside SessionManager.Create before publish
	// (Plan §C11.3, May 2026 audit) — no per-handler assignment needed.
	h.metrics.ActiveClients.Add(1)
	slog.Info("new session created (body-prefix)")

	v := uint8(1)
	serverHello.ProtoVersion = &v
	// C2 (FP-mimicry): embed fingerprint weights from server config so the client
	// can perform weighted profile selection matching this server's population model.
	// nil map (absent YAML section) is valid — client interprets as chrome 100%.
	serverHello.FingerprintWeights = h.config.FingerprintWeights
	responsePayload := encodeServerHello(serverHello)
	respBody, err := browser.BuildDownloadResponse(responsePayload, 0)
	if err != nil {
		// Should be unreachable — BuildDownloadResponse only fails on JSON errors
		// we control. Fall through to decoy to preserve wire cover.
		h.failClosedToDecoyWithReason(w, r, DecoyReasonInternal)
		return
	}

	// Mark the session as "handshake-attached" right before the response
	// flushes. Plan §C10 M2 originally tied AttachedAt to the WS first-frame,
	// but that semantic created a race: if the WS-upgrade rate-limit gate
	// rejected the subsequent upgrade attempt, the session stayed in newborn
	// state and got reaped by CleanupNewbornOrphans after 30s — producing
	// `orphan_session_cleaned` storms (351 in one 5-min test, 2026-05-18)
	// without any actual client-side abort. The new semantic is:
	//
	//   AttachedAt = "handshake completed successfully and the response is
	//                 about to be flushed to the client"
	//
	// CleanupNewbornOrphans now evicts only sessions whose handshake aborted
	// between Create() and this point (panic, validation reject, internal
	// error path returns). Sessions whose owner client failed AFTER the
	// handshake response was sent (incl. failed WS upgrade) fall under the
	// regular idle timeout policy via SessionManager.Cleanup — which is the
	// correct bucket: the session was reachable, the client just stopped
	// using it.
	session.AttachedAt.Store(time.Now().UnixNano())

	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

// sendAck writes an encrypted FlagAck chunk back to the client with the same
// ACK-path jitter applied to the seq-rejection and FIN ACK paths in handleData.
// Used by the Phase B routeDataChunk seq-num rejection branch and the FIN helper.
func (h *Handler) sendAck(w http.ResponseWriter, session *core.Session) {
	ackChunk := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     core.FlagAck,
	}
	encrypted, err := session.EncryptChunk(ackChunk)
	if err != nil {
		return
	}
	respBody, err := h.buildResponse(session, encrypted, ackChunk.SeqNum)
	if err != nil {
		return
	}
	time.Sleep(ackJitter())
	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

// handleFinChunk processes a FIN chunk: per-stream FIN when payload carries a
// StreamID, session-wide FIN otherwise. Mirrors the FlagFin branch of
// handleData; kept separate so routeDataChunk stays a thin switch.
func (h *Handler) handleFinChunk(w http.ResponseWriter, session *core.Session, chunk *core.Chunk) {
	if len(chunk.Payload) >= 2 {
		streamID := binary.BigEndian.Uint16(chunk.Payload[0:2])
		h.handleStreamFin(session, streamID)
	} else {
		h.handleFin(session)
	}
	h.sendAck(w, session)
}

// routeDataChunk dispatches a decrypted data chunk by Flags — the Phase B
// counterpart of the inline switch in handleData. Kept separate so both paths
// can evolve independently during migration; will converge once Phase A is
// removed (Phase 2 in the migration spec).
func (h *Handler) routeDataChunk(w http.ResponseWriter, r *http.Request, session *core.Session, chunk *core.Chunk) {
	if !session.AcceptSeqNum(chunk.SeqNum) {
		slog.Warn("rejected seq_num (new-path)", "seq", chunk.SeqNum, "flags", chunk.Flags)
		h.sendAck(w, session)
		return
	}
	switch chunk.Flags {
	case core.FlagData:
		h.handleDataChunk(w, session, chunk)
	case core.FlagPadding, core.FlagKeepalive:
		h.handleKeepalive(w, session)
	case core.FlagConnect:
		h.handleConnect(w, session, chunk)
	case core.FlagUDP:
		h.handleUDPData(w, session, chunk)
	case core.FlagControl:
		h.handleControl(w, session, chunk)
	case core.FlagFin:
		h.handleFinChunk(w, session, chunk)
	case core.FlagStreamOpen:
		// FlagStreamOpen carries no payload on the upload leg — it's a
		// signaling flag to "turn this POST's response body into a persistent
		// download stream". handleDownloadStreamV2 takes over the response
		// writer, disables write-timeout, and long-polls the tunnel's
		// Outgoing channel. It does NOT return a regular ACK; the stream
		// itself is the response.
		h.handleDownloadStreamV2(w, r, session)
	default:
		h.handleKeepalive(w, session)
	}
}

// handleNewFormatPost is the Phase B body-prefix dispatcher. Given a POST
// request body that may contain either an encrypted data chunk (with hint+token
// prefix) or a ClientHello for a new handshake, it chooses between them via:
//  1. Data path first — if the first `sessionTokenSize` bytes resolve via O(1)
//     findSessionByHint AND the trailing bytes decrypt as a valid chunk, route
//     the chunk. Tag verification (GCM) guarantees a wrong session's hint
//     collision (2^-32 space) fails closed without action.
//  2. Handshake fallback — if the payload is long enough to carry an X25519
//     ephemeral pub + EncryptedClientID (may be followed by padding), run the
//     new-version handshake.
//  3. Neither viable — fail closed to the decoy.
//
// B8 wires this into ServeHTTP. Standalone entry point so it can be unit-tested
// without touching the legacy dispatch.
func (h *Handler) handleNewFormatPost(w http.ResponseWriter, r *http.Request) {
	body, err := browser.ReadBodyLimited(r.Body, int64(h.config.ChunkSize+8192))
	if err != nil {
		h.failClosedToDecoyWithReason(w, r, DecoyReasonBodyInvalid)
		return
	}
	payload, err := browser.ParseUploadRequest(body)
	if err != nil {
		h.failClosedToDecoyWithReason(w, r, DecoyReasonBodyInvalid)
		return
	}

	tokenLen := h.sessionTokenSize()

	// Attempt 1: data path via O(1) hint lookup.
	// Pass the full [hint || encrypted_session_token] prefix (see B1 note): hint
	// alone cannot recover sid without the token's first 4 bytes.
	if len(payload) >= tokenLen+core.MinChunk {
		if session := h.findSessionByHint(payload[:tokenLen]); session != nil {
			encryptedChunk := payload[tokenLen:]
			if chunk, decErr := session.DecryptChunkSafe(encryptedChunk); decErr == nil {
				// Plan §C4 (May audit, 2026-05-02): exemption check runs
				// BEFORE the per-IP bucket consume so a trusted clientID
				// does not burn tokens on a path it has rights to skip.
				// First handshake from a fresh clientID still pays the
				// bucket cost (MarkSeen happens post-handshake-success);
				// the exemption activates from the second request onward.
				//
				// Soft-cap (AllowExempted) is intentionally NOT applied
				// on the data path. Soft-cap=60/min is sized for handshake
				// abuse protection (one clientID spinning up sessions);
				// applying it per-chunk caps sustained data throughput at
				// 60 chunks/min ≈ 12 KB/s with default 12 KB chunks —
				// unusable for VPN payload. The data path's protections
				// already include AES-GCM decrypt (proves session key
				// possession), session-manager device limits, and the
				// per-IP AllowData bucket on the non-exempt branch below.
				// An exempt clientID has paid for its trust at handshake
				// time and is allowed unrestricted data flow.
				// X1 Stage 2 follow-up (2026-05-03).
				clientIP := ClientIPFromRequest(r, h.config.BehindProxy)
				if h.exemption != nil {
					tunnelClientID := h.tunnelClientIDForSession(session.ID)
					if tunnelClientID != "" && h.exemption.IsExempt([]byte(tunnelClientID)) {
						h.metrics.IncRatelimitClientIDExempted()
						h.routeDataChunk(w, r, session, chunk)
						return
					}
				}

				// Normal path: rate limit the data path AFTER decrypt —
				// pre-decrypt limiting would let random-bytes probes
				// exhaust a legit session's budget. Valid-tag decrypt
				// proves the caller holds the session key.
				allowData, remaining, retryAfter := h.rateLimiters.AllowData(clientIP)
				if !allowData {
					// Data-bucket reject still emits the verbose
					// sentinel so the client can apply a per-bucket
					// cool-down rather than treating the decoy body
					// as a generic CDN failure.
					//
					// Plan §C7 (May audit, 2026-05-02): true bucket-empty
					// rejection. Exemption fast-path above already
					// returned without reaching here; soft-cap branch
					// owns its own series too — only non-exempt callers
					// hit this counter.
					h.metrics.IncRatelimitBurstRejected("data")
					h.failClosedToDecoyRateLimitedV2(w, r, RLSentinel{
						Bucket:    "data",
						BurstLeft: remaining,
						RefillIn:  retryAfter,
						Exempt:    0,
					})
					return
				}
				// Plan §C7 (May audit, 2026-05-02): token actually withdrawn
				// from the data bucket. Exemption fast-path bypasses this
				// (it returns inside the IsExempt branch above).
				h.metrics.IncRatelimitBurstConsumed("data")
				h.routeDataChunk(w, r, session, chunk)
				return
			}
		}
	}

	// Attempt 2: handshake path. Only v1 (Phase B body-prefix) layout is accepted:
	// 32-byte X25519 ephPub + fixed EncryptedClientIDSize. v0-fallback retired
	// in Phase 0 (2026-04-26) — pre-Phase-A binaries no longer accepted, payloads
	// shorter than v1HandshakeMin fall through to decoy with the same timing/body
	// shape as a probe (no observable difference on the wire).
	const v1HandshakeMin = 32 + core.EncryptedClientIDSize
	if len(payload) >= v1HandshakeMin {
		h.handleHandshakeNew(w, r, payload[:32], payload[32:v1HandshakeMin])
		return
	}

	// Layout not viable — decoy cover.
	h.failClosedToDecoyWithReason(w, r, DecoyReasonProtocolUnknown)
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
			streamCount := len(tunnel.streams)
			tunnel.mu.Unlock()
			if stream != nil && len(data) > 0 {
				// P2-9 fix (final audit 2026-05-03): copy TargetConn pointer
				// under stream.mu, release the mutex, THEN call Write. A slow
				// or congested target can stall Write up to streamWriteTimeout
				// (60s). Holding stream.mu across that window blocks every
				// other access to this stream — most importantly the CONNECT
				// activation path (handleConnect lines ~1265-1269 mutates
				// PendingBuf under the same mutex), causing cascading lock
				// contention. Mirrors the WS-side wsStream.Write pattern,
				// which only holds its mutex for buffer manipulation, not
				// for the underlying network IO.
				stream.mu.Lock()
				targetConn := stream.TargetConn
				if targetConn == nil {
					// Optimistic CONNECT: buffer data while dial is in progress
					if len(stream.PendingBuf) < 64 {
						cp := make([]byte, len(data))
						copy(cp, data)
						stream.PendingBuf = append(stream.PendingBuf, cp)
					}
					stream.mu.Unlock()
				} else {
					stream.mu.Unlock()
					// Write outside the lock — see P2-9 comment above.
					if _, err := targetConn.Write(data); err != nil {
						// M-1 fix (Review 2, 2026-05-05): error from targetConn.Write
						// was previously silently ignored. If the target closed between
						// stream.mu.Unlock() and Write, the packet is lost and the
						// stream leaks in the tunnel map. Close stream via the same
						// pattern as handleStreamFin: delete from map under tunnel.mu,
						// then close the conn to trigger relayStreamFromTarget exit.
						slog.Warn("targetConn.Write failed, closing stream",
							"stream_id", streamID, "err", err)
						tunnel.mu.Lock()
						delete(tunnel.streams, streamID)
						tunnel.mu.Unlock()
						targetConn.Close()
					} else {
						slog.Debug("data→target", "stream", streamID, "bytes", len(data), "activeStreams", streamCount)
					}
				}
			} else if stream == nil {
				slog.Warn("data for unknown stream", "stream", streamID, "bytes", len(data), "activeStreams", streamCount)
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

	// Collect outgoing data — batch multiple chunks per response to maximize throughput
	// through CDN (fewer HTTP round-trips = fewer chances for CF to throttle).
	// Each chunk is encrypted separately and placed in the JSON results array.
	//
	// CRITICAL: when download stream is active, do NOT poll Outgoing.
	// The download stream (chunked GET) delivers data at full speed.
	// Stealing data here would starve the download stream.
	const maxBatchChunks = 16
	const maxBatchBytes = 48 * 1024 // cap total response size
	var collectedChunks [][]byte    // raw data from tunnel.Outgoing
	var totalBytes int

	if ok && !tunnel.HasDownloadStream.Load() {
		tunnel.mu.Lock()
		hasAnyConn := len(tunnel.streams) > 0 || tunnel.connected
		tunnel.mu.Unlock()

		// 300ms for active connections (CDN poll fallback needs large batches).
		// 10-30ms for idle (legacy/non-CDN direct mode).
		waitTime := time.Duration(10+mathrand.IntN(20)) * time.Millisecond
		if hasAnyConn {
			waitTime = 300 * time.Millisecond
		}

		timer := time.NewTimer(waitTime)
		select {
		case data := <-tunnel.Outgoing:
			timer.Stop()
			collectedChunks = append(collectedChunks, data)
			totalBytes += len(data)
			// Drain more data without blocking (up to maxBatchChunks).
			for len(collectedChunks) < maxBatchChunks && totalBytes < maxBatchBytes {
				select {
				case more := <-tunnel.Outgoing:
					collectedChunks = append(collectedChunks, more)
					totalBytes += len(more)
				default:
					goto done
				}
			}
		case <-timer.C:
		}
	}
done:

	if len(collectedChunks) == 0 {
		// No data — send empty response (single empty chunk).
		respChunk := &core.Chunk{
			SessionID: session.ID,
			SeqNum:    session.NextSeqNum(),
			Flags:     core.FlagData,
		}
		encrypted, err := session.EncryptChunk(respChunk)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		h.metrics.ChunksSent.Add(1)
		respBody, _ := h.buildResponse(session, encrypted, respChunk.SeqNum)
		setStandardHeaders(w)
		w.WriteHeader(200)
		w.Write(respBody)
		return
	}

	// Encrypt each collected chunk separately.
	encryptedChunks := make([][]byte, 0, len(collectedChunks))
	for _, data := range collectedChunks {
		respChunk := &core.Chunk{
			SessionID: session.ID,
			SeqNum:    session.NextSeqNum(),
			Flags:     core.FlagData,
			Payload:   data,
		}
		encrypted, err := session.EncryptChunk(respChunk)
		core.PutBuffer(data) // return pooled buffer after encryption
		if err != nil {
			continue
		}
		encryptedChunks = append(encryptedChunks, encrypted)
	}

	h.metrics.ChunksSent.Add(uint64(len(encryptedChunks)))
	h.metrics.BytesSent.Add(uint64(totalBytes))

	var respBody []byte
	if len(encryptedChunks) == 1 {
		// Single chunk — use standard response (backward compatible with old clients).
		// Note: seqNum param is unused by buildResponse (uses random ID), but passing 0
		// to avoid wasting a seq_num from NextSeqNum() — the chunk already has its own.
		respBody, _ = h.buildResponse(session, encryptedChunks[0], 0)
	} else {
		// Multiple chunks — batch in results array.
		respBody, _ = browser.BuildDownloadResponseMulti(encryptedChunks)
	}
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
	respBody, _ := h.buildResponse(session, encrypted, ackChunk.SeqNum)

	// V6: break deterministic POST→ACK timing signal.
	time.Sleep(ackJitter())
	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

// handleDownloadStreamV2 is the Phase B body-prefix download stream entry
// point. The caller (routeDataChunk on FlagStreamOpen) has already resolved
// the session through findSessionByHint + DecryptChunkSafe, so auth
// extraction is skipped. Phase 0 retire (2026-04-26): legacy
// handleDownloadStream (GET + Authorization variant) deleted. The streaming
// loop in runDownloadStreamLoop is the single shared body.
//
// Behavior notes:
//
//   - Session is passed in — no Authorization header lookup.
//   - The priming frame carries a 100-500B random payload ("synthetic
//     preamble") instead of empty FlagAck. This gives CF an immediate first
//     byte that's already content-shaped, shortening the open→first-byte gap
//     and matching real streaming analytics responses.
//
// Everything downstream — keepalive, Outgoing/OutgoingUDP drain, teardown —
// is shared via runDownloadStreamLoop.
func (h *Handler) handleDownloadStreamV2(w http.ResponseWriter, r *http.Request, session *core.Session) {
	h.tunnelsMu.RLock()
	tunnel, ok := h.tunnels[session.ID]
	h.tunnelsMu.RUnlock()
	if !ok {
		h.failClosedToDecoyWithReason(w, r, DecoyReasonInternal)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.failClosedToDecoyWithReason(w, r, DecoyReasonInternal)
		return
	}

	if !tunnel.HasDownloadStream.CompareAndSwap(false, true) {
		slog.Warn("download stream v2: duplicate rejected")
		h.failClosedToDecoyWithReason(w, r, DecoyReasonStreamDuplicate)
		return
	}
	defer tunnel.HasDownloadStream.Store(false)

	writeStreamHeaders(w, flusher)
	slog.Info("download stream v2 started (body-prefix)")

	frameBuf := make([]byte, 4+32*1024)
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(60 * time.Second)); err != nil {
		slog.Debug("stream v2: SetWriteDeadline unsupported", "err", err)
	}

	// Synthetic preamble: 100-500B random bytes in a FlagAck frame. CF sees
	// immediate first-byte content that looks like analytics payload.
	preambleLen := 100 + mathrand.IntN(400)
	preamble := make([]byte, preambleLen)
	_, _ = crand.Read(preamble)
	if err := writeFrame(w, flusher, session, core.FlagAck, preamble, frameBuf); err != nil {
		slog.Warn("download stream v2: preamble write error", "err", err)
		return
	}

	h.runDownloadStreamLoop(w, r, session, tunnel, frameBuf)
}

// writeStreamHeaders configures the streaming response headers that keep CF
// and nginx from buffering. Matches XHTTP/Xray-core exactly — confirmed to
// stream without buffering through CF. Content-Encoding and
// X-Content-Type-Options MUST NOT be set here or CF will buffer.
func writeStreamHeaders(w http.ResponseWriter, flusher http.Flusher) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
}

// streamWriteTimeout is the body-write deadline applied on every loop
// iteration of runDownloadStreamLoop. Audit S-MED-3 (2026-04-25): the
// deadline must dwarf the worst-case ackJitter() cap (1500 ms — Pareto
// right-tail hard ceiling, set by C5 mixture reshape 2026-05-02) by
// enough margin that an in-flight ACK-path write cannot collide with the
// timeout. 60 s also exceeds Go's default WriteTimeout (30 s), which
// would otherwise kill the long-poll stream from underneath us. The
// invariant is structurally pinned by
// `TestDownloadStreamLoop_DeadlineExceedsMaxAckJitter`.
const streamWriteTimeout = 60 * time.Second

// runDownloadStreamLoop is the shared select-loop body of the two download
// stream paths. The caller must have: written streaming headers, acquired
// tunnel.HasDownloadStream, sent the path-specific priming frame, and
// verified flusher. Blocks until ctx cancels, tunnel closes, or Outgoing
// drains. Owns the 25s keepalive ticker and per-write deadline extension.
func (h *Handler) runDownloadStreamLoop(w http.ResponseWriter, r *http.Request, session *core.Session, tunnel *Tunnel, frameBuf []byte) {
	flusher, _ := w.(http.Flusher) // caller has already verified
	rc := http.NewResponseController(w)
	ctx := r.Context()

	extendDeadline := func() {
		rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	}

	msgCount := 0
	// Log-normal jittered keepalive (~25s, sigma=0.5) — destroys
	// FFT-visible periodic peak at 25s that a fixed-period ticker would
	// expose AND defeats ML classifiers that detect flat-band uniform
	// jitter via KS-test against a log-normal reference. Final-audit
	// 2026-05-03 P0-1 (T2 REGRESSION) shipped uniform ±30% server-side;
	// P1-3 upgrades recurring tickers to heavy-tailed log-normal.
	keepaliveTimer := time.NewTimer(core.JitteredIntervalLogNormal(25*time.Second, 0.5))
	defer keepaliveTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("download stream ended (client disconnect)", "messages", msgCount)
			return
		case <-tunnel.done:
			slog.Info("download stream ended (tunnel closed)", "messages", msgCount)
			return
		case data, ok := <-tunnel.Outgoing:
			if !ok || data == nil {
				slog.Info("download stream ended (channel closed)", "messages", msgCount)
				return
			}
			extendDeadline()
			if err := writeFrame(w, flusher, session, core.FlagData, data, frameBuf); err != nil {
				slog.Warn("download stream write error", "err", err, "messages", msgCount)
				core.PutBuffer(data)
				return
			}
			core.PutBuffer(data)
			msgCount++
			if msgCount <= 20 || msgCount%50 == 0 {
				slog.Info("download frame sent", "msg", msgCount, "bytes", len(data),
					"outgoingLen", len(tunnel.Outgoing))
			}

		case udpData := <-tunnel.OutgoingUDP:
			if udpData == nil {
				continue
			}
			extendDeadline()
			if err := writeFrame(w, flusher, session, core.FlagUDP, udpData, frameBuf); err != nil {
				slog.Warn("download stream UDP write error", "err", err)
				core.PutBuffer(udpData)
				return
			}
			msgCount++

		case <-keepaliveTimer.C:
			extendDeadline()
			// Empty FlagAck frame — writeFrame handles encryption + length prefix
			// + flush uniformly with the data/udp arms.
			if err := writeFrame(w, flusher, session, core.FlagAck, nil, frameBuf); err != nil {
				slog.Warn("download stream keepalive write error", "err", err)
				return
			}
			slog.Debug("download stream keepalive sent", "messages", msgCount)
			// Re-arm with fresh log-normal jittered interval so successive
			// keepalives don't accidentally fall back into a fixed-period
			// rhythm. P1-3: heavy-tailed sampling defeats ML KS-test
			// classifiers that uniform jitter would still trigger.
			keepaliveTimer.Reset(core.JitteredIntervalLogNormal(25*time.Second, 0.5))
		}
	}
}

// writeFrame encrypts data and writes a length-prefixed binary frame to the download stream.
// Single Write call + Flush — matches XHTTP/Xray-core pattern that works through CF CDN.
// frameBuf is a pre-allocated buffer to avoid per-frame allocations.
func writeFrame(w http.ResponseWriter, flusher http.Flusher, session *core.Session, flag byte, data []byte, frameBuf []byte) error {
	chunk := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     flag,
		Payload:   data,
	}
	encrypted, err := session.EncryptChunk(chunk)
	if err != nil {
		return nil // skip, don't kill stream
	}
	// Build frame: 4-byte length prefix + encrypted data — in one buffer, one Write.
	frameLen := 4 + len(encrypted)
	if frameLen > len(frameBuf) {
		frameBuf = make([]byte, frameLen)
	}
	binary.BigEndian.PutUint32(frameBuf[0:4], uint32(len(encrypted)))
	copy(frameBuf[4:], encrypted)
	if _, err := w.Write(frameBuf[:frameLen]); err != nil {
		return err
	}
	flusher.Flush()
	return nil
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
		slog.Warn("CONNECT: empty target", "payloadLen", len(chunk.Payload))
		h.sendConnectResult(w, session, nil, streamID, "CONNECT_FAIL")
		return
	}

	h.tunnelsMu.RLock()
	tunnel, ok := h.tunnels[session.ID]
	h.tunnelsMu.RUnlock()
	if !ok {
		slog.Warn("CONNECT: tunnel not found", "target", target)
		h.sendConnectResult(w, session, nil, streamID, "CONNECT_FAIL")
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
			h.sendConnectResult(w, session, tunnel, streamID, "CONNECT_FAIL")
			return
		}
	}

	// Optimistic CONNECT: register stream entry BEFORE dial so incoming data
	// is buffered (not dropped). Mirrors WS path behavior.
	tunnel.mu.Lock()
	if tunnel.streams == nil {
		tunnel.streams = make(map[uint16]*StreamConn)
	}
	if len(tunnel.streams) >= maxStreamsPerSession {
		tunnel.mu.Unlock()
		h.sendConnectResult(w, session, tunnel, streamID, "CONNECT_FAIL")
		return
	}
	stream := &StreamConn{StreamID: streamID} // TargetConn=nil — pending state
	tunnel.streams[streamID] = stream
	tunnel.mu.Unlock()

	// A3-S-HIGH-3 (2026-04-25): bind the dial context to tunnel.done so
	// that closeTunnel during a slow CONNECT cancels the in-flight dial
	// instead of leaking a goroutine for the full 10s timeout. The
	// dialer goroutine + select-arm pattern gives us a hard upper bound
	// on dial-cancel latency irrespective of OS-level connect timeouts.
	dialCtx, cancelDial := context.WithCancel(context.Background())
	defer cancelDial()
	go func() {
		select {
		case <-tunnel.done:
			cancelDial()
		case <-dialCtx.Done():
		}
	}()

	conn, err := SafeDial(dialCtx, target, 10*time.Second)
	if err != nil {
		tunnel.mu.Lock()
		delete(tunnel.streams, streamID)
		tunnel.mu.Unlock()
		// If the dial was canceled by tunnel.done, the channel is gone —
		// sending CONNECT_FAIL via session.Encrypt is harmless but the
		// response writer may already be detached. sendConnectResult
		// handles writer-aborted cases via Write returning an error.
		h.sendConnectResult(w, session, tunnel, streamID, "CONNECT_FAIL")
		return
	}

	// Race window: if tunnel.done closed AFTER SafeDial returned but
	// BEFORE we wire the relay goroutine, the cleanup loop in
	// runDownloadStreamLoop / Cleanup could race with the relay setup.
	// The activate path below safely no-ops on a closed tunnel because
	// tunnel.mu serializes streams map writes and relayStreamFromTarget
	// always exits on tunnel.done. We keep this comment as the audit
	// pin for future reviewers.

	// Activate: set target conn, flush buffered data
	stream.mu.Lock()
	stream.TargetConn = conn
	pending := stream.PendingBuf
	stream.PendingBuf = nil
	stream.mu.Unlock()
	for _, data := range pending {
		conn.Write(data)
	}

	// Legacy compat
	if streamID == 0 {
		tunnel.mu.Lock()
		tunnel.targetConn = conn
		tunnel.mu.Unlock()
	}
	tunnel.mu.Lock()
	tunnel.connected = true
	tunnel.mu.Unlock()

	// Per-stream relay: target → tunnel.Outgoing (tagged with StreamID)
	go h.relayStreamFromTarget(session, tunnel, streamID, conn)

	h.sendConnectResult(w, session, tunnel, streamID, "CONNECT_OK")
}

// sendConnectResult sends CONNECT_OK or CONNECT_FAIL to the client.
// Always returns in the POST response body (reliable delivery).
// CF may buffer or kill the download stream — CONNECT results must not depend on it.
func (h *Handler) sendConnectResult(w http.ResponseWriter, session *core.Session, tunnel *Tunnel, streamID uint16, result string) {
	// Always send in POST response body — guaranteed delivery even if download stream is dead.
	chunk := core.NewDataChunk(session.ID, session.NextSeqNum(), []byte(result))
	encrypted, _ := session.EncryptChunk(chunk)
	respBody, _ := h.buildResponse(session, encrypted, chunk.SeqNum)
	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

// relayStreamFromTarget reads from a specific stream's target and tags data with StreamID.
// CRIT-4 fix: must check tunnel.done BEFORE sending to tunnel.Outgoing to avoid
// panic from send on closed channel (closeTunnel closes both done and Outgoing).
func (h *Handler) relayStreamFromTarget(session *core.Session, tunnel *Tunnel, streamID uint16, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in relayStreamFromTarget", "stream", streamID, "error", r)
		}
	}()
	// Clean up stream when relay exits (target closed, tunnel done, or error).
	// Without this, streams accumulate in tunnel.streams until maxStreamsPerSession
	// is hit and ALL new CONNECTs are rejected.
	defer func() {
		conn.Close()
		tunnel.mu.Lock()
		delete(tunnel.streams, streamID)
		remaining := len(tunnel.streams)
		tunnel.mu.Unlock()
		slog.Debug("stream removed", "stream", streamID, "remaining", remaining)
	}()
	buf := core.GetBuffer(16384)
	defer core.PutBuffer(buf)
	totalBytes := 0
	chunks := 0
	for {
		select {
		case <-tunnel.done:
			slog.Info("relay exit: tunnel done", "stream", streamID, "totalBytes", totalBytes)
			return
		default:
		}
		// V4: read into a randomized prefix to spread downstream chunk
		// sizes instead of clustering on the 16 KB boundary.
		limit := core.NextReadSize()
		if limit > len(buf) {
			limit = len(buf)
		}
		n, err := conn.Read(buf[:limit])
		if n > 0 {
			tagged := core.GetBuffer(2 + n)
			tagged = tagged[:2+n]
			binary.BigEndian.PutUint16(tagged[0:2], streamID)
			copy(tagged[2:], buf[:n])
			select {
			case tunnel.Outgoing <- tagged:
				totalBytes += n
				chunks++
				if chunks <= 5 || chunks%50 == 0 {
					slog.Info("relay→Outgoing", "stream", streamID, "bytes", n,
						"totalBytes", totalBytes, "chunks", chunks, "chanLen", len(tunnel.Outgoing))
				}
			case <-tunnel.done:
				core.PutBuffer(tagged)
				slog.Info("relay exit: tunnel done", "stream", streamID, "totalBytes", totalBytes)
				return
			}
		}
		if err != nil {
			slog.Info("relay exit: target closed", "stream", streamID, "totalBytes", totalBytes, "chunks", chunks, "err", err)
			return
		}
	}
}

func (h *Handler) handleControl(w http.ResponseWriter, session *core.Session, chunk *core.Chunk) {
	// Control chunks handle rekeying, chunk_size negotiation, etc.
	// Respond with proper encrypted FlagAck chunk — bare JSON causes client parse errors.
	h.handleKeepalive(w, session)
}

// handleUDPData processes a FlagUDP chunk: relays UDP data to the target via UDPRelay.
func (h *Handler) handleUDPData(w http.ResponseWriter, session *core.Session, chunk *core.Chunk) {
	streamID, targetAddr, data, err := core.ParseUDPChunk(chunk.Payload)
	if err != nil {
		h.handleKeepalive(w, session)
		return
	}
	if h.udpRelay == nil {
		h.handleKeepalive(w, session)
		return
	}

	h.tunnelsMu.RLock()
	tunnel, ok := h.tunnels[session.ID]
	h.tunnelsMu.RUnlock()
	if !ok {
		h.handleKeepalive(w, session)
		return
	}

	// X-2 fix: SSRF protection for UDP targets — resolve hostname first to prevent DNS rebinding
	udpHost := targetAddr
	if uh, _, err := net.SplitHostPort(targetAddr); err == nil {
		udpHost = uh
	}
	if isBlockedDomain(udpHost, h.config.BlockDomains) {
		slog.Debug("blocked domain UDP target", "addr", targetAddr)
		h.handleKeepalive(w, session)
		return
	}
	// Resolve hostname to IP to prevent DNS rebinding bypassing isPrivateIP
	resolvedAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		slog.Debug("failed to resolve UDP target", "addr", targetAddr, "error", err)
		h.handleKeepalive(w, session)
		return
	}
	if isPrivateIP(resolvedAddr.IP) {
		slog.Debug("blocked private UDP target", "addr", targetAddr, "resolved", resolvedAddr.IP)
		h.handleKeepalive(w, session)
		return
	}
	// Use the resolved IP:port to prevent TOCTOU DNS rebinding
	resolvedTarget := resolvedAddr.String()

	h.udpRelay.Send(session.ID, streamID, resolvedTarget, data, func(response []byte) {
		if tunnel.HasDownloadStream.Load() {
			// SplitHTTP: push raw UDP payload to OutgoingUDP channel.
			// Download stream reads from it separately and sends with FlagUDP.
			udpPayload := core.BuildUDPChunkPayload(streamID, targetAddr, response)
			select {
			case tunnel.OutgoingUDP <- udpPayload:
			case <-tunnel.done:
			}
			return
		}
		// Classic poll mode: encrypt and queue.
		respChunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, response)
		encrypted, err := session.EncryptChunk(respChunk)
		if err != nil {
			return
		}
		select {
		case tunnel.Outgoing <- encrypted:
		case <-tunnel.done:
		default:
		}
	})

	// Collect any pending outgoing data (same pattern as handleDataChunk).
	// Skip when SplitHTTP download stream is active — it drains Outgoing.
	var responsePayload []byte
	if ok && !tunnel.HasDownloadStream.Load() {
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
	// Fix: release pooled buffer after encryption (prevents pool memory leak).
	if responsePayload != nil {
		core.PutBuffer(responsePayload)
	}
	if err != nil {
		w.WriteHeader(500)
		return
	}
	respBody, _ := h.buildResponse(session, encrypted, respChunk.SeqNum)
	setStandardHeaders(w)
	w.WriteHeader(200)
	w.Write(respBody)
}

// handleStreamFin closes a single multiplexed stream (target conn + remove from map).
// Sent by client when SOCKS5 connection closes — prevents stream leak.
func (h *Handler) handleStreamFin(session *core.Session, streamID uint16) {
	h.tunnelsMu.RLock()
	tunnel, ok := h.tunnels[session.ID]
	h.tunnelsMu.RUnlock()
	if !ok {
		return
	}
	tunnel.mu.Lock()
	sc := tunnel.streams[streamID]
	delete(tunnel.streams, streamID)
	remaining := len(tunnel.streams)
	tunnel.mu.Unlock()
	if sc != nil && sc.TargetConn != nil {
		sc.TargetConn.Close() // triggers relayStreamFromTarget exit
	}
	// C1b (2026-06-11): tear down any UDP flow bound to this stream so the NAT
	// entry + socket don't leak after the stream FINs.
	if h.udpRelay != nil {
		h.udpRelay.RemoveFlow(session.ID, streamID)
	}
	slog.Debug("stream FIN", "stream", streamID, "remaining", remaining)
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
	// C1b (2026-06-11): a dead session must not leave UDP sockets/NAT entries.
	if h.udpRelay != nil {
		h.udpRelay.RemoveSession(session.ID)
	}
	h.sessions.Remove(session.ID)
	h.metrics.ActiveClients.Add(-1)
}

// sessionTokenSize is the fixed wire-format length of [4B hint][encrypted_session_token].
// Encrypted session token = AES-GCM(nonce(12) + session_id(4) + tag(16)) = 32 bytes.
// Total = 4 + 32 = 36. Must be updated if encryptSessionToken format changes.
func (h *Handler) sessionTokenSize() int {
	return 4 + (12 + 4 + 16) // hint + nonce + session_id + GCM tag
}

// findSessionByHint does O(1) session lookup via the 4-byte XOR hint prefix.
//
// Input layout: [hint(4)] || [encrypted_session_token(>=16)] — exactly the
// format produced by browser.EncodeTokenWithHint on the client. The hint is
// XOR(session_id, first_4_bytes(encrypted_token)); combined with the token's
// first 4 bytes it unambiguously recovers the session ID for a direct map
// lookup, then the encrypted token's GCM tag is verified against the session's
// keys. Returns nil on length mismatch, unknown session, or tag failure.
//
// Used by the body-prefix dispatch path (handleNewFormatPost, WS first-frame
// auth, handleDownloadStreamV2). The Phase A legacy O(N) header-based fallback
// (findSession) was retired alongside the WS Bearer auth path (2026-04-26).
func (h *Handler) findSessionByHint(tokenBytes []byte) *core.Session {
	if len(tokenBytes) < 20 {
		return nil
	}
	hint := tokenBytes[:4]
	token := tokenBytes[4:]
	if len(token) < 4 {
		return nil
	}
	var xorMask [4]byte
	copy(xorMask[:], token[:4])
	sid := binary.BigEndian.Uint32(hint) ^ binary.BigEndian.Uint32(xorMask[:])

	s, ok := h.sessions.Get(sid)
	if !ok {
		return nil
	}
	// A1-H2 (2026-04-26): only the rolling/recv key seals session tokens.
	// `encryptSessionToken` uses session.RecvKey on the server side; the
	// send key path is algebraically dead (would only match on a 2^-256
	// collision). Removing the second branch halves the per-probe AES
	// key-schedule cost and shrinks the side-channel surface on the
	// hottest hint-resolve path. See findSessionByHint contract test
	// `TestFindSessionByHint_OnlyUsesRollingKey`.
	_, rk := s.Keys() // copy under lock (use-after-destroy fix)
	if verifySessionToken(token, s.ID, rk) {
		return s
	}
	return nil
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

// tunnelClientIDForSession returns the authenticated clientID stamped on the
// tunnel for the given session, or "" if no tunnel exists yet (newborn
// session whose handshake POST committed but whose data path/WS attach has
// not landed). Used by the §C4 exemption dance in handleNewFormatPost +
// handleHandshakeNew so the exemption lookup keys on the same clientID
// that NewClientHello/HandleClientHelloWithVersion authenticated.
func (h *Handler) tunnelClientIDForSession(sessionID uint32) string {
	h.tunnelsMu.RLock()
	defer h.tunnelsMu.RUnlock()
	t, ok := h.tunnels[sessionID]
	if !ok {
		return ""
	}
	return t.ClientID
}

// broadcastCloseConcurrency caps the parallelism inside BroadcastStreamClose.
// Sized to keep peak goroutines bounded for 10k tunnels (worst-case fleet size
// captured by the master spec exit criterion) while saturating the per-tunnel
// per-deadline budget. T1.7 (Phase 2, 2026-04-26).
const broadcastCloseConcurrency = 256

// broadcastCloseTotalDeadline bounds the wall-clock cost of one
// BroadcastStreamClose invocation. Combined with the per-tunnel 50ms select
// deadline, this guarantees graceful shutdown's drain phase never blocks the
// outer 30s shutdown budget for an unreasonable amount of time.
const broadcastCloseTotalDeadline = 5 * time.Second

// broadcastClosePerTunnelDeadline replaces the legacy 100ms serial deadline.
// At limit=256 concurrency a 50ms slice over 10k tunnels is bounded by
// (10000/256) * 50ms ≈ 2s — under the master spec SLA.
const broadcastClosePerTunnelDeadline = 50 * time.Millisecond

// defaultTunnelOutgoingBuffer is the per-tunnel Outgoing channel capacity.
// Sized so a single FlagFin enqueue from BroadcastStreamClose never blocks
// on the happy path. Production code and tests reference this constant to
// keep the buffer size in lockstep.
const defaultTunnelOutgoingBuffer = 256

// BroadcastStreamClose enqueues an encrypted FlagFin chunk to every active
// tunnel's Outgoing channel so clients reconnect immediately instead of
// waiting out their read-timeout on the next handshake. Used by the graceful
// shutdown path to drain active sessions in under a second rather than the
// SessionTimeout default.
//
// The `reason` is included as the payload so client logs can distinguish
// "server maintenance" from "session expiry" in the field.
//
// Bounded-parallel via errgroup (T1.7, Phase 2, 2026-04-26): the previous
// serial loop was 100ms × N, i.e. ~16 min for N=10k. The errgroup variant
// completes well under the master-spec SLA (<2s for 10k tunnels) at peak
// goroutine count = broadcastCloseConcurrency + small monitor baseline.
//
// Per-tunnel: still non-blocking — if a tunnel's Outgoing is full or the
// per-tunnel/total deadline trips we skip it, increment the dropped-reason
// counter, and move on. Client still gets the TCP FIN when the listener
// closes a beat later.
func (h *Handler) BroadcastStreamClose(reason string) int {
	start := time.Now()

	h.tunnelsMu.RLock()
	tunnels := make([]*Tunnel, 0, len(h.tunnels))
	for _, t := range h.tunnels {
		tunnels = append(tunnels, t)
	}
	h.tunnelsMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), broadcastCloseTotalDeadline)
	defer cancel()

	var enqueued atomic.Int64
	// Plain errgroup.Group (not WithContext): per-tunnel branches always
	// return nil, so we don't need cancellation-on-error. The outer ctx is
	// the only abort signal we care about and it's threaded into the select
	// below explicitly.
	var eg errgroup.Group
	eg.SetLimit(broadcastCloseConcurrency)

	for _, t := range tunnels {
		t := t
		eg.Go(func() error {
			session, ok := h.sessions.Get(t.SessionID)
			if !ok {
				return nil
			}
			chunk := &core.Chunk{
				SessionID: t.SessionID,
				SeqNum:    session.NextSeqNum(),
				Flags:     core.FlagFin,
				Payload:   []byte(reason),
			}
			encrypted, err := session.EncryptChunk(chunk)
			if err != nil {
				return nil
			}
			// Per-tunnel timer is reused via time.NewTimer so we don't
			// leak inside the bounded goroutine pool. Go 1.23+ made
			// timer.Stop() safe even on already-fired timers (the runtime
			// no longer keeps a reference into timer.C), so a plain
			// defer timer.Stop() is sufficient — no manual drain needed.
			timer := time.NewTimer(broadcastClosePerTunnelDeadline)
			defer timer.Stop()
			select {
			case t.Outgoing <- encrypted:
				enqueued.Add(1)
			case <-t.done:
				// Tunnel already closed (concurrent shutdown / FIN). After
				// A4-M5 closeTunnel no longer closes Outgoing, so the send
				// arm above is safe regardless — but biasing toward done
				// avoids enqueuing a chunk into a tunnel whose readers are
				// already gone (no leak, just wasted work).
				h.metrics.broadcastCloseDroppedDone.Add(1)
			case <-timer.C:
				// Channel full — skip. Shutdown-scoped deadline: we can't
				// hang waiting for a slow client during a drain.
				h.metrics.broadcastCloseDroppedTimeout.Add(1)
			case <-ctx.Done():
				// Total broadcast deadline exceeded — bail to keep the outer
				// 30s shutdown budget intact even on pathological fleets.
				h.metrics.broadcastCloseDroppedCtxCancel.Add(1)
			}
			return nil
		})
	}
	eg.Wait() // join; per-tunnel branches never return an error

	h.metrics.observeBroadcastCloseDrain(time.Since(start))
	return int(enqueued.Load())
}

// SessionCount returns the number of active sessions.
func (h *Handler) SessionCount() int {
	return h.sessions.Count()
}

// newbornOrphanMaxAge bounds how long a session may remain in the
// "handshake completed, transport never attached" state before §C10 M2
// (May 2026 audit) evicts it. The legacy idle-timeout cleanup runs at the
// 5-minute scale, which left orphan tunnels accumulating when a client
// failed between handshake POST OK and WS upgrade success. 30s is large
// enough to absorb worst-case CF→origin RTT + WS handshake + TLS
// renegotiation, small enough to keep the orphan footprint tiny.
const newbornOrphanMaxAge = 30 * time.Second

// detachedGhostGrace is how long an attached session may stay DETACHED (its WS
// reader exited) before the server ghost-sweep reclaims it. MUST be >= the Bug#9
// migration grace window (migrateGracePeriod, default 8s) so a session a stream
// is RESUMING onto is never reclaimed mid-migration — the gate
// (ghostSweepEligible) ALSO refuses while a relay is still bound, but the grace
// is the coarse first line so a re-adopting reconnect/RESUME has time to clear
// DetachedAt before the sweep even considers the session. 15s gives comfortable
// margin over the 8s orphan window while still draining ghosts ~20× faster than
// the 5-min idle timeout (the source of active_clients=18 in
// docs/sl-burst2-freeze-analysis.md §3). Server ghost-sweep, 2026-06-01.
const detachedGhostGrace = 15 * time.Second

// ghostSweepEligible is the eviction gate for CleanupDetachedGhosts. It returns
// true only when session `id` is safe to reclaim: NO live WS transport is
// attached (WSAttached==false) AND no orphaned relay is still bound to it (no
// stream is mid-RESUME). The Bug#9-coexistence constraint lives here — a session
// a stream is migrating onto must survive until its relay's grace expires.
func (h *Handler) ghostSweepEligible(id uint32) bool {
	sess, ok := h.sessions.Get(id)
	if !ok {
		return false // already gone — nothing to sweep
	}
	h.tunnelsMu.RLock()
	t, ok := h.tunnels[id]
	h.tunnelsMu.RUnlock()
	if !ok {
		// No tunnel: the session has no relay state to migrate and no live
		// transport. Safe to reclaim (the bare session is the pure ghost).
		return true
	}
	if t.WSAttached.Load() {
		return false // a transport re-attached — not a ghost
	}
	if t.ClientID != "" && h.relayRegistry.hasBoundEntriesForSession(t.ClientID, sess) {
		return false // an orphaned relay is still bound — a stream may RESUME
	}
	return true
}

// reapOrphanTunnels removes tunnel state for sessions evicted by the
// newborn-orphan fast path. Mirrors the post-Cleanup reap logic but
// keyed by the explicit eviction list rather than a presence check.
func (h *Handler) reapOrphanTunnels(ids []uint32) {
	if len(ids) == 0 {
		return
	}
	h.tunnelsMu.Lock()
	defer h.tunnelsMu.Unlock()
	for _, id := range ids {
		tunnel, ok := h.tunnels[id]
		if !ok {
			continue
		}
		if tunnel.ClientID != "" {
			h.clientAuth.OnSessionDestroyed(tunnel.ClientID, id)
		}
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

// StartCleanup runs periodic session cleanup in the background.
func (h *Handler) StartCleanup(stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(h.config.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// M6 fix: clean up rate limiter maps alongside sessions
				h.rateLimiters.Cleanup()

				// CRIT-1 (2026-06-11): reap idle UDP flows so the NAT map +
				// FDs don't grow unbounded. Mirrors rateLimiters.Cleanup().
				if h.udpRelay != nil {
					h.udpRelay.Cleanup()
				}

				// Plan §C10 M2 (May 2026 audit): fast-path eviction for
				// newborn-not-attached sessions. Runs BEFORE the regular
				// idle Cleanup so an orphan never lingers past the 30s
				// grace window even if its lastActivity is fresh
				// (handshake bumped it).
				orphanIDs := h.sessions.CleanupNewbornOrphans(time.Now(), newbornOrphanMaxAge)
				if n := len(orphanIDs); n > 0 {
					h.metrics.OrphanSessionCleaned.Add(uint64(n))
					h.reapOrphanTunnels(orphanIDs)
					slog.Debug("newborn orphan cleanup", "evicted", n)
				}

				// Server ghost-sweep (2026-06-01 pool-capacity-dip-fix): reclaim
				// ATTACHED sessions whose WS transport detached (TSPU age-cut)
				// past detachedGhostGrace, gated so a session a stream is RESUMING
				// onto (Bug#9 orphan window) is never reclaimed mid-migration.
				// Runs after the newborn sweep, before the coarse idle Cleanup —
				// the same reapOrphanTunnels teardown frees the matching tunnels.
				ghostIDs := h.sessions.CleanupDetachedGhosts(time.Now(), detachedGhostGrace, h.ghostSweepEligible)
				if n := len(ghostIDs); n > 0 {
					h.metrics.GhostSessionSwept.Add(uint64(n))
					h.reapOrphanTunnels(ghostIDs)
					slog.Debug("ghost session sweep", "swept", n)
				}

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
							// C1b (2026-06-11): reap UDP flows of the removed session.
							if h.udpRelay != nil {
								h.udpRelay.RemoveSession(id)
							}
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
//
// Wire shape (post Phase A Bearer retire, 2026-04-26):
// `handleNewFormatPost` is the sole production caller and ALWAYS supplies a
// non-nil ProtoVersion — `_v` is emitted, `_deprecated` stays false. The
// `Deprecated` field + `ProtoVersion == nil` branch are kept structurally
// (server-side type stability + legacy-path regression test in
// handler_test.go:667) but never tick on the wire from a real production
// handshake. Removing them is tracked as Open Question §5 in
// `shadowlink/docs/strategy/2026-05-03-final-audit/T4-quality-drift.md`
// pending verification that no fielded client still reads `_deprecated`.
func encodeServerHello(sh *core.ServerHello) []byte {
	// UA update mechanism: server sends current browser UA strings
	// so clients stay up-to-date without code changes.
	data, _ := json.Marshal(struct {
		EphPub       []byte            `json:"eph"`
		Token        []byte            `json:"tok"`
		MaxConns     uint8             `json:"mc"`
		ChunkSize    uint16            `json:"cs"`
		ProtoVersion *uint8            `json:"_v,omitempty"`
		Deprecated   bool              `json:"_deprecated,omitempty"`
		UA           map[string]string `json:"ua,omitempty"`
		FW           map[string]int    `json:"fw,omitempty"` // fingerprint weights
	}{
		EphPub:       sh.EphemeralPub,
		Token:        sh.EncryptedSessionToken,
		MaxConns:     sh.MaxConnsPerClient,
		ChunkSize:    sh.ChunkSize,
		ProtoVersion: sh.ProtoVersion,
		Deprecated:   sh.ProtoVersion == nil, // legacy path → mark deprecated
		FW:           sh.FingerprintWeights,
		UA: map[string]string{
			// Chrome UA mirrors browser.LockedChromeUA() (Chrome/133) so the
			// server-issued client config stays consistent with the four
			// wire surfaces.
			//
			// 2026-05-05: non-Chrome fingerprints retired (TSPU блокирует
			// Safari/Firefox/Edge). Из map выкинуты "safari" и "firefox" —
			// клиент и так теперь принимает только chrome (см.
			// allowedUAKeys в client/client.go), но не отдаём лишнего в JSON.
			"chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		},
	})
	return data
}

func httpPlaceholderRequest() *http.Request {
	r, _ := http.NewRequest("GET", "/", nil)
	return r
}

// TestEnqueueDownstream is a test-only hook that pushes one raw (pre-encryption)
// payload onto the given session's tunnel.Outgoing channel. The handler's normal
// dispatch (handleDataChunk) drains Outgoing, runs session.EncryptChunk on each
// element, and writes the resulting envelope in the POST response — same path a
// real relay→client flow would take.
//
// EXPORTED ONLY FOR INTEGRATION TESTS. Production code must NOT call this: it
// bypasses the relay→Outgoing backpressure checks in handler.go:1337/1393 and
// the tunnel.done guard. The method name carries the `Test` prefix so that
// grep + code review readers can spot misuse.
//
// Semantics:
//   - Returns false if no tunnel exists for sessionID (e.g. session destroyed
//     or never created).
//   - Returns false if the Outgoing channel is full (cap=256) — the send is
//     non-blocking to avoid deadlocking a test that forgot to drain.
//   - Returns true on successful enqueue.
//
// The payload []byte MUST remain alive until handleDataChunk reads it (the
// drain path calls core.PutBuffer on it afterwards; PutBuffer silently
// discards buffers whose cap doesn't match a pool tier, so a plain
// `make([]byte, N)` with non-tier N is safe to inject).
func (h *Handler) TestEnqueueDownstream(sessionID uint32, payload []byte) bool {
	h.tunnelsMu.RLock()
	tunnel, ok := h.tunnels[sessionID]
	h.tunnelsMu.RUnlock()
	if !ok {
		return false
	}
	select {
	case tunnel.Outgoing <- payload:
		return true
	default:
		return false
	}
}

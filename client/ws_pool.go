package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	mrand "math/rand"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// ErrRateLimited — see ratelimit_signal.go for the canonical declaration.
// Callers use errors.Is; the typed sentinel is now shared across the carrier
// chain (Phase 2.1) and the legacy header detection path.
//
// Task A2 (May audit, 2026-05-01). Moved to ratelimit_signal.go (Phase 2.1).
//
// Note: kept as a doc comment only — the var lives in ratelimit_signal.go.

// slotRateLimitedCooldown returns the wait duration applied by reconnectLoop
// when connectSlot surfaces ErrRateLimited. Spec: 180s ± 30% jitter, drawn
// uniformly from [126s, 234s].
//
// Why fixed (not exp): server told us "you are flooding me". We need to wait
// long enough for the per-IP rate window (1 minute) to elapse twice over,
// plus a safety margin so we don't immediately hit the limiter again. exp
// backoff would either undercut the window (attempt 0-2) or overshoot it
// massively (attempt 5+ → 60s cap which is still under window safety).
//
// Why ±30% (not ±10%): when N slots in a pool die together and all see the
// rate-limit sentinel, we need their cool-downs to spread enough that the
// post-cool-down handshake burst is decorrelated. 180s × 30% = 108s spread
// across 8 slots is comfortably bigger than the limiter window — the storm
// gets broken up.
//
// Why disjoint from slotBackoffDuration's [5s, 60s] range: failure-mode
// classification on the dashboard depends on the cool-down counter ticking
// only when the sentinel fires, not when the network just hiccupped. The
// floor at 126s is double the exp cap, so a single-slot dashboard panel can
// distinguish the two reconnect cadences cleanly.
func slotRateLimitedCooldown() time.Duration {
	const base = 180 * time.Second
	// Uniform [-0.30, +0.30) draw — math/rand/v2 Float64 is concurrent-safe.
	jitter := (rand.Float64()*0.6 - 0.3)
	return time.Duration(float64(base) * (1.0 + jitter))
}

// rateLimitRefillFloor / rateLimitRefillCeil are sanity bounds applied when
// honoring a server-directed RefillIn from *RateLimitError.Signal. They
// prevent the client from sleeping for less than 5 s (renders the rate-limit
// protection ineffective) or more than 30 min (excessive; likely a clock
// skew / config bug on the server side).
const (
	rateLimitRefillFloor = 5 * time.Second
	rateLimitRefillCeil  = 30 * time.Minute
)

// clampRefillIn applies [rateLimitRefillFloor, rateLimitRefillCeil] bounds to
// a server-supplied RefillIn duration. Returns the clamped value.
func clampRefillIn(d time.Duration) time.Duration {
	if d < rateLimitRefillFloor {
		return rateLimitRefillFloor
	}
	if d > rateLimitRefillCeil {
		return rateLimitRefillCeil
	}
	return d
}

// slotRateLimitedCooldownForTest is a test seam: production code calls
// slotRateLimitedCooldown directly, but TestReconnectLoop_AppliesCooldownOnRateLimit
// substitutes a 100ms shim so the integration test can complete in <1s.
//
// Defaults to slotRateLimitedCooldown so production behavior is unchanged
// when no test stub is installed.
var slotRateLimitedCooldownForTest = slotRateLimitedCooldown

// slotBackoffDurationForTest is a test seam matching slotRateLimitedCooldownForTest.
// Production reconnectLoop calls slotBackoffDuration(attempt) directly; tests
// override this to return a fast backoff so reconnectLoop integration tests
// finish in milliseconds instead of seconds.
var slotBackoffDurationForTest = slotBackoffDuration

// connectSlotForTest is a test seam for reconnectLoop integration tests —
// production code uses (*WSPoolTransport).connectSlot directly. The stub
// returns the desired error sequence (e.g. ErrRateLimited then nil) without
// needing a live WS server.
//
// nil means "fall through to the real implementation" — production paths
// must NOT see this hook and the build never references it.
var connectSlotForTest func() error

// sleepWithCancel sleeps for d, returning early if ctx is cancelled. Used
// by reconnectLoop to pace the rate-limit cool-down without blocking
// pool shutdown for the full 126-234s.
func sleepWithCancel(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// newDiscardLogger returns a slog logger whose output is silently dropped.
// Used by tests that exercise loops which would otherwise spam the test
// output stream. NOT used in production code.
func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

type slotState int32

const (
	slotConnecting slotState = iota
	slotReady
	slotDead
	slotDraining
)

// defaultMaxPendingPerSlot is the default in-flight CONNECTs cap per slot.
// 4 is suitable for direct-to-origin mode. For CF mode a lower value (2) is
// preferred because CF Free plan throttles aggressive WS burst traffic.
// Pass WSPoolConfig.MaxPendingPerSlot to override.
const defaultMaxPendingPerSlot = 4

// wsSlotTransport is the minimal interface that poolSlot.transport must satisfy.
// Using an interface instead of *WebSocketTransport lets tests inject a fake
// reader without spinning up a real gorilla WS connection, while keeping the
// production code structurally identical — *WebSocketTransport satisfies all
// five methods automatically (enforced by the compile-time assertion below).
//
// Phase 3 supervisor refactor will replace the loop body with a channel-based
// pump, but this interface remains the seam point so regression tests continue
// to drive the real reader path.
type wsSlotTransport interface {
	ReadMessage(timeout time.Duration) ([]byte, error)
	LastWriteUnixNano() int64
	WriteMessage(data []byte) error
	WriteControlMessage(data []byte) error
	Close() error
}

// Compile-time assertion: *WebSocketTransport must satisfy wsSlotTransport.
var _ wsSlotTransport = (*WebSocketTransport)(nil)

// poolSlot is a single WebSocket connection in the pool with its own crypto session.
//
// generation is incremented every time the slot is (re)connected. Each reader
// goroutine captures its slot's generation at start and checks it before each
// ReadMessage. If generation has advanced, the reader exits — preventing the
// gorilla "repeated read on failed websocket connection" panic that would
// otherwise occur when an old reader and a new reader race on the same conn
// after a fast reconnect.
type poolSlot struct {
	transport       wsSlotTransport
	session         *core.Session
	token           []byte
	state           atomic.Int32 // slotState
	streams         atomic.Int32 // active stream count (established)
	pendingConnects atomic.Int32 // in-flight CONNECTs (sent, awaiting CONNECT_OK)
	generation      atomic.Uint64
	index           int

	// downBytes counts encrypted payload bytes received on this TCP since last
	// (re)connect. Used for byte-based preemptive rotation: TSPU (Russia DPI,
	// 2026) silently freezes TCP after ~15-20KB downstream from "suspicious" IPs
	// with TLS 1.3 — we rotate before hitting the threshold to keep traffic moving.
	downBytes atomic.Int64
}

func (s *poolSlot) getState() slotState   { return slotState(s.state.Load()) }
func (s *poolSlot) setState(st slotState) { s.state.Store(int32(st)) }

// shouldExitReader returns true when the reader's captured generation no longer
// matches the slot's current generation — meaning a reconnect happened and a
// new reader has taken over.
func (p *WSPoolTransport) shouldExitReader(slot *poolSlot, capturedGen uint64) bool {
	return slot.generation.Load() != capturedGen
}

// classifyWSReadError maps a terminal slot-reader error to one of the bounded
// labels in frameAnomalyReasons. Used by R.3a diagnostic capture: dashboard
// counters and a structured log line both consume the same classification so
// "what failed?" is a single field across log, metric, and trace.
//
// Order matters — patterns are checked most-specific-first. Documented
// precedence invariants (also asserted in TestClassifyWSReadError_OrderingInvariants):
//   - `closed_local` before `eof` — a Close-then-read race produces both
//     signals and the local-close attribution is more useful for forensics.
//   - `tls` before `eof` — `tls: read EOF on record layer` is a TLS-layer
//     teardown, not raw TCP EOF; misclassifying it as `eof` hides JA3/MAC
//     drift signal.
//   - `reset_by_peer` before `eof` — a hard TCP RST that the kernel surfaces
//     as `connection reset by peer` is distinct from an orderly FIN read as
//     EOF; conflating them would erase the throttle/RST-injection signal.
//   - `io_timeout` before `eof` — a `i/o timeout` carries the same forensic
//     weight as a write deadline expiry and must not be hidden in `other`.
func classifyWSReadError(err error) string {
	if err == nil {
		return "other"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "RSV"):
		// gorilla returns "RSV1 set, RSV2 set, and RSV3 set, none of which is
		// supported" or similar permutations. All collapse to one label —
		// distinguishing 1 vs 2 vs 3 set bits adds cardinality without giving
		// us actionable signal.
		return "rsv"
	case strings.Contains(msg, "bad opcode"):
		return "opcode"
	case strings.Contains(msg, "use of closed network connection"):
		return "closed_local"
	case strings.Contains(msg, "close 1011"):
		return "close_1011"
	case strings.Contains(msg, "message too big"):
		// gorilla "websocket: read limit exceeded — ..." (ErrReadLimit), the
		// canonical close-1009 CloseError (`"websocket: close 1009 (message
		// too big)"`), and synthetic `"message too big"` middlebox responses.
		// MUST come BEFORE "websocket: close" because the close-1009 message
		// also contains the "websocket: close" prefix; otherwise close-1009
		// silently collapses into close_other and we lose the size-violation
		// signal entirely. Distinct from a corrupted-frame rsv/opcode signal
		// — the wire bytes were syntactically valid, just too big.
		return "message_too_big"
	case strings.Contains(msg, "websocket: close"):
		// Other WS close codes (1000/1001/1006/1008/...). 1011 is special
		// above; 1009 (message too big) is special above too.
		return "close_other"
	case strings.Contains(msg, "connection reset by peer"):
		// TCP RST surfaced through the kernel — explicit teardown, distinct
		// from orderly FIN (EOF). Hoster throttle and CDN RST-injection both
		// land here.
		return "reset_by_peer"
	case strings.Contains(msg, "i/o timeout"):
		// Read or write deadline expired without data — distinct from EOF
		// (peer never closed) and from `closed_local` (we didn't Close()).
		// Surface it as its own bucket so dashboards can spot stalled-but-
		// not-torn-down connections (CF/middlebox black-hole).
		return "io_timeout"
	case strings.Contains(msg, "tls:"):
		return "tls"
	case strings.Contains(msg, "EOF"):
		// Covers io.EOF and "unexpected EOF" — both signal TCP teardown.
		return "eof"
	case looksLikeHTTPPrefix(msg):
		// Middlebox (CF edge, hoster reverse proxy, captive portal) returned
		// an HTTP error page on what should have been a WS frame stream.
		// Common signature: gorilla parses leading "<HTML" / "HTTP/" bytes
		// as a frame header and complains about RSV (already caught above)
		// or unexpected payload — but the underlying cause is HTML/text on
		// the wire. Some gorilla versions surface this as "invalid UTF-8"
		// for text frames.
		return "html"
	default:
		return "other"
	}
}

// looksLikeHTTPPrefix returns true when the error message hints that the
// underlying wire contained HTTP/HTML bytes instead of WS frames.
func looksLikeHTTPPrefix(msg string) bool {
	return strings.Contains(msg, "invalid UTF-8") ||
		strings.Contains(msg, "HTTP") ||
		strings.Contains(msg, "<!DOCTYPE") ||
		strings.Contains(msg, "<html")
}

// slotBackoffDuration returns reconnect wait for a per-slot reconnect attempt.
//
// Behavior:
//   - attempt 0: uniform [5s, 10s) — slow-start with broad spread.
//   - attempt N>0: base = 5s × 2^N, jitter [1.0, 2.0), capped at 60s.
//
// Using a 5s base instead of the global 1s base (`backoffDuration`) prevents
// the cascade documented in `docs/strategy/2026-04-30-current-state-and-improvements.md`
// §2.2: 8 slots dying simultaneously and reconnecting at attempt=0 with the
// 1s base would all fire within ~1.25s, blow through the per-IP handshake
// rate limit, and cascade into a 70s backoff cliff. Wider [1.0, 2.0) jitter
// (vs the global ±25%) decorrelates the 8 first-attempts across a 5-10s
// window — comfortable spread under any reasonable handshake rate limit.
//
// Cap is applied AFTER jitter (not on the base) so the worst-case wait the
// user can ever experience is bounded at exactly 60s. This trades a slightly
// less aggressive curve at high attempts for predictable user-visible cap.
//
// Concurrency: math/rand/v2's package-level Float64 is concurrent-safe and
// cheap. No need to manage our own seeded RNG here.
//
// Attempt clamp: pinned at 6 (5s × 2^6 = 320s pre-cap, post-cap 60s) to
// prevent time.Duration overflow at attempt~37+ (May 2026 audit F1).
func slotBackoffDuration(attempt int) time.Duration {
	attempt = min(attempt, 6)
	base := float64(5*time.Second) * math.Pow(2, float64(attempt))
	jitter := 1.0 + rand.Float64() // [1.0, 2.0)
	d := time.Duration(base * jitter)
	if d > 60*time.Second {
		return 60 * time.Second
	}
	return d
}

// WSPoolTransport manages a pool of WebSocket connections for fault tolerance and throughput.
// Implements StreamTransport + PoolAware interfaces.
// Server is unaware of the pool — each WS is an independent tunnel.
type WSPoolTransport struct {
	slots    []*poolSlot
	poolSize int

	maxPendingPerSlot int32 // cap on in-flight CONNECTs per slot
	maxStreamsPerSlot int32 // cap on active streams per slot (0 = unlimited)
	maxBytesPerSlot   int64 // rotate slot after N downstream bytes (0 = disabled)

	streamMap sync.Map // map[uint16]int — streamID -> slot index

	// For creating new slots
	serverAddr   string
	sniHost      string // override TLS ServerName
	cfIP         string // specific CF edge IP
	useTLS       bool
	skipVerify   bool
	lockedFP     *browser.Fingerprint
	client       *Client       // back-reference for handshake
	writeTimeout time.Duration // per-frame write deadline (0 → 30s WSAsyncWriter default)
	staggerDelay time.Duration // initial/reconnect slot startup spacing (0 → no stagger)

	// Meltdown protection: when multiple slots die within a short window
	// (usually CF punishing an aggressive burst), pause reconnect loops so CF
	// can "cool down" instead of immediately spinning up replacement slots
	// that will get killed again.
	meltdownWindow    time.Duration
	meltdownThreshold int
	meltdownCooldown  time.Duration
	recentDeaths      atomic.Int32
	meltdownUntil     atomic.Int64 // unix nano; reconnects blocked until this time

	// meltdownLimiter rate-limits WARN-level meltdown log emission so the
	// emission cadence is not a deterministic side channel observable from
	// the network. severeMeltdown() additionally suppresses transient drops
	// from the WARN channel; transient events log at debug only.
	meltdownLimiter *rate.Limiter
	meltdownLogRNG  *mrand.Rand
	meltdownLogMu   sync.Mutex // guards meltdownLogRNG (math/rand is not safe for concurrent use)

	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger
}

// Compile-time assertions.
var (
	_ StreamTransport  = (*WSPoolTransport)(nil)
	_ PoolAware        = (*WSPoolTransport)(nil)
	_ PendingTracker   = (*WSPoolTransport)(nil)
	_ ControlPoolAware = (*WSPoolTransport)(nil)
	_ PoolReadiness    = (*WSPoolTransport)(nil)
)

// WSPoolConfig configures the WebSocket pool.
type WSPoolConfig struct {
	Size       int
	ServerAddr string
	UseTLS     bool
	SkipVerify bool
	LockedFP   *browser.Fingerprint
	SNIHost    string // override TLS ServerName (for origin IP with domain SNI)
	CFIP       string // specific CF edge IP (bypass DNS, keep domain as TLS SNI)

	// MaxPendingPerSlot caps in-flight CONNECTs per slot. 0 = default (4).
	MaxPendingPerSlot int

	// MaxStreamsPerSlot caps active streams per slot. 0 = unlimited.
	// For CF CDN mode, set low (4-8) so each WS carries light traffic.
	MaxStreamsPerSlot int

	// MaxBytesPerSlot triggers preemptive rotation after N downstream bytes on
	// a single slot's TCP. 0 = disabled. Critical for Russia TSPU DPI (2026)
	// which silently freezes foreign-IP TCPs after ~15-20KB over TLS 1.3.
	// Recommended 15 * 1024 for viaCF mode, 0 (disabled) for direct/SNI.
	MaxBytesPerSlot int64

	// WriteTimeout caps each WS frame's write deadline. 0 → WSAsyncWriter
	// default (30s). For viaCF mode pass 5-8s: CF-side stalls propagate as
	// TCP backpressure, and 30s means a stuck slot blocks traffic for 30s
	// before the pool can route around it. Cross-check 2026-04-15 H6.
	WriteTimeout time.Duration

	// StaggerDelay spaces initial slot handshakes. 0 disables. Recommended
	// ~300ms × slot index so 8 TCP SYNs don't arrive at CF edge in the same
	// millisecond and trip burst/rate-limit heuristics.
	StaggerDelay time.Duration

	// Meltdown protection parameters. All default to sensible values if zero.
	MeltdownWindow    time.Duration // how long "recent death" lasts (default 5s)
	MeltdownThreshold int           // N deaths in window triggers cooldown (default = ceil(size/2), min 2)
	MeltdownCooldown  time.Duration // reconnect pause after trigger (default 10s)
}

// NewWSPoolTransport creates a pool of WebSocket connections.
func NewWSPoolTransport(cl *Client, cfg WSPoolConfig) *WSPoolTransport {
	if cfg.Size < 1 {
		cfg.Size = 2
	}
	if cfg.MaxPendingPerSlot < 1 {
		cfg.MaxPendingPerSlot = defaultMaxPendingPerSlot
	}
	// Meltdown defaults tuned 2026-04-15 after field regression analysis:
	// the old 5s / ceil(size/2) combo turned a transient CF edge hiccup
	// into a self-sustaining outage. Widening the window to 15s and
	// raising the threshold to ⌈3·size/4⌉ means we still pause reconnect
	// when CF is genuinely angry, but don't trip on 4 correlated deaths
	// from one bad edge IP (see DNS-spray finding F4).
	if cfg.MeltdownWindow <= 0 {
		cfg.MeltdownWindow = 15 * time.Second
	}
	if cfg.MeltdownThreshold < 1 {
		cfg.MeltdownThreshold = (cfg.Size*3 + 3) / 4 // ceil(3·size/4)
		if cfg.MeltdownThreshold < 3 {
			cfg.MeltdownThreshold = 3
		}
	}
	if cfg.MeltdownCooldown <= 0 {
		cfg.MeltdownCooldown = 10 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WSPoolTransport{
		slots:             make([]*poolSlot, cfg.Size),
		poolSize:          cfg.Size,
		maxPendingPerSlot: int32(cfg.MaxPendingPerSlot),
		maxStreamsPerSlot: int32(cfg.MaxStreamsPerSlot),
		maxBytesPerSlot:   cfg.MaxBytesPerSlot,
		serverAddr:        cfg.ServerAddr,
		sniHost:           cfg.SNIHost,
		cfIP:              cfg.CFIP,
		useTLS:            cfg.UseTLS,
		skipVerify:        cfg.SkipVerify,
		lockedFP:          cfg.LockedFP,
		client:            cl,
		writeTimeout:      cfg.WriteTimeout,
		staggerDelay:      cfg.StaggerDelay,
		meltdownWindow:    cfg.MeltdownWindow,
		meltdownThreshold: cfg.MeltdownThreshold,
		meltdownCooldown:  cfg.MeltdownCooldown,
		meltdownLimiter:   newMeltdownLimiter(),
		meltdownLogRNG:    mrand.New(mrand.NewSource(time.Now().UnixNano())),
		ctx:               ctx,
		cancel:            cancel,
		log:               slog.Default(),
	}
}

// Connect establishes all WS connections in parallel.
// Returns success when at least one slot is ready.
func (p *WSPoolTransport) Connect(ctx context.Context) error {
	var wg sync.WaitGroup
	results := make([]error, p.poolSize)

	// Stagger the initial fan-out so N TCP SYNs don't arrive at CF edge in
	// the same millisecond (trips burst/rate-limit heuristics). Same pattern
	// WSReadyPool already uses. Zero staggerDelay → no stagger (direct mode).
	for i := 0; i < p.poolSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx > 0 && p.staggerDelay > 0 {
				select {
				case <-time.After(time.Duration(idx) * p.staggerDelay):
				case <-ctx.Done():
					results[idx] = ctx.Err()
					return
				}
			}
			results[idx] = p.connectSlot(ctx, idx)
		}(i)
	}

	wg.Wait()

	anyReady := false
	for i, err := range results {
		if err == nil {
			anyReady = true
			p.log.Info("WS pool slot ready", "slot", i)
		} else {
			p.log.Warn("WS pool slot failed", "slot", i, "err", err)
			go p.reconnectLoop(i)
		}
	}

	if !anyReady {
		return fmt.Errorf("ws pool: all %d slots failed to connect", p.poolSize)
	}

	go p.rotationLoop()
	go p.keepaliveLoop()

	return nil
}

// keepaliveLoop sends FlagKeepalive to every healthy slot at a jittered
// ~20s cadence. The base interval prevents Cloudflare Proxy Write Timeout
// (30s) and Idle Timeout (900s) from killing long-lived WebSocket
// connections; the log-normal jitter (final-audit-2026-05-03 P1-3,
// upgraded from uniform ±30% NEW-1 fix) destroys the FFT-visible
// periodic peak AND defeats ML classifiers that distinguish flat-band
// uniform jitter from heavy-tailed real-world inter-frame jitter.
func (p *WSPoolTransport) keepaliveLoop() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(JitteredIntervalLogNormal(20*time.Second, 0.5)):
			p.sendKeepaliveToAllSlots()
		}
	}
}

func (p *WSPoolTransport) sendKeepaliveToAllSlots() {
	sent := 0
	for i := 0; i < p.poolSize; i++ {
		slot := p.slots[i]
		if slot == nil || slot.getState() != slotReady || slot.transport == nil || slot.session == nil {
			continue
		}
		// Each slot has its own crypto session — must use slot.session, not global client session.
		chunk := core.NewKeepaliveChunk(slot.session.ID, slot.session.NextSeqNum())
		enc, err := slot.session.EncryptChunk(chunk)
		if err != nil {
			continue
		}
		if writeErr := slot.transport.WriteControlMessage(enc); writeErr != nil {
			p.log.Debug("keepalive write failed", "slot", i, "err", writeErr)
		} else {
			sent++
		}
	}
	if sent > 0 {
		p.log.Debug("keepalive sent", "slots", sent)
	}
}

// connectSlot creates a new WS connection for the given slot index.
func (p *WSPoolTransport) connectSlot(ctx context.Context, idx int) error {
	slot := &poolSlot{index: idx}
	slot.setState(slotConnecting)
	p.slots[idx] = slot

	// Perform handshake to get a new session
	hello, clientState, err := core.NewClientHello(p.client.clientID, p.client.serverPub)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: create hello: %w", idx, err)
	}

	respBody, err := p.client.transport.SendHandshake(ctx, hello)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: handshake: %w", idx, err)
	}

	respData, _, err := browser.ParseDownloadResponse(respBody)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: parse hello: %w", idx, err)
	}

	// `_v` MUST be threaded into core.ServerHello so CompleteHandshake picks the
	// matching key schedule. Server's handleHandshakeNew derives keys with
	// protoVersion=1; if we drop `_v` here, CompleteHandshake silently defaults
	// to protoVersion=0 (legacy) and the resulting keys diverge byte-for-byte
	// from the server's — every pool slot then fails with "cannot decrypt
	// session token" (datacanvases.com data-plane drift, 2026-04-30).
	var shData struct {
		EphPub       []byte `json:"eph"`
		Token        []byte `json:"tok"`
		MaxConns     uint8  `json:"mc"`
		ChunkSize    uint16 `json:"cs"`
		ProtoVersion *uint8 `json:"_v,omitempty"`
	}
	if err := json.Unmarshal(respData, &shData); err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: unmarshal hello: %w", idx, err)
	}

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
		ProtoVersion:          shData.ProtoVersion,
	}

	session, err := core.CompleteHandshake(clientState, serverHello)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: complete handshake: %w", idx, err)
	}

	slot.session = session
	slot.token = browser.EncodeTokenWithHint(session.ID, shData.Token)

	// Create WS transport and upgrade
	wst := NewWebSocketTransport(p.serverAddr, p.useTLS, p.skipVerify, p.lockedFP)
	wst.sniHost = p.sniHost // SNI trick: domain as ServerName when connecting to origin IP
	wst.cfIP = p.cfIP       // CF edge IP override: bypass DNS, keep domain as TLS SNI
	if p.writeTimeout > 0 {
		wst.SetWriteTimeout(p.writeTimeout) // viaCF: 5-8s, direct: 0 (→ 30s default)
	}
	if idx == 0 {
		wst.WarmupRequests() // Only warmup for first slot (looks natural)
	}
	// D3: ws upgrade now authenticates via a post-upgrade first frame built
	// from the slot's session — Bearer header is gone.
	if err := wst.UpgradeToWS(slot.token, slot.session); err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: ws upgrade: %w", idx, err)
	}

	slot.transport = wst
	// Reset downstream byte counter — fresh TCP starts the TSPU 15-20KB budget over.
	slot.downBytes.Store(0)
	// Bump generation BEFORE marking ready so any old reader checking
	// generation after this point exits cleanly. The new reader (started by
	// the caller) will capture the new generation at its first check.
	slot.generation.Add(1)
	slot.setState(slotReady)
	return nil
}

// reconnectLoop tries to reconnect a dead slot with exponential backoff.
// If meltdown cooldown is active (triggered by multiple recent slot deaths),
// the loop waits for it to elapse before attempting to reconnect. This
// prevents a spiral where CF rejects replacement slots as fast as they are
// created, keeping it under load and making recovery slower.
//
// Task A2 (May audit): if connectSlot surfaces ErrRateLimited (server
// emitted X-SL-RL: 1 from its rate-limit branch), the loop applies a fixed
// 180s ± 30% cool-down INSTEAD of exp backoff and resets the attempt counter
// to 0 afterwards. Resetting the counter prevents the cool-down from being
// stacked on top of an already-aged exp curve — after a rate-limit event
// we want a clean slow-start, not "5s × 2^N + 180s".
func (p *WSPoolTransport) reconnectLoop(idx int) {
	for attempt := 0; ; attempt++ {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		if wait := p.meltdownWaitDuration(); wait > 0 {
			p.log.Info("WS pool meltdown cooldown — pausing reconnect",
				"slot", idx, "wait", wait)
			timer := time.NewTimer(wait)
			select {
			case <-p.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}

		d := slotBackoffDurationForTest(attempt)
		p.log.Info("WS pool reconnecting slot", "slot", idx, "backoff", d, "attempt", attempt)

		timer := time.NewTimer(d)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		var connectErr error
		if connectSlotForTest != nil {
			// Test seam — see ws_pool.go::connectSlotForTest. Production
			// builds never enter this branch because nothing assigns the var.
			connectErr = connectSlotForTest()
		} else {
			connectErr = p.connectSlot(p.ctx, idx)
		}

		if connectErr == nil {
			p.log.Info("WS pool slot reconnected", "slot", idx)
			go p.slotReader(idx)
			return
		}

		// Task A2: typed sentinel — server told us we're rate-limited.
		// Honor Signal.RefillIn when present (Phase 2 fix); fall back to
		// fixed 180s ± 30% otherwise. Reset attempt counter so the next
		// iteration starts fresh from attempt=0 (slow-start). The counter
		// reset is safe: slotBackoffDuration is already clamped at attempt=6
		// (May audit F1, A1 fix), so over-counting can't overflow.
		if errors.Is(connectErr, ErrRateLimited) {
			Stats.RateLimitedFromServer.Add(1)
			var cooldown time.Duration
			var rlErr *RateLimitError
			if errors.As(connectErr, &rlErr) && rlErr.Signal != nil && rlErr.Signal.RefillIn > 0 {
				cooldown = clampRefillIn(rlErr.Signal.RefillIn)
				cooldown = JitteredInterval(cooldown, 0.30)
				p.log.Info("WS pool slot rate-limited by server (server-directed cooldown)",
					"slot", idx,
					"carrier", rlErr.Signal.Carrier,
					"bucket", rlErr.Signal.Bucket,
					"refill_in_server", rlErr.Signal.RefillIn,
					"cooldown_applied", cooldown,
				)
			} else {
				cooldown = slotRateLimitedCooldownForTest()
				p.log.Info("WS pool slot rate-limited by server (fallback fixed cooldown)",
					"slot", idx,
					"cooldown_applied", cooldown,
				)
			}
			sleepWithCancel(p.ctx, cooldown)
			// Reset attempt counter — the for-loop's `attempt++` will run
			// after `continue`, so we set it to -1 to land on 0 next iter.
			attempt = -1
			continue
		}

		p.log.Warn("WS pool slot reconnect failed", "slot", idx, "err", connectErr)
	}
}

// newMeltdownLimiter returns a token-bucket limiter capping meltdown WARN
// log emission at 1 per 10s with burst 3. Public-from-package for tests.
//
// Closes A2-MED-10: deterministic-cadence meltdown WARN emissions used to
// be a passive timing side channel observable from the network (DPI could
// correlate connection drops with predictable log timing). Token bucket +
// jittered emit + severity gate together obscure the timing fingerprint.
func newMeltdownLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Every(10*time.Second), 3)
}

// severeMeltdown returns true when at least half the pool is dead. Below
// this threshold, transient drops emit debug-only and are suppressed from
// WARN-level log channels — preventing single-slot blips from triggering a
// WARN that an attacker could correlate with their network probe.
func severeMeltdown(dead, total int) bool {
	if total <= 0 {
		return false
	}
	return dead*2 >= total
}

// countDeadSlots returns the number of slots currently in slotDead state and
// the pool size. Lock-free read of per-slot atomics.
func (p *WSPoolTransport) countDeadSlots() (dead, total int) {
	total = p.poolSize
	for _, slot := range p.slots {
		if slot == nil {
			// Nil slot has not been initialized yet — treat as not-yet-alive,
			// which for meltdown reporting purposes does not count as dead.
			continue
		}
		if slot.getState() == slotDead {
			dead++
		}
	}
	return dead, total
}

// meltdownLogJitter returns a [0.5×base, 1.5×base) duration sampled from the
// pool's RNG. Caller must NOT hold meltdownLogMu — this method takes it.
func (p *WSPoolTransport) meltdownLogJitter(base time.Duration) time.Duration {
	p.meltdownLogMu.Lock()
	defer p.meltdownLogMu.Unlock()
	if p.meltdownLogRNG == nil {
		return base
	}
	return time.Duration(0.5*float64(base) + p.meltdownLogRNG.Float64()*float64(base))
}

// meltdownWaitDuration returns how long the reconnect must still wait before
// the cooldown elapses, or 0 if no cooldown is active.
func (p *WSPoolTransport) meltdownWaitDuration() time.Duration {
	until := p.meltdownUntil.Load()
	if until == 0 {
		return 0
	}
	wait := time.Until(time.Unix(0, until))
	if wait <= 0 {
		return 0
	}
	return wait
}

// recordSlotDeath tracks slot deaths within a rolling window and triggers a
// meltdown cooldown if the threshold is exceeded. Called from handleSlotDeath.
func (p *WSPoolTransport) recordSlotDeath() {
	deaths := p.recentDeaths.Add(1)

	// Schedule decrement after the window so old deaths age out.
	go func() {
		timer := time.NewTimer(p.meltdownWindow)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			p.recentDeaths.Add(-1)
		}
	}()

	if int(deaths) >= p.meltdownThreshold {
		until := time.Now().Add(p.meltdownCooldown).UnixNano()
		// Only advance, never shorten, an already-active cooldown.
		if prev := p.meltdownUntil.Load(); until > prev {
			p.meltdownUntil.Store(until)
			p.emitMeltdownLog(int(deaths))
		}
	}
}

// emitMeltdownLog dispatches the meltdown WARN log through a rate-limited,
// severity-gated, jittered path. Closes A2-MED-10:
//
//   - Severity gate (severeMeltdown): single-slot or otherwise-transient
//     pool drops never surface at WARN; they emit at debug only.
//   - Token-bucket rate limit (meltdownLimiter): max 1 per 10s with burst 3,
//     capping the rate at which any meltdown WARN can be observed from the
//     network even under sustained churn.
//   - Jitter (meltdownLogJitter): the WARN emit is delayed by a random
//     [0.5×, 1.5×) × 5s draw, so the arrival timing is not a deterministic
//     function of the underlying death event.
func (p *WSPoolTransport) emitMeltdownLog(deathsInWindow int) {
	dead, total := p.countDeadSlots()

	if !severeMeltdown(dead, total) {
		// Transient: never surface to WARN, debug only. Side-channel-quiet.
		p.log.Debug("transient pool drop (suppressed from WARN)",
			"dead", dead,
			"total", total,
			"deaths_in_window", deathsInWindow,
			"threshold", p.meltdownThreshold)
		return
	}

	if !p.meltdownLimiter.Allow() {
		// Severity threshold met but emit budget exhausted — coalesce silently.
		p.log.Debug("meltdown WARN rate-limited",
			"dead", dead,
			"total", total,
			"deaths_in_window", deathsInWindow)
		return
	}

	jitter := p.meltdownLogJitter(5 * time.Second)
	go func(deathsInWindow, dead, total int, jitter time.Duration) {
		timer := time.NewTimer(jitter)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
			return
		case <-timer.C:
		}
		p.log.Warn("WS pool meltdown detected — entering cooldown",
			"deaths_in_window", deathsInWindow,
			"dead", dead,
			"total", total,
			"threshold", p.meltdownThreshold,
			"window", p.meltdownWindow,
			"cooldown", p.meltdownCooldown,
			"emit_jitter", jitter)
	}(deathsInWindow, dead, total, jitter)
}

// rotationLoop periodically rotates one slot for anti-fingerprinting.
func (p *WSPoolTransport) rotationLoop() {
	for {
		delay := 2*time.Minute + time.Duration(rand.Int64N(int64(6*time.Minute)))
		timer := time.NewTimer(delay)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		p.rotateOneSlot()
	}
}

// rotateOneSlot soft-rotates the slot with fewer active streams.
func (p *WSPoolTransport) rotateOneSlot() {
	minIdx := -1
	minStreams := int32(1<<31 - 1)
	for i, slot := range p.slots {
		if slot == nil || slot.getState() != slotReady {
			continue
		}
		s := slot.streams.Load()
		if s < minStreams {
			minStreams = s
			minIdx = i
		}
	}

	if minIdx < 0 {
		return
	}

	slot := p.slots[minIdx]
	slot.setState(slotDraining)
	p.log.Info("WS pool rotating slot", "slot", minIdx, "activeStreams", minStreams)

	// Wait for streams to drain (max 30s)
	deadline := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-deadline:
			goto reconnect
		case <-ticker.C:
			if slot.streams.Load() == 0 {
				goto reconnect
			}
		}
	}

reconnect:
	if slot.transport != nil {
		slot.transport.Close()
	}
	if slot.session != nil {
		slot.session.Destroy()
	}

	if err := p.connectSlot(p.ctx, minIdx); err != nil {
		p.log.Warn("WS pool rotation reconnect failed", "slot", minIdx, "err", err)
		go p.reconnectLoop(minIdx)
		return
	}

	go p.slotReader(minIdx)
	p.log.Info("WS pool slot rotated", "slot", minIdx)
}

// AssignStream assigns a streamID to the least-loaded ready slot.
// Prefers slots with fewer pending CONNECTs to distribute load evenly across CF CDN connections.
func (p *WSPoolTransport) AssignStream(streamID uint16) {
	minIdx := -1
	minScore := int32(1<<31 - 1)

	for i, slot := range p.slots {
		if slot == nil {
			continue
		}
		st := slot.getState()
		if st != slotReady {
			continue
		}
		streams := slot.streams.Load()
		// Skip slots at stream capacity (CF mode: each WS should carry few streams)
		if p.maxStreamsPerSlot > 0 && streams >= p.maxStreamsPerSlot {
			continue
		}
		// Score: pending CONNECTs weighted 4x (bottleneck through CDN) + established streams.
		// This spreads CONNECT load evenly and avoids piling onto one slot.
		pending := slot.pendingConnects.Load()
		score := pending*4 + streams
		if score < minScore {
			minScore = score
			minIdx = i
		}
	}

	if minIdx < 0 {
		// All slots at capacity — pick the slot with fewest streams (soft overflow).
		// This is better than always picking slot 0 which creates a hotspot.
		minStreams := int32(1<<31 - 1)
		for i, slot := range p.slots {
			if slot == nil || slot.getState() != slotReady {
				continue
			}
			s := slot.streams.Load()
			if s < minStreams {
				minStreams = s
				minIdx = i
			}
		}
		if minIdx < 0 {
			// Truly no ready slots — last resort fallback.
			for i, slot := range p.slots {
				if slot != nil {
					minIdx = i
					break
				}
			}
		}
		if minIdx < 0 {
			p.log.Warn("stream assign: no slots available", "stream", streamID)
			return
		}
	}

	p.streamMap.Store(streamID, minIdx)
	p.slots[minIdx].streams.Add(1)
	if p.log != nil {
		p.log.Debug("stream assigned", "stream", streamID, "slot", minIdx,
			"pending", p.slots[minIdx].pendingConnects.Load(),
			"streams", p.slots[minIdx].streams.Load())
	}
}

// IncrPending increments the pending CONNECT counter for the stream's assigned slot.
func (p *WSPoolTransport) IncrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].pendingConnects.Add(1)
		}
	}
}

// DecrPending decrements the pending CONNECT counter for the stream's assigned slot.
func (p *WSPoolTransport) DecrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].pendingConnects.Add(-1)
		}
	}
}

// SlotPending returns pending CONNECT count for the stream's assigned slot.
func (p *WSPoolTransport) SlotPending(streamID uint16) int32 {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].pendingConnects.Load()
		}
	}
	return 0
}

// AllSlotsAtMaxPending returns true when every ready slot has >= maxPendingPerSlot pending CONNECTs.
// Returns false when no slots are ready (don't block — let AssignStream fallback handle it).
func (p *WSPoolTransport) AllSlotsAtMaxPending() bool {
	anyReady := false
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady {
			anyReady = true
			if slot.pendingConnects.Load() < p.maxPendingPerSlot {
				return false
			}
		}
	}
	if !anyReady {
		return false // No ready slots — don't block, let the CONNECT fail fast downstream
	}
	return true
}

// ReleaseStream removes stream assignment.
func (p *WSPoolTransport) ReleaseStream(streamID uint16) {
	if v, ok := p.streamMap.LoadAndDelete(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].streams.Add(-1)
		}
	}
}

// SessionForStream returns the crypto session for the stream's assigned slot.
func (p *WSPoolTransport) SessionForStream(streamID uint16) *core.Session {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].session
		}
	}
	// Fallback: return first available session
	for _, slot := range p.slots {
		if slot != nil && slot.session != nil && slot.getState() == slotReady {
			return slot.session
		}
	}
	return nil
}

// WriteMessageForStream sends a data frame to the slot assigned to this stream.
func (p *WSPoolTransport) WriteMessageForStream(streamID uint16, data []byte) error {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.getState() == slotReady && slot.transport != nil {
				return slot.transport.WriteMessage(data)
			}
		}
	}
	return p.WriteMessage(data)
}

// WriteControlMessageForStream sends a control frame (CONNECT, FIN) with
// high priority to the slot assigned to this stream.
func (p *WSPoolTransport) WriteControlMessageForStream(streamID uint16, data []byte) error {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.getState() == slotReady && slot.transport != nil {
				return slot.transport.WriteControlMessage(data)
			}
		}
	}
	return p.WriteControlMessage(data)
}

// WriteMessage sends a data frame to a random ready slot (for non-stream data).
func (p *WSPoolTransport) WriteMessage(data []byte) error {
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady && slot.transport != nil {
			return slot.transport.WriteMessage(data)
		}
	}
	return fmt.Errorf("ws pool: no ready slots")
}

// WriteControlMessage sends a control frame to a random ready slot.
func (p *WSPoolTransport) WriteControlMessage(data []byte) error {
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady && slot.transport != nil {
			return slot.transport.WriteControlMessage(data)
		}
	}
	return fmt.Errorf("ws pool: no ready slots")
}

// StartReader starts background readers for all connected slots.
// Returns when ALL readers die or context is cancelled.
func (p *WSPoolTransport) StartReader(ctx context.Context, cl *Client) error {
	var wg sync.WaitGroup
	errCh := make(chan error, p.poolSize)

	for i := 0; i < p.poolSize; i++ {
		if p.slots[i] == nil || p.slots[i].getState() != slotReady {
			continue
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p.slotReaderWithClient(ctx, cl, idx)
		}(i)
	}

	go func() {
		wg.Wait()
		select {
		case errCh <- fmt.Errorf("all slot readers exited"):
		default:
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// slotReader runs a reader for a slot (used for reconnected slots).
func (p *WSPoolTransport) slotReader(idx int) {
	p.slotReaderWithClient(p.ctx, p.client, idx)
}

// slotReaderWithClient runs the WS reader for a specific slot.
// On error: marks slot dead, closes affected streams, triggers reconnect.
//
// Captures slot.generation at start and bails out (without touching the
// transport) when generation advances — meaning the slot was reconnected
// and a newer reader has taken over. This prevents the gorilla "repeated
// read on failed websocket connection" panic that occurs when two readers
// race on the same conn.
func (p *WSPoolTransport) slotReaderWithClient(ctx context.Context, cl *Client, idx int) {
	slot := p.slots[idx]
	if slot == nil || slot.transport == nil {
		return
	}
	// Capture transport pointer at reader start. The slot's transport field is
	// reassigned on rotation and replaced wholesale on reconnect (which creates
	// a new poolSlot at p.slots[idx]); reading slot.transport on every loop
	// iteration races with these mutations and could deliver the new conn to a
	// stale reader. Holding our own captured pointer means a stale reader keeps
	// reading from the OLD conn (which is Close'd by handleSlotDeath /
	// rotation), gets "use of closed network connection", and exits cleanly.
	// The new reader started after reconnect uses its own freshly captured
	// transport — no two readers ever share a *gorilla.Conn.
	myTransport := slot.transport
	myGen := slot.generation.Load()
	slotStart := time.Now()
	mode := "direct"
	if p.cfIP != "" {
		mode = "cf"
	}

	p.log.Info("WS pool slot reader started", "slot", idx, "gen", myGen, "mode", mode)

	defer func() {
		if r := recover(); r != nil {
			p.log.Warn("WS pool slot reader panic recovered", "slot", idx, "panic", r)
			// Only initiate slot death if our generation is still active.
			// A panic on a stale generation means we lost a race with a
			// reconnect; the new reader/transport must not be torn down.
			if !p.shouldExitReader(slot, myGen) {
				p.handleSlotDeath(cl, idx)
			}
		}
	}()

	msgCount := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Generation check: if the slot was reconnected, a newer reader
		// owns the new transport — exit silently to avoid concurrent
		// ReadMessage on the same conn.
		if p.shouldExitReader(slot, myGen) {
			p.log.Debug("WS pool slot reader exiting — slot reconnected",
				"slot", idx, "captured_gen", myGen, "current_gen", slot.generation.Load())
			return
		}

		data, err := myTransport.ReadMessage(30 * time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// If the slot was reconnected during our blocking ReadMessage, the
			// error is from the OLD (closed) conn — don't treat it as a death
			// of the new slot. Just exit.
			if p.shouldExitReader(slot, myGen) {
				return
			}
			// Phase −1 hotfix (2026-05-14): any read error is terminal.
			// Previously: `continue` on Timeout()==true created a tight loop
			// because gorilla/websocket v1.5.3 caches readErr (sticky), so
			// every subsequent ReadMessage() returns the same timeout without
			// blocking. After ~1000 iterations gorilla triggers a defensive
			// panic "repeated read on failed websocket connection".
			// Treating timeout as terminal moves the slot to handleSlotDeath
			// → reconnect, which is correct. Supervisor refactor (Phase 3)
			// makes this structurally enforced.
			// Terminal (non-timeout) reader error — attribute slot death.
			// If this correlates with writer_exits in stats, CF-side stalls
			// are the trigger (H6); if writer_exits stays low and
			// reader_exits climbs, the server or CF edge is actively
			// closing our TCP.
			Stats.ReaderExits.Add(1)

			// R.3a frame-anomaly diagnostic capture: classify the error and
			// log a structured record that pairs human review (the WARN line)
			// with a counter slice (`shadowlink_ws_frame_anomaly_total{type=}`).
			// `last_write_age_ms` distinguishes "conn was idle" (writer
			// exited or stalled) from "write was in flight" (suggests
			// middlebox interfering with active traffic).
			anomaly := classifyWSReadError(err)
			Stats.IncFrameAnomaly(anomaly)
			lastWriteAgeMs := int64(-1)
			if lw := myTransport.LastWriteUnixNano(); lw > 0 {
				lastWriteAgeMs = (time.Now().UnixNano() - lw) / int64(time.Millisecond)
			}
			p.log.Warn("WS pool slot reader error",
				"slot", idx,
				"err", err,
				"anomaly", anomaly,
				"messages", msgCount,
				"slot_age_ms", time.Since(slotStart).Milliseconds(),
				"down_bytes", slot.downBytes.Load(),
				"last_write_age_ms", lastWriteAgeMs,
				"writer_exits", Stats.WriterExits.Load(),
				"mode", mode,
			)
			p.handleSlotDeath(cl, idx)
			return
		}

		// Preemptive byte-based rotation (Russia TSPU 2026 mitigation).
		// TSPU freezes foreign-IP TCP silently after ~15-20KB downstream over
		// TLS 1.3. Rotate this slot BEFORE hitting that cliff — fresh TCP
		// resets the censor's byte counter. maxBytesPerSlot=0 disables this
		// (used for direct/SNI mode where there's no such limit).
		if p.maxBytesPerSlot > 0 {
			total := slot.downBytes.Add(int64(len(data)))
			if total >= p.maxBytesPerSlot {
				p.log.Info("WS pool slot preemptive rotation (TSPU byte budget)",
					"slot", idx, "downBytes", total, "limit", p.maxBytesPerSlot,
					"messages", msgCount)
				p.handleSlotDeath(cl, idx)
				return
			}
		}

		session := slot.session
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

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		if chunk.Flags == core.FlagUDP {
			cl.RouteToStream(streamID, chunk.Payload)
		} else {
			cl.RouteToStream(streamID, chunk.Payload[2:])
		}
	}
}

// handleSlotDeath marks a slot as dead, closes its streams, and triggers reconnect.
func (p *WSPoolTransport) handleSlotDeath(cl *Client, idx int) {
	slot := p.slots[idx]
	slot.setState(slotDead)

	// Close all streams assigned to this slot
	p.streamMap.Range(func(key, value any) bool {
		if value.(int) == idx {
			streamID := key.(uint16)
			p.streamMap.Delete(streamID)
			cl.streamMu.Lock()
			if ch, ok := cl.streamChans[streamID]; ok {
				close(ch)
				delete(cl.streamChans, streamID)
			}
			cl.streamMu.Unlock()
		}
		return true
	})

	slot.streams.Store(0)
	slot.pendingConnects.Store(0) // Reset: pending CONNECTs from dead slot can't be decremented normally

	if slot.transport != nil {
		slot.transport.Close()
	}

	// Record death for meltdown detection before kicking off reconnect so the
	// reconnect loop can observe the cooldown if we just hit the threshold.
	p.recordSlotDeath()

	go p.reconnectLoop(idx)
}

// Close shuts down all slots.
func (p *WSPoolTransport) Close() error {
	p.cancel()
	for _, slot := range p.slots {
		if slot == nil {
			continue
		}
		if slot.transport != nil {
			slot.transport.Close()
		}
		if slot.session != nil {
			slot.session.Destroy()
		}
		if slot.token != nil {
			core.ZeroBytes(slot.token)
		}
	}
	return nil
}

// HealthySlots returns the number of ready slots.
func (p *WSPoolTransport) HealthySlots() int {
	count := 0
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady {
			count++
		}
	}
	return count
}

// ReadyCount implements the PoolReadiness interface — same semantics as
// HealthySlots, exposed under a name independent of the legacy "Healthy"
// vocabulary so SOCKS5 UDP ASSOCIATE gating (C12 F6) reads naturally:
// `if pool.ReadyCount() < udpMinReadySlots { fail }`.
func (p *WSPoolTransport) ReadyCount() int { return p.HealthySlots() }

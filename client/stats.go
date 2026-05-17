package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// Stats holds live counters for debugging throughput/contention issues.
//
// Counters are package-global and accessed via atomic ops so hot paths pay
// nothing more than a CAS. The StartStatsLogger goroutine periodically logs
// *deltas* (not totals) so you can tell at a glance how much traffic each
// subsystem is generating right now — e.g. "is UDP poll storm dominating
// the HTTP transport?" or "how many per-stream WSs open per second?".
//
// Type convention: legacy fields use atomic.Int64 because StartStatsLogger
// computes delta = current − previous and stores prev as int64. Newer
// monotonic-only counters added since Phase 2 (PQ handshake) and Phase 0
// (WS lifecycle) use atomic.Uint64 — no overflow concerns at the edge,
// and they don't participate in the delta arithmetic (they're dumped raw
// or via separate aggregation, see §5.2 of the WS lifecycle design).
type statsRegistry struct {
	// Cover traffic HTTP POSTs from DirectTransport/CDNTransport.
	CoverPosts atomic.Int64
	// UDP ASSOCIATE poll ticker fires (20ms each) sending a poll POST.
	UdpPolls atomic.Int64
	// Per-stream WebSocket connections opened (fresh WS per SOCKS5 CONNECT).
	WsCreated atomic.Int64
	// Per-stream WebSocket connections died (reader/writer exit).
	WsDied atomic.Int64
	// Per-stream WS upgrades via the ready pool (Acquire returned a warmed WS).
	WsFromPool atomic.Int64
	// Session.EncryptChunk calls (every outgoing data/control frame).
	Encrypts atomic.Int64
	// Session.DecryptChunkSafe calls (every incoming frame).
	Decrypts atomic.Int64
	// Session.DecryptChunkSafe that failed — high number ⇒ wrong key, out-of-window
	// seq, or anti-replay rejection. A healthy client should see zero.
	DecryptFails atomic.Int64
	// SOCKS5 CONNECT requests accepted (both per-stream and pooled paths).
	SocksConnects atomic.Int64
	// Uplink bytes read from SOCKS5 client (before encryption).
	UplinkBytes atomic.Int64
	// Downlink bytes written to SOCKS5 client (after decryption).
	DownlinkBytes atomic.Int64
	// Async writer Run() exits — one of the two death causes for a pool slot.
	// A writer exit means the local 30s (or configured) WriteDeadline fired
	// because CF stalled our send buffer; we then close the conn ourselves.
	// Distinguishing this from a reader-side close is critical for telling
	// "CF closed us" apart from "we closed ourselves" — cross-check 2026-04-15.
	WriterExits atomic.Int64
	// Slot reader goroutine exits (terminal, not timeout continues). Paired
	// with WriterExits to attribute slot deaths. If WriterExits ≫ ReaderExits
	// then CF-side stall is the trigger, not a server-originated close.
	ReaderExits atomic.Int64

	// PQ ClientHello handshake outcomes (T1.1, Phase 2, 2026-04-26).
	// Counters only increment when SHADOWLINK_TLS_PQ=1 — they stay at zero in
	// default builds so a non-zero reading on the dashboard is itself a signal
	// that the PQ path is enabled in the field.
	//
	// Three labels in the Prom exposition (shadowlink_tls_pq_handshake_total):
	//   - success  : pqClientHelloSpec applied + Handshake completed
	//   - fallback : pqClientHelloSpec returned an error so we used helloID
	//                (Handshake itself succeeded on the fallback spec)
	//   - error    : the dial errored on either ApplyPreset or Handshake while
	//                in the PQ branch (regardless of whether the PQ spec or
	//                the fallback spec was loaded — both count as "PQ branch
	//                exposed an error to the caller")
	PQHandshakeSuccess  atomic.Uint64
	PQHandshakeFallback atomic.Uint64
	PQHandshakeError    atomic.Uint64

	// FrameAnomaliesTotal ticks shadowlink_ws_frame_anomaly_total{type=...}
	// when the slot reader receives a terminal (non-timeout) WS read error.
	// Cardinality is bounded by classifyWSReadError's known label set
	// (frameAnomalyReasons) — pre-created in init() so dashboards see a
	// complete label set from the very first error.
	FrameAnomaliesTotal sync.Map // map[string]*atomic.Uint64

	// RateLimitedFromServer ticks every time the WS upgrade or handshake POST
	// surfaces ErrRateLimited (server emitted X-SL-RL: 1 in the decoy response
	// because the per-IP rate limit fired). Task A2 (May audit, 2026-05-01).
	// Paired with the server's shadowlink_ratelimit_sentinel_emitted_total
	// counter on the dashboard so ops can correlate "client backed off" with
	// "server told it to back off". A non-zero rate is ALWAYS a signal the
	// pool is fighting the rate limit.
	RateLimitedFromServer atomic.Int64

	// Bypass routing decisions (Phase A, 2026-05-02). Each TCP/UDP dial
	// from tun2socks routes through BypassDialer; if dst IP is covered by
	// the embedded RIPE RU snapshot or admin override, the dial goes
	// "direct" (system physical interface) instead of through the SOCKS5
	// inner dialer (ShadowLink VPN). On dashboards, match/(match+miss)
	// approximates the fraction of traffic that bypassed the VPN — a
	// healthy Russian session should land between 0.4 and 0.7 depending
	// on which sites the user is hitting.
	BypassMatchTotal atomic.Int64
	BypassMissTotal  atomic.Int64

	// === Phase 0+ (2026-05-14): WS lifecycle refactor metrics ===
	// See docs/superpowers/specs/2026-05-14-shadowlink-ws-lifecycle-design.md §5.2.
	// Counters log via existing 5-sec delta dump in StartStatsLogger.

	// --- Slot lifecycle (Phase 3+: ticked by SlotSupervisor) ---
	SlotTransitionsToReady       atomic.Uint64
	SlotTransitionsToDraining    atomic.Uint64
	SlotTransitionsToCoolingDown atomic.Uint64
	// SlotDrainForceTimeouts — increments when a slot enters Draining and
	// EventInflightDone doesn't arrive within 30s, forcing transition with
	// attempt++. Operational signal: persistent growth indicates zombie
	// streams or server-side overload preventing graceful drain.
	SlotDrainForceTimeouts atomic.Uint64
	// SlotStaleEvents — increments when reader/writer goroutine sends an
	// event after StopReaderWriter completed. Race indicator. Should stay
	// near zero in steady state; non-zero rate suggests supervisor
	// blocking-action contract violated.
	SlotStaleEvents atomic.Uint64

	// --- Reconnect dynamics (Phase 3+) ---
	ReconnectAttemptsSuccess          atomic.Uint64
	ReconnectAttemptsFail             atomic.Uint64
	ReconnectCoolDownSourceRLDirected atomic.Uint64
	ReconnectCoolDownSourceBackoff    atomic.Uint64

	// Reconnect backoff distribution — bucketed counters as histogram
	// approximation. On each scheduled backoff, increment the smallest
	// bucket whose upper bound >= duration. Lets slog post-processors
	// derive approximate P50/P95 without TSDB.
	ReconnectBackoffBucketLe2s  atomic.Uint64
	ReconnectBackoffBucketLe5s  atomic.Uint64
	ReconnectBackoffBucketLe15s atomic.Uint64
	ReconnectBackoffBucketLe30s atomic.Uint64
	ReconnectBackoffBucketLe60s atomic.Uint64
	ReconnectBackoffBucketGt60s atomic.Uint64

	// --- Rate-limit detection (Phase 2+) ---
	RateLimitDetectedByBody   atomic.Uint64
	RateLimitDetectedByHeader atomic.Uint64
	// RateLimitDetectedFallback — no carrier signal extracted from response,
	// but body starts with '<' (HTML decoy). Lifeline path: client applies
	// default 90s cooldown to avoid tight reconnect loop. Non-zero rate
	// suggests CDN is stripping both header and body marker — operational
	// signal to investigate CF Transform Rules / Speed Brain settings.
	RateLimitDetectedFallback atomic.Uint64

	// === Phase 2 (2026-05-14) per-path rate-limit counters ===
	// Split detection events by transport path so ops can triage "which gate is
	// being throttled?" without guessing. The aggregate counters above
	// (RateLimitDetectedBy{Body,Header,Fallback}) are preserved for back-compat
	// and always equal the sum of the corresponding per-path fields.
	//
	// "handshake" path: transport.go DirectTransport.SendHandshake /
	//   SendHandshakeRaw — POST-only, detector runs Detect() (with lifeline).
	// "ws_upgrade" path: ws_transport.go WebSocketTransport.UpgradeToWS —
	//   WS Dial response, detector runs DetectCarriersOnly() (no lifeline).
	//
	// Note: no RateLimitDetectedFallback_WS — the WS path uses
	// DetectCarriersOnly which never fires the lifeline.
	RateLimitDetectedByBody_Handshake   atomic.Uint64
	RateLimitDetectedByBody_WS          atomic.Uint64
	RateLimitDetectedByHeader_Handshake atomic.Uint64
	RateLimitDetectedByHeader_WS        atomic.Uint64
	RateLimitDetectedFallback_Handshake atomic.Uint64

	// --- WS reader/writer health (Phase −1 partial, full Phase 3+) ---
	WSReaderExitsEOF     atomic.Uint64
	WSReaderExitsTimeout atomic.Uint64
	WSReaderExitsOther   atomic.Uint64
	// WSReaderPanics MUST stay at 0 in production. Tracks gorilla's
	// defensive "repeated read on failed websocket connection" panic
	// recovery. Phase −1 fix eliminated the known trigger; counter
	// remains as canary. Non-zero value = unrecognized bug.
	WSReaderPanics atomic.Uint64
	WSWriterExits  atomic.Uint64
}

// Cold-start observability counters (Task D5, 2026-05-02 plan).
//
// Captures the time-to-first-byte the user actually perceives during cold
// start, plus the underlying pool warmup duration. Two related counters
// expose the cold-start failure modes the pool was designed to absorb:
//   - rate-limit decoys received during handshake / WS upgrade,
//   - SOCKS5 demand getting batched by the coalescing dispatcher.
//
// All five live as package-level atomics + helpers (mirrors the spec in the
// 2026-05-02 plan §D5). FirstStreamMS / PoolWarmupMS are gauges holding the
// most-recent observed duration — a fresh cold start overwrites the prior
// value. The decoy/coalesce counters are monotonic since process start.
var (
	// FirstStreamMS — gauge: ms from Client.Connect() success to the first
	// SOCKS5 stream being attached (CONNECT_OK sent back to the SOCKS5
	// caller). Stamped exactly once per Connect() cycle via
	// firstStreamOnce on the Client; subsequent SOCKS5 CONNECTs do not
	// touch the gauge until the next Connect().
	FirstStreamMS atomic.Int64

	// PoolWarmupMS — gauge: ms from WSReadyPool.Start() to all
	// RequireDone=true phases having every slot publish to the ready
	// channel. Tail (RequireDone=false) phases are NOT included — the
	// gauge measures "the moment the pool is ready to serve a SOCKS5
	// burst", and best-effort tail slots are bonus capacity that arrives
	// later.
	PoolWarmupMS atomic.Int64

	// HandshakeDecoyReceived — counter: number of times the client's
	// handshake POST or WS upgrade got a server-emitted decoy response
	// (HTTP 200 + X-SL-RL header). Incremented at the first detection
	// site (transport.go SendHandshake AND ws_transport.go UpgradeToWS)
	// — both paths can independently trip the per-IP rate limiter. Paired
	// with Stats.RateLimitedFromServer on dashboards: this counter is the
	// "saw a decoy" event, RateLimitedFromServer ticks per reconnect-loop
	// cool-down. Dashboards plot decoys/min as the leading indicator.
	HandshakeDecoyReceived atomic.Int64

	// SOCKS5CoalesceGrouped — counter: number of SOCKS5 CONNECTs that
	// joined an in-flight coalescing window in
	// proxy/socks5/coalesce.go::CoalescingDispatcher. Counts every queued
	// joiner including the first caller of the window, so
	// SOCKS5CoalesceGroups is always ≤ SOCKS5CoalesceGrouped. The ratio
	// (Grouped - Groups) / Grouped is the fraction of CONNECTs that
	// benefited from batching (avoided a redundant pool acquire under
	// burst).
	SOCKS5CoalesceGrouped atomic.Int64

	// SOCKS5CoalesceGroups — counter: number of distinct coalescing
	// windows (groups) created. Ticks once per dispatcher window
	// (regardless of how many CONNECTs end up in it).
	SOCKS5CoalesceGroups atomic.Int64
)

// SetFirstStreamMS stamps the gauge with the elapsed duration. Caller is
// expected to gate the call with a sync.Once so only the very first
// SOCKS5 stream-attached event of the Connect cycle wins.
func SetFirstStreamMS(d time.Duration) { FirstStreamMS.Store(d.Milliseconds()) }

// SetPoolWarmupMS stamps the pool-warmup gauge. Called once per
// WSReadyPool.Start() lifecycle from a dedicated watcher goroutine when
// every RequireDone=true phase has tallied to its target.
func SetPoolWarmupMS(d time.Duration) { PoolWarmupMS.Store(d.Milliseconds()) }

// IncHandshakeDecoyReceived ticks the decoy-received counter. Called at
// the rate-limit detection sites in transport.go (handshake POST) and
// ws_transport.go (WS upgrade) — both surface ErrRateLimited to the caller.
func IncHandshakeDecoyReceived() { HandshakeDecoyReceived.Add(1) }

// IncSOCKS5CoalesceGrouped accepts the joiner count for a single
// coalescing window. n must be ≥ 0; values ≤ 0 are no-ops.
func IncSOCKS5CoalesceGrouped(n int) {
	if n <= 0 {
		return
	}
	SOCKS5CoalesceGrouped.Add(int64(n))
}

// IncSOCKS5CoalesceGroups ticks the per-group counter — exactly one call
// per coalescing window, regardless of the number of joiners.
func IncSOCKS5CoalesceGroups() { SOCKS5CoalesceGroups.Add(1) }

// Stats is the singleton stats registry. All increments across the codebase
// use this variable directly.
var Stats statsRegistry

// frameAnomalyReasons enumerates the labels emitted under
// shadowlink_ws_frame_anomaly_total. Kept in sync with classifyWSReadError
// (ws_pool.go) so dashboards see all series at startup. Adding a new label
// here AND in the classifier is required.
var frameAnomalyReasons = []string{
	"rsv",             // gorilla "RSV1/2/3 set" — corrupted/non-conformant frame header
	"opcode",          // gorilla "bad opcode" — frame header parser saw unsupported opcode
	"html",            // first bytes look like HTTP/HTML — middlebox returned an error page on a WS conn
	"close_1011",      // explicit WS close 1011 (server going away / internal error)
	"close_other",     // other WS close codes (1000/1001/1006/1008/...)
	"closed_local",    // "use of closed network connection" — we Close()d this conn
	"reset_by_peer",   // TCP RST surfaced by kernel — distinct from orderly FIN (eof)
	"io_timeout",      // read/write deadline expired — stalled, not torn down
	"message_too_big", // gorilla "read limit exceeded" — frame larger than ReadLimit
	"eof",             // EOF / unexpected EOF — orderly TCP FIN
	"tls",             // TLS-layer error (handshake done but record layer failed)
	"other",           // catch-all — review log line for unknown patterns
}

func init() {
	// Wire core.Session encrypt/decrypt counters into our atomic stats without
	// making core/ depend on client/.
	core.SetStatsCallbacks(
		func() { Stats.Encrypts.Add(1) },
		func() { Stats.Decrypts.Add(1) },
		func() { Stats.DecryptFails.Add(1) },
	)
	for _, r := range frameAnomalyReasons {
		Stats.frameAnomalyCounter(r)
	}
}

// frameAnomalyCounter returns (creating if needed) the counter for one of
// frameAnomalyReasons. sync.Map LoadOrStore guarantees one canonical entry
// under concurrent first-touch.
func (s *statsRegistry) frameAnomalyCounter(reason string) *atomic.Uint64 {
	if v, ok := s.FrameAnomaliesTotal.Load(reason); ok {
		return v.(*atomic.Uint64)
	}
	c := new(atomic.Uint64)
	actual, _ := s.FrameAnomaliesTotal.LoadOrStore(reason, c)
	return actual.(*atomic.Uint64)
}

// IncBypassMatch ticks shadowlink_bypass_match_total — set when a dial's
// destination IP is covered by the bypass trie and goes via the direct dialer.
func (s *statsRegistry) IncBypassMatch() { s.BypassMatchTotal.Add(1) }

// IncBypassMiss ticks shadowlink_bypass_miss_total — set when a dial goes
// via the SOCKS5 inner dialer (i.e. through the VPN tunnel).
func (s *statsRegistry) IncBypassMiss() { s.BypassMissTotal.Add(1) }

// IncFrameAnomaly ticks shadowlink_ws_frame_anomaly_total{type=<reason>}.
// reason MUST come from frameAnomalyReasons; unknown values collapse to
// "other" so cardinality stays bounded.
func (s *statsRegistry) IncFrameAnomaly(reason string) {
	if !slices.Contains(frameAnomalyReasons, reason) {
		reason = "other"
	}
	s.frameAnomalyCounter(reason).Add(1)
}

// WritePromMetrics emits the post-T1.1 client-side counters in the
// Prometheus text exposition format (v0.0.4). Only the counters whose
// underlying source-of-truth lives in the client package are exported here;
// server-side counters are exposed by server.Metrics.ServeHTTP.
//
// Mirrors the server/metrics.go writePromMetrics pattern (zero-dep, no
// promauto) so a test harness or future client-side admin endpoint can
// scrape this without a registry.
//
// T1.1 (Phase 2, 2026-04-26) introduces shadowlink_tls_pq_handshake_total
// with three labels: success / fallback / error. The counter only ticks when
// SHADOWLINK_TLS_PQ=1; default builds emit zeros across all three labels.
func WritePromMetrics(w io.Writer) {
	fmt.Fprintf(w, "# HELP shadowlink_tls_pq_handshake_total PQ ClientHello handshake outcomes (only ticks when SHADOWLINK_TLS_PQ=1)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_tls_pq_handshake_total counter\n")
	fmt.Fprintf(w, "shadowlink_tls_pq_handshake_total{result=\"success\"} %d\n", Stats.PQHandshakeSuccess.Load())
	fmt.Fprintf(w, "shadowlink_tls_pq_handshake_total{result=\"fallback\"} %d\n", Stats.PQHandshakeFallback.Load())
	fmt.Fprintf(w, "shadowlink_tls_pq_handshake_total{result=\"error\"} %d\n", Stats.PQHandshakeError.Load())

	// T1.6 cover-GET scheduler series retired 2026-05-02 (F3 wire/transport
	// DPI followup). The cover-GET periodic emission was itself an FFT-visible
	// signal and the peer tools we benchmark against (Reality, Hysteria2,
	// TrustTunnel) ship with no cover GETs and operate cleanly in Russia.
	// Counters dropped: shadowlink_cover_get_sent_total{path},
	// shadowlink_cover_get_send_errors_total{reason},
	// shadowlink_cover_get_ratio_observed. Dashboards must drop these series.

	// R.3a frame-anomaly classifier series. Iteration order is the
	// frameAnomalyReasons slice so the exposition output is deterministic.
	fmt.Fprintf(w, "# HELP shadowlink_ws_frame_anomaly_total WS slot read errors classified by failure mode (rsv|opcode|html|close_1011|close_other|closed_local|reset_by_peer|io_timeout|message_too_big|eof|tls|other)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ws_frame_anomaly_total counter\n")
	for _, r := range frameAnomalyReasons {
		fmt.Fprintf(w, "shadowlink_ws_frame_anomaly_total{type=\"%s\"} %d\n", r, Stats.frameAnomalyCounter(r).Load())
	}

	fmt.Fprintf(w, "# HELP shadowlink_bypass_match_total Dials routed via direct dialer (bypassing the VPN) because dst IP matched the bypass trie\n")
	fmt.Fprintf(w, "# TYPE shadowlink_bypass_match_total counter\n")
	fmt.Fprintf(w, "shadowlink_bypass_match_total %d\n", Stats.BypassMatchTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_bypass_miss_total Dials routed via the SOCKS5 inner dialer (through the VPN tunnel)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_bypass_miss_total counter\n")
	fmt.Fprintf(w, "shadowlink_bypass_miss_total %d\n", Stats.BypassMissTotal.Load())

	// Cold-start observability series (Task D5, 2026-05-02 plan).
	fmt.Fprintf(w, "# HELP shadowlink_first_stream_ms Milliseconds from Client.Connect() to first SOCKS5 stream attached (most recent observation)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_first_stream_ms gauge\n")
	fmt.Fprintf(w, "shadowlink_first_stream_ms %d\n", FirstStreamMS.Load())

	fmt.Fprintf(w, "# HELP shadowlink_pool_warmup_ms Milliseconds from WSReadyPool.Start() to all RequireDone=true phases ready (most recent observation)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_pool_warmup_ms gauge\n")
	fmt.Fprintf(w, "shadowlink_pool_warmup_ms %d\n", PoolWarmupMS.Load())

	fmt.Fprintf(w, "# HELP shadowlink_handshake_decoy_received_total Handshake POST or WS upgrade responses tagged X-SL-RL by the server (rate-limit decoy)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_handshake_decoy_received_total counter\n")
	fmt.Fprintf(w, "shadowlink_handshake_decoy_received_total %d\n", HandshakeDecoyReceived.Load())

	fmt.Fprintf(w, "# HELP shadowlink_socks5_coalesce_grouped_total SOCKS5 CONNECTs that joined a coalescing window (includes first-of-window callers)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_socks5_coalesce_grouped_total counter\n")
	fmt.Fprintf(w, "shadowlink_socks5_coalesce_grouped_total %d\n", SOCKS5CoalesceGrouped.Load())

	fmt.Fprintf(w, "# HELP shadowlink_socks5_coalesce_groups_total Distinct coalescing windows created in CoalescingDispatcher\n")
	fmt.Fprintf(w, "# TYPE shadowlink_socks5_coalesce_groups_total counter\n")
	fmt.Fprintf(w, "shadowlink_socks5_coalesce_groups_total %d\n", SOCKS5CoalesceGroups.Load())
}

// StartStatsLogger launches a goroutine that logs counter deltas every
// interval until ctx is cancelled. Called from the client engine after
// Connect() succeeds so we don't log while the session is still coming up.
//
// First line after the first interval is `delta over N.Ns` so it's obvious
// the numbers are per-interval, not cumulative.
func StartStatsLogger(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	go func() {
		var (
			lastCover, lastUDP, lastWSNew, lastWSDie, lastPool int64
			lastEnc, lastDec, lastDecFail                      int64
			lastSocks, lastUp, lastDown                        int64
			lastWriterExits, lastReaderExits                   int64
			lastBypassMatch, lastBypassMiss                    int64
		)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			cover := Stats.CoverPosts.Load()
			udp := Stats.UdpPolls.Load()
			wsNew := Stats.WsCreated.Load()
			wsDie := Stats.WsDied.Load()
			pool := Stats.WsFromPool.Load()
			enc := Stats.Encrypts.Load()
			dec := Stats.Decrypts.Load()
			decFail := Stats.DecryptFails.Load()
			socks := Stats.SocksConnects.Load()
			up := Stats.UplinkBytes.Load()
			down := Stats.DownlinkBytes.Load()
			writerExits := Stats.WriterExits.Load()
			readerExits := Stats.ReaderExits.Load()
			bypassMatch := Stats.BypassMatchTotal.Load()
			bypassMiss := Stats.BypassMissTotal.Load()

			slog.Info("shadowlink client stats (delta)",
				"interval", interval,
				"cover_posts", cover-lastCover,
				"udp_polls", udp-lastUDP,
				"ws_created", wsNew-lastWSNew,
				"ws_died", wsDie-lastWSDie,
				"ws_from_pool", pool-lastPool,
				"encrypts", enc-lastEnc,
				"decrypts", dec-lastDec,
				"decrypt_fails", decFail-lastDecFail,
				"socks_connects", socks-lastSocks,
				"uplink_kb", (up-lastUp)/1024,
				"downlink_kb", (down-lastDown)/1024,
				"writer_exits", writerExits-lastWriterExits,
				"reader_exits", readerExits-lastReaderExits,
				"bypass_match", bypassMatch-lastBypassMatch,
				"bypass_miss", bypassMiss-lastBypassMiss,
			)

			lastCover, lastUDP, lastWSNew, lastWSDie, lastPool = cover, udp, wsNew, wsDie, pool
			lastEnc, lastDec, lastDecFail = enc, dec, decFail
			lastSocks, lastUp, lastDown = socks, up, down
			lastWriterExits, lastReaderExits = writerExits, readerExits
			lastBypassMatch, lastBypassMiss = bypassMatch, bypassMiss
		}
	}()
}

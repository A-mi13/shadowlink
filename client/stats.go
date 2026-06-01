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
	// PQClientHelloSent — count of TLS ClientHellos sent with X25519MLKEM768
	// in supported_groups + key_share where the subsequent TLS handshake also
	// completed. Was named PQHandshakeSuccess until 2026-05-17 (Wave 3.3);
	// renamed because CF edge may negotiate classical X25519 in ServerHello
	// while we still record the ClientHello attempt — the metric tracks what
	// we send, not what completes with PQ on the server side. See
	// docs/superpowers/plans/2026-05-17-pq-wireshark-check.md for the
	// one-time wire-level verification procedure.
	//
	// Three labels in the Prom exposition (shadowlink_tls_pq_handshake_total):
	//   - clienthello_sent : pqClientHelloSpec applied + Handshake completed
	//                        (was "success" prior to 2026-05-17 rename)
	//   - fallback         : pqClientHelloSpec returned an error so we used
	//                        helloID (Handshake itself succeeded on the
	//                        fallback spec)
	//   - error            : the dial errored on either ApplyPreset or
	//                        Handshake while in the PQ branch (regardless of
	//                        whether the PQ spec or the fallback spec was
	//                        loaded — both count as "PQ branch exposed an
	//                        error to the caller")
	PQClientHelloSent   atomic.Uint64
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

	// === Phase 2 (2026-05-14) per-path rate-limit counters ===
	// Split detection events by transport path so ops can triage "which gate is
	// being throttled?" without guessing. The aggregate counters above
	// (RateLimitDetectedBy{Body,Header}) are preserved for back-compat
	// and always equal the sum of the corresponding per-path fields.
	//
	// "handshake" path: transport.go DirectTransport.SendHandshake /
	//   SendHandshakeRaw — POST-only.
	// "ws_upgrade" path: ws_transport.go WebSocketTransport.UpgradeToWS —
	//   WS Dial response.
	//
	// Both paths run DetectCarriersOnly() — only a genuine Schema.org body
	// marker or X-SL-RL header triggers a rate-limit signal.
	RateLimitDetectedByBody_Handshake   atomic.Uint64
	RateLimitDetectedByBody_WS          atomic.Uint64
	RateLimitDetectedByHeader_Handshake atomic.Uint64
	RateLimitDetectedByHeader_WS        atomic.Uint64

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

	// === WS Pool Graceful Drain metrics (2026-05-19) ===
	// See docs/superpowers/specs/2026-05-19-shadowlink-ws-pool-graceful-drain-design.md.
	// Populated by drainWatchdog (Task 8). Monotonic event counters →
	// atomic.Uint64 per the Phase 0+ convention (not part of delta dump).
	//
	// DrainStartedTotal — every startDrain invocation (a slot transitioned
	// from slotReady to slotDraining). Pairs with the sum of the two
	// finish counters: in steady state Started == NaturalFinish + HardCap.
	// A persistent gap is the signal that a watchdog goroutine leaked.
	DrainStartedTotal atomic.Uint64
	// DrainNaturalFinishTotal — drains that completed because in-flight
	// stream count reached zero before the hard cap. Healthy field
	// operation expects this to dominate DrainHardCapTotal (long-tail
	// streams are uncommon).
	DrainNaturalFinishTotal atomic.Uint64
	// DrainHardCapTotal — drains that were force-torn-down by the hard
	// cap deadline (SHADOWLINK_DRAIN_HARD_CAP, default 90s). A growing
	// ratio of HardCap / Started indicates long-lived SOCKS5 streams
	// (file downloads, persistent connections) that survive rotation
	// — review whether to extend the cap or rotate less aggressively.
	DrainHardCapTotal atomic.Uint64
	// Bug #6 sticky stream counters.
	// DrainStickyExtendedTotal — times the deadline branch extended a drain
	// because an active stream was still flowing (incremented in Task 6).
	DrainStickyExtendedTotal atomic.Uint64
	// DrainStickyBackstopAgeTotal — sticky drains torn down because the
	// per-drain age backstop (StickyMaxDrainAge) fired on an active stream.
	DrainStickyBackstopAgeTotal atomic.Uint64
	// DrainStickyBackstopBytesTotal — sticky drains torn down because the
	// per-TCP byte backstop (StickyMaxTotalBytes) fired on an active stream.
	DrainStickyBackstopBytesTotal atomic.Uint64
	// DrainStickyQuotaDeniedTotal — sticky drains torn down because the
	// sticky quota / readyCapacity gate denied (or revoked) the extension.
	DrainStickyQuotaDeniedTotal atomic.Uint64
	// DrainDurationSeconds — distribution of drain durations from
	// startDrain → terminal teardown (either natural finish or hard
	// cap). Bucket boundaries 1/5/10/30/60/90/120s match the operational
	// regimes: <5s = trivial, 5-30s = nominal, 30-90s = stretched, >90s
	// only possible under future hard-cap raise. Initialized in init().
	DrainDurationSeconds *Histogram

	// StaleFrameDroppedTotal — frames arriving on a slot whose
	// streamMap lookup returns a different idx (post-teardown
	// streamID reuse race). See spec 2026-05-20 §2.4.1. A non-zero
	// rate is expected during heavy rotation; sustained high rate is
	// a bug.
	StaleFrameDroppedTotal atomic.Uint64

	// SnapshotNegativeAgeTotal — counts cases where drainStreamSnapshot
	// observed lastWriteNs > now (clock went backwards under NTP adjust,
	// or, worse, arbitrary value stored). Clamped to 0 in snapshot logic;
	// counter exposes the underlying event for observability. Non-zero
	// rate at >1/h indicates clock skew or a stamping bug worth investigating.
	// Spec 2026-05-25 (drain-per-stream-diagnostics).
	SnapshotNegativeAgeTotal atomic.Uint64

	// InflightCapDeferredTotal — drain attempts deferred because
	// inflightDrains already at maxConcurrentDrains. Indicates the
	// rotation scheduler is healthy but at peak concurrency. High rate
	// is OK if bounded; persistent saturation suggests poolSize is too
	// small for the current rotation cadence. Counter increments on
	// EVERY defer; log emission is rate-limited (drainDeferredLogInterval).
	// Spec 2026-05-24 (drain-diagnostics-counter-split).
	InflightCapDeferredTotal atomic.Uint64

	// CapacityFloorDeferredTotal — drain attempts deferred because
	// readyCapacity fell below readyCapacityFloor (poolSize *
	// readyCapacityFloorFraction, see ws_pool.go). Catastrophic path —
	// pool losing slots faster than reconnectLoop heals. Non-zero rate
	// is a warning sign; persistent non-zero rate is cascading-slot-deaths
	// failure mode. Counter increments on EVERY defer; log emission
	// rate-limited. Spec 2026-05-24 (drain-diagnostics-counter-split,
	// updated by concurrency-lift-and-backoff to use the decoupled
	// fraction constant).
	CapacityFloorDeferredTotal atomic.Uint64

	// StreamBufferOverflowsTotal — cumulative count of frames dropped at
	// client.RouteToStream when the per-stream buffered channel (cap 512)
	// is full. Counter increments once per dropped frame, surfaced at
	// stream UnregisterStream as an aggregated INFO log. Non-zero rate
	// indicates SOCKS consumer death races (most often local app closing
	// TCP early) — see spec 2026-05-23.
	StreamBufferOverflowsTotal atomic.Uint64

	// Bug #8 flow control client-side counters.
	FlowWindowUpdatesSent   atomic.Uint64
	FlowWindowUpdateDropped atomic.Uint64 // TryEnqueueControl full → delta kept
	FlowNegotiationTimeout  atomic.Uint64 // ack not received within negotiationAckTimeout

	// Bug #9 §5.4 downlink-reassembler client-side counters.
	// StreamReassemblyOverflow: per-stream reassembler buffered past its byte cap
	// (unfillable gap grew the pending set) → stream broken (degradation).
	// StreamReassemblyGapTimeout: a downlink hole did not close within the gap
	// timeout → stream broken instead of hanging (NEW-1).
	StreamReassemblyOverflow   atomic.Uint64
	StreamReassemblyGapTimeout atomic.Uint64
	// StreamReassemblyBufferedBytes (gauge, Task 19): most-recent total bytes
	// held out-of-order across all active reassemblers. A persistently high
	// reading means downlink holes are common (frequent migration mid-stream
	// or reordering on the WS path); it's the leading indicator before an
	// overflow/gap-timeout teardown actually fires. Stored as the latest
	// observed snapshot — last writer wins, like FirstStreamMS.
	StreamReassemblyBufferedBytes atomic.Int64

	// Bug #9 Task 15 — client MIGRATE/RESUME send-side counters. (Full client
	// migration metrics land in Task 19; these are the minimum the send path
	// needs to surface ack-await outcomes.)
	//   MigrateAttempt: a MIGRATE/RESUME frame was enqueued and we began ack-await.
	//   MigrateOK / MigrateFail: server replied OK / FAIL within the window.
	//   MigrateTimeout: no reply within migrateAckTimeout → stream degraded.
	//   MigrateCapabilityDropped: 3 consecutive timeouts tripped the hysteresis.
	MigrateAttempt           atomic.Uint64
	MigrateOK                atomic.Uint64
	MigrateFail              atomic.Uint64
	MigrateTimeout           atomic.Uint64
	MigrateCapabilityDropped atomic.Uint64
	// MigrateScheduled: count of (stream, slot) preemptive migrations the
	// age-watchdog armed via scheduleSlotMigration (Bug #9 Task 16). Full
	// migration telemetry lands in Task 19; this is the minimum the watchdog
	// trigger surfaces.
	MigrateScheduled atomic.Uint64

	// MigrateResumeOnDeathOK / Fail: outcomes of the reactive RESUME-on-slot-death
	// path (Bug #9 Task 17, §5.5). OK = a stream survived a sudden slot death by
	// re-homing onto a live slot; Fail = no live target or the server refused, so
	// the stream broke (legacy degradation). Full migration telemetry lands in
	// Task 19; these are the minimum the slot-death path surfaces.
	MigrateResumeOnDeathOK   atomic.Uint64
	MigrateResumeOnDeathFail atomic.Uint64

	// DrainForceEvictedTotal — every time startDrain force-evicted an
	// idle slotReady cell (streams==0) because claimFreeSlot returned -1
	// (slice fully occupied). Spec 2026-05-20 §2.2.3 (slice-full
	// eviction policy). Non-zero rate is expected in long-running
	// sessions where stable network keeps cells alive past natural
	// rotation; required to keep anti-fingerprint rotation moving when
	// no natural reader-error frees a cell.
	DrainForceEvictedTotal atomic.Uint64

	// DrainForceEvictedActiveTotal — emergency eviction of a slotReady
	// cell that had ACTIVE streams (streams > 0) because (a) no idle
	// cell was available AND (b) the drain target's slot age exceeded
	// 2× maxSlotAge (over-aged threshold). Spec 2026-05-20 §2.2.3
	// (emergency eviction policy). Each increment represents one or
	// more user-visible SOCKS5 streams killed to break the deadlock —
	// anti-fingerprint priority wins over UX after the over-aged
	// threshold. Sustained non-zero rate means the pool is chronically
	// saturated; consider raising slice size.
	DrainForceEvictedActiveTotal atomic.Uint64

	// EmergencyEvictMigratedTotal — streams SAVED by PREEMPTIVELY migrating them
	// off an emergency-eviction victim cell BEFORE its forced teardown, while the
	// aging TCP is still healthy (spec 2026-06-01 emergency-evict-migrate).
	// Reuses the Bug#9 MIGRATE primitive at the tier-2 eviction site. A healthy
	// non-zero value means capacity-pressure evictions no longer break
	// user-visible flows that had a younger slot to move onto. Streams NOT moved
	// by this pass fall through to handleSlotDeath's RESUME-on-death attempt
	// (counted as MigrateResumeOnDeathOK/Fail) — there is deliberately no
	// separate "killed" counter here, which would double-count streams the
	// teardown's RESUME still rescues.
	EmergencyEvictMigratedTotal atomic.Uint64

	// ReserveConnectFailuresTotal — cumulative count of connectReserveSlot
	// failures (across all cells). High rate suggests TIME_WAIT exhaustion
	// or origin endpoint instability — investigate before raising
	// maxConcurrentDrainsFraction further. Spec 2026-05-24
	// (concurrency-lift-and-backoff).
	ReserveConnectFailuresTotal atomic.Uint64

	// DrainIdleFinishTotal — drains that completed because the slot showed
	// no decrypt/write activity for SHADOWLINK_DRAIN_IDLE_THRESHOLD AND the
	// remaining stream count was ≤ SHADOWLINK_DRAIN_IDLE_STREAMS_MAX. Logged
	// as natural finish (keeps the existing dashboard meaning intact); this
	// counter exposes WHY the natural finish fired so we can distinguish
	// the streams-reached-zero path from the keepalive-idle path. Subset
	// of DrainNaturalFinishTotal: in steady state, NaturalFinish ≥
	// IdleFinish always.
	DrainIdleFinishTotal atomic.Uint64

	// Pool capacity-dip fix (spec 2026-06-01-pool-capacity-dip-fix-design.md).
	//
	// AgeCutReconnectsTotal — slots that died to an EXPECTED TSPU age-cut
	// (mature slot, close 1006) and were reconnected via the fast path
	// (reconnectLoopFast attempt-0 success). The cascade of mature-slot cuts is
	// driven by the middlebox, not us; this counter measures how often the fast
	// reconnect healed the slot near-instantly instead of sitting in the old
	// 5-10s exponential. A steady non-zero rate in direct mode is EXPECTED and
	// healthy (it is the TSPU age-cutting bare-origin TCP).
	AgeCutReconnectsTotal atomic.Uint64

	// AgeCutReconnectFail — age-cut fast reconnect whose attempt-0 connect FAILED
	// (so the loop fell into the exponential ladder). A rising rate is the canary
	// signal that "age-cut" is masking a GENUINE failure (the origin is actually
	// down, not just the middlebox cutting a mature TCP) — if it climbs, the
	// classification (isAgeCut) or the ageCutMinAgeMs threshold needs review.
	// Healthy steady state: near zero (age-cuts reconnect cleanly).
	AgeCutReconnectFail atomic.Uint64

	// CapacityDipTotal — observability counter for the residual capacity dip
	// (Lever 4, counter-only). Incremented when an age-cut would drop the pool's
	// ready capacity below the floor while streams are active — the condition the
	// fast reconnect is meant to shorten. The canary uses this to PROVE the dip
	// is gone after Levers 1+3 ship; a non-zero residual rate gates the (deferred)
	// headroom-mechanism iteration.
	CapacityDipTotal atomic.Uint64
}

// Histogram is a fixed-bucket histogram for duration-style observations.
// Buckets are inclusive upper bounds: an observation x lands in counts[i]
// where i is the smallest index such that x <= buckets[i]. Observations
// exceeding the largest bucket fall into the overflow bucket
// (counts[len(buckets)]). Sum is stored as milliseconds (int64) so atomic
// arithmetic stays exact on a 64-bit integer; convert back to seconds at
// exposition time.
//
// Concurrency: Observe is lock-free (atomic ops on the bucket slice +
// the sum/count); safe for use from any number of goroutines once the
// histogram is published via NewHistogram.
type Histogram struct {
	buckets []float64
	counts  []atomic.Uint64
	sumMs   atomic.Int64
	count   atomic.Uint64
}

// NewHistogram constructs a histogram with the given inclusive upper-bound
// buckets. Buckets MUST be sorted ascending; this is a developer
// invariant, not a runtime check. The slice is retained (not copied) but
// is treated as immutable post-construction.
func NewHistogram(buckets []float64) *Histogram {
	return &Histogram{
		buckets: buckets,
		counts:  make([]atomic.Uint64, len(buckets)+1),
	}
}

// Observe records a single observation in seconds. The observation
// increments exactly one bucket counter (the first whose upper bound is
// >= seconds, or the overflow bucket), plus the running sum (in ms),
// and the total count LAST.
//
// Ordering matters: bucket → sum → count. A concurrent reader that
// samples count first and then walks buckets will see the invariant
// count >= sum(buckets) hold, because every count.Add is published
// strictly after its corresponding bucket.Add. Reading in the opposite
// order (bucket-sum-then-count) would briefly observe count == sum-1.
// Observe itself is not snapshot-atomic across fields — that's
// acceptable for monotonic event counters consumed eventually.
func (h *Histogram) Observe(seconds float64) {
	for i, b := range h.buckets {
		if seconds <= b {
			h.counts[i].Add(1)
			h.sumMs.Add(int64(seconds * 1000))
			h.count.Add(1)
			return
		}
	}
	h.counts[len(h.buckets)].Add(1)
	h.sumMs.Add(int64(seconds * 1000))
	h.count.Add(1)
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

// globalPoolForStatsPtr publishes the running pool transport for the
// shadowlink_drain_inflight gauge. atomic.Pointer keeps reads cheap
// in the exporter hot path. nil if no pool is active.
var globalPoolForStatsPtr atomic.Pointer[WSPoolTransport]

// SetGlobalPoolForStats publishes the pool for gauge exposition.
// Idempotent — last writer wins. Pass nil on Close to clear.
func SetGlobalPoolForStats(p *WSPoolTransport) {
	globalPoolForStatsPtr.Store(p)
}

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
	// Drain duration histogram — buckets in seconds, see field docstring
	// on statsRegistry.DrainDurationSeconds for rationale.
	Stats.DrainDurationSeconds = NewHistogram([]float64{1, 5, 10, 30, 60, 90, 120})
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
	fmt.Fprintf(w, "shadowlink_tls_pq_handshake_total{result=\"clienthello_sent\"} %d\n", Stats.PQClientHelloSent.Load())
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

	// === WS Pool Graceful Drain metrics (2026-05-19) ===
	// See docs/superpowers/specs/2026-05-19-shadowlink-ws-pool-graceful-drain-design.md.
	// Without these exposed in the metrics dump, pl1 canary cannot observe
	// Phase 1 behavior (whether drains are dominated by natural finish or
	// hard cap, and the duration distribution).
	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_started_total Total startDrain invocations (slot transitioned slotReady→slotDraining)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_started_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_started_total %d\n", Stats.DrainStartedTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_natural_finish_total Drains that completed because in-flight stream count reached zero before the hard cap\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_natural_finish_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_natural_finish_total %d\n", Stats.DrainNaturalFinishTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_hard_cap_total Drains force-torn-down by the hard-cap deadline (SHADOWLINK_DRAIN_HARD_CAP, default 90s)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_hard_cap_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_hard_cap_total %d\n", Stats.DrainHardCapTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_drain_sticky_extended_total Times the drain deadline was extended because an active stream was still flowing (Bug #6)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_sticky_extended_total counter\n")
	fmt.Fprintf(w, "shadowlink_drain_sticky_extended_total %d\n", Stats.DrainStickyExtendedTotal.Load())
	fmt.Fprintf(w, "# HELP shadowlink_drain_sticky_backstop_age_total Sticky drains torn down by the per-drain age backstop on an active stream\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_sticky_backstop_age_total counter\n")
	fmt.Fprintf(w, "shadowlink_drain_sticky_backstop_age_total %d\n", Stats.DrainStickyBackstopAgeTotal.Load())
	fmt.Fprintf(w, "# HELP shadowlink_drain_sticky_backstop_bytes_total Sticky drains torn down by the per-TCP byte backstop on an active stream\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_sticky_backstop_bytes_total counter\n")
	fmt.Fprintf(w, "shadowlink_drain_sticky_backstop_bytes_total %d\n", Stats.DrainStickyBackstopBytesTotal.Load())
	fmt.Fprintf(w, "# HELP shadowlink_drain_sticky_quota_denied_total Sticky drains torn down because the quota/readyCapacity gate denied the extension\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_sticky_quota_denied_total counter\n")
	fmt.Fprintf(w, "shadowlink_drain_sticky_quota_denied_total %d\n", Stats.DrainStickyQuotaDeniedTotal.Load())

	// Histogram exposition: cumulative bucket counts with le-labels, plus
	// _sum (seconds) and _count. Matches Prometheus histogram conventions.
	if h := Stats.DrainDurationSeconds; h != nil {
		fmt.Fprintf(w, "# HELP shadowlink_slot_drain_duration_seconds Drain duration from startDrain to teardown (natural or hard cap)\n")
		fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_duration_seconds histogram\n")
		var cumulative uint64
		for i, b := range h.buckets {
			cumulative += h.counts[i].Load()
			fmt.Fprintf(w, "shadowlink_slot_drain_duration_seconds_bucket{le=\"%g\"} %d\n", b, cumulative)
		}
		cumulative += h.counts[len(h.buckets)].Load()
		fmt.Fprintf(w, "shadowlink_slot_drain_duration_seconds_bucket{le=\"+Inf\"} %d\n", cumulative)
		fmt.Fprintf(w, "shadowlink_slot_drain_duration_seconds_sum %g\n", float64(h.sumMs.Load())/1000.0)
		fmt.Fprintf(w, "shadowlink_slot_drain_duration_seconds_count %d\n", h.count.Load())
	}

	fmt.Fprintf(w, "# HELP shadowlink_stale_frame_dropped_total Frames dropped due to streamID reuse race after drain teardown\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stale_frame_dropped_total counter\n")
	fmt.Fprintf(w, "shadowlink_stale_frame_dropped_total %d\n", Stats.StaleFrameDroppedTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_inflight_cap_deferred_total Drains deferred by storm-brake inflight-cap gate (concurrent drains >= maxConcurrentDrains)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_inflight_cap_deferred_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_inflight_cap_deferred_total %d\n", Stats.InflightCapDeferredTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_capacity_floor_deferred_total Drains deferred by storm-brake capacity-floor gate (readyCapacity < poolSize * readyCapacityFloorFraction)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_capacity_floor_deferred_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_capacity_floor_deferred_total %d\n", Stats.CapacityFloorDeferredTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_force_evicted_total Force-evictions of idle slotReady cells when claimFreeSlot would have returned -1 (slice full)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_force_evicted_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_force_evicted_total %d\n", Stats.DrainForceEvictedTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_stream_buffer_overflows_total Frames dropped at RouteToStream because the per-stream buffered channel was full (consumer dead/slow)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stream_buffer_overflows_total counter\n")
	fmt.Fprintf(w, "shadowlink_stream_buffer_overflows_total %d\n", Stats.StreamBufferOverflowsTotal.Load())
	fmt.Fprintf(w, "# HELP shadowlink_flow_window_updates_sent_total WINDOW_UPDATE frames sent by the client credit sender (Bug #8)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_window_updates_sent_total counter\n")
	fmt.Fprintf(w, "shadowlink_flow_window_updates_sent_total %d\n", Stats.FlowWindowUpdatesSent.Load())
	fmt.Fprintf(w, "# HELP shadowlink_flow_window_update_dropped_total WINDOW_UPDATE sends skipped because the control channel was full; delta retained (Bug #8)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_window_update_dropped_total counter\n")
	fmt.Fprintf(w, "shadowlink_flow_window_update_dropped_total %d\n", Stats.FlowWindowUpdateDropped.Load())
	fmt.Fprintf(w, "# HELP shadowlink_flow_negotiation_timeout_total Flow-control negotiation acks not received within the timeout (old server / off) (Bug #8)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_negotiation_timeout_total counter\n")
	fmt.Fprintf(w, "shadowlink_flow_negotiation_timeout_total %d\n", Stats.FlowNegotiationTimeout.Load())

	fmt.Fprintf(w, "# HELP shadowlink_stream_reassembly_overflow_total Migration downlink reassembler exceeded its per-stream byte cap; stream broken (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stream_reassembly_overflow_total counter\n")
	fmt.Fprintf(w, "shadowlink_stream_reassembly_overflow_total %d\n", Stats.StreamReassemblyOverflow.Load())
	fmt.Fprintf(w, "# HELP shadowlink_stream_reassembly_gap_timeout_total Migration downlink hole did not close within the gap timeout; stream broken instead of hung (Bug #9, NEW-1)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stream_reassembly_gap_timeout_total counter\n")
	fmt.Fprintf(w, "shadowlink_stream_reassembly_gap_timeout_total %d\n", Stats.StreamReassemblyGapTimeout.Load())
	fmt.Fprintf(w, "# HELP shadowlink_stream_reassembly_buffered_bytes Bytes currently held out-of-order across all downlink reassemblers (most recent observation) (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stream_reassembly_buffered_bytes gauge\n")
	fmt.Fprintf(w, "shadowlink_stream_reassembly_buffered_bytes %d\n", Stats.StreamReassemblyBufferedBytes.Load())

	// Bug #9 MIGRATE/RESUME client send-side + watchdog + slot-death telemetry.
	// Counters defined incrementally across Tasks 15-17; Task 19 surfaces them
	// in the exposition so the pl1 canary can observe migration health
	// (attempt → ok/fail/timeout funnel, capability-drop hysteresis trips,
	// preemptive schedules, and reactive resume outcomes).
	fmt.Fprintf(w, "# HELP shadowlink_migrate_attempt_total MIGRATE/RESUME frames enqueued and entering ack-await (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_attempt_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_attempt_total %d\n", Stats.MigrateAttempt.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_ok_total MIGRATE/RESUME acks that returned OK within the window (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_ok_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_ok_total %d\n", Stats.MigrateOK.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_fail_total MIGRATE/RESUME acks that returned FAIL within the window (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_fail_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_fail_total %d\n", Stats.MigrateFail.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_timeout_total MIGRATE/RESUME ack-await expired without a reply; stream degraded (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_timeout_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_timeout_total %d\n", Stats.MigrateTimeout.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_capability_dropped_total Consecutive migrate timeouts tripped the hysteresis; migration capability dropped (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_capability_dropped_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_capability_dropped_total %d\n", Stats.MigrateCapabilityDropped.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_scheduled_total Preemptive (stream, slot) migrations armed by the age-watchdog (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_scheduled_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_scheduled_total %d\n", Stats.MigrateScheduled.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_resume_on_death_ok_total Streams that survived a sudden slot death by re-homing onto a live slot (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_resume_on_death_ok_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_resume_on_death_ok_total %d\n", Stats.MigrateResumeOnDeathOK.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_resume_on_death_fail_total Streams that broke on a sudden slot death (no live target or server refused) (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_resume_on_death_fail_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_resume_on_death_fail_total %d\n", Stats.MigrateResumeOnDeathFail.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_force_evicted_active_total Emergency evictions of slotReady cells with active streams (over-aged drain target, no idle cell available)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_force_evicted_active_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_force_evicted_active_total %d\n", Stats.DrainForceEvictedActiveTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_emergency_evict_migrated_total Streams preemptively migrated off an emergency-eviction victim cell before its forced teardown (spec 2026-06-01). Reuses the Bug#9 MIGRATE primitive; non-zero means capacity-pressure evictions no longer break flows that had a younger slot to move onto. Streams not moved here fall through to RESUME-on-death (see migrate_resume_on_death_*).\n")
	fmt.Fprintf(w, "# TYPE shadowlink_emergency_evict_migrated_total counter\n")
	fmt.Fprintf(w, "shadowlink_emergency_evict_migrated_total %d\n", Stats.EmergencyEvictMigratedTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_reserve_connect_failures_total Cumulative count of connectReserveSlot failures across all cells. High sustained rate suggests TIME_WAIT exhaustion or origin endpoint instability — investigate before raising maxConcurrentDrainsFraction further.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_reserve_connect_failures_total counter\n")
	fmt.Fprintf(w, "shadowlink_reserve_connect_failures_total %d\n", Stats.ReserveConnectFailuresTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_idle_finish_total Drains classified as natural finish via the idle heuristic (no activity for SHADOWLINK_DRAIN_IDLE_THRESHOLD, ≤ SHADOWLINK_DRAIN_IDLE_STREAMS_MAX remaining streams). Subset of natural_finish_total.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_idle_finish_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_idle_finish_total %d\n", Stats.DrainIdleFinishTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_drain_inflight Drains currently in progress (atomic snapshot)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_inflight gauge\n")
	if pool := globalPoolForStatsPtr.Load(); pool != nil {
		fmt.Fprintf(w, "shadowlink_drain_inflight %d\n", pool.inflightDrains.Load())
	} else {
		fmt.Fprintf(w, "shadowlink_drain_inflight 0\n")
	}

	// Pool capacity-dip fix (2026-06-01).
	fmt.Fprintf(w, "# HELP shadowlink_age_cut_reconnects_total Slots that died to an expected TSPU age-cut (mature slot, close 1006) and were reconnected via the fast path. Steady non-zero rate in direct mode is expected (TSPU age-cutting bare-origin TCP).\n")
	fmt.Fprintf(w, "# TYPE shadowlink_age_cut_reconnects_total counter\n")
	fmt.Fprintf(w, "shadowlink_age_cut_reconnects_total %d\n", Stats.AgeCutReconnectsTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_age_cut_reconnect_fail_total Age-cut fast reconnects whose attempt-0 connect failed (fell into the exponential ladder). A rising rate signals age-cut is masking a genuine origin failure — review isAgeCut / ageCutMinAgeMs.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_age_cut_reconnect_fail_total counter\n")
	fmt.Fprintf(w, "shadowlink_age_cut_reconnect_fail_total %d\n", Stats.AgeCutReconnectFail.Load())

	fmt.Fprintf(w, "# HELP shadowlink_capacity_dip_total Times an age-cut would drop ready pool capacity below the floor while streams were active. Canary observability for the residual dip after the fast-reconnect fix; gates the deferred headroom-mechanism iteration.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_capacity_dip_total counter\n")
	fmt.Fprintf(w, "shadowlink_capacity_dip_total %d\n", Stats.CapacityDipTotal.Load())
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

package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// Metrics tracks server performance and resource usage.
type Metrics struct {
	ActiveClients      atomic.Int64
	ActiveConnections  atomic.Int64
	ChunksReceived     atomic.Uint64
	ChunksSent         atomic.Uint64
	BytesReceived      atomic.Uint64
	BytesSent          atomic.Uint64
	// HandshakesTotal — number of SUCCESSFUL handshake completions. Despite
	// the "Total" suffix, this counter is ticked only after ALL validation
	// passes: DecryptClientID + replay check + IsAuthorized + device-limit
	// check (see handler.go::handleHandshakeNew, after the exemption.MarkSeen
	// call). It is NOT a union of all outcomes. For outcome-split telemetry
	// see HandshakesOK (identical value, kept for dashboard clarity),
	// HandshakesAuthFailed, HandshakesMalformed, and HandshakesFailed.
	// Naming inherited from pre-2026-05 era; not renamed to avoid breaking
	// existing dashboard/alert queries that reference the metric name.
	HandshakesTotal    atomic.Uint64
	HandshakesNewTotal atomic.Uint64 // phase-tracking: handshakes served via body-prefix path
	HandshakesFailed   atomic.Uint64
	RejectedOverload   atomic.Uint64
	TimingOracleHits   atomic.Uint64 // hits on failClosedToDecoy; canary for DPI probing volume
	// NewPathHits counts POST dispatches routed to handleNewFormatPost.
	// Phase 0 retire (2026-04-26) deleted LegacyPathHits / DualAuthDetected /
	// HandshakesLegacyTotal / V0FallbackFromNewPath — legacy paths gone.
	NewPathHits atomic.Uint64

	// RateLimitSentinelEmitted counts decoy responses that carried the
	// X-SL-RL: 1 sentinel header (Task A2, May audit 2026-05-01). Ticked
	// from the two rate-limit branches of handleHandshakeNew + handleWebSocket
	// only — generic failClosedToDecoy callers (decrypt fail / replay reject /
	// backpressure / max-clients) do NOT increment this counter. The series
	// lets ops chart how often clients are rate-limited; a sustained non-zero
	// rate paired with a flat HandshakesNewTotal indicates a real flood.
	RateLimitSentinelEmitted atomic.Uint64

	// RatelimitClientIDExempted counts data-path / subsequent-handshake requests
	// that bypassed the per-IP rate-limit bucket via the §C4 ClientID exemption
	// fast path. A persistent non-zero rate confirms that authenticated clients
	// keep flowing under cold-start cascades; a flat counter paired with a
	// growing RateLimitSentinelEmitted signals exemption is misconfigured (TTL
	// too short, soft cap too tight) or the env flag is off.
	RatelimitClientIDExempted atomic.Uint64
	// RatelimitClientIDSoftLimitRejected counts exempt clientIDs whose soft cap
	// (default 60/min) tripped. Distinguishes "client legitimately busy" from
	// "client weaponized as bypass" — a single bad actor's clientID should be
	// the one ticking this counter.
	RatelimitClientIDSoftLimitRejected atomic.Uint64

	// === Phase 0+ (2026-05-14): WS lifecycle + sentinel framework metrics ===
	// See docs/superpowers/specs/2026-05-14-shadowlink-ws-lifecycle-design.md §5.3.

	// HandshakesOK — counter for handshake successes, symmetric to
	// HandshakesAuthFailed/HandshakesMalformed below. Functionally
	// identical to HandshakesTotal — both are ticked only on the success
	// path (see HandshakesTotal doc). Kept as a separate field to give
	// dashboards a clean "outcome split" stacked bar
	// (ok/rate_limited/auth_fail/malformed) without requiring consumers
	// to re-derive the success count; also provides future flexibility if
	// HandshakesTotal semantics ever shift to a true union of all outcomes.
	HandshakesOK atomic.Uint64

	// HandshakesAuthFailed — incremented when handshake fails due to bad
	// credentials (wrong server key, missing auth field, etc). Distinct from
	// HandshakesFailed which is a catch-all. Rapid growth indicates
	// credential scanning, protocol version mismatch on a deployed client
	// fleet, or a misconfigured client config rollout.
	HandshakesAuthFailed atomic.Uint64

	// HandshakesMalformed — incremented when handshake fails due to bad
	// request format (truncated JSON, wrong content-type, invalid version).
	// Most commonly triggered by random scanners hitting the decoy endpoint;
	// a sudden spike paired with low HandshakesTotal suggests targeted DPI
	// probing rather than baseline internet noise.
	//
	// NOTE: intentionally NOT wired from malformed-parse paths in handler.go.
	// Incrementing it there would create a timing oracle — slower codepath
	// (counter tick + return) is distinguishable from the fast decoy
	// fall-through, letting an attacker probe "is this a real ShadowLink
	// endpoint?" via response-time differential. Counter exists for future
	// wiring inside the decoy serve path itself (where the timing is
	// already paid).
	HandshakesMalformed atomic.Uint64

	// RateLimitEmittedByBody — Phase 1+: number of times the body-marker
	// carrier was emitted (i.e., snapshot was available and Emit injected it).
	// Compare to RateLimitSentinelEmitted (existing, counts header emissions)
	// — if EmittedByBody == RateLimitSentinelEmitted, full dual-carrier
	// coverage; if EmittedByBody < RateLimitSentinelEmitted, some emissions
	// fell back to header-only (Telegraph-proxy deploy or missing snapshot).
	RateLimitEmittedByBody atomic.Uint64

	// RateLimitEmittedByBodyMissing — Phase 1+: number of times Emit was
	// called but no pre-baked snapshot was available for the requested path,
	// so only header was emitted. Operational signal — if growing rapidly,
	// indicates incomplete snapshot config or Telegraph-proxy deployment.
	RateLimitEmittedByBodyMissing atomic.Uint64

	// RatelimitBucketHandshake / RatelimitBucketWSUpgrade / RatelimitBucketData
	// — gauge-like snapshots of current token bucket levels. Sampled
	// periodically by the metrics endpoint (NOT updated on every request to
	// avoid hot-path overhead). atomic.Int64 to allow negative deltas during
	// rapid drain.
	RatelimitBucketHandshake atomic.Int64
	RatelimitBucketWSUpgrade atomic.Int64
	RatelimitBucketData      atomic.Int64

	// IdleConnections — gauge of HTTP keep-alive connections currently in
	// the Idle state. Populated by Server.connStateHook (Wave 2.3,
	// 2026-05-17). Tracks memory pressure from the IdleTimeout=300s window
	// — when the 60s→300s bump shipped, idle pool size becomes the proxy
	// for "are we paying for the longer window?" Signed (atomic.Int64)
	// because the simple Idle→+1 / Active|Closed|Hijacked→-1 approximation
	// can briefly dip negative during ramp; absolute steady-state value is
	// what ops alerts on, not transient sign.
	IdleConnections atomic.Int64

	// Plan §C7 (May audit, 2026-05-02) — per-bucket Consumed/Rejected counters
	// for the three rate-limit gates. Consumed ticks once per AllowFoo() that
	// returned true (token actually withdrawn from the bucket). Rejected ticks
	// once per AllowFoo() that returned false (bucket empty / IP throttled).
	// These pair with the §C4 ClientID exemption counters to give ops a
	// complete view of the per-IP gate: bucket churn (Consumed) vs. attacker
	// pressure (Rejected) vs. trusted bypass (RatelimitClientIDExempted).
	//
	// SKIP RULE: the data-path and handshake-path ClientID exemption fast
	// paths (which call IncRatelimitClientIDExempted before reaching the
	// bucket consume) MUST NOT increment burst counters — exemption already
	// owns its own series. WS-upgrade gate fires before clientID is known
	// and always increments one of these.
	RatelimitBurstConsumed_WSUpgrade atomic.Uint64
	RatelimitBurstConsumed_Handshake atomic.Uint64
	RatelimitBurstConsumed_Data      atomic.Uint64
	RatelimitBurstRejected_WSUpgrade atomic.Uint64
	RatelimitBurstRejected_Handshake atomic.Uint64
	RatelimitBurstRejected_Data      atomic.Uint64

	// WSPathLegacyHits — count of WS upgrade accepts that landed on a
	// retired path (currently /_next/webpack-hmr and /track/realtime; see
	// legacyAcceptedWSPaths in urls.go). Ticked once per successful gorilla
	// Upgrade so the counter reflects actually-attaching clients, not
	// probe traffic stopped at IsAllowedWSPath. Used for the data-driven
	// cutoff decision (Wave 2.1, 2026-05-17 — MINOR-V2-6): when the rate
	// stays below 0.01/s for two weeks the entries in
	// legacyAcceptedWSPaths can be removed and old clients that still hash
	// to one of those paths will fall through to the decoy site.
	WSPathLegacyHits atomic.Uint64

	// OrphanSessionCleaned counts sessions evicted by the §C10 M2 (May audit)
	// 30-second newborn-not-attached timeout — sessions whose handshake POST
	// completed but whose client never landed the WS upgrade within the grace
	// window. A persistent non-zero rate indicates a network path where the
	// handshake succeeds but the WS upgrade fails (CF edge degradation, MITM
	// stripping the upgrade, NAT churn between two requests).
	OrphanSessionCleaned atomic.Uint64

	// GhostSessionSwept counts sessions reclaimed by the server ghost-sweep
	// (2026-06-01 pool-capacity-dip-fix): attached sessions whose WS transport
	// detached (TSPU age-cut close 1006 / io_timeout / peer_eof) more than the
	// short grace ago, with no orphan relay still bound to them. This is the
	// server-side close of the ghost-session leak the client cannot FIN (dead
	// transport, no on-wire session addressing). A non-zero rate is EXPECTED in
	// direct mode under TSPU age-cutting — it is the mechanism working, draining
	// ghosts that previously lingered to the idle timeout and drifted the server
	// toward its rate limit (the freeze aggravator, docs/sl-burst2-freeze-analysis.md §3-4).
	GhostSessionSwept atomic.Uint64

	// WS reader-exit classification (2026-05-18 forensics, post-storm-brake).
	// Field debug question we keep hitting: when the client logs `close 1006
	// (abnormal closure): unexpected EOF`, who CLOSED the TCP first — the
	// middlebox, the origin, or our own writer-side teardown? Each of these
	// counters increments on EVERY server-side WS reader exit, classified
	// by the gorilla error string. Comparing client `close_other`/`eof`
	// counts against server `WSReaderExitPeerEOF`/`WSReaderExitReset` answers
	// the question structurally instead of by speculation.
	//
	//   - PeerEOF: orderly FIN from the client side (gorilla "EOF" /
	//     "unexpected EOF"). If client logged close 1006 AND this increments
	//     → middlebox dropped the conn cleanly, client's gorilla synthesised
	//     the 1006 because no WS close frame ever arrived. Confirms external
	//     teardown.
	//   - Reset: TCP RST from peer (gorilla "connection reset by peer" /
	//     "wsarecv: An existing connection was forcibly closed"). Confirms
	//     hard middlebox/origin intervention.
	//   - IOTimeout: read deadline elapsed on a quiet conn — origin/middlebox
	//     stopped forwarding bytes without tearing down the TCP. Classic
	//     CF-edge black-hole signature.
	//   - LocalClose: our own Close() raced ahead of the read — "use of
	//     closed network connection". This is the only bucket that says
	//     "WE closed it first". If this dominates close-1006 events, the
	//     bug is in our preemptive rotation timing, not the network.
	//   - Other: residual; should stay flat. Persistent non-zero indicates
	//     an unclassified failure mode worth investigating.
	WSReaderExitPeerEOF    atomic.Uint64
	WSReaderExitReset      atomic.Uint64
	WSReaderExitIOTimeout  atomic.Uint64
	WSReaderExitLocalClose atomic.Uint64
	WSReaderExitOther      atomic.Uint64

	// Bug #8 flow-control metrics (Task 10).
	// FlowWindowUpdatesRecv — WindowUpdate frames received from client (server credits returned).
	// UnknownFlag — frames with an unrecognised Flags byte (defensive default counter).
	// FlowSessionsActive — gauge: WS sessions that negotiated flow control (signed for delta Add).
	FlowWindowUpdatesRecv atomic.Uint64
	UnknownFlag           atomic.Uint64
	FlowSessionsActive    atomic.Int64
	// Bug #8 credit-wait canary metrics (MEDIUM-2).
	// FlowStreamCreditWaitsTotal — number of waitForCredit calls that actually blocked
	// (available was <=0 on entry; threshold >1ms filters instant-return paths).
	// FlowStreamCreditWaitMsTotal — total milliseconds spent blocked in waitForCredit;
	// high value = window too small, throughput throttled by credit starvation.
	FlowStreamCreditWaitsTotal  atomic.Uint64
	FlowStreamCreditWaitMsTotal atomic.Uint64

	// Bug #9 stream-migration counters. Task 11 added the four core counters
	// (MigrateOK/ResumeOK/MigrateFail/MigrateGraceExpired) so the MIGRATE/RESUME/
	// grace handlers had something to tick; Task 18 finalizes the §4.3 table by
	// adding the {reason}-labelled fail breakdown, the tail-resend instrumentation,
	// and the registry-sourced orphan gauge/rejection counters (surfaced via
	// AttachRelayRegistry — see below), plus the text/JSON exposition that Task 11
	// deferred.
	//
	// MigrateFail is the AGGREGATE (every MIGRATE/RESUME rejection ticks it,
	// regardless of reason) — kept for at-a-glance dashboards and because Task 11
	// tests pin it. The three MigrateFail{NotFound,BadProof,GraceExpired} counters
	// are the per-reason breakdown; each fail site ticks BOTH the aggregate and the
	// matching reason counter so `MigrateFail == sum(reason counters)` holds.
	MigrateOK           atomic.Uint64 // successful preemptive MIGRATE reassociations
	ResumeOK            atomic.Uint64 // successful reactive RESUME reassociations (from grace)
	MigrateFail         atomic.Uint64 // MIGRATE/RESUME rejected (aggregate of the three reasons below)
	MigrateGraceExpired atomic.Uint64 // grace window elapsed without a RESUME → relay closed

	// Per-reason MIGRATE/RESUME fail breakdown (Task 18, §4.3).
	MigrateFailNotFound     atomic.Uint64 // relay not in registry for (clientID, streamID)
	MigrateFailBadProof     atomic.Uint64 // HMAC stream-proof verification failed
	MigrateFailGraceExpired atomic.Uint64 // RESUME lost CAS to the grace timer (relay already closed)

	// Tail-resend instrumentation (Task 18, §4.3 / §5.3). MigrateTailResent counts
	// frames re-enqueued on the new binding when slot A died before acking;
	// MigrateTailBufferedBytes is a gauge of bytes currently held in unacked tails
	// across all relays (signed for delta Add as tails fill/evict).
	MigrateTailResent        atomic.Uint64
	MigrateTailBufferedBytes atomic.Int64

	// relayReg, when non-nil, is the live relay registry whose self-contained
	// orphan counters (orphanedFDInUse gauge, orphanFDRejected, orphanedEvictedLimit)
	// the Snapshot reads directly — avoiding a duplicate count. Set once via
	// AttachRelayRegistry in NewHandler after the registry is constructed; read-only
	// thereafter (atomic.Pointer for the publish/read happens-before edge). When nil
	// (unit tests that build a bare *Metrics) the orphan series snapshot as zero.
	relayReg atomic.Pointer[relayRegistry]

	backpressureActive atomic.Bool

	// T1.7 (Phase 2, 2026-04-26) — BroadcastStreamClose drain instrumentation.
	// Master spec exit criterion: P99 wall-clock < 2s for a 10k-tunnel drain.
	// Counters track per-reason drops so ops can distinguish "channel full"
	// (slow client backpressure) from "total deadline" (overload) from
	// "tunnel done" (race vs. graceful close).
	broadcastCloseDrainNanosTotal  atomic.Uint64 // sum of per-invocation wall-clock ns
	broadcastCloseDrainNanosLast   atomic.Uint64 // most recent invocation wall-clock ns
	broadcastCloseDrainCount       atomic.Uint64 // # of BroadcastStreamClose invocations
	broadcastCloseDroppedTimeout   atomic.Uint64 // per-tunnel select timeout
	broadcastCloseDroppedDone      atomic.Uint64 // tunnel.done closed before send
	broadcastCloseDroppedCtxCancel atomic.Uint64 // total deadline exceeded

	// decoyServed counts decoy dispatches per reason (see DecoyReason vocab in
	// decoy_log.go). One atomic counter per reason — no mutex on the hot path.
	// Pre-sized to len(AllDecoyReasons) at NewMetrics time so reads/writes are
	// just a slice index lookup. A reason without a registered slot bumps the
	// `unspecified` counter (defensive default — keeps a typo from panicking
	// the gate).
	decoyServed []atomic.Uint64

	// D2 (FP-mimicry, 2026-06): aggregate handshake counters by browser profile
	// derived from the User-Agent header on the handshake POST.
	// PRIVACY: profile is derived locally in handleHandshakeNew from the UA on the
	// hot path — it is NEVER stored in core.Session or any per-client LRU. Only
	// these aggregate counters are updated. Dashboard use: A/B observability of
	// real-world population split reaching this server instance.
	HandshakesProfileChrome  atomic.Uint64
	HandshakesProfileFirefox atomic.Uint64
	HandshakesProfileOther   atomic.Uint64

	// UDP relay (CRIT-1 / LOW-4, 2026-06-11)
	UDPRespCapped  atomic.Uint64 // response packets dropped after per-flow byte cap
	UDPFlowsReaped atomic.Uint64 // flows removed by Cleanup ticker (idle reap)

	startTime time.Time
}

// IncRatelimitClientIDExempted bumps the §C4 exemption-bypass counter. Called
// when an authenticated clientID skips a per-IP rate-limit bucket consume on
// the data path or a subsequent handshake. Plan §C7 (May audit, 2026-05-02).
func (m *Metrics) IncRatelimitClientIDExempted() {
	m.RatelimitClientIDExempted.Add(1)
}

// IncRatelimitClientIDSoftLimitRejected bumps the §C4 soft-limit counter when
// an exempt clientID exceeds its per-window soft cap and is rejected. Plan
// §C7 (May audit, 2026-05-02).
func (m *Metrics) IncRatelimitClientIDSoftLimitRejected() {
	m.RatelimitClientIDSoftLimitRejected.Add(1)
}

// IncHandshakeProfile increments the aggregate handshake counter for the given
// browser profile label. Called from handleHandshakeNew using a locally-derived
// profile (from the User-Agent header) — the profile label is NEVER stored in
// the session or any per-client structure (D2 privacy invariant).
// Unknown labels route to "other".
func (m *Metrics) IncHandshakeProfile(profile string) {
	switch profile {
	case "chrome":
		m.HandshakesProfileChrome.Add(1)
	case "firefox":
		m.HandshakesProfileFirefox.Add(1)
	default:
		m.HandshakesProfileOther.Add(1)
	}
}

// IncRatelimitBurstConsumed routes a per-bucket "token actually consumed"
// increment to the right counter. Path values: "ws_upgrade" | "handshake" |
// "data". Unknown labels are a no-op (defensive default — keeps a typo at
// the call site from panicking the gate path). Plan §C7 (May audit,
// 2026-05-02).
func (m *Metrics) IncRatelimitBurstConsumed(path string) {
	switch path {
	case "ws_upgrade":
		m.RatelimitBurstConsumed_WSUpgrade.Add(1)
	case "handshake":
		m.RatelimitBurstConsumed_Handshake.Add(1)
	case "data":
		m.RatelimitBurstConsumed_Data.Add(1)
	}
}

// IncRatelimitBurstRejected routes a per-bucket "token-empty rejection"
// increment to the right counter. Same path vocabulary as
// IncRatelimitBurstConsumed; unknown labels are a safe no-op. Plan §C7
// (May audit, 2026-05-02).
func (m *Metrics) IncRatelimitBurstRejected(path string) {
	switch path {
	case "ws_upgrade":
		m.RatelimitBurstRejected_WSUpgrade.Add(1)
	case "handshake":
		m.RatelimitBurstRejected_Handshake.Add(1)
	case "data":
		m.RatelimitBurstRejected_Data.Add(1)
	}
}

// observeBroadcastCloseDrain records one BroadcastStreamClose drain for the
// T1.7 SLA dashboard. We expose total/last/count atomics rather than a real
// histogram because the rest of the file follows the same atomic counter
// pattern — keeping the surface uniform avoids dragging in a prom client just
// for one metric. JSON & Prometheus exposition both compute the average
// from total/count at serialization time.
func (m *Metrics) observeBroadcastCloseDrain(d time.Duration) {
	ns := uint64(d.Nanoseconds())
	if d < 0 {
		ns = 0
	}
	m.broadcastCloseDrainNanosTotal.Add(ns)
	m.broadcastCloseDrainNanosLast.Store(ns)
	m.broadcastCloseDrainCount.Add(1)
}

// NewMetrics creates a metrics tracker.
func NewMetrics() *Metrics {
	return &Metrics{
		startTime:   time.Now(),
		decoyServed: make([]atomic.Uint64, len(AllDecoyReasons)),
	}
}

// AttachRelayRegistry publishes the live relay registry so Snapshot can read its
// self-contained orphan counters directly (Bug #9 Task 18, §4.3). The registry
// owns orphanedFDInUse (the OrphanedRelaysActive gauge), orphanFDRejected, and
// orphanedEvictedLimit; reading them here avoids a duplicate count on the hot
// admit/evict paths. Called once in NewHandler; nil-safe.
func (m *Metrics) AttachRelayRegistry(reg *relayRegistry) {
	if m == nil {
		return
	}
	m.relayReg.Store(reg)
}

// decoyReasonIndex returns the slot index for a DecoyReason in the decoyServed
// slice. Unknown reasons map to the `unspecified` slot (index 0 by virtue of
// the AllDecoyReasons ordering — DecoyReasonUnspecified is the first entry).
func decoyReasonIndex(reason DecoyReason) int {
	for i, r := range AllDecoyReasons {
		if r == reason {
			return i
		}
	}
	return 0 // unspecified
}

// IncDecoyServed bumps the per-reason decoy-served counter. Safe for hot-path
// concurrent calls — atomic per-slot, no mutex. Unknown reasons fall back to
// `unspecified` (defensive default; see decoyReasonIndex).
func (m *Metrics) IncDecoyServed(reason DecoyReason) {
	if m == nil {
		return
	}
	idx := decoyReasonIndex(reason)
	if idx < 0 || idx >= len(m.decoyServed) {
		return
	}
	m.decoyServed[idx].Add(1)
}

// DecoyServedSnapshot returns a per-reason snapshot of the decoy-served
// counter. Order matches AllDecoyReasons. Used by the Prom exposer + tests.
func (m *Metrics) DecoyServedSnapshot() map[DecoyReason]uint64 {
	if m == nil || len(m.decoyServed) == 0 {
		return nil
	}
	out := make(map[DecoyReason]uint64, len(AllDecoyReasons))
	for i, r := range AllDecoyReasons {
		if i >= len(m.decoyServed) {
			break
		}
		out[r] = m.decoyServed[i].Load()
	}
	return out
}

// Snapshot returns a point-in-time copy of all metrics.
type MetricsSnapshot struct {
	ActiveClients      int64  `json:"active_clients"`
	ActiveConnections  int64  `json:"active_connections"`
	ChunksReceived     uint64 `json:"chunks_received"`
	ChunksSent         uint64 `json:"chunks_sent"`
	BytesReceived      uint64 `json:"bytes_received"`
	BytesSent          uint64 `json:"bytes_sent"`
	HandshakesTotal    uint64 `json:"handshakes_total"`
	HandshakesNewTotal uint64 `json:"handshakes_new_total"`
	HandshakesFailed   uint64 `json:"handshakes_failed"`
	RejectedOverload   uint64 `json:"rejected_overload"`
	TimingOracleHits   uint64 `json:"timing_oracle_hits"`
	NewPathHits        uint64 `json:"new_path_hits"`
	// Task A2 (May audit) — rate-limit sentinel emission counter.
	RateLimitSentinelEmitted uint64 `json:"ratelimit_sentinel_emitted"`
	// Phase 0+ (2026-05-14) — WS lifecycle + sentinel framework metrics.
	HandshakesOK                  uint64 `json:"handshakes_ok"`
	HandshakesAuthFailed          uint64 `json:"handshakes_auth_failed"`
	HandshakesMalformed           uint64 `json:"handshakes_malformed"`
	RateLimitEmittedByBody        uint64 `json:"ratelimit_emitted_by_body"`
	RateLimitEmittedByBodyMissing uint64 `json:"ratelimit_emitted_by_body_missing"`
	RatelimitBucketHandshake      int64  `json:"ratelimit_bucket_handshake"`
	RatelimitBucketWSUpgrade      int64  `json:"ratelimit_bucket_ws_upgrade"`
	RatelimitBucketData           int64  `json:"ratelimit_bucket_data"`
	// Wave 2.3 (2026-05-17) — idle connection gauge for IdleTimeout=300s
	// memory-pressure observability.
	IdleConnections int64 `json:"idle_connections"`
	// Plan §C4 (May audit) — ClientID exemption telemetry.
	RatelimitClientIDExempted          uint64 `json:"ratelimit_clientid_exempted"`
	RatelimitClientIDSoftLimitRejected uint64 `json:"ratelimit_clientid_softlimit_rejected"`
	// Plan §C7 (May audit) — per-bucket Consumed/Rejected. Consumed = token
	// actually withdrawn (gate returned true); Rejected = bucket-empty fail
	// (gate returned false). Exemption fast-path skips these — see SKIP RULE
	// in the Metrics struct.
	RatelimitBurstConsumedWSUpgrade uint64 `json:"ratelimit_burst_consumed_ws_upgrade"`
	RatelimitBurstConsumedHandshake uint64 `json:"ratelimit_burst_consumed_handshake"`
	RatelimitBurstConsumedData      uint64 `json:"ratelimit_burst_consumed_data"`
	RatelimitBurstRejectedWSUpgrade uint64 `json:"ratelimit_burst_rejected_ws_upgrade"`
	RatelimitBurstRejectedHandshake uint64 `json:"ratelimit_burst_rejected_handshake"`
	RatelimitBurstRejectedData      uint64 `json:"ratelimit_burst_rejected_data"`
	// Plan §C10 M2 (May audit) — newborn-not-attached evictions.
	OrphanSessionCleaned uint64 `json:"orphan_session_cleaned"`
	// 2026-06-01 pool-capacity-dip-fix — detached-ghost (age-cut) sweeps.
	GhostSessionSwept uint64 `json:"ghost_session_swept"`
	// 2026-05-18 forensics — server-side classification of WS reader exits.
	// Cross-reference against client `close 1006` reports to attribute
	// teardown source (peer EOF / TCP RST / read deadline / local Close).
	WSReaderExitPeerEOF    uint64 `json:"ws_reader_exit_peer_eof"`
	WSReaderExitReset      uint64 `json:"ws_reader_exit_reset"`
	WSReaderExitIOTimeout  uint64 `json:"ws_reader_exit_io_timeout"`
	WSReaderExitLocalClose uint64 `json:"ws_reader_exit_local_close"`
	WSReaderExitOther      uint64 `json:"ws_reader_exit_other"`
	// Bug #8 (2026-05-30) — per-stream flow-control observability.
	FlowWindowUpdatesRecv uint64 `json:"flow_window_updates_recv"`
	UnknownFlag           uint64 `json:"unknown_flag"`
	FlowSessionsActive    int64  `json:"flow_sessions_active"`
	// Bug #8 credit-wait canary (MEDIUM-2, 2026-05-30).
	FlowStreamCreditWaitsTotal  uint64 `json:"flow_stream_credit_waits_total"`
	FlowStreamCreditWaitMsTotal uint64 `json:"flow_stream_credit_wait_ms_total"`
	// Bug #9 (2026-05-31) — stream-migration observability (§4.3). MigrateFail is
	// the aggregate; the three *Fail* fields are the per-reason breakdown.
	// OrphanedRelaysActive / OrphanFDBudgetRejected / OrphanedEvictedLimit are
	// sourced from the relay registry (orphanedFDInUse / orphanFDRejected /
	// orphanedEvictedLimit) via the attached registry — single source of truth.
	MigrateOK                uint64 `json:"migrate_ok"`
	ResumeOK                 uint64 `json:"resume_ok"`
	MigrateFail              uint64 `json:"migrate_fail"`
	MigrateFailNotFound      uint64 `json:"migrate_fail_not_found"`
	MigrateFailBadProof      uint64 `json:"migrate_fail_bad_proof"`
	MigrateFailGraceExpired  uint64 `json:"migrate_fail_grace_expired"`
	MigrateGraceExpired      uint64 `json:"migrate_grace_expired"`
	MigrateTailResent        uint64 `json:"migrate_tail_resent"`
	MigrateTailBufferedBytes int64  `json:"migrate_tail_buffered_bytes"`
	OrphanedRelaysActive     int64  `json:"orphaned_relays_active"`
	OrphanFDBudgetRejected   uint64 `json:"orphan_fd_budget_rejected"`
	OrphanedEvictedLimit     uint64 `json:"orphaned_evicted_limit"`
	// Wave 2.1 (2026-05-17) — WS upgrade accepts on retired legacy paths.
	WSPathLegacyHits uint64 `json:"ws_path_legacy_hits"`
	// T1.7 (Phase 2) — BroadcastStreamClose drain SLA telemetry.
	BroadcastCloseDrainCount       uint64  `json:"broadcast_close_drain_count"`
	BroadcastCloseDrainSecondsLast float64 `json:"broadcast_close_drain_seconds_last"`
	BroadcastCloseDrainSecondsAvg  float64 `json:"broadcast_close_drain_seconds_avg"`
	BroadcastCloseDroppedTimeout   uint64  `json:"broadcast_close_dropped_timeout"`
	BroadcastCloseDroppedDone      uint64  `json:"broadcast_close_dropped_done"`
	BroadcastCloseDroppedCtxCancel uint64  `json:"broadcast_close_dropped_ctx_cancel"`
	UptimeSeconds                  float64 `json:"uptime_seconds"`
	MemoryMB                       float64 `json:"memory_mb"`
	GoRoutines                     int     `json:"goroutines"`
	Backpressure                   bool    `json:"backpressure_active"`
	// Per-reason decoy dispatch counter (this followup, 2026-05-05). JSON
	// emits the map keyed by reason label so dashboards that consume the
	// JSON variant don't need to know the slice order.
	DecoyServed map[DecoyReason]uint64 `json:"decoy_served"`
	// D2 (FP-mimicry, 2026-06): aggregate handshake counts by browser profile.
	// Derived from User-Agent on the handshake POST — never stored per-client.
	HandshakesProfileChrome  uint64 `json:"handshakes_profile_chrome"`
	HandshakesProfileFirefox uint64 `json:"handshakes_profile_firefox"`
	HandshakesProfileOther   uint64 `json:"handshakes_profile_other"`
	// UDP relay (CRIT-1 / LOW-4, 2026-06-11).
	UDPRespCapped  uint64 `json:"udp_resp_capped"`
	UDPFlowsReaped uint64 `json:"udp_flows_reaped"`
}

// Snapshot returns current metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Bug #9 Task 18: orphan series come from the attached relay registry (single
	// source of truth — the registry mutates these on the admit/evict hot paths).
	// nil registry (bare-*Metrics unit tests) snapshots them as zero.
	var orphanActive int64
	var orphanFDRejected, orphanEvicted uint64
	if reg := m.relayReg.Load(); reg != nil {
		orphanActive = reg.orphanedFDInUse.Load()
		orphanFDRejected = reg.orphanFDRejected.Load()
		orphanEvicted = reg.orphanedEvictedLimit.Load()
	}

	return MetricsSnapshot{
		ActiveClients:                      m.ActiveClients.Load(),
		ActiveConnections:                  m.ActiveConnections.Load(),
		ChunksReceived:                     m.ChunksReceived.Load(),
		ChunksSent:                         m.ChunksSent.Load(),
		BytesReceived:                      m.BytesReceived.Load(),
		BytesSent:                          m.BytesSent.Load(),
		HandshakesTotal:                    m.HandshakesTotal.Load(),
		HandshakesNewTotal:                 m.HandshakesNewTotal.Load(),
		HandshakesFailed:                   m.HandshakesFailed.Load(),
		RejectedOverload:                   m.RejectedOverload.Load(),
		TimingOracleHits:                   m.TimingOracleHits.Load(),
		NewPathHits:                        m.NewPathHits.Load(),
		RateLimitSentinelEmitted:           m.RateLimitSentinelEmitted.Load(),
		HandshakesOK:                       m.HandshakesOK.Load(),
		HandshakesAuthFailed:               m.HandshakesAuthFailed.Load(),
		HandshakesMalformed:                m.HandshakesMalformed.Load(),
		RateLimitEmittedByBody:             m.RateLimitEmittedByBody.Load(),
		RateLimitEmittedByBodyMissing:      m.RateLimitEmittedByBodyMissing.Load(),
		RatelimitBucketHandshake:           m.RatelimitBucketHandshake.Load(),
		RatelimitBucketWSUpgrade:           m.RatelimitBucketWSUpgrade.Load(),
		RatelimitBucketData:                m.RatelimitBucketData.Load(),
		IdleConnections:                    m.IdleConnections.Load(),
		RatelimitClientIDExempted:          m.RatelimitClientIDExempted.Load(),
		RatelimitClientIDSoftLimitRejected: m.RatelimitClientIDSoftLimitRejected.Load(),
		RatelimitBurstConsumedWSUpgrade:    m.RatelimitBurstConsumed_WSUpgrade.Load(),
		RatelimitBurstConsumedHandshake:    m.RatelimitBurstConsumed_Handshake.Load(),
		RatelimitBurstConsumedData:         m.RatelimitBurstConsumed_Data.Load(),
		RatelimitBurstRejectedWSUpgrade:    m.RatelimitBurstRejected_WSUpgrade.Load(),
		RatelimitBurstRejectedHandshake:    m.RatelimitBurstRejected_Handshake.Load(),
		RatelimitBurstRejectedData:         m.RatelimitBurstRejected_Data.Load(),
		OrphanSessionCleaned:               m.OrphanSessionCleaned.Load(),
		GhostSessionSwept:                  m.GhostSessionSwept.Load(),
		WSReaderExitPeerEOF:                m.WSReaderExitPeerEOF.Load(),
		WSReaderExitReset:                  m.WSReaderExitReset.Load(),
		WSReaderExitIOTimeout:              m.WSReaderExitIOTimeout.Load(),
		WSReaderExitLocalClose:             m.WSReaderExitLocalClose.Load(),
		WSReaderExitOther:                  m.WSReaderExitOther.Load(),
		FlowWindowUpdatesRecv:              m.FlowWindowUpdatesRecv.Load(),
		UnknownFlag:                        m.UnknownFlag.Load(),
		FlowSessionsActive:                 m.FlowSessionsActive.Load(),
		FlowStreamCreditWaitsTotal:         m.FlowStreamCreditWaitsTotal.Load(),
		FlowStreamCreditWaitMsTotal:        m.FlowStreamCreditWaitMsTotal.Load(),
		MigrateOK:                          m.MigrateOK.Load(),
		ResumeOK:                           m.ResumeOK.Load(),
		MigrateFail:                        m.MigrateFail.Load(),
		MigrateFailNotFound:                m.MigrateFailNotFound.Load(),
		MigrateFailBadProof:                m.MigrateFailBadProof.Load(),
		MigrateFailGraceExpired:            m.MigrateFailGraceExpired.Load(),
		MigrateGraceExpired:                m.MigrateGraceExpired.Load(),
		MigrateTailResent:                  m.MigrateTailResent.Load(),
		MigrateTailBufferedBytes:           m.MigrateTailBufferedBytes.Load(),
		OrphanedRelaysActive:               orphanActive,
		OrphanFDBudgetRejected:             orphanFDRejected,
		OrphanedEvictedLimit:               orphanEvicted,
		WSPathLegacyHits:                   m.WSPathLegacyHits.Load(),
		BroadcastCloseDrainCount:           m.broadcastCloseDrainCount.Load(),
		BroadcastCloseDrainSecondsLast:     float64(m.broadcastCloseDrainNanosLast.Load()) / 1e9,
		BroadcastCloseDrainSecondsAvg: func() float64 {
			c := m.broadcastCloseDrainCount.Load()
			if c == 0 {
				return 0
			}
			return float64(m.broadcastCloseDrainNanosTotal.Load()) / 1e9 / float64(c)
		}(),
		BroadcastCloseDroppedTimeout:   m.broadcastCloseDroppedTimeout.Load(),
		BroadcastCloseDroppedDone:      m.broadcastCloseDroppedDone.Load(),
		BroadcastCloseDroppedCtxCancel: m.broadcastCloseDroppedCtxCancel.Load(),
		UptimeSeconds:                  time.Since(m.startTime).Seconds(),
		MemoryMB:                       float64(memStats.Alloc) / 1024 / 1024,
		GoRoutines:                     runtime.NumGoroutine(),
		Backpressure:                   m.backpressureActive.Load(),
		DecoyServed:                    m.DecoyServedSnapshot(),
		HandshakesProfileChrome:        m.HandshakesProfileChrome.Load(),
		HandshakesProfileFirefox:       m.HandshakesProfileFirefox.Load(),
		HandshakesProfileOther:         m.HandshakesProfileOther.Load(),
		UDPRespCapped:                  m.UDPRespCapped.Load(),
		UDPFlowsReaped:                 m.UDPFlowsReaped.Load(),
	}
}

// BackpressureCheck evaluates memory pressure and updates backpressure state.
// Returns the recommended max connections per client.
// Per spec section 9:
//   - RAM > 80% → reduce max_conns_per_client to 4
//   - RAM > 90% → reject new connections (503)
func (m *Metrics) BackpressureCheck(maxConnsDefault int) (maxConns int, rejectNew bool) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Use Go's heap stats — Sys is total OS memory, Alloc is in-use
	// For a 2GB VPS, we target staying under ~1.5GB for Go process
	allocMB := float64(memStats.Alloc) / 1024 / 1024
	sysMB := float64(memStats.Sys) / 1024 / 1024

	// Adaptive thresholds based on system memory
	// Use Sys as rough indicator of available memory
	highThreshold := sysMB * 0.8
	critThreshold := sysMB * 0.9

	if allocMB > critThreshold {
		m.backpressureActive.Store(true)
		return 2, true // critical: reject new, minimal conns
	}

	if allocMB > highThreshold {
		m.backpressureActive.Store(true)
		return 4, false // high: reduce conns but allow new clients
	}

	m.backpressureActive.Store(false)
	return maxConnsDefault, false
}

// ServeHTTP handles metrics endpoint (for NixaVPN agent integration).
// Returns JSON by default; serves Prometheus text format when the client
// requests it via `?format=prom` or `Accept: text/plain`. NOT exposed to
// public — only internal.
//
// The Prometheus output exposes the post-migration steady-state counters:
// handshake totals, body-prefix path hits, active clients/connections, and
// live-decoy instrumentation.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap := m.Snapshot()

	wantProm := r.URL.Query().Get("format") == "prom" ||
		strings.Contains(r.Header.Get("Accept"), "text/plain")

	if wantProm {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		writePromMetrics(w, &snap)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap)
}

// writePromMetrics writes the post-migration steady-state counters in the
// Prometheus exposition format: handshake totals, body-prefix path hits,
// active clients/connections, and live-decoy instrumentation. The full
// picture is still available via the default JSON response.
func writePromMetrics(w io.Writer, s *MetricsSnapshot) {
	fmt.Fprintf(w, "# HELP shadowlink_handshakes_total Total handshakes across all paths\n")
	fmt.Fprintf(w, "# TYPE shadowlink_handshakes_total counter\n")
	fmt.Fprintf(w, "shadowlink_handshakes_total %d\n", s.HandshakesTotal)

	fmt.Fprintf(w, "# HELP shadowlink_handshakes_new_total Handshakes served via the body-prefix path\n")
	fmt.Fprintf(w, "# TYPE shadowlink_handshakes_new_total counter\n")
	fmt.Fprintf(w, "shadowlink_handshakes_new_total %d\n", s.HandshakesNewTotal)

	fmt.Fprintf(w, "# HELP shadowlink_new_path_hits_total POST dispatches routed to the body-prefix branch\n")
	fmt.Fprintf(w, "# TYPE shadowlink_new_path_hits_total counter\n")
	fmt.Fprintf(w, "shadowlink_new_path_hits_total %d\n", s.NewPathHits)

	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_sentinel_emitted_total Decoy responses that carried X-SL-RL: 1 (per-IP rate-limit branches of handshake-POST and WS-upgrade only)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_sentinel_emitted_total counter\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_sentinel_emitted_total %d\n", s.RateLimitSentinelEmitted)

	// Phase 0+ (2026-05-14) — WS lifecycle + sentinel framework metrics.
	fmt.Fprintf(w, "# HELP shadowlink_handshakes_ok_total Handshake successes (outcome split: ok/rate_limited/auth_fail/malformed)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_handshakes_ok_total counter\n")
	fmt.Fprintf(w, "shadowlink_handshakes_ok_total %d\n", s.HandshakesOK)

	fmt.Fprintf(w, "# HELP shadowlink_handshakes_auth_failed_total Handshakes rejected due to bad credentials (wrong key, missing auth field)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_handshakes_auth_failed_total counter\n")
	fmt.Fprintf(w, "shadowlink_handshakes_auth_failed_total %d\n", s.HandshakesAuthFailed)

	fmt.Fprintf(w, "# HELP shadowlink_handshakes_malformed_total Handshakes rejected due to bad request format (truncated JSON, wrong content-type)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_handshakes_malformed_total counter\n")
	fmt.Fprintf(w, "shadowlink_handshakes_malformed_total %d\n", s.HandshakesMalformed)

	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_emitted_by_body_total Body-marker carrier emissions (snapshot available, Emit injected it)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_emitted_by_body_total counter\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_emitted_by_body_total %d\n", s.RateLimitEmittedByBody)

	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_emitted_by_body_missing_total Emit calls where no pre-baked snapshot was available (header-only fallback)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_emitted_by_body_missing_total counter\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_emitted_by_body_missing_total %d\n", s.RateLimitEmittedByBodyMissing)

	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_bucket_handshake Current handshake token bucket level (gauge snapshot)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_bucket_handshake gauge\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_bucket_handshake %d\n", s.RatelimitBucketHandshake)

	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_bucket_ws_upgrade Current WS upgrade token bucket level (gauge snapshot)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_bucket_ws_upgrade gauge\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_bucket_ws_upgrade %d\n", s.RatelimitBucketWSUpgrade)

	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_bucket_data Current data token bucket level (gauge snapshot)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_bucket_data gauge\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_bucket_data %d\n", s.RatelimitBucketData)

	// Wave 2.3 (2026-05-17) — idle keep-alive gauge. Tracks memory pressure
	// from IdleTimeout=300s; signed so a brief negative-spike during ramp
	// (Idle→+1 / Active|Closed|Hijacked→-1 approximation) is observable
	// rather than wrapping.
	fmt.Fprintf(w, "# HELP shadowlink_idle_connections_count Estimated HTTP keep-alive connections currently in Idle state (gauge; tracks IdleTimeout=300s memory pressure)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_idle_connections_count gauge\n")
	fmt.Fprintf(w, "shadowlink_idle_connections_count %d\n", s.IdleConnections)

	fmt.Fprintf(w, "# HELP shadowlink_orphan_session_cleaned_total Newborn sessions evicted by the 30s §C10 M2 (May audit) fast-path timeout — handshake completed, transport never attached\n")
	fmt.Fprintf(w, "# TYPE shadowlink_orphan_session_cleaned_total counter\n")
	fmt.Fprintf(w, "shadowlink_orphan_session_cleaned_total %d\n", s.OrphanSessionCleaned)

	fmt.Fprintf(w, "# HELP shadowlink_ghost_session_swept_total Attached sessions reclaimed by the server ghost-sweep (2026-06-01 pool-capacity-dip-fix): WS transport detached (TSPU age-cut close 1006 / io_timeout / peer_eof) past the short grace, no orphan relay still bound. Closes the ghost leak the client cannot FIN. Non-zero rate is expected under TSPU age-cutting.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ghost_session_swept_total counter\n")
	fmt.Fprintf(w, "shadowlink_ghost_session_swept_total %d\n", s.GhostSessionSwept)

	// 2026-05-18 forensics — WS reader-exit attribution. Cross-reference
	// against client-side "WS pool slot reader error" lines to determine
	// whether teardowns originate at the middlebox (peer_eof + reset
	// dominate), in CF-edge black-hole stalls (io_timeout), or in our own
	// rotation timing (local_close — should stay near zero).
	fmt.Fprintf(w, "# HELP shadowlink_ws_reader_exit_total WS server-side reader exits classified by error kind (forensics for client close-1006 attribution)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ws_reader_exit_total counter\n")
	fmt.Fprintf(w, "shadowlink_ws_reader_exit_total{kind=\"peer_eof\"} %d\n", s.WSReaderExitPeerEOF)
	fmt.Fprintf(w, "shadowlink_ws_reader_exit_total{kind=\"reset\"} %d\n", s.WSReaderExitReset)
	fmt.Fprintf(w, "shadowlink_ws_reader_exit_total{kind=\"io_timeout\"} %d\n", s.WSReaderExitIOTimeout)
	fmt.Fprintf(w, "shadowlink_ws_reader_exit_total{kind=\"local_close\"} %d\n", s.WSReaderExitLocalClose)
	fmt.Fprintf(w, "shadowlink_ws_reader_exit_total{kind=\"other\"} %d\n", s.WSReaderExitOther)

	fmt.Fprintf(w, "# HELP shadowlink_ws_path_legacy_hits_total WS upgrade accepts on retired paths (used for cutoff decision; Wave 2.1 MINOR-V2-6, 2026-05-17)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ws_path_legacy_hits_total counter\n")
	fmt.Fprintf(w, "shadowlink_ws_path_legacy_hits_total %d\n", s.WSPathLegacyHits)

	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_clientid_exempted_total Requests that bypassed the per-IP rate-limit bucket via §C4 (May audit) ClientID exemption — authenticated clients keep flowing under cold-start cascades\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_clientid_exempted_total counter\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_clientid_exempted_total %d\n", s.RatelimitClientIDExempted)

	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_clientid_softlimit_rejected_total Exempt clientIDs whose §C4 (May audit) soft cap tripped within softWindow — distinguishes legit-busy from weaponized-as-bypass\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_clientid_softlimit_rejected_total counter\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_clientid_softlimit_rejected_total %d\n", s.RatelimitClientIDSoftLimitRejected)

	// Plan §C7 (May audit, 2026-05-02) — per-bucket Consumed/Rejected. Path
	// label vocabulary: ws_upgrade | handshake | data. Order is fixed for
	// deterministic exposition (no map iteration). Exemption fast-path does
	// NOT tick these — the §C4 ClientID counters above own that series.
	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_burst_consumed_total Per-bucket count of rate-limit tokens actually withdrawn (gate returned true)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_burst_consumed_total counter\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_burst_consumed_total{path=\"ws_upgrade\"} %d\n", s.RatelimitBurstConsumedWSUpgrade)
	fmt.Fprintf(w, "shadowlink_ratelimit_burst_consumed_total{path=\"handshake\"} %d\n", s.RatelimitBurstConsumedHandshake)
	fmt.Fprintf(w, "shadowlink_ratelimit_burst_consumed_total{path=\"data\"} %d\n", s.RatelimitBurstConsumedData)

	fmt.Fprintf(w, "# HELP shadowlink_ratelimit_burst_rejected_total Per-bucket count of rate-limit gate rejections (bucket empty / IP throttled)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ratelimit_burst_rejected_total counter\n")
	fmt.Fprintf(w, "shadowlink_ratelimit_burst_rejected_total{path=\"ws_upgrade\"} %d\n", s.RatelimitBurstRejectedWSUpgrade)
	fmt.Fprintf(w, "shadowlink_ratelimit_burst_rejected_total{path=\"handshake\"} %d\n", s.RatelimitBurstRejectedHandshake)
	fmt.Fprintf(w, "shadowlink_ratelimit_burst_rejected_total{path=\"data\"} %d\n", s.RatelimitBurstRejectedData)

	// Per-reason decoy dispatch counter (this followup, 2026-05-05). One
	// `shadowlink_decoy_served_total{reason=...}` series per DecoyReason. Order
	// matches AllDecoyReasons so output is deterministic across scrapes.
	if snap := s.DecoyServed; len(snap) > 0 {
		fmt.Fprintf(w, "# HELP shadowlink_decoy_served_total Decoy dispatches per failClosedToDecoy reason — observability for rate limit, auth fail, replay, etc.\n")
		fmt.Fprintf(w, "# TYPE shadowlink_decoy_served_total counter\n")
		for _, r := range AllDecoyReasons {
			fmt.Fprintf(w, "shadowlink_decoy_served_total{reason=%q} %d\n", string(r), snap[r])
		}
	}

	fmt.Fprintf(w, "# HELP shadowlink_active_clients Clients currently resident\n")
	fmt.Fprintf(w, "# TYPE shadowlink_active_clients gauge\n")
	fmt.Fprintf(w, "shadowlink_active_clients %d\n", s.ActiveClients)

	fmt.Fprintf(w, "# HELP shadowlink_active_connections Connections currently resident\n")
	fmt.Fprintf(w, "# TYPE shadowlink_active_connections gauge\n")
	fmt.Fprintf(w, "shadowlink_active_connections %d\n", s.ActiveConnections)

	// T1.7 (Phase 2) — BroadcastStreamClose drain SLA. Master spec exit
	// criterion: P99 wall-clock < 2s for 10k tunnels. We export count/last/avg
	// rather than a histogram to stay zero-dep; ops alerts on _last and _avg.
	fmt.Fprintf(w, "# HELP shadowlink_broadcast_close_drain_count_total BroadcastStreamClose invocations completed\n")
	fmt.Fprintf(w, "# TYPE shadowlink_broadcast_close_drain_count_total counter\n")
	fmt.Fprintf(w, "shadowlink_broadcast_close_drain_count_total %d\n", s.BroadcastCloseDrainCount)

	fmt.Fprintf(w, "# HELP shadowlink_broadcast_close_drain_seconds_last Wall-clock seconds of the most recent BroadcastStreamClose; T1.7 SLA target < 2s for 10k tunnels\n")
	fmt.Fprintf(w, "# TYPE shadowlink_broadcast_close_drain_seconds_last gauge\n")
	fmt.Fprintf(w, "shadowlink_broadcast_close_drain_seconds_last %g\n", s.BroadcastCloseDrainSecondsLast)

	fmt.Fprintf(w, "# HELP shadowlink_broadcast_close_drain_seconds_avg Mean wall-clock seconds across all BroadcastStreamClose invocations since process start\n")
	fmt.Fprintf(w, "# TYPE shadowlink_broadcast_close_drain_seconds_avg gauge\n")
	fmt.Fprintf(w, "shadowlink_broadcast_close_drain_seconds_avg %g\n", s.BroadcastCloseDrainSecondsAvg)

	fmt.Fprintf(w, "# HELP shadowlink_broadcast_close_dropped_total Per-reason count of tunnels whose FlagFin was not enqueued during BroadcastStreamClose\n")
	fmt.Fprintf(w, "# TYPE shadowlink_broadcast_close_dropped_total counter\n")
	fmt.Fprintf(w, "shadowlink_broadcast_close_dropped_total{reason=\"timeout\"} %d\n", s.BroadcastCloseDroppedTimeout)
	fmt.Fprintf(w, "shadowlink_broadcast_close_dropped_total{reason=\"done\"} %d\n", s.BroadcastCloseDroppedDone)
	fmt.Fprintf(w, "shadowlink_broadcast_close_dropped_total{reason=\"ctx_cancel\"} %d\n", s.BroadcastCloseDroppedCtxCancel)

	// Bug #8 (2026-05-30) — per-stream flow-control canary observability.
	fmt.Fprintf(w, "# HELP shadowlink_flow_window_updates_recv_total WINDOW_UPDATE frames received from clients (Bug #8 per-stream flow control)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_window_updates_recv_total counter\n")
	fmt.Fprintf(w, "shadowlink_flow_window_updates_recv_total %d\n", s.FlowWindowUpdatesRecv)
	fmt.Fprintf(w, "# HELP shadowlink_unknown_flag_total Unknown chunk flags seen in the WS reader switch (Bug #8 observability)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_unknown_flag_total counter\n")
	fmt.Fprintf(w, "shadowlink_unknown_flag_total %d\n", s.UnknownFlag)
	fmt.Fprintf(w, "# HELP shadowlink_flow_sessions_active WS sessions with per-stream flow control negotiated ON (Bug #8)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_sessions_active gauge\n")
	fmt.Fprintf(w, "shadowlink_flow_sessions_active %d\n", s.FlowSessionsActive)

	// Bug #8 credit-wait canary (MEDIUM-2, 2026-05-30).
	// High waits_total / wait_ms_total = window (default 1 MiB) too small;
	// throughput is being throttled by credit starvation. If both stay near zero
	// the 1 MiB window is adequate and can be kept.
	fmt.Fprintf(w, "# HELP shadowlink_flow_stream_credit_waits_total Times the per-stream relay blocked in waitForCredit (available<=0 for >1ms); high value = window too small\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_stream_credit_waits_total counter\n")
	fmt.Fprintf(w, "shadowlink_flow_stream_credit_waits_total %d\n", s.FlowStreamCreditWaitsTotal)

	fmt.Fprintf(w, "# HELP shadowlink_flow_stream_credit_wait_ms_total Total milliseconds the per-stream relay spent blocked in waitForCredit; high value = credit starvation\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_stream_credit_wait_ms_total counter\n")
	fmt.Fprintf(w, "shadowlink_flow_stream_credit_wait_ms_total %d\n", s.FlowStreamCreditWaitMsTotal)

	// Bug #9 (2026-05-31) — stream-migration observability (§4.3). MIGRATE is the
	// preemptive reassociation (slot A still alive); RESUME is the reactive one
	// after a slot died into the grace window. The per-reason fail breakdown
	// distinguishes "stale client / wrong streamID" (not_found) from "forged or
	// wrong-session proof" (bad_proof) from "RESUME arrived after grace closed the
	// relay" (grace_expired). shadowlink_migrate_fail_total is the aggregate.
	fmt.Fprintf(w, "# HELP shadowlink_migrate_ok_total Successful preemptive MIGRATE reassociations\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_ok_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_ok_total %d\n", s.MigrateOK)

	fmt.Fprintf(w, "# HELP shadowlink_resume_ok_total Successful reactive RESUME reassociations (from grace window)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_resume_ok_total counter\n")
	fmt.Fprintf(w, "shadowlink_resume_ok_total %d\n", s.ResumeOK)

	fmt.Fprintf(w, "# HELP shadowlink_migrate_fail_total MIGRATE/RESUME rejections (aggregate; see reason label for breakdown)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_fail_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_fail_total %d\n", s.MigrateFail)
	fmt.Fprintf(w, "shadowlink_migrate_fail_total{reason=\"not_found\"} %d\n", s.MigrateFailNotFound)
	fmt.Fprintf(w, "shadowlink_migrate_fail_total{reason=\"bad_proof\"} %d\n", s.MigrateFailBadProof)
	fmt.Fprintf(w, "shadowlink_migrate_fail_total{reason=\"grace_expired\"} %d\n", s.MigrateFailGraceExpired)

	fmt.Fprintf(w, "# HELP shadowlink_migrate_grace_expired_total Grace window elapsed without a RESUME → orphaned relay closed\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_grace_expired_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_grace_expired_total %d\n", s.MigrateGraceExpired)

	fmt.Fprintf(w, "# HELP shadowlink_migrate_tail_resent_total Unacked-tail frames re-enqueued on the new binding after slot-A death (§5.3)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_tail_resent_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_tail_resent_total %d\n", s.MigrateTailResent)

	fmt.Fprintf(w, "# HELP shadowlink_migrate_tail_buffered_bytes Bytes currently held in unacked relay tails (gauge)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_tail_buffered_bytes gauge\n")
	fmt.Fprintf(w, "shadowlink_migrate_tail_buffered_bytes %d\n", s.MigrateTailBufferedBytes)

	// Orphan / FD-budget series — sourced from the relay registry (Task 12 caps,
	// §5.5). OrphanedRelaysActive is the live count of orphaned relays holding an
	// egress socket through their grace window with no WS behind them; a sustained
	// high value paired with a rising FD-budget-rejected counter signals a peer
	// spraying CONNECT-then-kill-WS to pin sockets.
	fmt.Fprintf(w, "# HELP shadowlink_orphaned_relays_active Orphaned relays currently holding an egress conn through the grace window (gauge)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_orphaned_relays_active gauge\n")
	fmt.Fprintf(w, "shadowlink_orphaned_relays_active %d\n", s.OrphanedRelaysActive)

	fmt.Fprintf(w, "# HELP shadowlink_orphan_fd_budget_rejected_total admitOrphan rejections because the orphan FD budget was exhausted (egress closed instead of held)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_orphan_fd_budget_rejected_total counter\n")
	fmt.Fprintf(w, "shadowlink_orphan_fd_budget_rejected_total %d\n", s.OrphanFDBudgetRejected)

	fmt.Fprintf(w, "# HELP shadowlink_orphaned_evicted_limit_total Idle orphaned relays evicted to enforce the per-client / global orphan caps\n")
	fmt.Fprintf(w, "# TYPE shadowlink_orphaned_evicted_limit_total counter\n")
	fmt.Fprintf(w, "shadowlink_orphaned_evicted_limit_total %d\n", s.OrphanedEvictedLimit)

	// D2 (FP-mimicry, 2026-06) — handshake profile distribution.
	// Profile derived from User-Agent on handshake POST; never stored per-client.
	fmt.Fprintf(w, "# HELP shadowlink_handshakes_profile_total Successful handshakes by browser profile inferred from User-Agent (D2 FP-mimicry observability)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_handshakes_profile_total counter\n")
	fmt.Fprintf(w, "shadowlink_handshakes_profile_total{profile=\"chrome\"} %d\n", s.HandshakesProfileChrome)
	fmt.Fprintf(w, "shadowlink_handshakes_profile_total{profile=\"firefox\"} %d\n", s.HandshakesProfileFirefox)
	fmt.Fprintf(w, "shadowlink_handshakes_profile_total{profile=\"other\"} %d\n", s.HandshakesProfileOther)

	// UDP relay (CRIT-1 / LOW-4, 2026-06-11) — amplification cap drops + idle reaps.
	fmt.Fprintf(w, "# HELP shadowlink_udp_resp_capped_total UDP response packets dropped after hitting the per-flow byte cap (LOW-4 amplification ceiling)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_udp_resp_capped_total counter\n")
	fmt.Fprintf(w, "shadowlink_udp_resp_capped_total %d\n", s.UDPRespCapped)
	fmt.Fprintf(w, "# HELP shadowlink_udp_flows_reaped_total UDP flows removed by the idle Cleanup ticker (CRIT-1 NAT-map/FD reap)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_udp_flows_reaped_total counter\n")
	fmt.Fprintf(w, "shadowlink_udp_flows_reaped_total %d\n", s.UDPFlowsReaped)
}

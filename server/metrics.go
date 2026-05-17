package server

import (
	"encoding/json"
	"fmt"
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

	// OrphanSessionCleaned counts sessions evicted by the §C10 M2 (May audit)
	// 30-second newborn-not-attached timeout — sessions whose handshake POST
	// completed but whose client never landed the WS upgrade within the grace
	// window. A persistent non-zero rate indicates a network path where the
	// handshake succeeds but the WS upgrade fails (CF edge degradation, MITM
	// stripping the upgrade, NAT churn between two requests).
	OrphanSessionCleaned atomic.Uint64

	// Live decoy (T1.3) — /blog/* and /_cdn/* reverse-proxy instrumentation.
	DecoyLiveBlogRequests              atomic.Uint64
	DecoyLiveBlogCacheHits             atomic.Uint64
	DecoyLiveBlogCacheMisses           atomic.Uint64
	DecoyLiveBlogUpstreamOK            atomic.Uint64
	DecoyLiveBlogUpstreamErr           atomic.Uint64
	DecoyLiveBlogUpstreamRateLimited   atomic.Uint64
	DecoyLiveBlogStaleServed           atomic.Uint64
	DecoyLiveBlogFallbackSPA           atomic.Uint64
	DecoyLiveBlogRewritePanic          atomic.Uint64
	DecoyLiveBlogRewriteDrift          atomic.Uint64
	DecoyLiveBlogCanaryOK              atomic.Uint64
	DecoyLiveBlogCanaryFetchFail       atomic.Uint64
	DecoyLiveBlogCanaryLastHealthyUnix atomic.Int64 // unix seconds, 0 = never healthy
	DecoyLiveBlogCDNHits               atomic.Uint64
	DecoyLiveBlogCDNErrors             atomic.Uint64
	// DecoyLiveBlogServeHTTPPanic counts panics caught by the outer
	// defer-recover wrapper in LiveBlogHandler.ServeHTTP (A3-I-MED-4 closure).
	// Should stay flat; any non-zero increment indicates a logic bug or
	// unexpected nil deref reached the dispatch path.
	DecoyLiveBlogServeHTTPPanic atomic.Uint64
	backpressureActive          atomic.Bool

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
	// Live decoy (T1.3) — /blog/* and /_cdn/* reverse-proxy instrumentation.
	DecoyLiveBlogRequests              uint64 `json:"decoy_live_blog_requests"`
	DecoyLiveBlogCacheHits             uint64 `json:"decoy_live_blog_cache_hits"`
	DecoyLiveBlogCacheMisses           uint64 `json:"decoy_live_blog_cache_misses"`
	DecoyLiveBlogUpstreamOK            uint64 `json:"decoy_live_blog_upstream_ok"`
	DecoyLiveBlogUpstreamErr           uint64 `json:"decoy_live_blog_upstream_err"`
	DecoyLiveBlogUpstreamRateLimited   uint64 `json:"decoy_live_blog_upstream_rate_limited"`
	DecoyLiveBlogStaleServed           uint64 `json:"decoy_live_blog_stale_served"`
	DecoyLiveBlogFallbackSPA           uint64 `json:"decoy_live_blog_fallback_spa"`
	DecoyLiveBlogRewritePanic          uint64 `json:"decoy_live_blog_rewrite_panic"`
	DecoyLiveBlogRewriteDrift          uint64 `json:"decoy_live_blog_rewrite_drift"`
	DecoyLiveBlogCanaryOK              uint64 `json:"decoy_live_blog_canary_ok"`
	DecoyLiveBlogCanaryFetchFail       uint64 `json:"decoy_live_blog_canary_fetch_fail"`
	DecoyLiveBlogCanaryLastHealthyUnix int64  `json:"decoy_live_blog_canary_last_healthy_unix"`
	DecoyLiveBlogCDNHits               uint64 `json:"decoy_live_blog_cdn_hits"`
	DecoyLiveBlogCDNErrors             uint64 `json:"decoy_live_blog_cdn_errors"`
	DecoyLiveBlogServeHTTPPanic        uint64 `json:"decoy_live_blog_serve_http_panic"`
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
}

// Snapshot returns current metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

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
		RatelimitClientIDExempted:          m.RatelimitClientIDExempted.Load(),
		RatelimitClientIDSoftLimitRejected: m.RatelimitClientIDSoftLimitRejected.Load(),
		RatelimitBurstConsumedWSUpgrade:    m.RatelimitBurstConsumed_WSUpgrade.Load(),
		RatelimitBurstConsumedHandshake:    m.RatelimitBurstConsumed_Handshake.Load(),
		RatelimitBurstConsumedData:         m.RatelimitBurstConsumed_Data.Load(),
		RatelimitBurstRejectedWSUpgrade:    m.RatelimitBurstRejected_WSUpgrade.Load(),
		RatelimitBurstRejectedHandshake:    m.RatelimitBurstRejected_Handshake.Load(),
		RatelimitBurstRejectedData:         m.RatelimitBurstRejected_Data.Load(),
		OrphanSessionCleaned:               m.OrphanSessionCleaned.Load(),
		DecoyLiveBlogRequests:              m.DecoyLiveBlogRequests.Load(),
		DecoyLiveBlogCacheHits:             m.DecoyLiveBlogCacheHits.Load(),
		DecoyLiveBlogCacheMisses:           m.DecoyLiveBlogCacheMisses.Load(),
		DecoyLiveBlogUpstreamOK:            m.DecoyLiveBlogUpstreamOK.Load(),
		DecoyLiveBlogUpstreamErr:           m.DecoyLiveBlogUpstreamErr.Load(),
		DecoyLiveBlogUpstreamRateLimited:   m.DecoyLiveBlogUpstreamRateLimited.Load(),
		DecoyLiveBlogStaleServed:           m.DecoyLiveBlogStaleServed.Load(),
		DecoyLiveBlogFallbackSPA:           m.DecoyLiveBlogFallbackSPA.Load(),
		DecoyLiveBlogRewritePanic:          m.DecoyLiveBlogRewritePanic.Load(),
		DecoyLiveBlogRewriteDrift:          m.DecoyLiveBlogRewriteDrift.Load(),
		DecoyLiveBlogCanaryOK:              m.DecoyLiveBlogCanaryOK.Load(),
		DecoyLiveBlogCanaryFetchFail:       m.DecoyLiveBlogCanaryFetchFail.Load(),
		DecoyLiveBlogCanaryLastHealthyUnix: m.DecoyLiveBlogCanaryLastHealthyUnix.Load(),
		DecoyLiveBlogCDNHits:               m.DecoyLiveBlogCDNHits.Load(),
		DecoyLiveBlogCDNErrors:             m.DecoyLiveBlogCDNErrors.Load(),
		DecoyLiveBlogServeHTTPPanic:        m.DecoyLiveBlogServeHTTPPanic.Load(),
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
func writePromMetrics(w http.ResponseWriter, s *MetricsSnapshot) {
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

	fmt.Fprintf(w, "# HELP shadowlink_orphan_session_cleaned_total Newborn sessions evicted by the 30s §C10 M2 (May audit) fast-path timeout — handshake completed, transport never attached\n")
	fmt.Fprintf(w, "# TYPE shadowlink_orphan_session_cleaned_total counter\n")
	fmt.Fprintf(w, "shadowlink_orphan_session_cleaned_total %d\n", s.OrphanSessionCleaned)

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

	fmt.Fprintf(w, "# HELP decoy_live_blog_requests_total Total /blog/* and /_cdn/* requests dispatched to live-blog handler\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_requests_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_requests_total %d\n", s.DecoyLiveBlogRequests)

	fmt.Fprintf(w, "# HELP decoy_live_blog_cache_hits_total Requests served from LRU cache (fresh entry)\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_cache_hits_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_cache_hits_total %d\n", s.DecoyLiveBlogCacheHits)

	fmt.Fprintf(w, "# HELP decoy_live_blog_cache_misses_total Requests that missed the LRU cache and triggered upstream fetch\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_cache_misses_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_cache_misses_total %d\n", s.DecoyLiveBlogCacheMisses)

	fmt.Fprintf(w, "# HELP decoy_live_blog_upstream_ok_total Successful upstream fetches\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_upstream_ok_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_upstream_ok_total %d\n", s.DecoyLiveBlogUpstreamOK)

	fmt.Fprintf(w, "# HELP decoy_live_blog_upstream_err_total Failed upstream fetches (non-rate-limit errors)\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_upstream_err_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_upstream_err_total %d\n", s.DecoyLiveBlogUpstreamErr)

	fmt.Fprintf(w, "# HELP decoy_live_blog_upstream_rate_limited_total Upstream fetches dropped by the rate limiter\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_upstream_rate_limited_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_upstream_rate_limited_total %d\n", s.DecoyLiveBlogUpstreamRateLimited)

	fmt.Fprintf(w, "# HELP decoy_live_blog_stale_served_total Responses served from stale cache after upstream failure\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_stale_served_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_stale_served_total %d\n", s.DecoyLiveBlogStaleServed)

	fmt.Fprintf(w, "# HELP decoy_live_blog_fallback_spa_total Requests that fell back to static SPA decoy (no cache, upstream failed)\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_fallback_spa_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_fallback_spa_total %d\n", s.DecoyLiveBlogFallbackSPA)

	fmt.Fprintf(w, "# HELP decoy_live_blog_rewrite_panic_total HTMLRewriter panics recovered during response rewriting\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_rewrite_panic_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_rewrite_panic_total %d\n", s.DecoyLiveBlogRewritePanic)

	fmt.Fprintf(w, "# HELP decoy_live_blog_rewrite_drift_total HTMLRewriter drift events (rewrite output differs from template expectation)\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_rewrite_drift_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_rewrite_drift_total %d\n", s.DecoyLiveBlogRewriteDrift)

	fmt.Fprintf(w, "# HELP decoy_live_blog_canary_ok_total Canary watchdog successful article fetches\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_canary_ok_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_canary_ok_total %d\n", s.DecoyLiveBlogCanaryOK)

	fmt.Fprintf(w, "# HELP decoy_live_blog_canary_fetch_fail_total Canary watchdog failed article fetches\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_canary_fetch_fail_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_canary_fetch_fail_total %d\n", s.DecoyLiveBlogCanaryFetchFail)

	fmt.Fprintf(w, "# HELP decoy_live_blog_canary_last_healthy_unix Unix timestamp of the last successful canary fetch (0 = never)\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_canary_last_healthy_unix gauge\n")
	fmt.Fprintf(w, "decoy_live_blog_canary_last_healthy_unix %d\n", s.DecoyLiveBlogCanaryLastHealthyUnix)

	fmt.Fprintf(w, "# HELP decoy_live_blog_cdn_hits_total Successful /_cdn/* upstream fetches\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_cdn_hits_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_cdn_hits_total %d\n", s.DecoyLiveBlogCDNHits)

	fmt.Fprintf(w, "# HELP decoy_live_blog_cdn_errors_total Failed /_cdn/* upstream fetches\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_cdn_errors_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_cdn_errors_total %d\n", s.DecoyLiveBlogCDNErrors)

	fmt.Fprintf(w, "# HELP decoy_live_blog_serve_http_panic_total Panics caught by the LiveBlogHandler.ServeHTTP outer defer-recover (A3-I-MED-4)\n")
	fmt.Fprintf(w, "# TYPE decoy_live_blog_serve_http_panic_total counter\n")
	fmt.Fprintf(w, "decoy_live_blog_serve_http_panic_total %d\n", s.DecoyLiveBlogServeHTTPPanic)

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
}

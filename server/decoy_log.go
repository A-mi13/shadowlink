package server

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
)

// DecoyReason identifies WHY a request was routed through failClosedToDecoy.
// Used both for the structured WARN log emitted on every dispatch and for the
// per-reason `shadowlink_decoy_served_total{reason}` Prometheus counter.
//
// Vocabulary intentionally narrow: every distinct gate that can fail closed
// to the decoy site MUST map to one of these labels. Adding a new reason is
// a deliberate two-step change — register here, increment in metrics.go.
//
// `unspecified` is reserved for the backward-compat wrapper (test-only entry
// path that does not yet thread a reason). Production code MUST pass an
// explicit reason; CI flags any new "unspecified" sighting via the
// TestFailClosedToDecoy_UnspecifiedOnlyFromCompatWrapper guard.
type DecoyReason string

const (
	DecoyReasonUnspecified        DecoyReason = "unspecified"
	DecoyReasonRateLimitHandshake DecoyReason = "rate_limit_handshake"
	DecoyReasonRateLimitWSUpgrade DecoyReason = "rate_limit_ws_upgrade"
	DecoyReasonRateLimitData      DecoyReason = "rate_limit_data"
	DecoyReasonRateLimitSoftLimit DecoyReason = "rate_limit_softlimit"
	DecoyReasonAuthFail           DecoyReason = "auth_fail"
	DecoyReasonProtocolUnknown    DecoyReason = "protocol_unknown"
	DecoyReasonPathMismatch       DecoyReason = "path_mismatch"
	DecoyReasonReplayDetected     DecoyReason = "replay_detected"
	DecoyReasonBodyInvalid        DecoyReason = "body_invalid"
	DecoyReasonVersionUnsupported DecoyReason = "version_unsupported"
	DecoyReasonHandshakeFail      DecoyReason = "handshake_fail"
	DecoyReasonDeviceLimit        DecoyReason = "device_limit"
	DecoyReasonBackpressure       DecoyReason = "backpressure"
	DecoyReasonMaxClients         DecoyReason = "max_clients"
	DecoyReasonStreamDuplicate    DecoyReason = "stream_duplicate"
	DecoyReasonInternal           DecoyReason = "internal"
)

// AllDecoyReasons enumerates every reason label in deterministic order. The
// Prometheus exposer iterates this slice so the output line order is stable
// across process restarts (alert rules can pin to a known label list).
var AllDecoyReasons = []DecoyReason{
	DecoyReasonUnspecified,
	DecoyReasonRateLimitHandshake,
	DecoyReasonRateLimitWSUpgrade,
	DecoyReasonRateLimitData,
	DecoyReasonRateLimitSoftLimit,
	DecoyReasonAuthFail,
	DecoyReasonProtocolUnknown,
	DecoyReasonPathMismatch,
	DecoyReasonReplayDetected,
	DecoyReasonBodyInvalid,
	DecoyReasonVersionUnsupported,
	DecoyReasonHandshakeFail,
	DecoyReasonDeviceLimit,
	DecoyReasonBackpressure,
	DecoyReasonMaxClients,
	DecoyReasonStreamDuplicate,
	DecoyReasonInternal,
}

// decoyLogIPRate caps WARN emissions at decoyLogPerIPLimit per
// decoyLogPerIPWindow per source IP. Defends ops journals against
// scan/probe floods that would otherwise produce thousands of identical
// lines per minute. Token-bucket-light: per-IP counter that resets on
// window roll-over.
//
// H-14 (раунд 18): the cache used to be a bare map with no eviction and no TTL,
// growing linearly with distinct source IPs for the process lifetime. The old
// comment estimated 100 B/entry → 100 MB per 1M IPs and called that acceptable;
// the estimate was accurate (measured: 105.9 B/entry) but the conclusion was not.
// logDecoyServed fires on EVERY failClosedToDecoy*, including
// DecoyReasonBodyInvalid — i.e. on any junk POST with application/json — and a
// single /64 IPv6 subnet supplies 2^64 source addresses. At 10M IPs that is
// ~0.99 GB on a box DefaultConfig documents as "2 vCPU / 2 GB RAM VPS".
//
// It was also the ONLY unbounded structure in server/: TokenBucket uses an
// expirable LRU capped at 10k, ClientIDExemption an LRU with an eviction
// callback, RateLimiter a 10000 cap. This now follows the same expirable-LRU
// pattern as tokenbucket.go / clientid_exempt.go.
//
// Tradeoff, deliberate: an IP evicted by LRU pressure gets a fresh window when it
// comes back, so it can emit up to decoyLogPerIPLimit more lines. A bounded
// memory ceiling matters more than exact journal-limit fidelity — and an attacker
// rotating a /64 already spends one entry per address, where previously the same
// flood grew the map without limit. Locked in by
// TestDecoyLog_EvictionResetsWindow_DocumentedTradeoff.
const (
	decoyLogPerIPLimit  = 10
	decoyLogPerIPWindow = time.Minute

	// decoyLogMaxIPs bounds the per-IP cache. Matches the 10k ceiling used by
	// TokenBucket / RateLimiter so all per-IP state in the package shares one
	// order of magnitude. At ~106 B/entry this caps the cache near 1 MB.
	decoyLogMaxIPs = 10000

	// decoyLogIdleTTL drops entries idle longer than this. Well above
	// decoyLogPerIPWindow so a rolling window is never truncated mid-flight.
	decoyLogIdleTTL = 10 * time.Minute
)

type decoyLogIPState struct {
	windowStart time.Time
	count       int
	suppressed  uint64 // # of WARNs dropped within the current window
}

var (
	decoyLogMu      sync.Mutex
	decoyLogPerIP   = newDecoyLogCache()
	decoyLogTotal   uint64 // total log emissions (after rate-limit) across all IPs
	decoyLogDropped uint64 // total drops across all IPs
)

// newDecoyLogCache builds the bounded per-IP cache. No eviction callback needed —
// entries hold no external resource (mirrors the tbEntry rationale).
func newDecoyLogCache() *lru.LRU[string, *decoyLogIPState] {
	return lru.NewLRU[string, *decoyLogIPState](decoyLogMaxIPs, nil, decoyLogIdleTTL)
}

// decoyLogCacheLen reports the current entry count. Test helper for the bound.
func decoyLogCacheLen() int {
	decoyLogMu.Lock()
	defer decoyLogMu.Unlock()
	return decoyLogPerIP.Len()
}

// shouldLogForIP returns true when this IP is below the per-window cap.
// Increments the per-IP counter on `true`, the suppressed counter on `false`.
// The function MUST be called exactly once per WARN emission attempt — the
// counter mutation is the side effect that enforces the cap.
func shouldLogForIP(ip string, now time.Time) (allow bool, suppressedSinceLastAllow uint64) {
	decoyLogMu.Lock()
	defer decoyLogMu.Unlock()

	state, ok := decoyLogPerIP.Get(ip)
	if !ok {
		state = &decoyLogIPState{windowStart: now}
		// Add may evict the least-recently-used entry — that is the bound (H-14).
		decoyLogPerIP.Add(ip, state)
	}
	if now.Sub(state.windowStart) >= decoyLogPerIPWindow {
		// Window rolled over — reset count + start, but PRESERVE suppressed
		// across the boundary so the first allow of the new window can still
		// report "+N dropped during the storm". The next allow zeroes it
		// (see "since last allow" doc on the field).
		state.windowStart = now
		state.count = 0
	}
	if state.count < decoyLogPerIPLimit {
		state.count++
		decoyLogTotal++
		// Tell the caller how many we dropped since the last allow so the
		// surfaced WARN can carry a "+N suppressed" hint.
		s := state.suppressed
		state.suppressed = 0
		return true, s
	}
	state.suppressed++
	decoyLogDropped++
	return false, 0
}

// truncate clips s to at most n bytes (not runes — header values are typically
// ASCII, and even when they aren't, a byte boundary is always a safe cut for
// log fields). Returns "" if s is empty.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 0 {
		return ""
	}
	return s[:n]
}

// logDecoyServed emits a structured WARN for every decoy dispatch, subject
// to the per-IP rate limit. Fields surface the request shape that
// distinguishes a probe from a misbehaving legitimate client without leaking
// PII (no body, no cookies). Caller MUST pass the resolved client IP — we do
// not re-derive it here so the same IP-extraction policy (BehindProxy) applies
// uniformly to logs and to rate-limit gating upstream.
//
// suppressed > 0 means N additional WARNs were dropped from the same IP
// since the previous allow within the active window. Surfaced as an attr so
// ops can spot a probe storm even when the per-IP cap kicks in.
func logDecoyServed(reason DecoyReason, r *http.Request, clientIP string) {
	// Always count — even when the WARN itself is rate-limited the metric
	// must reflect every dispatch.
	now := time.Now()
	allow, suppressed := shouldLogForIP(clientIP, now)
	if !allow {
		return
	}
	args := []any{
		"reason", string(reason),
		"remote_ip", clientIP,
		"path", r.URL.Path,
		"method", r.Method,
		"ua", truncate(r.Header.Get("User-Agent"), 60),
		"content_length", r.ContentLength,
	}
	if suppressed > 0 {
		args = append(args, "suppressed_since_last", suppressed)
	}
	slog.Warn("decoy served", args...)
}

// DecoyLogStats returns coarse counters for the rate-limited log emitter.
// Test-only helper; production observability comes from the Prom counter on
// Metrics, not from this internal map.
func DecoyLogStats() (logged, dropped uint64) {
	decoyLogMu.Lock()
	defer decoyLogMu.Unlock()
	return decoyLogTotal, decoyLogDropped
}

// ResetDecoyLogStateForTest wipes the per-IP cache and global counters.
// Test-only helper — production code never calls this.
func ResetDecoyLogStateForTest() {
	decoyLogMu.Lock()
	defer decoyLogMu.Unlock()
	decoyLogPerIP = newDecoyLogCache()
	decoyLogTotal = 0
	decoyLogDropped = 0
}

package server

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
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
// The cache is intentionally simple — no LRU eviction, no TTL sweeper.
// The map grows linearly with distinct source IPs since process start.
// At 100B per entry × 1M unique IPs ≈ 100 MB; for the workloads ShadowLink
// targets this is comfortably below RAM budget. A future LRU upgrade is
// trivial (replace the map with a linked-hash) but unnecessary for now.
const (
	decoyLogPerIPLimit  = 10
	decoyLogPerIPWindow = time.Minute
)

type decoyLogIPState struct {
	windowStart time.Time
	count       int
	suppressed  uint64 // # of WARNs dropped within the current window
}

var (
	decoyLogMu      sync.Mutex
	decoyLogPerIP   = make(map[string]*decoyLogIPState)
	decoyLogTotal   uint64 // total log emissions (after rate-limit) across all IPs
	decoyLogDropped uint64 // total drops across all IPs
)

// shouldLogForIP returns true when this IP is below the per-window cap.
// Increments the per-IP counter on `true`, the suppressed counter on `false`.
// The function MUST be called exactly once per WARN emission attempt — the
// counter mutation is the side effect that enforces the cap.
func shouldLogForIP(ip string, now time.Time) (allow bool, suppressedSinceLastAllow uint64) {
	decoyLogMu.Lock()
	defer decoyLogMu.Unlock()

	state, ok := decoyLogPerIP[ip]
	if !ok {
		state = &decoyLogIPState{windowStart: now}
		decoyLogPerIP[ip] = state
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
	decoyLogPerIP = make(map[string]*decoyLogIPState)
	decoyLogTotal = 0
	decoyLogDropped = 0
}

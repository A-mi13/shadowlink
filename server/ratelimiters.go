package server

import (
	"os"
	"strings"
	"time"
)

// useTokenBucket reports whether the new TokenBucket rate-limit path is
// active. Default ON; opt out with SHADOWLINK_RL_TOKENBUCKET=0/false/no/off.
// Mirrors pqEnabled() semantics (client/utls_http.go).
func useTokenBucket() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_RL_TOKENBUCKET"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// useClientIDExemption reports whether the §C4 ClientID exemption fast-path
// is active. Default ON; opt out with
// SHADOWLINK_RL_CLIENTID_EXEMPT=0/false/no/off. Mirrors useTokenBucket()
// semantics.
func useClientIDExemption() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_RL_CLIENTID_EXEMPT"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// RateLimiters bundles per-path rate limiters. Splitting them keeps one path's
// burst (e.g. WS pool reconnect cascade) from starving another (e.g. a live
// session's data POSTs) of its budget.
//
// Per-path cost profile:
//   - Handshake: dominated by X25519 scalar mult (~50-100µs). Must be permissive
//     enough to survive legitimate WS pool reconnect bursts (20-50/min from
//     one client IP for a 4-8-slot pool) — see handler.go:87 incident note.
//   - Data: cheap per-call (AES-GCM open of ~12 KB). Bursty under streaming
//     workloads, so the cap is an order of magnitude higher.
//   - WSUpgrade: each upgrade pins a goroutine + conn for the session's
//     lifetime — the tightest cap keeps TCP-level resource exhaustion bounded.
//
// When UseBucket is true (default, controlled by useTokenBucket()), the
// AllowHandshake / AllowWSUpgrade / AllowData shim methods dispatch to the
// corresponding TokenBucket fields, which provide smooth token-bucket
// semantics with (remaining, retryAfter) feedback. When UseBucket is false
// (SHADOWLINK_RL_TOKENBUCKET=0), the legacy RateLimiter (counter+window) is
// used instead for backward compatibility.
type RateLimiters struct {
	Handshake *RateLimiter
	Data      *RateLimiter
	WSUpgrade *RateLimiter

	HandshakeBucket *TokenBucket
	DataBucket      *TokenBucket
	WSUpgradeBucket *TokenBucket

	UseBucket bool
}

// NewRateLimiters constructs the per-path rate limiters. handshakePerMin is
// wired from Config.HandshakeRateLimitPerMin so operators can tune it for
// their deployment; Data / WSUpgrade limits are fixed protocol policy.
// useBucket selects between the new TokenBucket path (smooth refill) and
// the legacy counter+window RateLimiter; call with useTokenBucket() at
// handler construction time.
//
// Default handshake rate (applied when handshakePerMin<=0) is 300/min, which
// deviates from the plan's 60/min: the 60 cap would regress the WS pool
// reconnect cascade fix in handler.go:87 that specifically raised the cap to
// 300 after a legacy 50/min incident. See memory phase-b-nuances.md (B7).
//
// Wraps NewRateLimitersWithConfig with the legacy single-rate Handshake spec
// + fixed WSUpgrade defaults so older callers (and tests pinned to the
// 2-arg signature) keep working. Plan §C6 (May audit, 2026-05-02).
func NewRateLimiters(handshakePerMin int, useBucket bool) *RateLimiters {
	if handshakePerMin <= 0 {
		handshakePerMin = 300
	}
	hs := RateLimitBucketSpec{Burst: 50, RefillPerMin: handshakePerMin}
	ws := RateLimitBucketSpec{Burst: 18, RefillPerMin: 30}
	return NewRateLimitersWithConfig(hs, ws, useBucket)
}

// NewRateLimitersWithConfig constructs per-path rate limiters from explicit
// per-bucket specs. Zero-valued specs trigger defensive defaults so a caller
// that forgot to fill them in cannot accidentally produce a 0-burst /
// 0-refill bucket that rejects every request. Plan §C6 (May audit,
// 2026-05-02).
//
// Data path is fixed protocol policy (600 RPM, burst 100) — operators don't
// tune it via YAML for now. If that need arises, add a third spec param.
func NewRateLimitersWithConfig(hs, ws RateLimitBucketSpec, useBucket bool) *RateLimiters {
	if hs.Burst <= 0 {
		hs.Burst = 50
	}
	if hs.RefillPerMin <= 0 {
		hs.RefillPerMin = 300
	}
	if ws.Burst <= 0 {
		ws.Burst = 18
	}
	if ws.RefillPerMin <= 0 {
		ws.RefillPerMin = 30
	}
	r := &RateLimiters{
		Handshake: NewRateLimiter(hs.RefillPerMin, time.Minute),
		Data:      NewRateLimiter(600, time.Minute),
		WSUpgrade: NewRateLimiter(ws.RefillPerMin, time.Minute),
		UseBucket: useBucket,
	}
	if useBucket {
		r.HandshakeBucket = NewTokenBucket(hs.Burst, float64(hs.RefillPerMin)/60.0, 10000)
		r.DataBucket = NewTokenBucket(100, 600.0/60.0, 10000)
		r.WSUpgradeBucket = NewTokenBucket(ws.Burst, float64(ws.RefillPerMin)/60.0, 10000)
	}
	return r
}

// AllowHandshake checks whether the given IP is within the handshake rate
// limit. Returns (allowed, remaining, retryAfter). When UseBucket is true,
// delegates to HandshakeBucket (token-bucket); otherwise falls back to the
// legacy counter+window limiter, returning (ok, 0, 0).
// Task C5 will wire remaining/retryAfter into the X-SL-RL sentinel header.
func (r *RateLimiters) AllowHandshake(ip string) (bool, int, time.Duration) {
	if r.UseBucket {
		return r.HandshakeBucket.Allow(ip)
	}
	ok := r.Handshake.Allow(ip)
	return ok, 0, 0
}

// AllowWSUpgrade checks whether the given IP is within the WS upgrade rate
// limit. Returns (allowed, remaining, retryAfter). Dispatches to WSUpgradeBucket
// when UseBucket is true, legacy WSUpgrade limiter otherwise.
func (r *RateLimiters) AllowWSUpgrade(ip string) (bool, int, time.Duration) {
	if r.UseBucket {
		return r.WSUpgradeBucket.Allow(ip)
	}
	ok := r.WSUpgrade.Allow(ip)
	return ok, 0, 0
}

// AllowData checks whether the given IP is within the data-path rate limit.
// Returns (allowed, remaining, retryAfter). Dispatches to DataBucket when
// UseBucket is true, legacy Data limiter otherwise.
func (r *RateLimiters) AllowData(ip string) (bool, int, time.Duration) {
	if r.UseBucket {
		return r.DataBucket.Allow(ip)
	}
	ok := r.Data.Allow(ip)
	return ok, 0, 0
}

// Cleanup prunes stale IP entries across every limiter. Called periodically
// from Handler.StartCleanup.
func (rls *RateLimiters) Cleanup() {
	rls.Handshake.Cleanup()
	rls.Data.Cleanup()
	rls.WSUpgrade.Cleanup()
	if rls.UseBucket {
		idle := 10 * time.Minute
		rls.HandshakeBucket.Cleanup(idle)
		rls.DataBucket.Cleanup(idle)
		rls.WSUpgradeBucket.Cleanup(idle)
	}
}

package server

import (
	"math/rand/v2"
	"time"
)

// applyFallbackJitter sleeps until (startTime + target ± jitter), where target and
// jitter come from h.cfg.FallbackLatencyMs / FallbackJitterMs. If the actual work
// (cache lookup, limiter check) already took longer than the target, returns immediately.
//
// Purpose: make every fail/rate-limit/timeout path in live_blog handlers complete
// in a single timing bucket, so DPI probes can't distinguish them from each other
// (C1/C3 from T1.3 code review 2026-04-23). Pattern copies decoy_timing.ackJitter.
//
// math/rand/v2 global functions are thread-safe per Go 1.22+.
func (h *LiveBlogHandler) applyFallbackJitter(startTime time.Time) {
	target := time.Duration(h.cfg.FallbackLatencyMs) * time.Millisecond
	if target <= 0 {
		return
	}
	var jitter time.Duration
	if h.cfg.FallbackJitterMs > 0 {
		// IntN(2*j+1) returns [0..2j]; subtract j to center around 0 → [-j..j]
		offset := rand.IntN(2*h.cfg.FallbackJitterMs+1) - h.cfg.FallbackJitterMs
		jitter = time.Duration(offset) * time.Millisecond
	}
	deadline := target + jitter
	elapsed := time.Since(startTime)
	if elapsed < deadline {
		time.Sleep(deadline - elapsed)
	}
}

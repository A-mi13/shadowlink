package client

import (
	"sync/atomic"
	"time"
)

// RateLimitDetector — runs carriers in order, returns first match. If none
// match but body starts with '<' (HTML decoy fallback), returns a lifeline
// signal with default cooldown — protects against P0 sticky-loop in worst
// case where both header and body marker are stripped by CDN.
type RateLimitDetector struct {
	carriers []RateLimitCarrier

	// Aggregate stats counters — atomic, wired to client/stats.go counters via DefaultDetector.
	// Always incremented regardless of ctx.Path, for back-compat with existing dashboards/tests.
	DetectedByBody   *atomic.Uint64
	DetectedByHeader *atomic.Uint64
	DetectedFallback *atomic.Uint64

	// metrics — optional statsRegistry pointer for per-path counter increments
	// (Phase 2, 2026-05-14). Nil in tests that use newTestDetector() — path
	// counters are skipped when nil. Production paths always pass &Stats via
	// DefaultDetector, so per-path counters are always wired in prod.
	metrics *statsRegistry
}

// DefaultDetector returns the standard production chain: body → header → fallback.
// metrics must be non-nil (pass &Stats).
func DefaultDetector(metrics *statsRegistry) *RateLimitDetector {
	return &RateLimitDetector{
		carriers: []RateLimitCarrier{
			BodyMarkerCarrier{},
			HeaderCarrier{},
		},
		DetectedByBody:   &metrics.RateLimitDetectedByBody,
		DetectedByHeader: &metrics.RateLimitDetectedByHeader,
		DetectedFallback: &metrics.RateLimitDetectedFallback,
		metrics:          metrics,
	}
}

// incPathCounter increments a per-path counter in d.metrics based on carrier
// and ctx.Path. No-op when d.metrics is nil or ctx.Path is unrecognized.
func (d *RateLimitDetector) incPathCounter(carrier string, path string) {
	if d.metrics == nil {
		return
	}
	switch carrier {
	case "body":
		switch path {
		case "handshake":
			d.metrics.RateLimitDetectedByBody_Handshake.Add(1)
		case "ws_upgrade":
			d.metrics.RateLimitDetectedByBody_WS.Add(1)
		}
	case "header_v1", "header_legacy":
		switch path {
		case "handshake":
			d.metrics.RateLimitDetectedByHeader_Handshake.Add(1)
		case "ws_upgrade":
			d.metrics.RateLimitDetectedByHeader_WS.Add(1)
		}
	case "fallback":
		switch path {
		case "handshake":
			d.metrics.RateLimitDetectedFallback_Handshake.Add(1)
		// Note: no fallback_WS — WS path uses DetectCarriersOnly (no lifeline).
		}
	}
}

// Detect runs the carrier chain; returns first signal found or fallback.
// Returns nil if response doesn't look rate-limited at all.
// ctx.Path ("handshake" | "ws_upgrade") is used to increment per-path counters
// in addition to the aggregate counters.
func (d *RateLimitDetector) Detect(ctx *DetectionContext) *RateLimitSignal {
	now := time.Now()

	for _, c := range d.carriers {
		sig := c.Detect(ctx)
		if sig == nil {
			continue
		}
		if sig.Carrier == "" {
			sig.Carrier = c.Name()
		}
		sig.DetectedAt = now

		switch sig.Carrier {
		case "body":
			d.DetectedByBody.Add(1)
			d.incPathCounter("body", ctx.Path)
		case "header_v1", "header_legacy":
			d.DetectedByHeader.Add(1)
			d.incPathCounter(sig.Carrier, ctx.Path)
		}
		return sig
	}

	// Lifeline: body starts with '<' AND header is empty → likely CDN-stripped
	// rate-limit response. Apply default 90s cooldown to break P0 tight loop.
	if isHTMLBody(ctx.BodyHead) && (ctx.Response == nil || ctx.Response.Header.Get("X-SL-RL") == "") {
		d.DetectedFallback.Add(1)
		d.incPathCounter("fallback", ctx.Path)
		return &RateLimitSignal{
			Bucket:     "unknown_via_fallback",
			RefillIn:   90 * time.Second,
			BurstLeft:  -1,
			Carrier:    "fallback",
			DetectedAt: now,
		}
	}

	return nil
}

// DetectCarriersOnly runs body marker + header carriers without the lifeline
// fallback. Use for the WS upgrade error path where any rejected upgrade
// (CF middlebox, generic decoy, etc.) returns HTML — the lifeline would fire
// on every non-101 response, causing false-positive rate-limit cooldowns.
// Only a genuine positive signal (Schema.org body marker or X-SL-RL header)
// triggers ErrRateLimited on the WS path.
func (d *RateLimitDetector) DetectCarriersOnly(ctx *DetectionContext) *RateLimitSignal {
	now := time.Now()

	for _, c := range d.carriers {
		sig := c.Detect(ctx)
		if sig == nil {
			continue
		}
		if sig.Carrier == "" {
			sig.Carrier = c.Name()
		}
		sig.DetectedAt = now

		switch sig.Carrier {
		case "body":
			d.DetectedByBody.Add(1)
			d.incPathCounter("body", ctx.Path)
		case "header_v1", "header_legacy":
			d.DetectedByHeader.Add(1)
			d.incPathCounter(sig.Carrier, ctx.Path)
		}
		return sig
	}

	return nil // no lifeline — caller treats nil as a regular network error
}

// isHTMLBody returns true if b starts with '<' (skipping leading whitespace).
func isHTMLBody(b []byte) bool {
	if len(b) < 1 {
		return false
	}
	// Skip whitespace
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i < len(b) && b[i] == '<'
}

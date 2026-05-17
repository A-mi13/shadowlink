package client

import (
	"math"
	"math/rand/v2"
	"time"
)

// JitteredInterval returns a duration uniformly sampled from
//
//	[base * (1 - jitterFraction), base * (1 + jitterFraction)]
//
// clamped at a lower bound of base/2 to prevent pathological zero/negative
// durations under extreme jitter values (e.g. jitterFraction=1.0).
//
// Examples:
//
//	JitteredInterval(20*time.Second, 0.3) ∈ [14s, 26s]
//	JitteredInterval(5*time.Second,  0.5) ∈ [2.5s, 7.5s]
//	JitteredInterval(20*time.Second, 1.0) ∈ [10s, 40s] (lower bound clamped from 0)
//
// Edge cases:
//   - jitterFraction <= 0  → returns base unchanged.
//   - base <= 0            → returns 0.
//
// Safe for concurrent use — `math/rand/v2`'s top-level `Float64()` is
// goroutine-safe.
//
// Use for **one-shot delays** (initial backoff, slot warmup) where the
// heavy tail of a log-normal sampler is undesirable. For
// **recurring/periodic** ticks (keepalive, cover, ratio-reset) prefer
// JitteredIntervalLogNormal — flat uniform histograms are themselves an
// FFT-visible signature against real-world heavy-tailed network jitter
// (final-audit-2026-05-03 T2 P1).
func JitteredInterval(base time.Duration, jitterFraction float64) time.Duration {
	if base <= 0 {
		return 0
	}
	if jitterFraction <= 0 {
		return base
	}
	// (Float64() - 0.5) ∈ [-0.5, 0.5) → *2 ∈ [-1.0, 1.0) → *frac*base ∈
	// [-frac*base, +frac*base). Add to base for the symmetric window.
	delta := time.Duration((rand.Float64() - 0.5) * 2 * jitterFraction * float64(base))
	out := base + delta
	if min := base / 2; out < min {
		out = min
	}
	return out
}

// normFloat64Source abstracts the standard-normal sampler so production
// callers can use the package-level `math/rand/v2` RNG (goroutine-safe,
// non-seedable) while tests inject a seeded `*rand.Rand`. Defined as a
// function-typed parameter rather than an interface to keep the hot path
// allocation-free. Mirror of the helper in core/jitter.go.
type normFloat64Source func() float64

// maxLogNormalRejections caps the rejection-sampling retry count inside
// JitteredIntervalLogNormalRng. Mirrors core/jitter.go (final-audit-
// 2026-05-05 Review 1 M-3).
const maxLogNormalRejections = 5

// JitteredIntervalLogNormal returns a duration sampled from a log-normal
// distribution centered around base, truncated to [base/2, base*2]:
//
//	interval = exp(ln(base) + sigma * N(0,1))   truncated [base/2, base*2]
//
// Use for **recurring/periodic** ticks (keepalive loops, cover-traffic
// schedulers, ratio-reset timers). Real-world RTT and browser
// inter-request jitter is approximately log-normal — heavy right tail,
// no hard upper cutoff. A flat uniform histogram inside the jitter band
// plus sharp band edges is detectable by a passive ML classifier
// (KS-test against log-normal reference is a common feature).
//
// Recommended sigma values:
//   - 0.3 — mild (matches the existing ±30% uniform feel; median preserved)
//   - 0.5 — moderate (default per final-audit-2026-05-03 P1-3)
//   - 0.7 — heavy (large variance; use sparingly)
//
// Edge cases:
//   - sigma <= 0  → returns base unchanged.
//   - base  <= 0  → returns 0.
//
// Truncation [base/2, base*2] is enforced via **rejection sampling** to
// avoid the point-mass-on-edges signature that a passive FFT analyser can
// pick up — re-draw N(0,1) up to maxLogNormalRejections times if the
// candidate is outside the rails. After exhausting retries (only happens
// for very large sigma) we clamp the next draw as a bounded-cost fallback;
// the residual edge-mass is empirically <0.5% (vs ~6% with bare clamp at
// sigma=0.5). Closes Review 1 M-3 of final-audit-2026-05-05.
//
// Safe for concurrent use — `math/rand/v2`'s `NormFloat64()` is
// goroutine-safe via the package-level RNG.
//
// See `shadowlink/docs/strategy/2026-05-03-final-audit/T2-transport-dpi.md`
// § P1 and `core.JitteredIntervalLogNormal` (mirror — kept in core/ so
// the server side can share without an import cycle).
func JitteredIntervalLogNormal(base time.Duration, sigma float64) time.Duration {
	return jitteredIntervalLogNormal(base, sigma, rand.NormFloat64)
}

// JitteredIntervalLogNormalRng is the seeded variant of
// JitteredIntervalLogNormal — accepts a caller-supplied `*rand.Rand` so
// tests can drive the sampler from a deterministic seed (PCG64 via
// `rand.NewPCG`). Production code should keep using
// JitteredIntervalLogNormal which routes through the package-level
// goroutine-safe RNG; this entry point exists purely to make the
// chi-square / KS gate tests reproducible (final-audit-2026-05-05
// Review 1 M-4).
//
// Passing rng=nil falls back to the package-level RNG.
func JitteredIntervalLogNormalRng(base time.Duration, sigma float64, rng *rand.Rand) time.Duration {
	if rng == nil {
		return JitteredIntervalLogNormal(base, sigma)
	}
	return jitteredIntervalLogNormal(base, sigma, rng.NormFloat64)
}

// jitteredIntervalLogNormal is the shared implementation behind both the
// package-RNG and seeded-RNG entry points. Splits the source function out
// so neither caller pays an interface dispatch cost on the hot path.
func jitteredIntervalLogNormal(base time.Duration, sigma float64, normFloat64 normFloat64Source) time.Duration {
	if base <= 0 {
		return 0
	}
	if sigma <= 0 {
		return base
	}
	muLog := math.Log(float64(base))
	lo := float64(base) / 2
	hi := float64(base) * 2

	// Rejection sampling: re-draw if outside [lo, hi]. Bounds the cost at
	// maxLogNormalRejections+1 NormFloat64 draws even under pathological
	// sigma (e.g. >2). For sigma <= 0.7 the success rate per draw is high
	// enough that the loop typically exits on the first or second attempt.
	for i := 0; i < maxLogNormalRejections; i++ {
		v := math.Exp(muLog + sigma*normFloat64())
		if v >= lo && v <= hi {
			return time.Duration(v)
		}
	}

	// Fallback: one more draw clamped to the rails. Preserves cost
	// predictability (the function never blocks on retries) at the price
	// of a tiny residual point-mass when sigma is extreme. Empirically
	// <0.5% at sigma=0.5 vs ~6% with bare clamp.
	v := math.Exp(muLog + sigma*normFloat64())
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return time.Duration(v)
}

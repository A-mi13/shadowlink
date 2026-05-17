package browser

import (
	"math"
	"math/rand"
)

// SamplePaddingTarget returns padding bytes ∈ [600, 3000] sampled from a log-normal
// distribution independent of PayloadDistribution.
//
// A2-HIGH-7 closure (Phase 2): legacy 80-byte threshold + payload-coupled
// sampling produced padding histogram correlated with download histogram.
// Independent distribution removes that side-channel signal.
//
// May-audit C6 closure (2026-05-02): placeholder shifted to Mixpanel /track
// public range (600-3000 bytes) — real Mixpanel /track POST sizes per public
// docs; pre-shift constants (μ_log = ln(48), [16, 512]) lived in the wrong
// absolute zone and were detectable against any reference Mixpanel fixture.
// Calibration vs captured Mixpanel fixture deferred to Phase 5 / S5 schema lock.
//
// Parameters: μ_log = ln(900) ≈ 6.80, σ_log = 0.5. Mean ≈ 1023, p99 ≈ 2900.
func SamplePaddingTarget(rng *rand.Rand) int {
	const muLog = 6.802394763324311 // ln(900)
	const sigmaLog = 0.5
	v := math.Exp(muLog + sigmaLog*rng.NormFloat64())
	switch {
	case v < 600:
		return 600
	case v > 3000:
		return 3000
	default:
		return int(v)
	}
}

// SampleHandshakePaddingTarget returns padding bytes ∈ [200, 800] sampled from a
// log-normal distribution with smaller mean than SamplePaddingTarget. Used for
// HANDSHAKE payloads — handshake POSTs are smaller than data POSTs in real
// analytics SDKs (init payload is just ID + version + minimal config preamble).
//
// A2-HIGH-5 closure (Phase 3 Plan A): handshake/data padding distributions
// must diverge (KS-test reject same-distribution H0 with p<0.01). Plan B
// Pre-flight will refit μ/σ against captured Mixpanel reference fixture; the
// constants here are placeholders sized to be provably distinct from
// SamplePaddingTarget. DO NOT remove this comment until Plan B Pre-flight
// task updates these constants.
//
// May-audit C6 closure (2026-05-02): shifted to Mixpanel-shape handshake range
// (200-800 bytes) — symmetric shift with SamplePaddingTarget so KS divergence
// is preserved while both distributions live in the right absolute zone.
// Calibration vs captured Mixpanel fixture deferred to Phase 5 / S5 schema lock.
//
// Parameters: μ_log = ln(350) ≈ 5.86, σ_log = 0.5. Mean ≈ 397; samples >800
// clamp to 800.
func SampleHandshakePaddingTarget(rng *rand.Rand) int {
	const muLog = 5.857933154483459 // ln(350)
	const sigmaLog = 0.5
	v := math.Exp(muLog + sigmaLog*rng.NormFloat64())
	switch {
	case v < 200:
		return 200
	case v > 800:
		return 800
	default:
		return int(v)
	}
}

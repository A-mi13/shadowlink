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
// May-audit C6 closure (2026-05-02): pre-shift constants (μ_log = ln(48),
// [16, 512]) lived in the wrong absolute zone — a few hundred bytes is below
// what any JSON-bodied POST from a browser application looks like, so the
// distribution was separable from web traffic on size alone.
//
// Range rationale (restated 2026-08-08, third-party-vendor persona retired):
// [600, 3000] is the body-size band of a batched JSON telemetry POST from a
// SPA to its own backend — several events with properties, not a single
// keystroke beacon. The band no longer references any specific analytics
// vendor: there is no reference fixture to match, and matching one was never
// achievable anyway (TSPU does not decrypt bodies — see the 2026-04-28 pivot
// in docs/PHASES-CHANGELOG.md). What must hold is the absolute zone and the
// divergence from the handshake distribution below, both of which are pinned
// by tests in padding_test.go.
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
// HANDSHAKE payloads — a client's first POST carries only identity and config
// preamble, so it is smaller than the batched event POSTs that follow.
//
// A2-HIGH-5 closure (Phase 3 Plan A): handshake/data padding distributions
// must diverge (KS-test reject same-distribution H0 with p<0.01). The two
// bands are deliberately non-overlapping in their bulk mass; a single
// distribution for both would make the handshake identifiable as "the first
// POST of the session" purely by size.
//
// May-audit C6 closure (2026-05-02): shifted to [200, 800] — a symmetric shift
// with SamplePaddingTarget, so KS divergence is preserved while both
// distributions sit in a plausible absolute zone for JSON POST bodies.
//
// Restated 2026-08-08: the former "refit against a captured vendor fixture"
// plan is dropped along with the third-party-analytics persona. There is no
// fixture to converge on, and the property that matters — divergence from
// SamplePaddingTarget plus a plausible absolute range — is pinned by tests
// rather than by resemblance to any one vendor.
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

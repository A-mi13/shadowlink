package browser

import (
	"math"
	"math/rand"
)

// SampleResponseSize returns a target response body size in bytes for inflated
// download responses. Distribution: Gaussian core (μ=2048, σ=800) for typical
// responses, with 5% Pareto-tail probability (α=2, scale=2048) for long-tail
// large responses.
//
// Output truncated to [256, 32768].
//
// T2.4 closure (Phase 3 Plan A): replaces discrete-size lookup table that
// produced histogram spikes at fixed bytes. Spec § 4.4.
//
// Note (Plan A): integration into BuildInflatedDownloadResponse padding is
// deferred to Plan B Stage 1 (server matcher reshapes response body assembly
// at that point, natural place to wire this in). Plan A ships sampler + tests.
func SampleResponseSize(rng *rand.Rand) int {
	if rng.Float64() < 0.05 {
		// Pareto tail: heavy-tailed large responses (~5% of traffic).
		const alpha = 2.0
		const scale = 2048.0
		u := rng.Float64()
		if u >= 1.0 {
			u = 0.999999
		}
		v := scale / math.Pow(1.0-u, 1.0/alpha)
		if v > 32768 {
			return 32768
		}
		if v < 2048 {
			return 2048
		}
		return int(v)
	}
	// Gaussian core
	const mu = 2048.0
	const sigma = 800.0
	v := rng.NormFloat64()*sigma + mu
	switch {
	case v < 256:
		return 256
	case v > 32768:
		return 32768
	default:
		return int(v)
	}
}

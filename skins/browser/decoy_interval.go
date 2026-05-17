package browser

import (
	"math"
	"math/rand"
	"time"
)

// NextDecoyInterval returns the wait time between fake decoy GET requests,
// sampled from a log-normal distribution truncated to [5s, 90s].
//
// Parameters: μ_log = ln(25), σ_log = 0.4. Median 25s, P95 ≈ 50s, P99 ≈ 70s.
//
// T2.4 closure (Phase 3 Plan A): replaces uniform [15s, 45s] used before, which
// was a detectable narrow-window pattern.
func NextDecoyInterval(rng *rand.Rand) time.Duration {
	const muLog = 3.2188758248682006 // ln(25)
	const sigmaLog = 0.4
	v := math.Exp(muLog + sigmaLog*rng.NormFloat64())
	switch {
	case v < 5:
		return 5 * time.Second
	case v > 90:
		return 90 * time.Second
	default:
		return time.Duration(v * float64(time.Second))
	}
}

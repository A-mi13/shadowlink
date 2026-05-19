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

// DecoyState represents the current mode of the bimodal decoy GET scheduler.
type DecoyState int

const (
	DecoyStateBurst DecoyState = iota
	DecoyStateQuiet
)

// NextDecoyIntervalBimodal returns the next decoy GET interval and updated
// Markov state. Burst mode: log-normal median 250ms. Quiet mode: log-normal
// median 60s. Switching: P(burst→quiet) = 0.15, P(quiet→burst) = 0.05.
//
// Accepts *rand.Rand for test reproducibility (Plan A KS-test seed=42 pattern).
// Passing nil falls back to a fresh time-seeded RNG; prefer seeded RNG in tests.
//
// Task 3.2 closure (Opus MAJOR-2 — seedable RNG): replaces unimodal log-normal
// `NextDecoyInterval` with bimodal Markov scheduler. Real browser cadence
// alternates between burst phases (rapid asset fetches, ~200ms apart) and
// quiet phases (idle tab, minutes between background polls). Single-mode
// distributions are FFT-detectable as a synthetic signal; bimodal+Markov
// destroys that spectral peak by adding a second mode + state correlation.
func NextDecoyIntervalBimodal(state DecoyState, rng *rand.Rand) (time.Duration, DecoyState) {
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	var newState DecoyState
	switch state {
	case DecoyStateBurst:
		if rng.Float64() < 0.15 {
			newState = DecoyStateQuiet
		} else {
			newState = DecoyStateBurst
		}
	case DecoyStateQuiet:
		if rng.Float64() < 0.05 {
			newState = DecoyStateBurst
		} else {
			newState = DecoyStateQuiet
		}
	}

	var d time.Duration
	if newState == DecoyStateBurst {
		d = sampleLogNormalClamped(rng, 0.25, 0.5, 100*time.Millisecond, 1*time.Second)
	} else {
		d = sampleLogNormalClamped(rng, 60.0, 0.5, 15*time.Second, 300*time.Second)
	}
	return d, newState
}

// sampleLogNormalClamped samples log-normal with the given median (seconds)
// and sigma, clamped to [min, max].
func sampleLogNormalClamped(rng *rand.Rand, medianSec, sigma float64, min, max time.Duration) time.Duration {
	muLog := math.Log(medianSec)
	v := math.Exp(muLog + sigma*rng.NormFloat64())
	d := time.Duration(v * float64(time.Second))
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}

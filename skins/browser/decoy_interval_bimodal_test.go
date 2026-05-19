package browser

import (
	"math/rand"
	"testing"
)

// TestNextDecoyIntervalBimodal_TwoModes — bimodal distribution: burst (~250ms) + quiet (~60s).
func TestNextDecoyIntervalBimodal_TwoModes(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const N = 10000

	short := 0
	long := 0
	state := DecoyStateBurst
	for i := 0; i < N; i++ {
		d, newState := NextDecoyIntervalBimodal(state, rng)
		state = newState
		secs := d.Seconds()
		if secs < 1 {
			short++
		}
		if secs > 10 {
			long++
		}
	}

	shortRatio := float64(short) / float64(N)
	longRatio := float64(long) / float64(N)
	// Steady-state of the Markov chain: P(Burst) = 0.05/(0.05+0.15) = 0.25,
	// P(Quiet) = 0.75. Burst median 250ms → ~all <1s; Quiet median 60s →
	// ~all >10s. Wide tolerances guard against transient swings + log-normal
	// clamping while still proving the distribution is bimodal.
	if shortRatio < 0.15 {
		t.Errorf("short-interval (burst) ratio %.2f%%, want > 15%% (steady-state ~25%%)", 100*shortRatio)
	}
	if longRatio < 0.50 {
		t.Errorf("long-interval (quiet) ratio %.2f%%, want > 50%% (steady-state ~75%%)", 100*longRatio)
	}
}

// TestNextDecoyIntervalBimodal_Reproducible — same seed gives same sequence (guards seedable RNG).
func TestNextDecoyIntervalBimodal_Reproducible(t *testing.T) {
	rng1 := rand.New(rand.NewSource(42))
	rng2 := rand.New(rand.NewSource(42))
	state1, state2 := DecoyStateBurst, DecoyStateBurst
	for i := 0; i < 100; i++ {
		d1, s1 := NextDecoyIntervalBimodal(state1, rng1)
		d2, s2 := NextDecoyIntervalBimodal(state2, rng2)
		if d1 != d2 || s1 != s2 {
			t.Errorf("step %d: sequences diverge (RNG not seedable): %v/%v vs %v/%v", i, d1, s1, d2, s2)
		}
		state1, state2 = s1, s2
	}
}

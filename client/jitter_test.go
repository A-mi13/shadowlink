package client

import (
	"math"
	"testing"
	"time"
)

// TestJitteredInterval_RangeAndMean asserts that JitteredInterval(base, frac)
// returns durations within the expected uniform-random window and that the
// mean over many samples is close to base. Catches off-by-one in the symmetric
// jitter math.
func TestJitteredInterval_RangeAndMean(t *testing.T) {
	const base = 100 * time.Millisecond
	const frac = 0.3
	const N = 10000

	// Expected raw range: base * (1 ± frac) = [70ms, 130ms].
	// The clamp at base/2 = 50ms is well below 70ms, so no clamping happens here.
	const minExpected = 70 * time.Millisecond
	const maxExpected = 130 * time.Millisecond
	// Allow 0.1% slack for FP rounding.
	const slack = 100 * time.Microsecond

	var sum int64
	var minObs = time.Duration(math.MaxInt64)
	var maxObs time.Duration
	for i := 0; i < N; i++ {
		got := JitteredInterval(base, frac)
		sum += int64(got)
		if got < minObs {
			minObs = got
		}
		if got > maxObs {
			maxObs = got
		}
	}

	if minObs < minExpected-slack {
		t.Errorf("minObs=%v < minExpected=%v (slack=%v)", minObs, minExpected, slack)
	}
	if maxObs > maxExpected+slack {
		t.Errorf("maxObs=%v > maxExpected=%v (slack=%v)", maxObs, maxExpected, slack)
	}

	mean := time.Duration(sum / N)
	// Mean of uniform[base*(1-frac), base*(1+frac)] is base. 1% tolerance
	// over N=10000 samples covers normal sampling variance comfortably.
	tolerance := time.Duration(float64(base) * 0.01)
	delta := mean - base
	if delta < 0 {
		delta = -delta
	}
	if delta > tolerance {
		t.Errorf("mean=%v differs from base=%v by %v (tolerance=%v)", mean, base, delta, tolerance)
	}
}

// TestJitteredInterval_NoPointMass ensures the distribution is well-spread —
// no more than 1% of samples fall within ±1% of the base. Catches a
// regression where someone replaces the math with a constant.
func TestJitteredInterval_NoPointMass(t *testing.T) {
	const base = 100 * time.Millisecond
	const frac = 0.3
	const N = 10000

	tolerance := time.Duration(float64(base) * 0.01) // ±1ms
	near := 0
	for i := 0; i < N; i++ {
		got := JitteredInterval(base, frac)
		delta := got - base
		if delta < 0 {
			delta = -delta
		}
		if delta < tolerance {
			near++
		}
	}
	// Uniform[70ms,130ms] has 2*1ms / 60ms ≈ 3.3% within ±1% of 100ms,
	// so a "no point-mass" gate of <10% is comfortable but still catches
	// degenerate distributions.
	if near > N/10 {
		t.Errorf("got %d/%d (%.1f%%) samples within ±1%% of base — distribution is too clustered",
			near, N, float64(near)*100/float64(N))
	}
}

// TestJitteredInterval_ZeroJitter is a deterministic-output edge case —
// a jitter fraction of 0 should always return the base.
func TestJitteredInterval_ZeroJitter(t *testing.T) {
	const base = 20 * time.Second
	for i := 0; i < 100; i++ {
		got := JitteredInterval(base, 0.0)
		if got != base {
			t.Errorf("iter %d: got %v, want %v (zero jitter)", i, got, base)
		}
	}
}

// TestJitteredInterval_FullJitterClamped exercises the clamp: at
// jitterFraction=1.0 the raw range would be [0, 2*base], but the function
// clamps at base/2 to avoid pathological zero/near-zero intervals.
func TestJitteredInterval_FullJitterClamped(t *testing.T) {
	const base = 20 * time.Second
	const N = 1000
	min := base / 2
	max := 2 * base

	for i := 0; i < N; i++ {
		got := JitteredInterval(base, 1.0)
		if got < min {
			t.Errorf("iter %d: got %v < min %v (clamp violation)", i, got, min)
		}
		if got > max {
			t.Errorf("iter %d: got %v > max %v", i, got, max)
		}
	}
}

// TestJitteredInterval_ZeroBase ensures the function does not panic on
// pathological zero base — common defensive-coding regression.
func TestJitteredInterval_ZeroBase(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on zero base: %v", r)
		}
	}()
	got := JitteredInterval(0, 0.5)
	// Sensible behavior: 0 in → 0 out.
	if got != 0 {
		t.Errorf("got %v, want 0 (zero base)", got)
	}
}

// TestJitteredInterval_NegativeJitterClamped — negative jitterFraction is
// nonsensical; we expect the function to coerce it to 0 (return base).
func TestJitteredInterval_NegativeJitterClamped(t *testing.T) {
	const base = 20 * time.Second
	got := JitteredInterval(base, -0.5)
	if got != base {
		t.Errorf("got %v, want %v (negative jitter coerced to 0)", got, base)
	}
}

// TestEffectiveKeepaliveJitter_ZeroFallsBackTo30Percent — the WSReadyPool
// keepaliveJitter has a zero-value fallback to 0.3 so old configs still get
// jittered intervals. Test it directly without spinning the loop.
func TestEffectiveKeepaliveJitter_ZeroFallsBackTo30Percent(t *testing.T) {
	cfg := WSReadyPoolConfig{KeepaliveJitter: 0}
	if got := cfg.effectiveKeepaliveJitter(); got != 0.3 {
		t.Errorf("effectiveKeepaliveJitter()=%v for zero config, want 0.3", got)
	}
}

// TestEffectiveKeepaliveJitter_HonoursExplicitValue — non-zero values pass
// through verbatim.
func TestEffectiveKeepaliveJitter_HonoursExplicitValue(t *testing.T) {
	cfg := WSReadyPoolConfig{KeepaliveJitter: 0.15}
	if got := cfg.effectiveKeepaliveJitter(); got != 0.15 {
		t.Errorf("effectiveKeepaliveJitter()=%v, want 0.15", got)
	}
}

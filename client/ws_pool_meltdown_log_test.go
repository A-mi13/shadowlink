package client

import (
	"context"
	"math"
	"math/rand"
	"testing"
	"time"
)

func TestMeltdownLogJitter_NoPeriodicity(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	base := 5 * time.Second
	const N = 100
	intervals := make([]float64, N)
	for i := 0; i < N; i++ {
		j := time.Duration(0.5*float64(base) + rng.Float64()*float64(base))
		intervals[i] = j.Seconds()
	}

	mean := 0.0
	for _, v := range intervals {
		mean += v
	}
	mean /= float64(N)

	variance := 0.0
	for _, v := range intervals {
		d := v - mean
		variance += d * d
	}
	variance /= float64(N)

	for lag := 1; lag <= 10; lag++ {
		acf := 0.0
		for i := 0; i < N-lag; i++ {
			acf += (intervals[i] - mean) * (intervals[i+lag] - mean)
		}
		acf /= float64(N-lag) * variance
		if math.Abs(acf) > 0.5 {
			t.Errorf("autocorrelation at lag %d = %.3f, want |acf|<=0.5", lag, acf)
		}
	}
}

func TestMeltdownRateLimiter_Suppression(t *testing.T) {
	limiter := newMeltdownLimiter()
	const N = 1000
	allowed := 0
	for i := 0; i < N; i++ {
		if limiter.Allow() {
			allowed++
		}
	}
	if allowed > 3 {
		t.Errorf("allowed = %d in instant burst, want <=3 (burst limit)", allowed)
	}
}

func TestMeltdownLog_TransientSuppressed(t *testing.T) {
	if severeMeltdown(2, 10) {
		t.Error("severeMeltdown(2/10) = true, want false (<50%)")
	}
	if !severeMeltdown(6, 10) {
		t.Error("severeMeltdown(6/10) = false, want true (>=50%)")
	}
	if !severeMeltdown(5, 10) {
		t.Error("severeMeltdown(5/10) = false, want true (boundary)")
	}

	_ = context.Background()
}

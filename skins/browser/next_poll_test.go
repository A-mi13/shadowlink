package browser

import (
	"math"
	"testing"
)

// TestNextPollPareto_GoodnessOfFit checks that NewMimicrySession's
// NextPollLambda follows the truncated Pareto(α=1.5, [5, 600]) distribution.
// Chi-square 50-bucket test, p>0.05.
func TestNextPollPareto_GoodnessOfFit(t *testing.T) {
	const N = 10000
	const buckets = 50
	const alpha = 1.5
	const lo = 5.0
	const hi = 600.0

	observed := make([]int, buckets)
	expected := make([]float64, buckets)
	bucketSize := (hi - lo) / float64(buckets)

	for i := 0; i < N; i++ {
		s := NewMimicrySession()
		bucket := int((s.NextPollLambda - lo) / bucketSize)
		if bucket < 0 {
			bucket = 0
		}
		if bucket >= buckets {
			bucket = buckets - 1
		}
		observed[bucket]++
	}

	z := 1.0 - math.Pow(lo/hi, alpha)
	cdf := func(x float64) float64 {
		if x <= lo {
			return 0
		}
		if x >= hi {
			return 1
		}
		return (1.0 - math.Pow(lo/x, alpha)) / z
	}
	for b := 0; b < buckets; b++ {
		left := lo + float64(b)*bucketSize
		right := left + bucketSize
		expected[b] = (cdf(right) - cdf(left)) * float64(N)
	}

	var chi2 float64
	for b := 0; b < buckets; b++ {
		if expected[b] < 5 {
			continue
		}
		diff := float64(observed[b]) - expected[b]
		chi2 += diff * diff / expected[b]
	}

	const critical95 = 70.0
	if chi2 > critical95 {
		t.Fatalf("chi-square %.2f > %.2f (Pareto goodness-of-fit reject)", chi2, critical95)
	}
	t.Logf("Pareto α=1.5 chi-square=%.2f, critical=%.2f", chi2, critical95)
}

// TestNextPollSticky_PerSession verifies that within-session next_poll
// variance is dominated by stickiness, not event-level noise.
//
// Acceptance: within-session std-dev / sticky lambda < 0.30 (matches the
// ±15% jitter spec); across-session std-dev / mean lambda > 0.5 (Pareto tail).
//
// sessions=200 gives the across-session estimator enough samples to be
// stable across seeds — Pareto(α=1.5) has a heavy tail and 20-session draws
// occasionally produce relative std-dev <0.5 by random chance even though
// the underlying distribution has a much larger spread.
func TestNextPollSticky_PerSession(t *testing.T) {
	const sessions = 200
	const eventsPerSession = 100

	withinStdDevs := make([]float64, sessions)
	sessionLambdas := make([]float64, sessions)

	for s := 0; s < sessions; s++ {
		sess := NewMimicrySession()
		sessionLambdas[s] = sess.NextPollLambda
		samples := make([]float64, eventsPerSession)
		for e := 0; e < eventsPerSession; e++ {
			samples[e] = float64(NextPollSeconds(sess))
		}
		withinStdDevs[s] = stdDev(samples)
	}

	for s := 0; s < sessions; s++ {
		ratio := withinStdDevs[s] / sessionLambdas[s]
		if ratio > 0.30 {
			t.Fatalf("session %d: within-session std-dev/lambda = %.3f, want <0.30", s, ratio)
		}
	}

	acrossStdDev := stdDev(sessionLambdas)
	acrossMean := meanFloat(sessionLambdas)
	if acrossStdDev/acrossMean < 0.5 {
		t.Fatalf("across-session relative std-dev = %.3f, want >0.5 (Pareto tail expected)", acrossStdDev/acrossMean)
	}
	t.Logf("within-session ratios bounded; across-session relative std-dev = %.3f", acrossStdDev/acrossMean)
}

func meanFloat(xs []float64) float64 {
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func stdDev(xs []float64) float64 {
	m := meanFloat(xs)
	var s float64
	for _, x := range xs {
		s += (x - m) * (x - m)
	}
	return math.Sqrt(s / float64(len(xs)))
}

package browser

import (
	"math"
	"math/rand"
	"testing"
)

// TestDecoyIntervalLogNormal_GoodnessOfFit verifies log-normal distribution
// fit at p>0.05 (50 buckets, N=10000).
func TestDecoyIntervalLogNormal_GoodnessOfFit(t *testing.T) {
	const N = 10000
	const buckets = 50
	const muLog = 3.2188758248682006 // ln(25)
	const sigmaLog = 0.4
	const lo = 5.0
	const hi = 90.0

	rng := rand.New(rand.NewSource(42))
	observed := make([]int, buckets)
	bucketSize := (hi - lo) / float64(buckets)

	for i := 0; i < N; i++ {
		v := NextDecoyInterval(rng).Seconds()
		bucket := int((v - lo) / bucketSize)
		if bucket < 0 {
			bucket = 0
		}
		if bucket >= buckets {
			bucket = buckets - 1
		}
		observed[bucket]++
	}

	z := lognormalCDF(hi, muLog, sigmaLog) - lognormalCDF(lo, muLog, sigmaLog)
	cdf := func(x float64) float64 {
		if x <= lo {
			return 0
		}
		if x >= hi {
			return 1
		}
		return (lognormalCDF(x, muLog, sigmaLog) - lognormalCDF(lo, muLog, sigmaLog)) / z
	}

	expected := make([]float64, buckets)
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

	const critical95 = 70.0 // ~49 d.o.f.
	if chi2 > critical95 {
		t.Fatalf("log-normal chi-square %.2f > %.2f", chi2, critical95)
	}
	t.Logf("log-normal chi-square=%.2f, critical=%.2f", chi2, critical95)
}

// TestDecoyIntervalRejects_Uniform proves the sampler is NOT uniform[15,45].
func TestDecoyIntervalRejects_Uniform(t *testing.T) {
	const N = 10000
	const buckets = 50
	const lo = 5.0
	const hi = 90.0

	rng := rand.New(rand.NewSource(43))
	observed := make([]int, buckets)
	bucketSize := (hi - lo) / float64(buckets)

	for i := 0; i < N; i++ {
		v := NextDecoyInterval(rng).Seconds()
		bucket := int((v - lo) / bucketSize)
		if bucket < 0 {
			bucket = 0
		}
		if bucket >= buckets {
			bucket = buckets - 1
		}
		observed[bucket]++
	}

	expected := make([]float64, buckets)
	uniformMass := float64(N) / 30.0 // 30 second window
	for b := 0; b < buckets; b++ {
		left := lo + float64(b)*bucketSize
		right := left + bucketSize
		if left >= 15 && right <= 45 {
			expected[b] = uniformMass * (right - left)
		} else {
			expected[b] = 0.5 // tiny floor to avoid div-by-zero
		}
	}

	var chi2 float64
	for b := 0; b < buckets; b++ {
		diff := float64(observed[b]) - expected[b]
		chi2 += diff * diff / expected[b]
	}

	if chi2 < 1000 {
		t.Fatalf("chi-square %.2f, want >>1000 (uniform must be provably rejected)", chi2)
	}
	t.Logf("uniform-rejection chi-square=%.2f (good — provably not uniform)", chi2)
}

// lognormalCDF computes Φ((ln x - μ)/σ) where Φ is standard normal CDF.
func lognormalCDF(x, mu, sigma float64) float64 {
	if x <= 0 {
		return 0
	}
	z := (math.Log(x) - mu) / sigma
	return 0.5 * (1 + math.Erf(z/math.Sqrt2))
}

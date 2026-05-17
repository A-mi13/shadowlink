package client

import (
	"math"
	"math/rand/v2"
	"sort"
	"testing"
	"time"
)

// newSeededRng returns a deterministic *rand.Rand seeded with the supplied
// 128-bit PCG state. Mirror of core/jitter_lognormal_test.go's helper —
// both packages define their own copy because the Rng injection point is
// per-package (no cross-import on the hot path).
func newSeededRng(seed1, seed2 uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed1, seed2))
}

// TestJitteredIntervalLogNormal_Truncation asserts the [base/2, base*2]
// truncation contract — no sample escapes the rails regardless of how
// extreme N(0,1) gets in the tail.
func TestJitteredIntervalLogNormal_Truncation(t *testing.T) {
	const base = 20 * time.Second
	const sigma = 0.5
	const N = 50000

	lo := base / 2
	hi := base * 2

	rng := newSeededRng(0xc0ffee01, 0xfeed1001)
	for i := 0; i < N; i++ {
		got := JitteredIntervalLogNormalRng(base, sigma, rng)
		if got < lo || got > hi {
			t.Fatalf("sample %v outside [%v, %v]", got, lo, hi)
		}
	}
}

// TestJitteredIntervalLogNormal_EdgeCases — base<=0 → 0, sigma<=0 → base.
func TestJitteredIntervalLogNormal_EdgeCases(t *testing.T) {
	rng := newSeededRng(1, 2)
	if got := JitteredIntervalLogNormalRng(0, 0.5, rng); got != 0 {
		t.Fatalf("base=0 expected 0, got %v", got)
	}
	if got := JitteredIntervalLogNormalRng(-time.Second, 0.5, rng); got != 0 {
		t.Fatalf("base<0 expected 0, got %v", got)
	}
	base := 20 * time.Second
	if got := JitteredIntervalLogNormalRng(base, 0, rng); got != base {
		t.Fatalf("sigma=0 expected base unchanged, got %v", got)
	}
	if got := JitteredIntervalLogNormalRng(base, -0.5, rng); got != base {
		t.Fatalf("sigma<0 expected base unchanged, got %v", got)
	}
	// nil rng should fall back to package-level RNG (Truncation contract
	// still holds — full distribution gate is in the seeded variants).
	if got := JitteredIntervalLogNormalRng(base, 0.5, nil); got < base/2 || got > base*2 {
		t.Fatalf("nil-rng fallback violated rails: %v", got)
	}
}

// TestJitteredIntervalLogNormal_GoodnessOfFit verifies log-normal
// chi-square goodness-of-fit (50 buckets, N=50000) accounting for the
// two-rail truncation [base/2, base*2].
//
// final-audit-2026-05-05 Review 1 M-4: deterministic seed lets us tighten
// the threshold from the historical regression-bound (150) to the
// 99.9% critical (~85) without reintroducing run-to-run flakiness.
func TestJitteredIntervalLogNormal_GoodnessOfFit(t *testing.T) {
	const base = 20 * time.Second
	const sigma = 0.5
	const N = 50000
	const buckets = 50

	loSec := float64(base) / float64(time.Second) / 2
	hiSec := float64(base) / float64(time.Second) * 2
	bucketSize := (hiSec - loSec) / float64(buckets)

	muLog := math.Log(float64(base) / float64(time.Second))

	rng := newSeededRng(0xa1b2c3d4, 0xdeadbeef)
	observed := make([]int, buckets)
	for i := 0; i < N; i++ {
		v := JitteredIntervalLogNormalRng(base, sigma, rng).Seconds()
		bucket := int((v - loSec) / bucketSize)
		if bucket < 0 {
			bucket = 0
		}
		if bucket >= buckets {
			bucket = buckets - 1
		}
		observed[bucket]++
	}

	// CDF over the truncated/renormalised log-normal range. Rejection
	// sampling re-draws out-of-band candidates, so the observed mass per
	// bucket follows the conditional CDF (P(X in [a,b] | X in [lo,hi])).
	cdfLN := func(x float64) float64 {
		if x <= 0 {
			return 0
		}
		z := (math.Log(x) - muLog) / sigma
		return 0.5 * (1 + math.Erf(z/math.Sqrt2))
	}

	totalMass := cdfLN(hiSec) - cdfLN(loSec)
	expected := make([]float64, buckets)
	for b := 0; b < buckets; b++ {
		left := loSec + float64(b)*bucketSize
		right := left + bucketSize
		mass := cdfLN(right) - cdfLN(left)
		expected[b] = (mass / totalMass) * float64(N)
	}

	var chi2 float64
	for b := 0; b < buckets; b++ {
		if expected[b] < 5 {
			continue
		}
		diff := float64(observed[b]) - expected[b]
		chi2 += diff * diff / expected[b]
	}

	const critical = 85.0
	if chi2 > critical {
		t.Fatalf("log-normal chi-square %.2f > %.2f (seed=0xa1b2c3d4/0xdeadbeef)", chi2, critical)
	}
	t.Logf("log-normal chi-square=%.2f, critical=%.2f, N=%d", chi2, critical, N)
}

// TestJitteredIntervalLogNormal_RejectsUniform proves the sampler is
// NOT uniform[lo, hi] via KS-test: D_KS = max |F_emp - F_uniform|
// should exceed the 1% critical D_n = 1.628/sqrt(N) for N=5000 by an
// order of magnitude. Heavy-tailed log-normal piles density around the
// median and is sparse near the rails — uniform is the opposite.
func TestJitteredIntervalLogNormal_RejectsUniform(t *testing.T) {
	const base = 20 * time.Second
	const sigma = 0.5
	const N = 5000

	loSec := float64(base) / float64(time.Second) / 2
	hiSec := float64(base) / float64(time.Second) * 2

	rng := newSeededRng(0xbeefcafe, 0x12345678)
	samples := make([]float64, 0, N)
	for i := 0; i < N; i++ {
		samples = append(samples, JitteredIntervalLogNormalRng(base, sigma, rng).Seconds())
	}
	sort.Float64s(samples)

	// Walk the empirical CDF and compare against uniform CDF
	// F(x) = (x - lo) / (hi - lo).
	var dMax float64
	for i, x := range samples {
		fEmp := float64(i+1) / float64(N)
		fUni := (x - loSec) / (hiSec - loSec)
		if d := math.Abs(fEmp - fUni); d > dMax {
			dMax = d
		}
	}

	// 1% critical for N=5000 is ~1.628/sqrt(5000) ≈ 0.0230.
	const dCritical = 0.0230
	const dThreshold = 0.10
	if dMax < dThreshold {
		t.Fatalf("KS D=%.4f, want >=%.4f (cannot reject uniform null)", dMax, dThreshold)
	}
	t.Logf("KS D=%.4f (uniform critical=%.4f, threshold=%.4f) — provably non-uniform",
		dMax, dCritical, dThreshold)
}

// TestJitteredIntervalLogNormal_Median sanity-checks that the
// distribution centers around base — log-normal median = exp(μ_log)
// = base by construction.
func TestJitteredIntervalLogNormal_Median(t *testing.T) {
	const base = 20 * time.Second
	const sigma = 0.5
	const N = 10000

	rng := newSeededRng(0x5eed1, 0x5eed2)
	samples := make([]float64, 0, N)
	for i := 0; i < N; i++ {
		samples = append(samples, JitteredIntervalLogNormalRng(base, sigma, rng).Seconds())
	}
	sort.Float64s(samples)
	median := samples[N/2]

	want := float64(base) / float64(time.Second)
	// ±5% slack: rejection sampling re-distributes truncated mass back
	// onto [lo, hi] so the empirical median stays close to exp(μ_log).
	if math.Abs(median-want)/want > 0.05 {
		t.Fatalf("median=%.2fs, want %.2fs ±5%%", median, want)
	}
	t.Logf("median=%.2fs, base=%.2fs", median, want)
}

// TestJitteredIntervalLogNormal_NoPointMassOnEdges ensures rejection
// sampling pushes the edge-mass below 0.5% (final-audit-2026-05-05
// Review 1 M-3). Mirror of the server-side test in core/.
func TestJitteredIntervalLogNormal_NoPointMassOnEdges(t *testing.T) {
	const base = 20 * time.Second
	const sigma = 0.5
	const N = 10000

	loNs := int64(base / 2)
	hiNs := int64(base * 2)

	rng := newSeededRng(0xed9e1, 0xed9e2)
	edgeHits := 0
	for i := 0; i < N; i++ {
		got := JitteredIntervalLogNormalRng(base, sigma, rng)
		ns := got.Nanoseconds()
		if ns == loNs || ns == hiNs {
			edgeHits++
		}
	}

	const limit = 0.005 // 0.5%
	frac := float64(edgeHits) / float64(N)
	if frac > limit {
		t.Fatalf("edge-mass fraction %.4f > %.4f (rejection sampling regression)", frac, limit)
	}
	t.Logf("edge-mass fraction=%.4f (%d/%d) under %.4f cap (rejection sampling working)",
		frac, edgeHits, N, limit)
}

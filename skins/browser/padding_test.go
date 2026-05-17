package browser

import (
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestSamplePaddingTarget_Range verifies all samples fall within the
// documented [600, 3000] clamp window (may-audit C6 shift, 2026-05-02).
// A2-HIGH-7: any drift outside this range is a clamp regression that
// would re-enable size-based fingerprinting at the tails.
func TestSamplePaddingTarget_Range(t *testing.T) {
	const N = 100_000
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < N; i++ {
		v := SamplePaddingTarget(rng)
		if v < 600 || v > 3000 {
			t.Fatalf("sample %d out of range [600, 3000]: got %d", i, v)
		}
	}
}

// TestSamplePaddingTarget_RangeWithinClamp pins the absolute clamp band
// independently of the histogram-shape tests. Closes may-audit C6: the
// regression we're guarding is "constants drift into Mixpanel-mismatch zone".
func TestSamplePaddingTarget_RangeWithinClamp(t *testing.T) {
	const N = 50_000
	rng := rand.New(rand.NewSource(101))
	for i := 0; i < N; i++ {
		v := SamplePaddingTarget(rng)
		if v < 600 || v > 3000 {
			t.Fatalf("data padding sample %d outside Mixpanel-shape clamp [600, 3000]: got %d", i, v)
		}
	}
}

// TestSampleHandshakePaddingTarget_RangeWithinClamp pins the handshake clamp.
// Closes may-audit C6 alongside its sibling above.
func TestSampleHandshakePaddingTarget_RangeWithinClamp(t *testing.T) {
	const N = 50_000
	rng := rand.New(rand.NewSource(103))
	for i := 0; i < N; i++ {
		v := SampleHandshakePaddingTarget(rng)
		if v < 200 || v > 800 {
			t.Fatalf("handshake padding sample %d outside Mixpanel-shape clamp [200, 800]: got %d", i, v)
		}
	}
}

// TestPaddingDeferredCalibration_DocComment guards regression: the C6
// shift is a *placeholder* — Phase 5 / S5 Mixpanel schema lock will refit
// against captured fixtures. If a future refactor removes the deferral
// note from padding.go, S5 may silently treat the placeholders as final.
func TestPaddingDeferredCalibration_DocComment(t *testing.T) {
	src, err := os.ReadFile("padding.go")
	if err != nil {
		t.Skipf("cannot read padding.go: %v", err)
	}
	body := string(src)
	if !strings.Contains(body, "Phase 5") && !strings.Contains(body, "S5") {
		t.Errorf("padding.go missing deferred-calibration marker (expected 'Phase 5' or 'S5')")
	}
}

// TestSamplePaddingTarget_DeterministicWithSeed verifies that the same
// seed produces the same sequence — required so the chi-square fit test
// and any future regression tests stay reproducible.
func TestSamplePaddingTarget_DeterministicWithSeed(t *testing.T) {
	const N = 1024
	seqA := make([]int, N)
	seqB := make([]int, N)
	rngA := rand.New(rand.NewSource(42))
	rngB := rand.New(rand.NewSource(42))
	for i := 0; i < N; i++ {
		seqA[i] = SamplePaddingTarget(rngA)
		seqB[i] = SamplePaddingTarget(rngB)
	}
	for i := 0; i < N; i++ {
		if seqA[i] != seqB[i] {
			t.Fatalf("non-deterministic at i=%d: a=%d b=%d", i, seqA[i], seqB[i])
		}
	}
}

// TestSamplePaddingTarget_DistinctFromUniform verifies the sampler is NOT
// uniformly distributed over [600, 3000] — that's the whole point of the
// log-normal shape. Uses a Kolmogorov-Smirnov statistic against the
// uniform CDF; if KS < 0.05 the sampler has effectively the same shape
// as a uniform [600, 3000] generator and the side-channel benefit collapses.
//
// Bounds shifted by may-audit C6 (2026-05-02).
func TestSamplePaddingTarget_DistinctFromUniform(t *testing.T) {
	const N = 20_000
	rng := rand.New(rand.NewSource(7))
	samples := make([]float64, N)
	for i := 0; i < N; i++ {
		samples[i] = float64(SamplePaddingTarget(rng))
	}
	sort.Float64s(samples)

	// Uniform [600, 3000] CDF: F(x) = (x - 600) / (3000 - 600).
	const lo, hi = 600.0, 3000.0
	maxD := 0.0
	for i, x := range samples {
		empirical := float64(i+1) / float64(N)
		uniform := (x - lo) / (hi - lo)
		if uniform < 0 {
			uniform = 0
		}
		if uniform > 1 {
			uniform = 1
		}
		d := math.Abs(empirical - uniform)
		if d > maxD {
			maxD = d
		}
	}
	if maxD < 0.05 {
		t.Errorf("KS statistic vs uniform[600,3000] = %.4f, want >=0.05 (distribution too uniform)", maxD)
	}
}

// TestSamplePaddingTarget_LogNormalShape verifies the empirical histogram
// matches a log-normal-ish bulk/tail split: bulk mass [600, 1500) >= 40% and
// tail mass [2000, 3000] < 20%. These bounds protect against accidental
// re-tuning of μ/σ that would push the curve toward uniform or toward a
// long tail (which would re-introduce a size-fingerprint at the upper end).
//
// Bin boundaries shifted by may-audit C6 (2026-05-02) to track the new
// Mixpanel-shape range [600, 3000]. Mean ≈ 1023, p99 ≈ 2900.
func TestSamplePaddingTarget_LogNormalShape(t *testing.T) {
	const N = 50000
	rng := rand.New(rand.NewSource(42))
	bins := []int{600, 800, 1100, 1500, 2000, 3000}
	counts := make([]int, len(bins))
	for i := 0; i < N; i++ {
		v := SamplePaddingTarget(rng)
		for b := len(bins) - 1; b >= 0; b-- {
			if v >= bins[b] {
				counts[b]++
				break
			}
		}
	}
	// Bulk: [800, 1500) covers two bins around the mean — we expect this
	// to dominate (well above 40% of mass for a log-normal with σ=0.5).
	bulkMass := counts[1] + counts[2]
	if bulkMass < N*40/100 {
		t.Errorf("bulk mass [800, 1500) = %d (%.1f%%), want >=40%% of N=%d",
			bulkMass, 100*float64(bulkMass)/float64(N), N)
	}
	// Tail: [2000, 3000] should be modest — log-normal puts heavy mass
	// in the bulk, with a thinning right tail. <20% guards against drift
	// toward fat-tail OR toward upper-clamp-saturation regression.
	tailMass := counts[4]
	if tailMass > N*20/100 {
		t.Errorf("tail mass [2000, 3000] = %d (%.1f%%) of N=%d, want <20%%",
			tailMass, 100*float64(tailMass)/float64(N), N)
	}
}

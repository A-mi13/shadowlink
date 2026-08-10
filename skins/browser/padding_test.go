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
// regression we're guarding is "constants drift out of the plausible zone".
func TestSamplePaddingTarget_RangeWithinClamp(t *testing.T) {
	const N = 50_000
	rng := rand.New(rand.NewSource(101))
	for i := 0; i < N; i++ {
		v := SamplePaddingTarget(rng)
		if v < 600 || v > 3000 {
			t.Fatalf("data padding sample %d outside clamp [600, 3000]: got %d", i, v)
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
			t.Fatalf("handshake padding sample %d outside clamp [200, 800]: got %d", i, v)
		}
	}
}

// TestPaddingBands_NoVendorPersonaReference guards the 2026-08-08 closure.
//
// The predecessor of this test (TestPaddingDeferredCalibration_DocComment)
// required padding.go to keep a "Phase 5 / S5 schema lock" marker, so that a
// deferred refit against a captured analytics-vendor fixture would not be
// silently forgotten. That refit is now cancelled along with the third-party
// vendor persona (2026-04-28 pivot: TSPU does not parse encrypted bodies), so
// the marker would have pointed at work nobody intends to do.
//
// What replaces it is the inverse guard: the band rationale must NOT re-acquire
// a dependency on some specific vendor's wire format. Naming one invites a
// future "let's match their fixture exactly" refactor whose premise is false —
// the adversary never sees the plaintext body.
func TestPaddingBands_NoVendorPersonaReference(t *testing.T) {
	src, err := os.ReadFile("padding.go")
	if err != nil {
		t.Skipf("cannot read padding.go: %v", err)
	}
	body := strings.ToLower(string(src))
	for _, vendor := range []string{"mixpanel", "posthog", "segment", "amplitude", "ga4"} {
		if strings.Contains(body, vendor) {
			t.Errorf("padding.go references retired vendor persona %q — bands must stand on "+
				"their own rationale, not on resemblance to a specific SDK", vendor)
		}
	}
}

// TestPaddingBands_MedianSeparation pins what the two bands actually buy.
//
// NOT "the bands don't overlap" — they overlap heavily and always did. The
// clamps are [200,800] and [600,3000], so [600,800] is shared, and measured
// at N=200k that shared zone holds ~14% of handshake draws and ~41% of data
// draws. A test asserting separation would be asserting something false; an
// earlier draft of this test did exactly that while only re-checking the
// clamps its two sibling tests already cover.
//
// The real property is a *location shift*: the handshake distribution sits
// well below the data distribution, so a passive observer cannot use "this
// POST is N bytes" to reliably tag the first POST of a session. Overlap in
// the tails is fine — it is what stops the split from being a clean binary
// classifier. What must not happen is the two medians drifting together,
// which is the regression a careless μ refit would introduce.
func TestPaddingBands_MedianSeparation(t *testing.T) {
	const N = 50_000
	rngData := rand.New(rand.NewSource(211))
	rngHS := rand.New(rand.NewSource(212))
	dataSamples := make([]int, N)
	hsSamples := make([]int, N)
	for i := range N {
		dataSamples[i] = SamplePaddingTarget(rngData)
		hsSamples[i] = SampleHandshakePaddingTarget(rngHS)
	}
	sort.Ints(dataSamples)
	sort.Ints(hsSamples)

	medianOf := func(sorted []int) int { return sorted[len(sorted)/2] }
	dataMed, hsMed := medianOf(dataSamples), medianOf(hsSamples)

	// μ_log = ln(900) vs ln(350) ⇒ medians ≈ 899 and ≈ 350, a ratio of ~2.57.
	// Require at least 2× so a refit cannot quietly collapse the two bands
	// into one while keeping both clamps technically satisfied.
	if dataMed < 2*hsMed {
		t.Errorf("median separation collapsed: data=%d handshake=%d (ratio %.2f), want data >= 2x handshake",
			dataMed, hsMed, float64(dataMed)/float64(hsMed))
	}

	// Overlap is expected, but it must not become total: if nearly every
	// handshake draw landed in the data band the split would carry no
	// information at all. Measured ~14%; alarm well clear of that.
	inDataBand := 0
	for _, v := range hsSamples {
		if v >= 600 {
			inDataBand++
		}
	}
	if frac := float64(inDataBand) / float64(N); frac > 0.35 {
		t.Errorf("handshake draws landing in the data band = %.1f%%, want <=35%%", 100*frac)
	}
}

// TestPaddingBands_NoClampPileup guards the failure mode the C6 shift was
// meant to remove and which the clamp-range tests cannot see: mass piling up
// ON a clamp boundary.
//
// A clamp turns every out-of-range draw into the boundary value itself, so a
// badly centred μ produces a spike at exactly 600 (or exactly 3000) rather
// than a smooth tail. A spike at a single byte length is a stronger size
// signal than the wide distribution was — the clamp stops being a safety net
// and becomes the fingerprint.
//
// ⚠ MEASURED STATE, 2026-08-08 (N=200k, averaged over 5 seeds):
//
//	data      μ=ln(900) [600,3000]: 21.0% at 600, 0.8% at 3000
//	handshake μ=ln(350) [200,800] : 13.3% at 200, 4.9% at 800
//
// So one in five data paddings is *exactly* 600 bytes. That is a genuine
// point mass, not a rounding artefact, and it is the same class of signal
// the log-normal shape exists to avoid. It is recorded here rather than
// silently fixed: correcting it means moving μ, and timing/size constants in
// this project are not moved by eyeballing (CLAUDE.md hard rule 8) — the
// shift needs its own justification and a field check.
//
// Thresholds below are therefore set just above the measured values: they
// pin the status quo and fail on *drift*, they do not certify the current
// numbers as good. Sweep for reference, same method:
//
//	μ=ln(950) → 18.0% · μ=ln(1000) → 15.4% · μ=ln(1100) → 11.3%
//
// If a refit happens, tighten these bounds along with μ. Do not widen them.
func TestPaddingBands_NoClampPileup(t *testing.T) {
	const N = 50_000
	for _, tc := range []struct {
		name    string
		sample  func(*rand.Rand) int
		lo, hi  int
		seed    int64
		maxFrac float64
	}{
		{"data", SamplePaddingTarget, 600, 3000, 311, 0.25},
		{"handshake", SampleHandshakePaddingTarget, 200, 800, 313, 0.20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(tc.seed))
			atLo, atHi := 0, 0
			for range N {
				switch v := tc.sample(rng); v {
				case tc.lo:
					atLo++
				case tc.hi:
					atHi++
				}
			}
			for _, p := range []struct {
				edge string
				n    int
			}{{"lower", atLo}, {"upper", atHi}} {
				if frac := float64(p.n) / float64(N); frac > tc.maxFrac {
					t.Errorf("%s clamp pileup at %s edge: %.1f%% of draws, want <=%.0f%% — "+
						"re-centre mu instead of widening this bound",
						tc.name, p.edge, 100*frac, 100*tc.maxFrac)
				}
			}
		})
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
// band [600, 3000]. Mean ≈ 1023, p99 ≈ 2900.
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

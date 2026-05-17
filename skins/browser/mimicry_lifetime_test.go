package browser

import (
	"math"
	"sort"
	"testing"
)

// HIGH-3 (May 2026 audit follow-up): SessionLifecycle.NextActiveInterval()
// switched from uniform [120, 480]s to log-normal with median ≈ 300s and
// heavy right tail (μ_log = ln(300), σ_log = 1.5, truncated to [60, 86400]s).
//
// The goal is to make the per-session lifetime distribution match real browser
// SPA behavior: most sessions live a few minutes, but a non-trivial fraction
// stretch into hours — eliminating the uniform-histogram fingerprint a passive
// observer could use to cluster ConnManager rotation timing.
//
// All tests below sample from the package-global RNG (math/rand/v2). The four
// statistical tests use sample sizes large enough that sampling noise stays
// well below the assertion margins; on rare flake the failure message points
// at the offending statistic so a re-run can confirm it's noise vs regression.

const (
	expectedLifetimeMedian = 300.0             // exp(ln(300)) — target median in seconds.
	expectedLifetimeMuLog  = 5.703782474656201 // ln(300); literal so test fails if production constant drifts.
	expectedLifetimeSigma  = 1.5
	expectedLifetimeMinSec = 60
	expectedLifetimeMaxSec = 86400
)

// Test 1 — Lower truncation honored.
// Sample 10000 times. Assert min ≥ 60 and max ≤ 86400. Catches regressions
// where the truncation bounds are forgotten or miswritten.
func TestSessionLifecycleLogNormal_TruncationBounds(t *testing.T) {
	sl := NewSessionLifecycle()
	const N = 10000
	minSeen := math.MaxInt
	maxSeen := math.MinInt
	for range N {
		v := sl.NextActiveInterval()
		if v < minSeen {
			minSeen = v
		}
		if v > maxSeen {
			maxSeen = v
		}
	}
	if minSeen < expectedLifetimeMinSec {
		t.Errorf("min observed %d < lower bound %d", minSeen, expectedLifetimeMinSec)
	}
	if maxSeen > expectedLifetimeMaxSec {
		t.Errorf("max observed %d > upper bound %d", maxSeen, expectedLifetimeMaxSec)
	}
}

// Test 2 — Median approximately 300 seconds.
// 10000 samples, sorted; the 5000th element should be within 10% of 300.
// Slack accounts for sampling noise + truncation skew.
func TestSessionLifecycleLogNormal_MedianApprox300(t *testing.T) {
	sl := NewSessionLifecycle()
	const N = 10000
	xs := make([]int, 0, N)
	for range N {
		xs = append(xs, sl.NextActiveInterval())
	}
	sort.Ints(xs)
	median := float64(xs[N/2])
	rel := math.Abs(median-expectedLifetimeMedian) / expectedLifetimeMedian
	if rel > 0.10 {
		t.Errorf("median %.1f deviates from %.0f by %.2f%% (>10%% slack)",
			median, expectedLifetimeMedian, rel*100)
	}
}

// Test 3 — Heavy tail: p99 ≥ 3600 seconds (60 minutes).
// With N=50000 the 99th percentile sampling stddev is ~σ_log/√(N·p·(1-p))/PDF
// — small enough that the test is reliable without a fixed seed for the
// p99 ≥ 3600 bound (3600s is itself only ~p93 of the un-truncated log-normal).
func TestSessionLifecycleLogNormal_P99HeavyTail(t *testing.T) {
	sl := NewSessionLifecycle()
	const N = 50000
	xs := make([]int, 0, N)
	for range N {
		xs = append(xs, sl.NextActiveInterval())
	}
	sort.Ints(xs)
	p99 := xs[N*99/100]
	if p99 < 3600 {
		t.Errorf("p99 = %d < 3600s (need ≥60min for heavy-tail spec)", p99)
	}
}

// Test 4 — Heavier tail: p99.9 ≥ 21600 seconds (6 hours).
// Sampling variance at p99.9 with N=100000 is non-trivial; the un-truncated
// log-normal at our parameters has p99.9 ≈ 31000s, leaving ~30% headroom.
// Run with the package-global RNG (no fixed-seed API exposed); flakes here
// should be re-checked against the 21600s floor — they signal real distribution
// shift, not noise (the headroom is large).
func TestSessionLifecycleLogNormal_P999At6Hours(t *testing.T) {
	sl := NewSessionLifecycle()
	const N = 100000
	xs := make([]int, 0, N)
	for range N {
		xs = append(xs, sl.NextActiveInterval())
	}
	sort.Ints(xs)
	p999 := xs[N*999/1000]
	if p999 < 21600 {
		t.Errorf("p99.9 = %d < 21600s (need ≥6h for heavy-tail spec)", p999)
	}
}

// Test 5 — Distribution is NOT uniform.
// Bucket 50000 samples into 30 equal-width buckets across [60, 7200]s.
// Compute chi-square against a uniform null hypothesis. Assert χ² ≫ 50
// (decisively rejecting H0=uniform at p<0.001 for ~29 d.o.f., critical ≈ 58.3).
//
// Rationale for [60, 7200]: 99% of probability mass lies under 7200s
// (un-truncated p99 ≈ 9818s, but most of the visible-bucket mass is shorter).
// A uniform distribution would put ~equal counts per bucket; log-normal
// dumps everything around the median bucket, producing huge χ².
func TestSessionLifecycleLogNormal_RejectsUniformNull(t *testing.T) {
	sl := NewSessionLifecycle()
	const (
		N       = 50000
		buckets = 30
		lo      = 60.0
		hi      = 7200.0
	)
	width := (hi - lo) / float64(buckets)
	counts := make([]int, buckets)
	inRange := 0
	for range N {
		v := float64(sl.NextActiveInterval())
		if v < lo || v >= hi {
			continue
		}
		idx := int((v - lo) / width)
		if idx >= buckets {
			idx = buckets - 1
		}
		counts[idx]++
		inRange++
	}
	if inRange == 0 {
		t.Fatalf("no samples landed in [%v, %v) — check distribution params", lo, hi)
	}
	expected := float64(inRange) / float64(buckets)
	chi2 := 0.0
	for _, c := range counts {
		d := float64(c) - expected
		chi2 += d * d / expected
	}
	// Critical χ² for 29 d.o.f. at p=0.001 ≈ 58.3. Use 100 as a comfortably
	// strict floor — log-normal vs uniform produces χ² in the thousands.
	if chi2 < 100 {
		t.Errorf("chi-square = %.1f against uniform null — too small to reject H0=uniform; "+
			"distribution may have collapsed back toward uniform. Expected χ² in the hundreds or thousands.",
			chi2)
	}
}

// Test 6 — Log-normal goodness-of-fit on the un-truncated middle range.
//
// At μ=ln(300), σ=1.5 the lower truncation 60s sits at z=(ln(60)-μ)/σ ≈ -1.07,
// so analytically ~14% of samples land at the lower bound. Using all samples
// (with clamped values folded back to the bounds) would bias σ downward by
// ~75%; using only un-clamped samples biases σ downward by ~25% from the
// known one-sided truncation. Neither gives a clean goodness-of-fit signal.
//
// To validate the log-normal *shape* without truncation distortion, we take
// the log of every sample but restrict the moment estimate to a "wide middle"
// window [120s, 3600s] (z ∈ [-0.875, 1.851] — covers ~78% of probability
// mass). Within that window the distribution is essentially un-truncated
// log-normal, so empirical mean/stddev of log-values should match
// ln(300) / 1.5 closely. We use the standard formulas for the truncated-normal
// (in log space) moments and assert empirical agreement within 5%/15% slack.
//
// If a future change drops μ or σ, this test fails because mean/stddev of
// the *middle window* shifts — the test is sensitive to shape, not to the
// boundary mass that the truncation pin would otherwise dominate.
func TestSessionLifecycleLogNormal_Moments(t *testing.T) {
	sl := NewSessionLifecycle()
	const (
		N           = 50000
		windowLoSec = 120.0
		windowHiSec = 3600.0
	)
	windowLoLog := math.Log(windowLoSec)
	windowHiLog := math.Log(windowHiSec)

	logs := make([]float64, 0, N)
	for range N {
		v := sl.NextActiveInterval()
		l := math.Log(float64(v))
		if l < windowLoLog || l > windowHiLog {
			continue
		}
		logs = append(logs, l)
	}
	if len(logs) < N/3 {
		t.Fatalf("only %d / %d samples landed in the [%v, %v]s shape-validation window — "+
			"distribution may have collapsed (median or σ shifted dramatically)",
			len(logs), N, windowLoSec, windowHiSec)
	}

	var sum float64
	for _, l := range logs {
		sum += l
	}
	mean := sum / float64(len(logs))
	var sqSum float64
	for _, l := range logs {
		d := l - mean
		sqSum += d * d
	}
	stddev := math.Sqrt(sqSum / float64(len(logs)))

	// Theoretical truncated-normal moments on [windowLoLog, windowHiLog]
	// for parent N(μ, σ²). Using the standard truncated normal formulas:
	//   mean   = μ + σ · (φ(α) - φ(β)) / (Φ(β) - Φ(α))
	//   var    = σ² · (1 + (α·φ(α) - β·φ(β))/(Φ(β) - Φ(α))
	//                    - ((φ(α) - φ(β))/(Φ(β) - Φ(α)))²)
	// where α=(lo-μ)/σ, β=(hi-μ)/σ.
	mu := expectedLifetimeMuLog
	sigma := expectedLifetimeSigma
	alpha := (windowLoLog - mu) / sigma
	beta := (windowHiLog - mu) / sigma
	phi := func(x float64) float64 { return math.Exp(-x*x/2) / math.Sqrt(2*math.Pi) }
	cap := func(x float64) float64 { return 0.5 * (1 + math.Erf(x/math.Sqrt2)) }
	z := cap(beta) - cap(alpha)
	pdfDelta := phi(alpha) - phi(beta)
	expectedMean := mu + sigma*pdfDelta/z
	varTerm := 1 + (alpha*phi(alpha)-beta*phi(beta))/z - (pdfDelta/z)*(pdfDelta/z)
	expectedStddev := sigma * math.Sqrt(varTerm)

	relMean := math.Abs(mean-expectedMean) / expectedMean
	if relMean > 0.05 {
		t.Errorf("window log-mean %.4f deviates from theoretical %.4f by %.2f%% (>5%% slack); "+
			"μ likely shifted from ln(300)≈5.7038", mean, expectedMean, relMean*100)
	}
	relStddev := math.Abs(stddev-expectedStddev) / expectedStddev
	if relStddev > 0.15 {
		t.Errorf("window log-stddev %.4f deviates from theoretical %.4f by %.2f%% (>15%% slack); "+
			"σ_log likely shifted from 1.5", stddev, expectedStddev, relStddev*100)
	}
}

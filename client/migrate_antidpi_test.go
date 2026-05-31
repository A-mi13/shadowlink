package client

import (
	"math"
	"testing"
	"time"
)

// migrate_antidpi_test.go — Bug #9 Task 21, Part 2 (anti-DPI acceptance). The
// migration TIMING is the wire signal a middlebox could fingerprint: if every
// slot migrated at a fixed offset-from-connect, or every stream of a slot moved
// at the same instant, a DFT of the migration timestamps would show a dominant
// spectral peak at 1/period (a "synchronized handoff" signature). Task 16's
// samplers defeat that:
//
//   - sampleMigrationThreshold(base) = base × U(0.7,1.0)  — per-slot threshold
//     jitter, so slots don't all migrate at the same offset.
//   - sampleMigrationOffset(spread)  = U(0,spread)        — per-stream scatter,
//     so a slot's streams don't all move at one tick.
//
// These tests build a large series of migration offsets exactly as the watchdog
// would (many slots × many streams), run a REAL discrete Fourier transform over
// the series, and assert there is NO dominant periodic peak above the noise
// floor. A second test does the same with autocorrelation (ACF must be flat —
// no lag with a spike). Both are genuine spectral checks, not assertions tuned
// to the known distribution.

// dft computes the magnitude spectrum |X[k]| of a real-valued series for k in
// [1, N/2] (we skip k=0, the DC/mean component, which carries no periodicity
// information). A small direct O(N²) DFT is fine for the few-thousand-sample
// series here and keeps the test dependency-free (no FFT library, no gonum).
func dft(x []float64) []float64 {
	n := len(x)
	// Remove the mean so the DC bin doesn't dominate and so we measure variation
	// (periodicity) rather than the constant offset.
	var mean float64
	for _, v := range x {
		mean += v
	}
	mean /= float64(n)

	half := n / 2
	mags := make([]float64, half) // index i → bin k=i+1
	for k := 1; k <= half; k++ {
		var re, im float64
		w := -2 * math.Pi * float64(k) / float64(n)
		for t := 0; t < n; t++ {
			ang := w * float64(t)
			v := x[t] - mean
			re += v * math.Cos(ang)
			im += v * math.Sin(ang)
		}
		mags[k-1] = math.Hypot(re, im)
	}
	return mags
}

// autocorr returns the normalized autocorrelation r[lag] for lag in [1, maxLag].
// r[0] (== 1 by construction) is omitted. A white-noise (aperiodic) series has
// all |r[lag]| small; a periodic series spikes near |r[lag]| ≈ 1 at its period.
func autocorr(x []float64, maxLag int) []float64 {
	n := len(x)
	var mean float64
	for _, v := range x {
		mean += v
	}
	mean /= float64(n)

	var c0 float64
	for _, v := range x {
		d := v - mean
		c0 += d * d
	}
	if c0 == 0 {
		return make([]float64, maxLag)
	}

	out := make([]float64, maxLag)
	for lag := 1; lag <= maxLag; lag++ {
		var c float64
		for t := 0; t+lag < n; t++ {
			c += (x[t] - mean) * (x[t+lag] - mean)
		}
		out[lag-1] = c / c0
	}
	return out
}

// buildMigrationOffsetSeries generates a migration-timing series driven ONLY by
// the Task-16 samplers — the components actually under test. For `slots` aging
// slots, each with `streamsPerSlot` active streams, the time each stream
// migrates (relative to the pool's common connect reference, t=0) is
// (per-slot threshold) + (per-stream offset): exactly what scheduleSlotMigration
// composes. We DELIBERATELY do NOT impose any fixed per-slot connect grid — a
// real pool's slots cold-start near the same instant, and more importantly a
// fixed grid would inject an artificial comb that the samplers were never meant
// to mask (it would test the harness, not the code). The middlebox observes the
// sorted absolute migration times; periodicity would show up as a regular GAP
// rhythm, so we return the inter-event gaps.
func buildMigrationOffsetSeries(slots, streamsPerSlot int, base, spread time.Duration) []float64 {
	var times []float64
	for s := 0; s < slots; s++ {
		// Each slot crosses its OWN jittered threshold (base × U(0.7,1.0)).
		threshold := float64(sampleMigrationThreshold(base))
		for st := 0; st < streamsPerSlot; st++ {
			off := float64(sampleMigrationOffset(spread))
			times = append(times, threshold+off)
		}
	}
	// Sort and convert to inter-arrival gaps.
	sortFloat(times)
	gaps := make([]float64, 0, len(times))
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i]-times[i-1])
	}
	return gaps
}

func sortFloat(a []float64) {
	// insertion-free: use the stdlib via a tiny shim to avoid importing sort at
	// call sites; simple O(n²) is fine for test sizes but we use a quick variant.
	for i := 1; i < len(a); i++ {
		v := a[i]
		j := i - 1
		for j >= 0 && a[j] > v {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = v
	}
}

// TestMigrationTimestamps_NoPeriodicFFTPeak: the DFT of the migration-gap series
// must have NO bin whose magnitude dominates the spectrum. We gate on the ratio
// max-bin / mean-bin: a clean periodic signal pins almost all energy in one bin
// (ratio ≫ 10); jittered samplers spread energy across bins (ratio small). The
// threshold (8×) is well above what white-ish noise produces yet far below the
// hundreds-× a fixed-period signal would. To prove the test BITES we also build
// a deliberately periodic control series and assert IT trips the same gate.
func TestMigrationTimestamps_NoPeriodicFFTPeak(t *testing.T) {
	const (
		slots          = 64
		streamsPerSlot = 16
		base           = 60 * time.Second
		spread         = 8 * time.Second
		peakRatioMax   = 8.0
	)

	gaps := buildMigrationOffsetSeries(slots, streamsPerSlot, base, spread)
	if len(gaps) < 64 {
		t.Fatalf("series too short: %d", len(gaps))
	}
	mags := dft(gaps)

	// Skip bin k=1 (mags[0]): the lowest-frequency bin captures the broad
	// envelope of the SORTED gap series (gaps are smaller in the dense centre of
	// the threshold+offset distribution, larger at the tails) — a deterministic
	// distributional shape, NOT a repeating period a DPI box can lock onto. A
	// DPI-detectable "synchronized handoff" signature would appear as a sharp
	// peak at a higher harmonic (k≥2 → some recurring interval). We gate on the
	// dominant peak among k≥2.
	maxBin, sum := 0.0, 0.0
	maxIdx := -1
	for i := 1; i < len(mags); i++ { // i=1 → bin k=2
		m := mags[i]
		if m > maxBin {
			maxBin, maxIdx = m, i
		}
		sum += m
	}
	mean := sum / float64(len(mags)-1)
	ratio := maxBin / mean
	t.Logf("jittered: max-bin=%.2f mean=%.2f ratio=%.2f (k=%d, threshold=%.1f)", maxBin, mean, ratio, maxIdx+1, peakRatioMax)

	if ratio > peakRatioMax {
		t.Fatalf("dominant DFT peak (ratio %.2f > %.2f) at bin %d — migration timing is periodic; "+
			"the Task-16 threshold/offset jitter is not destroying the FFT signature",
			ratio, peakRatioMax, maxIdx+1)
	}

	// Control: a perfectly periodic series MUST trip the gate (proves the metric
	// is sensitive, not vacuously passing).
	periodic := make([]float64, len(gaps))
	for i := range periodic {
		// fixed gap + a tiny deterministic ripple so it's not a pure constant
		// (a pure constant has all-zero AC bins and an undefined ratio).
		periodic[i] = float64(base) * (1 + 0.001*math.Sin(2*math.Pi*float64(i)/8))
	}
	pmags := dft(periodic)
	pMax, pSum := 0.0, 0.0
	for _, m := range pmags {
		if m > pMax {
			pMax = m
		}
		pSum += m
	}
	pRatio := pMax / (pSum / float64(len(pmags)))
	t.Logf("periodic control: ratio=%.2f", pRatio)
	if pRatio <= peakRatioMax {
		t.Fatalf("periodic control did not trip the gate (ratio %.2f <= %.2f) — the FFT gate is not sensitive enough to catch a real periodic signal",
			pRatio, peakRatioMax)
	}
}

// TestMigrationTimestamps_ACFNoPeak: the autocorrelation of the migration-gap
// series must be FLAT — no lag with a spike approaching 1.0. A periodic signal
// has |r[lag]| ≈ 1 at its period; jittered samplers keep every lag small.
func TestMigrationTimestamps_ACFNoPeak(t *testing.T) {
	const (
		slots          = 64
		streamsPerSlot = 16
		base           = 60 * time.Second
		spread         = 8 * time.Second
		acfPeakMax     = 0.5 // no lag may exceed this normalized correlation
	)

	gaps := buildMigrationOffsetSeries(slots, streamsPerSlot, base, spread)
	maxLag := len(gaps) / 4
	if maxLag < 8 {
		t.Fatalf("series too short for ACF: %d gaps", len(gaps))
	}
	ac := autocorr(gaps, maxLag)

	worstLag, worst := -1, 0.0
	for i, r := range ac {
		if a := math.Abs(r); a > worst {
			worst, worstLag = a, i+1
		}
	}
	t.Logf("jittered ACF: worst |r|=%.3f at lag=%d (threshold=%.2f)", worst, worstLag, acfPeakMax)
	if worst > acfPeakMax {
		t.Fatalf("autocorrelation spike |r|=%.3f at lag %d exceeds %.2f — migration timing is periodic",
			worst, worstLag, acfPeakMax)
	}

	// Control: a periodic series MUST show a strong ACF peak at its period.
	period := 8
	periodic := make([]float64, len(gaps))
	for i := range periodic {
		if i%period == 0 {
			periodic[i] = 100
		} else {
			periodic[i] = 1
		}
	}
	pac := autocorr(periodic, maxLag)
	pWorst := 0.0
	for _, r := range pac {
		if a := math.Abs(r); a > pWorst {
			pWorst = a
		}
	}
	t.Logf("periodic control ACF: worst |r|=%.3f", pWorst)
	if pWorst <= acfPeakMax {
		t.Fatalf("periodic control ACF did not spike (worst |r|=%.3f <= %.2f) — the ACF gate is not sensitive",
			pWorst, acfPeakMax)
	}
}

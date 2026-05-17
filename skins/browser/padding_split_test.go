package browser

import (
	"math"
	"math/rand"
	"sort"
	"testing"

	"github.com/nixavpn/shadowlink/core"
)

// TestPaddingDistributionDiverges verifies that handshake and data padding
// samplers produce statistically distinct distributions. Closes A2-HIGH-5.
//
// Method: Two-sample Kolmogorov-Smirnov test. KS statistic D = max |F_h - F_d|
// across the empirical CDFs. For N1=N2=5000, the 99% critical value is
// 1.628*sqrt((N1+N2)/(N1*N2)) ≈ 0.0326. A divergent split MUST produce
// D > 0.0326 (i.e. reject H0 same-distribution with p<0.01).
func TestPaddingDistributionDiverges(t *testing.T) {
	const N = 5000
	rng := rand.New(rand.NewSource(42))

	handshake := make([]float64, N)
	data := make([]float64, N)
	for i := 0; i < N; i++ {
		handshake[i] = float64(SampleHandshakePaddingTarget(rng))
		data[i] = float64(SamplePaddingTarget(rng))
	}

	d := ksStatistic(handshake, data)
	const ksCritical99 = 0.0326 // 1.628 * sqrt(2/N) for N1=N2=5000
	if d <= ksCritical99 {
		t.Fatalf("KS statistic D=%.4f, want >%.4f (reject H0 same-distribution at p<0.01)", d, ksCritical99)
	}
	t.Logf("KS D=%.4f (handshake vs data padding) — distributions provably diverge", d)
}

// ksStatistic computes the two-sample KS statistic between sorted copies of x and y.
func ksStatistic(x, y []float64) float64 {
	xs := append([]float64(nil), x...)
	ys := append([]float64(nil), y...)
	sort.Float64s(xs)
	sort.Float64s(ys)

	i, j := 0, 0
	var maxDiff float64
	nx, ny := float64(len(xs)), float64(len(ys))
	for i < len(xs) && j < len(ys) {
		fx := float64(i+1) / nx
		fy := float64(j+1) / ny
		var diff float64
		if xs[i] < ys[j] {
			diff = math.Abs(fx - fy + 1.0/ny)
			i++
		} else if xs[i] > ys[j] {
			diff = math.Abs(fx + 1.0/nx - fy)
			j++
		} else {
			i++
			j++
			diff = math.Abs(fx - fy)
		}
		if diff > maxDiff {
			maxDiff = diff
		}
	}
	return maxDiff
}

// TestBuildHandshakePayload_UsesHandshakeSampler is an integration-level guard
// that BuildHandshakePayload's emitted total length matches the
// SampleHandshakePaddingTarget distribution (not the data-padding distribution).
//
// The function is observed N=2000 times; we check that the emitted total
// length never exceeds the handshake sampler's cap.
func TestBuildHandshakePayload_UsesHandshakeSampler(t *testing.T) {
	const N = 2000
	const ephPubLen = 32
	encClientIDLen := core.EncryptedClientIDSize

	ephPub := make([]byte, ephPubLen)
	encClientID := make([]byte, encClientIDLen)

	for i := 0; i < N; i++ {
		out := BuildHandshakePayload(ephPub, encClientID, nil)
		// Total length = ephPub + encClientID + padding ∈ [200, 800] (after C6 shift).
		// Cap: ephPub(32) + encClientID + 800.
		maxLen := ephPubLen + encClientIDLen + 800
		if len(out) > maxLen {
			t.Fatalf("sample %d: total len %d exceeds handshake sampler cap %d",
				i, len(out), maxLen)
		}
		// Floor: at minimum ephPub + encClientID (when target <= len(base)).
		minLen := ephPubLen + encClientIDLen
		if len(out) < minLen {
			t.Fatalf("sample %d: total len %d below floor %d", i, len(out), minLen)
		}
	}
}

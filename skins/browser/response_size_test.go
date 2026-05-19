package browser

import (
	"encoding/json"
	"math/rand"
	"testing"
)

// TestSampleResponseSize_Range checks all outputs are within [256, 32768].
func TestSampleResponseSize_Range(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 50000; i++ {
		v := SampleResponseSize(rng)
		if v < 256 || v > 32768 {
			t.Fatalf("sample %d: got %d, want [256, 32768]", i, v)
		}
	}
}

// TestSampleResponseSize_HasFatTail verifies the Pareto tail produces a
// non-trivial fraction above 8KB. With 5% Pareto-call probability and
// scale=2048, α=2, the analytic mass above 8KB is 0.05 × (2048/8192)² ≈ 0.003.
// Gaussian core (μ=2048, σ=800) contributes effectively zero at 8KB (Z=7.68).
// Threshold ≥0.0025 still provably rejects the "no fat tail" null (without
// Pareto, fraction would be ~0). Upper bound 0.10 catches the inverse failure
// (Pareto dominates core).
func TestSampleResponseSize_HasFatTail(t *testing.T) {
	rng := rand.New(rand.NewSource(43))
	const N = 50000
	var fat int
	for i := 0; i < N; i++ {
		if SampleResponseSize(rng) > 8192 {
			fat++
		}
	}
	frac := float64(fat) / float64(N)
	if frac < 0.0025 {
		t.Fatalf("fat tail fraction %.4f, want >=0.0025 (Pareto tail effectively absent)", frac)
	}
	if frac > 0.10 {
		t.Fatalf("fat tail fraction %.4f, want <0.10 (otherwise tail dominates core)", frac)
	}
	t.Logf("fat-tail fraction (>8KB) = %.4f", frac)
}

// TestSampleResponseSize_DominatesGaussianCore verifies bulk of mass is in
// the Gaussian core (μ=2048, σ=800).
func TestSampleResponseSize_DominatesGaussianCore(t *testing.T) {
	rng := rand.New(rand.NewSource(44))
	const N = 50000
	var inCore int
	for i := 0; i < N; i++ {
		v := SampleResponseSize(rng)
		if v >= 1248 && v <= 2848 { // μ±σ
			inCore++
		}
	}
	frac := float64(inCore) / float64(N)
	if frac < 0.55 {
		t.Fatalf("core fraction %.3f, want >0.55", frac)
	}
	t.Logf("Gaussian core fraction (μ±σ) = %.3f", frac)
}

// TestBuildInflatedDownloadResponse_VariesSize verifies that SampleResponseSize
// is wired into BuildInflatedDownloadResponse — i.e. response bodies show
// meaningful size variance rather than a fixed size (Wave 1.1 wire-up).
func TestBuildInflatedDownloadResponse_VariesSize(t *testing.T) {
	enc := []byte("encrypted-payload-mock-fixed-length-padding-test")
	sizes := make(map[int]int)
	for i := 0; i < 100; i++ {
		body, err := BuildInflatedDownloadResponse(enc, uint32(i), nil)
		if err != nil {
			t.Fatalf("BuildInflatedDownloadResponse iteration %d: %v", i, err)
		}
		// Sanity: must still be valid JSON.
		var envelope map[string]any
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatalf("response is not valid JSON at iteration %d: %v", i, err)
		}
		sizes[len(body)]++
	}
	t.Logf("distinct response sizes over 100 calls: %d", len(sizes))
	if len(sizes) < 5 {
		t.Errorf("expected >=5 distinct response sizes (SampleResponseSize wired), got %d", len(sizes))
	}
}

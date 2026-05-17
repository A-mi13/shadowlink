package core

import (
	"sort"
	"testing"
)

// TestNextReadSizeBounds verifies every sample is within [Min, Max].
// Regression guard for V4 fix — going below Min tanks throughput, going above
// Max overflows the server body limit.
func TestNextReadSizeBounds(t *testing.T) {
	for range 10000 {
		s := NextReadSize()
		if s < ChunkSizingMin {
			t.Fatalf("size %d below min %d", s, ChunkSizingMin)
		}
		if s > ChunkSizingMax {
			t.Fatalf("size %d above max %d", s, ChunkSizingMax)
		}
	}
}

// TestNextReadSizeDistribution checks the output spreads across the range
// instead of clustering on a single value — the whole point of V4 is to
// avoid a deterministic chunk size. We require at least 8 distinct buckets
// of 1 KB width get hit out of the 12 possible, and that no single bucket
// swallows more than 70% of samples.
func TestNextReadSizeDistribution(t *testing.T) {
	const samples = 5000
	buckets := make(map[int]int)
	sizes := make([]int, 0, samples)
	for range samples {
		s := NextReadSize()
		buckets[s/1024]++
		sizes = append(sizes, s)
	}

	if len(buckets) < 8 {
		t.Fatalf("expected >=8 distinct 1KB buckets, got %d", len(buckets))
	}
	for b, c := range buckets {
		if pct := float64(c) / float64(samples); pct > 0.70 {
			t.Fatalf("bucket %d KB holds %.1f%% of samples — distribution collapsed", b, pct*100)
		}
	}

	// Median should be well below Max to confirm the heavy-tailed shape
	// (not uniform, not pegged high).
	sort.Ints(sizes)
	median := sizes[len(sizes)/2]
	if median > ChunkSizingMax/2 {
		t.Fatalf("median %d too high — distribution not skewed toward small sizes", median)
	}
}

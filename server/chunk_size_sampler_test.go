package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSampleChunkSize_FromSet pins the basic contract: for the production
// default config chunk_size (12288), every sample MUST be one of the four
// values in chunkSizeSampleSet. A regression that introduced a different
// distribution (e.g. continuous range) would silently change the wire
// shape for every client.
func TestSampleChunkSize_FromSet(t *testing.T) {
	allowed := map[uint16]struct{}{
		6144:  {},
		8192:  {},
		10240: {},
		12288: {},
	}
	const trials = 1000
	for i := 0; i < trials; i++ {
		got := sampleChunkSize(12288)
		_, ok := allowed[got]
		require.True(t, ok, "trial %d: sample %d not in allowed set", i, got)
	}
}

// TestSampleChunkSize_DistributionUniform asserts the wire-shape goal:
// across many sessions, ALL four candidate sizes are observed roughly
// equally. A regression that collapsed the sampler to a constant or
// heavily biased one value would silently regress the bimodal-defeat
// effect we're paying server-side latency for.
//
// 1000 trials, expected 250 per bucket, accept ±60 (24% slack). Bucket
// chi-square at this tolerance is ~10^-6 false-alarm — not flaky.
func TestSampleChunkSize_DistributionUniform(t *testing.T) {
	counts := map[uint16]int{}
	const trials = 1000
	for i := 0; i < trials; i++ {
		counts[sampleChunkSize(12288)]++
	}
	for _, v := range chunkSizeSampleSet {
		require.GreaterOrEqual(t, counts[v], 190,
			"value %d: only %d samples — distribution skew, %d expected", v, counts[v], trials/4)
		require.LessOrEqual(t, counts[v], 310,
			"value %d: %d samples — distribution skew, %d expected", v, counts[v], trials/4)
	}
}

// TestSampleChunkSize_RespectsCap is the operator-control invariant.
// If an admin runs `shadowlink-server -chunk-size 9000`, the sampler
// MUST NOT emit 10240 or 12288 — that would silently let WS frames
// exceed the operator's intended cap and could blow nginx buffer
// limits or break custom deployments.
//
// Acceptance: with cap=9000, only 6144 and 8192 are valid.
func TestSampleChunkSize_RespectsCap(t *testing.T) {
	allowed := map[uint16]struct{}{6144: {}, 8192: {}}
	const trials = 500
	for i := 0; i < trials; i++ {
		got := sampleChunkSize(9000)
		_, ok := allowed[got]
		require.True(t, ok, "trial %d: cap=9000 returned %d (must be ≤ cap)", i, got)
	}
}

// TestSampleChunkSize_CapBelowSmallest — degenerate but defensible case:
// operator caps below 6144 (e.g. -chunk-size 4096 for some custom
// constraint). Returning the cap value verbatim is the only sensible
// behavior — anything else would silently emit values above the cap.
func TestSampleChunkSize_CapBelowSmallest(t *testing.T) {
	got := sampleChunkSize(4096)
	require.Equal(t, uint16(4096), got,
		"cap below smallest sample value must return cap verbatim, got %d", got)
}

// TestSampleChunkSize_ZeroConfig — defensive contract for zero config.
// Returning 0 here is the only safe behavior: 0 means "feature disabled
// / no config" and the upstream serializer should treat it as no-op.
func TestSampleChunkSize_ZeroConfig(t *testing.T) {
	got := sampleChunkSize(0)
	require.Zero(t, got, "zero config must return zero (disabled), got %d", got)
}

// TestSampleChunkSize_NegativeConfig — defensive contract for the
// pathological case where config is somehow negative (shouldn't happen
// via flag parsing but defends against direct invocation in tests or
// future programmatic config injection). Same as zero — fail safe.
func TestSampleChunkSize_NegativeConfig(t *testing.T) {
	require.Zero(t, sampleChunkSize(-1), "negative config must return zero")
	require.Zero(t, sampleChunkSize(-12288), "negative config must return zero")
}

// TestChunkSizeSampleSet_AscendingOrder pins the implementation invariant
// that the sample set is in ascending order. sampleChunkSize's cap-honoring
// loop assumes this — if the set were sorted differently, the loop would
// return the WRONG max-allowed index for a given cap and the cap could
// be violated.
//
// Catches regressions where someone reorders the set "for readability"
// without realizing the loop depends on the ordering.
func TestChunkSizeSampleSet_AscendingOrder(t *testing.T) {
	for i := 1; i < len(chunkSizeSampleSet); i++ {
		require.Greater(t, chunkSizeSampleSet[i], chunkSizeSampleSet[i-1],
			"chunkSizeSampleSet must be strictly ascending; %d at idx %d not > %d at idx %d",
			chunkSizeSampleSet[i], i, chunkSizeSampleSet[i-1], i-1)
	}
}

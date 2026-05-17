package browser

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPayloadDistributionUpload(t *testing.T) {
	pd := NewPayloadDistribution()
	const N = 10000
	buckets := map[string]int{
		"80-150":   0,
		"151-350":  0,
		"351-800":  0,
		"801-2000": 0,
	}

	for range N {
		size := pd.UploadSize()
		assert.GreaterOrEqual(t, size, 80)
		assert.LessOrEqual(t, size, 2000)

		switch {
		case size >= 80 && size <= 150:
			buckets["80-150"]++
		case size >= 151 && size <= 350:
			buckets["151-350"]++
		case size >= 351 && size <= 800:
			buckets["351-800"]++
		case size >= 801 && size <= 2000:
			buckets["801-2000"]++
		}
	}

	// Verify distribution ±10%
	assert.InDelta(t, 0.45, float64(buckets["80-150"])/N, 0.10, "80-150 bucket should be ~45%%")
	assert.InDelta(t, 0.35, float64(buckets["151-350"])/N, 0.10, "151-350 bucket should be ~35%%")
	assert.InDelta(t, 0.15, float64(buckets["351-800"])/N, 0.10, "351-800 bucket should be ~15%%")
	assert.InDelta(t, 0.05, float64(buckets["801-2000"])/N, 0.10, "801-2000 bucket should be ~5%%")
}

func TestPayloadDistributionDownload(t *testing.T) {
	pd := NewPayloadDistribution()
	const N = 10000
	buckets := map[string]int{
		"50-100":    0,
		"201-600":   0,
		"601-2000":  0,
		"2001-8000": 0,
	}

	for range N {
		size := pd.DownloadSize()
		assert.GreaterOrEqual(t, size, 50)
		assert.LessOrEqual(t, size, 8000)

		switch {
		case size >= 50 && size <= 100:
			buckets["50-100"]++
		case size >= 201 && size <= 600:
			buckets["201-600"]++
		case size >= 601 && size <= 2000:
			buckets["601-2000"]++
		case size >= 2001 && size <= 8000:
			buckets["2001-8000"]++
		}
	}

	assert.InDelta(t, 0.40, float64(buckets["50-100"])/N, 0.10, "50-100 bucket should be ~40%%")
	assert.InDelta(t, 0.35, float64(buckets["201-600"])/N, 0.10, "201-600 bucket should be ~35%%")
	assert.InDelta(t, 0.20, float64(buckets["601-2000"])/N, 0.10, "601-2000 bucket should be ~20%%")
	assert.InDelta(t, 0.05, float64(buckets["2001-8000"])/N, 0.10, "2001-8000 bucket should be ~5%%")
}

func TestRatioControllerNoCoverNeeded(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	// Simulate ratio 3:1 (within target range)
	rc.RecordDownload(1000)
	rc.RecordUpload(3000)

	budget := rc.CoverBudget()
	assert.Equal(t, 0, budget, "ratio 3:1 is within [2.5, 3.5], no cover needed")
}

func TestRatioControllerNeedsCover(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	// Simulate ratio 0.5:1 — way below target
	rc.RecordDownload(1000)
	rc.RecordUpload(500)

	budget := rc.CoverBudget()
	assert.Greater(t, budget, 0, "ratio 0.5:1 is below target, cover needed")
	// Need to reach at least 2.5:1 → need 2500 upload, have 500 → need ~2000
	// But capped at maxCoverBudget (65536), so should be ~2000
	assert.InDelta(t, 2000, budget, 100, "should need ~2000 bytes to reach target low")
}

func TestRatioControllerZeroDownload(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	rc.RecordUpload(1000)
	// No download recorded

	budget := rc.CoverBudget()
	assert.Equal(t, 0, budget, "zero download should return 0 (guard clause)")
}

func TestRatioControllerCap(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	// 1MB download with no upload → needs 2.5MB upload cover
	// But capped at maxCoverBudget (65536)
	rc.RecordDownload(1_000_000)
	rc.RecordUpload(0)

	budget := rc.CoverBudget()
	assert.Equal(t, maxCoverBudget, budget, "budget should be capped at maxCoverBudget")
}

func TestRatioControllerReset(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	rc.RecordUpload(5000)
	rc.RecordDownload(2000)
	rc.Reset()

	// After reset, both counters should be 0
	budget := rc.CoverBudget()
	assert.Equal(t, 0, budget, "after reset, download is 0 → budget 0")
}

func TestChunkPayload(t *testing.T) {
	pd := NewPayloadDistribution()

	// 1300 bytes — should split into multiple chunks
	data := make([]byte, 1300)
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunks := pd.ChunkForUpload(data)
	require.Greater(t, len(chunks), 1, "1300B should split into >1 chunks")

	// Reassembly must match original
	var reassembled []byte
	for _, chunk := range chunks {
		reassembled = append(reassembled, chunk...)
	}
	assert.Equal(t, data, reassembled, "reassembled chunks must match original data")
}

func TestChunkPayloadSmall(t *testing.T) {
	pd := NewPayloadDistribution()

	// Small payload that fits in a single chunk
	data := []byte("hello")
	chunks := pd.ChunkForUpload(data)
	require.Len(t, chunks, 1)
	assert.Equal(t, data, chunks[0])
}

func TestChunkPayloadEmpty(t *testing.T) {
	pd := NewPayloadDistribution()
	chunks := pd.ChunkForUpload(nil)
	assert.Empty(t, chunks)
}

func TestPadToSize(t *testing.T) {
	data := []byte("hello")
	padded := PadToSize(data, 100)
	assert.Len(t, padded, 100)
	// First 5 bytes must be original data
	assert.Equal(t, data, padded[:5])
}

func TestPadToSizeNoOpWhenBigger(t *testing.T) {
	data := []byte("hello world this is longer than target")
	padded := PadToSize(data, 5)
	assert.Equal(t, data, padded, "should return original if already bigger")
}

// TestSessionLifecycleActiveInterval pins the truncation bounds of the
// log-normal lifetime distribution introduced for HIGH-3 (May 2026 audit
// follow-up). Was uniform [120, 480]s; is now log-normal with median ≈ 300s
// truncated to [60, 86400]s. Detailed shape assertions live in the
// mimicry_lifetime_test.go companion file.
func TestSessionLifecycleActiveInterval(t *testing.T) {
	sl := NewSessionLifecycle()
	for range 1000 {
		interval := sl.NextActiveInterval()
		assert.GreaterOrEqual(t, interval, 60)
		assert.LessOrEqual(t, interval, 86400)
	}
}

func TestSessionLifecycleGapDuration(t *testing.T) {
	sl := NewSessionLifecycle()
	const N = 10000
	under1500 := 0
	for range N {
		gap := sl.NextGapDuration()
		assert.GreaterOrEqual(t, gap, 500)
		assert.LessOrEqual(t, gap, 3000)
		if gap < 1500 {
			under1500++
		}
	}
	// 70% should be under 1500ms
	ratio := float64(under1500) / float64(N)
	assert.InDelta(t, 0.70, ratio, 0.10, "~70%% of gaps should be under 1500ms")
}

func TestMimicryEngineCreation(t *testing.T) {
	me := NewMimicryEngine()
	assert.NotNil(t, me.Payload)
	assert.NotNil(t, me.Session)
	assert.NotNil(t, me.Ratio)
}

func TestRatioControllerExactBoundaries(t *testing.T) {
	// Test exactly at low boundary — should be OK
	rc := NewRatioController(2.5, 3.5)
	rc.RecordDownload(1000)
	rc.RecordUpload(2500) // exactly 2.5:1
	assert.Equal(t, 0, rc.CoverBudget(), "exactly at low boundary should need no cover")

	// Test exactly at high boundary — should be OK
	rc.Reset()
	rc.RecordDownload(1000)
	rc.RecordUpload(3500) // exactly 3.5:1
	assert.Equal(t, 0, rc.CoverBudget(), "exactly at high boundary should need no cover")
}

func TestPayloadDistributionUploadSizeVariety(t *testing.T) {
	pd := NewPayloadDistribution()
	sizes := map[int]bool{}
	for range 500 {
		sizes[pd.UploadSize()] = true
	}
	assert.Greater(t, len(sizes), 50, "upload sizes should have high variety")
}

func TestPayloadDistributionDownloadSizeVariety(t *testing.T) {
	pd := NewPayloadDistribution()
	sizes := map[int]bool{}
	for range 500 {
		sizes[pd.DownloadSize()] = true
	}
	assert.Greater(t, len(sizes), 50, "download sizes should have high variety")
}

// TestRatioControllerConcurrency verifies atomic operations under contention.
func TestRatioControllerConcurrency(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	done := make(chan struct{})

	go func() {
		for range 10000 {
			rc.RecordUpload(100)
		}
		done <- struct{}{}
	}()
	go func() {
		for range 10000 {
			rc.RecordDownload(50)
		}
		done <- struct{}{}
	}()
	go func() {
		for range 10000 {
			_ = rc.CoverBudget()
		}
		done <- struct{}{}
	}()

	<-done
	<-done
	<-done

	// Just verify no panic; exact values depend on scheduling.
	_ = rc.CoverBudget()
}

// TestRatioControllerNeedsCoverPrecision checks the math more precisely.
func TestRatioControllerNeedsCoverPrecision(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	rc.RecordDownload(400)
	rc.RecordUpload(200)
	// Current ratio: 0.5:1. Need 2.5*400=1000 upload. Have 200. Need 800.
	budget := rc.CoverBudget()
	expected := int(math.Ceil(2.5*400)) - 200 // 1000 - 200 = 800
	assert.Equal(t, expected, budget)
}

package browser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimingJitterNotUniform(t *testing.T) {
	shaper := NewShaper(DefaultShaperConfig())
	unique := map[time.Duration]bool{}
	for range 200 {
		d := shaper.NextDelay()
		unique[d] = true
		assert.GreaterOrEqual(t, d, 5*time.Millisecond)
		assert.LessOrEqual(t, d, 50*time.Millisecond)
	}
	assert.Greater(t, len(unique), 10, "delays should vary significantly")
}

func TestTimingJitterWithinBounds(t *testing.T) {
	config := ShaperConfig{MinDelay: 100 * time.Millisecond, MaxDelay: 500 * time.Millisecond}
	shaper := NewShaper(config)
	for range 100 {
		d := shaper.NextDelay()
		assert.GreaterOrEqual(t, d, 100*time.Millisecond)
		assert.Less(t, d, 500*time.Millisecond)
	}
}

func TestCoverTrafficRatio(t *testing.T) {
	shaper := NewShaper(ShaperConfig{
		CoverTrafficRatio: 0.10,
		MinDelay:          time.Millisecond,
		MaxDelay:          2 * time.Millisecond,
	})
	cover := 0
	total := 10000
	for range total {
		if shaper.ShouldSendCoverTraffic() {
			cover++
		}
	}
	ratio := float64(cover) / float64(total)
	assert.InDelta(t, 0.10, ratio, 0.03, "cover traffic should be ~10%%")
}

func TestCoverTrafficZeroRatio(t *testing.T) {
	shaper := NewShaper(ShaperConfig{
		CoverTrafficRatio: 0.0,
		MinDelay:          time.Millisecond,
		MaxDelay:          2 * time.Millisecond,
	})
	for range 1000 {
		assert.False(t, shaper.ShouldSendCoverTraffic())
	}
}

func TestPaddingSizeVariation(t *testing.T) {
	shaper := NewShaper(ShaperConfig{
		MinChunkPadding: 50,
		MaxChunkPadding: 500,
		MinDelay:        time.Millisecond,
		MaxDelay:        2 * time.Millisecond,
	})
	sizes := map[int]bool{}
	for range 100 {
		s := shaper.PaddingSize()
		sizes[s] = true
		assert.GreaterOrEqual(t, s, 50)
		assert.Less(t, s, 500)
	}
	assert.Greater(t, len(sizes), 10, "padding sizes should vary")
}

func TestBurstPatternHasPauses(t *testing.T) {
	shaper := NewShaper(DefaultShaperConfig())
	delays := shaper.BurstPattern(20)

	assert.Len(t, delays, 20)

	// Should have at least one pause > 100ms (inter-burst)
	hasPause := false
	for _, d := range delays {
		if d > 100*time.Millisecond {
			hasPause = true
			break
		}
	}
	assert.True(t, hasPause, "burst pattern should have inter-burst pauses")
}

func TestBurstPatternNotAllSame(t *testing.T) {
	shaper := NewShaper(DefaultShaperConfig())
	delays := shaper.BurstPattern(15)

	unique := map[time.Duration]bool{}
	for _, d := range delays {
		unique[d] = true
	}
	assert.Greater(t, len(unique), 3, "burst pattern should have varied delays")
}

func TestDefaultShaperConfig(t *testing.T) {
	config := DefaultShaperConfig()
	assert.Equal(t, 5*time.Millisecond, config.MinDelay)
	assert.Equal(t, 50*time.Millisecond, config.MaxDelay)
	assert.InDelta(t, 0.10, config.CoverTrafficRatio, 0.001)
}

func TestBurstShaperConfig(t *testing.T) {
	config := BurstShaperConfig()
	assert.Less(t, config.MaxDelay, 10*time.Millisecond)
	assert.Less(t, config.CoverTrafficRatio, 0.10)
}

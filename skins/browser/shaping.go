package browser

import (
	"math/rand/v2"
	"time"
)

// ShaperConfig controls traffic shaping parameters.
type ShaperConfig struct {
	// MinDelay and MaxDelay for timing jitter between requests.
	MinDelay time.Duration
	MaxDelay time.Duration

	// CoverTrafficRatio is the probability of sending cover traffic (0.0-1.0).
	// Per spec: ~10% of requests should be cover traffic.
	CoverTrafficRatio float64

	// MinChunkPadding and MaxChunkPadding for payload size variation.
	MinChunkPadding int
	MaxChunkPadding int
}

// DefaultShaperConfig returns config matching real browser behavior.
func DefaultShaperConfig() ShaperConfig {
	return ShaperConfig{
		MinDelay:          5 * time.Millisecond,
		MaxDelay:          50 * time.Millisecond,
		CoverTrafficRatio: 0.10,
		MinChunkPadding:   0,
		MaxChunkPadding:   512,
	}
}

// BurstShaperConfig returns config for high-throughput mode (minimal delays).
func BurstShaperConfig() ShaperConfig {
	return ShaperConfig{
		MinDelay:          0,
		MaxDelay:          5 * time.Millisecond,
		CoverTrafficRatio: 0.05,
		MinChunkPadding:   0,
		MaxChunkPadding:   256,
	}
}

// Shaper controls timing and traffic patterns to match browser behavior.
type Shaper struct {
	config ShaperConfig
}

// NewShaper creates a traffic shaper with the given config.
func NewShaper(config ShaperConfig) *Shaper {
	if config.MinDelay == 0 && config.MaxDelay == 0 {
		config = DefaultShaperConfig()
	}
	return &Shaper{config: config}
}

// NextDelay returns a random delay between requests (jitter).
// Never returns fixed intervals — fixed intervals are a behavioral fingerprint.
func (s *Shaper) NextDelay() time.Duration {
	if s.config.MaxDelay <= s.config.MinDelay {
		return s.config.MinDelay
	}
	spread := s.config.MaxDelay - s.config.MinDelay
	jitter := time.Duration(rand.Int64N(int64(spread)))
	return s.config.MinDelay + jitter
}

// ShouldSendCoverTraffic returns true if the next request should be cover traffic.
func (s *Shaper) ShouldSendCoverTraffic() bool {
	return rand.Float64() < s.config.CoverTrafficRatio
}

// PaddingSize returns a random padding size for chunk payload variation.
// Creates bimodal distribution matching real HTTP (small headers ~200B + variable body).
func (s *Shaper) PaddingSize() int {
	if s.config.MaxChunkPadding <= s.config.MinChunkPadding {
		return s.config.MinChunkPadding
	}
	spread := s.config.MaxChunkPadding - s.config.MinChunkPadding
	return s.config.MinChunkPadding + rand.IntN(spread)
}

// BurstPattern returns a sequence of delays simulating a browser page load:
// several fast requests (burst), then a pause.
func (s *Shaper) BurstPattern(requestCount int) []time.Duration {
	delays := make([]time.Duration, requestCount)
	burstSize := 3 + rand.IntN(5) // 3-7 requests per burst
	for i := range delays {
		if i > 0 && i%burstSize == 0 {
			// Inter-burst pause: 200ms - 2s (like reading a page)
			delays[i] = 200*time.Millisecond + time.Duration(rand.Int64N(int64(1800*time.Millisecond)))
		} else {
			// Intra-burst: fast (5-50ms, like parallel resource loading)
			delays[i] = s.NextDelay()
		}
	}
	return delays
}

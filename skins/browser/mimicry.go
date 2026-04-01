package browser

import (
	"math"
	"math/rand/v2"
	"sync/atomic"
)

// maxCoverBudget caps cover traffic generation at 64 KB/sec to avoid bandwidth waste.
const maxCoverBudget = 65536

// --- PayloadDistribution ---

// PayloadDistribution generates analytics-realistic payload sizes matching
// GA4/Mixpanel traffic patterns to defeat ML-based DPI classification.
type PayloadDistribution struct{}

// NewPayloadDistribution creates a new payload distribution generator.
func NewPayloadDistribution() *PayloadDistribution {
	return &PayloadDistribution{}
}

// UploadSize returns a target size from GA4-like distribution:
//
//	80-150 bytes  (45%)
//	151-350 bytes (35%)
//	351-800 bytes (15%)
//	801-2000 bytes (5%)
func (pd *PayloadDistribution) UploadSize() int {
	r := rand.IntN(100)
	switch {
	case r < 45: // 45%
		return 80 + rand.IntN(71) // 80..150
	case r < 80: // 35%
		return 151 + rand.IntN(200) // 151..350
	case r < 95: // 15%
		return 351 + rand.IntN(450) // 351..800
	default: // 5%
		return 801 + rand.IntN(1200) // 801..2000
	}
}

// DownloadSize returns a target size from analytics config distribution:
//
//	50-100 bytes   (40%)
//	201-600 bytes  (35%)
//	601-2000 bytes (20%)
//	2001-8000 bytes (5%)
func (pd *PayloadDistribution) DownloadSize() int {
	r := rand.IntN(100)
	switch {
	case r < 40: // 40%
		return 50 + rand.IntN(51) // 50..100
	case r < 75: // 35%
		return 201 + rand.IntN(400) // 201..600
	case r < 95: // 20%
		return 601 + rand.IntN(1400) // 601..2000
	default: // 5%
		return 2001 + rand.IntN(6000) // 2001..8000
	}
}

// ChunkForUpload splits a large payload into analytics-sized pieces.
// Each chunk size is drawn from the upload distribution.
// Returns nil for nil/empty input.
func (pd *PayloadDistribution) ChunkForUpload(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}

	var chunks [][]byte
	offset := 0
	for offset < len(data) {
		chunkSize := pd.UploadSize()
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[offset:end])
		offset = end
	}
	return chunks
}

// PadToSize pads data to targetSize with random bytes.
// Returns data unchanged if already >= targetSize.
func PadToSize(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data
	}
	padded := make([]byte, targetSize)
	copy(padded, data)
	// Fill remaining with random bytes
	for i := len(data); i < targetSize; i++ {
		padded[i] = byte(rand.IntN(256))
	}
	return padded
}

// --- RatioController ---

// RatioController maintains the upload/download byte ratio within a target range.
// Real analytics traffic has a characteristic ratio (download > upload) because
// servers return config/audience data. We mimic this by injecting cover upload
// traffic when the ratio drops too low.
type RatioController struct {
	uploadBytes   atomic.Int64
	downloadBytes atomic.Int64
	targetLow     float64 // minimum acceptable ratio (e.g. 2.5)
	targetHigh    float64 // maximum acceptable ratio (e.g. 3.5)
}

// NewRatioController creates a controller targeting the given upload:download ratio range.
func NewRatioController(targetLow, targetHigh float64) *RatioController {
	return &RatioController{
		targetLow:  targetLow,
		targetHigh: targetHigh,
	}
}

// RecordUpload adds n bytes to the upload counter.
func (rc *RatioController) RecordUpload(n int) {
	rc.uploadBytes.Add(int64(n))
}

// RecordDownload adds n bytes to the download counter.
func (rc *RatioController) RecordDownload(n int) {
	rc.downloadBytes.Add(int64(n))
}

// CoverBudget returns the number of upload bytes needed to bring the ratio
// up to targetLow. Returns 0 if the ratio is already within range or if
// downloadBytes is zero (guard against division by zero). Capped at maxCoverBudget.
func (rc *RatioController) CoverBudget() int {
	down := rc.downloadBytes.Load()
	if down == 0 {
		return 0
	}

	up := rc.uploadBytes.Load()
	currentRatio := float64(up) / float64(down)

	if currentRatio >= rc.targetLow {
		return 0
	}

	// How many bytes needed to reach targetLow
	needed := int(math.Ceil(rc.targetLow*float64(down))) - int(up)
	if needed <= 0 {
		return 0
	}
	if needed > maxCoverBudget {
		return maxCoverBudget
	}
	return needed
}

// Reset clears both counters. Call every ~30s to keep the window fresh.
func (rc *RatioController) Reset() {
	rc.uploadBytes.Store(0)
	rc.downloadBytes.Store(0)
}

// --- SessionLifecycle ---

// SessionLifecycle controls transport rotation timing to match real analytics
// SDK behavior (sessions have limited lifetime, gaps between reconnects).
type SessionLifecycle struct {
	minActive int // minimum active duration in seconds
	maxActive int // maximum active duration in seconds
	minGap    int // minimum gap between sessions in milliseconds
	maxGap    int // maximum gap between sessions in milliseconds
}

// NewSessionLifecycle creates a lifecycle with production defaults:
// active 120-480s, gap 500-3000ms.
func NewSessionLifecycle() *SessionLifecycle {
	return &SessionLifecycle{
		minActive: 120,
		maxActive: 480,
		minGap:    500,
		maxGap:    3000,
	}
}

// NextActiveInterval returns a random session duration in seconds.
func (sl *SessionLifecycle) NextActiveInterval() int {
	return sl.minActive + rand.IntN(sl.maxActive-sl.minActive+1)
}

// NextGapDuration returns a random gap in milliseconds.
// ~70% of values are under 1500ms (biased toward short gaps like real SDKs).
func (sl *SessionLifecycle) NextGapDuration() int {
	// Use weighted selection: 70% short (500-1499ms), 30% long (1500-3000ms)
	if rand.IntN(100) < 70 {
		// Short gap: 500..1499
		return sl.minGap + rand.IntN(1000)
	}
	// Long gap: 1500..3000
	return 1500 + rand.IntN(sl.maxGap-1500+1)
}

// --- MimicryEngine ---

// MimicryEngine combines payload distribution, session lifecycle, and ratio
// control into a single facade for the transport layer.
type MimicryEngine struct {
	Payload *PayloadDistribution
	Session *SessionLifecycle
	Ratio   *RatioController
}

// NewMimicryEngine creates a fully-configured mimicry engine with production defaults.
func NewMimicryEngine() *MimicryEngine {
	return &MimicryEngine{
		Payload: NewPayloadDistribution(),
		Session: NewSessionLifecycle(),
		Ratio:   NewRatioController(2.5, 3.5),
	}
}

package browser

import (
	"math"
	"math/rand/v2"
	"sync/atomic"

	"github.com/nixavpn/shadowlink/core"
)

// maxCoverBudget caps cover traffic generation at 64 KB/sec to avoid bandwidth waste.
const maxCoverBudget = 65536

// --- PayloadDistribution ---

// PayloadDistribution generates analytics-realistic payload sizes matching
// analytics/telemetry traffic patterns to defeat ML-based DPI classification.
type PayloadDistribution struct{}

// NewPayloadDistribution creates a new payload distribution generator.
func NewPayloadDistribution() *PayloadDistribution {
	return &PayloadDistribution{}
}

// UploadSize returns a target size from an analytics-like distribution:
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
//
// HIGH-3 (May 2026 audit follow-up, 2026-05-02): the active-interval
// distribution switched from uniform [120, 480]s to a truncated log-normal
// with median ≈ 300s and a heavy right tail (μ_log = ln(300) ≈ 5.7038,
// σ_log = 1.5). This eliminates the flat-histogram fingerprint that a passive
// observer could derive from session-duration clustering across many
// connections — real browser SPA tabs show heavy-tailed lifetimes (most live
// minutes, but a non-trivial fraction stretches into hours).
//
// minActive / maxActive carry the truncation bounds (60s floor, 86400s = 24h
// ceiling), NOT the uniform endpoints — the field names are preserved for
// backward-compat with the prior API but their meaning changed. The 60s floor
// guarantees rotation forward progress on the unlucky-low draw; the 24h
// ceiling caps the right tail to keep behavior bounded across device sleeps
// and network changes.
type SessionLifecycle struct {
	// minActive / maxActive: log-normal truncation bounds (seconds).
	// Were uniform [120, 480]s endpoints prior to HIGH-3 closure.
	minActive int
	maxActive int

	// lifetimeMuLog / lifetimeSigmaLog: log-normal shape parameters.
	// median = exp(lifetimeMuLog) = 300s ≈ 5min; σ_log=1.5 yields
	// p99 ≈ 9818s ≈ 2.7h and p99.9 ≈ 31057s ≈ 8.6h pre-truncation.
	lifetimeMuLog    float64
	lifetimeSigmaLog float64

	minGap int // minimum gap between sessions in milliseconds
	maxGap int // maximum gap between sessions in milliseconds
}

// NewSessionLifecycle creates a lifecycle with production defaults:
// active log-normal (median 300s, σ_log=1.5) truncated to [60, 86400]s,
// gap 500-3000ms. See struct doc for the heavy-tail rationale.
func NewSessionLifecycle() *SessionLifecycle {
	return &SessionLifecycle{
		minActive:        60,
		maxActive:        86400,
		lifetimeMuLog:    math.Log(300), // ≈ 5.703782
		lifetimeSigmaLog: 1.5,
		minGap:           500,
		maxGap:           3000,
	}
}

// NextActiveInterval returns a random session duration in seconds drawn from a
// truncated log-normal: seconds = exp(μ + σ·N(0,1)), clamped to
// [minActive, maxActive].
//
// Distribution properties at the production parameters (μ=ln(300), σ=1.5):
//   - median ≈ 300s (5min) — matches the prior uniform center
//   - p99 ≈ 9818s (2.7h)   — heavy enough to survive long browse sessions
//   - p99.9 ≈ 31057s (8.6h) — matches occasional all-day-tab behavior
//
// Truncation rationale:
//   - 60s floor (well below median, negligible probability mass) ensures the
//     unlucky-low draw still rotates forward in finite time.
//   - 86400s (24h) ceiling caps the unbounded log-normal tail so a single
//     session can't outlive multiple network changes / device sleeps.
//
// Uses math/rand/v2 globals — safe for concurrent calls.
func (sl *SessionLifecycle) NextActiveInterval() int {
	seconds := math.Exp(rand.NormFloat64()*sl.lifetimeSigmaLog + sl.lifetimeMuLog)
	switch {
	case seconds < float64(sl.minActive):
		return sl.minActive
	case seconds > float64(sl.maxActive):
		return sl.maxActive
	default:
		return int(seconds)
	}
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

// --- Sticky next_poll sampler (T2.4) ---

// NewMimicrySession is a backward-compat shim over core.NewMimicrySession.
// Plan §C11.3 (May 2026 audit) moved the constructor into core so that
// SessionManager.Create can populate the field before publishing the
// session — guaranteeing a happens-before edge to every concurrent
// buildResponse reader. The browser-package wrapper is retained so external
// callers (and existing tests under skins/browser) keep working unchanged.
// T2.4 closure (Phase 3 Plan A); publish ordering tightened by §C11.3.
func NewMimicrySession() *core.MimicrySession {
	return core.NewMimicrySession()
}

// NextPollSeconds returns a per-event sample around the sticky lambda with
// ±15% multiplicative jitter. Output truncated to [1, 3600] (real analytics
// SDKs never emit next_poll above an hour). Safe for concurrent calls — uses
// math/rand/v2 globals.
func NextPollSeconds(s *core.MimicrySession) int {
	jitter := 1.0 + (rand.Float64()-0.5)*0.30 // ±15%
	v := s.NextPollLambda * jitter
	switch {
	case v < 1:
		return 1
	case v > 3600:
		return 3600
	default:
		return int(v)
	}
}

// (Pareto sampler relocated to core.NewMimicrySession — Plan §C11.3.)

package core

import (
	"math"
	"math/rand/v2"
)

// ChunkSizingMin is the smallest read slice we ever take. Going below this
// inflates syscall and encrypt overhead without meaningfully improving the
// size distribution — real analytics payloads are rarely below 64 bytes.
const ChunkSizingMin = 1024

// ChunkSizingMax caps the upper bound of a single read. 12288 matches the
// ShadowLink session ChunkSize default so an oversized read never overflows
// the server-side body limit.
const ChunkSizingMax = 12288

// NextReadSize returns a per-read capacity drawn from an exponential-ish
// distribution centered around ~4 KB. This replaces the fixed 16 KB buffer
// that previously caused chunk sizes to cluster on the upper boundary
// whenever the target connection had data queued.
//
// 2026-04 DPI audit vector V4 — TSPU and ML-DPI can build a histogram of
// HTTP-body lengths (chunk × base64 × JSON envelope) and spot the VPN
// signal as a tight cluster at 16-24 KB. Randomizing the read cap at each
// iteration spreads the distribution into something closer to browser
// analytics traffic (heavy-tailed, mode near 1-4 KB, occasional larger
// events).
//
// Distribution: min(max(ChunkSizingMin, ExpFloat64() * scale), ChunkSizingMax)
// with scale=3072 → mean ~3 KB, P95 ~9 KB, hard cap at ChunkSizingMax.
func NextReadSize() int {
	const scale = 3072.0
	v := rand.ExpFloat64() * scale
	if math.IsNaN(v) || v < ChunkSizingMin {
		return ChunkSizingMin
	}
	if v > ChunkSizingMax {
		return ChunkSizingMax
	}
	return int(v)
}

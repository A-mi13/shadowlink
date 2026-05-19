package server

import (
	"math/rand/v2"
)

// chunkSizeSampleSet is the per-session candidate chunk sizes for the
// A6 anti-TSPU debt fix (2026-05-18). Pre-A6 the server emitted a
// constant chunk_size (12288 bytes, server config default) — every
// data WS frame on the wire was ~12288 bytes plus AES-GCM overhead,
// a regular pattern that real Mixpanel/SDK analytics traffic does NOT
// exhibit (real flows have variable-size JSON 600-3000 byte bursts).
//
// Sampling uniformly from {6144, 8192, 10240, 12288} per session
// gives the data-frame size distribution four discrete peaks instead
// of one. Each session pins its choice for its entire lifetime so
// in-session the pattern stays consistent (a real session also has
// a relatively stable bulk-transfer size). Aggregate distribution
// across many sessions on the same origin is the wire-shape
// observable, and that is now bimodal+ not unimodal.
//
// Range bounds:
//
//   - 6144 (lo): half of the default, the smallest value where a
//     single AES-GCM-wrapped CONNECT chunk (~100-200 bytes overhead
//     vs payload) still fits comfortably without packet fragmentation
//     overhead dominating.
//   - 12288 (hi): the historical default. Keeping this in the set
//     means existing-default-clients (those measuring under cap=12288
//     already) won't perceive any change in throughput.
//   - 8192, 10240: intermediate quartile values. Even spacing gives
//     the wire-shape histogram four equal peaks.
//
// Why uniform (not log-normal or weighted): the goal is to break a
// unimodal signature, not to match real-world distribution shape.
// Real SDK traffic is heavy-tail tiny (≤4KB dominant) — we cannot
// match that without crippling throughput. Four uniform peaks at
// {6, 8, 10, 12 KB} is the minimum effort that breaks the unimodal
// pattern; matching real shape is a Phase 5 calibration task per
// the audit doc.
//
// Why pin per-session (not per-chunk): real Mixpanel SDK has a single
// chunk-size negotiated at session start (it's a property of the
// transport, not per-call). Per-chunk variation would itself be a
// signature ("client whose chunk size changes mid-session"). The
// per-session pinning matches plausible SDK behavior.
//
// Wire-format compatibility: chunk_size is already a uint16 field in
// the ServerHello JSON (`"cs"`). Changing the emitted value per
// session is fully wire-compatible — existing clients accept whatever
// the server sends via shData.ChunkSize.
var chunkSizeSampleSet = [4]uint16{6144, 8192, 10240, 12288}

// sampleChunkSize returns one of the candidate sizes uniformly at
// random. Caller passes the global server config chunk size as a
// fallback for when sampling is disabled (rare — defensive).
//
// If configChunkSize is 0 or smaller than the smallest sample value,
// the helper returns configChunkSize unchanged. This preserves the
// invariant that operators with custom config (`-chunk-size <N>`)
// see exactly that N, not a sampled value above their cap. In
// production with default 12288 this branch is never hit because the
// sample set max equals the default.
//
// Returns uint16 directly because that's the wire format type.
//
// Concurrency: math/rand/v2 package-level IntN is goroutine-safe and
// allocation-free. Called once per handshake (per session creation),
// not in any hot path.
func sampleChunkSize(configChunkSize int) uint16 {
	if configChunkSize <= 0 {
		return 0
	}
	// Operator capped below the smallest sample value? Honor their cap.
	if configChunkSize < int(chunkSizeSampleSet[0]) {
		return uint16(configChunkSize)
	}
	// Filter to samples ≤ configChunkSize so an operator with a tighter
	// cap (e.g. -chunk-size 9000) still sees only samples that fit.
	maxIdx := 0
	for i, v := range chunkSizeSampleSet {
		if int(v) <= configChunkSize {
			maxIdx = i
		}
	}
	return chunkSizeSampleSet[rand.IntN(maxIdx+1)]
}

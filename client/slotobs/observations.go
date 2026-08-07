// Package slotobs records how WS pool slots die, so the rotation threshold can
// be DERIVED from the user's own network instead of hard-coded globally.
//
// Why this exists (раунд 18, P0 reframed 2026-07-31)
//
// The whole timing subsystem (MAX_SLOT_AGE=75s, AGE_CUT_MIN_AGE, stagger, drain
// caps) is tuned to a "TSPU cuts bare-origin TCP at ~130-190s" window that is
// confirmed by NO source: the public corpus (net4people#490) describes a
// VOLUME trigger (~16-20 KB server→client per TCP), and the 130-190 figure looks
// like a GFW measurement carried over from a different censor.
//
// The original plan was a field measurement in a Russian network. That was
// dropped as the primary answer: ACM IMC 2022 (peer-reviewed) shows ТСПУ is
// behaviourally NON-UNIFORM across regions and operators, so any single
// measurement produces a number valid for one AS at one point in time. Shipping
// it as a global constant would just replace an unproven number with a measured
// one that is still wrong for most users — and wrong silently.
//
// So: observe locally, decide locally. This package is step 1 — the observation
// substrate. It deliberately does NOT decide anything: no threshold is derived
// here, no rotation policy is changed. Steps 2-5 (axis inference, adaptive
// threshold, hysteresis, persistence) build on top, and each needs its own
// design pass. Keeping observation separate means the data is trustworthy before
// anything acts on it.
//
// Field result (2026-08-07, n=222, single AS): the axis IS age — CV 0.26 vs 8.73
// on bytes, a 33x tighter cluster; slots die at 0 KB too, so the net4people#490
// volume trigger does not reproduce here. The window is 84-118s (p10 84.1 /
// p50 97.6 / p90 118.0), NOT the 130-190s this codebase was tuned against.
//
// ⚠ KNOWN BIAS — the sample is CENSORED. Record is called from exactly one site
// (the reader-error path in ws_pool.go), so slots torn down by our OWN planned
// rotation never enter it. Two consequences, both easy to get wrong:
//
//	1. ByCloseKind cannot yield "what fraction of slots the censor cut" — planned
//	   rotations are absent from the denominator by construction.
//	2. Percentiles are biased UPWARD: we only observe slots the censor reached
//	   BEFORE our rotation did, so the right tail is truncated by our own policy.
//	   The true window may be tighter than measured.
//
// This is why AgeMin exists: a minimum is a fact, a percentile over a censored
// sample is an estimate. Budget checks should prefer the former.
//
// Privacy: observations never leave the device. No addresses, no hostnames, no
// payload — only timings, byte counts and a close-shape label. The buffer lives
// in memory only; persistence (step 5) will be an explicit, separate decision.
package slotobs

import (
	"math"
	"sort"
	"sync"
)

// DefaultCapacity is the ring size. ~512 deaths is several hours of direct-mode
// operation at the observed age-cut cadence — enough for percentile estimates
// while bounded (this is a client process, and H-14 in the same audit round was
// exactly an unbounded per-key map).
const DefaultCapacity = 512

// Observation is one slot death. Fields mirror what ws_pool already logs at the
// reader-error site, because those three together are what distinguishes the
// competing hypotheses (see FIELD-CHECKS.md §2.4):
//
//	AgeMs ≈ constant across differing DownBytes  → cut by AGE
//	DownBytes ≈ constant across differing AgeMs  → cut by VOLUME
//	LastWriteAgeMs small (slot was active)       → not cut by idleness
type Observation struct {
	// AgeMs is how long the slot had been alive when it died.
	AgeMs int64
	// DownBytes is server→client bytes carried by this slot over its lifetime.
	// int64 (not uint64) to match the atomic counter it comes from — a negative
	// value would signal accounting drift and should be visible, not wrapped
	// into a huge unsigned number.
	DownBytes int64
	// LastWriteAgeMs is time since our last write; -1 when unknown. Separates
	// "connection was idle" from "a write was in flight".
	LastWriteAgeMs int64
	// CloseKind is the classified read-error shape (classifyWSReadError
	// vocabulary: close_other / reset / io_timeout / peer_eof / ...). Kept as a
	// plain string so this package does not depend on the client package.
	CloseKind string
	// Mature reports whether the current classification counted this as an
	// expected age-cut. Recorded, not trusted: it is the OUTPUT of the very
	// threshold under review, so treating it as ground truth would make the
	// data confirm the constant it is meant to test.
	Mature bool
}

// Recorder is a bounded ring of observations, safe for concurrent use.
//
// Each pool slot dies on its own goroutine, so Record is called concurrently;
// the mutex is uncontended in practice (a death is a rare event relative to
// data-path work) and keeps the snapshot consistent.
type Recorder struct {
	mu    sync.Mutex
	buf   []Observation
	next  int    // next write index
	count int    // live entries (< len(buf) until the ring wraps)
	total uint64 // lifetime deaths, including those overwritten
}

// NewRecorder creates a recorder holding up to capacity observations.
// capacity <= 0 uses DefaultCapacity.
func NewRecorder(capacity int) *Recorder {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Recorder{buf: make([]Observation, capacity)}
}

// Record stores one observation, overwriting the oldest when full.
func (r *Recorder) Record(o Observation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = o
	r.next = (r.next + 1) % len(r.buf)
	if r.count < len(r.buf) {
		r.count++
	}
	r.total++
}

// Len returns the number of observations currently held.
func (r *Recorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// Total returns lifetime deaths recorded, including overwritten ones.
func (r *Recorder) Total() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// Snapshot returns a copy of the held observations, oldest first.
// Returns nil when empty. The copy makes callers immune to concurrent writes.
func (r *Recorder) Snapshot() []Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		return nil
	}
	out := make([]Observation, 0, r.count)
	// Oldest entry: when the ring has wrapped it sits at r.next, otherwise at 0.
	start := 0
	if r.count == len(r.buf) {
		start = r.next
	}
	for i := 0; i < r.count; i++ {
		out = append(out, r.buf[(start+i)%len(r.buf)])
	}
	return out
}

// Reset drops all observations. Used by tests and by a future re-learn trigger
// (e.g. the network changed underneath us).
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next, r.count, r.total = 0, 0, 0
}

// Summary is a read-only digest of recorded deaths. It reports SPREAD, not just
// central tendency: the whole question is whether deaths cluster on the age axis
// or the byte axis, and a mean alone cannot answer that.
type Summary struct {
	Count int

	// Percentiles of slot age at death (ms). P10 is the interesting one for a
	// future threshold: rotate before the earliest deaths, not the median.
	AgeP10, AgeP50, AgeP90 int64

	// AgeMin is the earliest death observed (ms). The threshold exists to stay
	// LEFT of the death distribution, so the leftmost point is the one datum that
	// can falsify a budget — yet it was the one this Summary did not publish
	// (round-18 field review 2026-08-07). P10 is an estimate over a censored
	// sample; AgeMin is a fact. When AgeMin sits below the computed worst-case
	// teardown, the budget is provably wrong regardless of what P10 says.
	AgeMin int64

	// Percentiles of downlink bytes at death.
	BytesP10, BytesP50, BytesP90 int64

	// Coefficient of variation (stddev/mean) per axis. The axis with the LOWER
	// spread is the one the censor is keying on: a hard threshold produces
	// tightly clustered values on its own axis and scattered values on the
	// other. Zero when the mean is zero.
	AgeCV, BytesCV float64

	// ByCloseKind counts deaths per classified shape, so "middlebox teardown"
	// (close_other / reset) can be told apart from "we timed out" (io_timeout).
	ByCloseKind map[string]int
}

// Summarize computes the digest. Returns a zero Summary (Count 0) when empty.
//
// NOTE: this function deliberately stops at describing the data. It does not
// pick an axis and does not emit a threshold — that inference is step 2 and
// needs its own design (noise attribution, minimum sample size, hysteresis).
// Publishing a number from here would invite exactly the mistake this rework is
// undoing: a single value treated as truth.
func (r *Recorder) Summarize() Summary {
	obs := r.Snapshot()
	if len(obs) == 0 {
		return Summary{}
	}

	ages := make([]int64, 0, len(obs))
	bytesv := make([]int64, 0, len(obs))
	byKind := make(map[string]int, 4)
	for _, o := range obs {
		ages = append(ages, o.AgeMs)
		bytesv = append(bytesv, o.DownBytes)
		byKind[o.CloseKind]++
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i] < ages[j] })
	sort.Slice(bytesv, func(i, j int) bool { return bytesv[i] < bytesv[j] })

	return Summary{
		Count:       len(obs),
		AgeMin:      ages[0], // sorted ascending above
		AgeP10:      percentileInt64(ages, 10),
		AgeP50:      percentileInt64(ages, 50),
		AgeP90:      percentileInt64(ages, 90),
		BytesP10:    percentileInt64(bytesv, 10),
		BytesP50:    percentileInt64(bytesv, 50),
		BytesP90:    percentileInt64(bytesv, 90),
		AgeCV:       cvInt64(ages),
		BytesCV:     cvInt64(bytesv),
		ByCloseKind: byKind,
	}
}

// percentileInt64 returns the p-th percentile of a SORTED slice using
// nearest-rank. Empty → 0.
func percentileInt64(sorted []int64, p int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[percentileIndex(len(sorted), p)]
}

// percentileIndex maps a percentile to an index in [0, n-1].
func percentileIndex(n, p int) int {
	if n == 1 {
		return 0
	}
	idx := p * (n - 1) / 100
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return idx
}

// cvInt64 returns stddev/mean (coefficient of variation). 0 when mean is 0 or
// fewer than two samples — CV is meaningless there.
func cvInt64(xs []int64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += float64(x)
	}
	mean := sum / float64(len(xs))
	if mean == 0 {
		return 0
	}
	var sq float64
	for _, x := range xs {
		d := float64(x) - mean
		sq += d * d
	}
	return sqrt(sq/float64(len(xs))) / mean
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	return math.Sqrt(x)
}

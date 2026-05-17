package server

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// SentinelEmitter emits dual-carrier rate-limit sentinels (body marker via
// Schema.org JSON-LD value-field substitution + X-SL-RL header) for
// masqueraded rate-limit responses.
//
// Invariants:
//   - Emit is called ONLY from rate-limit branches (handleHandshakeNew
//     rate-limit, handleWebSocket rate-limit). NOT from auth_fail,
//     replay_detected, malformed, unauth_visitor, max_clients_overload.
//     Task 1.4 wires this; Task 1.5 enforces via test.
//   - Body marker emitted when a pre-baked snapshot exists for the path;
//     header always emitted. Missing snapshot increments the
//     RateLimitEmittedByBodyMissing counter for ops visibility.
//   - No synchronous delays. Server responds with natural latency.
//   - Body substitution is byte-precise: at IdentifierValueOffset for
//     IdentifierValueLength bytes. Surrounding HTML byte-for-byte
//     identical to baseline.
type SentinelEmitter struct {
	snapshots map[string]*DecoySnapshot // immutable after construction
	metrics   *Metrics                  // shared registry
	bufPool   sync.Pool                 // bytes.Buffer reuse for splicing
}

// NewSentinelEmitter constructs an emitter. nil snapshots → header-only
// emissions (e.g., Telegraph-proxy deploy without prebaked snapshots).
func NewSentinelEmitter(snapshots map[string]*DecoySnapshot, metrics *Metrics) *SentinelEmitter {
	e := &SentinelEmitter{
		snapshots: snapshots,
		metrics:   metrics,
	}
	e.bufPool = sync.Pool{
		New: func() any { return new(bytes.Buffer) },
	}
	return e
}

// Emit writes a masqueraded rate-limit response. Status code 200, NOT 429.
// snapshotKey selects which pre-baked decoy HTML; empty defaults to "index.html".
//
// Header carrier (X-SL-RL) always emitted; body carrier emitted when
// snapshot exists for the key. Missing snapshot → header-only + counter inc.
func (e *SentinelEmitter) Emit(w http.ResponseWriter, sig RLSentinel, snapshotKey string) {
	if snapshotKey == "" {
		snapshotKey = "index.html"
	}

	// Resolve snapshot. nil map or missing key → header-only mode.
	var snap *DecoySnapshot
	if e.snapshots != nil {
		snap = e.snapshots[snapshotKey]
	}

	// Always emit the header first (before any w.WriteHeader / body write).
	w.Header().Set("X-SL-RL", formatRLStateHeader(sig))
	e.metrics.RateLimitSentinelEmitted.Add(1)

	if snap == nil || len(snap.HTML) == 0 {
		// Header-only fallback: no snapshot available or empty HTML.
		e.metrics.RateLimitEmittedByBodyMissing.Add(1)
		// Header-only path: emits X-SL-RL only, no body. Caller does an early
		// return after Emit on this path (no timing-pipeline wrapping in Phase 1).
		// Timing-pipeline parity with legacy path is deferred to Phase 2 — see
		// TODO in decoy_timing.go.failClosedToDecoyRateLimitedV2.
		return
	}

	// Produce the padded body value.
	bodyVal, err := FormatRLStateValue(sig)
	if err != nil {
		// Defensive fallback: format error (should never happen with sane inputs).
		// Fall back to header-only so the response isn't left hanging.
		e.metrics.RateLimitEmittedByBodyMissing.Add(1)
		return
	}

	// Splice the value into the HTML using a pooled buffer. The substitution is
	// byte-precise: prefix || new-value (same length as placeholder) || suffix.
	// Total size is invariant — Content-Length can be set exactly.
	buf := e.bufPool.Get().(*bytes.Buffer)
	buf.Reset()

	off := snap.IdentifierValueOffset
	length := snap.IdentifierValueLength

	buf.Write(snap.HTML[:off])
	buf.WriteString(bodyVal)
	buf.Write(snap.HTML[off+length:])

	// CRIT-3 fix: copy bytes before returning buffer to pool, to avoid race
	// where another goroutine gets the buffer from pool and overwrites it
	// while http.ResponseWriter still streams from `body`. Under rate-limit
	// storm with many concurrent Emit calls, this race causes corrupted
	// response bodies. Allocation cost is small (snap.Size ≤ 256 KB).
	body := make([]byte, buf.Len())
	copy(body, buf.Bytes())

	// Set response headers before WriteHeader.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)

	// Write body.
	_, _ = w.Write(body)

	// Return buffer to pool. Drop oversized buffers (> 64 KB) to avoid
	// retaining large allocations in the pool indefinitely.
	if buf.Cap() > 64*1024 {
		// Let GC reclaim — don't return to pool.
	} else {
		buf.Reset()
		e.bufPool.Put(buf)
	}

	e.metrics.RateLimitEmittedByBody.Add(1)
}

// formatRLStateHeader converts an RLSentinel into the X-SL-RL header value.
// The format mirrors the body carrier value (FormatRLStateValue) but without
// trailing semicolon padding — clients parse by key=value pairs and ignore
// empty entries, so both carrier forms are semantically identical.
//
// Wire format: "v1;bucket=<label>;refill_in=<seconds>;burst_left=<n>;exempt=<0|1>"
// (semicolon-separated, same vocabulary as FormatRLStateValue, no padding)
//
// This is the single source of truth for both carriers — body uses the padded
// form (FormatRLStateValue), header uses the stripped form (this function).
func formatRLStateHeader(sig RLSentinel) string {
	core := fmt.Sprintf("v1;bucket=%s;refill_in=%d;burst_left=%d;exempt=%d",
		sig.Bucket,
		int(sig.RefillIn.Seconds()),
		sig.BurstLeft,
		sig.Exempt,
	)
	return strings.TrimRight(core, ";")
}

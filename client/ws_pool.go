package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	mrand "math/rand"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// ErrRateLimited — see ratelimit_signal.go for the canonical declaration.
// Callers use errors.Is; the typed sentinel is now shared across the carrier
// chain (Phase 2.1) and the legacy header detection path.
//
// Task A2 (May audit, 2026-05-01). Moved to ratelimit_signal.go (Phase 2.1).
//
// Note: kept as a doc comment only — the var lives in ratelimit_signal.go.

// slotRateLimitedCooldown returns the wait duration applied by reconnectLoop
// when connectSlot surfaces ErrRateLimited. Spec: 180s ± 30% jitter, drawn
// uniformly from [126s, 234s].
//
// Why fixed (not exp): server told us "you are flooding me". We need to wait
// long enough for the per-IP rate window (1 minute) to elapse twice over,
// plus a safety margin so we don't immediately hit the limiter again. exp
// backoff would either undercut the window (attempt 0-2) or overshoot it
// massively (attempt 5+ → 60s cap which is still under window safety).
//
// Why ±30% (not ±10%): when N slots in a pool die together and all see the
// rate-limit sentinel, we need their cool-downs to spread enough that the
// post-cool-down handshake burst is decorrelated. 180s × 30% = 108s spread
// across 8 slots is comfortably bigger than the limiter window — the storm
// gets broken up.
//
// Why disjoint from slotBackoffDuration's [5s, 60s] range: failure-mode
// classification on the dashboard depends on the cool-down counter ticking
// only when the sentinel fires, not when the network just hiccupped. The
// floor at 126s is double the exp cap, so a single-slot dashboard panel can
// distinguish the two reconnect cadences cleanly.
func slotRateLimitedCooldown() time.Duration {
	const base = 180 * time.Second
	// Uniform [-0.30, +0.30) draw — math/rand/v2 Float64 is concurrent-safe.
	jitter := (rand.Float64()*0.6 - 0.3)
	return time.Duration(float64(base) * (1.0 + jitter))
}

// rateLimitRefillFloor / rateLimitRefillCeil are sanity bounds applied when
// honoring a server-directed RefillIn from *RateLimitError.Signal. They
// prevent the client from sleeping for less than 5 s (renders the rate-limit
// protection ineffective) or more than 30 min (excessive; likely a clock
// skew / config bug on the server side).
const (
	rateLimitRefillFloor = 5 * time.Second
	rateLimitRefillCeil  = 30 * time.Minute
)

// clampRefillIn applies [rateLimitRefillFloor, rateLimitRefillCeil] bounds to
// a server-supplied RefillIn duration. Returns the clamped value.
func clampRefillIn(d time.Duration) time.Duration {
	if d < rateLimitRefillFloor {
		return rateLimitRefillFloor
	}
	if d > rateLimitRefillCeil {
		return rateLimitRefillCeil
	}
	return d
}

// slotRateLimitedCooldownForTest is a test seam: production code calls
// slotRateLimitedCooldown directly, but TestReconnectLoop_AppliesCooldownOnRateLimit
// substitutes a 100ms shim so the integration test can complete in <1s.
//
// Defaults to slotRateLimitedCooldown so production behavior is unchanged
// when no test stub is installed.
var slotRateLimitedCooldownForTest = slotRateLimitedCooldown

// slotBackoffDurationForTest is a test seam matching slotRateLimitedCooldownForTest.
// Production reconnectLoop calls slotBackoffDuration(attempt) directly; tests
// override this to return a fast backoff so reconnectLoop integration tests
// finish in milliseconds instead of seconds.
var slotBackoffDurationForTest = slotBackoffDuration

// connectSlotForTest is a test seam for reconnectLoop integration tests —
// production code uses (*WSPoolTransport).connectSlot directly. The stub
// returns the desired error sequence (e.g. ErrRateLimited then nil) without
// needing a live WS server.
//
// nil means "fall through to the real implementation" — production paths
// must NOT see this hook and the build never references it.
var connectSlotForTest func() error

// sleepWithCancel sleeps for d, returning early if ctx is cancelled. Used
// by reconnectLoop to pace the rate-limit cool-down without blocking
// pool shutdown for the full 126-234s.
func sleepWithCancel(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// newDiscardLogger returns a slog logger whose output is silently dropped.
// Used by tests that exercise loops which would otherwise spam the test
// output stream. NOT used in production code.
func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

type slotState int32

const (
	slotConnecting slotState = iota
	slotReady
	slotDead
	slotDraining
)

// slotDeathCause classifies WHY a slot was torn down. The cause is plumbed
// explicitly through handleSlotDeath because two semantically-different
// events share the cleanup path:
//
//   - deathCauseNatural — the slot's TCP died for reasons outside our
//     control: reader panic, ReadMessage error, middlebox close 1006, TCP
//     RST. These are signals that something in the network path is angry;
//     they MUST feed the meltdown detector so the reconnect loop pauses
//     when CF / TSPU / origin are punishing us.
//
//   - deathCausePreemptiveRotation — WE decided to rotate the slot before
//     a middlebox killed it (byte budget exceeded, age threshold reached,
//     or watchdog-driven). The TCP teardown is a success of the rotation
//     policy, not a failure. Counting these against the meltdown threshold
//     was a regression introduced by the age-watchdog: 6 staggered
//     rotations within ~15s tripped the 6-deaths/15s meltdown counter and
//     paused reconnect for 10s on a perfectly healthy pool (observed in
//     field log 2026-05-18 right after the watchdog landed).
//
// recordSlotDeath is only invoked for the Natural cause; the meltdown
// detector therefore tracks ONLY real failures.
type slotDeathCause int

const (
	deathCauseNatural slotDeathCause = iota
	deathCausePreemptiveRotation
	// deathCauseDrainTeardown — graceful drain finished (or hard cap fired)
	// and the slot is being torn down by US after a reserve replacement
	// already carried its capacity. This cause MUST NOT advance the meltdown
	// counter (it is not a network failure) and MUST NOT spawn reconnectLoop
	// on this idx (reserve slot owns the capacity in a different cell). The
	// dispatcher additionally sets p.slots[idx] = nil to free the cell for
	// future reserve reuse via findFreeReserveSlot.
	deathCauseDrainTeardown
)

func (c slotDeathCause) String() string {
	switch c {
	case deathCauseNatural:
		return "natural"
	case deathCausePreemptiveRotation:
		return "preemptive_rotation"
	case deathCauseDrainTeardown:
		return "drain_teardown"
	default:
		return "unknown"
	}
}

// defaultMaxPendingPerSlot is the default in-flight CONNECTs cap per slot.
// 4 is suitable for direct-to-origin mode. For CF mode a lower value (2) is
// preferred because CF Free plan throttles aggressive WS burst traffic.
// Pass WSPoolConfig.MaxPendingPerSlot to override.
const defaultMaxPendingPerSlot = 4

// wsSlotTransport is the minimal interface that poolSlot.transport must satisfy.
// Using an interface instead of *WebSocketTransport lets tests inject a fake
// reader without spinning up a real gorilla WS connection, while keeping the
// production code structurally identical — *WebSocketTransport satisfies all
// five methods automatically (enforced by the compile-time assertion below).
//
// Phase 3 supervisor refactor will replace the loop body with a channel-based
// pump, but this interface remains the seam point so regression tests continue
// to drive the real reader path.
type wsSlotTransport interface {
	ReadMessage(timeout time.Duration) ([]byte, error)
	LastWriteUnixNano() int64
	WriteMessage(data []byte) error
	WriteControlMessage(data []byte) error
	Close() error
}

// Compile-time assertion: *WebSocketTransport must satisfy wsSlotTransport.
var _ wsSlotTransport = (*WebSocketTransport)(nil)

// poolSlot is a single WebSocket connection in the pool with its own crypto session.
//
// generation is incremented every time the slot is (re)connected. Each reader
// goroutine captures its slot's generation at start and checks it before each
// ReadMessage. If generation has advanced, the reader exits — preventing the
// gorilla "repeated read on failed websocket connection" panic that would
// otherwise occur when an old reader and a new reader race on the same conn
// after a fast reconnect.
type poolSlot struct {
	transport       wsSlotTransport
	session         *core.Session
	token           []byte
	state           atomic.Int32 // slotState
	streams         atomic.Int32 // active stream count (established)
	pendingConnects atomic.Int32 // in-flight CONNECTs (sent, awaiting CONNECT_OK)
	generation      atomic.Uint64
	index           int

	// downBytes counts encrypted payload bytes received on this TCP since last
	// (re)connect. Used for byte-based preemptive rotation: TSPU (Russia DPI,
	// 2026) silently freezes TCP after ~15-20KB downstream from "suspicious" IPs
	// with TLS 1.3 — we rotate before hitting the threshold to keep traffic moving.
	downBytes atomic.Int64

	// lastDeathNs holds the UnixNano timestamp of the most recent handleSlotDeath
	// call. AssignStream uses it to deprioritize freshly-reconnected slots —
	// without this penalty, a slot that just came back from meltdown immediately
	// gets new TCP streams attached to it, and if it dies again (very likely
	// because the underlying CF/TSPU condition hasn't cleared) the user's upload
	// is killed mid-transfer. Zero means "never died" — fresh slots compete
	// equally on score.
	lastDeathNs atomic.Int64

	// readerActive guards against two slotReader goroutines reading the same
	// *gorilla.Conn concurrently. Two readers calling ReadMessage on one conn
	// interleave their reads at the byte boundary and gorilla decodes the
	// resulting stream as malformed frames — observed in production as
	// `RSV1/RSV2/RSV3 set`, `bad opcode N`, `continuation after FIN`. The
	// race opens when the outer engine restarts pool.StartReader after a
	// "all readers exited" event WHILE pool.reconnectLoop has already
	// scheduled a fresh slotReader for a slot it just brought back online
	// (ws_pool.go::reconnectLoop, line near `go p.slotReader(idx)`).
	//
	// Reader lifecycle: slotReaderWithClient performs CAS(false→true) at
	// entry and defers CAS(true→false) at exit. StartReader skips slots
	// where readerActive is already true.
	readerActive atomic.Bool

	// rotationDeferredNs holds the first time maybeRotateSlot wanted to
	// rotate this slot but found active streams on it. 0 means "rotation
	// not currently deferred". When the slot finally drains its streams
	// OR slotRotationGraceWithActiveStreams elapses (whichever happens
	// first), the rotation fires. Reset to 0 in connectSlot on reconnect.
	rotationDeferredNs atomic.Int64

	// startedAtNs is the UnixNano timestamp at which the current TCP for
	// this slot finished its handshake and became ready. Set by connectSlot
	// right before setState(slotReady). Reader-side age checks AND the
	// pool-level rotation watchdog goroutine both read this field to compute
	// slot_age. Atomic so the watchdog can read it without taking any lock.
	// Zero means "never connected" (initial state).
	startedAtNs atomic.Int64

	// byteBudget is the per-slot, per-session downlink-byte threshold that
	// triggers preemptive rotation. Sampled ONCE in connectSlot from a wide
	// jittered range based on WSPoolTransport.maxBytesPerSlot and the slot
	// index, then stored here and read directly by slotReaderWithClient.
	//
	// Why per-session sample (not per-frame, not per-call): re-sampling on
	// every ReadMessage would let a single frame trip rotation as soon as
	// the resampled threshold dropped below the current down_bytes total,
	// causing spurious instant rotations. Sampling once at connect freezes
	// the threshold for the slot's lifetime, so a heavy upload sees one
	// consistent budget all the way to rotation.
	//
	// Why per-slot random (not just idx-stagger): per-flow byte counters are
	// a documented TSPU 2024 detection vector (Citizen Lab "Stranger DPI in
	// Russia", Aug 2024; A*STAR anti-censorship workshop 2025). Our previous
	// deterministic ladder 8/9/10/.../15 MB produced a clean bimodal
	// distribution on the wire (our rotations vs middlebox kills around
	// 200 MB), which is a fingerprint. Wide random sampling smears the
	// "ours" cluster across a 4-30 MB band, much closer to organic decay.
	//
	// 0 = byte-budget rotation disabled for this slot (viaCF mode or
	// MaxBytesPerSlot config = 0). Read with Load; written with Store
	// exactly once per (re)connect by sampleByteBudget.
	byteBudget atomic.Int64

	// staggerOffsetNs is the per-slot, per-session additive grid jitter
	// applied to the rotation timing threshold. Sampled ONCE in connectSlot
	// via slotStaggerOffset(idx), stored here, and read by:
	//   - rotationWatchdogSweep — adds to maxSlotAge to compute when this
	//     slot is eligible for age-triggered rotation.
	//   - maybeRotateSlot byte_budget defer — adds to nowNs when recording
	//     rotationDeferredNs, so 8 simultaneously-deferred slots have
	//     grace-expiry events spread by ~staggerStep × idx + jitter.
	//
	// Why per-session (not per-call): if the watchdog re-samples on every
	// 5s tick, a slot near its threshold can repeatedly draw HIGH offsets
	// and never rotate — or alternate "ready / not ready" decisions tick
	// by tick. Freezing the offset at connect makes the rotation time a
	// single random variable per session, which is the right contract for
	// FFT-spectrum smearing.
	//
	// Range: idx=0 → always 0. idx≥1 → uniform on
	// [idx*step - step/2, idx*step + step/2). Read with Load; written with
	// Store exactly once per (re)connect.
	staggerOffsetNs atomic.Int64
}

// slotFreshnessPenaltyWindow defines how long after a slot's last death
// AssignStream's first pass excludes it from candidates. Tuned to outlast
// the typical reconnect-handshake-warmup cycle (~3-8s in field data) so
// the cooled-down slot has time to prove stability before long-lived TCP
// uploads land on it. If every ready slot is inside this window (cascade
// recovery), AssignStream falls through to a second pass that ignores
// the window — see AssignStream's pickInPass closure.
const slotFreshnessPenaltyWindow = 30 * time.Second

// slotRotationStaggerStep is the per-slot GRID INTERVAL added to MaxSlotAge
// so 8 slots created within milliseconds of each other don't all rotate at
// the same instant. With a 2-min base and 15s grid step, the 8th slot
// rotates ≈ 2m after the 1st — one rotation roughly every 15 seconds, no
// reconnect storm.
//
// 2026-05-18 (A1 fix): the offset for a given slot is no longer
// deterministic `idx × step` but `idx × step + uniform([-step/2, step/2))`
// via slotStaggerOffset below. The deterministic ladder produced a
// detectable arithmetic-progression signature in TCP-handshake-arrival
// times (FFT peak at 1/step Hz). Additive grid jitter smears that peak
// across a step-wide band while preserving slot ordering in expectation.
const slotRotationStaggerStep = 15 * time.Second

// slotStaggerOffset returns the per-slot rotation timing offset, computed
// as additive grid noise around the deterministic ladder. For slot N:
//
//	offset(N) = N * slotRotationStaggerStep + uniform[-step/2, step/2)
//
// Properties:
//   - offset(0) = 0 always. Slot 0 is the "first" rotation point — never
//     delayed by jitter. This preserves the existing invariant that some
//     tests rely on (e.g. TestRotationWatchdogSweep_RotatesAgedIdleSlot
//     drives slot 0 specifically).
//   - For N ≥ 1: offset is uniform on
//     [N*step - step/2, N*step + step/2). Mean = N*step. Width = step.
//   - Monotonicity in EXPECTATION across slots, NOT strictly per-call.
//     For 8 slots × 15s grid, P(offset(N) > offset(N-1)) ≈ 0.71 per pair
//     (window overlaps by step/2 on each side). Across the whole pool a
//     full reversal is statistically negligible.
//   - FFT effect: the additive grid noise spreads the ladder's spectral
//     peak (was a delta at 1/step) into a band centered at 1/step with
//     width ~1/step. A passive observer collecting ≥100 inter-arrival
//     samples can no longer reject the "irregular" null hypothesis.
//
// Why additive (not multiplicative / not cumulative independent):
//   - Multiplicative `idx × JitteredInterval(step, 0.5)` draws ONE sample
//     and scales it — the inter-slot ratios are preserved deterministically
//     per session, FFT peak survives. (Reviewed in
//     docs/audit/2026-05-18-anti-tspu-debt-review.md as the "single-sample
//     reused" anti-pattern.)
//   - Cumulative independent jitter `Σ_{k=1..idx} JitteredInterval(step, 0.5)`
//     breaks monotonicity outright — slot 7 can land before slot 3.
//   - Additive grid `idx × step + uniform[-step/2, step/2)` keeps slots
//     close to their grid points (monotonicity in expectation) AND breaks
//     the spectral signature. This is the contract used here.
//
// Why NOT JitteredInterval(step/2, 1.0) directly: that helper clamps
// output at base/2 (a sanity floor for the keepalive/backoff use case).
// Here we WANT the full [-step/2, +step/2) range — clamping would skew
// the distribution.
//
// Concurrency: `math/rand/v2`'s package-level Float64 is concurrent-safe
// and allocation-free. Called from rotationWatchdogSweep (single goroutine,
// 5s tick) and from maybeRotateSlot (single reader goroutine per slot
// via readerActive CAS). No hot-path pressure.
func slotStaggerOffset(idx int) time.Duration {
	if idx <= 0 {
		return 0
	}
	base := time.Duration(idx) * slotRotationStaggerStep
	// Float64() ∈ [0, 1.0). Map to [-0.5, 0.5) then to half-open
	// [-step/2, step/2).
	jitter := time.Duration((rand.Float64() - 0.5) * float64(slotRotationStaggerStep))
	return base + jitter
}

// reconnectJitterWindow defines how long after a meltdown event the
// reconnect path applies per-slot handshake jitter. Beyond this window
// (steady-state single-slot rotation), reconnects fire at their normal
// cadence — no added latency.
//
// 5 seconds matches the typical meltdown cooldown (10s default) cut in
// half, giving the post-meltdown reconnect burst a 5s spreading window
// before the next eligible cooldown could fire.
const reconnectJitterWindow = 5 * time.Second

// reconnectJitterStaggerStep is the per-slot offset grid for post-meltdown
// reconnect jitter. With 8 slots × 200ms step, the spread is roughly
// 0 → 1.6s across the pool. The additive grid jitter (±step/2 around
// each grid point) makes inter-slot timing fuzzy on the wire — see
// slotStaggerOffset for the rationale on additive-grid over multiplicative
// or cumulative-independent jitter.
//
// Tuning: 200ms is the smallest spread that visibly defuses a thunder-herd
// of 8 TLS handshakes (typical TCP+TLS handshake completes in 50-150ms,
// so 200ms ensures no two slots are mid-handshake simultaneously). Going
// larger (e.g. 500ms) would extend post-meltdown recovery time linearly
// in pool size — already 1.6s at 200ms, 4s at 500ms. 200ms is the sweet
// spot.
const reconnectJitterStaggerStep = 200 * time.Millisecond

// reconnectJitterOffset returns the per-slot additive grid jitter for
// post-meltdown reconnect spreading. Mirrors slotStaggerOffset but at a
// much smaller scale (200ms step vs 15s step) — handshake spreading is
// a sub-second concern, rotation timing is a multi-minute concern.
//
// Returns 0 for idx ≤ 0 (slot 0 is the "first reconnect" anchor).
// For idx ≥ 1 returns uniform on
//
//	[idx * reconnectJitterStaggerStep - step/2,
//	 idx * reconnectJitterStaggerStep + step/2).
//
// Concurrency: math/rand/v2 package-level Float64 is goroutine-safe.
// Called from reconnectLoop (one goroutine per slot, never concurrent
// for the same slot) so there's no contention even at the RNG level.
func reconnectJitterOffset(idx int) time.Duration {
	if idx <= 0 {
		return 0
	}
	base := time.Duration(idx) * reconnectJitterStaggerStep
	jitter := time.Duration((rand.Float64() - 0.5) * float64(reconnectJitterStaggerStep))
	return base + jitter
}

// slotRotationGraceWithActiveStreams caps how long maybeRotateSlot will
// defer a triggered rotation while active streams are still flowing on
// the slot. Hard limit: after this window, we rotate anyway, because a
// long-lived heavy upload would otherwise pin the slot past the
// middlebox kill window we were trying to avoid.
const slotRotationGraceWithActiveStreams = 30 * time.Second

// rotationStormBrakeFraction is the fraction of the pool that must be
// non-ready (dead, connecting, draining) before maybeRotateSlot pauses
// new preemptive rotations. Computed as ceil(poolSize * fraction).
//
// Rationale (2026-05-18 field observation): under heavy upload load
// (~60 Mbps sustained) every slot exceeds MaxBytesPerSlot within ~1s
// of the speedtest start. All 8 slots enter byte_budget defer in a 6s
// window; 30s later all 8 force-rotate. At the rotation peak, alive=4
// dead=4 — half the pool is reconnecting and the upload writer has
// nowhere to put bytes. Upload speed collapsed 55→16 Mbps observed.
//
// The brake: when ≥ ceil(poolSize * 0.25) slots are already non-ready,
// new rotations defer instead of firing. We do NOT reset the defer
// timestamp — the grace window keeps ticking in the background — so
// the brake doesn't ALSO pin slots past their max-age forever. If the
// brake stays engaged longer than grace, the deferred slot still hits
// force-rotate eventually, but spread out as slots come back online.
//
// 0.25 is chosen so a healthy pool of 8 still permits 2 simultaneous
// rotations (typical steady-state from age-stagger + byte-stagger),
// while clamping at 2 means we never enter the "alive=4 dead=4"
// state observed in the field.
const rotationStormBrakeFraction = 0.25

// effectiveMaxBytesForSlot returns the DETERMINISTIC center of the per-slot
// byte-budget distribution. The actual budget used by the slot reader is
// sampled with jitter around this center via sampleByteBudget below and
// stored once per (re)connect in poolSlot.byteBudget.
//
// Center formula: base + (idx × base / poolSize). For 8 slots × 8 MiB base:
//   slot 0 → 8.0 MiB center, slot 1 → 9.0, ..., slot 7 → 15.0 MiB.
// Spread is exactly +base across the pool (slot N has 2× the budget center
// of slot 0 at the high end), structurally identical to the 2× spread the
// age stagger produces (slot 0 = 2m, slot 7 = 2m + 7×15s = 3m45s before
// clamp).
//
// Returns 0 when base is 0 (feature disabled) — preserving the
// "byte budget off" semantics callers rely on.
func (p *WSPoolTransport) effectiveMaxBytesForSlot(idx int) int64 {
	if p.maxBytesPerSlot <= 0 {
		return 0
	}
	if p.poolSize <= 1 {
		return p.maxBytesPerSlot
	}
	return p.maxBytesPerSlot + (int64(idx)*p.maxBytesPerSlot)/int64(p.poolSize)
}

// byteBudgetJitterLow / byteBudgetJitterHigh bound the multiplicative jitter
// applied to each slot's byte-budget center at connect time. With center =
// effectiveMaxBytesForSlot(idx), the actual budget is sampled uniformly
// from the half-open interval [center * Low, center * High) — Float64
// returns [0, 1), so the upper end is exclusive. The 1-byte gap at the
// high end is irrelevant for byte-budget purposes.
//
// For slot 0 with 8 MiB center: budget ∈ [4 MiB, 16 MiB).
// For slot 7 with 15 MiB center: budget ∈ [7.5 MiB, 30 MiB).
// Aggregate across pool sessions: budget distribution spans ~4-30 MiB,
// smearing the previous deterministic 8/9/.../15 MiB ladder into a wide
// band that no longer reads as a clean bimodal cluster on the wire.
//
// Why uniform (not log-normal): the goal is to make the budget
// distribution look uninformative to an observer counting per-flow bytes
// at session teardown. Uniform on [0.5x, 2x] of the center is wider than
// log-normal would be at sigma=0.5 and computationally cheaper. Real
// browser flows have heavy-tail (Pareto-ish) byte distributions, so
// matching that exactly would require a different sampler — uniform here
// is the lower-effort first cut that already breaks the bimodal pattern
// per Citizen Lab "Stranger DPI in Russia" detection vector.
const (
	byteBudgetJitterLow  = 0.5
	byteBudgetJitterHigh = 2.0
)

// sampleByteBudget returns a freshly sampled byte budget for the given slot
// index. Returns 0 when byte-budget rotation is disabled (maxBytesPerSlot
// = 0, viaCF mode). Otherwise samples uniformly from
// [center * byteBudgetJitterLow, center * byteBudgetJitterHigh] where
// center = effectiveMaxBytesForSlot(idx).
//
// Concurrency: math/rand/v2's package-level Float64 is concurrent-safe and
// allocation-free. No need for a seeded RNG here — this is called once per
// connectSlot, not in any hot path.
//
// Caller contract: invoke ONCE per (re)connect after handshake completes,
// before the slot becomes ready for the reader. Store result in
// slot.byteBudget. Do NOT call from the read loop or watchdog.
func (p *WSPoolTransport) sampleByteBudget(idx int) int64 {
	center := p.effectiveMaxBytesForSlot(idx)
	if center <= 0 {
		return 0
	}
	span := byteBudgetJitterHigh - byteBudgetJitterLow
	multiplier := byteBudgetJitterLow + rand.Float64()*span
	return int64(float64(center) * multiplier)
}

// rotationStormBrakeThreshold returns the minimum count of non-ready
// slots that engages the brake. Always at least 1 so the formula has
// monotonic semantics; clamped to ≥ ceil(poolSize*fraction).
func (p *WSPoolTransport) rotationStormBrakeThreshold() int {
	t := int(float64(p.poolSize)*rotationStormBrakeFraction + 0.5)
	if t < 1 {
		t = 1
	}
	return t
}

// countNonReadySlots returns the count of slots NOT in slotReady that
// contribute to the storm brake calculation. Logic for each cell:
//
//	Primary range [0, poolSize):
//	  - nil cell: check if matching reserve cell[i+poolSize] is in
//	    slotReady — if yes, capacity is provided by reserve, skip;
//	    otherwise count (capacity gap).
//	  - non-slotReady (connecting/draining/dead): count.
//	  - slotReady: skip.
//
//	Reserve range [poolSize, 2*poolSize):
//	  - nil cell: skip (empty space).
//	  - slotConnecting: check if matching primary cell[i-poolSize] is
//	    in slotDraining — if yes, this is the parallel drain replacement
//	    and primary is still serving streams, skip (not a capacity gap);
//	    otherwise count.
//	  - slotDraining/slotDead: count.
//	  - slotReady: skip.
//
// This handles the full drain lifecycle without false-positive non-ready:
//   - Steady state: 8 primary ready, 8 reserve nil → count = 0
//   - Drain start: 7 ready + 1 draining + 1 reserve connecting (parallel) → count = 1
//   - Drain finish: 7 ready + 1 nil primary + 1 reserve ready → count = 0 (reserve covers)
//   - Two concurrent drains: 6 ready + 2 draining + 2 reserve connecting (parallel) → count = 2
//
// Used by storm brake to bound concurrent drains. Lock-free read of
// per-slot atomic state — snapshot-inconsistent reads of paired primary/
// reserve cells are tolerated because the brake re-evaluates on the next
// watchdog sweep (5s later); a single mis-counted tick has at most one
// extra deferred/granted drain, self-correcting.
func (p *WSPoolTransport) countNonReadySlots() int {
	n := 0
	for i, slot := range p.slots {
		if i < p.poolSize {
			// Primary range
			if slot == nil {
				reserveIdx := i + p.poolSize
				if reserveIdx < len(p.slots) && p.slots[reserveIdx] != nil &&
					p.slots[reserveIdx].getState() == slotReady {
					continue // capacity provided by reserve
				}
				n++
				continue
			}
			if slot.getState() != slotReady {
				n++
			}
		} else {
			// Reserve range
			if slot == nil {
				continue
			}
			st := slot.getState()
			if st == slotReady {
				continue
			}
			if st == slotConnecting {
				primaryIdx := i - p.poolSize
				if primaryIdx < p.poolSize && p.slots[primaryIdx] != nil &&
					p.slots[primaryIdx].getState() == slotDraining {
					continue // parallel drain replacement, capacity preserved
				}
			}
			n++
		}
	}
	return n
}

func (s *poolSlot) getState() slotState   { return slotState(s.state.Load()) }
func (s *poolSlot) setState(st slotState) { s.state.Store(int32(st)) }

// tryMarkDead atomically transitions the slot to slotDead from any non-dead
// state. Returns true if THIS caller performed the transition (i.e., the slot
// wasn't already dead). Used by handleSlotDeath to guarantee idempotency —
// without it, a single slot failure can fan out into 2-3 handleSlotDeath calls
// (reader panic + ReadMessage error + writer exit), each inflating the
// meltdown death counter and tripping the threshold artificially.
func (s *poolSlot) tryMarkDead() bool {
	for {
		cur := s.state.Load()
		if slotState(cur) == slotDead {
			return false
		}
		if s.state.CompareAndSwap(cur, int32(slotDead)) {
			return true
		}
	}
}

// shouldExitReader returns true when the reader's captured generation no longer
// matches the slot's current generation — meaning a reconnect happened and a
// new reader has taken over.
func (p *WSPoolTransport) shouldExitReader(slot *poolSlot, capturedGen uint64) bool {
	return slot.generation.Load() != capturedGen
}

// classifyWSReadError maps a terminal slot-reader error to one of the bounded
// labels in frameAnomalyReasons. Used by R.3a diagnostic capture: dashboard
// counters and a structured log line both consume the same classification so
// "what failed?" is a single field across log, metric, and trace.
//
// Order matters — patterns are checked most-specific-first. Documented
// precedence invariants (also asserted in TestClassifyWSReadError_OrderingInvariants):
//   - `closed_local` before `eof` — a Close-then-read race produces both
//     signals and the local-close attribution is more useful for forensics.
//   - `tls` before `eof` — `tls: read EOF on record layer` is a TLS-layer
//     teardown, not raw TCP EOF; misclassifying it as `eof` hides JA3/MAC
//     drift signal.
//   - `reset_by_peer` before `eof` — a hard TCP RST that the kernel surfaces
//     as `connection reset by peer` is distinct from an orderly FIN read as
//     EOF; conflating them would erase the throttle/RST-injection signal.
//   - `io_timeout` before `eof` — a `i/o timeout` carries the same forensic
//     weight as a write deadline expiry and must not be hidden in `other`.
func classifyWSReadError(err error) string {
	if err == nil {
		return "other"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "RSV"):
		// gorilla returns "RSV1 set, RSV2 set, and RSV3 set, none of which is
		// supported" or similar permutations. All collapse to one label —
		// distinguishing 1 vs 2 vs 3 set bits adds cardinality without giving
		// us actionable signal.
		return "rsv"
	case strings.Contains(msg, "bad opcode"):
		return "opcode"
	case strings.Contains(msg, "use of closed network connection"):
		return "closed_local"
	case strings.Contains(msg, "close 1011"):
		return "close_1011"
	case strings.Contains(msg, "message too big"):
		// gorilla "websocket: read limit exceeded — ..." (ErrReadLimit), the
		// canonical close-1009 CloseError (`"websocket: close 1009 (message
		// too big)"`), and synthetic `"message too big"` middlebox responses.
		// MUST come BEFORE "websocket: close" because the close-1009 message
		// also contains the "websocket: close" prefix; otherwise close-1009
		// silently collapses into close_other and we lose the size-violation
		// signal entirely. Distinct from a corrupted-frame rsv/opcode signal
		// — the wire bytes were syntactically valid, just too big.
		return "message_too_big"
	case strings.Contains(msg, "websocket: close"):
		// Other WS close codes (1000/1001/1006/1008/...). 1011 is special
		// above; 1009 (message too big) is special above too.
		return "close_other"
	case strings.Contains(msg, "connection reset by peer"):
		// TCP RST surfaced through the kernel — explicit teardown, distinct
		// from orderly FIN (EOF). Hoster throttle and CDN RST-injection both
		// land here.
		return "reset_by_peer"
	case strings.Contains(msg, "i/o timeout"):
		// Read or write deadline expired without data — distinct from EOF
		// (peer never closed) and from `closed_local` (we didn't Close()).
		// Surface it as its own bucket so dashboards can spot stalled-but-
		// not-torn-down connections (CF/middlebox black-hole).
		return "io_timeout"
	case strings.Contains(msg, "tls:"):
		return "tls"
	case strings.Contains(msg, "EOF"):
		// Covers io.EOF and "unexpected EOF" — both signal TCP teardown.
		return "eof"
	case looksLikeHTTPPrefix(msg):
		// Middlebox (CF edge, hoster reverse proxy, captive portal) returned
		// an HTTP error page on what should have been a WS frame stream.
		// Common signature: gorilla parses leading "<HTML" / "HTTP/" bytes
		// as a frame header and complains about RSV (already caught above)
		// or unexpected payload — but the underlying cause is HTML/text on
		// the wire. Some gorilla versions surface this as "invalid UTF-8"
		// for text frames.
		return "html"
	default:
		return "other"
	}
}

// looksLikeHTTPPrefix returns true when the error message hints that the
// underlying wire contained HTTP/HTML bytes instead of WS frames.
func looksLikeHTTPPrefix(msg string) bool {
	return strings.Contains(msg, "invalid UTF-8") ||
		strings.Contains(msg, "HTTP") ||
		strings.Contains(msg, "<!DOCTYPE") ||
		strings.Contains(msg, "<html")
}

// slotBackoffDuration returns reconnect wait for a per-slot reconnect attempt.
//
// Behavior:
//   - attempt 0: uniform [5s, 10s) — slow-start with broad spread.
//   - attempt N>0: base = 5s × 2^N, jitter [1.0, 2.0), capped at 60s.
//
// Using a 5s base instead of the global 1s base (`backoffDuration`) prevents
// the cascade documented in `docs/strategy/2026-04-30-current-state-and-improvements.md`
// §2.2: 8 slots dying simultaneously and reconnecting at attempt=0 with the
// 1s base would all fire within ~1.25s, blow through the per-IP handshake
// rate limit, and cascade into a 70s backoff cliff. Wider [1.0, 2.0) jitter
// (vs the global ±25%) decorrelates the 8 first-attempts across a 5-10s
// window — comfortable spread under any reasonable handshake rate limit.
//
// Cap is applied AFTER jitter (not on the base) so the worst-case wait the
// user can ever experience is bounded at exactly 60s. This trades a slightly
// less aggressive curve at high attempts for predictable user-visible cap.
//
// Concurrency: math/rand/v2's package-level Float64 is concurrent-safe and
// cheap. No need to manage our own seeded RNG here.
//
// Attempt clamp: pinned at 6 (5s × 2^6 = 320s pre-cap, post-cap 60s) to
// prevent time.Duration overflow at attempt~37+ (May 2026 audit F1).
func slotBackoffDuration(attempt int) time.Duration {
	attempt = min(attempt, 6)
	base := float64(5*time.Second) * math.Pow(2, float64(attempt))
	jitter := 1.0 + rand.Float64() // [1.0, 2.0)
	d := time.Duration(base * jitter)
	if d > 60*time.Second {
		return 60 * time.Second
	}
	return d
}

// WSPoolTransport manages a pool of WebSocket connections for fault tolerance and throughput.
// Implements StreamTransport + PoolAware interfaces.
// Server is unaware of the pool — each WS is an independent tunnel.
type WSPoolTransport struct {
	slots    []*poolSlot
	poolSize int

	maxPendingPerSlot int32 // cap on in-flight CONNECTs per slot
	maxStreamsPerSlot int32 // cap on active streams per slot (0 = unlimited)
	maxBytesPerSlot   int64         // rotate slot after N downstream bytes (0 = disabled)
	maxSlotAge        time.Duration // rotate slot after this much wallclock age (0 = disabled)

	streamMap sync.Map // map[uint16]int — streamID -> slot index

	// For creating new slots
	serverAddr   string
	sniHost      string // override TLS ServerName
	cfIP         string // specific CF edge IP
	useTLS       bool
	skipVerify   bool
	lockedFP     *browser.Fingerprint
	client       *Client       // back-reference for handshake
	writeTimeout time.Duration // per-frame write deadline (0 → 30s WSAsyncWriter default)
	staggerDelay time.Duration // initial/reconnect slot startup spacing (0 → no stagger)

	// Meltdown protection: when multiple slots die within a short window
	// (usually CF punishing an aggressive burst), pause reconnect loops so CF
	// can "cool down" instead of immediately spinning up replacement slots
	// that will get killed again.
	meltdownWindow    time.Duration
	meltdownThreshold int
	meltdownCooldown  time.Duration
	recentDeaths      atomic.Int32
	meltdownUntil     atomic.Int64 // unix nano; reconnects blocked until this time

	// meltdownLimiter rate-limits WARN-level meltdown log emission so the
	// emission cadence is not a deterministic side channel observable from
	// the network. severeMeltdown() additionally suppresses transient drops
	// from the WARN channel; transient events log at debug only.
	meltdownLimiter *rate.Limiter
	meltdownLogRNG  *mrand.Rand
	meltdownLogMu   sync.Mutex // guards meltdownLogRNG (math/rand is not safe for concurrent use)

	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger

	// Diagnostics counters surfaced in the periodic "WS pool health" INFO
	// summary. meltdowns1m: count of meltdown events in the last ~60s,
	// updated by emitMeltdownLog (inc) and a tick goroutine (dec after
	// 60s). rotations1m: count of preemptive rotations fired in the last
	// ~60s — high values indicate aggressive middlebox interference and
	// validate that the watchdog is doing useful work. startedAt is set
	// in NewWSPoolTransport for uptime reporting.
	meltdowns1m atomic.Int32
	rotations1m atomic.Int32
	startedAt   time.Time

	// recentMeltdownNs is the UnixNano timestamp of the most recent
	// meltdown event (set by emitMeltdownLog). Used by reconnectLoop's
	// A2 jitter gate: post-meltdown, when 8 reconnects start nearly
	// simultaneously after the cooldown window, we want to spread them
	// across a few hundred ms so the origin doesn't see a thunder-herd
	// of 8 identical-JA4 TLS handshakes. Routine single-slot rotation
	// (which happens often under steady state) should NOT pay this
	// latency — gating on "meltdown in last 5s" gives us spread when
	// it matters and zero cost when it doesn't.
	//
	// Zero = no meltdown observed yet (initial state). Read with Load;
	// written with Store from emitMeltdownLog only.
	recentMeltdownNs atomic.Int64
}

// Compile-time assertions.
var (
	_ StreamTransport  = (*WSPoolTransport)(nil)
	_ PoolAware        = (*WSPoolTransport)(nil)
	_ PendingTracker   = (*WSPoolTransport)(nil)
	_ ControlPoolAware = (*WSPoolTransport)(nil)
	_ PoolReadiness    = (*WSPoolTransport)(nil)
)

// WSPoolConfig configures the WebSocket pool.
type WSPoolConfig struct {
	Size       int
	ServerAddr string
	UseTLS     bool
	SkipVerify bool
	LockedFP   *browser.Fingerprint
	SNIHost    string // override TLS ServerName (for origin IP with domain SNI)
	CFIP       string // specific CF edge IP (bypass DNS, keep domain as TLS SNI)

	// MaxPendingPerSlot caps in-flight CONNECTs per slot. 0 = default (4).
	MaxPendingPerSlot int

	// MaxStreamsPerSlot caps active streams per slot. 0 = unlimited.
	// For CF CDN mode, set low (4-8) so each WS carries light traffic.
	MaxStreamsPerSlot int

	// MaxBytesPerSlot triggers preemptive rotation after N downstream bytes on
	// a single slot's TCP. 0 = disabled. Critical for Russia TSPU DPI (2026)
	// which silently freezes foreign-IP TCPs after ~15-20KB over TLS 1.3
	// via CF. Direct-mode (origin IP) uses a much larger budget — TSPU's
	// freeze threshold is far higher for direct flows than CF-mediated ones.
	// Recommended: 15*1024 for viaCF mode, 8*1024*1024 (8 MiB) for direct/SNI.
	MaxBytesPerSlot int64

	// MaxSlotAge triggers preemptive rotation after a slot's TCP has been
	// alive for this long, independent of how much data flowed. 0 = disabled.
	//
	// Rationale (2026-05-18 field analysis): direct-mode connections to
	// foreign origin IPs see periodic `close 1006 unexpected EOF` events
	// every 2-5 minutes. The byte-budget alone doesn't catch the case where
	// a long-idle WS is killed by a middlebox per-flow timer (NAT entries,
	// stateful firewalls, TSPU's age-based heuristics). Self-rotating just
	// before the typical kill window keeps the kill signal out of the
	// network path entirely.
	//
	// Recommended: 2 * time.Minute for direct/SNI mode (matches observed
	// slot_age_ms ~3min at moment of close 1006). 0 for viaCF (byte budget
	// alone handles the much shorter TSPU freeze).
	//
	// Per-slot stagger is automatic: slot N rotates at MaxSlotAge + N*15s,
	// so 8 slots ageing simultaneously don't all rotate in the same instant
	// and create a handshake storm.
	MaxSlotAge time.Duration

	// WriteTimeout caps each WS frame's write deadline. 0 → WSAsyncWriter
	// default (30s). For viaCF mode pass 5-8s: CF-side stalls propagate as
	// TCP backpressure, and 30s means a stuck slot blocks traffic for 30s
	// before the pool can route around it. Cross-check 2026-04-15 H6.
	WriteTimeout time.Duration

	// StaggerDelay spaces initial slot handshakes. 0 disables. Recommended
	// ~300ms × slot index so 8 TCP SYNs don't arrive at CF edge in the same
	// millisecond and trip burst/rate-limit heuristics.
	StaggerDelay time.Duration

	// Meltdown protection parameters. All default to sensible values if zero.
	MeltdownWindow    time.Duration // how long "recent death" lasts (default 5s)
	MeltdownThreshold int           // N deaths in window triggers cooldown (default = ceil(size/2), min 2)
	MeltdownCooldown  time.Duration // reconnect pause after trigger (default 10s)
}

// NewWSPoolTransport creates a pool of WebSocket connections.
func NewWSPoolTransport(cl *Client, cfg WSPoolConfig) *WSPoolTransport {
	if cfg.Size < 1 {
		cfg.Size = 2
	}
	if cfg.MaxPendingPerSlot < 1 {
		cfg.MaxPendingPerSlot = defaultMaxPendingPerSlot
	}
	// Meltdown defaults tuned 2026-04-15 after field regression analysis:
	// the old 5s / ceil(size/2) combo turned a transient CF edge hiccup
	// into a self-sustaining outage. Widening the window to 15s and
	// raising the threshold to ⌈3·size/4⌉ means we still pause reconnect
	// when CF is genuinely angry, but don't trip on 4 correlated deaths
	// from one bad edge IP (see DNS-spray finding F4).
	if cfg.MeltdownWindow <= 0 {
		cfg.MeltdownWindow = 15 * time.Second
	}
	if cfg.MeltdownThreshold < 1 {
		cfg.MeltdownThreshold = (cfg.Size*3 + 3) / 4 // ceil(3·size/4)
		if cfg.MeltdownThreshold < 3 {
			cfg.MeltdownThreshold = 3
		}
	}
	if cfg.MeltdownCooldown <= 0 {
		cfg.MeltdownCooldown = 10 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WSPoolTransport{
		slots:             make([]*poolSlot, cfg.Size*2),
		poolSize:          cfg.Size,
		maxPendingPerSlot: int32(cfg.MaxPendingPerSlot),
		maxStreamsPerSlot: int32(cfg.MaxStreamsPerSlot),
		maxBytesPerSlot:   cfg.MaxBytesPerSlot,
		maxSlotAge:        cfg.MaxSlotAge,
		serverAddr:        cfg.ServerAddr,
		sniHost:           cfg.SNIHost,
		cfIP:              cfg.CFIP,
		useTLS:            cfg.UseTLS,
		skipVerify:        cfg.SkipVerify,
		lockedFP:          cfg.LockedFP,
		client:            cl,
		writeTimeout:      cfg.WriteTimeout,
		staggerDelay:      cfg.StaggerDelay,
		meltdownWindow:    cfg.MeltdownWindow,
		meltdownThreshold: cfg.MeltdownThreshold,
		meltdownCooldown:  cfg.MeltdownCooldown,
		meltdownLimiter:   newMeltdownLimiter(),
		meltdownLogRNG:    mrand.New(mrand.NewSource(time.Now().UnixNano())),
		startedAt:         time.Now(),
		ctx:               ctx,
		cancel:            cancel,
		log:               slog.Default(),
	}
}

// allocSlots initializes p.slots as a slice of 2*poolSize cells.
// Indices [0, poolSize) are primary cells, populated by Connect's slot
// initialization loop. Indices [poolSize, 2*poolSize) are reserve cells,
// nil until a drain reserves one via findFreeReserveSlot (Task 8).
//
// Returns error reserved for future failure modes (e.g. ulimit checks).
// Currently never errors but the signature keeps Connect's "if err"
// pattern uniform.
func (p *WSPoolTransport) allocSlots(ctx context.Context) error {
	_ = ctx // reserved for future use (e.g. ulimit / cgroup probe)
	p.slots = make([]*poolSlot, p.poolSize*2)
	return nil
}

// Connect establishes all WS connections in parallel.
// Returns success when at least one slot is ready.
func (p *WSPoolTransport) Connect(ctx context.Context) error {
	if err := p.allocSlots(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	results := make([]error, p.poolSize)

	// Stagger the initial fan-out so N TCP SYNs don't arrive at CF edge in
	// the same millisecond (trips burst/rate-limit heuristics). Same pattern
	// WSReadyPool already uses. Zero staggerDelay → no stagger (direct mode).
	for i := 0; i < p.poolSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx > 0 && p.staggerDelay > 0 {
				select {
				case <-time.After(time.Duration(idx) * p.staggerDelay):
				case <-ctx.Done():
					results[idx] = ctx.Err()
					return
				}
			}
			results[idx] = p.connectSlot(ctx, idx)
		}(i)
	}

	wg.Wait()

	anyReady := false
	for i, err := range results {
		if err == nil {
			anyReady = true
			p.log.Info("WS pool slot ready", "slot", i)
		} else {
			p.log.Warn("WS pool slot failed", "slot", i, "err", err)
			go p.reconnectLoop(i)
		}
	}

	if !anyReady {
		return fmt.Errorf("ws pool: all %d slots failed to connect", p.poolSize)
	}

	go p.rotationLoop()
	go p.keepaliveLoop()
	go p.healthSummaryLoop()
	if p.maxSlotAge > 0 {
		go p.rotationWatchdogLoop()
	}

	return nil
}

// rotationWatchdogLoop ticks at a fixed cadence (independent of downlink
// data arrival) and checks every ready slot's age against its effective
// max-age (MaxSlotAge + slot.staggerOffsetNs, sampled per-session via
// slotStaggerOffset(idx) — see A1 fix 2026-05-18 for the additive-grid
// jitter rationale). When the threshold is reached, the watchdog invokes
// maybeRotateSlot, which respects the active-streams defer logic and the
// grace window.
//
// Why a separate goroutine instead of doing it inline in slotReader:
// slotReader's age check only runs after a successful ReadMessage. On a
// slot that has gone idle (no downlink for tens of seconds) the reader
// blocks until either data arrives OR the 60s read deadline fires. If
// MaxSlotAge passes during that idle blockage, the in-reader check would
// never run before the middlebox kills the TCP — defeating the purpose
// of preemptive rotation. The watchdog ticks every 5s regardless of
// reader activity.
//
// Concurrency: the watchdog reads slot.startedAtNs atomically, then calls
// maybeRotateSlot. maybeRotateSlot writes rotationDeferredNs atomically.
// handleSlotDeath (called from maybeRotateSlot when streams==0) flips
// state atomically. There is no lock contention with slotReader because
// every shared field is atomic.
func (p *WSPoolTransport) rotationWatchdogLoop() {
	const tickInterval = 5 * time.Second
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.rotationWatchdogSweep()
		}
	}
}

// rotationWatchdogSweep performs one pass over all slots, rotating any
// that have exceeded their effective max-age. Extracted from the loop
// so unit tests can drive it deterministically without time.Sleep.
func (p *WSPoolTransport) rotationWatchdogSweep() {
	nowNs := time.Now().UnixNano()
	for idx, slot := range p.slots {
		if slot == nil || slot.getState() != slotReady {
			continue
		}
		started := slot.startedAtNs.Load()
		if started == 0 {
			continue // not yet connected; connectSlot hasn't stamped it
		}
		// Per-slot age threshold = max-age + per-session frozen grid jitter.
		// staggerOffsetNs is sampled ONCE in connectSlot via
		// slotStaggerOffset(idx); re-sampling here every 5s tick would let a
		// slot near its threshold oscillate between "ready" and "not ready"
		// and never converge on a rotation decision.
		effectiveMaxAge := p.maxSlotAge.Nanoseconds() + slot.staggerOffsetNs.Load()
		if nowNs-started < effectiveMaxAge {
			continue
		}
		// Synthesise a slotStart time.Time for the log fields (maybeRotateSlot
		// expects one; we don't have anything but the atomic). This avoids
		// changing maybeRotateSlot's signature for a single log field.
		slotStart := time.Unix(0, started)
		p.maybeRotateSlot(p.client, idx, slot, "age",
			0, // msgCount unknown at watchdog level; the slot reader has the real value
			slotStart,
			slot.downBytes.Load(),
		)
	}
}

// healthSummaryLoop emits one INFO line every 30s with the live pool
// state. Designed to be the one log line an operator needs to look at
// to know if the pool is healthy — alive/dead/rate-limited slot counts,
// total active streams, recent meltdown events, uptime. Independent of
// the existing "shadowlink client stats (delta)" which reports per-
// interval byte counters; this one is structural.
func (p *WSPoolTransport) healthSummaryLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.emitHealthSummary()
		}
	}
}

func (p *WSPoolTransport) emitHealthSummary() {
	alive, dead, connecting, draining := 0, 0, 0, 0
	rateLimited := 0
	var totalStreams int32
	now := time.Now()
	for i, slot := range p.slots {
		if slot == nil {
			// nil primary cell = capacity gap (counts toward "dead"-like
			// for ops visibility). nil reserve cell = empty space (skip).
			if i < p.poolSize {
				dead++
			}
			continue
		}
		switch slot.getState() {
		case slotReady:
			alive++
		case slotDead:
			dead++
		case slotConnecting:
			connecting++
		case slotDraining:
			draining++
		}
		totalStreams += slot.streams.Load()
		// Slot is "rate-limited" from this client's perspective if it died
		// recently AND is still inside the freshness penalty window — that's
		// our best proxy without plumbing X-SL-RL state per-slot.
		if last := slot.lastDeathNs.Load(); last > 0 {
			if now.Sub(time.Unix(0, last)) < slotFreshnessPenaltyWindow {
				rateLimited++
			}
		}
	}
	uptime := time.Since(p.startedAt).Truncate(time.Second)
	p.log.Info("WS pool health",
		"alive", alive,
		"dead", dead,
		"connecting", connecting,
		"draining", draining,
		"rate_limited_recent", rateLimited,
		"active_streams", totalStreams,
		"meltdowns_1m", p.meltdowns1m.Load(),
		"rotations_1m", p.rotations1m.Load(),
		"uptime", uptime,
	)
}

// keepaliveLoop sends FlagKeepalive to every healthy slot at a jittered
// ~20s cadence. The base interval prevents Cloudflare Proxy Write Timeout
// (30s) and Idle Timeout (900s) from killing long-lived WebSocket
// connections; the log-normal jitter (final-audit-2026-05-03 P1-3,
// upgraded from uniform ±30% NEW-1 fix) destroys the FFT-visible
// periodic peak AND defeats ML classifiers that distinguish flat-band
// uniform jitter from heavy-tailed real-world inter-frame jitter.
func (p *WSPoolTransport) keepaliveLoop() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(JitteredIntervalLogNormal(20*time.Second, 0.5)):
			p.sendKeepaliveToAllSlots()
		}
	}
}

func (p *WSPoolTransport) sendKeepaliveToAllSlots() {
	sent := 0
	for i := 0; i < p.poolSize; i++ {
		slot := p.slots[i]
		if slot == nil || slot.getState() != slotReady || slot.transport == nil || slot.session == nil {
			continue
		}
		// Each slot has its own crypto session — must use slot.session, not global client session.
		chunk := core.NewKeepaliveChunk(slot.session.ID, slot.session.NextSeqNum())
		enc, err := slot.session.EncryptChunk(chunk)
		if err != nil {
			continue
		}
		if writeErr := slot.transport.WriteControlMessage(enc); writeErr != nil {
			p.log.Debug("keepalive write failed", "slot", i, "err", writeErr)
		} else {
			sent++
		}
	}
	if sent > 0 {
		Trace("keepalive sent", "slots", sent)
	}
}

// connectSlot creates a new WS connection for the given slot index.
func (p *WSPoolTransport) connectSlot(ctx context.Context, idx int) error {
	slot := &poolSlot{index: idx}
	slot.setState(slotConnecting)
	p.slots[idx] = slot

	// Perform handshake to get a new session
	hello, clientState, err := core.NewClientHello(p.client.clientID, p.client.serverPub)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: create hello: %w", idx, err)
	}

	respBody, err := p.client.transport.SendHandshake(ctx, hello)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: handshake: %w", idx, err)
	}

	respData, _, err := browser.ParseDownloadResponse(respBody)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: parse hello: %w", idx, err)
	}

	// `_v` MUST be threaded into core.ServerHello so CompleteHandshake picks the
	// matching key schedule. Server's handleHandshakeNew derives keys with
	// protoVersion=1; if we drop `_v` here, CompleteHandshake silently defaults
	// to protoVersion=0 (legacy) and the resulting keys diverge byte-for-byte
	// from the server's — every pool slot then fails with "cannot decrypt
	// session token" (datacanvases.com data-plane drift, 2026-04-30).
	var shData struct {
		EphPub       []byte `json:"eph"`
		Token        []byte `json:"tok"`
		MaxConns     uint8  `json:"mc"`
		ChunkSize    uint16 `json:"cs"`
		ProtoVersion *uint8 `json:"_v,omitempty"`
	}
	if err := json.Unmarshal(respData, &shData); err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: unmarshal hello: %w", idx, err)
	}

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
		ProtoVersion:          shData.ProtoVersion,
	}

	session, err := core.CompleteHandshake(clientState, serverHello)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: complete handshake: %w", idx, err)
	}

	slot.session = session
	slot.token = browser.EncodeTokenWithHint(session.ID, shData.Token)

	// Create WS transport and upgrade
	wst := NewWebSocketTransport(p.serverAddr, p.useTLS, p.skipVerify, p.lockedFP)
	wst.sniHost = p.sniHost // SNI trick: domain as ServerName when connecting to origin IP
	wst.cfIP = p.cfIP       // CF edge IP override: bypass DNS, keep domain as TLS SNI
	if p.writeTimeout > 0 {
		wst.SetWriteTimeout(p.writeTimeout) // viaCF: 5-8s, direct: 0 (→ 30s default)
	}
	if idx == 0 {
		wst.WarmupRequests() // Only warmup for first slot (looks natural)
	}
	// D3: ws upgrade now authenticates via a post-upgrade first frame built
	// from the slot's session — Bearer header is gone.
	if err := wst.UpgradeToWS(slot.token, slot.session); err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: ws upgrade: %w", idx, err)
	}

	slot.transport = wst
	// Reset downstream byte counter — fresh TCP starts the TSPU 15-20KB budget over.
	slot.downBytes.Store(0)
	// Reset rotation deferral — fresh TCP, no pending rotation to honour.
	slot.rotationDeferredNs.Store(0)
	// Sample THIS connection's byte budget once and freeze it for the slot
	// lifetime. The reader compares down_bytes against this value, never
	// against a recomputed-per-frame threshold (would cause spurious
	// instant-rotation when a fresh sample lands below current total).
	// Aggregate distribution across many sessions smears the previous
	// deterministic 8/9/.../15 MiB ladder into a wide 4-30 MiB band —
	// see byteBudgetJitterLow/High constants for rationale.
	slot.byteBudget.Store(p.sampleByteBudget(idx))
	// Sample additive grid jitter for rotation timing once per (re)connect.
	// Re-sampling per watchdog tick would let a slot near its age threshold
	// oscillate between "ready" and "not ready" — see slotStaggerOffset
	// docstring. Stored as nanoseconds (int64) so the watchdog can do raw
	// arithmetic with maxSlotAge.Nanoseconds().
	slot.staggerOffsetNs.Store(int64(slotStaggerOffset(idx)))
	// Stamp the slot's startup time — both the reader's local age check and
	// the pool-level rotation watchdog goroutine read this. Set BEFORE
	// setState(slotReady) so the watchdog never observes a ready slot with
	// startedAtNs=0.
	slot.startedAtNs.Store(time.Now().UnixNano())
	// Reset reader-active flag so the next slotReader can CAS into ownership.
	// At this point the previous reader either:
	//   (a) was never running for this slot (initial connect), or
	//   (b) had its conn Close()d by handleSlotDeath, observed the error in
	//       ReadMessage, and is on its way out via the deferred CAS-to-false.
	// We can't strictly wait for (b)'s defer to fire — that would require
	// SUB ms-level synchronization between handleSlotDeath and the new reader
	// startup. Forcing the flag false here is safe because the OLD transport
	// pointer the old reader still holds is already torn down; even if a
	// transient duplicate ran for a few iterations on the same `slot`, both
	// would call myTransport.ReadMessage on different underlying conns. The
	// generation check in the reader (shouldExitReader) handles the rest.
	slot.readerActive.Store(false)
	// Bump generation BEFORE marking ready so any old reader checking
	// generation after this point exits cleanly. The new reader (started by
	// the caller) will capture the new generation at its first check.
	slot.generation.Add(1)
	slot.setState(slotReady)
	return nil
}

// reconnectLoop tries to reconnect a dead slot with exponential backoff.
// If meltdown cooldown is active (triggered by multiple recent slot deaths),
// the loop waits for it to elapse before attempting to reconnect. This
// prevents a spiral where CF rejects replacement slots as fast as they are
// created, keeping it under load and making recovery slower.
//
// Task A2 (May audit): if connectSlot surfaces ErrRateLimited (server
// emitted X-SL-RL: 1 from its rate-limit branch), the loop applies a fixed
// 180s ± 30% cool-down INSTEAD of exp backoff and resets the attempt counter
// to 0 afterwards. Resetting the counter prevents the cool-down from being
// stacked on top of an already-aged exp curve — after a rate-limit event
// we want a clean slow-start, not "5s × 2^N + 180s".
func (p *WSPoolTransport) reconnectLoop(idx int) {
	for attempt := 0; ; attempt++ {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		if wait := p.meltdownWaitDuration(); wait > 0 {
			p.log.Info("WS pool meltdown cooldown — pausing reconnect",
				"slot", idx, "wait", wait)
			timer := time.NewTimer(wait)
			select {
			case <-p.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}

		// A2 (2026-05-18): post-meltdown handshake spreading. When 8
		// reconnect goroutines exit the cooldown together, without jitter
		// they fire 8 identical-JA4 TLS handshakes to origin within
		// milliseconds — a thunder-herd signature observable by any
		// per-source-IP TLS counter at the origin (or on path). The
		// per-slot offset spreads them across ~0-1.6s on a poolSize=8.
		//
		// Gate on attempt==0 && idx > 0 AND a recent meltdown timestamp:
		//   - attempt > 0 retries already have exp backoff jitter.
		//   - idx == 0 is the anchor reconnect, fires immediately.
		//   - No recent meltdown (steady-state single-slot rotation) skips
		//     the spread — it'd just add latency for no benefit.
		if attempt == 0 && idx > 0 {
			if last := p.recentMeltdownNs.Load(); last > 0 {
				since := time.Since(time.Unix(0, last))
				if since < reconnectJitterWindow {
					jitter := reconnectJitterOffset(idx)
					p.log.Debug("WS pool post-meltdown reconnect jitter",
						"slot", idx, "jitter", jitter, "since_meltdown", since.Truncate(time.Millisecond))
					sleepWithCancel(p.ctx, jitter)
				}
			}
		}

		d := slotBackoffDurationForTest(attempt)
		p.log.Debug("WS pool reconnecting slot", "slot", idx, "backoff", d, "attempt", attempt)

		timer := time.NewTimer(d)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		var connectErr error
		if connectSlotForTest != nil {
			// Test seam — see ws_pool.go::connectSlotForTest. Production
			// builds never enter this branch because nothing assigns the var.
			connectErr = connectSlotForTest()
		} else {
			connectErr = p.connectSlot(p.ctx, idx)
		}

		if connectErr == nil {
			p.log.Info("WS pool slot reconnected", "slot", idx)
			go p.slotReader(idx)
			return
		}

		// Task A2: typed sentinel — server told us we're rate-limited.
		// Honor Signal.RefillIn when present (Phase 2 fix); fall back to
		// fixed 180s ± 30% otherwise.
		//
		// 2026-05-18 — DO NOT reset attempt counter after rate-limit. The
		// old behavior (attempt = -1) made the next retry fire at attempt=0
		// backoff (5-10s), which under sustained server-side TokenBucket
		// pressure (other slots still consuming burst) walked straight back
		// into another rate-limit response and looped indefinitely. Letting
		// attempt keep growing means after a 180s server cooldown we add a
		// slot-local backoff that grows exp until the slotBackoffDuration
		// cap (60s, attempt=6 clamp). That gives the server time to refill.
		if errors.Is(connectErr, ErrRateLimited) {
			Stats.RateLimitedFromServer.Add(1)
			var cooldown time.Duration
			var rlErr *RateLimitError
			if errors.As(connectErr, &rlErr) && rlErr.Signal != nil && rlErr.Signal.RefillIn > 0 {
				cooldown = clampRefillIn(rlErr.Signal.RefillIn)
				cooldown = JitteredInterval(cooldown, 0.30)
				p.log.Info("WS pool slot rate-limited by server (server-directed cooldown)",
					"slot", idx,
					"carrier", rlErr.Signal.Carrier,
					"bucket", rlErr.Signal.Bucket,
					"refill_in_server", rlErr.Signal.RefillIn,
					"cooldown_applied", cooldown,
				)
			} else {
				cooldown = slotRateLimitedCooldownForTest()
				p.log.Info("WS pool slot rate-limited by server (fallback fixed cooldown)",
					"slot", idx,
					"cooldown_applied", cooldown,
				)
			}
			sleepWithCancel(p.ctx, cooldown)
			continue
		}

		p.log.Warn("WS pool slot reconnect failed", "slot", idx, "err", connectErr)
	}
}

// newMeltdownLimiter returns a token-bucket limiter capping meltdown WARN
// log emission at 1 per 10s with burst 3. Public-from-package for tests.
//
// Closes A2-MED-10: deterministic-cadence meltdown WARN emissions used to
// be a passive timing side channel observable from the network (DPI could
// correlate connection drops with predictable log timing). Token bucket +
// jittered emit + severity gate together obscure the timing fingerprint.
func newMeltdownLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Every(10*time.Second), 3)
}

// severeMeltdown returns true when at least half the pool is dead. Below
// this threshold, transient drops emit debug-only and are suppressed from
// WARN-level log channels — preventing single-slot blips from triggering a
// WARN that an attacker could correlate with their network probe.
func severeMeltdown(dead, total int) bool {
	if total <= 0 {
		return false
	}
	return dead*2 >= total
}

// countDeadSlots returns the number of slots currently in slotDead state and
// the pool size. Lock-free read of per-slot atomics.
func (p *WSPoolTransport) countDeadSlots() (dead, total int) {
	total = p.poolSize
	for _, slot := range p.slots {
		if slot == nil {
			// Nil slot has not been initialized yet — treat as not-yet-alive,
			// which for meltdown reporting purposes does not count as dead.
			continue
		}
		if slot.getState() == slotDead {
			dead++
		}
	}
	return dead, total
}

// meltdownLogJitter returns a [0.5×base, 1.5×base) duration sampled from the
// pool's RNG. Caller must NOT hold meltdownLogMu — this method takes it.
func (p *WSPoolTransport) meltdownLogJitter(base time.Duration) time.Duration {
	p.meltdownLogMu.Lock()
	defer p.meltdownLogMu.Unlock()
	if p.meltdownLogRNG == nil {
		return base
	}
	return time.Duration(0.5*float64(base) + p.meltdownLogRNG.Float64()*float64(base))
}

// meltdownWaitDuration returns how long the reconnect must still wait before
// the cooldown elapses, or 0 if no cooldown is active.
func (p *WSPoolTransport) meltdownWaitDuration() time.Duration {
	until := p.meltdownUntil.Load()
	if until == 0 {
		return 0
	}
	wait := time.Until(time.Unix(0, until))
	if wait <= 0 {
		return 0
	}
	return wait
}

// recordSlotDeath tracks slot deaths within a rolling window and triggers a
// meltdown cooldown if the threshold is exceeded. Called from handleSlotDeath.
func (p *WSPoolTransport) recordSlotDeath() {
	deaths := p.recentDeaths.Add(1)

	// Schedule decrement after the window so old deaths age out.
	go func() {
		timer := time.NewTimer(p.meltdownWindow)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			p.recentDeaths.Add(-1)
		}
	}()

	if int(deaths) >= p.meltdownThreshold {
		// Flat cooldown: once a meltdown cooldown is set, additional deaths
		// inside the active window only update the counter (already done
		// above) — they do NOT extend the cooldown. Previously, every new
		// death in the window pushed meltdownUntil forward by 10s from "now",
		// which under sustained churn (≥6 deaths/15s — the exact rate seen
		// in field logs 2026-05-18) kept reconnect paused indefinitely.
		// We only set meltdownUntil when no prior cooldown is active.
		nowNs := time.Now().UnixNano()
		until := nowNs + p.meltdownCooldown.Nanoseconds()
		if prev := p.meltdownUntil.Load(); prev == 0 || nowNs >= prev {
			if p.meltdownUntil.CompareAndSwap(prev, until) {
				p.emitMeltdownLog(int(deaths))
			}
		}
	}
}

// emitMeltdownLog dispatches the meltdown WARN log through a rate-limited,
// severity-gated, jittered path. Closes A2-MED-10:
//
//   - Severity gate (severeMeltdown): single-slot or otherwise-transient
//     pool drops never surface at WARN; they emit at debug only.
//   - Token-bucket rate limit (meltdownLimiter): max 1 per 10s with burst 3,
//     capping the rate at which any meltdown WARN can be observed from the
//     network even under sustained churn.
//   - Jitter (meltdownLogJitter): the WARN emit is delayed by a random
//     [0.5×, 1.5×) × 5s draw, so the arrival timing is not a deterministic
//     function of the underlying death event.
func (p *WSPoolTransport) emitMeltdownLog(deathsInWindow int) {
	// A2 (2026-05-18): stamp the meltdown timestamp before bumping the
	// counter. reconnectLoop reads this via recentMeltdownNs.Load() and
	// gates per-slot handshake jitter on it. Stamping FIRST means the
	// jitter gate sees a fresh timestamp even if the 1m counter goroutine
	// hasn't started yet.
	p.recentMeltdownNs.Store(time.Now().UnixNano())
	// Bump 1-minute counter for the periodic health summary. Decrement is
	// scheduled in a separate goroutine after 60s — keeps the counter as a
	// rolling window without needing a ring buffer or explicit timestamps.
	p.meltdowns1m.Add(1)
	go func() {
		timer := time.NewTimer(60 * time.Second)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			p.meltdowns1m.Add(-1)
		}
	}()

	dead, total := p.countDeadSlots()

	if !severeMeltdown(dead, total) {
		// Transient: never surface to WARN, debug only. Side-channel-quiet.
		p.log.Debug("transient pool drop (suppressed from WARN)",
			"dead", dead,
			"total", total,
			"deaths_in_window", deathsInWindow,
			"threshold", p.meltdownThreshold)
		return
	}

	if !p.meltdownLimiter.Allow() {
		// Severity threshold met but emit budget exhausted — coalesce silently.
		p.log.Debug("meltdown WARN rate-limited",
			"dead", dead,
			"total", total,
			"deaths_in_window", deathsInWindow)
		return
	}

	jitter := p.meltdownLogJitter(5 * time.Second)
	go func(deathsInWindow, dead, total int, jitter time.Duration) {
		timer := time.NewTimer(jitter)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
			return
		case <-timer.C:
		}
		p.log.Warn("WS pool meltdown detected — entering cooldown",
			"deaths_in_window", deathsInWindow,
			"dead", dead,
			"total", total,
			"threshold", p.meltdownThreshold,
			"window", p.meltdownWindow,
			"cooldown", p.meltdownCooldown,
			"emit_jitter", jitter)
	}(deathsInWindow, dead, total, jitter)
}

// rotationLoop periodically rotates one slot for anti-fingerprinting.
func (p *WSPoolTransport) rotationLoop() {
	for {
		delay := 2*time.Minute + time.Duration(rand.Int64N(int64(6*time.Minute)))
		timer := time.NewTimer(delay)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		p.rotateOneSlot()
	}
}

// rotateOneSlot soft-rotates the slot with fewer active streams.
func (p *WSPoolTransport) rotateOneSlot() {
	minIdx := -1
	minStreams := int32(1<<31 - 1)
	for i, slot := range p.slots {
		if slot == nil || slot.getState() != slotReady {
			continue
		}
		s := slot.streams.Load()
		if s < minStreams {
			minStreams = s
			minIdx = i
		}
	}

	if minIdx < 0 {
		return
	}

	slot := p.slots[minIdx]
	slot.setState(slotDraining)
	p.log.Info("WS pool rotating slot", "slot", minIdx, "activeStreams", minStreams)

	// Wait for streams to drain (max 30s)
	deadline := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-deadline:
			goto reconnect
		case <-ticker.C:
			if slot.streams.Load() == 0 {
				goto reconnect
			}
		}
	}

reconnect:
	if slot.transport != nil {
		slot.transport.Close()
	}
	if slot.session != nil {
		slot.session.Destroy()
	}

	if err := p.connectSlot(p.ctx, minIdx); err != nil {
		p.log.Warn("WS pool rotation reconnect failed", "slot", minIdx, "err", err)
		go p.reconnectLoop(minIdx)
		return
	}

	go p.slotReader(minIdx)
	p.log.Info("WS pool slot rotated", "slot", minIdx)
}

// AssignStream assigns a streamID to the least-loaded ready slot.
// Prefers slots with fewer pending CONNECTs to distribute load evenly
// across CF CDN connections.
//
// Selection algorithm (two-pass):
//
//  1. PASS-1 ("non-fresh preferred"): walk all slotReady slots, skip the
//     ones inside slotFreshnessPenaltyWindow of their last death, pick
//     the minimum score among the rest. If at least one non-fresh ready
//     slot exists with spare capacity, the stream lands there.
//
//  2. PASS-2 ("fresh allowed"): if pass-1 found nothing, walk again but
//     this time include freshly-reconnected slots. The penalty is dropped
//     because there is no "non-fresh" alternative — applying it would
//     either pick the same slot or fall through to the no-capacity branch
//     unnecessarily. This avoids the failure mode where every slot just
//     reconnected from a meltdown wave and AssignStream artificially
//     refuses to use any of them.
//
//  3. CAPACITY OVERFLOW: if every slot is at maxStreamsPerSlot, soft-
//     overflow onto the slot with fewest active streams. Last-resort
//     fallback: any non-nil slot at all (typically slotConnecting), so a
//     SOCKS5 CONNECT request never silently disappears.
func (p *WSPoolTransport) AssignStream(streamID uint16) {
	pickInPass := func(allowFresh bool) (idx int, score int32) {
		idx = -1
		score = int32(1<<31 - 1)
		nowNs := time.Now().UnixNano()
		windowNs := slotFreshnessPenaltyWindow.Nanoseconds()
		for i, slot := range p.slots {
			if slot == nil || slot.getState() != slotReady {
				continue
			}
			streams := slot.streams.Load()
			if p.maxStreamsPerSlot > 0 && streams >= p.maxStreamsPerSlot {
				continue
			}
			if !allowFresh {
				if lastDeath := slot.lastDeathNs.Load(); lastDeath > 0 {
					if nowNs-lastDeath < windowNs {
						continue
					}
				}
			}
			pending := slot.pendingConnects.Load()
			s := pending*4 + streams
			if s < score {
				score = s
				idx = i
			}
		}
		return idx, score
	}

	minIdx, _ := pickInPass(false)
	if minIdx < 0 {
		minIdx, _ = pickInPass(true)
	}

	if minIdx < 0 {
		// All slots at capacity — pick the slot with fewest streams (soft overflow).
		minStreams := int32(1<<31 - 1)
		for i, slot := range p.slots {
			if slot == nil || slot.getState() != slotReady {
				continue
			}
			s := slot.streams.Load()
			if s < minStreams {
				minStreams = s
				minIdx = i
			}
		}
		if minIdx < 0 {
			// Truly no ready slots — last resort fallback.
			for i, slot := range p.slots {
				if slot != nil {
					minIdx = i
					break
				}
			}
		}
		if minIdx < 0 {
			p.log.Warn("stream assign: no slots available", "stream", streamID)
			return
		}
	}

	p.streamMap.Store(streamID, minIdx)
	p.slots[minIdx].streams.Add(1)
	Trace("stream assigned", "stream", streamID, "slot", minIdx,
		"pending", p.slots[minIdx].pendingConnects.Load(),
		"streams", p.slots[minIdx].streams.Load())
}

// IncrPending increments the pending CONNECT counter for the stream's assigned slot.
func (p *WSPoolTransport) IncrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].pendingConnects.Add(1)
		}
	}
}

// DecrPending decrements the pending CONNECT counter for the stream's assigned slot.
func (p *WSPoolTransport) DecrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].pendingConnects.Add(-1)
		}
	}
}

// SlotPending returns pending CONNECT count for the stream's assigned slot.
func (p *WSPoolTransport) SlotPending(streamID uint16) int32 {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].pendingConnects.Load()
		}
	}
	return 0
}

// AllSlotsAtMaxPending returns true when every ready slot has >= maxPendingPerSlot pending CONNECTs.
// Returns false when no slots are ready (don't block — let AssignStream fallback handle it).
func (p *WSPoolTransport) AllSlotsAtMaxPending() bool {
	anyReady := false
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady {
			anyReady = true
			if slot.pendingConnects.Load() < p.maxPendingPerSlot {
				return false
			}
		}
	}
	if !anyReady {
		return false // No ready slots — don't block, let the CONNECT fail fast downstream
	}
	return true
}

// ReleaseStream removes stream assignment.
func (p *WSPoolTransport) ReleaseStream(streamID uint16) {
	if v, ok := p.streamMap.LoadAndDelete(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].streams.Add(-1)
		}
	}
}

// SessionForStream returns the crypto session for the stream's assigned slot.
func (p *WSPoolTransport) SessionForStream(streamID uint16) *core.Session {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].session
		}
	}
	// Fallback: return first available session from primary range only.
	// Reserve slots have their own sessions belonging to specific drain
	// replacements; using a reserve session for a stream not assigned to
	// that slot would yield decrypt mismatches at the server.
	for i, slot := range p.slots {
		if i >= p.poolSize {
			break
		}
		if slot != nil && slot.session != nil && slot.getState() == slotReady {
			return slot.session
		}
	}
	return nil
}

// WriteMessageForStream sends a data frame to the slot assigned to this
// stream.
//
// A stream-bound write accepts both slotReady AND slotDraining as valid
// targets: once a stream has been assigned to a slot, its crypto session
// lives on THAT slot's transport. If the slot transitions to slotDraining
// (preemptive rotation, byte-budget exhaustion, etc.), existing streams
// MUST continue routing frames through it until they finish naturally or
// the drain teardown unbinds them. Falling back to a random ready slot
// here would route the frame through a different crypto session, and the
// server would fail to decrypt (different per-slot session key) — see
// spec C1 in docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md.
//
// Only when the assigned slot is genuinely unusable (nil, no transport,
// or in slotConnecting/slotDead) do we fall back to WriteMessage, which
// scans for any ready slot and is reserved for non-stream traffic.
func (p *WSPoolTransport) WriteMessageForStream(streamID uint16, data []byte) error {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.transport != nil {
				st := slot.getState()
				if st == slotReady || st == slotDraining {
					return slot.transport.WriteMessage(data)
				}
			}
		}
	}
	return p.WriteMessage(data)
}

// WriteControlMessageForStream sends a control frame (CONNECT, FIN) with
// high priority to the slot assigned to this stream.
//
// Same draining-acceptance contract as WriteMessageForStream: a stream's
// control frames must travel over the same crypto session as its data
// frames. See WriteMessageForStream docstring for the full rationale and
// spec reference.
func (p *WSPoolTransport) WriteControlMessageForStream(streamID uint16, data []byte) error {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.transport != nil {
				st := slot.getState()
				if st == slotReady || st == slotDraining {
					return slot.transport.WriteControlMessage(data)
				}
			}
		}
	}
	return p.WriteControlMessage(data)
}

// WriteMessage sends a data frame to a random ready slot (for non-stream data).
func (p *WSPoolTransport) WriteMessage(data []byte) error {
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady && slot.transport != nil {
			return slot.transport.WriteMessage(data)
		}
	}
	return fmt.Errorf("ws pool: no ready slots")
}

// WriteControlMessage sends a control frame to a random ready slot.
func (p *WSPoolTransport) WriteControlMessage(data []byte) error {
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady && slot.transport != nil {
			return slot.transport.WriteControlMessage(data)
		}
	}
	return fmt.Errorf("ws pool: no ready slots")
}

// StartReader starts background readers for all connected slots.
// Returns when ALL readers die or context is cancelled.
func (p *WSPoolTransport) StartReader(ctx context.Context, cl *Client) error {
	var wg sync.WaitGroup
	errCh := make(chan error, p.poolSize)

	for i := 0; i < p.poolSize; i++ {
		if p.slots[i] == nil || p.slots[i].getState() != slotReady {
			continue
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p.slotReaderWithClient(ctx, cl, idx)
		}(i)
	}

	go func() {
		wg.Wait()
		select {
		case errCh <- fmt.Errorf("all slot readers exited"):
		default:
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// slotReader runs a reader for a slot (used for reconnected slots).
func (p *WSPoolTransport) slotReader(idx int) {
	p.slotReaderWithClient(p.ctx, p.client, idx)
}

// slotReaderWithClient runs the WS reader for a specific slot.
// On error: marks slot dead, closes affected streams, triggers reconnect.
//
// Captures slot.generation at start and bails out (without touching the
// transport) when generation advances — meaning the slot was reconnected
// and a newer reader has taken over. This prevents the gorilla "repeated
// read on failed websocket connection" panic that occurs when two readers
// race on the same conn.
func (p *WSPoolTransport) slotReaderWithClient(ctx context.Context, cl *Client, idx int) {
	slot := p.slots[idx]
	if slot == nil || slot.transport == nil {
		return
	}

	// CAS-gate against duplicate readers on the same slot. Two reader
	// goroutines can be scheduled for one slot when:
	//   1. reconnectLoop finishes connectSlot and calls `go p.slotReader(idx)`
	//      (ws_pool.go ~line 802) to attach a reader to the new conn.
	//   2. Concurrently, the outer engine's streamReaderLoop has observed
	//      "all slot readers exited" on a *previous* generation and calls
	//      pool.StartReader again, which walks all slotReady slots and
	//      starts goroutines for each (ws_pool.go::StartReader).
	// Both end up here for the same idx, with the same transport pointer
	// and the same generation. Without this gate, two ReadMessage calls
	// race on the same *gorilla.Conn — gorilla's frame parser observes the
	// byte-interleaved stream and reports `RSV1/RSV2/RSV3 set`, `bad
	// opcode N`, `continuation after FIN` — exactly the anomaly pattern
	// captured in field logs 2026-05-18 right after a poll-fallback
	// restart. Failing the CAS means another reader already owns the
	// slot; we exit silently without touching the conn.
	if !slot.readerActive.CompareAndSwap(false, true) {
		Trace("WS pool slot reader skipped — already active", "slot", idx)
		return
	}
	defer slot.readerActive.Store(false)

	// Capture transport pointer at reader start. The slot's transport field is
	// reassigned on rotation and replaced wholesale on reconnect (which creates
	// a new poolSlot at p.slots[idx]); reading slot.transport on every loop
	// iteration races with these mutations and could deliver the new conn to a
	// stale reader. Holding our own captured pointer means a stale reader keeps
	// reading from the OLD conn (which is Close'd by handleSlotDeath /
	// rotation), gets "use of closed network connection", and exits cleanly.
	// The new reader started after reconnect uses its own freshly captured
	// transport — paired with readerActive CAS, no two readers ever share
	// a *gorilla.Conn.
	myTransport := slot.transport
	myGen := slot.generation.Load()
	slotStart := time.Now()
	mode := "direct"
	if p.cfIP != "" {
		mode = "cf"
	}

	p.log.Info("WS pool slot reader started", "slot", idx, "gen", myGen, "mode", mode)

	defer func() {
		if r := recover(); r != nil {
			p.log.Warn("WS pool slot reader panic recovered", "slot", idx, "panic", r)
			// Only initiate slot death if our generation is still active.
			// A panic on a stale generation means we lost a race with a
			// reconnect; the new reader/transport must not be torn down.
			if !p.shouldExitReader(slot, myGen) {
				p.handleSlotDeath(cl, idx, deathCauseNatural)
			}
		}
	}()

	msgCount := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Generation check: if the slot was reconnected, a newer reader
		// owns the new transport — exit silently to avoid concurrent
		// ReadMessage on the same conn.
		if p.shouldExitReader(slot, myGen) {
			Trace("WS pool slot reader exiting — slot reconnected",
				"slot", idx, "captured_gen", myGen, "current_gen", slot.generation.Load())
			return
		}

		// Read deadline 60s: under heavy upload load the writer keeps the
		// gorilla send buffer warm, but a downlink-quiet window can briefly
		// exceed 30s if keepalive scheduling jitters into a slow writer.
		// 60s gives slack while still tripping well before nginx's default
		// proxy_read_timeout=60s on the origin (which itself should be raised
		// to ~900s on the server side — orthogonal fix, see deploy docs).
		data, err := myTransport.ReadMessage(60 * time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// If the slot was reconnected during our blocking ReadMessage, the
			// error is from the OLD (closed) conn — don't treat it as a death
			// of the new slot. Just exit.
			if p.shouldExitReader(slot, myGen) {
				return
			}
			// Phase −1 hotfix (2026-05-14): any read error is terminal.
			// Previously: `continue` on Timeout()==true created a tight loop
			// because gorilla/websocket v1.5.3 caches readErr (sticky), so
			// every subsequent ReadMessage() returns the same timeout without
			// blocking. After ~1000 iterations gorilla triggers a defensive
			// panic "repeated read on failed websocket connection".
			// Treating timeout as terminal moves the slot to handleSlotDeath
			// → reconnect, which is correct. Supervisor refactor (Phase 3)
			// makes this structurally enforced.
			// Terminal (non-timeout) reader error — attribute slot death.
			// If this correlates with writer_exits in stats, CF-side stalls
			// are the trigger (H6); if writer_exits stays low and
			// reader_exits climbs, the server or CF edge is actively
			// closing our TCP.
			Stats.ReaderExits.Add(1)

			// R.3a frame-anomaly diagnostic capture: classify the error and
			// log a structured record that pairs human review (the WARN line)
			// with a counter slice (`shadowlink_ws_frame_anomaly_total{type=}`).
			// `last_write_age_ms` distinguishes "conn was idle" (writer
			// exited or stalled) from "write was in flight" (suggests
			// middlebox interfering with active traffic).
			anomaly := classifyWSReadError(err)
			Stats.IncFrameAnomaly(anomaly)
			lastWriteAgeMs := int64(-1)
			if lw := myTransport.LastWriteUnixNano(); lw > 0 {
				lastWriteAgeMs = (time.Now().UnixNano() - lw) / int64(time.Millisecond)
			}
			p.log.Warn("WS pool slot reader error",
				"slot", idx,
				"err", err,
				"anomaly", anomaly,
				"messages", msgCount,
				"slot_age_ms", time.Since(slotStart).Milliseconds(),
				"down_bytes", slot.downBytes.Load(),
				"last_write_age_ms", lastWriteAgeMs,
				"writer_exits", Stats.WriterExits.Load(),
				"mode", mode,
			)
			p.handleSlotDeath(cl, idx, deathCauseNatural)
			return
		}

		// Preemptive byte-based rotation. budget = 0 → feature disabled
		// (viaCF mode). See poolSlot.byteBudget docstring for the jitter
		// rationale and the "sample once per (re)connect" invariant.
		budget := slot.byteBudget.Load()
		if budget > 0 {
			// Always advance the counter (even if we don't rotate here) so a
			// future read sees the correct total.
			total := slot.downBytes.Add(int64(len(data)))
			if total >= budget && p.maybeRotateSlot(cl, idx, slot, "byte_budget", msgCount, slotStart, total) {
				return
			}
		}

		// Age-based rotation lives in rotationWatchdog (pool-level
		// goroutine), NOT here. The reader-side check would only fire when
		// data arrives — on a slot that's gone idle just past the kill
		// window threshold, ReadMessage would block until the 60s deadline,
		// receive the close 1006 from the middlebox, and we'd handle it as
		// a death instead of a preemptive rotation. The watchdog ticks
		// independently of downlink traffic.

		session := slot.session
		if session == nil {
			continue
		}

		chunk, err := session.DecryptChunkSafe(data)
		if err != nil {
			continue
		}

		if len(chunk.Payload) < 2 {
			continue
		}

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		if chunk.Flags == core.FlagUDP {
			cl.RouteToStream(streamID, chunk.Payload)
		} else {
			cl.RouteToStream(streamID, chunk.Payload[2:])
		}
	}
}

// maybeRotateSlot is the policy gate for preemptive rotation triggers
// (byte budget, age budget). It performs the rotation immediately when
// the slot has no active streams. When streams are still active, it
// defers the rotation up to slotRotationGraceWithActiveStreams to let
// the in-flight uploads finish — interrupting a long heavy upload
// mid-flight wastes the upload's progress.
//
// Returns true iff rotation actually fired (caller must `return` to exit
// the read loop). Returns false if rotation was deferred OR aborted; in
// both cases the read loop continues and we'll re-evaluate on the next
// data frame.
//
// Lifecycle of the defer:
//   - First trigger with active streams → record rotationDeferredNs,
//     log "preemptive rotation deferred", return false.
//   - Subsequent triggers: if streams == 0 → rotate now. Else, check
//     whether grace window has elapsed; if so, rotate anyway. Otherwise
//     stay deferred (no log; the original log line carries the rationale).
//
// Storm brake: when ≥ rotationStormBrakeThreshold() slots are already
// non-ready (dead/connecting/draining), a NEW rotation request defers
// even if streams==0. Without this, byte-budget triggers under heavy
// upload load fire on all 8 slots within seconds, and the simultaneous
// teardowns leave the upload writer with nowhere to put bytes. The
// brake only blocks NEW rotations — it never overrides the "grace
// expired" force-rotate, because at that point we know the slot is
// past its safe age and must be replaced.
//
// Concurrency: rotationDeferredNs is atomic; CAS not strictly needed
// because the field is only written from the single slot reader goroutine
// that owns this idx (readerActive gate guarantees one writer). The
// brake reads countNonReadySlots which is a lock-free walk of per-slot
// atomics — race-free, eventually-consistent (acceptable: false brake
// just defers by one cycle, never wrong direction).
func (p *WSPoolTransport) maybeRotateSlot(cl *Client, idx int, slot *poolSlot,
	reason string, msgCount int, slotStart time.Time, downBytes int64) bool {

	activeStreams := slot.streams.Load()
	nowNs := time.Now().UnixNano()
	deferredAt := slot.rotationDeferredNs.Load()
	graceExpired := deferredAt != 0 && nowNs-deferredAt >= slotRotationGraceWithActiveStreams.Nanoseconds()

	// Storm brake: skip NEW rotations when too many slots are already
	// non-ready. Bypass when grace has expired — at that point the slot
	// is past its safe age and the cost of NOT rotating (middlebox close
	// 1006) exceeds the cost of a tight reconnect window. Recording the
	// defer timestamp here means the grace clock starts ticking, so a
	// stuck brake doesn't pin the slot indefinitely.
	if !graceExpired {
		nonReady := p.countNonReadySlots()
		if nonReady >= p.rotationStormBrakeThreshold() {
			if deferredAt == 0 {
				slot.rotationDeferredNs.Store(nowNs)
				p.log.Info("WS pool slot preemptive rotation deferred (storm brake)",
					"slot", idx, "reason", reason,
					"non_ready_slots", nonReady,
					"brake_threshold", p.rotationStormBrakeThreshold(),
					"active_streams", activeStreams,
					"slot_age", time.Since(slotStart).Truncate(time.Second),
					"grace_window", slotRotationGraceWithActiveStreams)
			}
			return false
		}
	}

	if activeStreams == 0 {
		p.log.Info("WS pool slot preemptive rotation",
			"slot", idx, "reason", reason,
			"slot_age", time.Since(slotStart).Truncate(time.Second),
			"down_bytes", downBytes, "messages", msgCount)
		p.fireRotation(cl, idx)
		return true
	}

	if deferredAt == 0 {
		// Per-slot defer stagger for byte_budget triggers. Without this,
		// 8 slots under heavy upload load (≥100 Mbps total) all hit their
		// byte budget within milliseconds (field log 2026-05-18: 8 slots
		// deferred in a 4s window, 8 force-rotates 30s later in a 4s
		// window → alive=2/8 during the storm).
		//
		// Offset = slot.staggerOffsetNs (sampled once in connectSlot via
		// slotStaggerOffset(idx) — additive grid jitter, see 2026-05-18 A1).
		// For idx=0 offset is always 0 so slot 0 defers at nowNs.
		//
		// Age-trigger does NOT need this offset — rotationWatchdogSweep
		// already adds slot.staggerOffsetNs to maxSlotAge, so age defers
		// arrive at maybeRotateSlot pre-spread. Applying the offset twice
		// would double-delay the last slots past any reasonable kill window.
		deferAt := nowNs
		if reason == "byte_budget" && p.poolSize > 1 {
			deferAt += slot.staggerOffsetNs.Load()
		}
		slot.rotationDeferredNs.Store(deferAt)
		p.log.Info("WS pool slot preemptive rotation deferred (active streams)",
			"slot", idx, "reason", reason, "active_streams", activeStreams,
			"slot_age", time.Since(slotStart).Truncate(time.Second),
			"grace_window", slotRotationGraceWithActiveStreams,
			"stagger_offset", time.Duration(deferAt-nowNs).Truncate(time.Second))
		return false
	}

	// Already deferred — check if grace window expired.
	if graceExpired {
		p.log.Info("WS pool slot preemptive rotation (grace expired, force rotate)",
			"slot", idx, "reason", reason, "active_streams", activeStreams,
			"slot_age", time.Since(slotStart).Truncate(time.Second),
			"deferred_for", time.Duration(nowNs-deferredAt).Truncate(time.Second))
		p.fireRotation(cl, idx)
		return true
	}

	return false
}

// fireRotation executes the rotation: bumps the 1-minute counter and
// triggers handleSlotDeath with the Preemptive cause so the meltdown
// detector does NOT count this teardown as a network failure.
// Extracted from maybeRotateSlot so both success branches (idle slot,
// grace-expired) share counter accounting without duplication.
// Decrement is scheduled in a separate goroutine after 60s — keeps the
// counter as a rolling window without a ring buffer.
func (p *WSPoolTransport) fireRotation(cl *Client, idx int) {
	p.rotations1m.Add(1)
	go func() {
		timer := time.NewTimer(60 * time.Second)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			p.rotations1m.Add(-1)
		}
	}()
	p.handleSlotDeath(cl, idx, deathCausePreemptiveRotation)
}

// handleSlotDeath marks a slot as dead, closes its streams, and triggers reconnect.
//
// Idempotent: if the slot is already dead, the function returns immediately
// without re-running cleanup or recording another death. A single failing
// slot can be observed by the reader (panic, timeout, terminal error) AND
// the writer simultaneously; without CAS the death counter would be inflated
// 2-3× per failure, tripping meltdown detection on what is really one event.
//
// cause distinguishes natural failures from preemptive rotations. ONLY
// natural failures advance the meltdown counter — see slotDeathCause.
func (p *WSPoolTransport) handleSlotDeath(cl *Client, idx int, cause slotDeathCause) {
	slot := p.slots[idx]
	if slot == nil {
		return
	}
	if !slot.tryMarkDead() {
		return
	}
	slot.lastDeathNs.Store(time.Now().UnixNano())

	// Close all streams assigned to this slot
	p.streamMap.Range(func(key, value any) bool {
		if value.(int) == idx {
			streamID := key.(uint16)
			p.streamMap.Delete(streamID)
			cl.streamMu.Lock()
			if ch, ok := cl.streamChans[streamID]; ok {
				close(ch)
				delete(cl.streamChans, streamID)
			}
			cl.streamMu.Unlock()
		}
		return true
	})

	slot.streams.Store(0)
	slot.pendingConnects.Store(0) // Reset: pending CONNECTs from dead slot can't be decremented normally

	if slot.transport != nil {
		slot.transport.Close()
	}

	// Post-cleanup dispatch by cause. See slotDeathCause doc-comment for the
	// rationale behind each branch.
	switch cause {
	case deathCauseNatural:
		// Real network failure — feed meltdown detector and reconnect the
		// same idx (reader observed the death, no replacement exists).
		p.recordSlotDeath()
		go p.reconnectLoop(idx)
	case deathCausePreemptiveRotation:
		// OUR rotation — do NOT advance meltdown (would falsely trip under
		// steady-state rotation load, see field log 2026-05-18), but DO
		// reconnect the same idx (legacy semantics: rotation tears one
		// slot down and brings the same idx back up).
		go p.reconnectLoop(idx)
	case deathCauseDrainTeardown:
		// Graceful drain finished — a reserve slot in a DIFFERENT cell
		// already carries this capacity. Reconnecting THIS idx would be
		// capacity duplication. Do NOT advance meltdown (not a failure)
		// and do NOT spawn reconnectLoop. Free the cell so future
		// reserve targets can pick it via findFreeReserveSlot.
		p.slots[idx] = nil
	}
}

// Close shuts down all slots.
func (p *WSPoolTransport) Close() error {
	p.cancel()
	for _, slot := range p.slots {
		if slot == nil {
			continue
		}
		if slot.transport != nil {
			slot.transport.Close()
		}
		if slot.session != nil {
			slot.session.Destroy()
		}
		if slot.token != nil {
			core.ZeroBytes(slot.token)
		}
	}
	return nil
}

// HealthySlots returns the number of ready slots in the entire pool
// (primary + reserve). A reserve slot in slotReady is providing real
// capacity (active drain replacement) so it counts toward health.
func (p *WSPoolTransport) HealthySlots() int {
	count := 0
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady {
			count++
		}
	}
	return count
}

// ReadyCount implements the PoolReadiness interface — same semantics as
// HealthySlots, exposed under a name independent of the legacy "Healthy"
// vocabulary so SOCKS5 UDP ASSOCIATE gating (C12 F6) reads naturally:
// `if pool.ReadyCount() < udpMinReadySlots { fail }`.
func (p *WSPoolTransport) ReadyCount() int { return p.HealthySlots() }

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

	"github.com/nixavpn/shadowlink/client/slotobs"
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

// slotRateLimitedCooldownForTestPtr / slotBackoffDurationForTestPtr are test
// seams for reconnectLoop integration tests. Production reconnectLoop calls
// slotRateLimitedCooldown() / slotBackoffDuration(attempt) directly; tests
// install a fast shim so the integration test finishes in milliseconds.
//
// Synchronized via atomic.Pointer for the SAME reason as connectSlotForTestPtr
// (see below): reconnectLoop reads these from a DETACHED background goroutine
// while tests overwrite them from the test goroutine — and a leaked background
// reconnectLoop from a prior subtest may still be reading when the next subtest
// writes. A plain package-global `var` races the reader under -race
// (TestReconnectLoop_RecycleGuard write vs a sibling test's live reconnectLoop
// read — 2026-06-01 race report). nil pointer → "use the production function".
var (
	slotRateLimitedCooldownForTestPtr atomic.Pointer[func() time.Duration]
	slotBackoffDurationForTestPtr     atomic.Pointer[func(int) time.Duration]
)

// slotRateLimitedCooldownForTest returns the installed cooldown shim, or the
// production slotRateLimitedCooldown when none is set. Safe from any goroutine.
func slotRateLimitedCooldownForTest() time.Duration {
	if fp := slotRateLimitedCooldownForTestPtr.Load(); fp != nil {
		return (*fp)()
	}
	return slotRateLimitedCooldown()
}

// setSlotRateLimitedCooldownForTest installs (nil clears) the cooldown shim.
func setSlotRateLimitedCooldownForTest(fn func() time.Duration) {
	if fn == nil {
		slotRateLimitedCooldownForTestPtr.Store(nil)
		return
	}
	slotRateLimitedCooldownForTestPtr.Store(&fn)
}

// slotBackoffDurationForTest returns the installed backoff shim, or the
// production slotBackoffDuration when none is set. Safe from any goroutine.
func slotBackoffDurationForTest(attempt int) time.Duration {
	if fp := slotBackoffDurationForTestPtr.Load(); fp != nil {
		return (*fp)(attempt)
	}
	return slotBackoffDuration(attempt)
}

// setSlotBackoffDurationForTest installs (nil clears) the backoff shim.
func setSlotBackoffDurationForTest(fn func(int) time.Duration) {
	if fn == nil {
		slotBackoffDurationForTestPtr.Store(nil)
		return
	}
	slotBackoffDurationForTestPtr.Store(&fn)
}

// connectSlotForTest is a test seam for reconnectLoop integration tests —
// production code uses (*WSPoolTransport).connectSlot directly. The stub
// returns the desired error sequence (e.g. ErrRateLimited then nil) without
// needing a live WS server.
//
// nil means "fall through to the real implementation" — production paths
// must NOT see this hook and the build never references it.
//
// Access is synchronized through an atomic.Pointer: the hook is read from
// background goroutines (reconnectLoop / connectReserveSlot run detached) while
// tests overwrite it from the test goroutine — and a leaked background goroutine
// from a prior subtest may still be reading when the next subtest writes. Plain
// global assignment races the reader (-race report on the package global). The
// stored value is a *(func() error) so a nil function pointer is representable
// (load returns nil → "fall through to real implementation"). Production keeps
// the pointer nil, so getConnectSlotForTest() is a single atomic.Load of a nil
// pointer on the hot path — no allocation, no lock, no measurable overhead.
var connectSlotForTestPtr atomic.Pointer[func() error]

// getConnectSlotForTest returns the currently installed test hook, or nil when
// none is set (production). Safe to call from any goroutine.
func getConnectSlotForTest() func() error {
	if fp := connectSlotForTestPtr.Load(); fp != nil {
		return *fp
	}
	return nil
}

// setConnectSlotForTest installs (or, with nil, clears) the test hook. Safe to
// call concurrently with getConnectSlotForTest readers in background goroutines.
func setConnectSlotForTest(fn func() error) {
	if fn == nil {
		connectSlotForTestPtr.Store(nil)
		return
	}
	connectSlotForTestPtr.Store(&fn)
}

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
//   - deathCauseAgeCut — the EXPECTED TSPU age-cut: a mature direct-TCP slot
//     (age >= ageCutMinAgeMs) closed 1006 by the middlebox (docs/
//     sl-burst2-freeze-analysis.md). This is routine and anticipated in direct
//     mode — not a fault. It MUST reconnect FAST (ageCutReconnectJitter, not the
//     5-10s exponential) so a cascade of mature-slot cuts does not bare the pool
//     and freeze quiet streams' downlink, and it MUST NOT feed the meltdown
//     detector (a steady cascade of routine cuts would otherwise trip the
//     cooldown and PAUSE all reconnects — deepening the dip, the opposite of
//     what we want). For FIN behavior the age-cut is identical to natural: the
//     transport is already dead (cut externally), so no session FIN is sent.
//
// recordSlotDeath is only invoked for the Natural cause; the meltdown
// detector therefore tracks ONLY real failures (age-cut is expected, not a
// failure).
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
	// future reserve reuse via claimFreeReserveSlot.
	deathCauseDrainTeardown
	// deathCauseAgeCut — expected TSPU age-cut on a mature slot (close 1006 at
	// age >= ageCutMinAgeMs). Fast reconnect (no exponential, no meltdown feed),
	// no FIN (transport already dead). See the doc-comment above for the full
	// rationale. Added 2026-06-01 (pool-capacity-dip-fix).
	deathCauseAgeCut
)

func (c slotDeathCause) String() string {
	switch c {
	case deathCauseNatural:
		return "natural"
	case deathCausePreemptiveRotation:
		return "preemptive_rotation"
	case deathCauseDrainTeardown:
		return "drain_teardown"
	case deathCauseAgeCut:
		return "age_cut"
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

	// nextDrainAttemptNs is a UnixNano deadline before which the rotation
	// watchdog must not attempt to drain this slot. Set when a drain is
	// deferred via storm brake or no-reserve-cell revert — prevents a
	// tight retry loop where the next 5s watchdog tick re-triggers the
	// same deferred drain. Zero = no backoff (slot eligible for drain
	// on next tick).
	nextDrainAttemptNs atomic.Int64

	// isSticky marks that THIS slot's drainWatchdog currently holds a sticky
	// extension slot in the pool-wide stickyDrainCount (Bug #6). Set via
	// markSticky (CAS false→true, increments count once), cleared via
	// releaseSticky (Swap, decrements once). Lives on poolSlot (not keyed by
	// index) so a recycled cell's NEW *poolSlot starts with isSticky=false
	// (zero value) and the OLD watchdog's deferred releaseSticky operates on
	// its OWN captured *poolSlot — no cross-recycle counter desync (spec H2).
	isSticky atomic.Bool

	// Bug #8 flow control, negotiated per-slot (each slot = own core.Session).
	flowControlEnabled bool
	flowWindow         uint64

	// migrateNegotiated is the PER-SLOT migration wire-format latch (audit
	// 2026-06-11 H-C3). Set true in connectSlot from this slot's OWN FLOWCTL V2
	// ack (wst.flowMigrateEnabled) — i.e. the downlink wire format the SERVER
	// session behind THIS slot speaks. The slot reader selects its decode shape
	// (seq-tagged vs legacy flat FlagData) from this field, NOT from the
	// pool-wide migrateEnabled bit.
	//
	// Why per-slot: migrateEnabled is pool-wide write-once-true, flipped when
	// ANY slot negotiates migration. If slot B flips it while slot A's session
	// still speaks the flat format (the server latches seq format per-session at
	// its own negotiation point — not atomically with the client's pool-wide
	// flip), a pool-wide read would make slot A's reader seq-decode flat frames,
	// mis-parsing 8 payload bytes as downSeq → frame drop / mis-route. Latching
	// the decode shape on the session that PRODUCED the frame closes that
	// window. Atomic so the slot reader reads it lock-free. Zero value (false) on
	// a fresh/recycled cell = flat decode until that slot negotiates.
	migrateNegotiated atomic.Bool

	// migrationThresholdNs is the per-slot, per-session age (nanoseconds) at
	// which the rotation watchdog begins preemptively MIGRATING this slot's
	// active streams onto a younger slot (Bug #9 Task 16, F7 §5.6). Sampled
	// ONCE in connectSlot as base × U(0.7, 1.0) where base = migrationThresholdBase()
	// (default 60s). Distinct from the byte-budget rotation and from
	// staggerOffsetNs age-rotation: migration moves streams to a fresh slot
	// while the aging slot's TCP is still healthy, so a long-lived download
	// survives the rotation instead of breaking.
	//
	// Why per-slot jitter (not a fixed 60s for every slot): a deterministic
	// threshold would make every slot start migrating at the same wall-clock
	// offset from its connect time — an FFT-visible periodicity. U(0.7,1.0)
	// smears the migration onset across an 18s band per slot.
	//
	// Why max ×1.0 (not ×1.0 + headroom): the observed TSPU cut window on a
	// bare origin is ~90s; capping the effective threshold at base (60s) keeps
	// a 30s margin to actually migrate the streams BEFORE the middlebox freezes
	// the aging TCP. 0 = migration trigger disabled for this slot.
	migrationThresholdNs atomic.Int64
}

// slotFreshnessPenaltyWindow defines how long after a slot's last death
// AssignStream's first pass excludes it from candidates. Tuned to outlast
// the typical reconnect-handshake-warmup cycle (~3-8s in field data) so
// the cooled-down slot has time to prove stability before long-lived TCP
// uploads land on it. If every ready slot is inside this window (cascade
// recovery), AssignStream falls through to a second pass that ignores
// the window — see AssignStream's pickInPass closure.
const slotFreshnessPenaltyWindow = 30 * time.Second

// slotRotationStaggerStep is the FALLBACK per-slot GRID INTERVAL added to
// MaxSlotAge so slots created within milliseconds of each other don't all
// rotate at the same instant. Used only when WSPoolConfig.StaggerStep is 0;
// the production direct-mode default is 6s + a 45s cap (env SHADOWLINK_STAGGER_STEP /
// SHADOWLINK_STAGGER_OFFSET_CAP, spec 2026-06-05 age-window-tuning) so even the
// highest-idx uniform cell rotates under the ~130s TSPU freeze window. This 15s
// const is the legacy fallback for callers that don't set StaggerStep.
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
//
// Step / cap (BLOCKER-1): the grid interval is p.staggerStep (falling back
// to slotRotationStaggerStep when unset) and the linear base is clamped to
// p.staggerOffsetCap when that is > 0. The cap bounds the ladder, which
// otherwise adds 15*step on top of MaxSlotAge at poolSize=8.
//
// ⚠ The cap does NOT make rotation safe — it only makes the overshoot finite.
// This offset is ADDED to the rotation threshold, so at cap=45s and step=6s the
// worst cell rotates 48s LATER than MaxSlotAge suggests. Field measurement
// 2026-08-07: applied threshold 69s + 48s = 114s against a p10 death age of 84s,
// i.e. cells idx 8..15 could not survive to their own rotation and were cut by
// the middlebox instead. The old comment claimed the cap "keeps every slot
// rotating before the freeze"; that was true only under the unverified 130-190s
// window, and is false under the measured 84-118s one.
//
// A second, subtler cost: every idx past cap/step gets the SAME base (all of
// idx 8..15 land on 45s), so those cells rotate in lockstep — the opposite of
// what staggering is for. Visible in the field log as bursts of same-second
// teardowns.
//
// Always size this through WSPoolTransport.worstCaseTeardown(), never by
// eyeballing MaxSlotAge. cap=0 preserves the legacy unbounded ladder.
// rotationWatchdogTick — период обхода слотов на предмет перезревания.
// Слагаемое worst-case: слот, перешедший порог сразу после тика, ждёт до целого
// периода, прежде чем ротация вообще будет замечена.
const rotationWatchdogTick = 5 * time.Second

// staggerSpan — МАКСИМАЛЬНЫЙ вклад stagger-джиттера в возраст слота, по всем
// ячейкам слайса. Ровно та величина, которой не хватало в расчёте worst-case.
//
// Почему это отдельная функция, а не «примерно cap»: slotStaggerOffset даёт
// base+jitter, где base клампится cap'ом, а jitter ∈ [-step/2, +step/2). Верхняя
// граница = cap + step/2, и при отсутствии cap'а — (2*poolSize-1)*step + step/2,
// потому что uniform-cells идут idx 0..2*poolSize-1 (см. поле p.slots).
//
// Замер 2026-08-07 показал, зачем это нужно явно: при staggerStep=6s и
// staggerOffsetCap=45s восемь ячеек из шестнадцати (idx 8..15) получают
// ОДИНАКОВЫЙ base=45s, то есть порог ротации 69+45=114s при наблюдаемом p10
// смертей 84s. Эти ячейки физически не доживали до собственной ротации, а лог
// worst_case_teardown про них не знал — он складывал только maxSlotAge+sticky.
func (p *WSPoolTransport) staggerSpan() time.Duration {
	step := p.staggerStep
	if step <= 0 {
		step = slotRotationStaggerStep
	}
	maxIdx := len(p.slots) - 1
	if maxIdx < 0 {
		maxIdx = 0
	}
	base := time.Duration(maxIdx) * step
	if p.staggerOffsetCap > 0 && base > p.staggerOffsetCap {
		base = p.staggerOffsetCap
	}
	return base + step/2 // jitter полуоткрыт сверху: [-step/2, +step/2)
}

// worstCaseTeardown — полное время жизни TCP-соединения худшей ячейки, от
// подключения до принудительного разрыва. ЕДИНСТВЕННЫЙ источник истины: и лог, и
// будущие проверки бюджета обязаны спрашивать здесь, а не складывать слагаемые
// заново по месту.
//
// Почему функция, а не выражение в лог-строке (урок раунда 18, H-15): до
// 2026-08-07 stats.go печатал `adaptedAge + stickyMaxDrainAge` и был прав только
// по совпадению — при hard_cap == sticky == 15s. Поднятие DRAIN_HARD_CAP не
// изменило бы ни одной цифры в логе, а реальность уехала бы на 15s. Контур,
// который рассказывает о себе неправду, хуже отсутствующего.
//
// Слагаемые:
//   - base    — действующий порог ротации (адаптированный, если адаптер сжал)
//   - stagger — максимальный вклад сетки размазывания, см. staggerSpan
//   - sweep   — задержка обнаружения: rotationWatchdogSweep тикает раз в 5s
//   - defer_  — отложенная ротация: если гейт startDrain не пропустил слот, тот
//     возвращается в slotReady и ждёт backoff, ПРОДОЛЖАЯ стареть и принимать
//     новые стримы. Берётся drainRevertBackoff (30s) — худшая из ветвей.
//   - tear    — удержание дренажа: рвёт ТОТ, ЧЕЙ ДЕДЛАЙН РАНЬШЕ. Дедлайн стоит
//     на drainHardCap (ws_pool_drain.go), а stickyMaxDrainAge проверяется лишь
//     ПО ЕГО СРАБАТЫВАНИИ — поэтому sticky меньше hard_cap не участвует вовсе.
//
// # Почему deferred и tear СКЛАДЫВАЮТСЯ, а не max (разобрано 2026-08-10)
//
// Соблазнительно счесть их взаимоисключающими: в одном вызове startDrain это
// действительно две ветки, разделённые `return` — ветка отсрочки не спавнит
// drainWatchdog, значит tear в ней не расходуется. Вывод «значит max()» НЕВЕРЕН,
// и попытка так сделать была откачена в тот же день.
//
// Бюджет моделирует ПОЛНЫЙ путь ячейки от подключения до принудительного
// разрыва, а не один заход watchdog. На этом уровне ветки идут ПОСЛЕДОВАТЕЛЬНО:
//
//  1. startDrain откладывает: ставит nextDrainAttemptNs = now+backoff и
//     возвращает слот в slotReady (ws_pool_drain.go:506 storm-brake, :579
//     no-free-cell). Ротация при этом НЕ отменяется.
//  2. rotationWatchdogSweep на отсрочку отвечает лишь `continue` (ws_pool.go
//     ~2100) — порог effectiveMaxAge уже перешагнут и остаётся перешагнутым.
//  3. На следующем годном тике startDrain вызывается заново. Гейты пройдены →
//     committed = true → drainWatchdog тратит tear СВЕРХ потраченной отсрочки.
//
// Один и тот же слот платит deferred, ПОТОМ tear.
//
// Полевая арифметика (86 минут, n=766 восстановленных времён жизни TCP):
// p90=118.0s, max=122.0s. Сумма даёт 141.5s и границу держит; max() дала бы
// 111.5s, то есть её пробивает уже p90 — ~10% выборки. Верхняя оценка, которую
// пробивает замер, верхней оценкой не является. Недостижение суммы её не
// опровергает: 4 события no-free-cell на ~766 ротаций — это и есть та редкая
// ячейка, которая доезжает до полной суммы.
//
// # Почему deferred = 30s, а не 5s
//
// Частая ветка — storm-brake (drainStormBrakeBackoff, 5s, 12 событий за час);
// редкая — no-free-cell (30s, 4 события). В бюджет идёт РЕДКАЯ, потому что она
// хуже: слот уже перешагнул порог и признан подлежащим замене, но возвращён в
// slotReady — то есть продолжает принимать новые стримы (фильтр
// `getState() != slotReady`) и при этом запрещён к ротации 30 полных секунд.
// Именно такая ячейка стареет вглубь окна реза 84–118s. «Учтено в счётчике
// no-free-cell» заменой не является: счётчик говорит «событие было», бюджет —
// «ячейка не доживёт»; это разные утверждения.
//
// ⚠ Не учтён drainCatastrophicBackoff (150s, ws_pool_drain.go:519-522) — ветка
// capacity floor при ready < poolSize/2. Бюджет её не моделирует ни до, ни
// после этого разбора; отдельная работа.
func (p *WSPoolTransport) worstCaseTeardown() (base, stagger, sweep, deferred, tear, total time.Duration) {
	base = p.maxSlotAge
	if adapted := p.ageAdapter.Threshold(); adapted > 0 {
		base = adapted
	}
	stagger = p.staggerSpan()
	sweep = rotationWatchdogTick
	if p.gracefulDrain {
		deferred = drainRevertBackoff

		tear = p.drainHardCap
		// sticky продлевает дренаж только когда он БОЛЬШЕ hard_cap: дедлайн
		// ставится на hard_cap, sticky проверяется по его срабатывании.
		if p.stickyMaxDrainAge > tear {
			tear = p.stickyMaxDrainAge
		}
	}
	return base, stagger, sweep, deferred, tear,
		base + stagger + sweep + deferred + tear
}

func (p *WSPoolTransport) slotStaggerOffset(idx int) time.Duration {
	if idx <= 0 {
		return 0
	}
	step := p.staggerStep
	if step <= 0 {
		step = slotRotationStaggerStep
	}
	base := time.Duration(idx) * step
	if p.staggerOffsetCap > 0 && base > p.staggerOffsetCap {
		base = p.staggerOffsetCap
	}
	// Float64() ∈ [0, 1.0). Map to [-0.5, 0.5) then to half-open
	// [-step/2, step/2).
	jitter := time.Duration((rand.Float64() - 0.5) * float64(step))
	return base + jitter
}

// keepaliveDefaultBase is the default base interval for the per-pool
// keepalive loop (Bug #9). The loop samples
// JitteredIntervalLogNormal(keepaliveDefaultBase, keepaliveSigma), which is
// truncated to [base/2, base*2] = [2.5s, 10s]. The 10s upper bound is the
// worst-case silence a quiet slot can experience between keepalive frames;
// it stays under the ~10-15s silent-cut window observed for direct-mode
// bare-origin TCP under the РФ TSPU (field log: close 1006 with
// last_write_age_ms=10000-15000). Was 20s (window [10s, 40s]) before Bug #9.
//
// Why not lower (e.g. 3s)? A real idle browser keep-alive WS pings every
// ~15-30s; 5s±jitter is already more frequent than a real browser, so going
// lower buys little headroom against the cut while drifting further from the
// browser-mimicry baseline. Why not a fixed 5s? Anti-DPI requires a
// non-periodic, heavy-tailed cadence (NEW-1 / final-audit-2026-05-03 P1-3) —
// we keep the log-normal jitter and only shrink the base.
const keepaliveDefaultBase = 5 * time.Second

// keepaliveSigma is the log-normal sigma for the keepalive sampler. 0.5 is
// the project-standard "moderate" jitter (see jitter.go) — preserved from the
// pre-Bug #9 keepalive so the anti-DPI cadence shape is unchanged; only the
// base shrank.
const keepaliveSigma = 0.5

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
// much smaller scale (200ms step vs the multi-second rotation step) — handshake spreading is
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

// maxConcurrentDrainsFraction — fraction of poolSize that defines the
// maximum number of concurrent in-flight drains. Inflight cap for the
// drain scheduler's storm-brake. Raised 2026-05-24 from 0.25 (=2 drains
// at poolSize=6) to 0.5 (=3 drains) because canary 2026-05-24-evening
// showed 100% of storm-brake defers landing on the inflight gate and 0%
// on the capacity-floor gate (12497 vs 0 over 4h3m). The pool spent 77%
// of its time at inflight=2 saturation — drains queued behind the cap,
// streams accumulated age, then hit the 90s hard-cap ceiling. Raising
// the cap allows the scheduler to dispatch drains promptly.
//
// Spec 2026-05-24 (concurrency-lift-and-backoff).
const maxConcurrentDrainsFraction = 0.5

// readyCapacityFloorFraction — fraction of poolSize that must be in
// slotReady state before storm-brake permits a new drain. Catastrophic-
// state gate: when ready slots fall below this floor, the pool is losing
// slots faster than reconnectLoop heals — defer drains so reconnects can
// catch up.
//
// Decoupled 2026-05-24 from maxConcurrentDrainsFraction (previously both
// derived from a single rotationStormBrakeFraction=0.25 constant). The
// canary 2026-05-24-evening proved this gate never triggers in steady
// state (0 defers over 4h), so it's set independently of the inflight
// cap. Value 0.75 preserves the prior floor at most poolSizes (the
// floor stays unchanged for poolSize ∈ {2, 4, 6, 8, 16}) — purely
// decoupling, no behavior change for the capacity-floor branch.
//
// Spec 2026-05-24 (concurrency-lift-and-backoff).
const readyCapacityFloorFraction = 0.75

// effectiveMaxBytesForSlot returns the DETERMINISTIC center of the per-slot
// byte-budget distribution. The actual budget used by the slot reader is
// sampled with jitter around this center via sampleByteBudget below and
// stored once per (re)connect in poolSlot.byteBudget.
//
// Center formula: base + (idx × base / poolSize). For 8 slots × 8 MiB base:
//
//	slot 0 → 8.0 MiB center, slot 1 → 9.0, ..., slot 7 → 15.0 MiB.
//
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

// byteBudgetMinRotationInterval is the wall-clock floor between a slot becoming
// ready and its first byte-budget-triggered rotation. It re-anchors the
// anti-TSPU rotation cadence to TIME rather than raw bytes.
//
// Why (Bug #4, 2026-05-29): byte budget (8 MiB) is a proxy for TCP lifetime.
// At ~50 MB/s a slot burns 8 MiB in ~0.16s, so without a floor every slot
// rotates several times per second — replacement handshakes (~0.5-1s) can't
// keep up, the reserve cells exhaust ("no free cell"), and pool downlink
// collapses mid-download. A new TCP that has lived 0.16s gives no anti-TSPU
// benefit anyway (the censor's per-flow age/volume counter hasn't tripped on a
// flow that young at that byte count over that little time). 10s floor: a slot
// rotates on byte budget at most once per 10s, capping byte-driven rotations at
// ~0.8/slot/8s-window even under saturation, while the 2-min age budget remains
// the upper bound so TCPs still cycle well inside any TSPU window.
//
// Tunable via SHADOWLINK_BYTE_BUDGET_MIN_INTERVAL; 0 disables the floor
// (restores pre-fix byte-only behaviour).
const byteBudgetMinRotationInterval = 10 * time.Second

// byteBudgetRotationAllowed reports whether a byte-budget-triggered rotation may
// fire given the slot's current age and the configured minimum interval. A
// non-positive minInterval disables the floor (always allowed). Pure function —
// unit-tested in byte_budget_floor_test.go.
func byteBudgetRotationAllowed(slotAge, minInterval time.Duration) bool {
	if minInterval <= 0 {
		return true
	}
	return slotAge >= minInterval
}

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

// readyCapacity returns the count of cells in slotReady across the
// entire slice. Uniform-cells design (spec 2026-05-20 §2.1) — no
// primary/reserve distinction. Used by startDrain storm brake to gate
// new drains against a capacity floor.
//
// Lock-free read of per-slot atomic state. Snapshot-inconsistency
// window is 2*poolSize cells; the brake is self-correcting on the next
// watchdog tick (acceptance #9).
func (p *WSPoolTransport) readyCapacity() int {
	n := 0
	for _, slot := range p.snapshotSlots() {
		if slot != nil && slot.getState() == slotReady {
			n++
		}
	}
	return n
}

// readyCapacityFloor returns the minimum readyCapacity the storm brake
// will tolerate before deferring new drains. Independent of
// maxConcurrentDrains after the 2026-05-24 knob decoupling — see spec
// §1.
//
// Derivation: floor(poolSize * readyCapacityFloorFraction), clamped to
// [1, poolSize-1]. The clamps preserve two invariants:
//   - floor >= 1 (always require at least one ready slot)
//   - floor <= poolSize-1 (never block all drains by setting floor at
//     pool size — at minimum poolSize-1 ready slots is "acceptable")
func (p *WSPoolTransport) readyCapacityFloor() int {
	floor := int(math.Floor(float64(p.poolSize) * readyCapacityFloorFraction))
	if floor < 1 {
		floor = 1
	}
	if floor >= p.poolSize {
		floor = p.poolSize - 1
	}
	return floor
}

// recordCapacityDip ticks the canary observability counter for a residual
// capacity dip (Lever 4, counter-only — the headroom MECHANISM is deferred, see
// spec Out-of-scope). Called from the age-cut death path when the cut would drop
// ready capacity below the floor with active streams in flight — i.e. exactly
// the condition the fast reconnect is meant to shorten. The canary uses this to
// prove the dip is gone after Levers 1+3 ship.
func (p *WSPoolTransport) recordCapacityDip() {
	Stats.CapacityDipTotal.Add(1)
}

// effectiveStickyMaxSlots is the static ceiling on concurrently-sticky slots
// (Bug #6). 0 (config) → auto = poolSize/2 (min 1). <0 → 0 (sticky disabled).
// The ACTUAL cap is further gated dynamically by readyCapacity in
// stickyQuotaAvailable — this is only the upper bound.
func (p *WSPoolTransport) effectiveStickyMaxSlots() int {
	if p.stickyMaxSlots > 0 {
		return p.stickyMaxSlots
	}
	if p.stickyMaxSlots < 0 {
		return 0
	}
	half := p.poolSize / 2
	if half < 1 {
		half = 1
	}
	return half
}

// markSticky records that slot's watchdog holds a sticky extension. CAS gate
// makes the pool-wide stickyDrainCount increment exactly once per slot,
// regardless of how many times the deadline branch extends (Bug #6, spec §4).
// Operates on the CAPTURED *poolSlot — never via p.slots[idx] — so a recycled
// cell cannot make this collide with another slot's accounting (spec H2).
func (p *WSPoolTransport) markSticky(slot *poolSlot) {
	if slot.isSticky.CompareAndSwap(false, true) {
		p.stickyDrainCount.Add(1)
	}
}

// releaseSticky frees slot's sticky extension. Idempotent: Swap returns the
// prior value, so a second call (panic + defer, double teardown path) does
// NOT double-decrement. Operates on the captured *poolSlot (spec H2).
func (p *WSPoolTransport) releaseSticky(slot *poolSlot) {
	if slot.isSticky.Swap(false) {
		p.stickyDrainCount.Add(-1)
	}
}

// stickyQuotaAvailable reports whether slot may (continue to) hold a sticky
// extension. Already-sticky slots always pass (we extend, not re-acquire).
// Fresh slots gate on BOTH the static cap (effectiveStickyMaxSlots) AND a
// dynamic capacity check: holding one more slot in slotDraining must not push
// readyCapacity to/below the storm-brake floor — otherwise the pool could
// clinch and stop rotating entirely (spec H4). The dynamic gate is
// deliberately conservative (fail-safe toward rotation).
//
// Best-effort under concurrent drains: the cap and capacity reads are not
// atomic relative to each other or to parallel drainWatchdog goroutines, so N
// slots hitting deadline.C simultaneously could each observe count<cap and all
// mark sticky, briefly exceeding the cap. This is acceptable — the cap is a
// soft ceiling, the readyCapacityFloor still prevents clinch, and the overshoot
// self-corrects within one stickyRecheckInterval as already-sticky slots take
// the fast path above. A hard cap (atomic check-and-reserve) is unnecessary
// given one drainWatchdog per slot ticking at multi-second intervals.
func (p *WSPoolTransport) stickyQuotaAvailable(slot *poolSlot) bool {
	if slot.isSticky.Load() {
		return true
	}
	stickyMax := p.effectiveStickyMaxSlots()
	if p.stickyDrainCount.Load() >= int32(stickyMax) {
		return false
	}
	if p.readyCapacity() <= p.readyCapacityFloor() {
		return false
	}
	return true
}

// maxConcurrentDrains is the inflightDrains hard cap. Independent of
// readyCapacityFloor after the 2026-05-24 knob decoupling — see spec
// §1.
//
// Derivation: ceil(poolSize * maxConcurrentDrainsFraction), clamped to
// [1, poolSize-1]. Clamps preserve invariants:
//   - cap >= 1 (always permit at least one drain — never deadlock the
//     scheduler by setting cap=0)
//   - cap <= poolSize-1 (never let all slots drain simultaneously)
//
// Clamp order matters: upper clamp (poolSize-1) is applied first so that
// the lower clamp (min=1) can rescue the degenerate poolSize=1 case
// (ceil(0.5)=1 → upper→0 → lower→1). Result is always ≥ 1.
func (p *WSPoolTransport) maxConcurrentDrains() int {
	mcd := int(math.Ceil(float64(p.poolSize) * maxConcurrentDrainsFraction))
	if mcd >= p.poolSize {
		mcd = p.poolSize - 1
	}
	if mcd < 1 {
		mcd = 1
	}
	return mcd
}

func (s *poolSlot) getState() slotState   { return slotState(s.state.Load()) }
func (s *poolSlot) setState(st slotState) { s.state.Store(int32(st)) }

// decStreamsFloor decrements s.streams by one but never below zero
// (spec 2026-06-01 stream-counter-leak-fix, F2). A negative counter — which a
// historical mismatched dec (dec landing on a slot whose paired inc went to a
// now-retired object) could otherwise produce — would corrupt AssignStream's
// load-balancing picker (picks the "least loaded" slot) and the health
// active_streams sum. The CAS loop keeps it race-safe against a concurrent
// Add/Add on the same counter. This bounds the SYMPTOM; the cause is fixed by
// addressing counter mutations via captured *poolSlot pointers (F1/F3).
func decStreamsFloor(s *poolSlot) {
	for {
		cur := s.streams.Load()
		if cur <= 0 {
			return
		}
		if s.streams.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

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

// tryMarkDraining CAS-transitions the slot from slotReady to slotDraining.
// Returns true on success, false if the slot was not in slotReady (already
// draining, connecting, or dead). Used by startDrain to guarantee a single
// drain in progress per slot, regardless of which trigger fired (age,
// byte_budget, anti-fingerprint timer, or a concurrent watchdog tick).
func (s *poolSlot) tryMarkDraining() bool {
	return s.state.CompareAndSwap(int32(slotReady), int32(slotDraining))
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
	case strings.Contains(msg, "connection reset by peer"),
		strings.Contains(msg, "forcibly closed by the remote host"):
		// TCP RST surfaced through the kernel — explicit teardown, distinct
		// from orderly FIN (EOF). Hoster throttle and CDN RST-injection both
		// land here.
		//
		// Второй паттерн — Windows (WSAECONNRESET, "wsasend: An existing
		// connection was forcibly closed by the remote host"). Go не
		// переписывает winsock-текст в POSIX-форму, поэтому без него сигнал
		// RST-инъекции на Windows недостижим в принципе.
		return "reset_by_peer"
	case strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "did not properly respond"):
		// Read or write deadline expired without data — distinct from EOF
		// (peer never closed) and from `closed_local` (we didn't Close()).
		// Surface it as its own bucket so dashboards can spot stalled-but-
		// not-torn-down connections (CF/middlebox black-hole).
		//
		// Второй паттерн — Windows (WSAETIMEDOUT, "wsarecv: A connection
		// attempt failed because the connected party did not properly
		// respond..."). Это НЕ косметика: filterNoise (slotobs/infer.go)
		// отсеивает io_timeout из выборки для инференса, а "other" не
		// отсеивает. Замер 2026-08-11: 11 таких смертей при падении origin
		// ушли в "other", шесть из них прошли в чистую выборку и сжали порог
		// ротации с 66s до 47s на 2ч48м — порог стал артефактом сетевого
		// сбоя, а не выводом о поведении цензора.
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

// ageCutMinAgeMs is the slot-age floor (milliseconds) above which a close-1006
// terminal read error is classified as an EXPECTED TSPU age-cut rather than a
// genuine failure. Rationale (docs/sl-burst2-freeze-analysis.md): warm-up plus
// any genuine early instability shows well under 60s; the observed TSPU cuts of
// bare-origin direct-TCP land at 100-190s. A 60s floor keeps the fast path
// conservative — only clearly-mature cuts qualify, a young-slot 1006 stays
// natural (exponential backoff + meltdown feed).
const ageCutMinAgeMs = 60_000

// DefaultStickyMaxDrainAge caps how long a draining slot may be held open for an
// ACTIVE download before it is torn down anyway. See the rationale at the
// assignment site in NewWSPoolTransport: derived from measured cut behaviour
// (earliest observed age-cut 85.3s), not from the unverified ~130s window the
// earlier tuning assumed.
const DefaultStickyMaxDrainAge = 15 * time.Second

// ageCutReconnectJitter bounds the near-zero initial delay (U(0, jitter)) the
// fast age-cut reconnect sleeps before its first connect attempt. A small spread
// avoids a synchronized JA4 handshake burst when several mature slots are cut
// close in time (same anti-thunder-herd rationale as reconnectJitterOffset),
// while staying far below slotBackoffDuration(0)'s 5-10s — that 5-10s curve was
// the measured source of the capacity dip (3-4 slots simultaneously in reconnect
// under the cascade).
const ageCutReconnectJitter = 800 * time.Millisecond

// isClose1006 reports whether a terminal reader error belongs to the close-1006
// (abnormal closure / unexpected EOF) family — the on-wire signature of a
// middlebox tearing down the TCP without a clean WS close handshake. Reuses the
// existing classifyWSReadError vocabulary so the label set stays single-sourced.
func isClose1006(err error) bool {
	return classifyWSReadError(err) == "close_other"
}

// isAgeCut reports whether a terminal reader error on a slot of the given age
// (milliseconds) is the EXPECTED middlebox age-cut rather than a genuine
// failure. Age-cuts are routine in direct mode and must reconnect fast
// (ageCutReconnectJitter) without feeding the meltdown detector.
//
// Classification keys on slot AGE, not error type (REVISED 2026-06-01 after the
// burst3 field test, docs/sl-burst3-agecut-gap-analysis.md). The TSPU/middlebox
// tears down a mature bare-origin direct-TCP slot via MULTIPLE shapes — a WS
// close 1006 AND a raw TCP RST ("wsarecv: forcibly closed by remote host" /
// "connection reset by peer"). The original close-1006-only test let a
// mature-slot RST fall through to deathCauseNatural → 6-9s exponential backoff →
// a downlink stall (the residual freeze the user still saw). Both shapes are the
// SAME routine age-cut, so ANY terminal error on a MATURE slot (age >=
// ageCutMinAgeMs) is an age-cut. This is safe because the server never RSTs
// (ws_reader_exit_reset=0 server-side — a mature-slot RST is always the on-path
// middlebox); a session a stream is migrating off is unaffected (migration is a
// separate path).
//
// A young-slot death (age < floor) is a genuine early failure and stays
// deathCauseNatural — there the error type WOULD matter, but warm-up
// instability is rare and conservative meltdown-feeding is correct.
//
// The floor is configurable via p.ageCutMinAge (held in lockstep with
// MaxSlotAge so the classification window does not collapse when MaxSlotAge is
// lowered). A zero p.ageCutMinAge falls back to the ageCutMinAgeMs (60s)
// default, preserving the historical behavior.
//
// nil error is never an age-cut (no terminal failure occurred).
func (p *WSPoolTransport) isAgeCut(err error, slotAgeMs int64) bool {
	if err == nil {
		return false
	}
	return slotAgeMs >= p.ageCutFloor().Milliseconds()
}

// ageCutFloor — возраст, ниже которого close-1006 НЕ считается age-cut.
//
// Вынесено из isAgeCut, чтобы у порога был один источник: его же спрашивает
// slotobs.InferWithMinAge при очистке выборки. Пока порог жил только внутри
// isAgeCut, инференс о нём не знал и принимал за наблюдение реза смерть
// двухмиллисекундного слота (замер 2026-08-07).
func (p *WSPoolTransport) ageCutFloor() time.Duration {
	if p.ageCutMinAge > 0 {
		return p.ageCutMinAge
	}
	return ageCutMinAgeMs * time.Millisecond
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

	maxPendingPerSlot int32         // cap on in-flight CONNECTs per slot
	maxStreamsPerSlot int32         // cap on active streams per slot (0 = unlimited)
	maxBytesPerSlot   int64         // rotate slot after N downstream bytes (0 = disabled)
	maxSlotAge        time.Duration // rotate slot after this much wallclock age (0 = disabled)
	staggerStep       time.Duration // per-slot grid interval (0 → slotRotationStaggerStep)
	staggerOffsetCap  time.Duration // max staggerOffset regardless of idx (0 → no cap)
	ageCutMinAge      time.Duration // age-cut classification floor (0 → ageCutMinAgeMs default)

	// ageAdapter сжимает порог ротации по наблюдаемому поведению сети
	// пользователя (P0 шаг 3). Только сжимает, никогда не поднимает выше
	// cfg.MaxSlotAge; с гистерезисом и требованием подтверждений. nil →
	// используется сконфигурированный порог как раньше.
	//
	// Зачем: зашитые 75 s против выведенных 66–71 s по трём полевым выборкам.
	// worst-case teardown был 90 s при самой ранней наблюдённой смерти 82.9 s —
	// разрыв, который правкой константы не закрыть, потому что у другого
	// провайдера окно другое (ACM IMC 2022).
	ageAdapter *slotobs.Adapter

	// slotDeaths records HOW slots die, so a future rotation threshold can be
	// derived from this user's own network instead of the global constant
	// (раунд 18 P0, reframed 2026-07-31 — see client/slotobs and
	// docs/audit/2026-07-25-round18/FIELD-CHECKS.md §2).
	//
	// ⚠ Больше НЕ observation-only. Комментарий «nothing reads this to make a
	// decision yet» был верен до шага 3 (2026-07-31): теперь ageAdapter читает
	// вывод из этих наблюдений и СЖИМАЕТ порог ротации (rotationWatchdog берёт
	// базу у адаптера, ws_pool.go ~2195). Ротацию по-прежнему ограничивает
	// сконфигурированный MaxSlotAge как потолок — адаптация только вниз.
	//
	// Плановые ротации пишутся в отдельный ринг того же рекордера
	// (RecordPlanned, см. slotobs/planned.go): они дают знаменатель для
	// CutShare/Hazard, но в вывод порога не входят.
	slotDeaths *slotobs.Recorder

	// lastInsufficientLog — последнее напечатанное состояние строки о нехватке
	// наблюдений, для дросселирования (см. logSlotDeathSummary). Хранит
	// insufficientSamplesKey.
	//
	// На пуле, а не в пакетной переменной: иначе ключ переживает пересоздание
	// пула, и первая строка после реконнекта может пропасть при совпадении
	// состояния — то есть ровно тогда, когда наблюдаемость нужнее всего.
	lastInsufficientLog atomic.Value
	// byteBudgetMinInterval — wall-clock floor before a byte-budget rotation
	// may fire on a freshly-(re)connected slot (Bug #4 storm fix). 0 disables
	// the floor. Defaults to byteBudgetMinRotationInterval when byte budget is
	// enabled; see NewWSPoolTransport.
	byteBudgetMinInterval time.Duration

	// gracefulDrain — when true, slot rotation transitions through
	// slotDraining + parallel reserve reconnect. When false, rotation
	// goes directly through fireRotation → handleSlotDeath (legacy hard
	// path). Wired via SHADOWLINK_GRACEFUL_DRAIN; default off in Phase 1.
	gracefulDrain bool
	// drainHardCap — max time a slot may stay in slotDraining before
	// forced teardown. Only consulted when gracefulDrain is true. Default
	// 90s (Envoy Gateway recommendation). Tune via SHADOWLINK_DRAIN_HARD_CAP.
	drainHardCap time.Duration
	// drainIdleThreshold — once a slot has been in slotDraining and the
	// remaining streams (≤ drainIdleStreamsMax) showed no decrypt/write
	// activity for this long, drainWatchdog treats the drain as natural
	// finish and tears the slot down early. Zero disables the heuristic
	// (legacy hard-cap-only behavior). Default 30s — chosen so that a
	// browser-tab keepalive (typical 25s interval) does ping the slot
	// at least once within the window if the tab is genuinely live.
	drainIdleThreshold time.Duration
	// drainIdleStreamsMax — upper bound on streams.Load() at which the
	// idle heuristic is allowed to fire. With many remaining streams the
	// drain SHOULD wait for the hard cap; with 1-2 streams the risk of
	// drainIdleStreamsMax — Deprecated: kept readable for env-parsing
	// backward compatibility. Step 2 (per-stream idle decision) ignores
	// this value in decision logic. Use DrainIdleThreshold=0 to disable
	// the idle gate. See spec 2026-05-25-drain-per-stream-idle-decision-design §2.5.
	drainIdleStreamsMax int32

	// ── Bug #6 sticky stream (adaptive backstop) ──
	stickyMaxDrainAge   time.Duration // от старта дренажа; <=0 = sticky выключен
	stickyMaxTotalBytes int64         // анти-TSPU потолок на TCP
	stickyMaxSlots      int           // статический потолок (0=авто poolSize/2, <0=выкл)
	stickyDrainCount    atomic.Int32  // слотов СЕЙЧАС в sticky-продлении (глобальный)

	// reserveMu serializes ALL writes to p.slots[idx] across drain
	// teardown, claim, and reconnect — see graceful drain spec §C3 race
	// fix. Originally introduced for the find-and-claim of reserve cells
	// in startDrain (two concurrent startDrains on different primary
	// slots could pick the same newIdx). The lock now also guards:
	//   - connectSlot's `p.slots[idx] = slot` install (reconnect path),
	//   - handleSlotDeath's `p.slots[idx] = nil` drain teardown,
	//   - claimFreeReserveSlot's placeholder install.
	// Linux -race detector flags any concurrent slice-cell read/write
	// regardless of which range (primary/reserve) the index belongs to.
	reserveMu sync.Mutex

	// inflightDrains caps concurrent drains atomically — see spec §2.1.0.
	// startDrain increments before any state mutation, decrements via
	// drainWatchdog defer (guaranteed on all exit paths). Cap consulted
	// before readyCapacity check to close the TOCTOU window where multiple
	// triggers (age/byte/anti-FP) read identical capacity and all proceed.
	inflightDrains atomic.Int32

	streamMap sync.Map // map[uint16]*streamEntry — streamID -> entry (see stream_entry.go)

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

	// keepaliveBase is the base interval for the per-pool keepalive loop.
	// The loop samples JitteredIntervalLogNormal(keepaliveBase, 0.5), which
	// is truncated to [base/2, base*2] — so the MAX silence window a healthy
	// quiet slot can experience between two keepalive frames is keepaliveBase*2.
	//
	// Bug #9 (2026-05-31): a quiet long-lived stream (user waiting 5+ min for
	// an AI agent reply — almost no bytes in either direction) left its slot
	// silent. A direct-mode TCP to the bare origin IP is cut by the РФ TSPU /
	// a stateful middlebox after only ~10-15s of silence (field log:
	// close 1006 with last_write_age_ms=10000-15000). The slot then reconnects
	// with a 5-9s backoff and the stream — whose channel is force-closed in
	// handleSlotDeath — dies and does NOT migrate to a surviving slot, so the
	// session "не восстанавливается". Root cause = keepalive too rare: base was
	// 20s → window [10s, 40s], routinely exceeding the cut threshold.
	//
	// Fix: base default 5s → window [2.5s, 10s]. Max gap 10s stays under the
	// observed ~10-15s cut. Jitter (sigma 0.5 log-normal) is PRESERVED — anti-DPI
	// requires a non-periodic, heavy-tailed cadence (NEW-1 / final-audit P1-3);
	// we only shrink the base, we do NOT go to a fixed period. Field-tunable via
	// SHADOWLINK_KEEPALIVE_INTERVAL without a redeploy.
	keepaliveBase time.Duration

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
	// drainDeferrals1m — count of storm-brake drain deferrals in the
	// last 60s (mirror of rotations1m). Surfaced in `WS pool health`
	// snapshot. Aggregate across both gates (inflight cap + capacity
	// floor) — its only consumer is the alert trigger threshold, so a
	// per-gate split would add state without operational value.
	// Spec 2026-05-23 (introduced) + 2026-05-24 (kept aggregate).
	drainDeferrals1m atomic.Int32

	// slotDeaths1m — НАБЛЮДАТЕЛЬНЫЙ счётчик смертей слотов за ~60s, по всем
	// причинам без исключения. Ничего не исполняет.
	//
	// Существует отдельно от recentDeaths потому, что тот кормит
	// meltdown-кулдаун и намеренно пропускает age-cut: штатный каскад резов
	// не должен ставить реконнекты на паузу. Исполнительно это верно, но
	// наблюдателя оно ослепляет.
	//
	// Замер 2026-08-11 15:48: origin стал недоступен, 8 слотов умерли за
	// 3.6s, пул лёг целиком (alive=0, active_streams=0, 45 отказов "no ready
	// slots", 24 стрима задето). Шесть смертей из восьми имели возраст
	// 55-79s > ageCutMinAge=45s и были классифицированы как age_cut, поэтому
	// recentDeaths увидел 2 при пороге 6 — health напечатал meltdowns_1m=0.
	// Полный отказ пула не отразился НИ В ОДНОМ счётчике.
	//
	// Разведение наблюдаемости и исполнения — прямое требование урока H-15:
	// контур, про который нельзя сказать, работает ли он, хуже отсутствующего.
	slotDeaths1m atomic.Int32

	// revivalMu / revivalCh — broadcast «origin снова отвечает».
	//
	// Замер 2026-08-11: origin упал в 15:48:34, вернулся к 15:49:19, но
	// слоты 2 и 11 к тому моменту уже сидели на attempt=3 (пауза 60s) и
	// простояли лишние ~50s по здоровой сети. Лестница 5s·2^N правильно
	// защищает origin от шторма хендшейков, но она слепа: единственный её
	// вход — время, хотя факт «сеть жива» в системе уже есть — это успешный
	// connect соседнего слота.
	//
	// Канал, а не atomic-флаг: нужен именно broadcast (восстановление
	// origin — событие всего пула), и нужно, чтобы сигнал НЕ копился.
	// Закрытие будит всех ждущих разом; на его месте сразу создаётся новый
	// канал, поэтому слот, зашедший в ожидание позже, ждёт следующего
	// события, а не срабатывает на прошлом.
	revivalMu sync.Mutex
	revivalCh chan struct{}

	// lastInflightCapLogNs / lastCapacityFloorLogNs — per-gate UnixNano
	// timestamp of the most recent INFO emission of "drain deferred".
	// Used by shouldLogDeferred to rate-limit the human-readable log
	// without throttling the counters. Zero value (initial) means "never
	// logged" — first call always logs. Spec 2026-05-24
	// (drain-diagnostics-counter-split) §2.
	lastInflightCapLogNs   atomic.Int64
	lastCapacityFloorLogNs atomic.Int64

	// reserveConnectFailures — per-cell consecutive-failure counter for
	// connectReserveSlot. Indexed by cell index (0..2*poolSize-1). Reset
	// to 0 on successful connect. Lives on the pool (not the poolSlot)
	// because cells get recycled — placing the counter on poolSlot would
	// reset it to zero each time a fresh slot replaces a failed one,
	// defeating the backoff under cascade failures. Slice is
	// pre-allocated in NewWSPoolTransport so connectReserveSlot can do
	// lock-free atomic Add/Store/Load on a stable address.
	//
	// Spec 2026-05-24 (concurrency-lift-and-backoff) §2.
	reserveConnectFailures []atomic.Int32

	startedAt time.Time

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

	flowDesiredWindow uint64 // Bug #8: 0 → flow control off; else advertised window

	// migrateEnabled is set true once ANY slot negotiates Bug #9 stream
	// migration (FLOWCTL V2 marker, migrate bit). Atomic so the SOCKS5 front-end
	// (MigrationEnabled accessor) reads it lock-free. Pool-wide and write-once-true
	// (connectSlot); never flipped back to false.
	//
	// SCOPE (H-C3, audit 2026-06-11): this bit drives ONLY the SOCKS front-end
	// registration decision (it must register seq channels as soon as ANY slot
	// CAN produce seq frames). It does NOT decide the per-frame downlink DECODE
	// shape — that is now per-slot (poolSlot.migrateNegotiated), latched from each
	// slot's OWN FLOWCTL ack. The old invariant "once on, the downlink format is
	// seq-tagged for all slots" was false: the server latches seq format
	// per-session at its own negotiation point, not atomically with this
	// pool-wide flip, so a flat-session slot must keep flat-decoding after the
	// flip. The decode shape follows the producing session, not this pool bit.
	migrateEnabled atomic.Bool

	// ── Bug #9 Task 15: MIGRATE/RESUME send + ack-await + hysteresis ──────────
	//
	// pendingMigrateAcks maps streamID → chan migrateResult. sendMigrate
	// registers a buffered (cap 1) chan before enqueuing the frame; the slot
	// reader resolves it via resolveMigrateReplyPayload when a MIGRATE_OK/FAIL
	// reply arrives (after decrypting the chunk with FlagMigrate/FlagResume).
	// sendMigrate races the resolve against migrateAckTimeout — exactly one of
	// {reply, timeout} wins (the chan is removed from the map under LoadAndDelete
	// so a late reply after a timeout is dropped, never delivered to a
	// closed/garbage chan). One in-flight MIGRATE per streamID at a time.
	pendingMigrateAcks sync.Map // map[uint16]chan migrateResult

	// consecutiveMigrateTimeouts counts MIGRATE/RESUME attempts that timed out
	// back-to-back. At >=migrateHysteresisThreshold it flips migrateCapable
	// false (the server stopped acking — stop trying and let streams hard-break
	// rather than stall 1.5s each). Reset to 0 on any OK reply or a fresh
	// handshake (resetMigrateHysteresis, called from connectSlot on negotiate).
	consecutiveMigrateTimeouts atomic.Int32

	// migrateCapable gates whether sendMigrate even attempts. Set true when a
	// slot negotiates migration (connectSlot); dropped to false by the
	// hysteresis. Distinct from migrateEnabled (the pool-wide wire-format flag,
	// never flipped back): migrateCapable is a runtime health bit that recovers
	// on the next successful handshake.
	migrateCapable atomic.Bool

	// migrateAckTimeoutOverride lets a unit test shorten the 1500ms ack window
	// so timeout tests don't sleep. Zero → use the migrateAckTimeout const.
	migrateAckTimeoutOverride time.Duration

	// ── Bug #9 Task 16: age-watchdog migration scheduling test hooks ──────────
	//
	// migrateStreamHook, when non-nil, replaces the real migrateStream wire
	// round-trip in scheduleSlotMigration's per-stream timers. Lets a unit test
	// observe scheduling/idempotency without a live slot. Production leaves it
	// nil (the AfterFunc calls p.migrateStream directly).
	migrateStreamHook func(streamID uint16)

	// migrateSpreadOverride shortens the U(0,spread) per-stream offset so a
	// unit test's AfterFunc timers fire in milliseconds instead of seconds.
	// Zero → use migrationSpread().
	migrateSpreadOverride time.Duration

	// migrateSendHook, when non-nil, replaces the real sendMigrate wire
	// round-trip used by BOTH the preemptive watchdog (migrateStream, T16) and
	// the reactive RESUME-on-slot-death path (resumeStreamOnDeath, T17). Lets a
	// unit test script the migrateResult (OK/FAIL/timeout) without a live slot or
	// crypto session. Production leaves it nil → callers invoke p.sendMigrate.
	migrateSendHook func(streamID uint16, kind byte, targetIdx int) migrateResult
}

// migrateHysteresisThreshold is the number of consecutive MIGRATE/RESUME
// timeouts that disables migration capability (§3.5). Three keeps a single
// transient hiccup from disabling the feature while still reacting fast to a
// server that genuinely stopped acking.
const migrateHysteresisThreshold = 3

// migrateResultKind discriminates the outcome of a MIGRATE/RESUME ack-await.
type migrateResultKind int

const (
	migrateResultOK      migrateResultKind = iota // server replied OK
	migrateResultFail                             // server replied FAIL (proof/grace/limit)
	migrateResultTimeout                          // no reply within the ack window
	migrateResultNoSend                           // could not even enqueue (no proof / dead slot)
)

// migrateResult is the outcome of sendMigrate. resumeDownSeq is meaningful only
// for migrateResultOK (the seq up to which the old slot's in-flight tail must
// be awaited before new-slot data is treated as continuous, §3.4). reason is
// the server's failure code for migrateResultFail (core.MigrateReason*).
type migrateResult struct {
	kind          migrateResultKind
	resumeDownSeq uint64
	reason        byte
}

// Compile-time assertions.
var (
	_ StreamTransport     = (*WSPoolTransport)(nil)
	_ PoolAware           = (*WSPoolTransport)(nil)
	_ PendingTracker      = (*WSPoolTransport)(nil)
	_ ControlPoolAware    = (*WSPoolTransport)(nil)
	_ TryControlPoolAware = (*WSPoolTransport)(nil) // Bug #8 Task 11: guards TryWriteControlMessageForStream
	_ PoolReadiness       = (*WSPoolTransport)(nil)
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
	// Per-slot stagger is automatic: slot N rotates at MaxSlotAge + N*step,
	// so 8 slots ageing simultaneously don't all rotate in the same instant
	// and create a handshake storm. The stagger ladder is capped via
	// StaggerOffsetCap so high-idx slots in the 2*poolSize uniform-cells
	// slice can't be pushed into the TSPU freeze window.
	MaxSlotAge time.Duration

	// StaggerStep is the per-slot grid interval used by slotStaggerOffset.
	// 0 → slotRotationStaggerStep default. env SHADOWLINK_STAGGER_STEP.
	StaggerStep time.Duration

	// StaggerOffsetCap clamps the linear idx*step stagger so high-idx slots
	// (the uniform-cells slice runs idx 0..2*poolSize-1) don't get pushed
	// past MaxSlotAge into the ~130s TSPU direct-TCP freeze window. 0 → no
	// cap (legacy unbounded ladder). env SHADOWLINK_STAGGER_OFFSET_CAP.
	StaggerOffsetCap time.Duration

	// AgeCutMinAge is the age-cut classification floor; kept in lockstep with
	// MaxSlotAge so slots are reclassified as "aged" consistently with the
	// rotation threshold. 0 → 60s default. env SHADOWLINK_AGE_CUT_MIN_AGE.
	AgeCutMinAge time.Duration

	// ByteBudgetMinInterval is the wall-clock floor before a byte-budget
	// rotation may fire on a freshly-(re)connected slot (Bug #4 storm fix).
	// 0 → use the default (byteBudgetMinRotationInterval) when byte budget is
	// enabled. Negative → disable the floor entirely. See
	// byteBudgetRotationAllowed.
	ByteBudgetMinInterval time.Duration

	// WriteTimeout caps each WS frame's write deadline. 0 → WSAsyncWriter
	// default (30s). For viaCF mode pass 5-8s: CF-side stalls propagate as
	// TCP backpressure, and 30s means a stuck slot blocks traffic for 30s
	// before the pool can route around it. Cross-check 2026-04-15 H6.
	WriteTimeout time.Duration

	// StaggerDelay spaces initial slot handshakes. 0 disables. Recommended
	// ~300ms × slot index so 8 TCP SYNs don't arrive at CF edge in the same
	// millisecond and trip burst/rate-limit heuristics.
	StaggerDelay time.Duration

	// KeepaliveInterval is the base interval for the per-pool keepalive loop.
	// 0 → default (keepaliveDefaultBase = 5s). The loop samples
	// JitteredIntervalLogNormal(KeepaliveInterval, 0.5), truncated to
	// [base/2, base*2], so the worst-case silence window on a quiet slot is
	// KeepaliveInterval*2. Keep it under the middlebox/TSPU silent-cut window
	// (~10-15s observed for direct-mode bare-origin TCP — Bug #9). Field-tune
	// via SHADOWLINK_KEEPALIVE_INTERVAL.
	KeepaliveInterval time.Duration

	// Meltdown protection parameters. All default to sensible values if zero.
	MeltdownWindow    time.Duration // how long "recent death" lasts (default 5s)
	MeltdownThreshold int           // N deaths in window triggers cooldown (default = ceil(size/2), min 2)
	MeltdownCooldown  time.Duration // reconnect pause after trigger (default 10s)

	// GracefulDrain enables the HTTP/2 GOAWAY-style draining path.
	// When true, slot rotation transitions through slotDraining +
	// parallel reserve reconnect; existing streams finish naturally
	// (up to DrainHardCap) instead of being force-closed.
	// When false, legacy behavior: rotation goes directly through
	// fireRotation → handleSlotDeath (kills all active streams).
	// Default false during Phase 1 rollout; flipped to true after
	// pl1 canary observation.
	GracefulDrain bool

	// DrainHardCap is the maximum time a slot can stay in slotDraining
	// before forced teardown. Only consulted when GracefulDrain is true.
	// Zero defaults to 90s (Envoy Gateway recommendation for long-lived
	// multiplexed streams). Field-tune via SHADOWLINK_DRAIN_HARD_CAP env.
	DrainHardCap time.Duration

	// DrainIdleThreshold enables drainWatchdog's idle-finish path: when a
	// draining slot has no decrypt/write activity for this long AND its
	// remaining stream count is ≤ DrainIdleStreamsMax, the drain is
	// treated as natural finish early. Zero disables the heuristic.
	// Field-tune via SHADOWLINK_DRAIN_IDLE_THRESHOLD env.
	DrainIdleThreshold time.Duration

	// DrainIdleStreamsMax is the upper bound on remaining streams under
	// which the idle-finish heuristic is allowed to fire. Zero disables
	// the heuristic (regardless of DrainIdleThreshold). Field-tune via
	// DrainIdleStreamsMax — Deprecated: no longer participates in the
	// idle gate decision after Step 2 (per-stream idle decision).
	// Kept on the struct for env-parsing backward compatibility. Use
	// DrainIdleThreshold=0 to disable the idle gate.
	DrainIdleStreamsMax int32

	// ── Bug #6 sticky stream (adaptive backstop) ──
	// StickyMaxDrainAge: макс. время, которое активный стрим переживает дренаж
	// (от старта дренажа, монотонные часы). 0 → default 10m. Отрицательное
	// cfg-значение → kill switch: deadline-ветка деградирует в слепой hard-cap.
	StickyMaxDrainAge time.Duration

	// StickyMaxTotalBytes: анти-TSPU потолок на текущем отрезке TCP (downBytes).
	// 0 → default 256 MiB. Рвём активный стрим если TCP прокачал столько —
	// per-flow byte counter detection vector (см. poolSlot.byteBudget docstring).
	StickyMaxTotalBytes int64

	// StickyMaxSlots: статический потолок одновременно sticky-слотов. 0 → авто
	// (poolSize/2). <0 → sticky запрещён (cap=0). Фактический cap ещё и
	// динамический — гейтится readyCapacity (см. stickyQuotaAvailable, позже).
	StickyMaxSlots int
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
	drainHardCap := cfg.DrainHardCap
	if drainHardCap <= 0 {
		// 90s default per Envoy Gateway recommendation for long-lived
		// multiplexed streams. Only consulted when GracefulDrain is true.
		drainHardCap = 90 * time.Second
	}
	drainIdleThreshold := cfg.DrainIdleThreshold
	if drainIdleThreshold < 0 {
		drainIdleThreshold = 0
	}
	drainIdleStreamsMax := cfg.DrainIdleStreamsMax
	if drainIdleStreamsMax < 0 {
		drainIdleStreamsMax = 0
	}
	// Byte-budget rotation rate floor (Bug #4). Apply the default only when
	// byte-budget rotation is actually enabled (maxBytesPerSlot > 0); with the
	// budget off the floor is meaningless. Negative cfg value disables it.
	byteBudgetMinInterval := cfg.ByteBudgetMinInterval
	if byteBudgetMinInterval == 0 && cfg.MaxBytesPerSlot > 0 {
		byteBudgetMinInterval = byteBudgetMinRotationInterval
	}
	if byteBudgetMinInterval < 0 {
		byteBudgetMinInterval = 0
	}
	// Bug #6 sticky stream defaults. StickyMaxDrainAge<=0 is the kill switch:
	// the deadline branch degrades to the legacy blind hard-cap teardown.
	//
	// Default 10min → 15s (2026-07-31), from MEASUREMENT rather than assumption.
	// Slot-death telemetry (client/slotobs, 19 age-cuts in one field session)
	// showed the middlebox cuts on the AGE axis (CV 0.18 vs 2.20 for bytes) with
	// the EARLIEST death at 85.3s — not the ~130s the previous tuning assumed.
	// A 10-minute sticky window let a draining slot live to 75s+10min, i.e. far
	// inside the observed cut window; the field log recorded 36 sticky-backstop
	// teardowns and 136 forcibly severed streams.
	//
	// Cutting it is safe because stream MIGRATION does the job better: the same
	// session logged 320 successful migrations with 0 failures and only 5 real
	// data losses. Holding a stale slot buys almost nothing and exposes it to the
	// cut. 75s rotation + 15s sticky = 90s worst-case teardown.
	//
	// This is still a hard-coded number and therefore still wrong for someone
	// else's network — 90s exceeds the 85.3s seen here, so the margin is not
	// positive even now. The real fix is deriving the threshold per-AS from
	// slotobs observations (P0 step 2, docs/audit/2026-07-25-round18/FIELD-CHECKS.md §2);
	// this default only stops the pathological case until then.
	stickyMaxDrainAge := cfg.StickyMaxDrainAge
	if stickyMaxDrainAge == 0 {
		stickyMaxDrainAge = DefaultStickyMaxDrainAge
	}
	// ⚠ Достижимость sticky. Дедлайн дренажа ставится на drainHardCap, и ветка
	// `drainAge >= stickyMaxDrainAge` проверяется только ПО ЕГО СРАБАТЫВАНИИ.
	// Поэтому sticky <= hard_cap не продлевает дренаж НИ НА СЕКУНДУ: первая же
	// проверка уходит в finishStickyAgeBackstop, а markSticky + deadline.Reset
	// недостижимы. Хуже всего, что лог при этом пишет sticky_outcome=age_backstop,
	// то есть механизм ВЫГЛЯДИТ работающим.
	//
	// Замер 2026-08-07 (2ч49м, hard_cap=sticky=15s): sticky_active=0 во всех
	// health-строках при 8 teardown с sticky_outcome=age_backstop; drain_duration
	// принимал ровно два значения — 15s и 0s, ни одного продления на
	// stickyRecheckInterval. Механизм не исполнялся ни разу.
	//
	// Не «чиним» значение молча: подмена настройки за спиной оператора — тот же
	// класс отказа. Говорим вслух, поведение оставляем как настроено.
	if cfg.GracefulDrain && stickyMaxDrainAge > 0 && drainHardCap > 0 && stickyMaxDrainAge <= drainHardCap {
		slog.Warn("sticky drain backstop is UNREACHABLE — sticky <= hard_cap",
			"sticky_max_drain_age", stickyMaxDrainAge,
			"drain_hard_cap", drainHardCap,
			"effect", "дренаж рвёт hard_cap; sticky_outcome в логах вводит в заблуждение",
			"fix", "SHADOWLINK_STICKY_MAX_DRAIN_AGE > SHADOWLINK_DRAIN_HARD_CAP, либо sticky<0 для явного выключения")
	}
	// negative stays negative → sticky disabled (kill switch).
	stickyMaxTotalBytes := cfg.StickyMaxTotalBytes
	if stickyMaxTotalBytes <= 0 {
		stickyMaxTotalBytes = 256 * 1024 * 1024 // 256 MiB
	}
	// Bug #9 keepalive interval. 0 → default 5s (window [2.5s, 10s] under the
	// log-normal sampler). Clamp negative/garbage to the default too. We do NOT
	// allow an arbitrarily large value to silently re-introduce the bug, but we
	// also don't hard-cap — operators tuning UP (e.g. a server known to tolerate
	// longer silence, or a viaCF path with a friendlier idle timeout) is a valid
	// field decision; the default is the safe floor.
	keepaliveBase := cfg.KeepaliveInterval
	if keepaliveBase <= 0 {
		keepaliveBase = keepaliveDefaultBase
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &WSPoolTransport{
		poolSize:              cfg.Size,
		maxPendingPerSlot:     int32(cfg.MaxPendingPerSlot),
		maxStreamsPerSlot:     int32(cfg.MaxStreamsPerSlot),
		maxBytesPerSlot:       cfg.MaxBytesPerSlot,
		maxSlotAge:            cfg.MaxSlotAge,
		staggerStep:           cfg.StaggerStep,
		staggerOffsetCap:      cfg.StaggerOffsetCap,
		ageCutMinAge:          cfg.AgeCutMinAge,
		slotDeaths:            slotobs.NewRecorder(0), // 0 → DefaultCapacity
		ageAdapter:            slotobs.NewAdapter(cfg.MaxSlotAge),
		byteBudgetMinInterval: byteBudgetMinInterval,
		gracefulDrain:         cfg.GracefulDrain,
		drainHardCap:          drainHardCap,
		drainIdleThreshold:    drainIdleThreshold,
		drainIdleStreamsMax:   drainIdleStreamsMax,
		stickyMaxDrainAge:     stickyMaxDrainAge,
		stickyMaxTotalBytes:   stickyMaxTotalBytes,
		stickyMaxSlots:        cfg.StickyMaxSlots,
		serverAddr:            cfg.ServerAddr,
		sniHost:               cfg.SNIHost,
		cfIP:                  cfg.CFIP,
		useTLS:                cfg.UseTLS,
		skipVerify:            cfg.SkipVerify,
		lockedFP:              cfg.LockedFP,
		client:                cl,
		writeTimeout:          cfg.WriteTimeout,
		staggerDelay:          cfg.StaggerDelay,
		keepaliveBase:         keepaliveBase,
		meltdownWindow:        cfg.MeltdownWindow,
		meltdownThreshold:     cfg.MeltdownThreshold,
		meltdownCooldown:      cfg.MeltdownCooldown,
		meltdownLimiter:       newMeltdownLimiter(),
		meltdownLogRNG:        mrand.New(mrand.NewSource(time.Now().UnixNano())),
		startedAt:             time.Now(),
		ctx:                   ctx,
		cancel:                cancel,
		log:                   slog.Default(),
	}
	p.flowDesiredWindow = flowWindowFromEnv(1 << 20)
	p.initRevivalSignal()
	p.allocSlots()
	return p
}

// allocSlots initializes p.slots as a slice of 2*poolSize cells.
// Indices [0, poolSize) are primary cells, populated by Connect's slot
// initialization loop. Indices [poolSize, 2*poolSize) are reserve cells,
// nil until populated by the drain machinery.
//
// Also (re)initializes p.reserveConnectFailures (spec 2026-05-24 §2)
// to a fresh zero-filled slice. This is correct for a fresh pool but
// would WIPE per-cell backoff state if called on a live pool mid-flight.
// Callers other than NewWSPoolTransport must understand this side
// effect before invoking allocSlots a second time.
func (p *WSPoolTransport) allocSlots() {
	p.slots = make([]*poolSlot, p.poolSize*2)
	// Pool-level per-cell counter for connectReserveSlot exponential
	// backoff (spec 2026-05-24 §2). Size matches slots — counter index
	// follows cell index. Zero-init is semantically correct (no prior
	// failures on a fresh pool).
	p.reserveConnectFailures = make([]atomic.Int32, p.poolSize*2)
}

// snapshotSlots returns a copy of the p.slots element pointers taken under
// reserveMu. Background sweepers (rotationWatchdogSweep) MUST iterate this
// snapshot rather than indexing p.slots directly: writers (connectSlot,
// connectReserveSlot, handleSlotDeath teardown, claimFreeReserveSlot,
// startDrain claim) mutate the slice cells under reserveMu, and an unguarded
// `slot := p.slots[idx]` read races with those writes (Linux -race, Bug#6
// drain/reconnect). The slice header itself never changes after allocSlots,
// so only the per-cell pointer read needs the lock; copying pointers is O(n)
// under a short critical section and lets the sweep run lock-free afterwards
// (every shared *poolSlot field it touches is atomic). The snapshot may go
// stale immediately after the lock is released — that is acceptable: a cell
// nilled or replaced after the copy is simply skipped/handled on the next
// 5s tick, exactly as before this fix.
func (p *WSPoolTransport) snapshotSlots() []*poolSlot {
	p.reserveMu.Lock()
	defer p.reserveMu.Unlock()
	out := make([]*poolSlot, len(p.slots))
	copy(out, p.slots)
	return out
}

// slotAt returns the *poolSlot installed at idx, read under reserveMu, or
// nil for an empty/out-of-range cell. This is the SINGLE centralized
// single-cell accessor: every read of p.slots[idx] outside snapshotSlots
// goes through here so the locking discipline is uniform — "every slice-cell
// access holds reserveMu" — rather than the half-applied "writers always
// lock; readers sometimes lock" hazard the 2026-06-01 snapshot/capture fixes
// left behind (audit H1, 2026-06-11). The lifecycle writers (connectSlot
// install, handleSlotDeath teardown nil, claimFreeSlot, connectReserveSlot
// free, rebind/ReleaseStream capture) all mutate cells under reserveMu; an
// unguarded `slot := p.slots[idx]` read races them (Linux -race). Critical
// section is a single pointer load — bounded by the same tiny window as the
// claim scan, so contention with the hot read paths is negligible.
func (p *WSPoolTransport) slotAt(idx int) *poolSlot {
	p.reserveMu.Lock()
	defer p.reserveMu.Unlock()
	if idx < 0 || idx >= len(p.slots) {
		return nil
	}
	return p.slots[idx]
}

// storeSlot installs (or, with nil, clears) the cell at idx under reserveMu.
// It is the centralized counterpart to slotAt for the rare test/utility
// writer; the production lifecycle writers keep their own bespoke
// reserveMu critical sections (connectSlot, handleSlotDeath teardown,
// claimFreeSlot, connectReserveSlot) because they couple the cell write with
// adjacent locked reads (recycle guard, claim scan). Out-of-range is a no-op.
func (p *WSPoolTransport) storeSlot(idx int, slot *poolSlot) {
	p.reserveMu.Lock()
	defer p.reserveMu.Unlock()
	if idx < 0 || idx >= len(p.slots) {
		return
	}
	p.slots[idx] = slot
}

// Connect establishes all WS connections in parallel.
// Returns success when at least one slot is ready.
func (p *WSPoolTransport) Connect(ctx context.Context) error {
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

	SetGlobalPoolForStats(p)
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
	ticker := time.NewTicker(rotationWatchdogTick)
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
	// Uniform-cells: iterate the entire slice. Cells that drifted from
	// primary to reserve range still need age-driven drain — see spec
	// 2026-05-20 §2.3.
	//
	// Snapshot the slice-cell pointers under reserveMu (see snapshotSlots):
	// connectSlot/connectReserveSlot/handleSlotDeath/startDrain all write
	// p.slots[idx] under reserveMu, so an unguarded `slot := p.slots[idx]`
	// read here races them (Bug#6 drain/reconnect, Linux -race). We do NOT
	// hold reserveMu across the sweep — startDrain/connect would stall — so
	// take the snapshot once, then iterate it lock-free (every *poolSlot
	// field below is atomic).
	slots := p.snapshotSlots()
	for idx := range slots {
		slot := slots[idx]
		if slot == nil || slot.getState() != slotReady {
			continue
		}
		// Skip slots in drain backoff (storm brake / no-reserve revert in
		// startDrain just deferred this one — don't immediately retry).
		if slot.nextDrainAttemptNs.Load() > nowNs {
			continue
		}
		started := slot.startedAtNs.Load()
		if started == 0 {
			continue // not yet connected; connectSlot hasn't stamped it
		}

		// Bug #9 Task 16: preemptive stream migration. When the slot crosses its
		// per-session migration threshold (sampled base × U(0.7,1.0), default
		// 60s) AND the pool can migrate AND the slot still carries active
		// streams, schedule each active stream to MIGRATE onto a younger slot
		// with an independent U(0,spread) delay (NOT a burst — F7 §5.6). This is
		// ADDITIVE to the age/byte rotation below: the aging slot keeps serving
		// until its streams drain or it hits the (later) age-rotation threshold,
		// but its long-lived downloads get moved off BEFORE the ~130s TSPU
		// freeze window freezes the TCP. Idempotent per stream via streamEntry.
		// migrationScheduled (covers streams that attach after the first pass).
		if migThresh := slot.migrationThresholdNs.Load(); migThresh > 0 &&
			nowNs-started >= migThresh &&
			p.MigrateCapable() &&
			slot.streams.Load() > 0 {
			p.scheduleSlotMigration(idx, slot)
		}

		// Per-slot age threshold = max-age + per-session frozen grid jitter.
		//
		// P0 шаг 3 (2026-07-31): базу берём у адаптера, а не напрямую из
		// p.maxSlotAge. Адаптер только СЖИМАЕТ порог по наблюдаемому поведению
		// сети (см. slotobs.Adapter) и никогда не поднимает выше
		// сконфигурированного, поэтому подстановка безопасна: при отсутствии
		// подтверждённого вывода Threshold() возвращает ровно p.maxSlotAge.
		// Stagger-джиттер добавляется поверх как раньше — он про размазывание
		// ротаций по сетке, а не про порог.
		baseMaxAge := p.maxSlotAge
		if adapted := p.ageAdapter.Threshold(); adapted > 0 {
			baseMaxAge = adapted
		}
		effectiveMaxAge := baseMaxAge.Nanoseconds() + slot.staggerOffsetNs.Load()
		if nowNs-started < effectiveMaxAge {
			continue
		}
		if p.gracefulDrain {
			p.startDrain(p.client, idx, "age")
		} else {
			slotStart := time.Unix(0, started)
			p.maybeRotateSlot(p.client, idx, slot, "age",
				0,
				slotStart,
				slot.downBytes.Load(),
			)
		}
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

// poolStateCounts returns the breakdown of cell states across the
// whole slice. Uniform-cells schema (spec 2026-05-20 §2.4):
//   - alive: slotReady cells
//   - dead: slotDead cells (literal, NOT nil)
//   - empty: nil cells (new field — replaces the old "nil primary = dead++" semantics)
//   - sum invariant: alive + dead + connecting + draining + empty == 2*poolSize
func (p *WSPoolTransport) poolStateCounts() (alive, dead, connecting, draining, empty int) {
	for _, slot := range p.snapshotSlots() {
		if slot == nil {
			empty++
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
	}
	return
}

func (p *WSPoolTransport) emitHealthSummary() {
	alive, dead, connecting, draining, empty := p.poolStateCounts()
	rateLimited := 0
	var totalStreams int32
	now := time.Now()
	for _, slot := range p.snapshotSlots() {
		if slot == nil {
			continue
		}
		totalStreams += slot.streams.Load()
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
		"empty", empty,
		"connecting", connecting,
		"draining", draining,
		"sticky_active", p.stickyDrainCount.Load(), // Bug #6: slots currently in sticky drain extension
		"rate_limited_recent", rateLimited,
		"active_streams", totalStreams,
		"meltdowns_1m", p.meltdowns1m.Load(),
		// slot_deaths_1m — все смерти, включая age-cut, который meltdowns_1m
		// намеренно не считает. Без этого поля полный отказ пула (замер
		// 2026-08-11 15:48: alive=0 при meltdowns_1m=0) не виден нигде.
		"slot_deaths_1m", p.slotDeaths1m.Load(),
		"rotations_1m", p.rotations1m.Load(),
		"inflight_drains", p.inflightDrains.Load(),
		"inflight_cap_deferred_total", Stats.InflightCapDeferredTotal.Load(),
		"capacity_floor_deferred_total", Stats.CapacityFloorDeferredTotal.Load(),
		"deferred_drains_1m", p.drainDeferrals1m.Load(),
		"uptime", uptime,
	)
}

// keepaliveLoop sends FlagKeepalive to every healthy slot at a jittered
// cadence centered on p.keepaliveBase (default 5s → window [2.5s, 10s]).
//
// Two jobs:
//  1. Keep a long-lived but QUIET slot alive. A direct-mode TCP to the bare
//     origin IP is cut by the РФ TSPU / a stateful middlebox after only
//     ~10-15s of silence (Bug #9). Keeping the keepalive gap under that
//     window stops the silent-cut from ever firing — which matters because
//     a slot death force-closes its streams (handleSlotDeath) and the stream
//     does NOT migrate, so a quiet AI-agent session would die unrecoverably.
//     The old 20s base (window up to 40s) routinely lost this race.
//  2. Keep CF's Proxy Write Timeout (30s) and Idle Timeout (900s) from
//     reaping the WS — trivially satisfied by the much tighter window.
//
// The log-normal jitter (final-audit-2026-05-03 P1-3, upgraded from uniform
// ±30% NEW-1 fix) is PRESERVED — it destroys the FFT-visible periodic peak and
// defeats ML classifiers that distinguish flat-band uniform jitter from
// heavy-tailed real-world inter-frame jitter. Bug #9 only shrank the base.
func (p *WSPoolTransport) keepaliveLoop() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(p.nextKeepaliveDelay()):
			p.sendKeepaliveToAllSlots()
		}
	}
}

// nextKeepaliveDelay samples the next keepalive interval from the log-normal
// jitter sampler centered on p.keepaliveBase. Extracted so the Bug #9
// max-silence-window invariant can be unit-tested deterministically without
// driving the goroutine loop.
func (p *WSPoolTransport) nextKeepaliveDelay() time.Duration {
	base := p.keepaliveBase
	if base <= 0 {
		base = keepaliveDefaultBase
	}
	return JitteredIntervalLogNormal(base, keepaliveSigma)
}

func (p *WSPoolTransport) sendKeepaliveToAllSlots() {
	sent := 0
	for i, slot := range p.snapshotSlots() {
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

// sendSlotSessionFIN emits a session-wide FIN (streamID=0) over the slot's
// still-live transport so the server can release the session immediately
// instead of waiting for its idle timeout.
//
// Why this exists (2026-05-29 ghost-session fix): when the pool retires a slot
// it controls — preemptive rotation or graceful-drain teardown — the slot's WS
// is closed but the server is never told the session is finished. The server
// keeps the session in its map until SessionTimeout (90s). With max_conns=8 and
// rotation every 30-90s, sessions accumulate faster than they idle out, so
// h.sessions.Count() breaches MaxClients and the server serves a max_clients
// decoy to a single legitimate client. A session-wide FIN drives the server's
// handleFin (Remove + ActiveClients--) at once, mirroring the single-WS path's
// sendBestEffortSessionFIN.
//
// Best-effort: the FIN rides the slot's control queue on the open transport;
// any error is ignored (the server's idle sweeper is the fallback, exactly as
// before this fix). Caller must invoke this BEFORE transport.Close(). No-op for
// nil slot / nil session / nil transport (e.g. a slot already dead from a real
// network failure — there is nothing live to send over).
func (p *WSPoolTransport) sendSlotSessionFIN(slot *poolSlot) {
	if slot == nil || slot.session == nil || slot.transport == nil {
		return
	}
	// Session-wide FIN: empty payload routes through the server's handleFinChunk
	// to handleFin (Remove session + ActiveClients--). NewStreamFinChunk(...,0)
	// would NOT work — its 2-byte streamID lands on the per-stream branch and
	// leaves the session to linger until idle timeout (the original bug).
	fin := core.NewSessionFinChunk(slot.session.ID, slot.session.NextSeqNum())
	enc, err := slot.session.EncryptChunk(fin)
	if err != nil {
		p.log.Debug("slot session FIN: encrypt failed", "err", err)
		return
	}
	if err := slot.transport.WriteControlMessage(enc); err != nil {
		p.log.Debug("slot session FIN: write failed", "err", err)
	}
}

// connectSlot creates a new WS connection for the given slot index.
func (p *WSPoolTransport) connectSlot(ctx context.Context, idx int) error {
	slot := &poolSlot{index: idx}
	slot.setState(slotConnecting)
	// reserveMu serializes this write with the drain-teardown nil-write
	// in handleSlotDeath and the placeholder write in claimFreeReserveSlot.
	// Without it, a concurrent drain teardown could nil this cell after
	// connectSlot installed the new *poolSlot — slot leak. See spec §C3.
	p.reserveMu.Lock()
	p.slots[idx] = slot
	p.reserveMu.Unlock()

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
	// H-K1 (2026-06-11): switch client uplink to counter-nonce AEAD. Wire-compat
	// (peer reads any 12-byte nonce from the frame header). Failure here means
	// SendKey is unusable — fail the slot rather than silently fall back to the
	// random-nonce regime.
	if err := session.InitSendEpoch(); err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: init send epoch: %w", idx, err)
	}
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
	wst.flowDesiredWindow = uint32(p.flowDesiredWindow) // 0 → off
	// D3: ws upgrade now authenticates via a post-upgrade first frame built
	// from the slot's session — Bearer header is gone.
	if err := wst.UpgradeToWS(slot.token, slot.session); err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: ws upgrade: %w", idx, err)
	}

	slot.transport = wst
	if wst.flowControlEnabled {
		slot.flowControlEnabled = true
		slot.flowWindow = uint64(wst.flowWindow)
		p.client.EnableFlowControl(uint64(wst.flowWindow), p)
	}
	// H-C3 (audit 2026-06-11): latch the seq-tagged decode shape PER-SLOT from
	// THIS slot's own FLOWCTL ack. The slot reader keys its FlagData decode on
	// slot.migrateNegotiated so a slot whose session speaks flat keeps
	// flat-decoding even after another slot flips the pool-wide bit. A recycled
	// cell got a fresh *poolSlot from connectSlot's reserve path, so this is set
	// fresh per (re)connect (no stale-true carry-over from a prior session).
	slot.migrateNegotiated.Store(wst.flowMigrateEnabled)
	// Bug #9 §5.4: latch pool-wide migration once a slot negotiated it. Kept for
	// the SOCKS5 front-end registration decision (MigrationEnabled accessor) —
	// it must register seq channels as soon as ANY slot can produce seq frames.
	// The downlink DECODE shape is now per-slot (above), not this bit.
	if wst.flowMigrateEnabled {
		p.migrateEnabled.Store(true)
		// Task 15: a fresh negotiated handshake re-arms migration capability and
		// clears the timeout hysteresis — the server is alive and acked FLOWCTL,
		// so any prior "stopped acking" verdict is stale.
		p.resetMigrateHysteresis()
	}
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
	slot.staggerOffsetNs.Store(int64(p.slotStaggerOffset(idx)))
	// Bug #9 Task 16: sample THIS connection's preemptive-migration threshold
	// once and freeze it (base × U(0.7,1.0)). Per-slot jitter smears the
	// migration onset so the pool's slots don't all begin migrating at the same
	// offset from connect (FFT-visible periodicity). The migration scheduling
	// gate is now per-stream (streamEntry.migrationScheduled) — a recycled cell's
	// fresh streamEntries start un-scheduled, so no per-slot reset is needed here.
	slot.migrationThresholdNs.Store(sampleMigrationThreshold(migrationThresholdBase()))
	// Stamp the slot's startup time — both the reader's local age check and
	// the pool-level rotation watchdog goroutine read this. Set BEFORE
	// setState(slotReady) so the watchdog never observes a ready slot with
	// startedAtNs=0.
	now := time.Now().UnixNano()
	slot.startedAtNs.Store(now)
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
	p.reconnectLoopInner(idx, false)
}

// reconnectLoopFast is the age-cut reconnect path (Lever 1, pool-capacity-dip-
// fix). It is reconnectLoop with a near-zero initial delay: attempt 0 sleeps
// U(0, ageCutReconnectJitter) instead of slotBackoffDuration(0)'s 5-10s. A
// successful attempt-0 connect heals the dip immediately; if attempt 0's connect
// FAILS (a genuine origin problem, not a routine middlebox cut), the loop falls
// into the SAME exponential ladder as reconnectLoop from attempt=1 — so a real
// outage still backs off properly. All other machinery (meltdown cooldown gate,
// recycle guard, ctx-cancel, ErrRateLimited cooldown) is shared verbatim.
func (p *WSPoolTransport) reconnectLoopFast(idx int) {
	p.reconnectLoopInner(idx, true)
}

// reconnectLoopInner is the shared reconnect loop body. fastFirstAttempt selects
// the age-cut fast path on attempt 0 (ageCutReconnectJitter, with age-cut
// counters); false is the legacy natural/rotation path (exponential backoff,
// post-meltdown handshake spreading). Extracted so the two entry points do NOT
// duplicate the recycle-guard / ctx-cancel / rate-limit logic (DRY).
func (p *WSPoolTransport) reconnectLoopInner(idx int, fastFirstAttempt bool) {
	// lastWasRateLimited — предыдущая попытка упёрлась в серверный
	// TokenBucket. Гейтит сброс лестницы по сигналу «сеть вернулась»:
	// см. запрет 2026-05-18 ниже по коду и обоснование там же.
	lastWasRateLimited := false
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

		// Initial-delay selection. The age-cut fast path (fastFirstAttempt) on
		// attempt 0 uses a near-zero U(0, ageCutReconnectJitter) spread — the
		// whole point of the dip fix is to NOT sit in the 5-10s exponential while
		// a routine TSPU cut heals. Once attempt 0 has failed, the loop is no
		// longer "fast": it falls into the same exponential ladder as the
		// natural path (a real outage backs off), so the fast branch is gated on
		// attempt == 0 only.
		if fastFirstAttempt && attempt == 0 {
			jitter := time.Duration(rand.Float64() * float64(ageCutReconnectJitter))
			p.log.Debug("WS pool fast age-cut reconnect", "slot", idx, "jitter", jitter)
			sleepWithCancel(p.ctx, jitter)
		} else {
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

			// Пауза прерывается, если origin ответил соседнему слоту.
			// Замер 2026-08-11: без этого слоты 2 и 11 досиживали 60s
			// (attempt=3) уже по здоровой сети — origin вернулся на ~50s
			// раньше их пробуждения.
			if p.waitBackoffOrRevival(d) {
				// ⚠ Сброс лестницы гейтится по rate-limit. Запрет
				// 2026-05-18 (ниже по коду) касается не только своей
				// ветки: рейт-лимит бывает per-carrier/bucket, поэтому
				// СОСЕДНИЙ слот может успешно подключиться и разбудить
				// зажатый. Обнулив ему attempt, мы отправили бы его на
				// повтор с паузой 5-10s прямо в тот же TokenBucket — тот
				// самый бесконечный цикл, от которого уходили.
				//
				// Пробуждение при этом безвредно и полезно: слот просто
				// пробует раньше, сохраняя накопленную лестницу.
				if lastWasRateLimited {
					p.log.Debug("WS pool reconnect woken early — ladder kept (rate-limited)",
						"slot", idx, "attempt", attempt)
				} else {
					p.log.Info("WS pool reconnect woken early — another slot connected",
						"slot", idx, "backoff_skipped", d, "attempt", attempt)
					// Держать лестницу после доказанного успеха соседа
					// значило бы наказывать слот за прошлое состояние
					// сети. Шторма не будет: сюда попадают только те, кто
					// реально ждал, и связность уже подтверждена.
					attempt = -1 // ++ в заголовке цикла вернёт 0
				}
			}
			select {
			case <-p.ctx.Done():
				return
			default:
			}
		}

		// Recycle guard (spec §2.2.2): if a drain has recycled this cell
		// while we were waiting, abandon this stale reconnect. claimFreeSlot
		// + drainWatchdog teardown both write p.slots[idx] under
		// reserveMu, so observing non-nil here is conclusive.
		p.reserveMu.Lock()
		recycled := p.slots[idx] != nil && p.slots[idx].getState() != slotDead
		p.reserveMu.Unlock()
		if recycled {
			p.log.Info("WS pool reconnect short-circuited — cell recycled by drain",
				"slot", idx)
			return
		}

		var connectErr error
		if hook := getConnectSlotForTest(); hook != nil {
			// Test seam — see ws_pool.go::connectSlotForTestPtr. Production
			// builds never enter this branch because nothing assigns the var.
			connectErr = hook()
		} else {
			connectErr = p.connectSlot(p.ctx, idx)
		}

		if connectErr == nil {
			if fastFirstAttempt {
				// Tick the age-cut reconnect counter once per healed age-cut slot
				// (the canary measures residual dip via this vs CapacityDipTotal).
				Stats.AgeCutReconnectsTotal.Add(1)
			}
			p.log.Info("WS pool slot reconnected", "slot", idx)
			// Связность подтверждена — будим слоты, сидящие в паузе после
			// того же отказа origin.
			p.signalNetworkRevival()
			go p.slotReader(idx)
			return
		}

		// Fast attempt-0 connect FAILED → this was not a routine middlebox cut,
		// it is a genuine connect failure. Record it (the canary watches this:
		// a rising AgeCutReconnectFail means "age-cut" is masking a real fault and
		// the classification/threshold needs review) and let the loop fall into
		// the exponential ladder from attempt=1 (a real outage backs off). Do NOT
		// double-count a rate-limit response as a fail — ErrRateLimited is the
		// server pacing us, handled below, not an origin fault.
		if fastFirstAttempt && attempt == 0 && !errors.Is(connectErr, ErrRateLimited) {
			Stats.AgeCutReconnectFail.Add(1)
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
			lastWasRateLimited = true
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

		// Обычный отказ (не рейт-лимит) снимает флаг: иначе один рейт-лимит
		// в начале жизни слота навсегда запретил бы ему сброс лестницы.
		lastWasRateLimited = false

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
	for _, slot := range p.snapshotSlots() {
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
		p.rotateMinLoadedSlot()
	}
}

// rotateMinLoadedSlot picks the slotReady cell with the fewest active
// streams and rotates it. Used by rotationLoop for anti-fingerprinting
// rotation cadence.
//
// When the gracefulDrain feature flag is on, the rotation goes through
// startDrain (HTTP/2 GOAWAY-style: parallel reserve + drain watchdog).
// When off, falls back to legacyRotateOneSlot (semi-graceful: polling
// up to 30s then teardown via handleSlotDeath).
//
// To be removed in Phase 4 cleanup when the legacy path is retired.
func (p *WSPoolTransport) rotateMinLoadedSlot() {
	minIdx := -1
	minStreams := int32(1<<31 - 1)
	for i, slot := range p.snapshotSlots() {
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

	if p.gracefulDrain {
		p.startDrain(p.client, minIdx, "anti_fingerprint")
		return
	}
	p.legacyRotateOneSlot(minIdx)
}

// legacyRotateOneSlot is the pre-graceful-drain rotation path, kept
// behind the gracefulDrain feature flag during Phase 1 rollout. Deleted
// in Phase 4 cleanup along with maybeRotateSlot and fireRotation.
func (p *WSPoolTransport) legacyRotateOneSlot(minIdx int) {
	slot := p.slotAt(minIdx)
	if slot == nil {
		return
	}
	slot.setState(slotDraining)
	p.log.Info("WS pool rotating slot (legacy)", "slot", minIdx,
		"activeStreams", slot.streams.Load())

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
	// M4 fix (audit 2026-06-11): bump generation BEFORE tearing the transport
	// down, mirroring drainWatchdog.tearDown (ws_pool_drain.go) and
	// tryForceEvictIdleSlot. Without the bump, the old reader blocked in
	// ReadMessage sees "use of closed network connection", shouldExitReader
	// returns false (generation unchanged), and it calls
	// handleSlotDeath(deathCauseNatural) on a cell connectSlot may have already
	// re-installed — feeding a false meltdown signal for a rotation WE
	// initiated. The bump makes the stale reader exit silently via gen mismatch.
	slot.generation.Add(1)
	if slot.transport != nil {
		slot.transport.Close()
	}
	if slot.session != nil {
		slot.session.Destroy()
	}

	if err := p.connectSlot(p.ctx, minIdx); err != nil {
		p.log.Warn("WS pool rotation reconnect failed (legacy)",
			"slot", minIdx, "err", err)
		go p.reconnectLoop(minIdx)
		return
	}

	go p.slotReader(minIdx)
	p.log.Info("WS pool slot rotated (legacy)", "slot", minIdx)
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
	// One consistent snapshot under reserveMu for all picking passes (audit
	// H1, 2026-06-11): the loops below previously indexed p.slots live, racing
	// the lifecycle writers. Picking on a single snapshot is also more
	// internally consistent than re-reading the slice between passes.
	snap := p.snapshotSlots()
	pickInPass := func(allowFresh bool) (idx int, score int32) {
		idx = -1
		score = int32(1<<31 - 1)
		nowNs := time.Now().UnixNano()
		windowNs := slotFreshnessPenaltyWindow.Nanoseconds()
		for i, slot := range snap {
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
		for i, slot := range snap {
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
			for i, slot := range snap {
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

	// R1-H3 fix: streams.Add MUST precede streamMap.Store so any
	// concurrent snapshot that observes the new entry also sees
	// the incremented counter. See spec §2.5.
	//
	// R2-M3 sanity-assert: log if streamID is already mapped (caller
	// bug — production SOCKS guarantees single-owner). Not atomic
	// protection; just observability for future regression.
	if existing, dup := p.streamMap.Load(streamID); dup {
		if e, ok := existing.(*streamEntry); ok {
			p.log.Warn("AssignStream called twice for same streamID without ReleaseStream",
				"stream", streamID, "old_slot", e.slotIdx, "new_slot", minIdx)
		} else {
			p.log.Warn("AssignStream duplicate with non-streamEntry value",
				"stream", streamID, "new_slot", minIdx)
		}
		return
	}
	// M1 fix (audit 2026-06-11): capture the *poolSlot currently at minIdx
	// under reserveMu (via slotAt) and inc on the captured pointer, symmetric
	// with rebindStreamToSlot/ReleaseStream (2026-06-01 counter-leak fix).
	// Previously the inc was by-index (p.slots[minIdx].streams.Add(1)) which
	// (a) was itself an unguarded slice read (H1) and (b) could land on a
	// fresh zeroed object if connectSlot replaced the cell between pick and
	// Add, while the paired ReleaseStream dec (captured under lock) landed on
	// a different object — inflating the health active_streams sum on the live
	// object. Capturing the live pointer here pairs inc and dec on a coherent
	// object (ReleaseStream re-reads the same way). If the cell is empty/nil
	// (raced a teardown), skip the inc but still publish the mapping so the
	// paired Release floor-clamp absorbs the asymmetry — matching prior
	// floor-clamp semantics.
	slot := p.slotAt(minIdx)
	if slot != nil {
		slot.streams.Add(1)
	}
	p.streamMap.Store(streamID, newStreamEntry(minIdx))
	if slot != nil {
		Trace("stream assigned", "stream", streamID, "slot", minIdx,
			"pending", slot.pendingConnects.Load(),
			"streams", slot.streams.Load())
	}
}

// IncrPending increments the pending CONNECT counter for the stream's assigned slot.
func (p *WSPoolTransport) IncrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return
		}
		if slot := p.slotAt(e.slotIdx); slot != nil {
			slot.pendingConnects.Add(1)
		}
	}
}

// DecrPending decrements the pending CONNECT counter for the stream's assigned slot.
func (p *WSPoolTransport) DecrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return
		}
		if slot := p.slotAt(e.slotIdx); slot != nil {
			slot.pendingConnects.Add(-1)
		}
	}
}

// SlotPending returns pending CONNECT count for the stream's assigned slot.
func (p *WSPoolTransport) SlotPending(streamID uint16) int32 {
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return 0
		}
		if slot := p.slotAt(e.slotIdx); slot != nil {
			return slot.pendingConnects.Load()
		}
	}
	return 0
}

// AllSlotsAtMaxPending returns true when every ready slot has >= maxPendingPerSlot pending CONNECTs.
// Returns false when no slots are ready (don't block — let AssignStream fallback handle it).
func (p *WSPoolTransport) AllSlotsAtMaxPending() bool {
	anyReady := false
	for _, slot := range p.snapshotSlots() {
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
	// R2-H2 fix: streams.Add(-1) MUST precede streamMap.Delete (symmetric
	// to the AssignStream flip from Step 1 spec §2.5). Under per-stream
	// idle decision (Step 2), the inverse ordering would let drainWatchdog
	// observe streams.Load()>0 while the released entry is already gone
	// from the map → allStreamsIdle could return true prematurely if the
	// gone stream was the only active one → tearDown fires while Release
	// hasn't completed counter decrement → silent drop or decrypt_fails.
	//
	// Read entry via Load first (need slotIdx), then decrement counter,
	// then Delete from map. Trade: not atomic vs old LoadAndDelete, but
	// SOCKS layer guarantees one owner per streamID so double-Release
	// requires a future bug (defense-in-depth via inner type checks).
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			p.streamMap.Delete(streamID)
			return
		}
		// Spec 2026-06-01 (counter-leak fix, F3): capture the slot pointer under
		// reserveMu and floor-clamp the dec. If the object at idx was replaced by
		// a fresh poolSlot (death+reconnect) between AssignStream and here, a
		// by-index dec would drive the new zeroed object negative; floor-clamp
		// absorbs that residual, and capturing keeps the dec on a coherent object.
		// slotAt performs the capture under reserveMu (audit H1, 2026-06-11).
		if slot := p.slotAt(e.slotIdx); slot != nil {
			decStreamsFloor(slot)
		}
		p.streamMap.Delete(streamID)
	}
}

// SessionForStream returns the crypto session for the stream's assigned
// slot, or nil if the stream is not mapped or the mapped cell is
// nil/non-Ready. The old "fallback to first primary's session" path
// was removed (spec 2026-05-20 §2.5, C4 review) — it produced silent
// decrypt failures (server keys sessions per-slot) and all callers
// (client.go:710, socks5/tcp.go:495/531/565) already nil-guard.
func (p *WSPoolTransport) SessionForStream(streamID uint16) *core.Session {
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return nil
		}
		if slot := p.slotAt(e.slotIdx); slot != nil {
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
		e, ok := v.(*streamEntry)
		if !ok {
			return p.WriteMessage(data)
		}
		if slot := p.slotAt(e.slotIdx); slot != nil && slot.transport != nil {
			st := slot.getState()
			if st == slotReady || st == slotDraining {
				e.lastWriteNs.Store(time.Now().UnixNano())
				return slot.transport.WriteMessage(data)
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
		e, ok := v.(*streamEntry)
		if !ok {
			return p.WriteControlMessage(data)
		}
		if slot := p.slotAt(e.slotIdx); slot != nil && slot.transport != nil {
			st := slot.getState()
			if st == slotReady || st == slotDraining {
				e.lastWriteNs.Store(time.Now().UnixNano())
				return slot.transport.WriteControlMessage(data)
			}
		}
	}
	return p.WriteControlMessage(data)
}

// TryWriteControlMessageForStream sends a control frame to the stream's slot
// WITHOUT blocking (Bug #8 credit sender). Returns true if enqueued. Returns
// false if the stream has no ready/draining slot or the slot's control channel
// is full — the caller keeps the accumulated delta for the next tick.
func (p *WSPoolTransport) TryWriteControlMessageForStream(streamID uint16, data []byte) bool {
	v, ok := p.streamMap.Load(streamID)
	if !ok {
		return false
	}
	e, ok := v.(*streamEntry)
	if !ok {
		return false
	}
	slot := p.slotAt(e.slotIdx)
	if slot == nil || slot.transport == nil {
		return false
	}
	if st := slot.getState(); st != slotReady && st != slotDraining {
		return false
	}
	tw, ok := slot.transport.(interface{ TryWriteControlMessage(data []byte) bool })
	if !ok {
		return false
	}
	if tw.TryWriteControlMessage(data) {
		e.lastWriteNs.Store(time.Now().UnixNano())
		return true
	}
	return false
}

// WriteMessage sends a data frame to a random ready slot (for non-stream data).
func (p *WSPoolTransport) WriteMessage(data []byte) error {
	for _, slot := range p.snapshotSlots() {
		if slot != nil && slot.getState() == slotReady && slot.transport != nil {
			return slot.transport.WriteMessage(data)
		}
	}
	return fmt.Errorf("ws pool: no ready slots")
}

// WriteControlMessage sends a control frame to a random ready slot.
func (p *WSPoolTransport) WriteControlMessage(data []byte) error {
	for _, slot := range p.snapshotSlots() {
		if slot != nil && slot.getState() == slotReady && slot.transport != nil {
			return slot.transport.WriteControlMessage(data)
		}
	}
	return fmt.Errorf("ws pool: no ready slots")
}

// StartReader spawns and supervises slot readers for the pool's
// lifetime. Polls every readerSupervisorInterval to find ready slots
// without an active reader and spawn a goroutine for each. The
// slot.readerActive CAS gate inside slotReaderWithClient prevents
// duplicate spawns when reconnectLoop / connectReserveSlot ALSO spawn
// readers concurrently.
//
// Returns ONLY on ctx.Done() — pool manages its own reader lifecycle
// via reconnectLoop and connectReserveSlot, so engine resets are
// counterproductive. (Previous WaitGroup-based implementation reflected
// only the snapshot of readers at StartReader call time, returning
// "all readers exited" when those original goroutines drained — even
// while replacement readers spawned on reserve cells were alive. F1
// architectural fix, 2026-05-20.)
func (p *WSPoolTransport) StartReader(ctx context.Context, cl *Client) error {
	const readerSupervisorInterval = 1 * time.Second

	// Initial fan-out: spawn readers for all currently-ready cells.
	p.spawnMissingReaders(ctx, cl)

	ticker := time.NewTicker(readerSupervisorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			p.spawnMissingReaders(ctx, cl)
		}
	}
}

// spawnMissingReaders iterates the slice and spawns slotReaderWithClient
// for any slotReady cell that doesn't already have an active reader.
// The readerActive CAS inside slotReaderWithClient is the authoritative
// duplicate-prevention gate — this function just primes the spawn.
func (p *WSPoolTransport) spawnMissingReaders(ctx context.Context, cl *Client) {
	for i, slot := range p.snapshotSlots() {
		if slot == nil {
			continue
		}
		if slot.getState() != slotReady {
			continue
		}
		if slot.readerActive.Load() {
			continue
		}
		// Best-effort spawn — readerActive CAS inside slotReaderWithClient
		// is the authoritative gate. If we lose the race to another
		// caller (reconnectLoop / connectReserveSlot), the CAS-fail
		// branch in slotReaderWithClient exits cleanly with no work done.
		go p.slotReaderWithClient(ctx, cl, i)
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
	slot := p.slotAt(idx)
	if slot == nil || slot.transport == nil {
		return
	}

	// CAS-gate against duplicate readers on the same slot. Two reader
	// goroutines can be scheduled for one slot when:
	//   1. reconnectLoop finishes connectSlot and calls `go p.slotReader(idx)`
	//      (ws_pool.go ~line 802) to attach a reader to the new conn.
	//   2. Concurrently, spawnMissingReaders (called by StartReader polling
	//      supervisor) sees a slotReady cell with readerActive=false and
	//      spawns a goroutine for it.
	//   3. connectReserveSlot (ws_pool_drain.go) calls `go p.slotReader(newIdx)`
	//      for a freshly connected reserve cell.
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
			slotAgeMs := time.Since(slotStart).Milliseconds()

			// Capacity-dip fix (2026-06-01): distinguish the EXPECTED TSPU
			// age-cut (a mature slot closed 1006 by the middlebox) from a
			// genuine failure. An age-cut reconnects FAST and does NOT feed the
			// meltdown detector (deathCauseAgeCut); a young-slot death or any
			// non-1006 error stays deathCauseNatural (exponential backoff +
			// meltdown feed — the conservative behavior for real instability).
			cause := deathCauseNatural
			if p.isAgeCut(err, slotAgeMs) {
				cause = deathCauseAgeCut
			}

			p.log.Warn("WS pool slot reader error",
				"slot", idx,
				"err", err,
				"anomaly", anomaly,
				"cause", cause,
				"messages", msgCount,
				"slot_age_ms", slotAgeMs,
				"down_bytes", slot.downBytes.Load(),
				"last_write_age_ms", lastWriteAgeMs,
				"writer_exits", Stats.WriterExits.Load(),
				"mode", mode,
			)

			// Раунд 18 P0: те же три поля, но в агрегируемую структуру, а не
			// только в лог-строку. Из логов нельзя ни посчитать перцентили, ни
			// сохранить историю между запусками — а именно распределение
			// (кластеризуется возраст или объём) отвечает на вопрос, по какой ОСИ
			// режет цензор. Наблюдение не влияет на решения: ротацией по-прежнему
			// управляют maxSlotAge / ageCutMinAge.
			//
			// `Mature: cause == deathCauseAgeCut` записывается, но доверять ему
			// нельзя — это ВЫВОД того самого порога, который мы проверяем.
			if p.slotDeaths != nil {
				p.slotDeaths.Record(slotobs.Observation{
					AgeMs:          slotAgeMs,
					DownBytes:      slot.downBytes.Load(),
					LastWriteAgeMs: lastWriteAgeMs,
					CloseKind:      anomaly,
					Mature:         cause == deathCauseAgeCut,
				})
			}
			p.handleSlotDeath(cl, idx, cause)
			return
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

		// Bug #9 Task 15: a MIGRATE/RESUME reply rides the NEW slot's downlink
		// with chunk.Flags == FlagMigrate/FlagResume and a status-byte payload
		// (NOT the [streamID][...] data shape — branching before the streamID
		// parse below keeps the reply payload from being misread as a streamID
		// header). Resolve the pending ack and consume the frame.
		if chunk.Flags == core.FlagMigrate || chunk.Flags == core.FlagResume {
			p.resolveMigrateReplyPayload(chunk.Payload)
			continue
		}

		// Bug #10: FlagStreamClose is a top-level control frame sent by the
		// server when the origin TCP connection for this stream died. Handle it
		// BEFORE the W5 stale-frame guard and BEFORE the len<2 payload filter
		// so the close is honored even if the stream just migrated to a
		// different slotIdx (the RESUME-fallback delivers FlagStreamClose on
		// slot B while the streamMap still records slotIdx A). Tearing the
		// stream down closes its chan -> the SOCKS5/memConn reader gets EOF ->
		// the app retries instead of hanging forever.
		if chunk.Flags == core.FlagStreamClose {
			if sid, perr := core.ParseStreamCloseFrame(chunk.Payload); perr == nil {
				p.handleStreamClose(cl, sid)
			}
			continue
		}

		// M1 (2026-06-11): downlink anti-replay. AEAD proves authenticity but NOT
		// freshness; an on-path injector (the TSPU/middlebox threat model) can
		// re-inject a captured authentic chunk, duplicating bytes in the proxied
		// TCP stream. Drive the same sliding window the server uses on uplink.
		// Control frames (Migrate/Resume/StreamClose) are handled above and are
		// exempt — they are idempotent and carry no stream bytes. Seq-tagged
		// migration data is additionally dedup'd by the reassembler (downSeq);
		// this chunk-level check is cheap defense-in-depth covering BOTH modes.
		if !session.AcceptSeqNum(chunk.SeqNum) {
			Stats.DownlinkReplayDroppedTotal.Add(1)
			continue
		}

		if len(chunk.Payload) < 2 {
			continue
		}

		// Per-stream lastWriteNs is stamped below, after the stale-frame
		// check (spec §2.4) — slot-level stamp was removed in Step 2.

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		// W5 stale-frame validation: drop frames whose streamID has been
		// reassigned to a different slot (post-drain-teardown streamID
		// reuse race). Spec 2026-05-20 §2.4.1.
		//
		// Spec 2026-05-25 §2.4: per-stream lastWriteNs is stamped ONLY
		// AFTER successful slotIdx == idx validation. Frames for
		// reassigned streamIDs do NOT count as activity on the new owner.
		if v, ok := p.streamMap.Load(streamID); ok {
			e, ok := v.(*streamEntry)
			if !ok {
				continue
			}
			if e.slotIdx != idx {
				Stats.StaleFrameDroppedTotal.Add(1)
				continue
			}
			e.lastWriteNs.Store(time.Now().UnixNano())
		}

		// Bug #9 §5.4: under negotiated migration the FlagData downlink wire
		// format is seq-tagged ([streamID(2)][downSeq(8)][data]) so the client
		// reassembler can reorder frames split across an old+new slot. FlagUDP
		// is NOT seq-tagged (datagram, no ordering contract) — it stays on the
		// legacy []byte path in both modes. FlagData routing (seq vs flat) is
		// decided per-slot in routeDownlinkFlagData (H-C2/H-C3, audit 2026-06-11).
		if chunk.Flags == core.FlagUDP {
			cl.RouteToStream(streamID, chunk.Payload)
		} else {
			p.routeDownlinkFlagData(cl, slot, streamID, chunk)
		}

		// Preemptive byte-based rotation — checked AFTER the frame is
		// decrypted and routed to its stream (above). CRITICAL: this block
		// MUST come after RouteToStream. Previously it sat BEFORE decrypt
		// and did `continue` on the budget-tripping frame, DROPPING that
		// already-read downlink frame — a hole in the stream's TCP byte
		// sequence that corrupted the app's TLS record stream
		// (SEC_E_DECRYPT_FAILURE / broken download). The frame that trips
		// the budget is now delivered first.
		// budget = 0 → feature disabled (viaCF mode). See poolSlot.byteBudget
		// docstring for jitter rationale and the "sample once per (re)connect"
		// invariant.
		if budget := slot.byteBudget.Load(); budget > 0 {
			// Advance the per-slot downlink counter. data is the raw WS
			// frame just read; len(data) is the wire size — same value the
			// old code used at the top of the loop.
			total := slot.downBytes.Add(int64(len(data)))
			// Rate floor (Bug #4): even if the byte budget is exhausted, do
			// not rotate until the slot has lived at least the min interval.
			// Prevents the high-throughput rotation storm where a fast
			// download burns the budget in a fraction of a second and the
			// pool thrashes. The age budget (rotationWatchdog) remains the
			// upper bound.
			if total >= budget && byteBudgetRotationAllowed(time.Since(slotStart), p.byteBudgetMinInterval) {
				if p.gracefulDrain {
					// Graceful path: startDrain transitions the slot to
					// slotDraining and spawns parallel reserve reconnect on a
					// SEPARATE goroutine (NOT inline — inline blocks this reader
					// from serving its own active stream's downlink). The slot
					// keeps reading/routing downlink for its sticky streams until
					// drainWatchdog natural-finish. Reset downBytes before
					// dispatch so subsequent reads don't spawn a second
					// startDrain before the slot flips to slotDraining;
					// startDrain is idempotent via tryMarkDraining CAS. Guard on
					// slotReady to minimize duplicate dispatches.
					if slot.getState() == slotReady {
						slot.downBytes.Store(0)
						go p.startDrain(cl, idx, "byte_budget")
					}
					// NO continue/return — the frame is already delivered; just
					// loop to the next ReadMessage. The slotDraining slot keeps
					// serving downlink.
				} else if p.maybeRotateSlot(cl, idx, slot, "byte_budget", msgCount, slotStart, total) {
					return
				}
			}
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
// Storm brake: when readyCapacity() drops below readyCapacityFloor(), a
// NEW rotation request defers even if streams==0. Without this,
// byte-budget triggers under heavy upload load fire on all 8 slots
// within seconds, and the simultaneous teardowns leave the upload
// writer with nowhere to put bytes. The brake only blocks NEW
// rotations — it never overrides the "grace expired" force-rotate,
// because at that point we know the slot is past its safe age and must
// be replaced.
//
// Concurrency: rotationDeferredNs is atomic; CAS not strictly needed
// because the field is only written from the single slot reader goroutine
// that owns this idx (readerActive gate guarantees one writer). The
// brake reads readyCapacity which is a lock-free walk of per-slot
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
		ready := p.readyCapacity()
		floor := p.readyCapacityFloor()
		if ready < floor {
			if deferredAt == 0 {
				slot.rotationDeferredNs.Store(nowNs)
				p.log.Info("WS pool slot preemptive rotation deferred (storm brake)",
					"slot", idx, "reason", reason,
					"ready_capacity", ready,
					"floor", floor,
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

// bumpRotations1m increments the 1-minute rolling rotation counter and
// schedules a decrement after 60s. Called by every code path that retires
// a slot under our control:
//   - fireRotation (legacy hard-rotation path)
//   - drainWatchdog tearDown (graceful drain path: natural, idle, hard cap)
//
// The counter's semantic is "slot teardowns we initiated in the last
// minute" — graceful drains are still our-initiated rotations, only the
// teardown mechanism differs. Previously this counter showed 0 on
// graceful-drain-only sessions even with hundreds of drains (2026-05-22
// 8h canary: 895 drains, rotations_1m always 0 in pool-health log).
//
// Lock-free: atomic.Int32 Add. Decrement goroutine exits cleanly on ctx
// cancel so pool shutdown doesn't leak timers.
func (p *WSPoolTransport) bumpRotations1m() {
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
}

// initRevivalSignal готовит broadcast-канал. Вызывается из
// NewWSPoolTransport; отдельным методом — чтобы тесты могли собрать пул
// напрямую структурным литералом, не поднимая весь конструктор.
func (p *WSPoolTransport) initRevivalSignal() {
	p.revivalMu.Lock()
	defer p.revivalMu.Unlock()
	if p.revivalCh == nil {
		p.revivalCh = make(chan struct{})
	}
}

// signalNetworkRevival сообщает пулу, что origin снова отвечает: будит все
// слоты, сидящие в backoff-паузе.
//
// Вызывается на УСПЕШНОМ connect. Сигнал не копится — закрытый канал сразу
// заменяется новым, поэтому слот, зашедший в ожидание после события, ждёт
// следующего, а не просыпается на прошлом.
//
// Лестницу это не отменяет: разбуженный слот идёт на обычную попытку
// подключения, и если origin всё-таки мёртв, он снова уйдёт в паузу. Защита
// от шторма хендшейков сохраняется, потому что будить может только реальный
// успех — а он означает, что origin принимает соединения.
func (p *WSPoolTransport) signalNetworkRevival() {
	p.revivalMu.Lock()
	defer p.revivalMu.Unlock()
	if p.revivalCh == nil {
		p.revivalCh = make(chan struct{})
		return
	}
	close(p.revivalCh)
	p.revivalCh = make(chan struct{})
}

// waitBackoffOrRevival ждёт d, но просыпается раньше, если другой слот
// успешно подключился. Возвращает true, если разбудил сигнал.
//
// Возврат по ctx.Done даёт false: пул останавливается, «оживления» не было.
func (p *WSPoolTransport) waitBackoffOrRevival(d time.Duration) bool {
	p.revivalMu.Lock()
	if p.revivalCh == nil {
		p.revivalCh = make(chan struct{})
	}
	ch := p.revivalCh // снимок ДО ожидания: следующий close() относится к нему
	p.revivalMu.Unlock()

	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-p.ctx.Done():
		return false
	case <-ch:
		return true
	case <-timer.C:
		return false
	}
}

// bumpSlotDeaths1m считает смерть слота в наблюдательный счётчик — по ЛЮБОЙ
// причине, включая age-cut и наши собственные teardown'ы.
//
// Намеренно НЕ трогает recentDeaths / meltdownUntil: кулдаун остаётся
// глухим к age-cut, как и задумано (иначе штатный каскад резов пришлось бы
// оплачивать паузой всех реконнектов). Здесь только наблюдение — см.
// докстринг поля slotDeaths1m про полевой отказ 2026-08-11, который не
// отразился ни в одном счётчике.
//
// Причина принимается параметром, а не выводится внутри, чтобы вызов стоял
// в диспетчере рядом с ветвлением по cause и не разъезжался с ним. Сейчас
// счётчик агрегатный: разбивка по причинам добавила бы состояние без
// операционной ценности — вопрос оператора «пул лёг?», а не «чем именно».
//
// Lock-free, тот же контракт распада, что у bumpRotations1m: decay-goroutine
// выходит по ctx, таймеры не текут при остановке пула.
func (p *WSPoolTransport) bumpSlotDeaths1m(_ slotDeathCause) {
	p.slotDeaths1m.Add(1)
	go func() {
		timer := time.NewTimer(60 * time.Second)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			p.slotDeaths1m.Add(-1)
		}
	}()
}

// bumpDrainDeferrals1m mirrors bumpRotations1m for storm-brake drain
// deferrals. Lock-free Int32 Add with a 60s decay goroutine that
// exits cleanly on pool ctx cancel. Spec 2026-05-23.
func (p *WSPoolTransport) bumpDrainDeferrals1m() {
	p.drainDeferrals1m.Add(1)
	go func() {
		timer := time.NewTimer(60 * time.Second)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			p.drainDeferrals1m.Add(-1)
		}
	}()
}

// fireRotation executes the rotation: bumps the 1-minute counter and
// triggers handleSlotDeath with the Preemptive cause so the meltdown
// detector does NOT count this teardown as a network failure.
// Extracted from maybeRotateSlot so both success branches (idle slot,
// grace-expired) share counter accounting without duplication.
func (p *WSPoolTransport) fireRotation(cl *Client, idx int) {
	p.bumpRotations1m()
	p.handleSlotDeath(cl, idx, deathCausePreemptiveRotation)
}

// handleStreamClose tears down a single stream on behalf of a FlagStreamClose
// control frame (Bug #10). It enforces the Delete-before-close invariant
// (streamMap.Delete before close(ch)) that ReleaseStream relies on, and is
// safe to call when the streamID is not present in streamChans (no-op then).
//
// This is the shared teardown used by both the demux FlagStreamClose branch
// and the handleSlotDeath closeStream helper, keeping the logic in one place.
// routeDownlinkFlagData routes a decrypted FlagData downlink frame to its
// stream, choosing the decode shape from the PRODUCING slot's own migration
// negotiation (H-C3) and refusing to silently drop an unparseable frame (H-C2).
//
// H-C3 — per-slot decode shape: the seq-tagged form is selected by
// slot.migrateNegotiated (latched in connectSlot from THIS slot's FLOWCTL ack),
// NOT the pool-wide p.migrateEnabled bit. A slot whose server session still
// speaks the flat format keeps flat-decoding even after another slot flips the
// pool-wide flag, so the 8-byte downSeq is never mis-parsed out of flat payload.
//
// H-C2 — no silent drop: on a migration slot, a frame that matches neither the
// legacy control path nor ParseStreamDataSeq (len<10 / malformed) is NOT dropped
// on the floor (a dropped already-decrypted downlink frame is a hole in the TCP
// byte stream → app-side corruption, the Bug#8 class). Instead it bumps
// Stats.MigrationFrameUnparseable, logs at WARN, and deterministically tears the
// stream (handleStreamClose → the SOCKS5/memConn reader gets EOF → the app
// retries) rather than handing the app a silently-corrupted byte stream.
func (p *WSPoolTransport) routeDownlinkFlagData(cl *Client, slot *poolSlot, streamID uint16, chunk *core.Chunk) {
	// Decode shape follows the session that produced the frame (H-C3).
	seqTagged := slot != nil && slot.migrateNegotiated.Load()
	if !seqTagged {
		// Legacy flat FlagData: byte-for-byte [streamID(2)][data].
		cl.RouteToStream(streamID, chunk.Payload[2:])
		return
	}

	// Migration slot: the FlagData downlink mixes two shapes — relay DATA is
	// seq-tagged ([streamID][downSeq(8)][data], downSeq>=1) but CONNECT_OK/FAIL
	// control is still emitted by the server's CONNECT handler as the legacy
	// flat [streamID][string] (no downSeq). Disambiguate by exact-matching the
	// known control strings on the post-streamID payload and routing them as
	// seq==0 control. Forward-compatible: if the server later seq-tags control
	// with downSeq==0, ParseStreamDataSeq yields seq==0 and the same path runs.
	body := chunk.Payload[2:]
	if isStreamControlMsg(body) {
		cl.RouteToStreamSeq(streamID, 0, body)
		return
	}
	if sid, downSeq, sdata, perr := core.ParseStreamDataSeq(chunk.Payload); perr == nil {
		cl.RouteToStreamSeq(sid, downSeq, sdata)
		return
	}

	// H-C2: unparseable on a migration slot. Do NOT silently drop — that punches
	// a hole in the stream's TCP byte sequence (app-side TLS decrypt failure /
	// broken download) with no telemetry. Count it and deterministically tear
	// the stream so the app gets EOF and retries.
	Stats.MigrationFrameUnparseable.Add(1)
	p.log.Warn("migration FlagData frame unparseable — tearing stream",
		"stream", streamID, "payload_len", len(chunk.Payload))
	p.handleStreamClose(cl, streamID)
}

func (p *WSPoolTransport) handleStreamClose(cl *Client, streamID uint16) {
	p.streamMap.Delete(streamID)
	cl.streamMu.Lock()
	if ch, ok := cl.streamChans[streamID]; ok {
		close(ch)
		delete(cl.streamChans, streamID)
	}
	// streamFramesChans is used when migrateEnabled — close it too so the
	// reassembler goroutine sees EOF and exits cleanly.
	if fch, ok := cl.streamFramesChans[streamID]; ok {
		close(fch)
		delete(cl.streamFramesChans, streamID)
	}
	cl.streamMu.Unlock()
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
	slot := p.slotAt(idx)
	if slot == nil {
		return
	}
	if !slot.tryMarkDead() {
		return
	}
	slot.lastDeathNs.Store(time.Now().UnixNano())

	// Uniform stream cleanup (spec 2026-05-20 §3): close(streamChans[id])
	// for every cause (natural, preemptive, drainTeardown). The earlier
	// design had drainTeardown skip the close in favor of network EOF
	// from transport.Close — but that was non-deterministic. Closing the
	// chan gives SOCKS5 readers an immediate, synchronous signal.
	// streamMap.Delete BEFORE close(ch) keeps the no-underflow invariant
	// (see ReleaseStream's LoadAndDelete semantics).
	//
	// Bug #9 Task 17 (RESUME-on-slot-death, §5.5): when the pool negotiated
	// stream migration, a sudden slot death no longer unconditionally breaks
	// its active streams. For each recoverable stream we first try a grace
	// RESUME onto a live slot; only on a confirmed failure (no live target,
	// RESUME_FAIL/timeout, or an already-migrating stream another goroutine is
	// moving) do we fall through to the legacy chan-close. closeStream delegates
	// to handleStreamClose which owns the Delete-before-close invariant and also
	// handles streamFramesChans (used when migrateEnabled).
	migrationOn := p.migrateEnabled.Load()
	closeStream := func(streamID uint16) {
		p.handleStreamClose(cl, streamID)
	}
	p.streamMap.Range(func(key, value any) bool {
		e, ok := value.(*streamEntry)
		if !ok || e.slotIdx != idx {
			return true
		}
		streamID := key.(uint16)

		if migrationOn {
			switch p.resumeStreamOnDeath(cl, streamID, e, idx) {
			case resumeOutcomeKept:
				// Stream survived (RESUME_OK → re-pointed to a live slot) or is
				// mid-move under another goroutine (migrating flag set). Do NOT
				// close its chan and do NOT delete its (re-pointed) entry.
				return true
			case resumeOutcomeBreak:
				// No live slot / RESUME failed — fall through to legacy close.
			}
		}

		closeStream(streamID)
		return true
	})

	// Tidy reset of THIS (dying) object's counters. As of the 2026-06-01
	// counter-leak fix, correctness no longer depends on this Store(0): the
	// live invariant (slot.streams == live entries on that object) is upheld by
	// pointer-addressed inc/dec in rebindStreamToSlot/ReleaseStream. This object
	// is about to be replaced by connectSlot's fresh poolSlot anyway, so a
	// residual count here is inert (it leaves p.slots and the health sum). Kept
	// as a defensive zero.
	slot.streams.Store(0)
	slot.pendingConnects.Store(0) // Reset: pending CONNECTs from dead slot can't be decremented normally

	// For OUR teardowns (preemptive rotation / graceful-drain) the transport is
	// still live, so tell the server to release this slot's session right away
	// via a session-wide FIN before we close the socket. Without this the server
	// keeps the session until its idle timeout; under pool rotation that lets
	// sessions accumulate and trip the server's MaxClients gate (ghost-session
	// bug, 2026-05-29). For deathCauseNatural AND deathCauseAgeCut the transport
	// is already broken (the latter was cut externally by the TSPU) — nothing to
	// send over — so we skip and rely on the SERVER ghost-sweep (a client FIN for
	// an age-cut session is impossible: the dead transport carries no session, and
	// there is no on-wire session addressing to route a FIN over a live sibling —
	// see docs/sl-capacity-dip-spec-review.md BLOCKER-1).
	if cause != deathCauseNatural && cause != deathCauseAgeCut {
		p.sendSlotSessionFIN(slot)
	}

	if slot.transport != nil {
		slot.transport.Close()
	}

	// Наблюдательный счётчик — ДО ветвления, чтобы он не зависел от того,
	// какая ветка что решит. Кулдаун по-прежнему кормится только из
	// deathCauseNatural ниже.
	p.bumpSlotDeaths1m(cause)

	// Post-cleanup dispatch by cause. See slotDeathCause doc-comment for the
	// rationale behind each branch.
	switch cause {
	case deathCauseNatural:
		// Real network failure — feed meltdown detector and reconnect the
		// same idx (reader observed the death, no replacement exists).
		p.recordSlotDeath()
		go p.reconnectLoop(idx)
	case deathCauseAgeCut:
		// Expected TSPU age-cut on a mature slot — routine in direct mode.
		// Reconnect FAST (ageCutReconnectJitter, NOT the 5-10s exponential) so
		// the cascade of mature-slot cuts does not bare the pool and freeze
		// quiet streams' downlink. Do NOT call recordSlotDeath: a steady cascade
		// of routine cuts must never trip the meltdown cooldown (which would
		// pause ALL reconnects and deepen the dip — Lever 3). Same idx as natural
		// (reader observed the death, no replacement exists).
		//
		// D1 A/B metric: split age-cut events by the selected TLS fingerprint
		// profile so the canary can tell whether a regional TSPU is targeting
		// Firefox specifically (Firefox-cohort cuts ≫ Chrome-cohort → adjust
		// weights).  p.lockedFP is write-once at pool construction; nil is safe
		// (falls into "other").
		{
			profileName := browser.ProfileChrome133 // sensible default when no FP is configured
			if p.lockedFP != nil {
				profileName = p.lockedFP.Profile().Name
			}
			Stats.IncAgeCut(profileName)
		}
		//
		// Lever 4 (counter-only): if this cut dropped ready capacity below the
		// floor, the pool is in (or entering) the dip the fast reconnect is meant
		// to shorten — tick the canary counter so we can measure the residual.
		if p.readyCapacity() < p.readyCapacityFloor() {
			p.recordCapacityDip()
		}
		go p.reconnectLoopFast(idx)
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
		// reserve targets can pick it via claimFreeReserveSlot.
		// reserveMu (Fix C3) serializes this write with connectSlot and
		// claimFreeReserveSlot.
		p.reserveMu.Lock()
		p.slots[idx] = nil
		p.reserveMu.Unlock()
	}
}

// resumeOutcome is the verdict resumeStreamOnDeath returns to the
// handleSlotDeath teardown loop.
type resumeOutcome int

const (
	// resumeOutcomeKept — the stream survived the slot death (RESUME_OK
	// re-pointed it to a live slot) or is mid-move under another goroutine
	// (its migrating flag is set). The teardown loop MUST NOT close its chan
	// or delete its (possibly re-pointed) entry.
	resumeOutcomeKept resumeOutcome = iota
	// resumeOutcomeBreak — no live target, RESUME failed, or RESUME was not
	// attempted. The teardown loop closes the chan (legacy degradation).
	resumeOutcomeBreak
)

// resumeStreamOnDeath attempts a grace RESUME of one stream off a dying slot
// (deadIdx) onto a live slot (Bug #9 Task 17, §5.5 — the SUDDEN-cut path that
// lets a stream survive an unexpected slot death). Called from handleSlotDeath's
// teardown loop for every active stream of the dead slot when migration is
// negotiated.
//
// Coordination with the preemptive watchdog (T16 migrateStream):
//   - If the stream's migrating flag is already set, a MIGRATE/RESUME is in
//     flight under another goroutine — that goroutine owns the stream's fate.
//     We return resumeOutcomeKept (do NOT close, do NOT delete) so we never
//     double-send or close a chan another goroutine is moving. The in-flight
//     move resolves on its own slot's reader; if it ultimately fails the stream
//     breaks then, which is acceptable (the slot is gone either way).
//   - Otherwise we CAS migrating false→true to claim the move (single winner),
//     pick a live target, and send a FlagResume. The flag is cleared on a
//     FAIL/timeout (stream breaks) and stays cleared-by-rebind on OK (the fresh
//     entry has migrating=false).
//
// The RESUME rides the LIVE TARGET slot's transport (slotForMigrate(targetIdx)),
// NOT the dead slot's broken socket — sendMigrate encrypts under the target
// session.
func (p *WSPoolTransport) resumeStreamOnDeath(cl *Client, streamID uint16, e *streamEntry, deadIdx int) resumeOutcome {
	// Already moving under another goroutine — keep, do not touch.
	if e.migrating.Load() {
		return resumeOutcomeKept
	}

	// Pick any live slot != the dead one. selectYoungTargetSlot returns the
	// youngest slotReady slot, which has the most runway before its own
	// lifecycle event — same target policy as the preemptive path.
	targetIdx, ok := p.selectYoungTargetSlot(deadIdx)
	if !ok {
		// No live slot to re-home onto — legacy degradation (close the chan).
		return resumeOutcomeBreak
	}

	// Single-winner CAS. Lost race → another goroutine claimed the move; keep.
	if !e.migrating.CompareAndSwap(false, true) {
		return resumeOutcomeKept
	}

	res := p.sendMigrateOrHook(streamID, core.FlagResume, targetIdx)
	if res.kind != migrateResultOK {
		// Server refused / no reply — the stream cannot be re-homed. Release the
		// flag and tell the loop to break (close) it.
		e.migrating.Store(false)
		Stats.MigrateResumeOnDeathFail.Add(1)
		return resumeOutcomeBreak
	}

	// RESUME_OK: re-point the binding to the live slot and transfer the per-slot
	// counter (inc target, dec the dead slot — the subsequent streams.Store(0)
	// on the dead slot is harmless, the stream already left). The fresh entry
	// installed by rebind has migrating=false, releasing the uplink barrier so
	// the next uplink write routes to the live target slot.
	p.rebindStreamToSlot(streamID, targetIdx)
	Stats.MigrateResumeOnDeathOK.Add(1)
	return resumeOutcomeKept
}

// Close shuts down all slots.
func (p *WSPoolTransport) Close() error {
	SetGlobalPoolForStats(nil)
	// Best-effort: tell the server to release every slot's session before we
	// tear the pool down (client exit / transport swap). Done BEFORE p.cancel()
	// so the slot transports are still live for the FIN write. Without this a
	// clean client shutdown leaves up to poolSize ghost sessions on the server
	// until their idle timeout (ghost-session bug, 2026-05-29).
	for _, slot := range p.snapshotSlots() {
		if slot == nil || slot.getState() != slotReady {
			continue
		}
		p.sendSlotSessionFIN(slot)
	}
	p.cancel()
	for _, slot := range p.snapshotSlots() {
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
	for _, slot := range p.snapshotSlots() {
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

// MigrationEnabled reports whether this pool negotiated Bug #9 stream migration
// (any slot's FLOWCTL V2 ack carried the migrate bit). When true the downlink
// wire format is seq-tagged (§5.4) and the SOCKS5 front-end must register
// streams via RegisterStreamSeq + run the downlink reassembler. Lock-free.
func (p *WSPoolTransport) MigrationEnabled() bool { return p.migrateEnabled.Load() }

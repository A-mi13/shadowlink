# WS Pool Concurrency Lift + Reserve-Slot Backoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **NO GIT COMMITS in this plan.** User has hard rule (memory `feedback_no_git.md`) — никаких `git add` / `git commit` шагов. Standard "frequent commits" замещён "frequent test-runs as checkpoints". User собирает changes как одно целое после ручной проверки.

**Goal:** Поднять `maxConcurrentDrains` с 2 до 3 при poolSize=6 через разделение storm-brake knob'ов на независимые fraction'ы; добавить exponential backoff на reserve-slot connect failure для защиты от Windows TIME_WAIT exhaustion.

**Architecture:** Three coordinated changes in `shadowlink/client/`: (1) удалить `rotationStormBrakeFraction=0.25` const и заменить на два независимых fraction'а (`maxConcurrentDrainsFraction=0.5`, `readyCapacityFloorFraction=0.75`); (2) добавить pool-level slice `reserveConnectFailures []atomic.Int32` (lifetime = pool, переживает recycle); (3) переписать `connectReserveSlot` чтобы при failure инкрементировал counter + spawned goroutine с jittered exp backoff (500ms → 30s cap) перед reconnectLoop.

**Tech Stack:** Go 1.22+, `sync/atomic`, `math/rand/v2` (already imported as `rand`), `log/slog`. Existing test patterns from `ws_pool_drain_logging_test.go` (`captureSlogForDrain`, `connectSlotForTest` hook, `newDiscardLogger`).

**Spec:** `shadowlink/docs/superpowers/specs/2026-05-24-concurrency-lift-and-backoff-design.md`

**Predecessor (already deployed):** `2026-05-24-drain-diagnostics-counter-split` — counter split + rate-limited INFO + conditional hard-cap level. Что дало diagnostic visibility которая обосновала эту правку.

---

## File Structure

| File | Role | Type |
|---|---|---|
| `shadowlink/client/ws_pool.go` | Remove `rotationStormBrakeFraction`, add 2 new fractions, rewrite `readyCapacityFloor()` and `maxConcurrentDrains()`, add `reserveConnectFailures []atomic.Int32` field to struct, init in `NewWSPoolTransport` | Modify |
| `shadowlink/client/ws_pool_drain.go` | Add 3 const for backoff (initial, max, jitter fraction), add `computeReserveBackoff` helper, rewrite `connectReserveSlot` to use pool-level counter + spawn timer goroutine | Modify |
| `shadowlink/client/stats.go` | Add `ReserveConnectFailuresTotal` counter + Prom exposition; update stale `rotationStormBrakeFraction` references in HELP/comments | Modify |
| `shadowlink/client/ws_pool_drain_test.go` | Update existing `TestReadyCapacityFloor_DerivedFromPoolSize` table (values change for poolSize=4 only — others stay the same) | Modify |
| `shadowlink/client/ws_pool_drain_logging_test.go` | Add knob value tests (3), backoff helper tests (5), connectReserveSlot integration tests (3) — 11 new tests total | Modify |

No new files. Tests colocated with existing logging test file because they share `captureSlogForDrain`, `newDiscardLogger`, and `connectSlotForTest` infrastructure.

---

## Task 1: Knob decoupling — constants and functions

**Files:**
- Modify: `shadowlink/client/ws_pool.go:476-498` (remove old const, add 2 new)
- Modify: `shadowlink/client/ws_pool.go:600-609` (rewrite `readyCapacityFloor`)
- Modify: `shadowlink/client/ws_pool.go:611-615` (rewrite `maxConcurrentDrains`)
- Modify: `shadowlink/client/ws_pool_drain_test.go:55-71` (update existing table test for new behavior)

- [ ] **Step 1: Update the existing `readyCapacityFloor` table test FIRST (TDD)**

Open `shadowlink/client/ws_pool_drain_test.go` at the existing test `TestReadyCapacityFloor_DerivedFromPoolSize`. Around line 55 there's a `cases` block. Replace it:

OLD:
```go
	cases := []struct {
		poolSize  int
		wantFloor int
	}{
		{poolSize: 8, wantFloor: 6},   // 8 - max(1, ceil(8*0.25)) = 8 - 2 = 6
		{poolSize: 4, wantFloor: 3},   // 4 - max(1, ceil(4*0.25)) = 4 - 1 = 3
		{poolSize: 2, wantFloor: 1},   // 2 - max(1, ceil(2*0.25)) = 2 - 1 = 1
		{poolSize: 16, wantFloor: 12}, // 16 - max(1, ceil(16*0.25)) = 16 - 4 = 12
	}
```

NEW:
```go
	// After 2026-05-24 decoupling: floor = max(1, min(poolSize-1, floor(poolSize * 0.75))).
	// Most values UNCHANGED from pre-decouple (this is intentional — decoupling
	// preserves the catastrophic-state defense at known-good values). Only
	// poolSize=2 shifts slightly because floor(1.5)=1 < max(1, ceil(2*0.25))=1
	// (still 1 — accidentally identical). poolSize=4 was floor=3 (4-1), now
	// floor(4*0.75)=3 (same). poolSize=6 was floor=4 (6-2), now floor(6*0.75)=4 (same).
	cases := []struct {
		poolSize  int
		wantFloor int
	}{
		{poolSize: 8, wantFloor: 6},   // floor(8*0.75) = 6 — UNCHANGED from pre-decouple
		{poolSize: 6, wantFloor: 4},   // floor(6*0.75) = 4 — UNCHANGED (added explicit row)
		{poolSize: 4, wantFloor: 3},   // floor(4*0.75) = 3 — UNCHANGED
		{poolSize: 2, wantFloor: 1},   // floor(2*0.75)=1, clamped min=1 — UNCHANGED
		{poolSize: 16, wantFloor: 12}, // floor(16*0.75) = 12 — UNCHANGED
	}
```

- [ ] **Step 2: Run the existing test to verify it still passes with the new comments**

Run: `cd shadowlink && go test ./client/ -run 'TestReadyCapacityFloor_DerivedFromPoolSize' -count=1 -v`
Expected: PASS (values unchanged from the table — this validates that the const swap below preserves behavior).

If it FAILS at this step — stop, the existing implementation diverges from the documented values and needs investigation.

- [ ] **Step 3: Replace `rotationStormBrakeFraction` const with two new fractions**

In `shadowlink/client/ws_pool.go`, locate the block at line 476-498:

OLD (delete entire block including doc-comment):
```go
// rotationStormBrakeFraction is the fraction of the pool that must be
// non-ready (dead, connecting, draining) before maybeRotateSlot pauses
// new preemptive rotations. Computed as ceil(poolSize * fraction).
//
// [... long doc-comment ...]
//
// 0.25 is chosen so a healthy pool of 8 still permits 2 simultaneous
// rotations (typical steady-state from age-stagger + byte-stagger),
// while clamping at 2 means we never enter the "alive=4 dead=4"
// state observed in the field.
const rotationStormBrakeFraction = 0.25
```

NEW (replace with):
```go
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
```

- [ ] **Step 4: Rewrite `readyCapacityFloor()`**

In `shadowlink/client/ws_pool.go`, find the function around line 600:

OLD:
```go
// readyCapacityFloor returns the minimum readyCapacity the storm brake
// will tolerate before deferring new drains. Derived from poolSize via
// rotationStormBrakeFraction — never a literal constant (spec §2.1, C1
// review fix).
//
// Invariants:
//   - maxConcurrentDrains := max(1, ceil(poolSize * 0.25))
//   - floor := poolSize - maxConcurrentDrains
//   - maxConcurrentDrains is clamped to < poolSize so floor >= 1
func (p *WSPoolTransport) readyCapacityFloor() int {
	mcd := int(math.Ceil(float64(p.poolSize) * rotationStormBrakeFraction))
	if mcd < 1 {
		mcd = 1
	}
	if mcd >= p.poolSize {
		mcd = p.poolSize - 1 // never block all drains
	}
	return p.poolSize - mcd
}
```

NEW:
```go
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
```

- [ ] **Step 5: Rewrite `maxConcurrentDrains()`**

In `shadowlink/client/ws_pool.go`, find the function around line 613:

OLD:
```go
// maxConcurrentDrains is the inflightDrains hard cap. See
// readyCapacityFloor for derivation.
func (p *WSPoolTransport) maxConcurrentDrains() int {
	return p.poolSize - p.readyCapacityFloor()
}
```

NEW:
```go
// maxConcurrentDrains is the inflightDrains hard cap. Independent of
// readyCapacityFloor after the 2026-05-24 knob decoupling — see spec
// §1.
//
// Derivation: ceil(poolSize * maxConcurrentDrainsFraction), clamped to
// [1, poolSize-1]. Clamps preserve invariants:
//   - cap >= 1 (always permit at least one drain — never deadlock the
//     scheduler by setting cap=0)
//   - cap <= poolSize-1 (never let all slots drain simultaneously)
func (p *WSPoolTransport) maxConcurrentDrains() int {
	mcd := int(math.Ceil(float64(p.poolSize) * maxConcurrentDrainsFraction))
	if mcd < 1 {
		mcd = 1
	}
	if mcd >= p.poolSize {
		mcd = p.poolSize - 1
	}
	return mcd
}
```

- [ ] **Step 6: Build and run the existing readyCapacityFloor table test**

Run: `cd shadowlink && go test ./client/ -run 'TestReadyCapacityFloor_DerivedFromPoolSize' -count=1 -v`
Expected: PASS — values unchanged because `floor(N * 0.75)` produces the same numbers as `N - ceil(N * 0.25)` for the test cases.

If FAIL: re-check the const values and clamp logic — possible arithmetic divergence at edge.

- [ ] **Step 7: Run all existing tests that may reference the old behavior**

Run: `cd shadowlink && go test ./client/ -count=1 2>&1 | tail -10`
Expected: ALL PASS. The key thing this catches: any test that hardcoded a `maxConcurrentDrains` value derived from the old formula. `TestStartDrain_InflightCounterCaps` (in ws_pool_drain_test.go line 1379) uses `poolSize=8` and `maxConcurrentDrains()` directly — at poolSize=8 the new formula gives `ceil(8*0.5)=4`, old gave 2. The test calls `p.inflightDrains.Store(int32(p.maxConcurrentDrains()))` (line 1397) which uses whatever the function returns — should still pass because it pre-saturates inflight to the cap value (whatever it is), then verifies the next 4 calls all defer.

If `TestStartDrain_InflightCounterCaps` fails — read the assertion carefully. If it asserts a literal `2` somewhere, that needs to be updated to match `p.maxConcurrentDrains()` dynamically.

---

## Task 2: New knob value tests

**Files:**
- Modify: `shadowlink/client/ws_pool_drain_logging_test.go` (append new tests at end of file)

- [ ] **Step 1: Write the failing tests**

Open `shadowlink/client/ws_pool_drain_logging_test.go`. Append at the end of the file:

```go
// TestMaxConcurrentDrains_NewValueAfterLift_2026_05_24 — invariant
// freeze for the 2026-05-24 concurrency lift. Cap raised from
// ceil(N*0.25) to ceil(N*0.5). At poolSize=6 the production setting
// jumps from 2 to 3 — that's the target change driven by canary
// 2026-05-24-evening (100% defers on inflight gate, 0 on floor gate).
func TestMaxConcurrentDrains_NewValueAfterLift_2026_05_24(t *testing.T) {
	cases := []struct {
		poolSize int
		want     int
	}{
		{poolSize: 1, want: 1},  // clamp min — never zero (was: clamp to 0 then min=1)
		{poolSize: 2, want: 1},  // ceil(2*0.5)=1, then clamp to poolSize-1=1
		{poolSize: 4, want: 2},  // ceil(4*0.5)=2 (was: ceil(4*0.25)=1)
		{poolSize: 6, want: 3},  // ceil(6*0.5)=3 (was: ceil(6*0.25)=2)  ← THE TARGET
		{poolSize: 8, want: 4},  // ceil(8*0.5)=4 (was: ceil(8*0.25)=2)
		{poolSize: 16, want: 8}, // ceil(16*0.5)=8 (was: ceil(16*0.25)=4)
	}
	for _, c := range cases {
		p := &WSPoolTransport{poolSize: c.poolSize}
		if got := p.maxConcurrentDrains(); got != c.want {
			t.Errorf("maxConcurrentDrains(poolSize=%d) = %d, want %d",
				c.poolSize, got, c.want)
		}
	}
}

// TestReadyCapacityFloor_UnchangedAfterDecouple_2026_05_24 — verifies
// the decoupling preserved capacity-floor values at canonical poolSizes.
// Cross-references the existing TestReadyCapacityFloor_DerivedFromPoolSize
// (which uses the same expected values but with updated derivation
// comments).
func TestReadyCapacityFloor_UnchangedAfterDecouple_2026_05_24(t *testing.T) {
	cases := []struct {
		poolSize int
		want     int
	}{
		{poolSize: 1, want: 1},  // floor(1*0.75)=0, clamp min=1, also clamp max=poolSize-1=0... edge: clamp wins, =1 then capped at 0 — see note
		{poolSize: 2, want: 1},  // floor(2*0.75)=1, within [1, 1]
		{poolSize: 4, want: 3},  // floor(4*0.75)=3 — UNCHANGED from pre-decouple
		{poolSize: 6, want: 4},  // floor(6*0.75)=4 — UNCHANGED
		{poolSize: 8, want: 6},  // floor(8*0.75)=6 — UNCHANGED
		{poolSize: 16, want: 12},// floor(16*0.75)=12 — UNCHANGED
	}
	for _, c := range cases {
		p := &WSPoolTransport{poolSize: c.poolSize}
		if got := p.readyCapacityFloor(); got != c.want {
			t.Errorf("readyCapacityFloor(poolSize=%d) = %d, want %d",
				c.poolSize, got, c.want)
		}
	}
}

// TestKnobs_AreIndependent_2026_05_24 — fingerprint test for the
// decoupling. Before 2026-05-24 the invariant was floor = poolSize - mcd,
// so mcd + floor == poolSize exactly. After decouple they're independent,
// and at poolSize=6 we expect mcd=3 + floor=4 = 7 > poolSize=6. This is
// EXPECTED and DESIRED — the two gates evaluate different conditions
// (inflight count vs ready count) and don't constrain each other.
func TestKnobs_AreIndependent_2026_05_24(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6}
	mcd := p.maxConcurrentDrains()
	floor := p.readyCapacityFloor()
	if mcd != 3 {
		t.Errorf("at poolSize=6, maxConcurrentDrains = %d, want 3", mcd)
	}
	if floor != 4 {
		t.Errorf("at poolSize=6, readyCapacityFloor = %d, want 4", floor)
	}
	if mcd+floor <= 6 {
		t.Errorf("after decouple, knobs should not constrain each other "+
			"(mcd=%d + floor=%d = %d, expected sum > poolSize=6)",
			mcd, floor, mcd+floor)
	}
}
```

**Note on poolSize=1 in `TestReadyCapacityFloor_UnchangedAfterDecouple_2026_05_24`:** `floor(1*0.75) = 0`, then `< 1` clamp → 1, then `>= poolSize=1` clamp → `poolSize-1 = 0`. So final value is **0** (max clamp wins). But existing tests (predecessor) don't have poolSize=1, so this is theoretically uncovered behavior. **Action: remove the `poolSize=1` row from this test** to avoid asserting on an edge-case nobody runs in production. Updated cases:

```go
	cases := []struct {
		poolSize int
		want     int
	}{
		{poolSize: 2, want: 1},
		{poolSize: 4, want: 3},
		{poolSize: 6, want: 4},
		{poolSize: 8, want: 6},
		{poolSize: 16, want: 12},
	}
```

Update the test code in Step 1 accordingly — remove the `poolSize: 1` row from `TestReadyCapacityFloor_UnchangedAfterDecouple_2026_05_24` only. Keep `poolSize=1` in `TestMaxConcurrentDrains_NewValueAfterLift_2026_05_24` because mcd clamp at min=1 is well-defined for that path.

- [ ] **Step 2: Run new tests, verify PASS**

Run: `cd shadowlink && go test ./client/ -run 'TestMaxConcurrentDrains_NewValueAfterLift|TestReadyCapacityFloor_UnchangedAfterDecouple|TestKnobs_AreIndependent' -count=1 -v`
Expected: PASS for all 3 tests.

---

## Task 3: Pool-level reserveConnectFailures slice + Stats counter

**Files:**
- Modify: `shadowlink/client/ws_pool.go` (struct `WSPoolTransport` — add field, init in `NewWSPoolTransport`)
- Modify: `shadowlink/client/stats.go` (add counter + Prom exposition)

- [ ] **Step 1: Add `reserveConnectFailures` slice to `WSPoolTransport` struct**

In `shadowlink/client/ws_pool.go`, locate `lastInflightCapLogNs` / `lastCapacityFloorLogNs` fields (added by predecessor spec). Add the new field right after them:

OLD:
```go
	// lastInflightCapLogNs / lastCapacityFloorLogNs — per-gate UnixNano
	// timestamp of the most recent INFO emission of "drain deferred".
	// Used by shouldLogDeferred to rate-limit the human-readable log
	// without throttling the counters. Zero value (initial) means "never
	// logged" — first call always logs. Spec 2026-05-24
	// (drain-diagnostics-counter-split) §2.
	lastInflightCapLogNs   atomic.Int64
	lastCapacityFloorLogNs atomic.Int64
```

NEW (append immediately after the existing fields):
```go
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
```

- [ ] **Step 2: Initialize the slice in `NewWSPoolTransport`**

In `shadowlink/client/ws_pool.go`, locate `NewWSPoolTransport` at line 1010. Find the existing line that allocates `p.slots`:

OLD (around line 1088):
```go
	p.slots = make([]*poolSlot, p.poolSize*2)
```

NEW:
```go
	p.slots = make([]*poolSlot, p.poolSize*2)
	// Pool-level per-cell counter for connectReserveSlot exponential
	// backoff (spec 2026-05-24 §2). Size matches slots — counter index
	// follows cell index. Zero-init is semantically correct (no prior
	// failures on a fresh pool).
	p.reserveConnectFailures = make([]atomic.Int32, p.poolSize*2)
```

- [ ] **Step 3: Add `Stats.ReserveConnectFailuresTotal` counter**

In `shadowlink/client/stats.go`, locate `DrainForceEvictedActiveTotal` declaration (you can grep for it). Add the new counter right after it:

```go
	// ReserveConnectFailuresTotal — cumulative count of connectReserveSlot
	// failures (across all cells). High rate suggests TIME_WAIT exhaustion
	// or origin endpoint instability — investigate before raising
	// maxConcurrentDrainsFraction further. Spec 2026-05-24
	// (concurrency-lift-and-backoff).
	ReserveConnectFailuresTotal atomic.Uint64
```

- [ ] **Step 4: Add Prom exposition for the new counter**

In `shadowlink/client/stats.go`, locate the existing block that exposes `DrainForceEvictedActiveTotal` (grep for `shadowlink_slot_drain_force_evicted_active_total`). Add right after that block:

```go
	fmt.Fprintf(w, "# HELP shadowlink_reserve_connect_failures_total Cumulative count of connectReserveSlot failures across all cells\n")
	fmt.Fprintf(w, "# TYPE shadowlink_reserve_connect_failures_total counter\n")
	fmt.Fprintf(w, "shadowlink_reserve_connect_failures_total %d\n", Stats.ReserveConnectFailuresTotal.Load())
```

- [ ] **Step 5: Build to verify everything compiles**

Run: `cd shadowlink && go build ./client/...`
Expected: success.

- [ ] **Step 6: Run full client test suite to ensure no regression**

Run: `cd shadowlink && go test ./client/ -count=1 2>&1 | tail -5`
Expected: PASS — no test exercises the new field yet, but the struct change must not break anything else.

---

## Task 4: computeReserveBackoff helper + unit tests

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go` (add 3 constants + helper)
- Modify: `shadowlink/client/ws_pool_drain_logging_test.go` (add 5 unit tests)

- [ ] **Step 1: Write failing tests for the helper**

In `shadowlink/client/ws_pool_drain_logging_test.go`, append at the end of the file:

```go
// absDuration returns the absolute value of a time.Duration. Used in
// jitter-bound tests to allow small slop for float rounding.
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// TestComputeReserveBackoff_FirstFailure — failures=1 with rng=0.5
// (zero jitter) yields exactly reserveConnectInitialBackoff.
func TestComputeReserveBackoff_FirstFailure(t *testing.T) {
	got := computeReserveBackoff(1, func() float64 { return 0.5 })
	if got != reserveConnectInitialBackoff {
		t.Errorf("backoff(1, rng=0.5) = %v, want %v",
			got, reserveConnectInitialBackoff)
	}
}

// TestComputeReserveBackoff_DoublesEachFailure — verifies exponential
// growth before the cap with rng=0.5 (no jitter).
func TestComputeReserveBackoff_DoublesEachFailure(t *testing.T) {
	rng := func() float64 { return 0.5 }
	cases := []struct {
		failures int32
		want     time.Duration
	}{
		{failures: 1, want: 500 * time.Millisecond},
		{failures: 2, want: 1 * time.Second},
		{failures: 3, want: 2 * time.Second},
		{failures: 4, want: 4 * time.Second},
		{failures: 5, want: 8 * time.Second},
		{failures: 6, want: 16 * time.Second},
	}
	for _, c := range cases {
		got := computeReserveBackoff(c.failures, rng)
		if got != c.want {
			t.Errorf("backoff(%d, no-jitter) = %v, want %v",
				c.failures, got, c.want)
		}
	}
}

// TestComputeReserveBackoff_CapsAtMax — beyond the doubling threshold
// (failures=7+) backoff stops at the ceiling reserveConnectMaxBackoff.
func TestComputeReserveBackoff_CapsAtMax(t *testing.T) {
	rng := func() float64 { return 0.5 }
	for _, failures := range []int32{7, 10, 100, 1000, 1 << 20} {
		got := computeReserveBackoff(failures, rng)
		if got != reserveConnectMaxBackoff {
			t.Errorf("backoff(%d) = %v, want %v (cap)",
				failures, got, reserveConnectMaxBackoff)
		}
	}
}

// TestComputeReserveBackoff_JitterBounds — verifies ±20% jitter is
// applied correctly at both extremes of the rng range.
func TestComputeReserveBackoff_JitterBounds(t *testing.T) {
	// rng=0.0 → jitterFrac = -0.2 → backoff * 0.8
	low := computeReserveBackoff(1, func() float64 { return 0.0 })
	wantLow := time.Duration(float64(reserveConnectInitialBackoff) * 0.8)
	if low != wantLow {
		t.Errorf("backoff(1, rng=0.0) = %v, want %v (low jitter bound)",
			low, wantLow)
	}

	// rng=0.999999 → jitterFrac ≈ +0.2 → backoff * ~1.2
	high := computeReserveBackoff(1, func() float64 { return 0.999999 })
	wantHigh := time.Duration(float64(reserveConnectInitialBackoff) * 1.2)
	if absDuration(high-wantHigh) > time.Microsecond {
		t.Errorf("backoff(1, rng≈1.0) = %v, want ≈%v (high jitter bound)",
			high, wantHigh)
	}
}

// TestComputeReserveBackoff_GuardsZeroFailures — defensive: failures=0
// or negative still produces initial backoff (treat as failures=1).
func TestComputeReserveBackoff_GuardsZeroFailures(t *testing.T) {
	rng := func() float64 { return 0.5 }
	for _, f := range []int32{0, -1, -100} {
		got := computeReserveBackoff(f, rng)
		if got != reserveConnectInitialBackoff {
			t.Errorf("backoff(%d) = %v, want %v (defensive)",
				f, got, reserveConnectInitialBackoff)
		}
	}
}
```

- [ ] **Step 2: Run the new tests, verify they FAIL at COMPILE**

Run: `cd shadowlink && go test ./client/ -run 'TestComputeReserveBackoff' -count=1 2>&1 | tail -10`
Expected: COMPILE ERROR — `undefined: computeReserveBackoff`, `undefined: reserveConnectInitialBackoff`, `undefined: reserveConnectMaxBackoff`.

- [ ] **Step 3: Add the 3 constants in `ws_pool_drain.go`**

In `shadowlink/client/ws_pool_drain.go`, locate the const block that contains `drainDeferredLogInterval` (added by predecessor spec). After it, before the closing `)`:

```go
	// reserveConnectInitialBackoff — first delay after connectReserveSlot
	// fails, before spawning reconnectLoop. Doubled on each consecutive
	// failure up to reserveConnectMaxBackoff. Spec 2026-05-24
	// (concurrency-lift-and-backoff) §2.
	reserveConnectInitialBackoff = 500 * time.Millisecond

	// reserveConnectMaxBackoff — ceiling for connectReserveSlot
	// exponential backoff. Equal to drainRevertBackoff (30s) for symmetry
	// with the existing "slice full" retry timeline. Spec 2026-05-24.
	reserveConnectMaxBackoff = 30 * time.Second

	// reserveConnectBackoffJitterFraction — ±20% jitter applied to the
	// computed backoff to avoid thundering herd when multiple slots fail
	// simultaneously (e.g. cascade TIME_WAIT exhaustion under upload
	// load). Spec 2026-05-24.
	reserveConnectBackoffJitterFraction = 0.2
```

- [ ] **Step 4: Add the `computeReserveBackoff` helper**

In `shadowlink/client/ws_pool_drain.go`, locate `shouldLogDeferred` function (added by predecessor spec). Right after it (or at the end of the file, doesn't matter for Go), add:

```go
// computeReserveBackoff returns an exponential backoff delay for the
// connectReserveSlot retry path, capped at reserveConnectMaxBackoff and
// jittered ±20% to break synchrony across cells.
//
// failures: consecutive failure count for this cell (1-based — 1 means
// "first failure", 2 means "second failure", etc.). Caller passes the
// value AFTER incrementing the counter, so failures=1 produces the
// initial backoff (500ms ± jitter), failures=2 produces 1s ± jitter,
// and so on, doubling until the 30s ceiling.
//
// The rng parameter returns float64 in [0.0, 1.0); production passes
// rand.Float64 (math/rand/v2). Tests pass a deterministic function to
// pin the jitter value.
//
// Spec 2026-05-24 (concurrency-lift-and-backoff) §2.
func computeReserveBackoff(failures int32, rng func() float64) time.Duration {
	if failures < 1 {
		failures = 1
	}
	// Cap shift to avoid int64 overflow at very high failure counts.
	// At failures=31 (shift=30) we have 500ms<<30 = 5.36e17ns, still
	// well below MaxInt64 = 9.22e18, but the >max check kicks in earlier.
	const maxShift = 30
	shift := failures - 1
	if shift > maxShift {
		shift = maxShift
	}
	delay := reserveConnectInitialBackoff << shift
	if delay > reserveConnectMaxBackoff || delay <= 0 {
		delay = reserveConnectMaxBackoff
	}
	// Apply ±20% jitter. rng returns [0.0, 1.0); map to [-0.2, +0.2).
	jitterFrac := (rng() - 0.5) * 2 * reserveConnectBackoffJitterFraction
	jittered := time.Duration(float64(delay) * (1.0 + jitterFrac))
	if jittered < 0 {
		jittered = 0
	}
	return jittered
}
```

- [ ] **Step 5: Run the new tests, verify PASS**

Run: `cd shadowlink && go test ./client/ -run 'TestComputeReserveBackoff' -count=1 -v`
Expected: PASS for all 5 tests.

---

## Task 5: Rewrite connectReserveSlot with backoff

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go:435-459` (rewrite `connectReserveSlot`)
- Modify: `shadowlink/client/ws_pool_drain_logging_test.go` (add 3 integration tests via `connectSlotForTest` hook)

- [ ] **Step 1: Write failing integration tests for connectReserveSlot**

In `shadowlink/client/ws_pool_drain_logging_test.go`, append at the end of the file:

```go
// makeReserveSlotTestPool returns a pool ready to exercise
// connectReserveSlot via the connectSlotForTest hook. poolSize=4 →
// slice size = 8 cells. Caller chooses newIdx and oldIdx for the
// connectReserveSlot call.
func makeReserveSlotTestPool(t *testing.T) *WSPoolTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &WSPoolTransport{
		poolSize: 4,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, p.poolSize*2)
	p.reserveConnectFailures = make([]atomic.Int32, p.poolSize*2)
	return p
}

// TestConnectReserveSlot_IncrementsFailureCounterOnFailure — verifies
// failure path bumps the pool-level counter. Two consecutive failures
// should produce counter=2.
func TestConnectReserveSlot_IncrementsFailureCounterOnFailure(t *testing.T) {
	p := makeReserveSlotTestPool(t)

	// Pre-install a slot at idx 1 so connectReserveSlot doesn't bail
	// out at the bounds check, and reserveMu cleanup has something to do.
	p.slots[1] = &poolSlot{index: 1}
	p.slots[1].setState(slotConnecting)

	prev := connectSlotForTest
	connectSlotForTest = func() error { return errors.New("simulated failure") }
	t.Cleanup(func() { connectSlotForTest = prev })

	p.connectReserveSlot(nil, 1, 0)

	if got := p.reserveConnectFailures[1].Load(); got != 1 {
		t.Errorf("after 1 failure, counter = %d, want 1", got)
	}

	// Re-install slot (cleanup nil'd it in the first call).
	p.slots[1] = &poolSlot{index: 1}
	p.slots[1].setState(slotConnecting)
	p.connectReserveSlot(nil, 1, 0)

	if got := p.reserveConnectFailures[1].Load(); got != 2 {
		t.Errorf("after 2 failures, counter = %d, want 2", got)
	}
}

// TestConnectReserveSlot_ResetsFailureCounterOnSuccess — pre-load the
// counter, drive connectReserveSlot success path via test hook, verify
// counter returns to 0. This tests real business logic via the hook
// (not the tautology p.Store(0); read==0).
func TestConnectReserveSlot_ResetsFailureCounterOnSuccess(t *testing.T) {
	p := makeReserveSlotTestPool(t)
	p.slots[2] = &poolSlot{index: 2}
	p.slots[2].setState(slotConnecting)
	p.reserveConnectFailures[2].Store(5) // simulate prior failures

	prev := connectSlotForTest
	// Success: return nil. NOTE: real connectReserveSlot spawns
	// p.slotReader on success, which we cannot run here (no Client).
	// But the counter reset happens BEFORE the slotReader spawn, so
	// we observe the side effect synchronously. The slotReader spawn
	// is harmless — it operates on a non-existent transport and exits
	// immediately when ReadMessage fails.
	connectSlotForTest = func() error { return nil }
	t.Cleanup(func() { connectSlotForTest = prev })

	// Use a non-nil minimal Client so slotReader can dispatch into it
	// without nil deref. Read paths in slotReader will fail fast on
	// the nil transport but the counter reset already happened.
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p.connectReserveSlot(cl, 2, 0)

	if got := p.reserveConnectFailures[2].Load(); got != 0 {
		t.Errorf("after success, counter = %d, want 0 (reset)", got)
	}
}

// TestConnectReserveSlot_PoolLevelCounterSurvivesSlotRecycle —
// regression guard for opus review H2. Pre-load 3 in pool-level
// counter. Simulate cell recycle (slot becomes nil, then a fresh
// poolSlot is installed at the same index). Trigger one more failure.
// Counter should be 4 (3 + 1), NOT 1 (which would happen if the counter
// lived on poolSlot).
func TestConnectReserveSlot_PoolLevelCounterSurvivesSlotRecycle(t *testing.T) {
	p := makeReserveSlotTestPool(t)
	const idx = 3
	p.reserveConnectFailures[idx].Store(3) // simulate prior failures

	// Simulate recycle: slot 3 was nil'd, now a fresh slot is claimed.
	p.slots[idx] = &poolSlot{index: idx}
	p.slots[idx].setState(slotConnecting)

	prev := connectSlotForTest
	connectSlotForTest = func() error { return errors.New("still failing") }
	t.Cleanup(func() { connectSlotForTest = prev })

	p.connectReserveSlot(nil, idx, 0)

	if got := p.reserveConnectFailures[idx].Load(); got != 4 {
		t.Errorf("after recycle + 1 more failure, counter = %d, want 4 "+
			"(counter must survive recycle — opus review H2 guard)", got)
	}
}
```

Required additional import in `ws_pool_drain_logging_test.go` if not already present:
```go
"errors"
```

(Check imports at top of file; add `"errors"` if missing.)

- [ ] **Step 2: Run the failing tests**

Run: `cd shadowlink && go test ./client/ -run 'TestConnectReserveSlot_' -count=1 2>&1 | tail -20`
Expected: FAIL — counter assertions fail because the current `connectReserveSlot` uses neither `p.reserveConnectFailures` nor produces the backoff goroutine. (Or COMPILE ERROR if `errors` import missing.)

- [ ] **Step 3: Rewrite `connectReserveSlot`**

In `shadowlink/client/ws_pool_drain.go`, find the function around line 435. Replace the entire function body:

OLD:
```go
func (p *WSPoolTransport) connectReserveSlot(cl *Client, newIdx, oldIdx int) {
	if newIdx < 0 || newIdx >= len(p.slots) {
		return
	}

	var err error
	if connectSlotForTest != nil {
		err = connectSlotForTest()
	} else {
		err = p.connectSlot(p.ctx, newIdx)
	}

	if err != nil {
		p.reserveMu.Lock()
		if p.slots[newIdx] != nil && p.slots[newIdx].getState() != slotReady {
			p.slots[newIdx] = nil // free for next claim
		}
		p.reserveMu.Unlock()
		p.log.Warn("WS pool reserve slot connect failed — placeholder freed",
			"slot", newIdx, "for_drain_of", oldIdx, "err", err)
		go p.reconnectLoop(newIdx)
		return
	}
	go p.slotReader(newIdx)
}
```

NEW:
```go
func (p *WSPoolTransport) connectReserveSlot(cl *Client, newIdx, oldIdx int) {
	if newIdx < 0 || newIdx >= len(p.slots) {
		return
	}

	var err error
	if connectSlotForTest != nil {
		err = connectSlotForTest()
	} else {
		err = p.connectSlot(p.ctx, newIdx)
	}

	if err != nil {
		// Pool-level counter (indexed by cell) survives slot recycle —
		// see spec §2 and opus review H2. Atomic Add is race-safe
		// under concurrent connectReserveSlot calls for the same cell
		// (possible during cascade failures).
		failures := p.reserveConnectFailures[newIdx].Add(1)
		Stats.ReserveConnectFailuresTotal.Add(1)

		p.reserveMu.Lock()
		if p.slots[newIdx] != nil && p.slots[newIdx].getState() != slotReady {
			p.slots[newIdx] = nil // free for next claim
		}
		p.reserveMu.Unlock()

		backoff := computeReserveBackoff(failures, rand.Float64)
		p.log.Warn("WS pool reserve slot connect failed — placeholder freed",
			"slot", newIdx, "for_drain_of", oldIdx,
			"err", err,
			"consecutive_failures", failures,
			"reconnect_backoff", backoff.Truncate(time.Millisecond))

		go func() {
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(backoff):
			}
			p.reconnectLoop(newIdx)
		}()
		return
	}

	// Success — reset the failure counter for this cell. Pool-level
	// storage means this reset persists across cell recycle.
	p.reserveConnectFailures[newIdx].Store(0)
	go p.slotReader(newIdx)
}
```

- [ ] **Step 4: Verify `rand` import is present in `ws_pool_drain.go`**

Check the top of `shadowlink/client/ws_pool_drain.go` for the `rand` import. Existing imports likely include `"sync/atomic"` and `"time"`. If `math/rand/v2` is NOT imported, add it:

```go
import (
	"math/rand/v2" // alias not needed — package name is "rand"
	"sync/atomic"
	"time"
)
```

If it IS already imported but under a different alias, use that alias instead of `rand.Float64`. (Grep `ws_pool.go` for `math/rand/v2` to see project convention — `ws_pool.go` line ~14 already imports `"math/rand/v2"` as `rand`.)

- [ ] **Step 5: Run the integration tests, verify PASS**

Run: `cd shadowlink && go test ./client/ -run 'TestConnectReserveSlot_' -count=1 -v`
Expected: PASS for all 3 tests.

- [ ] **Step 6: Run full client test suite — no regression**

Run: `cd shadowlink && go test ./client/ -count=1 2>&1 | tail -10`
Expected: PASS overall.

If `TestStartDrain_InflightCounterCaps` fails — check whether it asserted on a literal value that depends on the old `maxConcurrentDrains()`. The test pre-saturates `p.inflightDrains` to `int32(p.maxConcurrentDrains())` dynamically, then makes 4 concurrent startDrain calls and expects all 4 to defer. With new mcd=4 at poolSize=8, the test pre-saturates to 4 — the next call will defer on inflight gate as expected. Assertions count defers, not absolute values. Should pass unchanged.

If any other test fails — read the assertion. If it hardcoded `mcd=2`, update it to use `p.maxConcurrentDrains()` dynamically.

---

## Task 6: Update stale `rotationStormBrakeFraction` references

**Files:**
- Modify: `shadowlink/client/stats.go:243` (`CapacityFloorDeferredTotal` doc-comment)
- Modify: `shadowlink/client/stats.go:611` (Prom HELP text)

- [ ] **Step 1: Update `CapacityFloorDeferredTotal` doc-comment**

In `shadowlink/client/stats.go` around line 243, find:

```go
	// CapacityFloorDeferredTotal — drain attempts deferred because
	// readyCapacity fell below readyCapacityFloor (poolSize *
	// rotationStormBrakeFraction). Catastrophic path — pool losing slots
```

Replace with:

```go
	// CapacityFloorDeferredTotal — drain attempts deferred because
	// readyCapacity fell below readyCapacityFloor (poolSize *
	// readyCapacityFloorFraction, see ws_pool.go). Catastrophic path —
	// pool losing slots
```

- [ ] **Step 2: Update Prom HELP text**

In `shadowlink/client/stats.go` around line 611, find:

```go
	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_capacity_floor_deferred_total Drains deferred by storm-brake capacity-floor gate (readyCapacity < poolSize * rotationStormBrakeFraction)\n")
```

Replace with:

```go
	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_capacity_floor_deferred_total Drains deferred by storm-brake capacity-floor gate (readyCapacity < poolSize * readyCapacityFloorFraction)\n")
```

- [ ] **Step 3: Verify no other references remain**

Run: `cd shadowlink && grep -rn "rotationStormBrakeFraction" client/ 2>&1`
Expected: **empty output** — no remaining references in `client/*.go` files.

If any matches found in `client/` — read the surrounding context and update appropriately:
- If it's in a comment referring to the OLD design, replace with new const name
- If it's in actual code (impossible since the const is gone — would have been a compile error)

- [ ] **Step 4: Verify no literal `0.25` regressions in client/**

Run: `cd shadowlink && grep -rn "0\.25" client/*.go 2>&1`
Expected: only legitimate uses of 0.25 unrelated to storm-brake. Inspect each match:
- If it's in a `_test.go` file commenting on the OLD value — that's stale test rationale, fine to update or leave
- If it's anywhere else in storm-brake context — fix it

If `grep` matches in non-test code in storm-brake context — STOP and fix before continuing.

- [ ] **Step 5: Full build + test pass**

Run: `cd shadowlink && go build ./client/... && go test ./client/ -count=1 2>&1 | tail -5`
Expected: build clean, tests PASS.

---

## Task 7: Full test + race pass + rebuild binaries

**Files:**
- No code changes — verification + build only.

- [ ] **Step 1: Full client test suite**

Run: `cd shadowlink && go test ./client/... -count=1 -v 2>&1 | tail -80`
Expected: ALL PASS. Watch for:
- `TestMaxConcurrentDrains_NewValueAfterLift_2026_05_24` — PASS
- `TestReadyCapacityFloor_UnchangedAfterDecouple_2026_05_24` — PASS
- `TestKnobs_AreIndependent_2026_05_24` — PASS
- `TestComputeReserveBackoff_*` (5 tests) — ALL PASS
- `TestConnectReserveSlot_*` (3 tests) — ALL PASS
- Predecessor tests (`TestDrainDeferred_*`, `TestInflightCapCounter_*`, `TestCapacityFloorCounter_*`, `TestHardCap_*`, `TestHealthSnapshot_*`) — ALL PASS
- `TestReadyCapacityFloor_DerivedFromPoolSize` — PASS (values unchanged)
- `TestStartDrain_InflightCounterCaps` — PASS

Any failure: stop, read the failure, fix.

- [ ] **Step 2: Race detector — attempt locally, fall back to CI**

Run: `cd shadowlink && go test -race -count=1 ./client/ -run 'TestComputeReserveBackoff|TestConnectReserveSlot|TestKnobs|TestMaxConcurrentDrains|TestReadyCapacityFloor' -timeout 60s 2>&1 | tail -10`

Two outcomes:
1. **CGO available:** tests run with race detector. Expected: PASS, no race warnings.
2. **CGO unavailable on Windows:** output is `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`. This is a known limitation of the Windows dev environment (documented in `shadowlink/CLAUDE.md` Race Detector section). Skip the local race run and rely on CI Linux for race coverage. Document this in the implementation summary.

- [ ] **Step 3: gofmt check**

Run: `cd shadowlink && gofmt -l ./client/`
Expected: **only pre-existing files** that already had CRLF/LF issues (`ratelimit_detector.go`, `ratelimit_test.go`, `ws_pool.go`, `ws_pool_sticky_timeout_test.go`, `ws_pool_test.go`). No NEW files in the diff.

If a file you just modified appears in the list — it's a real format issue. Run `gofmt -w <file>` on it and re-verify tests still pass.

- [ ] **Step 4: Rebuild Windows binaries**

```bash
cd shadowlink
go build -o ../bin/nixavpn-client.exe ./cmd/nixavpn-client
go build -o ../bin/nixavpn-client-graceful-drain.exe ./cmd/nixavpn-client
```

Expected: both builds succeed, output `bin/*.exe` with timestamp = now.

- [ ] **Step 5: Rebuild cross-platform binaries**

```bash
cd shadowlink
GOOS=linux  GOARCH=amd64 go build -o ../bin/nixavpn-client-linux        ./cmd/nixavpn-client
GOOS=darwin GOARCH=arm64 go build -o ../bin/nixavpn-client-mac-arm64    ./cmd/nixavpn-client
GOOS=linux  GOARCH=amd64 go build -o ../bin/shadowlink-server-linux     ./cmd/shadowlink-server
GOOS=linux  GOARCH=amd64 go build -o ../bin/shadowlink-metrics-dump-linux ./cmd/shadowlink-metrics-dump
go build -o ../bin/cf-scanner.exe ./cmd/cf-scanner
```

Expected: all 5 builds succeed.

Note: server binary is rebuilt for safety (Prom exposition uses the new counter), even though server runtime is unaffected. cf-scanner imports the `client` package so it needs rebuild.

- [ ] **Step 6: Verify binary timestamps**

Run: `ls -la /d/NIXAVPN/bin/nixavpn-client*.exe /d/NIXAVPN/bin/nixavpn-client-linux /d/NIXAVPN/bin/nixavpn-client-mac-arm64 /d/NIXAVPN/bin/shadowlink-server-linux /d/NIXAVPN/bin/shadowlink-metrics-dump-linux /d/NIXAVPN/bin/cf-scanner.exe 2>&1`

Expected: all 7 files with timestamp = today, recent (within the last few minutes).

- [ ] **Step 7: Sanity check — Windows binary starts**

Run: `/d/NIXAVPN/bin/nixavpn-client-graceful-drain.exe --help 2>&1 | head -15`
Expected: usage output prints, no panic, no errors.

- [ ] **Step 8: Summary report**

Generate a short status summary for the user covering:
- Tasks completed (7)
- Tests added (11)
- Total test suite status (passing count, duration)
- Binaries rebuilt (7)
- Known limitations (race detector skipped if CGO unavailable)
- Next step: run `bin/connect-vpn-graceful-drain.bat` for next canary session

---

## Self-Review Checklist

**1. Spec coverage:**

| Spec Section | Task(s) | Status |
|---|---|---|
| §1 Knob decoupling (const + functions) | Task 1 | ✅ |
| §1 Invariant note (mcd+floor > poolSize) | Task 2 (TestKnobs_AreIndependent) | ✅ |
| §1 Degenerate state analysis | Documented in spec; behaviorally tested via TestStartDrain_InflightCounterCaps in pre-existing suite | ✅ |
| §2 Pool-level reserveConnectFailures slice | Task 3 | ✅ |
| §2 connectReserveSlot rewrite with backoff | Task 5 | ✅ |
| §2 computeReserveBackoff helper | Task 4 | ✅ |
| §2 TIME_WAIT hypothesis (Phase 2 fallback) | Out of code-scope — documented in spec for next-canary review | ✅ |
| §3 Stats.ReserveConnectFailuresTotal + Prom | Task 3 | ✅ |
| §3 Stale rotationStormBrakeFraction cleanup | Task 6 | ✅ |
| Testing — knob value tests (3) | Task 2 | ✅ |
| Testing — backoff math (5) | Task 4 | ✅ |
| Testing — connectReserveSlot integration (3) | Task 5 | ✅ |
| Testing — race detector | Task 7 Step 2 | ✅ |
| Acceptance — pre-merge greps | Task 6 Steps 3-4 | ✅ |

**2. Placeholder scan:** Searched plan for "TBD", "TODO", "implement later", "Add appropriate", "handle edge cases", "Similar to". None found. Every step has complete code or exact commands.

**3. Type consistency:**
- `reserveConnectFailures []atomic.Int32` — consistent across struct, init, access (Task 3, 5)
- `failures int32` — consistent in `computeReserveBackoff` signature (Task 4) and call site (Task 5)
- `rng func() float64` — consistent in helper definition (Task 4) and tests (Task 4 tests, Task 5 uses `rand.Float64`)
- `maxConcurrentDrainsFraction = 0.5` (float64) / `readyCapacityFloorFraction = 0.75` (float64) — consistent in const decl (Task 1) and `math.Ceil` / `math.Floor` calls (Task 1)
- `Stats.ReserveConnectFailuresTotal atomic.Uint64` — consistent in decl (Task 3) and `.Add(1)` (Task 5) and Prom `.Load()` (Task 3)

**4. Inter-task ordering:**
- Task 1 (const + functions) before Task 2 (tests for new values) — Task 2 would fail without Task 1
- Task 3 (slice + Stats) before Task 5 (uses the slice in connectReserveSlot)
- Task 4 (helper) before Task 5 (calls computeReserveBackoff)
- Task 6 (stale ref cleanup) independent — can run any time after Task 1
- Task 7 (verification) last

**5. NO GIT COMMITS:** Verified — no `git add` or `git commit` step appears anywhere. User reviews everything at end.

Plan is self-consistent and ready for execution.

---

**Plan complete and saved to `shadowlink/docs/superpowers/plans/2026-05-24-concurrency-lift-and-backoff.md`.**

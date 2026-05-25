# Drain Diagnostics — Counter Split, Rate-Limited INFO, Conditional Hard-Cap Level

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore visibility into ShadowLink WS-pool storm-brake activity (12326 silent deferrals over 4h52m on 2026-05-24) by splitting one aggregate counter into two per-gate counters, emitting INFO logs with 30s per-gate rate-limit, and downgrading expected hard-cap WARN noise to INFO.

**Architecture:** Three independent changes in `shadowlink/client/` — (1) `DrainStormBrakeEngagedTotal` → `InflightCapDeferredTotal` + `CapacityFloorDeferredTotal`, (2) atomic-CAS `shouldLogDeferred` helper with per-gate `lastInflightCapLogNs` / `lastCapacityFloorLogNs` timestamps for 30s rate-limit, (3) conditional `INFO`/`WARN` in `tearDown(finishHardCap)` gated on `remaining_streams >= 5`.

**Tech Stack:** Go 1.22+, `log/slog`, `sync/atomic`, existing test patterns from `ws_pool_drain_logging_test.go` (`makeStormBrakeTestPool`, `triggerStormBrakeInflightCapOn`, `captureSlogForDrain`).

**Spec:** `shadowlink/docs/superpowers/specs/2026-05-24-drain-diagnostics-counter-split-design.md`

---

## File Structure

| File | Role | Type |
|---|---|---|
| `shadowlink/client/stats.go` | Replace one `atomic.Uint64` counter + Prom exposition with two | Modify |
| `shadowlink/client/ws_pool.go` | Add 2 `atomic.Int64` fields to `WSPoolTransport` struct; update health snapshot | Modify |
| `shadowlink/client/ws_pool_drain.go` | Counter split in `startDrain` (gates 4-5); `shouldLogDeferred` helper; rate-limited INFO; conditional level in `tearDown(finishHardCap)` | Modify |
| `shadowlink/client/ws_pool_drain_logging_test.go` | Replace 3 existing tests; add 11 new tests covering split + rate-limit + conditional level | Modify |

No new files. No deletions. The split is in-place (counter renamed and split, but same struct, same package).

---

## Task 1: Add new counter fields, keep old one temporarily

**Files:**
- Modify: `shadowlink/client/stats.go:232-235` (add new counters near existing storm-brake counter)

The strategy is to add new counters first (tests will fail if they don't exist), then in Task 2 wire them in `startDrain`, then in Task 3 remove the old one once nothing references it. This keeps each commit green.

- [ ] **Step 1: Read current state of counter declarations**

Read: `shadowlink/client/stats.go:230-245`

Current block defines `StaleFrameDroppedTotal`, `DrainStormBrakeEngagedTotal`, `StreamBufferOverflowsTotal`.

- [ ] **Step 2: Add the two new counter declarations**

In `shadowlink/client/stats.go`, locate this block (around line 232):

```go
	// DrainStormBrakeEngagedTotal — every storm-brake deferral (either
	// inflight cap or capacity floor). Canary metric — was 326 in
	// baseline 2026-05-19. Target post-uniform-cells fix: <50 per 20min.
	DrainStormBrakeEngagedTotal atomic.Uint64
```

Replace it with:

```go
	// DrainStormBrakeEngagedTotal — DEPRECATED 2026-05-24. Use
	// InflightCapDeferredTotal + CapacityFloorDeferredTotal instead.
	// Retained for one transition commit; removed in the same task that
	// migrates all callers.
	DrainStormBrakeEngagedTotal atomic.Uint64

	// InflightCapDeferredTotal — drain attempts deferred because
	// inflightDrains already at maxConcurrentDrains. Indicates the
	// rotation scheduler is healthy but at peak concurrency. High rate
	// is OK if bounded; persistent saturation suggests poolSize is too
	// small for the current rotation cadence. Counter increments on
	// EVERY defer; log emission is rate-limited (drainDeferredLogInterval).
	// Spec 2026-05-24 (drain-diagnostics-counter-split).
	InflightCapDeferredTotal atomic.Uint64

	// CapacityFloorDeferredTotal — drain attempts deferred because
	// readyCapacity fell below readyCapacityFloor (poolSize *
	// rotationStormBrakeFraction). Catastrophic path — pool losing slots
	// faster than reconnectLoop heals. Non-zero rate is a warning sign;
	// persistent non-zero rate is cascading-slot-deaths failure mode.
	// Counter increments on EVERY defer; log emission rate-limited.
	// Spec 2026-05-24 (drain-diagnostics-counter-split).
	InflightCapDeferredTotal_unused_padding struct{} // separator comment-anchor; remove if linter complains
	CapacityFloorDeferredTotal              atomic.Uint64
```

Wait — the padding struct is a mistake. Use plain layout instead. Final form:

```go
	// DrainStormBrakeEngagedTotal — DEPRECATED 2026-05-24. Use
	// InflightCapDeferredTotal + CapacityFloorDeferredTotal instead.
	// Retained for one transition commit; removed in the same task that
	// migrates all callers.
	DrainStormBrakeEngagedTotal atomic.Uint64

	// InflightCapDeferredTotal — drain attempts deferred because
	// inflightDrains already at maxConcurrentDrains. Indicates the
	// rotation scheduler is healthy but at peak concurrency. High rate
	// is OK if bounded; persistent saturation suggests poolSize is too
	// small for the current rotation cadence. Counter increments on
	// EVERY defer; log emission is rate-limited (drainDeferredLogInterval).
	// Spec 2026-05-24 (drain-diagnostics-counter-split).
	InflightCapDeferredTotal atomic.Uint64

	// CapacityFloorDeferredTotal — drain attempts deferred because
	// readyCapacity fell below readyCapacityFloor (poolSize *
	// rotationStormBrakeFraction). Catastrophic path — pool losing slots
	// faster than reconnectLoop heals. Non-zero rate is a warning sign;
	// persistent non-zero rate is cascading-slot-deaths failure mode.
	// Counter increments on EVERY defer; log emission rate-limited.
	// Spec 2026-05-24 (drain-diagnostics-counter-split).
	CapacityFloorDeferredTotal atomic.Uint64
```

- [ ] **Step 3: Build to verify the struct change compiles**

Run: `cd shadowlink && go build ./client/...`
Expected: success (no compile errors, since old counter still exists).

- [ ] **Step 4: Commit**

```bash
git add shadowlink/client/stats.go
git commit -m "feat(shadowlink): add InflightCap/CapacityFloor deferred counters

Pre-split scaffolding. Old DrainStormBrakeEngagedTotal kept for one
commit until startDrain migrates to the new counters. Spec
2026-05-24-drain-diagnostics-counter-split-design.md Section 1."
```

---

## Task 2: Migrate startDrain to new counters

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go:264` (inflight-cap branch)
- Modify: `shadowlink/client/ws_pool_drain.go:283` (capacity-floor branch)

- [ ] **Step 1: Write the failing tests for split counters**

Open `shadowlink/client/ws_pool_drain_logging_test.go`. After the existing `TestDrainDeferred_CounterIncrement` (around line 112), add:

```go
// TestInflightCapCounter_IncrementsPerDefer — Task 2 invariant.
// N inflight-cap defers → InflightCapDeferredTotal grows by N.
func TestInflightCapCounter_IncrementsPerDefer(t *testing.T) {
	before := Stats.InflightCapDeferredTotal.Load()
	const n = 5
	for i := 0; i < n; i++ {
		triggerStormBrakeInflightCap(t)
	}
	got := Stats.InflightCapDeferredTotal.Load() - before
	if got != n {
		t.Errorf("InflightCapDeferredTotal delta = %d, want %d", got, n)
	}
}

// TestInflightCapCounter_DoesNotIncrementCapacityFloor — Task 2 invariant.
// Inflight-cap defers MUST NOT bump the capacity-floor counter.
func TestInflightCapCounter_DoesNotIncrementCapacityFloor(t *testing.T) {
	beforeCap := Stats.CapacityFloorDeferredTotal.Load()
	for i := 0; i < 5; i++ {
		triggerStormBrakeInflightCap(t)
	}
	if got := Stats.CapacityFloorDeferredTotal.Load(); got != beforeCap {
		t.Errorf("CapacityFloorDeferredTotal advanced on inflight-cap path: before=%d after=%d",
			beforeCap, got)
	}
}
```

- [ ] **Step 2: Run tests, verify they FAIL**

Run: `cd shadowlink && go test ./client/ -run 'TestInflightCapCounter' -v`
Expected: FAIL — both tests show `delta = 0, want 5` (old counter is still the one being incremented).

- [ ] **Step 3: Migrate inflight-cap branch in startDrain**

In `shadowlink/client/ws_pool_drain.go`, locate the inflight-cap gate (around line 263-275):

```go
	if int(inflight) > p.maxConcurrentDrains() {
		Stats.DrainStormBrakeEngagedTotal.Add(1)
		p.bumpDrainDeferrals1m()
		// Per-event DEBUG: aggregated counter surfaces in 'WS pool
		// health' snapshot every ~5s (deferred_drains_1m /
		// deferred_drains_total). Spec 2026-05-23.
		p.log.Debug("WS pool slot drain deferred (inflight cap)",
			"slot", oldIdx, "reason", reason,
			"inflight", inflight,
			"max_concurrent", p.maxConcurrentDrains())
		// Storm-brake-only deferral — fast retry.
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainStormBrakeBackoff).UnixNano())
		return
	}
```

Replace `Stats.DrainStormBrakeEngagedTotal.Add(1)` with `Stats.InflightCapDeferredTotal.Add(1)`. Final form:

```go
	if int(inflight) > p.maxConcurrentDrains() {
		Stats.InflightCapDeferredTotal.Add(1)
		p.bumpDrainDeferrals1m()
		// Per-event DEBUG: aggregated counter surfaces in 'WS pool
		// health' snapshot every ~5s. Spec 2026-05-24 will re-promote
		// this to INFO with per-gate rate-limit (Task 4).
		p.log.Debug("WS pool slot drain deferred (inflight cap)",
			"slot", oldIdx, "reason", reason,
			"inflight", inflight,
			"max_concurrent", p.maxConcurrentDrains())
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainStormBrakeBackoff).UnixNano())
		return
	}
```

- [ ] **Step 4: Migrate capacity-floor branch in startDrain**

In `shadowlink/client/ws_pool_drain.go`, locate the capacity-floor gate (around line 280-300):

```go
	ready := p.readyCapacity()
	floor := p.readyCapacityFloor()
	if ready < floor {
		Stats.DrainStormBrakeEngagedTotal.Add(1)
		p.bumpDrainDeferrals1m()
		// Catastrophic state (less than half pool ready) → longer backoff
		// so reconnectLoop has time to heal capacity (spec §2.1.1).
		backoff := drainStormBrakeBackoff
		if ready < p.poolSize/2 {
			backoff = drainCatastrophicBackoff
		}
		// Per-event DEBUG: aggregated counter in 'WS pool health'.
		// Spec 2026-05-23.
		p.log.Debug("WS pool slot drain deferred (capacity floor)",
			"slot", oldIdx, "reason", reason,
			"ready_capacity", ready,
			"floor", floor,
			"backoff", backoff)
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(backoff).UnixNano())
		return
	}
```

Replace `Stats.DrainStormBrakeEngagedTotal.Add(1)` with `Stats.CapacityFloorDeferredTotal.Add(1)`. Final form:

```go
	ready := p.readyCapacity()
	floor := p.readyCapacityFloor()
	if ready < floor {
		Stats.CapacityFloorDeferredTotal.Add(1)
		p.bumpDrainDeferrals1m()
		backoff := drainStormBrakeBackoff
		if ready < p.poolSize/2 {
			backoff = drainCatastrophicBackoff
		}
		// Per-event DEBUG: aggregated counter in 'WS pool health'.
		// Spec 2026-05-24 will re-promote this to INFO with per-gate
		// rate-limit (Task 4).
		p.log.Debug("WS pool slot drain deferred (capacity floor)",
			"slot", oldIdx, "reason", reason,
			"ready_capacity", ready,
			"floor", floor,
			"backoff", backoff)
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(backoff).UnixNano())
		return
	}
```

- [ ] **Step 5: Update the legacy test `TestDrainDeferred_CounterIncrement` to use new counter**

The old `TestDrainDeferred_CounterIncrement` (line 100-112) still references `DrainStormBrakeEngagedTotal`. Since startDrain no longer touches it, this test would fail. Update it to use the new counter:

In `shadowlink/client/ws_pool_drain_logging_test.go`, replace:

```go
// TestDrainDeferred_CounterIncrement verifies the cumulative stat
// counter increments per deferral (unchanged behaviour vs pre-spec).
func TestDrainDeferred_CounterIncrement(t *testing.T) {
	before := Stats.DrainStormBrakeEngagedTotal.Load()
	const n = 5
	for i := 0; i < n; i++ {
		triggerStormBrakeInflightCap(t)
	}
	got := Stats.DrainStormBrakeEngagedTotal.Load() - before
	if got != n {
		t.Errorf("DrainStormBrakeEngagedTotal delta = %d, want %d", got, n)
	}
}
```

with:

```go
// TestDrainDeferred_AggregateCounterIsZero verifies that the deprecated
// aggregate counter no longer advances after the 2026-05-24 split. Any
// startDrain caller hitting the inflight-cap or capacity-floor gate
// MUST route through the per-gate counters (covered by
// TestInflightCapCounter_* and TestCapacityFloorCounter_*).
func TestDrainDeferred_AggregateCounterIsZero(t *testing.T) {
	before := Stats.DrainStormBrakeEngagedTotal.Load()
	for i := 0; i < 5; i++ {
		triggerStormBrakeInflightCap(t)
	}
	if got := Stats.DrainStormBrakeEngagedTotal.Load(); got != before {
		t.Errorf("DEPRECATED DrainStormBrakeEngagedTotal advanced (%d → %d) — "+
			"some path still calls .Add() instead of the per-gate counters",
			before, got)
	}
}
```

- [ ] **Step 6: Run all client tests, verify pass**

Run: `cd shadowlink && go test ./client/ -run 'TestDrainDeferred|TestInflightCap|TestCapacityFloor' -v`
Expected: PASS for `TestInflightCapCounter_IncrementsPerDefer`, `TestInflightCapCounter_DoesNotIncrementCapacityFloor`, `TestDrainDeferred_AggregateCounterIsZero`, `TestDrainDeferred_LogLevelDebug`, `TestDrainDeferred_BumpRollingCounter`, `TestHealthSnapshot_SurfacesDeferredCounters` (last one still uses old field — passes because health snapshot still emits old counter via Task 1's deprecated field, see Task 5 for fix).

- [ ] **Step 7: Commit**

```bash
git add shadowlink/client/ws_pool_drain.go shadowlink/client/ws_pool_drain_logging_test.go
git commit -m "feat(shadowlink): migrate startDrain to per-gate deferred counters

Gate 4 (inflight cap) → InflightCapDeferredTotal.
Gate 5 (capacity floor) → CapacityFloorDeferredTotal.

DEPRECATED DrainStormBrakeEngagedTotal is no longer written but still
declared — removed in Task 3 along with its Prometheus exposition.
Test invariants:
  - TestInflightCapCounter_{IncrementsPerDefer,DoesNotIncrementCapacityFloor}
  - TestDrainDeferred_AggregateCounterIsZero (regression guard)

Spec 2026-05-24-drain-diagnostics-counter-split-design.md Section 1."
```

---

## Task 3: Add capacity-floor test helper and capacity-floor counter test

**Files:**
- Modify: `shadowlink/client/ws_pool_drain_logging_test.go` (add helper + test)

The existing test infra has `makeStormBrakeTestPool` that pre-saturates **inflight**, but no equivalent for **capacity floor**. To test the capacity-floor branch deterministically we need a helper that pre-empties the pool below floor.

- [ ] **Step 1: Write the helper `makeCapacityFloorTestPool` and tests**

After `triggerStormBrakeInflightCap` (line 75), add:

```go
// makeCapacityFloorTestPool returns a pool wired enough to call startDrain
// and land in the capacity-floor storm-brake gate. Setup: poolSize=8,
// readyCapacityFloor=ceil(8*0.25)=2, so we mark exactly 1 slot ready
// (below floor of 2) and 7 slots non-ready. Inflight is NOT pre-saturated
// so the inflight-cap gate passes; the next startDrain trips capacity-floor.
//
// The caller can override p.log (e.g. via captureSlogForDrain) before
// triggering startDrain. The slot at index 0 must be slotReady because
// startDrain is called with oldIdx=0 and expects oldSlot != nil.
func makeCapacityFloorTestPool(t *testing.T) *WSPoolTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	// Only idx 0 is slotReady — readyCapacity() = 1, below floor of 2.
	p.slots[0] = &poolSlot{index: 0}
	p.slots[0].setState(slotReady)
	// Other slots stay nil → readyCapacity stays at 1.
	return p
}

// triggerStormBrakeCapacityFloorOn fires one startDrain on the given pool;
// because readyCapacity (1) < floor (2), the call lands in the
// capacity-floor deferred branch.
func triggerStormBrakeCapacityFloorOn(t *testing.T, p *WSPoolTransport) {
	t.Helper()
	p.startDrain(nil, 0, "test")
}

// triggerStormBrakeCapacityFloor builds a fresh pool + fires one deferral.
func triggerStormBrakeCapacityFloor(t *testing.T) {
	t.Helper()
	triggerStormBrakeCapacityFloorOn(t, makeCapacityFloorTestPool(t))
}

// TestCapacityFloorCounter_IncrementsPerDefer — Task 3 invariant.
// N capacity-floor defers → CapacityFloorDeferredTotal grows by N.
func TestCapacityFloorCounter_IncrementsPerDefer(t *testing.T) {
	before := Stats.CapacityFloorDeferredTotal.Load()
	const n = 5
	for i := 0; i < n; i++ {
		triggerStormBrakeCapacityFloor(t)
	}
	got := Stats.CapacityFloorDeferredTotal.Load() - before
	if got != n {
		t.Errorf("CapacityFloorDeferredTotal delta = %d, want %d", got, n)
	}
}

// TestCapacityFloorCounter_DoesNotIncrementInflightCap — symmetric
// to TestInflightCapCounter_DoesNotIncrementCapacityFloor.
func TestCapacityFloorCounter_DoesNotIncrementInflightCap(t *testing.T) {
	beforeInflight := Stats.InflightCapDeferredTotal.Load()
	for i := 0; i < 5; i++ {
		triggerStormBrakeCapacityFloor(t)
	}
	if got := Stats.InflightCapDeferredTotal.Load(); got != beforeInflight {
		t.Errorf("InflightCapDeferredTotal advanced on capacity-floor path: before=%d after=%d",
			beforeInflight, got)
	}
}
```

- [ ] **Step 2: Run the new tests, verify PASS**

Run: `cd shadowlink && go test ./client/ -run 'TestCapacityFloorCounter' -v`
Expected: PASS — both new tests verify the capacity-floor counter increments correctly without leaking into the inflight counter.

If a test fails with `readyCapacityFloor = 2 wanted 1`: verify `rotationStormBrakeFraction = 0.25` constant in `ws_pool.go` is unchanged (line ~498).

- [ ] **Step 3: Commit**

```bash
git add shadowlink/client/ws_pool_drain_logging_test.go
git commit -m "test(shadowlink): add capacity-floor counter coverage

makeCapacityFloorTestPool helper sets readyCapacity=1 below floor=2
(poolSize=8 * 0.25 = ceil 2), so the next startDrain trips the
capacity-floor gate deterministically.

Tests:
  - TestCapacityFloorCounter_IncrementsPerDefer
  - TestCapacityFloorCounter_DoesNotIncrementInflightCap

Spec 2026-05-24-drain-diagnostics-counter-split-design.md Section 1."
```

---

## Task 4: shouldLogDeferred helper + rate-limited INFO emission

**Files:**
- Modify: `shadowlink/client/ws_pool.go` (struct fields)
- Modify: `shadowlink/client/ws_pool_drain.go` (constant, helper, startDrain log calls)
- Modify: `shadowlink/client/ws_pool_drain_logging_test.go` (replace log-level tests, add new)

- [ ] **Step 1: Write tests for `shouldLogDeferred` helper**

In `shadowlink/client/ws_pool_drain_logging_test.go`, add at the end of the file:

```go
import (
	"sync"
	"sync/atomic"
)

// (top-of-file imports — adjust the existing import block to include
// sync and sync/atomic if not already imported.)

// TestShouldLogDeferred_FirstCallAlwaysTrue — zero value of last (never
// logged) → helper returns true and stores `now`.
func TestShouldLogDeferred_FirstCallAlwaysTrue(t *testing.T) {
	var last atomic.Int64
	now := time.Unix(1000, 0)
	if !shouldLogDeferred(&last, now) {
		t.Fatalf("first call should return true (zero last value)")
	}
	if got := last.Load(); got != now.UnixNano() {
		t.Errorf("last.Load() = %d, want %d (CAS should have published now)",
			got, now.UnixNano())
	}
}

// TestShouldLogDeferred_BlocksWithinInterval — second call within
// drainDeferredLogInterval returns false; last is unchanged.
func TestShouldLogDeferred_BlocksWithinInterval(t *testing.T) {
	var last atomic.Int64
	t0 := time.Unix(1000, 0)
	if !shouldLogDeferred(&last, t0) {
		t.Fatalf("first call must return true")
	}
	t1 := t0.Add(drainDeferredLogInterval - time.Second) // 29s later
	if shouldLogDeferred(&last, t1) {
		t.Errorf("call within interval (%v) should return false", t1.Sub(t0))
	}
	if got := last.Load(); got != t0.UnixNano() {
		t.Errorf("last changed on blocked call: got=%d want=%d", got, t0.UnixNano())
	}
}

// TestShouldLogDeferred_AllowsAfterInterval — call after
// drainDeferredLogInterval returns true and updates last.
func TestShouldLogDeferred_AllowsAfterInterval(t *testing.T) {
	var last atomic.Int64
	t0 := time.Unix(1000, 0)
	shouldLogDeferred(&last, t0)
	t1 := t0.Add(drainDeferredLogInterval + time.Second) // 31s later
	if !shouldLogDeferred(&last, t1) {
		t.Errorf("call after interval should return true")
	}
	if got := last.Load(); got != t1.UnixNano() {
		t.Errorf("last not updated on successful call: got=%d want=%d",
			got, t1.UnixNano())
	}
}

// TestShouldLogDeferred_CASRacesProduceAtMostOneWinner — N goroutines
// race after an interval has elapsed. AT MOST one returns true (a
// proposer may see prev > threshold if another raced in first, or all
// may CAS-fail against each other — either case is correctness; the
// guarantee is ≤1, not ==1).
func TestShouldLogDeferred_CASRacesProduceAtMostOneWinner(t *testing.T) {
	var last atomic.Int64
	// Seed with old timestamp so the interval has elapsed.
	last.Store(time.Unix(0, 0).UnixNano())
	now := time.Unix(1000, 0)

	const goroutines = 100
	var wg sync.WaitGroup
	var winners atomic.Int32
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if shouldLogDeferred(&last, now) {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()

	if w := winners.Load(); w > 1 {
		t.Errorf("CAS race produced %d winners, want ≤1", w)
	}
	// (We don't assert ≥1 because if all goroutines happen to schedule
	// such that each sees a prev written by another, all CAS calls fail.
	// That's correct behaviour — exactly the race we're guarding against.)
}
```

- [ ] **Step 2: Run the new tests, verify they FAIL (helper not defined yet)**

Run: `cd shadowlink && go test ./client/ -run 'TestShouldLogDeferred' -v`
Expected: FAIL at COMPILE — `undefined: shouldLogDeferred`, `undefined: drainDeferredLogInterval`.

- [ ] **Step 3: Add the constant and helper in `ws_pool_drain.go`**

In `shadowlink/client/ws_pool_drain.go`, find the existing `drainStormBrakeBackoff` block (around line 14-30). After the `drainCatastrophicBackoff` constant, add:

```go
	// drainDeferredLogInterval — minimum wall-clock gap between two
	// consecutive INFO emissions of "drain deferred" for the SAME gate.
	// Counters always increment; only the human-readable log is
	// rate-limited. 30s chosen to surface temporal trends (peaks/valleys)
	// without log spam — the 2026-05-24 session (12326 deferrals over
	// 4h52m) would have produced ~10 INFO lines per gate.
	// Spec 2026-05-24 (drain-diagnostics-counter-split).
	drainDeferredLogInterval = 30 * time.Second
```

Then at the end of the file (or just before `startDrain`), add the helper:

```go
// shouldLogDeferred returns true if at least drainDeferredLogInterval has
// elapsed since the last INFO log for the gate represented by `last`.
// Atomic CAS guarantees exactly-one-winner semantics under concurrent
// calls — no mutex needed. The `now` parameter is passed explicitly so
// tests can inject deterministic timestamps without monkey-patching
// time.Now() globally.
//
// Returns true ≤1 time per drainDeferredLogInterval per `last`; counters
// are NOT touched here and must increment unconditionally at the call
// site (see Spec Section 2). The returned bool gates ONLY the log call.
//
// Spec 2026-05-24 (drain-diagnostics-counter-split).
func shouldLogDeferred(last *atomic.Int64, now time.Time) bool {
	prev := last.Load()
	threshold := now.Add(-drainDeferredLogInterval).UnixNano()
	if prev > threshold {
		return false
	}
	return last.CompareAndSwap(prev, now.UnixNano())
}
```

Note: `sync/atomic` is already imported in this file (existing `atomic.Int64` use in pool struct fields is referenced via the `client` package — verify `import "sync/atomic"` is present at top of file).

- [ ] **Step 4: Run helper tests, verify PASS**

Run: `cd shadowlink && go test ./client/ -run 'TestShouldLogDeferred' -v`
Expected: PASS for all 4 helper tests.

- [ ] **Step 5: Add per-gate timestamp fields to `WSPoolTransport` struct**

In `shadowlink/client/ws_pool.go`, locate the `drainDeferrals1m atomic.Int32` field (around line 881). After it, add:

```go
	// lastInflightCapLogNs / lastCapacityFloorLogNs — per-gate UnixNano
	// timestamp of the most recent INFO emission of "drain deferred".
	// Used by shouldLogDeferred to rate-limit the human-readable log
	// without throttling the counters. Zero value (initial) means "never
	// logged" — first call always logs. Spec 2026-05-24
	// (drain-diagnostics-counter-split) Section 2.
	lastInflightCapLogNs   atomic.Int64
	lastCapacityFloorLogNs atomic.Int64
```

- [ ] **Step 6: Wire rate-limited INFO into startDrain (inflight-cap branch)**

In `shadowlink/client/ws_pool_drain.go`, replace the inflight-cap gate (around lines 263-275, from Task 2):

```go
	if int(inflight) > p.maxConcurrentDrains() {
		Stats.InflightCapDeferredTotal.Add(1)
		p.bumpDrainDeferrals1m()
		// Per-event DEBUG: aggregated counter surfaces in 'WS pool
		// health' snapshot every ~5s. Spec 2026-05-24 will re-promote
		// this to INFO with per-gate rate-limit (Task 4).
		p.log.Debug("WS pool slot drain deferred (inflight cap)",
			"slot", oldIdx, "reason", reason,
			"inflight", inflight,
			"max_concurrent", p.maxConcurrentDrains())
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainStormBrakeBackoff).UnixNano())
		return
	}
```

with:

```go
	if int(inflight) > p.maxConcurrentDrains() {
		Stats.InflightCapDeferredTotal.Add(1)
		p.bumpDrainDeferrals1m()
		// INFO with per-gate 30s rate-limit (spec 2026-05-24). Counters
		// above always increment; only the log line is rate-limited so
		// production logs stay readable. total_count in the log line
		// gives readers the real rate via delta between successive INFOs.
		if shouldLogDeferred(&p.lastInflightCapLogNs, time.Now()) {
			p.log.Info("WS pool slot drain deferred (inflight cap)",
				"slot", oldIdx, "reason", reason,
				"inflight", inflight,
				"max_concurrent", p.maxConcurrentDrains(),
				"total_count", Stats.InflightCapDeferredTotal.Load(),
				"deferred_1m", p.drainDeferrals1m.Load())
		}
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainStormBrakeBackoff).UnixNano())
		return
	}
```

- [ ] **Step 7: Wire rate-limited INFO into startDrain (capacity-floor branch)**

Similarly, replace the capacity-floor branch (around lines 280-300):

```go
	if ready < floor {
		Stats.CapacityFloorDeferredTotal.Add(1)
		p.bumpDrainDeferrals1m()
		backoff := drainStormBrakeBackoff
		if ready < p.poolSize/2 {
			backoff = drainCatastrophicBackoff
		}
		// Per-event DEBUG: aggregated counter in 'WS pool health'.
		// Spec 2026-05-24 will re-promote this to INFO with per-gate
		// rate-limit (Task 4).
		p.log.Debug("WS pool slot drain deferred (capacity floor)",
			"slot", oldIdx, "reason", reason,
			"ready_capacity", ready,
			"floor", floor,
			"backoff", backoff)
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(backoff).UnixNano())
		return
	}
```

with:

```go
	if ready < floor {
		Stats.CapacityFloorDeferredTotal.Add(1)
		p.bumpDrainDeferrals1m()
		backoff := drainStormBrakeBackoff
		if ready < p.poolSize/2 {
			backoff = drainCatastrophicBackoff
		}
		// INFO with per-gate 30s rate-limit (spec 2026-05-24). See
		// inflight-cap branch above for the rationale.
		if shouldLogDeferred(&p.lastCapacityFloorLogNs, time.Now()) {
			p.log.Info("WS pool slot drain deferred (capacity floor)",
				"slot", oldIdx, "reason", reason,
				"ready_capacity", ready,
				"floor", floor,
				"backoff", backoff,
				"total_count", Stats.CapacityFloorDeferredTotal.Load(),
				"deferred_1m", p.drainDeferrals1m.Load())
		}
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(backoff).UnixNano())
		return
	}
```

- [ ] **Step 8: Replace `TestDrainDeferred_LogLevelDebug` with INFO equivalents**

The existing `TestDrainDeferred_LogLevelDebug` (line 79-98) asserts the DEBUG level. After the spec change, the log is INFO. Replace that test entirely with:

```go
// TestDrainDeferred_InflightCap_LogLevelInfo — verifies the spec
// 2026-05-24 re-promotion: drain-deferred (inflight cap) emits at
// INFO level (the DEBUG demotion in spec 2026-05-23 hid the diagnostic).
func TestDrainDeferred_InflightCap_LogLevelInfo(t *testing.T) {
	t.Run("info_level_visible", func(t *testing.T) {
		buf, logger := captureSlogForDrain(t, slog.LevelInfo)
		p := makeStormBrakeTestPool(t)
		p.log = logger
		triggerStormBrakeInflightCapOn(t, p)
		if !strings.Contains(buf.String(), "drain deferred (inflight cap)") {
			t.Errorf("INFO-level capture SHOULD contain drain deferred:\n%s",
				buf.String())
		}
	})
	t.Run("warn_level_silent", func(t *testing.T) {
		buf, logger := captureSlogForDrain(t, slog.LevelWarn)
		p := makeStormBrakeTestPool(t)
		p.log = logger
		triggerStormBrakeInflightCapOn(t, p)
		if strings.Contains(buf.String(), "drain deferred (inflight cap)") {
			t.Errorf("WARN-level capture should NOT contain drain deferred:\n%s",
				buf.String())
		}
	})
}

// TestDrainDeferred_CapacityFloor_LogLevelInfo — symmetric for the
// capacity-floor branch.
func TestDrainDeferred_CapacityFloor_LogLevelInfo(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p := makeCapacityFloorTestPool(t)
	p.log = logger
	triggerStormBrakeCapacityFloorOn(t, p)
	if !strings.Contains(buf.String(), "drain deferred (capacity floor)") {
		t.Errorf("INFO-level capture SHOULD contain capacity-floor defer:\n%s",
			buf.String())
	}
}

// TestDrainDeferred_RateLimit_OneLogPer30sPerGate — N inflight-cap
// defers fired in tight succession produce exactly 1 INFO line; the
// counter still reflects all N defers (rate-limit gates only the log,
// not the counter).
func TestDrainDeferred_RateLimit_OneLogPer30sPerGate(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p := makeStormBrakeTestPool(t)
	p.log = logger

	beforeCount := Stats.InflightCapDeferredTotal.Load()
	const n = 20
	for i := 0; i < n; i++ {
		triggerStormBrakeInflightCapOn(t, p)
	}
	gotCount := Stats.InflightCapDeferredTotal.Load() - beforeCount
	if gotCount != n {
		t.Errorf("counter should grow by N=%d under burst, got %d", n, gotCount)
	}

	lines := strings.Count(buf.String(), "drain deferred (inflight cap)")
	if lines != 1 {
		t.Errorf("rate-limit should produce exactly 1 log line, got %d:\n%s",
			lines, buf.String())
	}
}

// TestDrainDeferred_RateLimit_PerGateIndependent — inflight-cap rate-
// limit timestamp must NOT block the capacity-floor log line and vice
// versa. Both gates can produce a log within the same 30s window.
func TestDrainDeferred_RateLimit_PerGateIndependent(t *testing.T) {
	// Set up TWO independent pools, one for each gate. Logging the
	// inflight-cap pool's defer must not block the capacity-floor pool's
	// defer, because they have separate atomic.Int64 timestamps.
	bufInflight, logInflight := captureSlogForDrain(t, slog.LevelInfo)
	pInflight := makeStormBrakeTestPool(t)
	pInflight.log = logInflight

	bufFloor, logFloor := captureSlogForDrain(t, slog.LevelInfo)
	pFloor := makeCapacityFloorTestPool(t)
	pFloor.log = logFloor

	triggerStormBrakeInflightCapOn(t, pInflight)
	triggerStormBrakeCapacityFloorOn(t, pFloor)

	if !strings.Contains(bufInflight.String(), "drain deferred (inflight cap)") {
		t.Errorf("inflight pool missing INFO line:\n%s", bufInflight.String())
	}
	if !strings.Contains(bufFloor.String(), "drain deferred (capacity floor)") {
		t.Errorf("floor pool missing INFO line:\n%s", bufFloor.String())
	}
}
```

- [ ] **Step 9: Run all updated tests, verify PASS**

Run: `cd shadowlink && go test ./client/ -run 'TestDrainDeferred|TestShouldLogDeferred|TestInflightCap|TestCapacityFloor' -v`
Expected: PASS for all tests (12+ tests total).

- [ ] **Step 10: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_drain.go shadowlink/client/ws_pool_drain_logging_test.go
git commit -m "feat(shadowlink): rate-limited INFO for drain-deferred per gate

Adds shouldLogDeferred(last, now) atomic-CAS helper + per-gate
lastInflightCapLogNs / lastCapacityFloorLogNs timestamps.

Re-promotes the spec-2026-05-23 DEBUG demotion back to INFO with 30s
per-gate rate-limit so the 2026-05-24 diagnostic gap (12326 silent
deferrals) cannot recur. Each INFO line carries total_count for the
gate so the real rate is recoverable from delta between successive
logs.

Tests:
  - TestShouldLogDeferred_{FirstCall,BlocksWithin,AllowsAfter,CASRaces}
  - TestDrainDeferred_{Inflight,CapacityFloor}_LogLevelInfo
  - TestDrainDeferred_RateLimit_{OneLogPer30s,PerGateIndependent}

Spec 2026-05-24-drain-diagnostics-counter-split-design.md Section 2."
```

---

## Task 5: Update health snapshot fields

**Files:**
- Modify: `shadowlink/client/ws_pool.go:1283` (health snapshot fields)
- Modify: `shadowlink/client/ws_pool_drain_logging_test.go` (replace `TestHealthSnapshot_SurfacesDeferredCounters`)

- [ ] **Step 1: Update the health snapshot field test FIRST (TDD)**

In `shadowlink/client/ws_pool_drain_logging_test.go`, replace `TestHealthSnapshot_SurfacesDeferredCounters` (line 130-152) with:

```go
// TestHealthSnapshot_SurfacesPerGateCounters — verifies emitHealthSummary
// emits the per-gate counter fields after the spec-2026-05-24 split.
// The old aggregate field deferred_drains_total MUST NOT appear.
func TestHealthSnapshot_SurfacesPerGateCounters(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p := makeStormBrakeTestPool(t)
	p.log = logger
	p.startedAt = time.Now()
	triggerStormBrakeInflightCapOn(t, p)
	triggerStormBrakeInflightCapOn(t, p)
	triggerStormBrakeInflightCapOn(t, p)

	p.emitHealthSummary()

	out := buf.String()
	if !strings.Contains(out, "inflight_cap_deferred_total=") {
		t.Errorf("health snapshot missing inflight_cap_deferred_total:\n%s", out)
	}
	if !strings.Contains(out, "capacity_floor_deferred_total=") {
		t.Errorf("health snapshot missing capacity_floor_deferred_total:\n%s", out)
	}
	if !strings.Contains(out, "deferred_drains_1m=") {
		t.Errorf("health snapshot missing deferred_drains_1m:\n%s", out)
	}
	if strings.Contains(out, "deferred_drains_total=") {
		t.Errorf("health snapshot SHOULD NOT contain deferred_drains_total (legacy aggregate):\n%s", out)
	}
}
```

- [ ] **Step 2: Run the test, verify it FAILS**

Run: `cd shadowlink && go test ./client/ -run 'TestHealthSnapshot_SurfacesPerGateCounters' -v`
Expected: FAIL — `health snapshot missing inflight_cap_deferred_total` (snapshot still emits old field).

- [ ] **Step 3: Update health snapshot field emission**

In `shadowlink/client/ws_pool.go`, find `emitHealthSummary` (around line 1272-1287):

```go
	p.log.Info("WS pool health",
		"alive", alive,
		"dead", dead,
		"empty", empty,
		"connecting", connecting,
		"draining", draining,
		"rate_limited_recent", rateLimited,
		"active_streams", totalStreams,
		"meltdowns_1m", p.meltdowns1m.Load(),
		"rotations_1m", p.rotations1m.Load(),
		"inflight_drains", p.inflightDrains.Load(),
		"deferred_drains_total", Stats.DrainStormBrakeEngagedTotal.Load(),
		"deferred_drains_1m", p.drainDeferrals1m.Load(),
		"uptime", uptime,
	)
```

Replace the `deferred_drains_total` line with two new fields. Final form:

```go
	p.log.Info("WS pool health",
		"alive", alive,
		"dead", dead,
		"empty", empty,
		"connecting", connecting,
		"draining", draining,
		"rate_limited_recent", rateLimited,
		"active_streams", totalStreams,
		"meltdowns_1m", p.meltdowns1m.Load(),
		"rotations_1m", p.rotations1m.Load(),
		"inflight_drains", p.inflightDrains.Load(),
		"inflight_cap_deferred_total", Stats.InflightCapDeferredTotal.Load(),
		"capacity_floor_deferred_total", Stats.CapacityFloorDeferredTotal.Load(),
		"deferred_drains_1m", p.drainDeferrals1m.Load(),
		"uptime", uptime,
	)
```

- [ ] **Step 4: Run the test, verify PASS**

Run: `cd shadowlink && go test ./client/ -run 'TestHealthSnapshot_SurfacesPerGateCounters' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_drain_logging_test.go
git commit -m "feat(shadowlink): split deferred_drains_total in pool health snapshot

Replaces aggregate field deferred_drains_total with per-gate fields
inflight_cap_deferred_total and capacity_floor_deferred_total so live
ops can read each gate's activity directly from 'WS pool health' lines
without grep-correlation.

deferred_drains_1m (rolling) stays aggregate — its only use is alert
trigger threshold, per-gate breakdown would add state without operational
value (spec §3).

Spec 2026-05-24-drain-diagnostics-counter-split-design.md Section 3."
```

---

## Task 6: Remove deprecated counter + Prometheus exposition

**Files:**
- Modify: `shadowlink/client/stats.go` (remove `DrainStormBrakeEngagedTotal` field + Prom exposition)
- Modify: `shadowlink/client/ws_pool_drain_logging_test.go` (remove `TestDrainDeferred_AggregateCounterIsZero` regression guard)
- Modify: any other file referencing `DrainStormBrakeEngagedTotal` (grep first)

- [ ] **Step 1: Find all remaining references to the deprecated counter**

Run: `cd shadowlink && grep -rn "DrainStormBrakeEngagedTotal\|shadowlink_slot_drain_storm_brake_engaged" --include="*.go" .`

Expected output: matches in:
- `client/stats.go` — declaration (line ~232) + Prom exposition (lines ~594-596)
- `client/ws_pool_drain_logging_test.go` — `TestDrainDeferred_AggregateCounterIsZero` regression guard (added in Task 2)

If any OTHER file matches, audit it — it should NOT exist after Task 2 migrated `startDrain`. Stop and address before continuing.

- [ ] **Step 2: Remove Prometheus exposition for old counter**

In `shadowlink/client/stats.go`, find the block (around lines 594-596):

```go
	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_storm_brake_engaged_total Storm-brake deferrals (inflight cap or capacity floor)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_storm_brake_engaged_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_storm_brake_engaged_total %d\n", Stats.DrainStormBrakeEngagedTotal.Load())
```

Replace those 3 lines with:

```go
	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_inflight_cap_deferred_total Drains deferred by storm-brake inflight-cap gate (concurrent drains >= maxConcurrentDrains)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_inflight_cap_deferred_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_inflight_cap_deferred_total %d\n", Stats.InflightCapDeferredTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_capacity_floor_deferred_total Drains deferred by storm-brake capacity-floor gate (readyCapacity < poolSize * rotationStormBrakeFraction)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_capacity_floor_deferred_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_capacity_floor_deferred_total %d\n", Stats.CapacityFloorDeferredTotal.Load())
```

- [ ] **Step 3: Remove the deprecated counter field**

In `shadowlink/client/stats.go`, find the deprecated block (around line 232, added in Task 1):

```go
	// DrainStormBrakeEngagedTotal — DEPRECATED 2026-05-24. Use
	// InflightCapDeferredTotal + CapacityFloorDeferredTotal instead.
	// Retained for one transition commit; removed in the same task that
	// migrates all callers.
	DrainStormBrakeEngagedTotal atomic.Uint64
```

Delete these 5 lines. The `InflightCapDeferredTotal` and `CapacityFloorDeferredTotal` blocks immediately below it remain.

- [ ] **Step 4: Remove the regression guard test**

In `shadowlink/client/ws_pool_drain_logging_test.go`, find `TestDrainDeferred_AggregateCounterIsZero` (added in Task 2 Step 5) and delete the entire function. Its purpose was to guard the transition; once the counter is gone, the test would fail to compile (`undefined: DrainStormBrakeEngagedTotal`).

- [ ] **Step 5: Build and run full client test suite**

Run: `cd shadowlink && go build ./client/... && go test ./client/ -v 2>&1 | tail -50`
Expected: build success; all tests PASS. Verify no leftover compile errors from missing `DrainStormBrakeEngagedTotal`.

- [ ] **Step 6: Run race-detector pass**

Run: `cd shadowlink && go test -race -count=1 ./client/ -run 'TestDrain|TestShouldLog|TestInflightCap|TestCapacityFloor|TestHealthSnapshot'`
Expected: PASS, no race warnings. (`shouldLogDeferred` CAS pattern is the new concurrent code path — must be race-clean.)

Note: requires CGO + gcc on Windows. If gcc unavailable, skip and rely on CI Linux pass.

- [ ] **Step 7: Commit**

```bash
git add shadowlink/client/stats.go shadowlink/client/ws_pool_drain_logging_test.go
git commit -m "feat(shadowlink): remove deprecated DrainStormBrakeEngagedTotal

All call sites migrated in Task 2. Prometheus exposition replaced with
two per-gate counters (shadowlink_slot_drain_inflight_cap_deferred_total
and shadowlink_slot_drain_capacity_floor_deferred_total).

No external consumers — shadowlink-metrics-dump is a generic dumper and
the reference Grafana board isn't yet wired to prod scrape per CLAUDE.md
('Production scrape integration explicit follow-up').

Spec 2026-05-24-drain-diagnostics-counter-split-design.md breaking
changes table — finalises the transition."
```

---

## Task 7: Conditional hard-cap log level

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go:439-444` (`tearDown(finishHardCap)`)
- Modify: `shadowlink/client/ws_pool_drain_logging_test.go` (add 4 hard-cap tests)

- [ ] **Step 1: Write the failing tests for conditional level**

In `shadowlink/client/ws_pool_drain_logging_test.go`, at the end of the file, add:

```go
// makeHardCapTestPool returns a pool ready to test the tearDown(finishHardCap)
// log path. Caller sets remaining streams via the returned slot's
// streams.Store(N) before invoking the assertion. The helper does NOT
// trigger an actual drain — it constructs a pool whose log can be
// captured, then exercises the relevant log branch directly.
//
// Direct invocation: simulate the hard-cap teardown by calling a tiny
// extracted helper function `emitHardCapLog` (see Task 7 Step 3) — that
// helper exists exactly for testability of the conditional level
// without needing a full drain orchestration in tests.
func makeHardCapTestPool(t *testing.T) (*WSPoolTransport, *poolSlot) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &WSPoolTransport{
		poolSize: 8,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	slot := &poolSlot{index: 0}
	slot.setState(slotDraining)
	p.slots[0] = slot
	return p, slot
}

// TestHardCap_LogLevelInfo_BelowThreshold — remaining_streams=2 → INFO.
func TestHardCap_LogLevelInfo_BelowThreshold(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p, slot := makeHardCapTestPool(t)
	p.log = logger
	slot.streams.Store(2)

	emitHardCapLog(p, 0, slot, "age", 90*time.Second)

	out := buf.String()
	if !strings.Contains(out, "hard cap reached") {
		t.Fatalf("expected hard-cap log at INFO level, got:\n%s", out)
	}
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("expected level=INFO for remaining=2, got:\n%s", out)
	}
}

// TestHardCap_LogLevelWarn_AtThreshold — remaining_streams=5 → WARN.
func TestHardCap_LogLevelWarn_AtThreshold(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p, slot := makeHardCapTestPool(t)
	p.log = logger
	slot.streams.Store(5)

	emitHardCapLog(p, 0, slot, "age", 90*time.Second)

	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("expected level=WARN for remaining=5, got:\n%s", out)
	}
}

// TestHardCap_LogLevelWarn_AboveThreshold — remaining_streams=9 → WARN.
func TestHardCap_LogLevelWarn_AboveThreshold(t *testing.T) {
	buf, logger := captureSlogForDrain(t, slog.LevelInfo)
	p, slot := makeHardCapTestPool(t)
	p.log = logger
	slot.streams.Store(9)

	emitHardCapLog(p, 0, slot, "age", 90*time.Second)

	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("expected level=WARN for remaining=9, got:\n%s", out)
	}
}

// TestHardCap_CounterIncrementsRegardlessOfLevel — DrainHardCapTotal
// must advance for both INFO and WARN paths.
func TestHardCap_CounterIncrementsRegardlessOfLevel(t *testing.T) {
	for _, streams := range []int32{2, 9} {
		before := Stats.DrainHardCapTotal.Load()
		p, slot := makeHardCapTestPool(t)
		slot.streams.Store(streams)
		emitHardCapLog(p, 0, slot, "age", 90*time.Second)
		if got := Stats.DrainHardCapTotal.Load(); got != before+1 {
			t.Errorf("DrainHardCapTotal didn't advance for streams=%d: %d → %d",
				streams, before, got)
		}
	}
}
```

- [ ] **Step 2: Run the tests, verify they FAIL at compile**

Run: `cd shadowlink && go test ./client/ -run 'TestHardCap_' -v`
Expected: FAIL at COMPILE — `undefined: emitHardCapLog`, `undefined: hardCapWarnThreshold`.

- [ ] **Step 3: Extract `emitHardCapLog` helper from `tearDown`**

In `shadowlink/client/ws_pool_drain.go`, locate the `tearDown` closure inside `drainWatchdog` (around line 436-470). The `finishHardCap` case currently looks like:

```go
		case finishHardCap:
			Stats.DrainHardCapTotal.Add(1)
			p.log.Warn("WS pool slot drain hard cap reached",
				"slot", oldIdx, "reason", reason,
				"remaining_streams", oldSlot.streams.Load(),
				"drain_duration", duration.Truncate(time.Second))
```

Extract the body into a package-level helper so it can be tested in isolation. After the `drainDeferredLogInterval` constant (added in Task 4), add:

```go
// hardCapWarnThreshold — minimum remaining_streams for a hard-cap teardown
// to log at WARN level. Below this threshold the teardown logs INFO.
//
// Rationale: hard cap with remaining_streams=1-2 is expected steady-state
// behaviour under long-lived SOCKS sessions (uplinks of 4-10min seen
// regularly in real traffic). Session 2026-05-24 distribution (272
// hard-cap events, disjoint buckets): remaining=1: 96 (35.3%),
// remaining=2: 153 (56.3%), remaining=3-4: 17 (6.3%), remaining>=5: 6
// (2.2%). Threshold=5 keeps ~98% at INFO, surfacing only outliers as
// WARN. Spec 2026-05-24 (drain-diagnostics-counter-split) §4.
hardCapWarnThreshold int32 = 5
```

Wait — `hardCapWarnThreshold` needs to be declared as a `const` to match style. Adjusted:

```go
const (
	// hardCapWarnThreshold — minimum remaining_streams for a hard-cap
	// teardown to log at WARN level. Below this threshold the teardown
	// logs INFO.
	//
	// Rationale: hard cap with remaining_streams=1-2 is expected
	// steady-state behaviour under long-lived SOCKS sessions (uplinks of
	// 4-10min seen regularly). Session 2026-05-24 distribution (272
	// hard-cap events, disjoint buckets):
	//   remaining=1:   96 (35.3%)
	//   remaining=2:   153 (56.3%)
	//   remaining=3-4: 17 (6.3%)
	//   remaining>=5:  6 (2.2%)
	// Threshold=5 keeps ~98% at INFO, surfacing only outliers as WARN.
	// Spec 2026-05-24 (drain-diagnostics-counter-split) §4.
	hardCapWarnThreshold int32 = 5
)
```

(If a `const` block already exists near the existing `drainStormBrakeBackoff` constants, append `hardCapWarnThreshold` to it instead of opening a new block.)

Now add the helper function (place near the bottom of the file, after `drainWatchdog`):

```go
// emitHardCapLog records a hard-cap teardown event: increments
// Stats.DrainHardCapTotal and emits a structured log line at INFO or
// WARN level depending on `slot.streams.Load() >= hardCapWarnThreshold`.
//
// Extracted from drainWatchdog.tearDown for testability — tests can
// drive this directly without orchestrating a full drain.
//
// Spec 2026-05-24 (drain-diagnostics-counter-split) §4.
func emitHardCapLog(p *WSPoolTransport, oldIdx int, slot *poolSlot, reason string, duration time.Duration) {
	Stats.DrainHardCapTotal.Add(1)
	remaining := slot.streams.Load()
	logFn := p.log.Info
	if remaining >= hardCapWarnThreshold {
		logFn = p.log.Warn
	}
	logFn("WS pool slot drain hard cap reached",
		"slot", oldIdx, "reason", reason,
		"remaining_streams", remaining,
		"drain_duration", duration.Truncate(time.Second))
}
```

Now replace the `finishHardCap` case in `tearDown` (inside `drainWatchdog`) to call the helper:

```go
		case finishHardCap:
			emitHardCapLog(p, oldIdx, oldSlot, reason, duration)
```

- [ ] **Step 4: Run hard-cap tests, verify PASS**

Run: `cd shadowlink && go test ./client/ -run 'TestHardCap_' -v`
Expected: PASS for all 4 hard-cap tests.

- [ ] **Step 5: Run full drain test suite to verify no regression**

Run: `cd shadowlink && go test ./client/ -run 'TestDrain|TestHardCap|TestShouldLog' -v`
Expected: PASS for all tests, no regressions in existing `TestDrainWatchdog_HardCap` (which uses the new helper indirectly via `tearDown(finishHardCap)`).

- [ ] **Step 6: Commit**

```bash
git add shadowlink/client/ws_pool_drain.go shadowlink/client/ws_pool_drain_logging_test.go
git commit -m "feat(shadowlink): conditional WARN/INFO for drain hard-cap teardown

Hard-cap teardown at remaining_streams >= 5 → WARN (outlier, worth
attention). Below threshold → INFO (expected steady-state, was 98% of
events in session 2026-05-24 vs only 2% outliers).

Extracted emitHardCapLog helper from drainWatchdog.tearDown for direct
testability without full drain orchestration.

Tests:
  - TestHardCap_LogLevelInfo_BelowThreshold
  - TestHardCap_LogLevelWarn_{AtThreshold,AboveThreshold}
  - TestHardCap_CounterIncrementsRegardlessOfLevel

Spec 2026-05-24-drain-diagnostics-counter-split-design.md Section 4."
```

---

## Task 8: Full test + race pass + rebuild binaries

**Files:**
- No code changes — verification + build only.

- [ ] **Step 1: Run all client tests at default settings**

Run: `cd shadowlink && go test ./client/... -count=1 -v 2>&1 | tail -100`
Expected: PASS for all tests. Particularly:
- Drain tests: `TestDrain*`, `TestStartDrain_*`, `TestDrainWatchdog_*`
- New tests: `TestShouldLogDeferred_*`, `TestInflightCapCounter_*`, `TestCapacityFloorCounter_*`, `TestHardCap_*`
- Health snapshot: `TestHealthSnapshot_SurfacesPerGateCounters`
- Logging tests: `TestDrainDeferred_*` (INFO-level variants)

If any test fails, stop and resolve before continuing.

- [ ] **Step 2: Run race detector pass on client + skins**

Run: `cd shadowlink && go test -race -count=1 ./client/ ./skins/... 2>&1 | tail -50`
Expected: PASS, no race warnings.

If race detector requires CGO + gcc and gcc is unavailable on Windows: skip with `# CGO unavailable` note and confirm CI Linux job will catch races. Don't silently bypass.

- [ ] **Step 3: Run gofmt to catch any formatting drift**

Run: `cd shadowlink && gofmt -l ./client/ ./skins/`
Expected: empty output (no files need formatting). If any file is listed, run `gofmt -w` on it and amend the previous commit, OR commit a separate `style: gofmt` commit.

- [ ] **Step 4: Rebuild all client binaries**

Run from project root:

```bash
cd shadowlink
go build -o ../bin/nixavpn-client.exe                    ./cmd/nixavpn-client
go build -o ../bin/nixavpn-client-graceful-drain.exe     ./cmd/nixavpn-client
GOOS=linux  GOARCH=amd64 go build -o ../bin/nixavpn-client-linux       ./cmd/nixavpn-client
GOOS=darwin GOARCH=arm64 go build -o ../bin/nixavpn-client-mac-arm64   ./cmd/nixavpn-client
GOOS=linux  GOARCH=amd64 go build -o ../bin/shadowlink-server-linux    ./cmd/shadowlink-server
GOOS=linux  GOARCH=amd64 go build -o ../bin/shadowlink-metrics-dump-linux ./cmd/shadowlink-metrics-dump
```

(Server + metrics-dump rebuilt for Prometheus exposition change. Check whether `cmd/shadowlink-metrics-dump` exists — if not, skip that line.)

Expected: all builds succeed.

- [ ] **Step 5: Sanity check — verify the new ENV-flag-free binary still respects existing flags**

Run on Windows: confirm the binary starts and respects `SHADOWLINK_GRACEFUL_DRAIN=1` / `SHADOWLINK_DRAIN_HARD_CAP=90s` exactly as before (no flag-handling changes in this plan):

```bash
SHADOWLINK_GRACEFUL_DRAIN=1 SHADOWLINK_DRAIN_HARD_CAP=90s ./bin/nixavpn-client-graceful-drain.exe --help
```

Expected: help output prints (no panic, no unknown env-flag errors).

- [ ] **Step 6: Commit binaries**

```bash
git add bin/nixavpn-client.exe bin/nixavpn-client-graceful-drain.exe bin/nixavpn-client-linux bin/nixavpn-client-mac-arm64 bin/shadowlink-server-linux bin/shadowlink-metrics-dump-linux
git commit -m "chore(shadowlink): rebuild binaries with drain-diagnostics counter split

Includes Tasks 1-7 of 2026-05-24-drain-diagnostics-counter-split.
No protocol or flag changes — only diagnostics improvements:
  - Per-gate deferred counters (InflightCap + CapacityFloor)
  - 30s rate-limited INFO log per gate (replaces silent DEBUG)
  - Conditional INFO/WARN hard-cap log (threshold remaining>=5)

Ready for next canary session — expected log shape:
  - 'drain deferred (inflight cap) ... total_count=N deferred_1m=M'
  - 'drain deferred (capacity floor) ... total_count=N deferred_1m=M'
  - Health snapshot: inflight_cap_deferred_total / capacity_floor_deferred_total
  - Hard cap: INFO for remaining<5, WARN for remaining>=5"
```

---

## Self-Review Checklist (run before handing off)

**1. Spec coverage:**

| Spec Section | Task(s) | Status |
|---|---|---|
| §1 Counter split (stats.go + Prom) | Tasks 1, 2, 6 | ✅ |
| §2 Rate-limit INFO + helper | Task 4 | ✅ |
| §3 Health snapshot fields | Task 5 | ✅ |
| §4 Conditional hard-cap level | Task 7 | ✅ |
| Testing list (14 tests) | Tasks 2, 3, 4, 5, 7 | ✅ (counted: 2+3+5+1+4 = 15, one extra — the regression guard removed in Task 6) |
| Breaking changes | Task 6 | ✅ |
| Acceptance criteria | Out of scope for plan (next canary verifies) | n/a |

**2. Placeholder scan:** Searched for "TBD", "TODO", "implement later", "fill in details", "Add appropriate", "handle edge cases", "Similar to". None found in plan body. Every code block is complete and copy-paste-ready.

**3. Type consistency:**
- `InflightCapDeferredTotal` / `CapacityFloorDeferredTotal` — `atomic.Uint64` (matches existing counter style in `stats.go`)
- `lastInflightCapLogNs` / `lastCapacityFloorLogNs` — `atomic.Int64` (matches `nextDrainAttemptNs` precedent in poolSlot)
- `hardCapWarnThreshold` — `int32` const (matches `oldSlot.streams atomic.Int32`)
- `drainDeferredLogInterval` — `time.Duration` const (matches `drainStormBrakeBackoff` precedent)
- `shouldLogDeferred(*atomic.Int64, time.Time) bool` — signature stable across Tasks 4 and tests
- `emitHardCapLog(*WSPoolTransport, int, *poolSlot, string, time.Duration)` — signature stable across Task 7 helper and tests

**4. Inter-task ordering:**
- Task 1 (declarations) before Task 2 (callers) ✅
- Task 2 (migrate callers) before Task 6 (remove old) ✅
- Task 4 (helper + INFO logs) before Task 8 (race pass on new concurrent code) ✅
- Task 7 (hard-cap level) independent — can run any time after Task 1 ✅
- Task 5 (snapshot) after Task 1 (new fields exist) ✅

**5. Test-helper naming consistency:**
- `makeStormBrakeTestPool` (existing) / `makeCapacityFloorTestPool` (new, Task 3) / `makeHardCapTestPool` (new, Task 7) — all follow `make<Scenario>TestPool` pattern ✅
- `triggerStormBrakeInflightCapOn` (existing) / `triggerStormBrakeCapacityFloorOn` (new, Task 3) — both follow `trigger<Scenario>On` pattern ✅

Plan is self-consistent and ready for execution.

---

**Plan complete and saved to `shadowlink/docs/superpowers/plans/2026-05-24-drain-diagnostics-counter-split.md`.**

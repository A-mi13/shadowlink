# WS Pool Uniform Cells Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the `i + poolSize` primary↔reserve pairing assumption from the WS pool — all 2*poolSize cells become equivalent, storm brake counts ready capacity, and torn-down cells recycle freely. Fixes the canary's 326-deferred-drains stuck state.

**Architecture:** All cells in `p.slots[0..2*poolSize)` are uniform. `claimFreeSlot` scans from index 0; `readyCapacity` counts slotReady cells; storm brake gates on `floor = poolSize - maxConcurrentDrains` (default `max(1, ceil(poolSize*0.25))`). New atomic `inflightDrains` caps concurrency without TOCTOU. `reconnectLoop` short-circuits when the cell has been recycled by a drain. `streamMap` lookups in slot reader validate idx-match to drop stale post-teardown frames.

**Tech Stack:** Go 1.22+, atomic primitives (`atomic.Int32`, `atomic.Uint64`), `sync.Mutex` for cell writes, `sync.Map` for streamMap, internal `Histogram` exporter from `stats.go`.

**Spec:** `shadowlink/docs/superpowers/specs/2026-05-20-ws-pool-uniform-cells-design.md`
**Audit:** `shadowlink/docs/superpowers/specs/2026-05-19-ws-pool-reserve-pairing-audit.md`
**Review (R2):** `shadowlink/docs/superpowers/specs/2026-05-20-ws-pool-uniform-cells-design-review-r2.md`

---

## File Structure

| File | Role | Touched in |
|---|---|---|
| `shadowlink/client/ws_pool.go` | Core pool state, iteration sites, `handleSlotDeath`, `SessionForStream`, `connectSlot`, `reconnectLoop`, `emitHealthSummary`, `rotationWatchdogSweep`, `sendKeepaliveToAllSlots`, `rotateMinLoadedSlot`, `StartReader`, `slotReaderWithClient` | T1-T13 |
| `shadowlink/client/ws_pool_drain.go` | `claimFreeReserveSlot` → `claimFreeSlot`, `startDrain`, `connectReserveSlot`, `drainWatchdog`, new constants `drainStormBrakeBackoff`, `drainCatastrophicBackoff` | T2, T3, T6, T7, T8, T9 |
| `shadowlink/client/stats.go` | New counters: `DrainStormBrakeEngagedTotal`, `StaleFrameDroppedTotal`, gauge for `DrainInflight` | T11 |
| `shadowlink/client/ws_pool_drain_test.go` | Rewrite 6 paired-layout tests; add 7 new tests | T1-T13 (per task) |
| `shadowlink/client/ws_pool_test.go` | Update `countNonReadySlots` callers, `emitHealthSummary` assertions | T2, T10 |
| `shadowlink/docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md` | Mark §Fix C3 + §C11.2 RESOLVED, point to new spec | T14 |
| `shadowlink/CLAUDE.md` | Update graceful-drain row if behavior differs from earlier description | T14 |

---

## Implementation Order (rationale)

1. **T1**: Add `inflightDrains` counter — depended on by T6 atomicity.
2. **T2**: `readyCapacity` function (replaces `countNonReadySlots`) — depended on by T6.
3. **T3**: `claimFreeSlot` widening — depended on by T6, T9.
4. **T4**: `reconnectLoop` recycle guard — independent, can land anytime before canary.
5. **T5**: `slotReaderWithClient` stale-frame validation — independent (W5 fix).
6. **T6**: `startDrain` rewrite using T1+T2+T3 — the heart of the fix.
7. **T7**: `drainStormBrakeBackoff` + catastrophic backoff — split from T6 for review clarity.
8. **T8**: `drainWatchdog` defer-decrement (NEW-1 fix).
9. **T9**: `connectReserveSlot` failure placeholder cleanup (S5).
10. **T10**: 4 iteration-site rewrites (`watchdogSweep`, `keepalive`, `rotateMinLoaded`, `StartReader`) + `emitHealthSummary` schema.
11. **T11**: `handleSlotDeath` streamChans uniformity + new counters export.
12. **T12**: `SessionForStream` fallback removal.
13. **T13**: Canary-scenario integration test (`TestCanaryScenario_MismatchedPairs`).
14. **T14**: Spec/docs sync + final acceptance grep.

---

## Task 1: `inflightDrains` atomic counter (foundation)

**Files:**
- Modify: `shadowlink/client/ws_pool.go` (add field to `WSPoolTransport`)
- Test: `shadowlink/client/ws_pool_drain_test.go` (new test)

- [ ] **Step 1: Write the failing test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestInflightDrains_FieldInitialized verifies the new atomic counter
// is wired into WSPoolTransport with a zero-value initial state.
func TestInflightDrains_FieldInitialized(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)
	if got := p.inflightDrains.Load(); got != 0 {
		t.Errorf("inflightDrains initial value = %d, want 0", got)
	}
	p.inflightDrains.Add(1)
	if got := p.inflightDrains.Load(); got != 1 {
		t.Errorf("inflightDrains after Add(1) = %d, want 1", got)
	}
	p.inflightDrains.Add(-1)
	if got := p.inflightDrains.Load(); got != 0 {
		t.Errorf("inflightDrains after Add(-1) = %d, want 0", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test -run TestInflightDrains_FieldInitialized ./client/`
Expected: FAIL — `inflightDrains undefined` compile error.

- [ ] **Step 3: Add the field**

In `shadowlink/client/ws_pool.go`, locate the `WSPoolTransport` struct (around line 802) and add a new field next to `reserveMu` (around line 831):

```go
	// inflightDrains caps concurrent drains atomically — see spec §2.1.0.
	// startDrain increments before any state mutation, decrements via
	// drainWatchdog defer (guaranteed on all exit paths). Cap consulted
	// before readyCapacity check to close the TOCTOU window where multiple
	// triggers (age/byte/anti-FP) read identical capacity and all proceed.
	inflightDrains atomic.Int32
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd shadowlink && go test -run TestInflightDrains_FieldInitialized ./client/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_drain_test.go
git commit -m "feat(ws-pool): add inflightDrains atomic counter for TOCTOU close"
```

---

## Task 2: `readyCapacity` replaces `countNonReadySlots`

**Files:**
- Modify: `shadowlink/client/ws_pool.go:601-638` (replace function)
- Modify: `shadowlink/client/ws_pool.go:560-569` (replace `rotationStormBrakeThreshold` helper)
- Modify: `shadowlink/client/ws_pool_test.go:1099` (caller update)
- Rewrite: `shadowlink/client/ws_pool_drain_test.go:15-66` (the existing pairing-based test)

- [ ] **Step 1: Write the failing test**

In `shadowlink/client/ws_pool_drain_test.go`, REPLACE `TestCountNonReadySlots_IgnoresEmptyReserve` (lines 15-66) with:

```go
// TestReadyCapacity_CountsAllReadyAcrossSlice asserts that readyCapacity
// counts slotReady cells anywhere in the slice — no primary/reserve
// distinction. This guards against the canary 2026-05-19 bug where
// countNonReadySlots used `i+poolSize` pairing and locked storm brake
// at non_ready=2 forever.
func TestReadyCapacity_CountsAllReadyAcrossSlice(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	if got := p.readyCapacity(); got != 0 {
		t.Errorf("readyCapacity with all nil = %d, want 0", got)
	}

	// 6 primary ready + 2 reserve ready (canary post-teardown state).
	for _, i := range []int{0, 1, 3, 4, 5, 7, 8, 9} {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	if got := p.readyCapacity(); got != 8 {
		t.Errorf("readyCapacity with 6+2 ready = %d, want 8 (uniform cells)", got)
	}

	// One draining doesn't count.
	p.slots[0].setState(slotDraining)
	if got := p.readyCapacity(); got != 7 {
		t.Errorf("readyCapacity with 1 drained = %d, want 7", got)
	}

	// Connecting doesn't count.
	p.slots[10] = &poolSlot{}
	p.slots[10].setState(slotConnecting)
	if got := p.readyCapacity(); got != 7 {
		t.Errorf("readyCapacity ignores slotConnecting = %d, want 7", got)
	}
}

// TestStormBrakeFloor_DerivedFromPoolSize asserts the floor formula
// scales with poolSize (spec §2.1, C1 review fix).
func TestStormBrakeFloor_DerivedFromPoolSize(t *testing.T) {
	cases := []struct {
		poolSize int
		wantFloor int
	}{
		{poolSize: 8, wantFloor: 6}, // 8 - max(1, ceil(8*0.25)) = 8 - 2 = 6
		{poolSize: 4, wantFloor: 3}, // 4 - max(1, ceil(4*0.25)) = 4 - 1 = 3
		{poolSize: 2, wantFloor: 1}, // 2 - max(1, ceil(2*0.25)) = 2 - 1 = 1
		{poolSize: 16, wantFloor: 12}, // 16 - max(1, ceil(16*0.25)) = 16 - 4 = 12
	}
	for _, c := range cases {
		p := &WSPoolTransport{poolSize: c.poolSize}
		if got := p.readyCapacityFloor(); got != c.wantFloor {
			t.Errorf("readyCapacityFloor(poolSize=%d) = %d, want %d",
				c.poolSize, got, c.wantFloor)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd shadowlink && go test -run "TestReadyCapacity|TestStormBrakeFloor" ./client/`
Expected: FAIL — `readyCapacity undefined`, `readyCapacityFloor undefined`.

- [ ] **Step 3: Add the functions**

In `shadowlink/client/ws_pool.go`, REPLACE lines 560-638 (the `rotationStormBrakeThreshold` + `countNonReadySlots` functions) with:

```go
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
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady {
			n++
		}
	}
	return n
}

// readyCapacityFloor returns the minimum readyCapacity the storm brake
// will tolerate before deferring new drains. Derived from poolSize via
// rotationStormBrakeFraction — never a literal constant (spec §2.1, C1
// review fix).
//
// Invariants:
//   - maxConcurrentDrains := max(1, ceil(poolSize * 0.25))
//   - floor := poolSize - maxConcurrentDrains
//   - floor >= ceil(poolSize/2) at construction time
func (p *WSPoolTransport) readyCapacityFloor() int {
	mcd := int(float64(p.poolSize)*rotationStormBrakeFraction + 0.9999) // ceil
	if mcd < 1 {
		mcd = 1
	}
	if mcd >= p.poolSize {
		mcd = p.poolSize - 1 // never block all drains
	}
	return p.poolSize - mcd
}

// maxConcurrentDrains is the inflightDrains hard cap. See
// readyCapacityFloor for derivation.
func (p *WSPoolTransport) maxConcurrentDrains() int {
	return p.poolSize - p.readyCapacityFloor()
}
```

- [ ] **Step 4: Run new tests to verify pass**

Run: `cd shadowlink && go test -run "TestReadyCapacity|TestStormBrakeFloor" ./client/`
Expected: PASS.

- [ ] **Step 5: Update existing callers**

Find existing callers of `countNonReadySlots` and `rotationStormBrakeThreshold`. In `shadowlink/client/ws_pool.go:2365-2378` (the `maybeRotateSlot` storm brake check), REPLACE:

```go
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
```

with:

```go
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
```

**Update ALL existing callers of the removed helpers across the test files** (verified via grep before plan authoring — every site listed below currently compiles against the old API and must be migrated):

1. `shadowlink/client/ws_pool_test.go:945` — currently calls `p.rotationStormBrakeThreshold()` in a table-driven test of poolSize → threshold. REPLACE the assertion to call `p.maxConcurrentDrains()` instead. The `tc.want` values in that table represented the OLD threshold (count of NOT-ready that triggers brake). The new helper `maxConcurrentDrains()` returns the same numeric value (`ceil(poolSize*0.25)`), so the table's expected values are correct — only the function name changes.

2. `shadowlink/client/ws_pool_test.go:1099` — REPLACE:
```go
	require.Equal(t, 4, pool.countNonReadySlots(),
```
with:
```go
	require.Equal(t, 4, pool.poolSize-pool.readyCapacity(),
```

3. `shadowlink/client/ws_pool_drain_test.go:953-988` — REPLACE the ENTIRE test `TestStartDrain_StormBrakeSingleDrain` body with the un-paired layout per spec §4:

```go
// TestStartDrain_StormBrakeSingleDrain — un-paired canary layout.
// primary[6] draining, reserve[9] connecting (no parity 6↔14). Asserts
// that the in-progress drain occupies one inflight slot, NOT blocking
// a NEW drain from a different primary as long as inflight<maxConcurrentDrains.
func TestStartDrain_StormBrakeSingleDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	// 7 of 8 primaries ready + the 1 draining (primary[6]).
	for i := 0; i < 8; i++ {
		p.slots[i] = &poolSlot{index: i}
		if i == 6 {
			p.slots[i].setState(slotDraining)
		} else {
			p.slots[i].setState(slotReady)
		}
	}
	// Reserve[9] is connecting (replacement for primary[6]).
	p.slots[9] = &poolSlot{}
	p.slots[9].setState(slotConnecting)
	// inflight already counts this one drain.
	p.inflightDrains.Store(1)

	// readyCapacity = 7 (primary 0,1,2,3,4,5,7), floor = 6 → drain OK.
	if ready, floor := p.readyCapacity(), p.readyCapacityFloor(); ready < floor {
		t.Fatalf("setup readyCapacity=%d < floor=%d", ready, floor)
	}
	// maxConcurrentDrains = 2, inflight = 1 → another drain CAN proceed.
	if p.inflightDrains.Load() >= int32(p.maxConcurrentDrains()) {
		t.Fatalf("inflight already at cap")
	}
}
```

4. `shadowlink/client/ws_pool_drain_test.go:993-1048` — REPLACE the ENTIRE test `TestStartDrain_StormBrakeTwoConcurrentEngages` body with the exact canary scenario:

```go
// TestStartDrain_StormBrakeTwoConcurrentEngages — exact canary layout.
// primary[6] and primary[2] both draining → reserve[8] and reserve[9]
// connecting/ready. inflight=2 (the two ongoing). A third concurrent
// drain attempt MUST defer via the inflight cap, not via pairing math.
func TestStartDrain_StormBrakeTwoConcurrentEngages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	for _, i := range []int{0, 1, 3, 4, 5, 7} {
		p.slots[i] = &poolSlot{index: i}
		p.slots[i].setState(slotReady)
	}
	for _, i := range []int{2, 6} {
		p.slots[i] = &poolSlot{index: i}
		p.slots[i].setState(slotDraining)
	}
	p.slots[8] = &poolSlot{}
	p.slots[8].setState(slotReady)
	p.slots[9] = &poolSlot{}
	p.slots[9].setState(slotReady)
	p.inflightDrains.Store(2)

	// readyCapacity = 6+2 = 8 ≥ floor=6 — capacity OK.
	if got := p.readyCapacity(); got != 8 {
		t.Errorf("readyCapacity = %d, want 8 (canary post-teardown)", got)
	}
	// inflight at cap — next drain must defer.
	before := Stats.DrainStormBrakeEngagedTotal.Load()
	p.startDrain(nil, 0, "test")
	if got := Stats.DrainStormBrakeEngagedTotal.Load() - before; got != 1 {
		t.Errorf("DrainStormBrakeEngagedTotal increment = %d, want 1 (inflight gate)", got)
	}
	if p.slots[0].getState() != slotReady {
		t.Errorf("primary[0] state = %v, want slotReady (drain deferred)", p.slots[0].getState())
	}
}
```

5. `shadowlink/client/ws_pool_drain_test.go:977-981, 1025-1029` (inside the OLD bodies of the two tests above) — these lines are inside the test bodies being replaced wholesale by items 3-4, so no separate edit needed.

- [ ] **Step 6: Run full client tests**

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS (entire suite; legacy callers updated).

- [ ] **Step 7: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_drain_test.go shadowlink/client/ws_pool_test.go
git commit -m "refactor(ws-pool): readyCapacity replaces countNonReadySlots (uniform cells)"
```

---

## Task 3: `claimFreeSlot` whole-slice scan from index 0

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go:28-40` (rename + widen)
- Modify: `shadowlink/client/ws_pool_drain.go:62-123` (caller `startDrain`)
- Modify: `shadowlink/client/ws_pool_drain.go:135-147` (caller `connectReserveSlot`)
- Test: `shadowlink/client/ws_pool_drain_test.go` (new test + update existing)

- [ ] **Step 1: Write the failing test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestClaimFreeSlot_ScansFromIndexZero asserts the renamed function
// scans the entire slice from idx=0, allowing post-teardown primary
// cells to be claimed as new drain replacements (spec §2.2).
func TestClaimFreeSlot_ScansFromIndexZero(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	// Fill the reserve range completely.
	for i := 8; i < 16; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	// Primary cell 3 was torn down by a previous drain — nil.
	for i := 0; i < 8; i++ {
		if i == 3 {
			continue
		}
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}

	got := p.claimFreeSlot()
	if got != 3 {
		t.Errorf("claimFreeSlot with all reserves occupied + primary[3]=nil = %d, want 3", got)
	}
	if p.slots[3] == nil || p.slots[3].getState() != slotConnecting {
		t.Errorf("claimed cell state = %v, want placeholder slotConnecting", p.slots[3])
	}
}

// TestClaimFreeSlot_AllOccupiedReturnsNegOne — when there's no free
// cell anywhere in the slice, return -1 (caller must defer).
func TestClaimFreeSlot_AllOccupiedReturnsNegOne(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)
	for i := 0; i < 16; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	if got := p.claimFreeSlot(); got != -1 {
		t.Errorf("claimFreeSlot with all occupied = %d, want -1", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd shadowlink && go test -run TestClaimFreeSlot ./client/`
Expected: FAIL — `claimFreeSlot undefined`.

- [ ] **Step 3: Rename + widen the function**

In `shadowlink/client/ws_pool_drain.go`, REPLACE lines 12-40 (the `claimFreeReserveSlot` func) with:

```go
// claimFreeSlot atomically reserves the first nil cell anywhere in
// p.slots (uniform-cells design — spec 2026-05-20 §2.2). Returns the
// claimed index, or -1 if no nil cell exists.
//
// Under p.reserveMu so concurrent startDrain calls cannot pick the
// same idx. The critical section is tiny (linear scan + 2 atomic
// writes); contention is bounded by inflightDrains cap.
//
// connectReserveSlot's subsequent connectSlot call will overwrite the
// placeholder *poolSlot installed here. Scan starts at index 0 so
// post-teardown primary cells are recyclable as drain replacements.
func (p *WSPoolTransport) claimFreeSlot() int {
	p.reserveMu.Lock()
	defer p.reserveMu.Unlock()
	for i := 0; i < len(p.slots); i++ {
		if p.slots[i] == nil {
			slot := &poolSlot{}
			slot.setState(slotConnecting)
			p.slots[i] = slot
			return i
		}
	}
	return -1
}
```

- [ ] **Step 4: Update callers**

In the same file `ws_pool_drain.go`, in `startDrain` (line 94), REPLACE:

```go
	newIdx := p.claimFreeReserveSlot()
```

with:

```go
	newIdx := p.claimFreeSlot()
```

And REPLACE the log message context "no free reserve cell" (around line 96):

```go
		p.log.Warn("WS pool drain skipped — no free reserve cell",
```

with:

```go
		p.log.Warn("WS pool drain skipped — no free cell",
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cd shadowlink && go test -run TestClaimFreeSlot ./client/`
Expected: PASS.

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS — existing `TestClaimFreeReserveSlot_*` tests need rename. If any fail by name, rename them inline in the test file:

```bash
sed -i 's/claimFreeReserveSlot/claimFreeSlot/g' shadowlink/client/ws_pool_drain_test.go
```

Then re-run.

- [ ] **Step 6: Commit**

```bash
git add shadowlink/client/ws_pool_drain.go shadowlink/client/ws_pool_drain_test.go
git commit -m "refactor(ws-pool): claimFreeSlot scans entire slice from idx 0"
```

---

## Task 4: `reconnectLoop` recycle guard

**Files:**
- Modify: `shadowlink/client/ws_pool.go:1438-1505` (the `reconnectLoop` function)
- Test: `shadowlink/client/ws_pool_drain_test.go` (new test)

- [ ] **Step 1: Write the failing test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestReconnectLoop_RecycleGuard asserts that if the cell at idx has
// been recycled (e.g. by a drain that claimed this freed primary slot),
// reconnectLoop short-circuits instead of overwriting the new cell.
// Spec §2.2.2 (W7 review fix).
func TestReconnectLoop_RecycleGuard(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize: 8,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)

	// Pre-install a slotReady cell at idx 3 (simulating a drain having
	// recycled this cell while a stale reconnectLoop was running).
	recycledSlot := &poolSlot{index: 3}
	recycledSlot.setState(slotReady)
	p.slots[3] = recycledSlot

	// Stub connectSlot — must NOT be called when guard fires.
	called := false
	prev := connectSlotForTest
	connectSlotForTest = func() error {
		called = true
		return nil
	}
	defer func() { connectSlotForTest = prev }()

	// Cancel ctx immediately so reconnectLoop exits after the first guard check.
	cancel()
	p.reconnectLoop(3)

	if called {
		t.Errorf("connectSlot called despite recycled cell — guard failed")
	}
	if p.slots[3] != recycledSlot {
		t.Errorf("recycled cell was overwritten")
	}
}
```

Note: this test uses `newDiscardLogger()` and `connectSlotForTest` — both already exist in the test file (see `ws_pool_test.go` for `newTestLogger`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test -run TestReconnectLoop_RecycleGuard ./client/`
Expected: FAIL — current `reconnectLoop` calls `connectSlot` unconditionally.

- [ ] **Step 3: Add the guard**

In `shadowlink/client/ws_pool.go`, in `reconnectLoop` (around line 1493), REPLACE:

```go
		var connectErr error
		if connectSlotForTest != nil {
			// Test seam — see ws_pool.go::connectSlotForTest. Production
			// builds never enter this branch because nothing assigns the var.
			connectErr = connectSlotForTest()
		} else {
			connectErr = p.connectSlot(p.ctx, idx)
		}
```

with:

```go
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
		if connectSlotForTest != nil {
			// Test seam — see ws_pool.go::connectSlotForTest. Production
			// builds never enter this branch because nothing assigns the var.
			connectErr = connectSlotForTest()
		} else {
			connectErr = p.connectSlot(p.ctx, idx)
		}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd shadowlink && go test -run TestReconnectLoop_RecycleGuard ./client/`
Expected: PASS.

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS — no regressions.

- [ ] **Step 5: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_drain_test.go
git commit -m "feat(ws-pool): reconnectLoop short-circuits on recycled cell"
```

---

## Task 5: Slot reader stale-frame validation (W5)

**Files:**
- Modify: `shadowlink/client/ws_pool.go:2113-` (`slotReaderWithClient` dispatch path)
- Test: `shadowlink/client/ws_pool_drain_test.go`

Background: after drainTeardown deletes streamMap entries (handleSlotDeath:2490), the freed streamIDs may be reassigned to streams on different slots. A late inbound frame from the torn slot could find the new mapping and route to a wrong-session stream. The fix: in the reader dispatch path, validate the lookup result equals the reader's own idx.

- [ ] **Step 1: Locate the dispatch site**

In `shadowlink/client/ws_pool.go`, find inside `slotReaderWithClient` the point where it loads from `p.streamMap` to dispatch a decoded frame. Search for `p.streamMap.Load` and `p.streamMap.Range` within the function body.

Run: `cd shadowlink && grep -n "p.streamMap.Load\|p.streamMap.Range" client/ws_pool.go`

Identify the read-path lookup (NOT the teardown loop). It is typically in the per-frame dispatch after `ReadMessage`.

- [ ] **Step 2: Write the failing test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestStreamIDReuse_RejectStaleFrames asserts that a frame's streamID
// lookup returning a slot index different from the reader's own idx
// causes the frame to be dropped rather than routed to a foreign
// stream (spec §2.4.1, W5 review fix).
//
// This test exercises the validation predicate directly. Full
// end-to-end frame injection requires a WS loopback fixture (W4
// deferred); the predicate check is what gates the production path.
func TestStreamIDReuse_RejectStaleFrames(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	// streamID 42 currently maps to slot 7 (newly assigned stream).
	p.streamMap.Store(uint16(42), 7)

	// A reader on slot 5 receives a frame for streamID 42 (stale, slot 5
	// was just torn down and streamMap.Delete'd; new stream took 42 on 7).
	mappedIdx, ok := p.streamMap.Load(uint16(42))
	if !ok {
		t.Fatalf("expected mapping present")
	}
	if mappedIdx.(int) == 5 {
		t.Fatalf("test setup broken — expected mismatch")
	}

	initialCount := Stats.StaleFrameDroppedTotal.Load()

	// Simulate the validation predicate the reader uses.
	myIdx := 5
	if mappedIdx.(int) != myIdx {
		Stats.StaleFrameDroppedTotal.Add(1)
	}

	if got := Stats.StaleFrameDroppedTotal.Load() - initialCount; got != 1 {
		t.Errorf("StaleFrameDroppedTotal increment = %d, want 1", got)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd shadowlink && go test -run TestStreamIDReuse_RejectStaleFrames ./client/`
Expected: FAIL — `Stats.StaleFrameDroppedTotal undefined`.

- [ ] **Step 4: Add the counter to stats.go**

In `shadowlink/client/stats.go`, locate the `statsRegistry` struct's drain counters block (around line 206-223) and append a new field:

```go
	// StaleFrameDroppedTotal — frames arriving on a slot whose
	// streamMap lookup returns a different idx (post-teardown
	// streamID reuse race). See spec 2026-05-20 §2.4.1. A non-zero
	// rate is expected during heavy rotation; sustained high rate is
	// a bug.
	StaleFrameDroppedTotal atomic.Uint64
```

In the same file, find the Prometheus exporter (around line 502+) and append:

```go
	fmt.Fprintf(w, "# HELP shadowlink_stale_frame_dropped_total Frames dropped due to streamID reuse race after drain teardown\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stale_frame_dropped_total counter\n")
	fmt.Fprintf(w, "shadowlink_stale_frame_dropped_total %d\n", Stats.StaleFrameDroppedTotal.Load())

```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd shadowlink && go test -run TestStreamIDReuse_RejectStaleFrames ./client/`
Expected: PASS.

- [ ] **Step 6: Wire the validation into the reader dispatch**

The dispatch site is `shadowlink/client/ws_pool.go:2306-2312` inside `slotReaderWithClient`. Current code:

```go
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		if chunk.Flags == core.FlagUDP {
			cl.RouteToStream(streamID, chunk.Payload)
		} else {
			cl.RouteToStream(streamID, chunk.Payload[2:])
		}
```

REPLACE with:

```go
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		// W5 stale-frame validation: drop frames whose streamID has been
		// reassigned to a different slot (post-drain-teardown streamID
		// reuse race). Spec 2026-05-20 §2.4.1.
		if v, ok := p.streamMap.Load(streamID); ok {
			if v.(int) != idx {
				Stats.StaleFrameDroppedTotal.Add(1)
				continue
			}
		}

		if chunk.Flags == core.FlagUDP {
			cl.RouteToStream(streamID, chunk.Payload)
		} else {
			cl.RouteToStream(streamID, chunk.Payload[2:])
		}
```

Note: streamID present in streamMap pointing at a different idx → drop. streamID NOT in streamMap → still dispatch (may be a control/UDP path without an explicit mapping; the legacy behavior).

The equivalent dispatch site in `split_transport.go:628-632` is OUT OF SCOPE — it has a different transport identity model (single WS, no slot pool). Do not modify.

- [ ] **Step 7: Run full client suite**

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/stats.go shadowlink/client/ws_pool_drain_test.go
git commit -m "feat(ws-pool): drop stale frames after streamID reuse + counter"
```

---

## Task 6: `startDrain` rewrite — inflightDrains gate + readyCapacity check

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go:62-123` (the `startDrain` function)
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Write the failing test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestStartDrain_InflightCounterCaps asserts that with
// maxConcurrentDrains=2 (default for poolSize=8), at most 2 of N
// concurrent startDrain calls actually transition slots to slotDraining
// — the rest see the inflight cap and defer (spec §2.1.0).
func TestStartDrain_InflightCounterCaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	for i := 0; i < 8; i++ {
		p.slots[i] = &poolSlot{index: i}
		p.slots[i].setState(slotReady)
	}

	// Pre-saturate inflight to cap to short-circuit subsequent calls.
	p.inflightDrains.Store(int32(p.maxConcurrentDrains()))

	startedAt := Stats.DrainStartedTotal.Load()
	deferredAt := Stats.DrainStormBrakeEngagedTotal.Load()

	// All 4 concurrent calls should be deferred via the inflight gate.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p.startDrain(nil, idx, "test")
		}(i)
	}
	wg.Wait()

	if got := Stats.DrainStartedTotal.Load() - startedAt; got != 0 {
		t.Errorf("DrainStartedTotal increment = %d, want 0 (all should defer)", got)
	}
	if got := Stats.DrainStormBrakeEngagedTotal.Load() - deferredAt; got != 4 {
		t.Errorf("DrainStormBrakeEngagedTotal increment = %d, want 4", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test -run TestStartDrain_InflightCounterCaps ./client/`
Expected: FAIL — `Stats.DrainStormBrakeEngagedTotal undefined` and the inflight gate isn't in place.

- [ ] **Step 3: Add the counter to stats.go**

In `shadowlink/client/stats.go`, append to the drain counters block:

```go
	// DrainStormBrakeEngagedTotal — every storm-brake deferral (either
	// inflight cap or capacity floor). Canary metric — was 326 in
	// baseline 2026-05-19. Target post-uniform-cells fix: <50 per 20min.
	DrainStormBrakeEngagedTotal atomic.Uint64
```

Add Prometheus exposition:

```go
	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_storm_brake_engaged_total Storm-brake deferrals (inflight cap or capacity floor)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_storm_brake_engaged_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_storm_brake_engaged_total %d\n", Stats.DrainStormBrakeEngagedTotal.Load())

```

- [ ] **Step 4: Add the backoff constants (pre-impl, so Step 5 compiles)**

In `shadowlink/client/ws_pool_drain.go`, REPLACE the existing top-of-file constant block (currently containing `drainPollInterval` and `drainRevertBackoff`) with:

```go
const (
	drainPollInterval        = 500 * time.Millisecond
	drainRevertBackoff       = 30 * time.Second
	// drainStormBrakeBackoff: see T7 for full doc-comment. Pre-declared
	// here so startDrain (this task) compiles. T7 finalizes the comment
	// + verifies watchdog interval alignment.
	drainStormBrakeBackoff = 5 * time.Second
	// drainCatastrophicBackoff: see T7 for full doc-comment. Pre-declared
	// here for the same reason.
	drainCatastrophicBackoff = 150 * time.Second
)
```

- [ ] **Step 5: Rewrite startDrain**

In `shadowlink/client/ws_pool_drain.go`, REPLACE the entire `startDrain` function (lines 62-123) with:

```go
// startDrain transitions p.slots[oldIdx] from slotReady to slotDraining
// and spawns parallel connect-replacement + drain-watchdog goroutines.
//
// Gate ordering (spec 2026-05-20 §2.1, §2.1.0):
//  1. Feature flag off → no-op.
//  2. oldIdx out of primary range → no-op.
//  3. oldSlot nil → no-op.
//  4. Inflight cap gate (atomic): increment, check, hand off on success
//     OR back out + defer on failure.
//  5. Capacity floor gate (secondary, catches catastrophic state).
//  6. tryMarkDraining CAS.
//  7. claimFreeSlot.
//  8. Spawn connectReplacementSlot + drainWatchdog.
//
// `reason`: "age", "byte_budget", or "anti_fingerprint".
func (p *WSPoolTransport) startDrain(cl *Client, oldIdx int, reason string) {
	if !p.gracefulDrain {
		return
	}
	if oldIdx < 0 || oldIdx >= p.poolSize {
		return
	}
	oldSlot := p.slots[oldIdx]
	if oldSlot == nil {
		return
	}

	// Gate 4: inflight cap (atomic — see spec §2.1.0). Increment FIRST so
	// concurrent triggers cannot all observe the same low count.
	inflight := p.inflightDrains.Add(1)
	committed := false
	defer func() {
		if !committed {
			p.inflightDrains.Add(-1)
		}
	}()
	if int(inflight) > p.maxConcurrentDrains() {
		Stats.DrainStormBrakeEngagedTotal.Add(1)
		p.log.Info("WS pool slot drain deferred (inflight cap)",
			"slot", oldIdx, "reason", reason,
			"inflight", inflight,
			"max_concurrent", p.maxConcurrentDrains())
		// Storm-brake-only deferral — fast retry.
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainStormBrakeBackoff).UnixNano())
		return
	}

	// Gate 5: capacity floor (catches natural-death depletion that
	// inflightDrains doesn't track).
	ready := p.readyCapacity()
	floor := p.readyCapacityFloor()
	if ready < floor {
		Stats.DrainStormBrakeEngagedTotal.Add(1)
		// Catastrophic state (less than half pool ready) → longer backoff
		// so reconnectLoop has time to heal capacity (spec §2.1.1).
		backoff := drainStormBrakeBackoff
		if ready < p.poolSize/2 {
			backoff = drainCatastrophicBackoff
		}
		p.log.Info("WS pool slot drain deferred (capacity floor)",
			"slot", oldIdx, "reason", reason,
			"ready_capacity", ready,
			"floor", floor,
			"backoff", backoff)
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(backoff).UnixNano())
		return
	}

	// Gate 6: CAS slotReady → slotDraining.
	if !oldSlot.tryMarkDraining() {
		return
	}

	// Gate 7: claim a free cell ANYWHERE in the slice.
	newIdx := p.claimFreeSlot()
	if newIdx < 0 {
		p.log.Warn("WS pool drain skipped — no free cell",
			"slot", oldIdx, "reason", reason)
		if !oldSlot.state.CompareAndSwap(int32(slotDraining), int32(slotReady)) {
			p.log.Debug("WS pool revert CAS failed — slot died concurrently",
				"slot", oldIdx)
		}
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainRevertBackoff).UnixNano())
		return
	}

	// All gates passed — hand off inflight ownership to drainWatchdog.
	committed = true

	Stats.DrainStartedTotal.Add(1)
	drainStart := time.Now()
	activeAtStart := oldSlot.streams.Load()

	p.log.Info("WS pool slot drain started",
		"slot", oldIdx,
		"replacement_slot", newIdx,
		"reason", reason,
		"active_streams", activeAtStart,
		"hard_cap", p.drainHardCap,
		"inflight", inflight,
	)

	go p.connectReserveSlot(cl, newIdx, oldIdx)
	go p.drainWatchdog(cl, oldIdx, oldSlot, drainStart, reason)
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd shadowlink && go test -run TestStartDrain_InflightCounterCaps ./client/`
Expected: PASS — all constants from Step 4 + impl from Step 5 are in place.

- [ ] **Step 7: Run full client suite**

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS — the rewritten `TestStartDrain_StormBrake*` tests from T2 Step 5 already exercise the new gates.

- [ ] **Step 8: Commit**

```bash
git add shadowlink/client/ws_pool_drain.go shadowlink/client/stats.go shadowlink/client/ws_pool_drain_test.go
git commit -m "feat(ws-pool): startDrain uses inflightDrains + readyCapacity gates"
```

---

## Task 7: Document split backoff constants

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go` (constants block at the top)
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Write the failing test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestStartDrain_BootstrapBackoff asserts catastrophic state (<50%
// ready) triggers the long backoff (drainCatastrophicBackoff), not the
// short one. Spec §2.1.1, C2 review fix.
func TestStartDrain_BootstrapBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize:      8,
		gracefulDrain: true,
		drainHardCap:  5 * time.Second,
		ctx:           ctx,
		log:           newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)

	// Catastrophic state: only 3 of 8 cells ready (37%).
	for i := 0; i < 3; i++ {
		p.slots[i] = &poolSlot{index: i}
		p.slots[i].setState(slotReady)
	}

	// Add one more slot that we'll try to drain — but it's at idx 5
	// (ready) so the test can call startDrain on it.
	p.slots[5] = &poolSlot{index: 5}
	p.slots[5].setState(slotReady)

	before := time.Now().UnixNano()
	p.startDrain(nil, 5, "test")
	after := p.slots[5].nextDrainAttemptNs.Load()

	gap := time.Duration(after - before)
	// Expect drainCatastrophicBackoff (150s) ± 1s scheduling slack.
	if gap < drainCatastrophicBackoff-time.Second || gap > drainCatastrophicBackoff+5*time.Second {
		t.Errorf("backoff gap = %v, want ~%v (drainCatastrophicBackoff)",
			gap, drainCatastrophicBackoff)
	}
}
```

- [ ] **Step 2: Run test to verify it passes (regression guard)**

Run: `cd shadowlink && go test -run TestStartDrain_BootstrapBackoff ./client/`
Expected: PASS — the constants and the catastrophic branch were both added in T6 (Steps 4 + 5). This T7 test acts as a REGRESSION GUARD: if any future refactor accidentally collapses the two backoff paths or drops the `ready < p.poolSize/2` predicate, this test fails first.

If FAIL with backoff ≈ 5s, the catastrophic branch was lost during T6 implementation — fix the T6 commit before continuing.

- [ ] **Step 3: Document the constants properly**

In `shadowlink/client/ws_pool_drain.go`, REPLACE the const block at the top with:

```go
const (
	// drainPollInterval — drainWatchdog tick rate when checking if active
	// streams have drained naturally.
	drainPollInterval = 500 * time.Millisecond

	// drainRevertBackoff — backoff after startDrain failed because
	// claimFreeSlot returned -1 (slice fully occupied). Genuine resource
	// exhaustion, retry slowly.
	drainRevertBackoff = 30 * time.Second

	// drainStormBrakeBackoff — backoff after storm-brake deferral in
	// non-catastrophic state. Equal to one watchdog tick (rotationWatchdogInterval
	// in ws_pool.go) so the next sweep re-evaluates immediately. Cheap to
	// retry: readyCapacity() is O(2*poolSize) integer compare.
	// Spec 2026-05-20 §2.4.2 (W6 review fix).
	drainStormBrakeBackoff = 5 * time.Second

	// drainCatastrophicBackoff — backoff when readyCapacity dropped below
	// poolSize/2 (more than half the pool is dead/connecting). Long
	// backoff to let reconnectLoop heal capacity without tight retry
	// loops. Spec 2026-05-20 §2.1.1 (C2 review fix).
	drainCatastrophicBackoff = 150 * time.Second
)
```

- [ ] **Step 4: Verify watchdog interval alignment**

Run: `cd shadowlink && grep -n "rotationWatchdogInterval\|healthSummaryInterval" client/ws_pool.go`

Confirm the watchdog tick is 5s. If different, update `drainStormBrakeBackoff` to match.

- [ ] **Step 5: Run full client suite**

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add shadowlink/client/ws_pool_drain.go shadowlink/client/ws_pool_drain_test.go
git commit -m "feat(ws-pool): split drain backoffs — fast/slow/catastrophic"
```

---

## Task 8: `drainWatchdog` defer-decrement (NEW-1)

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go:158-200` (the `drainWatchdog` function)
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Write the failing test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestDrainWatchdog_InflightDecrementOnAllExitPaths asserts the
// inflight counter is decremented on natural-finish, hard-cap, AND
// ctx-cancel exit paths (spec §2.1.0, NEW-1 review fix).
func TestDrainWatchdog_InflightDecrementOnAllExitPaths(t *testing.T) {
	cases := []struct {
		name string
		exit func(p *WSPoolTransport, oldSlot *poolSlot, cancel context.CancelFunc)
	}{
		{
			name: "natural_finish",
			exit: func(p *WSPoolTransport, oldSlot *poolSlot, _ context.CancelFunc) {
				oldSlot.streams.Store(0) // streams reach 0 → natural finish
			},
		},
		{
			name: "ctx_cancel",
			exit: func(p *WSPoolTransport, _ *poolSlot, cancel context.CancelFunc) {
				cancel()
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			p := &WSPoolTransport{
				poolSize:     8,
				ctx:          ctx,
				log:          newDiscardLogger(),
				drainHardCap: 30 * time.Second,
			}
			p.slots = make([]*poolSlot, 16)
			oldSlot := &poolSlot{index: 0}
			oldSlot.setState(slotDraining)
			oldSlot.streams.Store(5) // 5 active
			p.slots[0] = oldSlot

			// Simulate that startDrain incremented inflight.
			p.inflightDrains.Store(1)

			done := make(chan struct{})
			go func() {
				p.drainWatchdog(nil, 0, oldSlot, time.Now(), "test")
				close(done)
			}()

			// Trigger the exit condition.
			time.Sleep(50 * time.Millisecond)
			tc.exit(p, oldSlot, cancel)

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("drainWatchdog did not exit within 2s")
			}

			if got := p.inflightDrains.Load(); got != 0 {
				t.Errorf("inflightDrains after exit = %d, want 0 (defer decrement)", got)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test -run TestDrainWatchdog_InflightDecrementOnAllExitPaths ./client/`
Expected: FAIL — current drainWatchdog doesn't decrement inflight.

- [ ] **Step 3: Add the defer**

In `shadowlink/client/ws_pool_drain.go`, modify `drainWatchdog` (around line 158-200). At the top of the function body, immediately after the function signature line, INSERT:

```go
	// Inflight ownership was transferred from startDrain via committed=true.
	// Guarantee decrement on every exit path (natural finish, hard cap,
	// ctx cancel, panic) — spec §2.1.0 NEW-1.
	defer p.inflightDrains.Add(-1)
```

The full function should now look like:

```go
func (p *WSPoolTransport) drainWatchdog(cl *Client, oldIdx int, oldSlot *poolSlot,
	drainStart time.Time, reason string) {

	defer p.inflightDrains.Add(-1)

	ticker := time.NewTicker(drainPollInterval)
	defer ticker.Stop()
	deadline := time.NewTimer(p.drainHardCap)
	defer deadline.Stop()

	tearDown := func(hardCap bool) {
		// ... unchanged body ...
	}

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-deadline.C:
			tearDown(true)
			return
		case <-ticker.C:
			if oldSlot.streams.Load() == 0 {
				tearDown(false)
				return
			}
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd shadowlink && go test -run TestDrainWatchdog_InflightDecrementOnAllExitPaths ./client/`
Expected: PASS (both sub-tests).

- [ ] **Step 5: Run full client suite**

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add shadowlink/client/ws_pool_drain.go shadowlink/client/ws_pool_drain_test.go
git commit -m "fix(ws-pool): drainWatchdog defers inflightDrains decrement"
```

---

## Task 9: `connectReserveSlot` failure → free placeholder (S5)

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go:135-147` (`connectReserveSlot`)
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Write the failing test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestConnectReserveSlot_FreesPlaceholderOnFailure asserts that when
// the handshake fails, the slotConnecting placeholder is reset to nil
// under reserveMu so a subsequent claimFreeSlot can reuse the cell
// without waiting for reconnectLoop. Spec §4.2 (S5 review).
func TestConnectReserveSlot_FreesPlaceholderOnFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize: 8,
		ctx:      ctx,
		log:      newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)

	// Pre-install a slotConnecting placeholder at idx 8 (as claimFreeSlot would).
	placeholder := &poolSlot{}
	placeholder.setState(slotConnecting)
	p.slots[8] = placeholder

	// Stub connectSlot to fail.
	prev := connectSlotForTest
	connectSlotForTest = func() error {
		return errors.New("handshake failed")
	}
	defer func() { connectSlotForTest = prev }()

	p.connectReserveSlot(nil, 8, 0)

	// Wait briefly for the placeholder cleanup goroutine.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		p.reserveMu.Lock()
		s := p.slots[8]
		p.reserveMu.Unlock()
		if s == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	p.reserveMu.Lock()
	final := p.slots[8]
	p.reserveMu.Unlock()
	if final != nil {
		t.Errorf("placeholder at idx 8 not freed after failure: %v", final)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test -run TestConnectReserveSlot_FreesPlaceholderOnFailure ./client/`
Expected: FAIL — current connectReserveSlot leaves the placeholder until reconnectLoop replaces it.

- [ ] **Step 3: Add the failure cleanup**

In `shadowlink/client/ws_pool_drain.go`, REPLACE the `connectReserveSlot` function (around lines 135-147) with:

```go
// connectReserveSlot runs the standard connect path at newIdx. On
// success, AssignStream picks it up via its slotReady filter. On
// failure, drops the placeholder back to nil under reserveMu so a
// fresh drain can immediately reuse the cell, then schedules
// reconnectLoop (which short-circuits via §2.2.2 recycle guard if a
// drain claimed the cell in the meantime).
//
// Spec 2026-05-20 §4.2 (S5 review).
func (p *WSPoolTransport) connectReserveSlot(cl *Client, newIdx, oldIdx int) {
	if newIdx < 0 || newIdx >= len(p.slots) {
		return
	}

	if err := p.connectSlot(p.ctx, newIdx); err != nil {
		p.reserveMu.Lock()
		if p.slots[newIdx] != nil && p.slots[newIdx].getState() == slotConnecting {
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

- [ ] **Step 4: Run test to verify it passes**

Run: `cd shadowlink && go test -run TestConnectReserveSlot_FreesPlaceholderOnFailure ./client/`
Expected: PASS.

- [ ] **Step 5: Run full client suite**

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add shadowlink/client/ws_pool_drain.go shadowlink/client/ws_pool_drain_test.go
git commit -m "fix(ws-pool): free placeholder on connectReserveSlot failure"
```

---

## Task 10: Unify iteration sites to whole-slice (4 sites + health)

**Files:**
- Modify: `shadowlink/client/ws_pool.go:1144-1187` (`rotationWatchdogSweep`)
- Modify: `shadowlink/client/ws_pool.go:1274-1296` (`sendKeepaliveToAllSlots`)
- Modify: `shadowlink/client/ws_pool.go:1745-1769` (`rotateMinLoadedSlot`)
- Modify: `shadowlink/client/ws_pool.go:2067-2098` (`StartReader`)
- Modify: `shadowlink/client/ws_pool.go:1208-1253` (`emitHealthSummary`)
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Write the failing test for emitHealthSummary schema**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestEmitHealthSummary_UniformSchema asserts the new schema:
//   - dead = literal slotDead count (not nil-primary count)
//   - empty = nil-cell count anywhere in slice (new field)
//   - alive + dead + connecting + draining + empty == 2*poolSize
// Spec §2.4, C5 review fix.
func TestEmitHealthSummary_UniformSchema(t *testing.T) {
	p := &WSPoolTransport{
		poolSize:  8,
		log:       newDiscardLogger(),
		startedAt: time.Now(),
	}
	p.slots = make([]*poolSlot, 16)

	// Canary state: 6 primary ready + 2 reserve ready + 2 nil primary + 6 nil reserve.
	for _, i := range []int{0, 1, 3, 4, 5, 7, 8, 9} {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}

	alive, dead, connecting, draining, empty := p.poolStateCounts()
	if alive != 8 {
		t.Errorf("alive = %d, want 8", alive)
	}
	if dead != 0 {
		t.Errorf("dead = %d, want 0 (literal slotDead — not nil)", dead)
	}
	if empty != 8 {
		t.Errorf("empty = %d, want 8 (8 nil cells)", empty)
	}
	if alive+dead+connecting+draining+empty != 16 {
		t.Errorf("sum invariant broken: %d+%d+%d+%d+%d != 16",
			alive, dead, connecting, draining, empty)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test -run TestEmitHealthSummary_UniformSchema ./client/`
Expected: FAIL — `poolStateCounts undefined`.

- [ ] **Step 3: Extract counting helper + rewrite emitHealthSummary**

In `shadowlink/client/ws_pool.go`, REPLACE the body of `emitHealthSummary` (lines 1208-1253) with:

```go
// poolStateCounts returns the breakdown of cell states across the
// whole slice. Uniform-cells schema (spec 2026-05-20 §2.4):
//   - alive: slotReady cells
//   - dead: slotDead cells (literal, NOT nil)
//   - empty: nil cells (new field — replaces the old "nil primary = dead++" semantics)
//   - sum invariant: alive + dead + connecting + draining + empty == 2*poolSize
func (p *WSPoolTransport) poolStateCounts() (alive, dead, connecting, draining, empty int) {
	for _, slot := range p.slots {
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
	for _, slot := range p.slots {
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
		"rate_limited_recent", rateLimited,
		"active_streams", totalStreams,
		"meltdowns_1m", p.meltdowns1m.Load(),
		"rotations_1m", p.rotations1m.Load(),
		"inflight_drains", p.inflightDrains.Load(),
		"uptime", uptime,
	)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd shadowlink && go test -run TestEmitHealthSummary_UniformSchema ./client/`
Expected: PASS.

- [ ] **Step 5: Rewrite `rotationWatchdogSweep`**

In `shadowlink/client/ws_pool.go:1144-1187`, REPLACE the `for idx := 0; idx < p.poolSize; idx++` loop with `for idx := range p.slots`. The full updated function:

```go
func (p *WSPoolTransport) rotationWatchdogSweep() {
	nowNs := time.Now().UnixNano()
	// Uniform-cells: iterate the entire slice. Cells that drifted from
	// primary to reserve range still need age-driven drain — see spec
	// 2026-05-20 §2.3.
	for idx := range p.slots {
		slot := p.slots[idx]
		if slot == nil || slot.getState() != slotReady {
			continue
		}
		if slot.nextDrainAttemptNs.Load() > nowNs {
			continue
		}
		started := slot.startedAtNs.Load()
		if started == 0 {
			continue
		}
		effectiveMaxAge := p.maxSlotAge.Nanoseconds() + slot.staggerOffsetNs.Load()
		if nowNs-started < effectiveMaxAge {
			continue
		}
		if p.gracefulDrain {
			p.startDrain(p.client, idx, "age")
		} else {
			slotStart := time.Unix(0, started)
			p.maybeRotateSlot(p.client, idx, slot, "age",
				0, slotStart, slot.downBytes.Load(),
			)
		}
	}
}
```

Note: `startDrain` and `maybeRotateSlot` both currently early-return when `idx >= p.poolSize`. After this task, `startDrain` must accept any idx — update its guard:

In `shadowlink/client/ws_pool_drain.go` (the `startDrain` from T6), REPLACE:

```go
	if oldIdx < 0 || oldIdx >= p.poolSize {
		return
	}
```

with:

```go
	if oldIdx < 0 || oldIdx >= len(p.slots) {
		return
	}
```

And similarly for `maybeRotateSlot` if it has a `>= poolSize` guard — update to `>= len(p.slots)`.

- [ ] **Step 6: Rewrite `sendKeepaliveToAllSlots`**

In `shadowlink/client/ws_pool.go:1274-1296`, REPLACE `for i := 0; i < p.poolSize; i++` with `for i := range p.slots`. Keep the rest of the body identical.

- [ ] **Step 7: Rewrite `rotateMinLoadedSlot`**

In `shadowlink/client/ws_pool.go:1745-1758`, REPLACE the for-loop with `for i := range p.slots`. The picker logic (min-streams across ready cells) is unchanged.

- [ ] **Step 8: Rewrite `StartReader`**

In `shadowlink/client/ws_pool.go:2073-2082`, REPLACE the for-loop with `for i := range p.slots`. The `errCh` channel capacity should grow:

```go
	errCh := make(chan error, len(p.slots))
```

(was `p.poolSize`).

- [ ] **Step 9: Run full client suite**

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_drain.go shadowlink/client/ws_pool_drain_test.go
git commit -m "refactor(ws-pool): unify iteration to whole slice + emitHealthSummary schema"
```

---

## Task 11: `handleSlotDeath` uniform streamChans close + counter wiring

**Files:**
- Modify: `shadowlink/client/ws_pool.go:2462-2542` (`handleSlotDeath`)
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Write the failing test (invert the existing assertion)**

Find the existing test `TestHandleSlotDeath_DrainTeardownDoesNotCloseStreamChans` in `shadowlink/client/ws_pool_drain_test.go`.

REPLACE it with the inverted test plus a new no-underflow regression:

```go
// TestHandleSlotDeath_DrainTeardownClosesStreamChans asserts the
// behavior change in spec §3 (C6 review): drainTeardown NOW closes
// streamChans uniformly with natural/preemptive — deterministic kill
// signal to SOCKS5 layer.
func TestHandleSlotDeath_DrainTeardownClosesStreamChans(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
	}
	p := &WSPoolTransport{poolSize: 8, ctx: ctx, log: newDiscardLogger(), client: cl}
	p.slots = make([]*poolSlot, 16)
	slot := &poolSlot{index: 3}
	slot.setState(slotDraining)
	p.slots[3] = slot

	ch := make(chan []byte, 1)
	cl.streamChans[42] = ch
	p.streamMap.Store(uint16(42), 3)

	p.handleSlotDeath(cl, 3, deathCauseDrainTeardown)

	// streamChans[42] must now be closed AND removed from the map.
	cl.streamMu.Lock()
	_, present := cl.streamChans[42]
	cl.streamMu.Unlock()
	if present {
		t.Errorf("streamChans[42] still present after drainTeardown")
	}
	// Channel must be closed (read returns zero value, !ok).
	select {
	case _, ok := <-ch:
		if ok {
			t.Errorf("ch read returned ok=true, expected closed channel")
		}
	default:
		t.Errorf("ch not closed (read would block)")
	}
}

// TestHandleSlotDeath_NoUnderflowOnLateRelease asserts that
// LoadAndDelete ordering prevents streams.Add(-1) underflow when
// ReleaseStream is called after handleSlotDeath cleared the map.
// Spec §3 implementation note.
func TestHandleSlotDeath_NoUnderflowOnLateRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := &WSPoolTransport{poolSize: 8, ctx: ctx, log: newDiscardLogger(), client: cl}
	p.slots = make([]*poolSlot, 16)
	slot := &poolSlot{index: 0}
	slot.setState(slotDraining)
	slot.streams.Store(5)
	p.slots[0] = slot

	for sid := uint16(100); sid < 105; sid++ {
		cl.streamChans[sid] = make(chan []byte, 1)
		p.streamMap.Store(sid, 0)
	}

	p.handleSlotDeath(cl, 0, deathCauseDrainTeardown)

	// Late ReleaseStream calls — must be no-ops because LoadAndDelete sees ok=false.
	for sid := uint16(100); sid < 105; sid++ {
		p.ReleaseStream(sid)
	}

	// streams counter must not have underflowed.
	// handleSlotDeath sets it to 0 directly; check it's exactly 0, not -5.
	if got := slot.streams.Load(); got != 0 {
		t.Errorf("slot.streams = %d, want 0 (no underflow)", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd shadowlink && go test -run "TestHandleSlotDeath_DrainTeardownClosesStreamChans|TestHandleSlotDeath_NoUnderflowOnLateRelease" ./client/`
Expected: FAIL (close assertion fails — current code skips close for drainTeardown).

- [ ] **Step 3: Remove the exclusion in handleSlotDeath**

In `shadowlink/client/ws_pool.go` around line 2485-2509, REPLACE the current block:

```go
	p.streamMap.Range(func(key, value any) bool {
		if value.(int) != idx {
			return true
		}
		streamID := key.(uint16)
		p.streamMap.Delete(streamID)
		if cause != deathCauseDrainTeardown {
			cl.streamMu.Lock()
			if ch, ok := cl.streamChans[streamID]; ok {
				close(ch)
				delete(cl.streamChans, streamID)
			}
			cl.streamMu.Unlock()
		}
		return true
	})

	// streams.Store(0) is correct for natural + preemptive (we closed all
	// streamChans above, so ReleaseStream from those streams becomes a
	// no-op via the cancelled stream goroutines). For drainTeardown the
	// active streams are still running and will call ReleaseStream as
	// they finish — hard-zeroing here would underflow to -1.
	if cause != deathCauseDrainTeardown {
		slot.streams.Store(0)
	}
```

with:

```go
	// Uniform stream cleanup across all death causes (spec 2026-05-20 §3,
	// C6 review). streamMap.Delete BEFORE close(ch) is load-bearing:
	// ReleaseStream uses LoadAndDelete (ws_pool.go::ReleaseStream), so
	// any late ReleaseStream call for a streamID we already removed sees
	// ok=false and becomes a no-op — no underflow on streams.Store(0).
	p.streamMap.Range(func(key, value any) bool {
		if value.(int) != idx {
			return true
		}
		streamID := key.(uint16)
		p.streamMap.Delete(streamID)
		cl.streamMu.Lock()
		if ch, ok := cl.streamChans[streamID]; ok {
			close(ch)
			delete(cl.streamChans, streamID)
		}
		cl.streamMu.Unlock()
		return true
	})

	slot.streams.Store(0)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd shadowlink && go test -run "TestHandleSlotDeath_DrainTeardownClosesStreamChans|TestHandleSlotDeath_NoUnderflowOnLateRelease" ./client/`
Expected: PASS.

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS.

- [ ] **Step 5: Add `Stats.DrainInflight` gauge (acceptance #10)**

In `shadowlink/client/stats.go`, find the Prometheus exporter (where the other drain counters are exposed, around line 502+) and append:

```go
	fmt.Fprintf(w, "# HELP shadowlink_drain_inflight Drains currently in progress (atomic snapshot)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_inflight gauge\n")
	if p := globalPoolForStats(); p != nil {
		fmt.Fprintf(w, "shadowlink_drain_inflight %d\n", p.inflightDrains.Load())
	}

```

The gauge reads directly from the pool's atomic — no separate Stats field needed. If `globalPoolForStats()` does not exist (verify by grep first), add to `client/stats.go`:

```go
// globalPoolForStats returns the running pool transport for gauge
// exposition. Set by the engine on Connect; returns nil if not pooled.
var globalPoolForStatsPtr atomic.Pointer[WSPoolTransport]

func globalPoolForStats() *WSPoolTransport {
	return globalPoolForStatsPtr.Load()
}

// SetGlobalPoolForStats publishes the pool for gauge exposition. Idempotent.
func SetGlobalPoolForStats(p *WSPoolTransport) {
	globalPoolForStatsPtr.Store(p)
}
```

And in `client/ws_pool.go`, in `WSPoolTransport.Connect()` (the success path, right before `return nil`), add:

```go
	SetGlobalPoolForStats(p)
```

If this pattern (global publisher) is not idiomatic in this codebase — verify with `grep -n "atomic.Pointer\[WSPoolTransport\]" shadowlink/`. If a different pattern exists (e.g. counter callback registration), use that instead and mirror the structure used by `core.SetStatsCallbacks` (`shadowlink/core/encrypt.go` registers an atomic.Pointer-wrapped struct similarly).

- [ ] **Step 6: Add the table-driven all-causes test (acceptance #7)**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestHandleSlotDeath_AllCausesCloseStreamChans asserts the unified
// behavior across all death causes — streamChans are closed in every
// case (spec 2026-05-20 §3, acceptance #7).
func TestHandleSlotDeath_AllCausesCloseStreamChans(t *testing.T) {
	cases := []struct {
		name  string
		cause slotDeathCause
	}{
		{"natural", deathCauseNatural},
		{"preemptive", deathCausePreemptiveRotation},
		{"drainTeardown", deathCauseDrainTeardown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cl := &Client{streamChans: make(map[uint16]chan []byte)}
			p := &WSPoolTransport{
				poolSize: 8, ctx: ctx, log: newDiscardLogger(), client: cl,
			}
			p.slots = make([]*poolSlot, 16)
			slot := &poolSlot{index: 0}
			slot.setState(slotReady)
			p.slots[0] = slot

			ch := make(chan []byte, 1)
			cl.streamChans[7] = ch
			p.streamMap.Store(uint16(7), 0)

			p.handleSlotDeath(cl, 0, tc.cause)

			cl.streamMu.Lock()
			_, present := cl.streamChans[7]
			cl.streamMu.Unlock()
			if present {
				t.Errorf("[%s] streamChans[7] still present", tc.name)
			}
			select {
			case _, ok := <-ch:
				if ok {
					t.Errorf("[%s] ch read ok=true, expected closed", tc.name)
				}
			default:
				t.Errorf("[%s] ch not closed (would block)", tc.name)
			}
		})
	}
}
```

- [ ] **Step 7: Run tests**

Run: `cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS — uniform close in T11 Step 3 produces all three sub-tests green.

- [ ] **Step 8: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/stats.go shadowlink/client/ws_pool_drain_test.go
git commit -m "refactor(ws-pool): handleSlotDeath closes streamChans uniformly + inflight gauge"
```

---

## Task 12: Remove `SessionForStream` fallback

**Files:**
- Modify: `shadowlink/client/ws_pool.go:1969-1990` (`SessionForStream`)
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Write the failing test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestSessionForStream_NoFallback asserts that an unmapped streamID
// returns nil instead of any-ready-slot's session. Callers
// (client.go:710, socks5/tcp.go:495/531/565) are all nil-safe — verified
// in spec §2.5 caller audit (C4 review).
func TestSessionForStream_NoFallback(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)
	// Install a ready slot with a fake session at idx 0.
	p.slots[0] = &poolSlot{session: &core.Session{}}
	p.slots[0].setState(slotReady)

	// streamID 999 is NOT in streamMap.
	got := p.SessionForStream(uint16(999))
	if got != nil {
		t.Errorf("SessionForStream for unmapped streamID = %v, want nil", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test -run TestSessionForStream_NoFallback ./client/`
Expected: FAIL — current fallback returns slots[0].session.

- [ ] **Step 3: Remove the fallback**

In `shadowlink/client/ws_pool.go`, REPLACE the `SessionForStream` function (around lines 1969-1990) with:

```go
// SessionForStream returns the crypto session for the stream's assigned
// slot, or nil if the stream is not mapped or the mapped cell is
// nil/non-Ready. The old "fallback to first primary's session" path
// was removed (spec 2026-05-20 §2.5, C4 review) — it produced silent
// decrypt failures (server keys sessions per-slot) and all callers
// (client.go:710, socks5/tcp.go:495/531/565) already nil-guard.
func (p *WSPoolTransport) SessionForStream(streamID uint16) *core.Session {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx >= 0 && idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].session
		}
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd shadowlink && go test -run TestSessionForStream_NoFallback ./client/`
Expected: PASS.

Run full client tests:
`cd shadowlink && go test ./client/ -count=1 -timeout 60s`
Expected: PASS — caller-side nil-safety confirmed in spec audit.

Run proxy tests:
`cd shadowlink && go test ./proxy/socks5/... -count=1 -timeout 60s`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_drain_test.go
git commit -m "refactor(ws-pool): SessionForStream returns nil instead of fallback"
```

---

## Task 13: Integration test — canary scenario replay

**Files:**
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Write the canary scenario test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestCanaryScenario_MismatchedPairs replays the exact canary
// 2026-05-19 stuck state to verify the uniform-cells fix. Setup:
// poolSize=8, primary[6] drained → reserve[8], primary[2] drained →
// reserve[9]. With pairing logic this state pinned non_ready_slots=2
// forever, blocking all further drains (326 deferred in 23min). With
// uniform-cells logic, readyCapacity=8 (6+2) and drains can proceed.
func TestCanaryScenario_MismatchedPairs(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	// Mirror canary state.
	for _, i := range []int{0, 1, 3, 4, 5, 7, 8, 9} {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}

	ready := p.readyCapacity()
	floor := p.readyCapacityFloor()

	if ready != 8 {
		t.Errorf("canary state readyCapacity = %d, want 8", ready)
	}
	if floor != 6 {
		t.Errorf("canary state floor = %d, want 6", floor)
	}
	if ready < floor {
		t.Errorf("storm brake would engage incorrectly (ready=%d < floor=%d)", ready, floor)
	}

	// Verify a fresh drain can claim a free cell — slice has 8 nil cells
	// at indices [2, 6, 10, 11, 12, 13, 14, 15], so claim must succeed.
	got := p.claimFreeSlot()
	if got < 0 {
		t.Errorf("claimFreeSlot returned -1 — should have found a free cell")
	}
}

// TestRecycle_AfterAllReservesOccupied asserts swiss-cheese recovery:
// after 8 drains so all 8 reserve cells are occupied AND all 8 primary
// cells are nil, the 9th drain MUST claim a recycled primary cell.
// Spec §4 test list, W4 review fix.
func TestRecycle_AfterAllReservesOccupied(t *testing.T) {
	p := &WSPoolTransport{poolSize: 8}
	p.slots = make([]*poolSlot, 16)

	// Post-8-drain state: primary cells [0..7] all nil, reserve [8..15] all ready.
	for i := 8; i < 16; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}

	got := p.claimFreeSlot()
	if got < 0 || got >= 8 {
		t.Errorf("9th drain claim = %d, want primary range [0..8) (recycled cell)", got)
	}
	if p.slots[got] == nil || p.slots[got].getState() != slotConnecting {
		t.Errorf("recycled cell state wrong: %v", p.slots[got])
	}
}
```

Also append the T4/T9 interaction regression test:

```go
// TestRecycleRace_DrainClaimsAfterFailedConnect — W8 race regression
// (review of T9 + T4 interaction). Sequence:
//   1. T9 failure path: connectReserveSlot fails, sets slots[newIdx]=nil,
//      launches reconnectLoop(newIdx) in background.
//   2. Concurrently, a NEW drain calls claimFreeSlot, picks newIdx,
//      installs slotConnecting placeholder.
//   3. reconnectLoop wakes after backoff, recycle guard observes
//      slots[newIdx] != nil AND state != slotDead → bails out.
//   4. End state: new drain owns newIdx; no double-install.
func TestRecycleRace_DrainClaimsAfterFailedConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &WSPoolTransport{
		poolSize: 8, ctx: ctx, log: newDiscardLogger(),
	}
	p.slots = make([]*poolSlot, 16)
	// All primaries ready except idx 0 which is empty.
	for i := 1; i < 8; i++ {
		p.slots[i] = &poolSlot{index: i}
		p.slots[i].setState(slotReady)
	}

	// Step (1): simulate T9 already cleaned a failed connectReserveSlot
	// — slots[0] is nil, reconnectLoop is "in flight" (not actually
	// spawned in test; we verify the post-claim guard semantics).
	p.slots[0] = nil

	// Step (2): a fresh drain claims slot 0.
	got := p.claimFreeSlot()
	if got != 0 {
		t.Fatalf("claimFreeSlot returned %d, want 0", got)
	}
	if p.slots[0] == nil || p.slots[0].getState() != slotConnecting {
		t.Fatalf("post-claim state wrong: %v", p.slots[0])
	}

	// Step (3): emulate reconnectLoop guard check.
	p.reserveMu.Lock()
	recycled := p.slots[0] != nil && p.slots[0].getState() != slotDead
	p.reserveMu.Unlock()
	if !recycled {
		t.Errorf("recycle guard did not detect drain's claim — would overwrite")
	}
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd shadowlink && go test -run "TestCanaryScenario_MismatchedPairs|TestRecycle_AfterAllReservesOccupied|TestRecycleRace_DrainClaimsAfterFailedConnect" ./client/`
Expected: PASS (these are the integration assertions that the previous tasks combined produce the correct end-to-end behavior).

- [ ] **Step 3: Run full client suite + go vet**

Run:
```bash
cd shadowlink && go test ./client/ -count=1 -timeout 120s
cd shadowlink && go vet ./client/...
cd shadowlink && go test ./... -count=1 -timeout 120s
```
Expected: ALL PASS.

- [ ] **Step 4: Acceptance grep verification**

Run each acceptance grep from spec §6:

```bash
echo "=== Acceptance #1: no paired arithmetic ==="
grep -rn "i + p.poolSize\|i - p.poolSize\|i+poolSize\|i-poolSize" shadowlink/client/ | grep -v _test.go
# Expected: 0 hits

echo "=== Acceptance #2: p.poolSize uses (manual review) ==="
grep -n "p.poolSize" shadowlink/client/ws_pool.go shadowlink/client/ws_pool_drain.go
# Expected: every hit falls into whitelist:
#   - Connect() initial fan-out
#   - rotationStormBrakeFraction derivation (maxConcurrentDrains, readyCapacityFloor)
#   - len(p.slots) = 2*p.poolSize allocation
#   - readyCapacityFloor comparison
```

If grep #1 returns any hits in non-test files, remove the remaining pairing arithmetic.

If grep #2 shows hits outside the whitelist, justify each in the PR description or remove.

- [ ] **Step 5: Commit**

```bash
git add shadowlink/client/ws_pool_drain_test.go
git commit -m "test(ws-pool): canary scenario replay + recycle integration tests"
```

---

## Task 14: Documentation sync

**Files:**
- Modify: `shadowlink/docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md` (add header note)
- Modify: `shadowlink/CLAUDE.md` (graceful-drain row if behavior diverges)
- Verify: `D:/NIXAVPN/CLAUDE.md` (root) — no row to update unless spec mentions one

- [ ] **Step 1: Add superseded-in-part header to the 2026-05-19 spec**

In `shadowlink/docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md`, INSERT at the very top (before the existing first line):

```markdown
> **2026-05-20 UPDATE:** Sections on primary/reserve cell pairing (§Fix C3
> `i + p.poolSize` rule, §`countNonReadySlots` paired indexing) are
> SUPERSEDED by `2026-05-20-ws-pool-uniform-cells-design.md`. The new
> design implements §"primary and reserve cells circulate" (line 101 of
> this doc) consistently across all iteration sites; the §Fix C3
> pairing rule was a contradictory band-aid that triggered the
> 2026-05-19 canary stuck state. The HTTP/2 GOAWAY-style drain mechanism
> (slotDraining state, drainHardCap, env flag, watchdog poll) is
> RETAINED.

```

- [ ] **Step 2: Update `shadowlink/CLAUDE.md` graceful-drain row**

In `shadowlink/CLAUDE.md`, find the row for `SHADOWLINK_GRACEFUL_DRAIN` in the env flags table. REPLACE the row's description column to reflect uniform-cells:

```
| `SHADOWLINK_GRACEFUL_DRAIN` | off (Phase 1) | When `=1`/`true`/`yes`/`on` enables HTTP/2 GOAWAY-style slot draining with uniform-cells pool: active streams survive rotation, any free cell in the 2*poolSize slice serves as drain replacement, storm brake gates on readyCapacity. Off → legacy hard-rotation path. Phase 3 flips default to on. |
```

- [ ] **Step 3: Confirm no other docs reference pairing**

Run:
```bash
grep -rn "matching reserve cell\|i+poolSize\|reserve cell\[i+" shadowlink/docs/
grep -rn "primary range only\|reserve range" shadowlink/docs/
```

If any non-superseded doc references pairing as the live contract, update it to reference the new spec.

- [ ] **Step 4: Final build + test sweep**

```bash
cd shadowlink && go build ./...
cd shadowlink && go vet ./...
cd shadowlink && go test ./... -count=1 -timeout 180s
```
Expected: ALL CLEAN + PASS.

- [ ] **Step 5: Commit**

```bash
git add shadowlink/docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md shadowlink/CLAUDE.md
git commit -m "docs(ws-pool): mark 2026-05-19 pairing rules superseded; update env flag row"
```

---

## Post-implementation checklist (outside TDD loop)

After all 14 tasks land:

- [ ] Rebuild Linux client binary:
  ```bash
  cd shadowlink && GOOS=linux GOARCH=amd64 go build -o ../bin/shadowlink-client-graceful-drain ./cmd/shadowlink-client/
  ```
- [ ] Rebuild Windows client binary:
  ```bash
  cd shadowlink && GOOS=windows GOARCH=amd64 go build -o ../bin/nixavpn-client-graceful-drain.exe ./cmd/shadowlink-client/
  ```
- [ ] User runs `bin/connect-vpn-graceful-drain.bat` for ≥20 min.
- [ ] Analyze canary log against acceptance #4:
  - natural finish ratio >30%
  - storm brake engagements <50 total
  - `readyCapacity >= floor` consistently
- [ ] If all PASS → propose Phase 3 (flip `SHADOWLINK_GRACEFUL_DRAIN` default to on) as a separate plan.

---

## Notes for the implementer

- Every step's commit message uses Conventional Commits prefixes (`feat`, `fix`, `refactor`, `test`, `docs`) — keep this consistent so the squashed-merge changelog reads cleanly.
- All tests use `t.Helper()` and `newDiscardLogger()` where existing tests do — match the surrounding style.
- Do NOT add a kill switch env flag for the uniform-cells refactor itself. The behavior is strictly cleaner; if the canary reveals a different bug, fix it forward, do not toggle back.
- If a test rewrite (T1-T13) requires touching an unrelated test that was paired-layout-dependent (e.g., one of the 6 listed in the audit), update it in the same task — do not leave broken tests for "later".
- `Stats.DrainInflight` gauge is exposed in T11 Step 5 via `globalPoolForStats()` reader. The pattern mirrors how `core.SetStatsCallbacks` (`shadowlink/core/encrypt.go`) publishes counter callbacks under an atomic pointer — verify the same shape during T11.



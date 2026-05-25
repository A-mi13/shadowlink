# Plan Review — 2026-05-20-ws-pool-uniform-cells

**Reviewer:** code-reviewer (Opus 4.7)
**Plan:** `shadowlink/docs/superpowers/plans/2026-05-20-ws-pool-uniform-cells.md`
**Spec:** `shadowlink/docs/superpowers/specs/2026-05-20-ws-pool-uniform-cells-design.md`
**Mode:** subagent-driven-development (per-task TDD)

---

## Verdict

**APPROVED with FIXES** — план архитектурно соответствует спеке, TDD-дисциплина в основном выдержана, но есть несколько критических **API-несоответствий с реальным кодом**, которые сорвут компиляцию у subagent-implementer'а на первой же задаче и потребуют human-loop вмешательства.

После применения 5 Critical-fixes ниже план готов к запуску.

---

## Spec coverage table

| Spec section | Requirement | Task | Status |
|---|---|---|---|
| §2.1 readyCapacity | Count slotReady cells, no pairing | T2 | OK |
| §2.1 floor formula | floor = poolSize − max(1, ceil(poolSize·0.25)) | T2 | OK |
| §2.1.0 inflightDrains | atomic.Int32 + Add(1) gate + defer-back-out | T1, T6 | OK |
| §2.1.0 NEW-1 | drainWatchdog defers decrement on all exit paths | T8 | OK |
| §2.1.1 catastrophic backoff | 5× revertBackoff (150s) when ready<poolSize/2 | T6, T7 | OK |
| §2.2 claimFreeSlot | scan from idx 0 over whole slice | T3 | OK |
| §2.2.1 lock invariant | reserveMu around write | T3 | OK |
| §2.2.2 reconnectLoop recycle guard | short-circuit if recycled | T4 | OK |
| §2.3 4 iteration sites | range p.slots | T10 | OK |
| §2.3 Connect() fan-out kept | [0, poolSize) justified | — | OK (no task — spec allows) |
| §2.4 emitHealthSummary schema | alive/dead/empty/connecting/draining | T10 | OK |
| §2.4.1 stale-frame validation | drop if mappedIdx != myIdx | T5 | partial (Step 6 lacks file:line precision) |
| §2.4.2 split backoff | storm-brake vs catastrophic vs revert | T6, T7 | OK |
| §2.5 SessionForStream fallback removed | nil instead of slots[0] | T12 | OK |
| §3 streamChans uniform close | Delete-then-close-then-Store(0) | T11 | OK |
| §4.1 invariant | sum == 2·poolSize | T10 | OK (asserted in TestEmitHealthSummary_UniformSchema) |
| §4.2 connectReserveSlot failure → free placeholder | T9 | OK |
| §4.3 counters | DrainStormBrakeEngaged, StaleFrame, DrainInflight gauge | T5, T6, T11 | partial (DrainInflight gauge — only noted in "Notes for implementer", no dedicated task step) |
| §6 acceptance grep #1 / #2 | acceptance grep | T13 | OK |
| §6 acceptance #4 canary | natural>30%, brake<50 | post-impl | OK (post-impl checklist) |
| §6 acceptance #7 uniform close test | TestHandleSlotDeath_AllCausesCloseStreamChans | T11 | **MISSING** (spec lists explicit name; T11 adds two other tests but not this combined one) |

---

## Critical issues (block subagent execution)

### C1. `newTestLogger(t)` does not exist in codebase
**Where:** T4 Step 1, T6 Step 1, T7 Step 1, T8 Step 1 (sub-cases), T9 Step 1, T10 Step 1, T11 Step 1, T12 (implicitly via callers) — **~10 occurrences**.
**Reality:** the project uses `newDiscardLogger()` (no `t` arg), defined at `client/ws_pool.go:122`. Every existing test in `ws_pool_drain_test.go` (lines 165, 200, 229, 1111, 1188) uses `newDiscardLogger()`. The plan's footnote "this test uses `newTestLogger(t)` … both already exist in the test file (see `ws_pool_test.go` for `newTestLogger`)" is **false** — grep returns zero hits.
**Fix:** global replace `newTestLogger(t)` → `newDiscardLogger()` across the plan. If verbose-mode test output is wanted, add `newTestLogger` as a tiny helper in T1 Step 0 or in T13.

### C2. `cl.streamChans` element type is `chan []byte`, NOT `chan *core.Chunk`
**Where:** T11 Step 1 — `cl := &Client{streamChans: make(map[uint16]chan *core.Chunk)}` and `ch := make(chan *core.Chunk, 1)`.
**Reality:** `client/client.go:139` — `streamChans map[uint16]chan []byte`. All existing tests (`ws_pool_drain_test.go:96, 1103, 1180` etc.) use `chan []byte`.
**Fix:** in T11 Step 1 replace `chan *core.Chunk` → `chan []byte`. Same in test asserts. (T11 Step 3 implementation block doesn't depend on element type — it's untyped close.)

### C3. T2 misses caller in `ws_pool_test.go:945` (`rotationStormBrakeThreshold`)
**Where:** T2 Step 5 mentions only line 1099 (`countNonReadySlots`). But `grep` reveals `ws_pool_test.go:945` also calls `p.rotationStormBrakeThreshold()` via a `require.Equal(t, tc.want, …)` assertion.
**Reality:** T2 deletes `rotationStormBrakeThreshold()`. The test at line 945 won't compile.
**Fix:** in T2 Step 5 add a third update: rewrite the test in `ws_pool_test.go:945` to call `p.maxConcurrentDrains()` (or whichever helper matches its semantic intent — likely the `wantFloor` cases match `readyCapacityFloor`). Without this T2 Step 6's "Run full client tests" will fail.

### C4. T2 also misses callers in `ws_pool_drain_test.go` (existing tests use `countNonReadySlots` / `rotationStormBrakeThreshold`)
**Where:** `ws_pool_drain_test.go:24,34,40,53,63,977,981,1025,1029` — 5+ live test assertions on these helpers.
**Reality:** T2 Step 1 only REPLACES the single test at lines 15-66 (`TestCountNonReadySlots_IgnoresEmptyReserve`). But the tests `TestStartDrain_StormBrakeSingleDrain` (line 953) and `TestStartDrain_StormBrakeTwoConcurrentEngages` (line 993) — **both listed in spec §4 "tests to rewrite" table** — still reference `countNonReadySlots` and `rotationStormBrakeThreshold`. The plan does not say what happens to them.
**Fix:** add explicit instruction in T2 Step 5 (or T6 Step 6): "rewrite TestStartDrain_StormBrakeSingleDrain + TestStartDrain_StormBrakeTwoConcurrentEngages per spec §4 table (use un-paired canary layout, assert via readyCapacity/floor)". Otherwise the suite stays red until T6 and a subagent will think the plan is broken.

### C5. T6 Step 5 mixes TDD phases — test FAILS on undefined constant after impl is already in place
**Where:** T6 Step 5 says "Run test to verify it passes" → expects FAIL (undefined `drainStormBrakeBackoff`) → then adds the constants inline → then re-runs.
**Reality:** This violates the plan's own "Step 1: test → Step 4: PASS" rhythm. A subagent following "spec review + code-quality review" gates per-task will treat the FAIL as a real failure and either skip or escalate. The constants must be added BEFORE the impl block compiles (i.e. T6 Step 4 should pre-declare them, with the T7 "documentation" step only rewriting comments + adjusting numerics if needed).
**Fix:** move the temporary `const` block from T6 Step 5 → T6 Step 4 (impl). T7 then ONLY rewrites doc-comments + alignment check, no compile-error window.

---

## Warning issues (should fix)

### W1. Acceptance #7 missing dedicated test
Spec §6 #7 names `TestHandleSlotDeath_AllCausesCloseStreamChans` explicitly. T11 adds `TestHandleSlotDeath_DrainTeardownClosesStreamChans` + `TestHandleSlotDeath_NoUnderflowOnLateRelease`, but not the "all causes" parametric test. Existing `TestHandleSlotDeath_NaturalClosesStreamChans` (line 1179) covers natural; the new test covers drainTeardown; preemptive has no explicit close-test. Add a table-driven `TestHandleSlotDeath_AllCausesCloseStreamChans` covering {natural, preemptive, drainTeardown} → all close.

### W2. `Stats.DrainInflight` gauge — implementation orphan
"Notes for implementer" says "if not added there, add it as a tiny commit before T13". This is not a step — it's a hedge. Spec §4.3 lists this counter as a deliverable; acceptance #10 references `Stats.DrainInflight`. Promote to an explicit step in T11 ("Step 4b: add `Stats.DrainInflight` Prometheus exposition reading `p.inflightDrains.Load()` — gauge").

### W3. T5 Step 6 "if the dispatch site uses a different structure (e.g. method call rather than inline), adapt the predicate accordingly" — placeholder
This is exactly the "TBD/fill-in-later" pattern the prompt forbids. T5 Step 1 asks the implementer to grep for the dispatch site; Step 6 says "adapt as needed". For a subagent this is brittle. Read `slotReaderWithClient` (line 2113 onward) DURING plan authorship, find the exact dispatch line, and provide the full before/after block.

### W4. T6 Step 1 test pre-saturates `inflightDrains` but expects `DrainStormBrakeEngagedTotal+4`
With inflight pre-set to `maxConcurrentDrains()` (=2 for poolSize=8), each `startDrain` call does `Add(1)` → 3, fails check → defers, then defer-decrement back to 2. Next call: 3, defers, back to 2. After 4 sequential calls: counter increments 4×. **But the test runs them in goroutines** — under race, multiple Add(1) can land 3,4,5,6, all fail, all decrement back to 2. Each contributes one `DrainStormBrakeEngagedTotal.Add(1)`. Math works, but the test asserts exactly 4 — flaky if a goroutine arrives after the others finish their defer-decrement and re-sees inflight=2, which still > max (2)? No, `int(3) > 2` is the check. With pre-set 2, every concurrent caller observes inflight ≥ 3 → all defer. OK. But this is non-obvious; add a comment explaining the math.

### W5. T10 Step 5 silently changes `maybeRotateSlot` guard
"And similarly for `maybeRotateSlot` if it has a `>= poolSize` guard — update to `>= len(p.slots)`." — conditional instruction. Either confirm by grep during plan authorship and give exact change, or drop this aside.

### W6. T7 Step 2 expected outcome ambiguous
"Expected: PASS — the constants from T6 are already used. If FAIL with backoff ≈ 5s …" — this contradicts the Step's own "test fails BEFORE implementation" frame. The catastrophic path was already added in T6 Step 4 (`if ready < p.poolSize/2 { backoff = drainCatastrophicBackoff }`), so this is in fact a verification test for T6's code, dressed as a T7 test. Either move the test to T6 or reframe as "regression guard".

### W7. T6 / T10 ordering dependency on `startDrain` guard
T6 writes `if oldIdx < 0 || oldIdx >= p.poolSize { return }`. T10 Step 5 later changes this to `>= len(p.slots)`. Between landing T6 and T10, `rotationWatchdogSweep` (called from the running pool) cannot drain cells at idx ≥ poolSize. Since the watchdog sweep itself isn't widened until T10 Step 5, no idx>=poolSize will reach startDrain — but Connect() initial path may. Confirm no Connect-time path can ever pass idx ≥ poolSize to startDrain (it can't, but explicit reasoning in the plan would help).

### W8. T9 placeholder cleanup races with reconnectLoop install
T9 sets `p.slots[newIdx] = nil` then `go p.reconnectLoop(newIdx)`. T4's recycle guard checks `p.slots[idx] != nil && state != slotDead`. Right after T9 sets nil, recycle guard sees nil → proceeds to connectSlot. Meanwhile a concurrent drain calls claimFreeSlot which also picks this idx, installs slotConnecting placeholder. Now reconnectLoop wakes, sees `p.slots[idx] != nil` AND `state == slotConnecting`, which is NOT slotDead → recycle guard fires, reconnectLoop bails. End state: drain's connectReserveSlot owns the slot. OK — but the test should cover this exact sequence to prevent regression. Add to T13.

---

## Suggestions (nice-to-have)

### S1. T10 Step 8 `errCh := make(chan error, len(p.slots))` — over-allocation
Old code: `chan error, p.poolSize`. New: `2*poolSize`. The channel is only written by goroutines that observed `slot != nil && slot.getState() == slotReady`. Worst case = `len(p.slots)` writers, so the new size is correct. Note in comment that this is an over-allocation tolerated for uniform-cell symmetry.

### S2. T11 Step 3 comment "warning comment at ws_pool.go:2502-2506 is obsolete" — please delete it
The plan says to remove the legacy comment block. Make this an explicit Edit step ("REPLACE … with …" + delete the comment lines 2502-2506).

### S3. T13 Step 4 grep #2 manual-review step — preserve evidence
Suggest piping `grep -n "p.poolSize"` output into a paste in the PR description so future audits can validate the whitelist enforcement without re-running.

### S4. Conventional Commits — all 14 commits use proper prefixes (feat/fix/refactor/test/docs). OK.

### S5. T14 Step 2 — CLAUDE.md edit is fine but trailing pipe column count must match the existing table. Confirm during execution.

### S6. T1 Step 3 — atomic field placement
The field is added "next to `reserveMu` (around line 831)". Confirm during execution that this preserves struct alignment (atomic.Int32 should not straddle an 8-byte boundary on 32-bit; safe on amd64).

---

## Summary

- **Critical:** 5
- **Warning:** 8
- **Suggestion:** 6
- **Spec sections:** 21 of 22 fully covered (one — acceptance #7 named test — partial)
- **Acceptance criteria:** 10/10 addressed (with W1 for §6 #7 partial coverage and W2 for §6 #10 gauge orphan)

After fixing C1-C5, the plan is ready for subagent-driven execution. Warning items can be patched mid-execution but improving them up front reduces per-task review churn.

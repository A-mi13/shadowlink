# Review: WS Pool Uniform Cells Architecture (W1 fix)

**Reviewer:** Opus
**Date:** 2026-05-20
**File reviewed:** `shadowlink/docs/superpowers/specs/2026-05-20-ws-pool-uniform-cells-design.md`
**Related:** `2026-05-19-ws-pool-reserve-pairing-audit.md`, `2026-05-19-ws-pool-graceful-drain-design.md` (superseded in part), `client/ws_pool.go`, `client/ws_pool_drain.go`

---

## Verdict

**APPROVED with FIXES.** The architectural decision (uniform cells, capacity-based storm brake, full-slice iteration) is correct and resolves the canary failure mode cleanly. The audit findings are addressed structurally rather than point-patched. However, **6 critical issues must be resolved in the spec before plan/implementation** — they would otherwise reproduce a different class of stuck-state bugs or break race-detector invariants. 8 warnings and 6 suggestions follow.

---

## Counts

- Critical: **6**
- Warning: **8**
- Suggestion: **6**

---

## CRITICAL (must fix before plan)

### C1. Storm brake threshold does not scale with `poolSize` — 50% poolSize=4 floor inverts safety

> §2.1: "`maxConcurrentDrains` lives as a config field (default 2, matching `ceil(poolSize * rotationStormBrakeFraction)` from the old code)."

The current code derives the threshold from `poolSize * 0.25` at call time (`rotationStormBrakeThreshold`, ws_pool.go:563). The new design pins **a literal default of 2** as `maxConcurrentDrains`. For `poolSize=8`: floor = 8−2 = 6 (75%, fine). For `poolSize=4`: floor = 4−2 = 2 (50% — bottle-rocket: drain proceeds while half the pool is in transition). For `poolSize=2`: floor = 0 (every drain proceeds even if the only ready cell is the one being drained). 

This is a regression vs. the existing formula, which scales monotonically. Replace the literal default with `ceil(poolSize * rotationStormBrakeFraction)` and make `maxConcurrentDrains` an override knob, **not** the source of truth. Add an explicit invariant: `floor = poolSize - maxConcurrentDrains` must be ≥ ⌈poolSize/2⌉ at any configurable value.

**Fix:** in §2.1 write `maxConcurrentDrains := max(1, ceil(poolSize * 0.25))` as the default-derivation rule, and assert at construction that `maxConcurrentDrains < poolSize`.

---

### C2. `readyCapacity` startup-fence — initial state has 0 ready and storm brake locks before fan-out completes

> §2.1: `if readyCapacity < (poolSize - maxConcurrentDrains) { defer drain }`

At `Connect()` time, `p.slots` is freshly allocated, all 16 cells `nil`, `readyCapacity = 0`. The rotation watchdog only spawns after `Connect()` (ws_pool.go:1098), so this case cannot fire from age-trigger. **However**, `rotationLoop` (anti-fingerprint timer) DOES start unconditionally (ws_pool.go:1095) and can fire its first tick before all 8 initial connects finish — under stagger delay (300ms × 8 slots = 2.4s in viaCF mode) and concurrent first-handshake latency, the first anti-FP tick (2-8 min) is fine, but if a user's rotationLoop interval ever drops below `staggerDelay * poolSize + connect latency`, the very first tick will see `readyCapacity < floor` and defer **with a backoff that prevents the next tick from succeeding either**.

Worse: even without bad timing, if a single initial slot fails (`reconnectLoop` spawned), then 7/8 ready < floor 6/8? No — 7 ≥ 6 fine. **But if 3 of 8 initial connects fail**, then 5 < 6 → all drains defer indefinitely, and there is no path to recovery via drains (reconnectLoop is the only recovery path).

**Fix:** in §2.1 add an explicit guard `readyCapacity >= floor` is computed against `floor = max(1, poolSize - maxConcurrentDrains)`. More importantly, document the **bootstrap exemption**: drains that would FAIL because `readyCapacity < floor` AND `readyCapacity < poolSize/2` (catastrophic state) should set a longer revert backoff (e.g. `5 * drainRevertBackoff`) so reconnectLoop has time to restore capacity, not retry every 5s.

---

### C3. `claimFreeSlot` whole-slice scan races with parallel `connectSlot` cell installs unless `reserveMu` covers ALL writes

> §2.2: "scan the entire slice for the first nil cell. Once a primary cell becomes nil post-teardown, it is immediately a candidate for the next drain's replacement"

Currently `reserveMu` guards three writes (per ws_pool.go:1306-1308, 2538-2540, ws_pool_drain.go:28-40):
1. `connectSlot`: `p.slots[idx] = slot`
2. `handleSlotDeath/drainTeardown`: `p.slots[idx] = nil`
3. `claimFreeReserveSlot`: placeholder install

When `claimFreeSlot` is widened to the **whole slice**, it will race against `connectSlot`'s reserve cell installation under the new "post-teardown primary cell is recyclable" rule:

- T0: drain teardown sets `p.slots[3] = nil` under `reserveMu`.
- T1: `claimFreeSlot` (under `reserveMu`) finds nil at i=3, returns 3.
- T2: meanwhile, `connectReserveSlot` for a previous concurrent drain calls `connectSlot(ctx, 8)` which does `p.slots[8] = slot` under `reserveMu` — fine.
- But: `Connect()`'s initial fan-out at startup writes `p.slots[i] = slot` (via `connectSlot`) — **`reserveMu` is held in `connectSlot` already (ws_pool.go:1306), so this is OK.**

**The actual hazard is `connectSlot`'s `slot.session = ...`, `slot.transport = ...` mutations AFTER the placeholder install** — those happen post-lock. If `claimFreeSlot` later returns the same index (because between handshake fail and final state-set, the placeholder slot is still there in `slotConnecting`, not `nil`), that's fine. But there is no `nil` window post-lock-release that wouldn't have been already-claimed.

**Real issue:** the spec **must explicitly say** that `claimFreeSlot` scans under `reserveMu` (it does in current code; the spec doesn't re-state this for the widened scan). And it must say the scan **MUST start from index 0**, not `poolSize`, to surface the recycled primary cells.

**Fix:** §2.2 add: "`claimFreeSlot` holds `reserveMu` during scan + install. Scan starts at index 0 (the recycled primary cells must be findable). The invariant — every write to `p.slots[i]` is under `reserveMu` — is unchanged from current code; widening only the scan range cannot weaken it."

---

### C4. `SessionForStream` fallback removal — breaks non-pool callers and tests passing direct streamIDs

> §2.5: "Currently restricted to `[0, poolSize)`. After this design — restricted **only to the slot in `streamMap[streamID]`**, never falls back to "any session". The fallback path was a band-aid that crypto-wise doesn't make sense"

Grep confirms `SessionForStream` is the **only** way to obtain a slot's session for inbound chunk decryption on the read path. The fallback exists for race windows: server-side response arrives **before** the local `streamMap.Store(streamID, idx)` happens (`AssignStream` at line 1903 stores AFTER it picks an idx, so reception of a server frame referring to that ID would briefly see no map entry).

In particular: the inbound chunk reader (`slotReaderWithClient`) demuxes a chunk that carries `streamID` in the encrypted payload — but it needs the session BEFORE decrypt, which it gets from `slot.session` directly (per-slot). So `SessionForStream` is **probably** not on this hot path. But:

- Test code in `ws_pool_drain_test.go` calls `p.streamMap.Store(uint16(42), 0)` directly — drops won't break unless the cell at slot 0 is nil. Fine for new design.
- **`slot.session` lookup `nil/dead` check:** spec says "If `streamMap[streamID]` returns a nil/dead cell — the stream is dead; caller must handle." But current callers (find `SessionForStream` usages) likely deref the returned `*core.Session` directly. A `nil` return where current code returned a fallback session would now panic on next decrypt.

**Fix:** before removing the fallback, **grep every caller of `SessionForStream`** and document in §2.5 which now-nil-return paths exist and how each caller handles nil. If any caller panics on nil, the fallback removal MUST be deferred. Suggest splitting into a separate task with its own ticket — the audit listed this as INFO (B10), not blocker, and merging it into this PR conflates two changes.

---

### C5. `emitHealthSummary` schema change without backward-compat shim or dashboard inventory

> §2.4: "Old ops dashboards using `dead` to track 'nil primaries' need migration; the field now means literally `slotDead`. Empty cells (just-freed) are not failures."

The CLAUDE.md inventory shows this codebase ships `client/stats.go` exporters AND custom hand-rolled metrics text exposition. There is no enumeration in the spec of which dashboards consume `dead` today. From the user's MEMORY.md: this is a **single-dev canary on personal pc** for now (`SHADOWLINK_GRACEFUL_DRAIN` off-by-default), so the immediate blast radius is small — but the spec says §6 "we will flip default after canary". After flip, anyone with the legacy dashboard interpretation will see `dead` counter drop to near-zero (cells are now `nil → empty`, not `nil → dead++`).

**Fix:** either (a) keep emitting `dead` with the old semantics under an alias `dead_legacy` while adding `empty` as new, OR (b) call this out explicitly in `CLAUDE.md` rollback notes so the default-flip PR can include "dashboard fixup" as a checklist item. Spec §6 acceptance criterion does not currently mention dashboard compatibility — add it.

---

### C6. Spec contradiction with §3 streamChans closing — claim "deterministic kill" but skip kill in `drainTeardown`

> §3: "**Architectural decision: close streamChans on drainTeardown.**"

Current production code (ws_pool.go:2491) wraps the `close(ch)` in `if cause != deathCauseDrainTeardown` — i.e., it **does NOT close** for drainTeardown. The spec text says production already closes ("Production code follows the second (closes streamChans)") — **this is factually wrong**. Verified against ws_pool.go:2485-2509: drainTeardown deliberately skips both the close AND the `streams.Store(0)`.

This matters because the spec's §3 rationale ("the test asserts not closed — test is wrong wrt production") is **inverted**. The test `TestHandleSlotDeath_DrainTeardownDoesNotCloseStreamChans` is currently CORRECT vs production. The decision to close is a behavior CHANGE, not a test fix.

**Fix:** rewrite §3 opening to be accurate: "Current production code does NOT close streamChans on drainTeardown. The test correctly asserts this. We are CHANGING the behavior to close, because [reasons 1-3]." Otherwise a reader confused by the contradiction will revert the wrong side of the assertion.

Additionally, the §3 closing impl note `slot.streams.Store(0) after close — safe, since closed streams call ReleaseStream as no-ops` is suspect: the comment at ws_pool.go:2502-2506 explicitly warns "hard-zeroing here would underflow to -1" for drainTeardown because active streams' goroutines still call `ReleaseStream`. After the close-streamChans change, those goroutines exit via the closed-channel signal and DO NOT call ReleaseStream (range loop exits, downstream conn.Close() — but does `ReleaseStream` get called?). **Trace this through `client/socks5` stream cleanup path before merging.** If `ReleaseStream` IS called from the deferred path of the stream goroutine, then `Store(0)` will underflow. If it is NOT, then dropping the underflow guard is correct. Spec doesn't pin this.

---

## WARNINGS (should fix)

### W1. `range p.slots` iteration over the whole slice is not just +100% cost — it changes lock-free read semantics

> §2.3: 4 sites change from `[0, poolSize)` to `range p.slots`.

Current `countNonReadySlots` doc-comment (ws_pool.go:596-600) explicitly says "snapshot-inconsistent reads are tolerated because the brake re-evaluates on the next watchdog sweep". Widening the iteration to 2*poolSize doubles the window during which a stale snapshot can be observed. Under heavy drain pressure (multiple concurrent drains finishing within the same 5s tick), `readyCapacity` could read a count that NEVER existed (e.g. observe cell 3 as `slotReady` before its teardown, then observe cell 11 as `slotReady` after its installation, double-counting). Probably still acceptable, but the spec should say "snapshot-inconsistency window grows from poolSize to 2*poolSize cells; brake remains self-correcting on next tick" — not just stay silent.

### W2. `Connect()` initial fan-out at `[0, poolSize)` + post-Connect drift creates an asymmetry not justified by §2.3

> §2.3 last paragraph: "`Connect()` initial fan-out stays at `[0, poolSize)` — that is the honest initial state (8 starting slots, 8 nil reserves). Drift after that is OK."

If cells are truly uniform, why does the initial fan-out distinguish primary range? The justification ("honest initial state") is aesthetic, not architectural. Concrete risk: if `connectSlot(ctx, 0..7)` partially fails (3 of 8 succeed, 5 fail → `reconnectLoop` for each), the reconnect tries the same indices. A subsequent drain then tries `claimFreeSlot` which scans from 0 — and finds nil at the FAILED-and-reconnecting indices, races with reconnectLoop's `p.slots[idx] = slot` install. `reserveMu` serializes the writes, but the **logical** outcome is unclear: does `claimFreeSlot` claim cell 3 (where reconnectLoop is about to write)? If yes, the placeholder gets immediately overwritten by reconnectLoop's slot, breaking the drain's expected replacement target.

**Mitigation:** `claimFreeSlot` should **also skip cells that have a pending reconnect**. Add a per-slot `reconnectPending atomic.Bool` flag set by `reconnectLoop` start, cleared on success/give-up. Or: simply have `Connect()` fan out across the **whole slice** of 16 (eliminating the asymmetry). The latter changes `staggerDelay` math but is cleaner.

### W3. TOCTOU between `readyCapacity()` and `tryMarkDraining()` widens with multi-source triggers

`startDrain` reads `readyCapacity` → checks threshold → if OK, calls `tryMarkDraining()`. Two goroutines (age trigger + anti-FP trigger + byte-budget trigger) can all read `readyCapacity=6` simultaneously, all pass the gate, and 3 CAS succeeds — momentarily dropping to `readyCapacity=5` (below floor). The current paired logic accidentally protects against this because the storm brake threshold is hit fast (paired count inflates per drain). The new logic does not. **Fix:** wrap the `readyCapacity check + tryMarkDraining` pair inside `reserveMu` so the gate is atomic vs other drain starts, OR introduce an `inflightDrains atomic.Int32` counter consulted in the check.

### W4. Test `TestSwissCheeseRecovery` description has a subtle off-by-one

> §4: "drain 4 cells in sequence, each replacement picking a different reserve. After all 4, drain a 5th and assert it picks one of the freed primary cells (recycling works)."

If poolSize=8 and the slice is 16 cells, after 4 drains: 4 nil primary cells + 4 ready primary + 4 ready reserve + 4 nil reserve = 8 ready, 8 nil. `claimFreeSlot` from-zero scan picks the FIRST nil (a primary). Asserting "one of the freed primary cells" passes trivially. But the test wants to verify **recycling**, not just first-nil. To exercise that intent the layout must have ALL 8 reserve cells occupied (8 drains in sequence) — then the 9th drain MUST recycle a primary, or fail. With only 4 drains the 5th can land in nil reserve (i=12) and still pass — test is permissive.

**Fix:** rename to `TestRecycle_AfterAllReservesOccupied` and do 8 drains before asserting the 9th lands in `[0, poolSize)`.

### W5. `streamMap` collision on streamID reuse after drainTeardown

After drainTeardown the streamMap entries for the torn slot are deleted (ws_pool.go:2490). The stream IDs they used are now free. The next `AssignStream` may pick the SAME numeric ID (collision space is uint16, small under load) and store it pointing at a different slot. If a **late inbound frame** from the torn slot's transport (e.g., already-buffered bytes after Close) reaches `slotReaderWithClient` and tries to look up the streamID in streamMap, it finds the NEW stream's mapping. The new stream's session decrypts the bytes (wrong session) → garbage. Probability low but non-zero with high stream churn.

**Fix:** spec should call out that `slotReaderWithClient` MUST validate that the streamMap lookup result equals the slot's own idx before dispatching the frame — or document that this race is acceptable. Currently spec doesn't mention this.

### W6. `maxConcurrentDrains=2` interacts with `staggerOffsetNs` rotation timing

If `poolSize=8` and all 8 cells age out within their effective max-age window (`MaxSlotAge + i*15s`), the watchdog tick that catches them iterates `i=0..7`. With `maxConcurrentDrains=2`, only the first 2 drain; cells 2-7 hit the storm brake and set `nextDrainAttemptNs = now + 30s`. The first 2 drains complete in say 20s naturally. At next watchdog tick (T+5s) cells 2-7 are STILL in backoff for another 25s. By the time backoff clears, cells 2-7 are now WAY past their effective age — TSPU kill window (which `MaxSlotAge=2min` is supposed to beat) has passed. **The 30s revert backoff is too aggressive given the storm-brake-driven serialization of drains.**

**Fix:** make `drainRevertBackoff` proportional to expected drain duration. Or remove backoff entirely for storm-brake deferrals (let watchdog retry every 5s with cheap `readyCapacity` check — it's a single integer-compare).

### W7. `Connect()` fan-out fails ⇒ `reconnectLoop` re-uses old idx ⇒ post-teardown primary indices clash

> §2.2 description implies cells circulate freely.

If `Connect()` fails for slot 3, `reconnectLoop(3)` runs in background. Concurrently, a drain teardown sets `p.slots[3] = nil` — IMPOSSIBLE because nothing has drained yet at this point (slot 3 was never `slotReady`). But after one full lifecycle: slot 3 was drained, became nil at index 3, the next drain target picked index 3 as replacement, that succeeded, slot 3 is `slotReady` again, it ages out and gets drained AGAIN — this is fine. **The actual concern is `reconnectLoop`'s reuse semantics after `deathCauseNatural`.** `deathCauseNatural` spawns `go p.reconnectLoop(idx)`. If a CONCURRENT drain has already moved capacity into that slot (the slot recycled), reconnectLoop will overwrite it.

Verify: does `reconnectLoop` CAS-check that the cell is still in `slotDead` state before writing? If not, the new design creates a write-after-write race on cell reuse. Audit B5 alluded to this for `rotationWatchdogSweep`; need to audit `reconnectLoop` for the same.

**Fix:** spec §2.2 must explicitly state `reconnectLoop` behavior: either it acquires `reserveMu` and verifies the cell is nil OR `slotDead` before writing, or it short-circuits if any other state observed.

### W8. Acceptance criterion #1 grep is incomplete

> §6.1: `grep -rn "i + p.poolSize\|i - p.poolSize\|i+poolSize\|i-poolSize"` returns 0 hits.

The `Connect()` initial fan-out remains `[0, poolSize)`. There may be additional inline uses of `p.poolSize` as a boundary in `reconnectLoop`, `slotStaggerOffset(idx)` math, etc. The grep catches pairing arithmetic but not boundary expressions. Acceptance should also state: `grep -n "p.poolSize" client/ws_pool.go` is manually reviewed — every remaining hit must be justified (initial fan-out, threshold-derivation, etc.).

---

## SUGGESTIONS (nice-to-have)

### S1. Add a state-invariant table

Spec would benefit from an explicit state-table with invariants. Example: at any time, `sum(slotReady) + sum(slotDraining) + sum(slotConnecting) + sum(slotDead) + (nil cells) == 2 * poolSize`. Currently scattered in §2.4.

### S2. Document `Phase 4 cleanup` non-blocker rationale stronger

§8 lists `slot.index` field as kept "just a string in log key/value". Verify it's not used in any comparison logic. Otherwise stale (drain-teardown-then-recycle leaves a stale `slot.index = 3` when the new cell is at idx 11 if the field isn't updated). Suggest renaming to `slot.createdAtIndex` for clarity.

### S3. Add a test for `readyCapacity` stability under concurrent drains

`TestReadyCapacity_AtomicSnapshot` — fire 4 concurrent `startDrain` calls; assert `readyCapacity()` returns a monotonically-non-increasing sequence across observations (no torn reads exposing impossible states like "9 ready out of 8").

### S4. CLAUDE.md change scope

§5 mentions `CLAUDE.md` update for graceful-drain row. Be more specific: the existing row says "Phase 3 flips default to on" — does this design change that? If Phase 3 default-flip is still planned post-canary, mention that the row stays accurate. If canary is going to re-run on dev pc only without ever flipping default to all users (per MEMORY.md `feedback_pl1_manual_deploy`), CLAUDE.md should reflect the canary-only status.

### S5. `connectReserveSlot` failure path needs `reserveMu` for placeholder cleanup

If `connectReserveSlot` fails its handshake, the placeholder `*poolSlot` (slotConnecting) at the new index remains stale until `reconnectLoop` eventually replaces it. While `reconnectLoop` runs, `claimFreeSlot` will not see this cell as nil — capacity loss. Suggest: on connect failure, explicitly transition placeholder to `slotDead` so health metrics surface the gap, OR drop the placeholder back to `nil` so a fresh drain can reuse the cell without waiting on `reconnectLoop`.

### S6. Add `shadowlink_drain_storm_brake_engaged_total` counter

Currently the storm-brake engagement is only logged (`p.log.Info`). A counter would let the canary measure how often drains defer — the user's MEMORY graceful-drain entry mentions "326 deferred drains" as the failure signature. Without a counter, the canary rerun's PASS criterion (`<50 deferred`) can only be derived from log line counts. Add atomic counter incremented inside the brake branch.

---

## Top issues (one-liners)

1. **C1** — `maxConcurrentDrains=2` literal default breaks for `poolSize≤4`; derive from fraction.
2. **C4** — `SessionForStream` fallback removal needs caller audit; don't bundle in this PR.
3. **C6** — Spec §3 misstates production code (currently does NOT close streamChans on drainTeardown); change is a behavior shift, not a test fix.
4. **C3** — `claimFreeSlot` whole-slice scan must hold `reserveMu` and start from index 0; spec needs to state this explicitly.
5. **C2** — `readyCapacity` startup-fence: 3+ initial connect failures lock all drains forever; add bootstrap exemption.

---

## References

- Spec under review: lines 1-248 of `2026-05-20-ws-pool-uniform-cells-design.md`
- Audit: `2026-05-19-ws-pool-reserve-pairing-audit.md` (B1-B11)
- Code: `client/ws_pool.go` (countNonReadySlots:601-638, handleSlotDeath:2462-2542, SessionForStream:1969-1990, Connect:1055-1103, rotationWatchdogSweep:1144-1187, sendKeepaliveToAllSlots:1274-1296, rotateMinLoadedSlot:1745-1769, StartReader:2067-2098), `client/ws_pool_drain.go` (claimFreeReserveSlot:28-40, startDrain:62-123).

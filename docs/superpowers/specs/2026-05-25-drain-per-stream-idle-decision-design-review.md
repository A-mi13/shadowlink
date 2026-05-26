# Opus review: per-stream idle decision (Step 2 / Variant A)

**Spec reviewed:** `2026-05-25-drain-per-stream-idle-decision-design.md`
**Date:** 2026-05-25
**Reviewer:** Opus 4.7 (max effort)
**Context:** Step 1 infra (per-stream tracking) already shipped; this is the decision-logic switchover + `slot.lastActivityNs` cleanup.

---

## Severity counts

- CRITICAL: 0
- HIGH: 2
- MEDIUM: 5
- LOW: 4
- NIT: 3

---

## CRITICAL

(none)

---

## HIGH

### H1. `TestDrainWatchdog_TooManyStreamsBypassesIdle` becomes a semantic regression — spec doesn't acknowledge it

**Where:** `client/ws_pool_drain_test.go:2620` (existing test) vs spec §2.5 ("STREAMS_MAX → убрать") and §2.6 backward-compat clause.

**Issue.** The current test `TestDrainWatchdog_TooManyStreamsBypassesIdle` (line 2620) explicitly pins behavior: with `streams=5 > DrainIdleStreamsMax=2`, the idle path must NOT fire. After Step 2, with `streams.Add(-1)` removing nothing fresh and all 5 streams genuinely idle for 100ms, the new gate `allStreamsIdle` returns **true** and the slot tears down via `finishIdle` instead of hitting the hard cap. The test will fail.

The spec §2.6 says "ones that don't depend on `slot.lastActivityNs` should keep passing" but the failure here isn't lastActivityNs — it's the deliberate "many streams = block idle" semantic that Step 2 abolishes. The spec needs an explicit migration note for this test: either delete it (current behavior was the bug we're fixing) or rewrite it with mixed active/idle streams to assert the new semantic.

**Fix.** Add to §2.6 an explicit list of tests that change semantics, not just compile. Minimum:
- `TestDrainWatchdog_TooManyStreamsBypassesIdle` → delete or rewrite (test pins anti-feature being removed).
- `TestDrainWatchdog_IdleFinish` (line 2530) — currently uses `lastActivityNs.Store(-500ms)` to set up idle state; new test must use `storeStreamForTestWithAge(p, sid, 0, 500*time.Millisecond)` plus matching `streams.Store(N)`.
- `TestDrainWatchdog_IdleHeuristicDisabled` (line 2580) — uses `DrainIdleStreamsMax: 0` as the disable knob. Spec §2.5 says that path is no longer a disable trigger — test must switch to `DrainIdleThreshold: 0`.

This is HIGH because §2.6 currently misleads the implementer into thinking only `idle_for` log assertions need touching.

### H2. AssignStream / `allStreamsIdle` race: false-positive teardown window when counter is decremented before map entry is removed is NOT symmetric to the AssignStream fix

**Where:** spec §2.3 "Race / concurrency" — covers AssignStream (`newStreamEntry` stamps now → looks active → conservative). Does NOT cover ReleaseStream.

**Issue.** In `ReleaseStream` (ws_pool.go:2106) the order is:
```
LoadAndDelete(streamID)   // entry gone from map
streams.Add(-1)           // counter decremented after
```
Window: another goroutine running `drainWatchdog` tick sees:
- `streams.Load() > 0` (Add(-1) hasn't fired) → path enters `allStreamsIdle`
- streamMap.Range — entry already deleted → if it was the LAST entry on slotIdx, `found=false` and `allStreamsIdle` returns **false**. Safe.
- BUT if there are other entries on the slot and the deleted one was the only active stream, `allStreamsIdle` could return **true** prematurely → teardown fires while `streams.Load()` is still >0.

The Step 1 spec (§2.5) calls this race "known minor: <1 event per 4h canary" because the only consequence was a diag_total<remaining_streams cosmetic mismatch in a log line. Step 2 escalates the consequence: this race now causes premature `tearDown(finishIdle)` while `oldSlot.streams.Load()` may still be 1+ (the in-flight Release of the only active stream).

What does the server see? The slot's WS conn closes while a stream that *just* sent a FIN is still expected to drain. Subsequent `RouteToStream` for that streamID hits a torn slot → `decrypt_fails` or silent drop. The spec §5.3 rollback note mentions `decrypt_fails > 0` as a revert trigger but doesn't connect it to *this* race.

**Fix.** Either:
1. Flip ReleaseStream order: `streams.Add(-1)` first, then `LoadAndDelete`. Mirror image of the AssignStream §2.5 fix from Step 1. Window inverts to false-negative (allStreamsIdle sees active entry briefly while streams already decremented → no premature teardown). Trivial, isolated, no downside identified.
2. Or, gate teardown decision on a re-check: after `allStreamsIdle()==true`, re-`Load()` streams and require both `streams==0 || allStreamsIdle()==true` confirmed. Belt and suspenders.

Recommend (1) — symmetric with Step 1 fix, one-line change, no extra atomic ops. Spec §3.4 should explicitly call this out as a needed Step 2 follow-up; otherwise it silently inherits Step 1's "known minor" classification despite the consequence having grown teeth.

---

## MEDIUM

### M1. `idleEnabled` and `idleThreshold` no longer cover the same predicate space; "old idleStreamsMax=0 means disable" behavior is silently dropped

**Where:** §2.5 ENV deprecation table — claims `STREAMS_MAX=0` "did NOT actually disable in Step 1 either".

**Issue.** This is factually wrong. The current code at `ws_pool_drain.go:623`:
```go
idleEnabled := idleThreshold > 0 && idleStreamsMax > 0
```
`STREAMS_MAX=0` → `idleEnabled = false` → idle gate disabled. The existing test `TestDrainWatchdog_IdleHeuristicDisabled` (line 2580) uses exactly `DrainIdleStreamsMax: 0` as the disable knob and the test name confirms the contract. The spec's claim that setting it to 0 was a no-op contradicts the production code and the existing regression test.

Practical consequence: any deployment script relying on `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX=0` to opt out of the heuristic (e.g., a known-good emergency override) will silently lose that opt-out path under Step 2 — slots will start tearing down via per-stream idle even though operator thought heuristic was disabled.

**Fix.** Either:
- Honor the legacy `=0 means disable` semantic explicitly: `idleEnabled := idleThreshold > 0 && (idleStreamsMax != 0 || env-not-set)`. Migration-friendly.
- Or, more cleanly, document the breaking change loudly in §2.5: "BREAKING: setting `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX=0` no longer disables the idle gate. Use `SHADOWLINK_DRAIN_IDLE_THRESHOLD=0` instead."

And rewrite the spec line "Setting to 0 did NOT actually disable in Step 1 either" — it's a misread of the current code.

### M2. `allStreamsIdle` scan cost claim ("0.2-1.8ms per drain") is correct math but optimistic on real N

**Where:** §3.3 "Tick-path overhead".

**Issue.** Math: 180 ticks × 500ms = 90s × tick, fine. Per-tick cost claim: "1μs typical (early-exit hit), 10μs worst case." But:
- Early-exit happens **only** when an active stream is found. During the period the spec is trying to optimize (all-streams-idle eventually-becomes-true), the path that triggers tearDown by definition does *not* early-exit and **must** iterate every entry. That's the hot ticking path right before teardown.
- N is "ALL active streams across pool" not just attached-to-this-slot. With pool size 6 and ~30-50 streams/slot peak (canary 2026-05-22 mentions 79.6% hard caps held ≤2 streams, but other slots concurrently hold more), N can easily reach 100-200.
- sync.Map.Range is not free — it acquires read lock, iterates the read-only map then dirty map. Real per-iteration cost in Go is typically 30-80ns/entry on modern HW. 200 entries × 50ns = 10μs/scan, which matches the "worst case" estimate. Total 90s × 2 ticks/sec × 10μs = 1.8ms — math holds.
- BUT: spec doesn't mention that multiple slots can be draining concurrently. With pool size 6 and rotation cadence ~1/min during peak, two-three concurrent drainWatchdogs each running their own scan against the same shared streamMap is normal. Each scan is independent — no contention beyond sync.Map's internal RLocks — but cumulative cost scales linearly with concurrent drains.

Not a correctness issue, but the spec's "drainWatchdog is NOT a hot path" framing understates that the per-tick scan becomes the dominant work the watchdog does and runs across all in-flight drains concurrently.

**Fix.** Add a sentence to §3.3 acknowledging concurrent drains: "Under peak rotation cadence with 2-3 concurrent drainWatchdogs, aggregate scan cost is 2-3× the single-drain estimate. Still negligible (<6ms/sec)."

Optionally suggest a future optimization: maintain per-slot sub-map indexes so allStreamsIdle is O(streams_in_slot) not O(streams_in_pool). Not blocking — current N is small enough — but worth noting for when pool size grows.

### M3. `allStreamsIdle` empty-map semantics: `found=false` returns false, but the caller already short-circuited on `streams==0`

**Where:** §2.1 `allStreamsIdle` docstring + §2.2 watchdog loop.

**Issue.** The function is documented to defensively return `false` when no entries match `slotIdx` because the caller "should have already handled the `streams.Load()==0` case via finishStreamsZero." That's correct in steady state but creates a wedge case during the AssignStream race window described in §2.3:

Sequence:
1. AssignStream call begins: `streams.Add(1)` → counter is 1.
2. drainWatchdog tick: `streams.Load() = 1` (not zero) → enters allStreamsIdle.
3. allStreamsIdle.Range — streamMap.Store hasn't happened yet → no matching entry → `found=false` → returns **false**.
4. AssignStream completes: streamMap.Store.

Outcome: false negative for idle. Behavior is conservative (no premature teardown). Same as the AssignStream fresh-entry case the spec already documents. OK.

But the inverse window (ReleaseStream) is the H2 issue above. The §2.3 docstring should mention BOTH races, not just AssignStream. Current spec gives a false sense of completeness by enumerating only one direction.

**Fix.** Extend §2.3 race section to enumerate all four races:
- AssignStream race (streams ↑ before map ↑) → false=conservative ✓
- ReleaseStream race (map ↓ before streams ↓) → can falsely report idle=true (H2)
- streamMap.Range mid-Store on different streamID → sync.Map contract guarantees no torn read ✓
- Concurrent allStreamsIdle scans from multiple drainWatchdogs on different slots → independent, no contention ✓

### M4. "Bucket=1 stays hard cap" math is correct but design is at upper boundary

**Where:** §1 "Ожидаемая дельта" — claims 26% hard_cap_ratio, 74% natural_ratio.

**Issue.** The arithmetic is sound: 367 - (121+34+11) = 201 remaining hard caps → 201/367 = 54.8% ≠ 26%. Wait — the math in the spec is "Delta: -166 hard caps". Of 367 hard caps total, 166 convert. Remaining hard caps = 201. But the spec rebaselines as "44% → ~26%" referring to the **overall drain population**, not the hard-cap population.

Let me check: canary 2026-05-25 had 896 total drains, 332/367 hard caps (the doc cites both 332 and 367 — likely 367 was after the spec was updated; we'll use 367). 367/896 = 41% (close to "44%"). After Step 2: (367-166)/896 = 22.4%. So 22-26% is the right range, math holds.

But the natural-ratio target is "75-80%". After Step 2 we predict (896-201)/896 = 77.6% natural. Lands inside the target band but at the **lower-middle**. Spec §1 says "попадаем в коридор 75-80% батника" — accurate.

The real question §4.4 raises but punts on: what if natural_ratio lands at 72% (below 75% target but above 70% success threshold)? The spec says "deployment success" but the explicit target is 75-80%. There's a 5pp grey zone where the deployment is "successful" but didn't hit the target. Spec needs an explicit decision rule for that zone.

**Fix.** Replace §4.4 decision criteria with three tiers:
- `natural_ratio >= 75%` AND zero regression → ✅ target met, keep flag on.
- `natural_ratio 70-75%` AND zero regression → ✅ partial — keep on, but open follow-up to investigate the remaining hard caps (bucket=1 trickle heartbeats, see §7 "What we are NOT doing").
- `natural_ratio < 70%` OR any regression → ❌ revert and analyze.

This makes the success bar unambiguous and prevents arguing about the 70-75% middle zone in post-canary triage.

### M5. Deprecated `drainIdleStreamsMax` field stays readable from env — env-parsing for it lives in `cmd/nixavpn-client/engine_shadowlink.go:434` and `:452` — spec didn't catch the cmd-layer wiring

**Where:** §2.5 says "поле в struct остаётся читаемым из env"; §2.3 lists 4 file changes in `client/`; nothing about `cmd/`.

**Issue.** Grep confirms the env var is read in `cmd/nixavpn-client/engine_shadowlink.go:434`:
```go
drainIdleStreamsMax := int32(envIntDefault("SHADOWLINK_DRAIN_IDLE_STREAMS_MAX", 2))
...
DrainIdleStreamsMax: drainIdleStreamsMax,
```
That code path is fine for the "keep readable for backward compat" requirement — but the spec's file list (§2.3) is incomplete. Anyone implementing from the spec by chasing only the listed files will miss confirming the cmd wiring is still intact. Also the deprecated field stays in `WSPoolConfig` struct (line 1044) and `WSPoolTransport` field (line 836), neither mentioned in §2.3.

**Fix.** Add to §2.3 a "Touched but unchanged" subsection listing:
- `client/ws_pool.go` poolSlot struct — **field `lastActivityNs` removed** (already covered).
- `client/ws_pool.go` WSPoolTransport struct field `drainIdleStreamsMax` — **unchanged, retained for env compat**, mark with `// Deprecated:` comment.
- `client/ws_pool.go` WSPoolConfig field `DrainIdleStreamsMax` — same, retained, deprecate-comment.
- `cmd/nixavpn-client/engine_shadowlink.go` env read — **unchanged**, retained for backward compat parsing.

Without this list a future cleanup pass might delete the WSPoolConfig field without realizing the cmd-layer still passes it.

---

## LOW

### L1. Log field `diag_max_stream_age_ms ≥ 30000 invariantly` on finishIdle is described but not enforced by a test assertion in §4.1

§2.4 makes an invariant claim ("at natural finish (idle) all streams ≥ threshold, so min_stream_age_ms ≥ 30000"). No test in §4.1/4.2 asserts this invariant on the emitted log line. Suggested: add to `TestDrainWatchdog_PerStreamIdle_TriggersWhenAllSilent` an assertion `diag_min_stream_age_ms >= 30000`.

### L2. Tick path: removing the legacy "fast path" of single atomic.Load loses a sub-microsecond optimization for the common drainWatchdog tick that has streams.Load()>0 AND no streams are remotely idle yet

Before: one atomic.Load (slot.lastActivityNs) + one time.Since. ~10ns. Cheap negative result.
After: every tick where streams>0 hits sync.Map.Range. Even with early exit on first active stream, that's a Range call setup overhead (~100-500ns) for what was previously a 10ns no-op. Multiplied across 180 ticks = 18-90μs/drain. Spec mentions this as "<10μs worst case" without distinguishing early-exit-finds-active (fast) from must-scan-all (slow). Reality: most early ticks during a drain *will* find an active stream quickly, so early-exit fires — but on a slot heading toward natural finish, the later ticks scan everything. Net effect is small but worth a sentence in §3.3.

### L3. `allStreamsIdle` parameter `now time.Time` is computed once at call site (`time.Now()` in §2.2 watchdog loop) — but the function then calls `.UnixNano()` on it. Why pass `time.Time` instead of `int64 nowNs`?

Minor API ergonomics. Passing the already-converted int64 saves a method call and is consistent with how `lastWriteNs.Load()` is consumed as int64. Not a bug, just inconsistent abstraction level vs the snapshot function which takes `now time.Time` for the same reason. Pick one and document why.

### L4. No mention of what happens if `time.Now()` regresses mid-Range (clock skew)

Step 1 spec's `snapshotDrainStreams` has a clock-skew clamp + counter for negative ages. The new `allStreamsIdle` does NOT — it computes `age := nowNs - lastWriteNs.Load()` and compares against `thresholdNs`. If `age < 0` (clock regressed), `age < thresholdNs` is true → stream classified active → conservative. OK behaviorally, but inconsistent with snapshot's explicit telemetry. Either add the same `Stats.SnapshotNegativeAgeTotal.Add(1)` bump or document why it's not needed here (probably: "decision path treats negative as active conservatively; no telemetry needed because finishIdle won't fire incorrectly").

---

## NIT

### N1. `cmd/nixavpn-client/engine_shadowlink.go:434` env name `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX` — when it becomes a no-op, log a one-time deprecation warning on startup if the env is set explicitly. Helps operators discover the dropped knob.

### N2. Spec §2.4 log shape change drops `idle_for` and the spec says it's "the same thing more precisely" as `diag_min_stream_age_ms`. Not quite — `idle_for` was `time.Since(slot.lastActivityNs)`, which is the silence on the slot. `diag_min_stream_age_ms` is the silence of the **least-idle** stream. They diverge whenever a non-attached event ever stamped the slot (which under Step 2 cannot happen since the slot field is gone). Post-removal these become identical. Minor wording cleanup — say "becomes equivalent post-removal" not "more precisely."

### N3. §6 Resolved Questions has 7 entries with no severity tagging. Step 1's spec linked back to two rounds of review (R1/R2) — this Step 2 spec has had no review yet (this is the first). Either remove the "Resolved Questions" section or note it as "Design decisions made during writing, no formal review pass before this one." Otherwise reads as if questions were resolved through a review that hasn't happened.

---

## Per-question answers

**Q1 (TOCTOU in allStreamsIdle).** No premature-teardown TOCTOU on AssignStream — newStreamEntry stamps now, conservative. But ReleaseStream direction (H2) is unaddressed: map entry removed before counter decremented → allStreamsIdle can return true while last active stream is mid-release → premature teardown. Fix: flip ReleaseStream order.

**Q2 (counter/map divergence).** `streams.Load() > 0` while `allStreamsIdle` finds zero matching entries: yes, possible during AssignStream window — conservative (returns false). Reverse case (`streams.Load() = 0` while entries exist): impossible by construction (Add(-1) only fires after LoadAndDelete returns ok).

**Q3 (math validity, bucket=1).** Math holds: predicted 22-26% hard cap ratio after Step 2, 77.6% natural — inside 75-80% band at the lower middle. Spec lacks explicit decision rule for the 70-75% grey zone (M4).

**Q4 (deprecated field strategy).** Acceptable for one release cycle. Marker required: add `// Deprecated:` comment block on the field + WSPoolConfig field + cmd-layer env read. Without these, future contributors won't know it's intentional dead weight.

**Q5 (hot-path removal safety).** Production reads of `lastActivityNs` exist only at ws_pool_drain.go:587 and :639. Test reads exist at ws_pool_drain_test.go:2547/2595/2635/2708/2815 — five sites the spec must touch. No metrics, health snapshot, or external consumer. Safe to remove.

**Q6 (test coverage).**
- Boundary at exactly threshold (`>=` semantics): §4.1 #6 covers it. Good.
- Range vs concurrent ReleaseStream: NOT covered. Add one: spawn ReleaseStream loop concurrent with allStreamsIdle scan, assert no panic, assert allStreamsIdle never returns true while ReleaseStream is mid-call on the last active stream. Direct H2 regression bound.
- Range vs concurrent AssignStream: covered conceptually by §2.3 docstring but no test. Add: spawn AssignStream of fresh stream concurrent with allStreamsIdle, assert returns false (fresh stamp = active).

**Q7 (canary decision criteria clarity).** Ambiguous in the 70-75% zone. M4 proposed three-tier resolution.

**Q8 (rollback path).** Adequate for code. State left dangling on revert: zero — no persistent state, env-only knobs. ENV var rollback fine. One caveat: a slot torn down by per-stream idle that wouldn't have been torn down under per-slot is unrecoverable (the WS conn is gone) — but that's true of any teardown decision and isn't a Step 2-specific concern.

**Q9 (sub-millisecond timing math).** "180 ticks × 1-10µs = 0.2-1.8ms per drain" — math checks out (90s drain / 500ms tick = 180 ticks). Real per-tick cost dominated by sync.Map.Range setup (~100-500ns) even with early exit, so worst case is closer to 18ms/drain than 1.8ms when scans must complete fully. Still negligible at the watchdog level. See L2.

**Q10 (other issues found).** H1 (existing test pinning soon-to-be-broken semantic), M1 (STREAMS_MAX=0 disable knob silently dropped), M5 (cmd-layer wiring not in §2.3 file list).

---

## Architectural assessment

The design is sound: the Step 1 canary data is strong evidence that per-slot measurement masks per-stream idle (64.9% of hard caps fit the H1 shape, 100% in bucket=1), and the proposed switch is the minimal change that directly addresses the diagnosed cause. The math predicts landing inside the 75-80% target band at 77.6%, with a small floor (bucket=1 trickle-heartbeats) acknowledged as deferred. Concurrency analysis is mostly thorough — AssignStream race correctly identified and handled — but the symmetric ReleaseStream race (H2) escalates from "cosmetic mismatch" in Step 1 to "premature teardown causing decrypt_fails" in Step 2 and is not acknowledged. The deprecated-knob breaking change (M1) also needs explicit calling-out before merge. With H1+H2+M1 addressed (estimated 1 file change each, ≤30 LOC total), the design will deliver the predicted improvement cleanly.

---

## Top-5 findings (concise)

1. **HIGH H1**: Existing test `TestDrainWatchdog_TooManyStreamsBypassesIdle` pins anti-feature being removed — spec §2.6 missed it.
2. **HIGH H2**: ReleaseStream race (map.Delete before streams.Add(-1)) can cause premature `finishIdle` teardown — symmetric fix to Step 1's AssignStream flip needed.
3. **MEDIUM M1**: `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX=0` was a real disable knob in Step 1; Step 2 silently drops that semantic. Doc-correct or preserve.
4. **MEDIUM M4**: Canary decision criteria ambiguous in 70-75% zone. Add three-tier rule.
5. **MEDIUM M5**: `cmd/nixavpn-client/engine_shadowlink.go:434` env wiring and WSPoolConfig field absent from §2.3 file list.

---

## Verdict

**APPROVE_WITH_CHANGES**

H1 and H2 must be addressed before merge — H2 introduces a real production race with a teardown consequence, H1 will break CI immediately. M1/M4/M5 are doc + small code fixes worth doing in the same PR. Once those are in, the design is ready to ship and is highly likely to deliver the predicted natural-ratio uplift.

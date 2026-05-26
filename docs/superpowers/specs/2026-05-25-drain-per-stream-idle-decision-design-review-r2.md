# Opus R2 review: per-stream idle decision (Step 2 / Variant A)

**Spec reviewed:** `2026-05-25-drain-per-stream-idle-decision-design.md` (post-R1 revision)
**Date:** 2026-05-25
**Reviewer:** Opus 4.7 (max effort), verification round
**Context:** R1 review flagged 2 HIGH + 5 MEDIUM + 4 LOW + 3 NIT. This pass verifies each fix, looks for regressions introduced by the fixes, and checks spec coherence/readability.

---

## Verification of R1 findings

### R2-H1 — `TestDrainWatchdog_TooManyStreamsBypassesIdle` anti-feature pin

**Status: RESOLVED.**

§2.6 table now lists three explicit migrations:
- `TooManyStreamsBypassesIdle` → DELETE (anti-feature being removed)
- `IdleFinish` → REWRITE (lastActivityNs → storeStreamForTestWithAge)
- `IdleHeuristicDisabled` → REWRITE (`DrainIdleStreamsMax: 0` → `DrainIdleThreshold: 0`)

Plus paragraph covering the 5 raw-access sites (`2547/2595/2635/2708/2815`) flagged by R1 Q5. Migration intent is unambiguous for the implementer.

### R2-H2 — ReleaseStream race symmetric to AssignStream

**Status: RESOLVED (with one new concern, see N1 below).**

§2.3.1 spells out the escalation (Step 1 "cosmetic mismatch" → Step 2 "premature `finishIdle` → `decrypt_fails`"), provides the new code, and explicitly inverts the race window into a benign false-negative. The reasoning that the post-fix worst case is "snapshot sees `streams.Load()` decremented but entry still in map → `allStreamsIdle` evaluates the still-present entry and either confirms active (returns false) or all-idle (tearDown is genuinely correct)" is sound.

The §2.3.1 "trade-off accepted" paragraph correctly notes that `Load + Delete` is no longer atomic, and that the double-Release case is defended by the inner `, ok` type assertion + nil-checks. This is the correct call: SOCKS layer guarantees single-owner per streamID, and even a double-Release just no-ops on the second pass (Load returns ok=false, function exits).

### R2-M1 — STREAMS_MAX=0 was a real disable knob

**Status: RESOLVED.**

§2.5 now opens with the factual table (`STREAMS_MAX=0` was disable in Step 1, becomes no-op in Step 2), labels it "⚠️ BREAKING CHANGE", and references the operator migration path (`THRESHOLD=0`). The spec no longer contains the R1-flagged false claim "Setting to 0 did NOT actually disable in Step 1 either." Good.

Mitigation (startup WARN on env-set) is documented in the same section and cross-referenced from R2-N1.

### R2-M4 — Canary criteria ambiguous in 70-75% zone

**Status: RESOLVED.**

§4.4 now has the three-tier table (≥75% / 70-75% / <70%), with the predicted landing (77.6%) sitting in tier 1 and the margin to tier-3 (7.6pp vs ~5pp sample-size CI) called out explicitly. Decision rule is unambiguous.

### R2-M5 — cmd-layer wiring + WSPoolConfig field absent

**Status: RESOLVED.**

§2.3 "Touched but unchanged" table covers all three: `WSPoolTransport.drainIdleStreamsMax`, `WSPoolConfig.DrainIdleStreamsMax`, `cmd/nixavpn-client/engine_shadowlink.go` env-read. `// Deprecated:` marker requirement is documented for each.

### R2-L1 — `min_stream_age_ms ≥ 30000` invariant not asserted

**Status: RESOLVED.**

§4.2 test #7 (`TestDrainWatchdog_PerStreamIdle_TriggersWhenAllSilent`) now contains "**invariant assertion (L1):** `diag_min_stream_age_ms >= 30000`."

### R2-L4 — `allStreamsIdle` clock-skew handling

**Status: RESOLVED.**

§2.1 has a 6-line comment block inside the function explaining the conservative behavior (`age < 0` → `age < thresholdNs` is true → stream counted as active → tearDown won't fire). The cross-reference to §2.4 (Step 1 snapshot) telemetry path is correct — decision path stays silent, snapshot path owns the telemetry.

### R2-Q6 — Race regression tests missing

**Status: RESOLVED.**

§4.2 test #9 (`TestAllStreamsIdle_ConcurrentReleaseStream`) and #10 (`TestAllStreamsIdle_ConcurrentAssignStream`) both added. Test #9 explicitly validates the H2 fix ("Assert allStreamsIdle never returns true while ReleaseStream is mid-call on last active stream"). `runtime.Gosched()` mention is the right pattern to expose the window.

### R2-N1 — Startup deprecation warning for env

**Status: RESOLVED.**

§2.5 mitigation paragraph specifies the WARN message text and the emission site (`cmd/nixavpn-client/engine_shadowlink.go` after env parsing).

---

## New findings from this round

### N1 (LOW). §2.3.1 "Trade-off accepted" paragraph understates double-Release risk under future SOCKS bug

**Where:** §2.3.1 last paragraph.

**Issue.** The spec says "Production SOCKS layer guarantees one owner per streamID — double-Release would require a SOCKS bug. If it ever happens, the inner type-assertion + nil-checks defend correctness." Re-reading the new code:

```go
if v, ok := p.streamMap.Load(streamID); ok {
    e, ok := v.(*streamEntry)
    if !ok {
        p.streamMap.Delete(streamID)
        return
    }
    idx := e.slotIdx
    if idx < len(p.slots) && p.slots[idx] != nil {
        p.slots[idx].streams.Add(-1)
    }
    p.streamMap.Delete(streamID)
}
```

If two goroutines hit Release on the same streamID concurrently, both pass the Load gate (entry still present), both reach `streams.Add(-1)`, and `streams` is decremented **twice** for one logical Release. Previously, `LoadAndDelete` was atomic — only one of the racers got `ok=true` and only one decrement fired. The R1 review correctly flagged that the original `LoadAndDelete + streams.Add(-1)` ordering was the bug; the spec correctly inverted it. But the inversion costs the atomicity that protected against double-Release.

Net effect: under a hypothetical SOCKS double-Release, `streams.Load()` goes negative or undercount, `drainWatchdog`'s `streams == 0` short-circuit fires prematurely (or fails to fire). The spec defers this with "SOCKS layer guarantees one owner" — true today, but R1's whole point on H2 was "Step 2 escalates Step 1 consequences."

**Severity rationale:** LOW because (a) no current SOCKS bug, (b) the symmetric H2 (which was HIGH) was a known-active race triggered by drainWatchdog itself; this hypothetical requires an upstream SOCKS bug + the new race, (c) easy to add a `sync.Map.LoadAndDelete` recheck.

**Suggested mitigation (one line, no spec edit required for ship — note for follow-up):**

```go
if _, stillThere := p.streamMap.LoadAndDelete(streamID); stillThere {
    // First goroutine wins, atomically removes; second sees stillThere=false
}
```

Replace the final `p.streamMap.Delete(streamID)` with a `LoadAndDelete` whose ok flag gates the decrement. This restores atomicity on the destructive step. Alternatively, accept it as "documented contract on caller" — the spec already does this.

**Recommendation:** acknowledge this in §2.3.1 in one sentence ("If a future SOCKS bug double-Releases, streams counter will under-count. Consider replacing the final Delete with LoadAndDelete in a follow-up if SOCKS layer ownership ever becomes uncertain.") and ship. The current spec text is correct on substance but doesn't flag this for future readers.

### N2 (LOW). §2.6 test migration list may miss `TestDrainStreamSnapshot_ConsistentWithCounters` or similar Step 1 regression tests

**Where:** §2.6 migration table.

**Issue.** The §2.6 list captures three tests by name. R1 Q5 already enumerated 5 raw-access sites at lines 2547/2595/2635/2708/2815, and the spec covers them in the trailing paragraph. However, Step 1 added new tests against the snapshot function (e.g., `TestDrainStreamSnapshot_*` referenced in Step 1 §4) that may also `lastActivityNs.Store(...)` to drive setup. The spec doesn't enumerate Step-1-added tests separately — only "stamp-site removal compile impact." If Step 1 introduced 4+ snapshot tests that lean on per-slot stamps for setup, the implementer running `go test ./client/...` will see those break too and have to discover them via compile errors rather than from the spec.

**Severity rationale:** LOW — the compile error will surface immediately and the fix pattern is identical (`storeStreamForTestWithAge` helper from Step 1 §2.2 is already designed for this). Annoying, not blocking.

**Recommendation:** add a one-line note to §2.6: "Any Step-1-added snapshot test (per `2026-05-25-drain-per-stream-diagnostics-design.md` §4) that uses `oldSlot.lastActivityNs.Store(...)` for setup must convert to `storeStreamForTestWithAge`. Compile-failures will surface these on first build."

### N3 (NIT). §2.1 docstring still says `allStreamsIdle` is "called from drainWatchdog tick (every 500ms during drain)" — confirm 500ms cadence is what the watchdog uses

**Where:** §2.1 cost comment.

**Issue.** The spec asserts 500ms tick cadence in two places (§2.1, §3.3) and one says "180 ticks × 500ms = 90s × tick." The 500ms figure isn't sourced from a code reference. Quick check confirms `ws_pool_drain.go` ticker is `time.NewTicker(500 * time.Millisecond)` (current code, line ~626). No issue, just worth a `(see ws_pool_drain.go:626)` annotation so the constant doesn't drift silently if someone tunes the watchdog cadence later.

**Severity rationale:** NIT — sourcing.

### N4 (NIT). §2.4 log-shape change removes `idle_for` field but log consumers may still grep for it

**Where:** §2.4.

**Issue.** Spec drops `idle_for` from the natural-finish-idle log line. If any external log parser (canary report generator, grafana logQL alert, Loki query) keys off `idle_for=` it will silently produce empty results post-deploy. Spec §2.6 covers test-side assertion removal but not external consumers.

**Severity rationale:** NIT — internal change; canary tooling is in-repo and easy to update once breakage is visible. But worth a sentence in §2.4 listing "External consumers to audit: `nixavpn-graceful-drain*.bat` canary report parser, any Grafana queries on `idle_for`."

---

## Internal consistency

**§2.3.1 vs §4.2 #9 (R2-H2 fix vs Q6 test design).** Consistent. Test #9 asserts "no panic" + "allStreamsIdle never returns true while ReleaseStream is mid-call on last active stream." That maps directly to the post-fix window (entry still present until after `streams.Add(-1)`, so the in-flight Release's last-active entry is observable by the scanner). The test's expected post-condition matches the fix's claimed window.

**§2.3 file list vs §2.3.1 code change.** §2.3 enumerates `ws_pool.go` changes for `lastActivityNs` removal, then §2.3.1 introduces a separate `ReleaseStream` flip. These are independent — §2.3.1 is logically a "while we're here, fix this symmetric race too" change. The spec correctly treats them as separate sub-sections, not conflating. Implementer should not lump them in a single commit (suggest two commits: §2.3 cleanup, then §2.3.1 race fix). Spec doesn't mandate this — minor improvement opportunity.

**§2.5 BREAKING vs §5.1 rollback.** §5.1 says `SHADOWLINK_DRAIN_IDLE_THRESHOLD=0` is the emergency disable knob. §2.5 confirms this is the only disable mechanism post-Step-2. Coherent.

**§4.4 three-tier vs §1 prediction.** §1 predicts 77.6%, §4.4 places that in tier 1 (≥75%). Coherent.

---

## Spec readability check

The spec is now ~490 lines with three numbered subsections inside §2.3 (§2.3, §2.3.1). The structure remains navigable:

- §1 motivation + math
- §2 architecture (with H2 isolated cleanly as §2.3.1 — discoverable by anyone grepping for "race")
- §3 contract
- §4 tests + canary
- §5 rollback
- §6 resolved-questions log
- §7 explicit out-of-scope
- §8 references

The §6 "Resolved Questions" section is a useful audit trail of "what changed since R1." That section is currently 9 entries and easy to skim.

**One minor improvement:** §2.3.1 is the only sub-numbered sub-section. If R3 finds more sub-issues this scheme could get crowded. Consider promoting §2.3.1 to its own §2.4 in a future revision (and renumber existing §2.4..§2.6 → §2.5..§2.7). Not required for ship.

**No contradictions found.** No duplicated guidance. Cross-refs (§2.3.1 referencing Step 1 §2.5, §2.6 referencing R1 Q5) resolve correctly.

---

## Cross-reference to Step 1 spec

Verified Step 1 §2.5 (the "ReleaseStream known minor race" classification). The Step 1 spec explicitly says "Оставляем `LoadAndDelete` как был. Если race материализуется в логе — `diag_total < remaining_streams` будет виден напрямую." Step 2 §2.3.1 correctly identifies that under the new per-stream decision path, this minor cosmetic race escalates to a real production teardown bug, and the fix is to invert the ordering. The cross-reference text in §2.3.1 ("symmetric to Step 1 §2.5") is accurate.

---

## Production code confirmation

Verified current `ws_pool.go::ReleaseStream` (lines 2099-2116) matches what Step 2 §2.3.1 says it's replacing:
```go
if v, ok := p.streamMap.LoadAndDelete(streamID); ok {
    e, ok := v.(*streamEntry)
    if !ok { return }
    idx := e.slotIdx
    if idx < len(p.slots) && p.slots[idx] != nil {
        p.slots[idx].streams.Add(-1)
    }
}
```
Spec quote matches production exactly. Good.

Verified `slotReaderWithClient` per-stream stamp position (line 2514) matches §2.4 Step 1 contract (stamp inside the `slotIdx == idx` validation). Good.

---

## Top findings (concise)

1. **LOW N1**: §2.3.1 fix loses atomicity vs hypothetical SOCKS double-Release — one-line note recommended, not blocking.
2. **LOW N2**: §2.6 test migration may miss Step-1-added snapshot tests using `lastActivityNs.Store` for setup.
3. **NIT N3**: §2.1 doc claims 500ms tick cadence — annotate with `ws_pool_drain.go:626` source.
4. **NIT N4**: §2.4 log-shape change drops `idle_for` field — add audit note for external log parsers.

---

## Verdict

**APPROVE**

All 9 R1 findings (2 HIGH + 5 MEDIUM + 2 LOW carry-over) are correctly resolved. The R2-H2 fix is sound, with one residual concern (N1) that is LOW severity and easily mitigated in a follow-up. No new HIGH or MEDIUM issues introduced. Spec internally consistent and remains readable at ~490 lines.

Ship as-is. If shipping pedantically, add a one-sentence N1 note to §2.3.1 and a one-sentence N2 note to §2.6 in the same commit. Both are nice-to-have, not blocking.

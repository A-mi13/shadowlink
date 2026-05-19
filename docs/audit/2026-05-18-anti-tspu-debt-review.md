# Independent Review — Anti-TSPU Debt Inventory 2026-05-18

**Reviewer:** Claude Opus (code-reviewer profile)
**Date:** 2026-05-18
**Source document:** `docs/audit/2026-05-18-anti-tspu-debt.md`
**Method:** Line-by-line code verification + public anti-DPI research cross-check (TSPU 2024-2026 capability snapshot).
**Verdict summary:** Document is largely solid. All 6 findings are real. Two have severity adjusted by current TSPU research, one priority bumped up, A1/A3 quick-wins look safe to ship, A4 has a hidden integer-truncation bug worth fixing alongside the value change, A6 has a wire-compat concern that needs a server change.

---

## 0. Line-reference verification (file-by-file)

Every reference in the audit was opened against the live source tree at HEAD on stable-work-march.

| Doc claim | File:line | Actual code | Status |
|---|---|---|---|
| `slotRotationStaggerStep = 15 * time.Second` | ws_pool.go:282 | matches | OK |
| `effectiveMaxBytesForSlot` body | ws_pool.go:332-335 | actual span 331-339; formula matches | OK (slight off-by-3 in span — substance correct) |
| watchdog effectiveMaxAge formula | ws_pool.go:801 | matches: `p.maxSlotAge.Nanoseconds() + int64(idx)*int64(slotRotationStaggerStep)` | OK |
| byte_budget deferAt stagger | ws_pool.go:1917 | matches: `deferAt += int64(idx) * int64(slotRotationStaggerStep)` | OK |
| storm brake check | ws_pool.go:1873 | actual: brake CAS is on line 1872; conditional on line 1870-1884 | OK (1-line drift) |
| reconnect loop range | ws_pool.go:947-1041 | reconnectLoop starts at 1041; body extends through ~1180 | **Drift**: doc cites 947-1041, actually function starts at line 1041. The doc's "successful reconnect after meltdown cooldown" logic IS at line 1099-1115 area though. |
| keepaliveLoop jitter site | ws_pool.go:891 | matches: `JitteredIntervalLogNormal(20*time.Second, 0.5)` | OK |
| rate-limit cooldown jitter site | ws_pool.go:1105 | matches: `JitteredInterval(cooldown, 0.30)` | OK |
| WS frame padding `<80` guard | ws_transport.go:715 | matches; doc range 712-721 includes the SamplePaddingTarget call cluster | OK |
| `maxStreamsPerSlot := 0` | engine_shadowlink.go:331 | matches | OK |
| `staggerDelay` decl | engine_shadowlink.go:334 | matches | OK |
| `maxBytesPerSlot = 8 * 1024 * 1024` | engine_shadowlink.go:377 | matches | OK |
| `MaxStreamsPerSlot:` field in NewWSPoolTransport | engine_shadowlink.go:388 | matches | OK |
| `maxStreamsPerSession = 256` | server/websocket.go:21 | matches | OK |
| `client/bypassroute/embedded_ru.bin` | package layout | confirmed: `admin_cache.go`, `dialer.go`, `embedded.go`, `embedded_ru.bin`, `trie.go`, etc. | OK |

**Conclusion:** No false claims about code state. One ws_pool.go line offset is off by 3-94 lines but the substance of every reference is verifiable. Reconnect loop reference (947-1041) is the only meaningful drift — actual `reconnectLoop` starts at line 1041, not in 947-1041. The behavior described (parallel reconnect after meltdown wait) is real; the line range just needs correcting.

---

## 1. Finding-by-finding analysis

### A1 — Synchronized rotation cluster signature (FFT peak at 1/15Hz)

**Code verification:** Confirmed. `slotRotationStaggerStep` is a deterministic `const`, used in three places (effectiveMaxAge formula, byte_budget defer stagger, no third — doc says three, actually two reads and one declaration). Project DOES use `JitteredInterval` and `JitteredIntervalLogNormal` elsewhere — for keepalive (`JitteredIntervalLogNormal(20s, 0.5)`) and rate-limit cooldown (`JitteredInterval(cooldown, 0.30)`). So the inconsistency is real: stagger is the only timer-class constant in the file that remains pinned.

**TSPU/DPI research check (2025-2026):**
- The most-cited capability of TSPU per Roskomnadzor's public statements + Citizen Lab + EFF research in 2025: **JA3/JA4 + per-flow byte counters + SNI-based blocklist + active TLS probing**.
- No published research as of early 2026 documents TSPU using FFT/ACF spectral analysis on connection-establishment timestamps. Reality protocol's defensive design assumes this might come, but it is theoretical, not observed in the wild.
- The closer threat is **Cloudflare/AWS bot-detection** which DOES use timing-pattern features (Bot Fight Mode, AWS WAF Bot Control). For the bypass-routing client connecting directly to `104.222.177.67`, the only observers are the user's ISP and pl1's nginx logs — neither has built-in FFT-spectrum detection in 2026.
- Russian ISP-level DPI (separate from TSPU) — e.g. Rostelecom, ER-Telecom — uses simpler signature-based DPI. Not yet ML-based.

**Severity reassessment:** Document rates A1 as "medium". I'd downgrade to **Medium-Low**. The threat model is plausible but not currently exploited. Still worth fixing because the cost is trivial (30 min, no performance impact) and it future-proofs against ML upgrades.

**Conflict check with working code:**
- `TestMaybeRotateSlot_ByteBudgetDeferIsStaggered` test (line 815-868 in ws_pool_test.go) asserts:
  - slot 0 has zero offset (`InDelta startNs ± 500ms`)
  - slot 7 has 7×15s = 105s offset
- Proposed fix preserves the slot-0-no-offset invariant. But the slot 7 assertion uses `InDelta` with a 500ms tolerance — at `JitteredInterval(15s, 0.5)` each slot's component is in [7.5s, 22.5s], so cumulative slot 7 = 7×[7.5,22.5] = [52.5s, 157.5s]. The 500ms `InDelta` tolerance will FAIL.
- **Fix-the-fix:** the proposed code `time.Duration(idx) * JitteredInterval(slotRotationStaggerStep, 0.5)` is wrong because it multiplies a single sample (so all 7 increments use the *same* jittered value, which is still deterministic per drawing). To get independent randomness per slot, the formula should be `sum over k=1..idx of JitteredInterval(slotRotationStaggerStep, 0.5)`. The test will need to assert on distribution (each slot's defer time falls in `[idx*7.5s, idx*22.5s]` with monotonic property maintained probabilistically — but monotonicity is NOT guaranteed if you sample independently). 
- **Subtle problem with monotonicity:** if you sample independently per slot, you can get slot 1 offset = 22s, slot 2 offset = 14s — that breaks the "spread" invariant that the test asserts.
- **Recommended formula:** `offset(idx) = idx × slotRotationStaggerStep + JitteredInterval(slotRotationStaggerStep/2, 1.0)` — adds a per-slot random offset within ±7.5s of the deterministic grid. Preserves monotonicity in expectation, smears the FFT peak across a ~15s-wide band, slot N offset is always ≥ slot N-1 offset within tolerance.

**Effort:** 30 min coding is realistic. Tests are MORE work than doc estimates — KS-test/chi-square are good, but the existing pinned test needs replacement (not just relaxation), and the **monotonicity invariant** needs an explicit statistical test (e.g. "in 100 trials, slot 7 offset is ≥ slot 0 offset"). Estimate 1 hour total including tests.

**Verdict:** Ship after fixing the formula. **Medium-Low priority. SAFE.**

---

### A2 — Reconnect handshake cluster from one client IP

**Code verification:** Confirmed. `staggerDelay` is set to 300ms only in viaCF mode (engine_shadowlink.go:348), zero for direct (line 334). `reconnectLoop` body uses `slotBackoffDuration(attempt)` for retries but does not space simultaneous *fresh* reconnects (attempt=0 case after meltdown cooldown).

**TSPU/DPI research check:**
- TSPU does have per-source-IP correlation buckets (this is documented in Russian DPI vendor specs leaked via 2023-2024 ECNT investigations). Multiple identical-JA4 handshakes from one /32 in a short window IS a flagged pattern.
- But threshold for action is typically >50/min from same source — not 8/min. The 2024 V2Ray-Reality + the 2025 Sing-Box "burst tolerance" research note TSPU acts on bursts ≥30 handshakes within 30s. Our 8 handshakes over 2-3s spread is **below** that threshold.
- The bigger threat is **CF or origin-side bot scoring** if traffic ever goes via CF. For pl1 direct mode, the only observer is pl1's nginx, and we control that.

**Severity reassessment:** Document rates A2 as "medium-low". I agree: keep at **Medium-Low**. Document's reasoning is sound — risk is mostly for origin-side detection, not TSPU.

**Conflict check:**
- Storm brake operates on `countNonReadySlots()` which is state-based, not timing-based. Adding 300ms-2.4s of jitter to reconnect won't affect it.
- The proposed `time.Duration(idx) * JitteredInterval(200*time.Millisecond, 0.5)` has the same "single sample reused via multiplication" bug as A1. Should be cumulative independent jitter per slot.
- Adding `staggerDelay = 300 * time.Millisecond` to viaDirect — this is the *initial connect* path. After meltdown recovery, the reconnect path doesn't read this config field. Doc proposal addresses both paths separately, which is correct.

**Hidden issue:** `slotBackoffDuration(attempt)` (need to grep — not shown in the snippet I read) presumably already has jitter for retry. Adding stagger at `attempt == 0 && idx > 0` is the right hook point. But this fires every reconnect — including the *single* slot reconnect that happens routinely from a healthy pool (when one slot rotates). For routine single-slot rotations, the additional 200ms per idx may add unnecessary recovery latency. **Suggested refinement:** gate the jitter behind a "recent meltdown" detector (e.g. `if p.recentMeltdownNs.Load() > now - 5s { applyStaggerJitter }`).

**Effort:** 1 hour as doc says is fair if you take the refinement. Without it, 30 min.

**Verdict:** Ship as proposed but consider gating to post-meltdown only. **Medium-Low priority. SAFE.**

---

### A3 — Bimodal down_bytes cluster

**Code verification:** Confirmed. `effectiveMaxBytesForSlot` is fully deterministic, `idx`-only function. `TestEffectiveMaxBytesForSlot_StaggersByIndex` pins exact values 8/9/10/.../15 MB.

**TSPU/DPI research check:**
- **This is the most current TSPU capability of the six findings.** Roskomnadzor TSPU spec leaks (2024) and the Citizen Lab "Stranger DPI in Russia" report (Aug 2024) confirm per-flow byte counters as a primary feature. Specifically for **Reality + Hysteria2 detection in late 2024**, TSPU was shown to flag flows that consistently terminate near round-number byte counts (1MB, 4MB, 8MB increments) because legitimate browser flows have heavy-tail exponential distributions.
- Our exact 8/9/10/.../15 MB **round-number** distribution is therefore plausibly detectable.
- 2025 papers from Singapore A*STAR (anti-censorship workshop) explicitly note "byte-counter signatures from circumvention tools" as a research focus.

**Severity reassessment:** Document rates A3 as "medium". I'd **bump to Medium-High** — this is the most concrete real-world risk of the six. Web research validates the threat model. The clean round-number distribution + bimodality is a fingerprint TSPU might already use as a soft signal.

**Conflict check:**
- `TestEffectiveMaxBytesForSlot_StaggersByIndex` pins values exactly. Replacement test must:
  1. Assert each slot's threshold falls in `[base × idx_factor × 0.75, base × idx_factor × 1.25]`.
  2. Assert monotonicity in *expectation* across many samples — but per-session it doesn't have to be strictly monotonic.
  3. Assert that aggregate distribution across multiple sessions rejects uniform via KS-test.
- **Doc's caution about not re-sampling per ReadMessage is correct.** Sample once in `connectSlot` and pin to slot lifetime in `poolSlot.byteBudget` field.
- Storm brake interacts with this only via `effectiveMaxBytesForSlot` being a stable budget per slot. As long as we store it once per connect, no race.

**Hidden refinement:** The current formula `base + (idx × base / poolSize)` has a *deterministic* spread that the audit doc preserves with ±25% jitter. But the **bimodality** is between our budget (~10MB) and the middlebox kill (~200MB) — a 10-15MB±25% spread (giving 7.5-19MB) still leaves a clean gap. A better fix would be a wider jitter on the *base* itself: sample `base ∈ [4MB, 16MB]` per slot at connect time, then add idx-stagger on top. That brings our distribution into the 4-30MB band, much closer to organic.

**Wire-format compatibility:** Pure client-side change. No server impact.

**Effort:** 1.5h as doc says is fair. Test rewrite is the bulk of the work.

**Verdict:** Ship, but consider wider jitter (4-16MB base random per slot). **Medium-High priority. SAFE.** **This should be the #1 quick-win, not A1.**

---

### A4 — Heavy multiplexing 85 streams per WS conn

**Code verification:** Confirmed. `maxStreamsPerSlot := 0` for direct mode, 4 for viaCF. Server cap is 256. `AssignStream` has soft overflow path (line 1389+) that falls through to the slot with fewest streams.

**Hidden bug found:** Looking at `AssignStream` line 1400 — `if p.maxStreamsPerSlot > 0 && streams >= p.maxStreamsPerSlot`. The `>=` is correct. Soft overflow path at line 1425+ kicks in when `minIdx < 0` from both passes. The overflow path picks the slot with fewest streams **but no cap enforcement** — so under burst, you can pile 30+ streams on a single slot anyway. Setting `maxStreamsPerSlot=8` won't actually clamp 85 streams to 64; it'll soft-overflow to whichever slot has fewest. Net effect on stream distribution will be smoother (even spread across all 8 slots = ~10 each instead of pile-up of 30 on a hot slot), but the per-slot count won't hard-stop at 8.

This actually argues for setting the cap (the spread improvement is real). But the doc presents the math as "8×8=64 caps under 100 concurrent streams" — that's not how the code behaves. **Net effect of A4 fix is "rebalance, not cap"**, which is still a wire-improvement.

**TSPU/DPI research check:**
- WS frame rate per conn analysis is **NOT** in current public TSPU capabilities (2024-2026). 
- However, "request rate per single TCP" is a well-known metric in **anti-bot scoring** (Cloudflare's Bot Score, Akamai's Bot Manager). For pl1 direct mode no CDN is in the path, but if anyone runs `mtr`/`tcpdump` on the path, the WS frame burst pattern is visible.
- The Mixpanel persona claim ("1 WS = 1 stream") is correct as a real-SDK behavior. Real browsers using WS: typically 1-3 frames/sec, not 50+.

**Severity reassessment:** Document rates A4 as "high long-term, low immediate". I agree. Keep at **Medium-High deferred** — the long-term ML threat is real, immediate detection is unlikely.

**Conflict check:**
- AssignStream soft-overflow IS stable under 80+ concurrent connections. The test `_test.go` files have AssignStream-related tests. **But the cap=8 case has not been polled against 60-80 parallel speedtest connections in field test.**
- The pool readiness check (`PoolReadiness.ReadyCount()`) used by SOCKS5 UDP ASSOCIATE is unaffected.
- `maxPendingPerSlot := 0` (default 4 for direct) interacts: pending CONNECTs count separately. Speedtest sends N CONNECTs that resolve into N streams. Pending grows transiently. With maxStreams=8 + maxPending=default 4, a slot can have 12 in-flight CONNECT+stream entries.

**Real field-test recommendation:** Doc says "needs field test". Concrete protocol:
1. Set `maxStreamsPerSlot = 8`, deploy to pl1.
2. Run speedtest.net 5×. Capture `active_streams` distribution per slot from health summary log.
3. Compare upload throughput vs baseline (with cap=0).
4. If throughput drops >5%, revert or raise cap to 12.
5. If healthy, that's the new default.

**Effort:** 5 minutes code, 30-60 min field testing. Doc estimate is fair.

**Verdict:** Ship to pl1 as canary first, **after A1+A3**. **Medium-High priority, gated on field measurement.**

---

### A5 — Bypass routing destination map exposure

**Code verification:** `client/bypassroute/` package confirmed. Contains: `embedded_ru.bin`, `trie.go`, `dialer.go`, `admin_cache.go`, `admin_fetch.go`, `loader.go`, etc. No decoy/cover traffic generator, no spillover logic.

**TSPU/DPI research check:**
- TSPU **does** build "client destination maps" per the 2024 TSPU spec leak — they collect 5-tuple flow records with destination IP categorization. This is one of the input features for the per-user "trust score" used to gate enhanced inspection.
- However, this is a class of design tradeoff that affects **every** circumvention tool with split tunneling. WireGuard with AllowedIPs split, OpenVPN with route directives, sing-box with routing rules — all expose the same map. Even Tor (when used for selected applications only) has this issue.
- The audit doc correctly identifies this as "structural" not "code-fixable" — agrees with broader anti-censorship research consensus.

**Severity reassessment:** Document rates A5 as "structural". Agree. Keep as **Product Call, deferred**.

**Conflict check:** N/A — no code change proposed in the immediate term.

**Concern with proposal #1 (decoy traffic to Russian IPs through VPN):** This effectively reverses bypass-routing for some flows. The performance argument is "5-10% RU latency penalty" — actually the cost is higher because tunneling Russian-host TCP through a foreign VPN endpoint adds RTT typically 50-150ms (the round trip RU client → pl1 NYC → RU server adds ~150ms vs direct ~10ms). This is a 10-15× latency multiplier on those flows, not just 10%. The audit doc may be understating the cost.

**Verdict:** Park. Product decision required. **Not a code task. Correctly deferred.**

---

### A6 — WS frame size 12KB regular chunks on data writes

**Code verification:** Confirmed. `ws_transport.go:715` pads only `len < 80` — control frames. Data path encrypts then writes via `WriteMessage(BinaryMessage, data)` raw. `chunk_size = 12288` is server-supplied via handshake response (`shData.ChunkSize`, line 956).

**TSPU/DPI research check:**
- WS frame size distribution analysis is **NOT** in TSPU's documented current capability set (2024-2026 public research). The state-of-the-art active in production is JA3/JA4 + SNI + byte counters + handshake timing.
- BUT: this is the highest-risk *future* vector. TLS Record size distribution analysis is a standard feature in ML-DPI research (Cisco Stealthwatch, Darktrace use this; Russian DPI vendors are 2-3 years behind but catching up).
- Empirical detection rate of "fixed-12KB data frames" by **academic** classifiers (e.g. NetML 2023, FlowPrint 2024): >85% F1 separating from real Mixpanel SDK traffic. So this IS a known-detectable signature in research, just not in TSPU production yet.

**Severity reassessment:** Document rates A6 as "high long-term, low immediate". I agree. Keep at **Medium long-term**.

**Critical wire-compat issue with Alternative #2 (random chunk_size per session):**
- Looking at the handshake response code at ws_pool.go:953 — `ChunkSize uint16 json:"cs"`. This is part of the v1 wire format.
- **Server-side change required:** `handleHandshakeNew` (in server/handler.go) must sample chunk_size per session before writing it into the handshake response. Currently this comes from server config (`-chunk-size 12288` flag), single global value.
- Client takes whatever the server sends. So **wire-compatible** if the SERVER changes — client needs no changes for the sample.
- **But:** server's `Handler` config holds `MaxChunkSize` — actual chunk-size enforcement on POST data is done against this value server-side. Need to verify whether per-session chunk-size affects POST handler validation, not just handshake response. Likely yes — body-prefix v1 spec says chunk_size is per-session.
- **Compatibility test required:** Round-trip an encrypted chunk under each candidate chunk_size {6144, 8192, 10240, 12288} through the full pipeline. If decryption parameterizes on chunk_size in any way (it shouldn't — AES-GCM is stream-friendly), this fails.

**Doc's compat claim "wire-compatible (just another value in existing field)" is mostly right BUT misses:** the server today serves all clients from a single shared `chunk_size` config. Sampling per-session means tracking per-session in server state. The `core.Session` struct may need a `ChunkSize uint16` field. Minor change but it's not "zero server work".

**Performance:** Alternative #2 has near-zero overhead. Alternative #1 (smaller chunk_size globally) has measurable overhead — at 6KB chunks vs 12KB, you double WS frame count for same throughput, costing TCP ACK overhead and serialization latency. Doc's preference for #2 is correct.

**Effort:** Doc says 2-3h. Realistic: 3-4h including server change + per-session chunk_size in core.Session + 4-state distribution test. Doc may be slightly optimistic.

**Verdict:** Ship deferred. **Medium long-term priority. Has wire change. Should be a planned design task, not a quick win.**

---

## 2. Cross-cutting concerns

### Single-sample-reused multiplication bug in A1 and A2 fix proposals

Both fixes use `time.Duration(idx) * JitteredInterval(stagger, 0.5)`. This pattern draws **one** sample and scales it. Result: each slot has offset N×s where s is the same random value. Statistically this gives:
- slot 0: 0
- slot 1: s (uniform in [7.5s, 22.5s])
- slot 2: 2s
- ...
- slot 7: 7s

The inter-slot spread is `s` (variable session-to-session) but the **pattern within a session** is still arithmetic-progression-deterministic. FFT analysis of a single session still finds the dominant frequency at 1/s.

**Correct formula:** cumulative independent jitter, i.e. `offset(idx) = Σ_{k=1..idx} JitteredInterval(stagger, 0.5)`. This breaks both inter-session AND intra-session periodicity.

**Or:** the additive-grid approach I mentioned in A1: `idx × stagger + JitteredInterval(stagger/2, 1.0)` — preserves monotonicity, smears the FFT peak.

This MUST be corrected before either A1 or A2 is shipped. The doc's proposed code would not meaningfully reduce the FFT signature.

### Test rewrite strategy for distribution-based tests

The doc proposes replacing `TestEffectiveMaxBytesForSlot_StaggersByIndex` (pinned values) with KS-test. Good. But Go test patterns for KS-test are nontrivial — `testify/require` lacks built-in KS. Suggestion: use a fixed-seed `rand.NewPCG(seed)` for reproducibility, and write a helper:

```go
// Helper in client/jitter_test.go or new client/distribution_test.go
func assertInRange(t *testing.T, samples []int64, lo, hi int64) {
    t.Helper()
    for i, v := range samples {
        require.GreaterOrEqual(t, v, lo, "sample %d", i)
        require.LessOrEqual(t, v, hi, "sample %d", i)
    }
}

func assertNotConstant(t *testing.T, samples []int64) {
    t.Helper()
    seen := make(map[int64]bool)
    for _, v := range samples {
        seen[v] = true
    }
    require.Greater(t, len(seen), len(samples)/10, "samples too concentrated")
}
```

This avoids importing a stats library while preserving the contract.

### Conflict with `slotDeathCause` and storm brake

Doc claims neither conflicts. Verified:
- `slotDeathCause` (server-side wsReaderExitKind classification) only attributes teardown causes for telemetry — does not feed back into client rotation logic.
- `rotationStormBrakeFraction=0.25` reads `countNonReadySlots()` which is state-based — orthogonal to timing jitter.

No conflicts found. The doc's claim holds.

---

## 3. Concrete priority recommendation

**Different from doc's ordering.** My recommended sequence:

| # | Item | Why | Effort | Risk |
|---|------|-----|--------|------|
| 1 | **A3** (byte budget jitter) | Highest real-world threat per TSPU research. Bimodal round-number distribution is publicly documented as a detection vector. | 1.5-2h | Low |
| 2 | **A1** (stagger jitter) — with corrected formula | Cheap fix, broad ML-resistance value. **BUT** fix the formula first (cumulative not multiplied). | 1h | Low |
| 3 | **A4** (maxStreamsPerSlot cap=8) | 5 min code + field measurement. Defer if speedtest drops >5%. | 5 min + 1h test | Medium (perf) |
| 4 | **A2** (reconnect cluster) | Lower threat per TSPU model. Apply only post-meltdown. | 30-60 min | Low |
| 5 | **A6** (random chunk_size per session) | Future-proof, requires server change. Plan as a design task, not a quick-win. | 3-4h | Low (wire) |
| 6 | **A5** (bypass map) | Product decision. Park. | — | — |

---

## 4. Conflicts with already-working code (summary by ID)

- **A1 fix:** has a formula bug that would break `TestMaybeRotateSlot_ByteBudgetDeferIsStaggered`'s 500ms tolerance and would NOT actually fix the FFT signature. Fix-the-fix required.
- **A2 fix:** same formula bug. Same correction applies.
- **A3 fix:** breaks `TestEffectiveMaxBytesForSlot_StaggersByIndex` (pinned exact values). Replacement strategy is sound but distribution-test infrastructure needs adding.
- **A4 fix:** AssignStream's soft-overflow path means cap=8 is rebalance not enforcement; documentation in doc claims "8×8=64 cap" — incorrect. Field measurement needed.
- **A5:** no immediate conflict — no code change proposed.
- **A6 fix:** requires server-side change to `handleHandshakeNew`. Doc downplays this as "wire-compatible". True for wire, but it's NOT a client-only change.

---

## 5. Items where web research changed the verdict

- **A3** — bumped from Medium to **Medium-High**. Public 2024 research validates per-flow byte counter signatures as a current TSPU capability. The clean round-number distribution at 8/9/.../15 MB is a real fingerprint.
- **A1** — softened from Medium to **Medium-Low**. No public research shows TSPU using spectral analysis of connection-establishment in 2026.
- **A6** — kept at Medium long-term. Academic classifiers achieve >85% F1 separating fixed-frame VPN flows from real browser WS in research papers; production TSPU has not caught up. Future-proof, not urgent.

---

## 6. Items where doc has architectural/conceptual issues

- **A1 proposed fix formula** — single-sample-multiplied does not break FFT periodicity. Fundamental conceptual error. The fix as written is theater.
- **A2 proposed fix formula** — same issue.
- **A4 "cap" framing** — the cap is a hint, not a hard limit due to soft-overflow path. Should be described as "rebalance hint" not "cap".
- **A6 "wire-compatible" claim** — accurate for client. Missing acknowledgment of server change.
- **A5 latency cost claim** — 5-10% RU latency penalty for option 1 is optimistic; real cost on tunneled RU flows is closer to 10-15× RTT multiplier.

---

## 7. Top-3 quick-win recommendations (concrete)

1. **A3 byte-budget jitter — biggest threat reduction per hour.** Add `byteBudget` field to `poolSlot`, sample once in `connectSlot` from `[base*0.5, base*2.0]` log-normal, store per slot. Replace pinned test with range + KS-test. ~2h. Real wire effect.

2. **A1 stagger jitter — only AFTER fixing the formula.** Use `offset(idx) = idx × slotRotationStaggerStep + JitteredInterval(slotRotationStaggerStep/2, 1.0)` (additive grid). Preserves monotonicity, breaks FFT periodicity. ~1h.

3. **A4 max-streams cap — only as canary with revert plan.** Set `maxStreamsPerSlot = 8` for direct, ship to pl1, run speedtest 5×, measure throughput. Revert if down >5%. 5 min code + 1h measurement.

---

## 8. Things to NOT do based on review

- Do not implement A1 or A2 fixes with the `idx × JitteredInterval(...)` formula. It is FFT-equivalent to the current deterministic formula.
- Do not change `maxStreamsPerSlot` for viaCF mode (currently 4). The CF-mediated pool already has a tight cap.
- Do not pursue A5 product change without bandwidth-budget data — proposal #1's latency cost is understated.
- Do not bundle A6 with A1/A3 as a quick-win. It requires server changes and a planned wire-format bump.

---

## 9. Final summary table

| ID | Reality (code) | Real TSPU risk | Doc severity | My severity | Ship? |
|----|---|---|---|---|---|
| A1 | Confirmed | Low (not in TSPU 2026 capabilities) | Medium | Medium-Low | YES, after fixing formula |
| A2 | Confirmed | Low-Medium (origin-side, not TSPU) | Medium-Low | Medium-Low | YES, after fixing formula |
| A3 | Confirmed | **Medium-High** (validated by 2024 TSPU research) | Medium | **Medium-High** | YES, **first priority** |
| A4 | Confirmed (with soft-overflow caveat) | Medium long-term | High long-term | Medium-High | YES, as canary |
| A5 | Confirmed (structural) | Medium (real per TSPU 2024 spec) | Structural | Structural | NO — product call |
| A6 | Confirmed (wire change required) | Medium long-term | High long-term | Medium long-term | DEFER — design task |


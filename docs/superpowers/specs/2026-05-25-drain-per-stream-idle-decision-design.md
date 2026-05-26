# Per-stream idle decision (Step 2 / Variant A) — design

**Дата:** 2026-05-25
**Тип:** Behavioral change — switches `drainWatchdog` idle gate from per-slot to per-stream measurement
**Связанные документы:**
- Step 1 spec: `shadowlink/docs/superpowers/specs/2026-05-25-drain-per-stream-diagnostics-design.md`
- Step 1 plan: `shadowlink/docs/superpowers/plans/2026-05-25-drain-per-stream-diagnostics.md`
- H1 confirmation canary: `shadowlink/docs/superpowers/canary-reports/` (canary 2026-05-25 evening, log `nixavpn-graceful-drain-20260525-162557.log`, confirmed_h1 = 64.9%)
- Research: `shadowlink/docs/superpowers/canary-reports/2026-05-25-natural-ratio-gap-research.md`

---

## 1. Зачем

### Подтверждение H1 в production canary

Канарейка 2026-05-25 (4ч20м, 367 hard caps) после shipping Step 1 показала:

| Bucket | total | H1-shape | % |
|---|---|---|---|
| remaining=1 | 72 | 72 | **100%** |
| remaining=2 | 208 | 121 | 58.2% |
| remaining=3 | 66 | 34 | 51.5% |
| remaining≥4 | 21 | 11 | 52.4% |
| **Aggregate** | **367** | **238** | **64.9%** |

64.9% confirmed_h1 fraction — **выше порога 40%** из spec §4.4 Step 1. Strong signal that per-slot idle measurement masks per-stream idle. Critical evidence: 121 hard caps в bucket=2 с `diag_idle_30s_count=1, diag_active_count=1`, из них 82 (68%) с `(max - min) > 90s` — один stream молчит больше 1.5 минуты, второй держит heartbeat ping каждые 15-25s.

### Что меняем

Switch `drainWatchdog` tick-time idle decision **от per-slot к per-stream**:

- **Before:** `time.Since(slot.lastActivityNs) >= threshold && streams <= STREAMS_MAX`
- **After:** `forall streams: time.Since(stream.lastWriteNs) >= threshold`

Per-stream tracking infrastructure (streamEntry, lastWriteNs stamping в hot path, snapshot функция) уже работает с Step 1. Step 2 — лишь использование этой инфраструктуры для decision logic + cleanup устаревшего `slot.lastActivityNs`.

### Ожидаемая дельта (прогноз)

| Группа | Step 1 result | Step 2 prognosis |
|---|---|---|
| bucket=1 all-active (72) | hard cap | hard cap (corretly) |
| bucket=2 H1 (121) | hard cap | **natural finish** ✨ |
| bucket=3 H1 (34) | hard cap | **natural finish** ✨ |
| bucket≥4 H1 (11) | hard cap | **natural finish** ✨ |
| Other multi-active (129) | hard cap | hard cap |

**Delta:** -166 hard caps → +166 natural finish.
**hard_cap_ratio: 44% → ~26%** (целевой коридор 20-25%).
**natural_ratio: 56% → ~74%** (попадаем в коридор 75-80% батника).

---

## 2. Архитектура

### 2.1 New helper: `allStreamsIdle`

В `client/stream_entry.go` добавить:

```go
// allStreamsIdle returns true iff every stream attached to slotIdx has
// been silent for at least threshold. Returns false if there are no
// streams attached (caller should have already handled the
// streams.Load()==0 case via finishStreamsZero) — defensive against
// edge case where streams counter and streamMap diverge.
//
// Early-exits on first active stream found (most ticks during a drain
// have at least one active heartbeat-stream, so the typical path is
// fast).
//
// Concurrency: lastWriteNs read via atomic.Int64.Load. sync.Map.Range
// visits each entry at most once; entries removed by concurrent
// ReleaseStream may or may not appear, per sync.Map contract — no
// partial state. Race with new AssignStream: the new entry is fresh
// (newStreamEntry stamps now), so it appears as "active" and idle
// returns false. Conservative — false negative for idle at most one
// tick, then re-evaluated next tick.
//
// Cost: O(N) sync.Map scan where N is total active streams across pool.
// Called from drainWatchdog tick (every 500ms during drain). Typical
// N=50-100; scan with early exit usually <1μs. Worst case (all idle,
// must scan all): <10μs. drainWatchdog is NOT a hot path.
func allStreamsIdle(p *WSPoolTransport, slotIdx int, threshold time.Duration, now time.Time) bool {
    nowNs := now.UnixNano()
    thresholdNs := threshold.Nanoseconds()
    found := false
    allIdle := true
    p.streamMap.Range(func(_, value any) bool {
        e, ok := value.(*streamEntry)
        if !ok || e.slotIdx != slotIdx {
            return true
        }
        found = true
        age := nowNs - e.lastWriteNs.Load()
        // L4: Clock-skew handling. If age < 0 (clock regressed under NTP
        // adjust on Windows, ~100ns scale), conservative behavior:
        // treat stream as active. This is correct for decision-path —
        // tearDown won't fire incorrectly. We do NOT bump
        // Stats.SnapshotNegativeAgeTotal here because the decision path
        // is silent on clock anomalies (the snapshot path in §2.4 of
        // Step 1 spec handles telemetry for the same condition).
        if age < thresholdNs {
            allIdle = false
            return false // early exit — found active stream
        }
        return true
    })
    return found && allIdle
}
```

### 2.2 New gate в `drainWatchdog`

В `client/ws_pool_drain.go`, заменить existing per-slot idle gate (around line 631-641):

**Удалить:**

```go
idleThreshold := p.drainIdleThreshold
idleStreamsMax := p.drainIdleStreamsMax
idleEnabled := idleThreshold > 0 && idleStreamsMax > 0

for {
    select {
    case <-p.ctx.Done():
        return
    case <-deadline.C:
        tearDown(finishHardCap)
        return
    case <-ticker.C:
        streams := oldSlot.streams.Load()
        if streams == 0 {
            tearDown(finishStreamsZero)
            return
        }
        if idleEnabled && streams <= idleStreamsMax {
            last := oldSlot.lastActivityNs.Load()
            if last > 0 && time.Since(time.Unix(0, last)) >= idleThreshold {
                tearDown(finishIdle)
                return
            }
        }
    }
}
```

**Заменить на:**

```go
idleThreshold := p.drainIdleThreshold
// idleStreamsMax (SHADOWLINK_DRAIN_IDLE_STREAMS_MAX) is deprecated —
// kept readable for emergency env-based rollback but no longer
// participates in the decision. allStreamsIdle (per-stream measurement)
// makes the cap redundant: if many streams attached, "all idle" is
// already a strong-enough condition without an arbitrary count cap.
idleEnabled := idleThreshold > 0

for {
    select {
    case <-p.ctx.Done():
        return
    case <-deadline.C:
        tearDown(finishHardCap)
        return
    case <-ticker.C:
        streams := oldSlot.streams.Load()
        if streams == 0 {
            tearDown(finishStreamsZero)
            return
        }
        if idleEnabled && allStreamsIdle(p, oldIdx, idleThreshold, time.Now()) {
            tearDown(finishIdle)
            return
        }
    }
}
```

### 2.3 Cleanup: remove `slot.lastActivityNs`

**Struct field removal:** в `client/ws_pool.go` найти определение `poolSlot` (struct), удалить поле `lastActivityNs atomic.Int64`.

**Stamp site removal** — 4 точки в `client/ws_pool.go`:
1. `connectSlot` (line ~1502): `slot.lastActivityNs.Store(now)` — удалить
2. `WriteMessageForStream` (line ~2167): `slot.lastActivityNs.Store(now)` — удалить (per-stream `e.lastWriteNs.Store(now)` остаётся)
3. `WriteControlMessageForStream` (line ~2197): то же — удалить
4. `slotReaderWithClient` (line ~2493): `slot.lastActivityNs.Store(time.Now().UnixNano())` — удалить

**Read site removal** — 2 точки в `client/ws_pool_drain.go`:
1. line ~587: `idleFor := time.Since(time.Unix(0, oldSlot.lastActivityNs.Load()))` — удалить
2. line ~639: existing idle gate — заменено в §2.2

**Touched but unchanged (retained for backward-compat parsing, resolves R2-M5):**

| File | Location | Action |
|---|---|---|
| `client/ws_pool.go` | `WSPoolTransport` struct, field `drainIdleStreamsMax` | **Keep.** Add `// Deprecated:` comment block: "Read from env for backward compat; ignored in Step 2 decision logic. Use DrainIdleThreshold=0 to disable." |
| `client/ws_pool.go` | `WSPoolConfig` struct, field `DrainIdleStreamsMax` | **Keep.** Same `// Deprecated:` marker. |
| `cmd/nixavpn-client/engine_shadowlink.go` | env-read for `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX` (around line 434) | **Keep** env parsing + add startup WARN log (see §2.5 N1 mitigation). |

### 2.3.1 ReleaseStream flip order (resolves R2-H2 — symmetric to Step 1 §2.5)

**Critical race fix.** Step 1 §2.5 acknowledged "ReleaseStream known minor race": map entry deleted before `streams.Add(-1)`, window where snapshot sees inconsistent state. Under Step 1 the consequence was a cosmetic `diag_total < remaining_streams` log mismatch.

Under Step 2 this race **escalates to a production teardown bug**:
1. ReleaseStream begins: `LoadAndDelete(streamID)` removes entry from map.
2. `drainWatchdog` tick: `streams.Load() > 0` (counter still pre-Add(-1)), enters `allStreamsIdle`.
3. `allStreamsIdle.Range` does NOT see deleted entry. If remaining entries are idle → returns **true**.
4. `tearDown(finishIdle)` fires while the in-flight `Release` of the (was-)active stream hasn't completed counter decrement.
5. Slot torn down → subsequent `RouteToStream` for already-deleted streamID hits a torn slot → silent drop OR (worse) frame arrives on a now-reused slot and triggers `decrypt_fails`.

**Fix.** Flip ReleaseStream order — symmetric to AssignStream fix from Step 1:

Current `ws_pool.go::ReleaseStream` (around line 2106):
```go
func (p *WSPoolTransport) ReleaseStream(streamID uint16) {
    if v, ok := p.streamMap.LoadAndDelete(streamID); ok {
        e, ok := v.(*streamEntry)
        if !ok { return }
        idx := e.slotIdx
        if idx < len(p.slots) && p.slots[idx] != nil {
            p.slots[idx].streams.Add(-1)
        }
    }
}
```

Replace with (preserve doc-comment):
```go
func (p *WSPoolTransport) ReleaseStream(streamID uint16) {
    // R2-H2 fix: streams.Add(-1) MUST precede streamMap.Delete (symmetric
    // to the AssignStream §2.5 flip from Step 1). Under per-stream idle
    // decision (Step 2), the inverse ordering would let drainWatchdog
    // observe an empty-map-but-counter>0 state and tearDown the slot
    // while a Release is mid-call → decrypt_fails. Read entry via Load
    // first (so we know the slotIdx), then decrement, then delete.
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
}
```

**Window inversion:** Now if the race fires, snapshot sees `streams.Load()` *already decremented* but entry *still in map* — `allStreamsIdle` finds the entry, evaluates its `lastWriteNs`, and either confirms still-active (caller wrote recently → returns false → no premature teardown) or all-idle (caller really was silent for >=threshold → tearDown is correct). False-positive teardown window is closed. Worst residual: a fraction of a microsecond where `streams.Load()` is one less than entries — purely diagnostic, no operational impact.

**Trade-off accepted:** `Load + Delete` is not atomic, vs the previous atomic `LoadAndDelete`. Production SOCKS layer guarantees one owner per streamID — double-Release would require a SOCKS bug. If it ever happens, the inner type-assertion + nil-checks defend correctness.

**N1 follow-up (R2 review).** Under hypothetical future SOCKS bug causing concurrent double-Release of the same streamID, the non-atomic `Load + Delete` could trigger `streams.Add(-1)` twice — under-counting. The atomic `LoadAndDelete` of the original code guarded this. We accept the trade because (a) flip is critical for Step 2 correctness; (b) double-Release would surface as `streams<0` slot state — caught by existing test `TestSlotStreamCounter_NeverNegative` if it exists; (c) sentinel mitigation (using `LoadAndDelete` at the end + gated decrement) is a future opt-in if the SOCKS contract weakens.

### 2.4 Log shape change

`finishIdle` log branch меняется:

**Before:**
```
WS pool slot drain natural finish (idle) slot=X reason=Y remaining_streams=N idle_for=37s drain_duration=Ds diag_total=N ...
```

**After:**
```
WS pool slot drain natural finish (idle) slot=X reason=Y remaining_streams=N drain_duration=Ds diag_total=N ... diag_min_stream_age_ms=N ...
```

Удалить поле `idle_for` — `diag_min_stream_age_ms` (минимальный возраст среди ВСЕХ remaining streams) показывает то же самое более точно (per-stream vs per-slot). При natural finish (idle) все streams ≥ threshold, поэтому `min_stream_age_ms ≥ 30000` инвариантно.

В `tearDown` switch (`finishIdle` branch):

**Удалить:**
```go
case finishIdle:
    Stats.DrainNaturalFinishTotal.Add(1)
    Stats.DrainIdleFinishTotal.Add(1)
    idleFor := time.Since(time.Unix(0, oldSlot.lastActivityNs.Load()))
    snap := snapshotDrainStreams(p, oldIdx, time.Now())
    p.log.Info("WS pool slot drain natural finish (idle)",
        "slot", oldIdx, "reason", reason,
        "remaining_streams", oldSlot.streams.Load(),
        "idle_for", idleFor.Truncate(time.Second),
        "drain_duration", duration.Truncate(time.Second),
        ...diag fields...,
    )
```

**Заменить на:**
```go
case finishIdle:
    Stats.DrainNaturalFinishTotal.Add(1)
    Stats.DrainIdleFinishTotal.Add(1)
    snap := snapshotDrainStreams(p, oldIdx, time.Now())
    p.log.Info("WS pool slot drain natural finish (idle)",
        "slot", oldIdx, "reason", reason,
        "remaining_streams", oldSlot.streams.Load(),
        "drain_duration", duration.Truncate(time.Second),
        ...diag fields...,
    )
```

### 2.5 ENV deprecation

| ENV | Step 1 behavior | Step 2 behavior |
|---|---|---|
| `SHADOWLINK_DRAIN_IDLE_THRESHOLD` | Active. Default `30s`. Setting to `0` was disable (AND condition with STREAMS_MAX). | Active. Default `30s`. **THE disable knob now.** Setting to `0` disables idle gate entirely. |
| `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX` | Active. Default `2`. **Setting to `0` was a real disable knob** (`idleEnabled := threshold > 0 && streamsMax > 0`). Verified by `TestDrainWatchdog_IdleHeuristicDisabled`. | **⚠️ BREAKING CHANGE.** Deprecated no-op. Setting to `0` no longer disables. Honor only `THRESHOLD=0` for disable. Value still read from env (won't break parsing) but ignored in decision logic. |

**⚠️ Operator-visible breaking change:** Any deployment scripts using `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX=0` as the disable mechanism will silently lose the opt-out path under Step 2. Migration: switch to `SHADOWLINK_DRAIN_IDLE_THRESHOLD=0`.

**Mitigation — startup deprecation warning (N1):** On startup, if `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX` is set explicitly in env (any value), emit a one-time `WARN` log: `"SHADOWLINK_DRAIN_IDLE_STREAMS_MAX is deprecated and no longer affects drain behavior. Use SHADOWLINK_DRAIN_IDLE_THRESHOLD=0 to disable idle gate."` Emitted in `cmd/nixavpn-client/engine_shadowlink.go` after env parsing. Helps operators discover the dropped knob.

`pool.drainIdleStreamsMax` поле в struct остаётся читаемым из env (чтобы старые скрипты не падали при parse'е), но в decision logic не используется. Documented in code as deprecated. Future cleanup может удалить поле, но не сейчас — приоритет на минимизацию blast radius Step 2.

### 2.6 Backward compatibility

- **ENV API**: оба env остаются readable, threshold default `30s` без изменений.
- **Wire protocol**: no change. Server side: no change.

**Existing tests requiring active migration (resolves R2-H1):**

| Test | File:line | Change reason |
|---|---|---|
| `TestDrainWatchdog_TooManyStreamsBypassesIdle` | `client/ws_pool_drain_test.go:2620` | **DELETE** — пинит anti-feature (when streams > STREAMS_MAX, idle does NOT fire). Step 2 explicitly abolishes this. The "anti-feature" was the bug we're fixing. |
| `TestDrainWatchdog_IdleFinish` | `client/ws_pool_drain_test.go:2530` | **REWRITE** — currently uses `slot.lastActivityNs.Store(...)` to set up state. Must use `storeStreamForTestWithAge(p, streamID, slotIdx, age)` plus matching `slot.streams.Store(N)` to construct per-stream idle state. |
| `TestDrainWatchdog_IdleHeuristicDisabled` | `client/ws_pool_drain_test.go:2580` | **REWRITE** — uses `DrainIdleStreamsMax: 0` as disable knob (was real in Step 1). Switch to `DrainIdleThreshold: 0` per §2.5 BREAKING note. |

**Tests with only assertion-text updates (idle_for log field removal):** any test capturing the `drain natural finish (idle)` log line and asserting `idle_for=` — drop that assertion. The diag_min_stream_age_ms field already present supersedes it semantically.

**Tests with stamp-site removal compile impact:** any test that reads `oldSlot.lastActivityNs` directly (per Q5 in review: 5 sites at lines 2547, 2595, 2635, 2708, 2815 in `ws_pool_drain_test.go`) — replace with `storeStreamForTestWithAge` setups or remove if no longer testing meaningful behavior.

---

## 3. Поведенческий контракт

### 3.1 Изменения для observer'а

**`drain natural finish (idle)` лог теперь срабатывает раньше** для slots с heartbeat-stream'ами:

- Был: slot молчит 30s (per-slot timer reset любым stream'ом) → редко достижимо при активных heartbeat'ах
- Стал: ВСЕ streams молчат 30s (per-stream) → достижимо если slot имеет N стримов и все они одновременно тихи 30s+

В частности: bucket=2 H1 case (1 active heartbeat + 1 idle 60s+) теперь:
- В прошлом: hard cap на 90s
- В будущем: ждём пока active heartbeat-stream замолчит на 30s → tearDown(finishIdle)

Если heartbeat не замолкает (например long-lived push WebSocket), slot всё равно hard cap'нется на 90s — это корректно (slot реально занят).

### 3.2 Hot-path overhead

- **Removed**: 4 atomic stores на каждый write/decrypt (`slot.lastActivityNs`). **Saving:** ~5-10ns per write. Под peak 24K writes/sec = ~120-240μs/sec = 0.012-0.024% CPU. Negligible но cumulative cleanup.
- **Added**: ноль hot-path additions. `allStreamsIdle` вызывается только в tick (500ms cadence в drainWatchdog).

### 3.3 Tick-path overhead

- **Was**: 1 atomic.Load на tick (slot.lastActivityNs) + 1 time arithmetic. ~10ns.
- **Now**: O(N) sync.Map iteration (typical N=50-100, early-exit when active found). ~1μs typical (early-exit hit), ~10μs worst case. Per drain = 180 ticks × 1-10μs = 0.2-1.8ms. drainWatchdog goroutine is dedicated to one slot, no contention.

### 3.4 Race / concurrency

- **streamMap.Range + UnregisterStream race**: sync.Map contract guarantees no partial entry exposure. Entry "snapshot" view может включать или не включать удаляемые streams — это OK, потому что в следующий tick это будет переоценено.
- **streamMap.Range + AssignStream race**: новые entries (newStreamEntry) stamps `lastWriteNs = now()`, поэтому они выглядят как active — `allStreamsIdle` returns false. Это false negative для idle на максимум 1 tick (500ms), за следующий tick refreshed.

---

## 4. Тестовая стратегия

### 4.1 Unit tests for `allStreamsIdle` (`client/stream_entry_test.go`)

1. **`TestAllStreamsIdle_Empty`** — пустой streamMap → false (no streams to be "all idle").
2. **`TestAllStreamsIdle_AllActive`** — 3 streams, все с age<threshold → false.
3. **`TestAllStreamsIdle_AllIdle`** — 3 streams, все с age>threshold → true.
4. **`TestAllStreamsIdle_BimodalSmokingGun`** — 2 streams: 1 active (age=1s), 1 idle (age=60s) → **false** (active один блокирует, это и есть H1 case в Step 1 prognosis где slot НЕ должен tearDown пока activity heartbeat жив).
5. **`TestAllStreamsIdle_OnlyOurSlot`** — streamMap имеет entries для нескольких slots; вызываем `allStreamsIdle(p, 5, ...)` → возвращает решение только по entries с slotIdx=5.
6. **`TestAllStreamsIdle_ExactlyAtThreshold`** — boundary case: stream age = threshold exactly → idle (≥, not >).

### 4.2 Integration test (`client/ws_pool_drain_test.go`)

7. **`TestDrainWatchdog_PerStreamIdle_TriggersWhenAllSilent`** — orchestrate watchdog с 2 streams initially active. Sleep 35s (mock-clocked если возможно, или real-time wait — следовать существующему pattern в drain tests). После того как обe stream становятся idle → tearDown(finishIdle), assert log emit'ит "natural finish (idle)" AND **invariant assertion (L1):** `diag_min_stream_age_ms >= 30000` (per spec §2.4 invariant — at finishIdle, all streams must be ≥ threshold).

8. **`TestDrainWatchdog_PerStreamIdle_HoldsOpenForActiveStream`** — orchestrate watchdog с 2 streams: один заведомо idle, другой активный (write каждые 100ms). Watchdog должен НЕ срабатывать idle, дойти до hard cap.

9. **`TestAllStreamsIdle_ConcurrentReleaseStream`** (R2-Q6 follow-up) — spawn ReleaseStream loop concurrent с allStreamsIdle scan. Assert no panic. Assert allStreamsIdle never returns true while ReleaseStream is mid-call on last active stream (validates H2 fix). Use real goroutines + `runtime.Gosched()` to expose the window.

10. **`TestAllStreamsIdle_ConcurrentAssignStream`** — spawn AssignStream of fresh stream concurrent with allStreamsIdle scan. Assert returns false (fresh stamp = active, conservative).

### 4.3 Race detector

`go test -race -count=3 ./client/` (skipped on Windows w/o CGO per project convention).

### 4.4 Canary validation

После merge — запустить `connect-vpn-graceful-drain.bat` на 4h+. Анализ:

**Primary metrics:**
- `natural_ratio = (finishIdle + finishStreamsZero) / total_drains` — целевой коридор **75-80%**, прогноз **~74%** (близко к низу коридора).
- `hard_cap_ratio = finishHardCap / total_drains` — прогноз **~26%** (vs 44% в canary 2026-05-25 evening).

**Validation checks:**
- Bucket distribution идентична (нет регрессии в типе hard caps).
- Bucket=1 cases (`active=1 idle=0`) **остаются** hard cap (corretly — реально активный single stream).
- Bucket=2 H1 cases (`idle=1 active=1`) — **резко падают** в hard cap, перемещаются в natural-finish-idle.

**Edge cases to watch:**
- `Stats.DrainHardCapTotal` сильно ↓ — ожидаемо.
- `Stats.DrainNaturalFinishTotal` сильно ↑ — ожидаемо.
- `Stats.DrainIdleFinishTotal` ↑ (subset natural finish с idle path).
- `meltdowns_1m` остаётся 0 — sanity check, новый decision не должен ускорять teardown настолько что pool не успевает recover.
- `inflight_cap_deferred_total` — может ↓ потому что rotations теперь чаще завершаются natural (без force teardown).

**Decision after canary (three-tier rule, resolves R2-M4):**

| natural_ratio | Other signals | Verdict |
|---|---|---|
| **≥75%** | meltdowns_1m=0, decrypt_fails=0, no new ERROR | ✅ **Target met.** Keep deployed. |
| **70-75%** | meltdowns_1m=0, decrypt_fails=0, no new ERROR | ✅ **Partial win.** Keep deployed. Open follow-up issue to investigate bucket=1 trickle-heartbeat floor (see §7 "What we are NOT doing"). |
| **<70%** | OR any meltdown / decrypt_fail / ERROR regression | ❌ **Revert.** Git revert PR. Re-canary on Step 1 baseline. Analyze diag fields from failure log to update H1-derived plan. |

Predicted landing: **77.6%** (math from §1). Strong signal lands in tier 1. Margin to tier-3 boundary (<70%) is 7.6pp, which is well above sample-size CI (~5pp on n=300+ hard caps).

---

## 5. Inverse / Rollback

### 5.1 Emergency disable

`SHADOWLINK_DRAIN_IDLE_THRESHOLD=0` отключает idle gate целиком (`idleEnabled = false`). Slots будут только hard-cap teardown'иться на 90s. Same behavior as if heuristic was never added.

### 5.2 Code rollback

Git revert PR (single PR подаёт все изменения Step 2). Откатит:
- `allStreamsIdle` функцию
- drainWatchdog gate change
- `slot.lastActivityNs` cleanup (returns the field + 4 stamps + 2 reads)
- log format change (`idle_for` returns)

Полный revert восстанавливает Step 1 state. Никаких внешних зависимостей нет.

### 5.3 Если canary показывает регрессию

- Если `meltdowns_1m > 0` появится → Step 2 разогнал drains слишком aggressive, поднять threshold (env tweak без redeploy).
- Если `decrypt_fails > 0` появится → indicates teardown race (slot torn down пока stream ещё писал) — это race в `allStreamsIdle` который мы не предусмотрели. Revert PR, investigate.
- Если bucket distribution changes unexpectedly → новый baseline, decide based on actual numbers.

---

## 6. Resolved Questions

**Design-phase resolved (during brainstorming):**

- ✅ STREAMS_MAX cap → убрать (per-stream сам решает, cap становится redundant).
- ✅ slot.lastActivityNs → полный removal (4 stamps + 1 field + 2 reads + idle_for log).
- ✅ allStreamsIdle location → в `stream_entry.go` рядом с snapshot.
- ✅ Approach → A (inline iteration in drainWatchdog tick).
- ✅ Empty streamMap edge case → `allStreamsIdle` returns false (caller responsible for handling).
- ✅ AssignStream race → newStreamEntry stamps now, выглядит как active, conservative behavior.
- ✅ ENV deprecation strategy → STREAMS_MAX остаётся readable для backward-compat parsing, no-op в logic.

**Opus R1 review findings resolved in this revision:**

- ✅ R2-H1: existing test migration explicit list (§2.6 table — delete `TooManyStreamsBypassesIdle`, rewrite `IdleFinish` and `IdleHeuristicDisabled`).
- ✅ R2-H2: ReleaseStream race flip order (§2.3.1 — production-grade fix mirroring Step 1 AssignStream).
- ✅ R2-M1: STREAMS_MAX=0 was a real disable knob — documented as **BREAKING CHANGE** with startup WARN log mitigation (§2.5).
- ✅ R2-M4: canary decision criteria three-tier rule (§4.4).
- ✅ R2-M5: cmd-layer env wiring + WSPoolConfig field added to file list with `// Deprecated:` markers (§2.3).
- ✅ R2-L1: `diag_min_stream_age_ms >= 30000` invariant assertion in integration test (§4.2 test #7).
- ✅ R2-L4: clock-skew handling in `allStreamsIdle` documented + conservative behavior (§2.1).
- ✅ R2-Q6: ReleaseStream/AssignStream race regression tests added (§4.2 tests #9, #10).
- ✅ R2-N1: startup deprecation warning for STREAMS_MAX env (§2.5 mitigation).

---

## 7. What we are NOT doing

- **Meaningful-activity threshold** (variant B из research): не применяем "ignore writes <256 bytes" filter. Если bucket=1 trickle-heartbeats окажутся проблемой после Step 2 — отдельный spec.
- **STREAMS_MAX field removal** из struct: оставляем поле читаемым для env (для emergency `=0` disable), но не используем в decision logic.
- **`SHADOWLINK_DRAIN_HARD_CAP` tweak**: не меняем default 90s. Если canary покажет что 30-60% drains hits hard cap, tune later.
- **Migration of slot.startedAtNs**: out of scope (only lastActivityNs cleanup).

---

## 8. References

- Step 1 spec/plan: `2026-05-25-drain-per-stream-diagnostics-{design,}.md`
- Step 1 implementation: commits `faeb8e2..adff5e0` (8 commits)
- Canary log proving H1: `nixavpn-graceful-drain-20260525-162557.log` (4ч20м, 367 hard caps, 64.9% H1-shape)
- Existing graceful drain logic: `client/ws_pool_drain.go::drainWatchdog`
- Existing snapshot: `client/stream_entry.go::snapshotDrainStreams`

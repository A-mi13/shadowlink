# Drain diagnostics — counter split, INFO rate-limit, conditional hard-cap level

**Status:** design ready for review (2026-05-24)
**Driver session:** `/tmp/nixavpn-graceful-drain-20260524-104705.log` (4h52m, 2026-05-24)
**Previous fix:** `2026-05-23-stream-buffer-and-drain-log-fixes-design.md`

## Problem statement

Канарейка 2026-05-24 показала `deferred_drains_total=12326` за 4h52m (~20× выше
baseline 2026-05-22 8h канарейки). При этом в логе **ноль строк**
`WS pool slot drain deferred` — потому что фикс 2026-05-23 переключил эти
сообщения на DEBUG, а `.bat`-лаунчер запускает клиента с `-log info`.

Это создаёт диагностический gap: storm-brake **реально срабатывал 12326 раз**,
но ни одна из этих сработок не оставила следа в логе. Дополнительно текущий
единый счётчик `DrainStormBrakeEngagedTotal` агрегирует обе ветки
(inflight-cap и capacity-floor) — невозможно понять, какой именно gate
доминирует, без отдельных метрик.

Параллельно в той же сессии 272 hard-cap эвента (40% от 684 drain'ов)
писались в WARN, но 96 из них с `remaining_streams=1` и 153 с `=2` — это
expected steady-state поведение, не аномалия. WARN на ожидаемом событии
маскирует реальные outliers (6 событий с `remaining_streams≥5`).

## Goals

1. **Раздельные счётчики** для двух storm-brake gate'ов (inflight cap vs capacity floor) — точная диагностика какой механизм доминирует.
2. **INFO-уровень с rate-limit** для deferred-log (1 строка / 30s на gate) — счётчики и таймсерия видны в логе без шума.
3. **Conditional WARN/INFO для hard-cap** — WARN только при `remaining_streams >= 5` (~2% реальных событий), INFO для expected steady-state hard caps.

После следующей канарейки с этими изменениями можно будет обоснованно
выбрать дальнейшие действия (hard cap ceiling, poolSize, capacity floor
fraction) — текущее предложение «поднять hard cap до 180s» взято вслепую
и может ухудшить storm-brake, если inflight gate уже в насыщении.

## Non-goals

- Менять `SHADOWLINK_DRAIN_HARD_CAP` с 90s — преждевременно без диагностики
- Менять `poolSize` (6 default) — то же
- Менять `rotationStormBrakeFraction = 0.25` — то же
- Histogram `drain_natural_finish_duration` — отдельная задача после baseline
- Fix leakguard `exit 0xc000013a` shutdown race — отдельный bugfix
- WiFi `io_timeout` кластер 2026-05-24 10:57-11:26 — клиентский локальный, не туннельный

## Design

### 1. Counter split

В `shadowlink/client/stats.go`:

**Удалить:**
```go
DrainStormBrakeEngagedTotal atomic.Uint64
```
и его Prometheus exposition `shadowlink_slot_drain_storm_brake_engaged_total`.

**Добавить:**
```go
// InflightCapDeferredTotal — drain attempts deferred because inflightDrains
// already at maxConcurrentDrains. This indicates the rotation scheduler
// is healthy but operating at peak concurrency. High rate is OK if it
// stays bounded; persistent saturation suggests poolSize too small for
// the current rotation cadence. Counter increments on EVERY defer; the
// log line emission is rate-limited (drainDeferredLogInterval).
//
// Spec 2026-05-24 (drain-diagnostics-counter-split).
InflightCapDeferredTotal atomic.Uint64

// CapacityFloorDeferredTotal — drain attempts deferred because readyCapacity
// fell below readyCapacityFloor (poolSize * rotationStormBrakeFraction).
// This is the catastrophic path — indicates the pool is losing slots
// faster than reconnectLoop can heal. Non-zero rate is a warning sign;
// persistent non-zero rate is a failure mode (cascading slot deaths).
// Counter increments on EVERY defer; log emission rate-limited.
//
// Spec 2026-05-24 (drain-diagnostics-counter-split).
CapacityFloorDeferredTotal atomic.Uint64
```

Prometheus exposition adds two counters:
```
shadowlink_slot_drain_inflight_cap_deferred_total
shadowlink_slot_drain_capacity_floor_deferred_total
```

### 2. Rate-limited INFO log per gate

В `shadowlink/client/ws_pool.go` (struct `WSPoolTransport`):

```go
// Spec 2026-05-24: per-gate rate-limit for deferred-drain INFO logs.
// UnixNano timestamp of last INFO emission per storm-brake gate; CAS
// guarantees exactly-one-logger under concurrent defers. Zero value
// (first defer) always logs.
lastInflightCapLogNs   atomic.Int64
lastCapacityFloorLogNs atomic.Int64
```

В `shadowlink/client/ws_pool_drain.go` (рядом с `drainStormBrakeBackoff`):

```go
// drainDeferredLogInterval — minimum wall-clock gap between two
// consecutive INFO emissions of "drain deferred" for the SAME gate.
// Counters always increment; only the human-readable log is rate-limited.
// 30s chosen to surface temporal trends (peaks/valleys) without log spam
// — the 2026-05-24 session would have produced ~10 INFO lines per gate.
// Spec 2026-05-24.
drainDeferredLogInterval = 30 * time.Second
```

Helper:

```go
// shouldLogDeferred returns true if at least drainDeferredLogInterval has
// elapsed since the last INFO log for this gate. Atomic CAS guarantees
// exactly one winner under concurrent calls (no mutex needed). The `now`
// parameter is passed explicitly for testability — tests inject a clock
// without monkey-patching time.Now().
//
// Spec 2026-05-24.
func shouldLogDeferred(last *atomic.Int64, now time.Time) bool {
    prev := last.Load()
    threshold := now.Add(-drainDeferredLogInterval).UnixNano()
    if prev > threshold {
        return false
    }
    return last.CompareAndSwap(prev, now.UnixNano())
}
```

Patch `startDrain` (gates 4 and 5):

```go
// Gate 4: inflight cap
if int(inflight) > p.maxConcurrentDrains() {
    Stats.InflightCapDeferredTotal.Add(1)
    p.bumpDrainDeferrals1m()
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

// Gate 5: capacity floor
ready := p.readyCapacity()
floor := p.readyCapacityFloor()
if ready < floor {
    Stats.CapacityFloorDeferredTotal.Add(1)
    p.bumpDrainDeferrals1m()
    backoff := drainStormBrakeBackoff
    if ready < p.poolSize/2 {
        backoff = drainCatastrophicBackoff
    }
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

**Поле `total_count` в каждой INFO строке** критично: дельта между двумя
соседними INFO строками одного gate = реальный темп defer'ов в окне.

### 3. Health snapshot fields

В `shadowlink/client/ws_pool.go` (вокруг line 1283 — `WS pool health`):

**Заменить:**
```go
"deferred_drains_total", Stats.DrainStormBrakeEngagedTotal.Load(),
"deferred_drains_1m",    p.drainDeferrals1m.Load(),
```

**На:**
```go
"inflight_cap_deferred_total",   Stats.InflightCapDeferredTotal.Load(),
"capacity_floor_deferred_total", Stats.CapacityFloorDeferredTotal.Load(),
"deferred_drains_1m",            p.drainDeferrals1m.Load(),
```

`drainDeferrals1m` остаётся общим (per-1m суммарный для обоих gate'ов) —
плодить три счётчика на rolling window избыточно, общий темп достаточен
для триггера алертов.

### 4. Conditional hard-cap log level

В `shadowlink/client/ws_pool_drain.go`:

**Константа:**
```go
// hardCapWarnThreshold — minimum remaining_streams for hard-cap teardown
// to log at WARN level. Below this threshold the teardown logs INFO.
//
// Rationale: hard cap with remaining_streams=1-2 is expected steady-state
// behavior under long-lived SOCKS sessions (uplink 4-10min sessions seen
// regularly in real traffic). The 2026-05-24 session distribution (272
// total hard-cap events, disjoint buckets):
//   remaining=1:   96 events (35.3%)
//   remaining=2:   153 events (56.3%)
//   remaining=3-4: 17 events  (6.3%)
//   remaining>=5:  6 events   (2.2%)
// Threshold=5 keeps ~98% of expected hard caps at INFO, surfacing only
// outliers as WARN. Spec 2026-05-24.
hardCapWarnThreshold int32 = 5
```

**Patch `tearDown(finishHardCap)`:**

```go
case finishHardCap:
    Stats.DrainHardCapTotal.Add(1)
    remaining := oldSlot.streams.Load()
    logFn := p.log.Info
    if remaining >= hardCapWarnThreshold {
        logFn = p.log.Warn
    }
    logFn("WS pool slot drain hard cap reached",
        "slot", oldIdx, "reason", reason,
        "remaining_streams", remaining,
        "drain_duration", duration.Truncate(time.Second))
```

Тип `int32` соответствует `oldSlot.streams atomic.Int32`.

## Testing

Все новые тесты — в `shadowlink/client/ws_pool_drain_logging_test.go`,
following existing patterns (`makeStormBrakeTestPool`, `triggerStormBrakeInflightCapOn`).

### Counter split tests

1. **`TestInflightCapCounter_IncrementsPerDefer`** — N defer'ов через inflight gate → `InflightCapDeferredTotal` вырос на N
2. **`TestCapacityFloorCounter_IncrementsPerDefer`** — N defer'ов через capacity gate → `CapacityFloorDeferredTotal` вырос на N
3. **`TestCountersIndependent`** — inflight defer НЕ инкрементирует capacity counter и наоборот

### Rate-limit tests

4. **`TestDrainDeferred_InflightCap_LogLevelInfo`** — replaces `TestDrainDeferred_LogLevelDebug` for inflight branch
5. **`TestDrainDeferred_CapacityFloor_LogLevelInfo`** — same for capacity-floor branch
6. **`TestDrainDeferred_RateLimit_OneLogPer30s`** — N defer'ов за <30s → ровно 1 лог-строка; counter растёт на N
7. **`TestDrainDeferred_RateLimit_PerGateIndependent`** — defer на inflight не блокирует лог capacity-floor
8. **`TestShouldLogDeferred_FirstCallAlwaysTrue`** — zero value timestamp → true
9. **`TestShouldLogDeferred_CASRacesProduceAtMostOneWinner`** — N goroutines одновременно вызывают, **≤1** получает true. (Может быть 0 если рейсят после deadline и `now` одного proposera обогнал другого через CAS — корректное поведение, не баг.)

### Conditional hard-cap tests

10. **`TestHardCap_LogLevelInfo_BelowThreshold`** — drain с `streams.Store(2)` → INFO
11. **`TestHardCap_LogLevelWarn_AtThreshold`** — drain с `streams.Store(5)` → WARN
12. **`TestHardCap_LogLevelWarn_AboveThreshold`** — drain с `streams.Store(9)` → WARN
13. **`TestHardCap_CounterIncrementsRegardlessOfLevel`** — `DrainHardCapTotal++` независимо от того, INFO или WARN

### Health snapshot test

14. **`TestHealthSnapshot_NewCounterFields`** — snapshot строка содержит `inflight_cap_deferred_total=` и `capacity_floor_deferred_total=`, НЕ содержит `deferred_drains_total=`

## Breaking changes

| Removed | Added | Migration |
|---|---|---|
| `Stats.DrainStormBrakeEngagedTotal` | `Stats.InflightCapDeferredTotal` + `Stats.CapacityFloorDeferredTotal` | Sum the two to recover the old aggregate |
| Prom `shadowlink_slot_drain_storm_brake_engaged_total` | Prom `..._inflight_cap_deferred_total` + `..._capacity_floor_deferred_total` | Update `shadowlink-metrics-dump-linux` parser if it consumes the field |
| Health field `deferred_drains_total` | Fields `inflight_cap_deferred_total` + `capacity_floor_deferred_total` | Log-parsing tools update field names |

**Внешних потребителей нет** (Grafana board ещё не подключён к prod scrape
per CLAUDE.md "Production scrape integration explicit follow-up").

## Acceptance criteria

После деплоя + 2-3h канарейки:

1. `grep -c "drain deferred (inflight cap)"` > 0 если gate работал
2. `grep -c "drain deferred (capacity floor)"` > 0 если gate работал
3. Каждая INFO строка содержит `total_count=<N>` и `deferred_1m=<M>`
4. Между двумя соседними INFO строками одного gate ≥ 30s
5. WS pool health snapshot содержит `inflight_cap_deferred_total=` и `capacity_floor_deferred_total=`
6. WARN строк `hard cap reached` ~2-3% от total hard caps (vs текущие ~100%)

При выполнении этих 6 criteria — следующая канарейка даёт данные для
обоснованного решения по `SHADOWLINK_DRAIN_HARD_CAP` / `poolSize` /
`rotationStormBrakeFraction`.

## Files affected

| File | Type of change | ~LOC |
|---|---|---:|
| `shadowlink/client/stats.go` | Remove 1 counter+Prom, add 2 counters+Prom+doc | ~30 |
| `shadowlink/client/ws_pool.go` | 2 atomic.Int64 fields in struct; health snapshot fields | ~10 |
| `shadowlink/client/ws_pool_drain.go` | Counter split in startDrain, `shouldLogDeferred` helper, hard-cap conditional, constants | ~40 |
| `shadowlink/client/ws_pool_drain_logging_test.go` | Update 3 existing tests + add 11 new | ~150 |
| `shadowlink/client/ws_pool_drain_test.go` | Counter assertion updates if affected | ~10 |

**Total: ~240 LOC, ~160 in tests.**

Один пересбор бинарей (Windows + Linux + Mac ARM64).

## References

- Driver session log: `/tmp/nixavpn-graceful-drain-20260524-104705.log`
- Session analysis: `docs/session-analysis-2026-05-24.md`
- Previous drain fix: `shadowlink/docs/superpowers/specs/2026-05-23-stream-buffer-and-drain-log-fixes-design.md`
- Storm-brake design: `shadowlink/docs/superpowers/specs/2026-05-20-ws-pool-uniform-cells-design.md` (sections on `readyCapacityFloor` / `rotationStormBrakeFraction`)
- Code: `shadowlink/client/ws_pool_drain.go::startDrain` (lines 242-369), `::drainWatchdog` (lines 414-505)

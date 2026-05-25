# Per-stream activity diagnostics + idle infrastructure — design

**Дата:** 2026-05-25
**Тип:** Infrastructure step (foundation для следующего варианта решения)
**Связанные документы:**
- Research: `shadowlink/docs/superpowers/canary-reports/2026-05-25-natural-ratio-gap-research.md`
- Predecessor: `shadowlink/docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md`
- Reviews (Opus, max effort, two rounds):
  - Round 1: `shadowlink/docs/superpowers/specs/2026-05-25-drain-per-stream-diagnostics-design-review.md` (3 HIGH + 6 MEDIUM + 4 LOW + 3 NIT — all resolved)
  - Round 2: `shadowlink/docs/superpowers/specs/2026-05-25-drain-per-stream-diagnostics-design-review-r2.md` (1 HIGH + 4 MEDIUM + 3 LOW + 2 NIT — all resolved)

---

## 1. Зачем

### Проблема

Канарейка 2026-05-25 (4h32m): natural-finish ratio = **62.6%** (561/896 drain). Цель 75-80%. **332 hard cap reached (37%)**, из них **278 (84%)** с `remaining_streams ≤ 2` — то есть формально в диапазоне existing idle-finish heuristic (`SHADOWLINK_DRAIN_IDLE_THRESHOLD=30s`, `STREAMS_MAX=2`), но heuristic не сработал.

### Главная гипотеза (H1, HIGH confidence из research)

**Idle-heuristic измеряет тишину на уровне slot'а, а не stream'а.** В `ws_pool_drain.go:632` читается **одна** `oldSlot.lastActivityNs.Load()` метка — обновляется на каждом write/decrypt от ЛЮБОГО stream'а аттаченного к slot'у. Один долгоживущий heartbeat-stream (Gmail/Docs/CF push-WS с ping-cadence 15-30s) **постоянно** сбрасывает таймер для соседних молчаливых streams, не давая slot'у попасть в idle-зону за 90s drain window.

### Что мы НЕ знаем

Прямого доказательства H1 в логах нет — `streamMap` хранит только `map[uint16]int` (streamID → slot index), без per-stream activity timestamp. Поэтому при `hard cap reached remaining_streams=2` мы не знаем:
- Все 2 stream'а активны? (тогда heuristic правильно не сработал)
- Один активен, один тих 60s? (тогда heuristic был обязан сработать — bug H1)
- Оба тихи, но slot.lastActivityNs обновлялся какой-то третьей сущностью? (тогда bug в другом месте)

### Решение

**Этот spec — Шаг 1 из двух:** добавить per-stream activity tracking как **инфраструктуру** + использовать её для **диагностических полей** в drain-логах. Idle-decision logic пока **НЕ меняем** — остаётся per-slot, как сейчас. Это даст:

1. Прямое доказательство (или опровержение) H1 в следующей канарейке.
2. Готовую инфраструктуру для **Шага 2** (Variant A — per-stream idle decision), если H1 подтвердится. ~30 LOC сверху текущего step'а.
3. Постоянный observability для будущих расследований drain-патологий.

**Шаг 2 — отдельный spec**, начинаемый только после анализа diagnostic-канарейки.

### 1.1 Variant A scope split

Research §5 предложил полный Variant A (per-stream idle decision). Здесь — split:

| Артефакт | Step 1 (этот spec) | Step 2 (следующий spec) |
|---|---|---|
| `*streamEntry` структура + `slotIdx` миграция (вкл. test layer ~12 сайтов через helpers) | ✅ | — |
| Hot-path stamping `lastWriteNs` | ✅ | — |
| Snapshot + diag-поля в drain logs | ✅ | — |
| `drainWatchdog` переключение на per-stream idle | — | ✅ |
| Удаление `slot.lastActivityNs` | — | ✅ |
| Counters/histograms для per-stream idle | — | ✅ |

После Step 1 vs Step 2 — `slot.lastActivityNs` всё ещё используется для idle-decision. Двойной stamping (per-slot + per-stream) — by design, временно, до Step 2.

---

## 2. Архитектура

### 2.1 Новый тип `streamEntry`

Заменить `sync.Map` со значениями `int` на `sync.Map` со значениями `*streamEntry`:

```go
// streamEntry tracks per-stream state required for both routing
// (which slot owns the stream) and diagnostics (when this stream
// last had wire activity).
//
// Stored as *streamEntry in sync.Map; pointer storage avoids
// re-Store on lastWriteNs update.
type streamEntry struct {
    slotIdx     int           // immutable after first Store
    lastWriteNs atomic.Int64  // unix nanos of most recent wire activity
}

// newStreamEntry constructs a fully-initialized entry: slotIdx pinned,
// lastWriteNs pre-stamped to time.Now() so snapshot logic never sees
// a zero clock (avoids special-casing fresh assignments — see M3).
func newStreamEntry(slotIdx int) *streamEntry {
    e := &streamEntry{slotIdx: slotIdx}
    e.lastWriteNs.Store(time.Now().UnixNano())
    return e
}
```

**Инварианты:**
- `slotIdx` immutable after first Store. AssignStream использует `streamMap.Store(streamID, newStreamEntry(idx))`. Любое последующее обновление того же streamID — это double-AssignStream и считается ошибкой (см. §2.7).
- `lastWriteNs` атомарно обновляется только методами `atomic.Int64`. Никакого raw access к int64-полю. Snapshot читает через `Load()`, hot path пишет через `Store()`.
- При `UnregisterStream` запись удаляется через `streamMap.LoadAndDelete(streamID)` — entry попадает под GC.

### 2.2 Полный список миграций streamMap

Spec до review упоминал только 3 точки. Реальный список ниже (grep `p.streamMap.` в `client/`). **Все** сайты должны быть мигрированы в одном PR, иначе compile-fail или type-assertion panic при первом CONNECT.

#### Production sites (`client/ws_pool.go`)

| Строка | Функция | Изменение |
|---|---|---|
| **declaration** ~857 | `streamMap sync.Map` | docstring обновить: `// map[uint16]*streamEntry — streamID → entry` |
| ~2014 | `AssignStream::Store` | `p.streamMap.Store(streamID, newStreamEntry(minIdx))`. **Порядок:** перед Store — `p.slots[minIdx].streams.Add(1)` (см. H3 §2.5). |
| ~2023 | `IncrPending::Load` | `v.(*streamEntry).slotIdx` |
| ~2033 | `DecrPending::Load` | `v.(*streamEntry).slotIdx` |
| ~2043 | `SlotPending::Load` | `v.(*streamEntry).slotIdx` |
| ~2072 | `ReleaseStream::LoadAndDelete` | `v.(*streamEntry).slotIdx` |
| ~2087 | `SessionForStream::Load` | `v.(*streamEntry).slotIdx` |
| ~2113 | `WriteMessageForStream::Load` | `e := v.(*streamEntry); idx := e.slotIdx; ...; stamp e.lastWriteNs ВНУТРИ if-блока после успешного write — см. §2.4` |
| ~2137 | `WriteControlMessageForStream::Load` | то же что выше, для control frame |
| ~2447 | `slotReaderWithClient::Load` (stale-frame W5 check) | `e := v.(*streamEntry); if e.slotIdx != idx { dropStale }`; stream-stamp **только после** успешной валидации (см. §2.4) |
| ~2658 | `handleSlotDeath::Range` | `value.(*streamEntry).slotIdx != idx` |
| ~2663 | `handleSlotDeath::Delete` | без изменений (ключ всё ещё uint16) |

Все line numbers выше — приблизительные snapshot'ы; единый источник правды — имена функций.

#### Test sites

Существующие тесты (`ws_pool_test.go`, `ws_pool_drain_test.go`) ~14+ мест делают `p.streamMap.Store(uint16(X), 0)` напрямую с literal `int`. Они **все** сломают компиляцию после refactor'а.

**Решение:** создать test helper в `client/ws_pool_test_helper.go` (под `//go:build !race_only` либо в обычном `*_test.go` файле):

```go
// storeStreamForTest is a test-only helper that constructs and stores a
// streamEntry. Tests outside of newStreamEntry's package can't access
// the unexported constructor — this exposes it under test scope only.
func storeStreamForTest(p *WSPoolTransport, streamID uint16, slotIdx int) {
    p.streamMap.Store(streamID, newStreamEntry(slotIdx))
}

// storeStreamForTestWithAge stores entry with lastWriteNs offset by `age`
// into the past, useful for idle-finish tests.
func storeStreamForTestWithAge(p *WSPoolTransport, streamID uint16, slotIdx int, age time.Duration) {
    e := newStreamEntry(slotIdx)
    e.lastWriteNs.Store(time.Now().Add(-age).UnixNano())
    p.streamMap.Store(streamID, e)
}
```

Все existing test sites переписываются на эти helpers. Это часть scope этого spec'а.

### 2.3 Stream-bound точки обновления `lastWriteNs`

Три stream-bound точки (per-slot prime в `connectSlot` остаётся как есть — slot-level event, per-stream аналога нет):

| Файл:функция | Контекст | Когда stamp |
|---|---|---|
| `ws_pool.go::WriteMessageForStream` | uplink data frame | Внутри if-блока, после успешного routing-валидации (slot != nil, state in {Ready, Draining}) и **перед** `slot.transport.WriteMessage(data)`. То же место что existing `slot.lastActivityNs.Store(now)`. |
| `ws_pool.go::WriteControlMessageForStream` | CONNECT/FIN | То же |
| `ws_pool.go::slotReaderWithClient` после `DecryptChunkSafe` | downlink chunk | **После** stale-frame check `e.slotIdx == idx` (см. §2.4). |

В каждой из этих точек **уже** есть `streamID` в scope и **уже** есть load из streamMap для routing. Дополнительный cost: одна `atomic.Int64.Store(time.Now().UnixNano())` на путь. Микроскопически — измеряется в наносекундах.

**Per-slot `lastActivityNs` остаётся** — он по-прежнему используется existing idle-logic (`drainWatchdog`). Не дублируем, а дополняем. Двойной stamping вписан в design до Step 2 (см. §1.1).

### 2.4 Stamp position vs stale-frame check (resolves H2)

В `slotReaderWithClient` (текущий `ws_pool.go:2436-2459`) сейчас:

```go
slot.lastActivityNs.Store(time.Now().UnixNano())    // slot-stamp до streamID parse
msgCount++
streamID := uint16(...)
if v, ok := p.streamMap.Load(streamID); ok {
    if v.(int) != idx {                              // stale-frame check (W5)
        Stats.StaleFrameDroppedTotal.Add(1)
        continue
    }
}
// ... route the chunk
```

**Решение по H2:** stream-stamp выполняется **только после** успешной валидации `entry.slotIdx == idx`. То есть frames от refused streamID'ов **не считаются** stream-level активностью.

```go
slot.lastActivityNs.Store(time.Now().UnixNano())    // slot-stamp остаётся как был (out-of-scope)
msgCount++
streamID := uint16(...)
if v, ok := p.streamMap.Load(streamID); ok {
    e := v.(*streamEntry)
    if e.slotIdx != idx {
        Stats.StaleFrameDroppedTotal.Add(1)
        continue
    }
    e.lastWriteNs.Store(time.Now().UnixNano())      // stream-stamp ПОСЛЕ валидации
}
// ... route the chunk
```

**Rationale:**
- Семантика "activity = wire activity owned by THIS stream entry, delivered server-side". Это то что нам нужно для proof H1 — frame'ы от чужого slot'а не должны влиять на наш per-stream таймер.
- Slot-stamp на 2439 оставляем как был. Текущий existing-behavior (slot stamp'ится даже от stale frame'ов) формально incorrect, но это **out-of-scope этого patch'а** — мы не трогаем existing graceful-drain логику.
- **Known limitation:** stream-stamp выполняется **ДО** `RouteToStream`. Если application-side reader повешен (закрытый streamChan) или chan заполнен — frame отбрасывается, но stamp уже сделан. То есть "wire activity" не означает "application-side consumption". Для H1 диагностики это OK: мы измеряем server→client wire delivery; если server отправляет frames в "мёртвый" stream, slot.lastActivityNs всё равно бы сбросился (existing behavior), наш per-stream tracker лишь отражает ту же реальность на per-stream уровне. В крайне edge case'е (живой server-side wire, мёртвый reader > 30s) classification = "active" — false-negative для idle. Принимаем как narrow case, без расширения `RouteToStream` signature.

В `WriteMessageForStream` / `WriteControlMessageForStream` stale-frame check не существует (uplink не валидируется ту же сторону) — stamp выполняется в существующем if-блоке `slot != nil && st in {Ready, Draining}`. То же место где сейчас `slot.lastActivityNs.Store`.

### 2.5 AssignStream race fix (resolves H3)

Сейчас `ws_pool.go:2014-2015`:

```go
p.streamMap.Store(streamID, minIdx)        // ← snapshot может Load
p.slots[minIdx].streams.Add(1)             // ← snapshot может ещё НЕ видеть инкремент
```

**Race**: snapshot в drainWatchdog между этими двумя строками увидит entry, но `oldSlot.streams.Load()` отрапортует на 1 меньше. В логе `remaining_streams=2 diag.total=3` — incoherent.

**Fix:** flip order:

```go
p.slots[minIdx].streams.Add(1)             // counter ВПЕРЁД
p.streamMap.Store(streamID, newStreamEntry(minIdx))  // entry публикуем после
```

**W5 stale-frame check** (`ws_pool.go:2447`) валидирует `entry.slotIdx == idx`. Flip-перестановка между `streams.Add` и `streamMap.Store` не затрагивает W5 — он зависит только от `slotIdx`, не от `streams` counter. W5 и flip — изолированные fix'ы для разных инвариантов.

**ReleaseStream race — known minor.** Существующий код:

```go
if v, ok := p.streamMap.LoadAndDelete(streamID); ok {
    e := v.(*streamEntry)
    if e.slotIdx < len(p.slots) && p.slots[e.slotIdx] != nil {
        p.slots[e.slotIdx].streams.Add(-1)
    }
}
```

Окно между `LoadAndDelete` и `streams.Add(-1)` (порядок ns): snapshot может увидеть `streams=N+1` но entry уже удалена → `diag.total=N` в логе. Логически это "diag.total=N, remaining_streams=N+1".

**Оценка вероятности:** snapshot вызывается только при teardown (~100/h). Race window — порядка наносекунд. Joint probability snapshot-during-Release ≈ window × snapshot-rate ≈ 1ns × 0.028/s = практически 0 events за 4h канарейку.

**Решение:** Оставляем `LoadAndDelete` как был. Если race материализуется в логе — `diag_total < remaining_streams` будет виден напрямую (`diag_total` отдельное поле, см. §2.8) и интерпретируется как явный сигнал "snapshot observed mid-Release". Не разрушает диагностику, не требует структурного fix.

AssignStream получает основной fix (flip order). ReleaseStream — known minor race, документирован.

### 2.6 Snapshot функция

```go
// drainStreamSnapshot аггрегирует per-stream activity для конкретного
// slot'а на момент drain teardown. Используется только в логах,
// inflight cost — один scan streamMap (O(N) где N = ВСЕ active streams
// в pool, не только в target slot — sync.Map.Range не умеет фильтровать).
// Typical N=50-100 streams, scan duration <10μs.
type drainStreamSnapshot struct {
    total           int    // streams attached to target slot
    idleAge30sCount int    // entries с last_write_age >= 30s
    activeCount     int    // entries с last_write_age < 30s
    maxIdleAgeMs    int64  // max age (ms) среди attached streams. 0 если total==0
    minIdleAgeMs    int64  // min age (ms) среди attached streams. 0 если total==0
}

// snapshotDrainStreams scans the pool's streamMap and computes a
// distribution snapshot for streams currently attached to slotIdx.
//
// Concurrency contract:
//   - lastWriteNs is read via atomic.Int64.Load() (no torn read possible).
//   - sync.Map.Range visits each entry at most once; entries removed
//     concurrently by ReleaseStream may or may not appear in the iteration —
//     sync.Map contract permits either, no partial-entry exposure.
//   - All age math operates on local copies; race-free by construction.
//   - lastWriteNs is guaranteed >0 for all entries (set by newStreamEntry
//     via Store at AssignStream time). No zero-clock special case.
//
// Cost: O(N) where N is total active streams across all slots. Typical
// N=50-100, single iter ≈ 10μs. Invoked only at drain teardown — never
// in hot path.
func snapshotDrainStreams(p *WSPoolTransport, slotIdx int, now time.Time) drainStreamSnapshot {
    nowNs := now.UnixNano()
    snap := drainStreamSnapshot{}
    const idleThresholdMs = 30000

    p.streamMap.Range(func(_, value any) bool {
        e := value.(*streamEntry)
        if e.slotIdx != slotIdx {
            return true
        }
        snap.total++
        ageMs := (nowNs - e.lastWriteNs.Load()) / int64(time.Millisecond)
        if ageMs < 0 {
            // Clock went backwards (NTP adjust under Windows, ~100ns scale).
            // Clamp to 0 and bump telemetry counter so a real clock-skew bug
            // (or arbitrary lastWriteNs corruption) is observable, not masked.
            Stats.SnapshotNegativeAgeTotal.Add(1)
            ageMs = 0
        }
        if ageMs >= idleThresholdMs {
            snap.idleAge30sCount++
        } else {
            snap.activeCount++
        }
        if snap.total == 1 || ageMs > snap.maxIdleAgeMs {
            snap.maxIdleAgeMs = ageMs
        }
        if snap.total == 1 || ageMs < snap.minIdleAgeMs {
            snap.minIdleAgeMs = ageMs
        }
        return true
    })
    return snap
}
```

**`lastWriteNs == 0` устранён** (см. M3): `newStreamEntry` всегда stamps. Snapshot не нуждается в специальном branch.

### 2.7 Double-AssignStream — sanity-assert

Семантика: повторный `AssignStream(sameStreamID)` без промежуточного ReleaseStream — **запрещён** на уровне design. Production SOCKS layer гарантирует single-owner per streamID — двойной call не происходит.

Это **sanity-assert, не атомарная защита.** Если future bug в SOCKS layer вызовет double-assign concurrently — наш Load+Store с race window между ними двойной защиты не даст. Цель: ловить нарушение invariant'а post-fact в логе.

`sync.Map.LoadOrStore` дал бы атомарность, но конфликтует с invariant'ом §2.5 (`streams.Add(1)` обязан выполниться ДО `streamMap.Store`). Поэтому используем простой Load+early-return:

```go
if existing, dup := p.streamMap.Load(streamID); dup {
    if e, ok := existing.(*streamEntry); ok {
        p.log.Warn("AssignStream called twice for same streamID without ReleaseStream",
            "stream", streamID, "old_slot", e.slotIdx, "new_slot", minIdx)
    } else {
        p.log.Warn("AssignStream duplicate with non-streamEntry value",
            "stream", streamID, "new_slot", minIdx)
    }
    return
}
p.slots[minIdx].streams.Add(1)
p.streamMap.Store(streamID, newStreamEntry(minIdx))
```

Cost: один extra `sync.Map.Load` на каждом AssignStream — negligible. Type assertion с `, ok` form — defensive против будущих storages непредвиденных типов.

### 2.8 Расширение существующих лог-сообщений

**`WS pool slot drain hard cap reached`** (как INFO, так и WARN ветки в `emitHardCapLog`):

Существующие поля:
```
slot reason remaining_streams drain_duration
```

Добавить:
```
diag_total diag_idle_30s_count diag_active_count diag_max_idle_age_ms diag_min_idle_age_ms
```

`diag_total` — даём отдельно от `remaining_streams` чтобы любой mini-race (см. §2.5 ReleaseStream) был виден напрямую, а не маскировался.

**`WS pool slot drain natural finish (idle)`**:

Существующие поля:
```
slot reason remaining_streams idle_for drain_duration
```

Добавить те же 5 diag-полей.

**`WS pool slot drain natural finish`** (без idle suffix, streams=0):

Snapshot бессмысленен (streams=0). Поля не добавляем.

### 2.9 Что НЕ меняем

- Idle-decision logic в `drainWatchdog` — остаётся per-slot (`oldSlot.lastActivityNs`). Step 2.
- Pool size, drain hard cap, idle threshold, streams max — все ENV defaults без изменений.
- Существующие counters/histograms — без изменений (новый только один: `Stats.SnapshotNegativeAgeTotal` для observability clock skew, см. §2.6).
- Существующие `WS pool drain skipped`, `deferred`, `force-evicted` логи — без изменений.
- `AssignStream` signature — `(streamID uint16)`. Destination не добавляется (требует расширения StreamTransport interface, вне scope).
- `slot.lastActivityNs` stamp position в `slotReaderWithClient` (existing pre-stale-check) — оставляем как был, не трогаем.

---

## 3. Поведенческий контракт

### 3.1 Изменения для observer'а (логи)

**До patch'а:**
```
WS pool slot drain hard cap reached slot=5 reason=age remaining_streams=2 drain_duration=1m30s
```

**После patch'а — case "1 active + 1 idle" (доказательство H1):**
```
WS pool slot drain hard cap reached slot=5 reason=age remaining_streams=2 drain_duration=1m30s diag_total=2 diag_idle_30s_count=1 diag_active_count=1 diag_max_idle_age_ms=87420 diag_min_idle_age_ms=1340
```

**После patch'а — case "2 active" (NOT H1):**
```
WS pool slot drain hard cap reached slot=5 reason=age remaining_streams=2 drain_duration=1m30s diag_total=2 diag_idle_30s_count=0 diag_active_count=2 diag_max_idle_age_ms=2100 diag_min_idle_age_ms=540
```

### 3.2 Изменения для производительности (hot path)

- На каждый `WriteMessage` / `WriteControlMessage`: +1 `streamMap.Load` (уже есть, type assertion `*streamEntry`) + 1 `atomic.Int64.Store` ≈ 5-10 ns.
- На каждый успешный decrypt: +1 `streamMap.Load` (уже есть) + 1 `atomic.Int64.Store` ≈ 5-10 ns.
- Размер `streamEntry` ≈ 24 bytes (int + atomic.Int64) vs существующий int (8 bytes). Net delta = +16 bytes per stream. Под peak 100 streams в pool = +1.6 KB. Negligible.

Под peak 295 MB/5s (канарейка 2026-05-22) трафик ~24K writes/sec — atomic store 5-10 ns. Total <300 μs/sec = 0.03% CPU.

### 3.3 Изменения для teardown latency

- Snapshot scans entire streamMap (O(N) где N = total active streams в pool, не отфильтрованный по slot). Typical N=50-100, scan <10 μs. Invoked только при teardown — никакого hot-path impact.

### 3.4 Совместимость

- ENV flags: ноль изменений.
- Wire protocol: ноль изменений.
- Server-side: ноль изменений.
- StreamTransport interface: ноль изменений.

---

## 4. Тестовая стратегия

### 4.1 Unit tests

1. **`TestStreamEntry_LastWriteNsAtomic`** — race-проверка: N goroutines пишут в один `streamEntry.lastWriteNs` через atomic.Store, никакого data race. Запускается под `-race`.

2. **`TestNewStreamEntry_StampsLastWriteNs`** — после `newStreamEntry(5)`:
   - `entry.slotIdx == 5`
   - `entry.lastWriteNs.Load() > 0` и в пределах 1ms от `time.Now().UnixNano()`

3. **`TestSnapshotDrainStreams_Buckets`** — table-driven, использует `storeStreamForTestWithAge`:
   - 0 streams на slot → `total=0, idle_30s_count=0, active=0, max=0, min=0`
   - 1 active (age=1s) → `total=1, idle_30s_count=0, active=1, max=min≈1000`
   - 1 idle (age=60s) → `total=1, idle_30s_count=1, active=0, max=min≈60000`
   - 2 streams (1 active 1s, 1 idle 60s) → `total=2, idle_30s_count=1, active=1, max≈60000, min≈1000` (это **smoking gun shape** для H1)
   - 5 streams с разными ages → `total=5`, бакеты корректны

4. **`TestSnapshotDrainStreams_OnlyOurSlot`** — streamMap содержит entries для нескольких slot'ов (0, 1, 5), вызываем `snapshotDrainStreams(p, 5, now)` → `total` соответствует только entries для slot=5.

5. **`TestWriteMessageForStream_StampsStreamLastWrite`** — после успешного `WriteMessageForStream(streamID=42, data)`:
   - `streamMap.Load(42).lastWriteNs` обновлён в пределах 1ms от `time.Now().UnixNano()`
   - `slot.lastActivityNs` ТАКЖЕ обновлён (sanity-check что existing path не сломали)

6. **`TestSlotReaderWithClient_StampsStreamLastWrite_AfterValidation`** — два sub-теста:
   - `valid_streamID`: streamID owned by slot=5, slotReader runs on slot=5, decrypt OK → `streamMap[streamID].lastWriteNs` обновлён.
   - `stale_streamID`: streamID owned by slot=3, slotReader runs on slot=5, decrypt returns frame → **stream stamp НЕ обновлён** (stale frame, validation failed). `slot.lastActivityNs` (slot-5) обновляется как было (existing behavior).

7. **`TestAssignStream_OrdersStreamsAddBeforeStore`** — fake slot transport, race detector. Repeated AssignStream → проверка что в любой момент `slot.streams.Load() >= streamMap_entries_for_this_slot`.

8. **`TestAssignStream_DoubleAssignWarns`** — `AssignStream(42)` дважды без `ReleaseStream(42)` между → second call возвращает без замены entry. Лог содержит warning.

### 4.2 Integration tests

**`TestDrainWatchdog_LogsDiagnostics_OnHardCap`**:

Использовать существующий test helper pattern из `ws_pool_drain_test.go::TestDrainWatchdog_HardCapTimeout` (~line 1113). Шаги:
1. Set up pool с mock slots через существующие fixtures.
2. Через `storeStreamForTestWithAge(p, sid_a, slotIdx=5, age=1*time.Second)` — assign one "active" stream.
3. Через `storeStreamForTestWithAge(p, sid_b, slotIdx=5, age=60*time.Second)` — assign one "idle" stream.
4. `p.slots[5].streams.Store(2)` чтобы согласовать с streamMap.
5. Capture log output через testing slog handler (либо bytes.Buffer + slog.NewTextHandler — паттерн из `ws_pool_drain_logging_test.go`).
6. Invoke `drainWatchdog` с short hard cap (10ms), wait teardown.
7. Assert log contains: `WS pool slot drain hard cap reached`, `diag_total=2`, `diag_idle_30s_count=1`, `diag_active_count=1`, `diag_max_idle_age_ms` ≈ 60000±200, `diag_min_idle_age_ms` ≈ 1000±200.

**`TestDrainWatchdog_LogsDiagnostics_OnIdleFinish`**: тот же setup но оба stream'а с age=60s, hard cap 5s, idle threshold 30s → natural-finish (idle) ветка emit'ит diag поля.

### 4.3 Race detector

Все тесты — под `go test -race -count=3 ./client/`. Под Windows без CGO/gcc — fallback на plain (стандартная процедура per `shadowlink/CLAUDE.md`).

### 4.4 Канарейка validation

После merge — запустить `connect-vpn-graceful-drain.bat` на 4h+. Анализ:

#### Sample size планирование

При 4h+ канарейке ожидаем ~300-400 hard caps (baseline 332 за 4h32m). Стандартная ошибка пропорции на n=350 даёт CI ±5pp на 95%. Под n=350 различить 40% vs 50% — за пределами CI, различить 45% vs 50% — на грани. Поэтому критерии ниже выбраны с buffer'ом ≥10pp от 50%.

#### Decision criteria (resolves M4 + R2-H1)

Простая single-formula критерий смешивает H1 и H4 (stale streams) для маленьких `remaining_streams`. Поэтому анализ разбивается на бакеты по `remaining_streams`.

**Step 1 — Bucket hard caps по `remaining_streams`:**

| Bucket | Что искать (H1 shape) |
|---|---|
| `remaining_streams == 1` | Single stream с `idle_30s_count == 1` AND `max_idle_age_ms > 30000` → этот stream полностью молчит, но heuristic не сработал. ВЕРОЯТНО H4 (stale stream, не H1). |
| `remaining_streams == 2` | `idle_30s_count == 1` AND `(max_idle_age_ms - min_idle_age_ms) > 25000` → **bimodal shape "1 active + 1 idle"** — это smoking gun для H1. |
| `remaining_streams >= 3` | `idle_30s_count >= remaining_streams - 1` AND bimodal `max-min > 25000ms` → все-кроме-одного молчат, один активен. H1. |

**Step 2 — Compute confirmed_h1_fraction:**

```
confirmed_h1 = count of hard caps matching H1-shape in their bucket
total_hard_caps = total hard caps in canary
fraction = confirmed_h1 / total_hard_caps
```

**Step 3 — Decision thresholds** (sample size ~300-400 hard caps на 4h+ канарейку, CI ±5pp at 95%):

| confirmed_h1 / total | Интерпретация | Action |
|---|---|---|
| ≥40% | **H1 strong signal**: bimodal shape "active heartbeat + idle siblings" в >40% случаев — пер-slot measurement действительно маскирует idle. | Идём в Шаг 2 (Variant A). |
| ≤15% | **H1 опровергнута**: bimodal shape редок, большинство hard caps это либо truly-active multi-stream, либо H4 stale singletons. | Пересматриваем гипотезы. H4 (stale streams) проверяется отдельно: какая доля `remaining_streams=1 idle_age>30s`? Если значительна — отдельный fix для H4. |
| 15-40% | **Mixed signal**: H1 присутствует но не dominant. | Углубляем диагностику — добавляем list per-stream lastWriteNs ages (не только bucket counts) в логе. Conditional на trigger reason. Не идём в Step 2 пока не разделим причину остаточных hard caps. |

**Sample size note:** На bucket'е `remaining_streams >= 3` исторически ~14% (54/332 в 2026-05-25 канарейке) — это даёт ~50 events за 4h, CI ±15pp. Поэтому делать сильные выводы только по >=3 bucket'у нельзя — главный сигнал из bucket'а `remaining_streams == 2` (55-60% всех hard caps).

**Дополнительный data collection (для понимания, не для decision):**

- Гистограмма `(max_idle_age_ms - min_idle_age_ms)` — bimodal распределение с пиками на (~0, ~60000) = H1.
- Conditional confirmed_h1 fraction по trigger reason (age vs anti_fingerprint vs byte_budget). Ожидание: H1 равномерна по reason'ам.
- `diag.total != remaining_streams` events — если ≥10 events за 4h → есть систематический race не покрытый §2.5 анализом, нужен follow-up.

---

## 5. Inverse / Rollback

### 5.1 Если diagnostic данные показывают другой root cause

Patch остаётся в коде как permanent observability (overhead negligible). Под новую гипотезу пишется отдельный spec.

### 5.2 Если обнаружен performance regression

Git revert полного PR (production + tests) — атомарно. Никаких внешних зависимостей. Снапшот данных канарейки и логов остаётся для post-mortem.

### 5.3 Если data race найден в production

Снапшот iterates sync.Map — safe by sync.Map contract. Atomic.Int64 — safe. Двойной AssignStream защищён через LoadOrStore-like pattern. ReleaseStream race documented as known minor (см. §2.5). Если что-то найдётся — добавить regression test, mitigate в отдельном patch'е, не revert.

---

## 6. Resolved Questions

После двух rounds Opus review все технические open questions резолвены в spec'е.

**Round 1 (3 HIGH + 6 MEDIUM + 4 LOW + 3 NIT):**

- ✅ Race AssignStream (R1-H3) → flip order: `streams.Add(1)` ДО `streamMap.Store`.
- ✅ Stamp position vs stale-frame (R1-H2) → stream-stamp **только** после успешной валидации `slotIdx == idx`.
- ✅ Полный call-sites list (R1-H1) → §2.2 + test helpers.
- ✅ `lastWriteNs == 0` edge case (R1-M2/M3) → `newStreamEntry` всегда stamps; zero-case устранён.
- ✅ Atomic semantics (R1-M1) → docstring snapshot функции явно фиксирует.
- ✅ Test orchestration (R1-M6) → ссылка на конкретный existing pattern.
- ✅ ReleaseStream race → принят как known minor, документирован в §2.5 (с corrected arithmetic после R2-M2).

**Round 2 (1 HIGH + 4 MEDIUM + 3 LOW + 2 NIT):**

- ✅ Decision criteria formula bug (R2-H1) → §4.4 переписан с bucket'ами по `remaining_streams` + bimodal shape (`max - min > 25000ms`) в основной критерий.
- ✅ Stamp position vs RouteToStream (R2-M1) → §2.4 явно документирует known limitation (wire activity, не application-level consumption).
- ✅ ReleaseStream race arithmetic (R2-M2) → §2.5 переписано с честным расчётом probability.
- ✅ "LoadOrStore-like" misleading wording (R2-M3) → §2.7 переформулировано как sanity-assert.
- ✅ Clock skew counter (R2-M4) → `Stats.SnapshotNegativeAgeTotal` для observability.
- ✅ Type assertion safety (R2-L3) → `, ok` form в §2.7.
- ✅ W5 invariant formulation (R2-L2) → §2.5 уточнено.
- ✅ ReleaseStream verbosity (R2-L1) → §2.5 сокращён.
- ✅ Scope split включает test layer (R2-N1) → §1.1 уточнено.

---

## 7. References

- Research: `shadowlink/docs/superpowers/canary-reports/2026-05-25-natural-ratio-gap-research.md`
- Существующая graceful drain логика: `client/ws_pool_drain.go::drainWatchdog`, `client/ws_pool.go::WSPoolTransport`
- Канарейка 2026-05-25: `C:\Users\Lenovo\AppData\Local\Temp\nixavpn-graceful-drain-20260525-095219.log`

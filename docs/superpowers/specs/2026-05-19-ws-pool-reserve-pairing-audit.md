# WS Pool Reserve Pairing Audit — 2026-05-19

**Контекст:** канарейка показала 326 deferred drain'ов за 23 минуты после двух
успешных drain'ов (primary[6]→reserve[8], primary[2]→reserve[9]). Storm brake
заклинило навсегда на `non_ready_slots=2` потому что `countNonReadySlots()`
ожидает «парность» reserve[i+poolSize] ↔ primary[i], а реальный аллокатор
`claimFreeReserveSlot()` выдаёт **первый свободный** reserve idx.

Этот аудит — *систематический* поиск **всех** мест, где живёт то же ошибочное
предположение, плюс архитектурный вопрос «парность vs независимость».

---

## TL;DR

Базовый дизайн-инвариант spec'и (`shadowlink/docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md`)
говорит явно: **«primary и reserve ячейки циркулируют»** (§Reserve slot
promotion to primary, line 101) — то есть после teardown primary[oldIdx]
становится `nil`, а reserve[newIdx] фактически становится «primary» в той
ячейке, где он лежит. Это **архитектура независимых ячеек, НЕ парных**.

Текущий код частично следует этой архитектуре (claimFreeReserveSlot —
first-nil), а частично — старой парной (countNonReadySlots:
`i + p.poolSize`). Это противоречие живёт в **двух точках кода** в
`ws_pool.go`, **двух точках документации** там же, и **двух тестах**, которые
случайно проходят, потому что используют парный layout.

Дополнительно есть **четыре места**, где итерация ограничена `[0, poolSize)`
и потому полностью пропускает reserve cells, превратившихся фактически в
primary после первого же drain — это **architectural debt category 2**.

---

## 1. Места с парностью-bug (по убыванию severity)

### CRITICAL — ломает в проде (canary already observed)

#### B1. `countNonReadySlots` primary→reserve mapping (`ws_pool.go:601-638`)

```go
// Primary range
if slot == nil {
    reserveIdx := i + p.poolSize          // <-- BUG: парность
    if reserveIdx < len(p.slots) && p.slots[reserveIdx] != nil &&
        p.slots[reserveIdx].getState() == slotReady {
        continue // capacity provided by reserve
    }
    n++
    continue
}
```

**Что сломано:** primary[6] = nil после teardown. Код смотрит slots[14].
Реальный reserve лежит в slots[8] (первая свободная reserve cell, по
`claimFreeReserveSlot()`). slots[14] = nil → код считает primary[6] как gap →
`n++`. Через два drain'а n=2 навсегда, threshold=2, brake заклинивает.

**Подтверждено:** canary report — 326 deferred за 23 мин, `non_ready_slots=2`.

#### B2. `countNonReadySlots` reserve→primary mapping (`ws_pool.go:627-633`)

```go
if st == slotConnecting {
    primaryIdx := i - p.poolSize          // <-- BUG: та же парность в обратную сторону
    if primaryIdx < p.poolSize && p.slots[primaryIdx] != nil &&
        p.slots[primaryIdx].getState() == slotDraining {
        continue // parallel drain replacement, capacity preserved
    }
}
```

**Что сломано:** parallel-replacement exception для slotConnecting reserve
cell работает **только** если reserve был выделен по правилу `i+poolSize`.
В нашем аллокаторе reserve может быть в ANY свободной ячейке. Сценарий:
primary[6] draining, reserve[8] connecting. Код смотрит на primary[8-8]=
primary[0] (slotReady, не draining) → НЕ применяет exception → reserve[8]
считается non-ready → n++. Storm brake может заклинить уже на ПЕРВОМ drain'е
если повезёт с сочетанием состояний.

**Подтверждено логикой:** `TestStartDrain_StormBrakeSingleDrain` (drain_test.go:953)
проходит ТОЛЬКО потому что использует парный layout (primary[0] draining,
reserve[8] connecting) — то есть тест ложно подтверждает корректность.

---

### BLOCKER — ломает корректность семантики

#### B3. Doc-comment в `ws_pool.go:570-595` (описание countNonReadySlots)

Цитата:
> Primary range [0, poolSize):
>   - nil cell: check if matching reserve cell[i+poolSize] is in slotReady
> Reserve range [poolSize, 2*poolSize):
>   - slotConnecting: check if matching primary cell[i-poolSize] is in slotDraining

Это явная декларация парного инварианта, противоречащая spec §Reserve slot
promotion to primary. Сам doc — источник bug'а, тот, кто будущее писал
countNonReadySlots, копировал из этого doc'а.

#### B4. Doc-comment в spec'е (`2026-05-19-ws-pool-graceful-drain-design.md:481-499`)

```go
// Updated rule for primary range:
if i < p.poolSize {
    if slot == nil {
        // Check if matching reserve cell took over (drain finished).
        reserveIdx := i + p.poolSize
        ...
```

В spec'е инвариант «matching reserve cell» введён **умышленно** в FIX C3
(line 481-499), но **противоречит** §«primary and reserve cells circulate»
(line 101). Это **внутреннее противоречие самой спеки** — фикс C3 откатывает
гибкость которую §Reserve slot promotion декларирует.

---

### WARNING — пропускает reserve cells, превратившихся в фактический primary

#### B5. `rotationWatchdogSweep` (`ws_pool.go:1144-1187`)

```go
// Loop scope limited to primary range [0, poolSize) — reserve cells
// are not directly drained by the age trigger; they cycle into the
// primary range via the drain machinery first.
for idx := 0; idx < p.poolSize; idx++ {
```

**Что сломано:** комментарий говорит «reserve cycles into primary via drain
machinery first», но в текущем коде reserve[8] **никогда** не переедет в
primary[6] — он там и останется. Через 2 минуты reserve[8] перерастёт
MaxSlotAge, но watchdog его **не увидит**, и он умрёт через middlebox-kill
(close 1006) → recordSlotDeath → false meltdown.

Это **второй порядок** того же bug'а: watchdog зависит от парности, чтобы
«никогда не видеть reserve напрямую».

#### B6. `sendKeepaliveToAllSlots` (`ws_pool.go:1276`)

```go
for i := 0; i < p.poolSize; i++ {
    slot := p.slots[i]
    ...
```

Reserve cells не получают keepalive → если reserve[8] остался единственным
«живым» в позиции 0 после teardown primary[0], нет keepalive → CF idle
timeout (900s) убъёт TCP → false natural death.

#### B7. `rotateMinLoadedSlot` anti-FP rotation (`ws_pool.go:1748`)

```go
for i := 0; i < p.poolSize; i++ {
    slot := p.slots[i]
    if slot == nil || slot.getState() != slotReady {
        continue
    }
    ...
```

Если after-drain reserve[8] фактически serves traffic как primary,
rotationLoop (anti-FP timer 2-8min) **никогда не выберет его на ротацию**.
Slot живёт вечно → anti-fingerprinting goal не достигнут для тех cells,
которые когда-то были reserves.

#### B8. `StartReader` (`ws_pool.go:2073`)

```go
for i := 0; i < p.poolSize; i++ {
    if p.slots[i] == nil || p.slots[i].getState() != slotReady {
        continue
    }
    ...go p.slotReaderWithClient(ctx, cl, idx)
```

Reserve readers стартуют только через `connectReserveSlot → go p.slotReader(newIdx)`
(drain.go:146). Если внешний engine рестартанул StartReader (после «all
readers exited»), reserve readers НЕ перезапустятся. Зависим от readerActive
CAS для предотвращения race, но reader exit при reconnect reserve cell
оставит её без reader навсегда.

#### B9. `WSPoolTransport.Connect` initial fan-out (`ws_pool.go:1062`)

```go
for i := 0; i < p.poolSize; i++ {
    ...
    go func(idx int) { ...; results[idx] = p.connectSlot(ctx, idx) }(i)
}
```

Это нормально на initial connect (reserve cells должны стартовать nil), но
вместе с B8 формирует архитектурную ассимметрию: primary стартует через
Connect, reserve — через connectReserveSlot.

---

### INFO — менее критично, но контекстно

#### B10. `SessionForStream` fallback restricted to primary (`ws_pool.go:1979-1989`)

```go
// Fallback: return first available session from primary range only.
// Reserve slots have their own sessions belonging to specific drain
// replacements; using a reserve session for a stream not assigned to
// that slot would yield decrypt mismatches at the server.
for i, slot := range p.slots {
    if i >= p.poolSize {
        break
    }
    ...
}
```

**Это не bug, но архитектурный сигнал:** код сам признаёт, что reserve session
≠ primary session per-stream. Если архитектурно решить «cells взаимозаменяемы»
— этот fallback нужно либо снять (любой ready slot годится для non-stream),
либо явно бороться (привязать session к streamID, не к slot index).

#### B11. `claimFreeReserveSlot` сам ограничен reserve range (`ws_pool_drain.go:28-40`)

```go
for i := p.poolSize; i < len(p.slots); i++ {
    if p.slots[i] == nil {
        ...
```

Это **противоречит** spec §Reserve slot promotion. Если primary[0] стал nil
(после первого drain teardown), то по spec'е «primary[0] теперь свободен и
может быть переиспользован как новый reserve target». Текущий код этого НЕ
делает — он ищет только в reserve range, что усиливает «swiss cheese»: после
8 drain'ов primary range весь nil, reserve range весь занят, и `findFreeReserve
returns -1` → drain'ы deferred навсегда (другая форма того же зависания, но
через 8 drain'ов вместо 2).

---

## 2. Тесты, которые не ловят bug (используют парный setup)

| Тест | Файл:строка | Почему false-positive |
|---|---|---|
| `TestCountNonReadySlots_IgnoresEmptyReserve` | `ws_pool_drain_test.go:19-66` | Использует `slots[0] draining + slots[4] connecting` для poolSize=4 — это парность 0↔4 ровно по формуле. Если бы тест поставил `slots[5]` вместо `slots[4]` — провалился бы. |
| `TestStartDrain_StormBrakeSingleDrain` | `ws_pool_drain_test.go:953-988` | `primary[0] draining + reserve[8] connecting` для poolSize=8 — парность 0↔8 ровно. С `reserve[12]` тест бы провалился. |
| `TestStartDrain_StormBrakeTwoConcurrentEngages` | `ws_pool_drain_test.go:993-1048` | `primary[0,1] draining + reserve[8,9] connecting` — парность 0↔8, 1↔9. Реальность canary: primary[6,2] → reserve[8,9] — НЕ парность. Тест бы провалился. |
| `TestClaimFreeReserveSlot_PrefersFirstNil` | `ws_pool_drain_test.go:382-415` | Использует свежий пул, где первый claim → idx=4 — выглядит парным с primary[0], но это случайность first-nil. Тест **не проверяет** что claim корректно работает после `p.slots[0] = nil` (post-teardown reuse primary as reserve target). |
| `TestHandleSlotDeath_DrainTeardownClearsCell` | `ws_pool_drain_test.go:156-184` | Делает teardown primary[0], проверяет что `p.slots[0] = nil`. Никогда не проверяет что после этого claim вернёт idx=0 (per spec'е) или idx=2 (per current code). |
| `TestDrainWatchdog_NaturalFinish` | `ws_pool_drain_test.go:478-521` | Аналогично — teardown primary[0], нет следующего drain'а на освободившуюся ячейку. |

**Тесты, которые «правильно» сделаны (НЕ ловят bug, но и не маскируют):**
`TestWriteMessageForStream_AcceptsDraining`, `TestAssignStream_SkipsDraining`,
`TestHandleSlotDeath_DrainTeardownDoesNotCloseStreamChans` — они тестируют
поведение per-slot без зависимости от parity.

**ВАЖНОЕ ДОПОЛНЕНИЕ:** `TestHandleSlotDeath_DrainTeardownDoesNotCloseStreamChans`
(line 1093+) фиксирует поведение «streamChans **не** закрываются на drain
teardown». Это противоречит финальному decision в spec'е §Race conditions
fix #4 (line 357-361): «drainTeardown упрощается: закрывает streamChans
(как deathCauseNatural), НЕ инкрементирует metrics, НЕ запускает reconnectLoop».
Текущий production-код в `handleSlotDeath` (ws_pool.go:2485-2509) **закрывает**
streamChans для drainTeardown (ветка `if cause != deathCauseDrainTeardown`).
Сам spec в одной части (§deathCauseDrainTeardown) говорит «НЕ закрывать», в
другой части (§Race fix #4) — «закрывать». Тест и код разошлись. Это
**отдельный bug** не связанный с парностью, но обнаружился в этом обзоре.

---

## 3. Race conditions / TOCTOU

### R1. Snapshot-inconsistent read в countNonReadySlots (`ws_pool.go:597-601`)

Doc-comment явно признаёт:
> snapshot-inconsistent reads of paired primary/reserve cells are tolerated
> because the brake re-evaluates on the next watchdog sweep

Это OK теоретически, но **в новой архитектуре без парности** возможна
ситуация: thread A читает primary[6]=nil, thread B стартует connectReserveSlot
для нового drain'а который попал в reserve[14] (потому что reserve[8,9]
заняты), thread A смотрит slots[14]=nil → считает primary[6] как gap. Через
5s sweep, картина может уже стать другой. **Acceptable**, но шум добавляет.

### R2. SessionForStream race с teardown primary[oldIdx]=nil

После drain teardown `p.slots[oldIdx] = nil` (под reserveMu). Если stream
уже unmapped (streamMap.Delete), `SessionForStream(sid)` фоллбэчится в
primary range first-ready. Если ВСЕ primary nil после серии drain'ов (B5,
B7 архитектурного дрейфа) — fallback вернёт nil. Не bug сейчас, но риск
если архитектурный дрейф усугубится.

---

## 4. Категоризация по severity

| Severity | Count | IDs |
|---|---|---|
| CRITICAL | 2 | B1, B2 |
| BLOCKER | 2 | B3, B4 |
| WARNING | 5 | B5, B6, B7, B8, B9 |
| INFO | 2 | B10, B11 |
| Race | 2 | R1, R2 |
| Test gaps | 6 | TestCountNonReadySlots_IgnoresEmptyReserve, TestStartDrain_StormBrakeSingleDrain, TestStartDrain_StormBrakeTwoConcurrentEngages, TestClaimFreeReserveSlot_PrefersFirstNil, TestHandleSlotDeath_DrainTeardownClearsCell, TestDrainWatchdog_NaturalFinish |

---

## 5. Рекомендуемая архитектура

### Вопрос: парность vs независимость

**Парность (текущая частично-внедрённая):**
- + Простой формальный invariant: «cell i serves slot mod poolSize».
- − Требует `claimFreeReserveSlot` искать **строго** `i + poolSize`, а не
  first-nil. Это означает что если reserve[i+poolSize] занят (concurrent
  drain'ы), новый drain невозможен — даже если другие reserve cells пусты.
- − Storm brake threshold = 2 означает «не более 2 concurrent drain'ов»,
  что при парности **жёстко** ограничивает: одна занятая reserve cell
  блокирует ВЕСЬ её primary, а не просто «есть resourse pressure».
- − Не выживает «promote reserve to primary» (§spec line 101): после
  teardown primary[0]=nil, чтобы её использовать как новый reserve target
  для drain[3]→reserve[0] — парность ломается (3 не пара 0).

**Независимость (рекомендую):**
- + Любая `ready` cell в slice = capacity. Любая `nil` cell = свободный
  слот для claim'а.
- + Storm brake становится **purely capacity-based**: считаем `ready_count`
  (count of slotReady cells), defer drain если `ready_count <
  threshold_for_capacity`. Threshold для poolSize=8: «не drain если ready
  < 6», то есть гарантируем 75% capacity всегда.
- + `claimFreeReserveSlot` ищет first-nil **во всём slice** (не только в
  reserve range), позволяя переиспользовать освобождённые primary cells
  как reserve targets.
- + Соответствует §Reserve slot promotion to primary в spec'е (line 101).
- − Требует унифицировать ВСЕ итерации: либо «по всему slice» (для health/
  keepalive/watchdog), либо «по slotReady cells» (для AssignStream — уже
  так), либо «по cells с активными streams» (для teardown). Никакого
  `i < poolSize` гейта по индексу.

**TSPU давление и graceful semantics:**
- При независимости быстрая ротация при TSPU не ограничена reserve range —
  можно одновременно draining'нуть 2-4 cells и поднять их replacements в
  любых свободных ячейках. Под нагрузкой это критично.
- При парности дрейф «pool становится swiss cheese» неминуем после ~8
  drain'ов (все reserve cells заняты, все primary nil) → дальнейшие drains
  невозможны → fallback на legacy hard rotation? Не работает по дизайну.

**Рекомендация: переходить на независимость.**

### Конкретные изменения

1. **`countNonReadySlots`** → **`readyCapacity`**: вернуть
   `count of cells with state == slotReady`. Storm brake:
   `if readyCapacity < (poolSize - threshold) { defer }`.
   Никакого `i + poolSize` мэппинга. Никакого primary/reserve distinction.

2. **`claimFreeReserveSlot`** → **`claimFreeSlot`**: искать first-nil во
   **всём** slice. Удалить логику «reserve range only».

3. **Унифицировать все итерации**:
   - `rotationWatchdogSweep` — итерировать `range p.slots`, не `[0, poolSize)`.
   - `sendKeepaliveToAllSlots` — то же.
   - `rotateMinLoadedSlot` — то же.
   - `StartReader` — то же (но осторожно с readerActive CAS, чтобы не
     дублировать readers от connectReserveSlot).

4. **`emitHealthSummary`** — упростить: nil cell = просто «empty slot»,
   без `dead++` для primary range.

5. **Phase 4 cleanup в spec'е** надо переформулировать: вместо «retire
   legacy path», явно сказать «pool layout: 2*poolSize slice, ALL cells
   equivalent, no primary/reserve distinction. Aged cells drain, new cells
   come up in any free index».

6. **`Connect` (initial fan-out)** оставить ограниченным `[0, poolSize)` —
   это initial state target. После любого drain слой может «дрейфовать»
   в любые ячейки, что OK при независимости.

### Тесты для переписать

- `TestCountNonReadySlots_IgnoresEmptyReserve` → переименовать в
  `TestReadyCapacity_CountsAllReady`, проверить что reserve ready cells
  считаются как capacity без `i + poolSize` логики. Использовать
  непарный layout (primary[6] + reserve[14]).
- `TestStartDrain_StormBrakeSingleDrain` → использовать `primary[6] +
  reserve[9]` (НЕ пара 6↔14). После фикса тест должен показывать
  `readyCapacity = poolSize - 1 = 7` → brake disengaged.
- `TestStartDrain_StormBrakeTwoConcurrentEngages` → использовать
  `primary[6,2] + reserve[8,9]` (canary scenario). После фикса:
  `readyCapacity = 6 + 0 = 6` (или 8 если reserves уже ready). Threshold —
  на основании capacity.
- Добавить новый: **`TestClaimFreeSlot_ReusesPostTeardownPrimary`** — после
  teardown primary[3], следующий claim должен иметь возможность вернуть
  idx=3 (per spec §Reserve slot promotion to primary).
- Добавить новый: **`TestCanaryScenario_MismatchedPairs`** — воспроизвести
  exact canary: drain primary[6] → reserve[8], drain primary[2] →
  reserve[9]. После фикса pool должен показать `readyCapacity = 8` (6
  ready primaries + 2 ready reserves), storm brake disengaged, дальнейшие
  drains возможны.
- Опционально: **`TestSwissCheesePool_ContinuesDraining`** — после 8
  drain'ов (все primary nil, все reserves ready), 9-й drain должен либо
  переиспользовать nil primary cell, либо drain один из reserves. Текущая
  парная архитектура этот тест провалит.

---

## 6. Зависимости перед фиксом

Перед началом фикса обязательно:

1. Решить противоречие в спеке: §«primary and reserve cells circulate»
   (line 101) vs §«matching reserve cell» в countNonReadySlots fix
   (line 481-499). Я рекомендую первое (независимость) — spec нужно
   переписать.

2. Решить противоречие в коде: `TestHandleSlotDeath_DrainTeardownDoesNotCloseStreamChans`
   vs production handleSlotDeath закрывает streamChans на drainTeardown.
   Это **отдельный bug** не связан с парностью, но всплыл в обзоре.

3. Подтвердить с user'ом: «делаем architecture cleanup сейчас» (большой
   refactor, 2-4 часа) vs «точечный фикс B1/B2 сейчас, architecture
   cleanup в Phase 4». Точечный фикс — превратить B1/B2 в «scan reserve
   range for any ready cell with primaryIdx → if primary[i] is nil AND
   any reserve.state==slotReady exists with no live primary covering it,
   exempt one such reserve». Грязный workaround.

---

## References

- `ws_pool.go:601-638` — `countNonReadySlots` (B1, B2)
- `ws_pool.go:570-595` — doc-comment of countNonReadySlots (B3)
- `ws_pool_drain.go:28-40` — `claimFreeReserveSlot` (B11)
- `ws_pool.go:1144-1187` — `rotationWatchdogSweep` (B5)
- `ws_pool.go:1274-1296` — `sendKeepaliveToAllSlots` (B6)
- `ws_pool.go:1745-1769` — `rotateMinLoadedSlot` (B7)
- `ws_pool.go:2069-2098` — `StartReader` (B8)
- `ws_pool.go:1055-1103` — `Connect` (B9)
- `ws_pool.go:1969-1990` — `SessionForStream` fallback (B10)
- `2026-05-19-ws-pool-graceful-drain-design.md:101` — «cells circulate» invariant (contradicts B4)
- `2026-05-19-ws-pool-graceful-drain-design.md:481-499` — «matching reserve» rule (B4)
- canary observation: 326 deferred drains in 23 min, `non_ready_slots=2`

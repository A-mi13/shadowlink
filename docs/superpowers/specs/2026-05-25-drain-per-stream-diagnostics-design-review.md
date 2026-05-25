# Code review — Per-stream activity diagnostics + idle infrastructure (design spec)

**Дата ревью:** 2026-05-25
**Ревьюер:** Claude (Opus, max effort)
**Ревью-объект:** `shadowlink/docs/superpowers/specs/2026-05-25-drain-per-stream-diagnostics-design.md`
**Связанные документы:** research `2026-05-25-natural-ratio-gap-research.md`, существующий код `client/ws_pool.go`, `client/ws_pool_drain.go`

---

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH     | 3 |
| MEDIUM   | 6 |
| LOW      | 4 |
| NIT      | 3 |

**Verdict:** APPROVE_WITH_CHANGES.

Дизайн в целом обоснован: гипотеза H1 сформулирована корректно, инфраструктурный шаг (snapshot + дополнительные diag-поля) — правильная стратегия "сначала измерь, потом чини". Hot-path overhead и race-safety в общих чертах рассмотрены. Однако спека **умалчивает о нескольких неочевидных деталях**, которые при наивной имплементации либо дадут data race (точечно), либо обнулят диагностическую ценность собранных данных, либо потребуют переписывать значительные куски тестов. Все правки локальные и должны попасть **в spec до начала имплементации**, иначе будет неоднозначность.

Перечень изменений ниже отсортирован по severity.

---

## HIGH

### H1. Полный список call-sites streamMap НЕ перечислен — спека пропускает 3 production-сайта и весь test layer

**Где в спеке:** §2.1, §2.2 описывают только три точки обновления (`WriteMessageForStream`, `WriteControlMessageForStream`, `slotReaderWithClient`). Никакого явного списка сайтов, которые нужно мигрировать с `int` на `*streamEntry`.

**Реальный список (grep по `p.streamMap.` в `client/`):**

| Файл:строка | Операция | Изменение нужно |
|---|---|---|
| `ws_pool.go:2014` | `Store(streamID, minIdx)` (AssignStream) | Store `*streamEntry{slotIdx:minIdx}` |
| `ws_pool.go:2023` | `Load` (IncrPending) | `v.(*streamEntry).slotIdx` |
| `ws_pool.go:2033` | `Load` (DecrPending) | `v.(*streamEntry).slotIdx` |
| `ws_pool.go:2043` | `Load` (SlotPending) | `v.(*streamEntry).slotIdx` |
| `ws_pool.go:2072` | `LoadAndDelete` (ReleaseStream) | `v.(*streamEntry).slotIdx` |
| `ws_pool.go:2087` | `Load` (SessionForStream) | `v.(*streamEntry).slotIdx` |
| `ws_pool.go:2113` | `Load` (WriteMessageForStream) | `v.(*streamEntry).slotIdx` + stamp `lastWriteNs` |
| `ws_pool.go:2137` | `Load` (WriteControlMessageForStream) | `v.(*streamEntry).slotIdx` + stamp |
| `ws_pool.go:2447` | `Load` (stale-frame check, W5) | `v.(*streamEntry).slotIdx` + stamp (см. H2) |
| `ws_pool.go:2658` | `Range` (handleSlotDeath cleanup) | `value.(*streamEntry).slotIdx` |
| `ws_pool.go:2663` | `Delete` | без изменений |
| `ws_pool_test.go:25,34,61,80,96` | `Load(...).(int)` | переделать на `*streamEntry` |
| `ws_pool_drain_test.go:122,147,1113,1153,1196,1244,1250,1550,1554` | `Store(uint16, int)` + `Load(...).(int)` | переделать на конструктор `*streamEntry` |

**Что пропустила спека:**
- IncrPending / DecrPending / SlotPending (3 сайта) — нужны для CONNECT pending tracking. Если их забыть в имплементации, AssignStream получит `*streamEntry` а IncrPending всё ещё ожидает `int` → panic при первом же CONNECT.
- handleSlotDeath `Range` — без явного указания на `value.(*streamEntry).slotIdx` ревьюер плана может пропустить.
- **Весь test layer (5+ файлов, ≥14 сайтов)** — `p.streamMap.Store(uint16(X), 0)` напрямую с literal `int`. Это сломает компиляцию **всех** drain-тестов сразу после refactor'а. Spec не упоминает что нужен helper-конструктор (`storeStreamForTest(p, sid, idx)`) или массовый rewrite.

**Severity rationale:** "type assertion panic при первом write" — это HIGH, потому что есть гарантированный путь к багу если имплементатор полагается только на спеку.

**Fix:** §2.2 заменить таблицу из 3 строк на полную из 11 production + указать в §4 что test layer мигрируется отдельной подзадачей с helper-функцией. Идеально — поместить helper в production-код (`func storeStreamForTest`) под build tag или в `*_helper_test.go` (внутри package, common).

---

### H2. Семантика "wire activity" для idle-detection несовместима с местом stamping'а в decrypt path

**Где в спеке:** §2.2 говорит "в `slotReaderWithClient` после `DecryptChunkSafe`" — но не уточняет, ДО или ПОСЛЕ stale-frame check (`ws_pool.go:2447`).

**Где в коде:** `ws_pool.go:2436-2459`:

```
2436: // Stamp activity for drainWatchdog
2439: slot.lastActivityNs.Store(time.Now().UnixNano())     // SLOT stamp ДО streamID parse
2441: msgCount++
2442: streamID := uint16(...)
2447: if v, ok := p.streamMap.Load(streamID); ok {
2448:    if v.(int) != idx {
2449:        Stats.StaleFrameDroppedTotal.Add(1)
2450:        continue                                       // ← stale frame dropped, но slot уже отмечен!
2451:    }
2452: }
```

**Проблема для per-stream stamping:** где именно stamp'ить `lastWriteNs`?

- Вариант A: ДО stale-frame check (как сейчас slot-stamp на 2439) — отмечает stream'а ДО валидации владельца. Но если streamID был reassign'ен на другой slot, мы stamp'нем активность на *нашем* slotEntry, чьё `slotIdx` мог быть переписан AssignStream — race + неверная классификация.
- Вариант B: ПОСЛЕ stale-frame check, только при `v.(*streamEntry).slotIdx == idx` — корректно для per-stream, но тогда **slot-stamp на строке 2439 семантически становится более consistent если ТОЖЕ перенести после check** (иначе slot пометится активным от чужого frame'а — это уже existing bug, но per-stream invariant его делает заметным).
- Вариант C: Stamp'ить и slot-stamp, и stream-stamp **внутри** if-блока после успешного `slotIdx == idx`.

Спека этот вопрос вообще не поднимает. Имплементатор может выбрать любой вариант — каждый ведёт к разной интерпретации `diag_active_count` в логах.

**Severity:** HIGH потому что от выбора зависит **что именно мы измеряем в канарейке**. Если выбрать вариант A, diagnostic'и будут систематически завышать `active_count` (frames от refused streamID'ов). Если B — нужно явно объявить semantic'у "activity = wire activity, owned by THIS stream entry".

**Fix:** §2.2 явно зафиксировать: stamp `lastWriteNs` происходит **только после успешной валидации `entry.slotIdx == idx` в `slotReaderWithClient`** (вариант C). Plus — обсудить в спеке должен ли slot-stamp ALSO переехать после валидации, или это вне scope (мой предпочтительный вариант — да, оставить out-of-scope, но явно сказать "оставляем существующий slot-stamp на 2439 как был, чтобы не trip'нуть никакие existing-баги вместе с этим refactor'ом").

---

### H3. Race: AssignStream создаёт *streamEntry, но `slot.streams.Add(1)` идёт ПОСЛЕ `streamMap.Store` → snapshot может видеть entry без увеличения counter'а

**Где в коде:** `ws_pool.go:2014-2015`:

```go
p.streamMap.Store(streamID, minIdx)        // снепшот может Load
p.slots[minIdx].streams.Add(1)             // снепшот может ещё НЕ видеть инкремент
```

**Это existing race**, но per-stream snapshot **усиливает его последствия**: 
- `drainWatchdog.tearDown` сначала смотрит `oldSlot.streams.Load()` (т.е. `2018`), потом вызывает `snapshotDrainStreams` (новый код), который итерирует `streamMap`. 
- Если AssignStream race'ит между этими двумя точками — snapshot увидит **больше** entry чем `streams.Load()` отрапортовал. Поле `total` в `drainStreamSnapshot` рассинхронизируется с `remaining_streams` в логе.

В логе появятся записи `remaining_streams=2 diag_active_count=2 diag_idle_30s_count=1` — totally consistent с `diag.total=3`, но логически непонятно: "три stream'а активны + один idle, но remaining=2?" Это создаст ложную тревогу в анализе.

**Severity:** HIGH потому что разрушает доверие к diagnostic'у в edge case'ах (а edge case'ы — это ровно то что мы хотим расследовать).

**Fix:** §2.3 явно описать сценарий и решение. Варианты:
- (a) Игнорировать (race окно <microsecond, при 332 hard cap'ах в 4h за всё время может встретиться 0-1 раз) — но **указать это** в спеке как known-limitation.
- (b) В `snapshotDrainStreams` clamp `total` к `oldSlot.streams.Load()` — отбросить excess как inflight assignment.
- (c) Зафиксировать invariant "AssignStream stamps streamMap СТРОГО после streams.Add" — flip двух строк, перепроверить W5 stale-frame check (он завязан на этот же порядок).

Минимум: упомянуть в spec. Сейчас вообще не поднято.

---

## MEDIUM

### M1. `atomic.Int64` без явного указания, что snapshot читает АТОМАРНО

**Где в спеке:** §2.3 пример кода:

```go
type drainStreamSnapshot struct { ... }
func snapshotDrainStreams(p *WSPoolTransport, slotIdx int, now time.Time) drainStreamSnapshot {
    // итерация streamMap, выборка только entries с slotIdx == oldIdx
    // ...
}
```

Спека ни разу не пишет в явном виде "snapshot reads `entry.lastWriteNs.Load()` (atomic.Int64) — never accesses the raw int64 field". Под Go 1.19+ это формально гарантировано типом `atomic.Int64` (нет публичного raw access), но для имплементатора, читающего спеку, это должно быть **явно**.

Также — снапшот хранит локальные копии `lastWriteNs` в `drainStreamSnapshot`. Между Load и `time.Since(time.Unix(0, ageNs))` тоже не должно быть data race — но т.к. это локальная переменная, всё OK. Это **должно быть** сказано в spec.

**Fix:** §2.3 добавить параграф: "All reads of `lastWriteNs` are via `atomic.Int64.Load()`. The snapshot captures the value into a local `int64` variable; subsequent arithmetic (`now.UnixNano() - localCopy`) operates on the snapshot and is race-free by construction."

---

### M2. Edge case "lastWriteNs==0" описан только в §4.1 (test), но НЕ в §2.3 (snapshot semantic)

**Где в спеке:** §4.1 test #3 упоминает: "stream с `lastWriteNs == 0` (свежеассайнен, ни одного write ещё не было) — учитывается как `activeCount++`". Хорошо.

Но §2.3 (где описывается сама функция `snapshotDrainStreams`) этого не упоминает. Имплементатор может написать `if entry.lastWriteNs.Load() == 0 { skip }` либо `ageMs := (now - 0) / 1e6` (огромное число → ложное `idle_30s_count++`). Только обнаружит логику через тест.

**Fix:** §2.3 явно зафиксировать contract: "If `entry.lastWriteNs.Load() == 0`, classify as active (just-assigned), skip min/max update, increment activeCount. Reason: stream was assigned but hasn't been written through yet — treating zero-clock as `age=now` would always classify it as idle, masking the case where AssignStream is followed by a slow first write."

Также подумать: **a что если AssignStream stamps lastWriteNs одновременно** (см. M3 ниже)? — устранит этот edge case полностью.

---

### M3. AssignStream НЕ stamps lastWriteNs — possible improvement или явное anti-decision?

**Где в спеке:** не покрыто.

**Контекст:** `AssignStream` создаёт `*streamEntry` с `lastWriteNs=0`. Между assign и первым write может пройти несколько секунд (CONNECT roundtrip + server handshake). За это время stream **технически активен** (только что присоединился), но snapshot увидит lastWriteNs=0.

Опция A (current spec): zero = special case, classify as active. Работает, но требует помнить.
Опция B (clean): `AssignStream` ставит `lastWriteNs = time.Now().UnixNano()` сразу после Store. Тогда invariant простой "lastWriteNs всегда > 0 для valid entry, classify by age". Cost: +1 atomic store на каждом stream creation (один раз на stream lifecycle, ~hundreds/sec при peak — negligible).

**Я считаю B лучше**, потому что:
1. Убирает edge case из snapshot semantic'а.
2. Тест #3 от §4.1 становится тривиальным ("after AssignStream, age ≈ now").
3. Если в будущем Шаг 2 переключит idle decision на per-stream — отсутствие "zero = special" branch снизит риск регрессии.

**Fix:** §2.2 решить и зафиксировать. Я бы написал: "AssignStream stamps `lastWriteNs` to `time.Now().UnixNano()` immediately after Store. This means `lastWriteNs` is always >0 for any entry in streamMap, removing the zero-edge case from snapshot logic."

---

### M4. Decision criteria для перехода к Шагу 2 — границы 50% / 80% / 20-50% выбраны без обоснования

**Где в спеке:** §4.4:

> - Если `diag_idle_30s_count >= 1` встречается в >50% hard cap записей → H1 подтверждена, идём в Variant A.
> - Если `diag_idle_30s_count == 0` в >80% hard caps → H1 опровергнута.
> - Промежуточный случай (20-50%) → расширенная диагностика.

Эти границы — **с потолка**. Если канарейка покажет 49% или 51% — что? Канарейка с 332 hard caps даёт довольно широкий confidence interval (±5-6 pp на 95% CI). 50%-граница с CI ±5 — это не decision point, это flip a coin.

Также: "если diag_idle_30s_count >= 1 встречается в >50%" — это НЕ то же самое что "H1 подтверждена". H1 говорит о **причине** (heartbeat-stream блокирует slot-таймер). 1 idle stream в записи объясняется и H1, и Hypothesis 4 (stale streams) одновременно.

**Fix:** §4.4 переделать decision criteria. Например:
- "Strong H1 signal" = `diag_idle_30s_count >= remaining_streams - 1` встречается в >40% hard caps (это значит "хотя бы все-кроме-одного stream'а мертвы" — точно тот сигнал что предсказывает H1).
- "Strong NOT-H1" = `diag_idle_30s_count == 0` в >70% hard caps.
- Промежуточно — собираем гистограммы `(max_idle - min_idle)` и conditional на reason='age'.

Также: 332 hard cap'ов — sample size достаточен, но если канарейка вышла короче 4h (например 2h как предложено в §4.4), будет ~150 hard caps → CI ±8pp. Spec не учитывает что критерии должны зависеть от sample size.

---

### M5. Тест `TestSnapshotDrainStreams_Buckets` упоминает `top_active_dests` — но в §2.3 это **явно out-of-scope**

**Где в спеке:** §4.1 test #2 пятая ветка:

> - 5 streams с разными ages → top_active_dests возвращает 3 самых свежих

Но §2.3 Note прямо говорит: "destinations не включаются, scope-out". Это противоречие в самой спеке.

**Severity:** MEDIUM потому что либо тест нужно удалить, либо вернуть destinations в scope (и тогда — re-evaluate H2 на изменение `AssignStream` сигнатуры).

**Fix:** удалить эту ветку теста из §4.1, либо пересмотреть scope §2.3.

---

### M6. Test `TestDrainWatchdog_LogsDiagnostics_OnHardCap` — нет описания как именно тест orchestrate'ит "один stream active, один idle"

**Где в спеке:** §4.2 одно предложение: "orchestrate drain'ed slot с 2 streams (один active, один idle), trigger hard cap, capture log output".

Текущие drain-тесты в `ws_pool_drain_test.go:1113-1696` показывают что для подобного нужно вручную набивать `streamMap`, `slot.streams`, поднимать fake transport — много кода. Без приме­рного caller'а ('как настроить per-stream lastWriteNs до запуска watchdog'а') имплементатор будет писать новый паттерн с нуля.

**Fix:** §4.2 описать конкретно: "use existing test helper pattern from `ws_pool_drain_test.go:TestDrainWatchdog_HardCapTimeout` (line ~1113): set up pool with mock slots, populate streamMap with two `*streamEntry`s (one with `lastWriteNs.Store(time.Now().Add(-60s).UnixNano())`, one with `lastWriteNs.Store(time.Now().UnixNano())`), invoke `drainWatchdog(...)` with short hard cap, capture via `slogtest.NewBuffer` (or whatever exists), assert".

---

## LOW

### L1. Спека неточно описывает "три точки обновления `slot.lastActivityNs`", а их 4

**Где в спеке:** §2.2 "Три точки соответствуют существующим точкам обновления `slot.lastActivityNs`".

**Где в research:** §1 уже перечислил 4 точки: `connectSlot:1502` (prime при reconnect), `WriteMessageForStream:2120`, `WriteControlMessageForStream:2144`, `slotReaderWithClient:2439`.

Spec говорит "три точки" — упускает connectSlot prime. Это OK, потому что connectSlot — slot-level event, per-stream аналога нет (slot prime'ится без участия stream'ов). Но текст несоответствует research'у — может вызвать confusion.

**Fix:** §2.2 уточнить "три stream-bound точки обновления... Per-slot prime в connectSlot (не stream-bound) остаётся как есть."

---

### L2. Spec не упоминает что streamEntry должен иметь конструктор-helper, и где он живёт

Учитывая что test layer широко создаёт `streamEntry` напрямую — спека должна явно предписать:

```go
func newStreamEntry(slotIdx int) *streamEntry {
    e := &streamEntry{slotIdx: slotIdx}
    e.lastWriteNs.Store(time.Now().UnixNano())  // если M3 принят
    return e
}
```

И что AssignStream вызывает именно его. Иначе будут дубликаты `&streamEntry{slotIdx: minIdx}` по всему коду, разные инициализации.

**Fix:** §2.1 после struct определения добавить helper-конструктор.

---

### L3. References в спеке к `ws_pool.go:1502, 2120, 2144, 2439` — могут оказаться устаревшими ко времени имплементации

§7 References:

> Точки lastActivityNs: `client/ws_pool.go:1502, 2120, 2144, 2439`

Это снапшот номеров строк на момент написания. Любой merge между сейчас и началом имплементации сдвинет их. Лучше ссылки по имени функции (что уже сделано в §2.2 таблице) + удалить numeric refs.

**Fix:** убрать §7 строку с line numbers, оставить только §2.2.

---

### L4. Rollback §5.2 говорит "pure-revert" — но это не покрывает test layer

§5.2: "Pure-revert: `streamEntry` обратно в int, дроп hot-path Store'ов, дроп snapshot."

Но к тому моменту test layer (~14 сайтов) тоже мигрирован. Revert требует синхронного отката тестов. Не невозможно, но не "pure" — это full revert PR'а.

**Fix:** §5.2 уточнить "Pure git revert of the implementation PR (включая обновлённые тесты)."

---

## NIT

### N1. §6 "Open Questions: ни одного блокирующего" — после этого review добавьте M1-M6

После применения замечаний M1-M6, §6 нужно обновить либо переименовать в "Resolved Questions" со списком решений.

### N2. §2.1 inline comment "Pointer storage is intentional..." — обоснование верное, но затянутое

Доcстринг для `streamEntry` занимает 9 строк объяснения почему pointer. Можно сжать до 3 строк: "Stored as *streamEntry in sync.Map; pointer storage avoids re-Store on lastWriteNs update."

### N3. §3.2 утверждение "+1.6 KB. Negligible"

При peak 100+ streams в pool * 16 байт = 1.6 KB. ОК, действительно negligible. Но "100+ streams в pool" — это нагрузка одного slot'а или всего pool'а? Pool из 6 slots * peak 5-10 streams/slot = 30-60 streams. **Точнее**: 100 streams * 24 bytes = 2.4 KB (а не +1.6 KB), потому что мы выкидываем 8 байт (int) на каждый stream и добавляем 24 байт `streamEntry`. Net delta = +16/stream * 100 = 1.6 KB. Так что формально OK, но запись путает.

---

## Top-5 findings (compressed)

1. **HIGH** — §2.2 не перечисляет все 11 production + 14 test call-sites streamMap; имплементация без полного списка → panic на type assertion при первом IncrPending.
2. **HIGH** — §2.2 не определяет, ДО или ПОСЛЕ stale-frame check в `slotReaderWithClient` происходит stream-stamp; от этого зависит интерпретация всей канарейки.
3. **HIGH** — race AssignStream stores entry до streams.Add(1) — snapshot может видеть entry без соответствующего инкремента counter'а → `diag.total != remaining_streams` в логах, рушит доверие к диагностике.
4. **MEDIUM** — decision criteria для перехода к Шагу 2 (50%/80%/20-50%) выбраны без statistical обоснования; на sample 332 hard caps CI ±5-6pp убивает граничный case.
5. **MEDIUM** — edge case `lastWriteNs==0` описан только в тесте, не в §2.3 контракте функции; ИЛИ AssignStream должен stamps lastWriteNs (M3 предлагает clean fix).

---

## Дополнительно: что я мог пропустить (вопрос от пользователя)

Если бы я впервые читал этот spec и должен был его имплементить:

- Меня бы смутило **отсутствие сравнения с research §5 Variant A**. Research уже предлагал Variant A (per-stream idle decision) и упомянул конкретный набор изменений. Spec этого шага говорит "это инфраструктура для Variant A" — но не показывает дельту: что из Variant A уже здесь, что остаётся для Шага 2. Хорошо бы добавить мини-табличку "Variant A scope split":
  - Step 1 (this spec): streamEntry, per-stream lastWriteNs stamping, snapshot, diag logs.
  - Step 2 (next spec): drainWatchdog switch from `slot.lastActivityNs` to per-stream iteration, deprecation of slot-level stamp.

- §3.3 "Snapshot iterates streamMap (O(active streams в pool))" — это **не точно**. sync.Map.Range итерирует **ВСЁ** содержимое map'а, не только entries с targetSlot. Под peak 100 streams в pool из 6 slots, draining slot держит ~10-15 streams, но Range всё равно посетит все 100. Реальная стоимость: 100 entries * ~10ns/load = 1μs, всё равно negligible — но текст некорректен. Лучше: "Snapshot scans the entire streamMap (O(N) где N = total active streams в pool), filtering by slotIdx. Typical N=50-100, scan duration <10μs."

- **Не упомянут sync.Map's quirk**: повторный `Store` *того же* `*streamEntry` pointer'а — дешёвый. Но если в будущем имплементация ошибочно начнёт **пересоздавать** `*streamEntry` (например, в IncrPending'е), это раздует cost. Spec явно говорит "slotIdx immutable after Store", это покрывает, но imho стоит добавить "ANY mutation to streamEntry must be through atomic methods on its fields; никогда не Store(key, NEW *streamEntry) для существующего streamID".

- **Не покрыт сценарий double-AssignStream того же streamID**. Сейчас если test (или баг) дважды вызовет AssignStream(42), второй вызов Store'нет новый int. С `*streamEntry` — Store'нет новый pointer, старый `*streamEntry` лишится reference и попадёт под GC. Если первый pointer попал в snapshot до этого — мы держим reference на dead entry. Не баг (atomic.Int64 на dead entry читается нормально), но invariant "slotIdx immutable" нарушается между Store'ами, что противоречит §2.1 docstring. Лучше — добавить test'ом invariant'у "double-AssignStream одного streamID — undefined behavior" либо явно его поддержать через `LoadOrStore`.

---

## Verdict (re-statement)

**APPROVE_WITH_CHANGES** — дизайн на правильном направлении (диагностика до фикса, отдельный шаг), hot-path overhead-обоснование корректно, гипотеза артикулирована. НО:

- H1/H2/H3 необходимо разрешить **в спеке** до начала имплементации (риск багов или потери диагностической ценности).
- M1-M6 — уточнения, без которых имплементатору придётся гадать. Не блокеры, но плохой опыт ревью.

После применения замечаний H+M — рекомендую сразу к plan/implementation.

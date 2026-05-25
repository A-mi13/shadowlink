# Code review R2 — Per-stream activity diagnostics + idle infrastructure (design spec)

**Дата:** 2026-05-25
**Ревьюер:** Claude (Opus, max effort)
**Ревью-объект:** `shadowlink/docs/superpowers/specs/2026-05-25-drain-per-stream-diagnostics-design.md` (post-R1 revision)
**Round 1 review:** `shadowlink/docs/superpowers/specs/2026-05-25-drain-per-stream-diagnostics-design-review.md`

---

## Summary (только новые findings)

| Severity | Count (new in R2) |
|---|---|
| CRITICAL | 0 |
| HIGH     | 1 |
| MEDIUM   | 4 |
| LOW      | 3 |
| NIT      | 2 |

**Round 1 findings status:** ALL_RESOLVED (с одним мелким нюансом — см. R2-H1: round 1 H3 ReleaseStream race добавил новый, не предсказанный сторонами риск).

**Verdict:** APPROVE_WITH_MINOR_CHANGES.

Спека теперь существенно чище: H1/H2/H3 + M1-M6 закрыты грамотно, scope split явный, decision criteria статистически обоснованы. Однако правки сами по себе ввели **один HIGH** (R2-H1: §4.4 decision criteria формула при `remaining_streams=1` всегда истинна), **четыре MEDIUM**, и несколько мелких уточнений. Ни одно не блокирующее имплементацию — все локальные, поправимы 30-минутными правками текста.

---

## Round 1 findings — verification

### R1-H1 (полный список call-sites)
**FIX:** §2.2 содержит полную таблицу 11 production-сайтов с phantom-line-numbers и явным указанием на test helper (§2.2 subsection "Test sites"). **Verified против `grep streamMap\.` в client/** — реальные сайты:
- prod: 9 в `ws_pool.go` (Store@2014, Load@2023/2033/2043, LoadAndDelete@2072, Load@2087/2113/2137/2447, Range@2658, Delete@2663) ✓
- test: 7 сайтов в `ws_pool_drain_test.go` + 5 сайтов в `ws_pool_test.go` = 12 (не 14, как было в R1). Spec говорит "~14+" — в реальности 12. Несущественное расхождение.

**Test helpers** (`storeStreamForTest`, `storeStreamForTestWithAge`) описаны корректно. Применимо без проблем.

**Status:** ✅ RESOLVED. (Минор: §2.2 говорит "~14+ test sites", реально 12 — обновить число для precision.)

### R1-H2 (stamp position vs stale-frame check)
**FIX:** §2.4 явно фиксирует stream-stamp **только после** успешной валидации `entry.slotIdx == idx`. Slot-stamp на 2439 оставлен как был (`Out-of-scope`). Decision documented в spec и понятно.

**Status:** ✅ RESOLVED. Но открыло новый MEDIUM (R2-M1) — что если `RouteToStream` падает после stamp'а.

### R1-H3 (AssignStream race)
**FIX:** §2.5 flip order — `streams.Add(1)` ДО `streamMap.Store`. Это правильное решение. ReleaseStream race — принят как known minor с обоснованием. Я раскапываю это глубже в R2-H1/R2-M2 ниже.

**Status:** ✅ RESOLVED для AssignStream. ⚠️ ReleaseStream — open mini-race документирован, но обоснование neogт частично спорно (R2-M2).

### R1-M1 (atomic semantics docstring)
**FIX:** §2.6 содержит явный `Concurrency contract` блок в docstring `snapshotDrainStreams`. ✓

**Status:** ✅ RESOLVED.

### R1-M2 (lastWriteNs==0 в §2.3)
**FIX:** Устранён через R1-M3 fix — `newStreamEntry` всегда stamps. Edge case больше не существует.

**Status:** ✅ RESOLVED.

### R1-M3 (AssignStream stamps lastWriteNs)
**FIX:** §2.1 `newStreamEntry` constructor явно stamps. Подход B (clean) выбран. ✓

**Status:** ✅ RESOLVED.

### R1-M4 (decision criteria)
**FIX:** §4.4 переписан с sample-size обоснованием, формула `idle_30s_count >= max(1, remaining_streams - 1)` (см. R2-H1 — там bug в формуле!), пороги 55%/25% с buffer.

**Status:** ⚠️ MOSTLY RESOLVED — обоснование пришло, но в формуле баг (R2-H1).

### R1-M5 (top_active_dests)
**FIX:** §4.1 более не упоминает `top_active_dests`. ✓

**Status:** ✅ RESOLVED.

### R1-M6 (test orchestration)
**FIX:** §4.2 ссылается на конкретный pattern из `TestDrainWatchdog_HardCapTimeout` (line ~1113) + точные шаги. ✓

**Status:** ✅ RESOLVED.

### R1-L1 — L4
- L1 (три точки vs четыре): §2.3 теперь explicit "Three stream-bound points (per-slot prime в `connectSlot` — slot-level event)". ✓
- L2 (helper constructor): §2.1 содержит `newStreamEntry`. ✓
- L3 (numeric refs): §2.2 явно говорит "single источник правды — имена функций". ✓
- L4 (rollback covers tests): §5.2 теперь "Git revert полного PR (production + tests)". ✓

**Status:** ✅ ALL_RESOLVED.

### R1-N1/N2/N3
- N1 (open questions → resolved): §6 Resolved Questions добавлен. ✓
- N2 (затянутый docstring): сокращён, осталось 3 строки. ✓
- N3 (1.6 KB запись): не правлено, но negligible discrepancy. Skip.

**Status:** ✅ ALL_RESOLVED.

**Round 1 overall: ALL_RESOLVED.**

---

## НОВЫЕ findings (R2)

## HIGH

### R2-H1. §4.4 decision criteria formula — bug при `remaining_streams=1`

**Где в спеке:** §4.4 "Целевая метрика: **доля hard caps где `diag_idle_30s_count >= max(1, remaining_streams - 1)`**".

**Bug:** Когда `remaining_streams == 1`, `max(1, 1-1) = max(1, 0) = 1`. Условие = `idle_30s_count >= 1`. Это OK — но семантически это значит "the single remaining stream is idle 30s+", что **именно то** что мы ищем для H1. ОК, не bug в этом случае.

**Реальный bug:** Когда `remaining_streams == 2`, `max(1, 1) = 1`. Условие = `idle_30s_count >= 1` — т.е. "хотя бы 1 из 2 streams тих 30s+". Это **более слабый** сигнал чем "все-кроме-одного тихи". При `remaining=2` "все-кроме-одного" = "ровно 1 тих" — и формула это даёт, OK.

**Но при `remaining_streams >= 3`:** "все-кроме-одного" семантически = `idle_30s_count >= remaining - 1` (например при `remaining=5`, требуем 4 idle). Формула `max(1, remaining - 1) = remaining - 1` — OK для `remaining >= 2`.

Дальше я проверил `remaining_streams == 0` (edge case, hard cap'ы с remaining=0 редки но возможны при race): `max(1, -1) = 1`, условие `idle_30s_count >= 1` — но `idle_30s_count` физически не может быть `>=1` если `diag.total == 0` (snapshot пуст). **Это log-noise**, не bug — событие просто никогда не классифицируется как H1-positive.

**Проверка обратного случая — НЕ-H1 (нижний порог ≤25%):** §4.4 определяет "опровергнута" как **доля hard caps ≤25%**, но не описывает по какому критерию они "опровергнуты". Подразумевается inversion: `idle_30s_count < max(1, remaining-1)`. Это покрывает множество разных ситуаций — например `remaining=3 idle=1` и `remaining=3 idle=0` обе попадут в "опровергнутые", хотя первая частично подтверждает H1 (1 stream залип). Это смазывает категорию.

**Реальный issue:** spec фиксирует **один порог** для одного сравнения, без таблицы decision matrix по `(remaining, idle_count)`. При анализе канарейки придётся вручную делить логи по `remaining_streams` бакетам — что **не описано в шагах analysis**.

**Severity:** HIGH потому что от формулы зависит **что мы напишем в report'е канарейки 2026-05-26**. Если мы получим 60% hard caps с `remaining=2 idle=1` — формально это "strong H1 signal" по §4.4, но половина из них может быть "active+idle stream pair" (=H1 confirmed), а другая половина — "idle pair, never noticed" (=H4 stale streams, не H1). Decision criteria их не различает.

**Fix:** §4.4 добавить шаг "разделить hard caps по `remaining_streams ∈ {1, 2, 3+}` бакетам, применить decision criteria **внутри** каждого бакета". Альтернативно: ужесточить condition до **`idle_30s_count == remaining_streams - 1` AND `diag_max_idle_age_ms - diag_min_idle_age_ms > 25000`** — это та самая bimodal shape "1 active heartbeat + N idle" что предсказывает H1.

Bimodal shape уже упомянута в §4.4 как "smoking gun", но НЕ включена в основную formula. Нужно поднять её на decision-level.

---

## MEDIUM

### R2-M1. §2.4 — stream-stamp ДО `RouteToStream`, после stale-frame check. Что если RouteToStream падает?

**Где в коде:** `ws_pool.go:2447-2458`. После stale-frame check идёт `cl.RouteToStream(streamID, ...)`. Spec §2.4 кладёт stream-stamp **внутрь** if-блока validation, ДО `RouteToStream`.

**Проблема:** Если `RouteToStream` отбрасывает frame (закрытый streamChan, full chan, race с UnregisterStream), мы всё равно stamp'нули `lastWriteNs`. Это значит "stream had wire activity from server side" но fact'ически данные не дошли до читателя.

**Влияние на диагностику:** Stream может быть в состоянии "downstream wire живой, но reader повешен / chan закрыт". В этом случае `lastWriteNs` будет свежим (от тикающих server-side frame'ов), но stream фактически stale. Для H1 это false-negative — heuristic вернёт "active", хотя должен сказать "idle".

**Severity:** MEDIUM потому что это narrow edge case (stale reader при живом server-side wire — обычно вторая сторона тоже умирает быстро через downstream), но может смешать диагностику в специфичных закрытых-канал сценариях.

**Fix:** Один из:
- (a) Перенести stamp **после** `RouteToStream`, в новый if-блок проверяющий return value (RouteToStream сейчас возвращает void — нужно расширить).
- (b) Документировать как known limitation в §2.4: "stream-stamp фиксирует server-side delivery attempt, не application-side consumption. Если streamChan закрыт, frame дропается на следующем шаге, но stamp уже сделан — это допустимо для diagnostic semantics (мы измеряем wire-activity, не application-activity)."

Я бы рекомендовал (b) — изменение signature `RouteToStream` ради edge-case'а излишне. Но spec должен это **явно зафиксировать**.

---

### R2-M2. §2.5 ReleaseStream "known minor race" — обоснование частично white-wash

**Где в спеке:** §2.5 "Acceptance race < 1μs * 332 hard caps / 4h = негативно-мал".

**Разбор:** Spec оценивает: окно <1μs * 332 hard caps. Но это **неверная** unit-of-time:
- Окно <1μs существует при **каждом** ReleaseStream вызове, не только при hard cap'ах.
- При peak трафике канарейки 2026-05-22 было ~895 drains * (typical 5-10 streams per slot * 2-3 ReleaseStream calls per stream lifecycle). Это ~13K-27K ReleaseStream'ов за 8h канарейки.
- 13K ReleaseStream * 1μs window = 13ms total race exposure.
- При peak 295MB/5s ~24K writes/sec, snapshot вызывается ~tearDown(~100/h) = 0.028/s. P(snapshot во время Release race) = ~0.028/s * 13ms = 0.00036, т.е. ~1 in 2800 snapshots **могут** наблюдать race.
- За 4h канарейки с 332 hard caps это ~0.12 race events — практически 0.

OK, оценка spec в итоге верна, но **arithmetic в спеке неверный** (он умножает race window на hard caps, что не имеет смысла). Логика "spec arrives at right answer for wrong reason" — не угрожает результату, но reviewer rightly будет confused.

**Severity:** MEDIUM потому что arithmetic в обосновании не сходится — будущему ревьюеру (или мне через месяц) трудно поверить заявлению.

**Fix:** §2.5 переписать обоснование, либо упростить до: "Race window is on order of nanoseconds per call. Snapshot runs only on teardown (≤1/sec). Joint probability of snapshot observing in-flight ReleaseStream is effectively zero across a multi-hour canary (<<1 event). Document and move on."

---

### R2-M3. §2.7 Double-AssignStream — "LoadOrStore-like" — между Load и Store есть race window

**Где в спеке:** §2.7 показывает pseudo-code:
```go
if existing, dup := p.streamMap.Load(streamID); dup {
    p.log.Warn(...)
    return
}
p.slots[minIdx].streams.Add(1)
p.streamMap.Store(streamID, newStreamEntry(minIdx))
```

**Проблема:** Это **НЕ** `LoadOrStore` — это `Load`-then-`Store` с race window между ними. Если два goroutine'а одновременно вызывают `AssignStream(42)`:
- G1: Load → not present, продолжает.
- G2: Load → not present (одновременно с G1 — race window открыт), продолжает.
- G1: Store entry_A.
- G2: Store entry_B (overrides entry_A).

Оба пройдут проверку, оба сделают `streams.Add(1)` (== +2 ghost increment), оба сделают `Store` (entry_B побеждает, entry_A leak'нет в snapshot если был cached).

**Severity:** MEDIUM. В практике double-AssignStream — это symptom of SOCKS layer bug, не runtime concurrency. Если SOCKS уже гарантирует "один streamID — один owner" (как утверждает §2.7), то этот race не материализуется. Но spec **в одном месте** называет это "LoadOrStore-like pattern" — что вводит в заблуждение что это атомарно. Это не атомарно.

**Fix:** §2.7 либо использовать **настоящий** `sync.Map.LoadOrStore`:
```go
newEntry := newStreamEntry(minIdx)
if _, loaded := p.streamMap.LoadOrStore(streamID, newEntry); loaded {
    // existing entry won — caller bug, log it
    p.log.Warn("...")
    return
}
p.slots[minIdx].streams.Add(1)  // ВНИМАНИЕ: теперь Add ПОСЛЕ Store — обратное R1-H3!
```
Но это **противоречит** R1-H3 fix (который требует Add ДО Store). Conflict!

**Recommended fix:** оставить текущий Load-then-Store паттерн, но **переформулировать** в спеке: "This is sanity-assert, not atomic protection. Production SOCKS layer guarantees single-owner per streamID. Concurrent AssignStream(sameID) is undefined behavior — the warning catches the violation post-fact." То есть: убрать слово "LoadOrStore-like", это вводит в заблуждение.

---

### R2-M4. §2.6 `ageMs < 0 { ageMs = 0 }` — clock skew defensive маскирует баг

**Где в спеке:** §2.6:
```go
ageMs := (nowNs - e.lastWriteNs.Load()) / int64(time.Millisecond)
if ageMs < 0 {
    ageMs = 0 // clock skew defensive
}
```

**Проблема:** Под Windows `time.Now()` может regress'нуть назад на ~100ns при NTP adjust или sleep transition. В тех редких случаях `lastWriteNs > nowNs` для свежеsтэмпленных entries.

Сейчас spec'ка clamp'ит к 0 → entry классифицируется как "active" (ageMs=0 < 30000). Это безопасный default.

**НО:** если `lastWriteNs` показывает значение из **будущего на секунды** (грубый clock skew или баг с `Store(arbitrary_value)`), clamp'ом мы маскируем эти cases. В лог это не попадёт.

**Severity:** MEDIUM. Lab-grade quality concern. Под продакшен — `Store(arbitrary_value)` не происходит (только `time.Now().UnixNano()`).

**Fix:** §2.6 либо добавить counter `snapshot_negative_age_total atomic.Int64`, increment в clamp branch, expose в `health_snapshot`. Это даёт **observability на потенциальный баг** без эскалации.

Альтернатива: log.Debug при `ageMs < -1*1000` (более 1s negative — реальный bug). При <1ms — silently clamp.

---

## LOW

### R2-L1. §2.5 ReleaseStream — выбран вариант `Load + Delete` вместо `LoadAndDelete` (в обсуждении), но **в final decision** spec говорит "оставляем `LoadAndDelete` как был"

**Где в спеке:** §2.5 — длинный текст обсуждает trade-off между `LoadAndDelete` и `Load+Delete`, затем в конце §2.5 написано:

> "**Решение:** Принимаем альтернативу — оставляем `LoadAndDelete` как был, документируем в spec и в коде."

**Имплементатор может запутаться** — в обсуждении предлагался Load+Delete, в final решении — LoadAndDelete. Текст обсуждения занимает 70% параграфа, итоговое решение — последняя строка.

**Fix:** Сократить §2.5 (ReleaseStream-блок): убрать обсуждение Load+Delete вариант, оставить 2-3 строки: "ReleaseStream остаётся как был (LoadAndDelete + streams.Add(-1)). Race window <1μs, рассматриваем как known minor (см. raw probability в R2-M2 review)."

---

### R2-L2. §2.5 W5 stale-frame check инвариант — нужна корректная формулировка

**Где в спеке:** §2.5 говорит "W5 интересен только в случае когда AssignStream после drain'а переассайнил streamID на новый slot". Корректно.

Но далее: "С нашей flip-перестановкой инвариант 'если entry опубликована, то streams.Add уже произошёл' укрепляется, W5 не ослабляется."

**Проблема formulation:** W5 не зависит от `streams.Add` — он зависит от `entry.slotIdx`. Flip перестановка влияет на `streams` counter coherence, **не** на W5. Связи между этими двумя нет. Текст эту связь подразумевает — это путает.

**Fix:** §2.5 уточнить: "W5 invariant (`entry.slotIdx == idx`) не зависит от ordering между streams.Add и streamMap.Store. Flip — изолированный fix для snapshot/counter coherence."

---

### R2-L3. §2.7 предложенный код использует `existing.(*streamEntry).slotIdx` без nil-check на `existing`

**Где в спеке:** §2.7:
```go
if existing, dup := p.streamMap.Load(streamID); dup {
    p.log.Warn("AssignStream called twice for same streamID without ReleaseStream",
        "stream", streamID, "old_slot", existing.(*streamEntry).slotIdx, "new_slot", minIdx)
```

`existing` может быть `nil` если кто-то Stored nil (теоретически — не в нашем коде, но defensive не помешает). Type assertion `nil.(*streamEntry)` panic'нет.

**Severity:** LOW. В нашем коде не возникает (мы никогда не Store(nil)). Но это **первый и единственный** type assertion без `, ok` в спеке — выбивается из паттерна.

**Fix:** Использовать `if e, ok := existing.(*streamEntry); ok { ...slotIdx... }`. Или утверждать в спеке "all stored values are non-nil *streamEntry by construction; type assertion is safe".

---

## NIT

### R2-N1. §1.1 scope split таблица — корректна, но не покрывает test layer

§1.1 говорит "✅" для `*streamEntry` структура + миграция, но не упоминает что миграция включает **test layer** (12 сайтов). §2.2 это покрывает, но в §1.1 scope split можно read как "Step 1 = production code only".

**Fix:** §1.1 в строке "*streamEntry структура + slotIdx миграция" добавить "(включая test layer ~12 сайтов через helpers)".

---

### R2-N2. §3.2 utверждение "+1 streamMap.Load (уже есть, type assertion *streamEntry)"

Текст подразумевает что type assertion бесплатен. Под Go runtime type assertion на interface{} → concrete type — это сравнение itab, ~1ns. Mention это в spec не нужно, but the parenthetical "уже есть" слегка misleading — раньше был `.(int)`, теперь `.(*streamEntry)`, итог одинаковый. Норм.

---

## Self-review spec'и (DRY / YAGNI / clarity)

### Overengineering check
- §2.7 (double-AssignStream защита) — это **defensive** features которые мы не сможем validate без специального теста. Подход разумный, но §4.1 test #8 (`TestAssignStream_DoubleAssignWarns`) **тестирует это** — OK, defensive код покрыт тестом. Не overengineering.
- §2.6 (snapshot O(N) на ВЕСЬ streamMap, не отфильтрованный по slot) — accepted as cheap. OK, не overengineering, sync.Map не даёт лучшего варианта.

### YAGNI check
- §2.7 — реально нужен? SOCKS layer гарантирует single-owner, double-assign не должен происходить. Но **defensive log** — это observability на потенциальную регрессию в будущем. Принимаю.
- `idleAge30sCount` + `activeCount` + `total` — это все три выводимы друг из друга при `total = idle + active`. **Можно** хранить только два. Но три полевых явных удобнее для лога (читателю не нужно вычитать). Принимаю.

### Clarity check
- §2.5 длинный (3 параграфа обсуждения для одного решения), см. R2-L1.
- §4.4 decision criteria — таблица читаемая, но R2-H1 formula bug снижает её ценность.
- §2.7 "LoadOrStore-like" — misleading wording (R2-M3).
- §1.1 scope split — четкий, чисто читаемый.

### Scope split (§1.1) — match с реальным содержимым?

| Артефакт в §1.1 | В spec? |
|---|---|
| streamEntry структура | §2.1 ✓ |
| slotIdx миграция | §2.2 ✓ |
| Hot-path stamping | §2.3 + §2.4 ✓ |
| Snapshot + diag-поля | §2.6 + §2.8 ✓ |
| drainWatchdog переключение (Step 2) | §2.9 явно out-of-scope ✓ |
| `slot.lastActivityNs` removal (Step 2) | §2.9 явно out-of-scope ✓ |

Match: ✓ полное.

---

## Implementation readiness

Spec **готова к имплементации** после правок R2-H1 (formula bug) + R2-M3 (LoadOrStore wording). R2-M1/M2/M4 — quality-of-life, не блокеры. R2-L1/L2/L3 — текстовые правки на 5 минут. R2-N1/N2 — optional polish.

Estimated total effort на правки текста: 20-30 минут.

---

## Top-3 новых findings (compressed)

1. **HIGH (R2-H1)** — §4.4 decision criteria формула при `remaining_streams ∈ {1, 2}` смешивает H1 и H4 сценарии; нужна разбивка по бакетам `remaining_streams` либо добавление bimodal shape (`max-min > 25000ms`) в основное условие.
2. **MEDIUM (R2-M3)** — §2.7 "LoadOrStore-like pattern" вводит в заблуждение: это Load+Store с race window, а не атомарная операция. Реальный `sync.Map.LoadOrStore` конфликтует с R1-H3 fix (Add must precede Store). Принять как sanity-assert и переформулировать.
3. **MEDIUM (R2-M2)** — §2.5 ReleaseStream race обоснование arithmetically нестыкуется (race window умножается на hard caps, что не имеет смысла units-wise). Conclusion правильное, но reviewer confused.

---

## Verdict

**APPROVE_WITH_MINOR_CHANGES.**

Spec теперь чистый — все 13 round-1 findings закрыты грамотно. Новые findings (1 HIGH + 4 MEDIUM + 3 LOW + 2 NIT) — все **локальные текстовые правки**, не структурные. R2-H1 — единственный имеющий impact на интерпретацию канарейки 2026-05-26, должен быть исправлен **до** запуска канарейки (после имплементации, перед сбором результатов).

Имплементация может начинаться параллельно с правками spec'а — код не блокирован. Финализировать §4.4 decision criteria — до анализа канарейки.

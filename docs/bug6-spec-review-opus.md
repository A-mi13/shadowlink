# Bug #6 Sticky-Stream Design — Адверсариальное ревью спеки (opus)

**Дата:** 2026-05-29
**Ревьюер:** opus-агент (adversarial, pre-code)
**Спека:** `docs/superpowers/specs/2026-05-29-bug6-sticky-stream-design.md`
**Карта кода:** `docs/bug6-code-map.md` (verified)
**Метод:** прочитан реальный код `ws_pool.go`, `ws_pool_drain.go`, `stream_entry.go`. Все вердикты — от кода с file:line.

---

## Сводка по severity

| Severity | Кол-во |
|---|---|
| BLOCKER | 2 |
| HIGH | 4 |
| MEDIUM | 5 |
| LOW | 3 |

**BLOCKER:**
- B1. Удаление `downBytes.Store(0)` из byte_budget reader-пути → шторм повторных `startDrain` на каждом downlink-фрейме (inflight churn + лог-спам + deferred-counter loop).
- B2. `drainBytes = oldSlot.downBytes.Load()` НЕ измеряет «байты в дренаже» — reader продолжает `downBytes.Add()` во время дренажа, и объёмный предохранитель сработает почти мгновенно на активной большой закачке (рвёт ровно тот сценарий, который чинит).

**HIGH:**
- H1. Корень неполон — большой стрим рвётся НЕ только в `deadline.C`: `handleSlotDeath` (reader-error), `ctx.Done`, generation-bump, reserve-reconnect — спека их не покрывает и не аргументирует, почему их можно игнорировать.
- H2. Гонка `deadline.Reset` vs concurrent ticker-ветка `streams==0`/`allStreamsIdle` в том же `select` — после Reset слот может уже не подлежать продлению, а releaseSticky на этом пути не вызывается явно (зависит от defer, который в спеке не показан в drainWatchdog).
- H3. Анти-TSPU: bimodal-паттерн «3 липких + 3 гипер-ротируемых» — реальный новый detection-сигнал, спека утверждает обратное без анализа.
- H4. `effectiveStickyMaxSlots()` при `poolSize/2` и нечётном/малом poolSize + взаимодействие с readyCapacityFloor: sticky-слоты удерживают `slotDraining`, что вычитается из readyCapacity и может заклинить новые дренажи (storm brake) → пул перестаёт ротироваться вообще.

---

## BLOCKER

### B1 — Удаление `downBytes.Store(0)` из reader byte_budget-пути ломает идемпотентность триггера → шторм startDrain

**Спека (§3.3, §8):** «строку `slot.downBytes.Store(0)` из byte_budget reader-пути (`ws_pool.go:2548`) убрать — обнуление переезжает в `startDrain`».

**Код, который это ломает:**
- `ws_pool.go:2532` условие: `if total >= budget && byteBudgetRotationAllowed(...)`.
- `ws_pool.go:2547-2549` сейчас: `p.startDrain(...)` → `slot.downBytes.Store(0)` → `continue`.
- `ws_pool.go:2525` `total := slot.downBytes.Add(int64(len(data)))` — выполняется на КАЖДОМ downlink-фрейме.
- Комментарий `ws_pool.go:2544-2546` ПРЯМО фиксирует назначение Store(0): *«startDrain is idempotent via tryMarkDraining CAS, but resetting downBytes to 0 avoids triggering startDrain on every subsequent read (log spam) until teardown»*.

**Почему BLOCKER:** reader после `startDrain` НЕ выходит — он делает `continue` (`:2549`) и продолжает читать downlink-фреймы дренируемого слота (это by-design, чтобы не голодать активные стримы — `:2538-2542`). Если убрать `Store(0)`:

1. `downBytes` остаётся `>= budget`.
2. На каждом следующем фрейме `total := downBytes.Add(len)` → всё ещё `>= budget`.
3. `byteBudgetRotationAllowed(time.Since(slotStart), ...)` остаётся true (slotStart не меняется).
4. → `p.startDrain(cl, idx, "byte_budget")` вызывается на КАЖДОМ фрейме до teardown.

Спека полагается на «`startDrain` идемпотентен через tryMarkDraining CAS». Но идемпотентность относится только к ПЕРЕХОДУ состояния. Повторный вход в `startDrain`:
- `ws_pool_drain.go:366` `inflight := p.inflightDrains.Add(1)` — выполняется ДО CAS-гейта.
- `ws_pool_drain.go:368-372` defer `Add(-1)` если `!committed`.
- На каждом фрейме: Add(1)/Add(-1) churn на горячем atomic.
- Хуже: если в этот момент реально много дренажей, `inflight > maxConcurrentDrains` (`:373`) → `Stats.InflightCapDeferredTotal.Add(1)` + `bumpDrainDeferrals1m()` + потенциально лог (rate-limited, но счётчики растут) на каждом фрейме большой закачки.
- Аналогично Gate 5 capacity floor (`:395-419`) — счётчики `CapacityFloorDeferredTotal` молотят.

При большой закачке (десятки тысяч фреймов) это шторм счётчиков и atomic-контеншн на `inflightDrains`, плюс `nextDrainAttemptNs.Store(...)` дёргается. Спека в §3.3 утверждает что обнуление в startDrain делает поведение «единообразным», но НЕ учла что reader-путь `continue`-ит и re-тригерит. Самое ироничное: спека убирает Store(0), причина которого — ровно предотвращение этого шторма (комментарий :2544-2546).

**Рекомендация:**
- НЕ убирать `Store(0)` из reader-пути слепо. Если нужна «единая точка обнуления», то reader ПОСЛЕ `startDrain` должен прекратить проверку byte_budget (например, гейтить `budget > 0 && slot.getState() == slotReady`, или ввести `slot.byteBudgetSuspended` флаг, выставляемый при входе в дренаж). Иначе условие `:2532` обязано перестать быть истинным другим способом.
- Альтернатива: оставить Store(0) в reader И добавить Store(0) в startDrain для age-пути — это противоречит «единой ответственности», НО корректно. Тогда нужен другой механизм измерения «байт в дренаже» (см. B2).
- Тест §5 «byte_budget reader больше не делает Store(0) сам (нет двойного обнуления/гонки)» — ловит факт удаления, но НЕ ловит regression-шторм. Нужен тест: «после входа в дренаж byte_budget-путь не вызывает startDrain повторно на последующих фреймах».

---

### B2 — `drainBytes = oldSlot.downBytes.Load()` не измеряет «байты в дренаже» при активной закачке — объёмный предохранитель срабатывает мгновенно

**Спека (§3.3, §3.4):** «после этого "байты в дренаже" = просто `slot.downBytes.Load()` — БЕЗ дополнительного snapshot-поля. Всегда ≥0 (downBytes монотонно растёт от нуля после обнуления в startDrain)». В ветке deadline (§3.4): `drainBytes >= p.stickyMaxDrainBytes` → teardown.

**Код:**
- `ws_pool.go:2525` reader делает `slot.downBytes.Add(len(data))` на каждом downlink-фрейме — В ТОМ ЧИСЛЕ во время `slotDraining` (reader продолжает читать, `:2549 continue`).
- Сценарий, ради которого вся фича: большая активная закачка через дренируемый слот.

**Почему BLOCKER (логическая инверсия):** «байты в дренаже» по замыслу = объём, прокачанный ПОСЛЕ старта дренажа, как backstop «не держим слот вечно». Но `downBytes` обнуляется в startDrain и затем растёт от РЕАЛЬНОГО downlink активной закачки. Большая закачка — это сотни МБ/сек downlink. `StickyMaxDrainBytes = 1 GiB`. На быстром канале закачка прокачает 1 GiB за дренаж за секунды/десятки секунд → `drainBytes >= 1GiB` → teardown.

То есть объёмный предохранитель срабатывает БЫСТРЕЕ всего именно на быстрой большой закачке — ровно том сценарии, который фича призвана спасти. На медленном канале (где обрыв болезненнее, юзер ждёт) — предохранитель щадящий; на быстром — рубит. Это инверсия желаемого приоритета.

Глубже: «байты в дренаже» концептуально должны измерять *издержки удержания слота для скрытности* (сколько мы прокачали на нестандартно-долгоживущем TCP — TSPU per-flow byte counter). С этой точки зрения `downBytes.Load()` КОРРЕКТНО считает байты на TCP since startDrain-reset. НО спека в §3.4 трактует это как «успели прокачать большой файл» — это РАЗНЫЕ семантики, и спека их смешивает. Если цель — анти-TSPU предел на TCP, то 1 GiB слишком много (TSPU режет ~200 MB по комментарию `:294`), и предел должен считаться от ПОДКЛЮЧЕНИЯ (включая до-дренажные байты), а не от reset.

**Рекомендация:**
- Определить ОДНОЗНАЧНО что измеряет `StickyMaxDrainBytes`: (а) «не держать TCP дольше анти-TSPU предела» → считать от connect (НЕ обнулять в startDrain, использовать суммарный счётчик с момента connect, порог ~150-200 MB не 1 GiB); ИЛИ (б) «дать большой закачке шанс, но не бесконечно» → тогда метрика должна быть «сколько ЕЩЁ осталось / прогресс», а абсолютный downlink-объём для этого не годится.
- Текущий дизайн §3.4 даёт худшее из двух: рубит быстрые закачки рано, медленные поздно. Это надо переосмыслить ДО плана.
- Снять формулировку «1 GiB» до выбора семантики.

---

## HIGH

### H1 — Корень неполон: большой стрим рвётся не только в `deadline.C`

**Спека (§1, TL;DR):** «Единственная точка смерти стрима — drainWatchdog … case `<-deadline.C`». «Чинить надо ветку deadline, а не добавлять детекцию».

**Код показывает другие точки обрыва активного стрима:**
1. **reader-error → handleSlotDeath** (`ws_pool.go:2514` `p.handleSlotDeath(cl, idx, deathCauseNatural)` после reader-error на `:2465`). Это НЕ дренаж — слот умирает немедленно, generation bump, streamChans закрываются → активная закачка на этом слоте рвётся. `close 1006`/middlebox-kill во время большой закачки рвёт её мгновенно, в обход всего sticky-механизма. Спека это не упоминает.
2. **`ctx.Done()`** в drainWatchdog (`ws_pool_drain.go:626`) — graceful shutdown рвёт. Приемлемо, но не отмечено.
3. **generation-bump гонка** — если параллельный путь (reconnect, eviction) бампит generation дренируемого слота, reader выходит через shouldExitReader (`:2452`) → стрим теряет downlink.
4. **tier-2 emergency eviction** (`ws_pool_drain.go:452-456` `tryEmergencyEvictMinStreamsSlot`) — startDrain ДРУГОГО слота, не найдя idle cell, может эвакуировать слот с НЕНУЛЕВЫМ числом стримов (минимальным). Если sticky-слотов накопилось и slice заполнен, новый дренаж может выбрать наш активный слот под эвакуацию. Спека про cap sticky-слотов (§4) НЕ анализирует, что удержание sticky-слотов в `slotDraining` повышает давление на claimFreeSlot и провоцирует tier-2 эвакуацию активных стримов на ДРУГИХ слотах.

**Почему HIGH:** спека продаёт тезис «корень доказан, точка ровно одна». Это сужение неверно. Bug #6 в РЕАЛЬНОМ поле может проявляться и через reader-error teardown (middlebox-kill длинного TCP — это и есть документированная причина byte/age-ротации `:233-235`). Фикс только `deadline.C` оставит хвост обрывов, которые на канарейке спишут на «остаточный хвост» и ошибочно сочтут аргументом за миграцию.

**Рекомендация:** §1 должна явно перечислить ВСЕ пути обрыва активного стрима и обосновать для каждого, почему он вне scope (или в scope). Особенно: (1) reader-error teardown — оценить долю в поле; (2) tier-2 эвакуация под давлением sticky — это РЕГРЕССИЯ, вносимая самой фичей (больше slotDraining → выше шанс эвакуации). Добавить в §5 инвариант «sticky-слоты не повышают частоту tier-2 эвакуации активных стримов».

---

### H2 — Гонка `deadline.Reset` vs ticker-ветка + releaseSticky на путях выхода не доказан кодом

**Спека (§3.4, §4):** ветка `deadline.C` делает `markSticky` + `deadline.Reset(5s)`. Освобождение — «через `defer` в drainWatchdog … срабатывает на всех путях выхода».

**Код:**
- `drainWatchdog` (`ws_pool_drain.go:624-642`) — единый `for { select { ... } }`. Ветки `deadline.C` и `ticker.C` взаимоисключающи в одном проходе, гонки ВНУТРИ select нет (Go select атомарен по выбору ветки). ОК — это снимает часть опасения.
- НО: `tearDown` в ticker-ветке (`:631-640`) и продление в deadline-ветке используют РАЗНЫЕ источники активности. Сценарий: на тике `allStreamsIdle==false` (активен) → не рвёт; затем срабатывает `deadline.C`; внутри deadline-ветки повторно вычисляется `idle := allStreamsIdle(...)`. Между этими двумя точками стрим мог стать idle → deadline-ветка возьмёт idle-путь → корректный teardown. Это ОК, но спека не показывает что idle ПЕРЕсчитывается в deadline-ветке свежим `now` — в §3.4 псевдокод это делает (`now := time.Now()`), хорошо.
- **Проблема releaseSticky:** спека утверждает «defer releaseSticky на всех путях». Но в `drainWatchdog` (`:557-643`) уже есть `defer p.inflightDrains.Add(-1)` (`:563`). Спека НЕ показывает, КУДА встаёт `defer p.releaseSticky(oldIdx)` и при каком условии. Если defer ставится безусловно в начале watchdog — он вызовет releaseSticky даже для слотов, которые НИКОГДА не стали sticky. releaseSticky идемпотентен (`Swap(false)` вернёт false → no decrement, `§4`), так что счётчик не течёт — ОК. Но порядок defer'ов: `inflightDrains.Add(-1)` и `releaseSticky` — оба LIFO, без взаимозависимости, ОК.
- **Реальная гонка — markSticky vs releaseSticky при cell recycle:** `isSticky atomic.Bool` живёт на `poolSlot`. После teardown слот переиспользуется (claimFreeSlot отдаёт ту же `*poolSlot` ячейку под новый дренаж/reconnect). Если releaseSticky из старого watchdog ещё не отработал (defer в горутине, которая вот-вот вернётся), а новый дренаж той же ячейки вызывает markSticky → CAS(false→true). Возможна последовательность: новый markSticky выставил isSticky=true и Add(+1); старый defer releaseSticky делает Swap(false)→true → Add(-1). Итог: новый sticky потерял свой учёт в счётчике, isSticky=false, но drainWatchdog нового считает себя sticky. Рассинхрон счётчика и реального состояния. **Нужно подтвердить, что `*poolSlot` НЕ переиспользуется пока старый watchdog не вернулся** — код claimFreeSlot/handleSlotDeath надо проверить на этот инвариант; спека его не упоминает.

**Почему HIGH:** cross-recycle гонка `isSticky`/`stickyDrainCount` — классический источник «счётчик не сходится → quota навсегда занята → пул не ротируется» (см. H4). Спека декларирует идемпотентность, но не доказывает изоляцию по времени жизни ячейки.

**Рекомендация:**
- Показать в спеке точное место `defer p.releaseSticky(oldIdx)` в drainWatchdog и доказать, что между teardown старого watchdog'а и markSticky нового дренажа той же ячейки нет окна (handleSlotDeath → claimFreeSlot ordering).
- Альтернатива безопаснее: хранить sticky-учёт не на `poolSlot` (переиспользуемой), а ключевать по `(idx, generation)` или сбрасывать isSticky в `connectSlot`/`handleSlotDeath` под тем же замком, что и пересоздание ячейки.
- Тест: drain → sticky → teardown → немедленный reconnect+drain той же ячейки → проверить `stickyDrainCount == ожидаемое` под `-race`.

---

### H3 — Bimodal-паттерн «липкие + гипер-ротируемые» — новый detection-сигнал, спека утверждает обратное

**Спека (§4):** «Минимум `poolSize - effectiveStickyMaxSlots` слотов ВСЕГДА ротируются по графику → анти-TSPU пула сохранён».

**Код, релевантный к скрытности:**
- `ws_pool.go:289-295` — комментарий прямо ссылается на Citizen Lab «Stranger DPI in Russia» (Aug 2024): per-flow byte counters — detection vector; deterministic ladder давал «clean bimodal distribution on the wire» = fingerprint; поэтому byte-budget размазан 4-30 MiB.
- byte_budget — ПЕР-СЛОТ. age-ротация — пер-слот со stagger (`:302-321`, FFT-смазывание).

**Анализ сценария из задания:** 3 из 6 слотов sticky на 10 мин. Оставшиеся 3 несут весь uplink/downlink ротации:
- На активных 3 слотах downBytes набегает быстрее → byte_budget трипается чаще → они ротируются заметно чаще обычного.
- Получаем 2 кластера: 3 слота с аномально-долгим TCP lifetime (sticky, до 10 мин), 3 слота с аномально-частой ротацией. Это РОВНО та бимодальность по per-flow lifetime/byte-count, которую проектная заметка `:289-295` называет fingerprint и от которой ушли рандомизацией бюджета.
- Спека §4 рассматривает только инвариант «N/2 ротируются» (количество), но НЕ распределение lifetime/byte-count по слотам, которое и есть detection-вектор по той же цитируемой работе.

**Почему HIGH:** фича вводит новый стат-сигнал в ровно той метрике (per-flow lifetime distribution), которую проект уже признал detection-вектором и потратил усилия на сглаживание. Спека утверждает «анти-TSPU сохранён» без анализа распределения — это необоснованное заявление в критичном для проекта измерении. Это прямо противоречит самопозиционированию proposal §3 («наш единственный актив — незаметность»).

**Рекомендация:**
- Добавить в спеку раздел «влияние на per-flow lifetime/byte-count distribution» с честной оценкой бимодальности. Возможные смягчения: (а) cap sticky жёстче (1 слот, не poolSize/2); (б) при наличии sticky-слота временно расширять byte-budget/age-jitter оставшихся, чтобы не было гипер-ротации; (в) ограничить sticky-продление так, чтобы lifetime sticky-слота не выпадал из правого хвоста log-normal распределения активных слотов (HIGH-3 heavy-tail в `mimicry.go` уже даёт p99≈2.7h — sticky 10мин в этот хвост ВПИСЫВАЕТСЯ, это аргумент ЗА, но его надо сделать явно и связать распределения).
- Минимум: канареечная метрика, измеряющая разброс slot lifetime между sticky и non-sticky, с порогом-алертом.

---

### H4 — sticky слоты в `slotDraining` вычитаются из readyCapacity → возможен клинч дренажей (пул перестаёт ротироваться)

**Спека (§5, последняя строка):** «sticky-слот дольше в slotDraining; проверить … reserve (поднят при startDrain) не блокируется». То есть спека ОСОЗНАЁТ риск, но оставляет его как «проверить», а не решает.

**Код:**
- `startDrain` Gate 5 (`ws_pool_drain.go:395-419`): `ready := p.readyCapacity(); floor := p.readyCapacityFloor(); if ready < floor { defer }`. Дренаж НЕ стартует, если ready capacity ниже порога.
- При sticky каждый удерживаемый слот стоит в `slotDraining` до 10 мин. Его reserve-замена поднимается (`connectReserveSlot`), так что суммарно slice растёт к 2*poolSize. Но `readyCapacity` считает именно slotReady-ячейки.
- Сценарий: poolSize=6, effectiveStickyMaxSlots=3. 3 слота sticky (draining 10мин) + 3 их reserve поднимаются. Если reserve-подъём отстаёт (медленный handshake, meltdown, CF hiccup — `connectReserveSlot` fail-путь `:510-539` с backoff), readyCapacity проседает. Тогда НОВЫЕ age/byte триггеры на оставшихся слотах упираются в Gate 5 floor → дренаж откладывается → `drainCatastrophicBackoff` (`:404`). Пул может войти в состояние «3 застряли sticky, 3 не могут дренироваться из-за floor» → ротация по графику фактически останавливается.
- §5 инвариант «пул не залипает: cap + возрастной предохранитель = абсолютный потолок» относится к ОДНОМУ слоту (его watchdog конечен). Но он НЕ покрывает СИСТЕМНЫЙ клинч readyCapacity, описанный выше.

**Почему HIGH:** это сценарий полной остановки ротации (хуже Bug #6 — теряем анти-TSPU полностью, причём незаметно), вызванный взаимодействием sticky-cap (§4) с уже существующим storm-brake (Gate 5). Спека помечает его «проверить» — для дизайна это недостаточно, нужно решение.

**Рекомендация:**
- Учитывать sticky-слоты в расчёте доступной квоты С УЧЁТОМ readyCapacityFloor: `effectiveStickyMaxSlots` должен гарантировать `poolSize - stickyCount - (draining non-sticky) >= floor` в любой момент. То есть cap на sticky должен быть динамическим, привязанным к текущему readyCapacity, а не статическим poolSize/2.
- Явный инвариант в §5: «при максимальном sticky-cap readyCapacity не опускается ниже readyCapacityFloor при здоровом reserve» + тест на клинч (3 sticky + медленный reserve).
- Рассмотреть приоритет: при просадке readyCapacity ниже floor — досрочно снять sticky (предпочесть ротацию обрыву). Это политическое решение, его надо зафиксировать в спеке.

---

## MEDIUM

### M1 — `effectiveStickyMaxSlots()` при poolSize=1 / нечётном poolSize / StickyMaxSlots семантика

**Спека (§4):** «`effectiveStickyMaxSlots()` = StickyMaxSlots если >0, иначе poolSize/2 (минимум 1)».

**Код:** дефолтный размер пула 6 (CLAUDE.md Phase D «Default Size 8→6»), но `NewWSPoolTransport` допускает `cfg.Size < 1 → 2` (`ws_pool.go:1082-1084`). poolSize=1 теоретически невозможен после клампа (минимум 2), но poolSize=2 даёт poolSize/2=1 sticky → при 1 sticky из 2 слотов второй несёт всю ротацию (вырожденный H3). poolSize нечётный: код клампит до 2 минимум, но конфиг может дать 3,5,7 → poolSize/2 = 1,2,3 (целочисленно). Спека не специфицирует: `StickyMaxSlots < 0` — что значит? `=0` → авто. `<0` → отключить? §2.2 говорит «0 = авто», а §7 kill-switch завязан на `StickyMaxDrainAge <= 0`, не на StickyMaxSlots. Неоднозначность.

**Рекомендация:** явно задать таблицу: `StickyMaxSlots > 0` → значение; `=0` → poolSize/2 (min 1); `<0` → 0 (sticky запрещён, отдельно от age-kill-switch). Тест на poolSize=2 (вырожденный bimodal).

### M2 — `StickyMaxDrainAge <= 0` kill-switch vs обнуление downBytes

**Спека (§7):** «`StickyMaxDrainAge <= 0` отключает sticky … Обнуление downBytes в startDrain при этом сохраняется — безвредно для legacy hard-cap».

**Проблема:** если kill-switch активен, deadline-ветка деградирует в немедленный `tearDown(finishHardCap)` — ОК. Но обнуление downBytes в startDrain ОСТАЁТСЯ и при этом удалён Store(0) из reader (B1). Значит даже с выключенным sticky регрессия B1 (шторм startDrain на byte_budget reader-пути) сохраняется. Kill-switch НЕ откатывает B1. Только `SHADOWLINK_GRACEFUL_DRAIN=0` (legacy path) обходит, потому что reader byte_budget graceful-ветка не выполняется. Спека утверждает «безвредно» — неверно, если B1 не решён.

**Рекомендация:** решить B1 так, чтобы он не зависел от sticky. Тогда M2 снимается.

### M3 — Часы/clock skew: `deadline.Reset(5s)` и рост drainAge

**Спека (§5):** «каждый deadline.Reset приближает time.Since(drainStart) к StickyMaxDrainAge … Не зависит от поведения стрима».

**Код:** `drainStart := time.Now()` (`ws_pool_drain.go:474`), `drainAge = now.Sub(drainStart)`. `time.Now()` на Windows — wall clock, подвержен NTP-коррекции назад (snapshotDrainStreams уже ловит negative age `stream_entry.go:72-77`, `Stats.SnapshotNegativeAgeTotal`). Если wall clock прыгнул назад, `drainAge` может временно уменьшиться → продлений больше, чем рассчитано. Конечность всё равно держится (NTP-скачки ограничены), но «абсолютный потолок цикла» формально не гарантирован под адверсариальным clock skew.

**Рекомендация:** использовать монотонные часы. `time.Since(drainStart)` в Go УЖЕ монотонна, если `drainStart` получен из `time.Now()` (Go сохраняет монотонный компонент). НО в §3.4 псевдокод: `now := time.Now(); drainAge := now.Sub(drainStart)` — `now.Sub(drainStart)` тоже использует монотонный компонент, ОК. Указать явно в спеке, что drainAge считается через монотонный clock (`time.Since`), не через wall-clock вычитание UnixNano. Добавить hard-cap на число продлений как страховку (`maxStickyExtensions`).

### M4 — drainBytes при нескольких стримах на слоте (семантика суммы)

**Из задания (п.6):** downBytes — сумма по ВСЕМ стримам слота. Сценарий 5 средних закачек делят 1 GiB.

**Код:** `downBytes` пер-слот (`:236`), `Add` на каждом downlink-фрейме любого стрима (`:2525`). allStreamsIdle — пер-стрим. Значит «активность» детектится корректно пер-стрим, а «объём» — суммой слота. 5 параллельных закачек по 250 МБ суммарно 1.25 GiB → объёмный backstop рубит ВСЕ пять, хотя каждая по отдельности мелкая. Это несогласованность гранулярности: решение «продлевать» принимается пер-слот, предел объёма — пер-слот, но пользовательская единица — пер-стрим (закачка). Усугубляет B2.

**Рекомендация:** зафиксировать в спеке, что backstop — пер-СЛОТ агрегат (это by-design, т.к. дренаж пер-слот), и что multi-stream слот делит бюджет. Оценить на канарейке частоту multi-active-stream слотов. Если высока — поднять StickyMaxDrainBytes или сделать его функцией от числа активных стримов.

### M5 — Метрика `DrainHardCapTotal` меняет смысл — дашборды/алерты

**Спека (§6):** «DrainHardCapTotal сохраняется, но смысл очищается: теперь teardown при неактивных».

**Проблема:** существующие канареечные ноты и MEMORY оперируют «natural-finish ratio» и hard-cap как «убийца активных». После фикса hard-cap считает idle/zero. Любые исторические сравнения сломаются молча. emitHardCapLog (`ws_pool_drain.go:655`) сейчас вызывается ТОЛЬКО из finishHardCap; после фикса finishHardCap-ветка раздваивается (idle vs backstop vs quota_denied). Спека добавляет `sticky_outcome` поле — хорошо, но `DrainHardCapTotal` теперь смешивает idle-teardown (был бы natural по смыслу) и backstop-teardown. Это замусоривает основную метрику здоровья пула.

**Рекомендация:** не перегружать `DrainHardCapTotal`. idle-путь в deadline-ветке должен инкрементить `DrainIdleFinishTotal`/`DrainNaturalFinishTotal` (как ticker idle-ветка `:585-586`), а НЕ DrainHardCapTotal. Только реальный backstop/quota_denied teardown → DrainHardCapTotal (или новые `backstop_*` счётчики §6). Иначе ratio-метрика канареек становится несравнимой с историей.

---

## LOW

### L1 — Псевдокод §3.4 использует `oldSlot.downBytes` и `p.stickyMaxDrainAge`, но имена полей/методов не сверены
`drainWatchdog` принимает `oldSlot *poolSlot` (`:557`), поле `downBytes` есть (`:236`) — ОК. Но `p.stickyMaxDrainAge` / `p.stickyMaxDrainBytes` / `p.effectiveStickyMaxSlots()` — новые поля на WSPoolTransport, в §8 объём упомянут, но в §2.2 конфиг кладётся в WSPoolConfig (cfg.*), а watchdog читает p.* — нужен перенос cfg→p в NewWSPoolTransport (как drainHardCap `:1106-1111`). Спека это подразумевает, но явно не пишет про поля на transport. Уточнить.

### L2 — `idleEnabled` в deadline-ветке
§3.4: `idle := !idleEnabled || allStreamsIdle(...)`. Если `idleEnabled==false` (DrainIdleThreshold=0, idle-детекция выключена), `idle` всегда true → deadline всегда рвёт немедленно → sticky НИКОГДА не активируется. Это корректный fallback (нет детекции активности → нельзя безопасно продлевать), но спека не отмечает, что выключение idle-threshold полностью отключает sticky. Документировать взаимозависимость.

### L3 — `stickyRecheckInterval=5s` константа vs drainPollInterval
ticker уже тикает каждый `drainPollInterval` (`:565`). После `deadline.Reset(5s)` обе ветки активны. Если drainPollInterval < 5s, ticker-ветка успеет несколько раз проверить streams==0/idle ДО следующего deadline — это нормально (быстрее ловим natural finish). Но если drainPollInterval > 5s — deadline-ветка будет частить продления чаще, чем проверяется idle. Сверить отношение `stickyRecheckInterval` vs `drainPollInterval` и зафиксировать инвариант `stickyRecheckInterval >= drainPollInterval` (чтобы idle/zero ловились ticker'ом между продлениями).

---

## Ответы на 8 контрольных вопросов задания

1. **Корректность корня:** deadline.C ДЕЙСТВИТЕЛЬНО рвёт активный стрим вслепую (`ws_pool_drain.go:628-630`, не сверяется с allStreamsIdle), idle-ветка ДЕЙСТВИТЕЛЬНО работает (`:637`). НО корень НЕПОЛОН — см. H1 (reader-error teardown, tier-2 эвакуация, ctx, generation). Вердикт: фикс необходим, но не достаточен.

2. **Гонки:** утечки счётчика при штатном defer нет (Swap идемпотентен). НО cross-recycle гонка isSticky/stickyDrainCount при переиспользовании *poolSlot не доказана безопасной (H2). Гонка внутри select — нет (Go select). releaseSticky-место в спеке не показано (H2).

3. **Анти-залипание:** watchdog ОДНОГО слота конечен (монотонный clock, M3). НО СИСТЕМНЫЙ клинч readyCapacity при sticky+slow-reserve реален (H4) — пул может перестать ротироваться. «Залипание» в смысле H4 спекой не закрыто.

4. **Скрытность:** заявление «анти-TSPU сохранён» НЕОБОСНОВАНО. Bimodal lifetime/byte-count distribution — новый сигнал в метрике, которую проект сам признал detection-вектором (H3). Это, возможно, самая важная находка по приоритетам проекта.

5. **Регрессии:** B1 (шторм startDrain) — BLOCKER. rate-floor byteBudgetRotationAllowed НЕ затронут (гейтит по slotAge, `:566-571`, downBytes не участвует) — спека права в §3.3 footnote. reader-error лог `down_bytes` (`:2509`) — станет показывать «байты в дренаже» вместо «всего на TCP» после переноса reset, меняет смысл диагностики (MEDIUM, не вынесено отдельно — отметить). Идемпотентность tryMarkDraining: повторный вход в startDrain дёшев на CAS, но дорог на inflight churn (B1).

6. **Семантика drainBytes:** НЕкорректно мерить «байты большой закачки» суммой по слоту И измерять её через downBytes.Load() после reset (B2 + M4). 1 большая + idle heartbeats — heartbeat'ы малы, ОК. 5 средних делят бюджет — порвутся раньше (M4). Главное — B2: на быстром канале большая закачка сама набьёт 1 GiB за дренаж и сработает backstop рано.

7. **Edge cases:** poolSize=1 невозможен (кламп до 2, M1), но poolSize=2 даёт вырожденный bimodal. Нечётный poolSize → целочисленное деление. StickyMaxSlots `<0` семантика не определена (M1). Все стримы idle в момент Reset — deadline-ветка пересчитывает idle свежим now (§3.4), берёт idle-путь → корректный teardown (ОК).

8. **Полнота §5:** НЕ покрывает: (а) regression-шторм byte_budget reader (B1); (б) семантику/раннее срабатывание объёмного backstop (B2); (в) reader-error/tier-2 пути обрыва (H1); (г) cross-recycle гонку sticky-счётчика (H2); (д) системный клинч readyCapacity (H4); (е) bimodal lifetime detection (H3); (ж) загрязнение DrainHardCapTotal (M5). Список тестов §5 надо расширить на каждый.

---

## Вердикт

Спека технически грамотна и корректно идентифицирует ОДИН из путей обрыва (deadline.C). Но в текущем виде НЕ готова к плану:
- **2 BLOCKER** (B1 regression-шторм, B2 инверсия объёмного предохранителя) делают фикс в лучшем случае неработающим, в худшем — вносящим регресс.
- **H3** ставит под сомнение главный тезис «скрытность не страдает» — в проекте, где скрытность это единственный актив.
- **H1/H4** показывают, что либо хвост обрывов останется (и канарейка соврёт в пользу миграции), либо фича сама вызовет остановку ротации.

Рекомендация: переработать §3.3-3.4 (семантика downBytes/backstop), §4 (динамический cap от readyCapacity), §1 (полный перечень путей обрыва), добавить раздел про lifetime-distribution detection, и только затем writing-plans.

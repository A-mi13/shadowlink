# Bug #6 — Sticky Stream (adaptive backstop) — Design v2

**Дата:** 2026-05-29
**Статус:** Design v2 (переработан после адверсариального опус-ревью v1: 2 BLOCKER + 4 HIGH, все валидны и подтверждены кодом). Ожидает: спек-саморевью v2 → опус-ревью v2 → user-review → writing-plans.
**Задача:** Bug #6 — ротация WS-слота рвёт большие закачки (>90s).
**Подход:** Вариант 3 из `docs/stream-migration-proposal.md` (sticky slot + adaptive backstop). Полная stream-migration ОТКЛОНЕНА (proposal §3,§6,§7).
**История ревью:** v1 → `docs/bug6-spec-review-opus.md`. Все находки разрешены, см. §10 (журнал решений).

---

## 0. TL;DR

`drainWatchdog` уже НЕ рвёт активный стрим по idle-логике (`finishIdle` через `allStreamsIdle`), но поверх неё абсолютный таймер `deadline = DrainHardCap (90s)` рвёт стрим вслепую (`case <-deadline.C: tearDown(finishHardCap)`). Это **один из** путей обрыва (не единственный — см. §1.2). Фикс: при срабатывании deadline принимать осознанное решение — если стрим активен И не достигнуты предохранители backstop И есть динамическая sticky-квота → продлить дренаж; иначе teardown. Параметры — типизированные поля `WSPoolConfig`. Изменение локализовано в `ws_pool_drain.go` + `ws_pool.go` (поля/helpers). **Reader-путь byte_budget НЕ трогаем** (урок B1). Объёмный предохранитель — анти-TSPU потолок на весь TCP от connect (урок B2). Cap на sticky — **динамический от readyCapacity** (урок H4).

---

## 1. Корень и полный перечень путей обрыва активного стрима

Карта кода: `docs/bug6-code-map.md` (verified 2026-05-29).

### 1.1 Основной путь (чиним) — `deadline.C` в drainWatchdog
- `ws_pool_drain.go:567` `deadline := time.NewTimer(p.drainHardCap)` (90s).
- `ws_pool_drain.go:628-630` `case <-deadline.C: tearDown(finishHardCap)` — рвёт даже когда `allStreamsIdle==false` (данные текут). idle-ветка `:637` корректно не рвёт активный стрим, но deadline бьёт поверх. **Это корень Bug #6 для длинных закачек.**

### 1.2 Прочие пути обрыва активного стрима (вне scope этого фикса — обоснование для каждого)
Honest scoping (урок H1 — корень НЕ единственная точка):

| Путь | Код | В scope? | Обоснование |
|---|---|---|---|
| `deadline.C` hard-cap | `ws_pool_drain.go:628` | **ДА** | корень Bug #6 для длинных закачек |
| reader-error → `handleSlotDeath` | `ws_pool.go:2514` | НЕТ (но измеряем) | middlebox/CF реально убивает TCP (1006). Это НЕ наша ротация — это внешний обрыв, который sticky не предотвращает. Reconnect-механизм уже его обрабатывает. Sticky тут бессилен by design. На канарейке считаем долю reader-error-обрывов активных стримов отдельно — чтобы не списать их на «остаточный хвост sticky» (иначе ложный аргумент за миграцию). |
| `ctx.Done()` | `ws_pool_drain.go:626` | НЕТ | graceful shutdown всего пула — обрыв ожидаем и корректен. |
| generation-bump гонка | `ws_pool.go:2452` shouldExitReader | НЕТ | reader выходит при смене generation (teardown/eviction). Не вносится sticky-фичей. |
| tier-2 emergency eviction | `ws_pool_drain.go:449-457` `tryEmergencyEvictMinStreamsSlot` | **ДА — как РЕГРЕССИЯ** | startDrain ДРУГОГО слота при заполненном slice может эвакуировать слот с ненулевыми стримами. **Удержание sticky-слотов в slotDraining повышает давление на claimFreeSlot → повышает шанс tier-2 эвакуации активных стримов на других слотах.** Это регрессия, вносимая фичей. Инвариант + тест в §5. |

**Вывод §1:** фикс `deadline.C` необходим, но недостаточен «сам по себе» в том смысле, что (а) reader-error-обрывы остаются (внешние, измеряем отдельно), (б) фича создаёт новый риск tier-2 (контролируем динамическим cap, §4). Канарейка различает источники обрыва по метрикам §6.

---

## 2. Архитектура фикса

### 2.1 Принцип
Заменить **один абсолютный потолок (90s, слепой)** на **осознанное решение при срабатывании deadline**, ограниченное двумя предохранителями backstop и **динамическим** cap на число sticky-слотов. Drain-механизм сохраняется целиком. Меняется поведение одной ветки `select` + добавляются helpers и поля. Reader-путь (byte_budget trigger) НЕ трогаем.

### 2.2 Управляемость — через WSPoolConfig (типизированные поля)
`WSPoolConfig` (`ws_pool.go:980`) уже несёт `MaxSlotAge`, `DrainHardCap`, `DrainIdleThreshold`. Новые поля туда же:

```go
type WSPoolConfig struct {
    // ... существующие ...
    DrainHardCap        time.Duration // существует (90s): базовый потолок для idle/неактивных
    DrainIdleThreshold  time.Duration // существует
    // ── Bug #6 sticky stream (adaptive backstop) ──
    StickyMaxDrainAge   time.Duration // 10m — возрастной предохранитель (от старта ДРЕНАЖА, монотонные часы)
    StickyMaxTotalBytes int64         // 256 MiB — анти-TSPU потолок на TCP (от CONNECT, БЕЗ обнуления)
    StickyMaxSlots      int           // 0 = авто (динамический cap от readyCapacity, потолок poolSize/2)
}
```

Значения переносятся в поля `WSPoolTransport` в `NewWSPoolTransport` (как `drainHardCap` `:1106-1111`) — watchdog читает `p.*`. Дефолты задаются там же. `engine_shadowlink.go:450` заполняет cfg в единственной production-точке. `SHADOWLINK_GRACEFUL_DRAIN=0` обходит весь sticky-механизм.

**Все три параметра — конфиг-настраиваемые** (типизированные поля `WSPoolConfig`, не hard-coded константы). Дефолты в конструкторе — лишь стартовые значения; фактические значения приходят из cfg в точке `engine_shadowlink.go:450`. Тюнинг (например, поднять `StickyMaxTotalBytes` 256→512 MiB по данным канарейки) — через источник, заполняющий cfg, без правки логики `ws_pool_drain.go`. `stickyRecheckInterval` — единственная внутренняя константа (не параметр политики).

### 2.3 Параметры (согласованы)
| Поле | Дефолт | Смысл | Урок |
|---|---|---|---|
| `StickyMaxDrainAge` | 10m | макс. время продления дренажа (от `drainStart`, монотонно) | базовый |
| `StickyMaxTotalBytes` | 256 MiB | анти-TSPU: рвём если TCP прокачал столько на текущем отрезке (per-flow byte counter, `ws_pool.go:294`; age=от connect, byte_budget=от reset, см. §3.3) | B2 |
| `StickyMaxSlots` | 0=авто | потолок poolSize/2, но фактический cap динамический (§4) | H4 |
| `stickyRecheckInterval` | 5s (const, ≥ drainPollInterval) | период пере-оценки после продления | L3 |
| kill switch | `StickyMaxDrainAge <= 0` | deadline-ветка → слепой teardown (pre-Bug#6) | — |

---

## 3. Детекция активности + два предохранителя

### 3.1 Детекция активности — переиспользуем существующее
`!allStreamsIdle(p, oldIdx, p.drainIdleThreshold, now)` == есть активный стрим. Если `DrainIdleThreshold==0` (idle-детекция выключена) → нельзя безопасно определить активность → **sticky отключается** (deadline рвёт как сейчас). Документировано (урок L2).

### 3.2 Предохранитель 1 — возраст дренажа (монотонные часы)
`drainWatchdog` принимает `drainStart time.Time` (`:474`, получен из `time.Now()` → несёт монотонный компонент). Возраст = `time.Since(drainStart)` (монотонно, не подвержен NTP-скачкам — урок M3). `>= StickyMaxDrainAge` → teardown.

### 3.3 Предохранитель 2 — анти-TSPU объём на текущем отрезке TCP
**Семантика (урок B2 — НЕ «байты в дренаже за время продления», а «байты на текущем отрезке TCP»):** предел = «не держать TCP дольше, чем TSPU терпит по per-flow byte counter» (`ws_pool.go:289-295` Citizen Lab). Для age-дренажа отрезок = от connect; для byte_budget-дренажа = от последнего reset (см. ниже). В обоих случаях это объём, накопленный на TCP к моменту проверки.

- `slot.downBytes` уже считает encrypted payload bytes received с момента connect (`ws_pool.go:232-236`).
- **Reader-путь byte_budget НЕ трогаем** (урок B1): `slot.downBytes.Store(0)` на `:2548` остаётся как есть (его назначение — предотвратить шторм повторных startDrain, комментарий `:2544-2546`). Snapshot-поле НЕ вводим.
- **Тонкость:** `downBytes` обнуляется в byte_budget-дренаже (`:2548`), поэтому для byte_budget-пути `downBytes.Load()` после входа в дренаж считает уже от нуля, а не от connect. Это ПРИЕМЛЕМО для анти-TSPU семантики: byte_budget-ротация САМА срабатывает по достижении штатного бюджета (4-30 MiB), т.е. TCP уже «отметился» один раз; счёт заново от reset логичен (новый отрезок жизни TCP). Для age-дренажа обнуления нет → `downBytes.Load()` честно считает от connect. В ОБОИХ случаях это «байты на текущем отрезке TCP», что и есть нужный анти-TSPU сигнал. **Не вводим искусственного единообразия ценой регрессии B1.**
- `drainBytes := oldSlot.downBytes.Load()`; `>= StickyMaxTotalBytes` → teardown.

> Замечание о гранулярности (урок M4): `downBytes` — сумма по всем стримам слота. Backstop — пер-СЛОТ агрегат (by design — дренаж пер-слот). Несколько активных закачек на слоте делят бюджет. Это осознанно: предел защищает TCP/слот (анти-TSPU), а не отдельную закачку. Частоту multi-active-stream слотов измеряем на канарейке.
>
> Замечание об асимметрии (урок L1-v2): для byte_budget-пути суммарный байтовый возраст TCP может достигать ~(byteBudget + StickyMaxTotalBytes) ≈ до ~230MiB. Это приемлемо — первый byte_budget (4-30MiB) уже размыл per-flow кластер, а sticky-backstop ловит лишь хвост продления. Рвём в сторону РАНЬШЕ по первому byte_budget, не позже.

### 3.4 Логика ветки `deadline.C`
```
case <-deadline.C:
    now := time.Now()
    idle       := !idleEnabled || allStreamsIdle(p, oldIdx, idleThreshold, now)
    drainAge   := now.Sub(drainStart)                 // монотонно
    drainBytes := oldSlot.downBytes.Load()            // байты на текущем отрезке TCP
    switch {
    case idle:
        tearDown(finishIdle)        // idle → natural-finish метрики, НЕ hard-cap (урок M5)
        return
    case drainAge >= p.stickyMaxDrainAge:
        tearDown(finishStickyAgeBackstop)
        return
    case drainBytes >= p.stickyMaxTotalBytes:
        tearDown(finishStickyBytesBackstop)
        return
    case oldSlot.isSticky.Load() && p.readyCapacity() <= p.readyCapacityFloor():
        // Досрочное снятие уже-sticky слота при просадке ёмкости (урок H4):
        // приоритет ротация > UX одной закачки. Клинч саморазрешается.
        tearDown(finishStickyQuotaDenied)
        return
    case !p.stickyQuotaAvailable(oldSlot):            // динамический cap, см. §4
        tearDown(finishStickyQuotaDenied)
        return
    default:
        // активная закачка, в пределах backstop, квота есть → продлеваем
        p.markSticky(oldSlot)
        Stats.DrainStickyExtendedTotal.Add(1)
        deadline.Reset(stickyRecheckInterval)
    }
```

`min(возраст, объём)` — что раньше, то и рвёт. Все три «backstop» причины — отдельные finishCause для диагностики (§6). idle-путь идёт в natural-finish (не загрязняет hard-cap метрику).

**Сценарии:**
- YouTube 2ч (сегменты): паузы между сегментами → idle-ветка ticker штатно ротирует. Обрывов нет.
- Торрент 4 ГБ (десятки TCP): активные пиры переживают ротацию; idle-паузы → idle-finish; параллелизм покрыт динамическим cap.
- Один файл 4 ГБ медленно: доживает до min(10m, 200MiB-на-TCP). Экстрим → осознанный backstop-teardown. Хвост на канарейке.

---

## 4. Динамический cap на sticky-слоты (урок H4 — защита от клинча readyCapacity)

Sticky-квота проверяет НЕ статический `poolSize/2`, а **живой readyCapacity** — клинч невозможен по построению.

```go
// WSPoolTransport
stickyDrainCount atomic.Int32
// poolSlot
isSticky atomic.Bool

// stickyQuotaAvailable принимает ЗАХВАЧЕННЫЙ указатель slot (урок H2 — НЕ idx→p.slots[idx])
func (p *WSPoolTransport) stickyQuotaAvailable(slot *poolSlot) bool {
    if slot.isSticky.Load() { return true } // уже sticky → продлеваем дальше
    // статический потолок
    max := p.effectiveStickyMaxSlots()
    if p.stickyDrainCount.Load() >= int32(max) { return false }
    // ДИНАМИЧЕСКИЙ гейт: новый sticky не должен утопить readyCapacity ниже floor.
    // Удержание ещё одного слота в slotDraining фактически вычитает 1 из эффективной
    // ёмкости (его reserve может отставать). Требуем запас НАД floor.
    if p.readyCapacity() <= p.readyCapacityFloor() { return false }
    return true
}

func (p *WSPoolTransport) markSticky(slot *poolSlot) {
    if slot.isSticky.CompareAndSwap(false, true) {
        p.stickyDrainCount.Add(1)
    }
}
func (p *WSPoolTransport) releaseSticky(slot *poolSlot) {
    if slot.isSticky.Swap(false) {
        p.stickyDrainCount.Add(-1)
    }
}
func (p *WSPoolTransport) effectiveStickyMaxSlots() int {
    if p.stickyMaxSlots > 0 { return p.stickyMaxSlots }
    if p.stickyMaxSlots < 0 { return 0 } // <0 → sticky запрещён (урок M1)
    half := p.poolSize / 2
    if half < 1 { half = 1 }
    return half
}
```

**Cross-recycle безопасность (урок H2 — гонка ПОДТВЕРЖДЕНА):** `connectSlot:1475` создаёт НОВЫЙ `&poolSlot{}`, `handleSlotDeath:2865` ставит ячейку в nil. Поэтому `markSticky`/`releaseSticky`/`stickyQuotaAvailable` работают с **захваченным `oldSlot` указателем** (тем, что watchdog получил параметром `:557`), а НЕ через `p.slots[idx]`. Тогда:
- `defer p.releaseSticky(oldSlot)` в drainWatchdog бьёт по СВОЕЙ старой структуре. После recycle ячейка несёт НОВЫЙ `*poolSlot` — старый defer его не трогает. Гонки нет по построению.
- `releaseSticky` идемпотентен (`Swap(false)`==false → no decrement) — слоты, не ставшие sticky, безвредны.
- `stickyDrainCount` считает уникальные `*poolSlot`, занявшие квоту; каждый освобождается ровно своим watchdog'ом.

**Жизненный цикл квоты:**
- занятие: `markSticky(oldSlot)` при первом продлении (CAS → +1 один раз).
- освобождение: `defer p.releaseSticky(oldSlot)` в начале drainWatchdog (рядом с `defer inflightDrains.Add(-1)` `:563`) — срабатывает на ВСЕХ путях выхода (tearDown→return, ctx.Done, паника).

**Досрочное снятие при просадке (приоритет: ротация > обрыв одной закачки):** динамический гейт в `stickyQuotaAvailable` не даёт НОВЫЙ sticky при `readyCapacity <= floor`. Дополнительно уже-sticky слот рвётся досрочно при просадке — это реализовано отдельным `case` в §3.4 (перед quota-гейтом). Клинч саморазрешается в пользу ротации.

**При исчерпании квоты/просадке:** слот рвётся по hard-cap как сейчас. Минимум `floor` слотов всегда ротируются → анти-TSPU пула сохранён.

**Уточнения по консервативности гейта (уроки M1-v2, L3-v2):**
- Гейт `readyCapacity <= floor` ловит ИМЕННО реальную просадку reserve, а не «всегда −1». В штатном случае reserve-замена дренируемого слота к моменту deadline-тика (≥90s) уже `slotReady`, ёмкость восстановлена → sticky активируется/держится свободно. Гейт срабатывает лишь когда несколько reserve не поднялись. Тест §5 проверяет ОБА режима (здоровый reserve → sticky держится; медленный → снимается).
- При деградации пула (readyCapacity ≤ floor) sticky **сознательно отключается** — приоритет восстановлению ёмкости (иначе анти-TSPU теряется для ВСЕХ стримов), а не спасению одной закачки. Остаточные обрывы в этом режиме — НЕ провал фичи; на канарейке отделять по `quota_denied` при низком readyCapacity.

---

## 5. Регрессионные инварианты (каждый → тест в TDD)

| Инвариант | Как держим | Урок |
|---|---|---|
| idle-finish работает | `allStreamsIdle==true` рвёт в ticker-ветке (не тронута) и первым case в deadline-ветке | базовый |
| streams-zero работает | ветка `streams==0` в ticker не тронута | базовый |
| неактивный слот рвётся по hard-cap как раньше | при idle deadline → teardown (natural-finish метрики) | базовый |
| legacy путь не затронут | sticky только в graceful drainWatchdog; `maybeRotateSlot` не тронут; `GRACEFUL_DRAIN=0` обходит | базовый |
| **reader byte_budget не штормит** | Store(0) на `:2548` НЕ трогаем; reader-путь не меняется | B1 |
| **объёмный backstop не рубит быструю закачку рано** | предел ~200MiB семантически «на TCP от connect», не «байты в дренаже»; тест на быстром канале | B2 |
| **sticky не повышает tier-2 эвакуацию активных** | динамический cap ограничивает число slotDraining; тест: N sticky + новый дренаж не выбирает активный слот чаще baseline | H1 |
| **cross-recycle: счётчик не рассинхронится** | helpers работают по захваченному `*poolSlot`, не по idx; тест -race: drain→sticky→teardown→reconnect той же ячейки→`stickyDrainCount` корректен | H2 |
| **нет системного клинча readyCapacity** | динамический гейт + досрочное снятие; тест: poolSize/2 sticky + медленный reserve → пул продолжает ротироваться, readyCapacity не залипает <floor | H4 |
| счётчик sticky не течёт | defer-releaseSticky на всех путях + идемпотентность Swap | H2 |
| watchdog-цикл конечен | каждый Reset приближает монотонный drainAge к StickyMaxDrainAge | M3 |
| pool-invariant держится | `alive+dead+connecting+draining+empty==2*poolSize` при удержании sticky в slotDraining | базовый |
| tearDown ровно один раз | Go select атомарен по выбору ветки; tearDown делает `return` → повторного входа нет; idle-case в deadline-ветке и idle-ветка ticker взаимоисключающи в одном проходе | M2-v2 |
| H4 в обоих режимах reserve | здоровый reserve → sticky НЕ снимается ложно; медленный reserve → снимается, пул ротируется | M1-v2 |
| poolSize=2 / нечётный | `effectiveStickyMaxSlots` тест на 2 (cap=1, вырожденный bimodal), нечётный (целочисл.) | M1 |
| idle выключен → sticky выключен | `DrainIdleThreshold==0` → sticky не активируется | L2 |

---

## 6. Метрики + влияние на lifetime distribution

### 6.1 Метрики (hand-rolled atomic, как весь stats.go)
```
shadowlink_drain_sticky_extended_total          # counter: deadline продлён (стрим активен)
shadowlink_drain_sticky_active_slots            # gauge: = stickyDrainCount
shadowlink_drain_sticky_backstop_age_total      # counter: teardown по возрасту (10m)
shadowlink_drain_sticky_backstop_bytes_total    # counter: teardown по объёму (200MiB на TCP)
shadowlink_drain_sticky_quota_denied_total      # counter: не дали/сняли sticky (cap или readyCapacity)
```
- **Замер остаточного хвоста (канарейка):** `backstop_age + backstop_bytes + quota_denied` = активные закачки, всё-таки прерванные НАШИМ механизмом. ≈0 → Bug #6 закрыт. Считать ОТДЕЛЬНО от reader-error-обрывов (§1.2) — иначе ложный аргумент за миграцию.
- idle-teardown в deadline-ветке → `DrainNaturalFinishTotal`/`DrainIdleFinishTotal` (НЕ DrainHardCapTotal — урок M5). `DrainHardCapTotal` остаётся чистой метрикой «реальный hard-cap».
- `emitHardCapLog`/новые tearDown-логи несут `sticky_outcome` = `idle|age_backstop|bytes_backstop|quota_denied`.
- **Алерты (урок M3-v2):** `active_slots > 0` в течение до `StickyMaxDrainAge` — НОРМА (большая закачка), НЕ залипание. Алерт строить на rate `quota_denied_total` и на разбросе lifetime (§6.2), НЕ на самом факте `active_slots>0`.

### 6.2 Влияние на per-flow lifetime distribution (урок H3)
**Честная оценка (НЕ «всё ок»):** штатный slot lifetime ДЕТЕРМИНИРОВАН — `maxSlotAge=2min + stagger` → [120s, ~232s] (подтверждено: `engine_shadowlink.go:374`, `ws_pool.go:1296`). Это НЕ log-normal хвост (тот в `mimicry.go` про сессию-маску, иной контекст). Sticky до 10min — это **выброс ~2.6× за штатный диапазон**, видимый в flow-age гистограмме TSPU.

**Почему приемлемо (с оговорками):**
- sticky активируется ТОЛЬКО на реальную активную закачку (idle рвёт быстро) — редкое событие, не штатный режим.
- динамический cap (≤ poolSize/2, и меньше при просадке) → минимум floor слотов всегда в штатном [120s,232s].
- возрастной потолок 10m — абсолютный.

**Обязательно:** канареечная метрика разброса slot lifetime (sticky vs non-sticky). Если хвост значим — усиление по полевым данным: `StickyMaxDrainAge` 10m→5m, `StickyMaxSlots` авто→poolSize/4, `stickyRecheckInterval` 5s→2.5s. Решение — по цифрам, не вслепую. Это явный follow-up, зафиксированный здесь.

---

## 7. Откат / kill switch
- `SHADOWLINK_GRACEFUL_DRAIN=0` → legacy hard-rotation, sticky не задействован (reader byte_budget graceful-ветка не выполняется → B1 не релевантен).
- `StickyMaxDrainAge <= 0` → deadline-ветка деградирует в слепой `tearDown(finishHardCap)`, поведение = pre-Bug#6. Reader-путь не тронут (B1 не вносится вовсе), поэтому kill-switch полон.
- `StickyMaxSlots < 0` → sticky запрещён (cap=0), отдельно от age-kill-switch.

---

## 8. Объём
- `ws_pool_drain.go` — ветка `deadline.C` (switch), `defer releaseSticky(oldSlot)`, новые finishCause + tearDown-ветки, sticky_outcome в логах.
- `ws_pool.go` — 3 поля `WSPoolConfig` + перенос в `p.*` + дефолты в `NewWSPoolTransport`; `WSPoolTransport.stickyDrainCount`; `poolSlot.isSticky`; helpers `stickyQuotaAvailable`/`markSticky`/`releaseSticky`/`effectiveStickyMaxSlots`. **Reader-путь byte_budget (:2521-2554) НЕ трогаем.**
- `stats.go` — 5 метрик.
- `engine_shadowlink.go:450` — заполнение 3 полей cfg.
- Snapshot-поля НЕТ. Провод НЕ меняется. Сервер НЕ трогаем.
- Оценка: 3-5 дней с TDD (вырос из-за динамического cap + cross-recycle тестов под -race).

## 9. Процесс перед мержем (обязательно)
1. Спек-саморевью v2 (этот док).
2. **Опус-ревью спеки v2** (повторное, проверить что v1-находки закрыты и новых нет).
3. User review спеки.
4. writing-plans → TDD (RED-GREEN-REFACTOR) по каждому инварианту §5, тесты под `-race`.
5. **Финальное адверсариальное опус-ревью КОДА** (как Bug #5).
6. Канарейка: замер остаточного хвоста (§6.1) + разброс lifetime (§6.2).

## 10. Журнал решений по опус-ревью v1 (`docs/bug6-spec-review-opus.md`)
| ID | Находка | Решение |
|---|---|---|
| B1 | удаление Store(0) → шторм startDrain | НЕ трогаем reader-путь вовсе; объём считаем от connect через существующий downBytes |
| B2 | drainBytes инверсия | семантика = анти-TSPU потолок на TCP (~200MiB от connect), не «байты в дренаже»; убран 1GiB |
| H1 | корень неполон | §1.2 полный перечень путей; tier-2 как регрессия + инвариант; reader-error измеряем отдельно |
| H2 | cross-recycle гонка (подтверждена) | helpers по захваченному `*poolSlot`, не по idx; -race тест |
| H3 | bimodal lifetime (подтверждён выброс) | принят с cap+потолком; §6.2 честная оценка + канареечная метрика + follow-up усиление по данным |
| H4 | клинч readyCapacity | динамический cap (readyCapacity>floor) + досрочное снятие; приоритет ротация>обрыв |
| M1 | effectiveStickyMaxSlots семантика | таблица >0/=0/<0; тест poolSize=2 |
| M3 | clock skew | монотонный time.Since |
| M5 | DrainHardCapTotal загрязнение | idle-teardown → natural-finish метрики |
| L2 | idle выключен | sticky выключается |
| L3 | recheck vs poll | stickyRecheckInterval ≥ drainPollInterval |

## Ссылки
- `docs/stream-migration-proposal.md` — почему НЕ миграция.
- `docs/bug6-code-map.md` — карта кода (file:line).
- `docs/bug6-spec-review-opus.md` — опус-ревью v1 (источник правок v2).
- CLAUDE.md Phase B+ — `SHADOWLINK_GRACEFUL_DRAIN`, `SHADOWLINK_DRAIN_HARD_CAP`.

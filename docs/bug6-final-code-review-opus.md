# Bug #6 Sticky-Stream — ФИНАЛЬНОЕ адверсариальное ревью КОДА (opus, whole-feature integration)

**Дата:** 2026-05-29
**Ревьюер:** opus-агент (финальный, pre-merge, whole-feature integration view)
**Дифф:** `git diff ee588b5 HEAD -- client/ws_pool.go client/ws_pool_drain.go client/stats.go client/sticky_stream_test.go client/ws_pool_drain_test.go cmd/nixavpn-client/engine_shadowlink.go`
**Спека:** `docs/superpowers/specs/2026-05-29-bug6-sticky-stream-design.md`
**v2 spec-review:** `docs/bug6-spec-review-opus-v2.md`
**Метод:** прочитан весь дифф + финальное состояние `drainWatchdog` (ws_pool_drain.go:554-757), `bumpRotations1m` (ws_pool.go:2855), `readyCapacity*` (ws_pool.go:604-642), env-парсеры (engine_shadowlink.go:808-833). Все вердикты — от кода с file:line.

---

## СВОДКА ПО SEVERITY

| Severity | Кол-во |
|---|---|
| BLOCKER | 0 |
| HIGH | 1 |
| MEDIUM | 2 |
| LOW | 3 |

---

## HIGH

### H-1 — Двойной `bumpRotations1m()` на каждом sticky-backstop teardown (искажает rotations_1m + лишняя горутина)

**Где:** `ws_pool_drain.go` — `tearDown` (строка 633) безусловно вызывает `p.bumpRotations1m()` на ЛЮБОМ teardown. Для sticky-путей (`finishStickyAgeBackstop` / `finishStickyBytesBackstop` / `finishStickyQuotaDenied`) `tearDown` сперва вызывает `emitStickyTeardownLog(...)`, а тот в конце (строка 756) **тоже** делает `p.bumpRotations1m()`.

**Суть:** один sticky-backstop teardown инкрементит `rotations1m` ДВАЖДЫ и спавнит ДВЕ decay-горутины (каждая со своим 60s-таймером и `Add(-1)`). Это интеграционный баг, который per-task ревью не могло увидеть в изоляции: `tearDown`'s `bumpRotations1m` существовал ДО Bug #6, а `emitStickyTeardownLog` добавлен в Task 6 — каждый по отдельности корректен.

**Доказательство асимметрии (от кода):**
- `emitHardCapLog` (ws_pool_drain.go:718-737) — НЕ вызывает `bumpRotations1m`. Hard-cap путь = ровно 1 bump (через tearDown). ✓
- `finishIdle` / `finishStreamsZero` ветки в tearDown — логируют инлайн, НЕ зовут bumpRotations1m. = 1 bump. ✓
- `emitStickyTeardownLog` (ws_pool_drain.go:756) — зовёт bumpRotations1m. Плюс tearDown's bump. = **2 bump.** ✗

**Последствие:**
1. `rotations1m` (pool-health лог, тот самый счётчик, что чинили в канарейке 2026-05-22) завышается ровно на число sticky-backstop teardown'ов. Канарейка Bug #6 будет читать ротаций больше, чем реально было, и может ложно выглядеть как «пул ротирует агрессивнее». Это прямо бьёт по метрике, на которой будет строиться приёмка фичи.
2. Двойная decay-горутина на каждый sticky teardown — мелкая утечка эфемерных горутин (живут 60s, не бесконечно, но удвоены без нужды).

**Почему HIGH, а не MEDIUM:** rotations_1m — это та самая операционная метрика, по которой принимают/отклоняют решение на канарейке (см. историю фиксов 2026-05-22/05-23). Завышение именно на sticky-событиях — то есть именно на новом поведении, которое и надо измерить — отравляет сигнал приёмки. И это чистый дефект (двойной счёт), а не trade-off.

**Фикс (одно из двух, выбрать одно):**
- Убрать `p.bumpRotations1m()` из `emitStickyTeardownLog` (строка 756) — пусть единственным источником bump'а остаётся `tearDown`, как у hard-cap / idle / streamsZero. Это приводит sticky-путь к той же дисциплине «1 teardown = 1 bump», что и все остальные пути. **Рекомендуемый вариант** (минимальный, симметричный с emitHardCapLog).
- ЛИБО убрать bump из `tearDown` и продублировать его в каждую лог-функцию — хуже (более инвазивно, легко рассинхронизировать).

---

## MEDIUM

### M-1 — `=0` НЕ выключает sticky через env, хотя kill-switch документирован как "StickyMaxDrainAge<=0"

**Где:** `engine_shadowlink.go:451-452` комментарий «StickyMaxDrainAge<=0 is the kill switch» + `envDurationDefault("SHADOWLINK_STICKY_MAX_DRAIN_AGE", 10*time.Minute)` (строка 808-818); `NewWSPoolTransport` `if stickyMaxDrainAge == 0 { stickyMaxDrainAge = 10*time.Minute }` (ws_pool.go:686-688).

**Суть (трассировка env→cfg→pool):**
- Оператор читает комментарий «<=0 = kill switch» и в полевых условиях ставит `SHADOWLINK_STICKY_MAX_DRAIN_AGE=0`, чтобы выключить фичу.
- `envDurationDefault`: `v="0"` → `time.ParseDuration("0")` = 0 (без ошибки) → возвращает 0 → cfg.StickyMaxDrainAge=0.
- `NewWSPoolTransport`: `stickyMaxDrainAge == 0` → **перезаписывает в 10m.** Sticky НЕ выключен — наоборот, включён с дефолтом.
- Чтобы реально получить kill-switch, нужно отрицательное (`=-1s`). Это работает (тест `TestDrainWatchdog_StickyKillSwitch` использует `-1`), но НЕ совпадает с тем, как оператор естественно прочитает «<=0».

**Почему MEDIUM:** функционально код корректен (kill-switch достижим через отрицательное), но env-контракт расходится с задокументированной семантикой «<=0». В стрессовой ситуации (надо срочно вырубить фичу на проде) оператор поставит `=0`, получит ВКЛЮЧЁННУЮ фичу и потеряет время. Это operational footgun на аварийном пути.

**Фикс:**
- Либо в env-слое: `if stickyMaxDrainAge == 0 { stickyMaxDrainAge = -1 }` когда env явно задан «0» (отличить «явный 0» от «unset» — сейчас envDurationDefault их склеивает). Проще: в `NewWSPoolTransport` трактовать только `< 0` как kill, а `== 0` → default — и тогда поправить комментарий env на «отрицательное = kill switch, 0/unset = default 10m».
- Либо явно задокументировать в комментарии env (строка 451): «kill switch = ОТРИЦАТЕЛЬНОЕ значение (например `-1s`); `=0` НЕ выключает — оно эквивалентно unset и даёт default 10m». Минимальный вариант — поправить вводящий в заблуждение комментарий.

То же замечание мягче применимо к `StickyMaxTotalBytes`: `<=0 → 256MiB` (ws_pool.go:691). Здесь нет отдельного kill-switch — байтовый backstop нельзя выключить через env вообще (всегда минимум 256MiB). Это by-design (backstop = анти-TSPU потолок, его и не должно быть выключаемым), но стоит явно сказать в комментарии, чтобы не искали `=0`.

### M-2 — `default`-ветка (extend) не имеет страховки от «streams==0 проскочил между тиками» в deadline-проходе

**Где:** `ws_pool_drain.go:688-693` default-ветка делает `markSticky + extend` БЕЗ проверки `oldSlot.streams.Load()==0`.

**Суть:** deadline-ветка проверяет `idle` (allStreamsIdle), но НЕ проверяет вырожденный `streams==0`. Сценарий: последний стрим закрылся ровно между последним ticker-тиком и deadline.C fire. allStreamsIdle на пустом наборе — нужно проверить его контракт: если он возвращает `true` для нулевого набора стримов, то idle-case (строка 670) поймает это и уйдёт в finishIdle — ОК. Если же возвращает `false` для пустого набора (нет стримов → «не все idle» вырожденно), default-ветка сделает markSticky+extend на слоте БЕЗ стримов, продлив дренаж пустого слота на 5s.

**Почему MEDIUM (не HIGH):** даже в худшем случае это самокорректируется на следующем ticker-тике (≤500ms): `case <-ticker.C: if streams==0 { tearDown(finishStreamsZero) }` (строки 694-698) поймает пустой слот и порвёт. Так что максимум — лишние 500ms удержания + один паразитный `DrainStickyExtendedTotal++` и один markSticky/releaseSticky цикл. Не клинч, не утечка, счётчик sticky самокорректируется через defer releaseSticky.

**Проверка контракта allStreamsIdle нужна перед мержем:** если allStreamsIdle({}) == true — проблемы нет вообще (idle-case ловит). Рекомендация: либо подтвердить это поведение тестом, либо добавить в deadline-ветку первым case'ом `case oldSlot.streams.Load() == 0: tearDown(finishStreamsZero); return` (симметрично ticker-ветке) — дёшево и снимает зависимость от семантики allStreamsIdle на пустом наборе.

---

## LOW

### L-1 — `DrainStickyExtendedTotal` инкрементится ПОСЛЕ markSticky, но markSticky идемпотентен → extended считает per-recheck, а не per-slot (by-design, но имя вводит в заблуждение)

**Где:** ws_pool_drain.go:690-691. `markSticky` (CAS) инкрементит `stickyDrainCount` один раз на слот, а `DrainStickyExtendedTotal.Add(1)` — на КАЖДОМ продлении (каждые 5s). Это два разных счётчика с разной семантикой, и это правильно (extended = «сколько раз продлевали», backstop/quota = «сколько teardown'ов»). Но при чтении метрик легко спутать `extended_total` с «числом sticky-слотов». Документация метрики (stats.go:10-11) говорит «times the deadline branch extended» — корректно. Замечание только к тому, что на одной 10-минутной закачке `extended_total` вырастет на ~120 (10min/5s), а не на 1 — это надо явно сказать в дашборде, чтобы канарейка не приняла 120 продлений за 120 застрявших стримов.
**Рекомендация:** одна строка в комментарии метрики: «инкремент на каждый 5s-recheck активного стрима; одна большая закачка даёт ~StickyMaxDrainAge/stickyRecheckInterval инкрементов».

### L-2 — Кросс-ссылка `byteBudgetMinInterval` (Bug #4) попала в тот же дифф, но не относится к Bug #6

**Где:** ws_pool.go:499-527, 611-615, 676-682, 768; WSPoolConfig.ByteBudgetMinInterval. Это Bug #4 (rotation-storm fix), а не Bug #6. Дифф `ee588b5..HEAD` смешивает две фичи. Функционально корректно (читал `byteBudgetRotationAllowed` — pure, дефолт применяется только при `MaxBytesPerSlot>0`, негатив выключает). Замечание чисто гигиеническое: при ревью «Bug #6» половина изменений ws_pool.go — это Bug #4 + ghost-session FIN (sendSlotSessionFIN, ws_pool.go:735, Close ordering :793-807). Все три фикса корректны по отдельности, но это затрудняет адресный rollback Bug #6.
**Рекомендация:** в commit/PR-описании явно перечислить, что HEAD несёт три разные фичи (Bug #6 sticky + Bug #4 byte-budget floor + ghost-session FIN), чтобы откат одной не задел другие.

### L-3 — `effectiveStickyMaxSlots` при poolSize=2 → cap=1 (вырожденный bimodal), как отмечено в spec L2-v2

**Где:** ws_pool.go:546-551. При clamp poolSize→2 получаем half=1: один слот sticky, второй несёт ротацию. Это ровно тот bimodal, что spec H3 называет TSPU-сигналом, но на минимальном пуле. Покрыто тестом `TestEffectiveStickyMaxSlots` («auto poolSize 2 → min 1»), т.е. осознано. Дефолтный пул = 6, poolSize=2 — аварийный clamp.
**Рекомендация (политическая, оставить автору):** рассмотреть форс cap=0 (sticky off) при poolSize<=2 — на пуле из 2 цена bimodal выше выгоды одной закачки. Не блокер.

---

## ПОВЕРКА ПО ПУНКТАМ ЗАДАНИЯ (1-7)

### Check 1 — End-to-end корректность deadline-ветки: ✅ с оговоркой M-2

Прочитан финальный `case <-deadline.C` (ws_pool_drain.go:651-693). Порядок case'ов трассирован целиком:
1. **kill/idle-disabled guard** (строка 661): `stickyMaxDrainAge<=0 || !idleEnabled` → finishHardCap+return. Корректно ДО любой sticky-логики — без него `!idleEnabled` провалился бы в idle-классификацию (как и сказано в комментарии). ✓
2. **idle** (670): простой → finishIdle. Должен быть первым в switch — и он первый. ✓
3. **age backstop** (674) перед **bytes backstop** (677): порядок не важен функционально (оба → teardown), но age-первым логично (жёсткий потолок времени). ✓
4. **already-sticky && capacity просел** (680): досрочное снятие. Корректно ПЕРЕД общим quota-гейтом — уже-sticky слот в `stickyQuotaAvailable` всегда вернул бы true (fast-path isSticky.Load), поэтому без этого отдельного case'а просадка ёмкости на уже-sticky слоте никогда бы не сняла его. Это и есть anti-clinch (H4). **Этот case НЕ unreachable** именно потому что стоит до строки 685. ✓ Критичный момент — порядок 680 перед 685 обязателен, и он соблюдён.
5. **!stickyQuotaAvailable** (685): свежий слот, квота/ёмкость не дают → quota_denied. ✓
6. **default** (688): extend. Взаимодействие с ticker-веткой: stickyRecheckInterval(5s) >= drainPollInterval(500ms) — ticker ловит streams==0/idle между rechecks (spec L3). Подтверждено: ticker-ветка (694-703) проверяет streams==0 и idle каждые 500ms. Единственная щель — M-2 (streams==0 в самой deadline-ветке зависит от семантики allStreamsIdle({})), самокорректируется за ≤500ms.

**Unreachable cases:** нет. **Порядок:** корректен (680 перед 685 — критично, соблюдено).

### Check 2 — defer releaseSticky vs handleSlotDeath ordering: ✅ ВЕРНО

`drainWatchdog` defers (LIFO): `defer inflightDrains.Add(-1)` (569) затем `defer releaseSticky(oldSlot)` (574). `tearDown` вызывает `handleSlotDeath` (ставит `slots[idx]=nil`, bump generation) ВНУТРИ тела, ДО return. Defers бегут ПОСЛЕ возврата tearDown→return.

Ключевой факт: `releaseSticky(oldSlot)` оперирует **захваченным** `*poolSlot` (параметр), НЕ `p.slots[idx]`. `handleSlotDeath` мутирует `p.slots[idx]` (обнуляет ячейку) и поля слота (streams.Store(0) и т.д.), но НЕ трогает `oldSlot.isSticky`. Поэтому `releaseSticky` после handleSlotDeath читает/Swap'ает `oldSlot.isSticky` — поле, которое handleSlotDeath не касался — и корректно декрементит ровно если этот слот был sticky. Иммунитет к recycle подтверждён: новый слот в ячейке — другой указатель, его isSticky=false (zero value), старый defer его не трогает. ✓ Покрыто `TestSticky_CrossRecycleNoDesync` + `TestSticky_CrossRecycleReorderedRelease`.

### Check 3 — stickyDrainCount lifecycle через реальную ротацию: ✅ КОРРЕКТНО

Прошёл: drain start → deadline fire → extend (markSticky CAS false→true, count=1) → N×extend (CAS уже true → НЕ инкрементит, count остаётся 1) → backstop teardown → handleSlotDeath (slots[idx]=nil, count всё ещё 1, isSticky_old=true) → defer releaseSticky(oldSlot) (Swap(false)=true → count=0) → ячейка recycled, connectSlot создаёт новый `&poolSlot{}` (isSticky=false zero) → новый drain → markSticky(newSlot) (count=1 от 0). Возврат к корректному значению подтверждён. Идемпотентность markSticky (повторные extend'ы не накручивают глобал) — ключ, и она держится через CAS. ✓ Покрыто `TestStickyMarkReleaseIdempotent` + `TestSticky_ConcurrentMarkRelease` (под -race).

### Check 4 — Обещания spec v2 «conditions before merge»: частично в коде, частично на CI/канарейку

v2 §«Условия перед мержем» (строки 173-179):
1. **-race тест H2** (drain→sticky→teardown→reconnect→count) — **✅ В КОДЕ:** `TestSticky_CrossRecycleNoDesync`, `TestSticky_CrossRecycleReorderedRelease`, `TestSticky_ConcurrentMarkRelease` (последний явно под -race). Прямого «reconnect той же ячейки внутри одного теста» нет — H2 проверяется через ручную симуляцию old/new указателей, а не через настоящий connectSlot. Это адекватная аппроксимация (recycle = новый указатель, что тест и моделирует), но **настоящий end-to-end recycle (connectSlot реально ставит новый слот) на канарейку/CI -race прогон**, не в unit.
2. **Тест H4 в ОБОИХ режимах** (здоровый reserve → держится; медленный → снимается) — **✅ В КОДЕ:** `TestSticky_NoClinch_UnhealthyCapacity` (denied) + `TestSticky_HealthyCapacity_Granted` (granted) + `TestStickyQuotaAvailable` подкейсы. Закрывает M1-v2. ✓
3. **3 LOW-формулировки в §3.3/§4/§6.2** — это правки СПЕКИ, не кода; не верифицируемо из диффа кода. **Deferred (документация).**
4. **Финальное опус-ревью КОДА** — это текущий документ. ✓
5. **Канарейка: остаточный хвост ОТДЕЛЬНО от reader-error + разброс lifetime** — **DEFERRED НА КАНАРЕЙКУ** (требует прод-телеметрии). Метрики для этого В КОДЕ есть (4 sticky-счётчика + DrainDurationSeconds гистограмма), но разделение reader-error vs backstop-хвоста и анализ разброса lifetime — операционная задача.

**Обещано В КОДЕ но отсутствует:** ничего критичного не пропущено. §6.2 bimodal-lifetime gauge `shadowlink_drain_sticky_active_slots` (упоминался в spec §6.1 как gauge=stickyDrainCount) — **в диффе stats.go его НЕТ.** Добавлены 4 counter'а (extended/backstop_age/backstop_bytes/quota_denied), но gauge активных sticky-слотов не экспонирован. Это снижает наблюдаемость на канарейке (нельзя в моменте увидеть «сколько слотов сейчас sticky»). Не блокер (можно вывести из extended - teardown'ы приблизительно), но **рекомендую добавить gauge перед канарейкой** — spec §6.1 его обещал, M3-v2 прямо его обсуждал.

### Check 5 — Корректность метрик end-to-end: ✅ кроме H-1 (двойной bumpRotations1m)

- `DrainStickyExtendedTotal` — per-extend (каждые 5s), ws_pool_drain.go:691. ✓ (см. L-1 про именование).
- 3 backstop/quota counter'а — per-teardown, ровно один Add(1) в tearDown switch (599/602/605). ✓
- `DrainHardCapTotal` — продвигается ТОЛЬКО через `emitHardCapLog` (719), который зовётся ТОЛЬКО для finishHardCap. Sticky teardown'ы и idle-в-deadline его НЕ трогают. ✓ Подтверждено тестами `TestDrainWatchdog_IdleGoesToNaturalFinish` (hard не растёт) и `TestDrainWatchdog_PerStreamIdle_HoldsOpenForActiveStream` (hard не растёт, extended растёт).
- `DrainNaturalFinishTotal` — idle-в-deadline идёт сюда (finishIdle, строка 608) + finishStreamsZero (622). Семантика чистая: natural = idle|streamsZero, hardcap отдельно, sticky отдельно. ✓
- **Двойной счёт ЕСТЬ — но в `rotations1m`, не в drain-counter'ах:** см. H-1. Drain-метрики (hardcap/natural/sticky/duration) считаются корректно по одному разу; искажается именно pool-health `rotations1m`.

### Check 6 — Регрессия non-sticky пути: ✅ ИДЕНТИЧНО pre-Bug#6

- **kill-switch** (`StickyMaxDrainAge<=0`): guard на строке 661 → `tearDown(finishHardCap); return` — буквально старый код (до Bug#6 deadline.C делал ровно `tearDown(finishHardCap); return`, см. дифф строки 869-871: `-tearDown(finishHardCap) / -return`). Поведение байт-в-байт. ✓
- **idle-disabled** (`DrainIdleThreshold==0` → `!idleEnabled`): тот же guard 661 → finishHardCap. До Bug#6 при отключённом idle deadline тоже рвал по hard-cap. ✓ Тест `TestDrainWatchdog_StickyKillSwitch` подтверждает teardown ~50ms (hard cap) + DrainHardCapTotal+1.
- ticker-ветка (694-703) НЕ изменена диффом — streams==0 и idle-finish работают как раньше. ✓

### Check 7 — engine wiring (env-дефолты vs NewWSPoolTransport): ⚠️ см. M-1

- **StickyMaxDrainAge:** env-дефолт 10m (engine:452) совпадает с NewWSPoolTransport-дефолтом 10m (ws_pool.go:687). Unset env → 10m → cfg=10m → pool оставляет 10m. Set-to-default `=10m` → тот же путь. **Расхождение только на `=0`** (M-1): env пропускает 0, pool превращает 0→10m, оператор ждёт kill-switch. Kill через отрицательное работает.
- **StickyMaxTotalBytes:** env-дефолт 256MiB (engine:453) == pool-дефолт 256MiB (ws_pool.go:692). ✓ `<=0` в pool → 256MiB; env пропустит 0 → pool→256MiB. Согласованно (backstop неотключаем by-design, см. M-1 хвост).
- **StickyMaxSlots:** env-дефолт 0 (engine:454) → cfg=0 → pool `effectiveStickyMaxSlots` трактует 0 как авто poolSize/2. `<0` → выкл. Согласованно. ✓

Никаких сюрпризов unset-vs-set-to-default, КРОМЕ kill-switch-через-`=0` (M-1).

---

## ЧТО СДЕЛАНО В КОДЕ vs ОТЛОЖЕНО

**Сделано в коде (верифицировано):**
- Полная deadline-ветка с 6-уровневым решением, корректный порядок case'ов (включая критичный 680-перед-685).
- H2 cross-recycle безопасность (captured pointer + CAS/Swap) + 3 теста, один под -race.
- H4 anti-clinch (динамический readyCapacity-гейт + досрочное снятие) + тесты в обоих режимах.
- Kill-switch + idle-disabled деградация в blind hard-cap, байт-в-байт с pre-Bug#6 + тест.
- 4 sticky-counter'а + Prom-экспозиция + idle→natural-finish (DrainHardCapTotal чист) + тесты.
- env-проброс 3 knob'ов с дефолтами, согласованными с pool (кроме `=0` footgun, M-1).
- Обновлён существующий `TestDrainWatchdog_PerStreamIdle_HoldsOpenForActiveStream` под новый контракт (active → extend, не hard-cap).

**Отложено на канарейку/CI (НЕ блокирует мерж):**
- Прод-измерение: остаточный backstop-хвост ОТДЕЛЬНО от reader-error обрывов (spec §6.1) — нужна телеметрия.
- Разброс lifetime sticky-слотов (bimodal H3) — канареечная метрика, follow-up пороги (10m→5m и т.д.) «по цифрам».
- end-to-end -race прогон реального recycle (connectSlot ставит новый слот в дренированную ячейку) — unit-тесты моделируют через два указателя; настоящий путь — на CI `go test -race -count=3 ./client/`.
- 3 LOW-уточнения формулировок в самой СПЕКЕ (§3.3/§4/§6.2) — документация.

**Отложено, но РЕКОМЕНДУЮ подтянуть перед канарейкой (не мерж-блокеры):**
- gauge `shadowlink_drain_sticky_active_slots` = stickyDrainCount (spec §6.1 обещал, в диффе stats.go отсутствует) — без него наблюдаемость sticky в моменте слабее.

---

## ФИНАЛЬНЫЙ ВЕРДИКТ

**NEEDS-FIXES** (один HIGH перед мержем; MEDIUM желательно).

Фича архитектурно когерентна, все 14 находок spec-review v2 подтверждены закрытыми В КОДЕ, deadline-ветка трассируется без unreachable/мисордеринга, H2/H4 безопасность доказана и покрыта тестами, non-sticky регрессии нет. Но:

- **H-1 (двойной `bumpRotations1m` на sticky teardown)** — обязателен к фиксу до мержа: он завышает именно ту метрику (`rotations_1m`), по которой будут принимать фичу на канарейке, и это чистый дефект, а не trade-off. Фикс однострочный (убрать bump из `emitStickyTeardownLog`).
- **M-1 (env `=0` не выключает sticky вопреки документации)** — починить или хотя бы исправить комментарий; это аварийный operational footgun.
- **M-2** — подтвердить семантику `allStreamsIdle({})` или добавить explicit `streams==0` case в deadline-ветку (дёшево).

После H-1 (+ желательно M-1, M-2) — **READY**. LOW-замечания и gauge — на усмотрение автора, можно после мержа/перед канарейкой.

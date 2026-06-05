# Критическое ревью: TSPU age-window tuning design (2026-06-05)

**Ревьюер:** opus (субагент)
**Спека:** `docs/superpowers/specs/2026-06-05-tspu-age-window-tuning-design.md`
**База:** `docs/client-log-analysis-2026-06-05.md` (клиент+сервер pl1)
**Код:** `client/ws_pool.go`, `client/migrate_watchdog.go`, `client/ws_pool_drain.go`,
`cmd/nixavpn-client/engine_shadowlink.go`, `server/ratelimiters.go`, `server/tokenbucket.go`,
`server/config.go`, `internal/deploy/steps_shadowlink.go`

---

## ВЕРДИКТ: CHANGES-REQUIRED

Спека верно диагностирует корень (age-based заморозка) и направление (опустить окно ротации под
130с). НО центральный расчёт спеки построен на неверной модели пула (idx 0..7), тогда как код
гоняет staggerOffset по idx 0..15 (uniform-cells `2*poolSize`). При предложенном
staggerStep=6s слот idx=15 режется в **165с** — прямо в центре окна заморозки 130-190с. Это
сводит на нет всю цель фикса для значимой доли слотов. Плюс rate-limit предложение (60/120)
недосчитано ~2× по агрегату для 16-слотового пула с резом каждые ~75-117с.

### Счётчики находок

| Severity | Кол-во |
|----------|--------|
| BLOCKER  | 2 |
| HIGH     | 3 |
| MEDIUM   | 4 |
| NIT      | 3 |

---

## BLOCKER

### BLOCKER-1 — staggerOffset считается по idx 0..15, не 0..7 → idx=15 режется в 165с (в окне заморозки)

**Файл:** `client/ws_pool.go:517-526` (`slotStaggerOffset`), `:1776-1809` (sweep iterates `slots :=
p.snapshotSlots()` = весь slice), `:1641` (`p.slots = make([]*poolSlot, p.poolSize*2)`),
`:2127` (`slot.staggerOffsetNs.Store(int64(slotStaggerOffset(idx)))`).

Спека (§"Решение", таблица "Итог") утверждает «разброс 8 слотов = 7×6s=42s → реальный возраст реза
75-117s, весь под 130s ✅». Это **ложно**. `slotStaggerOffset(idx)` принимает РЕАЛЬНЫЙ индекс ячейки
в slice длиной `2*poolSize`. При poolSize=8 индексы идут 0..15. В полевом логе alive доходил до 16
(uniform-cells держит до 2×poolSize живых ячеек).

`effectiveMaxAge := p.maxSlotAge.Nanoseconds() + slot.staggerOffsetNs.Load()` (ws_pool.go:1809).
При MaxSlotAge=75s, step=6s:

```
idx= 0: 75 + 0   = 75s
idx= 7: 75 + 42  = 117s   ← спека остановилась здесь
idx= 8: 75 + 48  = 123s
idx=11: 75 + 66  = 141s   ← в логе slot=11 замёрз на 132756ms
idx=15: 75 + 90  = 165s   ← ЦЕНТР окна заморозки 130-190с
```

`slotStaggerOffset` ещё добавляет ±step/2 джиттер (524) → idx=15 может уйти до 168s. Слоты idx≥9
режутся ВНУТРИ окна заморозки — для них фикс не работает вообще. Долгий GET, осевший на reserve-cell
с высоким idx, ловит ровно тот же stall, что и сейчас.

**Доказательство из лога:** `slot=11 slot_age_ms=132756 last_write_age_ms=15436 ← заморозка`. Слот с
idx=11 уже сегодня доживал до 132с — именно потому что staggerOffset(11) велик. Снижение базы до 75с
НЕ спасает idx=11: 75 + 11·6 = 141s > 130s.

**Чтобы даже idx=15 резался < 130с с запасом 5с (≤125s) при линейном stagger:**
`75 + 15·step ≤ 125 → step ≤ 3.33s`. Но step=3.33s даёт разброс 8 «нормальных» слотов = всего 23s
(idx 0..7), а 16 слотов = 50s — приемлемо, НО джиттер ±step/2=±1.67s почти исчезает (анти-FFT эффект
слабеет). Линейный step не может одновременно (а) дать разумный разброс и (б) удержать idx=15 < 130с.

**Рекомендация (см. также HIGH-1):** ввести **cap** на staggerOffset, привязанный к MaxSlotAge, а
не растить линейно до idx=15. Напр. `offsetCap = (freezeFloor − MaxSlotAge − margin)` и
`staggerOffset(idx) = min(idx·step, offsetCap) + jitter`. При MaxSlotAge=75s, freezeFloor=130s,
margin=10s → offsetCap=45s. Тогда idx=8..15 все кэпятся на 75+45=120s < 130s. step можно оставить 6s
(idx 0..7 распределены 75..117s, idx≥8 садятся на потолок 120s). Это закрывает дыру без жертвы
анти-FFT джиттера на «рабочих» младших слотах.

---

### BLOCKER-2 — rate-limit burst/refill недосчитан: честная агрегатная частота для 16 слотов ≈ 11-13 reconnect/min, пики выше; но WSUpgrade refill=120/min ОК по среднему, burst=60 мал под каскад

**Файл:** `server/ratelimiters.go:104-119`, `server/tokenbucket.go:40-65` (per-IP bucket),
`client/ws_pool.go:2029` (SendHandshake) + `:2089` (UpgradeToWS) — **каждый** reconnect слота жжёт
ОДИН handshake-токен И ОДИН ws_upgrade-токен.

Честный расчёт (формула из задания: reconnects/min = N_slots / средний_период_слота_сек × 60).

Средний период жизни слота = средний возраст реза. С BLOCKER-1-фиксом (cap 120s) средний ≈ (75+120)/2
≈ **97.5s**. Без cap (спека как есть) средний по 16 слотам ≈ (75+165)/2 ≈ 120s.

| Сценарий | N | период | reconnect/min (среднее) |
|----------|---|--------|--------------------------|
| pool 8, alive=8, период 97.5s | 8 | 97.5s | 8/97.5·60 ≈ **4.9/min** |
| pool 8, alive=16, период 97.5s | 16 | 97.5s | 16/97.5·60 ≈ **9.8/min** |
| pool 8, alive=16, период 120s (спека без cap) | 16 | 120s | 16/120·60 ≈ **8.0/min** |

Среднее (≈10/min) НИЖЕ предложенного refill=120/min — **запас по среднему ~12×, более чем достаточно**.
НО rate-limiter режет не по среднему, а по **burst при каскаде**. Худший случай — каскад age-cut:
несколько зрелых слотов режутся в близком окне (лог показывает io_timeout=18 за ~7 мин на pl1, т.е.
кластера по 3-5 одновременных cut реальны). Каждый cut → reconnectLoopFast (ageCutReconnectJitter
U(0,800ms)) → 1 handshake + 1 ws_upgrade почти синхронно.

Worst-case спайк: пул баре-стартует/перетряхивается → до 16 reconnect в окне ~1-2с. Это **16 ws_upgrade
токенов мгновенно**. burst=60 это переживёт (16 ≪ 60). НО handshake bucket: дефолт burst=50 (config.go),
16 ≪ 50 — ОК. Проблема в том, что спайки накладываются на фоновый поток: за 30с может пройти 2-3
каскада по 5-8 + фоновые ~5/min ⇒ до ~30-40 ws_upgrade за 30с против burst=60 + 60 refilled = OK.

**Вывод по числам:** предложенные **ws_upgrade burst=60 / refill=120** ДОСТАТОЧНЫ по агрегату (запас
>2× над худшим устойчивым ~10/min и >1.5× над worst-burst). Но:

1. **Спека не учла handshake-bucket.** Каждый reconnect жжёт и handshake-токен (ws_pool.go:2029).
   ClientID-exemption (clientid_exempt.go) гасит handshake на subsequent reconnects, НО только после
   первого аутентифицированного и через отдельный soft-limit 60/min. При резе ~10/min фон + каскады
   handshake exemption soft-limit=60/min может задеть на спайке. **Поднять и handshake** в генераторе
   (burst=80/refill=300 как минимум, или явно проверить exemption-путь под новой частотой).
2. **burst=60 впритык под двойной каскад при alive=16.** Рекомендую **burst=90** (запас 1.5× над
   единичным полным перетряхиванием 16 слотов + фон). refill=120/min оставить.
3. **per-IP риск anti-abuse:** bucket — per-IP (tokenbucket.go:9 "TokenBucket per-IP"). За одним
   публичным NAT/CF-edge IP может сидеть НЕСКОЛЬКО клиентов. refill=120/min на ОДИН IP при 3-4 клиентах
   за NAT = 30-40/min на клиента — впритык. CF-edge IP-ы агрегируют тысячи юзеров. **Для viaCF режима
   refill=120 может оказаться МАЛ** (хотя сейчас режим direct, спека про это не думает). Зафиксировать:
   значение валидно для direct-режима single-client-per-IP; для CF-режима — отдельная оценка.

**Рекомендация:** ws_upgrade **burst=90 / refill_per_min=120**; handshake **burst=80 /
refill_per_min=300** (тоже вынести в генератор). Документировать, что числа рассчитаны для direct
single-client-per-IP; CF-режим требует пересчёта.

---

## HIGH

### HIGH-1 — staggerStep должен быть кэпированным/нелинейным; const=6s сам по себе не решает (следствие BLOCKER-1)

**Файл:** `client/ws_pool.go:473` (`const slotRotationStaggerStep`), `:517-526`.

Спека предлагает плоско заменить const 15s→6s. Даже если так, BLOCKER-1 остаётся. Правильное решение —
изменить ФОРМУЛУ `slotStaggerOffset`, а не только константу:

```go
// псевдо
func (p *WSPoolTransport) slotStaggerOffset(idx int) time.Duration {
    if idx <= 0 { return 0 }
    base := time.Duration(idx) * slotRotationStaggerStep
    if base > p.staggerOffsetCap { base = p.staggerOffsetCap } // НОВЫЙ cap
    jitter := ...
    return base + jitter
}
```

где `staggerOffsetCap = max(0, freezeFloor − MaxSlotAge − safetyMargin)`. Заметь: `slotStaggerOffset`
сейчас **пакетная функция без приёмника** (ws_pool.go:517) — cap зависит от MaxSlotAge (поле
транспорта), поэтому её придётся сделать методом `*WSPoolTransport` ИЛИ передавать cap аргументом.
Это затрагивает вызовы на :2127 и тесты ws_pool_test.go:489/994/1063 (пинят `idx*slotRotationStaggerStep`).

### HIGH-2 — staggerStep вынести в env обязательно, иначе откат требует пересборки (спека сама признаёт, но оставляет «решить в плане»)

**Файл:** `client/ws_pool.go:473` (const), спека §"Объём/файлы" п. про env.

Спека пишет: «staggerStep — const, НЕ env: решить в плане (вынести в env ИЛИ оставить const)». При
агрессивном тюнинге под боевую DPI это рычаг №1 (BLOCKER-1 показал, что именно stagger — источник
дыры). Откат «через пересборку» (спека §Деплой) неприемлем для боевого параметра. **Вынести
staggerStep И staggerOffsetCap в `SHADOWLINK_*` env** (по образцу MaxSlotAge/DrainHardCap на
engine_shadowlink.go:386/433). Иначе при ошибке в поле нет мгновенного отката, а MaxSlotAge env
НЕ перекрывает stagger (offset аддитивен поверх MaxSlotAge — снижение MaxSlotAge не уменьшает
idx·step).

### HIGH-3 — MaxSlotAge=75s vs ageCutMinAgeMs=60s: окно классификации схлопывается, риск meltdown false-trip

**Файл:** `client/ws_pool.go:1032` (`ageCutMinAgeMs = 60_000`), `:1051+` (`isAgeCut`),
`:3642-3657` (age-cut → fast reconnect, НЕ feed meltdown; natural → recordSlotDeath+meltdown).

Сейчас MaxSlotAge=120s, ageCutMinAgeMs=60s — широкое окно: рез в 120-225с, классификатор уверенно
метит как age_cut (>60s). При MaxSlotAge=75s граница age_cut (60s) и наш собственный рез (75s) сходятся
на 15с. Любой **genuine** ранний обрыв слота в 60-75с теперь классифицируется как age_cut →
reconnectLoopFast, НЕ feed meltdown. И наоборот: наш плановый рез слота idx=0 в 75с — это
deathCausePreemptiveRotation/drainTeardown (не reader-error), так что классификатор его не видит. Но
если слот реально умер от сети в 65с — раньше это был natural (меньше 60? нет, >60 → age_cut и сейчас).
Фактический риск: окно «молодого natural-обрыва» (где meltdown-детектор ДОЛЖЕН сработать) сжалось до
0-60с. Это **скорее приемлемо**, но спека не проанализировала взаимодействие порогов вообще.
**Рекомендация:** опустить `ageCutMinAgeMs` пропорционально (напр. 45s) ИЛИ явно обосновать, что
60s-граница остаётся корректной при 75s-резе. Добавить в тесты регресс на классификацию обрыва в
65-74с.

---

## MEDIUM

### MEDIUM-1 — окно миграция→age-cut схлопывается, но AfterFunc успевает (пограничный край)

**Файл:** `client/migrate_watchdog.go:52` (threshold base 60s, ×U(0.7,1.0)=42-60s),
`:170-214` (`scheduleSlotMigration`, AfterFunc offset = `sampleMigrationOffset(spread)` = U(0,8s)),
`:198` (`time.AfterFunc(offset, ...)`), `client/ws_transport.go:632` (`migrateAckTimeout=1500ms`).

Худший случай тайминга:
- migrationThreshold high-end = 60s (база 60s × 1.0).
- Watchdog тикает каждые 5s (ws_pool.go:1746) → миграция может стартовать на тике в 60-65s.
- AfterFunc offset до 8s → реальный send в 60-73s.
- sendMigrate ack-window до 1.5s → MIGRATE_OK к 61.5-74.5s.

MaxSlotAge=75s (idx=0). **74.5s vs 75s — зазор 0.5s.** Для idx=0 (offset=0) миграция edge-случай
МОЖЕТ не успеть до age-cut → стрим попадает в RESUME-on-death (handleSlotDeath path, ws_pool.go:3589),
который тоже мигрирует. То есть НЕ теряется (resumeStreamOnDeath), но это уже реактивный, не
превентивный путь. Спека §"Инварианты" п.3 пишет «миграция всё ещё успевает (стартует в 42-60с, рез в
75-117с)» — для idx≥1 верно (рез ≥81s, запас ≥7s), для idx=0 (рез=75s) — впритык.

**Рекомендация:** опустить `migrationThresholdBase` до **45s** (env уже есть:
`SHADOWLINK_MIGRATE_THRESHOLD`, migrate_watchdog.go:53). Тогда high-end threshold=45s, send к 45+5+8+1.5
≈ 59.5s ≪ 75s — устойчивый запас. Спека сама это допускает («если тесно — 35s»). 45s — достаточно.

### MEDIUM-2 — DrainHardCap=45s worst-case TCP-возраст 162s, НО стримы RESUME'ятся (не теряются) — спека права, но обоснование неполное

**Файл:** `client/ws_pool_drain.go:680` (`deadline := time.NewTimer(p.drainHardCap)`),
`:763-802` (hard-cap/sticky teardown → `tearDown(...)` → `handleSlotDeath(deathCauseDrainTeardown)`),
`client/ws_pool.go:3589-3603` (drainTeardown → `migrationOn` → `resumeStreamOnDeath` мигрирует стрим
на живой слот).

Спека §"Инварианты" п.1 правильно говорит «стримы мигрируют ДО реза», но обоснование «дренаж не держит
TCP молодым» неполно. Реальная защита: при teardown дренируемого слота `handleSlotDeath` с
`migrateEnabled` гоняет `resumeStreamOnDeath` для КАЖДОГО активного стрима — стрим переезжает на живой
слот (selectYoungTargetSlot), байты целы. Worst-case: слот стартовал дренаж в 117s (idx=7) + 45s =
162s полного teardown — НО это TCP-возраст слота, который к этому моменту НЕ несёт долгий GET (тот
мигрировал в 42-60s через scheduleSlotMigration ИЛИ резюмируется сейчас). С BLOCKER-1-фиксом (cap 120s)
worst drain teardown = 120+45=165s — тот же порядок. **Не блокер**, потому что migration/resume
покрывает. Но: если `migrateEnabled=false` (миграция не негошиэйтилась — флоу не включён на слоте),
resumeStreamOnDeath НЕ вызывается (ws_pool.go:3578 `migrationOn := p.migrateEnabled.Load()`), и стрим
рвётся по close(chan) в 162s — в окне заморозки. **Рекомендация:** подтвердить, что flow/migrate
всегда негошиэйтится в боевом direct-режиме (лог: `migrate=true` на каждом CONNECT — да, негошиэйтится);
для подстраховки опустить DrainHardCap до **30s** (спека сама допускает) — worst teardown 120+30=150s,
и сократить хвост.

### MEDIUM-3 — генератор config.yaml не пишет rate_limit; но и не пишет ничего, что валидирует burst/refill

**Файл:** `internal/deploy/steps_shadowlink.go:60-94` (`renderShadowLinkYAMLContent` — пишет listen/
server_key/decoy/max_clients/behind_proxy/origin_death_teardown/management/domain_decoy_map; **блока
`rate_limit:` НЕТ**).

Спека верно идентифицирует, что генератор не эмитит `rate_limit:` → на pl1 применяются дефолты 18/30
(ratelimiters.go:104-108) → 4× HTTP 429 в поле. План добавить поля
`WSUpgradeBurst`/`WSUpgradeRefillPerMin` в `ShadowLinkYAMLParams` и рендерить блок по образцу
`origin_death_teardown` (emit только при non-zero) — архитектурно верно. **Нюанс:** при emit «только при
non-zero» сервер на отсутствие берёт дефолт 18/30 (config.go:159, ratelimiters.go:104). Значит на ВСЕХ
существующих деплоях без передеплоя останется 18/30 — а с ускорением реза они начнут массово ловить 429.
**Рекомендация:** (а) либо сделать non-zero дефолт В ГЕНЕРАТОРЕ (всегда писать 90/120), а не полагаться
на server-fallback 18/30; (б) staged-передеплой config.yaml на pl1 ОБЯЗАТЕЛЕН ВМЕСТЕ с клиентом, иначе
клиент ускорит рез → сервер начнёт резать ws_upgrade 429 → клиент не сможет пересоздавать слоты →
капасити-дип. Это **связка**: нельзя катить клиент-тюнинг без серверного config.yaml.

### MEDIUM-4 — учащённый рез усиливает нагрузку на storm-brake/force-evict; force-evict в логе уже частый

**Файл:** `client/ws_pool.go:3398-3413` (storm brake gate на readyCapacity),
`client/ws_pool_drain.go:535-566` (claimFreeSlot → tryForceEvictIdleSlot / tryEmergencyEvictMinStreams),
`:481-527` (inflight cap + capacity floor gates).

Лог уже показывает `WS pool drain force-evicted idle slot` — это НЕ ошибка сама по себе (tier-1
force-evict idle cell — штатный путь когда slice занят), но частота вырастет: рез каждые ~6-12с (вместо
~15с) при 16 ячейках → claimFreeSlot чаще упирается в «slice full» → чаще force-evict. Риски:
1. **Storm-brake клинч:** readyCapacityFloor = 0.75·poolSize = 6 (ws_pool.go:634, 767-776). При резе
   каждые 6с и reconnect ~0.4-0.8с слотов в connecting-состоянии больше → readyCapacity чаще < 6 →
   startDrain дефёрится (Gate 5, drain_drain.go:503-526) → дренаж копится → drainDeferrals растёт. Это
   САМОРАЗРЕШАЕТСЯ (grace-expired force-rotate, ws_pool.go:3454), но под агрессивным резом дип капасити
   глубже. **Нужна канарейка именно на readyCapacity-минимум и CapacityFloorDeferredTotal.**
2. **maxConcurrentDrains:** при step=6s и 16 слотах в окне 45s дренажа может быть одновременно
   дренируемо больше слотов → inflight cap (Gate 4, :481) чаще дефёрит. Проверить
   `maxConcurrentDrains()` под новой частотой.

**Рекомендация:** канарейка с явным мониторингом `readyCapacity` min, `CapacityFloorDeferredTotal`,
`InflightCapDeferredTotal`, `DrainForceEvictedTotal`, `DrainForceEvictedActiveTotal` (emergency-evict
активных стримов — вот ЭТО уже симптом, должно быть ≈0). Если force-evict-active растёт — рез слишком
агрессивен, поднять MaxSlotAge или cap.

---

## NIT

### NIT-1 — спека пишет «реальный рез 75-117s» в двух местах как факт; исправить на «75-120s при cap, иначе 75-165s»
§"Корень в цифрах" и итоговая таблица. После BLOCKER-1-фикса корректное число — 75-120s (с cap).

### NIT-2 — keepalive 5s не трогается верно, но стоит зафиксировать инвариант keepalive ≪ MaxSlotAge
keepaliveDefaultBase=5s (ws_pool.go:543), window [2.5s,10s]. При MaxSlotAge=75s инвариант
keepalive≪age сохраняется с большим запасом. Просто отметить в тестах.

### NIT-3 — тесты ws_pool_test.go пинят 15s/120s и `idx*slotRotationStaggerStep` напрямую
ws_pool_test.go:489, :994, :1063 хардкодят `slotRotationStaggerStep`/`int(i)*int(slotRotationStaggerStep)`.
При вводе cap (HIGH-1) эти тесты сломаются и должны быть переписаны на новую capped-формулу, а не просто
перепинены на 6s. Спека §"Тесты" это частично покрывает («обновить тесты, пинящие 120s/15s»), но не
упоминает cap-логику.

---

## ИТОГОВЫЕ РЕКОМЕНДОВАННЫЕ ЗНАЧЕНИЯ

| Параметр | Спека предлагала | РЕКОМЕНДУЮ | Почему |
|----------|------------------|-----------|--------|
| `MaxSlotAge` | 75s | **75s** (OK) | база реза под окном заморозки |
| `slotRotationStaggerStep` | 6s | **6s, НО с cap** | сам по себе 6s НЕ решает (idx до 15) |
| `staggerOffsetCap` (НОВЫЙ) | — отсутствует | **45s** (= 130−75−10 margin) | держит idx=8..15 на 120s < 130s |
| → реальный рез всех 16 слотов | (спека: 75-117s, неверно) | **75-120s** | весь под 130s с запасом 10s |
| `DrainHardCap` | 45s | **30s** | worst teardown 120+30=150s; стримы всё равно RESUME'ятся |
| `migrationThresholdBase` | без изменений (60s) | **45s** (env) | запас миграции до age-cut idx=0 |
| `ageCutMinAgeMs` | без изменений (60s) | **45s** | сошлось с 75s-резом (HIGH-3) |
| ws_upgrade `burst` | 60 | **90** | запас под двойной каскад при alive=16 |
| ws_upgrade `refill_per_min` | 120 | **120** (OK) | >2× над худшим устойчивым ~10/min |
| handshake `burst` | (не упомянут) | **80** (вынести в генератор) | reconnect жжёт и handshake-токен |
| handshake `refill_per_min` | (не упомянут) | **300** | паритет с server-default |

**Обязательная связка деплоя:** клиент-тюнинг НЕЛЬЗЯ катить без передеплоя config.yaml на pl1 с
поднятым rate_limit (MEDIUM-3) — иначе ускоренный рез упрётся в 18/30 → 429 → капасити-дип.

**Самое важное:** BLOCKER-1 (cap на staggerOffset для idx 0..15) — без него фикс не достигает цели для
слотов idx≥9, ровно тех, что в логе уже замерзали (slot=11 @132s).

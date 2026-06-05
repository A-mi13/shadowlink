# TSPU age-window tuning — обрыв долгого GET (Claude update) через ShadowLink — design

**Date:** 2026-06-05
**Status:** DESIGN — pending opus-review → plan
**Класс:** клиентский тюнинг порогов ротации слотов. Сервер НЕ меняется.
**Связь:** продолжение half-open фикса (`2026-06-04-halfopen-drain-stream-leak-design.md`, A+B уже в бинаре).

## Симптом
Claude Code auto-update (и любая долгая одиночная HTTP-загрузка одного файла) через ShadowLink
обрывается: `Auto-update failed`. Веб при этом работает, большие закачки в браузере (десятки/сотни МБ)
доходят. Полевой лог `nixavpn-DEBUG-20260605-100559.log` + серверный лог pl1 07:05-07:12 UTC.

## Корень (доказан с ДВУХ сторон — клиент + сервер pl1)

**TSPU/middlebox замораживает зрелые direct-TCP к голому origin IP 104.222.177.67 по ВОЗРАСТУ.**

Доказательная база — см. `docs/client-log-analysis-2026-06-05.md`:
- **Сервер pl1 ЗДОРОВ** (гипотеза «сервер залип» ОТВЕРГНУТА): свежий бинарь 04.06, аптайм 17ч,
  активен непрерывно без 30с-дыр, дилит за 1-45ms, decrypt_fails=0, `migrate=true` на каждом CONNECT.
  Распределение причин закрытия слотов: io_timeout=18, peer_eof=17, local_close=3. **0 migrate_fail/RESUME
  на сервере** — миграция чисто клиентская (half-open фикс A работает).
- **Симметричный i/o timeout** на КОНКРЕТНЫХ зрелых TCP при живом сервере и живых соседних соединениях =
  сигнатура age-based заморозки в сети.
- **Окно заморозки измерено (клиентский slot_age_ms при stall): ~130-190с.** Слоты возрастом 132-265с
  показывали last_write_age_ms 12-34с (downlink замёрз), молодые (89-101с) — норма.

**Keepalive НЕ спасает:** клиент уже шлёт WS keepalive каждые ~5с (`keepaliveDefaultBase=5s`,
ws_pool.go:543). Заморозка случается несмотря на 5с PING ⇒ режут по ВОЗРАСТУ, не по idle. Keepalive
не трогаем (бесполезен против age-based, и так есть).

**Почему рвётся именно долгий GET:** веб = сотни коротких параллельных стримов, переживают (миграция
спасает). Claude update = ОДИН длинный GET одного большого файла. Привязанный к слоту, который доживает
до 120-225с (см. ниже), стрим ловит 30с-провал downlink в окне заморозки = обрыв TCP в середине файла →
апдейтер ретраит → снова на замерзающий слот → fail.

## Корень в цифрах (текущие пороги vs окно заморозки)

| Параметр | Значение сейчас | Файл |
|----------|-----------------|------|
| migrationThresholdBase | 60s (env→45s), фактич. ×U(0.7,1.0)=42-60s | migrate_watchdog.go:52 |
| **MaxSlotAge** | **120s** + stagger idx×15s → реальный рез 120-225s | engine_shadowlink.go:386 |
| **slotRotationStaggerStep** | **15s** | ws_pool.go:473 |
| DrainHardCap | 90s | engine_shadowlink.go:433 |
| keepalive | 5s | ws_pool.go:543 |

**Корень:** maxSlotAge=120s + stagger до +105s (idx 7) → старшие слоты живут до 160-225с, прямо в зоне
заморозки 130-190с.

## Решение — опустить окно ротации под границу заморозки

**Принцип:** возраст реза ВСЕХ слотов (idx 0..15 — uniform-cells slice = 2×poolSize!) ДОЛЖЕН укладываться
НИЖЕ 130с с запасом. Превентивная миграция — первая линия. Долгий GET мигрирует по цепочке свежих слотов;
target всегда моложе окна заморозки.

### ⚠ ИСПРАВЛЕНО ПОСЛЕ ОПУС-РЕВЬЮ (BLOCKER-1): линейный stagger НЕ работает для idx 0..15
Код использует uniform-cells slice длиной `2*poolSize=16` (ws_pool.go:1641), `slotStaggerOffset(idx)`
(ws_pool.go:517) принимает РЕАЛЬНЫЙ idx ячейки 0..15, `effectiveMaxAge = maxSlotAge + staggerOffsetNs`
(ws_pool.go:1809). При линейном `idx×6s` слот idx=15 режется в `75 + 90 = 165с` — В ЦЕНТРЕ окна заморозки.
В логе alive доходил до 16, slot=11 (idx=11) уже замерзал @132с. Линейный stagger физически не может
одновременно дать разброс И удержать idx=15 под 130с. **РЕШЕНИЕ: cap на staggerOffset.**

**Финальные значения (после опус-ревью, все рекомендации приняты):**

| Параметр | Было | Станет | Обоснование |
|----------|------|--------|-------------|
| `MaxSlotAge` (engine_shadowlink.go:386, env `SHADOWLINK_MAX_SLOT_AGE`) | 120s | **75s** | база реза |
| `slotRotationStaggerStep` (ws_pool.go:473) | 15s | **6s** | разброс младших слотов |
| **`staggerOffsetCap` (НОВОЕ поле, env)** | — | **45s** | `min(idx×6s, 45s)+jitter` → idx≥8 кэпятся на 75+45=**120s** |
| **Итог: реальный рез ВСЕХ 16 слотов** | 120-225s | **75-120s** | весь под 130с с запасом 10с ✅ |
| `DrainHardCap` (engine_shadowlink.go:433) | 90s | **30s** | worst teardown 120+30=150с; стримы RESUME'ятся, не теряются |
| `migrationThresholdBase` (env `SHADOWLINK_MIGRATE_THRESHOLD`) | 60s | **45s** | запас миграции до age-cut idx=0 (иначе впритык 74.5 vs 75с) |
| `ageCutMinAgeMs` (ws_pool.go:1032) | 60s | **45s** | сошёлся с 75с-резом, окно классификации не схлопывается (HIGH-3) |
| keepalive | 5s | без изменений | бесполезен против age-based |

**Формула staggerOffset (HIGH-1) — менять ФОРМУЛУ, не только const:**
```go
func (p *WSPoolTransport) slotStaggerOffset(idx int) time.Duration {
    if idx <= 0 { return 0 }
    base := time.Duration(idx) * p.staggerStep      // env-tunable
    if base > p.staggerOffsetCap { base = p.staggerOffsetCap }  // НОВЫЙ cap
    jitter := time.Duration((rand.Float64() - 0.5) * float64(p.staggerStep))
    return base + jitter
}
```
`slotStaggerOffset` сейчас пакетная функция БЕЗ приёмника (ws_pool.go:517) — сделать методом `*WSPoolTransport`
ИЛИ передавать cap аргументом. Затрагивает вызов :2127 и тесты ws_pool_test.go:489/994/1063 (пинят
`idx*slotRotationStaggerStep` — переписать на capped-формулу, НЕ просто перепинить на 6s).

**Результат:** idx 0..7 распределены 75..117с, idx 8..15 садятся на потолок 120с. Ни один слот не доживает
до окна заморозки 130с. Долгий GET всегда мигрирует на слот моложе 120с.

### Env-флаги (HIGH-2 — staggerStep+cap ОБЯЗАТЕЛЬНО в env)
Боевые рычаги против DPI — мгновенный откат без пересборки: `SHADOWLINK_MAX_SLOT_AGE`,
`SHADOWLINK_DRAIN_HARD_CAP` (уже есть), + НОВЫЕ `SHADOWLINK_STAGGER_STEP`, `SHADOWLINK_STAGGER_OFFSET_CAP`,
`SHADOWLINK_AGE_CUT_MIN_AGE`. MaxSlotAge-env НЕ перекрывает stagger (offset аддитивен) — поэтому stagger
нужен отдельным env.

## Инварианты / нюансы

- **DrainHardCap=30s < MaxSlotAge=75s:** реальный рез всех слотов 75-123с (idx≥8 на потолке 75+45+jitter).
  Худший случай teardown: ≤123с + 30с дренажа ≤153с — НО дренаж не держит TCP «молодым», он лишь доживает
  существующие стримы; новые на дренируемый слот не садятся, а долгие мигрируют ДО реза (half-open A) либо
  RESUME'ятся при teardown (resumeStreamOnDeath). Финальное ревью: безопасно, пока migrate on (всегда в
  direct-режиме) — добавлен стартовый WARN-guard на случай migrate off (MEDIUM-1).
- **Чаще реконнекты:** рез каждые ~6с вместо 15с. Реконнект слота ~0.4-0.8с, дёшево. Rate-limit поднят
  (ws 90/120, hs 80/300) — закрыто Task 4; агрегат ~10 реконнектов/мин при 16 слотах ≪ refill 120/min.
- **migrationThreshold (31.5-45s) БЛИЗКО к MaxSlotAge (75s):** миграция idx=0 завершается к ~59.5с (тик 5с
  + AfterFunc offset ≤8с + ack 1.5с), запас ~15.5с до реза 75с. Для idx≥1 рез ≥81с — запас больше. Окно НЕ
  схлопнулось (подтверждено финальным ревью). migrationThresholdBase=45s через env, можно опустить до 35s при нужде.
- **MEDIUM-4 (downlink виснет в conn.Write):** в логе 2026-06-05 массово НЕ проявилась (почти все стримы
  имеют парный downlink done). НЕ трогаем в этом фиксе (YAGNI). Если после age-tuning всплывёт — отдельный
  фикс (gap-timeout на conn.Write).

## Объём / файлы

### Клиент (age-window tuning)
- `cmd/nixavpn-client/engine_shadowlink.go` — maxSlotAge 120s→75s (:386), drainHardCap default 90s→45s (:433).
- `client/ws_pool.go` — slotRotationStaggerStep 15s→6s (:473).
- Env-флаги (тюнинг в поле без пересборки, мгновенный откат): подтвердить что MaxSlotAge / staggerStep /
  DrainHardCap читаются из `SHADOWLINK_*`. MaxSlotAge и DrainHardCap — уже через env (engine:386,433).
  staggerStep — const, НЕ env: решить в плане (вынести в env ИЛИ оставить const, перекрывая через MaxSlotAge).

### Сервер rate-limit (ПОДНЯТЬ + в конфиг — НЕ хардкод)
**Факт (проверено в коде):** server rate-limit УЖЕ YAML-ready через `rate_limit.ws_upgrade.{burst,refill_per_min}`
(server/config.go:160-182 `RateLimitBucketSpec`/`RateLimitConfig`; server/handler.go:211-217 читает
`config.RateLimit.WSUpgrade`; server/ratelimiters.go:97-122 конструирует bucket). Хардкода в коде НЕТ —
только дефолты-фолбэки `WSUpgrade{Burst:18, RefillPerMin:30}`. ПРОБЛЕМА: генератор config.yaml в main tree
(`internal/deploy/steps_shadowlink.go::renderShadowLinkYAMLContent`) НЕ пишет блок `rate_limit:` → на pl1
применяются дефолты 18/30 → за полевое окно зафиксировано **4× HTTP 429** даже на текущей частоте реза ~15с.
С ускорением до ~6-10с rate-limit будет резать реконнекты массово.

**Честный расчёт частоты (опус-ревью BLOCKER-2):** агрегат ~10 реконнектов/мин (16 слотов / ~97.5с средний
период × 60) — refill=120/min даёт запас >2× по среднему. Но rate-limiter режет по BURST при каскаде:
полное перетряхивание 16 слотов = до 16 ws_upgrade токенов мгновенно + накладка каскадов.

**Финальные значения (после ревью):**
- **ws_upgrade: burst=90, refill_per_min=120** (burst 60 был впритык под двойной каскад при alive=16; 90 = запас 1.5×)
- **handshake: burst=80, refill_per_min=300** (КАЖДЫЙ reconnect жжёт И handshake-токен, ws_pool.go:2029 —
  спека раньше это упустила; ClientID-exemption гасит, но soft-limit 60/min может задеть на спайке)
- Числа валидны для **direct single-client-per-IP**. Для CF-режима (несколько клиентов за edge-IP) — отдельный пересчёт.

**Что сделать (architecturally correct, НЕ править YAML руками):**
1. `internal/deploy/steps_shadowlink.go` — добавить в `ShadowLinkYAMLParams` поля
   `WSUpgradeBurst/WSUpgradeRefillPerMin/HandshakeBurst/HandshakeRefillPerMin`, рендерить блок `rate_limit:`
   в `renderShadowLinkYAMLContent`. **ВАЖНО (MEDIUM-3): писать значения ВСЕГДА (non-zero дефолт 90/120/80/300
   в генераторе), НЕ полагаться на server-fallback 18/30** — иначе существующие деплои без явных значений
   останутся на 18/30 и поймают 429 при ускоренном резе.
2. Прокинуть значения от деплой-кода в `ShadowLinkYAMLParams` (как `OriginDeathTeardown`).
3. **СВЯЗКА ДЕПЛОЯ (MEDIUM-3, критично):** клиент-тюнинг НЕЛЬЗЯ катить без передеплоя config.yaml на pl1 с
   поднятым rate_limit. Иначе ускоренный рез → 429 → клиент не пересоздаёт слоты → капасити-дип. Деплоить ВМЕСТЕ.
- ClientID-exemption (server/clientid_exempt.go) обходит handshake-bucket на subsequent, но WS upgrade — отдельный bucket, exemption не покрывает.

**Только клиент** (age-tuning) **+ генератор конфига в main tree** (rate-limit). Бинарь сервера НЕ меняется.

## Тесты (TDD)
- **slotStaggerOffset с cap (HIGH-1/NIT-3):** idx 0..7 → 0..42s; idx 8..15 → кэп 45s; формула
  `min(idx×step, cap)+jitter`. Переписать ws_pool_test.go:489/994/1063 на capped-формулу (НЕ перепинить на 6s).
- rotationWatchdogSweep: idx=0 режется ~75s, idx=15 режется ~120s (НЕ 165s!). Весь разброс < 130с.
- migrationThreshold=45s срабатывает ДО age-cut idx=0 (75s) с запасом ≥15с (раньше было впритык 74.5 vs 75).
- DrainHardCap=30s: worst teardown idx=15 = 120+30=150с; стримы RESUME'ятся (resumeStreamOnDeath) — не теряются.
- ageCutMinAgeMs=45s: обрыв в 45-75с классифицируется корректно; регресс на классификацию обрыва 65-74с (HIGH-3).
- env: SHADOWLINK_STAGGER_STEP / _STAGGER_OFFSET_CAP / _AGE_CUT_MIN_AGE парсятся, zero→дефолт.
- Генератор (internal/deploy): renderShadowLinkYAMLContent пишет блок `rate_limit:` с ws_upgrade 90/120 +
  handshake 80/300 ВСЕГДА (non-zero). Снапшот-тест YAML.
- Регресс: half-open A+B не сломаны; Bug#6 sticky / Bug#8 flow / Bug#9 migration / Bug#10 — зелёные.
- race на Linux/pl1 (watchdog + migrate goroutines).

## Канарейка / валидация
- Метрики (вырастут ожидаемо): rotations_1m.
- Метрики (должны УПАСТЬ): reader error cause=age_cut на слотах >130с (теперь режем в 75-120с),
  last_write_age_ms при age-cut, серверные io_timeout reader exits (слоты не доживают до 60s read-timeout),
  HTTP 429 (после поднятия rate-limit).
- Метрики ПОД НАБЛЮДЕНИЕМ (MEDIUM-4 — учащённый рез давит на capacity): `readyCapacity` min,
  `CapacityFloorDeferredTotal`, `InflightCapDeferredTotal`, `DrainForceEvictedTotal`,
  **`DrainForceEvictedActiveTotal` (emergency-evict АКТИВНЫХ стримов — ЭТО симптом, должно быть ≈0;
  если растёт — рез слишком агрессивен, поднять MaxSlotAge или cap)**, `rate_limited_recent` (должен быть 0).
- **Полевой ретест: Claude Code auto-update через туннель** — главный приёмочный критерий.

## Деплой
- Пересборка клиента + race на Linux + полевой ретест (Claude update + долгая закачка >2мин) + канарейка.
- Сервер pl1 НЕ передеплоивается.
- Коммит — с пачкой (по плану юзера: Bug#10 + half-open A+B + 60s + emergency-evict + этот tuning).
- Откат: env `SHADOWLINK_*` вернуть к 120s/90s (staggerStep — через пересборку, если останется const).

## Доказательная база
- `docs/client-log-analysis-2026-06-05.md` — полный разбор клиент+сервер.
- Серверный лог pl1 (journalctl shadowlink, 2026-06-05 07:05-07:12 UTC): io_timeout=18, peer_eof=17,
  0 migrate_fail, бинарь /opt/shadowlink/shadowlink-server 04.06 07:59 UTC.
- Клиентский slot_age_ms при stall: заморозка 130-190с.

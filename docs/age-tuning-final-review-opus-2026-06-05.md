# Финальное целостное ревью ФИЧИ: TSPU age-window tuning (2026-06-05)

**Ревьюер:** opus (субагент), финальное ревью фичи как ЦЕЛОГО (не отдельных задач)
**Спека:** `docs/superpowers/specs/2026-06-05-tspu-age-window-tuning-design.md`
**Ревью спеки:** `docs/age-tuning-spec-review-opus-2026-06-05.md` (2 BLOCKER исправлены в плане)
**Дата:** 2026-06-05

---

## ВЕРДИКТ: APPROVED-WITH-NITS

Фича реализована согласованно и достигает заявленной цели. Все 2 BLOCKER и 3 HIGH из ревью спеки
закрыты в коде корректно. Build обоих модулей (shadowlink + main-tree internal/deploy) чист,
целевые тесты зелёные (client 50s, core, proxy/socks5, internal/deploy). Главный инвариант
(рез всех слотов idx 0..15 < 130с) подтверждён кодом И регресс-тестом, который ассертит его напрямую.

Находок уровня BLOCKER/HIGH нет. Несколько NIT — косметика/наблюдаемость, не блокируют деплой.

### Счётчики находок

| Severity | Кол-во |
|----------|--------|
| BLOCKER  | 0 |
| HIGH     | 0 |
| MEDIUM   | 1 |
| NIT      | 4 |

---

## 1. ГЛАВНЫЙ ИНВАРИАНТ — рез всех слотов idx 0..15 < 130с: **ДА ✅**

Формула (`client/ws_pool.go:526-542`):
```go
func (p *WSPoolTransport) slotStaggerOffset(idx int) time.Duration {
    if idx <= 0 { return 0 }
    step := p.staggerStep          // env SHADOWLINK_STAGGER_STEP=6s
    if step <= 0 { step = slotRotationStaggerStep }  // fallback 15s
    base := time.Duration(idx) * step
    if p.staggerOffsetCap > 0 && base > p.staggerOffsetCap { base = p.staggerOffsetCap } // cap 45s
    jitter := time.Duration((rand.Float64() - 0.5) * float64(step))   // ±step/2 = ±3s
    return base + jitter
}
```
Cap применяется к base ДО jitter (как требовала спека, NIT). effectiveMaxAge = `maxSlotAge + staggerOffsetNs`
(`ws_pool.go:1857`). При MaxSlotAge=75s, step=6s, cap=45s:

| idx | base | после cap | +jitter ±3s | effectiveMaxAge | <130s |
|-----|------|-----------|-------------|-----------------|-------|
| 0   | 0    | 0         | 0 (idx≤0 ранний возврат) | 75s | ✅ |
| 7   | 42s  | 42s       | 39..45s     | 114..120s | ✅ |
| 8   | 48s  | 45s (cap) | 42..48s     | 117..123s | ✅ |
| 15  | 90s  | 45s (cap) | 42..48s     | 117..123s | ✅ |

Worst-case (idx≥8, jitter=+3s): 75+48 = **123с < 130с**, запас 7с. Ни один слот не доживает до окна
заморозки. Дыра BLOCKER-1 из ревью спеки (idx=15 резался в 165с) закрыта. Подтверждено регресс-тестом
`TestSlotStaggerOffset_Capped` (ws_pool_test.go:1365), который ассертит `75s + g15 < 130s` напрямую.

---

## 2. ЦЕПОЧКА ТАЙМИНГОВ — согласована, инверсий нет ✅

- **migration**: base 45s (`migrate_watchdog.go:40`) × U(0.7,1.0) = 31.5–45s. Watchdog тик 5s
  (`ws_pool.go:1794`) → старт миграции на следующем тике (worst +5s → ~50s). AfterFunc offset U(0,8s)
  (`migrationSpreadDefault`, migrate_watchdog.go:48) → send ≤58s. migrateAckTimeout 1.5s
  (`ws_transport.go:632`) → MIGRATE_OK ≤ **~59.5s**.
- **age-cut floor**: ageCutMinAge 45s (классификация, не рез).
- **slot rotation idx=0**: 75s.
- **freeze**: ~130с.

Порядок: migration(≤59.5s) < age-cut-floor(45s — это floor классификации, корректно НИЖЕ реза) <
rotation idx=0(75s) < freeze(130s). Превентивная миграция idx=0 завершается с запасом **~15.5с** до
реза 75с (BLOCKER MEDIUM-1 из ревью спеки закрыт принятием 45s threshold). Для idx≥1 рез ≥81с — запас
ещё больше. migration high-end (45s) == ageCutMinAge (45s): не проблема — это разные оси (migration —
превентивный таймер по возрасту; ageCutMinAge — порог классификации УЖЕ случившегося terminal-error;
они не конкурируют за один и тот же момент). migration 45s vs MaxSlotAge 75s — 30с запас, миграция
успевает.

---

## 3. ИНТЕГРАЦИЯ Task1↔Task2 — без конфликта ✅

- `slotStaggerOffset` (Task1) и `isAgeCut` (Task2) оба — методы на `*WSPoolTransport` (ws_pool.go:526,
  1095). Конфликта приёмников нет.
- Поля `staggerStep`/`staggerOffsetCap`/`ageCutMinAge` объявлены ОДИН раз в struct (ws_pool.go:1151-1153),
  заполнены ОДИН раз в `NewWSPoolTransport` из cfg (ws_pool.go:1642-1644). `slotStaggerOffset` читает
  `p.staggerStep`/`p.staggerOffsetCap`; `isAgeCut` читает `p.ageCutMinAge`. Никакого пересечения записи.
- `staggerOffsetNs` сэмплится один раз per (re)connect через `p.slotStaggerOffset(idx)` (ws_pool.go:2175),
  idx — реальный индекс ячейки uniform-cells slice 0..2*poolSize-1. Это правильный idx (тот же, что в
  sweep).

---

## 4. РЕГРЕСС соседних фич — не сломаны ✅

- **half-open A+B (migrate re-arm / wakeUplink)**: миграция теперь стартует раньше (45s vs 60s base), но
  это лишь сдвигает превентивный путь раньше — re-arm/wakeUplink логика не зависит от абсолютного порога.
  Тесты `Migrat*` зелёные.
- **Bug#6 sticky**: drainHardCap 30s применяется ПОСЛЕ sticky-решений в drainWatchdog (sticky продлевает
  до StickyMaxDrainAge=10m по отдельной ветке). Hard-cap — нижняя граница для НЕ-sticky слотов. Sticky
  env-дефолты не тронуты (engine:467-472). Drain-тесты зелёные.
- **Bug#8 flow control / Bug#9 migration**: per-stream credit и migrateStream не зависят от age-порогов.
  Миграция при резе/смерти слота гоняет `resumeStreamOnDeath` — байты целы.
- **Bug#10 origin-death**: серверный сигнал, независим от клиентских age-порогов. В генераторе
  `OriginDeathTeardown: true` сохранён на обоих деплой-путях (steps_shadowlink.go:299,
  shadowlink_handlers.go:871).
- **drainHardCap 90→30s**: worst teardown = effectiveMaxAge(≤123s) + 30s = **≤153с**. Стримы в полёте
  НЕ теряются — `handleSlotDeath(deathCauseDrainTeardown)` при `migrateEnabled` гоняет
  `resumeStreamOnDeath` на живой слот (см. MEDIUM-2 ревью спеки — подтверждено `migrate=true` на каждом
  CONNECT в боевом логе). 30s достаточно для дренажа idle-keepalive хвоста (drainIdleThreshold=30s).
  Не рвёт раньше времени: дренаж стартует ТОЛЬКО при ротации (когда стрим уже мигрировал/мигрирует), не
  на молодом активном слоте.

---

## 5. RATE-LIMIT связка — ключи матчат, значения достаточны ✅

- Генератор (`internal/deploy/steps_shadowlink.go:106-112`) пишет:
  `rate_limit: → ws_upgrade: {burst, refill_per_min} + handshake: {burst, refill_per_min}`.
- Сервер (`shadowlink/server/config.go:154-170`) парсит ТЕ ЖЕ ключи: `rate_limit` (yaml:"rate_limit") →
  `ws_upgrade`/`handshake` (RateLimitConfig) → `burst`/`refill_per_min` (RateLimitBucketSpec). **Матч точный.**
- Значения: ws 90/120, hs 80/300. Per ревью спеки BLOCKER-2: агрегат ~10 reconnect/min при 16 слотах ≪
  refill 120/min (запас >2×); burst 90 покрывает двойной каскад полного перетряхивания 16 слотов (16≪90).
  handshake вынесен в генератор (спека раньше упускала). Достаточно для direct single-client-per-IP.
- **MEDIUM-3 закрыт корректно**: значения пишутся ВСЕГДА с non-zero дефолтом В ГЕНЕРАТОРЕ
  (`if wsB<=0 { wsB=90 }` и т.д., steps_shadowlink.go:92-105), НЕ полагаясь на server-fallback 18/30.
  Деплой-вызовы (steps_shadowlink.go:289, shadowlink_handlers.go:862) не передают поля явно → срабатывает
  генераторный дефолт 90/120/80/300. Это by-design.

---

## 6. СКВОЗНАЯ ТРАССИРОВКА env (SHADOWLINK_STAGGER_OFFSET_CAP) ✅

`os.Getenv` → `envDurationDefault("SHADOWLINK_STAGGER_OFFSET_CAP", 45s)` (engine_shadowlink.go:489) →
`staggerOffsetCap` локальная → `WSPoolConfig{StaggerOffsetCap: staggerOffsetCap}` (engine:507) →
`NewWSPoolTransport`: `staggerOffsetCap: cfg.StaggerOffsetCap` (ws_pool.go:1643) → читается в
`slotStaggerOffset`: `if p.staggerOffsetCap > 0 && base > p.staggerOffsetCap` (ws_pool.go:535). **Цепочка
непрерывна.** Аналогично трассированы SHADOWLINK_STAGGER_STEP (→staggerStep→ws_pool.go:530) и
SHADOWLINK_AGE_CUT_MIN_AGE (→ageCutMinAge→ws_pool.go:1100). Все три env реально читаются и используются
в формулах. zero→дефолт обработан (envDurationDefault + внутренние fallback'ы step≤0→15s, cap≤0→no-cap,
ageCutMinAge≤0→60s const).

---

## 7. КОМПИЛЯЦИЯ / ТЕСТЫ — подтверждено ✅

- `go build ./...` (shadowlink): EXIT 0.
- `go build ./internal/deploy/...` (main-tree): EXIT 0.
- `go test ./client/`: ok 50.6s.
- `go test ./core/ ./proxy/socks5/`: ok.
- `go test ./internal/deploy/ -run ShadowLink`: ok (вкл. `TestRenderShadowLinkYAML_RateLimitBlock`
  ассертит burst 90/refill 120/burst 80/refill 300).
- Целевые тесты `StaggerOffset|AgeCut|Close1006|RotationWatchdog|Migrat|Drain`: EXIT 0.

---

## MEDIUM

### MEDIUM-1 — drainHardCap worst-teardown зависит от `migrateEnabled`, в коде не форсируется инвариант
**Файл:** `client/ws_pool.go` handleSlotDeath path (`migrationOn := p.migrateEnabled.Load()`).
Защита от потери стримов при teardown дренируемого слота (effectiveMaxAge≤123s + 30s = ≤153с, в районе
freeze-края) держится на том, что `migrateEnabled=true` и `resumeStreamOnDeath` мигрирует стрим. В боевом
direct-режиме это всегда так (`migrate=true` на каждом CONNECT в логе pl1). НО код не имеет hard-инварианта
«если drainHardCap опущен ниже freeze-edge — migrate ОБЯЗАН быть on». Если в каком-то будущем code-path
flow/migrate не негошиэйтится (single-WS fallback, или флаг отключён), teardown в ~150с может попасть в
окно заморозки и порвать стрим по close(chan). **Рекомендация (не блокер):** добавить runtime-WARN при
старте, если `gracefulDrain && drainHardCap < (freezeFloor - maxSlotAge - cap)` И migrate выключен — или
явно задокументировать инвариант в engine_shadowlink.go. Сейчас это лишь комментарий «Streams still in
flight RESUME» (engine:437) без проверки. Достаточно для текущего деплоя (migrate всегда on), но хрупко.

---

## NIT

### NIT-1 — комментарий slotRotationStaggerStep всё ещё описывает 15s/2-min семантику
`ws_pool.go:461-465` docstring `slotRotationStaggerStep` говорит «2-min base and 15s grid step ... 8th
slot rotates ≈2m». При боевом step=6s/MaxSlotAge=75s это вводит в заблуждение. const остался 15s как
fallback (корректно), но шапка не отражает age-tuning. Косметика.

### NIT-2 — комментарий scheduleSlotMigration упоминает «~90s TSPU cut» (ws_pool.go:1846)
Старое число 90s в комментарии про окно заморозки; спека/код теперь оперируют ~130с. Рассинхрон
документации, поведение верное.

### NIT-3 — старые stagger-тесты (ws_pool_test.go:489/994/1063) пинят `slotRotationStaggerStep` (15s) напрямую
Это НЕ регресс — эти тесты (`*GraceExpiry*` / sweep) специально гоняют legacy 15s-ladder через прямой
`staggerOffsetNs.Store(int64(i)*int64(slotRotationStaggerStep))`, проверяя порядок sweep, а не боевую
capped-формулу. Боевая capped-формула покрыта отдельно `TestSlotStaggerOffset_Capped`. Дыры нет, но стоит
добавить комментарий, что 15s здесь — намеренный legacy-grid для проверки ordering, чтобы будущий читатель
не «починил» их под 6s.

### NIT-4 — спека NIT-1 (текст «реальный рез 75-117s») в спеке так и остался местами
В самой спеке таблица §«Корень в цифрах» и §Решение в части мест пишут 75-117s; корректное число с cap —
75-123s (idx≥8 садятся на 75+45±3). Документ, не код. Тест и реализация верны (123с).

---

## ИТОГ

Фича целостна и достигает цели: реальный рез ВСЕХ 16 uniform-cells укладывается в 75–123с (<130с с
запасом 7с), цепочка migration→age-cut→rotation→freeze без инверсий с запасом 15.5с на превентивной
миграции idx=0, rate-limit YAML-ключи генератора точно матчат серверный парсер с non-zero дефолтами,
env-флаги трассируются сквозь до формул, соседние фичи (half-open, Bug#6/8/9/10) не задеты. Build чист,
тесты зелёных. Остаётся юзеру (вне кода): race на Linux/pl1, полевой ретест (Claude update + закачка >2мин),
staged-деплой config.yaml ВМЕСТЕ с клиентом (MEDIUM-3 связка), канарейка с мониторингом
DrainForceEvictedActiveTotal (должен быть ≈0). MEDIUM-1 — хрупкость инварианта drainHardCap↔migrate,
закрыть документацией/WARN до того, как кто-то отключит миграцию.

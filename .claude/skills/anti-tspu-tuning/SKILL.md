---
name: anti-tspu-tuning
description: Use when working on slot rotation, graceful drain, connection age windows, sticky streams, flow control, cold start, rate limiting, or any SHADOWLINK_* env flag. Full ENV flag table and the TSPU age-cut model behind the timing constants.
---

# Anti-TSPU tuning — ротация, drain, тайминги

## Модель угрозы, из которой растут все константы

Долгие TCP-соединения к голому origin IP режутся **по возрасту соединения**.
Ось подтверждена замером; величина окна — нет.

⚠ **Окно ~130–190 с неверно.** Полевой замер 2026-08-07 (n=222, один AS):

| | значение |
|---|---|
| окно реза | **84–118 с** (p10 84.1 / p50 97.6 / p90 118.0) |
| ось | **возраст** — CV 0.26 против 8.73 по байтам |
| объём как триггер | не воспроизводится: умирают и слоты с 0 КБ |

Число валидно для одного AS: ТСПУ неоднородна по операторам (ACM IMC 2022),
поэтому «измерить и зашить» задачу не решает. Курс — адаптация per-AS
(`client/slotobs`).

### Бюджет считать ТОЛЬКО через `worstCaseTeardown()`

```
base + stagger + sweep + teardown_cap
```

До 2026-08-07 лог складывал `base + sticky` и **врал в 1.6 раза**: выпадал
`staggerOffsetCap` (до +48 с) и тик watchdog (+5 с). Следствие — 8 ячеек из 16
имели порог ротации 114 с при p10 смертей 84 с, то есть не доживали до
собственной ротации. Никогда не складывать слагаемые по месту.

⚠ **Выборка резов цензурирована** (не лечится): `slotobs.Record` зовётся только
на ошибке чтения, поэтому в неё попадают лишь слоты, до которых цензор добрался
раньше нашей ротации — правый хвост срезан нашей же политикой, p10 смещён вверх.

С 2026-08-12 плановые ротации пишутся в **отдельный ринг** (`RecordPlanned`,
`client/slotobs/planned.go`), что даёт знаменатель: `CutShare()` — долю «срезано
посредником», `Hazard(from,to)` — риск реза среди **доживших** до полосы.
Отдельный ринг, а не метка в общем: в поле плановых ~92x больше резов (740 против
8 за 2 часа), в общем буфере на 512 они вытеснили бы наблюдения о цензоре за
~20 минут. `Summarize`/`Infer` работают только по рингу резов.

⚠ **«Окно 84–118 с» — артефакт метода, а не интервал реза.** Разбор 2026-08-12:
восстановленные полные времена жизни TCP дали `n=744 p50=81.2 p90=86.2 max=104.5`
— то есть до 110 с почти ничего не доезжало, и посредник физически не мог там
показать рез. Hazard-кривая по тем же данным **монотонно растёт с 80 с**,
удваиваясь каждые ~5 с, ступеньки на 84 с нет ни в одном из двух прогонов. 84 с —
это где риск становится заметен при данном n, 118 с — где кончилась выборка.
Мерить порог по гистограмме смертей = мерить собственную политику ротации
(survivorship bias). Правильная величина — hazard, он на знаменателе доживших.

## ENV-флаги (активные)

| Flag | Default | Effect |
|---|---|---|
| `SHADOWLINK_TLS_PQ` | ON | `=0/false/no/off` → cold-path uTLS без MLKEM keyshare (hot-path всегда Chrome_133 по F2 lockstep) |
| `SHADOWLINK_FP_POOL` | — | `=0` → форс Chrome 100%, ignore весов/persist (откат FP-mimicry без передеплоя) |
| `SHADOWLINK_BYPASS_ENABLED` | on | `=0` → пропустить bypass dialer wrap |
| `SHADOWLINK_SPLIT_DNS` | follows-bypass | split-DNS forwarder (Yandex-vs-CF арбитраж); default следует за bypass |
| `SHADOWLINK_GRACEFUL_DRAIN` | ON | `=0` → legacy hard-rotation. GOAWAY-style drain: активные стримы переживают ротацию |
| `SHADOWLINK_DRAIN_HARD_CAP` | 90s (поле: 30s) | макс время слота в `slotDraining` до forced teardown |
| `SHADOWLINK_STAGGER_STEP` / `_STAGGER_OFFSET_CAP` / `_AGE_CUT_MIN_AGE` / `_MAX_SLOT_AGE` | tuned | age-window tuning. ⚠ `_STAGGER_OFFSET_CAP` **прибавляется к порогу ротации**, а не размазывает внутри него: cap=45s + step/2 даёт +48s к возрасту старших ячеек |
| `SHADOWLINK_STICKY_MAX_DRAIN_AGE` / `_MAX_TOTAL_BYTES` / `_MAX_SLOTS` | 15s / 256MiB / auto | sticky-stream backstop. ⚠ **Обязан быть СТРОГО больше `_DRAIN_HARD_CAP`** — иначе не работает вовсе (см. ниже). В поле 25s |
| `SHADOWLINK_FLOW_WINDOW` | 4 MiB | per-stream flow-control окно (negotiation = `min(client, server)`) |
| `SHADOWLINK_RL_TOKENBUCKET` / `_RL_CLIENTID_EXEMPT` | on (server) | rate-limit v2 / clientID exemption |
| `SHADOWLINK_PHASED_WARMUP` / `_SOCKS5_COALESCE` / `_ADMIN_OVERRIDE` | on | cold-start cascade митигации |
| `SHADOWLINK_DATAPATH_BODYPREFIX` | ON | `=0` → legacy Bearer header (только против pre-Phase-0 сервера) |
| `SHADOWLINK_DNS_STUB_IPS` | — | доп. RKN stub-IP к builtin (`89.221.226.6`); append, invalid→WARN |

## Graceful drain (GOAWAY-style)

Слот при ротации не рвётся, а уходит в `slotDraining`: активные стримы
доживают, новые уже идут в свежий слот. Hard cap ограничивает, сколько слот
может висеть в draining, чтобы drain не превратился в утечку слотов.

`SHADOWLINK_GRACEFUL_DRAIN=0` возвращает legacy hard-rotation — полезно как
бисекция при подозрении, что баг именно в drain.

## Sticky-stream backstop

Большая закачка не должна умирать от ротации. Три независимых предела (возраст
drain / суммарные байты / число слотов) — срабатывает первый достигнутый.
Ослабление любого увеличивает шанс попасть в age-cut окно.

### ⚠ Ловушка: sticky ≤ hard_cap выключает механизм молча

Дедлайн дренажа ставится на `drainHardCap`, и ветка `drainAge >= stickyMaxDrainAge`
проверяется **только по его срабатывании**. Поэтому при `sticky <= hard_cap`
первая же проверка уходит в teardown, а продление (`markSticky` +
`deadline.Reset`) недостижимо. **Равенство ломает так же, как «меньше»** — на это
наступали дважды (2026-07-31 и 2026-08-07).

Коварство в том, что лог при этом пишет `sticky_outcome=age_backstop`, то есть
механизм **выглядит работающим**. Как отличить по логу:

| Признак | Sticky мёртв | Sticky жив |
|---|---|---|
| `sticky_active` в health | всегда 0 | > 0 |
| `drain_duration` | ровно = hard_cap | 20s/25s/… |

⚠ **Признак по `drain_duration` имеет область применимости — за ней он врёт.**
Уточнено разбором 2026-08-12. Дедлайн ставится на `hard_cap`, продление идёт
шагами `stickyRecheckInterval` (5s), рез — при `drainAge >= sticky`. При
`hard_cap=15s / sticky=25s` последовательность 15 → 20 → 25 даёт `drain_duration`
**ровно 25s у живого механизма** — то же значение, что у мёртвого при
`sticky <= hard_cap`. В поле все 19 sticky-teardown имели ровно 25s, и по таблице
это читалось как смерть, хотя механизм работал.

Надёжен только `sticky_active > 0` в health. И он редок не от болезни:
sticky живёт 25s, health печатается раз в 30s, поэтому попадание в срез
маловероятно — 7 непустых строк из 235 это норма, а не слабый сигнал.

Замер 2026-08-07 (2ч49м, hard_cap=sticky=15s): `sticky_active=0` во всех
health-строках при 8 teardown с `sticky_outcome=age_backstop`; `drain_duration`
принимал ровно два значения — 15s и 0s. Механизм не исполнялся ни разу.

Сторожа: `TestStickyDrainBudget_HardCapNotBelowSticky` (проверяет `.bat`) и
`TestStickyDrainBudget_DefaultsSatisfyStickyReachability` (проверяет дефолты и
не скипается). Клиент печатает WARN `sticky drain backstop is UNREACHABLE`.

## Flow control v2

Per-stream окно, negotiation = `min(client, server)`. Спека —
`docs/protocols/flow-control-v2.md`. Код — `core/flowctl.go`.

## Где смотреть код

- `core/migrate.go`, `core/session.go` — миграция, слоты, ghost sweep
- `core/flowctl.go` — flow control
- `core/jitter.go` — lognormal jitter
- `client/connmanager.go` — слоты на клиенте, ротация
- `server/metrics.go` — метрики drain/rotation
- `docs/PHASES-CHANGELOG.md` — история тюнинга; читать при откате фичи

## Правило при изменении констант

Любая правка тайминга должна быть обоснована относительно НАБЛЮДАЕМОГО окна
(замер 2026-08-07: 84–118 с), а не относительно прежней константы 130–190 с, и
проверена тестами в `core/` (`session_*_test.go`, `migrate_*_test.go`). Тесты
на тайминги в этом проекте исторически флейковали под `-shuffle`/`-count` —
см. skill `testing-rules`.

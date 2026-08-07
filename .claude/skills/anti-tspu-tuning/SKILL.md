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

⚠ **Выборка цензурирована.** `slotobs.Record` вызывается только на ошибке чтения,
плановые ротации в неё не попадают. Долю «срезано посредником» из `by_close_kind`
вывести нельзя, а p10 смещён вверх.

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

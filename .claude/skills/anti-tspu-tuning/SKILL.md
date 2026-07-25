---
name: anti-tspu-tuning
description: Use when working on slot rotation, graceful drain, connection age windows, sticky streams, flow control, cold start, rate limiting, or any SHADOWLINK_* env flag. Full ENV flag table and the TSPU age-cut model behind the timing constants.
---

# Anti-TSPU tuning — ротация, drain, тайминги

## Модель угрозы, из которой растут все константы

TSPU режет долгие TCP-соединения к голому origin IP **по возрасту соединения** —
окно заморозки ~**130–190 с**. Отсюда: слоты ротируются до того, как соединение
доживёт до окна. Все тайминговые константы ниже — производные от этого числа,
менять их «на глаз» нельзя.

## ENV-флаги (активные)

| Flag | Default | Effect |
|---|---|---|
| `SHADOWLINK_TLS_PQ` | ON | `=0/false/no/off` → cold-path uTLS без MLKEM keyshare (hot-path всегда Chrome_133 по F2 lockstep) |
| `SHADOWLINK_FP_POOL` | — | `=0` → форс Chrome 100%, ignore весов/persist (откат FP-mimicry без передеплоя) |
| `SHADOWLINK_BYPASS_ENABLED` | on | `=0` → пропустить bypass dialer wrap |
| `SHADOWLINK_SPLIT_DNS` | follows-bypass | split-DNS forwarder (Yandex-vs-CF арбитраж); default следует за bypass |
| `SHADOWLINK_GRACEFUL_DRAIN` | ON | `=0` → legacy hard-rotation. GOAWAY-style drain: активные стримы переживают ротацию |
| `SHADOWLINK_DRAIN_HARD_CAP` | 90s (поле: 30s) | макс время слота в `slotDraining` до forced teardown |
| `SHADOWLINK_STAGGER_STEP` / `_STAGGER_OFFSET_CAP` / `_AGE_CUT_MIN_AGE` / `_MAX_SLOT_AGE` | tuned | TSPU age-window tuning (рез голого IP по возрасту ~130-190с) |
| `SHADOWLINK_STICKY_MAX_DRAIN_AGE` / `_MAX_TOTAL_BYTES` / `_MAX_SLOTS` | 10m / 256MiB / auto | sticky-stream adaptive backstop (большие файлы) |
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

Большая закачка не должна умирать от ротации. Backstop адаптивный, три
независимых предела (возраст drain / суммарные байты / число слотов) — срабатывает
первый достигнутый. Ослабление любого из трёх увеличивает шанс попасть в
age-cut окно.

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

Любая правка тайминга должна быть обоснована относительно окна 130–190 с и
проверена тестами в `core/` (`session_*_test.go`, `migrate_*_test.go`). Тесты
на тайминги в этом проекте исторически флейковали под `-shuffle`/`-count` —
см. skill `testing-rules`.

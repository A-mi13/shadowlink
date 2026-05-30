# ShadowLink Per-Stream Flow Control (Bug #8)

**Status:** Implemented, branch `new-version`. Server must be deployed first (see Rollout).

## Проблема

`RouteToStream` в `client.go` использовал non-blocking `select { case ch <- data: default: }` для раздачи входящих данных по per-stream каналам (cap 512). Быстрая закачка через CF (150 Мбит/с, stream = 110–490 MB) переполняла канал: `recordBufferOverflow` логировал drops=50, dropped\_bytes≈750 KB. Потеря байт в TCP-потоке → tun2socks закрывал appConn с fullClose=TRUE → "Ошибка сети" в Chrome. Паллиатив (увеличение cap) отвергнут: любой конечный буфер переполняется на достаточно быстром потоке.

## Решение

HTTP/2 / yamux-style per-stream credit. Сервер не отправляет больше `effectiveWindow` байт, не получив подтверждения от клиента. Дропов нет by design — сервер просто ждёт в per-stream goroutine. Reader-loop не блокируется, нет head-of-line blocking между стримами.

---

## Wire-формат

### FlagWindowUpdate = 0x0A

Новый флаг, добавленный в `core/chunk.go` рядом с `FlagStreamOpen = 0x09`.

```
Chunk.Flags = 0x0A
Chunk.Payload = [StreamID(2 BE)] [delta(4 BE)]   // 6 байт
```

- **StreamID** — идентификатор стрима, для которого возвращается кредит (2 байта big-endian).
- **delta** — число байт, потреблённых клиентом с момента последнего WINDOW\_UPDATE (HTTP/2-семантика: всегда положительный аддитивный инкремент, не абсолютное значение).
- Направление: **client → server**, по uplink того же WS-слота.
- Шифрование: стандартный `session.EncryptChunk` / `EncryptWith` — идентичен любому другому фрейму. Стеганография не затронута.

Конструктор: `core.NewWindowUpdateChunk(sessID, seq, streamID, delta)`.  
Парсер: `core.ParseWindowUpdate(payload)` — возвращает ошибку на payload < 6 байт (никогда не паникует).

### FLOWCTL capability marker

```
["FLOWCTL"(7 ASCII)] [window(4 BE)]   // 11 байт
```

- Ride inside зашифрованного `Chunk.Payload` — **не** в cleartext. DPI-наблюдатель видит только зашифрованный blob, неотличимый от keepalive.
- Клиент кладёт маркер в `Chunk.Payload` первого FlagKeepalive (первый фрейм после WS upgrade).
- Сервер кладёт маркер в `Chunk.Payload` FlagAck (ответ на первый keepalive).

API: `core.BuildFlowCtlMarker(window uint32) []byte` / `core.ParseFlowCtlMarker(payload []byte) (window uint32, ok bool)`.

---

## Переговоры (in-band, поверх v1-ключей)

Flow control — **опциональный слой поверх v1**. `DeriveSessionKeys` не трогается, нет новой crypto-версии, нет DPI-признака.

Переговоры привязаны к WS-соединению (слоту пула). Каждый слот — своя `core.Session` = свой handshake.

### Последовательность

```
Client                              Server
  │                                   │
  ├─ WS Upgrade ──────────────────→   │
  │                                   │
  ├─ FirstFrame: FlagKeepalive ───→   │  authenticateFirstFrame
  │   Payload = FLOWCTL(clientWindow) │  (внутри AES-GCM)
  │                                   │
  │                   ←─ FlagAck ─────┤  sync, до runWebSocketSession
  │   Payload = FLOWCTL(effectiveWin) │  (внутри AES-GCM)
  │                                   │
  ├─ UpgradeToWS читает ack ──────→   │  negotiationAckTimeout = 500 ms
  │   (синхронно, до slot reader)     │
  │                                   │
  ╔═ runWebSocketSession / slot  ══════╗
  ║  flow control активен            ║
```

**Клиент** (`ws_transport.go::UpgradeToWS`):
- Если `SHADOWLINK_FLOW_WINDOW > 0`: кладёт `FLOWCTL(clientWindow)` в payload keepalive (`buildFirstFramePayload`).
- После отправки первого фрейма синхронно читает ack с дедлайном `negotiationAckTimeout = 500ms`.
- Успех: парсит `ParseFlowCtlMarker` из `FlagAck.Payload` → `flowControlEnabled = true`, `flowWindow = effectiveWindow`.
- Fail (timeout / старый сервер / ошибка записи): `flowControlEnabled = false`; тикает `Stats.FlowNegotiationTimeout`. Слот работает в legacy-режиме (без flow control).

**Сервер** (`server/websocket.go::authenticateFirstFrame`):
- Если keepalive payload содержит валидный `FLOWCTL(cw)` маркер и `h.flowMaxWindow > 0`:  
  `effectiveWindow = min(clientWindow, serverMax)` (`negotiateFlowWindow`).
- Если `effectiveWindow > 0`: синхронно пишет FlagAck с `FLOWCTL(effectiveWindow)` **до** возврата из `authenticateFirstFrame`. `runWebSocketSession` получает ненулевой `flowWindow`.
- Fail-open: если запись ack упала — `effectiveWindow = 0`, flow off для этого слота (не паника).

---

## Credit-механика

### Defaults

| Параметр | Значение |
|---|---|
| Окно по умолчанию | 1 MiB (1 048 576 байт) |
| Клиентский clamp | 6 MiB (`maxFlowWindow = 6 << 20`) |
| Серверный max cap | 2 × effectiveWindow (`streamCredit.add`) |

### Клиент — downlink relay + credit sender

Downlink-goroutine: после `conn.Write` (запись в appConn / memConn):

```go
c.OnStreamConsumed(streamID, n)  // atomic Add pendingDelta, никогда не блокирует (I3)
```

Per-client credit sender (одна goroutine на клиента, `startCreditSender`):

- Тикер: **8 ms** (`creditSenderInterval`).
- Порог отправки: `pendingDelta >= jitter * window`, где jitter выбирается случайно в **[40%, 60%]** каждый тик.
- Watchdog: если `lastSentNs != 0` и с прошлой отправки прошло ≥ **200 ms** (`creditWatchdogNs`) → отправить независимо от порога.
- Отправка: CAS `pendingDelta → 0`. Если `sendWindowUpdate` вернул false (контрольный канал полон) — delta возвращается обратно через `pendingDelta.Add(d)`. Тикует `Stats.FlowWindowUpdateDropped`.
- `sendWindowUpdate` — non-blocking (`TryStreamWriteControl`). Сборка чанка через `core.NewWindowUpdateChunk` + `session.EncryptChunk`.

### Сервер — per-stream relay goroutine

При `flowEnabled` каждый новый стрим получает `newStreamCredit(int64(flowWindow))`.

Per-stream relay (выполняется в отдельной goroutine, НЕ в reader-loop):

```
waitForCredit(done)   // блокирует только эту goroutine пока credit <= 0
tc.Read(buf)          // читает из target TCP
enqueueData(...)      // отправляет клиенту
credit.consume(n)     // credit -= n
```

`FlagWindowUpdate` → `handleWindowUpdate` → `credit.add(delta, int64(flowWindow))` → кредит пополнен, `cond.Signal()`. Кламп: `min(available + delta, 2 * window)`.

Reader-loop никогда не блокируется на кредите — invariant I2 соблюдён.

Teardown: `streamCredit.close()` + `wake()` при закрытии сессии (done channel).

---

## Совместимость и rollout

| Сценарий | Поведение |
|---|---|
| Новый клиент + новый сервер | FLOWCTL negotiated, flow control активен |
| Старый клиент (пустой keepalive) + новый сервер | Сервер не видит маркер → `effectiveWindow = 0` → off. Работает |
| Новый клиент + старый сервер | Клиент шлёт маркер, ack не приходит за 500 ms → `flowControlEnabled = false`, `flow_negotiation_timeout_total++`. Работает |
| Клиент с `SHADOWLINK_FLOW_WINDOW=0` | Маркер не вкладывается, flow off |

**Порядок деплоя:** сначала обновить сервер pl1 (`-flow-max-window` по умолчанию 1 MiB), потом выкатывать клиентские бинари. Старые клиенты продолжают работать без flow control.

---

## Метрики

### Клиент (`client/stats.go`, Prometheus text `/metrics?format=prom`)

| Метрика | Тип | Значение |
|---|---|---|
| `shadowlink_flow_window_updates_sent_total` | counter | WINDOW\_UPDATE фреймов успешно поставлено в очередь |
| `shadowlink_flow_window_update_dropped_total` | counter | WINDOW\_UPDATE пропущен (контрольный канал полон), delta сохранена |
| `shadowlink_flow_negotiation_timeout_total` | counter | Слотов, где ack не получен за 500 ms (старый сервер / off) |

### Сервер (`server/metrics.go`, Prometheus `/metrics?format=prom` + JSON `/metrics`)

| Поле | Тип | Значение |
|---|---|---|
| `FlowWindowUpdatesRecv` | counter | WINDOW\_UPDATE фреймов получено от клиента |
| `UnknownFlag` | counter | Фреймы с неизвестным Flags байтом (defensive default) |
| `FlowSessionsActive` | gauge | WS-сессий с активным flow control прямо сейчас |
| `FlowStreamCreditWaitsTotal` | counter | Сколько раз per-stream relay заблокировался в `waitForCredit` (available≤0 дольше 1 мс) |
| `FlowStreamCreditWaitMsTotal` | counter | Суммарное время простоя в `waitForCredit`, мс; высокое значение = окно 1 MiB мало, throughput душится credit'ом |

> `FlowStreamCreditWaitsTotal` / `FlowStreamCreditWaitMsTotal` замеряются в `server/websocket.go` вокруг `cr.waitForCredit(done)` — порог >1 мс фильтрует мгновенные возвраты когда credit был. Prom-имена: `shadowlink_flow_stream_credit_waits_total`, `shadowlink_flow_stream_credit_wait_ms_total`. Добавлены 2026-05-30 (Bug #8 MEDIUM-2) — канарейка «достаточно ли окно 1 MiB?».

> Все метрики экспортируются через Prometheus (`writePromMetrics`) и JSON snapshot (`Snapshot()`) — добавлены 2026-05-30 для канарейки Bug #8.

---

## Env / флаги

| Env / Flag | Сторона | Значение |
|---|---|---|
| `SHADOWLINK_FLOW_WINDOW` | клиент | Желаемое окно в байтах. Пусто/unset → 1 MiB. `0` → off. Другое значение → парсится, кламп до 6 MiB. Невалидное → 1 MiB |
| `-flow-max-window` | сервер | Максимальное окно, которое сервер готов выдать. Default 1 MiB (задаётся через `Config.FlowMaxWindow`). `0` → off (сервер не предлагает flow control) |

---

## Ссылки

- Дизайн (3 опус-ревью): `docs/superpowers/specs/2026-05-30-bug8-flow-control-design.md`
- План (Tasks 1–18): `docs/superpowers/plans/2026-05-30-bug8-flow-control.md`
- Wire-код: `core/chunk.go` (`FlagWindowUpdate`, `NewWindowUpdateChunk`, `ParseWindowUpdate`), `core/flowctl.go` (FLOWCTL marker), `client/stream_flow.go` (credit sender, `OnStreamConsumed`), `server/stream_credit.go` (`streamCredit`), `server/websocket.go` (`authenticateFirstFrame`, `runWebSocketSession`)

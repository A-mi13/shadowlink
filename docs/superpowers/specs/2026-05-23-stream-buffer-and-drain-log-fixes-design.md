# ShadowLink Client — Stream Buffer Overflow Aggregation + Drain Spam Reduction

**Дата:** 2026-05-23
**Автор:** Claude (через брейншторм с юзером)
**Статус:** Approved — proceeding to implementation plan
**Триггер:** [canary-2026-05-23-healthy](../../../../C:\Users\Lenovo\.claude\projects\D--NIXAVPN\memory\canary-2026-05-23-healthy.md) — два non-blocking findings

## Контекст

Канарейка 2026-05-23 (graceful drain, 2h46m) показала:

1. **P0 — Stream buffer monitor fix 2026-05-22 не воспроизводится.** В `proxy/socks5/tcp.go:674-707` добавили drain loop с агрегированным INFO `"downlink post-error drain"`, но фикс активируется ТОЛЬКО на code path `HandleTCPConnectWS` при ошибке `conn.Write()` к SOCKS. В канарейке 2026-05-23 наблюдалось 115 отдельных WARN `"stream buffer full, data dropped"` все в одном `stream=312` за ~50ms — на другом code path (вероятно ServerClose или per-stream WS), где drain logic не активируется.

2. **P1 — 7811 INFO `"WS pool slot drain deferred (inflight cap)"`** = 50% всех INFO-строк за 2ч46м. Это корректный storm-brake backpressure, не баг, но забивает лог и мешает диагностике. Counter `Stats.DrainStormBrakeEngagedTotal` уже инкрементируется атомарно, но не surface'ится в health snapshot.

## Принципы

- Архитектурно топово, не локальные патчи в N местах ([[feedback_architecturally_correct]])
- TDD: failing tests first
- Изоляция в `shadowlink/` ([[feedback_shadowlink_isolation]])
- Никакого backwards-compat hack ([[feedback_proper_way]])

## P0: Centralized Stream Buffer Overflow Aggregation

### Проблема

`client.RouteToStream` (`shadowlink/client/client.go:917`) при non-blocking send на полный канал (`select ch <- data: default`) пишет WARN per-event. Вызывается из 3+ code paths параллельно: WS pool reader downlinkLoop, Split transport download reader, WS ready pool reader. Когда stream consumer уходит (SOCKS RST, ServerClose, optimistic CONNECT race), эти readers продолжают писать → 100+ WARN за секунды.

Фикс 2026-05-22 в `proxy/socks5/tcp.go:674-707` патчит только один путь — `HandleTCPConnectWS` после `conn.Write()` error. Остальные code paths остаются дырявыми.

### Решение

Перенести агрегацию **в Client** (где живёт `streamChans` map). Единственная точка детекции overflow, покрывает ВСЕ caller'ов `RouteToStream` автоматически.

#### Новая структура (в `client/client.go`):

```go
type streamOverflowState struct {
    firstAt     time.Time
    lastAt      time.Time
    drops       uint32
    droppedBytes uint64
    sources     map[string]uint32 // optional: caller hint → count
}

// Внутри Client:
type Client struct {
    // ...existing fields...
    streamOverflow   map[uint16]*streamOverflowState
    streamOverflowMu sync.Mutex
}
```

#### Изменения в `RouteToStream` (`client/client.go:909-920`):

Сейчас:
```go
func (c *Client) RouteToStream(streamID uint16, data []byte) {
    c.streamMu.Lock()
    ch, ok := c.streamChans[streamID]
    c.streamMu.Unlock()
    if !ok {
        return
    }
    select {
    case ch <- data:
    default:
        c.log.Warn("stream buffer full, data dropped",
            "stream", streamID, "buffer_len", len(ch), "data_size", len(data))
    }
}
```

Становится:
```go
func (c *Client) RouteToStream(streamID uint16, data []byte) {
    c.streamMu.Lock()
    ch, ok := c.streamChans[streamID]
    c.streamMu.Unlock()
    if !ok {
        return
    }
    select {
    case ch <- data:
    default:
        c.recordBufferOverflow(streamID, uint64(len(data)))
    }
}

func (c *Client) recordBufferOverflow(streamID uint16, size uint64) {
    c.streamOverflowMu.Lock()
    defer c.streamOverflowMu.Unlock()
    st, exists := c.streamOverflow[streamID]
    now := time.Now()
    if !exists {
        st = &streamOverflowState{firstAt: now}
        c.streamOverflow[streamID] = st
        // log ONCE at start
        c.log.Warn("stream buffer overflow started",
            "stream", streamID, "data_size", size)
    }
    st.lastAt = now
    st.drops++
    st.droppedBytes += size
}
```

#### Изменения в `UnregisterStream`:

При закрытии stream — flush overflow state. Если drops > 0, эмиттим финальный INFO с агрегатом:

```go
func (c *Client) UnregisterStream(streamID uint16) {
    // ...existing channel-close logic...

    c.streamOverflowMu.Lock()
    st, hasOverflow := c.streamOverflow[streamID]
    if hasOverflow {
        delete(c.streamOverflow, streamID)
    }
    c.streamOverflowMu.Unlock()

    if hasOverflow {
        c.log.Info("stream buffer overflow ended",
            "stream", streamID,
            "drops", st.drops,
            "dropped_bytes", st.droppedBytes,
            "duration", st.lastAt.Sub(st.firstAt),
        )
        // Increment cumulative stats counter
        c.Stats.StreamBufferOverflowsTotal.Add(uint64(st.drops))
    }
}
```

#### Counter в stats:

Добавить в `shadowlink/client/stats.go`:
```go
StreamBufferOverflowsTotal atomic.Uint64
```

#### Удаление дублирующей логики:

В `proxy/socks5/tcp.go:674-707` drain loop оставляем (он нужен чтобы НЕ писать в закрытый SOCKS socket, и **должен** читать `incomingCh` до конца чтобы освободить пишущих producers), но удаляем его INFO log `"downlink post-error drain"` (or downgrade до DEBUG) — централизованная агрегация в Client делает это сама. ВАЖНО: drain-loop в tcp.go нельзя удалить полностью — без него incomingCh заполнится и producers (RouteToStream) будут drop'ать ещё больше. Drain читает и выбрасывает данные, освобождая buffer для дальнейшей RouteToStream работы. Лог становится излишним.

### Тесты (TDD)

**Файл:** `shadowlink/client/stream_overflow_test.go` (новый)

**Failing tests сначала:**

1. `TestStreamBufferOverflow_SingleStreamMultipleDrops`:
   - Создать Client, register stream, не читать из канала
   - Вызвать RouteToStream 200 раз с маленькими payload'ами
   - Captures logs через test logger
   - Assert: exactly 1 WARN `"stream buffer overflow started"`, 0 других overflow-related WARN до Unregister
   - UnregisterStream → exactly 1 INFO `"stream buffer overflow ended"` с `drops` корректным count

2. `TestStreamBufferOverflow_NoOverflowNoLog`:
   - Register stream, RouteToStream 5 раз с consumer'ом который читает
   - UnregisterStream
   - Assert: 0 WARN, 0 INFO `"stream buffer overflow"`

3. `TestStreamBufferOverflow_ConcurrentProducersSingleStart`:
   - Register stream, не читать
   - 5 goroutines параллельно вызывают RouteToStream по 100 раз
   - Assert: exactly 1 WARN `"started"` (race-safe через mutex)
   - UnregisterStream → 1 INFO `"ended"` с drops = 500 (total, минус первый успешный send в free buffer slot, точное число зависит от buffer size 512 — учесть в expectation)

4. `TestStreamBufferOverflow_CumulativeStatCounter`:
   - Сделать overflow 30 drops в stream 100
   - UnregisterStream
   - Сделать overflow 50 drops в stream 200
   - UnregisterStream
   - Assert: `Client.Stats.StreamBufferOverflowsTotal.Load() == 80`

5. `TestStreamBufferOverflow_UnregisterClearsState`:
   - Register stream 100, overflow 10 drops, UnregisterStream
   - Register stream 100 again, overflow 0 drops, UnregisterStream
   - Assert: НЕ должен быть emitted второй INFO `"ended"` для второй регистрации (state cleared при first Unregister)

## P1: Storm-Brake Counter в Health Snapshot

### Проблема

Per-event INFO в `client/ws_pool_drain.go:265` и `:286` срабатывает ~1.6 раз/сек на 8-slot pool под нагрузкой → 7811 строк за 2ч46м = 50% всех INFO.

### Решение

1. Понизить per-event log с INFO до DEBUG (2 строки).
2. Surface counter `Stats.DrainStormBrakeEngagedTotal` в health snapshot.
3. Добавить rolling 1m counter аналогично существующему `rotations_1m`.

#### Изменения в `client/ws_pool_drain.go`:

Lines 265-271 и 286 — `p.log.Info(...)` → `p.log.Debug(...)`. Counter увеличивается КАК и сейчас (без изменений в логике).

#### Изменения в `client/ws_pool.go`:

В struct `WSPoolTransport` добавить:
```go
drainDeferrals1m *rollingCounter // analogous to rotations1m
```

Где увеличивается storm brake counter, добавить вызов `p.drainDeferrals1m.Add(1)`.

В `emitHealthSummary` (line 1249-1279) добавить два поля:
```go
p.log.Info("WS pool health",
    // ...existing fields...
    "deferred_drains_total", p.cl.Stats.DrainStormBrakeEngagedTotal.Load(),
    "deferred_drains_1m", p.drainDeferrals1m.Sum(),
)
```

### Тесты (TDD)

**Файл:** `shadowlink/client/ws_pool_drain_logging_test.go` (новый)

1. `TestDrainDeferred_LogLevelDebug`:
   - Trigger storm brake via mock (inflight >= max)
   - Assert: NO INFO log с `"drain deferred"`
   - Assert: DEBUG log есть (через test logger с level=debug)

2. `TestDrainDeferred_CounterIncrement`:
   - Trigger storm brake 5 раз
   - Assert: `Stats.DrainStormBrakeEngagedTotal == 5`

3. `TestHealthSnapshot_SurfacesDeferredCounters`:
   - Setup pool, trigger 3 deferrals
   - Call `emitHealthSummary`
   - Capture log
   - Assert: log INFO `"WS pool health"` содержит `deferred_drains_total=3` и `deferred_drains_1m=3`

4. `TestDrainDeferrals1m_Decays`:
   - 5 deferrals at t=0
   - Advance fake clock 70s
   - Assert: `drainDeferrals1m.Sum() == 0`
   - `Stats.DrainStormBrakeEngagedTotal` остаётся 5

## Data flow

### P0 flow

```
WS pool reader (downlinkLoop)  ─┐
Split transport download reader ├─→ Client.RouteToStream(streamID, data)
WS ready pool reader            ─┘            │
                                              ▼
                                   streamChans[streamID]
                                      ▲
                                      │ select case ch <- data: default
                                      │              │
                                      │              ▼
                                      │   recordBufferOverflow(streamID, size)
                                      │              │
                                      │              ▼
                                      │   streamOverflow[streamID].drops++
                                      │              │
                                      │              ▼ (на first drop)
                                      │   WARN "stream buffer overflow started" (один раз)
                                      │
SOCKS5 downlink relay reads ─────────┘
   │
   ▼
conn.Write fails → ctx2.Done() race → UnregisterStream
                                              │
                                              ▼
                                   delete streamOverflow[streamID]
                                              │
                                              ▼
                                   INFO "stream buffer overflow ended" drops=N bytes=M duration=T
                                              │
                                              ▼
                                   Stats.StreamBufferOverflowsTotal += N
```

### P1 flow

```
maybeRotateSlot (per-slot, 5s tick)
   │
   ▼
startDrain → inflight check → cap exceeded
   │
   ├─→ Stats.DrainStormBrakeEngagedTotal++  (как сейчас)
   ├─→ drainDeferrals1m.Add(1)              (НОВОЕ)
   └─→ log.Debug "drain deferred (inflight cap)"  (БЫЛО Info)

emitHealthSummary (5s)
   │
   ▼
INFO "WS pool health" alive=N dead=N ... deferred_drains_total=X deferred_drains_1m=Y
```

## Error handling / edge cases

### P0

- **stream UnregisterStream вызван без overflow** → no log, no state delete needed (map check)
- **stream получает overflow, никогда не Unregistered** (leak): добавить periodic flush every 60s в client run loop? **НЕТ** — это over-engineering. Если stream не unregister'ится — это другой баг (leak в streamChans), который надо чинить отдельно. В нашем фиксе assume что UnregisterStream вызывается всегда.
- **Race UnregisterStream vs RouteToStream**: после UnregisterStream может прилететь RouteToStream от lagging reader. `streamChans[streamID]` уже delete'ну → early return ДО recordBufferOverflow. Safe.
- **streamOverflowMu lock** — short critical section, no I/O в lock'е. Не bottleneck.
- **streamOverflow map**: не утечёт, потому что delete при UnregisterStream. Bounded by max active streams (4096).

### P1

- **rolling counter alignment** — использовать тот же утиль что и `rotations1m` (если он rollingCounter type) или time.Ticker-based decay. Не создавать новую абстракцию.
- **Debug-level в production** — оператор может включить через `-log debug` если нужна детальная диагностика. Counter в health snapshot покрывает 95% случаев.

## Acceptance criteria

1. **P0:**
   - Новая канарейка с эквивалентной нагрузкой (>=2h, >=1500 SOCKS connects, >=300 unique dests) показывает:
     - 0 raw WARN `"stream buffer full, data dropped"` (старое сообщение удалено)
     - Если есть проблемные streams — не более 1 WARN `"stream buffer overflow started"` и 1 INFO `"stream buffer overflow ended"` per stream
   - В тестах: все 5 TDD-кейсов PASS
   - `Stats.StreamBufferOverflowsTotal` surface'ится в metrics-dump

2. **P1:**
   - Новая канарейка показывает:
     - 0 INFO `"WS pool slot drain deferred"` (downgrade'нуто в DEBUG)
     - `WS pool health` snapshot содержит поля `deferred_drains_total` и `deferred_drains_1m`
     - `deferred_drains_total` монотонно растёт под нагрузкой, `deferred_drains_1m` пульсирует и спадает в idle
   - В тестах: все 4 TDD-кейса PASS

3. **Regression:** все существующие тесты в `shadowlink/...` продолжают PASS. `gofmt -w .` clean.

## Out of scope (deferred)

- Natural ratio optimization (P2 из canary report) — A/B hard_cap 90s→120s или max_concurrent 2→3. Это perf-tuning, отдельная итерация.
- Windows ephemeral port retry — P3. Отдельная задача.
- Metrics dashboard для новых counter'ов — пока metrics-dump bin покрывает.

## Файлы которые меняются

| Файл | Изменение |
|---|---|
| `shadowlink/client/client.go` | + `streamOverflowState`, `recordBufferOverflow`, изменения в `RouteToStream` и `UnregisterStream` |
| `shadowlink/client/stats.go` | + `StreamBufferOverflowsTotal atomic.Uint64` |
| `shadowlink/proxy/socks5/tcp.go` | Удалить INFO `"downlink post-error drain"` (lines 700-707), drain loop остаётся |
| `shadowlink/client/ws_pool_drain.go` | INFO → DEBUG (lines 265-271, 286), + `drainDeferrals1m.Add(1)` |
| `shadowlink/client/ws_pool.go` | + `drainDeferrals1m` поле в struct, + 2 поля в `emitHealthSummary` |
| `shadowlink/client/stream_overflow_test.go` | NEW — 5 TDD tests |
| `shadowlink/client/ws_pool_drain_logging_test.go` | NEW — 4 TDD tests |

## Бинарник

После acceptance:
1. `cd shadowlink && go build -o ../bin/nixavpn-client-graceful-drain.exe ./cmd/client` (через GOOS=windows если кросс-компилировать)
2. mtime обновится → юзер сможет запустить `connect-vpn-graceful-drain.bat` с новым бинарником
3. Новая канарейка с теми же env flags

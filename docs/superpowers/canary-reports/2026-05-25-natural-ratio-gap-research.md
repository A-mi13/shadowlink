# Natural finish ratio gap — research

**Дата:** 2026-05-25
**Канарейка:** 4h32m, лог `C:\Users\Lenovo\AppData\Local\Temp\nixavpn-graceful-drain-20260525-095219.log` (2.3 MB)
**Текущий результат:** natural ratio 62.6% (561 / 896 drain). Цель 75-80%.
**Контекст:** idle-finish heuristic (`SHADOWLINK_DRAIN_IDLE_THRESHOLD=30s`, `STREAMS_MAX=2`) включена с 2026-05-22; без неё ratio был бы только 10.5%.

---

## 1. Ключевой код

### Где живёт idle-finish heuristic

`shadowlink/client/ws_pool_drain.go:611-643` (внутри `drainWatchdog`):

```go
idleThreshold := p.drainIdleThreshold       // 30s
idleStreamsMax := p.drainIdleStreamsMax     // 2
idleEnabled := idleThreshold > 0 && idleStreamsMax > 0

for {
    select {
    case <-p.ctx.Done():
        return
    case <-deadline.C:                       // 90s hard cap
        tearDown(finishHardCap)
        return
    case <-ticker.C:                         // 500ms tick
        streams := oldSlot.streams.Load()
        if streams == 0 {
            tearDown(finishStreamsZero)
            return
        }
        if idleEnabled && streams <= idleStreamsMax {
            last := oldSlot.lastActivityNs.Load()
            if last > 0 && time.Since(time.Unix(0, last)) >= idleThreshold {
                tearDown(finishIdle)
                return
            }
        }
    }
}
```

### Где обновляется `lastActivityNs` (3 точки)

1. **`ws_pool.go:1502` (connectSlot)** — prime при reconnect: `slot.lastActivityNs.Store(now)`.
2. **`ws_pool.go:2120` (WriteMessageForStream)** — на каждом успешном write data-фрейме на slot.
3. **`ws_pool.go:2144` (WriteControlMessageForStream)** — на каждом control-фрейме (CONNECT, FIN).
4. **`ws_pool.go:2439` (slotReaderWithClient)** — на каждом успешном DecryptChunkSafe (downlink).

Это **per-slot**, а не per-stream. **Любая активность на любом stream'е, аттаченном к slot'у, сбрасывает таймер для всех остальных**.

### Hard cap

`shadowlink/client/ws_pool.go:1038-1044` + env `SHADOWLINK_DRAIN_HARD_CAP=90s` (по умолчанию). Полностью неусловный timer — короткое замыкание невозможно.

### Как считается `remaining_streams`

`oldSlot.streams.Load()` — int32, инкрементируется в `AssignStream`, декрементируется в `UnregisterStream` / `streamMap.Delete`. Считаются ВСЕ streams аттаченные к этому slot'у, в т.ч.:
- WS-keepalive control стримы (если они привязаны к slot)
- Stale streams чьи SOCKS-фронтенды уже умерли, но `UnregisterStream` ещё не пришёл

### Слотовая модель idle

Логика **per-slot, не per-stream**. Один долгоживущий stream (Google Docs heartbeat каждые 20s) **постоянно** сбрасывает таймер ВСЕХ остальных streams на slot'е. Slot не идёт в idle, даже если 1 из 2 streams тих как могила.

---

## 2. Данные из лога 2026-05-25

### Распределение drain'ов

| Категория | Count | % |
|---|---|---|
| **Total drain started** | 896 | 100% |
| natural finish (streams=0) | 94 | 10.5% |
| natural finish (idle) | 467 | 52.1% |
| hard cap | 332 | 37.1% |
| force-evicted | 11 | — |
| emergency-evicted | 14 | — |
| no free cell | 14 | — |

### Drain reason

| reason | count |
|---|---|
| age | 841 (93.9%) |
| anti_fingerprint | 43 (4.8%) |
| byte_budget | 12 (1.3%) |

### active_streams at drain start

| active | count | cumulative |
|---|---|---|
| 0 | 37 | 37 |
| 1 | 207 | 244 (27%) |
| 2 | 533 | 777 (87%) |
| 3 | 62 | 839 |
| 4 | 26 | 865 |
| 5+ | 31 | 896 |

**87% drain'ов стартуют с ≤2 active streams — то есть с самого начала попадают в idle-heuristic диапазон.**

### Распределение idle_for среди 467 natural-finish-idle

| idle_for | count | % |
|---|---|---|
| <=30s | 217 | 46.5% |
| 31-60s | 91 | 19.5% |
| 61-120s | 83 | 17.8% |
| >120s | 76 | 16.3% |

**54% (250/467) drain'ов успешно завершились с idle_for > 30s — то есть slot был фактически "мёртвый" задолго до drain.** В 256 случаях (55% от idle finish) `drain_duration=0s` — heuristic сработал на первом 500ms тике. Это означает что slot копил idle ДО старта drain.

### Распределение hard cap (332)

| remaining_streams | count | % | log level |
|---|---|---|---|
| 1 | 93 | 28.0% | INFO |
| 2 | 185 | 55.7% | INFO |
| 3 | 33 | 9.9% | INFO |
| 4 | 11 | 3.3% | INFO |
| ≥5 | 10 | 3.0% | WARN |

**278 hard caps (84%) имели remaining_streams ≤ 2 — точно в diapason'е idle-heuristic — но heuristic ни разу не сработал в течение 90s.**

Все hard cap drain_duration = ровно 1m30s (= max). Никаких ранних teardown'ов через другие пути.

### Warm-up cluster (первые 5 минут)

7 hard caps с remaining_streams 6-10 в окне 09:55:52-09:58:07. Это slot'ы со стартом 09:53:52 (start = 09:55:52 - 90s − 4-7s startup) — когда pool только что прогрелся до alive=8 и сразу начал ротацию первой генерации. Эти hard caps **не покрываются** idle-heuristic (streams > 2). Это нормальная цена warm-up'а.

### Долгоживущие stream destinations

Top destinations со временем жизни >1m: 142.251.1.94:443 (Google), 74.125.* (Google), 172.64.146.215 (Cloudflare), 173.194.* (Google), Microsoft endpoints. Это classic HTTPS keepalive flows к CDN — НЕ один долгий download, а push-server WebSocket'ы (Gmail/Docs/YouTube real-time) которые шлют heartbeat'ы каждые 15-30s.

### Reader errors

29 reader_exits, ВСЕ `anomaly=io_timeout`. Это server-side WS read timeout — соответствует graceful drain teardown.

---

## 3. Гипотезы

### Hypothesis 1 (HIGH confidence)

**Per-slot idle measurement детектит slot-уровень тишину, а не per-stream тишину. Долгоживущий "heartbeat stream" блокирует idle-классификацию ВСЕГО slot'а.**

**Evidence:**
- `ws_pool_drain.go:632`: `last := oldSlot.lastActivityNs.Load()` — читает ОДНУ метку на slot.
- `ws_pool.go:2120, 2144, 2439`: write/decrypt path пишут в `slot.lastActivityNs`, не в per-stream timestamp.
- В логе: 278 hard cap'ов с ≤2 streams. При нынешнем pool size 8 и ~30+ active streams в peak, slot регулярно держит 2 stream'а одновременно, где один — короткий burst, второй — long heartbeat. Heartbeat обновляет lastActivityNs каждые ~20s → idle threshold 30s никогда не достижим.
- top destinations long-tail (Google Docs/Gmail, CF WebSocket) — это именно SSE/WS keepalive с 15-30s heartbeats. Они **активны** по trickle, но trickle стабильно меньше любого реального user traffic.

**Counter-evidence:**
- 467 idle-finish случаев показывают что heuristic ВСЁ ЖЕ срабатывает на 54% drain'ов. То есть гипотеза "heartbeat блокирует всё" не абсолютна — она объясняет **278 hard caps**, а не все 332.
- Часть hard cap'ов могут быть с двумя heartbeat-streams (один Google, второй MS), где каждый по очереди сбрасывает таймер → суммарная активность на slot'е "плотнее" 30s, хотя каждый stream поодиночке тих > 30s.

**Confidence:** HIGH. Это самая прямая интерпретация observed data.

---

### Hypothesis 2 (MEDIUM confidence)

**Активность кодируется как WriteMessageForStream/WriteControlMessageForStream — но `lastActivityNs` обновляется ДО фактической отправки**, и любой trickle SOCKS heartbeat (например, TCP keepalive ack), уплывая через `WriteMessageForStream`, обнуляет таймер.

**Evidence:**
- `ws_pool.go:2120`: `slot.lastActivityNs.Store(time.Now().UnixNano())` стоит **перед** `return slot.transport.WriteMessage(data)`. То есть метка обновляется на каждом проходе, даже если payload — пустой keepalive или application-level ping.
- Для HTTPS long-lived соединений (Gmail XHR long-poll, Docs WS) клиент сам отправляет 15-25s keepalive пинги через SOCKS → они идут через WriteMessageForStream → reset.
- 7 hard caps первого warm-up cluster'а — каждые 10-30s друг от друга. Это первый цикл age-rotation: все 8 slot'ов hard-cap'нулись подряд **именно потому что reset происходит постоянно** на ОЧЕНЬ активном warm-up traffic'е.

**Counter-evidence:**
- Это не сильно отличается от Hypothesis 1 — пишут оба пути. Hypothesis 2 — это уточнение, что даже uplink trickle (а не только downlink Decrypt) сбрасывает таймер.
- Невозможно проверить без trace stream-level activity. В логе видно только slot-level lastActivityNs.

**Confidence:** MEDIUM. Подтверждается косвенно (warm-up cluster), но напрямую не доказано.

---

### Hypothesis 3 (LOW-MEDIUM confidence)

**Age-rotation interval (maxSlotAge=2min) + hard_cap=90s = слот должен прокачать idle-window 30s в течение 90s **после** того как уже жил 2 минуты. Для streams с rate=1 ping/20s, у slot'а ВСЕГДА есть 4-5 ping events за 90s drain → 30s gap не накапливается.**

**Evidence:**
- Reason breakdown: 841 (93.9%) drain'ов — age-trigger. То есть slot'ы попадают в drain ровно когда уже истёк maxSlotAge.
- Topdestinations: 313 streams к 142.251.1.94:443 (Google) — типичный keepalive 20s.
- Math: при 20s ping cadence, 90s drain window содержит 4-5 pings → max gap между ними ~25s < 30s threshold.

**Counter-evidence:**
- 467 idle-finishes показывают что 30s gap всё-таки часто появляется. Это значит cadence ping'ов **варьируется**, и часть stream'ов лопается между двумя дальними ping'ами.
- Hard cap'ы стабильно держатся ровно на 1m30s — нет early teardown через любой другой механизм.

**Confidence:** LOW-MEDIUM. Математически правдоподобно, но напрямую не доказано без per-stream activity trace.

---

### Hypothesis 4 (LOW confidence — counter-explanation)

**Streams=1-2 на slot — это часто "stale" streams, чьи application-side connections мертвы, но `UnregisterStream` ещё не пришёл от SOCKS5 side**. Если так, lastActivityNs действительно тихая, и idle-heuristic ДОЛЖЕН срабатывать. Если не срабатывает — значит и в "мёртвых" streams есть какой-то wire-level traffic.

**Evidence:**
- 256 idle-finish с drain_duration=0s — slot уже был idle ДО drain. То есть слотовое состояние «несколько stale streams, никто не пишет» вполне частое.
- 29 io_timeout reader_exits — server закрывает соединение, но это лишь ~9% от 332 hard caps.

**Counter-evidence:**
- Если бы все 278 hard cap'ов с ≤2 streams были stale-stream'ами, они должны были бы поймать idle. Они НЕ поймали → значит wire-уровень не тихий.

**Confidence:** LOW. Hypothesis служит больше как контр-проверка к H1/H2.

---

## 4. Выбор главной гипотезы

**Hypothesis 1** (per-slot vs per-stream measurement) — наиболее подтверждённая. Объясняет:
- Почему 278 hard caps с ≤2 streams не сработал idle
- Почему остальные 467 drain'ов всё ЖЕ ловят idle (когда ОБА stream'а тихие)
- Согласуется с архитектурой кода: одна метка на slot

Hypothesis 2 и 3 — модулирующие факторы, не отдельные причины.

---

## 5. Варианты решения

### Вариант A — Per-stream idle tracking (medium complexity)

**Подход:**
Заменить `slot.lastActivityNs` на map `lastActivityNs[streamID]`. Drain признаётся idle когда ВСЕ remaining streams тихие > 30s. Изменения в:
- `client.go::streamChans` либо `RegisterStream` — добавить per-stream timestamp.
- `WriteMessageForStream` / `WriteControlMessageForStream` — писать в per-stream метку.
- `slotReaderWithClient` после `DecryptChunkSafe` — писать в per-stream (streamID уже доступен).
- `drainWatchdog`: на каждом тике итерировать streamMap → для каждого stream'а с idx=oldIdx проверить timestamp.

**Trade-off:**
- + Захватывает истинное "все streams молчат" состояние.
- + Может детектировать 1 idle stream + 1 active = НЕ idle (правильно), 2 idle = idle.
- − Расширяет hot-path: дополнительная map lookup на каждом write/decrypt.
- − Усложняет cleanup: stale entries в lastActivity map при stream teardown.
- − Под нагрузкой 100+ streams возможен hot lock contention если не атомарно.

**Сложность:** Medium. ~150 LOC + 4-5 новых тестов.

**Риск:** Race между UnregisterStream и idle check (читаем timestamp удалённого stream'а). Mitigation: snapshot streamMap внутри tick.

**Валидация:** Канарейка 2-4h, сравнить natural-finish ratio с baseline 62.6%. Целевая дельта +10pp (target 72-75%). Метрика: добавить histogram `idle_per_stream_finish_total` отдельно от existing `IdleFinishTotal`.

---

### Вариант B — Активность с минимальным порогом байт (low-medium complexity)

**Подход:**
`lastActivityNs` обновляется только когда write/decrypt **превышает** некий byte-threshold (например 256 байт). HTTPS keepalive ping (TCP ACK + TLS record overhead = обычно <100 байт) — НЕ обновляет. Реальный data transfer — обновляет.

Изменения:
- Ввести `meaningfulActivityThreshold = 256` (env-tunable).
- В `WriteMessageForStream` / `slotReaderWithClient` обновлять `lastActivityNs` только при `len(data) >= threshold` (либо для decrypted chunk — `len(chunk.Payload) >= threshold`).

**Trade-off:**
- + Heartbeat'ы Google Docs/Gmail не блокируют idle.
- + Single-source изменение — touches только 3 файла.
- − Hardcode'нутый порог — не universal. Real HTTP/2 PING frames + TLS overhead = ~100-200 байт; крупный PING может пройти порог.
- − Можно случайно скрыть legitimate small data — например, SSH session с малыми payload'ами. Но в SOCKS5 это редко.
- − Не решает проблему "2 heartbeat-stream'а на slot'е каждый по 20s по очереди обновляют" — там pure latency-based fix не помогает.

**Сложность:** Low-Medium. ~30 LOC + 2-3 теста.

**Риск:** Misclassification стримов с легитимным low-volume траффиком. Mitigation: env-tunable, default conservative (128 байт).

**Валидация:** Канарейка 2h, метрики `drain_natural_finish_total` дельта. Дополнительно — экспозиция `meaningful_activity_skipped_total` чтобы видеть сколько write'ов прошли мимо.

---

### Вариант C — Двойной idle threshold по слоту (low complexity, частичный fix)

**Подход:**
Ввести ВТОРОЙ, более длинный threshold (например 60s) который игнорирует `streams` count. Если slot был idle 60s — drain считается natural-finish независимо от streams.Load(). А existing 30s threshold с STREAMS_MAX=2 остаётся.

```go
if idleEnabled && streams <= idleStreamsMax {
    if idle >= idleThreshold { ... }
}
// NEW: aggressive idle, ignoring streams count
if aggressiveIdleEnabled && idle >= aggressiveIdleThreshold {
    tearDown(finishIdle)
    return
}
```

**Trade-off:**
- + Ловит case'ы "slot quiescent, но stream count != 0 из-за stale UnregisterStream".
- + Минимальные изменения.
- − НЕ помогает с heartbeat-stream'ами — они активны по wire. Эта гипотеза 4, не главная.
- − Если threshold слишком короткий, killable активные streams.

**Сложность:** Low. ~20 LOC.

**Риск:** Если threshold для aggressive < 60s, можно убить legitimate streams. С 60s+ — почти equivalent to hard cap=90s, выигрыш только 30s.

**Валидация:** A/B канарейка с aggressiveIdleThreshold=60s vs текущим 90s hard cap. Сравнить natural ratio.

**Это маскировка симптома** — не атакует root cause (per-slot vs per-stream). Включил для полноты.

---

## 6. Рекомендация

**Вариант A — per-stream idle tracking.**

Обоснование:
1. Атакует root cause (Hypothesis 1 confirmed) — измерение тишины на правильном уровне.
2. Совпадает с industry pattern: HTTP/2 GOAWAY-style drain в production stack'ах (Envoy, gRPC) трекает per-stream activity для решений о teardown. Текущая реализация — упрощение.
3. Дельта ожидается значительная: 278 hard caps "потенциально eligible" → если хотя бы половина уйдёт в natural-idle, ratio поднимется на 15pp (62.6 → 77.6%) — в целевом коридоре.
4. Не маскирует — позволяет настоящему long-lived stream'у тянуть drain до hard cap, что правильно для UX.

**Confidence в рекомендации:** MEDIUM-HIGH. Есть две неопределённости:
- Невозможно без работы инкрементальной кода проверить точную процентовку streams с 20s vs 60s heartbeats — это влияет на ожидаемую дельту.
- Hot-path overhead (map lookup на каждом write/decrypt) под пиковой нагрузкой (peak 295 MB/5s в 2026-05-22 канарейке) надо проверить под -race + соответствующим load test.

Перед началом implementation: добавить в текущий бинарник одно поле в drain log — на каждом hard cap эмитить `active_stream_ids=[...]` (или хотя бы count distinct stream IDs за последнюю минуту на этом slot'е). Это даст data для уточнения ожидаемого improvement без полноценного refactor'а.

---

## 7. Что НЕ предлагается

- **Hard cap 180s** — маскировка, не fix. Long heartbeat-stream'ы и так будут жить 90s+. Просто увеличит средний drain_duration.
- **maxSlotAge увеличить** — снижает rotation rate, ослабляет anti-TSPU. Отдельная задача.
- **Force-evict при hard cap** — уже есть emergency-evict path для случая slice-full. Force-kill при норм hard cap = back to baseline (close streamChan).
- **Disable idle heuristic вообще** — natural ratio упадёт обратно в 10.5%.

---

## 8. Ограничения исследования

- Не пробовал инструментировать (run binary) — все выводы из static code reading + log grep.
- Не доступны per-stream activity timestamps в логе. Расчёт "streams=2, оба heartbeat-stream'а" — косвенный.
- Hot-path overhead Варианта A не профайлен. Под TLS keepalive в pool из 16 slot'ов это потенциально 30-100k atomic store/sec в peak.
- Не проверял что reset на write happens-before decrypt (race). Если так, может быть subtle race в idle check — Hypothesis 4 уточнение.

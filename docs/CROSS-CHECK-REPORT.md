# Cross-check отчёт: Claude ↔ Codex по регрессии ShadowLink/CF

**Задача:** независимый анализ одной и той же проблемы двумя агентами, сверка выводов, отсев галлюцинаций, консолидированные рекомендации.

**Метод:**
1. Claude прочитал код, написал собственный отчёт (сохранён в `C:\Users\ryzen\.claude\plans\typed-whistling-catmull.md`).
2. Codex (OpenAI CLI 0.120.0, `codex exec -s read-only`) получил `FOR-CODEX.md`, проанализировал независимо, вернул отчёт (`.codex-round1-output.md`).
3. Claude сверил оба отчёта построчно, верифицировал спорные утверждения чтением кода.

**HEAD кода:** `96fae7d`. Единственный содержательный коммит — `84ef181` от 2026-04-15.

---

## Итоговое ранжирование гипотез после cross-check

| # | Гипотеза | Claude | Codex | Консолидация | Доказательство |
|---|---|---|---|---|---|
| H1 | CF rate-limit на handshake POST burst | не основная | partially confirmed | **Amplifier, не trigger**. POST'ы мультиплексятся в H2, burst заметен от 8 WS TCP SYN'ов. | `ws_pool.go:176-181, 261, 307` |
| H2 | CF edge backpressure / tail-drop под нагрузкой | частично | **confirmed, best fit** | **Первичный внешний триггер**. Direct на том же origin = 225 Mbps, различие только в CF-сегменте. | `FOR-CODEX.md:9,14,16` + архитектурные CF-лимиты `engine_shadowlink.go:264-270` |
| H3 | MTU / fragmentation 32KB WS frames | маловероятно | **rejected** | **Rejected.** `chunkSize` дефолтится к 12288 (`client/client.go:156`), а не 32KB. Direct работает — значит не MTU. | `client.go:156-159` |
| H4 | nginx buffering на origin | исключено | **rejected** | **Rejected.** Direct идёт через тот же nginx → не он. | `FOR-CODEX.md:9,16,26` |
| H5 | Meltdown в ws_pool.go | **ДА, подтверждено** | partially confirmed | **Amplifier, self-sustaining loop**. Оба согласны, что threshold 4/8 @ 5s слишком чувствителен. | `ws_pool.go:136-146, 334-344, 370-380` |
| **H6** | **Writer-side 30s timeout → conn.Close() → reader death (НЕ read timeout!)** | **ПРОПУСТИЛ** | **partially confirmed (new)** | **Важная находка Codex.** Первичный локальный механизм смерти slot'а — не reader, а writer. | `core/wsasyncwriter.go:67, 136`; `ws_transport.go:324` |
| F1 | Startup fan-out без stagger | **ДА** | ДА (Tier 1 фикс) | **Оба согласны.** `StaggerDelay` есть в `ws_ready_pool.go:186-198`, не применён к основному pool. | `ws_pool.go:172-204` |
| F2 | Kill streams при смерти slot → белый экран | ДА (UX issue) | упомянул в H5 | **Оба согласны.** | `ws_pool.go:811-823` |
| F3 | Асимметричный warmup (только slot 0) | отметил как dead code | **пропустил** | **Claude: мёртвая косметика**, не критично. | `ws_pool.go:304-306` |
| F4 | DNS-spray → разные CF edges | **ДА** | **пропустил** | **Важная находка Claude.** Без `CFIP` каждый slot резолвит `datacanvases.com` независимо. | `ws_transport.go:219-275` |
| F5 | Split TLS fingerprint (H2 POST / H1.1 WS) | Tier 3 | **пропустил** | **Theoretical, низкий ROI.** Обе стороны с Chrome JA3, но разный ALPN. | `ws_transport.go:257-263`, `transport.go` |
| F6 | 30s read timeout vs 20s keepalive — баг? | **опровергнул** (агент 1 ошибся) | не поднимал | **Rejected.** На timeout reader делает `continue`, не смерть. | `ws_pool.go:772-774` |
| F7 | Per-WS silent drop stream data | **опровергнул** | не поднимал | **Rejected.** Миграции stream между slot нет в клиенте. | `ws_pool.go:71, 543, 630-640` |

---

## Находка Codex, которую пропустил Claude (главное)

### H6: **Writer-side timeout как реальный trigger смерти slot**

**Цепочка событий под CF backpressure:**
1. CF edge замедляется под нагрузкой → TCP backpressure на клиенте.
2. Writer'у надо отправить frame → `w.writeFrame` делает `SetWriteDeadline(now + 30s)` (`core/wsasyncwriter.go:136`).
3. Если TCP буфер не опорожняется за 30s → `i/o timeout` error.
4. `w.Run()` возвращает error → goroutine в `ws_transport.go:318-325` делает `conn.Close()`.
5. Reader на этом conn получает `wsarecv: A connection attempt failed` (Windows-специфичная форма `ECONNABORTED`).
6. Reader goroutine возвращает error → `p.handleSlotDeath(cl, idx)` (`ws_pool.go:776`).
7. При 4 таких за 5s → meltdown cooldown 10s.

**Почему это ценно:**
- Бриф описывает симптом как `wsarecv error` — Claude интерпретировал это как CF закрыл TCP первым. **Codex предложил альтернативу: наш writer закрыл conn первым**, а `wsarecv` на reader'е — следствие.
- Это объясняет коррелированную смерть 8 slot: если CF edge замедлился одновременно для всех (один edge на несколько slot'ов из-за F4), то 8 writer'ов независимо упираются в 30s deadline в близком окне.
- 30s writer timeout слишком терпелив для CF — трафик застывает на полминуты прежде чем slot помечается dead.

**Уточнение для Codex (verified):**
- Codex цитирует `client/ws_transport.go:318` как `w.SetWriteTimeout(t.writeTimeout)` — **галлюцинация**. Такой строки нет. `SetWriteTimeout` определён в `core/wsasyncwriter.go:73-77`, но из `client/` не вызывается вообще. Writer всегда работает с дефолтным 30s.
- Строка log в `ws_transport.go:320` — `slog.Debug` (не `slog.Warn` как говорит Codex). Значит **writer exit не попадает в обычные логи клиента** — это отдельный Tier 1 fix: **поднять уровень до Warn** чтобы различать writer-trigger vs reader-trigger death.

---

## Находки Claude, которые пропустил Codex

### F4: DNS-spray по CF edges (подтверждено кодом)

- `client/ws_transport.go:219-275`: когда `cfIP == ""`, `NetDialTLSContext` получает `addr` от gorilla-dialer'а уже после DNS lookup'а.
- 8 параллельных `dialer.Dial(wss://datacanvases.com/ws)` → 8 независимых DNS запросов → CF round-robin выдаёт 3-5 разных edge IP.
- Если один edge деградирует — 1-3 slot'ов умирают коррелированно → близко к meltdown threshold 4.
- **Инфраструктура фикса уже готова**: `CFIP` параметр пробрасывается во все слои, `cmd/cf-scanner/main.go` умеет находить оптимальный edge. Нужен лишь auto-resolve при старте pool'а.

### Synchronized stampede на выходе из meltdown

- Claude: после истечения `meltdownUntil` все 8 reconnect-loops просыпаются одновременно (`ws_pool.go:334-344, 370-380`). `backoffDuration(0)` даёт `[0.75s, 1.25s]` — окна слишком узкое для десинхронизации.
- Результат: 8 параллельных handshake + 8 WS upgrade → тот же burst, что вызвал первичный meltdown → **self-sustaining loop**.
- Codex признаёт meltdown как amplifier, но не выделяет synchronized wake как отдельный механизм.

---

## Консолидированные рекомендации (приоритизировано после cross-check)

### Tier 0 — диагностика (прежде чем фиксить)

**D1.** Поднять уровень writer exit с Debug до Warn в `client/ws_transport.go:320` — **обязательно**, чтобы разделить writer-trigger (H6) от reader-trigger (CF close). Без этого все фиксы — гадание.

**D2.** Добавить в stats counters (`client/stats.go`) раздельно: `writer_exits`, `reader_exits`, `slot_deaths_by_cause`. Запустить под CF, получить разбивку.

### Tier 1 — дешёвые, высокая вероятность помочь

**R1.** **Stagger в `WSPoolTransport.Connect`** (`ws_pool.go:172-204`): разнести старт 8 slot'ов на 150-300мс по индексу. Паттерн уже есть в `ws_ready_pool.go:186-198`. **[Оба согласны]**

**R2.** **Per-slot jitter на выходе из meltdown** (`ws_pool.go:334-344`): добавить `+ time.Duration(idx)*300*time.Millisecond + random jitter` к `meltdownWaitDuration()`. **[Claude]**

**R3.** **Снизить writer timeout для viaCF** — это прямой ответ на H6. Дефолт 30s (`core/wsasyncwriter.go:67`) слишком велик для CF: трафик застывает полминуты, прежде чем slot помечается dead и можно переключиться на соседний живой slot. Для CF: 5-8 секунд. Вызывать `w.SetWriteTimeout(...)` из `client/ws_transport.go:306` с передачей параметра от pool config. **[Codex H6 + верификация Claude]**

**R4.** **Pre-resolve CF domain один раз** в `NewWSPoolTransport`: если `CFIP == ""` и `cdn != ""` — сделать DNS lookup один раз, передать полученный edge IP как `cfIP` во все 8 slot. **[Claude F4]**

**R5.** **Поднять meltdown threshold** для 8-slot pool: `ceil(size/2)=4 @ 5s window` слишком чувствительно. Рекомендуется threshold=6/8 либо window=15-20s. **[Оба согласны]**

### Tier 2 — средние

**R6.** **Меньше slot'ов для CF, больше streams/slot**: 4 × 8 = 32 (та же capacity, вдвое меньше TCP fan-out). **[Оба согласны]**

**R7.** **Ленивый grow**: стартовать с 2-4 WS, расширяться только когда `AllSlotsAtMaxPending()` (`ws_pool.go:585`). **[Codex]**

**R8.** **Re-assignment stream при смерти slot** (`ws_pool.go:811-823`): вместо hard-close каналов — переставить stream на живой slot и послать новый CONNECT. Требует проверки серверного state machine на повторный CONNECT одного streamID. **[Claude F2]**

**R9.** **Поднять базовый backoff для viaCF** с 1s до 3-5s (`client.go:681-687` или локально). **[Claude]**

### Tier 3 — последнее средство

**R10.** **Runtime fallback после N meltdowns подряд**: автоматически переходить в менее агрессивный transport mode (SplitHTTP или single WS) вместо бесконечного storm/recover. **[Codex]**

**R11.** **Убрать warmup slot-0** как мёртвый код (`ws_pool.go:304-306`). **[Claude F3]**

**R12.** **Унификация TLS fingerprint** handshake и WS upgrade. Низкий ROI. **[Claude F5]**

---

## Чего НЕ рекомендуем (оба агента согласны)

- **Shared session между 8 WS** — per-slot архитектура правильная, contention нет (`decrypt_fails=0` подтверждает).
- **Трогать сервер** — direct-режим 225 Mbps на том же сервере доказывает, что он здоров.
- **Переписывать transport целиком** — проблема policy, не архитектуры.
- **Переход на per-stream WS** — уже пробовали 14 апреля, вышло хуже (`FOR-CODEX.md:12`).

---

## Где Codex и Claude существенно разошлись

| Тема | Claude | Codex | Разбор |
|---|---|---|---|
| **Первичный механизм смерти slot** | Synchronized reconnect stampede после meltdown | Writer 30s timeout → conn.Close() | **Codex прав на раннем этапе.** Writer — triggers первичную death; stampede — amplifier при reconnect. Оба нужны в комплексном фиксе. |
| **DNS-spray / edge pinning** | Важная находка (F4) | Не упомянул | **Claude прав.** CFIP инфраструктура готова, пропускать её нельзя. |
| **Apr 13/14 framing** | Бесполезно, в git нет снимка | "Полезно как подсказка, misleading как primary frame" | **Эквивалентно, формулировка Codex мягче.** |
| **Цитата `client/ws_transport.go:318`** | N/A | `w.SetWriteTimeout(t.writeTimeout)` | **Галлюцинация Codex** — такой строки нет. Тезис H6 верен, конкретная цитата — вымысел. |

---

## План действий для Codex-заказа (финальный)

**Минимальный жизнеспособный patch (Tier 0 + Tier 1):**

1. `D1` — поднять writer exit log до Warn + `D2` стату.
2. **Прогнать** под CF 5-10 минут → посмотреть разбивку: writer exits первичны?
3. Если **да** (ожидаемо) — **R3** (виaCF writer timeout 5-8s) + **R4** (pre-resolve CFIP) + **R1** (stagger).
4. Если **нет** (CF сам рубит TCP) — **R5** (meltdown threshold up) + **R2** (per-slot jitter) + **R1**.

**Любой сценарий:** R1 + R4 + R5 обязательны. R3 обязателен если H6 подтвердится рантаймом.

---

## Файлы для редактирования

- `D:\Job\shadowlink\client\ws_pool.go` — R1, R2, R5, R8
- `D:\Job\shadowlink\client\ws_transport.go` — D1, R3 (передача timeout)
- `D:\Job\shadowlink\core\wsasyncwriter.go` — (ничего — параметр передаётся извне)
- `D:\Job\shadowlink\cmd\nixavpn-client\engine_shadowlink.go` — R4, R6, R7
- `D:\Job\shadowlink\client\client.go` — R9
- `D:\Job\shadowlink\client\stats.go` — D2

## Верификация

См. раздел "Как верифицировать после фиксов" в `C:\Users\ryzen\.claude\plans\typed-whistling-catmull.md` — метод тот же.

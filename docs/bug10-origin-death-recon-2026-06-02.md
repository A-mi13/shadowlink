# Bug #10 — Origin Death Recon (2026-06-02)

Спроектировочная разведка для фикса «origin-TCP умер (broken pipe) → сервер
молча долбит мёртвый origin, клиент висит». НЕ чинить — карта кода.

## Доказанный симптом (серверный лог pl1)

- Origin-TCP сокет (сервер↔Anthropic 160.79.104.10:443) умирает: `write: broken pipe`.
- Сервер при записи uplink ловит broken pipe, логирует
  `WARN "WS uplink registry-fallback write failed" stream=N err="... write: broken pipe"`
  и ПРОДОЛЖАЕТ — НЕ закрывает стрим, НЕ сигналит клиенту. 342 за день, stream=351 долбился 5+ минут.
- Клиент не знает что origin мёртв → бесконечный uplink, пустой downlink, Claude Code висит "Frosting".

---

## 1. Точное место лога + uplink-write в origin

**`server/websocket.go:855-860`** (внутри reader-loop `case core.FlagData:` → ветка
«stream локально nil, но migration активна» = registry-fallback uplink после миграции):

```go
if entry, ok := h.relayRegistry.find(migrateClientID, streamID); ok && entry.tc != nil {
    if _, werr := entry.tc.Write(payload); werr != nil {
        slog.Warn("WS uplink registry-fallback write failed",
            "stream", streamID, "err", werr)
    }   // ← err только логируется. НЕТ teardown, НЕТ сигнала клиенту.
}
```

`entry.tc` — это `net.Conn` к origin (egress-TCP, переживает миграцию слота,
`relay_registry.go:111`). При мёртвом origin `tc.Write` → broken pipe, и код
просто логирует и продолжает читать следующий FlagData.

Комментарий выше (websocket.go:854) прямо признаёт пробел:
> «and on error we leave teardown to the FIN / grace / dest-EOF paths.»
— то есть осознанно положились на ДРУГИЕ пути закрытия, которых при долгом мёртвом
origin под активным uplink не наступает (FIN не придёт — клиент не знает; grace не
наступит — слот жив; dest-EOF на read не наступит — half-open: write-half мёртв, read-half висит).

---

## 2. ДВА пути записи uplink в origin (HIGH-4 подтверждён)

**Да, ровно два — и ОБА игнорируют ошибку записи:**

### Путь A — local fast-path (`server/websocket.go:825-826`), слот рождения стрима
```go
s := streams[streamID]
if s != nil && len(payload) > 0 {
    s.Write(payload) // async — never blocks!
}
```
`s` — `*wsStream`. `wsStream.Write` (websocket.go:362) — АСИНХРОННЫЙ enqueue в канал;
реальная запись в origin происходит в `startWriter` goroutine (websocket.go:328).
Ошибка записи в origin внутри writer-goroutine **тоже не сигналится клиенту** (нужно
прочитать startWriter полностью при фиксе — он закрывает только локальный стрим).

### Путь B — registry-fallback (`server/websocket.go:855-860`), слот после миграции
Это место из п.1. `entry.tc.Write` напрямую, ошибка только логируется.

**Вывод HIGH-4:** оба uplink-пути «fire-and-forget» по отношению к origin-write error.
Фикс должен покрыть ОБА (архитектурно — централизованный teardown, см. п.6),
иначе мёртвый origin на слоте рождения (путь A) даст тот же висяк.

---

## 3. Как сервер закрывает стрим штатно (origin read-EOF / error)

Два downlink-реле (origin→client), зеркальные двум uplink-путям:

### Legacy inline relay (`server/websocket.go:1120-1165`) — НЕ-migration стримы
Читает `tc.Read` в цикле. На `err != nil` (включая EOF) — просто `return`
(websocket.go:1162-1164). `defer` (websocket.go:1101-1119) закрывает локальный
`s.Close()`, удаляет `streams[sid]`, закрывает credit. **Клиенту НИЧЕГО не шлёт.**
Клиент узнаёт о конце только косвенно (TCP-поток обрывается на его стороне через
half-close uplink). Для НЕ-migration этого хватало.

### Migratable relayLoop (`server/relay_registry.go:576-650`) — production (migration ON)
`e.tc.Read` → downlink. На `err != nil` (origin EOF/error):
- если стрим orphaned → `e.destClosed.Store(true)` (relay_registry.go:627-629), RESUME
  потом флашит буфер и сигналит end-of-stream;
- если стрим ещё active → просто `return` (relay_registry.go:647), **клиенту явного
  сигнала НЕ шлётся**. Комментарий relay_registry.go:630-646 (TODO bug9-1b) прямо
  фиксирует: на NORMAL dest-EOF над live-binding entry НЕ удаляется и tc НЕ
  закрывается, потому что egress BIDIRECTIONAL (read-EOF download-half ≠ uplink-half
  закончен) — лечится только half-close-aware teardown, отложено.

**Итог:** даже штатный origin-EOF на active-стриме сервер клиенту явно НЕ сигналит —
полагается на то, что клиентский half-close uplink сам всё свернёт. При broken-pipe
на WRITE-половине этот механизм не срабатывает: read-половина relayLoop висит на
`tc.Read` (origin write-half мёртв, read-half ещё открыт или висит), поэтому даже
п.3-пути не наступают.

---

## 4. ГОТОВЫЙ server→client per-stream teardown сигнал — ЕСТЬ

**ДА. `CONNECT_FAIL` маркер, посланный как `FlagData` stream-data chunk на нужный streamID.**

### Как сервер его шлёт (примеры в коде)
- websocket.go:878 (max streams), :924 (blocked domain), :954 (dial fail):
```go
errChunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, []byte("CONNECT_FAIL"))
if enc, err := session.EncryptChunk(errChunk); err == nil { writeMsg(enc) }
```
Это обычный FlagData chunk с payload `[streamID(2)]["CONNECT_FAIL"]`, адресованный
конкретному стриму. Для migration-стрима на relayLoop эквивалент —
`enqueueDownFrame`/`writeMsg` под текущим binding (см. п.6).

### Как клиент его ПРИНИМАЕТ (уже умеет рвать стрим mid-flight)
Демукс: `client/ws_pool.go:3285-3289` — на migration-слоте `body=chunk.Payload[2:]`,
`isStreamControlMsg(body)` (client/client.go:1036) ловит точное «CONNECT_OK»/«CONNECT_FAIL»
и роутит как seq==0 control через `RouteToStreamSeq(streamID, 0, body)`.

Обработчик seq==0 control в downlink-реассемблере:
`proxy/socks5/tcp.go:530-538` → `dep.onControl(f.Data)`; контракт (tcp.go:462-464):
**«Returns keepGoing=false to tear the stream down (CONNECT_FAIL).»** То есть в
migration-режиме CONNECT_FAIL на seq==0 рвёт стрим в ЛЮБОЙ момент (не только при connect).

Подтверждающий тест: `proxy/socks5/downlink_reassembly_test.go:106,119,124` —
«CONNECT_OK (control) then one real data frame, then CONNECT_FAIL (break)» →
«CONNECT_FAIL did not tear the stream down» как fail-условие. Т.е. поведение
«mid-stream CONNECT_FAIL = teardown» уже закодировано и покрыто тестом.

### Другие кандидаты (НЕ подходят как per-stream сигнал)
- **`FlagFin`** (core/chunk.go:18, 0x05) — на сервере это SESSION-wide / broadcast
  (`BroadcastStreamClose` handler.go:1794, server.go:253 «server_maintenance»), рвёт
  ВСЮ сессию у клиента. Для одного дохлого origin-стрима — слишком грубо.
- **`BroadcastStreamClose`** — то же, вся сессия.

### Caveat (важно для фикса)
Legacy НЕ-migration downlink (tcp.go:379-391 и :1082-1108) распознаёт CONNECT_FAIL
ТОЛЬКО пока `!connectConfirmed`. После подтверждения connect CONNECT_FAIL-образный
фрейм запишется в приложение как сырые байты. **Но production = migration ON**, где
seq==0 `onControl` (tcp.go:530-538) ловит control в любой момент — так что для
Bug #10 (migration-путь) сигнал CONNECT_FAIL рабочий mid-stream. Если потребуется
покрыть и legacy-путь — нужен отдельный мелкий патч в tcp.go:379-391, но это вне
основного сценария.

---

## 5. relayEntry — пометка стрима dead + teardown

`server/relay_registry.go`:
- **State machine** (relay_registry.go:94-98): `stActive(0)/stOrphaned(1)/stClosing(2)`,
  поле `state atomic.Int32` (:117). Все переходы через CompareAndSwap.
- **`destClosed atomic.Bool`** (:145) — УЖЕ существующая пометка «origin закрылся пока
  стрим был orphaned». Ставится в relayLoop (:628). Но: (а) только при `state==stOrphaned`,
  (б) только на READ-error, не на WRITE-error. Для Bug #10 (write broken-pipe на
  active-стриме) НЕ срабатывает.
- **`closeReader()`** (relay_registry.go:213-220) — единый permanent-teardown: закрывает
  `closeCh` (будит relayLoop credit-wait) + закрывает credit. Идемпотентно (sync.Once).
  НЕ трогает `tc` (caller сам закрывает).
- **Единый паттерн single-winner teardown** (CAS stActive/stOrphaned→stClosing →
  `remove` → `closeReader` → `tc.Close` → `releaseOrphanFD` → broadcast bufCond):
  - grace timer: relay_registry.go:787-814
  - idle-evict: relay_registry.go:508-524
  - **FlagFin handler: websocket.go:1199-1219** ← ГОТОВЫЙ образец для копирования
- **`unregister` стрима** = `relayRegistry.remove(clientID, streamID)` (relay_registry.go:298-307).

---

## 6. Правильная точка вставки + какой сигнал переиспользовать

### Где (4-6 ключевых file:line)
1. **`server/websocket.go:856-859`** — registry-fallback uplink write error (путь B, п.2).
   Главная точка: при `werr != nil` → НЕ просто лог, а teardown стрима + сигнал клиенту.
2. **`server/websocket.go:328`+ (`wsStream.startWriter`)** — uplink write error на пути A
   (слот рождения). При write-error в origin внутри writer-goroutine → тот же teardown.
   ОБА пути обязаны звать общую точку (HIGH-4).
3. **`server/websocket.go:1199-1219`** — ГОТОВЫЙ образец single-winner teardown
   (FlagFin handler): CAS→stClosing → remove → closeReader → tc.Close → releaseOrphanFD →
   broadcast bufCond. Скопировать в новый хелпер `teardownStreamOnOriginDeath`.
4. **`server/relay_registry.go:213-220` (`closeReader`)** + **:298 (`remove`)** —
   переиспользовать как есть для серверной части teardown.
5. **Сигнал клиенту** — `core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID,
   []byte("CONNECT_FAIL"))` → encrypt → enqueue на текущем binding writer
   (`entry.bound.Load().writer.Enqueue`, см. enqueueDownFrame relay_registry.go:822-835),
   ровно как websocket.go:954 шлёт его на dial-fail.
6. **Приём клиентом — уже готов**: ws_pool.go:3286 `isStreamControlMsg` → seq==0 control →
   tcp.go:533 `onControl` возвращает keepGoing=false → стрим рвётся, appConn закрывается,
   Claude Code получает обрыв вместо вечного висяка.

### Архитектура фикса (одна строка)
При origin-write-error (broken pipe) на ЛЮБОМ из двух uplink-путей — выполнить
существующий single-winner teardown relayEntry (CAS→stClosing, remove, closeReader,
tc.Close, releaseOrphanFD) И послать клиенту уже-готовый per-stream `CONNECT_FAIL`
FlagData-chunk на текущем binding writer — новый фрейм НЕ изобретать.

### Точность сигнала / нюансы для проектирования
- `CONNECT_FAIL` нейтрален к направлению — клиент рвёт стрим, не различая «origin write
  vs read died». Это ОК: для приложения любой обрыв origin = разорванный стрим.
- НЕ слать `FlagFin` (broadcast = убьёт всю сессию).
- Teardown ДОЛЖЕН идти через тот же CAS single-winner, что и FlagFin/grace/idle-evict —
  иначе double-close race с grace-timer/RESUME (см. п.5 паттерн).
- Сигнал слать ДО или независимо от `tc.Close` — на текущем `bound.writer`; если стрим
  мигрировал, writer берётся из `entry.bound.Load()`, не из локального слота.

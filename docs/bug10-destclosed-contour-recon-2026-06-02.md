# Bug #10 — destClosed-контур: почему не сработал. Рекогносцировка (2026-06-02)

**Задача:** диагностика, НЕ фикс. Понять, почему задуманный механизм восстановления
(`relayEntry.destClosed` + «a subsequent RESUME flushes downBuffer and signals
end-of-stream») НЕ сработал для зависшего навсегда стрима (stream=1253, Claude
«Frosting»), когда origin-TCP сокет сервера к Anthropic умер на write (broken pipe).

Все ссылки — `file:line`, цитаты из кода.

---

## 0. Топология соединений (КЛЮЧЕВОЕ — два разных TCP)

Это ДВА независимых TCP-соединения, и их смерть НЕ связана:

```
SOCKS5 app (Chrome) ──uplink──▶ client WSPoolTransport ──[WS slot N]──▶ nginx/CF ──▶ server runWebSocketSession
                                                          (TCP #1: client↔server)            │
                                                                                              │ entry.tc
                                                                                              ▼
                                                                                  origin TCP #2: server↔Anthropic
```

- **TCP #1 (WS-слот client↔server):** живёт в `binding.writer` (`*core.WSAsyncWriter`,
  обёртка над `*websocket.Conn`), `server/relay_registry.go:32-35`. Это то, по чему
  сервер ШЛЁТ downlink клиенту.
- **TCP #2 (origin server↔Anthropic):** это `relayEntry.tc net.Conn`,
  `server/relay_registry.go:108-111`. На него сервер ПИШЕТ uplink и с него ЧИТАЕТ
  downlink.

`origin broken pipe ≠ смерть WS-слота`. Это разные FD, разные peer'ы, разные TSPU-пути.

---

## 1. Где ставится `destClosed=true` — ТОЛЬКО на READ-error origin→client

Единственное место установки во всём дереве — `server/relay_registry.go:621-629`
внутри `relayLoop` (downlink-насос: `tc.Read` → encrypt → enqueue клиенту):

```go
n, err := e.tc.Read(buf[:limit])   // relay_registry.go:591 — это READ origin→client
...
if err != nil {
    // F13: egress closed/errored. If this happened while the relay was
    // orphaned (no live WS behind it), record that the destination is gone...
    if e.state.Load() == stOrphaned {     // relay_registry.go:627
        e.destClosed.Store(true)          // relay_registry.go:628
    }
    return
}
```

**Подтверждено: `destClosed` ставится ИСКЛЮЧИТЕЛЬНО на ошибке `tc.Read` (downlink,
origin→client), И ТОЛЬКО когда `state==stOrphaned`.**

### Путь WRITE-broken-pipe (наш случай, uplink client→origin) — destClosed НЕ ставит

Uplink в origin идёт ТРЕМЯ путями, и НИ ОДИН не трогает `destClosed`:

1. **Путь A — `wsStream.startWriter`** (`server/websocket.go:328-360`). Дренаж
   `writeCh` в `s.targetConn.Write` (это тот же FD, что `entry.tc`):
   ```go
   _, err := s.targetConn.Write(data)   // websocket.go:338
   core.PutBuffer(data)
   if err != nil {
       s.Close()                        // websocket.go:341 — закрывает s.targetConn
       return
   }
   ```
   `s.Close()` (`websocket.go:389-403`) делает `s.targetConn.Close()` — закрывает
   origin FD. НО: НЕ трогает `entry.state`, НЕ ставит `entry.destClosed`, НЕ шлёт
   клиенту ничего, НЕ удаляет entry из registry. wsStream и relayEntry — РАЗНЫЕ
   объекты, разделяющие лишь один net.Conn; wsStream про relayEntry ничего не знает.

2. **Путь B — uplink registry-fallback после миграции** (`server/websocket.go:855-860`):
   ```go
   if entry, ok := h.relayRegistry.find(migrateClientID, streamID); ok && entry.tc != nil {
       if _, werr := entry.tc.Write(payload); werr != nil {
           slog.Warn("WS uplink registry-fallback write failed", "stream", streamID, "err", werr)
       }   // websocket.go:856-859 — ТОЛЬКО лог. Нет destClosed, нет teardown, нет сигнала клиенту.
   }
   ```

3. **Путь POST (legacy data-path)** — `server/handler.go:922-934`, `targetConn.Write`
   на ошибке делает `targetConn.Close()` + закрытие stream'а. Это НЕ migration-путь
   (отдельный код), тоже не трогает relayEntry.destClosed.

**Гипотеза задачи ПОДТВЕРЖДЕНА: `destClosed` ставится только на READ-error реле
origin→client; на WRITE-broken-pipe (наш случай) он не ставится ни на одном из трёх
uplink-путей.**

---

## 2. Условие `state==stOrphaned` — на ЖИВОМ active-слоте destClosed не ставится даже на READ-error

`relay_registry.go:627`: `if e.state.Load() == stOrphaned`.

Стрим становится `stOrphaned` ТОЛЬКО когда умирает его WS-слот и session-cleanup
вызывает `toOrphaned` (`relay_registry.go:768-774`, через `entriesForSession`).
Пока WS-слот клиент↔сервер ЖИВ, стрим остаётся `stActive`.

Для stream=1253: origin умер РАНО (до возраст-миграции слота, до смерти слота), стрим
был `stActive`. Значит:

- Даже если бы origin дал downlink READ-EOF (не наш случай — у нас WRITE-died),
  при `stActive` ветка `relay_registry.go:627` НЕ выполнилась бы (см. также явный
  `TODO(bug9-1b)` на `relay_registry.go:630-646`: «eager release on a NORMAL dest EOF
  over a LIVE binding is intentionally NOT done here» — relayLoop на active-слоте
  просто `return`, оставляя entry в registry до смерти сессии).
- На нашем WRITE-died origin при `stActive` — тем более ничего не ставится.

**Подтверждено: при `stActive` (стрим ещё не мигрировал, слот жив) `destClosed` не
ставится в принципе — ни на read-EOF, ни на write-error.**

---

## 3. Что делает `destClosed` на RESUME — НИЧЕГО. Это мёртвый флаг (write-only)

Это самая важная находка. Прогон `Grep` по `destClosed` во всём `server/`:

```
relay_registry.go:139   // комментарий-доктрина
relay_registry.go:145   destClosed atomic.Bool   // объявление
relay_registry.go:628   e.destClosed.Store(true) // ЕДИНСТВЕННАЯ запись
```

**`destClosed` НИГДЕ не читается.** Ни в `handleMigrateOrResume`
(`server/websocket.go:570-627`), ни в `reassociate` (`relay_registry.go:732-763`), ни
в grace-timer (`relay_registry.go:784-816`), ни где-либо ещё.

`reassociate` — единственный код, исполняемый на RESUME — делает ровно следующее:
переставляет binding, дренирует `downBuffer` в новый writer, при `aDead` пере-шлёт
`unackedTail` (`relay_registry.go:732-763`). **Никакой проверки `destClosed`,
никакого «signals end-of-stream», никакого FIN-фрейма клиенту не существует.**

Поиск любого end-of-stream / FIN-фрейма ОТ СЕРВЕРА к клиенту по `destClosed`: его нет.
Сервер шлёт клиенту FIN только... нигде в этом контуре — FIN в протоколе
односторонний (client→server, `FlagFin`, `server/websocket.go:1168`). Обратного
сигнала «origin закрылся, рви стрим» в коде НЕТ.

**Подтверждено: доктрина в `relay_registry.go:139-145` («A subsequent RESUME flushes
downBuffer and then signals end-of-stream to the client») — НЕ РЕАЛИЗОВАНА. Это
комментарий/намерение, а не код. Часть про «flushes downBuffer» работает (это делает
reassociate), но «signals end-of-stream» — отсутствует целиком.** Даже если бы
`destClosed` был выставлен, и даже если бы клиент сделал RESUME — клиент НЕ получил бы
никакого end-of-stream и продолжил бы ждать.

---

## 4. Клиент НЕ резюмит тихо висящий стрим на ЖИВОМ слоте — нет per-stream downlink-idle

Триггеры миграции/RESUME на клиенте — ТОЛЬКО слот-уровневые:

- **Возраст слота** — `migrate_watchdog.go` (`scheduleSlotMigration`/`migrateStream`,
  `client/migrate_watchdog.go:169-278`): мигрирует, когда СЛОТ перешёл age-порог (60s×jitter).
- **Смерть слота** — `handleSlotDeath` → `resumeStreamOnDeath`
  (`client/ws_pool.go:3523,3566,3690`). Срабатывает на ошибке reader/writer СЛОТА
  (close 1006, reader error, TCP RST — `ws_pool.go:208-253`).

`streamEntry` (`client/stream_entry.go:18-46`) хранит ТОЛЬКО `slotIdx`, `lastWriteNs`
(время UPLINK-записи) и `migrating`. **Нет поля `lastDownlinkNs`/`lastRecvNs`, нет
per-stream таймера/дедлайна, нет watchdog'а «downlink молчит N секунд на этом стриме».**
`allStreamsIdle`/`snapshotDrainStreams` (`stream_entry.go:62-180`) считают idle по
`lastWriteNs` (uplink) — и только чтобы НЕ держать drain открытым, т.е. это сигнал
«можно сворачивать», а НЕ «надо резюмить».

Для stream=1253: origin мёртв на сервере, но WS-слот клиент↔сервер ЖИВ (slotReader
успешно читает, ReadMessage не падает). Клиент не видит ни смерти слота, ни age-cut'а
по этому стриму. SOCKS5-reader стрима блокирован на чтении из per-stream канала
(`cl.streamChans[id]`), в который никогда не придёт ни данные, ни close.

**Гипотеза задачи ПОДТВЕРЖДЕНА: у клиента НЕТ механизма заметить «downlink молчит
слишком долго на этом конкретном стриме» при живом слоте. Клиент ждёт downlink
вечно.**

---

## 5. Свести воедино — причинно-следственная цепочка зависания stream=1253

1. Стрим CONNECT'ится на слоте N, регистрируется `relayEntry`, `state=stActive`,
   запущен `relayLoop` (читает origin), запущен `wsStream.startWriter` (пишет origin).
   `entry.tc` = origin TCP к Anthropic. `binding.writer` = WS-слот N (TCP #1).
2. **Origin TCP #2 умирает на WRITE** (TSPU режет direct-TCP по возрасту / Anthropic
   закрыл). Следующий `s.targetConn.Write` (uplink, путь A `websocket.go:338`) →
   `broken pipe` → `s.Close()` → закрывает origin FD. **`entry.state` остаётся
   `stActive`, `entry.destClosed` остаётся `false`, клиенту ничего не послано, entry
   остаётся в registry.**
3. `relayLoop` параллельно блокирован на `e.tc.Read` (downlink, `relay_registry.go:591`).
   После `s.Close()` закрыл FD, `tc.Read` вернёт ошибку → ветка `relay_registry.go:621`.
   Но `state==stActive` (не `stOrphaned`) → `destClosed` НЕ ставится
   (`relay_registry.go:627`) → `relayLoop` просто `return` (`relay_registry.go:647`),
   тихо. Entry остаётся в registry с протухшим `tc`. **Никакого сигнала клиенту.**
4. **Клиент:** WS-слот N ЖИВ (origin-смерть его не касается — это TCP #2, а слот это
   TCP #1). Значит ни `handleSlotDeath`, ни age-cut по слоту не срабатывают для
   stream=1253 раньше штатного времени. Per-stream downlink-idle watchdog'а нет
   (§4). SOCKS5-reader стрима ждёт данные в `streamChans[1253]` — которые никогда не
   придут. **Стрим висит вечно.**
5. Даже сценарий «слот N позже стареет/умирает → клиент делает RESUME» НЕ спасает:
   `reassociate` на RESUME не читает `destClosed` и НЕ шлёт end-of-stream (§3). Клиент
   получил бы MIGRATE_OK и продолжил ждать downlink с уже-мёртвого origin.

**Одной фразой:** origin умер на WRITE при `stActive` → серверный контур восстановления
(`destClosed`) физически не вооружается (он только на READ-EOF И только при
`stOrphaned`), а даже будь вооружён — его потребитель не существует (RESUME не читает
`destClosed` и не шлёт end-of-stream), плюс клиент при живом WS-слоте не имеет
per-stream downlink-idle, чтобы заметить молчание и инициировать teardown → вечный висяк.

### Жив ли WS-слот клиент↔сервер в момент origin-write-broken-pipe?

**ДА (почти всегда жив).** origin (TCP #2 server↔Anthropic) и WS-слот (TCP #1
client↔server) — разные соединения с разными peer'ами. Broken pipe на origin никак не
закрывает WS-слот. В коде смерть origin (`s.Close()` на `websocket.go:341`) НЕ трогает
`binding`/`writer`/WS-conn. Следовательно `entry.bound.Load().writer` в этот момент
ЖИВ и пригоден для отправки. Это значит, что **HIGH-1 из прошлого ревью (про «мёртвый
writer, некуда слать сигнал») НЕВЕРЕН для этого сценария** — сервер МОЖЕТ немедленно
послать сигнал прямо по текущему живому WS-слоту через `entry.bound.Load().writer`.
(Исключение «зависит»: если origin и WS-слот рвутся одновременно одним сетевым событием
— тогда слот мёртв и сработал бы обычный handleSlotDeath/RESUME-путь; но это НЕ кейс
stream=1253, где симптом — именно тихий висяк при живом слоте.)

---

## 6. Минимальный набор изменений, достраивающий существующий контур

Цель — НЕ изобретать новое, а закрыть три дыры (вооружить флаг / добавить потребителя /
дать клиенту реакцию). Сервер может слать сигнал НЕМЕДЛЕННО по живому WS-слоту, не
дожидаясь RESUME.

1. **Ставить `destClosed` на ВСЕ origin-смерти, не только READ-EOF-при-orphaned.**
   В uplink-write-error путях добавить пометку реле: путь A `server/websocket.go:338-343`
   (на `err != nil` после `s.targetConn.Write` — пометить соответствующий relayEntry) и
   путь B `server/websocket.go:855-859` (registry-fallback уже держит `entry` в руках —
   на `werr` пометить его). Снять условие «только `stOrphaned`» на read-error пути
   `server/relay_registry.go:627` (ставить `destClosed=true` и при `stActive`).

2. **Сделать `destClosed` потребляемым — слать end-of-stream немедленно по живому
   binding.** Завести один helper `signalStreamEnd(entry)`: если `entry.bound.Load()`
   жив (writer != nil), зашифровать и enqueue клиенту явный stream-end/FIN-фрейм по
   `globalStreamID` (новый flag, напр. `FlagStreamClose`, симметрично существующему
   client→server `FlagFin` в `core`). Вызывать его из точки установки `destClosed`
   (`server/relay_registry.go:621-629` и из uplink-write-error путей §1) — т.к. WS-слот
   обычно жив (§5), сигнал уйдёт сразу, без ожидания RESUME.

3. **Прочитать `destClosed` на RESUME (достроить доктрину `relay_registry.go:139-145`).**
   В `reassociate`/`handleMigrateOrResume` (`server/websocket.go:620`,
   `server/relay_registry.go:732-763`) после дренажа `downBuffer`: если
   `entry.destClosed.Load()` — послать тот же end-of-stream-фрейм (§2) на НОВЫЙ binding.
   Это покрывает редкий случай, когда слот всё-таки умер до отправки сигнала из §2.

4. **Клиент: принять end-of-stream и закрыть стрим.** В роутере downlink
   (`slotReaderWithClient`, диспетчер `FlagData`/control в `client/ws_pool.go`, около
   `:2109`) распознать новый `FlagStreamClose` по `globalStreamID` → `streamMap.Delete`
   + `close(cl.streamChans[id])` (тот же teardown, что `closeStream` в
   `ws_pool.go:3549-3557`). Это и есть точка, где висящий SOCKS5-reader получает EOF и
   стрим рвётся чисто — корень симптома «не восстанавливается».

5. **(Defence-in-depth, опционально) Per-stream downlink-idle watchdog на клиенте.**
   Добавить `streamEntry.lastDownlinkNs` (`client/stream_entry.go:18-46`), штамповать
   при доставке `FlagData`, и в watchdog-тике проверять: стрим с большим
   downlink-молчанием НА ЖИВОМ слоте → инициировать RESUME/teardown. Закрывает класс
   «origin тихо умер, а сервер по любой причине не прислал сигнал» без опоры на
   серверный путь. Можно отложить, если пп.1-4 закрывают наблюдаемый кейс.

Минимально-достаточно для устранения симптома stream=1253: **пункты 1+2+4** (вооружить
флаг на write-death → немедленно послать end-of-stream по живому слоту → клиент рвёт
стрим). Пункты 3 и 5 — добор оставшихся углов.

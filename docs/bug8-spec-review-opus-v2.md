# Bug #8 — Per-Stream Flow Control Design v2 — Adversarial Protocol Review (2nd pass)

**Reviewer role:** adversarial protocol-design reviewer (pre-implementation, 2nd pass)
**Дата:** 2026-05-30
**Спека (v2):** `docs/superpowers/specs/2026-05-30-bug8-flow-control-design.md`
**Отчёт 1-го пасса:** `docs/bug8-spec-review-opus.md` (3 BLOCKER + 5 HIGH + 5 MEDIUM + 3 LOW)
**Задача:** (а) верифицировать закрытие находок 1-го пасса против РЕАЛЬНОГО кода, (б) найти НОВЫЕ дыры, внесённые переписыванием.

---

## Вердикт

**NOT-READY — нужен ещё один пасс.** v2 правильно переориентировал дизайн на WS-путь (B1 закрыт), правильно
развязал downlink-goroutine от отправки (B2 — частично), и правильно поставил credit-gate перед `tc.Read`
(H3 закрыт). НО переписывание внесло **2 новых BLOCKER** в механизме негоциации (§4) — он архитектурно
несовместим с тем, как WS-pool реально устанавливает соединения (per-slot upgrade, ack читается асинхронно,
capability per-session vs per-slot mismatch). Плюс §5.3 содержит **ложное утверждение про неблокируемость**
`EnqueueControl`, которое опровергается кодом (B2 закрыт лишь частично).

---

## Counts по severity

| Severity | Кол-во | Из них NEW |
|---|---|---|
| BLOCKER | 2 | 2 |
| HIGH | 3 | 2 |
| MEDIUM | 4 | 1 |
| LOW | 2 | 0 |

---

## BLOCKER

### NB1 — [NEW] Негоциация §4.2 архитектурно несовместима с WS-pool: ack не читается синхронно, capability per-session vs первый-фрейм-per-slot

**Заголовок:** §4.2 требует, чтобы клиент ПРОЧИТАЛ ack-ответ на первый keepalive и извлёк `effectiveWindow`.
Но `UpgradeToWS` (ws_transport.go:308-566) после отправки первого фрейма (ws_transport.go:512) **немедленно
возвращается** и НЕ читает никакого ответа. Ack (FlagAck от сервера, websocket.go:782) попадает в общий поток
и потребляется АСИНХРОННО позже в `slotReaderWithClient` (ws_pool.go:2578 `ReadMessage`), который не знает про
негоциацию и не выставляет `effectiveWindow`. Дизайн §4.2 описывает синхронный handshake, которого в коде НЕТ.

**Доказательство (проверено в коде):**
- ws_transport.go:512 — `conn.WriteMessage(BinaryMessage, firstFramePayload)`; ws_transport.go:565 — `return nil`.
  Между ними НЕТ ни одного `conn.ReadMessage`. Первый ack читается уже в slot reader (ws_pool.go:2578) после того,
  как `UpgradeToWS` вернул управление и слот помечен ready.
- Сервер на keepalive формирует ack БЕЗ payload: `ack := &core.Chunk{... Flags: core.FlagAck}` (websocket.go:782) —
  `Payload` nil. Чтобы вложить маркер `["FLOWCTL"][effectiveWindow]`, нужно править этот код (ОК, это ожидаемо),
  но на клиенте НЕТ места, которое этот payload прочитает и распарсит как negotiation-ответ.
- `slotReaderWithClient` (ws_pool.go:2555+) — это generic demux: `ReadMessage → decrypt → RouteToStream`. Он не
  выделяет «первый ack после upgrade» и не имеет хука «capability negotiated».

**Худшее последствие — per-slot vs per-session split-brain:** WS-pool делает upgrade на КАЖДОМ слоте независимо
(до 8 слотов, `-max-conns 8`), каждый шлёт свой первый keepalive (ws_transport.go:316 `buildFirstFramePayload`)
по ОДНОЙ И ТОЙ ЖЕ сессии. Сервер же ведёт credit-state и `flowControlEnabled` как **per-WS-session локальную
переменную внутри `runWebSocketSession`** (§6.1, websocket.go:485). Но `runWebSocketSession` запускается на
КАЖДЫЙ WS-conn (websocket.go:463 вызывается из `handleWebSocket` на каждый upgrade). То есть «сессия» в смысле
`runWebSocketSession` ≠ `core.Session`: один `core.Session` обслуживается НЕСКОЛЬКИМИ параллельными
`runWebSocketSession` (по одному на слот). Стрим мигрирует между слотами (Bug#6 sticky) → между РАЗНЫМИ
`runWebSocketSession`-инстансами → между РАЗНЫМИ `credits`-картами. Дизайн §6.1 кладёт `credits` локально в
`runWebSocketSession`, но стрим, родившийся на слоте A (relay в runWebSocketSession-A), при ротации шлёт данные
с того же `streamID`, и его `FlagConnect`/relay могут оказаться на слоте B (runWebSocketSession-B) с ОТДЕЛЬНОЙ
`credits`-картой, где этого стрима нет. WINDOW_UPDATE, пришедший на слот B, не найдёт credit стрима, живущего
в relay слота A. → credit рассинхрон → зависание (ровно тот класс бага, что §7 якобы закрывает).

**Почему 1-й пасс это пропустил:** H4 (1-й пасс) рассматривал потерю update при ротации на КЛИЕНТЕ (pendingDelta
привязан к стриму — ОК). Но 1-й пасс НЕ заметил, что на СЕРВЕРЕ relay-goroutine стрима физически живёт внутри
конкретного `runWebSocketSession` (конкретного WS-conn/слота), а credit-карта локальна этому инстансу. §7 спеки
утверждает «Credit-state на сервере привязан к WS-сессии (не к слоту) — стрим жив, сервер ждёт» — это
**фактически неверно**: relay стрима и его `credits[streamID]` живут в `runWebSocketSession` ОДНОГО WS-conn
(websocket.go:470-834), а WS-conn = слот. Стрим НЕ переживает смену WS-conn на серверной стороне в рамках одной
relay-goroutine — при ротации слота клиент открывает НОВЫЙ FlagConnect на новом conn, и сервер создаёт НОВЫЙ
relay + НОВЫЙ credit в новом `runWebSocketSession`. Дизайн этого не моделирует.

**Фикс дизайна (обязателен перед реализацией):**
1. Решить, синхронная ли негоциация. Если да — `UpgradeToWS` ДОЛЖЕН после первого фрейма сделать
   `conn.ReadMessage()` с дедлайном, распарсить ack-payload, выставить capability ДО старта slot reader. Это
   меняет сигнатуру/поток `UpgradeToWS` и взаимодействие со slot reader (reader не должен «съесть» этот первый ack).
2. Явно определить scope capability: per-`core.Session` (тогда хранить в `Client`, а не per-slot) или
   per-WS-conn. Если per-conn — нужно согласовать на КАЖДОМ слоте отдельно (8 негоциаций на сессию), и credit-state
   на сервере honest per-conn — тогда §7 «стрим переживает ротацию» переписать: стрим НЕ переживает на сервере, при
   ротации это новый relay+credit, и клиентский pendingDelta надо ПЕРЕНОСИТЬ/СБРАСЫВАТЬ согласованно с новым
   server-side credit (иначе клиент думает «уже потребил N», а новый server-credit стартует с полного окна → клиент
   недослёт update → stall на хвосте).
3. Прописать в §6.1, что `runWebSocketSession` — per-WS-conn, и доказать, что credit-карта и relay стрима всегда
   в одном инстансе. Сейчас §6.1 говорит «локальная в runWebSocketSession рядом со streams» — это верно для одного
   conn, но §7 противоречит этому, утверждая привязку к «WS-сессии», переживающей ротацию.

**Статус находки 1-го пасса:** H4 — **partially closed** (клиентская половина закрыта pendingDelta-per-stream;
серверная половина НЕ закрыта и вскрыла этот новый BLOCKER).

---

### NB2 — [NEW] §5.3 утверждает «trySendWindowUpdate неблокирующая через control-путь» — это ЛОЖЬ: EnqueueControl блокирует при полном cap-64

**Заголовок:** §5.3 и §8 строят весь B2-фикс на том, что отправка WINDOW_UPDATE идёт «через `WSAsyncWriter`
control-путь, но **неблокирующая**». Реальный `EnqueueControl` (wsasyncwriter.go:215-231) **БЛОКИРУЕТ** на
`w.control <- ...` когда канал (cap 64) полон — селект только на `case w.control<-...` и `case <-w.done`, БЕЗ
`default`. То есть ровно тот блокирующий путь, что 1-й пасс назвал в B2, остаётся.

**Доказательство (проверено в коде):**
```go
// wsasyncwriter.go:225-230
select {
case w.control <- wsOutboundMsg{msgType: msgType, data: cp}:
    return nil
case <-w.done:
    return ErrWSWriterClosed
}
```
Нет `default:` → при полном `control` (cap 64) горутина блокируется до освобождения слота или закрытия writer'а.
То же у `Enqueue` (wsasyncwriter.go:204-209, cap = bufSize). Клиентский writer создаётся как
`core.NewWSAsyncWriter(conn, 256)` → 256 data + 64 control (ws_transport.go:525, комментарий это подтверждает).

**Последствие:** если credit-sender зовёт `WriteControlMessageForStream` → `EnqueueControl`, и control-канал
полон (массовая отправка update по многим стримам слота + стоящий Run под CF-столлом + pong'и/keepalive'ы тоже
идут в control), credit-sender БЛОКИРУЕТСЯ. Если credit-sender — per-slot goroutine (§5.3), блокировка stop'ит
отправку update для ВСЕХ стримов слота → сервер не пополняет credit → закачки зависают. Это **возврат B2**, просто
перенесённый с downlink-goroutine на credit-sender-goroutine. Спека прямо обещает обратное (I3, §5.3 буллет
«если control-канал (cap 64) полон — НЕ блокируем»), но механизм для этого в коде ОТСУТСТВУЕТ — `EnqueueControl`
такого режима не имеет.

**Фикс дизайна:**
- Либо добавить в `WSAsyncWriter` НОВЫЙ метод `TryEnqueueControl` с `default:` (неблокирующий, возвращает
  «не влезло»), и credit-sender при «не влезло» оставляет pendingDelta накопленным (аддитивность спасает). Это
  надо ЯВНО прописать как изменение в `core/wsasyncwriter.go` в §14 (сейчас там его нет — §14 трогает только
  client/server, не core writer).
- Либо отдельная bounded-очередь у credit-sender'а с собственным неблокирующим enqueue.
- В любом случае §5.3/§8/I3 переписать: «неблокируемость» сейчас декларирована, но не обеспечена ни одним
  существующим API. Это не деталь реализации — это инвариант корректности, на котором держится весь B2-фикс.

**Статус находки 1-го пасса:** B2 — **partially closed**. Идея (Add-only downlink + отдельный sender +
coalescing + Swap) верна и закрывает downlink-половину. Но «неблокирующая отправка» опирается на несуществующий
неблокирующий control-API → сам sender может заблокироваться → B2 воспроизводится на новом акторе. До добавления
`TryEnqueueControl` (или эквивалента) B2 НЕ закрыт полностью.

---

## HIGH

### NH1 — [NEW] §5.3 per-slot credit-sender теряет стрим при ротации слота (миграция стрима ≠ миграция sender'а)

**Заголовок:** Спека вешает credit-sender как per-slot goroutine, «которая проходит активные стримы СЛОТА».
Но pendingDelta привязан к СТРИМУ (`Client.streamFlow[streamID]`, §5.1), а стрим мигрирует между слотами (Bug#6
sticky). Per-slot sender итерирует «стримы своего слота» — но как он узнаёт, какие стримы сейчас на его слоте?
`streamMap` (ws_pool.go:2356) резолвит слот стрима, но обратного индекса «слот → его стримы» в дизайне нет.
В момент миграции стрим может «выпасть» между sender'ом старого слота (уже не считает его своим) и sender'ом
нового слота (ещё не подхватил) → его pendingDelta никто не шлёт → stall на хвосте закачки.

**Доказательство:**
- §5.1: `pendingDelta` в `Client.streamFlow[streamID]` (per-stream).
- §5.3: «per-slot credit-sender goroutine ... проходит активные стримы СЛОТА».
- ws_pool.go:2355-2373 `WriteMessageForStream` резолвит ТЕКУЩИЙ слот стрима через `streamMap`, но это
  stream→slot. Обратной карты slot→streams в показанном коде нет; per-slot sender'у она нужна, а её lifecycle
  при миграции — источник гонки.
- §7 говорит «следующий тик дошлёт через новый слот стрима» — но это работает только если КАКОЙ-ТО sender
  итерирует этот стрим. Если sender привязан к слоту, а стрим переехал, ни старый (стрим уже не его), ни новый
  (если индекс slot→streams обновляется лениво) могут его не увидеть в окне миграции.

**Фикс дизайна:** Сделать credit-sender **per-client** (одна goroutine, итерирует `Client.streamFlow` — карту
ВСЕХ стримов, независимо от слота) ИЛИ **per-stream** (sender живёт ровно столько, сколько стрим). Per-client
проще и устраняет проблему миграции полностью: sender берёт streamID, резолвит текущий слот через
`WriteMessageForStream`/`WriteControlMessageForStream` (которые сами следуют за миграцией), шлёт. Дизайн §5.3
прямо называет «per-slot» как выбранный вариант — это и есть дыра. §14 тоже фиксирует «per-slot credit-sender
goroutine lifecycle в ws_pool.go» — переписать на per-client.

**Статус находки 1-го пасса:** это уточнение/расширение H4 в новой форме — **NEW issue**, порождённый выбором
«per-slot sender» в v2 (1-й пасс sender'а ещё не специфицировал).

### NH2 — [NEW] Старый сервер на keepalive с непустым payload: поведение НЕ проверено до бита, риск отказа auth

**Заголовок:** §4.3 утверждает «старый сервер получает keepalive с непустым payload — игнорирует лишние байты
(keepalive payload и так не парсился), отвечает обычным ack». Проверка кода это **в основном подтверждает**, но
с оговоркой, которую дизайн не учёл: первый фрейм проходит через `authenticateFirstFrame`, а не через обычный
keepalive-case, и там есть проверка длины + seq + flags. Нужно убедиться, что добавление 11-байтного маркера
(`"FLOWCTL"`(7)+window(4)) в payload первого keepalive НЕ ломает `authenticateFirstFrame` старого сервера.

**Доказательство (проверено в коде):**
- `authenticateFirstFrame` (websocket.go:144): читает `[token][encrypted_chunk]`, декриптит, проверяет
  `len(data) < tokenLen+core.MinChunk` (websocket.go:155), `AcceptSeqNum` (168), `chunk.Flags != FlagKeepalive`
  (172). **payload chunk'а не инспектируется вообще** — маркер в payload не нарушит ни одну проверку. ✅
- Обычный keepalive-case (websocket.go:781) тоже payload не читает. ✅
- НО: `MinChunk` — это минимум; маркер увеличивает payload, что меняет РАЗМЕР зашифрованного первого фрейма.
  `firstFrameReadLimit = 8*1024` (websocket.go:126) — 11 байт payload'а внутри лимита. ✅
- Вывод: старый сервер действительно ответит обычным ack без маркера, клиент увидит отсутствие маркера → off.
  Compat-логика КОНЦЕПТУАЛЬНО верна.

**Почему всё равно HIGH, а не «verified closed»:** дизайн НЕ зафиксировал, что маркер кладётся в **payload
зашифрованного chunk'а** (а не в `[token]`-префикс или между token и chunk). §4.2 формулирует «в payload первого
FlagKeepalive» — это надо прибить гвоздями к `core.Chunk.Payload`, потому что `buildFirstFramePayload`
(ws_transport.go:316) строит `[token][encrypted_chunk]`, и есть соблазн вложить маркер не туда. Если маркер
попадёт в незашифрованную часть — это новый cleartext DPI-признак (ровно то, чего H1 избегал). Требуется явная
строка спеки: «маркер — внутри `Chunk.Payload` keepalive-чанка, шифруется вместе с ним; token-префикс и формат
кадра не меняются».

**Статус находки 1-го пасса:** B3/H1 — **verified closed по сути** (старый сервер не падает, ключи не трогаются,
cleartext не добавляется ЕСЛИ маркер в зашифрованном payload). Остаётся задокументировать точное место маркера.

### NH3 — H5 half-close: путь для update подтверждён кодом, но §8 опирается на §5.3-отправку, которая под NB2/NH1

**Заголовок:** §8 верно утверждает, что downlink-goroutine переживает half-close (tcp.go:679-685: при
`!socks5Replies && hasWriteCloseDetector` и half-close uplink-goroutine `return`, downlink продолжает с tcp.go:717).
WS uplink-направление слота физически независимо от appConn half-close — это код подтверждает. НО §8 говорит
«Отправитель WINDOW_UPDATE — credit-sender (§5.3)», а §5.3 содержит NB2 (блокирующий control) и NH1 (per-slot
теряет стрим). То есть half-close сам по себе ОК, но отправка update на половинно-закрытом стриме наследует оба
дефекта §5.3.

**Доказательство (проверено в коде):**
- tcp.go:679-685: half-close → uplink `return`, downlink живёт. ✅
- tcp.go:802-810: `peerFullClose` закрывает только на полный Close, не на CloseWrite — half-close downlink жив. ✅
- §5.2-хук `OnStreamConsumed` стоит после `conn.Write(data)` (tcp.go:778) в downlink-goroutine — она жива при
  half-close, значит Add продолжается. ✅
- Проблема только в том, КТО и КАК шлёт накопленное (NB2/NH1).

**Фикс дизайна:** После исправления NB2 (неблокирующий control) и NH1 (per-client sender) — H5 закрыт. Тест
§9.6 обязателен. Понизил бы до verified-closed, если бы §5.3 не был дефектен.

**Статус находки 1-го пасса:** H5 — **verified closed для самого half-close инварианта**; зависит от закрытия NB2/NH1.

---

## MEDIUM

### M-rot — [NEW] §7 watchdog Swap-обнуление: гонка с OnStreamConsumed корректна, НО клиент/сервер credit-rebase при ротации не определён

**Заголовок:** §7 + §5.3 Swap-логика (atomic Swap забирает delta, при неудаче отправки delta остаётся) —
сама по себе race-free против параллельного `pendingDelta.Add` (атомики). Swap забирает текущее значение,
конкурентный Add просто добавит к остатку (0 после успешного swap) — ни потери, ни задвоения. ✅ Это корректно.
НО при серверной ротации (NB1): новый server-side credit стартует с полного окна, а клиент уже «потребил» часть
на старом relay. Если клиент НЕ ребейзит pendingDelta при миграции — рассинхрон счётчиков (не потеря байт, но
неоптимальный credit). Дизайн не специфицирует ребейз.

**Доказательство:** §5.3 `Swap`/`CompareAndSwap` — корректная atomic-семантика, гонок нет. Проблема — на стыке
с NB1 (server credit per-conn, не переживает ротацию).

**Фикс:** после решения NB1 определить: при миграции стрима на новый WS-conn клиент сбрасывает pendingDelta в 0
(новый server-credit = полное окно, ничего ещё не «потреблено» в терминах нового relay). Прописать явно.

### M1 — кламп `available <= 2*window` (§6.6) — verified closed

waitForCredit стоит ПЕРЕД tc.Read → кламп не теряет байт (target не читается без credit). §6.6 документирует это
+ метрика `credit_wait_seconds_total`. Соответствует коду (relay tc.Read на websocket.go:754 — credit-gate
вставляется перед ним). **verified closed.**

### M2 — cap(incomingCh) ↔ окно (§5.5) — verified closed

§5.5 клампит окно так, что `effectiveWindow/minChunk <= cap(incomingCh)`. cap incomingCh = 512
(`make(chan []byte, 512)`, client.go:695 — подтверждено). При окне 1 MiB / ~12 KiB ≈ 85 ≪ 512. Кламп — страховка
от env-переконфига. **verified closed.** Замечание: §5.5 называет cap «incomingCh», в коде это `streamChans[id]`
(RegisterStream, client.go:695) — терминология, не баг.

### M4/M5 — cond signal/closed + teardown leak (§6.5) — verified closed по дизайну

§6.5 правильно: `close`+`Signal` под `c.mu` (happens-before, нет потерянного сигнала); на teardown (websocket.go:827-834
цикл по streams) для каждого credit вызвать close; relay defer (websocket.go:742-751) + FlagFin case (websocket.go:772)
закрывают credit. `done`-интеграция через закрытие всех credits, не через Cond на канал — корректно для `sync.Cond`.
Соответствует структуре кода (cleanup на websocket.go:827-834 существует, relay defer на 742-751 существует, FlagFin
на 772-779 существует). **verified closed по дизайну** (реализация должна точно следовать).

---

## LOW

### L1 — ParseWindowUpdate ≥6 байт (§3, §9.1) — verified closed
Дизайн требует error (не panic) при len<6, как `ParseUDPChunk`. 0x0A свободен (последний флаг 0x09, chunk.go:22).
**verified closed.**

### L2 — sessions_active counter (§10) — verified closed
§10 заменил gauge 0/1 на `shadowlink_flow_sessions_active`. **verified closed.**

### L3 — StreamID=0 (§3) — verified closed
§3 явно не использует StreamID=0 для session-wide; session-wide отложен (YAGNI). Соответствует коду
(StreamID=0 legacy/poll — chunk.go NewConnectChunk, client.go PollStreams). **verified closed.**

---

## Карта закрытия находок 1-го пасса (итог)

| Находка 1-го пасса | Статус | Где |
|---|---|---|
| B1 (неверный путь POST→WS) | **verified closed** | §1/§6 переписаны под runWebSocketSession; код подтверждает reader-loop@555, relay@742-770, switch@591 |
| B2 (uplink-deadlock) | **partially** | downlink Add-only ✅; но «неблокирующий control» опирается на несуществующий API → NB2 |
| B3 (тихий разнобой версий) | **verified closed** | §4.3 единый источник истины; default в switch (§4.4); authenticateFirstFrame не падает |
| H1 (ClientHello/cleartext bid) | **verified closed** | §4 модель (b): ключи v1 не трогаются (handshake.go подтверждает protoVersion в DeriveSessionKeys — не меняется); маркер в зашифрованном payload (уточнить — NH2) |
| H2 (tunnel.Outgoing bottleneck) | **verified closed** | §6.4 WS-путь не имеет session-wide bottleneck на чтении; POST out of scope (§12) |
| H3 (общий writer) | **verified closed** | §6.2 credit-gate ПЕРЕД tc.Read@754 (I4) |
| H4 (потеря update при ротации) | **partially** | клиент pendingDelta-per-stream ✅; сервер credit per-conn не переживает ротацию → NB1; per-slot sender → NH1 |
| H5 (half-close) | **verified closed** (инвариант) | §8; tcp.go:679-685/802-810 подтверждают; зависит от NB2/NH1 для отправки |
| M1 (кламп) | **verified closed** | §6.6 |
| M2 (cap↔окно) | **verified closed** | §5.5 |
| M3 (DPI uplink-всплеск) | open-subquestion | §16 jitter обязателен, пиггибэк в план — приемлемо |
| M4 (cond signal/closed) | **verified closed** | §6.5 |
| M5 (teardown leak) | **verified closed** | §6.5 |
| L1/L2/L3 | **verified closed** | §3/§9.1/§10 |

**Регрессий (закрытое → снова открыто): нет.** Все НОВЫЕ находки (NB1, NB2, NH1, M-rot) порождены конкретными
проектными решениями v2 (per-slot sender, синхронная негоциация поверх асинхронного reader'а, опора на
несуществующий неблокирующий control-API), а не откатом ранее закрытого.

---

## Что обязательно перед реализацией (3-й пасс не нужен, если эти 4 пункта закрыты в спеке)

1. **NB1** — переопределить scope negotiation и server-side credit как honest per-WS-conn; переписать §7, что
   стрим на сервере НЕ переживает ротацию (новый relay+credit), и определить client-side rebase pendingDelta при
   миграции (M-rot). Решить, синхронно ли читается ack в `UpgradeToWS` (нужен ReadMessage + interplay со slot reader).
2. **NB2** — добавить `TryEnqueueControl` (неблокирующий, с `default:`) в `core/wsasyncwriter.go` и в §14;
   переписать §5.3/§8/I3 на этот API. Без него B2 воспроизводится.
3. **NH1** — credit-sender сделать **per-client** (итерирует `Client.streamFlow`), не per-slot; отправка через
   `WriteControlMessageForStream` (следует за миграцией).
4. **NH2** — зафиксировать в §4.2, что маркер лежит в `Chunk.Payload` зашифрованного keepalive (не в token-префиксе).

Остальное (M1/M2/M4/M5/L1-3/H2/H3/H5-инвариант) — verified closed, в реализацию как есть.

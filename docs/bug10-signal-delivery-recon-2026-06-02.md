# Bug #10 — Signal-delivery recon: can the server deliver CONNECT_FAIL for a streamID over ANY live WS slot of the client session?

Date: 2026-06-02
Scope: architectural reconnaissance only (no fix). Server Go code in `D:\NIXAVPN\shadowlink`.

## TL;DR — ВЕРДИКТ

**«Слать CONNECT_FAIL по ЛЮБОМУ живому слоту сессии» — НЕ реализуемо as-is. С важной оговоркой: механически близко, но блокируется ДВУМЯ независимыми причинами на обеих сторонах.**

Доставка управляющего фрейма для `streamID` по слоту B (другому, чем slot A, на котором стрим открыт) проваливается потому, что:

1. **Сервер: НЕТ реестра «clientID → все живые WS-writer'ы».** Сервер видит слоты как N независимых сессий, проиндексированных по `session.ID`, а не сгруппированных по clientID. Нет структуры, по которой можно взять «другой живой writer того же клиента». Reverse-индексы что есть (`ClientAuth.clientSession map[string]uint32`, `activeSessions map[string][]uint32`) хранят **session IDs для device-limit учёта**, а не `*core.Session`/`*WSAsyncWriter`, и `clientSession` вообще 1:1 (перетирается на reconnect). Реестр стримов `relayRegistry.byClient` индексирует по `(clientID, streamID)`, но хранит ОДИН binding на стрим (`relayEntry.bound` = одна `{session, writer}` пара), а не список всех writer'ов клиента.

2. **Клиент: W5 stale-frame guard ДРОПАЕТ фрейм, пришедший не на «свой» слот.** Даже если бы сервер физически послал фрейм для `streamID` по слоту B, клиентский slot-reader на слоте B сбросит его ДО роутинга, потому что `streamMap[streamID].slotIdx != idxB`.

Шифрование per-slot — НЕ блокер сам по себе (клиент расшифрует на B ключом B), и demux по streamID на клиенте ГЛОБАЛЕН (slot-agnostic) — но W5-guard стоит раньше demux и режет именно cross-slot доставку.

**Реально доступный механизм доставки сигнала при мёртвом слоте A — см. раздел «Что доступно».**

---

## 1. Модель «клиентская сессия → её WS-слоты» на сервере

КАЖДЫЙ WS-слот клиента = ОТДЕЛЬНАЯ серверная `*core.Session` со своим `session.ID`, своими `SendKey/RecvKey`, своим `MigrateNonce`, своим anti-replay окном.

- WS-upgrade → `authenticateFirstFrame` (server/websocket.go:144) резолвит слот в `*core.Session` по hint первого фрейма (`findSessionByHint`, websocket.go:159). Это разные session.ID для разных слотов одного клиента (каждый слот делал свой handshake POST → свой `SessionManager.Create`, core/session.go:530).
- `runWebSocketSession` (websocket.go:665) держит локально: `session` (этого слота), `writer *core.WSAsyncWriter` (websocket.go:708 — этого слота, обёрнутый вокруг `conn` этого слота), локальные `streams map[uint16]*wsStream` и `credits`.
- Связь clientID известна только через `h.tunnels[session.ID].ClientID` (websocket.go:692-696; tunnel создаётся в handler.go:627-634, keyed по `session.ID`).

**НЕТ обратного индекса `clientID → []*core.Session` или `clientID → []*WSAsyncWriter`.** Чтобы перечислить «все живые слоты clientID», сервер сейчас не имеет структуры. `h.tunnels` (handler.go:84, `tunnelsMu`) — `map[sessionID]*Tunnel`; чтобы собрать все слоты клиента надо просканировать всю map с фильтром `t.ClientID == X` (O(всех сессий), и tunnel НЕ хранит writer).

Ключевые ссылки:
- `Tunnel{ ClientID string }` — server/handler.go:118-120
- `h.tunnels[session.ID] = tunnel` — server/handler.go:633-634
- writer создаётся per-session — server/websocket.go:708
- `ClientAuth{ activeSessions map[string][]uint32; clientSession map[string]uint32 }` — server/ratelimit.go:97-99 (учёт device-limit, не транспорт)

## 2. relayEntry.bound — один слот на стрим. Как RESUME находит новый слот.

`relayEntry.bound` (server/relay_registry.go:114) — `atomic.Pointer[binding]`, где `binding{session, writer}` (relay_registry.go:32-35) = ОДНА активная пара. Это НЕ список writer'ов клиента.

RESUME НЕ «ищет новый слот» на сервере — **слот выбирает КЛИЕНТ**. Клиент при смерти слота A сам шлёт `FlagResume[streamID][proof]` по уже-живому слоту B (своего пула). Этот фрейм приходит на reader-loop слота B, и `handleMigrateOrResume` (websocket.go:570) вызывает `entry.reassociate(session_B, writer_B, ...)` (websocket.go:620, relay_registry.go:732) — т.е. binding перенаправляется на ту пару `{session,writer}`, на которой ПРИШЁЛ RESUME. Сервер пассивен: он не выбирает слот и не знает заранее, какие слоты у клиента живы.

Вывод: пула доступных серверных writer'ов нет. «Новый слот» = тот, по которому клиент инициативно прислал RESUME.

## 3. Шифрование per-slot? demux по streamID per-slot или глобальный?

- **Шифрование PER-SLOT.** Каждый фрейм шифруется ключом своей сессии: downlink-relay `enqueueDownFrame` шифрует под `b.session.EncryptChunk` (relay_registry.go:825-829), CONNECT_FAIL в websocket.go шифруется под `session.EncryptChunk` локального слота (websocket.go:878-880, 924-927, 954-957). Клиент расшифровывает per-slot: `slot.session.DecryptChunkSafe(data)` (ws_pool.go:3215-3220).
  → Если сервер пошлёт фрейм по слоту B, он обязан зашифровать его ключом session_B. Это ОК — клиент на слоте B расшифрует ключом B.

- **demux по streamID на клиенте — ГЛОБАЛЬНЫЙ (slot-agnostic).** После расшифровки клиент роутит по streamID в Client-глобальные map'ы, НЕ привязанные к слоту:
  - `RouteToStream(streamID,…)` → `cl.streamChans[streamID]` (client.go:1009-1019)
  - `RouteToStreamSeq(streamID, seq, …)` → `cl.streamFramesChans[streamID]` (client.go:1158-1169)
  - `streamChans`/`streamFramesChans` — поля `Client`, под общим `streamMu` (client.go:142-147), один на весь пул. streamID глобально уникален в пределах clientID (см. §5).
  → Значит ЕСЛИ фрейм дойдёт до RouteToStream*, он попадёт в правильный стрим независимо от слота. Сама по себе крипта per-slot demux'у НЕ мешает.

- **НО: W5 stale-frame guard режет cross-slot ДО demux.** В slot-reader'е слота B (ws_pool.go:3252-3262):
  ```
  if v, ok := p.streamMap.Load(streamID); ok {
      e := v.(*streamEntry)
      if e.slotIdx != idx {        // streamID привязан к слоту A, пришло на B
          Stats.StaleFrameDroppedTotal.Add(1)
          continue                  // DROP — до RouteToStream*
      }
      ...
  }
  ```
  `streamMap` (client ws_pool.go:1192) — `map[uint16]*streamEntry`, `streamEntry.slotIdx` = слот, на который стрим назначен/ребинднут (`AssignStream` ws_pool.go:2739, `rebindStreamToSlot` после RESUME ws_pool.go:3724). Пока RESUME не перепривязал streamID на B, фрейм для него, прилетевший на B, ДРОПАется. Это и есть архитектурный замок: cross-slot доставка для ещё-не-мигрированного стрима запрещена на клиенте намеренно (anti stale-frame после drain-teardown reuse, спец 2026-05-20 §2.4.1).

## 4. Существует ли «послать фрейм по любому/всем живым слотам клиента»?

НЕТ механизма per-client broadcast/anycast управляющего фрейма.

- Keepalive/ping — per-session (websocket.go:762-776, на свой writer).
- `BroadcastStreamClose` — это КЛИЕНТСКИЙ механизм session-wide teardown (sendSlotSessionFIN streamID=0, ws_pool.go:1980), не серверный per-client fan-out управления.
- Все серверные отправки идут через локальный `writer` конкретного `runWebSocketSession`. Нет кода, итерирующего «все writer'ы clientID».
- Доставка по другому слоту возможна только реактивно — когда клиент сам инициирует RESUME по тому слоту и приносит туда свой `writer` (см. §2). Сервер не может ПЕРВЫМ постучать на слот B.

## 5. streamID — глобален per-clientID, demux принимает с любого слота?

- streamID **глобально уникален в пределах clientID** (а не per-slot). Клиент выделяет его из общего счётчика, проверяя ОБА глобальных map'а (`streamChans` + `streamFramesChans`, client.go:719-731). relayRegistry на сервере keyed по `(clientID, streamID)` (relay_registry.go:227, find/add) — подтверждает глобальность по clientID.
- Клиентский demux (`RouteToStream*`) по streamID берёт фрейм с любого слота (§3) — НО только после прохождения W5-guard, который для ещё-не-ребиндженного streamID на «чужом» слоте делает `continue`/drop (§3).

---

## Что РЕАЛЬНО доступно для доставки сигнала при мёртвом слоте A

Прямой server-push «CONNECT_FAIL по слоту B» закрыт W5-guard'ом + отсутствием per-client writer-реестра. Доступные пути:

### Вариант 1 (наиболее «в зерно» существующей архитектуры) — пере-использовать RESUME-канал и destClosed-флаг.
Механика уже есть: при смерти origin relayLoop ставит `e.destClosed.Store(true)` если стрим был orphaned (relay_registry.go:627-629), и комментарии говорят, что «a subsequent RESUME flushes the remaining downBuffer and then signals end-of-stream» (relay_registry.go:139-145). Т.е. сигнал «dest умер» уже задуман к доставке ИМЕННО в момент RESUME — когда клиент сам приносит живой слот B и делает `rebindStreamToSlot` (после чего W5-guard пропускает фреймы на B). Bug #10 — это, по сути, «destClosed → не молчать, а на reassociate дослать stream-end/CONNECT_FAIL-эквивалент». Здесь шифрование/demux уже корректны (фрейм идёт по слоту, который клиент только что привязал). Точки: `reassociate` (relay_registry.go:732 — место дослать FIN/fail после drain), `destClosed` (relay_registry.go:145).
- Ограничение: сигнал доставится только КОГДА клиент инициирует RESUME. Если клиент не делает RESUME (стрим не «sticky»/idle), нужен триггер на клиенте, чтобы он спросил.

### Вариант 2 — добавить серверный per-clientID реестр writer'ов + ослабить W5-guard для control-фреймов.
Чтобы реально слать «по любому живому слоту», нужно ДВА новых куска:
(a) сервер: индекс `clientID → []{session,writer}` живых слотов (новая структура, поддерживаемая в authenticateFirstFrame attach / detach defer, websocket.go:188-197 / 522-539) — чтобы выбрать живой слот B и зашифровать под session_B;
(b) клиент: разрешить control-фреймам (seq==0 CONNECT_FAIL для streamID) проходить W5-guard на «чужом» слоте — например, не дропать, а позволить RouteToStreamSeq доставить управляющий сигнал стриму глобально (demux уже глобален, §3).
Это самый «прямой» ответ на вопрос, но требует правок на ОБЕИХ сторонах (новый реестр + явное исключение в stale-guard) — то, что в постановке вопроса описано как «реализуемо только если есть реестр + общий demux». Общий demux ЕСТЬ, реестра НЕТ, guard МЕШАЕТ.

### Вариант 3 (минимальный, без cross-slot доставки) — клиент сам обнаруживает мёртвый слот A.
Клиент уже детектит смерть слота (`handleSlotDeath`, `resumeStreamOnDeath`, ws_pool.go:3203/3690) и для sticky-стримов делает RESUME. Bug #10 можно закрыть полностью на клиенте: при смерти слота A, на котором висел стрим, для которого dest на сервере уже мёртв — клиент при попытке RESUME получит ответ сервера, отражающий destClosed (см. Вариант 1), и закроет SOCKS-conn с ошибкой. Сервер тогда ничего не шлёт по «чужому» слоту — он лишь честно отвечает на RESUME клиента.

## Рекомендация

Вопрос «по ЛЮБОМУ живому слоту» в чистом виде = **Вариант 2** и он реализуем только с новым per-clientID writer-реестром на сервере + исключением в клиентском W5-guard. «Из коробки» это НЕ работает (нет реестра; guard дропает; крипта per-slot — решаемо шифрованием под session выбранного слота).
Архитектурно дешевле и «в зерно» — **Вариант 1** (RESUME-инициированная доставка через уже существующий `destClosed`/`reassociate` контур): доставка происходит по слоту, который клиент сам привязал, поэтому ни реестр, ни обход guard не нужны. Цена — сигнал привязан к моменту RESUME, а не «немедленный server-push».

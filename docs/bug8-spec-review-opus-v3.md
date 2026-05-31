# Bug #8 — Per-Stream Flow Control Design v3 — Adversarial Protocol Review (3rd / final pass)

**Reviewer role:** adversarial protocol-design reviewer (pre-implementation, final pass)
**Дата:** 2026-05-30
**Спека (v3):** `docs/superpowers/specs/2026-05-30-bug8-flow-control-design.md`
**Отчёт 2-го пасса:** `docs/bug8-spec-review-opus-v2.md` (2 BLOCKER NB1/NB2 + 2 HIGH NH1/NH2 + M-rot)
**Задача:** проверить против КОДА, что 5 пунктов 2-го пасса реально закрыты и что правки v3 не внесли новых дыр.

---

## Вердикт

**NOT-READY — 1 NEW BLOCKER (NV1).** Четыре из пяти пунктов 2-го пасса в v3 закрыты КОРРЕКТНО и
подтверждены кодом (NB2/NH1/NH2/M-rot — verified; архитектурная часть NB1 — verified). НО центральная
посылка §4.2/§4.5 — «сервер отвечает FLOWCTL-ack в ответ на первый keepalive» — **опровергнута кодом**:
сервер физически НЕ отвечает на первый keepalive ничем. `authenticateFirstFrame` потребляет первый кадр
и возвращает session БЕЗ отправки ack; keepalive-ack-ветка reader-loop'а (websocket.go:781) до первого
keepalive НЕ доходит. Синхронное чтение §4.5 повиснет до таймаута на КАЖДОМ слоте → +2s на старт слота
и flow control НИКОГДА не включится. Это ровно тот «потенциальный BLOCKER», который указан в фокусе
задачи — он РЕАЛЕН. Механизм негоциации надо переспроектировать (сервер ДОЛЖЕН явно слать ack-ответ на
первый keepalive). После этого — READY.

---

## Counts по severity

| Severity | Кол-во | Из них NEW в v3 |
|---|---|---|
| BLOCKER | 1 | 1 |
| HIGH | 0 | 0 |
| MEDIUM | 2 | 1 |
| LOW | 1 | 0 |

Статус пунктов 2-го пасса: NB1 — **частично закрыт** (архитектура верна, но механизм ack ложен → NV1);
NB2 — **verified closed**; NH1 — **verified closed**; NH2 — **verified closed**; M-rot — **verified closed**.

---

## BLOCKER

### NV1 — [NEW] §4.2/§4.5: сервер НЕ отвечает ack'ом на первый keepalive — синхронное чтение повиснет, flow control не включится

**Заголовок:** §4.2 утверждает: «Сервер … подтверждает в ack-ответе на keepalive:
`Chunk{Flags:FlagAck, Payload:["FLOWCTL"][effectiveWindow]}`», а §4.5 строит на этом синхронное
`conn.ReadMessage()` в `UpgradeToWS`. **Проверка кода доказывает, что сервер на ПЕРВЫЙ keepalive не
отвечает вообще** — ни ack'ом, ни чем-либо. Синхронное чтение §4.5 заблокируется на
`negotiationAckTimeout` (2s) на каждом слоте, и поскольку ack не придёт, `flowControlEnabled` НИКОГДА
не выставится в true → весь flow control мёртв, плюс старт каждого слота замедляется на 2s.

**Доказательство (по коду, верь коду):**
- `authenticateFirstFrame` (server/websocket.go:144-203) — ЕДИНСТВЕННЫЙ потребитель первого кадра:
  `conn.ReadMessage()` (websocket.go:149) → decrypt → AcceptSeqNum → проверка `Flags != FlagKeepalive`
  (websocket.go:172) → CAS WSAttached → **`return session` (websocket.go:202). НИ ОДНОЙ отправки
  обратно клиенту в этой функции нет.** Единственный write-путь на провал — `fakeAckAndClose`
  (websocket.go:214), который шлёт мусорный ack и закрывает conn. На УСПЕХ ack не шлётся.
- `handleWebSocket` после успешного auth (websocket.go:440-463): `SetReadLimit(256*1024)` → ставит
  defer на WSAttached → `runWebSocketSession(conn, session)`. Опять — никакой отправки клиенту.
- Внутри `runWebSocketSession` reader-loop (websocket.go:554-589) делает СВОЙ `conn.ReadMessage()` для
  СЛЕДУЮЩИХ кадров. Первый keepalive уже потреблён в `authenticateFirstFrame` и в этот цикл НЕ попадает.
- Keepalive-ack-ветка `case core.FlagKeepalive` (websocket.go:781-785) шлёт `FlagAck` — но она
  срабатывает ТОЛЬКО для keepalive'ов, прочитанных reader-loop'ом, т.е. для ВТОРОГО и далее. **Первый
  keepalive до неё не доходит by design** (его съел authenticateFirstFrame).

**Следствие точно как в фокусе задачи:** клиентский §4.5 `conn.ReadMessage()` (вставленный между
ws_transport.go:519 и :525) не получит ничего. Через 2s — `SetReadDeadline` timeout. Дизайн §4.5
говорит «иначе (старый сервер: ack без маркера / любой не-FLOWCTL фрейм): flowControlEnabled=false» —
но таймаут это НЕ «ack без маркера», это полное отсутствие кадра, и оно настигнет **и новый, и старый**
сервер одинаково. То есть FLOWCTL не включится ни против какого сервера + регрессия старта слота на 2s.
(Замечу: на 256-байтном fakeAck старый/мисматч-сервер всё же шлёт кадр — но это ТОЛЬКО на провал auth,
т.е. когда слота уже нет; на успешном auth кадра нет ни у старого, ни у нового сервера.)

**Почему 2-й пасс это не добил:** NB1 верно потребовал «синхронно ли читается ack в UpgradeToWS (нужен
ReadMessage + interplay со slot reader)», но НЕ проверил, ПОРОЖДАЕТ ли сервер этот ack на первый
keepalive вообще. v3 «починил» клиентскую сторону (синхронное чтение) поверх несуществующего серверного
ответа.

**Фикс дизайна (обязателен перед реализацией):** сделать ack-ответ на первый keepalive ЯВНЫМ серверным
действием. Варианты:
1. **(рекомендуется)** `authenticateFirstFrame` (или `handleWebSocket` сразу после её успеха, до
   `runWebSocketSession`) при обнаружении FLOWCTL-маркера в payload первого keepalive формирует и
   синхронно пишет ack-кадр `Chunk{Flags:FlagAck, Payload:["FLOWCTL"][effectiveWindow]}` через
   `session.EncryptChunk` + `conn.WriteMessage` ДО старта async writer'а/reader-loop'а — симметрично
   тому, что клиент пишет первый кадр синхронным `conn.WriteMessage` до создания writer'а. Тогда §4.5
   синхронное чтение получает кадр гарантированно.
2. Если FLOWCTL-маркера НЕТ (старый/незаявивший клиент) — сервер НЕ шлёт ack (как сейчас), а клиент
   тоже НЕ читает (env off / маркер не послан) — поток не меняется, регрессии 2s нет. Критично: §4.5
   уже это предусматривает («Если клиент НЕ шлёт маркер — чтение ack пропускается полностью»), значит
   синхронное чтение делается ТОЛЬКО когда клиент сам послал маркер. Тогда «старый сервер + клиент
   послал маркер» — единственный плохой случай: старый сервер маркер проигнорирует и ack НЕ пришлёт →
   клиент повиснет на 2s и решит off. Это приемлемо для compat ТОЛЬКО если 2s-штраф разовый на слот и
   логируется; но лучше уменьшить `negotiationAckTimeout` (напр. 500ms) ИЛИ не блокировать поток
   ожидания — см. под-вопрос ниже.
3. **Зафиксировать в §4.2 и §4.5**, что (а) сервер на успешный first-keepalive-с-маркером ОБЯЗАН
   синхронно эмитить FLOWCTL-ack ДО reader-loop'а; (б) этот ack — единственный кадр, который читает
   §4.5; (в) slot reader стартует строго после (что код УЖЕ гарантирует — см. NV-verified ниже).

**Под-вопрос для плана (не блокер сам по себе):** «клиент послал маркер, сервер старый» даёт 2s-stall
на слот. Решение: либо короткий дедлайн (≤500ms) + явная метрика `flow_negotiation_timeout_total`,
либо negotiation off-by-default до подтверждения, что прод-сервер всегда новее клиента (на pl1 это
управляемо — деплой сервера первым). Зафиксировать в плане роллаута.

---

## Verified closed (пункты 2-го пасса, подтверждённые кодом)

### NB1 (архитектурная часть) — VERIFIED: стрим НЕ мигрирует между слотами/сессиями в пределах своего streamID
- `AssignStream` (ws_pool.go:2142) вызывается ОДИН раз на стрим; на повторный вызов с тем же streamID —
  WARN + early return (ws_pool.go:2213-2222). `streamMap.Store` — единственный (ws_pool.go:2224).
- `streamEntry.slotIdx` НИГДЕ не переписывается: grep по `slotIdx` (строки 2237/2251/2265/2311/2331/
  2361/2389/2704/2711/2924) — все READ, ни одного write кроме `newStreamEntry(minIdx)` при Store.
- `WriteMessageForStream`/`WriteControlMessageForStream` (ws_pool.go:2355/2383) принимают `slotReady` И
  `slotDraining` — стрим продолжает идти по СВОЕМУ исходному слоту, пока тот дренируется (Bug#6 sticky),
  и умирает вместе с ним. Новый SOCKS-конект → новый `NextStreamID` (client.go:669) → новый
  `AssignStream` → новый слот = новый streamID.
- **Вывод:** §4.2 «1 слот = 1 core.Session = 1 conn = 1 runWebSocketSession; стрим не мигрирует на
  сервере» — ФАКТИЧЕСКИ ВЕРНО. credits-карта per-`runWebSocketSession` (§6.1) и per-client sender,
  резолвящий текущий слот (§5.3), — корректны. M-rot снят верно: ребейз не нужен, т.к. стрим не меняет
  слот в пределах своего streamID. **Эта часть NB1 закрыта.** Открытым остаётся ТОЛЬКО механизм ack (NV1).

### NB2 — VERIFIED closed: TryEnqueueControl добавляется чисто
- `EnqueueControl` (wsasyncwriter.go:215-231) действительно БЛОКИРУЕТ: `select { case w.control<-…;
  case <-w.done }` без `default`. Подтверждено.
- `control chan wsOutboundMsg` cap 64 (wsasyncwriter.go:70). Добавить `TryEnqueueControl` с `default:`
  тривиально и чисто — отдельный метод, та же структура, не трогает приоритетную семантику `Run()`
  (control по-прежнему дренируется первым в Phase 1, wsasyncwriter.go:98-108). Дроп при полном control
  безопасен — additive pendingDelta дошлёт. §14 уже фиксирует новый метод в core/wsasyncwriter.go.
- Замечание (MV2 ниже): WINDOW_UPDATE делит 64-слотовый control-канал с pong/keepalive. Pong идёт через
  блокирующий `EnqueueControl` (ws_transport.go:542) и имеет приоритетный drain — не голодает. Но при
  массовом WINDOW_UPDATE через Try возможны частые дропы update'ов под нагрузкой; additive + watchdog
  (§7) это покрывают. Не блокер.

### NH1 — VERIFIED closed: per-client sender через WriteControlMessageForStream следует за стримом
- `WriteControlMessageForStream` (ws_pool.go:2383) резолвит ТЕКУЩИЙ слот стрима через `streamMap` →
  `slot.transport.WriteControlMessage` → `EnqueueControl` (ws_transport.go:802-811). Поскольку стрим не
  мигрирует (NB1-verified), «текущий слот» = «исходный слот» весь срок жизни. Per-client sender,
  итерирующий `Client.streamFlow` и шлющий через этот метод, корректно адресует кадр. **Закрыт.**
- Для I3 (неблокируемость) этот путь ДОЛЖЕН использовать `TryEnqueueControl`, а не `EnqueueControl` —
  §5.3/§14 это требуют, но в коде `WriteControlMessage` сейчас зовёт блокирующий `EnqueueControl`.
  Реализация обязана добавить неблокирующий вариант пути (напр. `TryWriteControlMessageForStream`).
  Это деталь реализации, дизайн её называет — не блокер.

### NH2 — VERIFIED closed: маркер в зашифрованном Chunk.Payload, auth не ломается
- `buildFirstFramePayload` (ws_transport.go:684-695) строит `core.Chunk{SeqNum, Flags:FlagKeepalive}` с
  nil `Payload`, шифрует `session.EncryptChunk`, оборачивает `browser.BuildDataPayload(token, encrypted)`.
  Добавление `["FLOWCTL"][window]` в `keepalive.Payload` ДО шифрования кладёт маркер ВНУТРЬ AES-GCM —
  cleartext-часть кадра (token-префикс, обёртка) не меняется. NH2 закрыт верно.
- `authenticateFirstFrame` (websocket.go:144-203) проверяет ТОЛЬКО: msgType, `len(data) < tokenLen+
  MinChunk`, hint, GCM-tag, `AcceptSeqNum`, `chunk.Flags != FlagKeepalive`. **payload chunk'а не
  инспектируется** — маркер не нарушит ни одной проверки. `firstFrameReadLimit = 8*1024` (websocket.go:126),
  11-байтный маркер легко влезает. Старый сервер примет keepalive с маркером и НЕ упадёт. **Закрыт.**
  (Но из-за NV1 «ответ ack'ом» он всё равно не сформирует — это NV1, не NH2.)

### M-rot — VERIFIED closed: ребейз не нужен
- Следует из NB1-verified: стрим не меняет слот/сессию в пределах streamID, серверный credit живёт всю
  жизнь стрима в одном `runWebSocketSession`, клиентский pendingDelta — в `Client.streamFlow[streamID]`
  весь срок (RegisterStream/UnregisterStream под streamMu, client.go:686/702). Рассинхрона «новый
  server-credit = полное окно» не возникает. §7 корректен. **Закрыт.**

### §4.5 slot reader не перечитывает ack — VERIFIED (клиентская сторона корректна)
- Фокус-вопрос 2: гарантированно ли slot reader стартует ПОСЛЕ синхронного чтения и не теряет первый
  data-кадр? **Да, по коду:** `connectSlot` зовёт `UpgradeToWS` синхронно (ws_pool.go:1665) и лишь
  ПОСЛЕ её успеха ставит `slot.transport = wst` (1670), `setState(slotReady)` (1712). Reader
  (`slotReaderWithClient`, ws_pool.go:2494) стартует ТОЛЬКО для `slotReady`-слота с
  `readerActive.CAS(false→true)` (ws_pool.go:2517) — т.е. строго после возврата connectSlot.
  Следовательно вставленный в `UpgradeToWS` (между :519 и :525) синхронный `conn.ReadMessage()`
  выполняется, пока reader заведомо ещё не стартовал → reader не «съест» ack и стартует со следующего
  кадра. Потери первого РЕАЛЬНОГО data-кадра нет: данные не идут до первого CONNECT, а CONNECT клиент
  шлёт уже после ready. **Клиентская половина §4.5 архитектурно состоятельна** — ломает её только NV1
  (нечего читать).

---

## MEDIUM

### MV1 — [NEW] §4.5 negotiationAckTimeout на compat-пути: 2s-stall на слот при «клиент новый, сервер старый»
Даже после фикса NV1 (новый сервер шлёт ack) остаётся compat-окно: клиент с маркером против старого
сервера повиснет на `negotiationAckTimeout` на каждом слоте (старый сервер ack не шлёт). При 8 слотах и
2s — заметная регрессия холодного старта против непроапгрейженного сервера. Фикс: короткий дедлайн
(≤500ms) + метрика; либо staged rollout (сервер первым) + negotiation off, пока сервер не подтверждён
новым. Прописать в плане. (Связано с под-вопросом NV1.)

### MV2 — control-канал (cap 64) делится между WINDOW_UPDATE и pong/keepalive
При быстрой закачке per-client sender шлёт ~36 update/сек (§16) через тот же 64-слотовый control-канал,
что pong'и (ws_transport.go:542, блокирующий EnqueueControl) и keepalive'и. `TryEnqueueControl` для
update неблокирующий → под пиком update'ы будут дропаться (ОК, additive дошлёт), а pong'и через
блокирующий путь + приоритетный drain — пройдут. Риск не в потере pong, а в том, что блокирующий
`EnqueueControl(pong)` может на миг встать, если канал забит update'ами, прежде чем Run его осушит.
Практически Run дренирует control в Phase 1 целиком на каждой итерации (wsasyncwriter.go:98-108), так что
окно крошечное. Не блокер; зафиксировать как наблюдаемость (метрика дропа update). Рассмотреть отдельный
channel/path для update, если поле покажет дропы.

---

## LOW

### LV1 — §4.4 default в WS switch
reader-switch (websocket.go:591) сейчас БЕЗ `default` — неизвестный флаг проваливается молча (фрейм
просто не матчит ни один case, итерация продолжается). Добавление `case FlagWindowUpdate` + `default`
no-op + метрика — чисто и безопасно. Подтверждено структурой switch. **closed по дизайну.**

---

## Карта закрытия 2-го пасса (итог против кода)

| Находка 2-го пасса | Статус в v3 (против кода) |
|---|---|
| NB1 — негоциация/scope | **частично**: архитектура (per-conn, no server-side migration) VERIFIED верна; механизм ack ЛОЖЕН → переоткрыт как **NV1** |
| NB2 — EnqueueControl блокирует | **verified closed**: control chan cap 64, TryEnqueueControl добавляется чисто, Run-приоритет не нарушен |
| NH1 — per-slot sender теряет стрим | **verified closed**: per-client sender + WriteControlMessageForStream, стрим не мигрирует |
| NH2 — место маркера | **verified closed**: маркер в зашифрованном Chunk.Payload, authenticateFirstFrame payload не инспектирует |
| M-rot — credit-rebase при ротации | **verified closed**: стрим не меняет слот в пределах streamID |

**Регрессий ранее-закрытого (1-й пасс) нет.** NV1 — НЕ регрессия, а недоисследованная половина NB1
(серверная эмиссия ack), которую v3 не закрыл.

---

## Что нужно для READY (один пункт)

1. **NV1** — переспроектировать §4.2/§4.5 так, чтобы сервер ЯВНО эмитил FLOWCTL-ack на первый
   keepalive-с-маркером (синхронно, до reader-loop'а, в `authenticateFirstFrame` или сразу после неё в
   `handleWebSocket`), и зафиксировать в спеке, что без этого синхронное чтение клиента не имеет
   источника. Заодно закрыть MV1 (compat-таймаут: короткий дедлайн + метрика + staged rollout) и
   отметить MV2 (метрика дропа update) / LV1 (default в switch) к реализации.

Всё остальное (NB2/NH1/NH2/M-rot + клиентский interplay §4.5 + архитектурная часть NB1) — verified
closed против кода, в реализацию как есть.

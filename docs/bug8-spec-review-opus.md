# Bug #8 — Per-Stream Flow Control Design — Adversarial Protocol Review

**Reviewer role:** adversarial protocol-design reviewer (pre-implementation)
**Дата:** 2026-05-30
**Спека:** `docs/superpowers/specs/2026-05-30-bug8-flow-control-design.md`
**Вердикт:** **НЕ реализовывать как есть.** Дизайн нацелен на неверный серверный код-путь (POST/SplitHTTP `tunnel.Outgoing`), тогда как продакшен-обрыв происходит на WebSocket-пути (`server/websocket.go`), у которого совершенно другая backpressure-модель. Плюс несколько deadlock-рисков и проблема с negotiation.

---

## Counts по severity

| Severity | Кол-во |
|---|---|
| BLOCKER | 3 |
| HIGH | 5 |
| MEDIUM | 5 |
| LOW | 3 |

---

## BLOCKER

### B1 — Дизайн серверной стороны нацелен на НЕВЕРНЫЙ код-путь (WS vs POST)

**Заголовок:** Весь §6 описывает `relayStreamFromTarget` + `tunnel.Outgoing`, но продакшен-закачки идут по WebSocket-пути `server/websocket.go`, где нет ни `relayStreamFromTarget`, ни `tunnel.Outgoing`, ни `tunnel.credits` — фикс не затронет реальный баг.

**Доказательство (проверено в коде, НЕ по спеке):**

На сервере существуют ДВА независимых стрим-relay механизма:

1. **POST / SplitHTTP download-stream путь** (`server/handler.go`):
   - `handleConnect` (handler.go:1255) → `go h.relayStreamFromTarget(...)` (handler.go:1359)
   - `relayStreamFromTarget` (handler.go:1380) читает target → `tunnel.Outgoing <- tagged` (handler.go:1421)
   - ОДИН drain-goroutine `runDownloadStreamLoop` (handler.go:1104-1147) сливает `tunnel.Outgoing` (cap `defaultTunnelOutgoingBuffer = 256`, handler.go:1719) на ВСЕ стримы сессии.
   - Диспетчер: `routeDataChunk` (handler.go:676-705).

2. **WebSocket путь** (`server/websocket.go`) — **это и есть продакшен hot-path**:
   - Собственный reader-loop (websocket.go:551-825) с СОБСТВЕННЫМ switch по флагам (websocket.go:591).
   - Собственная карта `streams map[uint16]*wsStream` (websocket.go:485), НЕ `tunnel.streams`.
   - Per-stream downlink relay — отдельная goroutine на стрим (websocket.go:733-770): `tc.Read(buf)` → `writeMsg(enc)` → `writer.Enqueue` в общий `core.NewWSAsyncWriter(conn, 512)` (websocket.go:480).
   - **НЕТ `tunnel.Outgoing`, НЕТ `relayStreamFromTarget`, НЕТ `routeDataChunk`, НЕТ `handleConnect`.**

Memory/CLAUDE.md и сам debug-лог из §1 («WS slot reader», `slotReaderWithClient`, viaCF=false, max_conns=8) однозначно указывают: продакшен-клиент работает через **WS pool**. Значит сервер обслуживает его через `handleWebSocket`/`websocket.go`, а НЕ через POST download-stream. Дизайн §6 (init credit в `handleConnect`, gate в `relayStreamFromTarget`, `handleWindowUpdate` рядом с `handleStreamFin` в `routeDataChunk`) физически не находится на пути продакшен-закачки.

**Последствие:** реализовав §6 как написано, мы добавим credit-gate в POST-путь, который в проде не используется для WS-сессий, а WS-relay (websocket.go:753-769) продолжит лить `tc.Read → writeMsg` без всякого credit. Баг #8 НЕ будет исправлен. Хуже: integration-тест §7.5, если он гоняет POST-путь, даст зелёный, маскируя то, что прод-путь не покрыт.

**Фикс дизайна:** переписать §6 под WS-путь:
- credit-state привязать к WS-сессии (per-`handleWebSocket`-вызов), инициализировать при `FlagConnect` (websocket.go:627, где создаётся `pendingStream`), а не в `handleConnect`.
- credit-gate вставить в per-stream relay-goroutine ПЕРЕД `tc.Read` (websocket.go:754).
- `handleWindowUpdate` добавить как новый `case core.FlagWindowUpdate` в switch websocket.go:591 (там сейчас НЕТ default, см. B3).
- Решить судьбу POST-пути: либо тоже покрыть (для SplitHTTP CDN-режима), либо явно задокументировать, что flow control только для WS, а POST-путь остаётся со статус-кво drop. Дизайн должен явно перечислить ОБА пути и какой из них носитель бага.

---

### B2 — Уплинк-deadlock: WINDOW_UPDATE может застрять за данными в общем async-writer'е слота (HoL на uplink)

**Заголовок:** WINDOW_UPDATE отправляется по uplink через `StreamWrite`/`StreamWriteControl`, который кладёт фрейм в общий per-slot `WSAsyncWriter`; если очередь полна (медленный uplink/CF-столл), отправка update БЛОКИРУЕТСЯ, сервер не пополняет credit, закачка зависает — взаимоблокировка по credit.

**Доказательство:**

Клиентский uplink на WS-pool слоте проходит через `WSAsyncWriter` (client/ws_transport.go:55, `asyncWriter`):
- data: `Enqueue` (wsasyncwriter.go:190) — **блокирует** при полном `outbound` (cap = bufSize) до `<-w.done`.
- control: `EnqueueControl` (wsasyncwriter.go:215) — **блокирует** при полном `control` (cap 64).

Дизайн §5.2 говорит слать update «через `StreamWriteControl`/`StreamWrite`». Если через `StreamWrite` (data-очередь) — она же используется для uplink-данных приложения; при активной двусторонней нагрузке (или CF-столле на отправку) очередь полна → отправка WINDOW_UPDATE блокирует ту goroutine, что его шлёт. В дизайне update шлётся из downlink-goroutine `tunnelTCPStream` ПОСЛЕ `conn.Write` (§5.2, tcp.go:778). Значит блокируется downlink-goroutine стрима → она перестаёт читать `incomingCh` → `incomingCh` переполняется → `RouteToStream` снова дропает (тот самый баг, но теперь как «детектор инварианта» §5.3 кричит WARN). Классическая credit-deadlock-петля: клиент не может прислать credit, потому что занят отправкой, а отправка ждёт credit (косвенно — через заполнение каналов).

Даже `EnqueueControl` (cap 64) не спасает полностью: при массовой одновременной отправке update по многим стримам одного слота + стоящем Run (медленный сокет) 64-буфер исчерпается и `EnqueueControl` заблокирует downlink-goroutine.

Принцип из §2 («reader-loop никогда не блокируется, WINDOW_UPDATE не flow-controlled») соблюдён только для серверного reader'а. Но на КЛИЕНТЕ отправка WINDOW_UPDATE сама может блокироваться на писателе — это упущено.

**Фикс дизайна:**
- Отправка WINDOW_UPDATE должна быть **неблокирующей** с гарантией доставки: либо выделенный bounded control-путь, который при заполнении НЕ блокирует, а коалесцирует (накопить delta и слить при освобождении), либо отдельная goroutine-«credit sender» на слот с собственной очередью, которую downlink-goroutine кормит неблокирующе.
- Поскольку delta аддитивна (§3), потеря промежуточного update не фатальна, если следующий несёт накопленную сумму. Спроектировать «coalescing window updater»: per-stream atomic-аккумулятор `pendingDelta`, отдельный лёгкий sender, который шлёт `swap(pendingDelta, 0)` когда писатель готов. downlink-goroutine только делает `atomic.Add` (никогда не блокируется).
- Явно прописать в дизайне инвариант: **ни одна операция в downlink-goroutine не должна блокироваться на uplink-писателе.**

---

### B3 — Старый сервер на WS-пути молча проглотит WINDOW_UPDATE; старый клиент при downgrade — тоже; нет ack-семантики → невидимое зависание

**Заголовок:** WS switch (websocket.go:591-823) НЕ имеет `default` — неизвестный `FlagWindowUpdate=0x0A` от нового клиента к старому серверу будет тихо проигнорирован (соединение не рвётся — это хорошо), НО если negotiation ошибётся и клиент решит, что flow control включён, а сервер его игнорирует, credit на сервере не существует → сервер не ограничивает отправку (ок), а клиент ждёт... ничего. Несимметричное понимание версии = тихий разнобой.

**Доказательство:**
- POST-путь `routeDataChunk` имеет `default: handleKeepalive` (handler.go:703) — неизвестный флаг → keepalive-ответ, соединение живёт.
- WS-путь switch (websocket.go:591) **без default** — неизвестный флаг просто проваливается, фрейм отбрасывается молча. `FlagWindowUpdate=0x0A` у старого сервера = no-op. Соединение НЕ рвётся (это безопасно для compat), но если рассинхрон версий привёл к тому, что клиент думает v2, а сервер v1 — сервер льёт без ограничения окна (статус-кво баг), а клиент шлёт update'ы в пустоту.

Реальная опасность не в самом дропе фрейма (безопасно), а в том, что **единственный механизм синхронизации версии — DeriveSessionKeys** (B4/B-negotiation). Если версия согласована криптографически верно (ключи сошлись), то обе стороны ЗНАЮТ версию и проблемы нет. Если negotiation спроектирована неверно (см. H1), возможен сценарий «ключи сошлись на v1, но клиент локально включил flow control по другому сигналу» → тихое зависание.

**Фикс дизайна:**
- Источник истины для `flowControlEnabled` ДОЛЖЕН быть согласованная `protoVersion` (та же, что вошла в `DeriveSessionKeys`), и НИЧЕГО больше. Если ключи сошлись на v2 — обе стороны гарантированно знают про flow control. Если на v1 — обе выключают. Это делает разнобой криптографически невозможным. Дизайн должен это прибить гвоздями: «`flowControlEnabled = (negotiatedVersion >= 2)`, где `negotiatedVersion` — РОВНО то значение, что подано в DeriveSessionKeys».
- Добавить `default` в WS switch при добавлении нового флага (хотя бы no-op + метрика `unknown_flag_total`) — чтобы будущие флаги были наблюдаемы, а не молча терялись.

---

## HIGH

### H1 — Version-bid в ClientHello ломает фикс-размерный парсер; cleartext-bid = DPI-признак

**Заголовок:** `ClientHello` парсится по фикс-константам `EphemeralPub[32] || encClientID[65] || padding` без length-prefix (handshake.go:11-16); вставка version-bid в любое место сдвинет границы для старого сервера ЛИБО потребует bump'а формата, а cleartext-bid создаёт новый отличительный признак для DPI.

**Доказательство:**
- `EncryptedClientIDSize = 65` — жёсткая константа парсинга. Комментарий прямо предупреждает: «Changing this value requires a ServerHello._v bump and a per-version size map in parsers» (handshake.go:15).
- `ClientHello` struct (handshake.go:18-22) несёт только `EphemeralPub` + `EncryptedClientID`. Старый сервер читает первые 32 байта как ephemeral pub, следующие 65 — как encClientID. Любой байт bid'а ДО или МЕЖДУ этими полями ломает дешифровку у старого сервера → handshake падает → нет graceful fallback.
- Bid в хвостовом padding'е: старый сервер padding игнорирует (читает только по константам) — ВЫГЛЯДИТ безопасно для compat, НО padding сейчас random (DPI-нейтрален); фиксированный/структурированный bid в padding'е = детектируемый паттерн.
- Cleartext-bid: §4.3 сам отмечает риск. Но альтернатива «в аутентифицированной части» = внутри `encClientID` (NaCl Box), что меняет фикс-размер 65 → опять bump парсера.

**Фикс дизайна:** Принять **альтернативу из §4.3 (bid в первом зашифрованном data-frame)** как ОСНОВНОЙ путь, не fallback. Обоснование:
- `ClientHello` не трогаем вообще → нулевой риск для старого сервера и нулевой новый DPI-признак на handshake.
- Сервер дефолтит v1 (текущие ключи), клиент шлёт v2-capability в первом аутентифицированном фрейме. НО: это означает, что ключи ВСЕГДА выводятся под v1 (иначе рассинхрон). Тогда `protoVersion` в DeriveSessionKeys остаётся 1, а flow control — это **post-handshake feature negotiation поверх v1-ключей**, не новая crypto-версия. Это снимает всю проблему downgrade-через-ключи (B4): flow control становится опциональной фичей внутри v1-сессии, а не v2-протоколом.
- Тогда «версия» во флаге — это feature-flag, а не key-binding версия. Дизайн должен ЯВНО выбрать одну из двух моделей: (a) v2 как новая crypto-версия (ключи меняются, нужен bid в ClientHello) ИЛИ (b) flow control как in-band feature внутри v1 (ключи не меняются, capability в первом фрейме). Смешивание — источник багов.
- **Рекомендация: модель (b).** Flow control не требует смены ключевой схемы; key-binding downgrade-защита здесь излишня (нет криптографического секрета в самом факте flow control). Это радикально упрощает и убирает B4 целиком.

### H2 — `tunnel.Outgoing` остаётся session-wide узким местом даже с per-stream credit (только для POST-пути)

**Заголовок:** На POST/SplitHTTP-пути ВСЕ стримы делят один `tunnel.Outgoing` (cap 256, handler.go:1719) и один drain-goroutine (handler.go:1131); per-stream credit не устраняет HoL, если один стрим с полным окном заполняет общий канал и блокирует enqueue других стримов на `tunnel.Outgoing <- tagged` (handler.go:1421).

**Доказательство:**
- `relayStreamFromTarget` блокирует на `case tunnel.Outgoing <- tagged` (handler.go:1420-1432) когда канал (256) полон. Это блокирует goroutine ОДНОГО стрима — но если канал полон, то ВСЕ relay-goroutine'ы блокируются на enqueue, пока единственный `runDownloadStreamLoop` их не сольёт. Per-stream credit ограничивает, сколько каждый стрим положит, но суммарно N стримов × окно могут переполнить 256-буфер → косвенный HoL: медленный потребитель downlink (CF backpressure на `writeFrame`, handler.go:1137) останавливает drain → канал полон → все стримы стоят.
- §12 вопрос 4 это признаёт, но откладывает («YAGNI»). При окне 1 MiB / chunk ~12 KiB = ~85 фреймов на стрим, 256-буфер вмещает ~3 полных окна. 4+ активных закачки → переполнение → HoL.

**Фикс дизайна:** Если POST-путь покрывается (B1), увеличить `tunnel.Outgoing` ИЛИ ввести session-wide credit (StreamID=0), ИЛИ — лучше — на WS-пути проблемы нет (каждый стрим пишет в `WSAsyncWriter` независимо, см. H3), поэтому приоритизировать WS-путь и для POST явно задокументировать ограничение. Не оставлять «YAGNI» без числового обоснования BDP × конкурентность.

### H3 — На WS-пути общий `WSAsyncWriter(512)` — тоже session-wide bottleneck; per-stream credit не устраняет HoL на писателе

**Заголовок:** WS downlink-relay каждого стрима пишет в ОДИН `core.NewWSAsyncWriter(conn, 512)` (websocket.go:480) через `writer.Enqueue` (блокирующий при полном буфере); per-stream credit ограничивает чтение target, но N стримов всё равно делят 512-фреймовую общую очередь к одному сокету.

**Доказательство:**
- websocket.go:753-769: per-stream goroutine `tc.Read → writeMsg(enc)`; `writeMsg = writer.Enqueue` (websocket.go:481).
- `Enqueue` блокирует при полном `outbound` (cap 512, wsasyncwriter.go:204-209). При медленном сокете (CF backpressure) Run стоит → 512 заполняется → relay-goroutine стрима блокируется на Enqueue. Это per-goroutine блок (не блокирует server reader-loop), значит HoL на ПРИЁМ uplink'а нет. Но downlink-throughput всех стримов ограничен одной 512-очередью.
- Хорошая новость: серверный reader-loop (websocket.go:555) НЕ блокируется отправкой downlink (отправка в отдельных goroutine'ах) → uplink WINDOW_UPDATE от клиента ВСЕГДА читается сервером, даже если downlink-писатель стоит. Это снимает серверную половину B2. **Но клиентская половина B2 остаётся.**

**Фикс дизайна:** Per-stream credit на WS-пути архитектурно корректен (блокируется только relay-goroutine стрима, у которого нет credit, на `waitForCredit` ПЕРЕД `tc.Read` — раньше, чем фрейм попадёт в общий writer). Это правильнее текущего блока на Enqueue. Дизайн должен указать, что credit-gate ставится ПЕРЕД `tc.Read` (websocket.go:754), и тогда стрим без credit вообще не читает target → не кладёт в общий writer → меньше давления на общую очередь. Это и есть настоящая цель. Прописать явно.

### H4 — Потеря WINDOW_UPDATE при смерти/ротации слота → стрим навсегда без credit → вечное зависание закачки

**Заголовок:** Стрим переживает ротацию слота (Bug#6 sticky drain), но WINDOW_UPDATE отправляется «по слоту стрима» (§5.2); если слот умер между `conn.Write` и отправкой update, накопленный `consumed` теряется, а после переезда на новый слот сервер по-прежнему ждёт credit, которого уже не придёт → закачка висит.

**Доказательство:**
- `WriteMessageForStream`/`WriteControlMessageForStream` (ws_pool.go:2355/2383): если слот не `slotReady`/`slotDraining`, фоллбэк на `p.WriteMessage` (любой ready-слот) или ошибка «no ready slots» (ws_pool.go:2411). При реконнекте slot-а отправка update может вернуть ошибку → delta потеряна.
- §5.2: `delta := st.consumed; st.consumed = 0` — обнуление происходит ДО подтверждения отправки. Если отправка упала, delta потеряна безвозвратно (аддитивная модель не восстановит).
- Credit на сервере привязан к WS-сессии (B1-фикс) или tunnel — НЕ к слоту. Стрим жив, сервер ждёт. Клиент потерял delta. Mismatch навсегда.

**Фикс дизайна:**
- Обнулять `consumed` ТОЛЬКО после успешного `Enqueue`/отправки. При ошибке отправки — НЕ обнулять, следующий update понесёт накопленную сумму (аддитивность спасает, если канал восстановится).
- Но если сам слот мёртв, а стрим мигрировал — нужен re-send по новому слоту. Поскольку `WriteMessageForStream` уже резолвит текущий слот стрима через `streamMap`, отправка после миграции пойдёт по новому слоту — ОК, если delta не была обнулена при неудаче. Зафиксировать инвариант: «consumed обнуляется атомарно с успехом отправки; неудача оставляет consumed нетронутым».
- Рассмотреть watchdog: если стрим имеет неподтверждённый downlink и не слал update дольше T — форсировать отправку (страховка от потери порога).

### H5 — Half-close: после `appConn.CloseWrite` uplink-goroutine выходит — кто шлёт WINDOW_UPDATE для продолжающейся закачки?

**Заголовок:** §12 вопрос 5 верно ставит проблему, но дизайн не даёт ответа: при HTTP keep-alive download приложение делает CloseWrite, uplink-goroutine возвращается (tcp.go:684), downlink продолжает качать — отправку update делает downlink-goroutine, и она использует тот же per-slot writer; нужно подтвердить, что путь жив.

**Доказательство:**
- tcp.go:679-685: при half-close (`writeClosed()==false`) uplink-goroutine `return` (перестаёт читать uplink), downlink-goroutine продолжает (tcp.go:717-818). Отправка update в §5.2 — из downlink-goroutine после `conn.Write` (tcp.go:778). Значит отправитель update'а — downlink-goroutine, которая ЖИВА при half-close. ОК концептуально.
- НО `StreamWrite`/`StreamWriteControl` пишет в per-slot `WSAsyncWriter` (uplink-направление WS), которое физически независимо от appConn uplink. WS-слот остаётся открытым на чтение И запись независимо от half-close приложения. Значит путь для update жив. **Это надо явно верифицировать тестом и зафиксировать в дизайне** — сейчас это «открытый вопрос», а это инвариант корректности закачки.

**Фикс дизайна:** Закрыть вопрос §12.5 утверждением + тестом: «WS uplink-направление слота не зависит от appConn half-close; downlink-goroutine отправляет WINDOW_UPDATE через slot writer независимо от того, что uplink-goroutine приложения завершилась». Добавить integration-тест: half-close после первого запроса + большая закачка → 0 дропов, update'ы продолжают идти.

---

## MEDIUM

### M1 — Кламп `available <= 2*window`: легальный, НО при агрессивном пополнении возможны простои, не дропы (§12.3)

`waitForCredit` блокирует relay ПЕРЕД `tc.Read`, поэтому кламп не теряет байт (target не читается, TCP-окно target'а само придержит отправителя). Off-by-one не приводит к дропу — приводит к недоиспользованию окна (relay прочитает меньше, попросит credit чаще). Не BLOCKER. **Фикс:** документировать, что кламп влияет только на верхнюю границу in-flight, дропов не создаёт; метрика `credit_wait_seconds_total` (§8) поймает, если кламп душит throughput. Можно поднять до `2*window` или убрать кламп вовсе, доверяя аддитивности (злой delta не страшен — он лишь разрешит серверу читать больше, но target-сокет сам ограничит реальный объём).

### M2 — `incomingCh` cap 512 vs окно: §5.4 верно, но при изменении окна через env инвариант ломается

§5.4: окно 1 MiB / 12 KiB ≈ 85 фреймов, 512 покрывает. Но окно конфигурируемо (§10, env `SHADOWLINK_FLOW_WINDOW`). Если оператор выставит окно 8 MiB, то 8M/12K ≈ 680 фреймов > 512 → дропы вернутся. **Фикс:** связать инвариант явно: либо `cap(incomingCh) >= window/minChunkSize` (вычислять cap из окна при старте), либо клампить окно сверху так, чтобы `window/minChunk <= cap(incomingCh)`. Сейчас два независимо настраиваемых числа с неявной зависимостью — мина.

### M3 — Стеганография: всплеск мелких uplink-фреймов WINDOW_UPDATE при 50%-политике создаёт новый временной паттерн

При быстрой закачке update шлётся каждые ~512 KiB потреблённых (порог window/2). На 150 Мбит/с это ~36 мелких uplink-фреймов/сек строго коррелированных с downlink-объёмом — новый признак «download triggers periodic tiny uplink». Реальный браузер при скачивании файла НЕ генерирует такой regular ack-подобный uplink на прикладном уровне (TCP ACK'и — ниже, на транспорте, невидимы внутри WS). **Фикс:** (1) джиттерить порог (например 40–60% случайно), (2) пиггибэкать WINDOW_UPDATE на существующие uplink data-фреймы когда они есть (как TCP piggyback ack), отдельный фрейм слать только при чистой закачке без uplink-данных, (3) добавить в существующий padding-сэмплер так, чтобы размер update-фрейма попадал в ту же log-normal, что и обычные фреймы (он уже шифруется — размер 8 байт payload + overhead может быть аномально мал). Проверить, что `EncryptChunk` для 6-байтового payload (streamID+delta) не даёт детектируемо короткий фрейм.

### M4 — `cond.Signal` vs `cond.Broadcast` и потерянные сигналы при closed/done

§6.2 `waitForCredit`: `for available<=0 && !closed && !done { cond.Wait() }`. §6.3 `cond.Signal()` при пополнении. Один стрим — один cond, один waiter, Signal ок. Но §6.4 «closed=true + cond.Signal вызвать из cleanup-defer relay'я И из handleStreamFin» — два источника сигнала, гонка: если closed выставлен, но relay уже прошёл проверку и сел в Wait ПОСЛЕ Signal — повиснет. **Фикс:** выставлять `closed` и слать Signal ВСЕГДА под `mu` (тот же лок, что Wait), тогда happens-before гарантирует, что waiter увидит closed. Дизайн упоминает «под mu» для waitForCredit, но не для close-пути явно. Прописать: close обязательно `mu.Lock(); closed=true; cond.Signal(); mu.Unlock()`. Рассмотреть `tunnel.done`/session-done интеграцию через тот же cond (нужен отдельный watcher-goroutine, будящий cond на done, т.к. sync.Cond не селектится на канал).

### M5 — `tunnel.done`/session-done не интегрируется в `sync.Cond` напрямую — риск зависания relay при teardown сессии

§6.2 «`cond.Wait()` пока `available<=0 && !closed && !done`» — но `sync.Cond` не умеет ждать канал `done`. Если сессия рвётся, пока relay в `cond.Wait()`, никто не вызовет Signal → relay висит до... ничего (goroutine-leak). **Фикс:** при teardown сессии пройтись по всем `credits` и `cond.Signal()` каждому (выставив closed), ЛИБо отдельная goroutine на сессию, которая на `<-done` будит все cond'ы. Дизайн обязан это покрыть — иначе leak при каждом разрыве WS под активной закачкой (а Bug#8 как раз про разрывы под закачкой).

---

## LOW

### L1 — `ParseWindowUpdate` минимальная длина и FlagWindowUpdate=0x0A коллизий нет

`FlagData=0x01..FlagStreamOpen=0x09` (chunk.go:13-22); `0x0A` свободен — ок. `ParseWindowUpdate` должен проверять `len(payload) >= 6` (streamID 2 + delta 4) и отвергать иначе (как `ParseUDPChunk` делает, chunk.go:266). Дизайн §3 формат указывает, но §7.1 тест на «битый/короткий» — убедиться, что короткий payload = no-op, не паника.

### L2 — Метрика `flow_enabled` gauge: убедиться, что считает per-session, не глобально

§8 `shadowlink_flow_enabled` «gauge 0/1 — сессий на v2». Gauge 0/1 не отражает «сколько сессий». Нужен counter/gauge по числу v2-сессий, иначе при смешанном парке (v1+v2) метрика бесполезна для диагностики раскатки. Уточнить семантику.

### L3 — `StreamID=0` зарезервирован под session-wide — но StreamID=0 уже используется как legacy/poll

chunk.go: `NewDataChunk`/`NewConnectChunk` используют StreamID=0 (legacy, chunk.go:179/296). `PollStreams` шлёт StreamID=0 (client.go:822). Резервирование `StreamID=0` под session-wide flow control (§3) конфликтует с legacy-использованием 0. Если когда-нибудь включат session-wide credit — коллизия с poll/legacy. **Фикс:** задокументировать конфликт; для session-wide использовать иной маркер (например выделенный FlagSessionWindowUpdate), не StreamID=0.

---

## Сводка рекомендаций (приоритет)

1. **Переписать §6 под WS-путь** (`server/websocket.go`), а не POST/`tunnel.Outgoing` (B1). Явно перечислить оба серверных пути и носитель бага.
2. **Сменить модель negotiation на in-band feature-flag поверх v1-ключей** (H1, устраняет B4 и упрощает B3): не трогать ClientHello, не плодить crypto-версию; flow control — опциональная фича внутри v1, capability в первом аутентифицированном фрейме. `flowControlEnabled` строго = negotiatedVersion (B3).
3. **Сделать отправку WINDOW_UPDATE неблокирующей + coalescing** (B2): atomic-аккумулятор delta + отдельный sender; downlink-goroutine никогда не блокируется на писателе.
4. **Credit-gate ставить ПЕРЕД `tc.Read`** на WS-пути (H3) — стрим без credit не читает target, не давит на общий writer.
5. **Закрыть half-close (H5) и потерю update при ротации/смерти слота (H4)** инвариантами + тестами.
6. **Закрыть teardown-leak в sync.Cond** (M5/M4): будить все cond'ы на session-done под mu.
7. Связать `cap(incomingCh)` с окном (M2), джиттер/пиггибэк WINDOW_UPDATE (M3).

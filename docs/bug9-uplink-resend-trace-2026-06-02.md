# Bug #9 — трассировка UPLINK при миграции стрима. Дублируется ли uplink? 2026-06-02

Цель: локализовать механику UPLINK при миграции стрима на новый WS-слот и найти места, где
uplink-данные могут ПЕРЕОТПРАВЛЯТЬСЯ (дублироваться). Контекст полевого лога: короткий запрос
к Claude API (stream к 160.79.104.10:443) дал аномальный uplink `bytes=1054952` (1 МБ) за
`uploads=208` при downlink всего 6225 байт.

---

## TL;DR (главный ответ)

**Клиент НЕ переотправляет уже отправленные uplink-байты при миграции.** В коде нет uplink
resend/tail буфера. Миграция меняет только привязку стрима к слоту (`rebindStreamToSlot`),
а uplink-барьер (`WaitStreamMigrateBarrier`) лишь ПРИОСТАНАВЛИВАЕТ чтение нового `conn.Read`
на время in-flight MIGRATE/RESUME (≤1.5s) и после переноса шлёт СЛЕДУЮЩИЙ чанк под новой
сессией. Уже отправленные чанки нигде не хранятся для повторной отправки.

Метрика `migrate_tail_resent` (`MigrateTailResent`) — это **СЕРВЕРНЫЙ DOWNLINK** хвост
(egress→client), а НЕ uplink. Сервер переотправляет неподтверждённые downlink-кадры на новый
слот при смерти старого; клиентский reassembler их дедуплицирует по `seq < expectedSeq`.
К uplink это отношения не имеет.

**Может ли это раздуть короткий запрос до 1 МБ за счёт переотправки uplink при миграции? —
По коду самой миграции: НЕТ.** Путь миграции байты uplink не дублирует. Счётчик `uploads` тоже
НЕ растёт на переотправках, потому что переотправок uplink в коде нет — он растёт ровно по числу
успешных `conn.Read` (tcp.go:901), т.е. по числу порций, которые ПРИЛОЖЕНИЕ реально прислало.

Поэтому `uploads=208 / bytes=1054952` означает, что **memConn/tun2socks реально отдал в стрим
208 порций суммарно ~1 МБ** — это НЕ артефакт дублирования внутри миграции. Источник лишнего
объёма надо искать ВЫШЕ уровня миграции (на стороне приложения/tun2socks/повторных попыток
самого HTTP-клиента), либо в ретраях на уровне нового стрима (новый CONNECT = новый streamID =
повторная заливка тела запроса приложением). Внутри ShadowLink-миграции один и тот же
uplink-байт по проводу второй раз не уходит.

Статус «неясно» остаётся только для одного: если приложение/tun2socks при обрыве стрима
открывает НОВЫЙ TCP-поток и заново заливает тело запроса — это будет НОВЫЙ streamID с новым
`conn.Read`-потоком, `uploads` законно вырастет, и сервер примет данные дважды (он uplink НЕ
дедуплицирует, см. §4). Это не «дублирование внутри миграции», а ретрай на уровне приложения,
который выглядит как раздувание. Доказать/опровергнуть — DEBUG-точками ниже (особенно §5-а и §5-д).

---

## 1. Полный путь UPLINK при миграции (file:line)

### 1.1 Uplink-горутина (единственный отправитель uplink-чанков)
`proxy/socks5/tcp.go:847-928` — uplink goroutine внутри `tunnelTCPStream`:
- `tcp.go:859` — `n, err := conn.Read(buf)` — читает порцию ОТ приложения (через memConn).
- `tcp.go:900-901` — `total += n; uploads++` — счётчики растут РОВНО на один успешный Read.
  **`uploads++` считает число `conn.Read`, НЕ число отправок и НЕ переотправки.** Переотправки
  в этом цикле нет вообще: каждая итерация = ровно один новый Read = ровно одна отправка.
- `tcp.go:910-915` — **uplink-барьер**: `mb.WaitStreamMigrateBarrier(streamID)`, затем
  re-resolve `uplinkSession = client.StreamSession(wst, cl, streamID)` (приватная копия сессии
  этой горутины — в shared `session` не пишется, чтобы не было гонки с downlink).
- `tcp.go:916-917` — `chunk := core.NewStreamDataChunk(uplinkSession.ID, uplinkSession.NextSeqNum(), streamID, buf[:n])`;
  `enc, encErr := uplinkSession.EncryptChunk(chunk)` — каждая порция шифруется ОДИН раз под
  текущей (возможно уже новой) сессией с НОВЫМ session-seq.
- `tcp.go:923` — `client.StreamWrite(wst, streamID, enc)` — отправка на провод ОДИН раз.

Вывод: один `conn.Read` → один `EncryptChunk` → один `StreamWrite`. Буфер `buf[:n]` после
отправки не сохраняется. Нет структуры, хранящей отправленные uplink-чанки.

### 1.2 WaitStreamMigrateBarrier — как работает
`client/migrate_send.go:210-241`:
- Быстрый путь: если пул не migrate-enabled или у `streamEntry` флаг `migrating==false` — мгновенный return.
- Если `migrating==true` — крутит `time.Sleep(migrateBarrierPollInterval=2ms)` до снятия флага
  ИЛИ до `deadline = now + migrateAckTimeout` (1.5s, `ws_transport.go:632`), перечитывая entry.
- Барьер **только держит** uplink-горутину от записи на стареющий слот. Он НЕ буферизует, НЕ
  пересылает и НЕ повторяет байты. После снятия флага следующий (новый) Read уходит на новый слот.

### 1.3 Что происходит с уже отправленными, но не подтверждёнными uplink-чанками при резе слота
**Ничего — они не сохраняются и не переотправляются.** На клиенте нет uplink-ack и нет uplink-tail.
`migrateStream` (`client/migrate_watchdog.go:224-278`) и `resumeStreamOnDeath`
(`client/ws_pool.go:3690-3727`) меняют только привязку (`rebindStreamToSlot`,
`migrate_watchdog.go:315-361`) и переносят per-slot счётчик стримов. Никакого реплея uplink.
Если чанк был отправлен на слот, который умер ДО доставки на сервер — этот чанк ПОТЕРЯН (а не
продублирован). Целостность uplink при резе слота кодом миграции НЕ гарантируется (в отличие от
downlink, где есть tail-resend + reassembler).

## 2. Есть ли uplink RESEND / tail-resend буфер на клиенте?

**Нет.** Поиск по `resendTail|tailFrames|unackedTail|TailResent` даёт совпадения ТОЛЬКО в
`server/` (relay_registry.go, websocket.go, metrics.go) — это серверный DOWNLINK-хвост. На
клиенте такого буфера нет. `streamEntry` (`client/stream_entry.go:18-46`) хранит лишь
`slotIdx`, `lastWriteNs`, `migrating` — никаких отправленных байтов.

Следовательно «переслать одни и те же байты несколько раз если миграции идут подряд быстрее
чем приходят ack» — на uplink НЕВОЗМОЖНО, потому что нет ни буфера, ни механизма реплея uplink.
(Этот сценарий реален ТОЛЬКО для серверного downlink-хвоста — см. §3.)

## 3. Что такое migrate_tail_resent (это downlink, не uplink)

`server/websocket.go:613-620` (`handleMigrateOrResume`): только на пути `aDead = (flag==FlagResume)`
сервер делает `h.metrics.MigrateTailResent.Add(len(entry.resendTail()))` и затем
`entry.reassociate(..., aDead=true)`.

`server/relay_registry.go:716-763` (`reassociate`) + `:546-557` (`resendTail`) + `:673-714`
(`routeDownFrame`): сервер ведёт `unackedTail` (boundedBuffer отправленных, но не подтверждённых
DOWNLINK-кадров). При RESUME на новый слот после смерти старого он заново шлёт этот хвост
(`relay_registry.go:759-761`). Клиентский reassembler дедуплицирует:
`relay_registry.go:754-755` комментарий — «client reassembler dedups by f.seq < expectedSeq».
То есть downlink-дубликаты есть, но они идемпотентны (отбрасываются по downSeq на клиенте,
`proxy/socks5/tcp.go:540 reasm.push`). Uplink в этой механике не участвует — серверный uplink
приходит без downSeq (`server/migrate_e2e_test.go:607-608`: «uplink is never seq-tagged because
the client serializes it onto a single slot at a time»).

## 4. Дедуплицирует ли сервер повторно полученный uplink seq_num?

**Нет дедупликации НА УРОВНЕ uplink-ДАННЫХ.** Серверный приём uplink — `server/handler.go:877-941`
(`handleDataChunk`, ветка `FlagData`): `targetConn.Write(data)` (`handler.go:922`) пишет байты в
origin-сокет НАПРЯМУЮ, без проверки на дубликат по per-stream seq.

Sliding-window (4096) существует, но это anti-replay на уровне ДЕКРИПТА всей сессии по
`Chunk.SeqNum` (core), а не per-stream дедуп прикладных uplink-байтов. Каждый uplink-чанк
получает свежий `session.NextSeqNum()` (tcp.go:916), поэтому если бы клиент ОТПРАВИЛ те же
прикладные байты повторно (в новом чанке с новым seq) — окно их НЕ отсекло бы, и сервер записал
бы их в origin ДВАЖДЫ. Защита от такого дублирования держится ИСКЛЮЧИТЕЛЬНО на том, что клиент
uplink не реплеит (§1-2). Если дубль uplink придёт от ретрая приложения на новом streamID —
сервер примет оба (это новый стрим/новый origin-conn, для него это «легальные» данные).

## 5. ТОЧНЫЕ DEBUG-точки чтобы ДОКАЗАТЬ/ОПРОВЕРГНУТЬ дублирование uplink

(а) **Счётчик миграций на стрим + лог каждого реального Read** —
`proxy/socks5/tcp.go:900-901` (после `uploads++`): логировать `slog.Debug("uplink read",
"stream", streamID, "n", n, "uploads", uploads, "total", total, "session", uplinkSession.ID,
"seq", <будущий NextSeqNum НЕ дёргать здесь>)`. Это докажет, растёт ли `uploads` за счёт
РЕАЛЬНЫХ новых Read (приложение реально шлёт 1 МБ) или скачет аномально. Параллельно завести
на `streamEntry` атомарный `migrations atomic.Uint32`, инкремент в `rebindStreamToSlot`
(`migrate_watchdog.go:355`), и логировать его тут же — связать «сколько Read» с «сколько раз
мигрировал стрим».

(б) **Срабатывание uplink-барьера с длительностью** — `client/migrate_send.go:224-240`
(`WaitStreamMigrateBarrier`, вход в медленную ветку при `e.migrating.Load()==true`): засечь
`start := time.Now()` перед циклом и на выходе `slog.Debug("uplink barrier", "stream", streamID,
"waited", time.Since(start), "clearedByRebind", <ok>, "timedOut", time.Now().After(deadline))`.
Покажет, как часто и насколько долго барьер реально держит uplink (частые срабатывания = частые
миграции под TSPU-давлением).

(в) **Отправка uplink-чанка с seq и размером** — `proxy/socks5/tcp.go:916-923` (перед/после
`StreamWrite`): логировать `slog.Debug("uplink send", "stream", streamID, "session",
uplinkSession.ID, "seq", chunk.SeqNum, "bytes", n, "slot", <текущий slotIdx из streamMap>)`.
Так как uplink seq монотонен в рамках сессии, повтор ОДНОГО И ТОГО ЖЕ прикладного содержимого
будет виден как ДВА разных seq при одинаковом `bytes` подряд — это и есть прямое доказательство
дублирования (если оно вдруг появится). На текущем коде дублей быть не должно.

(г) **Сервер: счётчик уникальных vs повторных uplink-байт на origin** —
`server/handler.go:922` (перед `targetConn.Write(data)`): логировать
`slog.Debug("uplink→origin", "stream", streamID, "bytes", len(data), "sessionSeq", chunk.SeqNum,
"cumUplink", <накопитель на stream>)`. Сверка серверного `cumUplink` с реальным размером
HTTP-запроса докажет/опровергнет, что в origin ушло больше, чем приложение должно было послать.
Если на сервер пришли два РАЗНЫХ streamID с одинаковым телом — это ретрай приложения, а не
дублирование миграции.

(д) **Сколько РАЗ один и тот же streamID был CONNECT'нут (ретрай-детектор)** —
`proxy/socks5/tcp.go:695` (`streamID := cl.NextStreamID()`) + `tcp.go:778`/`tcp.go:741`
(отправка CONNECT): логировать `slog.Debug("stream connect", "stream", streamID, "dest",
destAddr)`. Если к одному `dest` (160.79.104.10:443) за короткое окно идёт МНОГО CONNECT с
разными streamID — это приложение/tun2socks пересоздаёт поток и перезаливает тело, что и
объясняет 1 МБ uplink без какого-либо дублирования внутри миграции. Это самая вероятная
гипотеза по симптому.

---

## Сводка по 5 вопросам задачи

1. Путь uplink: `tcp.go:847-928`; барьер `migrate_send.go:210-241`; неподтверждённые uplink-чанки
   при резе слота — НЕ сохраняются, НЕ переотправляются (могут быть потеряны, не продублированы).
2. Uplink resend/tail буфер: ОТСУТСТВУЕТ на клиенте. Tail-resend есть только на сервере для DOWNLINK.
3. `uploads++` (tcp.go:901) считает успешные `conn.Read`, НЕ переотправки. Рост uploads = реальные
   порции от приложения, не дубли миграции.
4. Сервер uplink-данные НЕ дедуплицирует (`handler.go:922` пишет в origin напрямую); sliding-window
   4096 — anti-replay по session-seq при декрипте, не per-stream дедуп прикладных байт.
5. DEBUG-точки: (а) tcp.go:900-901 + счётчик миграций в rebindStreamToSlot; (б) migrate_send.go:224-240;
   (в) tcp.go:916-923; (г) server/handler.go:922; (д) tcp.go:695/741/778 (ретрай-детектор CONNECT).

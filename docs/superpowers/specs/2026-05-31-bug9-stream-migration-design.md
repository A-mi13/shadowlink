# Bug #9 — Stream Migration Design (Дизайн миграции стримов между WS-слотами)

**Дата:** 2026-05-31
**Статус:** REVISED-v3 — закрыты все 15 находок первого опус-ревью (`docs/bug9-spec-review-opus.md`) + все 5 НОВЫХ находок повторного ревью v2 (`docs/bug9-spec-review-opus-v2.md`, NEW-1..NEW-5). Готова к writing-plans.
**Связанные:** Bug#8 (flow-control, FLOWCTL control-фрейм паттерн), Bug#6 (sticky-drain), исследование корня `docs/bug9-silent-stream-death-finding.md`, исследование архитектуры `docs/bug9-stream-migration-design.md`, ревью v1 `docs/bug9-spec-review-opus.md`, ревью v2 `docs/bug9-spec-review-opus-v2.md`

> **История версий**
> - v1 (DRAFT) — первичный дизайн, вердикт ревью NOT-READY (2 BLOCKER, 5 HIGH, 4 MEDIUM, 4 LOW).
> - v2 (REVISED) — выбран **полный вариант A с реассемблером** (юзер): мигрируют И тихие, И быстрые стримы. Закрыты все 15 находок ревью (F1–F13 + 10 пунктов «обязательно исправить»). Главные переработки: §3 (+per-stream sequence на проводе), §4 (+крипто-proof с crypto/rand nonce + per-device binding + DoS/FD budget), §5 (+client-side реассемблер, +динамическое чтение boundSession в relay-loop, +перенос credits, +single-winner state-машина, +drain-координация). Трассировка закрытия — в конце документа.
> - v3 (REVISED) — закрыты 5 НОВЫХ находок повторного ревью (`docs/bug9-spec-review-opus-v2.md`):
>   - **NEW-1 [HIGH]** — реассемблер без gap-таймаута → вечно висящий стрим при потерянном хвосте A. Закрыто ДВУМЯ механизмами: (a) серверный буфер недоACKнутого хвоста при упреждающей миграции (хвост не теряется в корне — §5.3, §5.4), (b) `reassemblyGapTimeout` как backstop (не виснем, если дыра всё же возникла — §5.4). Устранено внутреннее противоречие «сервер не обязан буферизовать при A-жив».
>   - **NEW-2 [MEDIUM]** — стартовая нумерация seq (control=0, первый data=1) + клиентский guard `len(payload)<2` → `<10` в seq-режиме (§3.1).
>   - **NEW-3 [MEDIUM]** — hard-инвариант: `downSeqCounter` НИКОГДА не сбрасывается при reassociate (§3.1).
>   - **NEW-4 [MEDIUM]** — session-mu contention от динамического relay-loop → риск §8 + perf-acceptance §6.
>   - **NEW-5 [MEDIUM]** — `boundSession`+`boundWriter` упакованы в ОДИН `atomic.Pointer[binding]` (прецедент `sendEpoch`) — устранена несогласованная пара (§5.1, §5.2, §5.3).

---

## 1. Проблема и корень (доказано)

### Симптом
Долго-живущие стримы (общение с AI-агентом, видео, большие закачки) рвутся и **не восстанавливаются**. Юзер: «на долгих ожиданиях обрывы и не восстанавливается больше», «нужно чтоб миграция стримов работала корректно и не было обрывов никаких».

### Доказанный корень (лог nixavpn-DEBUG-20260531-124541.log, 2457 строк, 39 мин + серверные метрики)
- **126× close 1006** на слотах. Распределение по `slot_age_ms`: 66× на 2-4мин, 40× на 1-2мин, 20× на 4мин+. По `last_write_age_ms`: 58× active(0-2s), 42× 2-5s, лишь 8× quiet(10s+). По `down_bytes`: 94× при <50KB.
- **Вывод:** middlebox/TSPU в РФ режет долгий direct-TCP к голому origin (104.222.177.67, mode=direct, CF блокируется — direct намеренный) **по ВОЗРАСТУ слота ~1-4 мин**, не по молчанию и не по объёму.

### Профиль обрывающихся стримов (обоснование scope — почему ПОЛНЫЙ вариант A)
Анализ `downlink done (ch closed)` (371 событие) по двум осям:
- **Долгие малотрафичные стримы — большинство (291/371 живут >1 мин; 278/371 несут <10 KB).** Это keep-alive HTTP-коннекты, polling-агенты (общение с AI), long-poll, gRPC-стримы. Им смерть слота фатальна: переоткрыть TCP к тому же endpoint можно, но прикладной протокол (например установленная HTTP/2-сессия или активный диалог с агентом) теряется. Это объясняет жалобу юзера «на долгих ожиданиях обрывы и не восстанавливается».
- **Быстрые закачки (>1 MB) — меньшинство, но критичны.** Реже рвутся (слот часто умирает раньше, чем стрим успевает накачать объём), но обрыв виден как «Ошибка сети» в Chrome посреди файла. Эти стримы имеют in-flight данные в момент миграции — именно для них критичен **порядок байт** (см. §5 реассемблер).

**Решение (юзер):** ПОЛНЫЙ вариант A — мигрируем И тихие, И быстрые стримы единым механизмом. НЕ упрощаем до quiesce-only (миграция только молчащих стримов): quiesce-only оставил бы быстрые закачки рваться, а они дают самый заметный пользовательский симптом. Цена полного варианта — client-side реассемблер для in-flight данных (§5.4); цена принята как обязательная для корректности.
- Сервер НЕ виноват: `ws_reader_exit_reset=0`, `other=0`, `local_close=0`. nginx `proxy_read_timeout=86400`. Рез строго между клиентом и origin.
- **Следствие (настоящая проблема):** 371× `downlink done (ch closed)` — стрим умер потому что его слот закрыли (vs 172× штатных app-close). + 11× `no ready slot`. Стримы умирают вместе со слотом, **не мигрируют**.
- Bug#8 держится: `closed pipe=0`, `decrypt_fails=0`. Bug#9 keepalive (5s) помог частично (тихих слотов 10s+ стало 8 из 126), но рез по возрасту keepalive НЕ лечит.

### Почему миграция невозможна СЕЙЧАС (доказано кодом, исследование `bug9-stream-migration-design.md`)
- Egress-TCP (`tc`, сервер→destination) живёт в локальной `streams`-мапе внутри `runWebSocketSession` (одна WS-conn), `server/websocket.go:523`. `<-done` (смерть слота) закрывает все `tc` (`:780-781`, `:946-953`).
- Крипто-сессия **per-slot** (свой ключ на слот, `client/ws_pool.go:2421-2452`) — намеренно (forward secrecy).
- streamID живёт в рамках одной core.Session. relay не переживает смену WS-conn.

### Цель
Egress-TCP **никогда не рвётся** при смене WS-слота клиента (если миграция/resume успели). Для приложения на том конце соединение непрерывно. Рез слота по возрасту — данность канала; боремся с **последствием**, а не с резом.

---

## 2. Архитектура (общая картина)

Два механизма, дополняющих друг друга:

### A. Упреждающая миграция (основной путь, ~80% случаев — рез по возрасту)
1. Клиент следит за возрастом каждого слота. При `age > migrationThreshold` (default 60s, env-настраиваемый, заведомо < порога реза ~90-120с) слот помечается «стареющий».
2. Для каждого **активного** стрима на стареющем слоте клиент выбирает молодой живой слот и шлёт серверу зашифрованный control-фрейм `MIGRATE(streamID, proof)` по новому слоту.
3. Сервер находит relay по `(clientID, streamID)`, переключает его egress-TCP с старой крипто-сессии на новую (нового слота). Байты стрима дальше текут через новый слот.
4. Старый слот без активных стримов → штатный drain. Middlebox режет его уже пустым.

### B. Grace-fallback (внезапный рез раньше порога — ~остаток)
1. Слот умер до миграции (close 1006 раньше порога) → сервер **не убивает** egress-TCP стримов сразу, а держит relayEntry в состоянии `orphaned` в течение `gracePeriod` (default 8s, env).
2. Клиент, обнаружив смерть слота, выбирает живой слот и шлёт `RESUME(streamID, proof)`.
3. Сервер реассоциирует осиротевший relay на новый слот → `RESUME_OK`.
4. Если grace истёк без RESUME → relay закрывается (как сейчас).

### Ключевой инвариант
Egress-TCP (сервер→сайт) непрерывен при смене WS-слота, если миграция/resume успели. При неуспехе (нет слотов, истёк grace, плохой proof) — деградация: стрим рвётся как сейчас, **не хуже текущего**.

### Что переиспользуем (не изобретаем)
- Control-фрейм в зашифрованном payload — точный паттерн FLOWCTL/WINDOW_UPDATE из Bug#8 (`core/chunk.go`, `core/flowctl.go`).
- clientID — уже есть в authorized_clients (`server/ratelimit.go` whitelist).
- Per-slot крипто **не трогаем** (forward secrecy цел) — relay переключается server-side, ключи между слотами не шарятся.
- Flow-control окно (Bug#8) — для backpressure буфера в grace.
- Capability-негоциация — механизм из Bug#8 (capability-маркер в первом keepalive).

### Новые компоненты
- **Сервер:** `relayRegistry` по `(clientID, globalStreamID)` — живёт независимо от одной WS-сессии; reassociate + grace-TTL + лимиты + FD-budget. Relay-goroutine читает привязку `bound` (session+writer одним `atomic.Pointer[binding]`, NEW-5) ДИНАМИЧЕСКИ на каждой итерации. Credit-bucket (Bug#8), downlink-sequence счётчик и буфер недоACKнутого хвоста (`unackedTail`, NEW-1) переезжают/живут в `relayEntry`.
- **Клиент:** age-watchdog миграции (распределённый, не залп) + MIGRATE/RESUME отправка + перенаправление стрима на новый слот + uplink-барьер + **per-stream реассемблер** (буферизует out-of-order downlink, отдаёт в `conn.Write` строго по seq) + downlink-ACK отправка.
- **Core:** новые control-флаги `FlagMigrate`/`FlagResume` + per-stream **monotonic sequence number** в data-фрейме + `FlagStreamAck` (барьер освобождения серверного буфера) + stateless HMAC proof-of-ownership (crypto/rand nonce).

---

## 3. Протокол MIGRATE / RESUME на проводе

### 3.1. Per-stream sequence number в data-фрейме (БАЗА для реассемблера — F1)

**Проблема (F1, BLOCKER).** Сегодня формат stream-data в `core/chunk.go` —
`NewStreamDataChunk` (`core/chunk.go:191`): payload = `[StreamID(2)] + [data]`.
Порядок гарантируется ТОЛЬКО тем, что один слот = один TCP/WS-сокет = FIFO. В
заголовке `Chunk` есть `SeqNum uint32` (`core/chunk.go:38`), но это **session-level**
счётчик (`session.NextSeqNum()` на `core/session.go`), общий на ВСЕ стримы сессии и
сбрасывающийся per-session — он НЕ годится для упорядочивания одного стрима через
смену сессии/слота. При миграции downlink стрима 42 приходит частично по сокету слота
A (in-flight, ещё в буферах CF/nginx/TCP) и частично по слоту B — два независимых
сокета, порядок прихода на клиент недетерминирован. На клиенте оба reader'а
(`slotReaderWithClient`, `client/ws_pool.go:2817-2819`) пушат в ЕДИНЫЙ
`streamChans[streamID]` (`client/client.go:932 RouteToStream`) — канал сохраняет
порядок ВСТАВКИ, но вставка из двух сокетов перемешана → переупорядочивание байт в
TCP-потоке приложения = повреждение.

**Решение.** Вводим **per-stream monotonic downlink sequence number** на проводе,
внутри зашифрованного payload, рядом со streamID. Новый конструктор и формат
(добавляется в `core/chunk.go`):

```
NewStreamDataChunkSeq payload (Flags=FlagData):
  [StreamID(2 BE)] [downSeq(8 BE)] [data]
```

- `downSeq` (uint64) — **per-stream** монотонный счётчик downlink-байт-чанков,
  присваивается **сервером** в момент чтения с egress-TCP. Считает ЧАНКИ (не байты):
  каждый `tc.Read`→`NewStreamDataChunkSeq` инкрементирует `relayEntry.downSeqCounter`.
  Переживает смену слота — счётчик живёт в `relayEntry` (§5.1), НЕ в per-session
  состоянии. Монотонность сохраняется через миграцию: слот A отдал seq до N, слот B
  продолжает с N+1.
- uint64 не переполняется на реальных объёмах (2^64 чанков по ≥1 байту = эксабайты).

**Стартовая нумерация и резервирование seq=0 (NEW-2, MEDIUM).** Жёстко фиксируем:
- `downSeq == 0` **зарезервирован под control-чанки** (CONNECT_OK / CONNECT_FAIL и
  любой будущий per-stream control, который шлётся в data-канале стрима). Все control
  всегда несут `downSeq=0`.
- Первый **РЕАЛЬНЫЙ data-чанк** стрима = `downSeq=1`. Сервер инициализирует
  `relayEntry.downSeqCounter` так, чтобы `downSeqCounter.Add(1)` для первого data-чанка
  вернул именно `1` (т.е. counter стартует с 0, `Add(1)`→1). CONNECT_OK/FAIL
  отправляются ОТДЕЛЬНО (до relay-loop, `server/websocket.go:759` `NewStreamDataChunk`) и
  НЕ проходят через `downSeqCounter` — им присваивается `downSeq=0` напрямую. Так
  исключён конфликт «CONNECT_OK получил seq=1, а реассемблер ждёт первый data с seq=1».
- Клиентский реассемблер стартует с `expectedSeq=1` (§5.4); `f.seq==0` → control-ветка
  (обрабатывается как раньше, не участвует в переупорядочивании).

**Клиентский guard в seq-режиме (NEW-2, MEDIUM).** `slotReaderWithClient` сейчас имеет
guard `len(chunk.Payload) < 2` (`client/ws_pool.go:2787`) — это длина под legacy-формат
`[StreamID(2)] + [data]`. В **seq-режиме** (capability=on) минимальная длина payload =
`2 (streamID) + 8 (downSeq) = 10` байт, поэтому guard ОБЯЗАН стать `len(chunk.Payload)
< 10`. Иначе короткий/битый seq-чанк (например 3 байта) пройдёт guard как валидный,
распарсится по legacy-смещениям → мусорный `streamID = payload[0]<<8 | payload[1]` →
доставка не тому стриму / в несуществующий. Гейтится тем же capability-флагом:
capability=off → guard остаётся `< 2` (legacy формат не изменился). Зафиксировать оба
guard'а как инвариант: `len < 2` (legacy) / `len < 10` (seq).

**HARD-инвариант монотонности `downSeqCounter` (NEW-3, MEDIUM).** `downSeqCounter`
(per-stream, в `relayEntry`, §5.1) **НИКОГДА не сбрасывается / не реинициализируется при
reassociate** (MIGRATE_OK / RESUME_OK / любая смена `boundSession`). Сброс допустим
ТОЛЬКО при удалении `relayEntry` (close стрима, grace-expiry). **Почему это критично:**
клиентский реассемблер (§5.4) дедупит дубли по `f.seq < expectedSeq`. При двойной
миграции A→B→C (§5.8): если C начнёт нумерацию заново с малого seq, реассемблер сочтёт
эти валидные чанки дублями (их seq < уже продвинутого `expectedSeq`) и **молча дропнет
реальные данные** → повреждение TCP-потока приложения без единой ошибки. Монотонность
держится тем, что единственный writer счётчика — relay-loop под захваченным
`relayEntry` (§5.2), а reassociate меняет только `boundSession`/`boundWriter`, НЕ
counter. Тест на инвариант: A→B→C, проверить что seq строго возрастает через обе
миграции и реассемблер ничего не дропает как ложный дубль (§6).

**Обратная совместимость формата.** Capability-негоциация (§3.5) гейтит формат: если
обе стороны поддерживают миграцию, ВЕСЬ stream-data использует seq-формат (8 доп.
байт на чанк — ничтожно vs payload + padding mimicry). Если миграция off — старый
формат `[StreamID(2)] + [data]` без изменений. Сервер выбирает формат per-session по
capability-флагу клиента. Клиентский parser (`slotReaderWithClient`) знает по тому же
флагу, есть ли seq. **Внутри одной сессии формат не меняется** — нет ambiguity при
парсинге.

> **Почему downlink-only seq, а НЕ uplink.** Uplink (клиент→сервер→сайт)
> упорядочивается client-side барьером (§5.2 поток A шаг 3): клиент гарантирует, что
> после отправки MIGRATE он шлёт uplink стрима 42 ТОЛЬКО по новому слоту, а сервер
> дочитывает uplink старого слота до закрытия. На egress-TCP сервер пишет uplink-байты
> в том порядке, в каком извлёк их из WS-фреймов; client-side барьер + ack гарантируют,
> что новый слот не обгонит старый. Поэтому uplink seq на проводе НЕ нужен —
> асимметрия осознанная (downlink идёт из ДВУХ сокетов одновременно, uplink — нет).
> Детальное доказательство барьера в §5.2.

### 3.2. Новые control-флаги (`core/chunk.go`, рядом с `FlagWindowUpdate=0x0A`)
- `FlagMigrate = 0x0B` — упреждающая миграция (слот A жив, переезд на B).
- `FlagResume = 0x0C` — reactive resume (слот A умер, подъём из grace на B).
- `FlagStreamAck = 0x0D` — клиент → сервер: «получил downlink стрима до downSeq=N
  включительно» (барьер освобождения серверного буфера A, см. §5.4).

Все в **зашифрованном payload** нового слота (как FLOWCTL). Middlebox видит обычный
шифротрафик. Анти-DPI не страдает (§4 анти-DPI, §5.6 распределение миграций).

### 3.3. Формат control-фреймов (после расшифровки)

`FlagMigrate` / `FlagResume`:
```
[globalStreamID(2 BE)] [proofToken(32)]
```
- `globalStreamID` (uint16) — глобально-уникальный per-clientID ID стрима (см. §3.6).
- `proofToken` (32 байта) — HMAC-SHA256, доказательство владения (см. §4).

`FlagStreamAck`:
```
[globalStreamID(2 BE)] [ackedDownSeq(8 BE)]
```
- `ackedDownSeq` (uint64) — наибольший downSeq, который клиент УЖЕ отдал в `conn.Write`
  приложению (т.е. реассемблер слил по порядку до этого seq). Сервер до получения
  достаточного ack держит соответствующий хвост старого слота освобождаемым лениво
  (§5.4). Отправляется клиентом периодически и форсированно сразу после MIGRATE_OK.

### 3.4. Ответ сервера (зашифрованный control-фрейм обратно по новому слоту)
- `MIGRATE_OK(globalStreamID, resumeDownSeq)` — relay переключён; `resumeDownSeq` —
  последний downSeq, присвоенный серверным relay ДО переключения boundSession (клиент
  знает, до какого seq ждать «хвост» по старому слоту перед тем как примет данные с B
  как непрерывные). Байты дальше текут по новому слоту.
- `RESUME_OK(globalStreamID, resumeDownSeq, bufferedFromSeq)` — relay поднят из grace;
  `bufferedFromSeq` — downSeq первого чанка в `downBuffer`, который сервер сольёт по B
  (клиент знает, не дырявит ли последовательность).
- `MIGRATE_FAIL(reason)` / `RESUME_FAIL(reason)` — reason ∈
  `not_found|bad_proof|grace_expired|limit|dest_closed`. Короткий код для метрик/логов.

### 3.5. Capability-негоциация (+fail-safe таймаут — F3)

Миграция работает только если **обе** стороны её поддерживают. Capability-маркер
`MIGRATE` в первом keepalive (рядом с FLOWCTL, переиспользуем Bug#8 механизм
`core/flowctl.go::BuildFlowCtlMarker` — расширяем маркер доп. capability-битом, НЕ новым
keepalive). Старый сервер/клиент → миграция off, поведение как сейчас (стрим рвётся при
резе). Per-stream seq-формат (§3.1) тоже гейтится этим флагом.

**Fail-safe таймаут (F3, HIGH).** Старый сервер на `FlagMigrate` попадёт в `default:`
case reader-switch (`server/websocket.go:929-930`) → `h.metrics.UnknownFlag.Add(1)`,
фрейм молча проигнорирован. Клиент НИКОГДА не получит ни OK, ни FAIL. Защита:
- Клиент анонсирует/слушает capability ТОЛЬКО из keepalive-handshake — но возможна
  race (capability распознана, сервер откатили на старый бинарь между keepalive и
  MIGRATE) или баг.
- Поэтому каждый MIGRATE/RESUME ставится с **таймаутом** `migrateAckTimeout`
  (= `negotiationAckTimeout` Bug#8, default 1.5s — тот же порядок, что first-frame
  keepalive окно). Таймаут истёк без OK/FAIL → клиент **деградирует**: считает миграцию
  данного стрима неуспешной, стрим рвётся ровно как СЕЙЧАС (closes streamChan). Клиент
  НЕ зависает в ожидании. Метрика `shadowlink_migrate_timeout_total{kind=migrate|resume}`.
- Доп. защита от ложной capability: при первом `*_timeout` подряд по ≥3 стримам клиент
  снимает capability-флаг до следующего keepalive-handshake (сервер явно не отвечает →
  ведём себя как со старым сервером). Гистерезис не даёт зависать каждому стриму.

### 3.6. Глобально-уникальный streamID per-clientID (F11, LOW)

Формат фрейма несёт `streamID uint16`. На клиенте `NextStreamID`
(`client/client.go:684`) — это per-`Client`-инстанс счётчик; `Client` ОДИН на весь пул
(общий `streamChans`), значит streamID уникален среди всех слотов одного клиента — **на
клиенте коллизии нет**. Но на сервере streamID живёт per-`core.Session` (счётчик
рестартует с 0 на каждой новой сессии). `relayRegistry` ключуется
`(clientID, streamID)` — два слота одного clientID, у каждого своя session с counter от
0, могут переиспользовать один streamID → коллизия в registry.

**Решение.** Ключ registry — `(clientID, globalStreamID)`, где `globalStreamID` — тот
самый client-allocated `NextStreamID` (per-Client, уникален). Сервер НЕ генерирует
streamID сам; он берёт его из `FlagConnect`-payload, который клиент уже шлёт
(`NewStreamConnectChunk`, `core/chunk.go:202` — payload = `[StreamID(2)] + [target]`).
Так server-side streamID == client-side globalStreamID по построению. Дополнительно
relayRegistry хранит `originSessionNonce` (§4) — даже теоретическая коллизия отсекается
proof-несовпадением. Зафиксировать: сервер при CONNECT кладёт relayEntry под
`(clientID, streamIDFromConnect)`, НЕ под локально-сгенерированный ID.

---

## 4. Безопасность (строгая защита)

### 4.1. Proof-of-ownership — stateless HMAC (F2, BLOCKER + F12, LOW)

Проблема: злоумышленник (тот же clientID, второе устройство аккаунта, или укравший
токен) не должен перехватить чужой egress-TCP через RESUME/MIGRATE.

**КДF серверного ключа.** Сервер хранит ТОЛЬКО `serverMasterKey` (32 байта,
сгенерирован при старте/из конфига, тот же материал, что для прочей серверной крипты —
НЕ путать с per-session ключами клиента). Выводит per-client ключ:
```
serverPerClientKey = HKDF-SHA256(
    ikm  = serverMasterKey,
    salt = []byte("shadowlink-migrate-v1"),
    info = clientID-bytes,
    L    = 32)
```
HKDF (`golang.org/x/crypto/hkdf` — уже доступен, проверить go.mod; иначе
`hmac`-based HKDF-Expand вручную) детерминирован → сервер пересчитывает на лету,
**stateless** (не хранит per-client/per-stream секретов).

**session_nonce — crypto/rand, НЕ session.ID.** При создании КАЖДОЙ сессии сервер
генерирует:
```
session_nonce = crypto/rand 16 байт   // НЕ session.ID (uint32, последовательный!)
```
Хранится в `core.Session` (новое поле `MigrateNonce [16]byte`) и в `relayEntry`
(§5.1). Энтропия 128 бит делает перебор `streamID(16 бит) × nonce` вычислительно
невозможным. **Явно запрещено** выводить nonce из публично-наблюдаемых данных
(session.ID, IP, timestamp) — только `crypto/rand`.

**streamSecret.** При создании стрима (на CONNECT) сервер вычисляет и кладёт в
relayEntry (для последующей сверки):
```
streamSecret = HMAC-SHA256(serverPerClientKey,
                           clientID ‖ globalStreamID ‖ session_nonce)
```
и передаёт клиенту в ответе на CONNECT (внутри уже зашифрованного канала
**оригинального** слота — устройство A). При MIGRATE/RESUME клиент предъявляет
`proofToken = streamSecret`. Сервер пересчитывает HMAC по `(clientID, globalStreamID,
session_nonce)` из relayEntry и сверяет:
```go
hmac.Equal(received, recomputed)   // constant-time — F12, ОБЯЗАТЕЛЬНО
```
(`crypto/hmac.Equal`; НЕ `bytes.Equal`).

**Разрешение проблемы shared clientID между устройствами (F2).** Device-limit допускает
несколько сессий на один clientID (`server/ratelimit.go` `activeSessions[userID]`).
`serverPerClientKey` ОДИН на оба устройства. НО proof привязан к `session_nonce`
**конкретной сессии**, в которой стрим создан. Устройство B НЕ видит `session_nonce`
устройства A — он передан в CONNECT-ответе по зашифрованному каналу сессии A (своя
per-slot крипта), B физически не может его прочитать. Чтобы устройство B подделало proof
стрима A, ему нужно угадать 128-битный nonce A → невозможно. **Это и есть
per-device binding** без отдельного per-device ключа: дискриминатор — непредсказуемый
session_nonce, а не clientID. Зафиксировать в спеке: relayEntry хранит `originClientID`
И `originSessionNonce`; MIGRATE/RESUME принимаются ТОЛЬКО если предъявленный proof
сходится с пересчётом по этим двум полям. Стрим, созданный в сессии A, можно мигрировать
только зная nonce A.

**Свойства:**
- Знать `streamSecret` может только владелец оригинальной сессии (получил по
  зашифрованному каналу). Внешний clientID — другой `serverPerClientKey`. Второе
  устройство того же clientID — не знает nonce A.
- Сервер хранит per-stream только `originSessionNonce` (16 байт) для сверки — ничтожно.
- Replay: после закрытия стрима relayEntry удаляется → proof не с чем сверить →
  `*_FAIL(not_found)`. session_nonce привязывает к конкретной сессии; завершённая
  сессия → nonce больше не активен.

### 4.2. Лимиты против DoS: память + FD budget (F5, F6 — HIGH)

**Worst-case расчёт.** Flow-окно Bug#8 — серверный cap `Config.FlowMaxWindow`
(`server/config.go:154 flowMaxWindowOrDefault`, `server/handler.go:40 flowMaxWindow`),
эффективное окно = `negotiateFlowWindow(clientWindow, serverMax)` =
`min(client, serverMax)` (`server/stream_credit.go:7`). Типичный serverMax в тестах/конфиге
**1 MB** (`1<<20`, `server/stream_credit_test.go:60`). Берём 1 MB как верхнюю границу
downBuffer (1 окно). Каждый осиротевший relay в grace держит:
- 1 open egress-TCP FD + kernel send/recv буферы (~64–256 KB, вне нашего управления).
- `downBuffer` ≤ 1 flow-окно (≤ серверный cap, worst-case 1 MB).
- relayEntry struct + nonce (≈ сотни байт).

При наивном `maxOrphanedTotal=4096`: 4096 × (1 MB buf + ~128 KB kernel) ≈ **4.5 GB**
+ **4096 FD**. На обычном `ulimit -n` (часто 1024–65536) FD исчерпываются РАНЬШЕ памяти и
бьют по легитимным новым соединениям. → старый default 4096 **отвергнут**.
(При меньшем serverMax — например 256 KB — память ниже, но FD-аргумент держится: FD —
доминирующий ограничитель независимо от размера окна.)

**Новые лимиты (пересчитаны под реальный сервер pl1, ulimit предполагаем 65536 FD,
делим бюджет: egress-TCP активных стримов + orphaned + listener overhead):**
- `maxOrphanedTotal` (default **1024**) — глобальная крышка осиротевших relay. Память
  worst-case ≈ 1024 × 256 KB ≈ **256 MB** + 1024 FD — приемлемо.
- **Отдельный FD-budget (F5).** Сервер ведёт `atomic.Int64 orphanedFDInUse` и
  `orphanFDBudget` (default = min(maxOrphanedTotal, ulimit_soft/4)). Перед переводом
  relay в orphaned проверяем budget; если исчерпан → relay НЕ осиротевший, сразу
  `tc.Close()` (деградация к текущему обрыву — не хуже). Метрика
  `shadowlink_orphan_fd_budget_rejected_total`. На старте сервер читает `getrlimit`
  (RLIMIT_NOFILE) и логирует выбранный budget.
- `maxOrphanedPerClient` (default **16**, было 32) — на clientID. Eviction-политика
  ниже.
- `gracePeriod` короткий (default 8s, env `SHADOWLINK_MIGRATE_GRACE`).
- `downBuffer` ограничен **1 окном flow-control** на стрим. Полон → backpressure
  тормозит чтение с egress-TCP (`tc.Read` не вызывается) → TCP-окно к сайту схлопывается,
  сайт притормаживает (естественно, без потери байт). Взаимодействие с dest-таймаутом —
  §5.5.

**Eviction-политика (F5 — НЕ бить по active-migrating).** При достижении
`maxOrphanedPerClient` выселяем **строго истинно-осиротевшие idle** entry (state=orphaned
И последняя downlink-активность старше `evictIdleThreshold`=2s) по LRU. Активно
мигрирующий стрим (state=active, boundSession в процессе смены) и недавно-осиротевший
(downlink ещё течёт в downBuffer) НЕ выселяются — лучше отклонить НОВЫЙ orphan
(`RESUME_FAIL(limit)`, стрим деградирует), чем убить уже спасаемый. Если все entry под
clientID active/недавние → новый orphan отклоняется.

**Защита от clientID-ротации (F6).** Whitelist-режим (`server/ratelimit.go`
`authorized_clients`) — обычно closed: набор clientID конечен и аутентифицирован, ротация
невозможна. Глобальный `maxOrphanedTotal=1024` + FD-budget — потолок при любом числе
clientID. **Риск open-mode** (пустой whitelist, тестовый): атакующий ротирует clientID,
обходя per-client лимит, упирается только в global+FD budget. Явно зафиксировано:
**в open-mode миграция-grace это amplification-вектор** (дешёвый WS-drop → дорогой
server-side hold egress-TCP+буфер); продакшн ВСЕГДА closed-whitelist (pl1 closed),
поэтому риск принят для prod, но для open-mode рекомендуется `SHADOWLINK_MIGRATE_GRACE=0`
(grace off, остаётся только упреждающая миграция A-жив, без orphaned-hold). Документируем
в §7.

### 4.3. Метрики (для канарейки)
```
shadowlink_migrate_ok_total
shadowlink_migrate_fail_total{reason}        # not_found|bad_proof|limit|dest_closed
shadowlink_migrate_timeout_total{kind}       # migrate|resume — F3 fail-safe сработал
shadowlink_resume_ok_total
shadowlink_resume_fail_total{reason}         # not_found|bad_proof|grace_expired|limit
shadowlink_orphaned_relays_active            # gauge
shadowlink_orphaned_evicted_limit_total      # выселено по per-client/total лимиту
shadowlink_orphan_fd_budget_rejected_total   # F5 — FD-budget исчерпан, relay не осиротел
shadowlink_migrate_grace_expired_total       # grace истёк без resume
shadowlink_stream_reassembly_buffered_bytes  # gauge — F1 client-side out-of-order буфер
shadowlink_stream_reassembly_overflow_total  # реассемблер-буфер переполнен по РАЗМЕРУ (§5.4)
shadowlink_stream_reassembly_gap_timeout_total # NEW-1 — дыра в seq не закрылась за gap-таймаут, стрим оборван
shadowlink_migrate_tail_resent_total         # NEW-1 — хвост unackedTail перепослан по B при смерти A (§5.3)
shadowlink_migrate_tail_buffered_bytes       # gauge NEW-1 — суммарный размер unackedTail
```

### 4.4. Анти-DPI (базовое; углублённое распределение — §5.6, F7)

MIGRATE/RESUME/StreamAck в зашифрованном payload = неотличимы от данных. Новый слот
создаётся штатным механизмом пула (тот же uTLS Chrome 133, та же негоциация) — миграция
**не добавляет** нового wire-сигнала на уровне отдельного фрейма. Per-stream seq (§3.1) —
8 байт ВНУТРИ шифротекста, не виден middlebox'у.

**Корреляционный риск (F7, MEDIUM) — вынесен в §5.6** как отдельный дизайн
распределения миграций во времени. Кратко: наивная упреждающая миграция «слот A
замолкает + слот B оживает за Δt до реза» — потенциальная НОВАЯ сигнатура (хуже
текущего reconnect-ПОСЛЕ-реза). §5.6 описывает рандомизацию момента, распределение
стримов одного слота и асинхронный переход нагрузки на B.

---

## 5. Data flow и жизненный цикл relay

### 5.1. relayRegistry (server-level, не per-WS-conn) + relayEntry

```go
relayRegistry: map[clientID] → map[globalStreamID] → *relayEntry   // RWMutex map-level

// binding пакует (session, writer) в ОДНУ единицу под единым atomic.Pointer (NEW-5).
// Прецедент в кодовой базе: core/session.go:27 sendEpoch{gcm, nonce} живёт под
// sendEpochPtr atomic.Pointer[sendEpoch] (session.go:79), читается одним Load() на
// каждом EncryptChunk (session.go:312) — ровно тот же приём «связанная пара под
// одним указателем, чтобы исключить торн-чтение несогласованной пары».
type binding struct {
    session *core.Session  // крипто-сессия активного слота
    writer  *wsWriter      // async writer того же слота
}

relayEntry struct {
    // Идентичность / proof
    originClientID    string
    globalStreamID    uint16
    originSessionNonce [16]byte    // §4.1 — для HMAC proof; из crypto/rand

    // Egress
    tc                net.Conn     // egress-TCP к сайту — ПЕРЕЖИВАЕТ смену слота

    // Динамическая привязка к крипто-сессии активного слота (F4 + NEW-5)
    // ОДИН atomic.Pointer на пару (session, writer) — НЕ два раздельных.
    // relay-loop делает binding := bound.Load() ОДИН раз за итерацию и видит
    // согласованную пару (либо обе старые, либо обе новые — никогда new sess +
    // old writer). reassociate делает ОДИН bound.Store(&binding{sessB, writerB}).
    bound             atomic.Pointer[binding]

    // Состояние (F8 — single-winner state-машина)
    state             atomic.Int32 // stActive | stOrphaned | stClosing (CAS-переходы)
    orphanedAt        atomic.Int64 // unix nanos, для grace-TTL

    // Порядок байт (F1) — счётчик НИКОГДА не сбрасывается при reassociate (NEW-3, §3.1)
    downSeqCounter    atomic.Uint64 // монотонный per-stream downlink seq (§3.1)
    downBuffer        *boundedBuffer // ≤1 flow-окно; буфер downlink в orphaned/grace
    // NEW-1: буфер недоACKнутого хвоста при упреждающей миграции. Чанки, отправленные
    // по слоту A, но ещё не подтверждённые FlagStreamAck. ≤1 flow-окно. FlagStreamAck
    // (ackedDownSeq=N) выкидывает всё с seq ≤ N. Если A умер ДО ack — перепосыл по B.
    unackedTail       *boundedBuffer // §5.3

    // Flow-control (F9 — credits переезжают сюда из per-WS-conn map)
    credit            *streamCredit  // Bug#8 bucket, жив через миграцию

    // FD-учёт (F5)
    holdsFD           bool           // учтён ли в orphanedFDInUse
    perEntryMu        sync.Mutex     // для не-atomic операций (смена tc и т.п.)
}
```

**Почему один atomic.Pointer, а не два (NEW-5, MEDIUM).** v2-спека делала ДВА раздельных
`boundSession.Store` + `boundWriter.Store`. Между ними есть микроокно, в котором relay-loop
загрузит **новый** `boundSession` + **старый** `boundWriter` (или наоборот) → зашифрует
чанк ключом слота B, но отправит в writer слота A → клиент A-reader не расшифрует ключом A
→ drop (лишняя потеря байт, нагрузка на реассемблер/overflow). Не corruption, но
устранимый класс гонок. Решение — упаковать в `binding{session, writer}` под одним
`atomic.Pointer[binding]`: один `Store` атомарно публикует согласованную пару, один
`Load` атомарно читает её. Стоимость нулевая (тот же один atomic-load, что и раньше),
прецедент `sendEpoch` уже в проде на горячем пути EncryptChunk.

**Single-winner state-машина (F8, MEDIUM).**
```
stActive ──(slot death, начало orphan)──► stOrphaned ──(grace expiry)──► stClosing ─► remove
   ▲                                          │
   └──────────── RESUME/MIGRATE OK ───────────┘  (CAS stOrphaned→stActive)
```
Все переходы через `state.CompareAndSwap`. Grace-таймер и RESUME — единственный
победитель: grace-таймер делает `CAS(stOrphaned, stClosing)`; RESUME делает
`CAS(stOrphaned, stActive)`. Кто первым выиграл CAS — тот и обработал. Проигравший
RESUME (таймер уже перевёл в stClosing) → `RESUME_FAIL(grace_expired)`, клиент
деградирует. Проигравший таймер (RESUME успел) → таймер видит state≠stOrphaned, НЕ
закрывает tc. Это закрывает дыру F8 «таймер закрыл tc но не удалил entry, RESUME
реассоциировал мёртвый tc» — RESUME никогда не реассоциирует entry в stClosing.

**Синхронизация:** RWMutex на registry (map find/add/delete) + atomic state + perEntryMu
для смены `tc`/буфера. Лок-порядок: registry.RLock → atomic CAS (без вложенного
registry-lock внутри perEntryMu, чтобы не было deadlock с eviction-проходом).

### 5.2. Relay-goroutine: динамическое чтение boundSession (F4, HIGH)

**Проблема (F4).** Сегодня relay-goroutine (`server/websocket.go:807-851`) шифрует через
`session.EncryptChunk` (`:831`), где `session` — захваченная **замыканием** сессия СТАРОГО
слота (параметр `runWebSocketSession`). Смена `boundSession` в relayEntry НЕ повлияет —
байты продолжат шифроваться ключом мёртвого слота → RESUME/MIGRATE бессмысленны.

**Рефакторинг (обязательный).** Relay-goroutine выносится из `runWebSocketSession` в
относящийся к `relayEntry` и читает привязку ДИНАМИЧЕСКИ на каждой итерации:

```go
// псевдокод relay-loop, привязанный к *relayEntry, НЕ к одной WS-conn
for {
    // credit (F9) — из entry, не из per-WS map
    if got := entry.credit.waitForCredit(entry.closeCh); got <= 0 { return }
    n, err := entry.tc.Read(buf[:limit])
    if n > 0 {
        // ОДИН atomic-load согласованной пары (session, writer) — NEW-5.
        // Невозможно прочитать new sess + old writer: они под одним указателем.
        b := entry.bound.Load()
        // seq присваивается ВСЕГДА (даже в окне без привязки), чтобы счётчик был
        // монотонен и непрерывен — буфер хранит чанк ПОД его seq (NEW-1 reorder-safe).
        seq := entry.downSeqCounter.Add(1)    // первый data → 1 (control=0, §3.1, NEW-2)
        frame := pendingDownFrame{seq: seq, data: copyOf(buf[:n])}
        if b == nil || b.session == nil || b.writer == nil {
            // окно миграции «нет привязки» (reassociate в полёте) — буферизуем
            entry.downBuffer.Push(frame)      // ≤1 flow-окно; полон → backpressure (§4.2)
            continue
        }
        // NEW-1: при упреждающей миграции держим короткий буфер недоACKнутого
        // хвоста — копию ИМЕННО под этим seq в entry.unackedTail. Освобождается
        // FlagStreamAck'ом клиента (§5.4). Если слот A подтверждённо умер ДО ack —
        // перепошлём хвост по новому слоту (см. §5.3 «буфер хвоста»).
        entry.unackedTail.Push(frame)         // ограничен 1 flow-окном; ack чистит
        chunk := core.NewStreamDataChunkSeq(b.session.ID, b.session.NextSeqNum(),
                                            entry.globalStreamID, seq, frame.data)
        enc, _ := b.session.EncryptChunk(chunk)
        b.writer.Enqueue(enc)                 // в async writer ТЕКУЩЕГО слота
        entry.credit.consume(n)
    }
    if err != nil { /* dest closed → §5.5 */ return }
}
```

> **NEW-4 (session-mu contention) — осознанный риск, см. §8.** `b.session.NextSeqNum()`
> берёт `s.mu.Lock()` (`core/session.go:127-133`). До рефакторинга F4 на одну сессию
> приходились relay-goroutine только её собственных стримов (сериализация приемлема).
> После F4, когда МНОГО стримов мигрировали на один слот B, их relay-loop'ы конкурируют
> за `s.mu` сессии B вместе с её reader/keepalive. Не corruption (mutex корректен), но
> потенциальный contention-регресс под нагрузкой. Внесено в риски §8 + нагрузочный
> acceptance §6. Это ОТДЕЛЬНО от «нет HoL» в §5.4 (то про `conn.Write` на клиенте,
> здесь — про серверный session-mu). `b.session.EncryptChunk` lock-free
> (sendEpochPtr.Load, session.go:312) — узкое место именно `NextSeqNum`, не Encrypt.

**Отвязка от `done` старого слота (F4).** Сегодня watchdog (`server/websocket.go:766-784`)
закрывает `tc` на `<-done` (смерть WS-conn). Это убивает egress-TCP вместе со слотом —
ровно то, что мы лечим. В новой схеме relay-goroutine живёт в `relayRegistry`, НЕ
привязан к `done` конкретной WS-conn. Смерть WS-conn слота A:
- НЕ закрывает `tc` (убираем watchdog-закрытие tc по done для migration-capable
  сессий — гейтится capability-флагом, для старых клиентов поведение прежнее).
- Переводит relayEntry в `stOrphaned` (если стрим не был упреждающе мигрирован) ИЛИ
  ничего не делает (если boundSession уже переключён на B — стрим уже на новом слоте).

relay-goroutine завершается только при: dest EOF/error (§5.5), grace-expiry close,
session-FIN от клиента, или превышении лимитов. Не при смерти отдельного WS-слота.

### 5.3. Поток A — упреждающая миграция (слот A жив)

1. Клиент: `age(slotA) > migrationThreshold` → для стрима 42 ставит миграцию в очередь
   (НЕ залпом — §5.6 распределение) → шлёт `MIGRATE(42, proof)` по слоту B с таймаутом
   `migrateAckTimeout` (§3.5).
2. Сервер: `hmac.Equal` proof (§4.1) → находит `relayEntry[clientID][42]` →
   `bound.Store(&binding{session: sessionB, writer: writerB})` (ОДИН atomic Store
   согласованной пары — NEW-5; relay-loop подхватит на следующей итерации) →
   `resumeDownSeq = downSeqCounter.Load()` → `MIGRATE_OK(42, resumeDownSeq)` по B.
3. **Downlink** (сайт→клиент): часть данных стрима 42 с seq ≤ resumeDownSeq ещё
   in-flight по сокету A (буферы CF/nginx/TCP), часть с seq > resumeDownSeq пойдёт по B.
   Клиентский **реассемблер** (§5.4) собирает по порядку независимо от того, по какому
   слоту чанк пришёл. **Uplink** (клиент→сайт): клиент после `MIGRATE_OK` шлёт uplink
   стрима 42 ТОЛЬКО по B (см. uplink-барьер ниже).
4. Слот A без активных стримов → штатный drain (координация с Bug#6 — §5.7).

**Буфер недоACKнутого хвоста A — основной механизм против NEW-1 (HIGH).** Корень NEW-1:
при упреждающей миграции хвост стрима 42 (seq N+1..N+4), который сервер УЖЕ отдал в
сокет A до переключения `bound`, ещё in-flight в буферах CF/nginx/TCP сокета A. Если
сокет A **внезапно умрёт посреди миграции** (close 1006 раньше, чем хвост долетел), эти
чанки потеряны навсегда → у клиента дыра в seq → реассемблер ждёт N+1, который никогда
не придёт. v2-спека утверждала «сервер НЕ обязан буферизовать при A-жив» — это и
создавало дыру. **Устраняем в корне:** сервер держит в `relayEntry.unackedTail`
короткий буфер чанков, отправленных по слоту A, но ещё НЕ подтверждённых клиентским
`FlagStreamAck` (§5.4). Буфер:
- Ограничен **1 flow-окном** (тот же `Config.FlowMaxWindow`, что downBuffer — §4.2):
  больше окна in-flight быть не может (credit-bucket Bug#8 не даст), поэтому хвост
  заведомо ≤ 1 окна. Память worst-case как у downBuffer (учтена в §4.2).
- **Освобождается лениво по `FlagStreamAck`:** клиент шлёт `ackedDownSeq=N` (наибольший
  seq, отданный приложению, §5.4) → сервер выкидывает из `unackedTail` всё с seq ≤ N.
  Пока ack не пришёл — хвост держится.
- **Перепосыл при подтверждённой смерти A ДО ack:** если слот A умер (его reader-error)
  ПОКА в `unackedTail` есть чанки с seq > последнего ack'нутого, И стрим уже привязан к
  B (boundSession=B по MIGRATE_OK), сервер **перепосылает** эти чанки по слоту B (в их
  исходном seq-порядке). Реассемблер клиента дедупит, если что-то всё же дошло и по A, и
  по B (`f.seq < expectedSeq` → drop дубля, §5.4) — by design идемпотентно. Это закрывает
  дыру: хвост не теряется, даже если A умер внезапно посреди миграции.
- Координация со state-машиной (§5.1): перепосыл хвоста делается под `perEntryMu`, после
  того как `bound` уже указывает на B; если стрим к моменту смерти A ещё НЕ мигрирован
  (boundSession всё ещё A) — это путь grace-fallback (§5.5), там работает `downBuffer`.

Таким образом NEW-1 закрыт ДВУМЯ слоями: (a) **серверный `unackedTail`** — основной, не
теряет данные; (b) **`reassemblyGapTimeout`** на клиенте (§5.4) — backstop, не виснет,
если хвост всё же неустраним (например A и B оба умерли).

**Uplink-барьер (доказательство корректности порядка uplink, F1).** Uplink из ОДНОГО
источника (локальный `conn.Read`, `proxy/socks5/tcp.go:652`). Клиент:
- До отправки MIGRATE — uplink стрима 42 идёт по A.
- После `client.StreamWrite` последнего uplink-чанка по A и отправки MIGRATE — НЕ шлёт
  новых uplink-чанков 42 по A; ждёт `MIGRATE_OK`, затем шлёт по B.
- Сервер: relay пишет на egress-TCP байты в порядке извлечения из WS-фреймов. Слот A
  reader дочитывает оставшиеся uplink-фреймы 42 ДО закрытия A (FIFO сокета A сохранён),
  слот B стартует ПОСЛЕ MIGRATE_OK. Клиент гарантирует, что не отправит по B uplink-чанк
  42 раньше, чем последний по A ушёл в сеть — порядок отправки на одном клиенте
  тривиально соблюдается (uplink-goroutine стрима 42 одна, последовательная). Поэтому
  uplink seq на проводе НЕ нужен — порядок гарантирован источником + барьером.

### 5.4. Client-side реассемблер downlink (F1, BLOCKER — центральный механизм)

**Где встроить.** Downlink-goroutine в `proxy/socks5/tcp.go:713-795` читает
`incomingCh` (= per-stream `streamChans[streamID]`, наполняется через `RouteToStream`,
`client/client.go:932`) и пишет `conn.Write(data)` (`:774`). Реассемблер вставляется
МЕЖДУ чтением из `incomingCh` и `conn.Write` — в этой же goroutine (естественная точка
сериализации одного стрима, никаких новых goroutine, нет HoL для других стримов).

**Почему здесь, а не в RouteToStream.** `RouteToStream`/`slotReaderWithClient` —
slot-agnostic демукс на горячем пути ВСЕХ стримов; держать там per-stream
переупорядочивающий буфер = усложнить общий путь и рисковать HoL. Downlink-goroutine
уже per-stream и уже сериализует запись в `conn` — идеальная точка.

**Контракт данных на проводе.** При capability=on `RouteToStream` доставляет в
`incomingCh` не голые байты, а `(downSeq uint64, data []byte)` (новый тип
`streamFrame{seq, data}` вместо `[]byte` в канале при миграционном режиме; для
старого режима — прежний `[]byte`). `slotReaderWithClient` парсит seq из
`NewStreamDataChunkSeq`-формата (§3.1) и кладёт `streamFrame` в канал.

**Алгоритм реассемблера (в downlink-goroutine):**
```
expectedSeq := 1                 // первый downlink-чанк стрима = seq 1 (§3.1, NEW-2)
pending := map[uint64]streamFrame // out-of-order буфер, ограничен reassemblyMaxBuffered
gapTimer := stopped              // NEW-1 backstop: взводится, когда есть данные за дырой
for {
    select {
    case f, ok := <-incomingCh:
        if !ok { return }        // канал закрыт (drain-teardown без migrating) — выход
        if f.seq == 0 {          // control (CONNECT_OK/FAIL) — без seq, как раньше (§3.1)
            handleControl(f); continue
        }
        if f.seq < expectedSeq { // дубль (мог прийти по A и по B, или перепосыл хвоста) — дроп
            continue
        }
        pending[f.seq] = f
        // слить непрерывный префикс
        for {
            nf, ok := pending[expectedSeq]
            if !ok { break }
            conn.Write(nf.data)      // строго по порядку
            cl.OnStreamConsumed(streamID, len(nf.data))  // credit назад (Bug#8)
            sendStreamAck(streamID, expectedSeq)          // барьер освобождения (§ниже)
            delete(pending, expectedSeq)
            expectedSeq++
        }
        if buffered(pending) > reassemblyMaxBuffered {    // защита ПАМЯТИ (по размеру)
            Stats.StreamReassemblyOverflow.Add(1)
            return  // рвём стрим — деградация, не повреждение (лучше обрыв, чем дыра)
        }
        // NEW-1 backstop: после слива префикса в pending остались чанки за дырой
        // (есть seq > expectedSeq, но самого expectedSeq нет) → дыра существует →
        // взвести gap-таймер. Если pending пуст → дыры нет → остановить таймер.
        if len(pending) > 0 {    // префикс уже слит выше, значит всё что осталось — за дырой
            if !gapTimer.running { gapTimer.Reset(reassemblyGapTimeout) }
        } else {
            gapTimer.Stop()
        }

    case <-gapTimer.C:           // NEW-1: expectedSeq НЕ продвинулся за окно ПРИ наличии
                                 // данных в pending → дыра неустранима → деградация
        Stats.StreamReassemblyGapTimeout.Add(1)
        return  // рвём стрим — НЕ виснем молча (закрывает регресс «не восстанавливается»)
    }
}
```
- **Идемпотентность дублей.** При миграции один и тот же seq может прийти и по A
  (in-flight), и по B (перепосыл хвоста, §5.3) — `f.seq < expectedSeq` дропает дубль.
  В норме сервер НЕ дублирует (downSeqCounter монотонный, NEW-3), но реассемблер
  устойчив к дублю by design.
- **Out-of-order приём.** Чанк B (seq=N+5) пришёл раньше хвоста A (seq=N+1..N+4) →
  лежит в `pending`, не пишется в conn, пока не придёт N+1. Порядок в `conn.Write`
  строго монотонный → TCP-поток приложения цел.
- **Граница буфера (по РАЗМЕРУ).** `reassemblyMaxBuffered` (default 4 MB или 64 чанка —
  env `SHADOWLINK_REASSEMBLY_BUFFER`). Переполнение → рвём стрим (деградация), НЕ пишем
  дыру. Метрика `shadowlink_stream_reassembly_overflow_total`.
- **Gap-таймаут (по ВРЕМЕНИ) — backstop NEW-1 (HIGH).** Размерная граница НЕ ловит
  сценарий «малый буфер, вечная дыра»: хвост A (seq N+1..N+4) потерян, по B пришло мало
  (только seq N+5, 3 KB ≪ 4 MB) → `expectedSeq` застрял на N+1, буфер НЕ переполнен →
  стрим **висел бы вечно молча** (ровно симптом «не восстанавливается», который Bug#9
  лечит). Backstop: `reassemblyGapTimeout` (default **2s**, env
  `SHADOWLINK_REASSEMBLY_GAP_TIMEOUT`). Взводится, когда в `pending` ЕСТЬ данные за
  дырой (есть `f.seq > expectedSeq`, но `expectedSeq` отсутствует), останавливается при
  закрытии дыры. Истёк → рвём стрим (деградация, не вечное зависание). Метрика
  `shadowlink_stream_reassembly_gap_timeout_total`.
  - **Обоснование значения 2s.** Чуть больше `migrateAckTimeout` (1.5s, §3.5):
    нормальный путь восполнения дыры — это либо приход хвоста A in-flight (микросекунды-
    миллисекунды сетевой буферизации CF/nginx/TCP), либо серверный перепосыл хвоста по B
    при смерти A (§5.3), который инициируется по reader-error слота A и ограничен тем же
    порядком, что MIGRATE_OK. 2s > 1.5s гарантирует, что перепосыл успеет долететь
    раньше срабатывания backstop в норме, а истечение означает реально неустранимую
    дыру (A и B оба умерли / перепосыл не дошёл). Не слишком велик, чтобы не держать
    приложение в подвешенном состоянии дольше человеко-заметного.
  - **Соотношение слоёв (NEW-1).** Основной механизм — серверный `unackedTail` +
    перепосыл (§5.3): в норме дыра восполняется, gap-таймер даже не успевает взвестись.
    Gap-таймаут — backstop ИМЕННО на случай, когда оба слота умерли и перепосылать
    некуда: тогда деградация (обрыв) вместо вечного зависания. Вместе они закрывают
    NEW-1: данные не теряются (буфер хвоста), а если всё же потеряны — не виснем
    (gap-таймаут).

**ACK как барьер освобождения серверного буфера (F1 + NEW-1 + OQ#1).** `FlagStreamAck`
(§3.3): клиент по мере слива непрерывного префикса шлёт серверу `ackedDownSeq =
expectedSeq-1` (наибольший отданный приложению). Сервер:
- Для **упреждающей** миграции (A жив): сервер держит `unackedTail` (§5.3) — копию
  отправленного по A, но ещё не подтверждённого хвоста. **Это исправляет внутреннее
  противоречие v2** («сервер не обязан буферизовать при A-жив»): он ОБЯЗАН держать
  короткий буфер (≤1 окно) недоACKнутого хвоста, потому что A может внезапно умереть
  посреди миграции с недоставленным in-flight хвостом (NEW-1). ACK ≥ N освобождает
  `unackedTail` до seq N; пока ack не пришёл — хвост держится. Если A умер ДО ack —
  хвост перепосылается по B (§5.3). Так хвост не теряется в корне.
- Для **grace/orphaned**: сервер держит `downBuffer` с seq > последнего ack'нутого. ACK
  ≥ N → сервер выкидывает из downBuffer всё ≤ N (освобождение). Предотвращает
  бесконечный рост downBuffer, если клиент медленно собирает.
- ACK throttled (не на каждый чанк — батч раз в ~50 мс или каждые K чанков, чтобы не
  плодить wire-сигнал). **НО** клиент шлёт ACK форсированно сразу после `MIGRATE_OK`
  (§3.3) — это минимизирует размер `unackedTail` к моменту реза слота A.
- **Граница буферов хвоста.** И `unackedTail`, и `downBuffer` ограничены 1 flow-окном
  (Bug#8 credit-bucket физически не даёт серверу отправить больше окна без ACK), поэтому
  ленивое освобождение не приводит к неограниченному росту даже при медленном клиенте:
  при полном буфере backpressure тормозит `tc.Read` (§4.2).

### 5.5. Поток B — grace-fallback (слот A умер внезапно) + dest-closed (F13)

1. Слот A: close 1006. Сервер: relay-goroutine НЕ закрывает `tc` (F4 отвязка). Переход
   `CAS(stActive → stOrphaned)`, `orphanedAt=now`, FD-budget check (§4.2): budget есть →
   relay продолжает `tc.Read` в `downBuffer` (ограничен 1 flow-окном; полон →
   backpressure, `tc.Read` не вызывается). Budget исчерпан → `tc.Close()`, деградация.
2. Клиент видит смерть слота A (`handleSlotDeath`, `client/ws_pool.go:3050`) → для каждого
   активного стрима слота A шлёт `RESUME(streamID, proof)` по живому слоту B с таймаутом.
3. Сервер: proof OK + `CAS(stOrphaned → stActive)` выиграл → `bound.Store(&binding{B,
   writerB})` (ОДИН atomic Store согласованной пары — NEW-5), сливает `downBuffer` на B
   по seq (реассемблер клиента соберёт), `RESUME_OK(streamID, resumeDownSeq,
   bufferedFromSeq)`.
4. grace истёк до RESUME → `CAS(stOrphaned → stClosing)` выиграл таймер → `tc.Close()`,
   удаление entry. Опоздавший RESUME → `RESUME_FAIL(grace_expired)`.

**dest-closed во время grace (F13).** Если сайт закрыл соединение (EOF на `tc.Read`)
ПОКА entry в orphaned: relay фиксирует `destClosed=true`, дочитывает остаток в
downBuffer, ставит финальный FIN-маркер в конец буфера. Состояние entry —
`stOrphaned` + `destClosed`. RESUME в окне → `RESUME_OK` + сервер сливает остаток
downBuffer + FlagFin стрима по B, затем удаляет entry. RESUME после dest-close, но буфер
пуст → `RESUME_OK` сразу с немедленным FlagFin (клиент закроет conn штатно).
**Взаимодействие backpressure↔dest-таймаут:** если downBuffer полон и сайт ждёт
(не читаем `tc`), сайт может сам таймаутить соединение — это эквивалентно медленному
клиенту в обычном режиме, корректно (сайт закроет → destClosed путь). Не хуже текущего
поведения, где медленный клиент так же давит backpressure.

### 5.6. Анти-DPI: распределение миграций во времени (F7, MEDIUM)

**Риск.** Наивная упреждающая миграция: за Δt до реза слота A клиент ЗАЛПОМ мигрирует
все его стримы на B → middlebox видит «A резко замолкает, B резко оживает» в коротком
окне, периодично перед каждой сменой слота. Это НОВАЯ сигнатура, хуже текущего
(reconnect происходит ПОСЛЕ реза, реактивно, не предсказуемо-периодично).

**Дизайн распределения (обязательный):**
1. **Рандомизированный момент старта миграции.** `migrationThreshold` (default 60s) НЕ
   фиксированная точка: фактический порог = `migrationThreshold × U(0.7, 1.0)` сэмплится
   ОДИН раз на слот при его создании (как byteBudget jitter, `poolSlot.byteBudget`
   docstring). Разные слоты мигрируют в разном возрасте → нет жёсткой периодики «всегда
   на 60s».
2. **Распределение стримов одного слота по времени (НЕ залп).** Стримы стареющего слота
   мигрируют не одновременно, а с per-stream джиттером: каждый стрим стартует миграцию в
   `t0 + U(0, migrationSpreadWindow)` (default spread 8s). На слоте с 10 стримами
   миграции размазаны по 8s, а не в одном кадре. A не «замолкает резко» — трафик
   стекает на B постепенно.
3. **B не берёт нагрузку синхронно с замолканием A.** Поскольку миграции стримов
   размазаны (п.2) и обычный фоновый трафик пула продолжается на других слотах, нет
   момента «B мгновенно подхватил весь объём A». Дополнительно: упреждающую миграцию
   запускаем заведомо РАНЬШЕ типичного реза (порог 60s ≪ рез 90-120s), так что к моменту
   реза A уже пуст и тих какое-то время — рез пустого слота неотличим от штатного drain
   (который уже есть в Bug#6 и не вызывал сигнатур по канарейкам).
4. **Проверка на периодичность (acceptance).** Канарейка должна подтвердить отсутствие
   FFT/ACF-пика на частоте миграций (как делали для jittered keepalive-тикеров в
   wire-trigger followup 2026-05-02). Если пик появится — увеличить spread window и
   рандомизацию порога. Зафиксировано в §6.

### 5.7. Координация drain (Bug#6) vs migration-в-полёте (F10, MEDIUM)

**Гонка (F10).** Drain слота A может стартовать (по byte-budget/возрасту,
`client/ws_pool.go:2833-2844` + rotationWatchdog) ПОКА миграция стрима 42 в полёте
(MIGRATE послан, MIGRATE_OK не пришёл). `handleSlotDeath`/drainTeardown
(`client/ws_pool.go:3067-3081`) закроет `streamChans[42]` → обрыв ДО завершения
миграции.

**Решение — миграция приоритетна над drain-teardown стрима:**
- Клиент ведёт per-stream флаг `migrating` (в `streamEntry`, `client/ws_pool.go`
  streamMap). Стрим помечается `migrating=true` при отправке MIGRATE, снимается при
  MIGRATE_OK/FAIL/timeout.
- `handleSlotDeath` при drain-teardown слота A: для стрима с `migrating=true` НЕ
  закрывает `streamChans` сразу — стрим уже переезжает на B, его канал общий
  (slot-agnostic), новый слот B продолжит наполнять тот же `streamChans[42]`. Закрытие
  пропускается; `streamMap`-entry переключается на slotIdx B по MIGRATE_OK.
- Если MIGRATE завершился timeout/FAIL (миграция не удалась) ПОСЛЕ старта drain →
  тогда стрим действительно рвётся (деградация, не хуже текущего) — закрываем канал.
- **Координация со sticky-drain (Bug#6).** Bug#6 backstop (drainWatchdog
  `StickyMaxDrainAge`/`StickyMaxTotalBytes`) удерживает слот в drain, пока есть активные
  стримы. Упреждающая миграция СНИМАЕТ активные стримы со слота РАНЬШЕ (порог 60s ≪
  sticky backstop 10m), поэтому к моменту sticky-проверки слот обычно уже без активных
  стримов = natural finish. Гонка остаётся только в узком окне (drain стартовал прямо в
  момент MIGRATE-в-полёте) — закрыта флагом `migrating` выше. Явно: `migrating`-стрим
  НЕ считается «active» для sticky-backstop teardown (он уезжает, не держит слот).

### 5.8. Граничные случаи
- **Двойной MIGRATE (A→B, потом A→C)** → последний выигрывает: `bound` атомарно
  становится `{C, writerC}` (один Store, NEW-5); `downSeqCounter` НЕ сбрасывается (NEW-3)
  → seq строго монотонен через A→B→C, реассемблер не дропнет валидные данные как ложные
  дубли. in-flight по B с seq > resumeDownSeq(C) реассемблер примет (seq монотонный,
  дубли по `f.seq < expectedSeq` дропаются). `MIGRATE_OK` по каждому. Идемпотентно при
  повторе на тот же слот.
- **MIGRATE на умирающий B** → `MIGRATE_FAIL`/timeout → клиент пробует другой живой
  слот; нет слотов → деградация (рвём).
- **MIGRATE/RESUME для несуществующего стрима** → `*_FAIL(not_found)`.
- **Гонка MIGRATE vs close слота A** → state-машина (§5.1): close переводит в
  stOrphaned (если не мигрирован); MIGRATE по B делает `CAS(stOrphaned→stActive)` —
  превращается в RESUME-семантику, entry найден, reassociate. Если MIGRATE выиграл
  раньше (boundSession уже B, state остался stActive) — close слота A не трогает entry
  (relay отвязан от done слота A, §5.2).
- **Реассемблер: вечная дыра** (хвост A потерян, B ушёл вперёд) → закрыто ДВУМЯ слоями
  (NEW-1): (a) серверный `unackedTail` + перепосыл хвоста по B при смерти A (§5.3) —
  в норме дыры не возникает; (b) если хвост всё же неустраним (A и B оба умерли) —
  клиентский `reassemblyGapTimeout` (2s) рвёт стрим (деградация), НЕ виснет вечно;
  размерный `reassemblyMaxBuffered` ловит параллельный случай большого буфера (§5.4).

### 5.9. Что НЕ меняется / переезжает
- Flow-control (Bug#8): credit-bucket **переезжает в relayEntry** (F9 — НЕ остаётся в
  per-WS-conn `credits` map `server/websocket.go:502`). При RESUME/MIGRATE relay-loop
  читает `entry.credit`, не локальную map. Остаток окна сохраняется через миграцию.
- keepalive (Bug#9) — на новом слоте свой (per-slot).
- Per-slot крипто цело (forward secrecy) — relay переключает `bound` (session+writer,
  NEW-5) server-side, ключи между слотами не шарятся.
- sticky-drain (Bug#6) — координация §5.7.
- UDP-стримы (SOCKS5 UDP ASSOCIATE) — **вне scope V1** (см. §8, OQ#5): UDP stateless,
  переподключение дёшево. Migration-логика TCP не затрагивает UDP-relay; смерть слота с
  UDP не ломает TCP-миграцию (UDP relay привязан к слоту через `udpMinReadySlots`,
  отдельный путь).

---

## 6. Тестирование (TDD)

### Core (unit)
- Build/parse `FlagMigrate`/`FlagResume`/`FlagStreamAck` фреймов (globalStreamID + 32-байт proof; ack + downSeq).
- Build/parse `NewStreamDataChunkSeq` (§3.1): `[StreamID(2)][downSeq(8)][data]` round-trip; старый формат без seq при capability=off.
- HMAC proof: вычисление, `hmac.Equal` verify валидного, отказ невалидного, отказ чужого clientID (другой serverPerClientKey), отказ при другом session_nonce (replay/второе устройство — F2).
- HKDF serverPerClientKey: детерминизм, разные clientID → разные ключи.
- session_nonce: 16 байт, источник crypto/rand (тест на не-нулевую энтропию, не равен session.ID — F2).

### Server (unit)
- relayRegistry: add/find/reassociate/remove, ключ `(clientID, globalStreamID)`; коллизия per-session streamID НЕ возникает (F11).
- relay-loop динамический `bound` (F4 + NEW-5): смена `bound.Store(&binding{...})` → следующая итерация шифрует НОВЫМ ключом и пишет в НОВЫЙ writer (тест: 2 сессии, переключение, дешифруется ключом B).
- credit-перенос (F9): credit жив через MIGRATE/RESUME, `waitForCredit` не возвращает 0 после переключения; остаток окна сохранён.
- **`unackedTail` + перепосыл хвоста (NEW-1):** упреждающая миграция, хвост отправлен по A → `unackedTail` непуст; FlagStreamAck(N) → `unackedTail` очищен до seq N; A умер ДО ack ПРИ непустом `unackedTail` и bound=B → хвост перепослан по B в исходном seq-порядке, `tail_resent_total` тикнул; A умер ПОСЛЕ полного ack → перепосыла нет.
- **bound — единый atomic (NEW-5):** `bound.Store(&binding{B, writerB})` → relay-loop следующей итерацией читает СОГЛАСОВАННУЮ пару (session B + writer B); НЕ существует промежуточного состояния new-session+old-writer (тест: race-проверка многократного Store при конкурентном Load — пара всегда согласована).
- **Монотонность downSeqCounter через A→B→C (NEW-3):** двойная миграция, seq строго возрастает через обе reassociate, counter НЕ сбрасывается; клиентский реассемблер НЕ дропает валидные C-чанки как ложные дубли.
- single-winner state-машина (F8): CAS orphaned→active (RESUME) vs orphaned→closing (timer) — ровно один победитель в обеих очерёдностях; проигравший RESUME → FAIL(grace_expired), проигравший timer НЕ закрывает tc.
- grace TTL: orphaned → expired → close.
- Лимиты: maxOrphanedPerClient (eviction НЕ бьёт active-migrating — F5), maxOrphanedTotal, FD-budget reject (F5).
- downBuffer: backpressure при переполнении (1 flow-окно); dest-closed во время grace → FIN+остаток (F13).
- Гонка MIGRATE vs close (state-машина, обе очерёдности).

### Server (integration)
- Упреждающая миграция A→B: стрим качает (>1 MB), миграция, байты целы и **в порядке** (реассемблер на клиенте, in-flight A + B без переупорядочивания) — F1 acceptance.
- Grace-resume: внезапная смерть A, RESUME с B в окне → стрим продолжается, downBuffer слит по seq.
- RESUME_FAIL на плохой proof / истёкший grace.
- Double-MIGRATE (A→B→C) идемпотентность + порядок байт сохранён.

### Client (unit)
- **Реассемблер (F1):** out-of-order приём (B-чанк раньше хвоста A) → `conn.Write` строго по seq; дубль (seq<expected) дропается; overflow буфера по РАЗМЕРУ → стрим рвётся (не дыра).
- **Gap-таймаут реассемблера (NEW-1):** дыра в seq при МАЛОМ буфере (хвост N+1..N+4 потерян, пришёл только N+5 = 3 KB, буфер НЕ переполнен) → стрим рвётся по `reassemblyGapTimeout`, НЕ виснет; счётчик `gap_timeout_total` тикнул. Дыра, закрытая ВОВРЕМЯ (пришёл N+1 до таймаута) → таймер сброшен, стрим продолжается, gap_timeout НЕ тикнул.
- **Стартовая нумерация + guard (NEW-2):** первый data-чанк = seq 1; control = seq 0 (handleControl, не в pending); seq-чанк длиной <10 байт отброшен guard'ом (`len<10`), НЕ распарсен как legacy streamID; legacy-режим (capability off) использует guard `<2`.
- age-watchdog триггерит MIGRATE на распределённом пороге (jitter U(0.7,1.0), не фиксированный) — F7.
- распределение стримов слота: миграции НЕ залпом, spread по времени (F7).
- uplink-барьер: не шлёт по старому слоту после MIGRATE.
- RESUME при смерти слота; FlagStreamAck отправка throttled.
- capability fail-safe (F3): нет OK/FAIL за migrateAckTimeout → стрим рвётся (деградация), клиент НЕ зависает; гистерезис снятия capability после ≥3 timeout.
- drain-координация (F10): `migrating`-стрим не закрывается drainTeardown; после FAIL/timeout по drain — рвётся.
- Fallback: рвём стрим при отсутствии живых слотов (деградация не хуже текущего).

### Compat matrix
- Новый клиент ↔ старый сервер (capability off → миграция не активируется, поведение как сейчас).
- Старый клиент ↔ новый сервер (то же).

### Race / HoL / Perf
- Миграция не блокирует другие стримы слота (нет HoL на клиентском conn.Write).
- **session-mu contention (NEW-4, нагрузочный):** смигрировать СОТНИ стримов на ОДИН целевой слот B, гнать downlink-трафик по всем → замерить contention на `s.mu` сессии B (`NextSeqNum`) + throughput/latency регрессию vs baseline (стримы распределены по нескольким слотам). Acceptance: contention не вызывает заметной деградации throughput; если вызывает — применить митигацию из §8 (atomic sendSeq или ограничение стримов на слот через §5.6 spread). Профилировать `go test -bench` / `-mutexprofile`.
- `go test -race -count=3 ./core/ ./client/ ./server/` (Linux/CI — Windows без gcc).

### Полевая канарейка (acceptance)
- `ch closed` резко падает (был 371 за 39 мин).
- `migrate_ok` растёт, `resume_ok` появляется при внезапных резах.
- Обрывы долгих стримов (агент) исчезают — главный acceptance-критерий от юзера.
- Быстрые закачки (>1 MB) переживают рез слота без «Ошибка сети» в Chrome (F1 в поле).
- `orphaned_relays_active` ограничен (не растёт неограниченно = нет утечки/DoS).
- `orphan_fd_budget_rejected_total` низок (budget не давит легитимный трафик); FD на сервере не исчерпываются (F5).
- `stream_reassembly_overflow_total` ≈ 0 (реассемблер-буфер не переполняется в норме по размеру).
- `stream_reassembly_gap_timeout_total` ≈ 0 (дыры в seq восполняются `unackedTail`/перепосылом в норме — NEW-1; ненулевой рост = хвост теряется, копать перепосыл).
- `migrate_tail_resent_total` низок (перепосыл хвоста — редкий путь, только при смерти A до ack); `migrate_tail_buffered_bytes` ограничен (≤1 окно/стрим, NEW-1).
- decrypt_fails=0, closed_pipe=0 (Bug#8 не сломан).
- **Анти-DPI (F7):** FFT/ACF по таймстемпам миграций НЕ показывает периодического пика (как проверяли jittered keepalive-тикеры в wire-trigger followup). Рез слота происходит, когда слот УЖЕ пуст/тих (миграция успела заранее) — неотличимо от штатного drain.

### Pre-flight (рекомендация ревью — сохранена)
Перед полным деплоем измерить долю длинных vs коротких стримов в обрывах (уже сделано:
§1 — 291/371 длинные малотрафичные, 278/371 <10 KB). Подтверждает выбор полного A:
основная боль — длинные стримы (для них миграция критична), но быстрые закачки тоже
покрыты реассемблером. Quiesce-only отвергнут осознанно (§1).

---

## 7. ENV флаги

| Флаг | Default | Эффект |
|---|---|---|
| `SHADOWLINK_STREAM_MIGRATION` | on | `=0/false/no/off` — миграция off (capability не анонсируется, seq-формат не используется), поведение как сейчас. Главный kill-switch. |
| `SHADOWLINK_MIGRATE_THRESHOLD` | 60s | Базовый возраст слота для начала упреждающей миграции. Фактический порог = base × U(0.7,1.0) per-slot (F7 jitter). |
| `SHADOWLINK_MIGRATE_SPREAD` | 8s | Окно распределения миграций стримов одного слота (F7 — не залп). |
| `SHADOWLINK_MIGRATE_GRACE` | 8s | Сервер: сколько держать осиротевший relay для RESUME. `=0` → grace off (только упреждающая миграция; рекомендуется для open-mode, F6). |
| `SHADOWLINK_MIGRATE_MAX_ORPHANED` | 16 | Лимит осиротевших relay на clientID (был 32; F5). |
| `SHADOWLINK_MIGRATE_MAX_ORPHANED_TOTAL` | 1024 | Глобальная крышка осиротевших relay (был 4096; F5). |
| `SHADOWLINK_MIGRATE_ACK_TIMEOUT` | 1.5s | Таймаут ожидания MIGRATE_OK/RESUME_OK; истёк → деградация к обрыву (F3 fail-safe). |
| `SHADOWLINK_REASSEMBLY_BUFFER` | 4MB | Клиент: предел out-of-order буфера реассемблера на стрим (по РАЗМЕРУ); переполнение → рвём стрим (F1). |
| `SHADOWLINK_REASSEMBLY_GAP_TIMEOUT` | 2s | Клиент: backstop NEW-1 — если дыра в seq не закрылась за это окно ПРИ наличии данных за дырой → рвём стрим (деградация, не вечное зависание). >migrateAckTimeout (1.5s), чтобы перепосыл хвоста (§5.3) успел в норме. |

Размер downBuffer (верх = 1 flow-окно) НЕ нов: берётся из существующего серверного
`Config.FlowMaxWindow` (Bug#8, `server/config.go:154`), эффективное окно =
`negotiateFlowWindow(client, serverMax)` (`server/stream_credit.go:7`). Server-side
FD-budget (`orphanFDBudget`) НЕ env — вычисляется на старте из
`getrlimit(RLIMIT_NOFILE)`: `min(maxOrphanedTotal, soft_limit/4)`, логируется (F5).

## 8. Объём и риски

- **Объём:** XL (> Bug#6 + Bug#8 — добавился реассемблер + relay-loop рефакторинг).
  Затрагивает:
  - `core/chunk.go` — `NewStreamDataChunkSeq` + seq-парсинг, `FlagMigrate/Resume/StreamAck`.
  - `core/flowctl.go` — расширение capability-маркера migration-битом.
  - `core/session.go` — поле `MigrateNonce [16]byte` (crypto/rand при создании сессии).
  - новый `core/migrate.go` — HKDF serverPerClientKey, HMAC proof, build/parse migrate-фреймов.
  - `server/websocket.go` — вынос relay-goroutine из `runWebSocketSession`, отвязка tc от `done`, динамический boundSession, credit в relayEntry.
  - `server/handler.go` — установка relayEntry на CONNECT под `(clientID, globalStreamID)`.
  - новый `server/relay_registry.go` — registry, state-машина, grace-timer, eviction, FD-budget, `binding{session,writer}` под одним atomic.Pointer (NEW-5), `unackedTail` буфер хвоста + перепосыл по B при смерти A (NEW-1), инвариант немонотонности downSeqCounter (NEW-3).
  - `client/ws_pool.go` — age-watchdog (распределённый), MIGRATE/RESUME отправка, seq-парсинг в `slotReaderWithClient`, drain-координация (`migrating` флаг), capability fail-safe.
  - `client/client.go` — `RouteToStream` доставляет `streamFrame{seq,data}` в migration-режиме.
  - `proxy/socks5/tcp.go` — **реассемблер в downlink-goroutine** (между incomingCh и conn.Write), `reassemblyGapTimeout` backstop (NEW-1), стартовая нумерация expectedSeq=1 (NEW-2), uplink-барьер, FlagStreamAck отправка.
- **Главный риск (F1, BLOCKER — ЗАКРЫТ):** порядок байт. Решён per-stream wire seq (§3.1)
  + client-side реассемблер (§5.4) + ACK-барьер. Приоритет в тестах: out-of-order,
  дубли, overflow.
- **Релейный рефакторинг (F4, HIGH — ЗАКРЫТ):** relay-goroutine читает `bound`
  (session+writer одним atomic.Pointer, NEW-5) динамически, отвязан от `done` слота. Это
  центральная механика, без неё переключение не работает (§5.2).
- **Потеря хвоста при упреждающей миграции (NEW-1, HIGH — ЗАКРЫТ):** при внезапной
  смерти A посреди миграции in-flight хвост A мог теряться → вечно висящий стрим. Закрыто
  серверным `unackedTail` (буфер недоACKнутого хвоста + перепосыл по B при смерти A до
  ack, §5.3) КАК ОСНОВНОЙ механизм + клиентским `reassemblyGapTimeout` (2s backstop,
  §5.4) на случай неустранимой дыры. Устранено внутреннее противоречие «сервер не обязан
  буферизовать при A-жив».
- **session-mu contention в relay-loop (NEW-4, MEDIUM — ПРИНЯТЫЙ РИСК):** после F4
  несколько relay-loop разных стримов, мигрировавших на ОДИН слот B, вызывают
  `b.session.NextSeqNum()` (`core/session.go:127-133`, берёт `s.mu.Lock()`) конкурентно
  друг с другом И с reader/keepalive сессии B. Не corruption (mutex корректен), но
  потенциальный contention-регресс при высокой концентрации стримов на одном слоте.
  `EncryptChunk` уже lock-free (sendEpochPtr.Load, `session.go:312`) — узкое место именно
  `NextSeqNum`. Митигация при необходимости (на этапе плана/после нагрузочного теста):
  per-session sendSeq на atomic вместо mutex (как уже сделано для sendEpoch) ЛИБО
  ограничение макс. числа стримов на один целевой слот при миграции (размазывание по
  нескольким молодым слотам — естественно вытекает из §5.6 spread). Замер обязателен —
  нагрузочный acceptance в §6. ОТДЕЛЬНО от «нет HoL» (§5.4, то про клиентский conn.Write).
- **DoS/FD (F5/F6 — ЗАКРЫТЫ):** worst-case посчитан (§4.2), отдельный FD-budget,
  лимиты пересчитаны (1024/16), eviction не бьёт active-migrating, open-mode риск
  задокументирован + рекомендация grace=0.
- **Анти-DPI корреляция (F7 — ЗАКРЫТ):** распределение миграций во времени §5.6 +
  FFT/ACF acceptance в канарейке.
- **Деградация:** при любом неуспехе миграции (нет слотов, истёк grace/timeout, плохой
  proof, overflow реассемблера, FD-budget) стрим рвётся как сейчас — регрессии нет,
  только улучшение. Fail-safe (F3) гарантирует, что клиент не зависает.

## 9. Rollback
- Клиент: `SHADOWLINK_STREAM_MIGRATION=0` → миграция off (capability не анонсируется,
  seq-формат не используется → старый wire-формат). Поведение строго как до Bug#9.
- Сервер: capability off если клиент не анонсирует; per-стрим fail-safe (F3) деградирует
  даже при ошибочной capability. Полный откат — revert + redeploy pre-Bug9-migration
  бинаря. Поскольку seq-формат гейтится capability per-session, смешанный парк
  (старые+новые бинари) безопасен: каждая сессия использует формат по своей negotiation.
- Аварийно сузить поверхность без полного отката: `SHADOWLINK_MIGRATE_GRACE=0` (off
  grace/orphaned-hold, остаётся только упреждающая миграция A-жив — нулевой DoS-риск
  orphaned), либо снизить лимиты через env.

---

## Open questions — РЕШЕНО (по итогам ревью `docs/bug9-spec-review-opus.md`)

1. **seqBarrier vs реассемблер — РЕШЕНО (F1).** seqBarrier НЕдостаточен. Введён
   per-stream monotonic downlink seq на проводе (§3.1) + client-side реассемблер (§5.4),
   собирающий out-of-order строго по seq перед `conn.Write`, + `FlagStreamAck` как барьер
   освобождения серверного downBuffer. Это закрывает BLOCKER F1.
2. **Анти-DPI распределение — РЕШЕНО (F7).** Только age-jitter недостаточен. §5.6:
   рандомизированный порог per-slot (×U(0.7,1.0)), распределение стримов слота по окну
   spread (8s, не залп), B не берёт нагрузку синхронно, рез происходит на уже-пустом
   слоте; FFT/ACF-проверка в acceptance.
3. **session_nonce — РЕШЕНО (F2).** Хранится в relayEntry (`originSessionNonce [16]byte`,
   +память ничтожна) И в `core.Session.MigrateNonce`. Энтропия: 16 байт `crypto/rand`,
   ЯВНО не из session.ID/публичных данных. Закрывает BLOCKER F2 + per-device binding.
4. **sticky-drain (Bug#6) — РЕШЕНО (F10).** Координация §5.7: per-stream `migrating`
   флаг, миграция приоритетна над drain-teardown, migrating-стрим не считается active для
   sticky-backstop. Узкое окно гонки закрыто.
5. **UDP — РЕШЕНО (OQ#5).** Вне scope V1 (§5.9, §8): UDP stateless, переподключение
   дёшево. Migration-логика TCP не затрагивает UDP-relay; смерть слота с UDP не ломает
   TCP-миграцию (UDP привязан к слоту через `udpMinReadySlots`, отдельный путь).

## Закрытие находок ревью (трассировка F1–F13 + NEW-1..NEW-5)

| # | Sev | Где закрыто |
|---|-----|-------------|
| F1 | BLOCKER | §3.1 per-stream wire seq + §5.4 реассемблер + ACK-барьер |
| F2 | BLOCKER | §4.1 crypto/rand 16-байт nonce + HKDF + per-device binding через nonce + hmac.Equal |
| F3 | HIGH | §3.5 migrateAckTimeout fail-safe + гистерезис снятия capability |
| F4 | HIGH | §5.2 динамический boundSession (atomic.Pointer) + отвязка relay от `done` |
| F5 | HIGH | §4.2 worst-case расчёт + FD-budget + лимиты 1024/16 + eviction не бьёт active-migrating |
| F6 | HIGH | §4.2 open-mode amplification задокументирован + grace=0 рекомендация + closed-whitelist prod |
| F7 | MEDIUM | §5.6 распределение миграций + §6 FFT/ACF acceptance |
| F8 | MEDIUM | §5.1 single-winner CAS state-машина orphaned→{active|closing} |
| F9 | MEDIUM | §5.9 + §5.1 credit-bucket переезжает в relayEntry |
| F10 | MEDIUM | §5.7 drain vs migration координация (`migrating` флаг, приоритет миграции) |
| F11 | LOW | §3.6 ключ registry `(clientID, globalStreamID)`, server берёт streamID из CONNECT |
| F12 | LOW | §4.1 `hmac.Equal` зафиксирован явно |
| F13 | LOW | §5.5 dest-closed во время grace + backpressure↔dest-таймаут |
| NEW-1 | HIGH | **РЕШЕНО** — §5.3 серверный `unackedTail` (буфер недоACKнутого хвоста + перепосыл по B при смерти A до ack) КАК ОСНОВНОЙ механизм + §5.4 `reassemblyGapTimeout` (2s) как backstop. Устранено противоречие «сервер не обязан буферизовать при A-жив». ОБА слоя. |
| NEW-2 | MEDIUM | **РЕШЕНО** — §3.1: control=seq 0, первый data=seq 1; counter стартует так, что `Add(1)`→1; клиентский guard `len(payload)<2` → `<10` в seq-режиме. |
| NEW-3 | MEDIUM | **РЕШЕНО** — §3.1 hard-инвариант: `downSeqCounter` НИКОГДА не сбрасывается при reassociate (MIGRATE_OK/RESUME_OK), только при удалении entry. Защита dedup A→B→C. |
| NEW-4 | MEDIUM | **РЕШЕНО** (принятый риск + замер) — §8 риск session-mu contention в relay-loop + митигация (atomic sendSeq / spread по слотам) + §6 нагрузочный perf-acceptance. |
| NEW-5 | MEDIUM | **РЕШЕНО** — §5.1 `binding{session,writer}` под ОДНИМ `atomic.Pointer[binding]` (прецедент `sendEpoch` core/session.go:27,312); один Store/Load согласованной пары в §5.2/§5.3/§5.5. |

> **Первое ревью (`docs/bug9-spec-review-opus.md`):** 13 буквенных находок F1–F13
> (BLOCKER×2 [F1,F2], HIGH×5, MEDIUM×4, LOW×4 — 15 по severity-сумме). Все 13 закрыты в
> v2. Все 10 пунктов «Что ОБЯЗАТЕЛЬНО исправить»:
> 1. F1 реассемблер+seq+ACK → §3.1, §5.4 ✓
> 2. F2 nonce/KDF/per-device → §4.1 ✓
> 3. F4 relay-loop boundSession → §5.2 ✓
> 4. F9 credit перенос → §5.9 ✓
> 5. F3 ack-timeout fail-safe → §3.5 ✓
> 6. F5/F6 DoS память+FD → §4.2 ✓
> 7. F7 анти-DPI распределение → §5.6 ✓
> 8. F8 single-winner state-машина → §5.1 ✓
> 9. F10 drain vs migration → §5.7 ✓
> 10. F11/F12 streamID уникальность + hmac.Equal → §3.6, §4.1 ✓
>
> **Повторное ревью (`docs/bug9-spec-review-opus-v2.md`, вердикт READY-WITH-CHANGES):**
> 5 НОВЫХ находок (1 HIGH + 4 MEDIUM), все 5 пунктов «Что ОБЯЗАТЕЛЬНО до writing-plans»
> закрыты в v3:
> 1. NEW-1 gap-таймаут + буфер хвоста (ОБА) → §5.3 `unackedTail`+перепосыл, §5.4 `reassemblyGapTimeout` ✓
> 2. NEW-3 downSeqCounter немонотонный инвариант → §3.1 ✓
> 3. NEW-2 control=seq0 / data=seq1 + guard `<10` → §3.1 ✓
> 4. NEW-5 `binding{session,writer}` один atomic.Pointer → §5.1, §5.2, §5.3, §5.5 ✓
> 5. NEW-4 session-mu contention → §8 риск + §6 нагрузочный acceptance ✓

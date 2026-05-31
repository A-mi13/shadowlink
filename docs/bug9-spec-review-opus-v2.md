# Bug #9 — Повторное независимое опус-ревью (REVISED-v2)

**Дата:** 2026-05-31
**Ревьюер:** независимый (повторный проход после первого NOT-READY)
**Спека:** `docs/superpowers/specs/2026-05-31-bug9-stream-migration-design.md` (REVISED-v2)
**Первое ревью:** `docs/bug9-spec-review-opus.md` (2 BLOCKER + 5 HIGH + 4 MEDIUM + 4 LOW)
**Код перечитан (не на слово):** core/chunk.go, core/session.go, server/websocket.go (480-600, 750-960), server/stream_credit.go, server/config.go, client/client.go (670-720, 900-950), client/ws_pool.go (2740-2860, 3045-3095), proxy/socks5/tcp.go (640-810), go.mod

---

## ВЕРДИКТ: READY-WITH-CHANGES

Доработка **закрыла оба BLOCKER реально, не на словах** — введён per-stream wire seq + client-side реассемблер с границей буфера и gap-overflow деградацией; крипто-proof переведён на crypto/rand 16-байт nonce + HKDF + per-device binding через непредсказуемость nonce + `hmac.Equal`. Все 5 HIGH и 4 MEDIUM/LOW адресованы предметно и согласованы с фактическим кодом (проверено: credits — WS-conn-scoped map `websocket.go:502`; relay захватывает `session` замыканием `:830`; watchdog рвёт `tc` на `<-done` `:778-784`; `UnknownFlag` `:930`; `FlowMaxWindow` default 1 MiB; `x/crypto` присутствует для HKDF).

Спека на уровне дизайна готова. НЕ ставлю чистый READY, потому что доработка породила **несколько НОВЫХ конкретных дефектов корректности** (1 HIGH + 4 MEDIUM), которые должны быть зафиксированы в спеке ДО writing-plans, иначе план их унаследует как баги реализации. Все они локальны (не требуют пересмотра архитектуры) — отсюда READY-WITH-CHANGES, а не повторный NOT-READY.

**Из 13 находок первого ревью: 12 ЗАКРЫТО полностью, 1 ЗАКРЫТА частично (F1 — корень закрыт, но осталась дыра в gap-таймауте/перф atomic; см. ниже).**

---

## Таблица: статус находок F1–F13

| # | Sev | Статус | Обоснование (по коду + тексту) |
|---|-----|--------|--------------------------------|
| F1 | BLOCKER | **ЧАСТИЧНО (≈90%)** | §3.1 вводит `[StreamID(2)][downSeq(8)][data]` + §5.4 реассемблер. Корень закрыт верно: проверено `client.go:932 RouteToStream` и `ws_pool.go:2795/2819` — оба reader'а действительно пушат в общий `streamChans[streamID]`, порядок вставки из 2 сокетов недетерминирован → реассемблер нужен. Реассемблер: out-of-order буфер, дроп дублей (`seq<expected`), монотонный слив, граница `reassemblyMaxBuffered`, overflow→рвём (не дыра) — корректно. downSeq живёт в `relayEntry.downSeqCounter` (переживает миграцию) — верно. **НО осталось:** (а) НЕТ gap-таймаута — если хвост A навсегда потерян, но буфер НЕ достиг лимита, стрим висит вечно без write и без обрыва (NEW-1 HIGH ниже); (б) `expectedSeq:=1` хардкод противоречит §5.4-control-ветке (NEW-3); (в) перф atomic.Load на hot-loop (NEW-4, низкий). Главная угроза повреждения данных снята — потому ≈закрыто, но не на 100%. |
| F2 | BLOCKER | **ЗАКРЫТО** | §4.1: `session_nonce` = crypto/rand 16 байт, ЯВНО запрещён вывод из session.ID/публичных данных (проверено: `session.ID uint32` последовательный в `session.go:506`, был бы перебираем — спека это прямо адресует). HKDF salt=`"shadowlink-migrate-v1"`, info=clientID. proof = HMAC(perClientKey, clientID‖globalStreamID‖nonce). Shared-clientID закрыт: nonce A передан по зашифрованному каналу сессии A, устройство B физически не видит → 128 бит перебора. Replay закрыт: relayEntry удаляется при close → not_found. Корректно и полно. |
| F3 | HIGH | **ЗАКРЫТО** | §3.5: `migrateAckTimeout`=1.5s, истёк→деградация (рвём как сейчас), клиент не зависает. Подтверждено кодом: старый сервер реально молча проглотит FlagMigrate (`websocket.go:929-930 default→UnknownFlag`). Гистерезис снятия capability после ≥3 timeout — разумно. |
| F4 | HIGH | **ЗАКРЫТО** | §5.2: relay-loop выносится из `runWebSocketSession`, читает `boundSession.Load()` каждую итерацию + отвязка от `done`. Подтверждено: сейчас `session` captured замыканием (`:830`), watchdog рвёт tc на `<-done` (`:778-784`) — спека верно идентифицирует ОБА места как обязательные к рефакторингу. Псевдокод корректен. |
| F5 | HIGH | **ЗАКРЫТО** | §4.2: worst-case посчитан (1024×256KB≈256MB+1024 FD), отдельный `orphanFDBudget`=min(max,ulimit/4) через getrlimit, eviction бьёт только idle-orphaned (state=orphaned И >evictIdleThreshold), НЕ active-migrating. Лимиты 4096→1024 / 32→16. Полно. |
| F6 | HIGH | **ЗАКРЫТО** | §4.2: open-mode amplification явно задокументирован как принятый риск + рекомендация `SHADOWLINK_MIGRATE_GRACE=0`; prod всегда closed-whitelist (pl1). §9 повторяет grace=0 как аварийное сужение. Адекватно. |
| F7 | MEDIUM | **ЗАКРЫТО** | §5.6: рандомизация порога ×U(0.7,1.0) per-slot, spread стримов U(0,8s) не залпом, B не берёт нагрузку синхронно, рез на уже-пустом слоте + FFT/ACF acceptance в §6. Гораздо глубже простого age-jitter. |
| F8 | MEDIUM | **ЗАКРЫТО** | §5.1: single-winner CAS `stOrphaned→{stActive\|stClosing}`; проигравший RESUME→FAIL(grace_expired), проигравший timer не трогает tc. Дыра «реассоциация мёртвого tc» закрыта: RESUME никогда не видит stClosing. Корректно. |
| F9 | MEDIUM | **ЗАКРЫТО** | §5.9+§5.1: credit-bucket переезжает в `relayEntry.credit`. Подтверждено: сейчас `credits map` локальна в `runWebSocketSession` (`:502`), новый слот создал бы пустую — спека верно требует перенос. relay-loop читает `entry.credit`. |
| F10 | MEDIUM | **ЗАКРЫТО** | §5.7: per-stream `migrating` флаг в streamEntry; `handleSlotDeath`/drainTeardown пропускает close для migrating-стрима; migrating не считается active для sticky-backstop. Подтверждено: `handleSlotDeath:3067-3081` closes streamChans для всех стримов слота — спека верно ловит гонку. |
| F11 | LOW | **ЗАКРЫТО** | §3.6: ключ registry `(clientID, globalStreamID)`, server берёт streamID из CONNECT-payload (`NewStreamConnectChunk`, `chunk.go:202`), не генерит сам. Подтверждено: `NextStreamID` (`client.go:684`) per-Client, уникален на клиенте. Верно. |
| F12 | LOW | **ЗАКРЫТО** | §4.1: `hmac.Equal` зафиксирован явно, НЕ bytes.Equal. |
| F13 | LOW | **ЗАКРЫТО** | §5.5: dest-closed во время grace → destClosed флаг + FIN-маркер в конец downBuffer + взаимодействие backpressure↔dest-таймаут описано как «не хуже текущего». Корректно. |

Counts: **ЗАКРЫТО полностью = 12/13**, ЧАСТИЧНО = 1 (F1), НЕ-ЗАКРЫТО = 0.
Все 10 пунктов раздела «Что ОБЯЗАТЕЛЬНО исправить» из первого ревью адресованы.

---

## НОВЫЕ находки (порождённые доработкой)

### NEW-1 [HIGH] — Реассемблер без gap-таймаута → вечно висящий стрим (дыра в F1)
§5.4 рвёт стрим ТОЛЬКО при `buffered(pending) > reassemblyMaxBuffered`. Но рассмотрим: хвост A (seq N+1..N+4) потерян навсегда (слот A умер, эти чанки НЕ перепосланы сервером, потому что для упреждающей миграции сервер «не обязан буферизовать» — §5.4 явно так пишет), а по B пришло немного — например только seq N+5 (3 KB). `pending` = 3 KB ≪ 4 MB лимита. `expectedSeq` застрял на N+1. Стрим **никогда** не пишет в conn и **никогда** не рвётся — зависает молча. Это ровно тот класс «не восстанавливается», который Bug#9 и лечит.

Корень: для **упреждающей** миграции (A жив на момент MIGRATE, но умер до того как in-flight хвост A долетел) НЕТ гарантии, что потерянные in-flight чанки A будут доставлены — сервер их уже отдал в сокет A и не держит. Если сокет A порвался с недоставленным хвостом, seq-gap неустраним.

**Требуется в спеку:** (а) gap-таймаут в реассемблере (`reassemblyGapTimeout`, напр. = migrateAckTimeout или dest-связанный) — если `expectedSeq` не продвинулся за окно при наличии данных в pending → рвём стрим (деградация, не вечное зависание); ИЛИ (б) сделать так, чтобы при MIGRATE сервер ВСЁ РАВНО держал короткий буфер недоack'нутого хвоста и перепосылал по B при подтверждённой смерти A (но это сближает упреждающий путь с grace — надо решить явно). Сейчас §5.4 говорит «сервер НЕ обязан буферизовать при A-жив» — это и создаёт дыру, когда A внезапно умирает посреди миграции. Без этого F1 закрыт не полностью.

### NEW-2 [MEDIUM] — `expectedSeq:=1` vs control-чанки без seq: рассинхрон стартовой нумерации
§5.4 псевдокод: `expectedSeq:=1`, и `if f.seq==0 → control (CONNECT_OK/FAIL), continue`. Но downSeq присваивается сервером в relay-loop как `downSeqCounter.Add(1)` на КАЖДЫЙ `tc.Read` (§3.1/§5.2). CONNECT_OK отправляется ОТДЕЛЬНО (`websocket.go:759`, до relay-loop, через `NewStreamDataChunk` — БЕЗ seq-формата в текущем коде). В seq-режиме надо однозначно определить: CONNECT_OK/FAIL несут seq=0 (зарезервирован под control) ИЛИ первый data-чанк = seq=1. Если сервер по ошибке присвоит CONNECT_OK seq=1 (через тот же counter), а реассемблер ждёт data с seq=1 — конфликт. Спека упоминает seq=0=control, но НЕ фиксирует, что `downSeqCounter` стартует так, чтобы первый РЕАЛЬНЫЙ data-чанк был именно 1, а все control шли с 0. Также `slotReaderWithClient` сейчас имеет guard `len(chunk.Payload) < 2` (`ws_pool.go:2787`) — в seq-режиме это должно стать `< 10` (2+8), иначе короткий seq-чанк примут как legacy и распарсят мусорный streamID. Зафиксировать оба инварианта в §3.1.

### NEW-3 [MEDIUM] — Double-MIGRATE (A→B→C): dedup `seq<expected` может ложно дропнуть валидные данные при reset-семантике
§5.8 «двойной MIGRATE A→B→C, последний выигрывает». Реассемблер дедупит по `f.seq < expectedSeq`. Это безопасно ТОЛЬКО пока `downSeqCounter` строго монотонен и НЕ сбрасывается при смене boundSession. Спека (§3.1) это утверждает («слот B продолжает с N+1»), и пока единственный writer counter'а — relay-loop под `relayEntry`, инвариант держится. НО надо явно ЗАПРЕТИТЬ в спеке любой сброс/реинициализацию `downSeqCounter` при reassociate (MIGRATE_OK/RESUME_OK), иначе C начнёт с малого seq → реассемблер сочтёт это дублями и дропнет реальные данные → молчаливая потеря. Сейчас это «следует из» текста, но не выделено как hard-инвариант — добавить в §3.1 строкой «downSeqCounter НИКОГДА не сбрасывается до удаления entry».

### NEW-4 [MEDIUM] — `NextSeqNum()` под session-mu в hot relay-loop: новая точка сериализации
§5.2 псевдокод вызывает `sess.NextSeqNum()` на каждый downlink-чанк. Проверено: `NextSeqNum` берёт `s.mu.Lock()` (`session.go:127-133`). В текущей архитектуре каждый relay-goroutine принадлежит одной WS-сессии и таких goroutine на сессию столько, сколько стримов — они уже сериализуются на session-mu (приемлемо). После рефакторинга F4 relay-loop читает `boundSession` динамически: НЕСКОЛЬКО relay-loop'ов разных стримов будут конкурировать за `s.mu` сессии B одновременно с её собственным reader/keepalive. Это не corruption (mutex корректен), но потенциальный contention-регресс под нагрузкой (сотни стримов мигрировали на один слот B). Не BLOCKER, но спека утверждает «нет HoL» (§5.4) — это про conn.Write, а session-mu contention отдельно. Зафиксировать как риск в §8 + добавить в race/perf acceptance (§6). Сам seq в session-header (`Chunk.SeqNum uint32`) остаётся для anti-replay окна — это ОК, не путать с per-stream downSeq.

### NEW-5 [LOW] — Метрика `boundSession==nil` окна не покрыта; downBuffer push при nil-привязке может молча копить
§5.2 псевдокод: при `sess==nil || w==nil` (окно миграции) → `entry.downBuffer.Push(seq, copy)`, `continue`. Это значит даже на пути упреждающей миграции (A-жив) есть микроокно, когда boundSession атомарно меняется и временно может быть прочитан как несогласованный (boundSession обновлён, boundWriter ещё нет — два отдельных atomic.Pointer, §5.1). Между двумя `.Store` есть гонка: relay-loop может загрузить новый sess + старый writer. Спека делает 2 раздельных `boundSession.Store` и `boundWriter.Store` (§5.3 шаг 2) — НЕ атомарно вместе. Надо либо паковать (session,writer) в ОДИН atomic.Pointer на struct (как сделано с `sendEpoch` в `session.go:27` — прямой прецедент в кодовой базе!), либо явно описать, что несогласованная пара безопасна (writer старого слота примет чанк, зашифрованный ключом нового слота → клиент A-reader не расшифрует → drop). Рекомендую паковать в один pointer (дёшево, устраняет класс гонок). LOW, потому что деградирует в drop, не в corruption — но это лишняя потеря байт → нагрузка на реассемблер/overflow.

---

## Прочие проверки (без находок — подтверждаю корректность)

- **Обратная совместимость seq-формата:** §3.1+§3.5 гейтят формат capability-флагом per-session, формат не меняется внутри сессии — ambiguity нет. Старый сервер на FlagMigrate → UnknownFlag (подтверждено `:930`), клиент деградирует по таймауту (F3). Смешанный парк безопасен. ОК.
- **atomic.Pointer boundSession в hot-loop (перф чтения):** `atomic.Pointer.Load` — это обычный atomic load, дёшево; прецедент `sendEpochPtr.Load()` на каждом EncryptChunk уже в проде (`session.go:312`). Перф-проблема НЕ в Load, а в `NextSeqNum` mutex (NEW-4). Чтение boundSession — ОК.
- **Реассемблер как DoS-вектор на клиенте (сервер шлёт дыры):** закрыт `reassemblyMaxBuffered` (4MB/64 чанка)→рвём. НО см. NEW-1: дыра не в РАЗМЕРЕ буфера, а во ВРЕМЕНИ при малом буфере. Размерный DoS закрыт, временной — нет.
- **Самопротиворечий:** §5.4 «сервер НЕ обязан буферизовать при A-жив» противоречит надёжности упреждающего пути при внезапной смерти A посреди миграции (NEW-1). Это единственное реальное внутреннее противоречие.
- **go.mod / HKDF:** `golang.org/x/crypto v0.49.0` присутствует → `golang.org/x/crypto/hkdf` доступен, fallback на ручной HMAC-HKDF не нужен. `crypto/hmac.Equal` — stdlib. ОК.

---

## Что ОБЯЗАТЕЛЬНО до writing-plans (минимум)

1. **[HIGH NEW-1]** Добавить gap-таймаут в реассемблер ИЛИ гарантию доставки хвоста A при упреждающей миграции. Без этого упреждающий путь может молча вешать стрим при внезапной смерти A посреди миграции — регресс к симптому юзера.
2. **[MEDIUM NEW-3]** Зафиксировать hard-инвариант: `downSeqCounter` никогда не сбрасывается до удаления entry (защита dedup при A→B→C).
3. **[MEDIUM NEW-2]** Зафиксировать стартовую нумерацию (control=seq 0, первый data=seq 1) + изменить клиентский guard `len(payload)<2` → `<10` в seq-режиме.
4. **[MEDIUM NEW-5 / рекоменд.]** Упаковать `boundSession`+`boundWriter` в один atomic.Pointer[struct] (прецедент `sendEpoch`), устранить несогласованную пару.
5. **[MEDIUM NEW-4]** Внести session-mu contention от динамического relay-loop в риски §8 + perf-acceptance §6.

После закрытия NEW-1 (HIGH) и фиксации NEW-2/3 инвариантов спеку можно вести в writing-plans; NEW-4/5 допустимо адресовать на этапе плана как явные задачи.

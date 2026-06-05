# Bug #10 — Spec review (origin-death teardown + client signal)

**Reviewer:** senior eng, critical pre-implementation review
**Date:** 2026-06-02
**Spec reviewed:** `docs/superpowers/specs/2026-06-02-bug10-origin-death-teardown-design.md`
**Recon reviewed:** `docs/bug10-origin-death-recon-2026-06-02.md`
**Code verified against:** `server/websocket.go`, `server/relay_registry.go`, `core/session.go`,
`core/wsasyncwriter.go`, `proxy/socks5/tcp.go`, `client/ws_pool.go`, `client/client.go`

## ВЕРДИКТ: NEEDS-REVISION

2 BLOCKER, 4 HIGH, 5 MEDIUM, 3 NIT. Корень доказан и решение по форме верное (переиспользование
single-winner teardown + CONNECT_FAIL), но спека НЕ ДОПРОЕКТИРОВАНА в трёх местах где она сама
себе ставит TODO ("план уточнит по чтению startWriter"), и в этих местах лежат настоящие дыры:
путь A физически не может позвать хелпер из текущего scope, а CAS single-winner имеет окно гонки
с RESUME, которое спека не разобрала. Их надо закрыть в ДИЗАЙНЕ, не в плане.

---

## BLOCKER

### BLOCKER-1 — Путь A (startWriter) физически не имеет доступа к session/streamID/clientID/registry; «план уточнит» прячет дыру дизайна

Спека (Компонент 2, путь A; §«Объём»): «при write-error в origin внутри writer-goroutine → тот
же хелпер. (Точное место — внутри startWriter… план уточнит по чтению startWriter целиком.)»

Проверка кода. `startWriter` (`websocket.go:328-360`) — метод на `*wsStream`:

```go
func (s *wsStream) startWriter() {
    go func() {
        for {
            select {
            case data, ok := <-s.writeCh:
                ...
                _, err := s.targetConn.Write(data)   // ← origin write here
                core.PutBuffer(data)
                if err != nil {
                    s.Close()                          // closes ONLY local stream + targetConn
                    return
                }
```

`wsStream` (struct, `websocket.go:~290`) держит ТОЛЬКО `writeCh/done/targetConn/pendingBuf/mu/closeOnce`.
У него **НЕТ** ни `session`, ни `streamID`, ни `clientID`, ни указателя на `relayRegistry`, ни на
`Handler`. Хелпер `teardownStreamOnOriginDeath` требует ВСЕ из них (CAS на entry → нужен registry +
clientID + streamID; CONNECT_FAIL → нужен session.ID + session.NextSeqNum + session.EncryptChunk +
binding writer). Из тела startWriter-goroutine их взять неоткуда.

Чтобы путь A мог звать хелпер, надо изменить СТРУКТУРУ `wsStream` (добавить streamID, clientID,
ссылку на handler/registry/session) либо пробросить колбэк `onOriginWriteError func()` при создании
pendingStream в CONNECT-хендлере (`websocket.go:889`). Это не «уточнение в плане» — это изменение
data-model + сигнатур, которое тянет за собой:
- кто владеет lifetime колбэка (он замыкает session/clientID — те же, что и CONNECT goroutine);
- порядок: startWriter-error СЕЙЧАС делает `s.Close()` (закрывает targetConn). Если targetConn ==
  relayEntry.tc (для migration-стрима targetConn передан в Activate, а entry.tc — тот же conn,
  `websocket.go:1037` `tc: tc`), то `s.Close()` закрывает egress, который relayLoop ещё читает →
  гонка с хелпером, который тоже делает entry.tc.Close(). Двойной Close net.Conn идемпотентен, но
  relayLoop получит read-error И запись credit, а helper параллельно делает closeReader → надо
  доказать что порядок безопасен.

**Замечание о фактической достижимости пути A для Bug #10.** Для migration-стрима uplink идёт через
`s.Write` (путь A) ТОЛЬКО на слоте рождения ДО первой миграции (`websocket.go:825-826`,
`streams[streamID]` непуст на birth-слоте). 342 наблюдённых broken pipe были на пути B (после
миграции). Но симптом Bug #10 (stream=1253, зависший Claude) — это `CONNECT_OK migrate=true` затем
тишина: origin умер РАНО, возможно ДО миграции, т.е. под путём A. Так что путь A — не теоретический;
он на основном сценарии. Оставить путь A «только лог» = баг воспроизводится для стримов, чей origin
умер до миграции.

**Что требуется от ревизии:** спроектировать механику пути A явно (структура wsStream или
onError-колбэк), с разбором гонки s.Close() vs entry.tc.Close() vs relayLoop, ДО плана.

### BLOCKER-2 — CAS `stActive|stOrphaned→stClosing` имеет окно гонки с RESUME: хелпер может убить только что воскрешённый стрим

Спека (Компонент 1, шаг 1): «CAS state `stActive|stOrphaned → stClosing` (single-winner: если
grace-timer / RESUME / idle-evict уже начали teardown — мы проигрываем CAS и выходим)».

Проблема: спека считает что CAS из `stActive` ИЛИ `stOrphaned` всегда безопасен. Это неверно для
RESUME. Последовательность RESUME (`handleMigrateOrResume`, `websocket.go:600-626`):

```
600:  if !entry.state.CompareAndSwap(stOrphaned, stActive) { ...fail... }   // state := stActive
610:  releaseOrphanFD(entry)
620:  resumeSeq := entry.reassociate(session, writer, ...)                   // bound.Store(newBinding) ЗДЕСЬ
626:  enqueueMigrateOK(...)
```

Между строкой 600 (state уже stActive) и строкой 620 (bound переставлен на НОВЫЙ живой слот)
**state == stActive, но `entry.bound` ещё указывает на МЁРТВЫЙ слот A.** Если в этом окне путь B
(или путь A) на старом слоте A ещё дочитывает буферизованный uplink и ловит broken pipe, хелпер
сделает CAS(stActive→stClosing) и ВЫИГРАЕТ — снесёт стрим, который клиент только что успешно
переподнял на слоте B. Клиент получит CONNECT_FAIL на свежем стриме и порвёт рабочее соединение.

Это не надуманно: RESUME происходит ИМЕННО когда слот A умер (aDead), т.е. ровно в момент когда на
слоте A копятся write-ошибки. Реактивный RESUME и origin-broken-pipe на старом слоте — соседние во
времени события.

Существующие single-winner пути (FlagFin `websocket.go:1199`, grace-timer, idle-evict) делают CAS из
`stOrphaned` (idle/grace) или из `stActive|stOrphaned` (FlagFin) — но FlagFin это КЛИЕНТСКИЙ
definitive-сигнал, он не конкурирует с in-flight RESUME того же стрима (клиент не шлёт FIN и RESUME
одновременно на один sid). Хелпер origin-death — СЕРВЕРНОЕ событие, асинхронное к клиентскому RESUME,
поэтому окно реально.

**Что требуется:** либо (a) хелпер CASит ТОЛЬКО из `stActive` И дополнительно проверяет, что
текущий `entry.bound.Load()` указывает на ТУ ЖЕ session/writer, на которой случился write-error
(если binding уже переехал — не наш стрим, выходим без teardown); либо (b) RESUME сделать атомарным
относительно teardown (reassociate ДО публикации stActive, как сделано с FD-charge в cleanup
`websocket.go:1376-1392`). Вариант (a) проще и согласуется с «слать на текущий binding writer».
Разобрать в дизайне.

---

## HIGH

### HIGH-1 — CONNECT_FAIL на binding writer мёртвого слота A молча теряется → стрим НЕ рвётся у клиента

Спека (Компонент 1, шаг 4): «enqueue на ТЕКУЩЕМ binding writer (`entry.bound.Load().writer`)».

Когда origin умирает, обычно умер и слот A (TSPU режет direct-TCP). `entry.bound.Load()` вернёт
binding слота A, чей `writer` (WSAsyncWriter) уже закрыт. `Enqueue` (`wsasyncwriter.go:190-194`)
на закрытом writer возвращает `ErrWSWriterClosed` и НЕ шлёт ничего — а enqueueDownFrame
(`relay_registry.go:834`) игнорит ошибку (`_ = b.writer.Enqueue(...)`). Итог: CONNECT_FAIL «отправлен»
по коду, но по проводу не ушёл — клиент НЕ получает сигнал, стрим продолжает висеть. Это ровно
тот сценарий, который Bug #10 чинит.

Если binding ещё жив (origin умер, но WS-слот цел — origin сам закрыл соединение) — сигнал дойдёт.
Но «origin closed, slot alive» — это НЕ основной сценарий Bug #10 (там TSPU убивает direct-TCP,
обычно вместе со слотом).

**Что требуется:** дизайн должен признать, что при мёртвом слоте A сигнал не доставляется СЕЙЧАС, и
он доставится только когда стрим зарезюмится на живой слот B (тогда reassociate сбросит буфер +
сигнал) ИЛИ грейс истечёт. Если стрим НЕ резюмится (клиент не знает что нужно резюмить — он же висит),
то CONNECT_FAIL не дойдёт никогда. Возможный выход: хелпер не должен пытаться слать на заведомо-мёртвый
writer; вместо этого пометить `destClosed`/новый флаг, чтобы при РЕЗУЛЬТАТЕ (RESUME или грейс) клиент
получил end-of-stream. Но если клиент не резюмит — нужен отдельный путь. Это пересекается с уже
зафиксированным в коде TODO(bug9-1b) о half-close. Спека обязана это разобрать, иначе фикс лечит
только подмножество (origin-closed-slot-alive), а доказанный симптом (slot-dead) остаётся.

### HIGH-2 — Гонка `bound.Load()` vs RESUME-reassociate при отправке сигнала (отдельно от BLOCKER-2)

Даже если CAS-гонку (BLOCKER-2) закрыть, шаг 4 читает `entry.bound.Load().writer` БЕЗ синхронизации
с reassociate, который делает `bound.Store(newBinding)` (`relay_registry.go:735`). `bound` —
`atomic.Pointer[binding]`, так что сам Load/Store атомарен (торна пары нет, NEW-5). Но логически:
хелпер может прочитать СТАРЫЙ binding (слот A) и заэнкьюить туда, пока RESUME уже переставил на B —
сигнал уйдёт в мёртвый writer (см. HIGH-1) ИЛИ, если хелпер выиграл teardown после RESUME-CAS
(BLOCKER-2), уйдёт в живой B и порвёт здоровый стрим. Спека утверждает «слать на текущий binding,
НЕ на локальный слот» как будто это закрывает гонку — оно её не закрывает, только выбирает источник
writer. Нужен явный порядок: CAS-выигрыш ПЕРЕД чтением binding, и чтение binding после того как
доказано что binding не переедет (т.е. мы в stClosing — RESUME уже не сможет CAS).

### HIGH-3 — Двойной CONNECT_FAIL / порядок «CAS первым, сигнал потом» не зафиксирован в спеке

Вопрос ревью №6. Спека перечисляет шаги 1-5 по порядку (CAS → remove → closeReader → сигнал →
tc.Close), что подразумевает «сигнал ПОСЛЕ выигранного CAS». Это правильно. НО спека нигде явно не
говорит «оба uplink-пути обязаны вызвать CAS ПЕРВЫМ и слать сигнал ТОЛЬКО при выигрыше CAS». Если
реализация пути A и пути B сначала формирует/шлёт CONNECT_FAIL, а потом делает CAS (наивная копи-паста
из dial-fail `websocket.go:954`, где CAS нет) — два почти-одновременных broken pipe (A и B на разных
слотах того же стрима — возможно если стрим мигрировал и старый слот A ещё дренит буфер) дадут ДВА
CONNECT_FAIL. Клиент на втором: первый уже сделал onControl→keepGoing=false→UnregisterStream; второй
CONNECT_FAIL прилетит на уже-снятый streamID → `RouteToStreamSeq` найдёт `ch==nil` (client.go:1160-1162)
и дропнет — безвредно. Но это надо ПРОПИСАТЬ в инварианте хелпера: «сигнал отправляется ИСКЛЮЧИТЕЛЬНО
внутри ветки выигранного CAS», иначе путь A и путь B могут слать сигнал до CAS. Зафиксировать в дизайне.

### HIGH-4 — Legacy non-migration путь: CONNECT_FAIL mid-stream пишется в приложение как сырые байты (коррупция). Спека отсекает «production=migration», но это не гарантия на уровне кода

Вопросы ревью №3 и №4. Проверка кода подтверждает caveat recon §4 ПОЛНОСТЬЮ:

Legacy downlink (`proxy/socks5/tcp.go:379-402`):
```go
if !connectConfirmed {
    if msg == "CONNECT_OK" { connectConfirmed = true; continue }
    if msg == "CONNECT_FAIL" { return }   // teardown — только пока !connectConfirmed
    connectConfirmed = true
}
total += len(payload); ...
conn.Write(payload)   // ← после connectConfirmed CONNECT_FAIL (12 байт) пишется в app raw = коррупция
```

Хорошая новость (проверено): хелпер вызывается ТОЛЬКО под `migrateEnabled && migrateClientID != ""`,
и `migrateEnabled` — per-session, решается в `authenticateFirstFrame` (`websocket.go:507`). На CONNECT
для migration-сессии путь делает `return` на `websocket.go:1077` ДО legacy inline-relay — т.е. в
одной WS-сессии стримы НЕ смешивают legacy и migration: либо вся сессия migration, либо вся legacy.
Так что хелпер (под migrateEnabled) НЕ может сработать на legacy-стриме. Это снижает риск.

НО: спека пишет «production = migration ON, ОК» как декларацию, без кодовой гарантии. Риски остаются:
1. **Split transport / single-WS:** существуют ли клиентские транспорты, которые НЕ negotiateMigration
   (single-WS, split)? Если такой клиент подключится, `migrateEnabled=false`, хелпер не зовётся —
   и значит для НЕГО Bug #10 НЕ чинится вообще (origin-death так и виснет). Спека это не оговаривает
   как известное ограничение. Надо явно: «фикс покрывает только migration-сессии; non-migration
   клиенты остаются с багом» — или закрыть и legacy-путь (см. рекомендацию ниже).
2. **Старый клиент + новый сервер:** если старый клиент не умеет migration, сессия будет legacy,
   хелпер не сработает — то же, что п.1, безопасно (коррупции нет, т.к. хелпер не вызван), но баг
   для него не лечится. Спека утверждает «старый клиент + новый сервер = корректно» — это ВЕРНО в
   смысле «не ломается», но НЕВЕРНО подразумевает «лечится». Уточнить формулировку.

**Что требуется:** в дизайн добавить явный инвариант «teardownStreamOnOriginDeath вызывается строго
под migrateEnabled; на legacy-сессии origin-death остаётся необработанным (известное ограничение)»,
и решить продуктово: достаточно ли покрыть только migration (если 100% prod-клиентов migration —
да), либо нужен мелкий патч legacy tcp.go:379 (распознавать CONNECT_FAIL и после connectConfirmed).
Рекомендую как минимум добавить на сервере assert/лог если хелпер достигнут с migrateEnabled==false
(не должно случаться) — defense in depth против будущего рефактора, который случайно вызовет хелпер
с legacy-сессии и устроит тихую коррупцию app-потока.

---

## MEDIUM

### MEDIUM-1 — `s.Close()` в startWriter уже закрывает targetConn (==entry.tc); хелпер тоже закроет tc → гонка/двойной teardown egress

При origin-write-error путь A СЕЙЧАС делает `s.Close()` (`websocket.go:341`) → `s.targetConn.Close()`
(`websocket.go:399-401`). Для migration-стрима `s.targetConn` — тот же net.Conn, что `entry.tc`
(передан в Activate, сохранён в entry на `websocket.go:1037`). Если путь A дополнительно зовёт хелпер,
а хелпер тоже делает `entry.tc.Close()` (шаг 5) — двойной Close (идемпотентно ОК для net.Conn). Но
relayLoop читает тот же tc; `s.Close()` закроет его раньше CAS → relayLoop получит read-error и пойдёт
по `websocket.go:621` ветке (`destClosed` если orphaned, иначе return). Порядок «s.Close vs CAS vs
relayLoop-exit» не разобран. Нужно: путь A для migration-стрима НЕ должен звать `s.Close()` (который
убивает egress до CAS), а делегировать закрытие egress хелперу (как CloseKeepTarget уже разделяет эти
обязанности для session-teardown, `websocket.go:413`). Спека про CloseKeepTarget-аналог для origin-death
молчит.

### MEDIUM-2 — `releaseOrphanFD` в хелпере, но стрим на пути B обычно stActive (не orphaned) → FD не заряжен → release корректен? проверить

Образец FlagFin (`websocket.go:1209`) зовёт `releaseOrphanFD(entry)`. `releaseOrphanFD` идемпотентен
по holdsFD (см. relay_dos_test.go:149). Для стрима, убитого хелпером в stActive (никогда не был
orphaned), holdsFD==false → release — no-op. Это корректно, но спека не перечисляет releaseOrphanFD
в шагах хелпера явно (шаг 5 говорит «releaseOrphanFD + broadcast bufCond — как в образце»). ОК, но
стоит зафиксировать что для не-orphaned стрима это no-op (не баг, для полноты).

### MEDIUM-3 — `entry.tc != nil` проверка и nil-binding при отправке сигнала

Шаг 4 читает `entry.bound.Load().writer`. Если `entry.bound.Load()` вернёт nil (теоретически между
orphan и reassociate binding может быть… нет — bound ставится при CONNECT `websocket.go:1054` и
переставляется, но НИКОГДА не зануляется; проверено — нет `bound.Store(nil)`). Значит nil-binding
маловероятен. Но `b.writer`/`b.session` могут быть мёртвыми (HIGH-1). Спека должна явно nil-guard
`bound.Load()` перед разыменованием (enqueueDownFrame этого не делает, т.к. вызывается только с
живым b из routeDownFrame). Хелпер — новый caller, обязан guard.

### MEDIUM-4 — seqNum гонка: безопасна, но шлётся под СТАРОЙ session (мёртвый слот) → seq бесполезен

Вопрос ревью №7. `session.NextSeqNum()` (`core/session.go:161-167`) — mutex-guarded, потокобезопасен
при параллельных teardown разных стримов. Это ОК. НО для CONNECT_FAIL chunk спека (шаг 4) берёт
`session.NextSeqNum()` от КАКОЙ session? Текст шага 4: «`core.NewStreamDataChunk(session.ID,
session.NextSeqNum(), ...)`». Откуда `session`? Если это session слота-A (мёртвого), то и шифруем
под session A, и шлём на writer A — оба мёртвы (HIGH-1). Логичнее брать `entry.bound.Load().session`
(consistent с writer из того же binding). Спека смешивает «session» (неясно чей) и «binding writer» —
несогласованность источников. Зафиксировать: chunk шифровать под `b.session`, слать на `b.writer`,
оба из ОДНОГО `bound.Load()` снимка (как enqueueDownFrame). Иначе можно зашифровать под session A,
а отправить на writer B (если переехал) — клиент B не расшифрует (другой ключ сессии) → дроп.

### MEDIUM-5 — Тест «гонка teardown vs grace-timer» не покрывает гонку teardown vs RESUME (главный риск)

Спека (Тесты): «server unit — гонка: одновременный teardown от origin-death и от grace-timer → ровно
один winner». Но настоящий опасный конкурент — RESUME (BLOCKER-2), не grace-timer. grace-timer и
idle-evict CASят из stOrphaned; origin-death CASит из stActive ИЛИ stOrphaned — пересечение с ними
только на stOrphaned, и там они эквивалентны (любой winner закрывает стрим — приемлемо). Гонка с
RESUME (CAS stOrphaned→stActive, затем хелпер CAS stActive→stClosing в окне до reassociate) — вот что
надо тестировать: origin-death НЕ должен убить стрим, который успешно зарезюмился. Добавить тест:
«RESUME выиграл CAS → origin-death хелпер на старом binding НЕ тирдаунит (binding-check или CAS-from-
stActive-only с binding match)».

---

## NIT

### NIT-1 — ENV-флаг default: спека противоречит сама себе
«ENV-флаг… (default on)» в одной строке и «Default-off на первую канарейку» в следующей. Выбрать одно.
Рекомендую default-OFF на первую канарейку (согласуется с осторожностью Bug #6/#8/#9), флип в default-on
после зелёной канарейки — и зафиксировать имя `SHADOWLINK_ORIGIN_DEATH_TEARDOWN`.

### NIT-2 — Метрика для канарейки не названа
«Проверка перед ship» говорит «registry-fallback write failed БОЛЬШЕ НЕ повторяется десятки раз» —
это косвенный признак. Добавить явный счётчик `shadowlink_origin_death_teardown_total{path=A|B}` и
`shadowlink_origin_death_signal_sent_total` / `_signal_dropped_total` (дропнут когда writer мёртв,
HIGH-1) — иначе HIGH-1 (тихая потеря сигнала) не видна на канарейке.

### NIT-3 — «CONNECT_FAIL семантика слегка натянута» — стоит добавить лог-различение
Для будущей диагностики: клиентский `onControl` не различает «origin не подключился» от «origin умер
mid-stream» — оба CONNECT_FAIL. Не блокер (клиент рвёт корректно в обоих), но в серверном логе хелпера
стоит писать `reason=origin_write_broken_pipe` отдельно от dial-fail, чтобы канарейка/форензика
2026-06-02 могли отличить новый teardown от старого dial-fail CONNECT_FAIL.

---

## Сводка к ответам на вопросы ревью

1. **Гонка teardown (CAS single-winner):** НЕ покрывает полностью. CAS из stActive безопасен против
   grace/idle (они из stOrphaned), но НЕ против RESUME, который флипает stOrphaned→stActive и держит
   старый binding до reassociate — окно где хелпер убьёт воскрешённый стрим. → BLOCKER-2.
2. **Сигнал на binding writer при миграции:** при мёртвом слоте A `bound.Load().writer` закрыт,
   Enqueue→ErrWSWriterClosed, сигнал молча теряется (enqueueDownFrame игнорит ошибку). → HIGH-1, HIGH-2.
3. **CONNECT_FAIL mid-stream рвёт ВСЕГДА?** Только на migration-пути (onControl seq==0, tcp.go:530-538).
   Подтверждено что хелпер зовётся строго под migrateEnabled и сессия не смешивает legacy/migration
   (CONNECT возвращается на :1077 до legacy relay). Но non-migration/split/single-WS клиенты НЕ
   лечатся (и НЕ ломаются). → HIGH-4.
4. **CONNECT_FAIL как сырые байты:** реальный риск ТОЛЬКО если хелпер сработает на legacy-стриме
   (connectConfirmed=true → tcp.go:393 пишет 12 байт в app = коррупция). Текущий код гарантирует
   хелпер только под migrateEnabled — коррупции нет. Но гарантия не закодирована как assert. → HIGH-4.
5. **Путь A startWriter:** ДЫРА. startWriter — метод wsStream без доступа к session/streamID/clientID/
   registry. Хелпер оттуда не вызвать без изменения структуры wsStream или проброса колбэка. → BLOCKER-1.
6. **Двойной CONNECT_FAIL:** CAS даёт один teardown; второй CONNECT_FAIL на снятый sid безвреден
   (ch==nil дроп). Но порядок «CAS первым, сигнал только при выигрыше» не зафиксирован в спеке. → HIGH-3.
7. **seqNum гонка:** NextSeqNum mutex-safe. Но неясно ЧЬЯ session (A или binding) — надо брать
   b.session из того же bound-снимка, что и b.writer, иначе encrypt-под-A/send-на-B → клиент не
   расшифрует. → MEDIUM-4.
8. **Обратная совместимость:** старый клиент+новый сервер = не ломается (legacy-сессия, хелпер не
   зовётся), НО и не лечится. Новый сервер+старый клиент: если старый клиент non-migration — сессия
   legacy, хелпер не сработает (безопасно). Спека формулирует «корректно» — точнее «не ломается, но
   баг не лечится для non-migration». → HIGH-4 уточнение.

## Рекомендация
Вернуть на ревизию. До плана закрыть в ДИЗАЙНЕ: BLOCKER-1 (механика пути A + структура wsStream/колбэк
+ гонка s.Close vs entry.tc.Close), BLOCKER-2 (binding-aware CAS или reassociate-before-publish),
HIGH-1 (что делать когда слот A мёртв и сигнал недоставим — самый частый сценарий Bug #10), HIGH-4
(явный инвариант migrateEnabled-only + продуктовое решение по legacy/non-migration). HIGH-2/3 и
MEDIUM-1..5 — зафиксировать в дизайне, реализуемы в плане. NIT — по вкусу.

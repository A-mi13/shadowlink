# Bug #10 — Origin death → stream-end signal (достройка destClosed-контура) — design

**Date:** 2026-06-02 (v4 — переработана после 3 опус-ревью + 3 разведок; v4 закрывает BLOCKER-2 через b1)
**Status:** DESIGN v4 — pending final opus-review → plan
**Класс:** серверный фикс (достройка существующего полумеханизма) + клиентский приём нового control-фрейма.

## Симптом (доказан серверным логом pl1)

Через ShadowLink Claude Code зависает «Frosting…, спиннер и пусто»; без протокола — стабильно.
Прямое доказательство (journalctl pl1): 342 `WS uplink registry-fallback write failed ... write:
broken pipe`, распределение по стримам совпадает с раздутым uplink клиента (stream=117 → 4.6МБ +
213 write-fail; stream=1207 → 9.9МБ + 110). stream=1253 (зависший Claude): `CONNECT_OK migrate=true`
затем тишина 3 мин до отключения юзером.

## Корневая причина (доказана 3 разведками)

**Ключевой факт: `entry.tc` (origin: сервер↔назначение, TCP #2) и `binding.writer` (WS:
клиент↔сервер, TCP #1) — ДВА РАЗНЫХ TCP-соединения.** Смерть origin (`broken pipe` на TCP #2) НЕ
трогает WS-слот (TCP #1). Значит при смерти origin `entry.bound.Load().writer` **жив** и пригоден
слать сигнал клиенту немедленно.

Сервер при смерти origin **не уведомляет клиента**, потому что задуманный механизм восстановления
не достроен — ТРИ дыры в связке:

1. **`destClosed` не взводится для нашего случая.** Ставится только на READ-EOF origin→client реле
   (`relay_registry.go:627`) и только при `state==stOrphaned`. Наш случай — WRITE-broken-pipe
   (uplink в мёртвый origin) на `stActive` стриме (origin умер до миграции). Флаг не ставится.
2. **`destClosed` — write-only мёртвый флаг.** Нигде не читается: RESUME/`reassociate` его не
   проверяет, end-of-stream не шлёт. Задумка («a subsequent RESUME flushes downBuffer and signals
   end-of-stream», relay_registry.go:139-145) осталась TODO — потребителя нет.
3. **Клиент не замечает молчание.** При живом WS-слоте клиент не имеет per-stream downlink-idle →
   ждёт downlink вечно, не инициирует RESUME/teardown.

**Цепочка зависания stream=1253:** origin умер на write при stActive → destClosed не взведён (write,
не read; active, не orphaned) → даже будь взведён, никто не читает → клиент при живом WS-слоте не
замечает → вечный висяк, клиент бесконечно льёт uplink в мёртвый origin (отсюда мегабайты).

**Два uplink-пути в origin, оба игнорируют write-error (HIGH-4):** путь A `s.Write`→startWriter
(websocket.go:825/338), путь B `entry.tc.Write` (websocket.go:855).

## Решение — достроить destClosed→stream-end контур (немедленный сигнал + RESUME-fallback)

Не новый хак, а завершение задуманного механизма. Новый чистый control-фрейм `FlagStreamClose`
(семантика «стрим закрыт со стороны origin», в отличие от натянутого CONNECT_FAIL).

### Компонент 1 — взводить destClosed на ВСЕ origin-смерти (server)

- Путь B (websocket.go:855-859): при `werr != nil` → пометить стрим origin-dead (см. Компонент 3),
  не «только лог».
- Путь A (startWriter, websocket.go:338-343): при origin-write-error → то же. **Проблема scope
  (BLOCKER-1):** `wsStream` не держит session/streamID/clientID/registry. Решение: при создании
  pendingStream в CONNECT-хендлере (websocket.go:889) пробросить колбэк `onOriginWriteError func()`,
  замыкающий clientID+streamID+registry (те же, что доступны CONNECT-горутине). startWriter при
  write-error зовёт колбэк ВМЕСТО голого `s.Close()`. Колбэк → общий teardown (Компонент 3).
- Read-EOF (relay_registry.go:627): снять условие `==stOrphaned` — взводить destClosed и на active.

### Компонент 2 — `FlagStreamClose` control-фрейм (core + протокол)

- Новый `core.FlagStreamClose = 0x0E` (MEDIUM-1, v3-ревью: старший занятый flag = `FlagStreamAck
  0x0D`, 0x0E свободен — проверить в core/chunk.go перед фиксацией, при конфликте взять следующий
  свободный, но по текущему коду 0x0E). Per-stream, НЕ session-wide (в отличие от FlagFin).
- Хелперы `core.NewStreamCloseChunk(...)` / парс на клиенте — по образцу StreamData.
- **Семантика:** «origin этого стрима закрылся, стрим завершён». Клиент рвёт стрим, отдаёт
  приложению EOF.

### Компонент 3 — `signalStreamEnd(entry)` + single-winner teardown (server)

Хелпер (по образцу FlagFin teardown websocket.go:1199-1219):
1. CAS `stActive|stOrphaned → stClosing` (single-winner: проигравший выходит).

   **BLOCKER-2 (гонка с RESUME) — закрывается на стороне RESUME, вариант (b1) reassociate-before-publish.**

   **Окно гонки (доказано опус-ревью v2+v3):** в `handleMigrateOrResume` CAS `stOrphaned→stActive`
   (websocket.go:600) выполняется ДО `reassociate` (websocket.go:620, `bound.Store(B)`
   relay_registry.go:735). В окне между ними `state==stActive`, но `bound` ещё указывает на мёртвый
   слот A → origin-death хелпер выигрывает CAS(stActive→stClosing), сносит воскрешаемый стрим,
   сигнал уходит в мёртвый writer A. Перечитывание `bound.Load()` НЕ помогает — в окне он = A.

   **Почему b2 (writer-liveness) ОТКЛОНЁН (v3-ревью, решающий под-факт):** дискриминатор «writer A
   закрыт ⟺ слот A мёртв» НЕВЕРЕН в коде. Трассировка WS-death cleanup (одна горутина,
   последовательно): `toOrphaned` публикует `stOrphaned` на **websocket.go:1427**, а `writer.Close()`
   (закрытие `done`-канала writer'а A) — только на **websocket.go:1475**, ПОСЛЕ цикла orphan'инга всех
   стримов + цикла teardown стримов. То есть существует реальное окно: `state==stOrphaned` опубликовано
   (RESUME armed на :600), но `writer A.done` ещё НЕ закрыт ⇒ `writerA.isClosed()==false`. b2 в этом
   окне ложно заключает «writer жив → слот жив → сносить безопасно» и убивает воскрешаемый RESUME'ом
   стрим. b2 не отличает «слот A мёртв, но writer ещё не закрыт» от «слот A жив» — потому что в коде
   orphan-публикация (:1427) ОПЕРЕЖАЕТ закрытие writer'а (:1475). Дискриминатор ложно-положителен
   ровно в опасном окне.

   **ФИКС (b1) — reassociate-before-publish:** в `handleMigrateOrResume` для RESUME-пути переставить
   **`e.bound.Store(B)` ДО** `CompareAndSwap(stOrphaned→stActive)` (websocket.go:600). Тогда окна
   «state==stActive + bound==мёртвый A» **не существует вовсе**: к моменту публикации stActive
   `bound` уже указывает на живой слот B. Любой порядок origin-death↔RESUME безопасен:

   - **origin-death выиграл первым** — но до RESUME-CAS state ещё `stOrphaned`, значит origin-death-CAS
     из `stActive` НЕ проходит (state не stActive). Origin-death на orphaned-стриме идёт по **orphaned-
     ветке (К4): `destClosed.Store(true)` БЕЗ смены state, без remove/closeReader** — НЕ делает
     `CAS(stOrphaned→stClosing)` сам (иначе снёс бы право RESUME воскресить стрим). Это согласуется с
     существующим relayLoop:627-629 (там ровно `state==stOrphaned → destClosed.Store(true)` без CAS).
     RESUME затем делает `bound.Store(B)` и `CAS(stOrphaned→stActive)` — выигрывает (state всё ещё
     stOrphaned, никто его не менял) → reassociate видит `destClosed` и шлёт FlagStreamClose на живой B
     (Компонент 4 RESUME-fallback). Если же entry успел подобрать grace-timer (`CAS(stOrphaned→
     stClosing)` :787) — RESUME-CAS проигрывает и штатно возвращает grace_expired fail
     (websocket.go:600-604), не воскрешает мёртвый стрим. Оба исхода корректны: state в orphaned-ветке
     меняет ТОЛЬКО single-winner authority (grace-timer / evict / RESUME), а origin-death лишь
     взводит флаг.
   - **RESUME выиграл первым** — `bound` уже = B (переставлен ДО публикации stActive). origin-death
     CAS(stActive→stClosing) возьмёт `bound.Load()` = B (живой) → сигнал уйдёт по живому слоту B.
     Стрим всё равно корректно сносится origin-death'ом (origin мёртв), клиент получит FlagStreamClose
     на актуальном слоте B и сделает retry. Корректно.

   **Граница перестановки (КРИТИЧНО для Bug #9 — план обязан соблюсти):** переезжает **ТОЛЬКО**
   `e.bound.Store(B)`. Весь дренаж `reassociate` (drainAll downBuffer + resendTail + Broadcast bufCond)
   **ОСТАЁТСЯ ПОСЛЕ** `CAS(stOrphaned→stActive)`. Обоснование безопасности (анализ по живому коду
   2026-06-03):
   - `bound.Store` атомарен и идемпотентен (atomic.Pointer[binding]); сам по себе ничего не закрывает
     и не сносит.
   - Дренаж downBuffer/resendTail не влияет на выбор binding origin-death-хелпером (хелпер читает
     только `bound.Load()` + `state`), поэтому может оставаться после CAS без влияния на гонку.
   - `routeDownFrame`/`relayLoop` читают `bound.Load()` на каждом фрейме. После раннего `bound.Store(B)`
     loop может начать слать на B ДО дренажа: если `downBuffer` непуст, `routeDownFrame` пойдёт по
     буферной ветке (frame в downBuffer), а `reassociate.drainAll` сольёт буфер под тем же `perEntryMu`
     → порядок seq сохранён (тот же инвариант, что Bug #9 уже держит — drainAll и routeDownFrame
     сериализованы через perEntryMu). Если `downBuffer` пуст — loop пойдёт по fast-path на B, что
     корректно (B живой).
   - Перенос ВСЕГО reassociate за :600 ОТКЛОНЁН (это «рискованнее для Bug #9», от чего v3 справедливо
     уклонялся): дренаж трогает state-зависимую буферную логику под perEntryMu и не должен опережать
     публикацию stActive. Переезжает только атомарный `bound.Store`.

   **Read-EOF / `evictIdleOrphan` под b1 (проверено):** `entriesForSession`/`hasBoundEntriesForSession`
   фильтруют `b.session==sess` — ранний `bound.Store(B)` лишь раньше перепривязывает relay к ЖИВОЙ
   сессии B (корректнее, ghost-sweep защитит B). `evictIdleOrphan` гейтится `state==stOrphaned`: в окне
   «bound=B, CAS ещё не сделан» state всё ещё stOrphaned, evict может выбрать entry, но через
   single-winner `CAS(stOrphaned→stClosing)` — если он выиграет, RESUME-CAS проигрывает (штатный
   grace_expired fail); bound=B при этом безвреден (entry сносится целиком). Деградации против текущего
   поведения нет.

   После выигрыша CAS origin-death-хелпером — snapshot `b := bound.Load()` ОДИН раз (session+writer из
   одного binding, MEDIUM-4), nil-guard (MEDIUM-3). Под b1 `b` после успешного RESUME = B (живой) →
   слать FlagStreamClose по B. Для orphaned-стрима (RESUME ещё не приходил, origin и WS умерли разом) —
   ветка Компонент 4 (destClosed, без немедленного сноса).
2. `relayRegistry.remove` + `closeReader` + `releaseOrphanFD` + broadcast bufCond (как образец).
3. **Сигнал клиенту ТОЛЬКО внутри выигранной ветки CAS** (HIGH-3): из snapshot `b := bound.Load()`
   зашифровать `FlagStreamClose(b.session.ID, b.session.NextSeqNum(), globalStreamID)` под
   `b.session`, enqueue на `b.writer`. session И writer — из ОДНОГО снимка (иначе encrypt-под-A /
   send-на-B → клиент не расшифрует).
4. `entry.tc.Close()`.

Оба uplink-пути и read-EOF зовут этот хелпер → централизованно (правило architecturally_correct).

### Компонент 4 — RESUME-fallback (server, на случай «оба TCP умерли разом»)

Достроить потребление destClosed: в `reassociate` (relay_registry.go:732) после дренажа downBuffer,
если `destClosed` → послать `FlagStreamClose` на новый binding. Покрывает редкий случай, когда WS-слот
тоже умер (одно сетевое событие убило оба TCP) — тогда немедленный сигнал (Компонент 3) ушёл в
мёртвый writer и потерялся, но при RESUME на живой слот клиент получит stream-close.

**Когда destClosed-ветка хелпера НЕ сносит entry (стык К3↔К4, HIGH-B под b1):** origin-death-хелпер
сносит entry (`remove`+`closeReader`+`tc.Close`) ТОЛЬКО когда выиграл `CAS(stActive→stClosing)` с
актуальным live binding (под b1 это означает RESUME уже переехал на живой B, либо стрим никогда не
орфанился). Если же стрим орфанен (`state==stOrphaned`, WS-слот недоступен, RESUME ещё не приходил —
сценарий «оба TCP умерли разом»): хелпер ставит `destClosed=true` и НЕ делает remove/closeReader —
оставляет entry для RESUME-fallback (К4, пошлёт FlagStreamClose на живой слот B и затем teardown) ИЛИ
для grace-timer (`launchGraceTimer` :784-816 гарантированно снесёт через grace-период, утечки entry
нет). Дискриминатор ветки — **«выиграл ли CAS из stActive с актуальным live binding»** (что естественно
даёт b1), НЕ «writerA.isClosed()» (ненадёжно в окне :600→:620, см. BLOCKER-2).

### Компонент 5 — клиент принимает FlagStreamClose

`client/ws_pool.go` demux: распознать `FlagStreamClose` для streamID как **top-level control-бранч
ДО W5-guard** (рядом с распознаванием migrate-reply, ws_pool.go:3230, ВЫШЕ `len<2`-фильтра :3235 и
W5-guard :3252) → `streamMap.Delete(streamID)` + `close(cl.streamChans[streamID])` (как closeStream
ws_pool.go:3549) → downlink-реассемблер видит закрытый канал → выходит → SOCKS5/memConn reader получает
EOF → appConn закрывается → Claude Code получает обрыв → делает retry. Размещение ДО W5-guard критично:
close-сигнал не должен дропнуться, если стрим в этот момент мигрировал на другой slotIdx (нужно для
Компонента 4 RESUME-fallback на слот B). Demux по streamID глобален (slot-agnostic, client.go:1009) —
фрейм принимается с любого слота.

## Инварианты / нюансы (из опус-ревью)

- **migrateEnabled-only (HIGH-4 / HIGH-C):** хелпер достижим только под migration-сессией. При входе
  проверяет `migrateEnabled` — если false, лог WARN `bug10 helper reached on non-migration session` и
  return БЕЗ отправки сигнала (defense-in-depth против будущего рефактора, который случайно вызовет
  хелпер на legacy-сессии и устроит тихую коррупцию app-потока сырыми байтами «STREAM_CLOSE»). Оба
  uplink-пути уже гейтятся migrateEnabled (путь B websocket.go:827, путь A — колбэк только в
  migration-CONNECT), так что на текущем коде недостижимо — assert чистая страховка.
- **Порядок (HIGH-3):** CAS ПЕРВЫМ, сигнал ТОЛЬКО при выигрыше. Двойной сигнал (путь A+B одновременно)
  → второй проигрывает CAS, не шлёт. На снятый streamID `RouteToStreamSeq` дропнет (ch==nil) —
  безвредно.
- **startWriter s.Close vs entry.tc.Close (MEDIUM-1 / NIT-4):** путь A для migration-стрима НЕ должен
  сам звать `s.Close()` (убивает egress до CAS) — делегировать закрытие egress хелперу (`entry.tc.Close()`
  Компонент 3 шаг 4). Колбэк вместо s.Close.
- **nil-guard (MEDIUM-3):** `bound.Load()` никогда не зануляется (нет Store(nil)), но хелпер — новый
  caller, обязан nil-guard перед разыменованием.
- **TOCTOU writer жив→закрылся→Enqueue безвреден (v3-ревью):** `Enqueue`/`EnqueueControl` на закрытый
  writer возвращают `ErrWSWriterClosed` (wsasyncwriter.go:194/208), не паникуют — дроп фрейма, не
  коррупция. Это НЕ источник проблемы (BLOCKER-2 — обратная, ложно-ОТРИЦАТЕЛЬНАЯ liveness, закрытая b1).
- **W5 stale-frame guard (HIGH-A):** клиентский demux имеет stale-frame guard `client/ws_pool.go:3252`
  (`if e.slotIdx != idx { continue }`). FlagStreamClose обрабатывается top-level ДО guard (Компонент 5)
  — проходит с любого слота. **HIGH-A закрыт** (прецедент top-level-бранча :3230 подтверждён кодом).

## Тесты (TDD)

- core: FlagStreamClose (0x0E) round-trip; не конфликтует с существующими flags.
- server unit: destClosed взводится на write-error (путь A колбэк, путь B); и на read-EOF active.
- server unit: signalStreamEnd — CAS single-winner (2-й вызов no-op); шлёт FlagStreamClose из snapshot
  bound; session+writer из одного binding; идемпотентен; nil-guard.
- **server unit — гонка vs RESUME (MEDIUM-2, ГЛАВНЫЙ риск, b1-специфичный):** воспроизвести именно
  опасное окно **:600→:620 при незакрытом writer A**. Сценарий: стрим orphaned (stOrphaned
  опубликован, writer A ещё НЕ закрыт — как в WS-death cleanup до :1475); RESUME делает `bound.Store(B)`
  ДО `CAS(stOrphaned→stActive)` (b1); параллельный origin-death-хелпер. Утверждения: (a) после RESUME
  `bound`==B ещё ДО публикации stActive; (b) origin-death-CAS из stActive берёт bound==B (живой), шлёт
  FlagStreamClose по B, НЕ рвёт воскрешённый стрим некорректно (не шлёт по мёртвому A); (c) если
  origin-death выиграл первым из stOrphaned — RESUME-CAS проигрывает, штатный grace_expired fail.
  **Без воспроизведения interleaving (orphaned-published-but-writer-open) тест зелёный при сломанном
  b2 — поэтому тест обязан армить именно это окно.**
- **server unit — регресс Bug #9 (b1 не ломает миграцию):** обычный MIGRATE/RESUME без origin-death —
  downBuffer дренится в seq-порядке на B, resendTail на aDead, downSeqCounter монотонен, клиент-
  реассемблер не стопорится. Подтвердить, что ранний `bound.Store(B)` + дренаж-после-CAS не нарушает
  порядок (drainAll/routeDownFrame под общим perEntryMu).
- server e2e (расширить migrate_e2e_test.go): стрим active → origin-сокет закрыт (write broken pipe)
  → клиент получает FlagStreamClose по живому WS-слоту → стрим закрыт обе стороны, нет залипания.
  **Прямо воспроизводит Bug #10.**
- client: FlagStreamClose → канал закрыт → reader EOF; demux принимает с любого слота (top-level ДО
  W5-guard).

## Метрики (канарейка, NIT-2)

`shadowlink_origin_death_teardown_total{path=A|B|read}`, `_signal_sent_total`,
`_signal_dropped_total` (writer мёртв — редкий случай, RESUME-fallback подберёт). Серверный лог
хелпера: `reason=origin_write_broken_pipe` отдельно от dial-fail CONNECT_FAIL (NIT-3).

## Объём / деплой / флаг

- Файлы: `core/chunk.go` (FlagStreamClose=0x0E), `server/websocket.go` (оба пути + колбэк + b1-
  перестановка `bound.Store` до CAS в handleMigrateOrResume), `server/relay_registry.go`
  (signalStreamEnd, destClosed на active, RESUME-fallback, ветка writer-жив/orphaned),
  `client/ws_pool.go` (приём top-level) + тесты.
- **pl1 передеплой** (staged, сервер первым). Новый клиент нужен для приёма FlagStreamClose — но
  старый клиент его проигнорирует (unknown flag → дроп), баг для него останется, не сломается.
- ENV-флаг `SHADOWLINK_ORIGIN_DEATH_TEARDOWN` **default-OFF на первую канарейку** (осторожность
  Bug #6/#8/#9), флип в on после зелёной канарейки (NIT-1). b1-перестановка `bound.Store` ДО CAS —
  **безусловна** (не под флагом): она лишь сужает окно и корректна сама по себе, а origin-death-сигнал
  (потребитель окна) — под флагом. Это разводит риск: даже при флаге-off перестановка не меняет
  наблюдаемое поведение (RESUME и так делает bound.Store на :620; b1 двигает её на ~20 строк раньше
  внутри той же горутины без новых сигналов).

## Проверка перед ship

- `go test ./...`, `go build ./...`, `go vet` чисты.
- `go test -race -count=3 ./server/ ./client/ ./proxy/...` на pl1/Linux (гонка teardown vs RESUME
  критична; b1-окно — главный объект race-теста).
- Деплой pl1 → серверный лог: `registry-fallback write failed` НЕ повторяется десятки раз на стрим
  (teardown после первого broken pipe). Метрика `origin_death_teardown_total` растёт, `signal_dropped`
  ≈0.
- Полевой ретест: Claude Code под TSPU-давлением — при смерти origin стрим рвётся, Claude делает retry
  (новый запрос проходит) вместо вечного «Frosting».

## Журнал ревизий

- **v1** (NEEDS-REVISION): 2 BLOCKER / 4 HIGH.
- **v2** (NEEDS-REVISION): BLOCKER-2 не закрыт + HIGH-A/B/C. v2-ревью назвало b1 как правильное
  закрытие BLOCKER-2.
- **v3** (NEEDS-REVISION): HIGH-A/B/C закрыты архитектурно; выбрал b2 (writer.isClosed) — ОТКЛОНЁН
  v3-ревью (ложно-положителен в окне :600→:620, т.к. orphan-publish :1427 < writer.Close :1475).
- **v4** (этот документ): BLOCKER-2 закрыт через **b1 (reassociate-before-publish)** — `bound.Store(B)`
  ДО `CAS(stOrphaned→stActive)`, дренаж остаётся после CAS. HIGH-B переформулирован как «CAS из
  stActive с актуальным live binding» (не writer-liveness). MEDIUM-1 (0x0E явно), MEDIUM-2 (race-тест
  на окно при незакрытом writer A) учтены. Анализ безопасности b1 для всех читателей `bound`
  (entriesForSession / evictIdleOrphan / relayLoop / routeDownFrame) проведён по живому коду
  2026-06-03 и встроен в Компонент 3.
  - **Опус-ревью v4 = APPROVED-WITH-NITS (0 BLOCKER / 0 HIGH / 0 MEDIUM / 4 NIT)**, отчёт
    `docs/bug10-spec-review-v4-opus-2026-06-02.md`. BLOCKER-2 подтверждён закрытым построчно; новых
    гонок b1 не вносит; seq-инварианты Bug #9 сохраняются. NIT-3 (несогласованность текста про CAS в
    orphaned-ветке) **исправлен в этом документе** — orphaned-ветка делает только `destClosed.Store(true)`
    без смены state. NIT-1/2/4 — **обязательные требования к ПЛАНУ** (не дизайн-дыры):
    - **NIT-1:** `bound.Store` сидит ВНУТРИ `reassociate` (relay_registry.go:735). План обязан вынести
      `bound.Store` из reassociate и публиковать готовый `*binding` ДО CAS, передавая его параметром
      (reassociate перестаёт стораить, только дренит) — чтобы был ОДИН pointer и однозначная точка
      публикации B. (Альтернатива — двойной идемпотентный store — допустима, но грязнее; рекомендуется
      вынос.)
    - **NIT-2:** переезжает РОВНО `bound.Store`; `releaseOrphanFD` (:610), resendTail-метрика (:618) и
      весь дренаж reassociate ОСТАЮТСЯ после CAS. releaseOrphanFD привязан к CAS-успеху (освобождать FD
      только когда RESUME реально выиграл entry), НЕ тащить его до CAS вслед за bound.Store.
    - **NIT-4:** race-тест MEDIUM-2 армит окно «`bound.Store(B)` сделан, `CAS(stOrphaned→stActive)` ещё
      НЕ сделан, state==stOrphaned» — иначе тест зелёный и при наивной реализации, забывшей перенести
      Store (не ловит регресс b1→b0).

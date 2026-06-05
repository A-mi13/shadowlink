# Bug #10 — Spec review v2 (origin-death teardown + FlagStreamClose)

**Reviewer:** senior eng, повторное критическое pre-implementation ревью
**Date:** 2026-06-02
**Spec reviewed:** `docs/superpowers/specs/2026-06-02-bug10-origin-death-teardown-design.md` (v2)
**Prior review:** `docs/bug10-spec-review-opus-2026-06-02.md` (NEEDS-REVISION, 2 BLOCKER / 4 HIGH / 5 MED / 3 NIT)
**Code verified against:** `server/websocket.go` (startWriter 328-360, Close 389-403, CloseKeepTarget
405-423, uplink FlagData 819-861, CONNECT 863-1078, migration entry 1032-1077, FlagFin teardown
1199-1219, handleMigrateOrResume 570-627), `server/relay_registry.go` (state machine 93-145,
closeReader 213-220, relayLoop EOF 621-648, reassociate 732-763, launchGraceTimer 784-816),
`core/chunk.go` (flags 13-27), `client/ws_pool.go` (demux 3220-3293, W5-guard 3252-3262, closeStream
3549-3557), `client/client.go` (RouteToStreamSeq 1158-1169).

## ВЕРДИКТ: NEEDS-REVISION

Новый фундаментальный факт **origin≠слот — ПОДТВЕРЖДЁН кодом** (см. ниже), и это правильно
переворачивает архитектуру: немедленный сигнал по живому `binding.writer` концептуально реализуем,
HIGH-1 в прежней форме («сигнал на мёртвый слот теряется») для основного сценария снят. BLOCKER-1
(путь A) закрыт корректно — колбэк имеет доступ к нужному scope. НО **BLOCKER-2 НЕ закрыт**: v2
заменил его на «snapshot bound.Load() после CAS», и эта мера НЕ перекрывает реальное окно гонки с
RESUME (CAS выигран, но `reassociate` ещё не переставил binding) — origin-death хелпер в этом окне
снесёт стрим, который RESUME в процессе воскрешения, и сигнал при этом уйдёт в мёртвый writer.
Дополнительно v2 вносит НОВУЮ дыру (W5 stale-frame guard на клиенте vs FlagStreamClose) и
оставляет недоспецифицированной гонку двух сигналов (Компонент 3 vs 4).

Это близко к APPROVED — фундамент верен, 4 из 6 прежних замечаний закрыты — но BLOCKER-2 остаётся
настоящим (доказан построчно ниже) и обязан быть закрыт в ДИЗАЙНЕ, не в плане.

---

## Подтверждение нового факта origin≠слот: ДА, ПОДТВЕРЖДЁН

Спека-фундамент: «`entry.tc` (origin) и `binding.writer` (WS) — РАЗНЫЕ TCP; смерть origin не трогает
WS-слот; `entry.bound.Load().writer` жив и пригоден слать сигнал немедленно».

Проверка по коду — ВЕРНО:

1. **`s.targetConn == entry.tc` — один и тот же `net.Conn`.** На migration-CONNECT (websocket.go:1037)
   `entry := &relayEntry{ tc: tc }` берёт ровно тот `tc`, что был передан в `s.Activate(tc)`
   (websocket.go:310-312 ставит `s.targetConn = tc`). Это origin-сокет (сервер↔назначение).
2. **`startWriter` при origin write-error закрывает ТОЛЬКО `targetConn`, НЕ WS-conn.** websocket.go:341
   `s.Close()` → :399-401 `s.targetConn.Close()`. WS-conn (`conn`/`writer` слота) не трогается — он
   живёт в `runWebSocketSession`, отдельный объект. Значит broken-pipe на origin НЕ роняет WS-слот.
3. **`binding.writer` — это WS-writer слота** (websocket.go:1054 `bound.Store(&binding{session, writer})`,
   где `writer` создан per-session на WS-conn слота, websocket.go:708). Он переживает смерть origin.
4. **relayLoop читает egress отдельно** (relay_registry.go:606 `e.routeDownFrame`), downlink идёт через
   `binding.writer` (relay_registry.go:818+ enqueueDownFrame) — независимо от uplink-write в origin.

**Вывод:** при смерти origin (write broken pipe) WS-слот и его writer ЖИВЫ. Сигнал по
`entry.bound.Load().writer` физически доставляется. Прежний HIGH-1 (в формулировке «слот A тоже мёртв,
сигнал теряется») для ОСНОВНОГО сценария Bug #10 (origin умер, WS жив — именно так в логе stream=1253:
WS-слот продолжал принимать uplink, иначе не было бы 213 write-fail на одном стриме) — **снят
корректно**. Остаточный under-сценарий «оба TCP умерли разом» v2 закрывает Компонентом 4 (RESUME-fallback) —
направление верное.

Этот факт — реальный, не натяжка. Фундамент v2 стоит.

---

## BLOCKER

### BLOCKER-2 (НЕ ЗАКРЫТ) — origin-death хелпер сносит стрим в окне RESUME «CAS выигран, binding ещё не переставлен»; «snapshot bound.Load() после CAS» этого не лечит

v2 Компонент 3, шаг 1: «если RESUME уже выиграл CAS (stOrphaned→stActive) и **переставил binding**,
наш CAS из stActive возьмёт АКТУАЛЬНЫЙ `bound.Load()`… Доп. защита: после выигрыша CAS перечитать
`bound.Load()`».

Дыра — в слове «**переставил**». Построчная трассировка RESUME (`handleMigrateOrResume`):

```
600:  if !entry.state.CompareAndSwap(stOrphaned, stActive) { ...fail... }  // state := stActive
610:  releaseOrphanFD(entry)
620:  resumeSeq := entry.reassociate(session_B, writer_B, ...)              // bound.Store(B) ТОЛЬКО ЗДЕСЬ
626:  enqueueMigrateOK(...)
```

`reassociate` (relay_registry.go:732-735): `b := &binding{session_B, writer_B}; e.bound.Store(b)` —
БЕЗ какой-либо проверки state. То есть в окне **между строкой 600 и строкой 620**:
`state == stActive`, но `entry.bound` ещё указывает на МЁРТВЫЙ слот A.

Сценарий гонки (полностью реальный — RESUME происходит ИМЕННО потому что слот A умер, ровно тогда же
на пути B копятся origin-write-ошибки):

1. RESUME выигрывает CAS(stOrphaned→stActive) на :600. state=stActive. bound всё ещё = A.
2. origin-death хелпер (путь B registry-fallback ИЛИ запоздавший колбэк пути A) делает
   CAS(stActive→stClosing). **ВЫИГРЫВАЕТ** (state был stActive).
3. Хелпер по v2-логике перечитывает `bound.Load()` → возвращает **A** (reassociate на :620 ещё не
   выполнился). Шлёт FlagStreamClose на МЁРТВЫЙ writer A → **потерян**. Делает `remove` +
   `closeReader` (закрывает closeCh+credit) + `tc.Close`.
4. RESUME продолжает на :620 → `reassociate(B)` делает `bound.Store(B)`, дренит буфер, enqueue на
   живой writer B — но relay УЖЕ снесён (closeReader закрыл closeCh и credit; entry removed из реестра).
   relayLoop уже вышел/выходит (alive=false на :607). Клиент получил RESUME_OK (:626), но стрим мёртв.

Итог: стрим, который клиент успешно воскресил, **убит**, а FlagStreamClose **потерян** (ушёл в writer A).
Клиент думает что migrate прошёл (RESUME_OK), но downlink не идёт → ровно тот же висяк, плюс мы
сломали рабочий путь. «Перечитать bound после CAS» НЕ помогает — в опасном окне bound ещё = A.

Прежнее ревью предлагало ДВА корректных варианта; v2 не взял ни один:
- **(a) binding-identity guard:** хелпер CASит только из stActive И сверяет, что `bound.Load()`
  указывает на ТУ ЖЕ {session,writer}, на которой случился write-error. Если binding уже не та
  (RESUME переехал ИЛИ ещё держит A, а ошибка пришла с A) — это требует, чтобы хелпер ЗНАЛ, на каком
  writer'е была ошибка, и сравнил. v2 этого сравнения не вводит — он шлёт «куда bound смотрит сейчас»,
  а не «совпадает ли это с источником ошибки».
- **(b) reassociate-before-publish:** сделать `bound.Store(B)` ДО публикации stActive (как FD-charge
  упорядочен до stActive-publish в cleanup, websocket.go ~1376-1392). Тогда окна «stActive + bound=A»
  не существует.

**Что требуется от ревизии:** закрыть окно в дизайне явно — вариант (b) (переставить binding до
CAS-публикации stActive в handleMigrateOrResume) либо вариант (a) с РЕАЛЬНЫМ сравнением источника
ошибки (хелперу прокинуть, на каком writer'е была origin-write-ошибка — но origin-write и WS-writer
разные объекты, так что (a) тут неудобен; (b) проще). Голый «snapshot bound.Load() после CAS» —
недостаточен и его надо убрать как ложно-успокаивающий.

---

## BLOCKER-1 (ЗАКРЫТ) — путь A через колбэк onOriginWriteError

v2 Компонент 1, путь A: при создании pendingStream в CONNECT-хендлере (websocket.go:889) пробросить
колбэк `onOriginWriteError func()`, замыкающий clientID+streamID+registry; startWriter зовёт его
вместо `s.Close()`.

Проверка scope (websocket.go:889 и dial-goroutine 911+): в этом месте в области видимости РЕАЛЬНО
есть `session`, `sid` (=streamID), `streams`/`streamsMu`, `h.relayRegistry`, и `clientID` резолвится
выше (websocket.go:692-696). Колбэк, замыкающий `(h, clientID, sid)` и вызывающий общий хелпер
`signalStreamEnd`, формируется корректно — те же значения, что у CONNECT-горутины. **BLOCKER-1
закрыт** — проблема scope решена, «план уточнит» больше нет.

Lifetime колбэка: он замыкает `h` (Handler, живёт всю жизнь процесса) + clientID/sid (значения,
копируются). Не висячих указателей. ОК.

Гонка `s.Close()` vs `entry.tc.Close()` (прежний MEDIUM-1) — v2 её адресует: путь A для migration
НЕ зовёт `s.Close()` (который убил бы egress до CAS), а делегирует хелперу (Компонент 3 §«MEDIUM-1»).
Корректно — `CloseKeepTarget` (websocket.go:413) уже даёт прецедент разделения «закрыть writer-goroutine,
не трогая targetConn». NIT ниже про точную механику.

---

## HIGH

### HIGH-A (НОВЫЙ) — W5 stale-frame guard на клиенте уронит FlagStreamClose, если он попадёт под общий FlagData-путь демукса; Компонент 5 не указывает место относительно guard

Клиентский демукс (ws_pool.go): guard на :3252-3262 выполняется для ЛЮБОГО фрейма с
`len(chunk.Payload) >= 2` ПЕРЕД роутингом: если `streamMap[streamID].slotIdx != idx` → `continue`
(дроп). Контрольные фреймы (seq==0 CONNECT_FAIL) тоже проходят через этот guard — он НЕ делает
исключения для control.

Для НЕМЕДЛЕННОГО сигнала (Компонент 3, origin умер, WS-слот жив, binding не двигался): сервер шлёт
по `bound.writer` = слот, на который стрим И назначен у клиента (`slotIdx == idx`) → guard
ПРОПУСКАЕТ. Здесь ОК (и это прямое следствие подтверждённого факта origin≠слот). Но:

1. **Компонент 4 (RESUME-fallback):** сигнал шлётся в `reassociate` на НОВЫЙ слот B. На сервере
   binding уже = B, но на клиенте `rebindStreamToSlot` (обновляющий slotIdx на idxB) и приём
   downlink на слоте B — асинхронны. Если FlagStreamClose придёт на B ДО того, как клиент обновил
   `slotIdx=idxB`, guard (slotIdx ещё =A) сделает `continue` → сигнал потерян. Это тот самый W5-замок,
   который прежняя signal-delivery разведка (`bug10-signal-delivery-recon`) назвала блокером
   cross-slot доставки. v2 его не разобрал.
2. **Куда вставлять FlagStreamClose в демукс — не специфицировано.** Компонент 5 говорит «demux
   распознаёт FlagStreamClose для streamID → Delete+close», но не указывает: ДО guard (как
   FlagMigrate/FlagResume на :3230, которые `continue` ВЫШЕ guard) или ПОСЛЕ. Правильно — обрабатывать
   FlagStreamClose как отдельный `chunk.Flags`-бранч НА УРОВНЕ :3230 (до :3235 `len<2` и до guard),
   тогда (а) он не подчиняется W5-guard (нужно для Компонента 4), (б) не конфликтует с
   FlagData seq/flat disambiguation. Это надо прописать в дизайне, иначе наивная реализация под
   общим FlagData-путём словит guard.

**Что требуется:** зафиксировать, что FlagStreamClose — собственный top-level `chunk.Flags` бранч
ДО W5-guard (по образцу FlagMigrate :3230), и что он роутит per-streamID глобально (RouteToStream*
demux slot-agnostic, client.go подтверждает) — тогда и Компонент 3, и Компонент 4 доставляются.

### HIGH-B — Гонка двух сигналов (Компонент 3 немедленный vs Компонент 4 RESUME-fallback): возможен дубль или сигнал по мёртвому writer без подхвата

v2 ставит destClosed на ВСЕ origin-смерти (Компонент 1) И шлёт немедленный сигнал (Компонент 3) И
дослывает на reassociate если destClosed (Компонент 4). Сценарии:

- **Немедленный сигнал ушёл успешно (слот жив), CAS выигран хелпером → стрим уже stClosing/removed.**
  Тогда RESUME на этот стрим получит MigrateReasonNotFound (entry removed) — клиент уже закрыл стрим
  по FlagStreamClose, RESUME и не нужен. ОК, дубля нет.
- **Немедленный сигнал ушёл в МЁРТВЫЙ writer (под-сценарий «оба TCP умерли»), но хелпер всё равно
  выиграл CAS → remove+closeReader+tc.Close.** Тогда entry removed. Последующий RESUME → NotFound →
  Компонент 4 (reassociate-dispatch destClosed) **никогда не выполнится** (entry уже нет). Значит при
  «оба умерли разом» Компонент 4 НЕ страхует — стрим не существует к моменту RESUME. v2 утверждает,
  что Компонент 4 «подберёт» этот случай, но если Компонент 3 СНЁС entry, подбирать нечего. Покрытие
  есть только если немедленный сигнал НЕ сносит entry при недоставке (writer мёртв) — т.е. хелпер
  должен НЕ делать teardown, если writer заведомо мёртв, оставив destClosed для RESUME. v2 этого
  различения не делает (хелпер всегда teardown'ит после CAS).

**Что требуется:** определить взаимодействие явно. Либо (i) немедленный сигнал и teardown идут вместе
ВСЕГДА, а Компонент 4 — только для стримов, которые на момент origin-смерти были stOrphaned (entry не
сносится, ждёт RESUME — это исходная destClosed-семантика); либо (ii) при недоставке Enqueue
(ErrWSWriterClosed) хелпер откатывает teardown и оставляет entry orphaned+destClosed для RESUME.
Сейчас Компоненты 3 и 4 описаны как независимые, и их стык даёт либо дубль (безвреден — guard/ch==nil),
либо ДЫРУ (entry снесён до RESUME) для редкого «оба умерли». Дизайн обязан выбрать.

### HIGH-C — migrateEnabled-only: инвариант объявлен, но кодовая защита (assert/лог при migrateEnabled==false) не помещена в правильную точку

v2 §Инварианты признаёт HIGH-4 (хелпер достижим только под migration; legacy не покрыт; defense-in-depth
лог/assert). Это правильно и закрывает прежний HIGH-4 на уровне намерения. Замечание: оба uplink-пути,
которые зовут хелпер, УЖЕ гейтятся `migrateEnabled` (путь B — websocket.go:827 `&& migrateEnabled`;
путь A — колбэк ставится только в migration-CONNECT, websocket.go:1032). Так что коррупции legacy-app
нет (хелпер физически не зовётся на legacy). Понизил с BLOCKER/HIGH прежнего ревью до HIGH-инварианта:
дизайн должен ЯВНО сказать, что assert/лог ставится ВНУТРИ `signalStreamEnd` (early-return если
сессия не migration) — как страховка от будущего рефактора, который случайно дёрнет хелпер с legacy.

---

## MEDIUM

### MEDIUM-1 — FlagStreamClose flag number: 0x0E свободен (не 0x0F)
core/chunk.go: старший занятый флаг = `FlagStreamAck 0x0D`. Значит **0x0E свободен** и есть для
FlagStreamClose. v2 формулирует «следующий свободный после 0x0E; если 0x0F свободен — он» — неточность
(0x0E сам свободен; брать 0x0E, не 0x0F). Несмертельно, но зафиксировать число явно в дизайне (0x0E),
чтобы план не выбрал 0x0F и не оставил дыру нумерации.

### MEDIUM-2 — snapshot {session,writer} из одного bound.Load() — правильно, но бессмысленно пока BLOCKER-2 открыт
v2 §Компонент 3 шаг 3 и §MEDIUM-4: шифровать под `b.session`, слать на `b.writer`, оба из ОДНОГО
`bound.Load()`. Это корректно закрывает прежний MEDIUM-4 (encrypt-под-A/send-на-B рассинхрон). НО
пока BLOCKER-2 открыт, «один снимок» всё равно может быть снимком МЁРТВОГО A в RESUME-окне. Фикс
BLOCKER-2 (reassociate-before-publish) делает снимок осмысленным. Зафиксировать зависимость.

### MEDIUM-3 — nil-guard bound.Load() — учтён
v2 §MEDIUM-3 требует nil-guard перед разыменованием. Код подтверждает: `bound` никогда не Store(nil)
(нет такого вызова), но новый caller обязан guard. ОК, оставить как есть.

### MEDIUM-4 — releaseOrphanFD на stActive-стриме = no-op — стоит явно отметить
Хелпер копирует образец FlagFin (websocket.go:1209 releaseOrphanFD). Для стрима, убитого в stActive
(никогда не был orphaned, holdsFD==false), это no-op (relay_registry.go releaseOrphanFD идемпотентен).
Корректно; v2 §Компонент 3 шаг 2 перечисляет его «как образец» — добавить полслова «(no-op для
не-orphaned)» для полноты, не баг.

### MEDIUM-5 — тест гонки vs RESUME назван, но он и есть проверка BLOCKER-2 — должен ловить именно окно 600→620
v2 §Тесты: «RESUME выиграл CAS+переставил binding → origin-death хелпер шлёт по АКТУАЛЬНОМУ binding».
Этот тест проверяет состояние ПОСЛЕ reassociate (binding уже B) — он НЕ ловит опасное окно (CAS
выигран, binding ещё A). Тест надо переформулировать: «RESUME выиграл CAS(:600) но reassociate(:620)
ЕЩЁ не выполнен → origin-death CAS(stActive→stClosing) НЕ должен снести стрим / должен проиграть».
Без воспроизведения именно этого interleaving тест зелёный при сломанном коде.

---

## NIT

- **NIT-1** ENV-флаг: v2 устранил прежнее противоречие — `SHADOWLINK_ORIGIN_DEATH_TEARDOWN` default-OFF
  на первую канарейку, флип после зелёной. ОК.
- **NIT-2** Метрики: `origin_death_teardown_total{path}`, `_signal_sent_total`, `_signal_dropped_total`
  названы. ОК. Добавить, что `_signal_dropped_total` (writer мёртв) — прямой индикатор под-сценария
  «оба TCP умерли», по которому канарейка увидит, нужен ли Компонент 4 на практике.
- **NIT-3** Лог `reason=origin_write_broken_pipe` отдельно от dial-fail — учтён. ОК.
- **NIT-4** Точная механика пути A «не звать s.Close, делегировать хелперу»: уточнить, что хелпер для
  закрытия egress зовёт `entry.tc.Close()` (Компонент 3 шаг 4), а writer-goroutine завершается через
  колбэк-путь без `s.targetConn.Close()` — иначе двойной Close (идемпотентен для net.Conn, но
  закрытие egress ДО CAS открывает relayLoop read-error раньше teardown). Прецедент — CloseKeepTarget.

---

## Сводка по прежним замечаниям

| Прежнее | Статус в v2 |
|---|---|
| BLOCKER-1 (путь A scope) | **ЗАКРЫТ** — колбэк onOriginWriteError, scope подтверждён (websocket.go:889) |
| BLOCKER-2 (CAS vs RESUME) | **НЕ ЗАКРЫТ** — «snapshot bound после CAS» не перекрывает окно 600→620; нужен reassociate-before-publish |
| HIGH-1 (сигнал на мёртвый слот A) | **СНЯТ для осн. сценария** фактом origin≠слот (WS-слот жив); остаток «оба TCP» → см. HIGH-B |
| HIGH-2 (bound.Load vs reassociate) | частично — атомарность ОК, но логическая гонка = BLOCKER-2 |
| HIGH-3 (CAS первым, сигнал при выигрыше) | **ЗАКРЫТ** — Компонент 3 шаг 3 + §HIGH-3 инвариант |
| HIGH-4 (migrateEnabled-only / legacy) | **ЗАКРЫТ по намерению** → HIGH-C (точка assert) |
| MEDIUM-1..5 | учтены; MEDIUM-1(s.Close)→NIT-4; MEDIUM-4(session source)→MEDIUM-2; тест-гонка→MEDIUM-5 |
| Новые в v2 | HIGH-A (W5-guard vs FlagStreamClose), HIGH-B (Компонент3↔4 стык), MEDIUM-1 (0x0E flag #) |

## Рекомендация
Вернуть на короткую ревизию. До плана закрыть в ДИЗАЙНЕ: **BLOCKER-2** (reassociate-before-publish в
handleMigrateOrResume — убрать ложно-успокаивающий «snapshot после CAS»), **HIGH-A** (FlagStreamClose =
top-level chunk.Flags бранч ДО W5-guard), **HIGH-B** (явный стык Компонент 3↔4: не сносить entry при
недоставке, либо ограничить Компонент 4 stOrphaned-стримами). HIGH-C и MEDIUM/NIT — формулировки,
реализуемы в плане. Фундамент (origin≠слот, немедленный сигнал, FlagStreamClose, колбэк пути A) —
верный; до APPROVED осталось закрыть один настоящий BLOCKER и две гонки доставки.

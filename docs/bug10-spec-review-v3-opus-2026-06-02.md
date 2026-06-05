# Bug #10 — Spec review v3 (origin-death teardown + FlagStreamClose)

**Reviewer:** senior eng, третье критическое pre-implementation ревью
**Date:** 2026-06-02
**Spec reviewed:** `docs/superpowers/specs/2026-06-02-bug10-origin-death-teardown-design.md` (v3)
**Prior reviews:** v1 (NEEDS-REVISION, 2 BLOCKER / 4 HIGH), v2 (NEEDS-REVISION, BLOCKER-2 не закрыт + 3 HIGH-A/B/C)
**Code verified against:**
- `core/wsasyncwriter.go` (полный файл — поиск метода liveness)
- `server/websocket.go` (handleMigrateOrResume 570-627, CAS :600, releaseOrphanFD :610, reassociate-call :620; WS-death cleanup 1375-1478 — порядок toOrphaned :1427 vs writer.Close :1475)
- `server/relay_registry.go` (reassociate 732-763, state machine 93-145, closeReader 213-220, launchGraceTimer 784-816, destClosed 139-145)
- `client/ws_pool.go` (demux 3215-3293, top-level FlagMigrate/Resume бранч :3230, W5-guard :3252-3262)

## ВЕРДИКТ: NEEDS-REVISION

v3 закрыла HIGH-A, HIGH-B, HIGH-C корректно и архитектурно чисто. НО **BLOCKER-2 НЕ закрыт** выбранным вариантом **b2** — и не из-за того, что метод `isClosed()` отсутствует (это тривиально добавить), а из-за того, что **дискриминатор «writer A закрыт ⇒ слот A мёртв ⇒ не сносить» НЕВЕРЕН в самом частом RESUME-сценарии**: writer A в опасном окне `:600→:620` ещё ЖИВ (не закрыт), хотя слот A уже фактически мёртв и RESUME выиграл CAS. Доказательство построчное ниже. b2 как сформулирован пропускает гонку, которую призван закрыть.

Это снова «близко к APPROVED» — три HIGH закрыты, фундамент верен — но выбранный вариант закрытия BLOCKER-2 опирается на ложную посылку о порядке закрытия writer'а. Спека сама поставила правильный вопрос в задании ревью («writer A может быть ещё НЕ закрыт в окне → b2 дыра») — ответ: ДА, может, и это дыра.

---

## BLOCKER-2 — b2 НЕ закрывает гонку. Дискриминатор `writer.isClosed()` ложно-положителен в окне :600→:620

### Под-факт 1: метод `isClosed()` НЕ существует (минор сам по себе)

`core/wsasyncwriter.go` — поиск `isClosed|IsClosed|Closed(` по core и server: **0 совпадений**. У `WSAsyncWriter` есть приватный `done chan struct{}` (закрывается в `Close()` :258-260 и в `Run()` на write-error :102/:118/:125), `Enqueue` возвращает `ErrWSWriterClosed` при закрытом `done` (:190-209), и `RunDone()` (:138). Публичного/приватного предиката «жив ли writer» нет.

Сам по себе это NIT: добавить `func (w *WSAsyncWriter) isClosed() bool { select { case <-w.done: return true; default: return false } }` — 4 строки, без гонок (читает только закрытие канала). НО спека формулирует b2 как уже-существующую проверку (`bound.Load().writer.isClosed()`), что вводит в заблуждение про готовность. План обязан явно добавить этот метод. **Понижаю до NIT-1** — реальный BLOCKER ниже.

### Под-факт 2 (РЕШАЮЩИЙ): writer A НЕ закрыт в окне :600→:620 — посылка b2 ложна

b2 (spec строки 90-95, 154-158): «если writer ЖИВ (слот жив) — сносить безопасно; если binding ещё мёртвый слот A (writer закрыт), НЕ сносить — оставить RESUME». Посылка: **`writer A закрыт ⟺ слот A мёртв`**.

Трассировка WS-death cleanup (`server/websocket.go`, ОДНА горутина, последовательно):

```
1375: for _, e := range entriesForSession(...) {        // цикл по ВСЕМ стримам сессии
1403:     admitOrphan(...)                                // FD-charge
1427:     e.toOrphaned(now)   // CAS stActive→stOrphaned  ← RESUME ТЕПЕРЬ МОЖЕТ ВЫИГРАТЬ CAS :600
1442:     launchGraceTimer(...)
       }                                                 // конец цикла
...
1463:     s.CloseKeepTarget() / s.Close()                // teardown стримов
1475: writer.Close()          // done канал A закрывается ← writer A ТОЛЬКО ТЕПЕРЬ "закрыт"
1476: <-writer.RunDone()
1477: conn.Close()
```

`toOrphaned` (:1427) публикует `stOrphaned` — с этого момента RESUME на ДРУГОМ слоте (независимая горутина) может выиграть `CAS(stOrphaned→stActive)` на websocket.go:600. А `writer.Close()` (:1475) выполняется ПОЗЖЕ — после полного цикла orphan'инга всех стримов + цикла teardown стримов. То есть существует реальное окно:

> **`state==stOrphaned` опубликовано (RESUME armed), но `writer A.done` ещё НЕ закрыт ⇒ `writerA.isClosed()==false`.**

Сценарий гонки, который b2 НЕ ловит:

1. Cleanup-горутина A: `toOrphaned` (:1427) → state=stOrphaned. Цикл продолжает orphan'ить остальные стримы (или ещё не дошёл до :1475 writer.Close).
2. RESUME-горутина (слот B): CAS(stOrphaned→stActive) :600 **ВЫИГРЫВАЕТ**. state=stActive. `bound` ещё = A (reassociate на :620 не выполнен).
3. origin-death хелпер (путь B registry-fallback / запоздавший колбэк пути A): CAS(stActive→stClosing) **ВЫИГРЫВАЕТ** (state был stActive).
4. Хелпер по b2: `bound.Load()` = A; `A.writer.isClosed()` → **FALSE** (cleanup ещё не дошёл до :1475). b2 заключает «writer жив, слот жив → сносить безопасно». **Сносит стрим** (`remove`+`closeReader`+`tc.Close`), шлёт FlagStreamClose на writer A.
5. RESUME продолжает :620 → `reassociate(B)` на УЖЕ снесённом relay (closeReader закрыл closeCh+credit, entry removed). Клиент получил RESUME_OK — но relay мёртв. + FlagStreamClose ушёл по writer A (он ещё формально открыт, может даже доставиться на клиента раньше RESUME_OK → клиент закроет стрим, который думал что воскресил).

**Итог идентичен BLOCKER-2 из v2:** воскрешаемый RESUME'ом стрим убит origin-death хелпером в окне CAS-выигран-binding-ещё-A. b2 не отличает «слот A мёртв но writer ещё не закрыт» от «слот A жив» — потому что **в коде orphan-публикация ОПЕРЕЖАЕТ закрытие writer'а** (порядок 1427 < 1475). Дискриминатор liveness writer'а ложно-положителен ровно в опасном окне.

### Почему v2-рекомендация (b1, reassociate-before-publish) корректнее

v2-ревью рекомендовало вариант (b) reassociate-before-publish: переставить `bound.Store(B)` ДО публикации `state=stActive` в `handleMigrateOrResume`. Тогда окна «stActive + bound=A» не существует вовсе — origin-death CAS из stActive всегда возьмёт `bound.Load()` = B (живой), сигнал уйдёт по B, teardown корректен (origin всё равно мёртв). v3 ОТКЛОНИЛ b1 как «рискованнее для Bug #9» и выбрал b2 — но b2 опирается на инвариант `writer-closed ⟺ slot-dead`, которого в коде НЕТ.

**Что требуется от ревизии (выбрать одно):**

- **(b1, рекомендую) reassociate-before-publish.** В `handleMigrateOrResume` для RESUME-пути: сделать `e.bound.Store(B)` (или вынести минимальную «rebind binding»-часть reassociate) ДО `CompareAndSwap(stOrphaned→stActive)` :600. Риск Bug #9 управляем: `bound.Store` сам по себе атомарен и идемпотентен; downBuffer-дренаж/resendTail можно оставить ПОСЛЕ CAS (они не влияют на выбор binding origin-death хелпером). Достаточно переставить ТОЛЬКО `bound.Store(B)` до публикации stActive — дренаж остаётся на месте. Тогда любой origin-death CAS-победитель из stActive увидит B.
- **(b2-fixed) binding-identity, а не writer-liveness.** Хелпер должен сравнивать НЕ «жив ли текущий bound.writer», а «совпадает ли текущий `bound.Load()` с тем binding'ом, на котором случилась origin-write-ошибка». Если binding сменился (RESUME переехал на B) ⇒ origin-death на устаревшем источнике ⇒ не снос (RESUME владеет). Но: origin-write-ошибка и WS-writer — РАЗНЫЕ объекты (entry.tc vs binding.writer), у пути B/колбэка нет естественной ссылки на «binding на момент ошибки». Это делает (b2-fixed) неудобным (как и отмечало v2). **b1 проще и надёжнее.**
- **Любой вариант: дренаж reassociate (downBuffer/resendTail/Broadcast) ДОЛЖЕН остаться ПОСЛЕ CAS** — только `bound.Store` переезжает раньше. Зафиксировать это в дизайне явно, чтобы план не уволок весь reassociate за :600 (что и есть «рискованнее для Bug #9», от чего v3 справедливо уклонялся).

BLOCKER-2 остаётся открытым. Закрыть в ДИЗАЙНЕ (не в плане): убрать b2 (writer-liveness), взять b1 (bound.Store(B) до stActive-publish).

---

## HIGH

### HIGH-A (ЗАКРЫТ) — FlagStreamClose top-level бранч ДО W5-guard

v3 (строки 142-147): FlagStreamClose обрабатывается top-level в demux ДО W5-guard, рядом с распознаванием migrate-reply (ws_pool.go:3230).

Проверка по коду — **ВЕРНО и реализуемо**. В `client/ws_pool.go` demux есть top-level `chunk.Flags`-бранч на :3230:
```
3230: if chunk.Flags == core.FlagMigrate || chunk.Flags == core.FlagResume {
3231:     p.resolveMigrateReplyPayload(chunk.Payload); continue }
3235: if len(chunk.Payload) < 2 { continue }
3252: if v, ok := p.streamMap.Load(streamID); ok { ... if e.slotIdx != idx { continue } }   // W5-guard
```
Этот бранч стоит ВЫШЕ `len<2`-фильтра (:3235) И выше W5-guard (:3252). Добавить `if chunk.Flags == core.FlagStreamClose { ... close(streamChan); continue }` ровно по этому образцу — close-сигнал не подчиняется W5-guard, проходит с любого слота (нужно для Компонента 4 RESUME-fallback на слот B, где slotIdx клиента мог не успеть обновиться). Прямой прецедент существует, реализация однозначна. **HIGH-A закрыт.**

### HIGH-B (ЗАКРЫТ ЛОГИЧЕСКИ, но привязан к BLOCKER-2) — стык К3/К4

v3 (строки 149-158): writer жив → сигнал+teardown (К3); writer мёртв → только `destClosed`, teardown отложен RESUME/grace (К4).

Логика непротиворечива и закрывает дыру v2 (где К3 всегда сносил entry, оставляя К4 без объекта при «оба TCP умерли»). При мёртвом writer хелпер НЕ делает `remove`/`closeReader` — entry остаётся orphaned+destClosed, его подберёт RESUME (Компонент 4 шлёт FlagStreamClose на живой слот B) ИЛИ grace-timer (launchGraceTimer :784-816 — `CAS(stOrphaned→stClosing)` + `remove`+`closeReader`+`tc.Close` через `migrateGracePeriod`). Утечки entry нет: если RESUME не придёт, grace-timer гарантированно снесёт через grace-период. **Подтверждено кодом** (grace-timer уже армится на :1442 при orphan'инге). **HIGH-B закрыт логически.**

**Оговорка:** разводка «writer жив/мёртв» в К3/К4 опирается на ТОТ ЖЕ дискриминатор liveness, что и b2. Если BLOCKER-2 закрывается через b1 (binding всегда указывает на живой B после RESUME), то ветка «writer мёртв» в хелпере остаётся осмысленной ТОЛЬКО для под-сценария «оба TCP умерли разом до RESUME» (binding всё ещё A, A мёртв, RESUME ещё не приходил) — а это именно read-EOF/grace-window-orphaned случай, где entry уже stOrphaned и хелпер не должен сносить. То есть после b1 разводка writer-liveness в хелпере корректна как «teardown только если стрим был stActive с живым WS; orphaned-стримы (writer недоступен) → destClosed+ждать RESUME/grace». План должен переформулировать ветку не как «writerA.isClosed()» (ненадёжно в окне), а как «выиграл ли CAS из stActive с актуальным живым binding» — что естественно даёт b1.

### HIGH-C (ЗАКРЫТ) — assert migrateEnabled внутри хелпера

v3 (строки 160-164): хелпер при входе проверяет `migrateEnabled`; если false — WARN-лог `bug10 helper reached on non-migration session` + return без отправки. Defense-in-depth против будущего рефактора. Точка размещения (внутри `signalStreamEnd`, early-return) указана явно. Оба uplink-пути уже гейтятся migrateEnabled (путь B websocket.go:827, путь A — колбэк только в migration-CONNECT), так что на текущем коде недостижимо — assert чистая страховка. **HIGH-C закрыт.**

---

## Новых гонок от разводки веток — частично (см. BLOCKER-2)

Заданный вопрос: «writer.isClosed() проверён → true → writer закрывается между проверкой и Enqueue — безопасно?». ДА, безопасно: `Enqueue`/`EnqueueControl` на закрытый writer возвращают `ErrWSWriterClosed` (wsasyncwriter.go:194/208), не паникуют — дроп фрейма, не коррупция. TOCTOU «жив→закрылся→Enqueue» безвреден. **Это НЕ источник проблемы.**

Реальная новая гонка — обратная и серьёзнее: «writer.isClosed() → **false** (ложно, в окне :600→:620), хотя слот фактически мёртв и RESUME его воскрешает» → хелпер сносит воскрешаемый стрим. Это и есть незакрытый BLOCKER-2. Разводка веток по writer-liveness ВНЕСЛА эту ложно-положительную ветку, потому что инвариант `writer-closed ⟺ slot-dead` в коде не держится (orphan-публикация :1427 опережает writer.Close :1475).

---

## MEDIUM

### MEDIUM-1 (перенос из v2, ОК) — FlagStreamClose = 0x0E
v2 зафиксировал: старший занятый flag = `FlagStreamAck 0x0D`, 0x0E свободен. v3 §Компонент 2 говорит «следующий свободный после 0x0E; если 0x0F свободен — он» — всё ещё неточная формулировка (0x0E сам свободен). Зафиксировать в дизайне ЯВНО `FlagStreamClose = 0x0E`, чтобы план не выбрал 0x0F. Несмертельно.

### MEDIUM-2 — тест гонки должен ловить именно окно :600→:620 ПРИ незакрытом writer A
v3 §Тесты (строка 172-174): «RESUME выиграл CAS+переставил binding → хелпер шлёт по актуальному binding». Этот тест проверяет состояние ПОСЛЕ reassociate (binding=B) — он НЕ ловит опасное окно (CAS выигран на :600, bound ещё A, writer A ещё открыт). После выбора b1 тест надо переформулировать: «RESUME выиграл CAS(:600), bound уже переставлен на B ДО публикации stActive → origin-death CAS(stActive→stClosing) берёт bound=B, не рвёт воскрешённый стрим / шлёт по B». Без воспроизведения interleaving (orphaned-published-but-writer-not-closed) тест зелёный при сломанном b2.

---

## NIT

- **NIT-1** — добавить `WSAsyncWriter.isClosed()` (4 строки, читает `done`-канал) в план. После перехода на b1 он может вообще не понадобиться в хелпере (binding-identity заменяет writer-liveness) — решить при ревизии.
- **NIT-2** — метрики (`origin_death_teardown_total{path}`, `_signal_sent_total`, `_signal_dropped_total`) и лог `reason=origin_write_broken_pipe` — учтены, ОК.
- **NIT-3** — ENV-флаг `SHADOWLINK_ORIGIN_DEATH_TEARDOWN` default-OFF на первую канарейку — учтено, ОК.
- **NIT-4** — путь A: не звать `s.Close()`, делегировать egress-закрытие хелперу (`entry.tc.Close()` Компонент 3 шаг 4) — учтено в §инвариантах. ОК.

---

## Сводка по замечаниям v2

| v2-замечание | Статус в v3 |
|---|---|
| BLOCKER-2 (CAS vs RESUME окно :600→:620) | **НЕ ЗАКРЫТ** — b2 (writer-liveness) ложно-положителен в окне (orphan-publish :1427 < writer.Close :1475); нужен b1 (bound.Store(B) до stActive-publish) |
| HIGH-A (W5-guard vs FlagStreamClose) | **ЗАКРЫТ** — top-level бранч ДО W5-guard, прецедент :3230 подтверждён кодом |
| HIGH-B (стык К3↔К4) | **ЗАКРЫТ логически** — writer мёртв ⇒ destClosed+grace/RESUME, entry не утечёт (grace-timer подберёт); привязан к форме дискриминатора (см. оговорку) |
| HIGH-C (assert migrateEnabled внутри хелпера) | **ЗАКРЫТ** — точка и поведение указаны |

## Рекомендация

Короткая ревизия v3→v4. ОДНО изменение в дизайне: заменить **b2 (writer.isClosed)** на **b1 (reassociate-before-publish: `e.bound.Store(B)` ДО `CAS(stOrphaned→stActive)` на :600; дренаж downBuffer/resendTail/Broadcast ОСТАЁТСЯ после CAS)**. Переформулировать ветку «writer мёртв» в хелпере (HIGH-B) как «CAS из stActive с актуальным live binding», а не «writerA.isClosed()». Поправить MEDIUM-2 (тест на interleaving orphaned-published-but-writer-open) и MEDIUM-1 (0x0E явно). HIGH-A/B/C закрыты, фундамент (origin≠слот, немедленный сигнал, FlagStreamClose, колбэк пути A) верен — до APPROVED остался один настоящий BLOCKER, причём его правильное закрытие (b1) v2-ревью уже назвало.

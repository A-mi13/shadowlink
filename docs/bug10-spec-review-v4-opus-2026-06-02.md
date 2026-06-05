# Bug #10 — Spec review v4 (origin-death teardown + FlagStreamClose, b1 closure)

**Reviewer:** senior eng, ЧЕТВЁРТОЕ критическое pre-implementation ревью
**Date:** 2026-06-02 (verified against live code 2026-06-03)
**Spec reviewed:** `docs/superpowers/specs/2026-06-02-bug10-origin-death-teardown-design.md` (v4)
**Prior reviews:** v1 (2 BLOCKER/4 HIGH), v2 (BLOCKER-2 + HIGH-A/B/C), v3 (HIGH-A/B/C закрыты; b2 отклонён, рекомендован b1)

**Code verified line-by-line:**
- `server/websocket.go` — handleMigrateOrResume 570-627 (CAS :600, releaseOrphanFD :610, resendTail-metric :618, reassociate-call :620); WS-death cleanup 1375-1478 (entriesForSession :1375, admitOrphan :1403, reject-CAS :1404, toOrphaned :1427, launchGraceTimer :1442, CloseKeepTarget-vs-find :1456-1464, writer.Close :1475)
- `server/relay_registry.go` — state machine 93-145 (destClosed 139-145), entriesForSession 317-327, hasBoundEntriesForSession 337-346, admitOrphan 395-422, releaseOrphanFD 436-440, evictIdleOrphanExcept 464-525, reassociate 732-763 (bound.Store :735, drainAll :739, resend :742, Broadcast :750), toOrphaned 768-774, launchGraceTimer 784-816, relayLoop 576-650 (destClosed-on-EOF 627-629), routeDownFrame 673-714
- `core/chunk.go` — flags 14-27 (FlagStreamAck 0x0D highest)
- `core/wsasyncwriter.go` — Enqueue 190-210, EnqueueControl 215-231, Close 258-260 (no isClosed predicate)
- `client/ws_pool.go` — demux 3215-3293 (top-level FlagMigrate/Resume :3230, len<2 :3235, W5-guard :3252), closeStream 3549-3557

---

## ВЕРДИКТ: APPROVED-WITH-NITS

b1 **закрывает** BLOCKER-2 в той форме, в какой он был доказан v2/v3 (окно «stActive + bound==мёртвый A» на :600→:620). Перепроверено построчно: после переноса `bound.Store(B)` перед `CAS(stOrphaned→stActive)` origin-death-хелпер, который читает ТОЛЬКО `bound.Load()` + `state`, в выигрышной из-stActive ветке гарантированно видит B (живой). Старого окна больше нет.

Новых **BLOCKER/HIGH** гонок b1 не вносит — проверены все 4 читателя `bound` (entriesForSession, hasBoundEntriesForSession, evictIdleOrphan, relayLoop/routeDownFrame) в новом промежуточном окне «bound=B, CAS не сделан, state=stOrphaned». Bug #9 seq-инварианты сохраняются.

Остаются **4 NIT** — все про точность ПЛАНА реализации (не дизайна): спека говорит «переезжает ТОЛЬКО `bound.Store(B)`», но в коде `bound.Store` сидит ВНУТРИ `reassociate` (:735), и наивная реализация создаст две разные `*binding`-структуры. Это надо явно зафиксировать в плане, иначе TDD-исполнитель ошибётся. Ни один NIT не блокирует дизайн.

Счётчики: **BLOCKER 0 / HIGH 0 / MEDIUM 0 / NIT 4**.

---

## 1. BLOCKER-2 закрыт b1 — перепроверка по коду (ПОДТВЕРЖДЕНО)

Origin-death-хелпер (Компонент 3) в выигрышной ветке делает `b := bound.Load()` ОДИН раз и шлёт FlagStreamClose по `b.writer`, шифруя под `b.session`. Его единственные входы для решения — `state` (CAS) и `bound.Load()`. Никакой ссылки на «binding на момент write-ошибки» у него нет (это и делало b2-fixed неудобным, v3 §69).

Окно v2/v3: между `CAS(stOrphaned→stActive)` :600 и `reassociate`(bound.Store) :620 state==stActive, но bound==A. Origin-death выигрывал CAS(stActive→stClosing), брал bound==A (мёртвый) → сигнал в мёртвый writer + снос воскрешаемого стрима.

b1: `bound.Store(B)` ПЕРЕД `CAS(stOrphaned→stActive)`. Разбор по interleaving (сверено с :600, :768, :508, :787 — все переходы через единый `state.CompareAndSwap`):

- **origin-death выиграл первым.** До RESUME-CAS state==stOrphaned. Origin-death-CAS из stActive **не проходит** (state не stActive). Хелпер идёт по orphaned-ветке (Компонент 4: destClosed без сноса). Если origin-death сделал `CAS(stOrphaned→stClosing)` (он вправе из orphaned по своей destClosed-ветке — НО см. NIT-3: спека НЕ говорит, что orphaned-ветка делает этот CAS; она ставит флаг и НЕ сносит) — тогда RESUME-CAS(stOrphaned→stActive) :600 проигрывает → штатный grace_expired fail (:601-604). Корректно, мёртвый стрим не воскрешается.
- **RESUME выиграл первым.** `bound` уже = B (переставлен ДО публикации stActive). origin-death-CAS(stActive→stClosing) берёт `bound.Load()`==B (живой) → FlagStreamClose уйдёт по живому B, клиент получит close на актуальном слоте и сделает retry. Стрим корректно сносится (origin мёртв). Корректно.

Окна «stActive + bound==A» **не существует** ни при каком порядке. BLOCKER-2 закрыт. ✔

---

## 2. b1 не ломает Bug #9 — перепроверка seq-порядка (ПОДТВЕРЖДЕНО)

Спека (§106-122) утверждает: переезжает только `bound.Store(B)`; дренаж (drainAll/resendTail/Broadcast) остаётся после CAS. Проверка:

- **drainAll vs routeDownFrame под perEntryMu.** `reassociate.drainAll` (:739) держит `perEntryMu` для снимка буфера; `routeDownFrame` (:675) держит тот же `perEntryMu` на каждый фрейм. Ранний `bound.Store(B)` (атомарный, вне мьютекса) может позволить relayLoop увидеть B ДО дренажа. Сверено с :687-709: если `downBuffer.byteLen() != 0` (буфер непуст), routeDownFrame идёт по БУФЕРНОЙ ветке (`bufferEmpty==false` на :688-689 → fast-path не берётся), кладёт фрейм в downBuffer под perEntryMu. drainAll сольёт буфер под тем же perEntryMu в seq-порядке. Инвариант «фрейм либо целиком в буфере (флашится reassociate в seq-порядке), либо целиком на fast-path при ПОДТВЕРЖДЁННО пустом буфере» (docstring :662-669) держится независимо от того, когда выполнен `bound.Store`. ✔
- **downSeqCounter монотонен.** `bound.Store` не трогает downSeqCounter; счётчик двигают только routeDownFrame (:693/:707) и читается reassociate (:733). Перенос Store раньше CAS на seq-нумерацию не влияет. ✔
- **resendTail.** `resendTail()` (:550) и `reassociate`-resend (:742) снимают `unackedTail` под perEntryMu; `aDead`-флаг определяется `flag==FlagResume` (:595), не зависит от момента `bound.Store`. Метрика :618 (`resendTail()`) — побочно-чистое наблюдение (docstring :613-616). Перенос Store раньше её не меняет. ✔
- **entriesForSession / hasBoundEntriesForSession (ghost-sweep).** Оба фильтруют `b.session==sess` (:322/:341). Ранний `bound.Store(B)` лишь раньше перепривязывает relay к ЖИВОЙ сессии B:
  - дряхлая сессия A (WS которой умирает): её cleanup-loop `entriesForSession(A)` (:1375) теперь НЕ увидит этот entry (binding уже B) → не будет его орфанить. Это КОРРЕКТНО — entry уже воскрешён на B, орфанить его по A было бы багом. ✔
  - ghost-sweep по B: `hasBoundEntriesForSession(B)` теперь раньше вернёт true → B защищён от reclaim-mid-migration раньше. Строго безопаснее. ✔

Регресс-тест Bug #9 (спека §211-214) корректно требует подтвердить seq-порядок при раннем bound.Store + дренаж-после-CAS. ✔

---

## 3. evictIdleOrphan в окне «bound=B, CAS не сделан, state=stOrphaned» (БЕЗОПАСНО)

В этом промежуточном окне state всё ещё `stOrphaned` (:475-480 `consider` берёт только stOrphaned-кандидатов — entry ПОДХОДИТ под выбор). Если evict выбирает entry жертвой:
- evict делает `CAS(stOrphaned→stClosing)` (:508) — единый single-winner authority.
- Если evict ВЫИГРАЛ CAS — последующий RESUME-CAS(stOrphaned→stActive) :600 ПРОИГРАЕТ → штатный grace_expired fail (:601-604). RESUME не воскрешает снесённый entry. `bound==B` при этом безвреден: evict сносит entry целиком (`remove`+`closeReader`+`tc.Close`+`releaseOrphanFD`+Broadcast :511-524), не глядя на binding. ✔
- Если RESUME-CAS выиграл первым (state стал stActive) — evict-CAS из stOrphaned проиграет (:508 `return`). ✔

Деградации против текущего поведения нет: и сейчас evict может выбрать orphaned entry в гонке с RESUME; single-winner CAS разводит. Ранний bound.Store ничего тут не меняет (evict не читает bound для решения — только `state` :479 и `lastDownlinkNs` :482). ✔

Замечу: `evictIdleOrphanExcept` вызывается из `admitOrphan` (:406/:413) на cleanup-горутине ДРУГОЙ дряхлой сессии. В окне b1 entry bound=B, stOrphaned — admitOrphan(A) для entry ПОД A его не тронет (entry не в map по... — нет, entry в map всегда; но evict consider берёт по `state==stOrphaned` глобально/по scope). Если случайно выберет наш entry — тот же single-winner CAS защитит (см. выше). ✔

---

## 4. Стык К3/К4 (HIGH-B) под b1 — дискриминатор (КОРРЕКТНО)

Спека (§152-160) переформулировала ветку как «выиграл ли CAS из stActive с актуальным live binding» (естественно даёт b1), НЕ «writerA.isClosed()». Проверка:

- **Ветка снос (К3):** хелпер выиграл `CAS(stActive→stClosing)`. Под b1 это значит RESUME уже переехал на живой B (bound==B), ЛИБО стрим никогда не орфанился (bound==исходный живой слот). В обоих случаях `b := bound.Load()` — живой → FlagStreamClose уходит по живому writer, затем `remove`+`closeReader`+`tc.Close`. ✔
- **Ветка не-снос (К4):** стрим orphaned (`state==stOrphaned`, WS-слот недоступен, RESUME ещё не приходил — «оба TCP умерли разом»). Хелпер ставит `destClosed=true`, НЕ делает remove/closeReader. Entry подберёт:
  - либо RESUME-fallback (Компонент 4): reassociate после дренажа видит destClosed → шлёт FlagStreamClose на B, затем teardown;
  - либо grace-timer (:784-816): `CAS(stOrphaned→stClosing)` гарантированно снесёт через grace-период.
  
  **Утечки entry нет** — grace-timer армится на :1442 при каждом orphan'инге; даже если RESUME не придёт, :787 CAS снесёт. ✔

**Дополнительная проверка на утечку при b1 (НЕ в v3):** может ли быть orphaned-стрим, для которого grace-timer НЕ армлен? Grace-timer армится только в cleanup-loop после успешного `toOrphaned` (:1427→:1442). Есть путь публикации stOrphaned без grace-timer? `toOrphaned` (:768) вызывается ТОЛЬКО из cleanup-loop :1427 (grep подтверждает единственный caller). Значит каждый stOrphaned-entry имеет grace-timer. К4-ветка не сносит, но grace-timer подберёт. Утечки нет. ✔

Дискриминатор НЕ опирается на writer-liveness (которая ложно-положительна в окне :1427<:1475, как доказало v3). ✔

---

## 5. 0x0E свободен (ПОДТВЕРЖДЕНО)

`core/chunk.go:14-26` — занятые flags 0x01..0x0D, старший `FlagStreamAck=0x0D` (:26). `0x0E` свободен, `0x0F` тоже. Спека фиксирует `FlagStreamClose=0x0E` явно (§59, MEDIUM-1 закрыт). Per-stream семантика (не session-wide как FlagFin) — корректно, payload `[globalStreamID(2 BE)]` по образцу StreamData. ✔

---

## 6. Новые гонки/дыры от b1 — НЕ найдено (с 4 NIT по реализации)

Заданный вопрос: «гонки, которых не было при b2». b2 вносил ложно-ОТРИЦАТЕЛЬНУЮ liveness (writer-open-but-slot-dead → ошибочный снос). b1 этой ветки не имеет вовсе (дискриминатор = CAS-из-stActive, §4). TOCTOU «writer жив→закрылся→Enqueue» безвреден: `Enqueue`/`EnqueueControl` на закрытый writer возвращают `ErrWSWriterClosed` (:194/:208), не паникуют — дроп фрейма (signal_dropped, RESUME-fallback подберёт). ✔

Новых гонок дизайн b1 не вносит. Но реализация требует точности — отсюда NIT ниже.

---

## NIT (точность ПЛАНА, не дизайна)

### NIT-1 (важнейший для плана) — «только bound.Store переезжает», но Store сидит ВНУТРИ reassociate

Спека (§106-107, §229): «переезжает ТОЛЬКО `e.bound.Store(B)` … дренаж остаётся после CAS». В коде `bound.Store(b)` находится на `relay_registry.go:735` ВНУТРИ `reassociate`, где `b := &binding{session: sess, writer: w}` (:734). Наивная реализация b1 в `handleMigrateOrResume`:
```
b := &binding{session: session, writer: writer}   // новый pointer #1
e.bound.Store(b)                                    // b1: до CAS
if !entry.state.CompareAndSwap(stOrphaned, stActive) { ... }
...
entry.reassociate(...)   // ВНУТРИ снова b2 := &binding{...}; e.bound.Store(b2)  ← pointer #2
```
создаст ДВЕ разные `*binding`-структуры (логически эквивалентные, но разные указатели). Это **не баг корректности** (binding immutable, session/writer те же), НО:
- relayLoop читает `bound.Load()` на каждом фрейме (:687) — между Store#1 и Store#2 может закэшировать pointer#1, потом увидеть pointer#2. Поскольку оба несут {session=B, writer=B}, наблюдаемое поведение идентично. Безопасно, но «лишний» re-store.
- План ДОЛЖЕН выбрать ОДНО из:
  - (a) вынести `bound.Store` из reassociate, передавать готовый `*binding` параметром (reassociate перестаёт стораить, только дренит) — чище, один pointer;
  - (b) оставить двойной store, задокументировать идемпотентность (binding по значению эквивалентны; relayLoop/routeDownFrame безразличны к идентичности pointer'а, читают только .session/.writer).
  
  Рекомендую (a) — устраняет двусмысленность «какой именно Store считается публикацией B». **План обязан это зафиксировать**, иначе TDD-исполнитель реализует по-разному и race-тест MEDIUM-2 может армить не то окно. Спека формулирует инвариант верно, но не указывает механику — для дизайна это NIT, для плана — обязательный пункт.

### NIT-2 — releaseOrphanFD (:610) должен остаться ПРИВЯЗАН к CAS-успеху, не к bound.Store

Сейчас `releaseOrphanFD(entry)` :610 стоит ПОСЛЕ успешного CAS (:600). b1 переносит только `bound.Store` — releaseOrphanFD остаётся после CAS. Это правильно (releaseOrphanFD идемпотентен через CAS holdsFD true→false :437, безопасен даже при гонке с grace-timer). План НЕ должен утащить releaseOrphanFD до CAS вслед за bound.Store: FD-budget освобождается только когда RESUME реально выиграл entry (state стал stActive), иначе при проигрыше CAS мы бы освободили FD у живого orphaned-entry, который ещё держит grace-timer. Зафиксировать в плане: переезжает РОВНО `bound.Store`, ничего больше из тела handleMigrateOrResume. (Спека это подразумевает §107, но явно про releaseOrphanFD не пишет.)

### NIT-3 — orphaned-ветка хелпера: ставит ли destClosed CAS-ом или просто Store?

Спека §97-99 в разборе «origin-death выиграл первым» пишет: «если origin-death успел сделать `CAS(stOrphaned→stClosing)`». Но §152-160 (К4) говорит orphaned-ветка «ставит destClosed=true и НЕ делает remove/closeReader» — т.е. НЕ переводит в stClosing, оставляет stOrphaned для grace/RESUME. Это два разных утверждения. Правильное — §152-160: orphaned-ветка ДОЛЖНА оставить state==stOrphaned (просто `destClosed.Store(true)`, как relayLoop на :628), НЕ делать `CAS(→stClosing)`, иначе она сама снесёт право RESUME воскресить «оба-TCP-живы-но-задержались» стрим. Формулировка §98 («origin-death успел CAS(stOrphaned→stClosing)») вводит в заблуждение — на orphaned-пути хелпер НЕ должен этого CAS делать. План должен взять §152-160 как канон: **orphaned-ветка = `destClosed.Store(true)` без смены state**. Согласуется с существующим relayLoop:627-629 (там ровно `state==stOrphaned → destClosed.Store(true)`, без CAS). Несмертельно (это внутренняя несогласованность текста, не дизайн-дыра), но план обязан разрешить в пользу §152-160.

### NIT-4 — race-тест MEDIUM-2 должен армить окно «bound=B опубликован, CAS ещё НЕ сделан»

Спека §202-210 требует воспроизвести «:600→:620 при незакрытом writer A». Под b1 опасное (теперь безопасное) окно сместилось: «`bound.Store(B)` сделан, `CAS(stOrphaned→stActive)` ещё нет, state==stOrphaned». Тест обязан армить ИМЕННО этот interleaving и проверить: (a) origin-death в этом окне НЕ выигрывает CAS-из-stActive (state==stOrphaned) → идёт по orphaned-ветке (destClosed, без сноса); (b) после CAS origin-death берёт bound==B. Если тест армит только пост-reassociate состояние (bound=B, state=stActive) — он зелёный и при наивной реализации, которая забыла перенести Store (т.е. не ловит регресс b1→b0). Спека §202-210 это в целом покрывает, но под b1 формулировку окна надо уточнить «bound опубликован ДО CAS» (а не «:600→:620 writer-open», что было про b2). NIT — уточнение текста теста, не дизайн.

---

## Сводка по замечаниям v3

| v3-замечание | Статус в v4 |
|---|---|
| BLOCKER-2 (окно stActive+bound=A) | **ЗАКРЫТ** — b1 (bound.Store до CAS); старого окна нет, новое окно (bound=B,state=stOrphaned) безопасно для всех 4 читателей bound |
| HIGH-A (W5-guard) | закрыт в v3, подтверждён: top-level :3230 ВЫШЕ len<2 :3235 и W5-guard :3252 |
| HIGH-B (стык К3/К4) | **ЗАКРЫТ** — дискриминатор «CAS-из-stActive с live binding», не writer-liveness; grace-timer гарантирует отсутствие утечки (единственный caller toOrphaned :1427 всегда армит :1442) |
| HIGH-C (assert migrateEnabled) | закрыт в v3 |
| MEDIUM-1 (0x0E явно) | закрыт §59; 0x0E подтверждён свободным |
| MEDIUM-2 (race-тест на окно) | учтён §202-210 → уточнить под b1-окно (NIT-4) |

## Рекомендация

**APPROVED-WITH-NITS.** Дизайн b1 корректен и закрывает BLOCKER-2 без новых гонок. Все 4 NIT — про механику ПЛАНА/тестов (где именно живёт `bound.Store`, привязка releaseOrphanFD, формулировка orphaned-ветки, окно race-теста), а не про дизайн-дыры. Перед TDD план обязан:
1. **NIT-1:** явно решить — вынести `bound.Store` из reassociate (рекоменд.) ИЛИ задокументировать двойной идемпотентный store.
2. **NIT-2:** зафиксировать «переезжает РОВНО bound.Store; releaseOrphanFD/resendTail-метрика/reassociate-дренаж остаются после CAS».
3. **NIT-3:** orphaned-ветка хелпера = `destClosed.Store(true)` без `CAS(→stClosing)` (канон §152-160, согласовать §97-99).
4. **NIT-4:** race-тест армит окно «bound=B опубликован, CAS ещё НЕ сделан».

Фундамент (origin≠слот, немедленный сигнал по живому writer, FlagStreamClose=0x0E, колбэк пути A, RESUME-fallback) верен. Можно идти в план.

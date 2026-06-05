# Bug #10 — Финальное целостное code-review реализации (origin-death → stream-end signal)

**Дата:** 2026-06-03
**Ревьюер:** Claude (Opus 4.8)
**Объём:** вся фича (9 задач), а не отдельные таски
**Вердикт:** **APPROVED-WITH-NITS**
**Счётчики:** BLOCKER 0 · HIGH 0 · MEDIUM 0 · NIT 3

`go build ./...` — чисто. `go vet ./server/ ./client/ ./core/` — чисто.
`go test ./...` — **PASS** (зелёный на повторном прогоне; см. раздел «Тесты» про транзиентный флак).

---

## 1. Интеграция компонентов спеки v4 — СОГЛАСОВАНЫ

Все 5 компонентов + b1 реализованы и согласованы между собой:

| Компонент спеки v4 | Реализация | Статус |
|---|---|---|
| 1 — destClosed на ВСЕ origin-смерти | read-EOF `relay_registry.go:639` (безусловно, снято `==stOrphaned`); path A `onWriteErr`; path B `signalStreamEnd` | ✓ |
| 2 — `FlagStreamClose=0x0E` | `core/chunk.go:27`; `NewStreamCloseChunk`/`ParseStreamCloseFrame` (407-420) | ✓ |
| 3 — централизованный teardown | `signalStreamEnd` (`relay_registry.go:883`) | ✓ |
| 4 — RESUME-fallback | `reassociate(...,originDeathTeardown)` (`relay_registry.go:782-790`) | ✓ |
| 5 — клиент demux | `handleStreamClose` (`ws_pool.go:3535`), ветка до W5-guard (3243-3248) | ✓ |
| b1 — bound.Store до CAS | `handleMigrateOrResume` (`websocket.go:624-644`) | ✓ |
| YAML-флаг | `config.go:95/206`, `relay_registry.go:250/285`, резолв `handler.go:294` | ✓ |

**Согласованность wire-формата (encode↔decode):** payload `[globalStreamID(2 BE)]` единый везде:
- Сервер encode: `NewStreamCloseChunk` → `binary.BigEndian.PutUint16` (chunk.go:409); зовётся из `signalStreamEnd` (relay_registry.go:893) И `reassociate` RESUME-fallback (relay_registry.go:783) — оба через один конструктор.
- Клиент decode: `ParseStreamCloseFrame` → `binary.BigEndian.Uint16` (chunk.go:419); demux ws_pool.go:3244.
Один конструктор и один парсер, big-endian с обеих сторон — расхождений нет.

**session+writer из одного снимка:** во ВСЕХ трёх местах отправки FlagStreamClose `session` и `writer`
берутся из ОДНОГО `binding`-снимка под одним `bound.Load()`:
- `signalStreamEnd`: `b := e.bound.Load()` один раз, далее `b.session`/`b.writer` (relay_registry.go:891-895).
- `reassociate`: `b` — параметр (caller'ом уже опубликован), `b.session`/`b.writer` (783-785).
- `enqueueDownFrame`: `b` — параметр (851-863).
`binding{session,writer}` — единый `atomic.Pointer` (NEW-5), порвать пару mid-encrypt нельзя.

---

## 2. BLOCKER-2 (гонка RESUME↔origin-death) — ЗАКРЫТ ЦЕЛОСТНО

Стык b1 ↔ signalStreamEnd ↔ reassociate-fallback проверен пошагово:

**b1 (websocket.go:624-625):** `entry.bound.Store(b)` происходит ДО `CAS(stOrphaned→stActive)` (632).
Это устраняет окно, где `state==stActive` но `bound` ещё указывает на мёртвый слот A. После Store любой
origin-death-победитель из stActive прочитает `bound==B` (живой) и пошлёт сигнал на живой слот. Доказано
тестом `TestE2E_b1_ResumeThenOriginDeath_SignalsLiveSlot` — FlagStreamClose приходит на slot B, не A.

**Случай проигрыша RESUME-CAS:** если origin-death выиграл первым из stOrphaned (через grace-путь — но
signalStreamEnd из active-ветки на orphaned стрим CAS НЕ выиграет, уйдёт в `state.Load()==stOrphaned` →
только `destClosed.Store(true)`), либо grace timer успел — RESUME-CAS вернёт `grace_expired fail`
(websocket.go:632-637). `bound==B` при этом безвреден: teardown сносит entry целиком, grace timer
binding не читает (relay_registry.go:816-844). Подтверждено комментарием 629-631 и кодом.

**NIT-2 соблюдён:** ТОЛЬКО `bound.Store` поднят выше CAS; `releaseOrphanFD` (643), tail-resent метрика
(650-652), `reassociate`-drain (653) — все ПОСЛЕ CAS, выполняются лишь когда RESUME реально выиграл.

**signalStreamEnd single-winner:** `CAS(stActive→stClosing)` — единственная authority. Победитель
снимает binding раз, шлёт FlagStreamClose, делает permanent teardown (remove+closeReader+releaseOrphanFD+
tc.Close+broadcast). Не-победитель (orphaned/closing) НЕ снимает entry, лишь `destClosed.Store` если
orphaned (NIT-3, зеркалит read-EOF). Покрыто `TestSignalStreamEnd_SingleWinner`,
`TestSignalStreamEnd_OrphanedOnlySetsDestClosed_NIT3`, `TestSignalStreamEnd_ActiveWinnerSendsAndTearsDown`.

**Двойной сигнал исключён:** активный-победитель шлёт один раз и сносит entry (больше никто не дойдёт).
Orphaned-путь сигнал НЕ шлёт — лишь взводит destClosed; единственный последующий отправитель —
RESUME-fallback в reassociate (один раз на живом B). Grace timer сигнал НЕ шлёт вообще (см. §7 NIT-1).

---

## 3. Флаг default-OFF — ЦЕЛОСТНО

**Гейтинг отправки в ОБОИХ местах:**
- `signalStreamEnd` active-ветка: `if r.originDeathTeardown && b!=nil && ...` (relay_registry.go:892).
- `reassociate` RESUME-fallback: `if originDeathTeardown && e.destClosed.Load()` (relay_registry.go:782).
При OFF ни одно из двух мест FlagStreamClose не шлёт. Третье потенциальное (grace timer) сигнал не шлёт
никогда. → при OFF клиент сигнала не получает нигде. Подтверждено `TestE2E_OriginDeath_FlagOff_NoSignal_Bug10`.

**Teardown всё равно происходит при OFF:** `signalStreamEnd` CAS-победитель делает remove/closeReader/
releaseOrphanFD/tc.Close/broadcast БЕЗ гейта — гейт только вокруг отправки чанка. Egress не виснет.
Подтверждено `TestSignalStreamEnd_GateOff_TeardownStillHappens` (явный тест на это свойство).

**b1-перестановка безусловна и безопасна при OFF:** `bound.Store(b)` до CAS не гейтится флагом
(config.go:93-94 явно фиксирует «not gated»). При OFF перестановка просто публикует живой binding раньше
— это всегда корректное состояние (RESUME именно туда и переключает relay). Сужает гонку, новых путей не
открывает: единственный потребитель более раннего `bound==B` — это та же машина teardown/relayLoop,
которая и так читает `bound.Load()` на каждом фрейме. Безопасно независимо от флага.

---

## 4. Bug #9 НЕ сломан

- `reassociate` сигнатура расширена параметром `originDeathTeardown` — это чистый drain (NIT-1: больше
  НЕ сторит binding, caller публикует до вызова). Тест `TestReassociate_..._NIT1` проверяет, что
  `bound` не меняется внутри reassociate. seq-порядок (`downSeqCounter` не сбрасывается, NEW-3),
  drain downBuffer + resend unackedTail — без изменений.
- RESUME/grace/ghost-sweep: state-машина (stActive/stOrphaned/stClosing) и single-winner CAS
  нетронуты; b1 лишь переставил `bound.Store` относительно CAS, сама CAS-логика та же.
- Прогон `TestMigrate*/TestResume*/TestReassociate*/TestSignalStreamEnd*/TestE2E*/TestRegistry*` вместе
  — **зелёный** (3.2s). Полный `./server/` — зелёный (17.7s).

---

## 5. Гонки / lock-order — ИНВЕРСИЙ НЕТ

Иерархия блокировок при отправке/teardown:
- `onWriteErr` (path A): колбэк ЧИТАЕТСЯ под `s.mu`, но ВЫЗЫВАЕТСЯ после `s.mu.Unlock()`
  (websocket.go:353-356). Значит `signalStreamEnd` НЕ держит `s.mu`. ✓
- `signalStreamEnd`: берёт `registry.mu` (через `remove`) и `perEntryMu` (для broadcast) — по очереди,
  не вложенно (remove завершается до perEntryMu.Lock). `bound`/`state` — atomics. ✓
- demux `handleStreamClose`: только `cl.streamMu`. Полностью на клиенте, серверных mutex не касается. ✓
- `reassociate`: `perEntryMu` держится лишь на snapshot (drainAll+broadcast), отпускается ДО enqueue
  (relay_registry.go:753-766) — encrypt/enqueue вне локов. ✓

Порядок «registry.mu (отпущен) → per-entry CAS/perEntryMu» соблюдён везде (как в Bug #9 Task 11/12).
`creditsMu` не пересекается с teardown-путями FlagStreamClose. Инверсий s.mu↔perEntryMu↔registry.mu↔
streamMu↔creditsMu не обнаружено.

---

## 6. Архитектурная чистота

- **Централизация (architecturally_correct):** все origin-death-пути сходятся в `signalStreamEnd`
  (path A через onWriteErr, path B напрямую) либо во взвод `destClosed`+`reassociate`-fallback
  (read-EOF orphaned). Один teardown-хелпер, один конструктор фрейма, один парсер.
- **Клиент:** `handleStreamClose` — единый teardown, переиспользуется и demux-веткой, и
  `handleSlotDeath.closeStream` (ws_pool.go:3589). Инвариант Delete-before-close в одном месте.
- Мёртвого кода нет; `migrateEnabled` defense-in-depth assert в signalStreamEnd (884-887) оправдан.
- Комментарии адекватны и местами избыточно подробны (см. NIT-2).

---

## 7. Покрытие спеки — каждый инвариант имеет тест

| Инвариант | Тест |
|---|---|
| Флаг nil→OFF, *true→ON | `TestOriginDeathTeardownEnabledOrDefault_*` (config_test) |
| Setter registry | `TestRegistry_OriginDeathTeardownFlag` |
| round-trip FlagStreamClose | `core/chunk_test.go` (NewStreamClose/ParseStreamClose) |
| signal на active-победителе | `TestSignalStreamEnd_ActiveWinnerSendsAndTearsDown` |
| orphaned только destClosed (NIT-3) | `TestSignalStreamEnd_OrphanedOnlySetsDestClosed_NIT3` |
| OFF → teardown без сигнала | `TestSignalStreamEnd_GateOff_TeardownStillHappens` |
| single-winner | `TestSignalStreamEnd_SingleWinner` |
| RESUME-fallback шлёт close | `TestReassociate_DestClosed_SendsStreamClose` |
| NIT-1 reassociate не сторит | `TestReassociate_..._NIT1` |
| e2e origin-death→сигнал (ON) | `TestE2E_OriginDeath_SignalsClient_Bug10` |
| e2e нет сигнала (OFF) | `TestE2E_OriginDeath_FlagOff_NoSignal_Bug10` |
| e2e b1 RESUME→origin-death на живом B | `TestE2E_b1_ResumeThenOriginDeath_SignalsLiveSlot` |
| клиент demux teardown | `TestHandleStreamClose_ClosesStreamAndMap` |
| demux до W5-guard (cross-slot) | `TestHandleStreamClose_BypassesW5Guard` |
| unknown stream no-op | `TestHandleStreamClose_IgnoresUnknownStream` |

**НЕ покрыто (отмечено и приемлемо):**
- Гонка RESUME↔origin-death под `-race -count=3` — требует Linux/gcc (Windows dev без gcc). Должна быть
  прогнана на CI/Linux перед деплоем. Это уже зафиксировано пользователем как остаточная задача.

---

## NIT (3) — не блокеры, на усмотрение

**NIT-1 — grace-expiry без RESUME не шлёт FlagStreamClose (документированный gap).**
Если origin умер пока relay orphaned И RESUME так и не пришёл до истечения grace — grace timer сносит
entry молча (relay_registry.go:813-844, сигнал не шлёт). Клиент в этом сценарии узнаёт об обрыве через
СВОЙ `handleSlotDeath` (слот A умер → closeStream закрыл стрим). То есть висяка нет, но путь доставки —
не FlagStreamClose, а локальная slot-death-очистка клиента. Это согласуется со спекой (симптом-висяк был
именно про ЖИВОЙ WS-слот, где у клиента нет per-stream idle). Рекомендация: добавить одну строку
комментария в launchGraceTimer, что для destClosed-orphan клиента закрывает slot-death (сейчас читателю
неочевидно, почему grace timer не трогает destClosed).

**NIT-2 — избыточно длинные комментарии.** signalStreamEnd / reassociate / b1 несут очень развёрнутые
обоснования (по 10-20 строк). Полезно для свежего ревью, но при будущем рефакторинге легко
рассинхронизировать с кодом. Не действие, наблюдение.

**NIT-3 — `core.PutBuffer(chunk.Payload)` на не-pooled 2-байтном слайсе.** В signalStreamEnd (900) и
reassociate (789) после NewStreamCloseChunk вызывается PutBuffer на heap-слайсе `make([]byte,2)` — это
no-op (комментарий честно это отмечает «kept for symmetry»). Безвредно; при желании можно убрать ради
ясности, но симметрия с enqueueDownFrame — разумный аргумент оставить.

---

## Тесты — результат

- `go build ./...` — OK
- `go vet ./server/ ./client/ ./core/` — OK
- `go test ./...` — **PASS** (полностью зелёный на повторном прогоне, все 12 пакетов ok).
- **Транзиентный флак (НЕ Bug #10):** первый прогон `./...` показал `TestServerHandshakeOverHTTP` и
  `TestServerFullCycle` упавшими (handshake POST уехал в decoy — «invalid character '<'»). В ИЗОЛЯЦИИ
  оба PASS; `./server/` целиком PASS; повторный `./...` PASS. Это межпакетная транзиентная контеншн
  при параллельном прогоне (порты/тайминг), не детерминированный регресс и не связано с фиксом.
- `TestBackpressureStateTracking` падает ТОЛЬКО под `-shuffle=on` — преэкзистентная order-зависимость
  теста, не Bug #10.
- `TestAckJitter_ParetoTailPresent` — преэкзистентный статистический флак, по условию игнорируется.

Итог: реализация Bug #10 целостна, согласована, тесты на фичу зелёные, BLOCKER-2 закрыт без новых дыр,
флаг default-OFF корректен, Bug #9 не задет. Перед деплоем — прогнать `-race` на Linux.

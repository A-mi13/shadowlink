# Review R2: WS Pool Uniform Cells Architecture — после фиксов

**Reviewer:** Opus
**Date:** 2026-05-20
**File reviewed:** `shadowlink/docs/superpowers/specs/2026-05-20-ws-pool-uniform-cells-design.md`
**Previous review:** `2026-05-20-ws-pool-uniform-cells-design-review.md` (R1) — 6C/8W/6S.
**Code cross-checked:** `client/ws_pool.go` (connectSlot:1299, handleSlotDeath:2462, reconnectLoop:1438, ReleaseStream:1960), `client/ws_pool_drain.go` (claimFreeReserveSlot:28, startDrain:62).

---

## Verdict

**APPROVED with MINOR FIXES.** Архитектурное направление сохраняется,
все 6 critical и 8 warning адресованы корректно с конкретными
имплементационными деталями. Plan-writer сможет работать со спекой
без догадок. Найдено 2 новых minor issue, 1 doc-only ambiguity.

---

## Status by fix (14 issues from R1)

**12/14 addressed correctly. 2/14 addressed-but (minor concerns). 0/14 not addressed.**

### Critical

- **C1 — addressed correctly.** §2.1 явно derives `maxConcurrentDrains :=
  max(1, ceil(poolSize * rotationStormBrakeFraction))` с invariant
  `floor >= ceil(poolSize/2)`. Worked through для poolSize 2/4/8.
  Старая ссылка на "literal default of 2" удалена.

- **C2 — addressed correctly.** §2.1.1 описывает bootstrap exemption:
  `5 * drainRevertBackoff` (150s) при `readyCapacity < poolSize/2`.
  Counter `DrainStormBrakeEngagedTotal` (S6) tied in.

- **C3 — addressed correctly.** §2.2.1 явно говорит "scan starts at
  index 0" + "MUST hold reserveMu for the entire scan + install" +
  whitelist всех writers. Reconnect recycle guard в §2.2.2 закрывает
  W7 одновременно.

- **C4 — addressed correctly.** §2.5 содержит call-site table со всеми
  4 callers и их nil-safe поведением (client.go:710, socks5/tcp.go
  :495/531/565). Conclusion столбец явный. Verified из R1 grep, что
  callers действительно nil-guard'ят.

- **C5 — addressed correctly.** §6 acceptance #8 теперь включает
  dashboard update + CLAUDE.md row update. Schema change documented в
  §2.4 с явным "empty = nil cells (NEW field)".

- **C6 — addressed correctly.** §3 переписан: "Current production code
  follows the FIRST" (НЕ closes). Behavior CHANGE отмечен прямо.
  Underflow analysis через `LoadAndDelete` (ws_pool.go:1961) корректен —
  я verified line 1961 действительно atomic `LoadAndDelete`, тогда
  обещанный "no underflow" логически правилен. Старый комментарий
  ws_pool.go:2502-2506 помечен obsolete.

### Warning

- **W1 — addressed correctly.** §6 acceptance #9 — doc-update note
  про snapshot window 2*poolSize и self-correcting brake.

- **W2 — addressed-but.** Спека сохраняет `Connect()` initial fan-out
  на `[0, poolSize)` без явного обоснования почему это не race с
  `claimFreeSlot`. Я НЕ нашёл прямого discussion того asymmetry concern
  из R1 W2. Минорно — на старте никакой drain ещё не запущен (watchdog
  spawns after Connect), но это стоило бы явно сказать одной фразой.

- **W3 — addressed correctly.** §2.1.0 описывает atomic gate
  `inflightDrains.Add(1)` с rollback semantics + secondary
  `readyCapacity` check. Pseudo-code корректный (committed flag,
  hand-off ownership к drainWatchdog).

- **W4 — addressed correctly.** §4 table + new test list:
  `TestRecycle_AfterAllReservesOccupied` с 8 drains.

- **W5 — addressed correctly.** §2.4.1 — frame validation
  `mappedIdx != idx` → drop + `Stats.StaleFrameDroppedTotal`.

- **W6 — addressed correctly.** §2.4.2 split backoff: 5s (regular
  brake), 150s (catastrophic), 30s (no-free-cell). Three cases
  exhaustive, rationale явный.

- **W7 — addressed correctly** (через C3 fix §2.2.2). reconnectLoop
  takes reserveMu, проверяет `p.slots[idx] != nil`, releases lock
  before calling `connectSlot` (который сам берёт reserveMu).
  **Двойного locking'а нет** — это sequential acquire-release-acquire
  pattern, не nested. Verified против ws_pool.go:1306-1308.

- **W8 — addressed correctly.** §6 acceptance #2 — manual whitelist
  review `p.poolSize` usage.

---

## New issues (R2)

### NEW-1 (minor / warning) — §6 acceptance #10 invariant зависит от commit semantics

Acceptance #10 "DrainInflight at session end equals 0" предполагает,
что counter всегда decremented. В §2.1.0 ownership transfer описан:
"committed = true; hand-off counter ownership to drainWatchdog". Но
если drainWatchdog паникует или горутина утекает (e.g. ctx cancel
между Add(+1) и `tearDown`), counter может зависнуть. Стоит явно
сказать: drainWatchdog `defer p.inflightDrains.Add(-1)` независимо от
exit path (timeout, hardCap, ctx.Done, panic recovery). Иначе #10
будет flaky.

**Fix:** в §2.1.0 после "hand-off counter ownership" добавить:
"drainWatchdog uses `defer p.inflightDrains.Add(-1)` to guarantee
decrement on every exit path including ctx cancellation."

### NEW-2 (minor / suggestion) — §3 закрытие streamChans + §C10 newborn-orphan может race

`shadowlink/CLAUDE.md` упоминает `CleanupNewbornOrphans` (§C10 M2,
2026-05) — это server-side periodic eviction. На клиенте если
streamChans закрыт в drainTeardown, а отложенный goroutine SOCKS5 ещё
читает из ch через `range` → exit clean (закрытый канал → range
exits). Это OK. Но `TestHandleSlotDeath_NoUnderflowOnLateRelease`
полагается на то, что после teardown в `ReleaseStream(streamID)`
вернётся `ok=false` от `LoadAndDelete`. Это true только если в loop
ws_pool.go:2485-2500 `streamMap.Delete(streamID)` происходит ДО
закрытия канала. В §3 написано "calls `streamMap.Delete(streamID)`
BEFORE `close(ch)`" — корректно. Но текущий код (line 2485-2500)
делает Delete и close внутри одной Range iteration, порядок Delete-
then-close сохраняется. Стоит закрепить порядок в спеке как явный
invariant ("must remain Delete-before-close"), иначе будущий refactor
может переставить.

**Fix:** §3 после "loop calls streamMap.Delete(streamID) BEFORE
close(ch)" добавить: "This ordering is load-bearing; any future
refactor must preserve Delete-before-close to avoid ReleaseStream
underflow."

### NEW-3 (doc-only ambiguity) — §2.4.2 формулировки "one watchdog tick" и "5s" expect WatchdogInterval

§2.4.2 говорит `drainStormBrakeBackoff = 5 * time.Second` "one
watchdog tick". Predicate WatchdogInterval=5s. Если кто-то снизит
watchdog interval до 2s (config), 5s станет ">2 ticks". Лучше
defined as `1 * watchdogInterval` (derived) или явно сказать "value
chosen because current watchdogInterval = 5s; if watchdog interval
changes, this constant must be revisited."

**Fix:** §2.4.2 связать константу с watchdog interval (либо derived
expression, либо invariant note).

---

## Internal consistency check

- §2.1 floor formula vs §2.1.0 inflightDrains gate vs §2.1.1
  bootstrap — все три формулы согласованы. Сходимость: primary gate
  = inflight counter; secondary gate = readyCapacity < floor; tertiary
  rule = bootstrap exemption под condition `readyCapacity < poolSize/2`.
  Не overlap'аются.

- §2.4.2 split backoff vs §2.1.1 catastrophic backoff — оба используют
  `5 * drainRevertBackoff = 150s` в одной и той же ветке (catastrophic =
  `readyCapacity < poolSize/2`). Это intentional re-statement, не
  contradiction. OK.

- §2.2.1 reserveMu invariant vs §2.2.2 reconnect guard — acquire-release-
  acquire pattern явно описан, double-lock невозможен (verified против
  ws_pool.go:1306 connectSlot самостоятельно берёт reserveMu, а
  reconnectLoop releases перед вызовом). OK.

- §4.2 connectReserveSlot failure path drops placeholder под reserveMu
  ТОЛЬКО если state == slotConnecting — корректно защищает от stomping
  на drain-driven recycle, который мог перевести cell в другое state.

---

## Acceptance criteria completeness

10 criteria покрывают:
1. No paired indexing (grep)
2. Whitelist p.poolSize usage
3. Test rewrites + new tests (7 listed)
4. Canary metrics (natural finish >30%, brake <50)
5. Baseline regression check
6. go vet / go test
7. streamChans uniformity test (new)
8. Dashboard + CLAUDE.md update
9. Snapshot-window doc note
10. inflightDrains underflow check

Покрытие хорошее. Missing edge: НЕТ acceptance для `staleFrameDropped`
counter sanity (W5). Стоит добавить criterion: "during canary,
StaleFrameDroppedTotal grows at most O(drains) — not O(streams)".
Иначе W5 fix не имеет verification.

---

## Plan-writer readiness

Spec self-contained. Code pointers с line numbers явные. Pseudo-code
блоки достаточны для plan tasks. Tests enumerated. Rollback path
явный (env flag off-by-default). Acceptance measurable.

---

## Suggestions to improve plan quality

1. Plan должен включать acceptance #10 check как final step (read
   `DrainInflight` gauge at session shutdown).
2. Plan task для NEW-1 (defer decrement в drainWatchdog) должен быть
   до интеграционных тестов, чтобы flaky #10 не маскировал реальные
   баги.
3. Plan tasks по C6 (streamChans close) должны идти ПОСЛЕ тестового
   refactor (invert assertion в `TestHandleSlotDeath_DrainTeardown
   ClosesStreamChans`), иначе CI red flag заблокирует merge.
4. Counter `StaleFrameDroppedTotal` нужно добавить в acceptance #4
   как sanity-bound (см. completeness section).

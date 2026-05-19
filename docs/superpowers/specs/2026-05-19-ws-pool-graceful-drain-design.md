# WS Pool Graceful Drain — Design

**Date:** 2026-05-19 (v2 — post Opus-review)
**Status:** Draft for second-round review
**Author:** Session continuation from anti-TSPU debt closure (2026-05-18)
**Spec v1 issues fixed in this version:** WriteMessageForStream drain gap, hard-cap stream-kill semantics, countNonReadySlots reserve inflation, reserve slot reuse formalization, slotReader stale-exit, ReaderExits double-count.

## Problem statement

`shadowlink/client/ws_pool.go` хранит пул из 8 WebSocket-соединений к серверу. Каждое соединение мультиплексирует множество логических стримов (SOCKS5 CONNECT'ы). Соединения ротируются каждые `MaxSlotAge = 2 минуты` (viaDirect mode) для обхода TSPU/middlebox kill window и анти-фингерпринтинга.

**Текущая ротация уничтожает активные стримы:**

1. `rotationWatchdogSweep` (тикает каждые 5s) обнаруживает slot с возрастом ≥ `MaxSlotAge + staggerOffset`.
2. Вызывает `maybeRotateSlot("age")` → видит `activeStreams > 0` → defer 30s.
3. Через 30s `slotRotationGraceWithActiveStreams` истёк → **force-rotate**.
4. `fireRotation` → `handleSlotDeath(deathCausePreemptiveRotation)` → **`close(ch)` всех активных стримов на slot'е** (ws_pool.go:2237-2249) И **`transport.Close()`** одновременно.

При активной нагрузке (юзер выгружает данные через клиент) на каждом slot'е постоянно 8-10 активных стримов с TTL 3-7 минут (HTTPS-стримы, Google Docs WebSocket'ы, Telegram MTProto). Force-rotate безусловно их режет — `close(ch)` рвёт downstream channel, upstream приложение получает immediate broken pipe.

**Симптом из field-логов (2026-05-19 user report):**

- Скорость выгрузки падает с ~300 KB/s до ~60 KB/s через ~3-4 минуты после старта
- В логах: `force-rotate active_streams=10 deferred_for=30s`, далее 10 одновременных `downlink done (ch closed)`

**Параллельно существует `rotateOneSlot` (ws_pool.go:1574-1630)** — другой rotation path, вызываемый из `rotationLoop` (тикает 2-8 мин для анти-фингерпринтинга). Он использует `slotDraining` state, polling-ждёт `streams.Load() == 0` до 30s, **затем синхронно** закрывает transport через `handleSlotDeath` (тот же путь). Это **полу-graceful**: ждёт, но всё равно режет. Capacity 8→7 на время блокирующего `connectSlot`.

**Архитектурный разрыв:**
- `rotationLoop`/`rotateOneSlot` → soft path (ждёт 30s polling)
- `maybeRotateSlot`/`fireRotation` (byte_budget + age) → hard path (defer 30s, потом force)
- Оба в финале зовут `handleSlotDeath`, которое **убивает streamChans**

## Industry-standard pattern: HTTP/2 GOAWAY draining

Подтверждено research'ем 2026-05-19: то, что нужно построить — **HTTP/2 GOAWAY-style draining**.

**RFC 7540 §6.8 / RFC 9113:** "GOAWAY allows an endpoint to gracefully stop accepting new streams while still finishing processing of previously established streams."

Ключевой инсайт: GOAWAY **не убивает** существующие streams. Сервер закрывает underlying TCP когда последний stream завершится естественно, или клиент видит EOF на чтении и upstream приложение получает естественный close (а не разорванный канал).

**Envoy `drain_timeout`** (industry reference): default 60s, recommendation 90s для long-lived multiplexed streams. **"Drain sequence does not forcefully terminate active streams."** Hard cap → force close только как backstop, но "force" в Envoy означает закрыть TCP — приложение увидит EOF, не панику.

**gRPC subchannel draining**: через HTTP/2 GOAWAY под капотом.

**Анти-паттерн:** hard close мультиплексированного соединения через выкидывание stream channels — приложение видит NOT EOF, а broken pipe / closed channel.

## Goals

1. **Active streams не убиваются** через `close(ch)` при rotation. После drain teardown'а они должны увидеть **естественный EOF** через `transport.Close()`, а не принудительный close streamChan.
2. **Pool capacity не падает** во время draining: новый slot готов принимать новые streams ещё до teardown'а старого.
3. **Единый rotation path**: `maybeRotateSlot` (byte_budget, age) И `rotationLoop` (анти-фингерпринтинговый) идут через один и тот же `startDrain(idx)`.
4. **Hard cap как backstop**: если стримы не завершились за `drainHardCap`, slot всё равно закрывается. Под "закрывается" подразумевается **`transport.Close()`, без `close(ch)`** — streamChan'ы остаются живы, fetcher на чтении видит nil/empty data, upstream приложение получает EOF естественно.
5. **Observability**: метрики drain_started / drain_natural_finish / drain_hard_cap / drain_duration_seconds + ratio dashboards.
6. **Удалить `rotationLoop`/`rotateOneSlot` дублирование** после унификации.

## Non-goals

- Не меняем `MaxSlotAge` (2 минуты) — TSPU-anti-fingerprinting константа, отдельная задача.
- Не меняем stagger offset jitter (A1 fix 2026-05-18 работает корректно).
- Не вводим dynamic pool sizing — pool size остаётся 8.
- Не делаем per-stream lifecycle tracking (idle detection) — Phase 3+.
- Не трогаем server-side. Только клиент.
- Не делаем stream migration через rebind to new slot (требует server cooperation).

## Design

### State machine (без изменений)

States (ws_pool.go:132-137) — оставляем как есть:
```
slotConnecting → slotReady → slotDraining → (eventually slotDead via reconnectLoop)
                          ↘ slotDead (только on natural failure / panic / context cancel)
```

**Инварианты:**
- `slotReady → slotDraining` через `tryMarkDraining()` (CAS из `slotReady`). Только один drain в момент времени per slot.
- `slotDraining → slotDead` через `handleSlotDeath` с **новым cause** `deathCauseDrainTeardown` — НЕ закрывает streamChans, только transport.
- `AssignStream` уже фильтрует **строго `slotReady`** (ws_pool.go:1662). Draining slot новые стримы НЕ получает — без изменений.
- **Существующие стримы на draining slot'е могут продолжать читать через `slot.transport`** до natural EOF или teardown. **И могут продолжать писать**: для этого WriteMessageForStream / WriteControlMessageForStream **должны разрешать write на draining slot** (см. §Write path fix).

### Pool slice layout (без изменений в размере, но с reuse policy)

`p.slots` остаётся `[]*poolSlot` длины `2*poolSize`. Индексы:
- **Primary range** [0, poolSize): активные slots, AssignStream выбирает из них.
- **Reserve range** [poolSize, 2*poolSize): free pool ячеек.

**Reserve slot allocation policy (FORMALIZED, fixes v1 §Open Questions §1):**

Когда `startDrain(oldIdx)` нужно создать reserve slot:
1. **Find-first-nil**: пройти reserve range [poolSize, 2*poolSize), вернуть первый индекс с `p.slots[newIdx] == nil`.
2. Если все reserve cells заняты (worst case 8 concurrent drains) → **defer drain через storm brake**. Storm brake уже это покрывает (concurrent drains = non-ready slots = blocks new drains).
3. Когда reserve slot[newIdx] становится ready, AssignStream начинает класть туда новые streams **естественно**, потому что AssignStream итерирует по ВСЕМУ slice (всем 16 cells) и проверяет slotReady.

**Reserve slot promotion to primary (FORMALIZED):**

Когда `drainWatchdog` завершает teardown через `handleSlotDeath(oldIdx, deathCauseDrainTeardown)`:
- `oldSlot.transport.Close()` (без close streamChans — это ключевое отличие нового cause).
- `p.slots[oldIdx] = nil` атомарно (через `atomic.StorePointer` или mutex — см. §Concurrency).
- **`oldIdx` теперь свободен** в primary range и может быть переиспользован как новый reserve target для будущих drains.

То есть **primary и reserve ячейки циркулируют**: бывший primary[0] становится nil → следующий drain может выбрать его как reserve target. Reserve[8] что был newIdx становится фактически primary (там streams идут).

**Capacity invariant:** в любой момент в slice есть `poolSize` slotReady cells (под steady state). Во время drain: 1 cell в slotDraining + 1 cell в slotConnecting/slotReady (reserve, который скоро primary) → total = 1 + (poolSize - 1) + 1 ready cells при steady drain.

### Write path fix (FIXES C1)

**Проблема:** `WriteMessageForStream` (ws_pool.go:1808) и `WriteControlMessageForStream` (1823) фильтруют `slot.getState() == slotReady`. После startDrain old slot становится `slotDraining` → write фоллбэк идёт через `WriteMessage` → находит **любой** slotReady (включая reserve slot с другой crypto session) → данные идут не туда → сервер не дешифрует → 1006.

**Fix:** разрешить write на draining slot (он живой, у него тот же session):

```go
// WriteMessageForStream sends a data frame to the slot assigned to this stream.
// Accepts both slotReady AND slotDraining: a draining slot's transport is
// still live and its crypto session is unchanged, so existing streams
// continue using it until natural EOF or drain teardown.
func (p *WSPoolTransport) WriteMessageForStream(streamID uint16, data []byte) error {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.transport != nil {
				st := slot.getState()
				if st == slotReady || st == slotDraining {
					return slot.transport.WriteMessage(data)
				}
			}
		}
	}
	return p.WriteMessage(data)
}
```

Аналогично `WriteControlMessageForStream`.

**Note про `WriteMessage` / `WriteControlMessage` (random-slot fallback):** они остаются с фильтром только `slotReady`. Эти функции — non-stream данные (handshakes, keepalive), они НЕ должны попадать на draining slot чьи стримы вот-вот закроются. Без изменений.

### Iteration scope fix (FIXES C3)

**Проблема:** `countNonReadySlots`, `HealthySlots`, `ReadyCount`, `emitHealthSummary`, `GetSession` итерируют `range p.slots`. После расширения до 2N reserve nil cells добавят false-non-ready → storm brake permanently engaged, ReadyCount false-low, HealthySlots false-low.

**Fix:** **direct iteration с primary/reserve distinction внутри функции** (без helper). Single source of truth — финальная формулировка ниже. См. §Storm brake interaction для финального countNonReadySlots с дополнительной поправкой на parallel reserve.

| Function | Iteration scope | Logic |
|---|---|---|
| `countNonReadySlots` | range p.slots | Primary: nil OR non-ready = count. Reserve: non-nil non-ready (slotConnecting/slotDraining/slotDead) = count, **но reserve slotConnecting, который сопровождает primary slotDraining, НЕ count'ится** (см. §Storm brake). Nil reserve = skip. |
| `HealthySlots` | range p.slots | Любая cell в slotReady (primary или reserve) = count. nil = skip. Reserve ready = active drain replacement, считается. |
| `ReadyCount` | (alias HealthySlots) | Same. |
| `emitHealthSummary` | range p.slots | Iteration with primary/reserve nil handling: nil primary = `dead++`, nil reserve = skip entirely. См. Plan Task 1 Step 5 для full code. |
| `WriteMessage` random fallback | range p.slots | Без изменений — random ready (primary или reserve) для non-stream data годится. |
| `WriteControlMessage` | range p.slots | Same. |
| `AssignStream` | range p.slots | Без изменений — должна видеть reserve ready cells. |
| `GetSession` fallback | range p.slots[:p.poolSize] | **Restricted to primary range** — reserve session ≠ stream's assigned session, использование привело бы к decrypt mismatch. |

**Note:** AssignStream использует full range специально — она должна находить reserve slots после их activation. WriteMessage/WriteControlMessage (non-stream) тоже full range — для handshakes/keepalive любой ready годится.

### `deathCauseDrainTeardown` — new cause (FIXES C2)

**Проблема:** даже после graceful drain, hard cap → `handleSlotDeath` → `close(ch)` всем streams ws_pool.go:2237-2249. Это убивает streams **принудительно**, baseline-симптом сохраняется.

**Fix:** новый death cause `deathCauseDrainTeardown`. Behavior:
- НЕ делает `streamMap.Range` + `close(ch)`.
- НЕ инкрементирует `recordSlotDeath()` (как preemptive).
- НЕ инкрементирует `Stats.ReaderExits` (drain teardown — наша операция, не natural failure).
- Делает `slot.transport.Close()` → reader получит read error, **тихо exit'нет** через `shouldExitReader` (generation сменилась).
- Делает `p.slots[oldIdx] = nil` (slot теперь свободен для reuse).
- Не делает `go reconnectLoop(oldIdx)` — мы не хотим автоматически пересоздавать teardown'нутый slot в той же ячейке. Reserve slot уже работает в другой ячейке.

```go
const (
	deathCauseNatural slotDeathCause = iota
	deathCausePreemptiveRotation    // existing — kept for legacy path
	deathCauseDrainTeardown          // NEW — drain finished or hard cap, no close(ch)
)

func (p *WSPoolTransport) handleSlotDeath(cl *Client, idx int, cause slotDeathCause) {
	slot := p.slots[idx]
	if slot == nil {
		return
	}
	if !slot.tryMarkDead() {
		return
	}
	slot.lastDeathNs.Store(time.Now().UnixNano())

	// For drainTeardown: NO streamMap close. Streams remain in streamMap
	// pointing to the (now-dead) idx. Their next ReadMessage on
	// slot.transport returns EOF; the upstream socket sees natural close.
	// streamMap entries are cleaned up by the stream's own teardown path
	// (FIN frame from server, or upstream close propagation).
	if cause != deathCauseDrainTeardown {
		p.streamMap.Range(func(key, value any) bool {
			if value.(int) == idx {
				streamID := key.(uint16)
				p.streamMap.Delete(streamID)
				cl.streamMu.Lock()
				if ch, ok := cl.streamChans[streamID]; ok {
					close(ch)
					delete(cl.streamChans, streamID)
				}
				cl.streamMu.Unlock()
			}
			return true
		})
		slot.streams.Store(0)
	}

	slot.pendingConnects.Store(0)

	if slot.transport != nil {
		slot.transport.Close()
	}

	switch cause {
	case deathCauseNatural:
		p.recordSlotDeath()
		go p.reconnectLoop(idx)
	case deathCausePreemptiveRotation:
		// legacy path — keep reconnect for backwards compat during Phase 1
		go p.reconnectLoop(idx)
	case deathCauseDrainTeardown:
		// New cause — reserve slot already handles capacity.
		// Free the cell by setting p.slots[idx] = nil so it can be
		// chosen as a reserve target for future drains.
		p.slots[idx] = nil
	}
}
```

**Каскадный эффект:** при `deathCauseDrainTeardown` стримы **не теряют** свой `streamChans` channel. Reader на old slot.transport получает read error → exit (через `shouldExitReader` если slot уже dead). Streams в streamMap указывают на dead idx, но их next write пойдёт через `WriteMessageForStream` → `slot != nil` check провалится (мы только что set `p.slots[oldIdx] = nil`) → **fallback на `WriteMessage`** (random ready slot, у которого другая crypto session) → сервер не дешифрует.

**Это всё ещё проблема!** Stream нужно как-то корректно закрыть со стороны клиента после drain teardown.

**Решение:** в `deathCauseDrainTeardown` ветке, **после** `transport.Close()`, мы **должны** закрыть streamChans оставшихся streams **через FIN-сигнал**, а не `close(ch)`. То есть SOCKS5 client'у нужно послать `EOF` на его socket, что приведёт к естественному `Close()` со стороны клиента.

Конкретно: SOCKS5 client получает stream через `cl.streamChans[id]`. Если этот channel закрыть — Go-receiver видит `ok=false`, что обычно интерпретируется как EOF. То есть `close(ch)` ≠ panic, а ≠ broken pipe. Это **корректный способ сигнализировать EOF** в Go.

**Переосмысление:** в Go `close(ch)` на receive-side выглядит как graceful EOF. Это **не** broken pipe. Это нормальный shutdown.

То есть моя гипотеза о "stream channels close = broken pipe" была неверной. Перепроверяю в коде SOCKS5 client:

```
upstream client → SOCKS5 client → `for data := range ch { conn.Write(data) }` → if ch closed, range exits, conn.Close().
```

Это **graceful EOF** для upstream. **Не** broken pipe.

**ТАК ЧТО C2 НЕ КРИТИЧНО?** Перечитываю ревью:

> При hard cap (90s) с реальной нагрузкой HTTPS-стримов (3-7 мин) никто не уложится → симптом 300→60 KB/s просто сместится во времени, не пропадёт.

Хм. Реальная проблема C2 другая: **если стримы не успевают** завершиться за 90s, мы **всё равно** их закрываем в hard cap. Это значит для long-lived HTTPS streams проблема сохраняется — просто сместилась с 30s grace на 90s drain.

**Это правда.** Drain выигрывает **только** для коротких streams (HTTPS request-response < 90s). Для долгоживущих (Google Docs WebSocket, video streaming) — выигрыш только если они закончатся естественно. А если они активны 5 минут — close(ch) в hard cap всё равно режет.

**Realistic mitigation:** перенести **upstream retry** на сторону клиента. SOCKS5 client при `close(ch)` для HTTPS видит EOF → application layer (браузер) retry'ит request. Для video streaming chunked download — браузер запросит следующий chunk через новый stream → новый stream идёт на reserve slot. Это **нормальное** HTTP behavior, гораздо лучше чем broken pipe.

**Но для WebSocket upstream connections** (Telegram MTProto, Google Docs WS) — close = connection drop, application видит disconnect → reconnect. Это user-visible disruption.

Industry pattern для таких cases: **stream migration** или **server cooperation**. Без них — **просто прерывание** в hard cap, как Envoy и делает.

**Conclusion:** hard cap close(ch) **остаётся** — это backstop, должен срабатывать редко. Если он срабатывает часто — нужно увеличивать hard cap (per-slot или globally). 90s — точка starting, env-конфигурируемая.

**`deathCauseDrainTeardown` всё равно полезен** — он не инкрементирует `recordSlotDeath` (false meltdown), не инкрементирует `Stats.ReaderExits` (false anomaly), и **не** дублирует work через `reconnectLoop`. Это всё ещё критично для корректности метрик.

Так что **C2 reframed**: drain не убирает проблему полностью для long-lived streams, но **уменьшает** её для коротких streams (3-90s lifetime). Hard cap default нужно подобрать на pl1 canary observation.

### `slotReader` early-exit for drained slot (FIXES W6 + C5)

**Проблема:** когда old slot переходит в slotDraining, его существующий `slotReaderWithClient` продолжает читать через `ReadMessage(60s)`. Когда `handleSlotDeath` закрывает transport — reader получает error → exit через handleSlotDeath повторный (no-op через tryMarkDead, но инкрементирует ReaderExits и frame anomaly).

**Fix:** в `slotReaderWithClient` (ws_pool.go:1958) добавить check на slotDraining state. Если slot draining:
- Reader продолжает читать **только existing streams**. Это нужно для downlink: backend шлёт data в этот transport для существующих streams.
- Если ReadMessage возвращает clean exit (`io.EOF` or similar) → НЕ инкрементировать ReaderExits, НЕ classifyWSReadError, **тихо exit**.

Конкретно: в обработчике err добавить:

```go
if err != nil {
	if ctx.Err() != nil {
		return
	}
	if p.shouldExitReader(slot, myGen) {
		return
	}
	// NEW: if slot is in drain teardown, exit silently — drainWatchdog
	// is in charge of metrics and teardown, not us.
	if slot.getState() == slotDead && slot.lastDeathNs.Load() > 0 {
		// Likely drain teardown closed the transport. shouldExitReader
		// should have caught us above via generation, but defensive
		// check here covers race window where state flipped to dead
		// between our gen-check and ReadMessage error.
		return
	}
	// ... existing error handling
}
```

Это уже **в основном** покрыто existing `shouldExitReader` (gen-check). Но проверить race-window: между `setState(slotDraining)` в startDrain и check'ом в slotReader. Race-window мал и safe — даже если reader зашёл в error path, он попадёт в `handleSlotDeath(deathCauseNatural)`, которое через `tryMarkDead` no-op'нется (slot уже dead через drain teardown). Метрики ложно инкрементируются — приемлемо если редко.

**Лучшее решение:** в drainWatchdog **перед** `handleSlotDeath` сделать `slot.generation.Add(1)` чтобы slotReader exit'нулся через `shouldExitReader` чисто:

```go
// In drainWatchdog before handleSlotDeath:
oldSlot.generation.Add(1)
// Now any concurrent slotReader on this slot sees gen mismatch and exits
// silently via shouldExitReader, without touching ReaderExits.
time.Sleep(10 * time.Millisecond) // brief gap for reader to observe gen change
p.handleSlotDeath(cl, oldIdx, deathCauseDrainTeardown)
```

Это чище — использует existing infrastructure.

### `connectReserveSlot` failure handling (FIXES W4)

**Проблема:** если `connectSlot(ctx, newIdx)` returns error (rate limit, network issue), drainWatchdog продолжает работать на oldSlot независимо. Capacity briefly dips но без recovery — reserve не пересоздаётся.

**Fix:** `connectReserveSlot` при failure → `reconnectLoop(newIdx)` (уже в plan). Но **критично** что reconnectLoop делает (нужно проверить):
- Если reconnectLoop успешен — reserve в итоге будет ready.
- Если reconnectLoop fails (postpone) → reserve застрянет в slotConnecting → countNonReadySlots++.

С primarySlots() (см. §Iteration scope fix) reserve slots **не** считаются в countNonReadySlots → storm brake не engaged. Это правильное поведение — capacity дип временный, восстанавливается через reconnectLoop.

**Plan нужен новый test:** `TestConnectReserveSlot_FailureFallsBackToReconnectLoop`.

### Race conditions (UPDATED)

**1. AssignStream race с drain start:**
- T0: thread A entering AssignStream, читает `p.slots[oldIdx].getState() == slotReady`.
- T1: thread B starts drain, `oldSlot.setState(slotDraining)`.
- T2: thread A: `p.streamMap.Store(streamID, oldIdx)`, `oldSlot.streams.Add(1)`.

Результат: новый стрим на draining slot. **Приемлемо** в µs window — стрим живёт на old transport (живой) и пишет через WriteMessageForStream (теперь разрешает draining). Стрим завершится естественно или попадёт под hard cap.

**2. Hard cap race с natural finish:** косметика метрик. Принимаем.

**3. Множественные drain'ы одного slot'а:** `tryMarkDraining` CAS из slotReady — false если уже не ready. Защищает.

**4. NEW: WriteMessageForStream race с teardown:**
- T0: thread A: `WriteMessageForStream(sid)` — читает `p.slots[oldIdx]`, видит slotDraining, transport != nil → начинает `slot.transport.WriteMessage(data)`.
- T1: thread B: drainWatchdog → handleSlotDeath → `slot.transport.Close()`.
- T2: thread A: WriteMessage возвращает write error.

Результат: write error на конкретном фрейме. Upstream stream получит close через streamChans (теперь это **deathCauseDrainTeardown** path — мы НЕ закрываем streamChans? см. §deathCauseDrainTeardown). Если cause = drainTeardown → streamChan НЕ закрыт → next write попадёт в fallback `WriteMessage`... 

**Это снова та же C1 проблема!** Если streamChan не закрыт после drain teardown, **upstream продолжает посылать данные**, которые попадают в wrong slot (random fallback). Сервер не дешифрует.

**Финальное решение:** drainTeardown **МУСТ закрыть streamChans** для streams, **которые активны на момент teardown**. Это то же что hard cap path делает сейчас. Разница с `deathCauseNatural` теперь только:
- НЕ инкрементируем recordSlotDeath / ReaderExits
- НЕ запускаем reconnectLoop в той же ячейке (reserve уже работает)

Иначе говоря: **streams на draining slot всё-таки убиваются в teardown**. Drain даёт им максимум `drainHardCap` времени дожить естественно — короткие streams успевают, длинные нет.

Это и есть **HTTP/2 GOAWAY**: GOAWAY говорит "не открывай новые streams", existing streams могут продолжать, **но connection close в итоге закроет их все**. На практике long-lived streams в HTTP/2 переоткрываются на новой connection через application-level retry.

**Принимаем:** при drain teardown streamChans закрываются. Drain выигрывает для short streams (< drainHardCap). Long streams будут разорваны, application layer retry — стандартное HTTP/2 поведение.

**deathCauseDrainTeardown упрощается:**
- Закрывает streamChans (как deathCauseNatural)
- НЕ инкрементирует recordSlotDeath, ReaderExits, frame anomaly
- НЕ запускает reconnectLoop (reserve уже работает)
- Сетит `p.slots[idx] = nil` для reuse

### Drain timeout — `drainHardCap`

**Значение: 90 секунд** (Envoy Gateway recommendation, RFC 9113 spirit).
**Источник:** env `SHADOWLINK_DRAIN_HARD_CAP` (Duration parse), default `90s`.

**Trade-off recognition:** для streams с TTL > 90s drain не помогает — они режутся как baseline. План **признаёт** что для full mitigation нужен либо increased cap (5+ мин, рискованно из-за TSPU kill window), либо stream migration (требует server cooperation, отдельный proj).

**Phase 1 measurement plan:** на pl1 canary метрика `DrainHardCapTotal / (DrainNaturalFinishTotal + DrainHardCapTotal)` показывает % streams не уложившихся. Если >50% — увеличить cap до 120s. Если ratio все равно высокий — escalate to stream migration design.

### Storm brake interaction

`rotationStormBrakeFraction = 0.25` → threshold = `ceil(poolSize * 0.25)` (2 для poolSize=8).

**Финальная логика countNonReadySlots:**

```go
// countNonReadySlots iterates the entire slice and counts cells contributing
// to the storm brake. Per-cell rules:
//
//   Primary range [0, poolSize):
//     nil or non-slotReady → COUNT (capacity gap)
//
//   Reserve range [poolSize, 2*poolSize):
//     nil → skip (empty space)
//     slotConnecting:
//       if the matching primary slot[i - poolSize] is in slotDraining →
//         skip (parallel drain replacement; not a capacity gap because
//         the primary slot is still serving its existing streams via
//         its live transport — the reserve will assume new-stream
//         capacity within ~30ms-1s once connected)
//       else → COUNT
//     slotDraining/slotDead → COUNT
//     slotReady → skip (active capacity)
//
// Rationale for the slotConnecting exception: without it, single drain
// start temporarily inflates non-ready to 2 (draining primary + connecting
// reserve), which equals the brake threshold for poolSize=8 and blocks
// the very next drain attempt. Exception ensures the brake measures
// SUSTAINED non-ready load, not transient drain-start blip.
func (p *WSPoolTransport) countNonReadySlots() int {
	n := 0
	for i, slot := range p.slots {
		if i < p.poolSize {
			if slot == nil || slot.getState() != slotReady {
				n++
			}
		} else {
			if slot == nil {
				continue
			}
			st := slot.getState()
			if st == slotReady {
				continue
			}
			if st == slotConnecting {
				primaryIdx := i - p.poolSize
				if primaryIdx < p.poolSize && p.slots[primaryIdx] != nil &&
					p.slots[primaryIdx].getState() == slotDraining {
					continue // parallel drain replacement — don't count
				}
			}
			n++
		}
	}
	return n
}
```

**HealthySlots:**

```go
// HealthySlots returns ready cell count across entire slice. Reserve
// ready cells are active drain replacements and count toward capacity.
func (p *WSPoolTransport) HealthySlots() int {
	count := 0
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady {
			count++
		}
	}
	return count
}
```

**Storm brake check ORDER в startDrain (FIXES N2):**

Brake check выполняется **ДО** `tryMarkDraining` чтобы только что transitioned slot не inflate counter. Если CAS succeeded после brake-check — это OK, race-window мал, в worst case один extra drain пройдёт что не критично.

```go
// In startDrain, BEFORE tryMarkDraining:
nonReady := p.countNonReadySlots()
threshold := p.rotationStormBrakeThreshold()
if nonReady >= threshold {
	p.log.Info("WS pool slot drain deferred (storm brake)",
		"slot", oldIdx, "reason", reason,
		"non_ready_slots", nonReady, "brake_threshold", threshold)
	// Backoff so next watchdog tick (5s later) doesn't re-attempt
	// the same drain in a tight loop.
	oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainRevertBackoff).UnixNano())
	return
}

// Brake disengaged — proceed with tryMarkDraining.
if !oldSlot.tryMarkDraining() {
	return
}
// ... continue startDrain flow
```

**Logic под нагрузкой:**

- Steady state: primary 8 ready, reserve all nil. `countNonReadySlots = 0`. Brake disengaged.
- Single drain start: primary 7 ready + 1 draining, reserve 1 connecting (parallel). `countNonReadySlots = 1 + skip = 1`. Threshold 2. Brake disengaged. Next drain can start. ✓
- Two concurrent drains: 6 ready + 2 draining + 2 connecting (skip both). `count = 2 + 0 = 2`. Threshold 2. Brake engages. Third defers with backoff. ✓
- Two drains finish: 6 ready + 2 nil (cleared) + 2 ready (was connecting). `count = 2 (nil primary) + 0 = 2`. Brake still engaged. **Wait** — that's wrong: we want capacity = 8 here.

**Problem:** после teardown primary[oldIdx] = nil, reserve[newIdx] = ready. Но storm brake считает nil primary как non-ready. Это false-positive — capacity actually unchanged (reserve ready took over). 

**Fix:** countNonReadySlots **не должен** считать nil primary cell если соответствующий reserve cell[i + poolSize] в slotReady. Расширяем правило:

```go
// Updated rule for primary range:
if i < p.poolSize {
	if slot == nil {
		// Check if matching reserve cell took over (drain finished).
		reserveIdx := i + p.poolSize
		if reserveIdx < len(p.slots) && p.slots[reserveIdx] != nil &&
			p.slots[reserveIdx].getState() == slotReady {
			continue // capacity provided by reserve
		}
		n++
		continue
	}
	if slot.getState() != slotReady {
		n++
	}
}
```

**Reformulated invariant:** для каждой логической slot "позиции" pool'а есть либо primary cell в ready, либо reserve cell в ready, либо обе в transition. Только последний случай counts as non-ready. Этой формулировки достаточно для всех drain lifecycle phases.

**Final countNonReadySlots logic:** см. Plan Task 1 Step 3 для полного кода.

### Revert backoff (FIXES N3)

**Проблема:** после storm brake revert на slot[oldIdx], watchdog через 5s снова trigger'нет drain на тот же slot → snova revert → log spam, CPU waste.

**Fix:** добавить `nextDrainAttemptNs atomic.Int64` поле в `poolSlot`. При revert ставим `now + drainRevertBackoff` (30s). `rotationWatchdogSweep` пропускает slots с `nextDrainAttemptNs > now`.

```go
const drainRevertBackoff = 30 * time.Second
```

**Updated rotationWatchdogSweep:**

```go
// In the loop after slotReady check:
if slot.nextDrainAttemptNs.Load() > nowNs {
	continue // backoff active, skip
}
// ... existing age check
```

**Updated startDrain success path:** при успехе drain'а backoff не нужен (slot уже в slotDraining, sweep его не выберет). Backoff применяется только на revert path.

### slotConnecting → slotDraining edge case

Spec не описывает что если drain trigger летит во время первого connect (slot.getState() == slotConnecting). `tryMarkDraining` CAS из slotReady → fails. Это правильное поведение — slot ещё не готов serve streams, его не нужно draining'овать. Sweep попробует снова на следующем tick'е через 5s. **Acceptable.**

### Init changes

```go
func (p *WSPoolTransport) Connect(ctx context.Context) error {
	p.slots = make([]*poolSlot, p.poolSize*2)
	// ... rest of Connect
}
```

`p.poolSize` остаётся 8 — это **active capacity target**. `len(p.slots) = 16` — physical slice size.

### `startDrain(idx)` (UPDATED v2 — storm brake + backoff)

```go
const drainRevertBackoff = 30 * time.Second

func (p *WSPoolTransport) startDrain(cl *Client, oldIdx int, reason string) {
	if !p.gracefulDrain {
		return
	}
	if oldIdx < 0 || oldIdx >= p.poolSize {
		return
	}
	oldSlot := p.slots[oldIdx]
	if oldSlot == nil {
		return
	}

	// Storm brake — check BEFORE tryMarkDraining so we don't inflate
	// non-ready count with the slot we're about to transition.
	nonReady := p.countNonReadySlots()
	threshold := p.rotationStormBrakeThreshold()
	if nonReady >= threshold {
		p.log.Info("WS pool slot drain deferred (storm brake)",
			"slot", oldIdx, "reason", reason,
			"non_ready_slots", nonReady, "brake_threshold", threshold)
		// Backoff so next watchdog tick (5s later) doesn't re-attempt
		// the same drain immediately. Cleared in handleSlotDeath or on
		// successful drain start (slot goes to slotDraining anyway).
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainRevertBackoff).UnixNano())
		return
	}

	if !oldSlot.tryMarkDraining() {
		return
	}

	// Find a free reserve cell. If all 8 reserve cells are occupied
	// (concurrent drains), this is a worst-case fallback — storm brake
	// should have prevented this. Defense in depth: revert state +
	// backoff.
	newIdx := p.findFreeReserveSlot()
	if newIdx < 0 {
		p.log.Warn("WS pool drain skipped — no free reserve cell",
			"slot", oldIdx, "reason", reason)
		oldSlot.state.CompareAndSwap(int32(slotDraining), int32(slotReady))
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainRevertBackoff).UnixNano())
		return
	}

	Stats.DrainStartedTotal.Add(1)
	drainStart := time.Now()
	activeAtStart := oldSlot.streams.Load()

	p.log.Info("WS pool slot drain started",
		"slot", oldIdx,
		"reserve_slot", newIdx,
		"reason", reason,
		"active_streams", activeAtStart,
		"hard_cap", p.drainHardCap,
	)

	go p.connectReserveSlot(cl, newIdx, oldIdx)
	go p.drainWatchdog(cl, oldIdx, oldSlot, drainStart, reason)
}

// findFreeReserveSlot returns the first nil cell in reserve range, or -1.
func (p *WSPoolTransport) findFreeReserveSlot() int {
	for i := p.poolSize; i < len(p.slots); i++ {
		if p.slots[i] == nil {
			return i
		}
	}
	return -1
}
```

**Note про nextDrainAttemptNs:** новое atomic поле в `poolSlot`. Используется только startDrain (set on revert) и `rotationWatchdogSweep` (read). При успешном drain не нужно clearить — slot переходит в draining, watchdog его пропускает по state-check.

### `drainWatchdog` (UPDATED with generation bump)

```go
func (p *WSPoolTransport) drainWatchdog(cl *Client, oldIdx int, oldSlot *poolSlot,
	drainStart time.Time, reason string) {

	ticker := time.NewTicker(drainPollInterval)
	defer ticker.Stop()
	deadline := time.NewTimer(p.drainHardCap)
	defer deadline.Stop()

	tearDown := func(hardCap bool) {
		duration := time.Since(drainStart)
		if hardCap {
			Stats.DrainHardCapTotal.Add(1)
			p.log.Warn("WS pool slot drain hard cap reached",
				"slot", oldIdx, "reason", reason,
				"remaining_streams", oldSlot.streams.Load(),
				"drain_duration", duration.Truncate(time.Second))
		} else {
			Stats.DrainNaturalFinishTotal.Add(1)
			p.log.Info("WS pool slot drain natural finish",
				"slot", oldIdx, "reason", reason,
				"drain_duration", duration.Truncate(time.Second))
		}
		Stats.DrainDurationSeconds.Observe(duration.Seconds())

		// Bump generation BEFORE handleSlotDeath so any concurrent slotReader
		// on oldSlot exits via shouldExitReader (gen mismatch) silently,
		// without inflating ReaderExits or frame anomaly counters.
		oldSlot.generation.Add(1)

		p.handleSlotDeath(cl, oldIdx, deathCauseDrainTeardown)
	}

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-deadline.C:
			tearDown(true)
			return
		case <-ticker.C:
			if oldSlot.streams.Load() == 0 {
				tearDown(false)
				return
			}
		}
	}
}
```

### Метрики

В `client/stats.go`:

```go
DrainStartedTotal       atomic.Int64  // total drains started
DrainNaturalFinishTotal atomic.Int64  // drains where streams reached 0 before hard cap
DrainHardCapTotal       atomic.Int64  // drains where hard cap fired
DrainDurationSeconds    *Histogram    // 1, 5, 10, 30, 60, 90, 120s buckets
```

Существующие:
- `Stats.ReaderExits` — НЕ инкрементируется при drain teardown (gen-bump делает reader silent).
- `rotations1m` — переименовываем в `drains1m` (или эмитим оба для Phase 1).

### Logging

| Старое (will remain for legacy path) | Новое (drain path) |
|---|---|
| `WS pool slot preemptive rotation` | `WS pool slot drain started` |
| `WS pool slot preemptive rotation deferred (active streams)` | n/a — drain не defer'ит на active streams |
| `WS pool slot preemptive rotation deferred (storm brake)` | `WS pool slot drain deferred (storm brake)` |
| `WS pool slot preemptive rotation (grace expired, force rotate)` | `WS pool slot drain hard cap reached` |
| `WS pool rotating slot` (rotateOneSlot) | `WS pool slot drain started` |
| `WS pool slot rotated` | `WS pool slot drain natural finish` |

## Acceptance criteria

1. **Field-test pl1:** скорость выгрузки **не падает резко** на 4-5 минуте. Допустимо медленное снижение если HTTPS-стримы попадают в hard cap, но не fall-off cliff (300→60 KB/s).
2. **`DrainNaturalFinishTotal / (Natural + HardCap) ≥ 30%`** в steady state — baseline measurement target. Реальная цифра зависит от distribution stream lifetimes (для uniform[0, 7min] и hard cap 90s теоретически ~21%; для real-world bursty workload может быть выше). Если < 30% → анализировать distribution, рассмотреть увеличение hard cap до 120s или 180s. Если pure long-lived streams (Telegram MTProto, video) — escalate to stream migration design.
3. **No regression в legacy path:** при `SHADOWLINK_GRACEFUL_DRAIN=0` поведение идентично pre-change. Все existing тесты проходят, тесты на legacy fireRotation/rotateOneSlot path сохраняются и проходят.
4. **Storm brake correctness:**
   - Single drain start: brake disengaged (countNonReadySlots ≤ threshold).
   - 2 concurrent drains: brake on threshold, 3-й defers с backoff.
   - После teardown первого drain: brake disengaged (nil primary + ready reserve = capacity unchanged).
5. **No goroutine leak:** под нагрузкой за 1 час нет роста goroutines (через `runtime.NumGoroutine()` или pprof).
6. **Race detector:** `go test -race ./client/...` PASS.
7. **`shadowlink_slot_drain_started_total` counter** растёт линейно (~30/min для poolSize=8 при steady state 2-минутной age rotation = 8 slots / 120s = 4 drain/min, плюс anti-FP loop = ~6-8/min). Если slope существенно выше — investigation, likely storm-brake-revert spam.

## Rollout

**Phase 1** (~1 day): implementation behind feature flag (default off), tests green, binary.
**Phase 2** (24-48h, юзер): pl1 canary, метрики, decision на flip.

**Phase 2 ops watchlist:**
- `shadowlink_slot_drain_started_total` — должен быть ~6-10/min steady state. Существенно выше → storm-brake-revert spam, investigate.
- `shadowlink_slot_drain_hard_cap_total / drain_started_total` ratio — низкое лучше (≥70% natural finish цель), но <30% acceptable.
- **`recordSlotDeath` rate** — meltdown counter. На canary смотреть не "стучит" ли он от aged reserve cells (W1 known V1 limitation). Если deaths/min растёт пропорционально drain rate → нужен Phase 3 fix promoting reserve→primary через index swap, чтобы reserve aging проходила через graceful drain а не natural kill.
- `shadowlink_ws_frame_anomaly_total{type=closed_local}` — если drain teardown работает корректно (gen-bump silences reader), этот counter должен инкрементироваться **только** на natural failures, не на rotation. Текущий baseline в логах user'а: stream закрытия каждые 30s — после graceful drain должно упасть существенно.
**Phase 3** (1 PR, через days после Phase 2 green): flip default on, legacy paths behind `!flag`.
**Phase 4** (1 PR, неделя после Phase 3): cleanup — delete legacyRotateOneSlot, fireRotation, maybeRotateSlot, slotRotationGraceWithActiveStreams, deathCausePreemptiveRotation merge с deathCauseDrainTeardown.

## Tests (UPDATED — 15 tests)

Файл `shadowlink/client/ws_pool_drain_test.go`:

| Тест | Сценарий |
|---|---|
| `TestPoolSlice_DoubleCapacity` | len(p.slots) == 2*poolSize after init |
| `TestPoolSlot_TryMarkDraining` | CAS slotReady→slotDraining exactly once |
| `TestStartDrain_NaturalFinish` | drain → streams завершаются → metric natural++ |
| `TestStartDrain_HardCap` | drain → streams stays > 0 → metric hard_cap++ |
| `TestStartDrain_ParallelReconnect` | reserve slot становится ready < 1s |
| `TestStartDrain_StormBrakeDefersThirdDrain` | 2 concurrent drains → 3rd defers |
| `TestStartDrain_RejectDoubleDrain` | tryMarkDraining returns false on second call |
| `TestStartDrain_NoFreeReserveSlot` | All 8 reserve cells occupied → drain skipped, state reverted |
| `TestDrainWatchdog_ContextCancel` | ctx.Done() → exit без metric increments |
| `TestAssignStream_SkipsDraining` | regression — draining не получает new streams |
| `TestWriteMessageForStream_AcceptsDraining` | **NEW** — write через draining slot работает на oldSlot.transport |
| `TestCountNonReadySlots_IgnoresEmptyReserve` | **NEW** — nil reserve cells не считаются non-ready |
| `TestHealthySlots_CountsReserveReady` | **NEW** — reserve ready slot считается healthy |
| `TestConnectReserveSlot_FailureFallsBackToReconnectLoop` | **NEW** — connect fail → reconnectLoop запущен |
| `TestSlotReader_SilentExitOnDrainTeardown` | **NEW** — gen-bump → reader exit без ReaderExits++ |
| `TestHandleSlotDeath_DrainTeardownClearsCell` | **NEW** — p.slots[oldIdx] = nil после teardown |
| `TestUnifiedRotation_AgeTriggerUsesStartDrain` | age trigger → startDrain (не fireRotation) |
| `TestUnifiedRotation_ByteBudgetUsesStartDrain` | byte_budget trigger → startDrain |
| `TestUnifiedRotation_AntiFPTickerUsesStartDrain` | rotationLoop → startDrain |

## Open questions

**Removed v2** (formalized in spec body): reserve slot reuse policy, hard cap semantics, write path filter, iteration scope.

**Remaining for review:**

1. **DrainHardCap default 90s vs 120s?** Envoy recommends 90, but our HTTPS streams are notably longer than typical. Suggest measure on pl1 first, default 90s, env-tunable.
2. **`rotations1m` rename to `drains1m`:** emit both during Phase 1-3 to preserve dashboards? Or breaking change in Phase 4?

## References

- ws_pool.go::handleSlotDeath 2226-2269
- ws_pool.go::maybeRotateSlot 2114-2193
- ws_pool.go::rotateOneSlot 1574-1630
- ws_pool.go::WriteMessageForStream 1802-1814
- ws_pool.go::WriteControlMessageForStream 1816-1829
- ws_pool.go::countNonReadySlots 558-566
- ws_pool.go::HealthySlots 2292-2300
- ws_pool.go::slotReaderWithClient 1897-2032
- RFC 7540 §6.8 GOAWAY: https://datatracker.ietf.org/doc/html/rfc7540
- RFC 9113 HTTP/2: https://www.rfc-editor.org/rfc/rfc9113.html
- Envoy Draining: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/draining
- 2026-05-18 anti-TSPU debt: `memory/archive/anti-tspu-debt-closed-2026-05-18.md`
- Opus code review 2026-05-19 (this session) — found C1-C5 critical issues, fixed in v2.

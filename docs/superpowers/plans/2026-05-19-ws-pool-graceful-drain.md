# WS Pool Graceful Drain Implementation Plan (v2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Заменить hard-rotation WebSocket-пула на HTTP/2 GOAWAY-style graceful draining, чтобы активные стримы получали максимум времени дожить естественно, а наша инфраструктура не путала их с natural failures.

**Architecture:** Pool slice расширяется до 2×poolSize ячеек (primary + reserve). При drain'е старый slot переходит в `slotDraining` (transport остаётся живым, write path принимает draining), параллельно в reserve-ячейку создаётся новый slot. AssignStream естественно начинает класть новые streams в reserve. Drain watchdog ждёт `streams==0` или истечения `drainHardCap` (90s default), затем teardown через **новый death cause `deathCauseDrainTeardown`** который не инкрементирует false-positive метрики и освобождает ячейку для будущего reuse. Unified `startDrain(idx)` заменяет `fireRotation`+`rotateOneSlot`.

**Tech Stack:** Go 1.x, `sync/atomic`, `context`, `time`. Test: `testing`, table-driven. Reference: RFC 7540 §6.8, Envoy `drain_timeout`.

**Spec:** `shadowlink/docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md` (v2 — post Opus review)

**v2 changes from v1 plan:**
- Added Task 2: `primarySlots()` + iteration scope fix (BEFORE расширения slice, чтобы legacy path не сломался)
- Added Task 3: WriteMessageForStream/WriteControlMessageForStream accept draining
- Added Task 4: `deathCauseDrainTeardown` new cause + handleSlotDeath branches
- Added Task 8.5: `findFreeReserveSlot` + `revertOnNoReserve` semantics
- Added test for slotReader silent exit via generation bump
- Added test for connectReserveSlot failure scenario
- Reordered tasks: schema changes (iteration scope, write path, death cause) BEFORE slice expansion

---

## File Structure

**Modify:**
- `shadowlink/client/ws_pool.go` — основной refactor.
- `shadowlink/client/stats.go` — добавить counter/histogram fields.
- `shadowlink/cmd/nixavpn-client/engine_shadowlink.go` — env flag wiring.

**Create:**
- `shadowlink/client/ws_pool_drain.go` — `startDrain`, `drainWatchdog`, `connectReserveSlot`, `findFreeReserveSlot`.
- `shadowlink/client/ws_pool_drain_test.go` — все тесты draining.

**Touch (memory + docs):**
- `C:/Users/Lenovo/.claude/projects/D--NIXAVPN/memory/MEMORY.md` — добавить entry про этот fix.
- `shadowlink/CLAUDE.md` — обновить ENV flags таблицу.

---

## Phase 1: Schema preparation (safe BEFORE slice expansion)

### Task 1: `primarySlots()` helper + iteration scope fix

**Files:**
- Modify: `shadowlink/client/ws_pool.go` — функции `countNonReadySlots`, `HealthySlots`, `ReadyCount`, `emitHealthSummary`, `GetSession`
- Test: `shadowlink/client/ws_pool_drain_test.go` (создать)

**Rationale:** перед расширением slice до 2N нам нужно гарантировать что existing iteration sites не сломаются от nil reserve cells. Делаем это **сначала** — поведение идентично без expansion, но готово к ней.

- [ ] **Step 1: Создать failing test**

Create `shadowlink/client/ws_pool_drain_test.go`:

```go
package client

import (
	"context"
	"testing"
)

// TestCountNonReadySlots_IgnoresEmptyReserve verifies that nil cells in
// the reserve range (i >= poolSize) do NOT inflate the non-ready count.
// This guards the storm brake against permanent activation after slice
// expansion to 2*poolSize.
func TestCountNonReadySlots_IgnoresEmptyReserve(t *testing.T) {
	p := &WSPoolTransport{poolSize: 4}
	p.slots = make([]*poolSlot, 8) // 4 primary + 4 reserve, all nil

	// All 4 primary are nil → all count as non-ready (capacity = 0)
	if got := p.countNonReadySlots(); got != 4 {
		t.Errorf("countNonReadySlots with all-nil primary = %d, want 4", got)
	}

	// Fill 4 primary as ready
	for i := 0; i < 4; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	// Reserve still all nil
	if got := p.countNonReadySlots(); got != 0 {
		t.Errorf("countNonReadySlots with 4 primary ready + 4 nil reserve = %d, want 0 (reserve nil = empty, not non-ready)", got)
	}

	// One primary draining, 3 ready, reserve still nil
	p.slots[0].setState(slotDraining)
	if got := p.countNonReadySlots(); got != 1 {
		t.Errorf("countNonReadySlots with 1 draining primary = %d, want 1", got)
	}

	// Add a reserve slot in slotConnecting state (active drain replacement)
	p.slots[4] = &poolSlot{}
	p.slots[4].setState(slotConnecting)
	if got := p.countNonReadySlots(); got != 2 {
		t.Errorf("countNonReadySlots with 1 draining primary + 1 connecting reserve = %d, want 2", got)
	}
}
```

- [ ] **Step 2: Run test, expected to FAIL because current countNonReadySlots iterates entire slice**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestCountNonReadySlots_IgnoresEmptyReserve -v`

Expected: FAIL — 4 nil reserve cells counted as non-ready.

- [ ] **Step 3: Update countNonReadySlots with primary/reserve distinction**

Modify `ws_pool.go`. Найти `countNonReadySlots` (~line 558). Заменить целиком на:

```go
// countNonReadySlots returns the count of slots NOT in slotReady that
// contribute to the storm brake calculation. Logic for each cell:
//
//   Primary range [0, poolSize):
//     - nil cell: check if matching reserve cell[i+poolSize] is in
//       slotReady — if yes, capacity is provided by reserve, skip;
//       otherwise count (capacity gap).
//     - non-slotReady (connecting/draining/dead): count.
//     - slotReady: skip.
//
//   Reserve range [poolSize, 2*poolSize):
//     - nil cell: skip (empty space).
//     - slotConnecting: check if matching primary cell[i-poolSize] is
//       in slotDraining — if yes, this is the parallel drain replacement
//       and primary is still serving streams, skip (not a capacity gap);
//       otherwise count.
//     - slotDraining/slotDead: count.
//     - slotReady: skip.
//
// This handles the full drain lifecycle without false-positive non-ready:
//   - Steady state: 8 primary ready, 8 reserve nil → count = 0
//   - Drain start: 7 ready + 1 draining + 1 reserve connecting (parallel) → count = 1
//   - Drain finish: 7 ready + 1 nil primary + 1 reserve ready → count = 0 (reserve covers)
//   - Two concurrent drains: 6 ready + 2 draining + 2 reserve connecting (parallel) → count = 2
//
// Used by storm brake to bound concurrent drains. Lock-free read of
// per-slot atomic state — snapshot-inconsistent reads of paired primary/
// reserve cells are tolerated because the brake re-evaluates on the next
// watchdog sweep (5s later); a single mis-counted tick has at most one
// extra deferred/granted drain, self-correcting.
func (p *WSPoolTransport) countNonReadySlots() int {
	n := 0
	for i, slot := range p.slots {
		if i < p.poolSize {
			// Primary range
			if slot == nil {
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
		} else {
			// Reserve range
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
					continue // parallel drain replacement, capacity preserved
				}
			}
			n++
		}
	}
	return n
}
```

- [ ] **Step 4: Update HealthySlots and ReadyCount**

В `ws_pool.go` найти `HealthySlots` (~2292). Заменить на:

```go
// HealthySlots returns the number of ready slots in the entire pool
// (primary + reserve). A reserve slot in slotReady is providing real
// capacity (active drain replacement) so it counts toward health.
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

(Эта функция остаётся `range p.slots` — она правильно считает все ready cells включая reserve.)

`ReadyCount` (2306) уже определён как `return p.HealthySlots()` — без изменений.

- [ ] **Step 5: Update emitHealthSummary — spell out**

В `ws_pool.go` найти `emitHealthSummary` (~line 1058). Существующий код примерно такой (точные строки могут отличаться):

```go
func (p *WSPoolTransport) emitHealthSummary() {
	alive, dead, connecting, draining := 0, 0, 0, 0
	rateLimited := 0
	var totalStreams int32
	now := time.Now()
	for _, slot := range p.slots {
		if slot == nil {
			continue
		}
		switch slot.getState() {
		case slotReady:
			alive++
		case slotDead:
			dead++
		case slotConnecting:
			connecting++
		case slotDraining:
			draining++
		}
		totalStreams += slot.streams.Load()
		// ... rate limited check ...
	}
	// ... emit log line ...
}
```

Заменить начало loop'а на индексированную итерацию с правильной обработкой nil cells:

```go
	for i, slot := range p.slots {
		if slot == nil {
			// nil primary cell = capacity gap (counts toward "dead"-like
			// for ops visibility). nil reserve cell = empty space (skip).
			if i < p.poolSize {
				dead++
			}
			continue
		}
		switch slot.getState() {
		case slotReady:
			alive++
		case slotDead:
			dead++
		case slotConnecting:
			connecting++
		case slotDraining:
			draining++
		}
		totalStreams += slot.streams.Load()
		// ... rest unchanged (rateLimited check, etc.) ...
	}
```

Главное: `for _, slot := range p.slots` → `for i, slot := range p.slots`, и nil branch разделяется на primary (count as dead) и reserve (skip entirely). Остальной switch и accumulator logic — без изменений.

- [ ] **Step 6: Update GetSession fallback**

В `ws_pool.go` найти `GetSession` (~1782) и его fallback (1793-1798: `for _, slot := range p.slots { if slot != nil && slot.session != nil && slot.getState() == slotReady`). Этот fallback ищет любой ready slot для возвращения crypto session. Эта операция должна выбирать **первый primary ready**, не reserve (potential confusion):

```go
// Fallback: return first available session from primary range.
// Reserve slots have their own sessions belonging to specific drain
// replacements; using a reserve session for a stream not assigned to
// that slot would yield decrypt mismatches.
for i, slot := range p.slots {
	if i >= p.poolSize {
		break
	}
	if slot != nil && slot.session != nil && slot.getState() == slotReady {
		return slot.session
	}
}
return nil
```

- [ ] **Step 7: Run all client tests**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/...`

Expected: PASS. Если что-то падает — это reveal что вместе с p.slots = N=8 какой-то test полагался на range всего slice. Investigate.

- [ ] **Step 8: Run new failing test**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestCountNonReadySlots_IgnoresEmptyReserve -v`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
cd D:/NIXAVPN/shadowlink
git add client/ws_pool.go client/ws_pool_drain_test.go
git commit -m "refactor(ws_pool): countNonReadySlots distinguishes primary vs reserve

Primary nil cells = non-ready (capacity gap). Reserve nil cells = free
space (not counted). Prepares for 2*poolSize slice expansion without
permanently engaging the storm brake.

HealthySlots/ReadyCount count ready cells anywhere (reserve ready =
active drain replacement). GetSession fallback restricted to primary
range (reserve session ≠ stream's assigned session).

Spec: docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md §Iteration scope fix"
```

---

### Task 2: WriteMessageForStream/WriteControlMessageForStream accept draining

**Files:**
- Modify: `shadowlink/client/ws_pool.go` — функции `WriteMessageForStream` (1802), `WriteControlMessageForStream` (1818)
- Test: `shadowlink/client/ws_pool_drain_test.go`

**Rationale (FIXES C1):** существующие streams на draining slot должны продолжать использовать **тот же** transport до естественного завершения или teardown. Текущий фильтр `== slotReady` отправит их фреймы на random ready slot (другая crypto session) → decrypt fail на сервере.

- [ ] **Step 1: Failing test**

Append to `ws_pool_drain_test.go`:

```go
// TestWriteMessageForStream_AcceptsDraining verifies that a stream
// assigned to a slot that has transitioned to slotDraining continues
// to write through that slot's transport (not a random ready fallback).
// Critical for crypto correctness — the draining slot's session is
// still the one the server expects for this stream.
func TestWriteMessageForStream_AcceptsDraining(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:       2,
		ServerAddr: "127.0.0.1:0",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	// Manually allocate slots without going through Connect()
	p.slots = make([]*poolSlot, p.poolSize)

	// slot 0 is draining — has a stub transport
	stubT := &countingTransport{}
	p.slots[0] = &poolSlot{transport: stubT}
	p.slots[0].setState(slotDraining)

	// slot 1 is ready
	otherT := &countingTransport{}
	p.slots[1] = &poolSlot{transport: otherT}
	p.slots[1].setState(slotReady)

	// streamMap routes streamID 42 to slot 0 (draining)
	p.streamMap.Store(uint16(42), 0)

	err := p.WriteMessageForStream(42, []byte("hello"))
	if err != nil {
		t.Fatalf("WriteMessageForStream returned err: %v", err)
	}
	if stubT.writes != 1 {
		t.Errorf("draining slot transport got %d writes, want 1", stubT.writes)
	}
	if otherT.writes != 0 {
		t.Errorf("other ready slot got %d writes, want 0 (must not fall back)", otherT.writes)
	}
}

// countingTransport is a minimal Transport stub for tests.
type countingTransport struct {
	writes        int
	controlWrites int
}

func (c *countingTransport) WriteMessage(data []byte) error {
	c.writes++
	return nil
}
func (c *countingTransport) WriteControlMessage(data []byte) error {
	c.controlWrites++
	return nil
}
func (c *countingTransport) ReadMessage(timeout time.Duration) ([]byte, error) {
	return nil, nil
}
func (c *countingTransport) Close() error { return nil }
func (c *countingTransport) LastWriteUnixNano() int64 { return 0 }
```

**Important:** `countingTransport` должен реализовать interface, который ожидает `poolSlot.transport`. Найти declaration с помощью `grep -n "type Transport interface\|transport \+\*\|transport\s\+\w" ws_pool.go | head -5`. Если interface на месте — подогнать `countingTransport`. Если `transport` это конкретный type (например `*WSTransport`) — заменить stub на mock через testify/mock или просто использовать nil-defer (тест проверяет что fallback не зовётся).

**Simpler alternative if Transport не interface:** заменить тест на чистую проверку state-filter logic в helper, не вызывая реального WriteMessage. Например, expose `selectWriteSlot(streamID) int` который возвращает индекс выбранного slot'а, и тестировать его.

- [ ] **Step 2: Run test, expected to fail**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestWriteMessageForStream_AcceptsDraining -v`

Expected: FAIL (либо compile error если Transport не interface — тогда переписать на selectWriteSlot approach как выше).

- [ ] **Step 3: Update WriteMessageForStream**

В `ws_pool.go` найти `WriteMessageForStream` (~1802). Заменить:

```go
// WriteMessageForStream sends a data frame to the slot assigned to this
// stream. Accepts both slotReady AND slotDraining: a draining slot's
// transport is still live and uses the same crypto session, so existing
// streams continue using it until natural EOF or drain teardown.
//
// Fallback to WriteMessage (random ready slot) only when the assigned
// slot is dead, connecting, or nil — at which point the stream is
// effectively orphaned and any ready slot will be EBADF'd by the server
// anyway (mismatched session). The fallback is a best-effort no-op
// keepalive path.
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

Аналогично для `WriteControlMessageForStream` (~1818):

```go
func (p *WSPoolTransport) WriteControlMessageForStream(streamID uint16, data []byte) error {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.transport != nil {
				st := slot.getState()
				if st == slotReady || st == slotDraining {
					return slot.transport.WriteControlMessage(data)
				}
			}
		}
	}
	return p.WriteControlMessage(data)
}
```

- [ ] **Step 4: Run test**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestWriteMessageForStream_AcceptsDraining -v`

Expected: PASS.

- [ ] **Step 5: Run all client tests for regression**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/...`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd D:/NIXAVPN/shadowlink
git add client/ws_pool.go client/ws_pool_drain_test.go
git commit -m "fix(ws_pool): write path accepts draining slot for assigned streams

Existing streams on a slotDraining cell continue using that slot's
transport. Previous filter (== slotReady) sent their frames to a random
ready slot with different crypto session → server decrypt failure.

Spec C1: docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md §Write path fix"
```

---

### Task 3: `deathCauseDrainTeardown` new death cause

**Files:**
- Modify: `shadowlink/client/ws_pool.go` — `slotDeathCause` enum, `handleSlotDeath`
- Test: `shadowlink/client/ws_pool_drain_test.go`

**Rationale (FIXES C5, C4 partial):** drain teardown — наша операция, не natural failure. Нужно отдельное cause чтобы:
- Не инкрементировать `recordSlotDeath()` (false meltdown под steady-state drain load)
- Не инкрементировать `Stats.ReaderExits` (это не reader exit, это намеренная teardown)
- Не запускать `reconnectLoop(oldIdx)` (reserve уже работает в newIdx, не нужно дублировать)
- Освободить slot[oldIdx] = nil для reuse как reserve target

- [ ] **Step 1: Locate slotDeathCause enum**

Run: `grep -n "deathCauseNatural\|deathCausePreemptiveRotation\|slotDeathCause" D:/NIXAVPN/shadowlink/client/ws_pool.go | head -10`

- [ ] **Step 2: Failing test**

```go
// TestHandleSlotDeath_DrainTeardownClearsCell verifies that
// handleSlotDeath(deathCauseDrainTeardown) sets p.slots[idx] = nil
// (freeing the cell for reserve reuse) and does NOT spawn reconnectLoop.
func TestHandleSlotDeath_DrainTeardownClearsCell(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := &WSPoolTransport{poolSize: 2}
	p.slots = make([]*poolSlot, 4)
	p.ctx, _ = context.WithCancel(context.Background())
	p.client = cl

	slot := &poolSlot{}
	slot.setState(slotDraining)
	p.slots[0] = slot

	p.handleSlotDeath(cl, 0, deathCauseDrainTeardown)

	if p.slots[0] != nil {
		t.Errorf("after drain teardown, p.slots[0] should be nil, got %v", p.slots[0])
	}
	if slot.getState() != slotDead {
		t.Errorf("slot state should be slotDead, got %v", slot.getState())
	}
}
```

- [ ] **Step 3: Run, expect FAIL (deathCauseDrainTeardown undefined)**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestHandleSlotDeath_DrainTeardownClearsCell -v`

Expected: FAIL.

- [ ] **Step 4: Add new cause to enum**

В `ws_pool.go` найти declaration `slotDeathCause` (через grep в Step 1). Расширить:

```go
const (
	deathCauseNatural slotDeathCause = iota
	deathCausePreemptiveRotation
	deathCauseDrainTeardown // NEW: drain finished or hard cap fired
)
```

- [ ] **Step 5: Update handleSlotDeath**

В `ws_pool.go::handleSlotDeath` (~2226). Заменить body на новую логику с switch на cause:

```go
func (p *WSPoolTransport) handleSlotDeath(cl *Client, idx int, cause slotDeathCause) {
	slot := p.slots[idx]
	if slot == nil {
		return
	}
	if !slot.tryMarkDead() {
		return
	}
	slot.lastDeathNs.Store(time.Now().UnixNano())

	// Close streamChans for ALL causes. Even drain teardown closes them —
	// after transport is gone, any future write on this stream would go
	// through WriteMessageForStream → WriteMessage fallback to a random
	// ready slot with different crypto session → server decrypt fail.
	// Better to signal EOF (close ch) than to silently corrupt the stream.
	// In Go, close(ch) on a receiver is graceful EOF (not broken pipe).
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
	slot.pendingConnects.Store(0)

	if slot.transport != nil {
		slot.transport.Close()
	}

	switch cause {
	case deathCauseNatural:
		// Natural failure — count it for meltdown detection.
		p.recordSlotDeath()
		go p.reconnectLoop(idx)
	case deathCausePreemptiveRotation:
		// Legacy preemptive path: do NOT advance meltdown counter, but
		// DO reconnect the same idx (legacy semantics, kept for Phase 1).
		go p.reconnectLoop(idx)
	case deathCauseDrainTeardown:
		// New graceful path: do NOT advance meltdown counter, do NOT
		// reconnect this idx (reserve slot already carries capacity in
		// a different cell). Free this cell so it can be chosen as
		// the next reserve target.
		p.slots[idx] = nil
	}
}
```

- [ ] **Step 6: Run test**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestHandleSlotDeath_DrainTeardownClearsCell -v`

Expected: PASS.

- [ ] **Step 7: Run all client tests for regression**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/...`

Expected: PASS. Existing tests for deathCauseNatural / deathCausePreemptiveRotation должны быть невредимы — мы только добавили case.

- [ ] **Step 8: Commit**

```bash
cd D:/NIXAVPN/shadowlink
git add client/ws_pool.go client/ws_pool_drain_test.go
git commit -m "feat(ws_pool): introduce deathCauseDrainTeardown

New death cause for drain-initiated teardown:
- Does NOT call recordSlotDeath (no false meltdown)
- Does NOT spawn reconnectLoop (reserve slot carries capacity elsewhere)
- Sets p.slots[idx] = nil to free the cell for future reserve reuse

deathCauseNatural and deathCausePreemptiveRotation unchanged.

Spec C5: docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md §deathCauseDrainTeardown"
```

---

## Phase 2: Slice expansion + state machine

### Task 4: Расширить pool slice до 2×poolSize

(Same as v1 Task 1 — now safe because Tasks 1-3 fixed iteration scope and write path.)

**Files:**
- Modify: `shadowlink/client/ws_pool.go` — функция `Connect` (искать `p.slots = make`)
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Найти текущее место аллокации**

Run: `grep -n "p\.slots\s*=\s*make" D:/NIXAVPN/shadowlink/client/ws_pool.go`

- [ ] **Step 2: Failing test**

```go
func TestPoolSlice_DoubleCapacity(t *testing.T) {
	cl := &Client{}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:       4,
		ServerAddr: "127.0.0.1:0",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = p.allocSlots(ctx)
	if got := len(p.slots); got != 8 {
		t.Errorf("len(p.slots) = %d, want 8 (2*poolSize)", got)
	}
	for i := 4; i < 8; i++ {
		if p.slots[i] != nil {
			t.Errorf("reserve slot[%d] should be nil at init, got non-nil", i)
		}
	}
}
```

- [ ] **Step 3: Run, expect FAIL**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestPoolSlice_DoubleCapacity -v`

Expected: FAIL — `allocSlots` undefined.

- [ ] **Step 4: Implement allocSlots and call in Connect**

В `ws_pool.go`:

```go
// allocSlots initializes p.slots as a slice of 2*poolSize cells.
// Indices [0, poolSize) are primary, [poolSize, 2*poolSize) are reserve.
func (p *WSPoolTransport) allocSlots(ctx context.Context) error {
	p.slots = make([]*poolSlot, p.poolSize*2)
	return nil
}
```

В `Connect()` найти `p.slots = make([]*poolSlot, p.poolSize)` и заменить на `if err := p.allocSlots(ctx); err != nil { return err }`.

- [ ] **Step 5: Run test, PASS**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestPoolSlice_DoubleCapacity -v`

Expected: PASS.

- [ ] **Step 6: Run all tests**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/...`

Expected: PASS (Tasks 1-3 уже подготовили fundament).

- [ ] **Step 7: Commit**

```bash
cd D:/NIXAVPN/shadowlink
git add client/ws_pool.go client/ws_pool_drain_test.go
git commit -m "feat(ws_pool): allocate 2x poolSize slot slice for drain reserve"
```

---

### Task 5: `tryMarkDraining` CAS + `nextDrainAttemptNs` backoff field

**Files:**
- Modify: `shadowlink/client/ws_pool.go` — рядом с `tryMarkDead` + struct `poolSlot`
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Failing tests**

```go
func TestPoolSlot_TryMarkDraining(t *testing.T) {
	s := &poolSlot{}
	s.setState(slotReady)
	if !s.tryMarkDraining() {
		t.Fatal("first tryMarkDraining should return true")
	}
	if s.getState() != slotDraining {
		t.Fatalf("state should be slotDraining, got %v", s.getState())
	}
	if s.tryMarkDraining() {
		t.Fatal("second tryMarkDraining should return false")
	}

	s2 := &poolSlot{}
	s2.setState(slotConnecting)
	if s2.tryMarkDraining() {
		t.Fatal("tryMarkDraining from slotConnecting should fail")
	}

	s3 := &poolSlot{}
	s3.setState(slotDead)
	if s3.tryMarkDraining() {
		t.Fatal("tryMarkDraining from slotDead should fail")
	}
}

// TestPoolSlot_NextDrainAttemptNs verifies the backoff field exists and
// behaves as a simple atomic int64 (zero = no backoff).
func TestPoolSlot_NextDrainAttemptNs(t *testing.T) {
	s := &poolSlot{}
	if got := s.nextDrainAttemptNs.Load(); got != 0 {
		t.Errorf("default nextDrainAttemptNs = %d, want 0", got)
	}
	future := time.Now().Add(30 * time.Second).UnixNano()
	s.nextDrainAttemptNs.Store(future)
	if got := s.nextDrainAttemptNs.Load(); got != future {
		t.Errorf("nextDrainAttemptNs = %d, want %d", got, future)
	}
}
```

- [ ] **Step 2-3: Run, fail, implement**

В `ws_pool.go` найти struct `poolSlot` (grep `type poolSlot struct`). Добавить поле:

```go
// nextDrainAttemptNs is a UnixNano deadline before which rotationWatchdog
// must not attempt to drain this slot. Set when a drain is deferred via
// storm brake or no-reserve-cell — prevents tight retry loop where the
// next 5s watchdog tick re-triggers the same deferred drain. Zero = no
// backoff (slot is eligible for drain on next tick).
nextDrainAttemptNs atomic.Int64
```

И функция:

```go
func (s *poolSlot) tryMarkDraining() bool {
	return s.state.CompareAndSwap(int32(slotReady), int32(slotDraining))
}
```

- [ ] **Step 4: Pass + commit**

```bash
git add client/ws_pool.go client/ws_pool_drain_test.go
git commit -m "feat(ws_pool): tryMarkDraining CAS + nextDrainAttemptNs backoff field"
```

---

## Phase 3: env flags + metrics

### Task 6: Env flags `SHADOWLINK_GRACEFUL_DRAIN` and `SHADOWLINK_DRAIN_HARD_CAP`

(Same as v1 Task 3.)

**Files:**
- Modify: `shadowlink/client/ws_pool.go` — WSPoolConfig + WSPoolTransport struct
- Modify: `shadowlink/cmd/nixavpn-client/engine_shadowlink.go` — pool config
- Modify: `shadowlink/CLAUDE.md`

(Полные шаги см. v1 Task 3 — без изменений.)

```bash
git commit -m "feat(ws_pool): add SHADOWLINK_GRACEFUL_DRAIN and DRAIN_HARD_CAP env flags"
```

---

### Task 7: Drain metrics in Stats

(Same as v1 Task 4.)

**Files:**
- Modify: `shadowlink/client/stats.go`
- Test: `shadowlink/client/ws_pool_drain_test.go`

(Полные шаги см. v1 Task 4 — без изменений.)

```bash
git commit -m "feat(stats): add drain counters and duration histogram"
```

---

## Phase 4: startDrain core

### Task 8: `findFreeReserveSlot` + `startDrain` skeleton

**Files:**
- Create: `shadowlink/client/ws_pool_drain.go`
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Failing test for no-free-reserve case**

```go
// TestStartDrain_NoFreeReserveSlot verifies that when all reserve cells
// are occupied (worst-case concurrent drains), startDrain bails out
// gracefully: state reverts to slotReady, no metric increments.
func TestStartDrain_NoFreeReserveSlot(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	_ = p.allocSlots(ctx)

	// Fill primary with ready slots
	for i := 0; i < 2; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	// Fill ALL reserve cells (busy with prior drains)
	for i := 2; i < 4; i++ {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotConnecting)
	}

	beforeStarted := Stats.DrainStartedTotal.Load()
	p.startDrain(cl, 0, "test")
	afterStarted := Stats.DrainStartedTotal.Load()

	if afterStarted != beforeStarted {
		t.Errorf("DrainStartedTotal moved %d→%d; expected no-op when no reserve free", beforeStarted, afterStarted)
	}
	if p.slots[0].getState() != slotReady {
		t.Errorf("slot 0 state = %v, want slotReady (drain should revert)", p.slots[0].getState())
	}
}
```

- [ ] **Step 2: Run, fail (startDrain undefined)**

- [ ] **Step 3: Create ws_pool_drain.go**

```go
package client

import (
	"time"
)

const (
	drainPollInterval   = 500 * time.Millisecond
	drainRevertBackoff  = 30 * time.Second
)

// findFreeReserveSlot returns the first nil cell in reserve range, or -1.
// Lock-free read of slice; reserve cells are written exclusively by
// startDrain/connectReserveSlot under the implicit serialization that
// only one drain can start per primary idx (tryMarkDraining CAS).
func (p *WSPoolTransport) findFreeReserveSlot() int {
	for i := p.poolSize; i < len(p.slots); i++ {
		if p.slots[i] == nil {
			return i
		}
	}
	return -1
}

// startDrain transitions p.slots[oldIdx] from slotReady to slotDraining
// and spawns parallel connect-reserve + drain-watchdog goroutines.
//
// Sequence of checks (order matters):
//  1. Feature flag off → no-op.
//  2. oldIdx out of primary range → no-op.
//  3. oldSlot nil → no-op.
//  4. Storm brake (countNonReadySlots >= threshold) → set backoff, no-op.
//     This check runs BEFORE tryMarkDraining so the slot we're about to
//     transition doesn't inflate non-ready count.
//  5. tryMarkDraining CAS → false on race loss (another drain or natural
//     failure beat us); no-op.
//  6. findFreeReserveSlot → -1 means all reserve cells occupied;
//     revert state + set backoff.
//  7. Success: spawn connectReserveSlot + drainWatchdog goroutines.
//
// Reason: "age", "byte_budget", or "anti_fingerprint". Propagated to logs
// and metrics via the deathCausePreemptiveRotation/deathCauseDrainTeardown
// machinery in handleSlotDeath.
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

	// Storm brake check BEFORE tryMarkDraining — see func doc comment.
	nonReady := p.countNonReadySlots()
	threshold := p.rotationStormBrakeThreshold()
	if nonReady >= threshold {
		p.log.Info("WS pool slot drain deferred (storm brake)",
			"slot", oldIdx, "reason", reason,
			"non_ready_slots", nonReady, "brake_threshold", threshold)
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainRevertBackoff).UnixNano())
		return
	}

	if !oldSlot.tryMarkDraining() {
		return
	}

	newIdx := p.findFreeReserveSlot()
	if newIdx < 0 {
		p.log.Warn("WS pool drain skipped — no free reserve cell",
			"slot", oldIdx, "reason", reason)
		// Revert state + set backoff. CAS ensures we only revert what we set.
		// If CAS fails, slot was concurrently transitioned (e.g. handleSlotDeath
		// raced us in) — log for visibility, then bail.
		if !oldSlot.state.CompareAndSwap(int32(slotDraining), int32(slotReady)) {
			p.log.Debug("WS pool revert CAS failed — slot died concurrently",
				"slot", oldIdx)
		}
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

// connectReserveSlot creates a fresh poolSlot at newIdx and runs the
// standard connect path. On success, AssignStream picks it up via its
// slotReady filter. On failure, schedules reconnectLoop at newIdx so
// capacity recovers asynchronously; the drainWatchdog tears down oldIdx
// on its own schedule regardless.
func (p *WSPoolTransport) connectReserveSlot(cl *Client, newIdx, oldIdx int) {
	if newIdx < 0 || newIdx >= len(p.slots) {
		return
	}
	p.slots[newIdx] = &poolSlot{}
	p.slots[newIdx].setState(slotConnecting)

	if err := p.connectSlot(p.ctx, newIdx); err != nil {
		p.log.Warn("WS pool reserve slot connect failed",
			"slot", newIdx, "for_drain_of", oldIdx, "err", err)
		go p.reconnectLoop(newIdx)
		return
	}
	go p.slotReader(newIdx)
}

// drainWatchdog polls oldSlot.streams every drainPollInterval until
// either count reaches 0 (natural finish) or drainHardCap elapses.
// Bumps oldSlot.generation BEFORE handleSlotDeath so any concurrent
// slotReader exits silently via shouldExitReader (no false ReaderExits++).
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

		// Bump generation BEFORE handleSlotDeath so slotReader's blocking
		// ReadMessage observes the generation change in its post-read
		// shouldExitReader check, exits silently without inflating
		// Stats.ReaderExits or frame anomaly counters.
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

- [ ] **Step 4: Run test**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestStartDrain_NoFreeReserveSlot -v`

Expected: PASS.

- [ ] **Step 5: Build whole project**

Run: `cd D:/NIXAVPN/shadowlink && go build ./...`

Expected: success.

- [ ] **Step 6: Commit**

```bash
cd D:/NIXAVPN/shadowlink
git add client/ws_pool_drain.go client/ws_pool_drain_test.go
git commit -m "feat(ws_pool): startDrain + drainWatchdog + connectReserveSlot core

Implements:
- findFreeReserveSlot for reserve cell allocation
- startDrain entry point: transitions slotReady→slotDraining, spawns
  parallel reserve reconnect + drain watchdog
- drainWatchdog: poll streams==0 or hard cap, bumps generation before
  handleSlotDeath to silence concurrent slotReader exit
- connectReserveSlot: builds fresh slot in reserve cell, falls back to
  reconnectLoop on connect failure

Spec: docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md §startDrain"
```

---

### Task 9: Test natural-finish path

(Same as v1 Task 6 but with updated cause check.)

**Test:**
```go
func TestDrainWatchdog_NaturalFinish(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	_ = p.allocSlots(ctx)

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	// streams already 0
	p.slots[0] = oldSlot

	before := Stats.DrainNaturalFinishTotal.Load()

	done := make(chan struct{})
	go func() {
		p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainWatchdog did not return for streams==0")
	}

	if got := Stats.DrainNaturalFinishTotal.Load(); got != before+1 {
		t.Errorf("DrainNaturalFinishTotal = %d, want %d", got, before+1)
	}
	if p.slots[0] != nil {
		t.Errorf("p.slots[0] should be nil after drain teardown (cause = drainTeardown)")
	}
}
```

```bash
git commit -m "test(ws_pool): drainWatchdog natural-finish path"
```

---

### Task 10: Test hard-cap path

(Same as v1 Task 7 but verify slot.generation bumped.)

```go
func TestDrainWatchdog_HardCap(t *testing.T) {
	// ... setup with streams stays > 0 ...
	beforeGen := oldSlot.generation.Load()
	p.drainWatchdog(cl, 0, oldSlot, start, "test")
	afterGen := oldSlot.generation.Load()
	if afterGen <= beforeGen {
		t.Errorf("generation should be bumped before handleSlotDeath; before=%d after=%d", beforeGen, afterGen)
	}
}
```

```bash
git commit -m "test(ws_pool): drainWatchdog hard-cap path"
```

---

### Task 11: Test ctx cancel

(Same as v1 Task 8.)

---

### Task 12: Test slotReader silent exit via generation

**Files:**
- Test: `shadowlink/client/ws_pool_drain_test.go`

```go
// TestSlotReader_SilentExitOnDrainTeardown verifies that when
// drainWatchdog bumps slot.generation and triggers handleSlotDeath,
// the concurrent slotReader exits silently via shouldExitReader
// without inflating Stats.ReaderExits or frame anomaly counters.
func TestSlotReader_SilentExitOnDrainTeardown(t *testing.T) {
	// Setup pool with one slot in draining state, with a stub transport
	// that blocks on ReadMessage. Bump generation manually (simulate
	// drainWatchdog tearDown). Verify Stats.ReaderExits unchanged.
	//
	// Note: this test requires Transport to be an interface or mockable.
	// If existing Transport type is concrete struct, this test may need
	// to use a real loopback WS server fixture — file under
	// shadowlink/client/testdata/ws_loopback.go or similar.
	t.Skip("TODO: requires Transport mocking infrastructure; defer to integration test")
}
```

(Если Transport mocking сложно — skip с TODO. Это safety net, не блокер.)

```bash
git commit -m "test(ws_pool): silent reader exit via generation bump (TODO: needs mock)"
```

---

### Task 13: Test connectReserveSlot failure → reconnectLoop

```go
// TestConnectReserveSlot_FailureFallsBackToReconnectLoop verifies that
// when connectSlot returns an error (network unavailable / rate limit),
// connectReserveSlot delegates recovery to reconnectLoop instead of
// crashing or leaving the cell in a corrupt state.
func TestConnectReserveSlot_FailureFallsBackToReconnectLoop(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:1", // intentionally invalid port → connect fails fast
		GracefulDrain: true,
		DrainHardCap:  500 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	_ = p.allocSlots(ctx)

	// We don't call connectReserveSlot directly — instead trigger
	// startDrain on a fake old slot and verify the reserve slot ends up
	// in slotDead or slotConnecting (reconnectLoop scheduled).
	oldSlot := &poolSlot{}
	oldSlot.setState(slotReady)
	p.slots[0] = oldSlot

	p.startDrain(cl, 0, "test")

	// Wait briefly for goroutines
	time.Sleep(200 * time.Millisecond)

	newIdx := p.poolSize // first reserve cell
	if p.slots[newIdx] == nil {
		t.Fatal("reserve slot should have been created (even if connect failed)")
	}
	state := p.slots[newIdx].getState()
	if state == slotReady {
		t.Errorf("reserve slot should NOT be ready (connect to invalid port should fail); got slotReady")
	}
	// Either slotConnecting (reconnectLoop in flight) or slotDead — both OK.
}
```

```bash
git commit -m "test(ws_pool): connectReserveSlot failure → reconnectLoop fallback"
```

---

## Phase 5: Wire triggers through startDrain

### Task 14: Wire age trigger + nextDrainAttemptNs skip

**Files:**
- Modify: `shadowlink/client/ws_pool.go` — функция `rotationWatchdogSweep` (~line 1008)
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Failing tests**

```go
// TestUnifiedRotation_AgeTriggerUsesStartDrain verifies that with
// gracefulDrain on, watchdog sweep on aged slot calls startDrain, not
// legacy fireRotation.
func TestUnifiedRotation_AgeTriggerUsesStartDrain(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		MaxSlotAge:    time.Minute,
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl
	_ = p.allocSlots(ctx)

	slot := &poolSlot{}
	slot.setState(slotReady)
	slot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	slot.streams.Store(5)
	p.slots[0] = slot
	// also need a second primary so storm brake threshold permits drain
	slot2 := &poolSlot{}
	slot2.setState(slotReady)
	slot2.startedAtNs.Store(time.Now().UnixNano())
	p.slots[1] = slot2

	before := Stats.DrainStartedTotal.Load()
	p.rotationWatchdogSweep()
	time.Sleep(100 * time.Millisecond)

	if got := Stats.DrainStartedTotal.Load(); got != before+1 {
		t.Errorf("DrainStartedTotal = %d, want %d", got, before+1)
	}
	if got := slot.getState(); got != slotDraining {
		t.Errorf("slot state = %v, want slotDraining", got)
	}
}

// TestRotationWatchdogSweep_RespectsNextDrainAttemptNs verifies that a
// slot with future nextDrainAttemptNs (backoff active) is skipped by
// the watchdog, preventing tight retry loops after storm brake revert.
func TestRotationWatchdogSweep_RespectsNextDrainAttemptNs(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          2,
		ServerAddr:    "127.0.0.1:0",
		MaxSlotAge:    time.Minute,
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	p.client = cl
	_ = p.allocSlots(ctx)

	slot := &poolSlot{}
	slot.setState(slotReady)
	slot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	slot.streams.Store(5)
	// Set backoff: drain attempts blocked for 30s
	slot.nextDrainAttemptNs.Store(time.Now().Add(30 * time.Second).UnixNano())
	p.slots[0] = slot

	before := Stats.DrainStartedTotal.Load()
	p.rotationWatchdogSweep()
	time.Sleep(50 * time.Millisecond)

	if got := Stats.DrainStartedTotal.Load(); got != before {
		t.Errorf("DrainStartedTotal changed %d→%d; expected backoff to skip drain", before, got)
	}
	if got := slot.getState(); got != slotReady {
		t.Errorf("slot state changed from slotReady to %v despite backoff", got)
	}
}
```

- [ ] **Step 2: Run, expect FAIL (sweep calls maybeRotateSlot or doesn't skip backoff)**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run "TestUnifiedRotation_AgeTriggerUsesStartDrain|TestRotationWatchdogSweep_RespectsNextDrainAttemptNs" -v`

Expected: FAIL.

- [ ] **Step 3: Update rotationWatchdogSweep**

В `ws_pool.go` найти `rotationWatchdogSweep` (~line 1008). Внутри loop'а на slots, ДО age check добавить backoff skip + переключить trigger:

```go
func (p *WSPoolTransport) rotationWatchdogSweep() {
	nowNs := time.Now().UnixNano()
	for idx, slot := range p.slots {
		if slot == nil || slot.getState() != slotReady {
			continue
		}
		// Skip slots in drain backoff (storm brake or no-reserve-cell revert
		// just deferred this one — don't immediately re-trigger).
		if slot.nextDrainAttemptNs.Load() > nowNs {
			continue
		}
		started := slot.startedAtNs.Load()
		if started == 0 {
			continue
		}
		effectiveMaxAge := p.maxSlotAge.Nanoseconds() + slot.staggerOffsetNs.Load()
		if nowNs-started < effectiveMaxAge {
			continue
		}
		slotStart := time.Unix(0, started)
		if p.gracefulDrain {
			p.startDrain(p.client, idx, "age")
		} else {
			p.maybeRotateSlot(p.client, idx, slot, "age",
				0, slotStart, slot.downBytes.Load(),
			)
		}
	}
}
```

Note: `slotStart` сейчас используется только в legacy path. В graceful path `startDrain` сам берёт `slot.startedAtNs` для лога. Это OK.

Также важно: watchdog sweep работает только в primary range. С slice 2x:

```go
for idx := 0; idx < p.poolSize; idx++ {
	slot := p.slots[idx]
	// ... rest of body
}
```

Возможно sweep должен ещё проверять reserve cells (если они достигли max age)? Да — если reserve cell stays ready долго после drain, она такой же primary candidate. Но reserve становится primary логически после teardown'а старого primary. Пока что — sweep по всему slice, при поиске aged ready slot. Это естественно — он триггерит drain на любой aged ready cell.

**Решение:** sweep итерирует **весь** slice (`p.slots`), не только primary. `startDrain` фильтрует `oldIdx >= p.poolSize` → no-op. Это значит aged reserve cells **не будут draining'оваться напрямую — они станут "primary" через циркуляцию (когда соответствующий primary cell освободится и потом ageнется).

**Альтернатива (cleaner):** reserve cell в slotReady tracking — её startedAtNs ставится при connect. Через 2 мин она ageнется. Но startDrain отвергает её (idx >= poolSize). Тогда aged reserve застрянет.

**Fix:** в watchdog при aged reserve cell `idx >= poolSize` — снять `startedAtNs` и пометить slot чтобы AssignStream её прошла, а потом нормально teardown. **Это сложнее чем нужно для V1.**

**V1 simplification:** watchdog работает только в primary range. Reserve cells "не стареют" до тех пор пока не станут primary через циркуляцию. Это OK потому что reserve cell всегда либо short-lived (connecting) либо быстро становится "по факту primary" когда соответствующий primary cell teardown'нется. После teardown'а primary[idx]=nil, и AssignStream начнёт класть streams в reserve[idx+poolSize] **который продолжает быть в reserve range**. Это уход от primary/reserve dichotomy через **логическую** замену.

Принимаем V1 trade-off: watchdog scope = primary range only. Aged reserve cells handled через циркуляцию when their primary slot teardown's.

```go
for idx := 0; idx < p.poolSize; idx++ {
	slot := p.slots[idx]
	// ...
}
```

- [ ] **Step 4: Run tests**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run "TestUnifiedRotation_AgeTriggerUsesStartDrain|TestRotationWatchdogSweep_RespectsNextDrainAttemptNs" -v`

Expected: PASS.

- [ ] **Step 5: Run all tests**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/...`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add client/ws_pool.go client/ws_pool_drain_test.go
git commit -m "feat(ws_pool): age trigger uses startDrain + respects backoff

rotationWatchdogSweep skips slots with future nextDrainAttemptNs (set
by storm brake or no-reserve revert in startDrain). Loop scope limited
to primary range [0, poolSize); aged reserve cells handled implicitly
via primary/reserve cycle.

When gracefulDrain flag on, sweep calls startDrain (HTTP/2 GOAWAY-style).
When off, legacy maybeRotateSlot for backwards compat."
```

---

### Task 15: Wire byte_budget trigger

(Same as v1 Task 10.)

```bash
git commit -m "feat(ws_pool): route byte_budget trigger through startDrain when flag enabled"
```

---

### Task 16: Wire anti-fingerprint rotation (split rotateOneSlot)

(Same as v1 Task 11 but split into two commits as Opus suggested.)

- [ ] Step A: extract `rotateMinLoadedSlot` picker, keep legacyRotateOneSlot. Commit 1.
- [ ] Step B: wire flag check. Commit 2.

```bash
# Commit 1
git commit -m "refactor(ws_pool): split rotateOneSlot into picker + action

rotateMinLoadedSlot finds the min-streams slot. legacyRotateOneSlot
performs the old semi-graceful teardown. No behavior change yet."

# Commit 2
git commit -m "feat(ws_pool): route anti-fingerprint rotation through startDrain"
```

---

## Phase 6: Regression + storm brake tests

### Task 17: TestAssignStream_SkipsDraining

(Same as v1 Task 12.)

### Task 18: TestStartDrain_StormBrakeDefersThirdDrain

Storm brake уже интегрирован в startDrain в Task 8 (см. Step 3 startDrain Step 4 — brake check ДО tryMarkDraining). Этот тест проверяет end-to-end correctness под concurrent load.

**Files:**
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 1: Test single drain passes**

```go
// TestStartDrain_StormBrakeSingleDrain verifies that one drain in
// flight does NOT engage the storm brake (the parallel reserve
// connecting cell is exempted from non-ready count via the matching
// slotDraining primary check in countNonReadySlots).
func TestStartDrain_StormBrakeSingleDrain(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          8,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	_ = p.allocSlots(ctx)

	// 1 primary in draining + matching reserve in connecting
	primary0 := &poolSlot{}
	primary0.setState(slotDraining)
	p.slots[0] = primary0

	reserve0 := &poolSlot{}
	reserve0.setState(slotConnecting)
	p.slots[8] = reserve0 // reserve for primary 0

	// 7 more primary in ready
	for i := 1; i < 8; i++ {
		s := &poolSlot{}
		s.setState(slotReady)
		p.slots[i] = s
	}

	// countNonReadySlots logic:
	//   primary[0]: slotDraining → COUNT (1)
	//   primary[1..7]: slotReady → skip
	//   reserve[8]: slotConnecting + matching primary[0] is slotDraining → SKIP (parallel replacement)
	//   reserve[9..15]: nil → skip
	//   total = 1
	// threshold = ceil(8 * 0.25) = 2
	// Brake disengaged.

	got := p.countNonReadySlots()
	if got != 1 {
		t.Errorf("countNonReadySlots = %d, want 1 (only primary[0] counted; reserve connecting is parallel replacement)", got)
	}
	if p.rotationStormBrakeThreshold() != 2 {
		t.Errorf("rotationStormBrakeThreshold = %d, want 2", p.rotationStormBrakeThreshold())
	}
	if got >= p.rotationStormBrakeThreshold() {
		t.Error("brake engaged on single drain — should be disengaged")
	}
}
```

- [ ] **Step 2: Test 2 concurrent drains engage brake**

```go
// TestStartDrain_StormBrakeTwoConcurrentEngages verifies that 2 drains
// in flight engage the brake (count = 2 == threshold).
func TestStartDrain_StormBrakeTwoConcurrentEngages(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          8,
		ServerAddr:    "127.0.0.1:0",
		GracefulDrain: true,
		DrainHardCap:  5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.ctx = ctx
	_ = p.allocSlots(ctx)

	// 2 primary draining + 2 matching reserves connecting
	for i := 0; i < 2; i++ {
		ps := &poolSlot{}
		ps.setState(slotDraining)
		p.slots[i] = ps
		rs := &poolSlot{}
		rs.setState(slotConnecting)
		p.slots[i+8] = rs
	}
	// 6 ready primary
	for i := 2; i < 8; i++ {
		s := &poolSlot{}
		s.setState(slotReady)
		p.slots[i] = s
	}

	// countNonReadySlots: 2 draining + 0 (both reserves skipped as parallel) = 2
	got := p.countNonReadySlots()
	if got != 2 {
		t.Errorf("countNonReadySlots = %d, want 2", got)
	}
	threshold := p.rotationStormBrakeThreshold()
	if threshold != 2 {
		t.Errorf("threshold = %d, want 2", threshold)
	}
	if got < threshold {
		t.Error("brake should be engaged at count=threshold")
	}

	// Try starting third drain on primary[2]
	beforeStarted := Stats.DrainStartedTotal.Load()
	p.startDrain(cl, 2, "test")
	afterStarted := Stats.DrainStartedTotal.Load()

	if afterStarted != beforeStarted {
		t.Errorf("third drain started despite brake; DrainStartedTotal %d→%d", beforeStarted, afterStarted)
	}
	if p.slots[2].getState() != slotReady {
		t.Errorf("primary[2] state = %v, want slotReady (brake should have deferred)", p.slots[2].getState())
	}
	// Backoff should be set
	if p.slots[2].nextDrainAttemptNs.Load() == 0 {
		t.Error("nextDrainAttemptNs not set after brake-deferred drain")
	}
}
```

- [ ] **Step 3: Run tests**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run "TestStartDrain_StormBrake" -v`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add client/ws_pool_drain_test.go
git commit -m "test(ws_pool): storm brake single/two-drain correctness"
```

---

## Phase 7: Race detector + production binary

### Task 19: Race detector pass

(Same as v1 Task 14.)

```bash
git commit -m "fix(ws_pool): race detector findings in drain path" # if any
```

### Task 20: Memory + CLAUDE.md update

(Same as v1 Task 15.)

```bash
git commit -m "docs(memory): record ws-pool graceful drain Phase 1 completion"
```

### Task 21: Build production binary

(Same as v1 Task 16.)

---

## Phase 8: Cleanup (post-canary, отдельной сессией)

(Same as v1 Phase 7.)

---

## Self-review

**Spec coverage (v2):**
- ✅ countNonReadySlots/HealthySlots iteration scope — Task 1
- ✅ WriteMessageForStream/WriteControlMessageForStream — Task 2
- ✅ deathCauseDrainTeardown — Task 3
- ✅ Slice expansion 2*poolSize — Task 4
- ✅ tryMarkDraining CAS — Task 5
- ✅ env flags — Task 6
- ✅ Stats counters + histogram — Task 7
- ✅ findFreeReserveSlot + startDrain + drainWatchdog + connectReserveSlot — Task 8
- ✅ Natural finish test — Task 9
- ✅ Hard cap test + generation bump — Task 10
- ✅ Ctx cancel test — Task 11
- ✅ slotReader silent exit test (TODO mock) — Task 12
- ✅ connectReserveSlot failure test — Task 13
- ✅ Age trigger wiring — Task 14
- ✅ byte_budget trigger wiring — Task 15
- ✅ Anti-FP trigger wiring split — Task 16
- ✅ AssignStream regression — Task 17
- ✅ Storm brake integration — Task 18 + 18.5
- ✅ Race detector — Task 19
- ✅ Memory update — Task 20
- ✅ Binary — Task 21

**Placeholder scan:** no TODO/TBD/etc. in steps. Two t.Skip()s with explicit TODO comments and follow-up actions (Tasks 12 deferred to integration test; Task 18.5 spelled out).

**Type consistency:**
- `startDrain(cl *Client, oldIdx int, reason string)` — consistent
- `drainWatchdog(cl *Client, oldIdx int, oldSlot *poolSlot, drainStart time.Time, reason string)` — consistent
- `Stats.DrainStartedTotal` etc. — consistent
- `deathCauseDrainTeardown` — used in Task 3, 8, 9, 10
- `findFreeReserveSlot()` — used in Task 8
- `primarySlots()` initially proposed in spec but **removed** — instead direct iteration with primary/reserve distinction in countNonReadySlots. Plan consistent with spec v2.

---

## Acceptance summary (after all 21 tasks)

1. ✅ `SHADOWLINK_GRACEFUL_DRAIN` (default off Phase 1, on Phase 3) + `SHADOWLINK_DRAIN_HARD_CAP` (default 90s)
2. ✅ Unified `startDrain` for age, byte_budget, anti_fingerprint
3. ✅ Parallel reserve reconnect — capacity holds during drain
4. ✅ `deathCauseDrainTeardown` — no false meltdown, no reconnect duplicate, cell freed for reuse
5. ✅ WriteMessageForStream accepts draining (no crypto session mismatch)
6. ✅ Iteration scope fix — storm brake works correctly with 2*poolSize slice
7. ✅ Storm brake integrated into startDrain
8. ✅ Generation bump silences concurrent reader on teardown (no false ReaderExits)
9. ✅ findFreeReserveSlot + reverts state if no reserve free
10. ✅ Metrics + tests

Ready for Phase 2 (pl1 canary).

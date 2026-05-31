# Bug #8 Per-Stream Flow Control — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Устранить Bug #8 (потеря байт TCP при быстрой закачке из-за `RouteToStream` drop) внедрением per-stream flow control (HTTP/2/yamux-стиль credit): сервер не шлёт больше окна неподтверждённых байт на стрим, дропов нет by design, без head-of-line blocking.

**Architecture:** Новый wire-фрейм `FlagWindowUpdate`. Capability согласуется in-band поверх v1-ключей (маркер в зашифрованном payload первого keepalive + синхронный server-ack). Клиент: downlink-goroutine только `atomic.Add` потреблённых байт; отдельный per-client credit-sender неблокирующе шлёт WINDOW_UPDATE при 50% окна. Сервер: per-stream credit-gate перед `tc.Read` в WS-relay; `handleWindowUpdate` пополняет credit. Всё под флагом — старые клиенты/сервер работают как сейчас.

**Tech Stack:** Go, `database/sql`-free (in-process), gorilla/websocket, AES-256-GCM (core), atomic-метрики (hand-rolled), TDD (`go test`), race на CI/Linux.

**Спека:** `shadowlink/docs/superpowers/specs/2026-05-30-bug8-flow-control-design.md` (v4 READY, 3 опус-ревью).

**Ветка:** работать в текущей рабочей ветке (как Bug#6). НЕ коммитить в main.

**ВАЖНО — порядок и совместимость:**
- Всё под `flowControlEnabled`, по умолчанию согласование работает только если ОБЕ стороны умеют. Старый сервер не шлёт ack → клиент за 500мс решает off. Нулевая регрессия для не-flow пути.
- Рекомендованный rollout: сервер pl1 деплоится ПЕРВЫМ, клиенты с маркером — после.
- Trace-код Bug#8 (tcp.go/inprocess.go/memconn_halfclose_test.go, бинарь 10:07) при реализации фикса убрать — отдельная финальная задача.
- CRLF преэкзистентен в репо: НЕ запускать `gofmt -w` на целых файлах. Только проверять `go build ./...` и `go test`.
- Windows-хост без gcc: `-race` гонять на CI/Linux. Локально — обычный `go test`.

---

## Файловая структура

| Файл | Ответственность |
|---|---|
| `core/chunk.go` | `FlagWindowUpdate=0x0A`, `NewWindowUpdateChunk`, `ParseWindowUpdate` |
| `core/flowctl.go` (новый) | Константы маркера `"FLOWCTL"`, `BuildFlowCtlMarker`/`ParseFlowCtlMarker` (payload негоциации) |
| `core/wsasyncwriter.go` | `TryEnqueueControl` (неблокирующий) |
| `client/stream_flow.go` (новый) | `streamFlowState`, `OnStreamConsumed`, per-client credit-sender goroutine + watchdog + порог-jitter |
| `client/client.go` | `streamFlow` map в Register/Unregister; `flowControlEnabled`; sender lifecycle; RouteToStream-детектор |
| `client/ws_transport.go` | синхронное чтение FLOWCTL-ack в `UpgradeToWS`; маркер в первом keepalive; `TryWriteControlMessage` |
| `client/ws_pool.go` | `poolSlot.flowControlEnabled`/`flowWindow`; `TryWriteControlMessageForStream` |
| `client/split_transport.go` | интерфейс `TryControlPoolAware` + helper `TryStreamWriteControl` |
| `client/stats.go` | новые метрики |
| `proxy/socks5/tcp.go` | `OnStreamConsumed` после `conn.Write` |
| `server/stream_credit.go` (новый) | `streamCredit`: waitForCredit/consume/add/close |
| `server/websocket.go` | negotiation (ack), `credits` map, credit-gate, `case FlagWindowUpdate`+default, teardown |
| `server/metrics.go` | новые серверные метрики |
| `shadowlink/docs/protocols/flow-control-v2.md` (новый) | wire-спека |

**Дефолты:** окно 1 MiB, `negotiationAckTimeout=500ms`, порог 40-60% jitter, watchdog T=200ms, кламп 2×window.

---

## ФАЗА 1 — core wire (фрейм + маркер)

### Task 1: FlagWindowUpdate + конструктор/парсер

**Files:**
- Modify: `core/chunk.go` (флаги ~13-23; добавить конструктор/парсер рядом с `NewUDPDataChunk`)
- Test: `core/chunk_test.go`

- [ ] **Step 1: Failing test** — добавить в `core/chunk_test.go`:

```go
func TestWindowUpdateChunk_RoundTrip(t *testing.T) {
	c := NewWindowUpdateChunk(0x11223344, 7, 0xABCD, 0x0010FFFF)
	if c.Flags != FlagWindowUpdate {
		t.Fatalf("Flags = %#x, want %#x", c.Flags, FlagWindowUpdate)
	}
	sid, delta, err := ParseWindowUpdate(c.Payload)
	if err != nil {
		t.Fatalf("ParseWindowUpdate: %v", err)
	}
	if sid != 0xABCD || delta != 0x0010FFFF {
		t.Fatalf("got sid=%#x delta=%#x, want 0xABCD/0x0010FFFF", sid, delta)
	}
}

func TestParseWindowUpdate_TooShort(t *testing.T) {
	if _, _, err := ParseWindowUpdate([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("expected error for <6-byte payload, got nil")
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./core/ -run TestWindowUpdate -v` (и `TestParseWindowUpdate`). Expected: compile error (undefined: NewWindowUpdateChunk / FlagWindowUpdate / ParseWindowUpdate).

- [ ] **Step 3: Implement** — в `core/chunk.go`:

Добавить флаг (после `FlagStreamOpen byte = 0x09`):
```go
	FlagWindowUpdate byte = 0x0A // payload = [StreamID(2)] + [delta(4)] per-stream flow-control credit
```

Добавить функции (рядом с `NewUDPDataChunk`):
```go
// NewWindowUpdateChunk creates a per-stream flow-control credit update.
// Payload format: [StreamID(2 BE)] + [delta(4 BE)]. delta is the additive
// number of bytes the receiver has consumed since its last update (HTTP/2
// WINDOW_UPDATE semantics — always positive, never absolute).
func NewWindowUpdateChunk(sessID, seq uint32, streamID uint16, delta uint32) *Chunk {
	p := make([]byte, 6)
	binary.BigEndian.PutUint16(p[0:2], streamID)
	binary.BigEndian.PutUint32(p[2:6], delta)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagWindowUpdate, Payload: p}
}

// ParseWindowUpdate extracts stream ID and credit delta from a window-update
// payload. Returns an error (never panics) on a payload shorter than 6 bytes.
func ParseWindowUpdate(payload []byte) (streamID uint16, delta uint32, err error) {
	if len(payload) < 6 {
		return 0, 0, fmt.Errorf("window update payload too short: %d < 6", len(payload))
	}
	streamID = binary.BigEndian.Uint16(payload[0:2])
	delta = binary.BigEndian.Uint32(payload[2:6])
	return streamID, delta, nil
}
```

- [ ] **Step 4: Run, verify PASS** — `go test ./core/ -run 'TestWindowUpdate|TestParseWindowUpdate' -v`. Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add core/chunk.go core/chunk_test.go
git commit -m "feat(shadowlink): add FlagWindowUpdate wire frame (Bug #8 flow control)"
```

---

### Task 2: FLOWCTL capability-маркер (negotiation payload)

**Files:**
- Create: `core/flowctl.go`
- Test: `core/flowctl_test.go`

- [ ] **Step 1: Failing test** — `core/flowctl_test.go`:

```go
package core

import "testing"

func TestFlowCtlMarker_RoundTrip(t *testing.T) {
	p := BuildFlowCtlMarker(1 << 20) // 1 MiB
	win, ok := ParseFlowCtlMarker(p)
	if !ok {
		t.Fatal("ParseFlowCtlMarker: not recognized")
	}
	if win != 1<<20 {
		t.Fatalf("window = %d, want %d", win, 1<<20)
	}
}

func TestParseFlowCtlMarker_Rejects(t *testing.T) {
	if _, ok := ParseFlowCtlMarker(nil); ok {
		t.Fatal("nil payload should not parse as marker")
	}
	if _, ok := ParseFlowCtlMarker([]byte("FLOWCT")); ok {
		t.Fatal("short payload should not parse")
	}
	if _, ok := ParseFlowCtlMarker([]byte("XXXXXXX\x00\x00\x00\x01")); ok {
		t.Fatal("wrong magic should not parse")
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./core/ -run TestFlowCtl -v`. Expected: undefined symbols.

- [ ] **Step 3: Implement** — `core/flowctl.go`:

```go
package core

import "encoding/binary"

// flowctl.go — in-band capability negotiation marker for per-stream flow
// control (Bug #8). The marker rides inside the ENCRYPTED Chunk.Payload of the
// first keepalive (client → server) and the FlagAck reply (server → client),
// so it never appears in cleartext and adds no DPI signal. Flow control is an
// optional feature layered over the v1 session — NOT a new crypto version, so
// DeriveSessionKeys is untouched (no downgrade-via-keys risk).

// flowCtlMagic prefixes a window-advertisement payload. Layout:
//   ["FLOWCTL"(7)] + [window(4 BE)]  = 11 bytes
var flowCtlMagic = []byte("FLOWCTL")

const flowCtlMarkerLen = 7 + 4

// BuildFlowCtlMarker builds the 11-byte capability+window advertisement that
// goes inside the encrypted keepalive/ack chunk payload.
func BuildFlowCtlMarker(window uint32) []byte {
	p := make([]byte, flowCtlMarkerLen)
	copy(p[:7], flowCtlMagic)
	binary.BigEndian.PutUint32(p[7:11], window)
	return p
}

// ParseFlowCtlMarker reports whether payload begins with the FLOWCTL marker and
// returns the advertised window. ok=false for any non-marker payload (nil,
// short, or wrong magic) — callers treat that as "peer does not support flow
// control".
func ParseFlowCtlMarker(payload []byte) (window uint32, ok bool) {
	if len(payload) < flowCtlMarkerLen {
		return 0, false
	}
	for i := 0; i < 7; i++ {
		if payload[i] != flowCtlMagic[i] {
			return 0, false
		}
	}
	return binary.BigEndian.Uint32(payload[7:11]), true
}
```

- [ ] **Step 4: Run, verify PASS** — `go test ./core/ -run TestFlowCtl -v`. Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add core/flowctl.go core/flowctl_test.go
git commit -m "feat(shadowlink): add FLOWCTL capability marker for flow-control negotiation"
```

---

### Task 3: TryEnqueueControl (неблокирующий control write)

**Files:**
- Modify: `core/wsasyncwriter.go` (после `EnqueueControl` ~231)
- Test: `core/wsasyncwriter_test.go` (создать если нет, иначе добавить)

- [ ] **Step 1: Failing test** — добавить в `core/wsasyncwriter_test.go`:

```go
func TestTryEnqueueControl_NonBlockingWhenFull(t *testing.T) {
	// Writer with NO Run() goroutine draining → control fills then Try fails.
	w := NewWSAsyncWriter(nopWSConn{}, 1)
	// control cap is fixed 64. Fill it without draining.
	filled := 0
	for i := 0; i < 64; i++ {
		if !w.TryEnqueueControl(2 /*BinaryMessage*/, []byte("x")) {
			break
		}
		filled++
	}
	if filled == 0 {
		t.Fatal("expected at least some control frames to enqueue")
	}
	// Next Try must NOT block and must return false (channel full).
	done := make(chan bool, 1)
	go func() { done <- w.TryEnqueueControl(2, []byte("y")) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("TryEnqueueControl returned true on full channel")
		}
	case <-time.After(time.Second):
		t.Fatal("TryEnqueueControl BLOCKED on full channel (must be non-blocking)")
	}
}
```

Если `nopWSConn` ещё нет в тестах пакета — добавить минимальную заглушку:
```go
type nopWSConn struct{}

func (nopWSConn) WriteMessage(int, []byte) error                    { return nil }
func (nopWSConn) WriteControl(int, []byte, time.Time) error         { return nil }
func (nopWSConn) Close() error                                      { return nil }
func (nopWSConn) SetWriteDeadline(time.Time) error                  { return nil }
```
(Сверить с реальным интерфейсом `WSConnWriter` в `core/wsasyncwriter.go` — реализовать ровно его методы. Если интерфейс другой — подогнать заглушку под него.)

- [ ] **Step 2: Run, verify FAIL** — `go test ./core/ -run TestTryEnqueueControl -v`. Expected: undefined: TryEnqueueControl.

- [ ] **Step 3: Implement** — в `core/wsasyncwriter.go` после `EnqueueControl`:

```go
// TryEnqueueControl is the non-blocking variant of EnqueueControl: it enqueues
// a control frame if there is room and returns true, or returns false
// immediately if the control channel is full or the writer is closed. Used by
// the flow-control credit sender (Bug #8): a dropped WINDOW_UPDATE is harmless
// because the next one carries the accumulated (additive) delta, so the sender
// must NEVER block on a congested control channel (that would re-introduce the
// B2 uplink deadlock).
func (w *WSAsyncWriter) TryEnqueueControl(msgType int, data []byte) bool {
	select {
	case <-w.done:
		return false
	default:
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case w.control <- wsOutboundMsg{msgType: msgType, data: cp}:
		return true
	default:
		return false
	}
}
```

- [ ] **Step 4: Run, verify PASS** — `go test ./core/ -run TestTryEnqueueControl -v`. Expected: PASS. Также `go test ./core/` (весь пакет зелёный).

- [ ] **Step 5: Commit**
```bash
git add core/wsasyncwriter.go core/wsasyncwriter_test.go
git commit -m "feat(shadowlink): add non-blocking TryEnqueueControl (Bug #8 credit sender)"
```

---

## ФАЗА 2 — клиентская транспортная обвязка (неблокирующая отправка по стриму)

### Task 4: TryWriteControlMessage на WebSocketTransport + TryWriteControlMessageForStream на пуле

**Files:**
- Modify: `client/ws_transport.go` (рядом с существующим `WriteControlMessage`)
- Modify: `client/ws_pool.go` (рядом с `WriteControlMessageForStream` ~2383)
- Modify: `client/split_transport.go` (интерфейс + helper, ~59-93)
- Test: `client/stream_flow_test.go` (создать)

- [ ] **Step 1: Failing test** — `client/stream_flow_test.go`:

```go
package client

import "testing"

// fakeTryControl implements TryControlPoolAware for the helper test.
type fakeTryControl struct {
	tried   bool
	allowed bool
}

func (f *fakeTryControl) TryWriteControlMessageForStream(streamID uint16, data []byte) bool {
	f.tried = true
	return f.allowed
}

func TestTryStreamWriteControl_UsesPoolPath(t *testing.T) {
	f := &fakeTryControl{allowed: true}
	if !TryStreamWriteControl(f, 5, []byte("x")) {
		t.Fatal("expected true when pool path accepts")
	}
	if !f.tried {
		t.Fatal("pool TryWriteControlMessageForStream not called")
	}
}

func TestTryStreamWriteControl_FalseWhenNotSupported(t *testing.T) {
	// A transport that is NOT TryControlPoolAware → helper returns false
	// (cannot deliver credit non-blockingly; caller keeps the delta).
	var notSupported StreamTransport = &nopStreamTransport{}
	if TryStreamWriteControl(notSupported, 1, []byte("x")) {
		t.Fatal("expected false for transport without TryControlPoolAware")
	}
}
```

Минимальная заглушка `nopStreamTransport` (если ещё нет в тестах пакета) — реализует `StreamTransport`. Сверить методы интерфейса в `split_transport.go:23-34` и реализовать как no-op, методы возвращают `nil`/`nil,nil`.

- [ ] **Step 2: Run, verify FAIL** — `go test ./client/ -run TestTryStreamWriteControl -v`. Expected: undefined: TryControlPoolAware / TryStreamWriteControl.

- [ ] **Step 3: Implement**

В `client/split_transport.go` (после `ControlPoolAware` ~62):
```go
// TryControlPoolAware extends ControlPoolAware with a non-blocking priority
// write per stream. Used by the flow-control credit sender (Bug #8): a credit
// frame that can't be enqueued right now is simply retried on the next tick
// (the delta is additive), so the sender must never block.
type TryControlPoolAware interface {
	TryWriteControlMessageForStream(streamID uint16, data []byte) bool
}

// TryStreamWriteControl sends a control frame to the stream's slot without
// blocking. Returns true if enqueued, false if the channel was full / the
// transport doesn't support non-blocking control writes (caller keeps the
// pending delta to retry).
func TryStreamWriteControl(wst StreamTransport, streamID uint16, data []byte) bool {
	if tpa, ok := wst.(TryControlPoolAware); ok {
		return tpa.TryWriteControlMessageForStream(streamID, data)
	}
	return false
}
```

В `client/ws_transport.go` — добавить метод (рядом с `WriteControlMessage`; найти его и положить ниже):
```go
// TryWriteControlMessage enqueues a control frame without blocking. Returns
// false if the async writer is absent or its control channel is full.
func (t *WebSocketTransport) TryWriteControlMessage(data []byte) bool {
	t.mu.Lock()
	w := t.asyncWriter
	t.mu.Unlock()
	if w == nil {
		return false
	}
	return w.TryEnqueueControl(websocket.BinaryMessage, data)
}
```

В `client/ws_pool.go` (после `WriteControlMessageForStream` ~2402):
```go
// TryWriteControlMessageForStream sends a control frame to the stream's slot
// WITHOUT blocking (Bug #8 credit sender). Returns true if enqueued. Returns
// false if the stream has no ready/draining slot or the slot's control channel
// is full — the caller keeps the accumulated delta for the next tick.
func (p *WSPoolTransport) TryWriteControlMessageForStream(streamID uint16, data []byte) bool {
	v, ok := p.streamMap.Load(streamID)
	if !ok {
		return false
	}
	e, ok := v.(*streamEntry)
	if !ok {
		return false
	}
	idx := e.slotIdx
	if idx >= len(p.slots) {
		return false
	}
	slot := p.slots[idx]
	if slot == nil || slot.transport == nil {
		return false
	}
	if st := slot.getState(); st != slotReady && st != slotDraining {
		return false
	}
	tw, ok := slot.transport.(interface{ TryWriteControlMessage(data []byte) bool })
	if !ok {
		return false
	}
	if tw.TryWriteControlMessage(data) {
		e.lastWriteNs.Store(time.Now().UnixNano())
		return true
	}
	return false
}
```

- [ ] **Step 4: Run, verify PASS** — `go test ./client/ -run TestTryStreamWriteControl -v`; затем `go build ./...`. Expected: PASS + build OK.

- [ ] **Step 5: Commit**
```bash
git add client/split_transport.go client/ws_transport.go client/ws_pool.go client/stream_flow_test.go
git commit -m "feat(shadowlink): non-blocking per-stream control write path (Bug #8)"
```

---

## ФАЗА 3 — клиентское flow-state + credit-sender

### Task 5: streamFlowState + OnStreamConsumed (Add-only)

**Files:**
- Create: `client/stream_flow.go`
- Modify: `client/client.go` (поля Client рядом со `streamChans` ~137-146; Register/Unregister ~686-707)
- Test: `client/stream_flow_test.go`

- [ ] **Step 1: Failing test** — добавить в `client/stream_flow_test.go`:

```go
func TestOnStreamConsumed_AccumulatesPendingDelta(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 1 << 20
	c.streamFlow = map[uint16]*streamFlowState{}
	c.streamFlow[7] = &streamFlowState{window: 1 << 20}

	c.OnStreamConsumed(7, 1000)
	c.OnStreamConsumed(7, 2000)

	if got := c.streamFlow[7].pendingDelta.Load(); got != 3000 {
		t.Fatalf("pendingDelta = %d, want 3000", got)
	}
}

func TestOnStreamConsumed_NoopWhenDisabled(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = false
	c.streamFlow = map[uint16]*streamFlowState{7: {window: 1 << 20}}
	c.OnStreamConsumed(7, 5000)
	if got := c.streamFlow[7].pendingDelta.Load(); got != 0 {
		t.Fatalf("pendingDelta = %d, want 0 (disabled)", got)
	}
}

func TestOnStreamConsumed_UnknownStreamSafe(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = true
	c.streamFlow = map[uint16]*streamFlowState{}
	c.OnStreamConsumed(999, 100) // no panic, no-op
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./client/ -run TestOnStreamConsumed -v`. Expected: undefined: streamFlowState / fields / OnStreamConsumed.

- [ ] **Step 3: Implement**

В `client/client.go` — добавить поля в struct `Client` (рядом со `streamOverflow` ~145):
```go
	// Per-stream flow control (Bug #8). Guarded by streamMu (same lifecycle as
	// streamChans). flowControlEnabled is set true only when the slot this
	// client's streams ride negotiated FLOWCTL with the server.
	streamFlow         map[uint16]*streamFlowState
	flowControlEnabled bool
	flowWindow         uint64
```

В `RegisterStream` (после `c.streamChans[streamID] = ch` ~696, перед `return`):
```go
	if c.flowControlEnabled {
		if c.streamFlow == nil {
			c.streamFlow = make(map[uint16]*streamFlowState)
		}
		c.streamFlow[streamID] = &streamFlowState{window: c.flowWindow}
	}
```

В `UnregisterStream` (после `delete(c.streamChans, streamID)` ~704, под тем же `streamMu`):
```go
	delete(c.streamFlow, streamID)
```

Создать `client/stream_flow.go`:
```go
package client

import "sync/atomic"

// stream_flow.go — client-side per-stream flow control (Bug #8). The downlink
// relay goroutine calls OnStreamConsumed after each successful conn.Write into
// the app (memConn) — it ONLY does an atomic add and NEVER sends or blocks
// (invariant I3). A separate per-client credit sender (see creditSender) drains
// pendingDelta into WINDOW_UPDATE frames non-blockingly.

// streamFlowState accumulates bytes the app has consumed but not yet credited
// back to the server via WINDOW_UPDATE.
type streamFlowState struct {
	pendingDelta atomic.Uint64 // bytes consumed since last WINDOW_UPDATE sent
	window       uint64        // negotiated effective window (read-only)
	lastSentNs   atomic.Int64  // unix-nano of last successful WINDOW_UPDATE (watchdog)
}

// OnStreamConsumed records that n bytes were delivered to the app for streamID.
// Add-only: never blocks, never sends (I3). No-op if flow control is disabled
// or the stream has no flow state.
func (c *Client) OnStreamConsumed(streamID uint16, n int) {
	if !c.flowControlEnabled || n <= 0 {
		return
	}
	c.streamMu.Lock()
	st := c.streamFlow[streamID]
	c.streamMu.Unlock()
	if st == nil {
		return
	}
	st.pendingDelta.Add(uint64(n))
}
```

- [ ] **Step 4: Run, verify PASS** — `go test ./client/ -run TestOnStreamConsumed -v`; `go build ./...`. Expected: PASS + build OK.

- [ ] **Step 5: Commit**
```bash
git add client/stream_flow.go client/client.go client/stream_flow_test.go
git commit -m "feat(shadowlink): client streamFlowState + OnStreamConsumed (Bug #8, Add-only)"
```

---

### Task 6: per-client credit-sender (порог-jitter + watchdog + Swap-обнуление)

**Files:**
- Modify: `client/stream_flow.go`
- Modify: `client/client.go` (Session field для streamID-сессии — credit-sender строит WINDOW_UPDATE chunk; lifecycle старт/стоп)
- Modify: `client/stats.go` (метрики)
- Test: `client/stream_flow_test.go`

- [ ] **Step 1: Failing test** — добавить:

```go
func TestCreditSender_SendsAtThreshold(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 1000
	c.streamFlow = map[uint16]*streamFlowState{7: {window: 1000}}
	c.streamFlow[7].pendingDelta.Store(600) // > 50% of 1000

	sent := map[uint16]uint32{}
	// inject a send fn that records instead of touching the network
	c.flowSendForTest = func(streamID uint16, delta uint32) bool {
		sent[streamID] = delta
		return true
	}

	c.creditSenderTick(0.5) // fixed threshold ratio for determinism
	if sent[7] != 600 {
		t.Fatalf("sent delta = %d, want 600", sent[7])
	}
	if got := c.streamFlow[7].pendingDelta.Load(); got != 0 {
		t.Fatalf("pendingDelta after send = %d, want 0", got)
	}
}

func TestCreditSender_BelowThresholdNoSend(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 1000
	c.streamFlow = map[uint16]*streamFlowState{7: {window: 1000}}
	c.streamFlow[7].pendingDelta.Store(400) // < 50%

	called := false
	c.flowSendForTest = func(uint16, uint32) bool { called = true; return true }
	c.creditSenderTick(0.5)
	if called {
		t.Fatal("should not send below threshold")
	}
}

func TestCreditSender_KeepsDeltaOnSendFailure(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 1000
	c.streamFlow = map[uint16]*streamFlowState{7: {window: 1000}}
	c.streamFlow[7].pendingDelta.Store(600)

	c.flowSendForTest = func(uint16, uint32) bool { return false } // send failed
	c.creditSenderTick(0.5)
	if got := c.streamFlow[7].pendingDelta.Load(); got != 600 {
		t.Fatalf("pendingDelta after failed send = %d, want 600 (kept)", got)
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./client/ -run TestCreditSender -v`. Expected: undefined: creditSenderTick / flowSendForTest.

- [ ] **Step 3: Implement**

В `client/stats.go` — добавить в struct `statsRegistry` (рядом со `StreamBufferOverflowsTotal` ~272):
```go
	FlowWindowUpdatesSent     atomic.Uint64
	FlowWindowUpdateDropped   atomic.Uint64 // TryEnqueueControl full → delta kept
	FlowNegotiationTimeout    atomic.Uint64 // ack not received within negotiationAckTimeout
```
И в текстовый экспортёр (рядом со `shadowlink_stream_buffer_overflows_total` ~657):
```go
	fmt.Fprintf(w, "shadowlink_flow_window_updates_sent_total %d\n", Stats.FlowWindowUpdatesSent.Load())
	fmt.Fprintf(w, "shadowlink_flow_window_update_dropped_total %d\n", Stats.FlowWindowUpdateDropped.Load())
	fmt.Fprintf(w, "shadowlink_flow_negotiation_timeout_total %d\n", Stats.FlowNegotiationTimeout.Load())
```

В `client/client.go` — добавить поля (рядом с flow-полями из Task 5):
```go
	// flowSendForTest, when non-nil, replaces the real WINDOW_UPDATE send in
	// creditSenderTick (unit-test seam). Production path is nil.
	flowSendForTest func(streamID uint16, delta uint32) bool
	// flowTransport is the StreamTransport credit updates ride (set when the
	// pool/transport is wired; the sender resolves the stream's slot via it).
	flowTransport StreamTransport
	flowStop      chan struct{}
```

В `client/stream_flow.go` — credit-sender:
```go
import (
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

const (
	creditSenderInterval = 8 * time.Millisecond // tick cadence (cheap)
	creditWatchdogNs     = int64(200 * time.Millisecond)
)

// startCreditSender launches the single per-client credit-sender goroutine.
// It iterates Client.streamFlow each tick and emits WINDOW_UPDATE for any
// stream whose pendingDelta crossed the (jittered 40-60%) threshold, or whose
// tail has been waiting longer than the watchdog window. Idempotent guard via
// flowStop.
func (c *Client) startCreditSender() {
	if !c.flowControlEnabled {
		return
	}
	c.streamMu.Lock()
	if c.flowStop != nil {
		c.streamMu.Unlock()
		return
	}
	c.flowStop = make(chan struct{})
	stop := c.flowStop
	c.streamMu.Unlock()

	go func() {
		t := time.NewTicker(creditSenderInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				// jitter threshold ratio 40-60% to break uplink periodicity (§16)
				ratio := 0.4 + rand.Float64()*0.2
				c.creditSenderTick(ratio)
			}
		}
	}()
}

func (c *Client) stopCreditSender() {
	c.streamMu.Lock()
	if c.flowStop != nil {
		close(c.flowStop)
		c.flowStop = nil
	}
	c.streamMu.Unlock()
}

// creditSenderTick scans all streams once. thresholdRatio is the fraction of
// the window that must accumulate before a WINDOW_UPDATE is emitted (the
// watchdog overrides it for stale tails). Pure given flowSendForTest.
func (c *Client) creditSenderTick(thresholdRatio float64) {
	c.streamMu.Lock()
	// snapshot to avoid holding the lock across sends
	type item struct {
		id uint16
		st *streamFlowState
	}
	items := make([]item, 0, len(c.streamFlow))
	for id, st := range c.streamFlow {
		items = append(items, item{id, st})
	}
	c.streamMu.Unlock()

	nowNs := time.Now().UnixNano()
	for _, it := range items {
		d := it.st.pendingDelta.Load()
		if d == 0 {
			continue
		}
		threshold := uint64(float64(it.st.window) * thresholdRatio)
		stale := nowNs-it.st.lastSentNs.Load() >= creditWatchdogNs
		if d < threshold && !stale {
			continue
		}
		// Take the current delta atomically; only zero it if the send succeeds.
		if it.st.pendingDelta.CompareAndSwap(d, 0) {
			if c.sendWindowUpdate(it.id, uint32(d)) {
				it.st.lastSentNs.Store(nowNs)
				Stats.FlowWindowUpdatesSent.Add(1)
			} else {
				// send failed → give the delta back (additive, race-safe)
				it.st.pendingDelta.Add(d)
				Stats.FlowWindowUpdateDropped.Add(1)
			}
		}
		// CAS failure means OnStreamConsumed added concurrently — next tick handles it.
	}
}

// sendWindowUpdate builds and non-blockingly sends a WINDOW_UPDATE for streamID.
// Returns true if enqueued. Uses the test seam when set.
func (c *Client) sendWindowUpdate(streamID uint16, delta uint32) bool {
	if c.flowSendForTest != nil {
		return c.flowSendForTest(streamID, delta)
	}
	if c.flowTransport == nil {
		return false
	}
	session := StreamSession(c.flowTransport, c, streamID)
	if session == nil {
		return false
	}
	chunk := core.NewWindowUpdateChunk(session.ID, session.NextSeqNum(), streamID, delta)
	enc, err := session.EncryptChunk(chunk)
	if err != nil {
		return false
	}
	return TryStreamWriteControl(c.flowTransport, streamID, enc)
}
```

- [ ] **Step 4: Run, verify PASS** — `go test ./client/ -run TestCreditSender -v`; `go build ./...`. Expected: PASS + build OK.

- [ ] **Step 5: Commit**
```bash
git add client/stream_flow.go client/client.go client/stats.go client/stream_flow_test.go
git commit -m "feat(shadowlink): per-client credit sender with jitter+watchdog (Bug #8)"
```

---

### Task 7: вызов OnStreamConsumed из downlink-goroutine

**Files:**
- Modify: `proxy/socks5/tcp.go` (downlink goroutine, после `conn.Write(data)` ~778)
- Test: проверяется в integration (Task 12); здесь — компиляция + grep.

- [ ] **Step 1: Implement** — в `tcp.go` в downlink-goroutine `tunnelTCPStream`, СРАЗУ после успешного `conn.Write(data)` (там где сейчас `client.Stats.DownlinkBytes.Add(int64(len(data)))` ~773 — добавить ПОСЛЕ успешной записи, ~779):

Найти блок:
```go
				if _, err := conn.Write(data); err != nil {
					slog.Warn("downlink write error", ...)
					...
				}
```
Сразу ПЕРЕД ним (после `lastDownlinkNs.Store(...)` / `DownlinkBytes.Add`) на пути УСПЕШНОЙ записи добавить вызов. Точнее: после `conn.Write(data)` без ошибки — на следующей строке внутри блока успеха. Поскольку текущий код пишет `conn.Write(data)` в `if`, добавить в ветку успеха:

```go
				n, werr := conn.Write(data)
				if werr != nil {
					slog.Warn("downlink write error", "dest", destAddr, "stream", streamID, "err", werr,
						"connectConfirmed", connectConfirmed, "downlinkBytes", total, "downlinkChunks", chunks,
						"streamAgeMs", time.Since(relayStart).Milliseconds())
					// ... (существующий drain-loop без изменений)
				}
				// Bug #8: credit the consumed bytes back so the server may send more.
				cl.OnStreamConsumed(streamID, n)
```

ВНИМАНИЕ: текущий код — `if _, err := conn.Write(data); err != nil`. Переписать на именованные `n, werr` чтобы получить число записанных байт; в ветке ошибки сохранить весь существующий drain-loop дословно; вызов `OnStreamConsumed` — ТОЛЬКО на пути успеха. То же для второй `conn.Write(more)` в draining-цикле НЕ требуется (тот цикл — fallback при мёртвом consumer'е; там данные не доходят до приложения, credit не начисляем). Но в ОСНОВНОМ downlink-пути (tcp.go:778 и draining-вложенный успешный путь ~162 в HandleTCPConnect — НЕ трогаем poll-mode) добавить только в `tunnelTCPStream`.

- [ ] **Step 2: Run, verify build** — `go build ./...`. Expected: OK. `go vet ./proxy/...`.

- [ ] **Step 3: grep-проверка** — `grep -n "OnStreamConsumed" proxy/socks5/tcp.go` → ровно 1 вызов, в `tunnelTCPStream` после успешного `conn.Write`.

- [ ] **Step 4: Commit**
```bash
git add proxy/socks5/tcp.go
git commit -m "feat(shadowlink): credit consumed downlink bytes from tunnelTCPStream (Bug #8)"
```

---

## ФАЗА 4 — клиентская негоциация (маркер + синхронный ack)

### Task 8: poolSlot flow-поля + маркер в первом keepalive + синхронное чтение ack

**Files:**
- Modify: `client/ws_pool.go` (`poolSlot` struct ~222; connectSlot после UpgradeToWS)
- Modify: `client/ws_transport.go` (`buildFirstFramePayload` ~684; `UpgradeToWS` между ~519 и ~525)
- Test: `client/ws_transport_test.go` (или новый) — юнит на парс ack

- [ ] **Step 1: Failing test** — добавить в `client/stream_flow_test.go` (юнит на хелпер парсинга ack):

```go
func TestParseFlowAck_Recognizes(t *testing.T) {
	// server ack payload = FLOWCTL marker with effectiveWindow
	win, ok := parseFlowAckPayload(core.BuildFlowCtlMarker(1 << 20))
	if !ok || win != 1<<20 {
		t.Fatalf("parseFlowAckPayload = (%d,%v), want (1MiB,true)", win, ok)
	}
	if _, ok := parseFlowAckPayload(nil); ok {
		t.Fatal("nil ack must not parse as flow ack")
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./client/ -run TestParseFlowAck -v`. Expected: undefined: parseFlowAckPayload.

- [ ] **Step 3: Implement**

В `client/ws_pool.go` `poolSlot` struct (рядом с `byteBudget` ~300):
```go
	// Bug #8 flow control, negotiated per-slot (each slot = own core.Session).
	flowControlEnabled bool
	flowWindow         uint64
```

В `client/ws_transport.go` — `buildFirstFramePayload`: добавить маркер в payload keepalive КОГДА клиент хочет flow control. Сигнатуру расширить флагом:
```go
func (t *WebSocketTransport) buildFirstFramePayload(token []byte, session *core.Session, flowWindow uint32) ([]byte, error) {
	keepalive := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     core.FlagKeepalive,
	}
	if flowWindow > 0 {
		keepalive.Payload = core.BuildFlowCtlMarker(flowWindow) // inside AES-GCM (NH2)
	}
	encrypted, err := session.EncryptChunk(keepalive)
	if err != nil {
		return nil, err
	}
	return browser.BuildDataPayload(token, encrypted), nil
}
```
(Обновить ВСЕ вызовы `buildFirstFramePayload` — передавать 0, если flow не запрошен, иначе desired window. `UpgradeToWS` должен знать desired window — добавить поле `t.flowDesiredWindow uint32` на `WebSocketTransport`, выставляемое пулом перед upgrade. Если 0 — маркер не шлётся, ack не читается.)

В `client/ws_transport.go` — добавить хелпер парсинга ack + поле:
```go
// parseFlowAckPayload reports whether a decrypted FlagAck chunk payload carries
// the server's FLOWCTL confirmation and returns the effective window.
func parseFlowAckPayload(payload []byte) (window uint32, ok bool) {
	return core.ParseFlowCtlMarker(payload)
}
```

В `UpgradeToWS` — между отправкой первого фрейма (после ~519 success) и созданием `WSAsyncWriter` (~525), вставить синхронное чтение ТОЛЬКО если `t.flowDesiredWindow > 0`:
```go
	// Bug #8 §4.5: synchronously read the server's FLOWCTL-ack BEFORE starting
	// the async writer / slot reader. Only when we advertised a window — else
	// the wire path is unchanged. The slot reader starts only after UpgradeToWS
	// returns (connectSlot sets slotReady afterwards), so it won't race this read.
	if t.flowDesiredWindow > 0 {
		conn.SetReadDeadline(time.Now().Add(negotiationAckTimeout))
		ackType, ackData, ackErr := conn.ReadMessage()
		conn.SetReadDeadline(time.Time{})
		if ackErr == nil && ackType == websocket.BinaryMessage {
			if ackChunk, derr := session.DecryptChunkSafe(ackData); derr == nil && ackChunk.Flags == core.FlagAck {
				if win, okFlow := parseFlowAckPayload(ackChunk.Payload); okFlow {
					t.flowControlEnabled = true
					t.flowWindow = win
				}
			}
		}
		if !t.flowControlEnabled {
			Stats.FlowNegotiationTimeout.Add(1)
		}
	}
```
Добавить на `WebSocketTransport` поля `flowDesiredWindow uint32`, `flowControlEnabled bool`, `flowWindow uint32`, константу:
```go
const negotiationAckTimeout = 500 * time.Millisecond
```

В `client/ws_pool.go` `connectSlot` — ПОСЛЕ успешного `UpgradeToWS` и установки `slot.transport`, скопировать negotiated значения в слот (найти место установки `slot.transport = wst`):
```go
	if wst.flowControlEnabled {
		slot.flowControlEnabled = true
		slot.flowWindow = uint64(wst.flowWindow)
	}
```
И ПЕРЕД upgrade — установить желаемое окно из конфигурации пула:
```go
	wst.flowDesiredWindow = uint32(p.flowDesiredWindow) // 0 → off
```
(Добавить `WSPoolTransport.flowDesiredWindow uint64`, заполняемый из env `SHADOWLINK_FLOW_WINDOW` при создании пула — см. Task 11.)

- [ ] **Step 4: Run, verify PASS** — `go test ./client/ -run TestParseFlowAck -v`; `go build ./...`. Expected: PASS + build OK.

- [ ] **Step 5: Commit**
```bash
git add client/ws_pool.go client/ws_transport.go client/stream_flow_test.go
git commit -m "feat(shadowlink): client FLOWCTL negotiation — marker + sync ack read (Bug #8)"
```

---

## ФАЗА 5 — серверная сторона

### Task 9: streamCredit (waitForCredit / consume / add / close)

**Files:**
- Create: `server/stream_credit.go`
- Test: `server/stream_credit_test.go`

- [ ] **Step 1: Failing test** — `server/stream_credit_test.go`:

```go
package server

import (
	"testing"
	"time"
)

func TestStreamCredit_WaitUnblocksOnAdd(t *testing.T) {
	c := newStreamCredit(0) // start with zero credit
	done := make(chan int64, 1)
	doneCh := make(chan struct{})
	go func() { done <- c.waitForCredit(doneCh) }()

	// waiter must be blocked
	select {
	case <-done:
		t.Fatal("waitForCredit returned with zero credit")
	case <-time.After(50 * time.Millisecond):
	}

	c.add(500, 1<<20)
	select {
	case got := <-done:
		if got != 500 {
			t.Fatalf("waitForCredit = %d, want 500", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForCredit did not unblock after add")
	}
}

func TestStreamCredit_CloseUnblocks(t *testing.T) {
	c := newStreamCredit(0)
	done := make(chan int64, 1)
	go func() { done <- c.waitForCredit(make(chan struct{})) }()
	time.Sleep(20 * time.Millisecond)
	c.close()
	select {
	case got := <-done:
		if got > 0 {
			t.Fatalf("waitForCredit after close = %d, want <=0", got)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock waiter")
	}
}

func TestStreamCredit_ConsumeAndClamp(t *testing.T) {
	c := newStreamCredit(1000)
	c.consume(400)
	if got := c.snapshot(); got != 600 {
		t.Fatalf("after consume available = %d, want 600", got)
	}
	c.add(100000, 1000) // window=1000 → clamp at 2*window=2000
	if got := c.snapshot(); got > 2000 {
		t.Fatalf("available = %d, exceeds clamp 2000", got)
	}
}

func TestStreamCredit_WaitReturnsWhenDoneClosed(t *testing.T) {
	c := newStreamCredit(0)
	doneCh := make(chan struct{})
	res := make(chan int64, 1)
	go func() { res <- c.waitForCredit(doneCh) }()
	time.Sleep(20 * time.Millisecond)
	close(doneCh)
	c.wake() // done-watcher wakes the cond
	select {
	case got := <-res:
		if got > 0 {
			t.Fatalf("got %d, want <=0 on done", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter not woken on done")
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./server/ -run TestStreamCredit -v`. Expected: undefined: newStreamCredit etc.

- [ ] **Step 3: Implement** — `server/stream_credit.go`:

```go
package server

import "sync"

// stream_credit.go — server-side per-stream send credit (Bug #8). The WS
// per-stream relay goroutine calls waitForCredit BEFORE reading the target
// (websocket.go), so a stream with no credit simply doesn't read — the target
// TCP socket applies its own backpressure. Credit is replenished by
// handleWindowUpdate when the client confirms consumption. Blocking happens
// ONLY in the per-stream relay goroutine, never in the session reader-loop
// (invariant I2) — so there is no head-of-line blocking across streams.
type streamCredit struct {
	mu        sync.Mutex
	cond      *sync.Cond
	available int64
	closed    bool
}

func newStreamCredit(window int64) *streamCredit {
	c := &streamCredit{available: window}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// waitForCredit blocks until available > 0, then returns it; or returns -1 if
// the stream/session was closed (caller exits the relay). done is the session
// done channel — the caller arranges wake() to be called when done fires
// (sync.Cond cannot select on a channel).
func (c *streamCredit) waitForCredit(done <-chan struct{}) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.available <= 0 && !c.closed {
		select {
		case <-done:
			return -1
		default:
		}
		c.cond.Wait()
		if c.closed {
			return -1
		}
	}
	if c.closed {
		return -1
	}
	return c.available
}

// consume decrements available by n (after enqueueing n bytes to the client).
func (c *streamCredit) consume(n int) {
	c.mu.Lock()
	c.available -= int64(n)
	c.mu.Unlock()
}

// add replenishes credit by delta, clamped at 2*window, and wakes the waiter.
func (c *streamCredit) add(delta uint32, window int64) {
	c.mu.Lock()
	c.available += int64(delta)
	if cap := 2 * window; c.available > cap {
		c.available = cap
	}
	c.cond.Signal()
	c.mu.Unlock()
}

// close marks the credit closed and wakes any waiter. Signal under mu so the
// waiter sees closed (no lost wakeup — M4).
func (c *streamCredit) close() {
	c.mu.Lock()
	c.closed = true
	c.cond.Signal()
	c.mu.Unlock()
}

// wake nudges the waiter to re-check (used on session done). Safe to call
// repeatedly.
func (c *streamCredit) wake() {
	c.mu.Lock()
	c.cond.Signal()
	c.mu.Unlock()
}

// snapshot returns current available (test/diagnostic helper).
func (c *streamCredit) snapshot() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.available
}
```

- [ ] **Step 4: Run, verify PASS** — `go test ./server/ -run TestStreamCredit -v`. Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add server/stream_credit.go server/stream_credit_test.go
git commit -m "feat(shadowlink): server streamCredit (waitForCredit/add/close) (Bug #8)"
```

---

### Task 10: серверная негоциация ack + credit-gate + handleWindowUpdate + teardown

**Files:**
- Modify: `server/websocket.go` (authenticateFirstFrame ~144; handleWebSocket ~439; runWebSocketSession ~470; reader-switch ~591; per-stream relay ~752; cleanup ~827; FlagConnect ~601; FlagFin ~772)
- Modify: `server/metrics.go` (метрики)
- Test: `server/stream_credit_test.go` (handleWindowUpdate-уровень) + integration в Task 12

- [ ] **Step 1: Failing test** — добавить серверный юнит на парс маркера в первом keepalive (чистый, без сети). Добавить в `server/stream_credit_test.go`:

```go
func TestNegotiateFlowWindow(t *testing.T) {
	// server max 1 MiB, client asks 4 MiB → min = 1 MiB
	if got := negotiateFlowWindow(4<<20, 1<<20); got != 1<<20 {
		t.Fatalf("negotiateFlowWindow(4M,1M) = %d, want 1M", got)
	}
	// client asks 256 KiB → min = 256 KiB
	if got := negotiateFlowWindow(256<<10, 1<<20); got != 256<<10 {
		t.Fatalf("got %d, want 256KiB", got)
	}
	// client 0 (no marker) → 0 (off)
	if got := negotiateFlowWindow(0, 1<<20); got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./server/ -run TestNegotiateFlowWindow -v`. Expected: undefined: negotiateFlowWindow.

- [ ] **Step 3: Implement**

В `server/stream_credit.go` добавить:
```go
// negotiateFlowWindow returns the effective window = min(clientWindow,
// serverMax), or 0 if the client did not advertise (clientWindow==0 → off).
func negotiateFlowWindow(clientWindow, serverMax uint32) uint32 {
	if clientWindow == 0 {
		return 0
	}
	if clientWindow > serverMax {
		return serverMax
	}
	return clientWindow
}
```

В `server/websocket.go`:

**(a) authenticateFirstFrame** — вернуть negotiated window. Изменить сигнатуру на `(*core.Session, uint32)` где второй — effectiveWindow (0=off). После проверки `chunk.Flags != FlagKeepalive` (~172), перед `return session`:
```go
	// Bug #8: read FLOWCTL marker from the (decrypted) keepalive payload and,
	// if present & we support it, emit a synchronous FLOWCTL-ack BEFORE the
	// relay loop starts (the first keepalive never reaches the reader-loop).
	var effectiveWindow uint32
	if cw, okFlow := core.ParseFlowCtlMarker(chunk.Payload); okFlow {
		effectiveWindow = negotiateFlowWindow(cw, uint32(h.flowMaxWindow))
		if effectiveWindow > 0 {
			ack := &core.Chunk{SessionID: session.ID, SeqNum: session.NextSeqNum(), Flags: core.FlagAck,
				Payload: core.BuildFlowCtlMarker(effectiveWindow)}
			if enc, encErr := session.EncryptChunk(ack); encErr == nil {
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_ = conn.WriteMessage(websocket.BinaryMessage, enc)
				conn.SetWriteDeadline(time.Time{})
			}
		}
	}
	// ... existing AttachedAt store ...
	return session, effectiveWindow
```
Обновить вызов в `handleWebSocket` (~439): `session, flowWindow := h.authenticateFirstFrame(conn)`; передать `flowWindow` в `runWebSocketSession(conn, session, flowWindow)`.
Добавить `Handler.flowMaxWindow uint64` (config, Task 11).

**(b) runWebSocketSession** — принять `flowWindow uint32`; завести credit-карту:
```go
func (h *Handler) runWebSocketSession(conn *websocket.Conn, session *core.Session, flowWindow uint32) {
	flowEnabled := flowWindow > 0
	credits := make(map[uint16]*streamCredit)
	creditsMu := &sync.Mutex{}
	...
```

**(c) FlagConnect** (~627, где создаётся pendingStream) — инициализировать credit:
```go
	if flowEnabled {
		creditsMu.Lock()
		credits[streamID] = newStreamCredit(int64(flowWindow))
		creditsMu.Unlock()
	}
```

**(d) per-stream relay** (~752-769) — credit-gate перед `tc.Read`:
```go
	buf := make([]byte, 32768)
	for {
		limit := len(buf)
		if flowEnabled {
			creditsMu.Lock()
			cr := credits[sid]
			creditsMu.Unlock()
			if cr != nil {
				got := cr.waitForCredit(done)
				if got <= 0 {
					return
				}
				if int(got) < limit {
					limit = int(got)
				}
			}
		}
		n, err := tc.Read(buf[:limit])
		if n > 0 {
			resp := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), sid, buf[:n])
			enc, encErr := session.EncryptChunk(resp)
			core.PutBuffer(resp.Payload)
			if encErr != nil {
				return
			}
			if writeMsg(enc) != nil {
				return
			}
			if flowEnabled {
				creditsMu.Lock()
				cr := credits[sid]
				creditsMu.Unlock()
				if cr != nil {
					cr.consume(n)
				}
			}
		}
		if err != nil {
			return
		}
	}
```

**(e) reader-switch** (~591) — новый case + default:
```go
		case core.FlagWindowUpdate:
			streamID, delta, perr := core.ParseWindowUpdate(chunk.Payload)
			if perr != nil {
				continue
			}
			creditsMu.Lock()
			cr := credits[streamID]
			creditsMu.Unlock()
			if cr != nil {
				cr.add(delta, int64(flowWindow))
			}
			h.metrics.FlowWindowUpdatesRecv.Add(1)

		default:
			h.metrics.UnknownFlag.Add(1)
```

**(f) FlagFin** (~772) — закрыть credit:
```go
		case core.FlagFin:
			streamID, _ := core.ParseStreamID(chunk.Payload)
			streamsMu.Lock()
			if s := streams[streamID]; s != nil {
				s.Close()
				delete(streams, streamID)
			}
			streamsMu.Unlock()
			creditsMu.Lock()
			if cr := credits[streamID]; cr != nil {
				cr.close()
				delete(credits, streamID)
			}
			creditsMu.Unlock()
```

**(g) per-stream relay defer** (~742-751) — закрыть credit:
```go
		defer func() {
			...
			creditsMu.Lock()
			if cr := credits[sid]; cr != nil {
				cr.close()
				delete(credits, sid)
			}
			creditsMu.Unlock()
		}()
```

**(h) session done watcher** — после старта reader, разбудить все credit-waiter'ы на `<-done` (M5). Добавить goroutine в `runWebSocketSession` (рядом со старыми):
```go
	go func() {
		<-done
		creditsMu.Lock()
		for _, cr := range credits {
			cr.close()
		}
		creditsMu.Unlock()
	}()
```

**(i) cleanup** (~827-834) — уже закроет через done-watcher; дополнительно в финальном цикле по streams credit'ы уже закрыты. Достаточно (h).

В `server/metrics.go` — добавить в metrics struct + экспортёр:
```go
	FlowWindowUpdatesRecv atomic.Uint64
	UnknownFlag           atomic.Uint64
	FlowSessionsActive    atomic.Int64
```
Экспозиция (по образцу соседних counters):
```go
	shadowlink_flow_window_updates_recv_total
	shadowlink_unknown_flag_total
	shadowlink_flow_sessions_active
```
(Инкремент `FlowSessionsActive` при `flowEnabled` входе в runWebSocketSession, декремент в defer.)

- [ ] **Step 4: Run, verify PASS** — `go test ./server/ -run 'TestNegotiateFlowWindow|TestStreamCredit' -v`; `go build ./...`; `go test ./server/` (весь пакет зелёный — не сломали существующее).

- [ ] **Step 5: Commit**
```bash
git add server/websocket.go server/stream_credit.go server/metrics.go
git commit -m "feat(shadowlink): server flow-control negotiation, credit-gate, handleWindowUpdate (Bug #8)"
```

---

## ФАЗА 6 — конфиг, проводка, integration-тесты

### Task 11: конфигурируемость окна (env/config) + проводка flowTransport

**Files:**
- Modify: `client/ws_pool.go` (WSPoolConfig / создание пула — `flowDesiredWindow` из env)
- Modify: `client/client.go` (выставить `flowControlEnabled`/`flowWindow`/`flowTransport` + `startCreditSender` когда пул negotiated flow; `stopCreditSender` на Close)
- Modify: `server/handler.go` или `cmd/shadowlink-server/main.go` (`flowMaxWindow` из flag/config, default 1 MiB)
- Test: `client/stream_flow_test.go` (env-parsing)

- [ ] **Step 1: Failing test**:
```go
func TestFlowWindowFromEnv(t *testing.T) {
	t.Setenv("SHADOWLINK_FLOW_WINDOW", "2097152") // 2 MiB
	if got := flowWindowFromEnv(1 << 20); got != 2<<20 {
		t.Fatalf("got %d, want 2MiB", got)
	}
	t.Setenv("SHADOWLINK_FLOW_WINDOW", "0")
	if got := flowWindowFromEnv(1 << 20); got != 0 {
		t.Fatalf("got %d, want 0 (off)", got)
	}
	t.Setenv("SHADOWLINK_FLOW_WINDOW", "")
	if got := flowWindowFromEnv(1 << 20); got != 1<<20 {
		t.Fatalf("got %d, want default 1MiB", got)
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./client/ -run TestFlowWindowFromEnv -v`. undefined: flowWindowFromEnv.

- [ ] **Step 3: Implement**

В `client/stream_flow.go`:
```go
import "os"
import "strconv"
import "strings"

// flowWindowFromEnv resolves the client's desired flow-control window.
// SHADOWLINK_FLOW_WINDOW (bytes): empty/unset → def; "0" → 0 (disable);
// other → parsed value. Clamped so window/minChunk <= incomingCh cap (512):
// minChunk≈512B floor → max ~256KiB*512... practical cap 6 MiB.
func flowWindowFromEnv(def uint64) uint64 {
	v := strings.TrimSpace(os.Getenv("SHADOWLINK_FLOW_WINDOW"))
	if v == "" {
		return clampFlowWindow(def)
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return clampFlowWindow(def)
	}
	if n == 0 {
		return 0
	}
	return clampFlowWindow(n)
}

const maxFlowWindow = 6 << 20 // M2: window/minChunk must fit incomingCh cap (512)

func clampFlowWindow(w uint64) uint64 {
	if w > maxFlowWindow {
		return maxFlowWindow
	}
	return w
}
```

Проводка в `client/ws_pool.go` (создание пула — найти конструктор `NewWSPoolTransport` или эквивалент): установить `p.flowDesiredWindow = flowWindowFromEnv(1 << 20)`.

Проводка в `client/client.go`: после того как пул negotiated (хотя бы один слот flowControlEnabled), выставить на Client: `c.flowControlEnabled=true`, `c.flowWindow=<slot.flowWindow>`, `c.flowTransport=<pool as StreamTransport>`, вызвать `c.startCreditSender()`. На `Client.Close`/`ResetStreams` — `c.stopCreditSender()`. (Найти точку, где пул становится готов — рядом с тем, где клиент узнаёт транспорт. Capability per-slot, но т.к. все слоты к одному серверу negotiate одинаково, клиент может взять окно первого slotReady с flowControlEnabled.)

Сервер: в `cmd/shadowlink-server/main.go` добавить flag `-flow-max-window` (default `1048576`), прокинуть в `Handler.flowMaxWindow`. Если 0 — сервер не подтверждает flow (off).

- [ ] **Step 4: Run, verify PASS** — `go test ./client/ -run TestFlowWindowFromEnv -v`; `go build ./...`.

- [ ] **Step 5: Commit**
```bash
git add client/stream_flow.go client/ws_pool.go client/client.go cmd/shadowlink-server/main.go server/handler.go
git commit -m "feat(shadowlink): wire flow-control window config + credit sender lifecycle (Bug #8)"
```

---

### Task 12: integration — 0 дропов при быстрой закачке (ГЛАВНЫЙ тест, доказывает фикс)

**Files:**
- Test: `client/flow_integration_test.go` (новый)

- [ ] **Step 1: Failing test** — смоделировать producer быстрее consumer'а через RouteToStream + flow control, проверить 0 overflow. Использовать реальные `RouteToStream` + `streamFlow` + фейковый transport, считающий WINDOW_UPDATE и эмулирующий серверный credit-gate:

```go
package client

import (
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// fakeFlowServer emulates the server credit-gate: it only "sends" (calls
// RouteToStream) while it has credit, and replenishes on WINDOW_UPDATE.
func TestFlowControl_NoDropsUnderFastDownload(t *testing.T) {
	const window = 64 * 1024
	const total = 4 * 1024 * 1024 // 4 MiB download
	const frame = 4096

	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = window
	c.streamFlow = map[uint16]*streamFlowState{}
	ch, err := c.RegisterStream(1)
	if err != nil {
		t.Fatal(err)
	}
	c.streamFlow[1] = &streamFlowState{window: window}

	// server-side credit mirror
	var mu sync.Mutex
	credit := int64(window)

	// client credit sender feeds WINDOW_UPDATE back to the server mirror
	c.flowSendForTest = func(_ uint16, delta uint32) bool {
		mu.Lock()
		credit += int64(delta)
		mu.Unlock()
		return true
	}

	baseline := Stats.StreamBufferOverflowsTotal.Load()

	// slow consumer: drains ch and credits consumption
	consumed := 0
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		for consumed < total {
			select {
			case data := <-ch:
				time.Sleep(time.Millisecond) // slow app
				consumed += len(data)
				c.OnStreamConsumed(1, len(data))
			case <-time.After(5 * time.Second):
				return
			}
		}
	}()

	// credit sender ticking
	stop := make(chan struct{})
	go func() {
		tk := time.NewTicker(2 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				c.creditSenderTick(0.5)
			}
		}
	}()

	// server: send frames only while credit available
	sent := 0
	for sent < total {
		mu.Lock()
		has := credit > 0
		mu.Unlock()
		if !has {
			time.Sleep(time.Millisecond)
			continue
		}
		c.RouteToStream(1, make([]byte, frame))
		mu.Lock()
		credit -= frame
		mu.Unlock()
		sent += frame
	}

	<-consumerDone
	close(stop)

	drops := Stats.StreamBufferOverflowsTotal.Load() - baseline
	if drops != 0 {
		t.Fatalf("flow control should yield 0 drops, got %d", drops)
	}
	if consumed < total {
		t.Fatalf("consumed %d < total %d (stalled)", consumed, total)
	}
}
```

- [ ] **Step 2: Run, verify FAIL первоначально** — если запустить с `flowControlEnabled=false` (контраст) — дропы есть. С flow on — должно стать 0 ПОСЛЕ корректной реализации. Сначала убедиться, что тест осмысленно падает на сломанной логике (например, если sender не обнуляет delta). Expected на правильной реализации: PASS.

- [ ] **Step 3: (реализация уже в Task 5-6)** — этот тест валидирует интеграцию, новой production-логики не вводит. Если падает — чинить Task 5/6, не тест.

- [ ] **Step 4: Run, verify PASS** — `go test ./client/ -run TestFlowControl_NoDrops -v -timeout 60s`. Expected: PASS, 0 drops.

- [ ] **Step 5: Commit**
```bash
git add client/flow_integration_test.go
git commit -m "test(shadowlink): integration — 0 drops under fast download with flow control (Bug #8)"
```

---

### Task 13: HoL-тест (один стрим застрял — другой качает)

**Files:**
- Test: `client/flow_integration_test.go`

- [ ] **Step 1: Failing test**:
```go
func TestFlowControl_NoHeadOfLineBlocking(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 32 * 1024
	c.streamFlow = map[uint16]*streamFlowState{}

	chStuck, _ := c.RegisterStream(1)
	chLive, _ := c.RegisterStream(2)
	c.streamFlow[1] = &streamFlowState{window: 32 * 1024}
	c.streamFlow[2] = &streamFlowState{window: 32 * 1024}

	_ = chStuck // never drained → its incomingCh fills, but RouteToStream must not block stream 2

	// stream 2 has an active consumer
	got2 := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for got2 < 100*1024 {
			select {
			case d := <-chLive:
				got2 += len(d)
			case <-time.After(2 * time.Second):
				return
			}
		}
	}()

	// fill stream 1 channel to cap (no consumer) — must not stop stream 2
	for i := 0; i < 600; i++ {
		c.RouteToStream(1, make([]byte, 1024)) // overflows cap 512 → drops on stream 1 only
	}
	// stream 2 keeps flowing
	for got2 < 100*1024 {
		c.RouteToStream(2, make([]byte, 1024))
	}
	<-done
	if got2 < 100*1024 {
		t.Fatalf("stream 2 starved: got %d", got2)
	}
}
```

- [ ] **Step 2: Run, verify** — `go test ./client/ -run TestFlowControl_NoHeadOfLine -v`. Демонстрирует: RouteToStream per-stream (стрим 1 переполняется/дропает, стрим 2 течёт). Expected: PASS (RouteToStream уже per-stream независим — тест фиксирует инвариант).

- [ ] **Step 3: Commit**
```bash
git add client/flow_integration_test.go
git commit -m "test(shadowlink): per-stream isolation — no head-of-line blocking (Bug #8)"
```

---

### Task 14: half-close тест (update идёт после CloseWrite)

**Files:**
- Test: `proxy/socks5/flow_halfclose_test.go` (новый)

- [ ] **Step 1: Failing test** — проверить, что отправка credit (через memConn half-close) не зависит от закрытия uplink. Использовать `newMemPipe`; после `appConn.CloseWrite()` убедиться, что downlink-путь и вызов `OnStreamConsumed` живут:

```go
package socks5

import (
	"testing"
)

// TestHalfClose_DownlinkCreditPathSurvives documents that after the app does
// CloseWrite (half-close), the relay's downlink side — which is where
// OnStreamConsumed is invoked — stays alive. memConn semantics: appConn.CloseWrite
// closes only uplink d1; ourConn.Write (downlink d2) still works.
func TestHalfClose_DownlinkCreditPathSurvives(t *testing.T) {
	appConn, ourConn := newMemPipe()

	if hc, ok := appConn.(interface{ CloseWrite() error }); ok {
		if err := hc.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	} else {
		t.Fatal("appConn missing CloseWrite")
	}

	// downlink write must still succeed (this is where OnStreamConsumed fires
	// after a successful conn.Write in tunnelTCPStream)
	if _, err := ourConn.Write([]byte("response after half-close")); err != nil {
		t.Fatalf("downlink write after half-close failed: %v", err)
	}
	buf := make([]byte, 64)
	if n, err := appConn.Read(buf); err != nil || n == 0 {
		t.Fatalf("appConn.Read after half-close: n=%d err=%v", n, err)
	}
}
```

- [ ] **Step 2: Run, verify PASS** — `go test ./proxy/socks5/ -run TestHalfClose_DownlinkCredit -v`. Expected: PASS (это инвариант memConn; уже есть похожий тест из Bug#8 trace — этот фиксирует именно credit-путь).

- [ ] **Step 3: Commit**
```bash
git add proxy/socks5/flow_halfclose_test.go
git commit -m "test(shadowlink): credit path survives TCP half-close (Bug #8)"
```

---

### Task 15: server teardown — нет goroutine-leak / credit-waiter будится

**Files:**
- Test: `server/stream_credit_test.go`

- [ ] **Step 1: Failing test**:
```go
func TestStreamCredit_TeardownWakesAllWaiters(t *testing.T) {
	credits := map[uint16]*streamCredit{
		1: newStreamCredit(0),
		2: newStreamCredit(0),
	}
	done := make(chan struct{})
	results := make(chan int64, 2)
	for id := range credits {
		cr := credits[id]
		go func() { results <- cr.waitForCredit(done) }()
	}
	time.Sleep(30 * time.Millisecond)
	// emulate session done-watcher: close all credits
	for _, cr := range credits {
		cr.close()
	}
	for i := 0; i < 2; i++ {
		select {
		case got := <-results:
			if got > 0 {
				t.Fatalf("waiter returned %d, want <=0 on teardown", got)
			}
		case <-time.After(time.Second):
			t.Fatal("waiter not woken on teardown (leak)")
		}
	}
}
```

- [ ] **Step 2: Run, verify PASS** — `go test ./server/ -run TestStreamCredit_Teardown -v`. Expected: PASS.

- [ ] **Step 3: Commit**
```bash
git add server/stream_credit_test.go
git commit -m "test(shadowlink): credit teardown wakes all waiters, no leak (Bug #8)"
```

---

### Task 16: negotiation совместимость (юнит, обе стороны)

**Files:**
- Test: `core/flowctl_test.go` (compat-матрица через маркер)

- [ ] **Step 1: Failing test**:
```go
func TestNegotiationMatrix(t *testing.T) {
	// клиент шлёт маркер 1MiB, сервер max 1MiB → ack 1MiB
	clientMarker := BuildFlowCtlMarker(1 << 20)
	cw, ok := ParseFlowCtlMarker(clientMarker)
	if !ok {
		t.Fatal("server must parse client marker")
	}
	// сервер: min(cw, serverMax)
	serverMax := uint32(1 << 20)
	eff := cw
	if eff > serverMax {
		eff = serverMax
	}
	ack := BuildFlowCtlMarker(eff)
	// клиент парсит ack
	got, ok := ParseFlowCtlMarker(ack)
	if !ok || got != 1<<20 {
		t.Fatalf("client ack parse = (%d,%v), want 1MiB,true", got, ok)
	}

	// старый клиент: пустой keepalive payload → сервер не видит маркер
	if _, ok := ParseFlowCtlMarker(nil); ok {
		t.Fatal("empty payload must not look like marker")
	}
}
```

- [ ] **Step 2: Run, verify PASS** — `go test ./core/ -run TestNegotiationMatrix -v`. Expected: PASS.

- [ ] **Step 3: Commit**
```bash
git add core/flowctl_test.go
git commit -m "test(shadowlink): flow-control negotiation compat matrix (Bug #8)"
```

---

## ФАЗА 7 — финализация

### Task 17: убрать Bug#8 trace-код

**Files:**
- Modify: `proxy/socks5/tcp.go` (trace в downlink write error / uplink done / downlink cancelled — диагностика 10:07)
- Modify: `proxy/socks5/inprocess.go` (slog.Debug "in-process relay exit" + import log/slog если только для trace)
- Delete/Keep: `proxy/socks5/memconn_halfclose_test.go` — ЗАМЕНЁН Task 14; решить: оставить (полезен) или удалить дубль

- [ ] **Step 1:** Найти trace-добавления (по комментариям про Bug#8 диагностику / лишние поля в slog.Warn "downlink write error" — `connectConfirmed/downlinkBytes/downlinkChunks/streamAgeMs`). Оставить штатное логирование, убрать диагностические поля, добавленные ТОЛЬКО для трейса. `inprocess.go`: убрать `slog.Debug("in-process relay exit → ourConn.Close", ...)` и import `log/slog` если он больше нигде не нужен в файле.

- [ ] **Step 2: Run** — `go build ./...`; `go test ./proxy/...`. Expected: OK.

- [ ] **Step 3: Commit**
```bash
git add proxy/socks5/tcp.go proxy/socks5/inprocess.go
git commit -m "chore(shadowlink): remove Bug #8 diagnostic trace (root cause fixed via flow control)"
```

---

### Task 18: wire-спека документ + полный прогон

**Files:**
- Create: `shadowlink/docs/protocols/flow-control-v2.md`

- [ ] **Step 1:** Написать `flow-control-v2.md`: формат `FlagWindowUpdate` (0x0A, [streamID(2)][delta(4)]), FLOWCTL-маркер (["FLOWCTL"][window(4)] в зашифрованном payload keepalive/ack), негоциация (клиент маркер → сервер синхронный ack → клиент синхронное чтение), credit-семантика (порог 50%±, кламп 2×window, watchdog 200ms), env `SHADOWLINK_FLOW_WINDOW` / server `-flow-max-window`, compat (старый сервер не шлёт ack → off за 500ms). Ссылка на спеку дизайна.

- [ ] **Step 2: Полный прогон**:
```bash
go build ./...
go test ./core/ ./client/ ./server/ ./proxy/...
```
Expected: всё зелёное.

- [ ] **Step 3:** На Linux/CI (Windows без gcc): `go test -race -count=3 ./core/ ./client/ ./server/`. Зафиксировать результат (если нет gcc — отметить «race на CI», как для Bug#6).

- [ ] **Step 4: Commit**
```bash
git add shadowlink/docs/protocols/flow-control-v2.md
git commit -m "docs(shadowlink): flow-control-v2 wire protocol spec (Bug #8)"
```

---

## После реализации (НЕ часть subagent-плана — ручные шаги)

1. **Финальное опус-ревью КОДА** (как для Bug#6): адверсариальный проход по реализации против спеки. Отчёт в файл.
2. **Пересборка клиентского бинаря** `nixavpn-client-graceful-drain.exe` (+ бэкап `.bak-pre-flowctl`).
3. **Передеплой pl1 СЕРВЕРА ПЕРВЫМ** (staged rollout — спека §4.5), затем раздать клиент с `SHADOWLINK_FLOW_WINDOW` (default on). Через SSH (root@104.222.177.67, пароль `m3sDQFD2z9bY` — не сменён) или передаёт юзер.
4. **Канарейка:** проследить `shadowlink_flow_window_updates_*`, `flow_negotiation_timeout_total` (должен быть 0 после передеплоя сервера), `stream_buffer_overflows_total` (должен упасть до 0 на быстрых закачках), `credit_wait_seconds`/`flow_window_update_dropped_total` (тюнинг окна).
5. **Полевой тест:** большая закачка через Chrome — больше НЕ должна рваться.

---

## Self-Review (выполнено при написании)

**Spec coverage:** §3 wire→Task1/2; §4 negotiation→Task8/10/16; §5 client flow-state+sender→Task5/6/7; §6 server credit→Task9/10; §8 half-close→Task14; §10 метрики→Task6/10; §13 config→Task11; integration/HoL/teardown→Task12/13/15; trace cleanup→Task17; wire-doc→Task18. **TryEnqueueControl (NB2)→Task3.** Все разделы покрыты.

**Placeholder scan:** все шаги содержат реальный код/команды. Точки, где надо «найти место в существующем коде» (Task7/10/11 проводка) — указаны с номерами строк и якорями; это интеграция в большие существующие функции, не плейсхолдер.

**Type consistency:** `streamFlowState{pendingDelta atomic.Uint64, window uint64, lastSentNs atomic.Int64}` — консистентно Task5/6/12/13. `streamCredit{available int64}` + `newStreamCredit(int64)`/`add(uint32,int64)`/`waitForCredit(<-chan struct{}) int64` — консистентно Task9/10/15. `BuildFlowCtlMarker(uint32)`/`ParseFlowCtlMarker([]byte)(uint32,bool)` — Task2/8/10/16. `NewWindowUpdateChunk(.. uint16, uint32)`/`ParseWindowUpdate([]byte)(uint16,uint32,error)` — Task1/6/10. `TryEnqueueControl(int,[]byte)bool`/`TryWriteControlMessage([]byte)bool`/`TryWriteControlMessageForStream(uint16,[]byte)bool`/`TryStreamWriteControl(StreamTransport,uint16,[]byte)bool` — Task3/4/6. Согласовано.

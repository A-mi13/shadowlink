package client

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"math/rand/v2"

	"github.com/nixavpn/shadowlink/core"
)

const maxFlowWindow = 6 << 20 // M2: window/minChunk must fit incomingCh cap (512)

// clampFlowWindow caps the window so window/minChunk stays within the
// per-stream incomingCh capacity (512), preventing overflow re-introduction.
func clampFlowWindow(w uint64) uint64 {
	if w > maxFlowWindow {
		return maxFlowWindow
	}
	return w
}

// flowWindowFromEnv resolves the client's desired flow-control window.
// SHADOWLINK_FLOW_WINDOW (bytes): empty/unset → def; "0" → 0 (disable);
// other → parsed value (clamped). Invalid → def.
func flowWindowFromEnv(def uint64) uint64 {
	v := strings.TrimSpace(os.Getenv("SHADOWLINK_FLOW_WINDOW"))
	if v == "" {
		return clampFlowWindow(def)
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return clampFlowWindow(def)
	}
	if n == 0 {
		return 0
	}
	return clampFlowWindow(n)
}

// EnableFlowControl turns on per-stream flow control for this client and starts
// the credit sender. Idempotent: safe to call once per ready slot (only the
// first call wires state + launches the sender). transport is the pool the
// credit sender rides. Called from connectSlot when a slot negotiates FLOWCTL.
func (c *Client) EnableFlowControl(window uint64, transport StreamTransport) {
	c.streamMu.Lock()
	already := c.flowControlEnabled
	if !already {
		c.flowControlEnabled = true
		c.flowWindow = window
		c.flowTransport = transport
	}
	c.streamMu.Unlock()
	if !already {
		c.startCreditSender()
	}
}

// stream_flow.go — client-side per-stream flow control (Bug #8). The downlink
// relay goroutine calls OnStreamConsumed after each successful conn.Write into
// the app (memConn) — it ONLY does an atomic add and NEVER sends or blocks
// (invariant I3). A separate per-client credit sender (added in a later task)
// drains pendingDelta into WINDOW_UPDATE frames non-blockingly.

// streamFlowState accumulates bytes the app has consumed but not yet credited
// back to the server via WINDOW_UPDATE.
type streamFlowState struct {
	pendingDelta atomic.Uint64 // bytes consumed since last WINDOW_UPDATE sent
	window       uint64        // negotiated effective window (read-only)
	lastSentNs   atomic.Int64  // unix-nano of last successful WINDOW_UPDATE (watchdog)
}

const (
	creditSenderInterval = 8 * time.Millisecond // tick cadence (cheap)
	creditWatchdogNs     = int64(200 * time.Millisecond)

	// creditFlushFloor — minimum accumulated consumed bytes before the sender
	// emits a WINDOW_UPDATE. Eager sliding-window return (HTTP/2-style): we flush
	// credit as the app consumes it, NOT after hoarding a fraction of the window.
	// 32 KiB ≈ a few chunks — small enough that the server's `available` is
	// replenished continuously (no 242ms credit-stall / "zубцами" downlink that
	// left the slot idle and got it reaped with close 1006), large enough to
	// coalesce per-frame updates (avoids one tiny uplink frame per 12KiB chunk —
	// DPI hygiene). Independent of window size.
	creditFlushFloor = 32 * 1024
)

// nextCreditSenderWakeup возвращает задержку до следующего пробуждения
// credit-sender'а: creditSenderInterval + uniform[0, creditSenderInterval).
//
// Джиттер сэмплируется ЗАНОВО на каждом вызове. Один сэмпл, переиспользованный
// на весь сеанс, дал бы ту же решётку с другим шагом — антипаттерн
// «single-sample reused», разобранный у slotStaggerOffset и nextWatchdogWakeup.
//
// # Почему это не задерживает возврат credits
//
// Константа 8 мс НЕ менялась (hard rule 8) — джиттер добавляется сверху, то есть
// период пробуждения лежит в [8, 16) мс, среднее 12 мс. Отправку гейтит не тик,
// а объём: creditFlushFloor = 32 KiB накопленных байт либо creditWatchdogNs =
// 200 мс для «залежавшегося хвоста». Тик — лишь частота ПРОВЕРКИ этих условий,
// поэтому +4 мс к среднему интервалу проверки не приближает нас к watchdog'у
// (200 мс) и на порядок меньше его. Верхняя граница 16 мс против порога 200 мс —
// запас 12x.
//
// Риск, который тем не менее надо мерить: из-за задержки возврата credits сервер
// уже вставал в waitForCredit (~242 мс/блок), downlink шёл зубцами, слот
// простаивал и его жали с close 1006 (см. комментарий в creditSenderTick).
// Поэтому сторож TestCreditSender_JitteredWakeupBreaksGrid проверяет не только
// исчезновение решётки, но и максимальный интервал между отправками.
func nextCreditSenderWakeup() time.Duration {
	return creditSenderInterval + time.Duration(rand.Float64()*float64(creditSenderInterval))
}

// startCreditSender launches the single per-client credit-sender goroutine.
// It scans Client.streamFlow on each (jittered) wakeup and emits WINDOW_UPDATE
// for any stream that accumulated creditFlushFloor consumed bytes, or whose tail
// has been waiting longer than creditWatchdogNs. Idempotent via flowStop.
//
// ⚠ Здесь стояло «crossed the (jittered 40-60%) threshold» — описание механизма,
// которого НЕТ: thresholdRatio не гейтит отправку (`_ = thresholdRatio` в
// creditSenderTick), гейт идёт по абсолютному объёму creditFlushFloor. Из этой
// формулировки родилось ложное «фаза защищена джиттером», тогда как джиттер был
// приложен к порогу, а решётка жила на периоде тикера и была видна на проводе.
// Сторож: TestCreditSender_ThresholdRatioDoesNotGateSend.
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
		// time.Timer с перевзводом, а НЕ time.NewTicker: тикер даёт постоянный
		// период, то есть решётку на wire. Замер на проводе 2026-08-19 (pcap,
		// pktmon): uplink-пакеты payload 71 Б дали R@8мс = 0.9445 при n=21 991,
		// тогда как соседние размеры (75/65/99 Б) чисты — то есть линия 125 Гц
		// принадлежала именно WINDOW_UPDATE и была наблюдаема.
		//
		// Лечение то же, что применялось к rotationWatchdogTick (см.
		// nextWatchdogWakeup): джиттер на ПЕРИОД пробуждения, сэмплируется
		// заново каждый взвод. Джиттер на пороге (прежний thresholdRatio) фазу
		// не размазывает — порог проверяется всё равно только на тике.
		t := time.NewTimer(nextCreditSenderWakeup())
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				t.Reset(nextCreditSenderWakeup())
				// thresholdRatio сохранён в подписи для тестового seam'а; он
				// давно не гейтит отправку (см. creditSenderTick), поэтому на
				// фазу не влияет и передаётся как есть.
				c.creditSenderTick(0.4 + rand.Float64()*0.2)
			}
		}
	}()
}

// stopCreditSender stops the credit-sender goroutine. Idempotent.
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
		// Eager flush: emit WINDOW_UPDATE once the app has consumed at least
		// creditFlushFloor bytes, OR the watchdog fires for a stale tail. Do NOT
		// wait for a fraction of the window — that hoarding caused the server to
		// stall in waitForCredit (~242ms/block, window-independent floor) and the
		// downlink to flow in bursts, leaving the WS slot idle long enough to be
		// reaped with close 1006 mid-download. thresholdRatio param is retained
		// for the watchdog/test seam but no longer gates the floor.
		lastNs := it.st.lastSentNs.Load()
		stale := lastNs != 0 && nowNs-lastNs >= creditWatchdogNs
		if d < creditFlushFloor && !stale {
			continue
		}
		_ = thresholdRatio // retained for signature/test compatibility
		// Take the current delta atomically; only zero it if the send succeeds.
		if it.st.pendingDelta.CompareAndSwap(d, 0) {
			if c.sendWindowUpdate(it.id, uint32(d)) {
				it.st.lastSentNs.Store(nowNs)
				Stats.FlowWindowUpdatesSent.Add(1)
			} else {
				it.st.pendingDelta.Add(d) // give back (additive, race-safe)
				Stats.FlowWindowUpdateDropped.Add(1)
			}
		}
		// CAS failure → OnStreamConsumed added concurrently; next tick handles it.
	}
}

// NOTE: c.flowTransport must be assigned BEFORE startCreditSender launches the
// sender goroutine (happens-before via goroutine start) and not mutated after —
// so this lock-free read is race-free. Wiring (later task) must honor this.

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

// SendStreamAck builds and non-blockingly sends a FlagStreamAck for streamID
// confirming in-order downlink delivery up to ackedDownSeq (Bug #9 §5.4). The
// server uses it as a reassembler barrier to release the unacked resend tail.
// Best-effort: returns true if enqueued. Rides the same control channel as
// WINDOW_UPDATE (TryStreamWriteControl). Per-stream throttling is layered on
// top in a later task (T15); this is the raw send.
func (c *Client) SendStreamAck(wst StreamTransport, streamID uint16, ackedDownSeq uint64) bool {
	session := StreamSession(wst, c, streamID)
	if session == nil {
		return false
	}
	chunk := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     core.FlagStreamAck,
		Payload:   core.BuildStreamAckFrame(streamID, ackedDownSeq),
	}
	enc, err := session.EncryptChunk(chunk)
	if err != nil {
		return false
	}
	return TryStreamWriteControl(wst, streamID, enc)
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

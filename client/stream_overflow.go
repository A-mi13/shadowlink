package client

import (
	"log/slog"
	"time"
)

// streamOverflowState aggregates per-stream RouteToStream channel-full
// drops so we emit two logs per stream (one WARN on first drop, one INFO
// on stream end with totals) instead of N WARNs per drop event.
//
// Triggered by: SOCKS consumer death races, ServerClose mid-stream,
// per-stream WS path teardown — all paths funnel through RouteToStream's
// `select case ch <- data: default` fallthrough.
//
// Design: spec 2026-05-23.
type streamOverflowState struct {
	firstAt      time.Time
	lastAt       time.Time
	drops        uint32
	droppedBytes uint64
}

// recordBufferOverflow registers a single drop event for the given stream.
// Caller must hold no Client locks (function acquires streamOverflowMu).
//
// On the FIRST drop for a stream a WARN is emitted; subsequent drops are
// silently counted. The aggregate is flushed at flushBufferOverflow time
// (called from UnregisterStream).
func (c *Client) recordBufferOverflow(streamID uint16, dataSize int) {
	now := time.Now()
	c.streamOverflowMu.Lock()
	st, exists := c.streamOverflow[streamID]
	if !exists {
		if c.streamOverflow == nil {
			c.streamOverflow = make(map[uint16]*streamOverflowState)
		}
		st = &streamOverflowState{firstAt: now}
		c.streamOverflow[streamID] = st
	}
	st.lastAt = now
	st.drops++
	st.droppedBytes += uint64(dataSize)
	c.streamOverflowMu.Unlock()
	Stats.StreamBufferOverflowsTotal.Add(1)
	if !exists {
		slog.Warn("stream buffer overflow started",
			"stream_id", streamID, "data_size", dataSize)
	}
}

// flushBufferOverflow emits the aggregated INFO log for a stream if any
// drops were recorded and clears state. Safe to call for streams with
// no overflow (no-op in that case). Called from UnregisterStream.
func (c *Client) flushBufferOverflow(streamID uint16) {
	c.streamOverflowMu.Lock()
	st, has := c.streamOverflow[streamID]
	if has {
		delete(c.streamOverflow, streamID)
	}
	c.streamOverflowMu.Unlock()
	if !has {
		return
	}
	// Два интервала, каждый под своим именем (правка 2026-08-17).
	//
	// Здесь стояло единственное поле "duration" со значением
	// lastAt.Sub(firstAt) — интервал между первым и последним ДРОПОМ. При одном
	// дропе оно тождественно 0s, и прогон 20260817 напечатал ровно это:
	// `drops=1 dropped_bytes=5600 duration=0s` при трёх минутах между строками
	// `started` (17:51:16.192) и `ended` (17:54:17.248). Имя обещало
	// длительность переполнения, значение её не измеряло ни при каком числе
	// дропов: последний дроп — не конец переполнения.
	//
	// since_first_drop — от первого дропа до конца стрима. Конец доступен,
	// потому что flush зовётся из UnregisterStream; это верхняя граница окна,
	// в котором стрим шёл с потерями.
	// drop_span — прежняя величина (первый→последний дроп); при drops=1 она
	// законно 0s, и теперь имя об этом говорит.
	slog.Info("stream buffer overflow ended",
		"stream_id", streamID,
		"drops", st.drops,
		"dropped_bytes", st.droppedBytes,
		"since_first_drop", time.Since(st.firstAt),
		"drop_span", st.lastAt.Sub(st.firstAt))
}

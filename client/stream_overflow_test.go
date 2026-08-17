package client

import (
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// captureSlogOverflow redirects the default slog logger to an in-memory buffer
// and returns a cleanup func + the buffer. Caller asserts on buffer
// contents to verify log emissions.
func captureSlogOverflow(t *testing.T, level slog.Level) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// newTestClient returns a minimal Client suitable for stream-overflow
// tests. Does NOT establish a network session — only the bits exercised
// by RegisterStream/RouteToStream/UnregisterStream are initialized.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	return &Client{}
}

func TestStreamBufferOverflow_SingleStreamMultipleDrops(t *testing.T) {
	buf := captureSlogOverflow(t, slog.LevelInfo)
	c := newTestClient(t)
	startBaseline := Stats.StreamBufferOverflowsTotal.Load()

	const sid uint16 = 7777
	ch, err := c.RegisterStream(sid)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	_ = ch // consumer never reads; channel cap = 512

	// First 512 sends fill the buffer; further sends drop.
	for i := 0; i < 512; i++ {
		c.RouteToStream(sid, []byte{0xAB})
	}
	// 200 guaranteed drops.
	for i := 0; i < 200; i++ {
		c.RouteToStream(sid, []byte{0xCD, 0xEF}) // 2 bytes each
	}

	// Before Unregister: exactly ONE WARN "started", zero INFO "ended".
	warnCount := strings.Count(buf.String(), `msg="stream buffer overflow started"`)
	if warnCount != 1 {
		t.Errorf("expected 1 WARN 'started', got %d. Log:\n%s", warnCount, buf.String())
	}
	if c := strings.Count(buf.String(), `msg="stream buffer overflow ended"`); c != 0 {
		t.Errorf("expected 0 INFO 'ended' before Unregister, got %d", c)
	}

	c.UnregisterStream(sid)

	// After Unregister: exactly ONE INFO "ended".
	endedCount := strings.Count(buf.String(), `msg="stream buffer overflow ended"`)
	if endedCount != 1 {
		t.Errorf("expected 1 INFO 'ended', got %d. Log:\n%s", endedCount, buf.String())
	}
	// Counter incremented exactly 200 (drops; first 512 fit in buffer).
	delta := Stats.StreamBufferOverflowsTotal.Load() - startBaseline
	if delta != 200 {
		t.Errorf("StreamBufferOverflowsTotal delta = %d, want 200", delta)
	}
}

// TestStreamBufferOverflow_SingleDropReportsRealWindow — сторож против поля
// `duration`, которое считало не то, чем называлось (полевой прогон
// 2026-08-17, лог nixavpn-DEBUG-20260817-092533).
//
// Что было: flushBufferOverflow печатал "duration", st.lastAt.Sub(st.firstAt) —
// интервал между ПЕРВЫМ и ПОСЛЕДНИМ дропом. При одном дропе (а это и был
// единственный случай в том прогоне) он тождественно равен 0s, и лог утверждал
// «переполнение длилось 0s», хотя между строками `started` (17:51:16.192) и
// `ended` (17:54:17.248) прошло три минуты:
//
//	msg="stream buffer overflow ended" stream_id=5950 drops=1 dropped_bytes=5600 duration=0s
//
// Ноль-по-построению — тот же класс, что мёртвые счётчики: он читается как
// наблюдение «переполнение мгновенное», хотя не измеряет ничего.
//
// Стало: два поля с честными именами вместо одного лживого —
// `since_first_drop` (от первого дропа до конца стрима, момент доступен, потому
// что flush зовётся из UnregisterStream) и `drop_span` (первый→последний дроп,
// прежняя величина под своим именем). Тест требует, чтобы поля `duration`
// не было вовсе: переименование при сохранении обоих смыслов в одном поле
// оставило бы читателя без возможности отличить одно от другого.
func TestStreamBufferOverflow_SingleDropReportsRealWindow(t *testing.T) {
	buf := captureSlogOverflow(t, slog.LevelInfo)
	c := newTestClient(t)

	const sid uint16 = 5950
	if _, err := c.RegisterStream(sid); err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	// Заполняем буфер, затем РОВНО один дроп — конфигурация из полевого лога.
	for i := 0; i < 512; i++ {
		c.RouteToStream(sid, []byte{0x01})
	}
	c.RouteToStream(sid, []byte{0x02})

	// Стрим живёт после дропа: именно этот интервал прежнее поле теряло.
	time.Sleep(30 * time.Millisecond)
	c.UnregisterStream(sid)

	line := buf.String()
	if !strings.Contains(line, `msg="stream buffer overflow ended"`) {
		t.Fatalf("нет строки 'ended':\n%s", line)
	}
	if strings.Contains(line, "duration=") {
		t.Errorf("поле duration осталось: при одном дропе оно тождественно 0s и "+
			"о длительности переполнения не говорит.\n%s", line)
	}
	if strings.Contains(line, "since_first_drop=0s") || !strings.Contains(line, "since_first_drop=") {
		t.Errorf("since_first_drop отсутствует или равен 0s — интервал от первого "+
			"дропа до конца стрима не измеряется.\n%s", line)
	}
	if !strings.Contains(line, "drop_span=") {
		t.Errorf("drop_span отсутствует — прежняя величина (первый→последний дроп) "+
			"должна остаться, но под своим именем.\n%s", line)
	}
}

func TestStreamBufferOverflow_NoOverflowNoLog(t *testing.T) {
	buf := captureSlogOverflow(t, slog.LevelInfo)
	c := newTestClient(t)

	const sid uint16 = 8888
	ch, err := c.RegisterStream(sid)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	// Active consumer drains.
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	for i := 0; i < 100; i++ {
		c.RouteToStream(sid, []byte{0x01})
	}
	c.UnregisterStream(sid)
	// Close channel so consumer exits.
	close(ch)
	<-done

	if got := buf.String(); strings.Contains(got, "stream buffer overflow") {
		t.Errorf("unexpected overflow log emitted on healthy stream:\n%s", got)
	}
}

func TestStreamBufferOverflow_ConcurrentProducersSingleStart(t *testing.T) {
	buf := captureSlogOverflow(t, slog.LevelInfo)
	c := newTestClient(t)
	startBaseline := Stats.StreamBufferOverflowsTotal.Load()

	const sid uint16 = 9999
	const producers = 5
	const sendsPerProducer = 300

	if _, err := c.RegisterStream(sid); err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	var wg sync.WaitGroup
	var startSignal atomic.Bool
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !startSignal.Load() {
			}
			for i := 0; i < sendsPerProducer; i++ {
				c.RouteToStream(sid, []byte{0xFF})
			}
		}()
	}
	startSignal.Store(true)
	wg.Wait()

	// Exactly ONE "started" log despite concurrent producers (mutex
	// serializes the first-drop detection).
	startedCount := strings.Count(buf.String(), `msg="stream buffer overflow started"`)
	if startedCount != 1 {
		t.Errorf("expected 1 WARN 'started' under concurrent producers, got %d", startedCount)
	}

	c.UnregisterStream(sid)
	endedCount := strings.Count(buf.String(), `msg="stream buffer overflow ended"`)
	if endedCount != 1 {
		t.Errorf("expected 1 INFO 'ended', got %d", endedCount)
	}
	// 5*300 = 1500 sends; first up-to-512 land in buffer, remainder
	// dropped. Exact split depends on goroutine scheduling — assert a
	// tight range rather than exact 988 to avoid flakes under -race or
	// heavy CI load while still catching real regressions.
	delta := Stats.StreamBufferOverflowsTotal.Load() - startBaseline
	if delta < 900 || delta > 1500 {
		t.Errorf("StreamBufferOverflowsTotal delta = %d, want in [900, 1500]", delta)
	}
}

func TestStreamBufferOverflow_CumulativeStatCounter(t *testing.T) {
	captureSlogOverflow(t, slog.LevelInfo)
	c := newTestClient(t)
	startBaseline := Stats.StreamBufferOverflowsTotal.Load()

	// Stream A: 30 drops.
	const sidA uint16 = 1001
	if _, err := c.RegisterStream(sidA); err != nil {
		t.Fatalf("RegisterStream A: %v", err)
	}
	for i := 0; i < 512+30; i++ {
		c.RouteToStream(sidA, []byte{0x01})
	}
	c.UnregisterStream(sidA)

	// Stream B: 50 drops.
	const sidB uint16 = 1002
	if _, err := c.RegisterStream(sidB); err != nil {
		t.Fatalf("RegisterStream B: %v", err)
	}
	for i := 0; i < 512+50; i++ {
		c.RouteToStream(sidB, []byte{0x02})
	}
	c.UnregisterStream(sidB)

	delta := Stats.StreamBufferOverflowsTotal.Load() - startBaseline
	if delta != 80 {
		t.Errorf("cumulative StreamBufferOverflowsTotal delta = %d, want 80", delta)
	}
}

func TestStreamBufferOverflow_UnregisterClearsState(t *testing.T) {
	buf := captureSlogOverflow(t, slog.LevelInfo)
	c := newTestClient(t)

	const sid uint16 = 4242
	// First lifecycle with overflow.
	if _, err := c.RegisterStream(sid); err != nil {
		t.Fatalf("RegisterStream 1: %v", err)
	}
	for i := 0; i < 512+10; i++ {
		c.RouteToStream(sid, []byte{0x00})
	}
	c.UnregisterStream(sid)

	endedCountAfterFirst := strings.Count(buf.String(), `msg="stream buffer overflow ended"`)
	if endedCountAfterFirst != 1 {
		t.Fatalf("expected 1 INFO 'ended' after first lifecycle, got %d", endedCountAfterFirst)
	}

	// Second lifecycle without overflow — state must have been cleared.
	if _, err := c.RegisterStream(sid); err != nil {
		t.Fatalf("RegisterStream 2: %v", err)
	}
	c.UnregisterStream(sid)

	endedCountAfterSecond := strings.Count(buf.String(), `msg="stream buffer overflow ended"`)
	if endedCountAfterSecond != endedCountAfterFirst {
		t.Errorf("unexpected 'ended' on second lifecycle (cleared state should suppress); count went from %d to %d",
			endedCountAfterFirst, endedCountAfterSecond)
	}
}

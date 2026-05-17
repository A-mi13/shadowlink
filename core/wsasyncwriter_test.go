package core

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeConnWriter implements WSConnWriter for tests with controllable latency and failure.
type fakeConnWriter struct {
	mu      sync.Mutex
	written [][]byte
	delay   time.Duration
	failAt  int // return error on N-th call (1-based; 0 = never)
	failErr error
	calls   atomic.Int32
}

func (f *fakeConnWriter) WriteMessage(messageType int, data []byte) error {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	n := f.calls.Add(1)
	if f.failAt > 0 && int(n) == f.failAt {
		return f.failErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	f.written = append(f.written, cp)
	return nil
}

func (f *fakeConnWriter) SetWriteDeadline(t time.Time) error { return nil }

func (f *fakeConnWriter) snapshot() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.written))
	copy(out, f.written)
	return out
}

// TestWSAsyncWriter_DecouplesProducersFromSlowConnection: 20 concurrent
// Enqueue calls must return nearly instantly even when the underlying
// conn.WriteMessage takes 50ms each. This is the symmetric root cause
// being fixed on both sides (server CONNECT_OK queued behind relay, client
// CONNECT queued behind SOCKS5 uplink).
func TestWSAsyncWriter_DecouplesProducersFromSlowConnection(t *testing.T) {
	conn := &fakeConnWriter{delay: 50 * time.Millisecond}
	w := NewWSAsyncWriter(conn, 256)
	go w.Run()
	defer w.Close()

	const producers = 20
	enqueueDone := make(chan time.Duration, producers)

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			err := w.Enqueue(websocket.BinaryMessage, []byte("payload"))
			require.NoError(t, err)
			enqueueDone <- time.Since(t0)
		}()
	}
	wg.Wait()
	enqueueElapsed := time.Since(start)
	close(enqueueDone)

	assert.Less(t, enqueueElapsed, 200*time.Millisecond,
		"Enqueue blocked on slow conn — async queue not working")

	for d := range enqueueDone {
		assert.Less(t, d, 100*time.Millisecond, "individual Enqueue blocked")
	}

	require.Eventually(t, func() bool {
		return conn.calls.Load() == producers
	}, 5*time.Second, 10*time.Millisecond, "writer did not drain queue")
}

// TestWSAsyncWriter_LastWriteUnixNano_TracksSuccess verifies the timestamp
// only ticks on successful writes — failed writes must not advance it, so
// the slot reader's diagnostic capture sees a stale (or zero) value when
// the conn was dead at the time of the read error.
func TestWSAsyncWriter_LastWriteUnixNano_TracksSuccess(t *testing.T) {
	conn := &fakeConnWriter{}
	w := NewWSAsyncWriter(conn, 16)
	go w.Run()
	defer w.Close()

	assert.Equal(t, int64(0), w.LastWriteUnixNano(), "before any write should be zero")

	require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte("hello")))
	// Wait on LastWriteUnixNano directly — the timestamp Store happens AFTER
	// fakeConnWriter increments its calls counter, so polling on calls would
	// be racy.
	require.Eventually(t, func() bool {
		return w.LastWriteUnixNano() > 0
	}, time.Second, 1*time.Millisecond)

	first := w.LastWriteUnixNano()

	time.Sleep(2 * time.Millisecond)
	require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte("world")))
	require.Eventually(t, func() bool {
		return w.LastWriteUnixNano() > first
	}, time.Second, 1*time.Millisecond)

	second := w.LastWriteUnixNano()
	assert.Greater(t, second, first, "second successful write should advance further")
}

// TestWSAsyncWriter_LastWriteUnixNano_FrozenOnFailure: when the underlying
// conn returns an error, the timestamp must NOT advance — a Run-exit-on-error
// is exactly the case the slot reader's diagnostic capture cares about
// (writer dead → likely middlebox-induced stall → log shows old timestamp →
// reviewer sees `last_write_age_ms` is large → CF/origin stall confirmed).
func TestWSAsyncWriter_LastWriteUnixNano_FrozenOnFailure(t *testing.T) {
	failErr := errors.New("simulated CF stall")
	conn := &fakeConnWriter{failAt: 2, failErr: failErr}
	w := NewWSAsyncWriter(conn, 16)
	runErr := make(chan error, 1)
	go func() { runErr <- w.Run() }()
	defer w.Close()

	require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte("ok-1")))
	require.Eventually(t, func() bool {
		return w.LastWriteUnixNano() > 0
	}, time.Second, 1*time.Millisecond)

	good := w.LastWriteUnixNano()

	// Second write fails — Run() exits.
	require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte("fail-2")))
	select {
	case err := <-runErr:
		require.ErrorIs(t, err, failErr)
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after underlying write error")
	}

	assert.Equal(t, good, w.LastWriteUnixNano(),
		"failed write must not advance lastWriteUnixNano")
}

func TestWSAsyncWriter_OrderingPreserved(t *testing.T) {
	conn := &fakeConnWriter{}
	w := NewWSAsyncWriter(conn, 64)
	go w.Run()
	defer w.Close()

	const n = 50
	for i := 0; i < n; i++ {
		require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte{byte(i)}))
	}

	require.Eventually(t, func() bool {
		return conn.calls.Load() == n
	}, 2*time.Second, 5*time.Millisecond)

	got := conn.snapshot()
	require.Len(t, got, n)
	for i := 0; i < n; i++ {
		assert.Equal(t, byte(i), got[i][0], "out of order at index %d", i)
	}
}

func TestWSAsyncWriter_PropagatesErrors(t *testing.T) {
	conn := &fakeConnWriter{
		failAt:  3,
		failErr: errors.New("simulated WS write failure"),
	}
	w := NewWSAsyncWriter(conn, 8)

	runDone := make(chan error, 1)
	go func() { runDone <- w.Run() }()

	require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte("a")))
	require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte("b")))
	require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte("c")))

	select {
	case err := <-runDone:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "simulated WS write failure")
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after underlying write error")
	}

	err := w.Enqueue(websocket.BinaryMessage, []byte("d"))
	assert.ErrorIs(t, err, ErrWSWriterClosed)
}

// TestWSAsyncWriter_ControlPriorityOverData verifies that control messages
// (EnqueueControl) are written before data messages (Enqueue) when both
// channels have pending frames. This is the core fix for CONNECT/FIN
// starvation under heavy data relay traffic.
func TestWSAsyncWriter_ControlPriorityOverData(t *testing.T) {
	// Slow connection: each write takes 10ms so messages accumulate in channels.
	conn := &fakeConnWriter{delay: 10 * time.Millisecond}
	w := NewWSAsyncWriter(conn, 64)

	// Fill data channel first (before Run starts).
	for i := 0; i < 20; i++ {
		require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte{0xDD, byte(i)}))
	}

	// Then add control messages.
	for i := 0; i < 5; i++ {
		require.NoError(t, w.EnqueueControl(websocket.BinaryMessage, []byte{0xCC, byte(i)}))
	}

	// Now start the writer — it should drain control first.
	go w.Run()
	defer w.Close()

	// Wait for all 25 messages to be written.
	require.Eventually(t, func() bool {
		return conn.calls.Load() == 25
	}, 5*time.Second, 5*time.Millisecond)

	got := conn.snapshot()
	require.Len(t, got, 25)

	// First 5 messages must be control (0xCC prefix).
	for i := 0; i < 5; i++ {
		assert.Equal(t, byte(0xCC), got[i][0],
			"message %d should be control (0xCC), got 0x%02X", i, got[i][0])
	}

	// Remaining 20 messages must be data (0xDD prefix).
	for i := 5; i < 25; i++ {
		assert.Equal(t, byte(0xDD), got[i][0],
			"message %d should be data (0xDD), got 0x%02X", i, got[i][0])
	}
}

// TestWSAsyncWriter_ControlPreemptsDataMidStream verifies that control
// messages arriving while data is being drained jump ahead of remaining
// data frames. Simulates the real scenario: 100 data goroutines writing
// while a new CONNECT arrives.
func TestWSAsyncWriter_ControlPreemptsDataMidStream(t *testing.T) {
	// 20ms per write — slow enough to let us enqueue control mid-drain.
	conn := &fakeConnWriter{delay: 20 * time.Millisecond}
	w := NewWSAsyncWriter(conn, 256)
	go w.Run()
	defer w.Close()

	// Enqueue 20 data messages.
	for i := 0; i < 20; i++ {
		require.NoError(t, w.Enqueue(websocket.BinaryMessage, []byte{0xDD, byte(i)}))
	}

	// Wait for a few data messages to drain (50ms → ~2 frames).
	time.Sleep(50 * time.Millisecond)

	// Now inject control message — should preempt remaining data.
	require.NoError(t, w.EnqueueControl(websocket.BinaryMessage, []byte{0xCC, 0x00}))

	// Wait for all to complete.
	require.Eventually(t, func() bool {
		return conn.calls.Load() == 21
	}, 5*time.Second, 5*time.Millisecond)

	got := conn.snapshot()
	require.Len(t, got, 21)

	// Find position of the control message.
	controlPos := -1
	for i, msg := range got {
		if msg[0] == 0xCC {
			controlPos = i
			break
		}
	}

	require.NotEqual(t, -1, controlPos, "control message not found in output")
	// Control message should NOT be last (position 20 = after all data).
	// It should appear within the first few positions after its injection.
	// With 20ms per write and 50ms sleep, ~2-3 data messages written before control.
	assert.Less(t, controlPos, 10,
		"control message at position %d — should preempt remaining data", controlPos)
}

// TestWSAsyncWriter_EnqueueControlClosedWriter verifies EnqueueControl
// returns ErrWSWriterClosed after the writer is closed.
func TestWSAsyncWriter_EnqueueControlClosedWriter(t *testing.T) {
	conn := &fakeConnWriter{}
	w := NewWSAsyncWriter(conn, 8)
	go w.Run()

	require.NoError(t, w.EnqueueControl(websocket.BinaryMessage, []byte("ctrl")))
	w.Close()

	time.Sleep(10 * time.Millisecond)

	err := w.EnqueueControl(websocket.BinaryMessage, []byte("after-close"))
	assert.ErrorIs(t, err, ErrWSWriterClosed)
}

func TestWSAsyncWriter_CloseUnblocksRun(t *testing.T) {
	conn := &fakeConnWriter{}
	w := NewWSAsyncWriter(conn, 8)

	runDone := make(chan error, 1)
	go func() { runDone <- w.Run() }()

	time.Sleep(10 * time.Millisecond)

	w.Close()

	select {
	case err := <-runDone:
		assert.NoError(t, err, "Run should return nil on graceful Close")
	case <-time.After(1 * time.Second):
		t.Fatal("Run did not return after Close")
	}

	w.Close() // idempotent
}

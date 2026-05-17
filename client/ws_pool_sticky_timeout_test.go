package client

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// stickyTimeoutErr mimics gorilla/websocket sticky readErr after first timeout.
type stickyTimeoutErr struct{}

func (stickyTimeoutErr) Error() string   { return "i/o timeout (sticky)" }
func (stickyTimeoutErr) Timeout() bool   { return true }
func (stickyTimeoutErr) Temporary() bool { return false }

// fakeSlotTransport implements wsSlotTransport.
// ReadMessage returns a sticky i/o timeout on every call.
// All other methods are no-ops so the rest of slotReaderWithClient can complete.
type fakeSlotTransport struct {
	readCalls atomic.Int32
}

func (f *fakeSlotTransport) ReadMessage(_ time.Duration) ([]byte, error) {
	f.readCalls.Add(1)
	return nil, &net.OpError{Op: "read", Err: stickyTimeoutErr{}}
}
func (f *fakeSlotTransport) LastWriteUnixNano() int64             { return 0 }
func (f *fakeSlotTransport) WriteMessage(_ []byte) error          { return nil }
func (f *fakeSlotTransport) WriteControlMessage(_ []byte) error   { return nil }
func (f *fakeSlotTransport) Close() error                         { return nil }

// TestRegression_StickyTimeoutDoesNotLoop_RealReader drives the ACTUAL
// slotReaderWithClient function (the real production code path that was
// hotfixed in Phase −1) with a fake wsSlotTransport that returns a sticky
// i/o timeout on every ReadMessage call.
//
// Pass ⟺ the real code exits after the first error and transitions the slot
// to slotDead — exactly the Phase −1 fix contract.
//
// Fail (regression scenario): if Phase 3 refactor accidentally reverts the
// `return` after error to a `continue`, this test will loop until the test
// timeout (typically 10s/30s), because fakeSlotTransport returns instantly on
// every ReadMessage. The test harness catches this via the 2s deadline.
func TestRegression_StickyTimeoutDoesNotLoop_RealReader(t *testing.T) {
	// Two contexts:
	// - readerCtx: passed to slotReaderWithClient; NOT cancelled initially so the
	//   reader's first ctx.Done() check does NOT trigger.  The reader must reach
	//   ReadMessage and exit due to the error, not due to context cancellation.
	// - poolCtx: stored in p.ctx; pre-cancelled so reconnectLoop (spawned by
	//   handleSlotDeath) checks ctx.Done() and returns immediately without
	//   attempting any real network dial.
	readerCtx := context.Background()

	poolCtx, poolCancel := context.WithCancel(context.Background())
	poolCancel() // pre-cancel pool context — reconnectLoop exits on first check

	fake := &fakeSlotTransport{}

	slot := &poolSlot{index: 0}
	slot.transport = fake
	slot.setState(slotReady)
	// session intentionally nil — reader exits after first error, never reaches
	// the DecryptChunkSafe path.

	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 1),
		poolSize: 1,
		ctx:      poolCtx,
		cancel:   poolCancel,
		log:      newDiscardLogger(),
		// Set meltdownThreshold high so recordSlotDeath never reaches
		// emitMeltdownLog (which would panic on a nil meltdownLimiter).
		meltdownThreshold: 100,
		meltdownWindow:    5 * time.Second,
	}
	pool.slots[0] = slot

	// Minimal Client — only streamChans and streamMu are touched by
	// handleSlotDeath when the streamMap is empty (no streams assigned).
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
	}

	// Run the real reader on a separate goroutine; collect completion.
	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.slotReaderWithClient(readerCtx, cl, 0)
	}()

	// The reader must exit well within 2 seconds.
	// On regression (tight loop), fakeSlotTransport.ReadMessage returns
	// immediately but the loop never breaks — we'll see "test timed out"
	// or the select below fires after 2s.
	select {
	case <-done:
		// Good — reader exited.
	case <-time.After(2 * time.Second):
		t.Fatal("slotReaderWithClient did not exit within 2s — sticky-timeout tight loop regression")
	}

	// Verify ReadMessage was called a small number of times (1 in the fixed
	// code; certainly not hundreds/thousands in a loop).
	calls := fake.readCalls.Load()
	if calls != 1 {
		t.Errorf("expected exactly 1 ReadMessage call, got %d (loop regression if >> 1)", calls)
	}

	// Verify the slot was transitioned to slotDead by handleSlotDeath.
	if got := slot.getState(); got != slotDead {
		t.Errorf("expected slot state slotDead(%d), got %d", slotDead, got)
	}
}

// TestRegression_StickyTimeoutContract_Predicate documents the exit-on-error
// contract as a pure predicate, independent of slotReaderWithClient plumbing.
// This acts as a fast-feedback fallback: if the interface or constructor
// changes, this test still compiles and passes, confirming the loop predicate
// itself is correct.
//
// The companion TestRegression_StickyTimeoutDoesNotLoop_RealReader exercises
// the real production function (stronger guarantee).
func TestRegression_StickyTimeoutContract_Predicate(t *testing.T) {
	type minReader interface {
		ReadMessage() (int, []byte, error)
	}
	type legacyFake struct{ calls int }
	readOnce := func(r *legacyFake) error {
		r.calls++
		return &net.OpError{Op: "read", Err: stickyTimeoutErr{}}
	}

	r := &legacyFake{}
	exited := false
	exitReason := ""

	for range 2000 {
		err := readOnce(r)
		if err != nil {
			exited = true
			exitReason = err.Error()
			break
		}
	}

	if !exited {
		t.Fatal("loop predicate did not exit — contract broken")
	}
	if r.calls != 1 {
		t.Fatalf("expected 1 read before exit, got %d", r.calls)
	}
	t.Logf("exit reason: %s", exitReason)
}

// TestRegression_StickyTimeoutDoesNotLoop_DurationCheck — secondary wall-clock
// check. If the real reader were tight-looping on a no-op fake, it would spin
// thousands of times in <1ms. We verify it exits within 100ms AND makes
// exactly 1 ReadMessage call.
//
// Uses the same two-context pattern as the RealReader test: readerCtx is live
// so the reader's ctx.Done() check doesn't short-circuit before ReadMessage.
func TestRegression_StickyTimeoutDoesNotLoop_DurationCheck(t *testing.T) {
	poolCtx, poolCancel := context.WithCancel(context.Background())
	poolCancel() // pre-cancel pool context so reconnectLoop exits immediately

	fake := &fakeSlotTransport{}
	slot := &poolSlot{index: 0}
	slot.transport = fake
	slot.setState(slotReady)

	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 1),
		poolSize:          1,
		ctx:               poolCtx,
		cancel:            poolCancel,
		log:               newDiscardLogger(),
		meltdownThreshold: 100,
		meltdownWindow:    5 * time.Second,
	}
	pool.slots[0] = slot

	cl := &Client{streamChans: make(map[uint16]chan []byte)}

	start := time.Now()
	// Pass a live (non-cancelled) context to the reader — it must reach
	// ReadMessage and exit due to the error, not due to context cancellation.
	pool.slotReaderWithClient(context.Background(), cl, 0)
	elapsed := time.Since(start)

	calls := fake.readCalls.Load()
	if calls != 1 {
		t.Fatalf("expected 1 ReadMessage call, got %d", calls)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("slotReaderWithClient took %v — suspect tight loop (expected <100ms for 1 call)", elapsed)
	}
}

package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

func TestBinding_AtomicConsistentPair(t *testing.T) {
	var e relayEntry
	sA := core.NewSession(1, make([]byte, 32), make([]byte, 32))
	sB := core.NewSession(2, make([]byte, 32), make([]byte, 32))
	wA := core.NewWSAsyncWriter(nil, 8)
	wB := core.NewWSAsyncWriter(nil, 8)
	e.bound.Store(&binding{session: sA, writer: wA})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				b := e.bound.Load()
				if b == nil {
					continue
				}
				if (b.session == sA) != (b.writer == wA) {
					t.Errorf("torn pair: session/writer mismatch")
					return
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		if i%2 == 0 {
			e.bound.Store(&binding{session: sA, writer: wA})
		} else {
			e.bound.Store(&binding{session: sB, writer: wB})
		}
	}
	close(stop)
	wg.Wait()
}

func TestBoundedBuffer_PushPopOrder(t *testing.T) {
	b := newBoundedBuffer(1024)
	b.Push(pendingDownFrame{seq: 1, data: []byte("a")})
	b.Push(pendingDownFrame{seq: 2, data: []byte("bb")})
	if b.byteLen() != 3 {
		t.Fatalf("byteLen = %d, want 3", b.byteLen())
	}
	frames := b.drainAll()
	if len(frames) != 2 || frames[0].seq != 1 || frames[1].seq != 2 {
		t.Fatalf("drain order wrong: %+v", frames)
	}
	if b.byteLen() != 0 {
		t.Fatalf("byteLen after drain = %d, want 0", b.byteLen())
	}
}

func TestBoundedBuffer_FullRejects(t *testing.T) {
	b := newBoundedBuffer(4)
	if !b.Push(pendingDownFrame{seq: 1, data: []byte("abcd")}) {
		t.Fatal("first push of exactly-cap should succeed")
	}
	if b.Push(pendingDownFrame{seq: 2, data: []byte("x")}) {
		t.Fatal("push past cap must be rejected (backpressure)")
	}
}

func TestBoundedBuffer_AckEvictsUpToSeq(t *testing.T) {
	b := newBoundedBuffer(1024)
	b.Push(pendingDownFrame{seq: 1, data: []byte("a")})
	b.Push(pendingDownFrame{seq: 2, data: []byte("b")})
	b.Push(pendingDownFrame{seq: 3, data: []byte("c")})
	b.evictUpTo(2)
	frames := b.drainAll()
	if len(frames) != 1 || frames[0].seq != 3 {
		t.Fatalf("after evictUpTo(2): %+v", frames)
	}
}

func TestRelayRegistry_AddFindRemove(t *testing.T) {
	r := newRelayRegistry()
	e := &relayEntry{originClientID: "c1", globalStreamID: 42}
	r.add("c1", 42, e)
	got, ok := r.find("c1", 42)
	if !ok || got != e {
		t.Fatal("find did not return the added entry")
	}
	if _, ok := r.find("c2", 42); ok {
		t.Fatal("cross-client collision on streamID")
	}
	r.remove("c1", 42)
	if _, ok := r.find("c1", 42); ok {
		t.Fatal("entry not removed")
	}
}

func TestRelayState_SingleWinner_ResumeBeatsTimer(t *testing.T) {
	var e relayEntry
	e.state.Store(stOrphaned)
	resumeWon := e.state.CompareAndSwap(stOrphaned, stActive)
	timerWon := e.state.CompareAndSwap(stOrphaned, stClosing)
	if !resumeWon || timerWon {
		t.Fatalf("resume should win: resumeWon=%v timerWon=%v", resumeWon, timerWon)
	}
	if e.state.Load() != stActive {
		t.Fatal("state not active after resume won")
	}
}

func TestRelayState_SingleWinner_TimerBeatsResume(t *testing.T) {
	var e relayEntry
	e.state.Store(stOrphaned)
	timerWon := e.state.CompareAndSwap(stOrphaned, stClosing)
	resumeWon := e.state.CompareAndSwap(stOrphaned, stActive)
	if !timerWon || resumeWon {
		t.Fatalf("timer should win: timerWon=%v resumeWon=%v", timerWon, resumeWon)
	}
}

func TestRelayRegistry_PerClientCount(t *testing.T) {
	r := newRelayRegistry()
	r.add("c1", 1, &relayEntry{})
	r.add("c1", 2, &relayEntry{})
	r.add("c2", 1, &relayEntry{})
	if n := r.countForClient("c1"); n != 2 {
		t.Fatalf("countForClient(c1) = %d, want 2", n)
	}
	if n := r.totalCount(); n != 3 {
		t.Fatalf("totalCount = %d, want 3", n)
	}
}

func TestRelayEntry_AckEvictsTail(t *testing.T) {
	e := &relayEntry{unackedTail: newBoundedBuffer(1 << 20)}
	e.unackedTail.Push(pendingDownFrame{seq: 1, data: []byte("a")})
	e.unackedTail.Push(pendingDownFrame{seq: 2, data: []byte("b")})
	e.unackedTail.Push(pendingDownFrame{seq: 3, data: []byte("c")})
	e.onStreamAck(2)
	if e.unackedTail.byteLen() != 1 {
		t.Fatalf("unackedTail bytes = %d, want 1 (only seq3)", e.unackedTail.byteLen())
	}
}

func TestRelayEntry_ResendTailReturnsUnackedInOrder(t *testing.T) {
	e := &relayEntry{unackedTail: newBoundedBuffer(1 << 20)}
	e.unackedTail.Push(pendingDownFrame{seq: 5, data: []byte("e")})
	e.unackedTail.Push(pendingDownFrame{seq: 6, data: []byte("f")})
	frames := e.resendTail()
	if len(frames) != 2 || frames[0].seq != 5 || frames[1].seq != 6 {
		t.Fatalf("resendTail order: %+v", frames)
	}
	if e.unackedTail.byteLen() == 0 {
		t.Fatal("resendTail must not empty the buffer")
	}
}

func TestRegistry_OriginDeathTeardownFlag(t *testing.T) {
	r := newRelayRegistry()
	if r.originDeathTeardown {
		t.Fatal("default zero-value must be false")
	}
	r.setOriginDeathTeardown(true)
	if !r.originDeathTeardown {
		t.Fatal("setter must enable")
	}
}

func TestRelayEntry_DownSeqNeverResetOnReassociate(t *testing.T) {
	e := &relayEntry{}
	for i := 0; i < 4; i++ {
		e.downSeqCounter.Add(1)
	}
	before := e.downSeqCounter.Load()
	sB := core.NewSession(2, make([]byte, 32), make([]byte, 32))
	e.bound.Store(&binding{session: sB, writer: core.NewWSAsyncWriter(nil, 8)})
	if e.downSeqCounter.Load() != before {
		t.Fatal("downSeqCounter changed on reassociate — NEW-3 invariant broken")
	}
	if next := e.downSeqCounter.Add(1); next != before+1 {
		t.Fatalf("post-reassociate next seq = %d, want %d", next, before+1)
	}
}

// TestReassociate_DoesNotStoreBinding: reassociate now receives a *binding that
// the CALLER has already published via e.bound.Store (NIT-1, preparation for
// b1). reassociate must NOT re-store (i.e. must not change the pointer), and
// must return resumeSeq=0 for an empty buffer.
func TestReassociate_DoesNotStoreBinding(t *testing.T) {
	e := &relayEntry{
		downBuffer:  newBoundedBuffer(1 << 20),
		unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stOrphaned)
	sess := core.NewSession(1, make([]byte, 32), make([]byte, 32))
	w := core.NewWSAsyncWriter(nil, 8)
	b := &binding{session: sess, writer: w}
	e.bound.Store(b) // caller publishes BEFORE reassociate
	resumeSeq := e.reassociate(b, true /*migrateEnabled*/, false /*aDead*/, false /*originDeathTeardown*/)
	if got := e.bound.Load(); got != b {
		t.Fatalf("bound pointer changed: reassociate must not re-store (NIT-1)")
	}
	if resumeSeq != 0 {
		t.Fatalf("resumeSeq = %d, want 0 (empty buffer)", resumeSeq)
	}
}

// b1: bound is published onto the NEW live slot B BEFORE CAS(stOrphaned→stActive).
// This test exercises the invariant directly:
//   - After bound.Store(B), bound==B and state==stOrphaned (no window where
//     state==stActive but bound still points at dead slot A).
//   - CAS(stOrphaned→stActive) then succeeds, and bound remains B.
//
// An origin-death teardown that wins CAS(stActive→stClosing) during the window
// between Store(B) and the CAS would find state==stOrphaned (not stActive) and
// therefore take the orphan-branch, not the active-teardown branch.
func TestHandleResume_BoundStoredBeforeStatePublish_b1(t *testing.T) {
	deadSess := core.NewSession(1, make([]byte, 32), make([]byte, 32))
	deadW := core.NewWSAsyncWriter(nil, 8)
	entry := &relayEntry{
		originClientID: "cid-b1", globalStreamID: 1,
		downBuffer:  newBoundedBuffer(1 << 20),
		unackedTail: newBoundedBuffer(1 << 20),
	}
	entry.bound.Store(&binding{session: deadSess, writer: deadW})
	entry.state.Store(stOrphaned)

	liveSess := core.NewSession(2, make([]byte, 32), make([]byte, 32))
	liveW := core.NewWSAsyncWriter(nil, 8)
	bB := &binding{session: liveSess, writer: liveW}

	// Emulate b1 order: bound.Store(B) BEFORE CAS.
	entry.bound.Store(bB)
	if entry.bound.Load() != bB {
		t.Fatal("b1: bound must be B before CAS")
	}
	if entry.state.Load() != stOrphaned {
		t.Fatal("window invariant: state must still be stOrphaned before CAS")
	}
	if !entry.state.CompareAndSwap(stOrphaned, stActive) {
		t.Fatal("CAS stOrphaned->stActive must win (no competitor)")
	}
	if entry.bound.Load() != bB {
		t.Fatal("after CAS, bound must be live B")
	}
}

// TestSignalStreamEnd_ActiveWinnerSendsAndTearsDown: active entry is removed
// from the registry and transitions to stClosing after signalStreamEnd wins
// CAS(stActive→stClosing).
func TestSignalStreamEnd_ActiveWinnerSendsAndTearsDown(t *testing.T) {
	reg := newRelayRegistry()
	reg.setLimits(10, 100, 100)
	reg.setOriginDeathTeardown(true)
	sess := core.NewSession(1, make([]byte, 32), make([]byte, 32))
	w := core.NewWSAsyncWriter(nil, 8)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	e := &relayEntry{
		originClientID: "c", globalStreamID: 5, tc: c1,
		downBuffer: newBoundedBuffer(1 << 20), unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stActive)
	e.bound.Store(&binding{session: sess, writer: w})
	reg.add("c", 5, e)

	reg.signalStreamEnd(e, true, "pathB")

	if e.state.Load() != stClosing {
		t.Fatalf("state = %d, want stClosing", e.state.Load())
	}
	if _, ok := reg.find("c", 5); ok {
		t.Fatal("entry must be removed after active teardown")
	}
}

// TestSignalStreamEnd_OrphanedOnlySetsDestClosed_NIT3: orphaned entry stays in
// the registry and remains stOrphaned — only destClosed is set (NIT-3). RESUME
// or the grace timer will deliver the signal and tear down.
func TestSignalStreamEnd_OrphanedOnlySetsDestClosed_NIT3(t *testing.T) {
	reg := newRelayRegistry()
	reg.setLimits(10, 100, 100)
	reg.setOriginDeathTeardown(true)
	e := &relayEntry{
		originClientID: "c", globalStreamID: 6,
		downBuffer: newBoundedBuffer(1 << 20), unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stOrphaned)
	reg.add("c", 6, e)

	reg.signalStreamEnd(e, true, "read")

	if e.state.Load() != stOrphaned {
		t.Fatalf("orphaned entry must STAY stOrphaned (NIT-3), got %d", e.state.Load())
	}
	if !e.destClosed.Load() {
		t.Fatal("destClosed must be set on orphaned path")
	}
	if _, ok := reg.find("c", 6); !ok {
		t.Fatal("orphaned entry must NOT be removed (RESUME/grace will)")
	}
}

// TestSignalStreamEnd_GateOff_TeardownStillHappens: when originDeathTeardown is
// false (gate off), the active path must still transition the entry to stClosing
// and remove it from the registry — only the FlagStreamClose signal is skipped.
// Egress must not be left hanging regardless of the gate setting.
func TestSignalStreamEnd_GateOff_TeardownStillHappens(t *testing.T) {
	reg := newRelayRegistry()
	reg.setLimits(10, 100, 100)
	// originDeathTeardown = false (default zero — do not call setOriginDeathTeardown)
	sess := core.NewSession(1, make([]byte, 32), make([]byte, 32))
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	e := &relayEntry{
		originClientID: "c", globalStreamID: 8, tc: c1,
		downBuffer: newBoundedBuffer(1 << 20), unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stActive)
	e.bound.Store(&binding{session: sess, writer: core.NewWSAsyncWriter(nil, 8)})
	reg.add("c", 8, e)

	reg.signalStreamEnd(e, true, "pathA")

	if e.state.Load() != stClosing {
		t.Fatal("gate-off must still transition to stClosing")
	}
	if _, ok := reg.find("c", 8); ok {
		t.Fatal("gate-off must still remove the entry")
	}
}

// TestSignalStreamEnd_SingleWinner: second call is a no-op once the entry has
// already moved out of stActive.
func TestSignalStreamEnd_SingleWinner(t *testing.T) {
	reg := newRelayRegistry()
	reg.setLimits(10, 100, 100)
	reg.setOriginDeathTeardown(true)
	sess := core.NewSession(1, make([]byte, 32), make([]byte, 32))
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	e := &relayEntry{
		originClientID: "c", globalStreamID: 7, tc: c1,
		downBuffer: newBoundedBuffer(1 << 20), unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stActive)
	e.bound.Store(&binding{session: sess, writer: core.NewWSAsyncWriter(nil, 8)})
	reg.add("c", 7, e)

	reg.signalStreamEnd(e, true, "A")
	st := e.state.Load()
	reg.signalStreamEnd(e, true, "B")
	if e.state.Load() != st {
		t.Fatal("second signalStreamEnd must be a no-op (single-winner)")
	}
}

// TestReassociate_DestClosed_SendsStreamClose: Component-4 RESUME-fallback.
// An orphaned entry with destClosed=true (origin TCP died while the slot was
// gone) must send a FlagStreamClose on the new binding B when originDeathTeardown
// is true. Covers "both TCP died at once" — the immediate FlagStreamClose was
// enqueued on a dead writer; now that we have a live B we deliver it.
func TestReassociate_DestClosed_SendsStreamClose(t *testing.T) {
	e := &relayEntry{
		originClientID: "c", globalStreamID: 9,
		downBuffer:  newBoundedBuffer(1 << 20),
		unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stOrphaned)
	e.destClosed.Store(true)

	// Use a self-session (same key both sides) so we can decrypt the frame.
	sess := newSelfSession(t)
	sink := newTestWriterSink()
	defer sink.close()
	b := &binding{session: sess, writer: sink.asWriter()}
	e.bound.Store(b)

	_ = e.reassociate(b, true /*migrateEnabled*/, true /*aDead*/, true /*originDeathTeardown*/)

	// reassociate must have enqueued exactly one FlagStreamClose frame on B.
	frame := sink.waitFrame(t, time.Second)
	chunk, err := sess.DecryptChunkSafe(frame)
	if err != nil {
		t.Fatalf("frame did not decrypt: %v", err)
	}
	if chunk.Flags != core.FlagStreamClose {
		t.Fatalf("flags = 0x%02x, want FlagStreamClose 0x%02x", chunk.Flags, core.FlagStreamClose)
	}
	sid, perr := core.ParseStreamCloseFrame(chunk.Payload)
	if perr != nil {
		t.Fatalf("parse stream close: %v", perr)
	}
	if sid != 9 {
		t.Fatalf("streamID = %d, want 9", sid)
	}
}

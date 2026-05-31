package server

import (
	"sync"
	"testing"

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

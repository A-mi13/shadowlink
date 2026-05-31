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

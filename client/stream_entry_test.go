package client

import (
	"testing"
	"time"
)

func TestNewStreamEntry_StampsLastWriteNs(t *testing.T) {
	before := time.Now().UnixNano()
	e := newStreamEntry(5)
	after := time.Now().UnixNano()

	if e.slotIdx != 5 {
		t.Errorf("slotIdx = %d, want 5", e.slotIdx)
	}
	got := e.lastWriteNs.Load()
	if got < before || got > after {
		t.Errorf("lastWriteNs = %d, want in [%d, %d]", got, before, after)
	}
}

func TestStreamEntry_LastWriteNsAtomic(t *testing.T) {
	e := newStreamEntry(0)
	const N = 1000
	done := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			e.lastWriteNs.Store(time.Now().UnixNano())
			done <- struct{}{}
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
	// Final read should be non-zero and recent.
	if e.lastWriteNs.Load() == 0 {
		t.Error("lastWriteNs should be non-zero after concurrent writes")
	}
}

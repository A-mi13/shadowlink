package client

import (
	"sync"
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

// snapshotTestHarness builds a minimal pool with just a streamMap
// populated with entries at controlled ages, enough to drive snapshot
// tests without spinning up real slots.
type snapshotTestHarness struct {
	pool *WSPoolTransport
}

func newSnapshotHarness() *snapshotTestHarness {
	return &snapshotTestHarness{
		pool: &WSPoolTransport{
			streamMap: sync.Map{},
		},
	}
}

func (h *snapshotTestHarness) put(streamID uint16, slotIdx int, age time.Duration) {
	e := newStreamEntry(slotIdx)
	e.lastWriteNs.Store(time.Now().Add(-age).UnixNano())
	h.pool.streamMap.Store(streamID, e)
}

func TestSnapshotDrainStreams_Empty(t *testing.T) {
	h := newSnapshotHarness()
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 0 || snap.idleAge30sCount != 0 || snap.activeCount != 0 {
		t.Errorf("empty snapshot = %+v, want zero values", snap)
	}
}

func TestSnapshotDrainStreams_SingleActive(t *testing.T) {
	h := newSnapshotHarness()
	h.put(42, 5, 1*time.Second)
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 1 || snap.activeCount != 1 || snap.idleAge30sCount != 0 {
		t.Errorf("single-active snapshot = %+v, want total=1 active=1 idle=0", snap)
	}
	if snap.maxIdleAgeMs < 800 || snap.maxIdleAgeMs > 1200 {
		t.Errorf("maxIdleAgeMs = %d, want ≈1000ms", snap.maxIdleAgeMs)
	}
}

func TestSnapshotDrainStreams_SingleIdle(t *testing.T) {
	h := newSnapshotHarness()
	h.put(42, 5, 60*time.Second)
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 1 || snap.idleAge30sCount != 1 || snap.activeCount != 0 {
		t.Errorf("single-idle snapshot = %+v, want total=1 idle=1 active=0", snap)
	}
}

// TestSnapshotDrainStreams_BimodalActivePlusIdle — the smoking-gun shape
// for hypothesis H1: one active heartbeat-stream + one idle stream attached
// to the same slot.
func TestSnapshotDrainStreams_BimodalActivePlusIdle(t *testing.T) {
	h := newSnapshotHarness()
	h.put(42, 5, 1*time.Second)
	h.put(43, 5, 60*time.Second)
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 2 || snap.activeCount != 1 || snap.idleAge30sCount != 1 {
		t.Errorf("bimodal snapshot = %+v, want total=2 active=1 idle=1", snap)
	}
	delta := snap.maxIdleAgeMs - snap.minIdleAgeMs
	if delta < 50000 {
		t.Errorf("max-min delta = %d ms, want >50000 (bimodal shape)", delta)
	}
}

func TestSnapshotDrainStreams_OnlyOurSlot(t *testing.T) {
	h := newSnapshotHarness()
	h.put(10, 0, 1*time.Second)
	h.put(11, 1, 60*time.Second)
	h.put(12, 5, 1*time.Second)
	h.put(13, 5, 60*time.Second)
	h.put(14, 5, 5*time.Second)
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 3 {
		t.Errorf("filtered total = %d, want 3 (only slot=5 entries)", snap.total)
	}
}

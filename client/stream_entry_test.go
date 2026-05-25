package client

import (
	"runtime"
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
	if snap.maxStreamAgeMs < 800 || snap.maxStreamAgeMs > 1200 {
		t.Errorf("maxStreamAgeMs = %d, want ≈1000ms", snap.maxStreamAgeMs)
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
	delta := snap.maxStreamAgeMs - snap.minStreamAgeMs
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

func TestAllStreamsIdle_Empty(t *testing.T) {
	h := newSnapshotHarness()
	if allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("empty streamMap should return false (no streams to be 'all idle')")
	}
}

func TestAllStreamsIdle_AllActive(t *testing.T) {
	h := newSnapshotHarness()
	h.put(1, 5, 1*time.Second)
	h.put(2, 5, 2*time.Second)
	h.put(3, 5, 5*time.Second)
	if allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("3 active streams should return false")
	}
}

func TestAllStreamsIdle_AllIdle(t *testing.T) {
	h := newSnapshotHarness()
	h.put(1, 5, 60*time.Second)
	h.put(2, 5, 45*time.Second)
	h.put(3, 5, 35*time.Second)
	if !allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("3 idle streams (all >30s) should return true")
	}
}

// TestAllStreamsIdle_BimodalSmokingGun — exactly the canary case for H1:
// 1 active heartbeat stream + 1 idle stream on same slot. The whole
// reason Step 2 exists. Must return false (active stream holds slot).
func TestAllStreamsIdle_BimodalSmokingGun(t *testing.T) {
	h := newSnapshotHarness()
	h.put(1, 5, 1*time.Second)   // active heartbeat
	h.put(2, 5, 60*time.Second)  // idle
	if allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("bimodal (1 active + 1 idle) should return false")
	}
}

func TestAllStreamsIdle_OnlyOurSlot(t *testing.T) {
	h := newSnapshotHarness()
	// other slots — active and idle, irrelevant to our scan
	h.put(10, 0, 1*time.Second)
	h.put(11, 1, 60*time.Second)
	// our slot 5 — all idle
	h.put(12, 5, 35*time.Second)
	h.put(13, 5, 40*time.Second)
	if !allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("should return true (only slot=5 streams considered, both idle)")
	}
}

// TestAllStreamsIdle_ExactlyAtThreshold — boundary: age == threshold
// (with 5ms safety margin for time.Now() jitter). The check is `age < threshold`,
// so an entry at >= threshold is counted as idle.
func TestAllStreamsIdle_ExactlyAtThreshold(t *testing.T) {
	h := newSnapshotHarness()
	// Stamp slightly older than threshold to avoid race with time.Now()
	// inside allStreamsIdle.
	h.put(1, 5, 30*time.Second+5*time.Millisecond)
	if !allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("stream at age >= threshold should count as idle")
	}
}

// TestAllStreamsIdle_ConcurrentReleaseStream — regression bound for
// R2-H2 fix. Spawns ReleaseStream-like loop concurrent with allStreamsIdle
// scan, asserts no panic. Validates that the new function survives
// concurrent map mutation.
func TestAllStreamsIdle_ConcurrentReleaseStream(t *testing.T) {
	p := &WSPoolTransport{streamMap: sync.Map{}}
	// Seed slot 5 with 10 idle streams.
	for sid := uint16(1); sid <= 10; sid++ {
		e := newStreamEntry(5)
		e.lastWriteNs.Store(time.Now().Add(-60 * time.Second).UnixNano())
		p.streamMap.Store(sid, e)
	}

	// Concurrent Delete + scan.
	done := make(chan struct{})
	go func() {
		for sid := uint16(1); sid <= 10; sid++ {
			p.streamMap.Delete(sid)
			runtime.Gosched()
		}
		close(done)
	}()

	// Spin scans during deletions. No panic, no incorrect behavior.
	for {
		select {
		case <-done:
			return
		default:
			_ = allStreamsIdle(p, 5, 30*time.Second, time.Now())
		}
	}
}

// TestAllStreamsIdle_ConcurrentAssignStream — race regression: scan
// while new entries are being added. Fresh entries stamp now → active →
// conservative (allStreamsIdle returns false). Asserts no panic and
// no false-positive idle.
func TestAllStreamsIdle_ConcurrentAssignStream(t *testing.T) {
	p := &WSPoolTransport{streamMap: sync.Map{}}
	// Seed one idle stream so map is non-empty.
	e := newStreamEntry(5)
	e.lastWriteNs.Store(time.Now().Add(-60 * time.Second).UnixNano())
	p.streamMap.Store(uint16(1), e)

	done := make(chan struct{})
	go func() {
		for sid := uint16(2); sid <= 20; sid++ {
			p.streamMap.Store(sid, newStreamEntry(5))
			runtime.Gosched()
		}
		close(done)
	}()

	// During Add — fresh entries are active, so allStreamsIdle must
	// return false (or true only if the goroutine hasn't started yet).
	// We just assert no panic. After done, all new entries are < 30s
	// old → still active → still false.
	for {
		select {
		case <-done:
			if allStreamsIdle(p, 5, 30*time.Second, time.Now()) {
				t.Error("after concurrent AssignStream, fresh entries should keep result false")
			}
			return
		default:
			_ = allStreamsIdle(p, 5, 30*time.Second, time.Now())
		}
	}
}

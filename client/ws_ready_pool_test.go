package client

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise WSReadyPool's channel/state logic without spinning up
// a real server. Integration tests (real handshake + upgrade) live alongside
// the main end-to-end suite — here we want fast, deterministic coverage of
// the parts that aren't bound to network IO.

func newTestReadyPool(t *testing.T, size int) *WSReadyPool {
	t.Helper()
	// nil client is fine as long as we never call Start() (worker/keepalive
	// are the only paths that touch cl).
	p := NewWSReadyPool(nil, WSReadyPoolConfig{
		Size:              size,
		ServerAddr:        "127.0.0.1:0",
		KeepaliveInterval: time.Hour, // never fires during test
		MaxIdleAge:        time.Hour,
	})
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestWSReadyPool_AcquireContextCancel(t *testing.T) {
	p := newTestReadyPool(t, 4)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Acquire(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestWSReadyPool_AcquirePoolClosed(t *testing.T) {
	p := newTestReadyPool(t, 4)
	_ = p.Close()

	ctx := context.Background()
	_, err := p.Acquire(ctx)
	assert.Error(t, err)
}

func TestWSReadyPool_AcquireSkipsBroken(t *testing.T) {
	p := newTestReadyPool(t, 4)

	broken := &pooledWS{stopCh: make(chan struct{})}
	broken.broken.Store(true)

	good := &pooledWS{stopCh: make(chan struct{})}

	p.ready <- broken
	p.ready <- good

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	wst, err := p.Acquire(ctx)
	require.NoError(t, err)
	assert.Nil(t, wst) // we didn't attach a real transport to `good`

	// broken + good both consumed; the broken entry's stop should have run.
	select {
	case <-broken.stopCh:
	default:
		t.Fatal("broken pooledWS.stopCh should have been closed by Acquire")
	}

	got, _, _ := p.Stats()
	assert.Equal(t, int64(0), got, "created counter only increments in worker")
	_, acquired, _ := p.Stats()
	assert.Equal(t, int64(1), acquired)
}

func TestWSReadyPool_CloseDrainsReadyChannel(t *testing.T) {
	p := newTestReadyPool(t, 4)

	// Queue a couple of entries and ensure Close doesn't leave them leaking.
	// We don't attach real WebSocketTransports — Close handles nil wst.
	p.ready <- &pooledWS{stopCh: make(chan struct{})}
	p.ready <- &pooledWS{stopCh: make(chan struct{})}
	require.Equal(t, 2, p.Ready())

	require.NoError(t, p.Close())
	assert.Equal(t, 0, p.Ready())

	// Close is idempotent from the consumer's perspective.
	assert.NoError(t, p.Close())
}

func TestWSReadyPool_DefaultsApplied(t *testing.T) {
	p := NewWSReadyPool(nil, WSReadyPoolConfig{})
	t.Cleanup(func() { _ = p.Close() })

	assert.Equal(t, 6, p.cfg.Size)
	assert.Equal(t, 25*time.Second, p.cfg.KeepaliveInterval)
	assert.Equal(t, 60*time.Second, p.cfg.MaxIdleAge)
	assert.Equal(t, 300*time.Millisecond, p.cfg.StaggerDelay)
	assert.Equal(t, 6, cap(p.ready))
}

func TestWSReadyPool_StopIdempotent(t *testing.T) {
	pw := &pooledWS{stopCh: make(chan struct{})}

	pw.stop()
	pw.stop() // double-close would panic without stopOnce

	select {
	case <-pw.stopCh:
	default:
		t.Fatal("stopCh not closed after pw.stop()")
	}
}

// --- phaseCoordinator tests --------------------------------------------------

func TestPhaseCoordinator_OrderingRequireDone(t *testing.T) {
	phases := []WarmupPhase{
		{Slots: []int{0}, Delay: 0, RequireDone: true},
		{Slots: []int{1, 2}, Delay: 0, RequireDone: true},
	}
	pc := newPhaseCoordinator(phases)
	ctx := context.Background()
	// phase 1 should not start until phase 0 done
	go func() {
		time.Sleep(50 * time.Millisecond)
		pc.MarkSlotReady(0) // closes done[0]
	}()
	start := time.Now()
	if err := pc.WaitPrior(ctx, 1); err != nil {
		t.Fatalf("WaitPrior returned error: %v", err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Error("WaitPrior should have blocked ≥ 40ms")
	}
}

func TestPhaseCoordinator_NotRequireDoneOpensImmediately(t *testing.T) {
	phases := []WarmupPhase{
		{Slots: []int{0, 1}, Delay: 0, RequireDone: false},
	}
	pc := newPhaseCoordinator(phases)
	pc.MarkSlotReady(0)
	select {
	case <-pc.done[0]:
		// good — first slot ready closed done immediately
	default:
		t.Fatal("RequireDone=false should close phase done immediately on first slot")
	}
}

func TestEffectiveWarmup_Default6(t *testing.T) {
	c := WSReadyPoolConfig{Size: 6}
	w := c.effectiveWarmup()
	if len(w) != 3 {
		t.Fatalf("want 3 phases for size=6, got %d", len(w))
	}
	if !reflect.DeepEqual(w[0].Slots, []int{0}) {
		t.Errorf("phase 0 slots: got %v, want [0]", w[0].Slots)
	}
	if !reflect.DeepEqual(w[1].Slots, []int{1, 2}) {
		t.Errorf("phase 1 slots: got %v, want [1 2]", w[1].Slots)
	}
	if !reflect.DeepEqual(w[2].Slots, []int{3, 4, 5}) {
		t.Errorf("phase 2 slots: got %v, want [3 4 5]", w[2].Slots)
	}
	// verify RequireDone values
	if !w[0].RequireDone {
		t.Error("phase 0: want RequireDone=true")
	}
	if !w[1].RequireDone {
		t.Error("phase 1: want RequireDone=true")
	}
	if w[2].RequireDone {
		t.Error("phase 2 (tail): want RequireDone=false")
	}
}

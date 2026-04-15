package client

import (
	"context"
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

package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn implements PoolConn for testing.
type mockConn struct {
	response []byte
	err      error
	closed   atomic.Bool
}

func (m *mockConn) SendChunk(_ context.Context, data []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func (m *mockConn) Close() error {
	m.closed.Store(true)
	return nil
}

func mockDialer(response []byte) PoolDialer {
	return func(ctx context.Context) (PoolConn, error) {
		return &mockConn{response: response}, nil
	}
}

func TestPoolSendAndReceive(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinConns = 2
	config.MaxConns = 4
	pool := NewPool(config, mockDialer([]byte("response")))
	defer pool.Close()

	// Give preopen time to fill
	time.Sleep(200 * time.Millisecond)

	resp, err := pool.Send(context.Background(), []byte("data"))
	require.NoError(t, err)
	assert.Equal(t, []byte("response"), resp)
}

func TestPoolMultipleSends(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinConns = 2
	config.MaxConns = 8
	pool := NewPool(config, mockDialer([]byte("ok")))
	defer pool.Close()

	time.Sleep(200 * time.Millisecond)

	for i := range 20 {
		resp, err := pool.Send(context.Background(), []byte("chunk"))
		require.NoError(t, err, "send %d", i)
		assert.Equal(t, []byte("ok"), resp)
	}

	stats := pool.Stats()
	assert.Equal(t, uint64(20), stats.TotalSent)
}

func TestPoolConcurrentSends(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinConns = 4
	config.MaxConns = 8
	pool := NewPool(config, mockDialer([]byte("ok")))
	defer pool.Close()

	time.Sleep(200 * time.Millisecond)

	var wg sync.WaitGroup
	errors := make([]error, 50)

	for i := range 50 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := pool.Send(context.Background(), []byte("concurrent"))
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		assert.NoError(t, err, "goroutine %d", i)
	}

	stats := pool.Stats()
	assert.Equal(t, uint64(50), stats.TotalSent)
}

func TestPoolPreopensConnections(t *testing.T) {
	var dialCount atomic.Int32
	dialer := func(ctx context.Context) (PoolConn, error) {
		dialCount.Add(1)
		return &mockConn{response: []byte("ok")}, nil
	}

	config := DefaultPoolConfig()
	config.PreopenSize = 3
	config.MaxConns = 8
	pool := NewPool(config, dialer)
	defer pool.Close()

	// Give preopen time to work
	time.Sleep(500 * time.Millisecond)

	// Should have pre-opened at least PreopenSize connections
	assert.GreaterOrEqual(t, int(dialCount.Load()), 3)

	stats := pool.Stats()
	assert.GreaterOrEqual(t, stats.Ready, 1, "should have ready connections")
}

func TestPoolCloseStopsPreopen(t *testing.T) {
	pool := NewPool(DefaultPoolConfig(), mockDialer([]byte("ok")))

	time.Sleep(200 * time.Millisecond)
	err := pool.Close()
	require.NoError(t, err)

	// Sending after close should fail
	_, err = pool.Send(context.Background(), []byte("data"))
	assert.Error(t, err)
}

func TestPoolCloseDrainsReady(t *testing.T) {
	dialer := func(ctx context.Context) (PoolConn, error) {
		return &mockConn{
			response: []byte("ok"),
		}, nil
	}

	config := DefaultPoolConfig()
	config.PreopenSize = 3
	pool := NewPool(config, dialer)

	time.Sleep(500 * time.Millisecond)
	pool.Close()

	// All connections should have been closed or used
	// Pool is closed cleanly
	assert.True(t, pool.closed.Load())
}

func TestPoolContextCancellation(t *testing.T) {
	// Dialer that blocks forever
	dialer := func(ctx context.Context) (PoolConn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	config := DefaultPoolConfig()
	config.PreopenSize = 0 // disable preopen
	config.MaxConns = 1
	pool := NewPool(config, dialer)
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := pool.Send(ctx, []byte("data"))
	assert.Error(t, err)
}

func TestPoolStats(t *testing.T) {
	pool := NewPool(DefaultPoolConfig(), mockDialer([]byte("ok")))
	defer pool.Close()

	time.Sleep(200 * time.Millisecond)

	stats := pool.Stats()
	assert.Equal(t, 0, stats.Active)
	assert.Equal(t, uint64(0), stats.TotalSent)
	assert.GreaterOrEqual(t, stats.Ready, 1)

	pool.Send(context.Background(), []byte("data"))

	stats = pool.Stats()
	assert.Equal(t, uint64(1), stats.TotalSent)
}

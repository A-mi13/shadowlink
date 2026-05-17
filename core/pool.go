package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// PoolConfig controls the adaptive connection pool.
type PoolConfig struct {
	MinConns    int           // minimum connections to maintain (default 4)
	MaxConns    int           // maximum connections allowed (default 16)
	PreopenSize int           // connections to open ahead of time (default 2)
	ChunkSize   int           // max bytes per connection before close (default 12288)
	DialTimeout time.Duration // timeout for opening new connection
}

// DefaultPoolConfig returns spec-compliant defaults.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MinConns:    4,
		MaxConns:    8,
		PreopenSize: 2,
		ChunkSize:   12288,
		DialTimeout: 5 * time.Second,
	}
}

// PoolDialer creates a new connection. Returns an opaque connection handle.
type PoolDialer func(ctx context.Context) (PoolConn, error)

// PoolConn represents one HTTP connection in the pool.
type PoolConn interface {
	// SendChunk sends encrypted data and returns the response.
	SendChunk(ctx context.Context, data []byte) ([]byte, error)
	// Close closes the connection.
	Close() error
}

// Pool manages a pool of short-lived connections per spec section 5.
// Each connection transfers <=ChunkSize bytes then closes.
// Preopen ensures next connections are ready before needed.
type Pool struct {
	config PoolConfig
	dialer PoolDialer

	ready  chan PoolConn // pre-opened connections ready to use
	mu     sync.Mutex
	active int32         // currently active connections (atomic)
	total  atomic.Uint64 // total chunks sent (for stats)
	closed atomic.Bool
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewPool creates a connection pool with the given dialer.
func NewPool(config PoolConfig, dialer PoolDialer) *Pool {
	if config.MinConns == 0 {
		config = DefaultPoolConfig()
	}
	if config.PreopenSize == 0 {
		config.PreopenSize = 2
	}

	p := &Pool{
		config: config,
		dialer: dialer,
		ready:  make(chan PoolConn, config.MaxConns),
		stopCh: make(chan struct{}),
	}

	// Start preopen goroutine
	p.wg.Add(1)
	go p.preopenLoop()

	return p
}

// Send sends data through an available connection.
// Gets a pre-opened connection from the pool (or dials a new one),
// sends the chunk, then the connection is discarded (short-lived per spec).
//
// A1-L4 fix: active-counter decrement is deferred only after successful acquire,
// guaranteeing the counter is balanced even if SendChunk panics or the runtime
// terminates the goroutine mid-send. Previous code did `-1` inline after Close,
// leaking the counter on panic.
func (p *Pool) Send(ctx context.Context, data []byte) ([]byte, error) {
	if p.closed.Load() {
		return nil, errors.New("pool closed")
	}

	conn, err := p.getConn(ctx)
	if err != nil {
		return nil, err
	}
	// Acquire succeeded — decrement is now guaranteed via defer.
	defer atomic.AddInt32(&p.active, -1)
	defer conn.Close()

	// Send chunk — connection is used once then discarded
	resp, err := conn.SendChunk(ctx, data)
	if err != nil {
		return nil, err
	}

	p.total.Add(1)
	return resp, nil
}

// getConn returns a pre-opened connection or dials a new one.
func (p *Pool) getConn(ctx context.Context) (PoolConn, error) {
	// Try to get a pre-opened connection first (non-blocking)
	select {
	case conn := <-p.ready:
		atomic.AddInt32(&p.active, 1)
		return conn, nil
	default:
	}

	// Check if we're at max
	if atomic.LoadInt32(&p.active) >= int32(p.config.MaxConns) {
		// Wait for one to become available
		select {
		case conn := <-p.ready:
			atomic.AddInt32(&p.active, 1)
			return conn, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Dial new connection
	atomic.AddInt32(&p.active, 1)
	dialCtx, cancel := context.WithTimeout(ctx, p.config.DialTimeout)
	defer cancel()

	conn, err := p.dialer(dialCtx)
	if err != nil {
		atomic.AddInt32(&p.active, -1)
		return nil, err
	}

	return conn, nil
}

// preopenLoop keeps the ready channel filled with pre-opened connections.
func (p *Pool) preopenLoop() {
	defer p.wg.Done()

	for {
		select {
		case <-p.stopCh:
			return
		default:
		}

		// Fill up to PreopenSize ready connections
		if len(p.ready) < p.config.PreopenSize {
			ctx, cancel := context.WithTimeout(context.Background(), p.config.DialTimeout)
			conn, err := p.dialer(ctx)
			cancel()

			if err != nil {
				// Dial failed — wait a bit before retry
				select {
				case <-time.After(500 * time.Millisecond):
				case <-p.stopCh:
					return
				}
				continue
			}

			select {
			case p.ready <- conn:
				// Successfully queued
			case <-p.stopCh:
				conn.Close()
				return
			default:
				// Channel full, close this connection
				conn.Close()
			}
		} else {
			// Pool is full enough — wait a bit
			select {
			case <-time.After(100 * time.Millisecond):
			case <-p.stopCh:
				return
			}
		}
	}
}

// Close shuts down the pool and drains pre-opened connections.
func (p *Pool) Close() error {
	if p.closed.Swap(true) {
		return nil // already closed
	}

	close(p.stopCh)
	p.wg.Wait()

	// Drain ready channel
	for {
		select {
		case conn := <-p.ready:
			conn.Close()
		default:
			return nil
		}
	}
}

// Stats returns pool statistics.
func (p *Pool) Stats() PoolStats {
	return PoolStats{
		Active:    int(atomic.LoadInt32(&p.active)),
		Ready:     len(p.ready),
		TotalSent: p.total.Load(),
	}
}

// PoolStats holds pool metrics.
type PoolStats struct {
	Active    int    // currently active connections
	Ready     int    // pre-opened connections waiting
	TotalSent uint64 // total chunks sent
}

package client

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// WSReadyPoolConfig configures a ready pool of pre-warmed WebSocket connections.
//
// Unlike WSPoolTransport (multiplexes many streams on a few WSs), every WS in
// WSReadyPool carries exactly one SOCKS5 stream — same model as VLESS+WS. The
// win is that the WS is already upgraded and idle when Acquire is called, so
// a SOCKS5 CONNECT skips the ~250ms TCP+TLS+WS-upgrade cost that dominates
// per-stream mode through CF CDN (browsers open 10-20 conns for one page →
// 2.5-5s of setup stalls everything).
type WSReadyPoolConfig struct {
	// Size is the target number of ready (pre-upgraded) WS connections kept warm.
	Size int
	// ServerAddr is the WS target (host:port).
	ServerAddr string
	// UseTLS enables TLS (wss://).
	UseTLS bool
	// SkipVerify disables TLS cert verification (testing only).
	SkipVerify bool
	// LockedFP pins a browser fingerprint profile across the pool.
	LockedFP *browser.Fingerprint
	// SNIHost overrides TLS ServerName (origin IP with domain SNI).
	SNIHost string
	// CFIP routes through a specific CF edge IP (bypass DNS).
	CFIP string
	// KeepaliveInterval is how often idle WSs send an encrypted keepalive
	// chunk to prevent CF from closing the connection. Default: 25s (CF idle
	// timeout is 100s, so 25s leaves a safe margin even with jitter).
	KeepaliveInterval time.Duration
	// MaxIdleAge is how long a WS can sit in the ready pool before it's
	// discarded and replaced. Default: 60s. Shorter than CF idle timeout so
	// we never serve a WS that's about to be closed by the edge.
	MaxIdleAge time.Duration
	// StaggerDelay is the interval between worker startups. Default: 300ms.
	// Without staggering, Size parallel WS upgrades in <500ms look like a
	// burst attack to CF and trigger throttling — throughput drops even
	// though every CONNECT_OK arrives fast. Each worker waits (idx * stagger)
	// before its first WS upgrade, spacing the initial fan-out across time.
	StaggerDelay time.Duration
}

// pooledWS is a single pre-upgraded WS waiting in the ready pool.
type pooledWS struct {
	wst       *WebSocketTransport
	createdAt time.Time
	// stopCh is closed when the WS is taken (Acquire) or aged out, so the
	// keepalive goroutine exits without racing the new owner.
	stopCh   chan struct{}
	stopOnce sync.Once
	// broken is set by keepalive when the underlying write fails, so Acquire
	// can skip dead WSs instead of handing a doomed conn to a SOCKS5 stream.
	broken atomic.Bool
}

func (pw *pooledWS) stop() { pw.stopOnce.Do(func() { close(pw.stopCh) }) }

// WSReadyPool keeps Size ready WebSocket connections warm in the background.
// Consumers call Acquire to grab one instantly (no upgrade cost); a worker
// goroutine immediately starts replacing what was taken.
//
// Compare to WSPoolTransport: that pool owns long-lived WSs that multiplex
// many streams — good for direct-to-origin, bad through CF CDN (one slow WS
// stalls all its streams). WSReadyPool fires and forgets: each WS carries
// one stream, then closes.
type WSReadyPool struct {
	cfg WSReadyPoolConfig
	cl  *Client // for cl.Session() / cl.Token() (shared across the pool)

	ready chan *pooledWS

	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger

	// stats
	created  atomic.Int64
	acquired atomic.Int64
	agedOut  atomic.Int64
}

// NewWSReadyPool creates (but does not start) a ready pool. Call Start() after
// the Client's handshake has completed so cl.Token() returns a valid token.
func NewWSReadyPool(cl *Client, cfg WSReadyPoolConfig) *WSReadyPool {
	if cfg.Size < 1 {
		// 6 balances: enough pre-warmed slots for a burst of 6-8 browser
		// conns, but small enough that CF doesn't flag the concurrent
		// upgrades as a bot/scraper burst. Larger pools (tested 20) tank
		// throughput even though CONNECT_OK stays fast.
		cfg.Size = 6
	}
	if cfg.KeepaliveInterval <= 0 {
		cfg.KeepaliveInterval = 25 * time.Second
	}
	if cfg.MaxIdleAge <= 0 {
		cfg.MaxIdleAge = 60 * time.Second
	}
	if cfg.StaggerDelay <= 0 {
		cfg.StaggerDelay = 300 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WSReadyPool{
		cfg:    cfg,
		cl:     cl,
		ready:  make(chan *pooledWS, cfg.Size),
		ctx:    ctx,
		cancel: cancel,
		log:    slog.Default(),
	}
}

// Start launches Size worker goroutines. Each worker keeps exactly one WS slot
// full: create → enqueue → wait for consumption or age-out → replace.
func (p *WSReadyPool) Start() {
	for i := 0; i < p.cfg.Size; i++ {
		go p.worker(i)
	}
}

// Acquire returns a ready WebSocketTransport from the pool. Blocks until one
// is available or the context is done. The returned WS is owned by the
// caller and must be Close()'d. Skips entries flagged broken by the
// keepalive goroutine — the worker that enqueued them will replace them.
func (p *WSReadyPool) Acquire(ctx context.Context) (*WebSocketTransport, error) {
	for {
		select {
		case pw := <-p.ready:
			pw.stop() // stop keepalive before handing ownership to the caller
			if pw.broken.Load() {
				if pw.wst != nil {
					pw.wst.Close()
				}
				continue // next iteration picks the next ready WS
			}
			p.acquired.Add(1)
			return pw.wst, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.ctx.Done():
			return nil, fmt.Errorf("ws ready pool closed")
		}
	}
}

// Size returns the configured pool target size.
func (p *WSReadyPool) Size() int { return p.cfg.Size }

// Ready returns the number of WSs currently waiting in the pool.
// Snapshot — may change immediately after return.
func (p *WSReadyPool) Ready() int { return len(p.ready) }

// Stats returns lifetime counters (created / acquired / agedOut).
func (p *WSReadyPool) Stats() (created, acquired, agedOut int64) {
	return p.created.Load(), p.acquired.Load(), p.agedOut.Load()
}

// Close tears down the pool: cancels workers, drains and closes ready WSs.
func (p *WSReadyPool) Close() error {
	p.cancel()
	for {
		select {
		case pw := <-p.ready:
			pw.stop()
			if pw.wst != nil {
				pw.wst.Close()
			}
		default:
			return nil
		}
	}
}

// worker runs one slot: create a WS, wait for it to be consumed or age out,
// then start over. Backoff on create failures avoids hammering a broken edge.
func (p *WSReadyPool) worker(idx int) {
	// Stagger the initial fan-out so Size parallel TLS handshakes don't
	// arrive at the same CF edge in the same millisecond — that pattern
	// trips CF's burst detection and silently throttles the whole session.
	// Subsequent refills (after Acquire takes a WS) are naturally spread
	// out by user traffic, so stagger is only needed for the cold start.
	if idx > 0 && p.cfg.StaggerDelay > 0 {
		stagger := time.Duration(idx) * p.cfg.StaggerDelay
		select {
		case <-time.After(stagger):
		case <-p.ctx.Done():
			return
		}
	}

	backoff := time.Second
	const maxBackoff = 10 * time.Second

	for {
		if p.ctx.Err() != nil {
			return
		}

		// Token isn't ready until Client.Connect() finishes. Instead of
		// failing the UpgradeToWS with a nil token, just wait briefly.
		token := p.cl.Token()
		if token == nil {
			select {
			case <-time.After(200 * time.Millisecond):
				continue
			case <-p.ctx.Done():
				return
			}
		}

		wst, err := p.createWS(token)
		if err != nil {
			p.log.Debug("ws ready pool create failed", "slot", idx, "err", err)
			select {
			case <-time.After(backoff):
			case <-p.ctx.Done():
				return
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			continue
		}
		backoff = time.Second
		p.created.Add(1)

		pw := &pooledWS{
			wst:       wst,
			createdAt: time.Now(),
			stopCh:    make(chan struct{}),
		}
		go p.keepaliveLoop(pw)

		ageOut := time.NewTimer(p.cfg.MaxIdleAge)

		select {
		case p.ready <- pw:
			ageOut.Stop()
			// Consumed (or will be) — loop back to refill this slot.
		case <-ageOut.C:
			// Aged out before anyone consumed it: CF might cut the idle
			// connection soon, so discard and make a fresh one.
			pw.stop()
			wst.Close()
			p.agedOut.Add(1)
		case <-p.ctx.Done():
			ageOut.Stop()
			pw.stop()
			wst.Close()
			return
		}
	}
}

// createWS performs the WS upgrade for one pool slot.
func (p *WSReadyPool) createWS(token []byte) (*WebSocketTransport, error) {
	wst := NewWebSocketTransport(p.cfg.ServerAddr, p.cfg.UseTLS, p.cfg.SkipVerify, p.cfg.LockedFP)
	if p.cfg.SNIHost != "" {
		wst.SetSNIHost(p.cfg.SNIHost)
	}
	if p.cfg.CFIP != "" {
		wst.SetCFIP(p.cfg.CFIP)
	}
	if err := wst.UpgradeToWS(token); err != nil {
		return nil, err
	}
	return wst, nil
}

// keepaliveLoop sends an encrypted keepalive chunk every KeepaliveInterval
// while the WS is sitting idle in the ready pool. Exits immediately when
// Acquire takes the WS (via pw.stop) or the pool context is cancelled.
//
// If a keepalive write fails, marks the entry broken so Acquire skips it —
// handing a dead WS to a SOCKS5 stream would just cause a fast failure that
// the browser would interpret as a blocked site.
func (p *WSReadyPool) keepaliveLoop(pw *pooledWS) {
	defer func() {
		if r := recover(); r != nil {
			p.log.Debug("ws ready pool keepalive panic recovered", "panic", r)
		}
	}()

	ticker := time.NewTicker(p.cfg.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pw.stopCh:
			return
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			sess := p.cl.Session()
			if sess == nil {
				return
			}
			ka := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
			enc, err := sess.EncryptChunk(ka)
			if err != nil {
				pw.broken.Store(true)
				return
			}
			if err := pw.wst.WriteControlMessage(enc); err != nil {
				p.log.Debug("ws ready pool keepalive write failed", "err", err)
				pw.broken.Store(true)
				return
			}
		}
	}
}

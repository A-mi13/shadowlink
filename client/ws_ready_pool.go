package client

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// phasedWarmupEnabled returns true unless SHADOWLINK_PHASED_WARMUP is set to a
// disabled sentinel (0/false/no/off). Spec §10 promises an env-flag opt-out
// that falls back to legacy linear stagger; this helper is the gate.
// Mirrors useTokenBucket() in server/ratelimiters.go.
func phasedWarmupEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_PHASED_WARMUP"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// WarmupPhase describes one stage of phased pool warmup. Slots listed in
// a phase are started together after the previous phase completes (or is
// sufficiently advanced, depending on RequireDone).
type WarmupPhase struct {
	// Slots is the list of worker indices that belong to this phase.
	Slots []int
	// Delay is the pause injected between the previous phase becoming done
	// and these slots being started. Applied after WaitPrior returns.
	Delay time.Duration
	// RequireDone: when true, every slot in this phase must call
	// MarkSlotReady before the next phase is unblocked. When false, the
	// first slot that becomes ready unblocks the next phase immediately
	// (best-effort / tail slots).
	RequireDone bool
}

// rangeSlots returns [start, start+1, …, start+count-1].
func rangeSlots(start, count int) []int {
	out := make([]int, 0, count)
	for i := range count {
		out = append(out, start+i)
	}
	return out
}

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
	// KeepaliveJitter is the sigma parameter passed to
	// JitteredIntervalLogNormal to destroy FFT-visible periodicity in the
	// keepalive frame timestamps. **Migration note (final-audit-2026-05-03
	// P1-3, 2026-05-05):** sampling shape changed from uniform `±KeepaliveJitter`
	// to log-normal `exp(ln(base) + sigma·N(0,1))` truncated to
	// `[base/2, base*2]`. The yaml field name was preserved for backward
	// compatibility, but the value is now interpreted as `sigma`, not as a
	// uniform fraction. Recommended values:
	//
	//   - 0.3 — mild (median preserved, p99 ≈ 1.6× base; matches the old
	//     uniform "feel" for already-deployed configs).
	//   - 0.5 — moderate (default per audit P1-3 recommendation).
	//   - 0.7 — heavy (large variance; use sparingly).
	//
	// Effective window with base=25s, sigma=0.3 → median≈25s, p99≈40s,
	// truncated [12.5s, 50s]. CF idle timeout is 100s, so 25s base leaves
	// 50s margin even at the upper rail.
	//
	// **Zero is treated as "use the default 0.3"** rather than "no jitter":
	// a literal zero would defeat the purpose, and old configs constructed
	// before this field existed must still produce jittered intervals.
	KeepaliveJitter float64
	// MaxIdleAge is how long a WS can sit in the ready pool before it's
	// discarded and replaced. Default: 60s. Shorter than CF idle timeout so
	// we never serve a WS that's about to be closed by the edge.
	MaxIdleAge time.Duration
	// StaggerDelay is the interval between worker startups. Default: 300ms.
	// Applies only when Warmup is empty (legacy mode). With phased warmup
	// the coordinator's per-phase Delay replaces the flat stagger.
	StaggerDelay time.Duration
	// Warmup overrides the default phased startup behaviour. When nil/empty
	// effectiveWarmup() derives sensible defaults from Size.
	Warmup []WarmupPhase
}

// effectiveWarmup returns Warmup if explicitly set, otherwise derives a
// default phased schedule for the configured Size.
//
// Default schedule for Size=6 (the production default):
//
//	Phase 0: slot 0           — RequireDone=true  (must ready before phase 1)
//	Phase 1: slots 1-2        — RequireDone=true  (parallel pair, gate tail)
//	Phase 2: slots 3-5        — RequireDone=false (best-effort tail)
func (c WSReadyPoolConfig) effectiveWarmup() []WarmupPhase {
	if len(c.Warmup) > 0 {
		return c.Warmup
	}
	// SHADOWLINK_PHASED_WARMUP=0 emergency rollback (spec §10): one phase per
	// slot, separated by StaggerDelay, RequireDone=false. Replicates the
	// pre-Phase-D linear stagger via the phaseCoordinator path so we don't
	// have to re-introduce a parallel non-coordinator code branch.
	if !phasedWarmupEnabled() {
		stagger := c.StaggerDelay
		if stagger <= 0 {
			stagger = 300 * time.Millisecond
		}
		phases := make([]WarmupPhase, 0, c.Size)
		for i := 0; i < c.Size; i++ {
			d := stagger
			if i == 0 {
				d = 0
			}
			phases = append(phases, WarmupPhase{
				Slots:       []int{i},
				Delay:       d,
				RequireDone: false,
			})
		}
		return phases
	}
	if c.Size <= 1 {
		return []WarmupPhase{
			{Slots: []int{0}, Delay: 0, RequireDone: true},
		}
	}
	if c.Size <= 3 {
		return []WarmupPhase{
			{Slots: []int{0}, Delay: 0, RequireDone: true},
			{Slots: rangeSlots(1, c.Size-1), Delay: 800 * time.Millisecond, RequireDone: false},
		}
	}
	// Default for size 4+: head=0, mid=1-2, tail=3..N-1
	tailStart := 3
	tailCount := c.Size - tailStart
	phases := []WarmupPhase{
		{Slots: []int{0}, Delay: 0, RequireDone: true},
		{Slots: []int{1, 2}, Delay: 800 * time.Millisecond, RequireDone: true},
	}
	if tailCount > 0 {
		phases = append(phases, WarmupPhase{
			Slots:       rangeSlots(tailStart, tailCount),
			Delay:       1600 * time.Millisecond,
			RequireDone: false,
		})
	}
	return phases
}

// effectiveKeepaliveJitter returns the jitter parameter the keepalive
// loop passes to JitteredIntervalLogNormal (final-audit-2026-05-03
// P1-3) — interpreted as sigma in `interval = exp(ln(base) + sigma·N(0,1))`,
// truncated to [base/2, base*2]. A zero stored value is treated as the
// default 0.3 — see KeepaliveJitter field doc. The historical name
// "Jitter" was preserved so existing config files keep parsing; the
// sampling shape changed from uniform[base*(1-j), base*(1+j)] to
// log-normal with sigma=j to defeat passive ML classifiers that detect
// the flat power spectrum of uniform jitter via KS-test against a
// log-normal reference.
func (c WSReadyPoolConfig) effectiveKeepaliveJitter() float64 {
	if c.KeepaliveJitter == 0 {
		return 0.3
	}
	return c.KeepaliveJitter
}

// phaseCoordinator gates worker goroutines so the pool warms up in phases
// instead of all N slots hitting the server simultaneously (which triggers
// rate-limit floods during cold start).
//
// Each phase has a done channel closed when the phase is considered complete.
// Workers call WaitPrior before starting, and MarkSlotReady once they have
// a first live WS in the ready channel.
type phaseCoordinator struct {
	phases []WarmupPhase
	done   []chan struct{} // done[i] is closed when phase i is complete
	once   []sync.Once     // ensures each done[i] is closed exactly once
	tally  []atomic.Int32  // ready-slot count per phase
	target []int           // number of slots required to complete phase i
}

func newPhaseCoordinator(phases []WarmupPhase) *phaseCoordinator {
	pc := &phaseCoordinator{
		phases: phases,
		done:   make([]chan struct{}, len(phases)),
		once:   make([]sync.Once, len(phases)),
		tally:  make([]atomic.Int32, len(phases)),
		target: make([]int, len(phases)),
	}
	for i, p := range phases {
		pc.done[i] = make(chan struct{})
		pc.target[i] = len(p.Slots)
	}
	return pc
}

// PhaseFor returns the phase index that contains slot idx, or -1 if not found.
func (pc *phaseCoordinator) PhaseFor(slotIdx int) int {
	for i, p := range pc.phases {
		for _, s := range p.Slots {
			if s == slotIdx {
				return i
			}
		}
	}
	return -1
}

// WaitPrior blocks until the phase before phaseIdx is done (or ctx is
// cancelled). Returns nil immediately if phaseIdx == 0.
func (pc *phaseCoordinator) WaitPrior(ctx context.Context, phaseIdx int) error {
	if phaseIdx <= 0 {
		return nil
	}
	select {
	case <-pc.done[phaseIdx-1]:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// MarkSlotReady is called by a worker when it first places a WS into the
// ready channel. It increments the phase tally and closes done[phase] when
// the completion criterion is met.
//
// When RequireDone is false: the first ready slot in the phase closes done
// immediately (best-effort — subsequent slots may still be warming up).
//
// When RequireDone is true: done is closed only when all slots in the phase
// have called MarkSlotReady.
func (pc *phaseCoordinator) MarkSlotReady(slotIdx int) {
	ph := pc.PhaseFor(slotIdx)
	if ph < 0 {
		return
	}
	curr := pc.tally[ph].Add(1)
	phase := pc.phases[ph]
	if !phase.RequireDone {
		// Any single slot becoming ready is enough to unblock the next phase.
		pc.once[ph].Do(func() { close(pc.done[ph]) })
		return
	}
	if int(curr) >= pc.target[ph] {
		pc.once[ph].Do(func() { close(pc.done[ph]) })
	}
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

	// pc coordinates phased warmup so workers don't all hammer the server at
	// the same time during cold start. Initialised by Start().
	pc *phaseCoordinator

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
	// KeepaliveJitter intentionally retains its zero-default semantics
	// (zero → 0.3 fallback at use-time via effectiveKeepaliveJitter) so the
	// constructor does not overwrite explicit zeros — see field comment.
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
//
// Workers are phased according to effectiveWarmup() so that the cold-start
// fan-out is spread in time: slot 0 must be ready before the mid-tier pair
// (1-2) start, and those must be ready before the tail (3+). This prevents
// the N×handshake burst that triggers CF/server rate-limit floods.
func (p *WSReadyPool) Start() {
	startedAt := time.Now()
	p.pc = newPhaseCoordinator(p.cfg.effectiveWarmup())
	// Task D5: watch the coordinator's RequireDone gates and stamp the
	// PoolWarmupMS gauge once every gating phase has tallied to its target.
	// The watcher exits cleanly if the pool is closed before warmup
	// completes (no goroutine leak under abandoned cold-start).
	go p.trackWarmupCompletion(startedAt)
	for i := range p.cfg.Size {
		go p.worker(i)
	}
}

// trackWarmupCompletion blocks until every RequireDone=true phase has
// closed its done channel, then stamps the PoolWarmupMS gauge with the
// elapsed time since Start(). Returns early if the pool ctx is cancelled
// (Close()) so a torn-down pool does not leak the watcher goroutine.
//
// Tail (RequireDone=false) phases are intentionally NOT awaited — the
// gauge measures "the moment the pool is ready to serve a SOCKS5 burst".
// Best-effort tail slots are bonus capacity that arrives later.
func (p *WSReadyPool) trackWarmupCompletion(startedAt time.Time) {
	for i, ph := range p.pc.phases {
		if !ph.RequireDone {
			continue
		}
		select {
		case <-p.pc.done[i]:
		case <-p.ctx.Done():
			return
		}
	}
	SetPoolWarmupMS(time.Since(startedAt))
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
//
// Cold-start gating: the worker first waits for the previous warmup phase to
// complete (WaitPrior), then applies the phase's inter-phase Delay before
// beginning its first WS upgrade. On every successful first-enqueue it calls
// pc.MarkSlotReady to advance the coordinator. The per-slot sync.Once ensures
// the coordinator gate fires only once even though the worker loops forever
// (re-enqueuing a fresh WS after each Acquire).
func (p *WSReadyPool) worker(idx int) {
	pc := p.pc
	phaseIdx := pc.PhaseFor(idx)

	// --- Phased cold-start gate -------------------------------------------
	// Replace the legacy flat stagger: instead of (idx * StaggerDelay),
	// wait for the previous phase to complete and then apply that phase's
	// inter-phase Delay. This bounds the handshake fan-out to at most one
	// phase at a time.
	if phaseIdx > 0 {
		if err := pc.WaitPrior(p.ctx, phaseIdx); err != nil {
			return // ctx cancelled
		}
		delay := pc.phases[phaseIdx].Delay
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-p.ctx.Done():
				return
			}
		}
	}
	// Legacy flat stagger is still applied for slot 0 (idx==0, phaseIdx==0)
	// when phaseIdx==0 and StaggerDelay is set — this is a no-op for the
	// default multi-phase config (phase 0 has no delay and doesn't wait), but
	// keeps old single-slot configs working without extra latency.
	// For idx > 0 with phaseIdx > 0 the phase Delay above replaces the stagger.
	// For idx > 0 with phaseIdx == 0 (custom Warmup that puts everything in
	// phase 0) fall through to legacy stagger below.
	if phaseIdx == 0 && idx > 0 && p.cfg.StaggerDelay > 0 {
		stagger := time.Duration(idx) * p.cfg.StaggerDelay
		select {
		case <-time.After(stagger):
		case <-p.ctx.Done():
			return
		}
	}
	// ----------------------------------------------------------------------

	backoff := time.Second
	const maxBackoff = 10 * time.Second

	// markOnce fires pc.MarkSlotReady exactly once per slot, even though
	// the worker loops and re-publishes a fresh WS after each Acquire. The
	// coordinator only needs the first-ready signal to unblock the next phase.
	var markOnce sync.Once

	for {
		if p.ctx.Err() != nil {
			return
		}

		// Token isn't ready until Client.Connect() finishes. Instead of
		// failing the UpgradeToWS with a nil token, just wait briefly.
		// D3: session also required for post-upgrade first-frame auth.
		// H4: atomic Snapshot avoids the TOCTOU where Token() and Session()
		// could read across a Close() or Reset and return a mismatched pair.
		token, session := p.cl.Snapshot()
		if token == nil || session == nil {
			select {
			case <-time.After(200 * time.Millisecond):
				continue
			case <-p.ctx.Done():
				return
			}
		}

		wst, err := p.createWS(token, session)
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
			// Successfully enqueued — notify the coordinator that this slot is
			// ready for the first time (no-op on subsequent iterations).
			markOnce.Do(func() { pc.MarkSlotReady(idx) })
			// Loop back to refill this slot after it's consumed.
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
// D3: the upgrade needs the client's active session to build the post-upgrade
// first-frame authentication payload — Authorization header is gone.
func (p *WSReadyPool) createWS(token []byte, session *core.Session) (*WebSocketTransport, error) {
	if session == nil {
		return nil, fmt.Errorf("ws ready pool: nil session")
	}
	wst := NewWebSocketTransport(p.cfg.ServerAddr, p.cfg.UseTLS, p.cfg.SkipVerify, p.cfg.LockedFP)
	if p.cfg.SNIHost != "" {
		wst.SetSNIHost(p.cfg.SNIHost)
	}
	if p.cfg.CFIP != "" {
		wst.SetCFIP(p.cfg.CFIP)
	}
	if err := wst.UpgradeToWS(token, session); err != nil {
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

	// Jittered keepalive (NEW-1 fix → final-audit-2026-05-03 P1-3): a fixed
	// 25s ticker emits encrypted frames at a perfectly periodic rate,
	// producing an FFT peak observable to a passive on-path attacker.
	// Uniform ±j flattens the FFT but leaves a flat-band signature an ML
	// classifier can KS-test against a log-normal reference. Sampling is
	// now log-normal (sigma=jitter, truncated [base/2, base*2]) so the
	// histogram matches real-world heavy-tailed inter-frame jitter.
	sigma := p.cfg.effectiveKeepaliveJitter()

	for {
		select {
		case <-pw.stopCh:
			return
		case <-p.ctx.Done():
			return
		case <-time.After(JitteredIntervalLogNormal(p.cfg.KeepaliveInterval, sigma)):
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

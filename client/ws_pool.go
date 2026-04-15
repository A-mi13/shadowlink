package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

type slotState int32

const (
	slotConnecting slotState = iota
	slotReady
	slotDead
	slotDraining
)

// defaultMaxPendingPerSlot is the default in-flight CONNECTs cap per slot.
// 4 is suitable for direct-to-origin mode. For CF mode a lower value (2) is
// preferred because CF Free plan throttles aggressive WS burst traffic.
// Pass WSPoolConfig.MaxPendingPerSlot to override.
const defaultMaxPendingPerSlot = 4

// poolSlot is a single WebSocket connection in the pool with its own crypto session.
//
// generation is incremented every time the slot is (re)connected. Each reader
// goroutine captures its slot's generation at start and checks it before each
// ReadMessage. If generation has advanced, the reader exits — preventing the
// gorilla "repeated read on failed websocket connection" panic that would
// otherwise occur when an old reader and a new reader race on the same conn
// after a fast reconnect.
type poolSlot struct {
	transport       *WebSocketTransport
	session         *core.Session
	token           []byte
	state           atomic.Int32 // slotState
	streams         atomic.Int32 // active stream count (established)
	pendingConnects atomic.Int32 // in-flight CONNECTs (sent, awaiting CONNECT_OK)
	generation      atomic.Uint64
	index           int
}

func (s *poolSlot) getState() slotState { return slotState(s.state.Load()) }
func (s *poolSlot) setState(st slotState) { s.state.Store(int32(st)) }

// shouldExitReader returns true when the reader's captured generation no longer
// matches the slot's current generation — meaning a reconnect happened and a
// new reader has taken over.
func (p *WSPoolTransport) shouldExitReader(slot *poolSlot, capturedGen uint64) bool {
	return slot.generation.Load() != capturedGen
}

// WSPoolTransport manages a pool of WebSocket connections for fault tolerance and throughput.
// Implements StreamTransport + PoolAware interfaces.
// Server is unaware of the pool — each WS is an independent tunnel.
type WSPoolTransport struct {
	slots    []*poolSlot
	poolSize int

	maxPendingPerSlot  int32 // cap on in-flight CONNECTs per slot
	maxStreamsPerSlot   int32 // cap on active streams per slot (0 = unlimited)

	streamMap sync.Map // map[uint16]int — streamID -> slot index

	// For creating new slots
	serverAddr   string
	sniHost      string // override TLS ServerName
	cfIP         string // specific CF edge IP
	useTLS       bool
	skipVerify   bool
	lockedFP     *browser.Fingerprint
	client       *Client       // back-reference for handshake
	writeTimeout time.Duration // per-frame write deadline (0 → 30s WSAsyncWriter default)
	staggerDelay time.Duration // initial/reconnect slot startup spacing (0 → no stagger)

	// Meltdown protection: when multiple slots die within a short window
	// (usually CF punishing an aggressive burst), pause reconnect loops so CF
	// can "cool down" instead of immediately spinning up replacement slots
	// that will get killed again.
	meltdownWindow    time.Duration
	meltdownThreshold int
	meltdownCooldown  time.Duration
	recentDeaths      atomic.Int32
	meltdownUntil     atomic.Int64 // unix nano; reconnects blocked until this time

	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger
}

// Compile-time assertions.
var (
	_ StreamTransport   = (*WSPoolTransport)(nil)
	_ PoolAware         = (*WSPoolTransport)(nil)
	_ PendingTracker    = (*WSPoolTransport)(nil)
	_ ControlPoolAware  = (*WSPoolTransport)(nil)
)

// WSPoolConfig configures the WebSocket pool.
type WSPoolConfig struct {
	Size       int
	ServerAddr string
	UseTLS     bool
	SkipVerify bool
	LockedFP   *browser.Fingerprint
	SNIHost    string // override TLS ServerName (for origin IP with domain SNI)
	CFIP       string // specific CF edge IP (bypass DNS, keep domain as TLS SNI)

	// MaxPendingPerSlot caps in-flight CONNECTs per slot. 0 = default (4).
	MaxPendingPerSlot int

	// MaxStreamsPerSlot caps active streams per slot. 0 = unlimited.
	// For CF CDN mode, set low (4-8) so each WS carries light traffic.
	MaxStreamsPerSlot int

	// WriteTimeout caps each WS frame's write deadline. 0 → WSAsyncWriter
	// default (30s). For viaCF mode pass 5-8s: CF-side stalls propagate as
	// TCP backpressure, and 30s means a stuck slot blocks traffic for 30s
	// before the pool can route around it. Cross-check 2026-04-15 H6.
	WriteTimeout time.Duration

	// StaggerDelay spaces initial slot handshakes. 0 disables. Recommended
	// ~300ms × slot index so 8 TCP SYNs don't arrive at CF edge in the same
	// millisecond and trip burst/rate-limit heuristics.
	StaggerDelay time.Duration

	// Meltdown protection parameters. All default to sensible values if zero.
	MeltdownWindow    time.Duration // how long "recent death" lasts (default 5s)
	MeltdownThreshold int           // N deaths in window triggers cooldown (default = ceil(size/2), min 2)
	MeltdownCooldown  time.Duration // reconnect pause after trigger (default 10s)
}

// NewWSPoolTransport creates a pool of WebSocket connections.
func NewWSPoolTransport(cl *Client, cfg WSPoolConfig) *WSPoolTransport {
	if cfg.Size < 1 {
		cfg.Size = 2
	}
	if cfg.MaxPendingPerSlot < 1 {
		cfg.MaxPendingPerSlot = defaultMaxPendingPerSlot
	}
	// Meltdown defaults tuned 2026-04-15 after field regression analysis:
	// the old 5s / ceil(size/2) combo turned a transient CF edge hiccup
	// into a self-sustaining outage. Widening the window to 15s and
	// raising the threshold to ⌈3·size/4⌉ means we still pause reconnect
	// when CF is genuinely angry, but don't trip on 4 correlated deaths
	// from one bad edge IP (see DNS-spray finding F4).
	if cfg.MeltdownWindow <= 0 {
		cfg.MeltdownWindow = 15 * time.Second
	}
	if cfg.MeltdownThreshold < 1 {
		cfg.MeltdownThreshold = (cfg.Size*3 + 3) / 4 // ceil(3·size/4)
		if cfg.MeltdownThreshold < 3 {
			cfg.MeltdownThreshold = 3
		}
	}
	if cfg.MeltdownCooldown <= 0 {
		cfg.MeltdownCooldown = 10 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WSPoolTransport{
		slots:             make([]*poolSlot, cfg.Size),
		poolSize:          cfg.Size,
		maxPendingPerSlot:  int32(cfg.MaxPendingPerSlot),
		maxStreamsPerSlot:  int32(cfg.MaxStreamsPerSlot),
		serverAddr:        cfg.ServerAddr,
		sniHost:           cfg.SNIHost,
		cfIP:              cfg.CFIP,
		useTLS:            cfg.UseTLS,
		skipVerify:        cfg.SkipVerify,
		lockedFP:          cfg.LockedFP,
		client:            cl,
		writeTimeout:      cfg.WriteTimeout,
		staggerDelay:      cfg.StaggerDelay,
		meltdownWindow:    cfg.MeltdownWindow,
		meltdownThreshold: cfg.MeltdownThreshold,
		meltdownCooldown:  cfg.MeltdownCooldown,
		ctx:               ctx,
		cancel:            cancel,
		log:               slog.Default(),
	}
}

// Connect establishes all WS connections in parallel.
// Returns success when at least one slot is ready.
func (p *WSPoolTransport) Connect(ctx context.Context) error {
	var wg sync.WaitGroup
	results := make([]error, p.poolSize)

	// Stagger the initial fan-out so N TCP SYNs don't arrive at CF edge in
	// the same millisecond (trips burst/rate-limit heuristics). Same pattern
	// WSReadyPool already uses. Zero staggerDelay → no stagger (direct mode).
	for i := 0; i < p.poolSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx > 0 && p.staggerDelay > 0 {
				select {
				case <-time.After(time.Duration(idx) * p.staggerDelay):
				case <-ctx.Done():
					results[idx] = ctx.Err()
					return
				}
			}
			results[idx] = p.connectSlot(ctx, idx)
		}(i)
	}

	wg.Wait()

	anyReady := false
	for i, err := range results {
		if err == nil {
			anyReady = true
			p.log.Info("WS pool slot ready", "slot", i)
		} else {
			p.log.Warn("WS pool slot failed", "slot", i, "err", err)
			go p.reconnectLoop(i)
		}
	}

	if !anyReady {
		return fmt.Errorf("ws pool: all %d slots failed to connect", p.poolSize)
	}

	go p.rotationLoop()
	go p.keepaliveLoop()

	return nil
}

// keepaliveLoop sends FlagKeepalive to every healthy slot every 20s.
// This prevents Cloudflare Proxy Write Timeout (30s) and Idle Timeout (900s)
// from killing long-lived WebSocket connections.
func (p *WSPoolTransport) keepaliveLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.sendKeepaliveToAllSlots()
		}
	}
}

func (p *WSPoolTransport) sendKeepaliveToAllSlots() {
	sent := 0
	for i := 0; i < p.poolSize; i++ {
		slot := p.slots[i]
		if slot == nil || slot.getState() != slotReady || slot.transport == nil || slot.session == nil {
			continue
		}
		// Each slot has its own crypto session — must use slot.session, not global client session.
		chunk := core.NewKeepaliveChunk(slot.session.ID, slot.session.NextSeqNum())
		enc, err := slot.session.EncryptChunk(chunk)
		if err != nil {
			continue
		}
		if writeErr := slot.transport.WriteControlMessage(enc); writeErr != nil {
			p.log.Debug("keepalive write failed", "slot", i, "err", writeErr)
		} else {
			sent++
		}
	}
	if sent > 0 {
		p.log.Debug("keepalive sent", "slots", sent)
	}
}

// connectSlot creates a new WS connection for the given slot index.
func (p *WSPoolTransport) connectSlot(ctx context.Context, idx int) error {
	slot := &poolSlot{index: idx}
	slot.setState(slotConnecting)
	p.slots[idx] = slot

	// Perform handshake to get a new session
	hello, clientState, err := core.NewClientHello(p.client.clientID, p.client.serverPub)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: create hello: %w", idx, err)
	}

	respBody, err := p.client.transport.SendHandshake(ctx, hello)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: handshake: %w", idx, err)
	}

	respData, _, err := browser.ParseDownloadResponse(respBody)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: parse hello: %w", idx, err)
	}

	var shData struct {
		EphPub    []byte `json:"eph"`
		Token     []byte `json:"tok"`
		MaxConns  uint8  `json:"mc"`
		ChunkSize uint16 `json:"cs"`
	}
	if err := json.Unmarshal(respData, &shData); err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: unmarshal hello: %w", idx, err)
	}

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
	}

	session, err := core.CompleteHandshake(clientState, serverHello)
	if err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: complete handshake: %w", idx, err)
	}

	slot.session = session
	slot.token = browser.EncodeTokenWithHint(session.ID, shData.Token)

	// Create WS transport and upgrade
	wst := NewWebSocketTransport(p.serverAddr, p.useTLS, p.skipVerify, p.lockedFP)
	wst.sniHost = p.sniHost // SNI trick: domain as ServerName when connecting to origin IP
	wst.cfIP = p.cfIP       // CF edge IP override: bypass DNS, keep domain as TLS SNI
	if p.writeTimeout > 0 {
		wst.SetWriteTimeout(p.writeTimeout) // viaCF: 5-8s, direct: 0 (→ 30s default)
	}
	if idx == 0 {
		wst.WarmupRequests() // Only warmup for first slot (looks natural)
	}
	if err := wst.UpgradeToWS(slot.token); err != nil {
		slot.setState(slotDead)
		return fmt.Errorf("slot %d: ws upgrade: %w", idx, err)
	}

	slot.transport = wst
	// Bump generation BEFORE marking ready so any old reader checking
	// generation after this point exits cleanly. The new reader (started by
	// the caller) will capture the new generation at its first check.
	slot.generation.Add(1)
	slot.setState(slotReady)
	return nil
}

// reconnectLoop tries to reconnect a dead slot with exponential backoff.
// If meltdown cooldown is active (triggered by multiple recent slot deaths),
// the loop waits for it to elapse before attempting to reconnect. This
// prevents a spiral where CF rejects replacement slots as fast as they are
// created, keeping it under load and making recovery slower.
func (p *WSPoolTransport) reconnectLoop(idx int) {
	for attempt := 0; ; attempt++ {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		if wait := p.meltdownWaitDuration(); wait > 0 {
			p.log.Info("WS pool meltdown cooldown — pausing reconnect",
				"slot", idx, "wait", wait)
			timer := time.NewTimer(wait)
			select {
			case <-p.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}

		d := backoffDuration(attempt)
		p.log.Info("WS pool reconnecting slot", "slot", idx, "backoff", d)

		timer := time.NewTimer(d)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if err := p.connectSlot(p.ctx, idx); err != nil {
			p.log.Warn("WS pool slot reconnect failed", "slot", idx, "err", err)
			continue
		}

		p.log.Info("WS pool slot reconnected", "slot", idx)
		go p.slotReader(idx)
		return
	}
}

// meltdownWaitDuration returns how long the reconnect must still wait before
// the cooldown elapses, or 0 if no cooldown is active.
func (p *WSPoolTransport) meltdownWaitDuration() time.Duration {
	until := p.meltdownUntil.Load()
	if until == 0 {
		return 0
	}
	wait := time.Until(time.Unix(0, until))
	if wait <= 0 {
		return 0
	}
	return wait
}

// recordSlotDeath tracks slot deaths within a rolling window and triggers a
// meltdown cooldown if the threshold is exceeded. Called from handleSlotDeath.
func (p *WSPoolTransport) recordSlotDeath() {
	deaths := p.recentDeaths.Add(1)

	// Schedule decrement after the window so old deaths age out.
	go func() {
		timer := time.NewTimer(p.meltdownWindow)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			p.recentDeaths.Add(-1)
		}
	}()

	if int(deaths) >= p.meltdownThreshold {
		until := time.Now().Add(p.meltdownCooldown).UnixNano()
		// Only advance, never shorten, an already-active cooldown.
		if prev := p.meltdownUntil.Load(); until > prev {
			p.meltdownUntil.Store(until)
			p.log.Warn("WS pool meltdown detected — entering cooldown",
				"deaths_in_window", deaths,
				"threshold", p.meltdownThreshold,
				"window", p.meltdownWindow,
				"cooldown", p.meltdownCooldown)
		}
	}
}

// rotationLoop periodically rotates one slot for anti-fingerprinting.
func (p *WSPoolTransport) rotationLoop() {
	for {
		delay := 2*time.Minute + time.Duration(rand.Int64N(int64(6*time.Minute)))
		timer := time.NewTimer(delay)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		p.rotateOneSlot()
	}
}

// rotateOneSlot soft-rotates the slot with fewer active streams.
func (p *WSPoolTransport) rotateOneSlot() {
	minIdx := -1
	minStreams := int32(1<<31 - 1)
	for i, slot := range p.slots {
		if slot == nil || slot.getState() != slotReady {
			continue
		}
		s := slot.streams.Load()
		if s < minStreams {
			minStreams = s
			minIdx = i
		}
	}

	if minIdx < 0 {
		return
	}

	slot := p.slots[minIdx]
	slot.setState(slotDraining)
	p.log.Info("WS pool rotating slot", "slot", minIdx, "activeStreams", minStreams)

	// Wait for streams to drain (max 30s)
	deadline := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-deadline:
			goto reconnect
		case <-ticker.C:
			if slot.streams.Load() == 0 {
				goto reconnect
			}
		}
	}

reconnect:
	if slot.transport != nil {
		slot.transport.Close()
	}
	if slot.session != nil {
		slot.session.Destroy()
	}

	if err := p.connectSlot(p.ctx, minIdx); err != nil {
		p.log.Warn("WS pool rotation reconnect failed", "slot", minIdx, "err", err)
		go p.reconnectLoop(minIdx)
		return
	}

	go p.slotReader(minIdx)
	p.log.Info("WS pool slot rotated", "slot", minIdx)
}

// AssignStream assigns a streamID to the least-loaded ready slot.
// Prefers slots with fewer pending CONNECTs to distribute load evenly across CF CDN connections.
func (p *WSPoolTransport) AssignStream(streamID uint16) {
	minIdx := -1
	minScore := int32(1<<31 - 1)

	for i, slot := range p.slots {
		if slot == nil {
			continue
		}
		st := slot.getState()
		if st != slotReady {
			continue
		}
		streams := slot.streams.Load()
		// Skip slots at stream capacity (CF mode: each WS should carry few streams)
		if p.maxStreamsPerSlot > 0 && streams >= p.maxStreamsPerSlot {
			continue
		}
		// Score: pending CONNECTs weighted 4x (bottleneck through CDN) + established streams.
		// This spreads CONNECT load evenly and avoids piling onto one slot.
		pending := slot.pendingConnects.Load()
		score := pending*4 + streams
		if score < minScore {
			minScore = score
			minIdx = i
		}
	}

	if minIdx < 0 {
		// All slots at capacity — pick the slot with fewest streams (soft overflow).
		// This is better than always picking slot 0 which creates a hotspot.
		minStreams := int32(1<<31 - 1)
		for i, slot := range p.slots {
			if slot == nil || slot.getState() != slotReady {
				continue
			}
			s := slot.streams.Load()
			if s < minStreams {
				minStreams = s
				minIdx = i
			}
		}
		if minIdx < 0 {
			// Truly no ready slots — last resort fallback.
			for i, slot := range p.slots {
				if slot != nil {
					minIdx = i
					break
				}
			}
		}
		if minIdx < 0 {
			p.log.Warn("stream assign: no slots available", "stream", streamID)
			return
		}
	}

	p.streamMap.Store(streamID, minIdx)
	p.slots[minIdx].streams.Add(1)
	if p.log != nil {
		p.log.Debug("stream assigned", "stream", streamID, "slot", minIdx,
			"pending", p.slots[minIdx].pendingConnects.Load(),
			"streams", p.slots[minIdx].streams.Load())
	}
}

// IncrPending increments the pending CONNECT counter for the stream's assigned slot.
func (p *WSPoolTransport) IncrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].pendingConnects.Add(1)
		}
	}
}

// DecrPending decrements the pending CONNECT counter for the stream's assigned slot.
func (p *WSPoolTransport) DecrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].pendingConnects.Add(-1)
		}
	}
}

// SlotPending returns pending CONNECT count for the stream's assigned slot.
func (p *WSPoolTransport) SlotPending(streamID uint16) int32 {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].pendingConnects.Load()
		}
	}
	return 0
}

// AllSlotsAtMaxPending returns true when every ready slot has >= maxPendingPerSlot pending CONNECTs.
// Returns false when no slots are ready (don't block — let AssignStream fallback handle it).
func (p *WSPoolTransport) AllSlotsAtMaxPending() bool {
	anyReady := false
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady {
			anyReady = true
			if slot.pendingConnects.Load() < p.maxPendingPerSlot {
				return false
			}
		}
	}
	if !anyReady {
		return false // No ready slots — don't block, let the CONNECT fail fast downstream
	}
	return true
}

// ReleaseStream removes stream assignment.
func (p *WSPoolTransport) ReleaseStream(streamID uint16) {
	if v, ok := p.streamMap.LoadAndDelete(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].streams.Add(-1)
		}
	}
}

// SessionForStream returns the crypto session for the stream's assigned slot.
func (p *WSPoolTransport) SessionForStream(streamID uint16) *core.Session {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].session
		}
	}
	// Fallback: return first available session
	for _, slot := range p.slots {
		if slot != nil && slot.session != nil && slot.getState() == slotReady {
			return slot.session
		}
	}
	return nil
}

// WriteMessageForStream sends a data frame to the slot assigned to this stream.
func (p *WSPoolTransport) WriteMessageForStream(streamID uint16, data []byte) error {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.getState() == slotReady && slot.transport != nil {
				return slot.transport.WriteMessage(data)
			}
		}
	}
	return p.WriteMessage(data)
}

// WriteControlMessageForStream sends a control frame (CONNECT, FIN) with
// high priority to the slot assigned to this stream.
func (p *WSPoolTransport) WriteControlMessageForStream(streamID uint16, data []byte) error {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.getState() == slotReady && slot.transport != nil {
				return slot.transport.WriteControlMessage(data)
			}
		}
	}
	return p.WriteControlMessage(data)
}

// WriteMessage sends a data frame to a random ready slot (for non-stream data).
func (p *WSPoolTransport) WriteMessage(data []byte) error {
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady && slot.transport != nil {
			return slot.transport.WriteMessage(data)
		}
	}
	return fmt.Errorf("ws pool: no ready slots")
}

// WriteControlMessage sends a control frame to a random ready slot.
func (p *WSPoolTransport) WriteControlMessage(data []byte) error {
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady && slot.transport != nil {
			return slot.transport.WriteControlMessage(data)
		}
	}
	return fmt.Errorf("ws pool: no ready slots")
}

// StartReader starts background readers for all connected slots.
// Returns when ALL readers die or context is cancelled.
func (p *WSPoolTransport) StartReader(ctx context.Context, cl *Client) error {
	var wg sync.WaitGroup
	errCh := make(chan error, p.poolSize)

	for i := 0; i < p.poolSize; i++ {
		if p.slots[i] == nil || p.slots[i].getState() != slotReady {
			continue
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p.slotReaderWithClient(ctx, cl, idx)
		}(i)
	}

	go func() {
		wg.Wait()
		select {
		case errCh <- fmt.Errorf("all slot readers exited"):
		default:
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// slotReader runs a reader for a slot (used for reconnected slots).
func (p *WSPoolTransport) slotReader(idx int) {
	p.slotReaderWithClient(p.ctx, p.client, idx)
}

// slotReaderWithClient runs the WS reader for a specific slot.
// On error: marks slot dead, closes affected streams, triggers reconnect.
//
// Captures slot.generation at start and bails out (without touching the
// transport) when generation advances — meaning the slot was reconnected
// and a newer reader has taken over. This prevents the gorilla "repeated
// read on failed websocket connection" panic that occurs when two readers
// race on the same conn.
func (p *WSPoolTransport) slotReaderWithClient(ctx context.Context, cl *Client, idx int) {
	slot := p.slots[idx]
	if slot == nil || slot.transport == nil {
		return
	}
	myGen := slot.generation.Load()

	p.log.Info("WS pool slot reader started", "slot", idx, "gen", myGen)

	defer func() {
		if r := recover(); r != nil {
			p.log.Warn("WS pool slot reader panic recovered", "slot", idx, "panic", r)
			// Only initiate slot death if our generation is still active.
			// A panic on a stale generation means we lost a race with a
			// reconnect; the new reader/transport must not be torn down.
			if !p.shouldExitReader(slot, myGen) {
				p.handleSlotDeath(cl, idx)
			}
		}
	}()

	msgCount := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Generation check: if the slot was reconnected, a newer reader
		// owns the new transport — exit silently to avoid concurrent
		// ReadMessage on the same conn.
		if p.shouldExitReader(slot, myGen) {
			p.log.Debug("WS pool slot reader exiting — slot reconnected",
				"slot", idx, "captured_gen", myGen, "current_gen", slot.generation.Load())
			return
		}

		data, err := slot.transport.ReadMessage(30 * time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// If the slot was reconnected during our blocking ReadMessage, the
			// error is from the OLD (closed) conn — don't treat it as a death
			// of the new slot. Just exit.
			if p.shouldExitReader(slot, myGen) {
				return
			}
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				continue
			}
			// Terminal (non-timeout) reader error — attribute slot death.
			// If this correlates with writer_exits in stats, CF-side stalls
			// are the trigger (H6); if writer_exits stays low and
			// reader_exits climbs, the server or CF edge is actively
			// closing our TCP.
			Stats.ReaderExits.Add(1)
			p.log.Warn("WS pool slot reader error", "slot", idx, "err", err, "messages", msgCount)
			p.handleSlotDeath(cl, idx)
			return
		}

		session := slot.session
		if session == nil {
			continue
		}

		chunk, err := session.DecryptChunkSafe(data)
		if err != nil {
			continue
		}

		if len(chunk.Payload) < 2 {
			continue
		}

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		if chunk.Flags == core.FlagUDP {
			cl.RouteToStream(streamID, chunk.Payload)
		} else {
			cl.RouteToStream(streamID, chunk.Payload[2:])
		}
	}
}

// handleSlotDeath marks a slot as dead, closes its streams, and triggers reconnect.
func (p *WSPoolTransport) handleSlotDeath(cl *Client, idx int) {
	slot := p.slots[idx]
	slot.setState(slotDead)

	// Close all streams assigned to this slot
	p.streamMap.Range(func(key, value any) bool {
		if value.(int) == idx {
			streamID := key.(uint16)
			p.streamMap.Delete(streamID)
			cl.streamMu.Lock()
			if ch, ok := cl.streamChans[streamID]; ok {
				close(ch)
				delete(cl.streamChans, streamID)
			}
			cl.streamMu.Unlock()
		}
		return true
	})

	slot.streams.Store(0)
	slot.pendingConnects.Store(0) // Reset: pending CONNECTs from dead slot can't be decremented normally

	if slot.transport != nil {
		slot.transport.Close()
	}

	// Record death for meltdown detection before kicking off reconnect so the
	// reconnect loop can observe the cooldown if we just hit the threshold.
	p.recordSlotDeath()

	go p.reconnectLoop(idx)
}

// Close shuts down all slots.
func (p *WSPoolTransport) Close() error {
	p.cancel()
	for _, slot := range p.slots {
		if slot == nil {
			continue
		}
		if slot.transport != nil {
			slot.transport.Close()
		}
		if slot.session != nil {
			slot.session.Destroy()
		}
		if slot.token != nil {
			core.ZeroBytes(slot.token)
		}
	}
	return nil
}

// HealthySlots returns the number of ready slots.
func (p *WSPoolTransport) HealthySlots() int {
	count := 0
	for _, slot := range p.slots {
		if slot != nil && slot.getState() == slotReady {
			count++
		}
	}
	return count
}

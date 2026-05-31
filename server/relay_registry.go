package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nixavpn/shadowlink/core"
)

// websocketBinaryMessage aliases the gorilla BinaryMessage opcode so the relay
// loop here uses the same value the rest of server/websocket.go enqueues with,
// without repeating the import everywhere. WSAsyncWriter.Enqueue takes the WS
// message type as its first argument.
const websocketBinaryMessage = websocket.BinaryMessage

// pendingDownFrame is one downlink chunk captured under its assigned downSeq.
// Buffered either while there is no active binding (downBuffer) or as the
// not-yet-acked tail after a preemptive migration (unackedTail). §5.1/§5.3.
type pendingDownFrame struct {
	seq  uint64
	data []byte
}

// binding packs the crypto session and async writer of the CURRENTLY active
// slot into one unit so the relay-loop reads a consistent pair under a single
// atomic.Load (NEW-5). Mirrors core.sendEpoch{gcm, nonce} under one
// atomic.Pointer (core/session.go:27,79,312).
type binding struct {
	session *core.Session
	writer  *core.WSAsyncWriter
}

// boundedBuffer is a FIFO of pendingDownFrame capped by total payload bytes
// (≤ 1 flow-window, §4.2). Push returns false when full (caller applies
// backpressure by not reading the egress-TCP). Not safe for concurrent use —
// callers hold relayEntry.perEntryMu.
type boundedBuffer struct {
	frames  []pendingDownFrame
	bytes   int
	maxByte int
}

func newBoundedBuffer(maxByte int) *boundedBuffer {
	return &boundedBuffer{maxByte: maxByte}
}

func (b *boundedBuffer) Push(f pendingDownFrame) bool {
	if b.bytes+len(f.data) > b.maxByte {
		return false
	}
	b.frames = append(b.frames, f)
	b.bytes += len(f.data)
	return true
}

func (b *boundedBuffer) byteLen() int { return b.bytes }

// drainAll returns all buffered frames in FIFO order and empties the buffer.
func (b *boundedBuffer) drainAll() []pendingDownFrame {
	out := b.frames
	b.frames = nil
	b.bytes = 0
	return out
}

// evictUpTo drops all frames with seq <= ackedSeq (FlagStreamAck barrier, §5.4).
func (b *boundedBuffer) evictUpTo(ackedSeq uint64) {
	kept := b.frames[:0]
	bytes := 0
	for _, f := range b.frames {
		if f.seq <= ackedSeq {
			continue
		}
		kept = append(kept, f)
		bytes += len(f.data)
	}
	b.frames = kept
	b.bytes = bytes
}

// tailFrames returns a copy of all buffered frames in seq order (for resend on
// slot-A death before ack, §5.3) without emptying the buffer.
func (b *boundedBuffer) tailFrames() []pendingDownFrame {
	out := make([]pendingDownFrame, len(b.frames))
	copy(out, b.frames)
	return out
}

// relay state machine (§5.1, F8). All transitions via state.CompareAndSwap.
const (
	stActive   int32 = 0
	stOrphaned int32 = 1
	stClosing  int32 = 2
)

// relayEntry owns one egress-TCP relay that survives WS-slot migration. Keyed
// (clientID, globalStreamID) in relayRegistry (§5.1).
type relayEntry struct {
	// Identity / proof
	originClientID     string
	globalStreamID     uint16
	originSessionNonce [16]byte

	// Egress — survives slot changes. net.Conn (not just Closer) because the
	// relay loop now reads it directly (F4); migration moves the binding, not
	// this conn.
	tc net.Conn

	// Dynamic binding to the active slot's crypto session+writer (NEW-5).
	bound atomic.Pointer[binding]

	// State machine (F8).
	state      atomic.Int32 // stActive | stOrphaned | stClosing
	orphanedAt atomic.Int64 // unix nanos

	// Ordering (F1) — counter NEVER reset on reassociate (NEW-3, §3.1).
	downSeqCounter atomic.Uint64
	downBuffer     *boundedBuffer // buffered while no binding / during grace
	unackedTail    *boundedBuffer // sent-on-A-but-unacked tail (NEW-1)

	// FD accounting (F5).
	holdsFD bool

	// Bug#8 stream credit — lives here, survives migration (F9, §5.9).
	credit *streamCredit

	perEntryMu sync.Mutex

	// bufCond signals the relay loop when downBuffer frees up (a binding was
	// reassociated and drained the buffer) so a relay loop that blocked on a
	// full downBuffer during the no-binding window can resume — the lazy-seq /
	// blocking-backpressure machinery that closes the Task 10 quality-review
	// gap (no seq assigned until a frame is guaranteed stored, NEW-1). Created
	// lazily by bufCondOf so the many relayEntry literals (production + tests)
	// don't each have to wire it; it is always backed by perEntryMu.
	bufCond     *sync.Cond
	bufCondOnce sync.Once
}

// bufCondOf returns the entry's downBuffer condition variable, creating it once
// on first use bound to perEntryMu. Safe for concurrent first-callers via the
// sync.Once. The relay loop, reassociate, and the grace timer all funnel
// buffer-availability signalling through this single cond so a blocked loop is
// woken exactly when space appears or the stream is torn down.
func (e *relayEntry) bufCondOf() *sync.Cond {
	e.bufCondOnce.Do(func() {
		e.bufCond = sync.NewCond(&e.perEntryMu)
	})
	return e.bufCond
}

// relayRegistry holds relays keyed (clientID, globalStreamID), living
// independently of any single WS session (§5.1). RWMutex guards the maps;
// per-entry mutation uses relayEntry.perEntryMu / atomics.
type relayRegistry struct {
	mu       sync.RWMutex
	byClient map[string]map[uint16]*relayEntry
}

func newRelayRegistry() *relayRegistry {
	return &relayRegistry{byClient: make(map[string]map[uint16]*relayEntry)}
}

func (r *relayRegistry) add(clientID string, streamID uint16, e *relayEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.byClient[clientID]
	if m == nil {
		m = make(map[uint16]*relayEntry)
		r.byClient[clientID] = m
	}
	m[streamID] = e
}

func (r *relayRegistry) find(clientID string, streamID uint16) (*relayEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if m := r.byClient[clientID]; m != nil {
		e, ok := m[streamID]
		return e, ok
	}
	return nil, false
}

func (r *relayRegistry) remove(clientID string, streamID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m := r.byClient[clientID]; m != nil {
		delete(m, streamID)
		if len(m) == 0 {
			delete(r.byClient, clientID)
		}
	}
}

// entriesForSession returns the relayEntries under clientID whose CURRENT
// binding is sess — i.e. relays still bound to the dying WS session, which must
// be orphaned (§5.5). Relays that were preemptively migrated to another slot
// have a binding pointing at a different session and are excluded (left running
// on their new slot). Snapshots the slice under RLock so the caller mutates
// each entry's state without holding the registry lock (lock order: registry
// RLock released before per-entry CAS — avoids deadlock with the grace timer's
// registry.remove, §5.1).
func (r *relayRegistry) entriesForSession(clientID string, sess *core.Session) []*relayEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*relayEntry
	for _, e := range r.byClient[clientID] {
		if b := e.bound.Load(); b != nil && b.session == sess {
			out = append(out, e)
		}
	}
	return out
}

func (r *relayRegistry) countForClient(clientID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byClient[clientID])
}

func (r *relayRegistry) totalCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, m := range r.byClient {
		n += len(m)
	}
	return n
}

// onStreamAck releases the not-yet-acked tail up to ackedSeq (FlagStreamAck
// barrier, §5.4). Called under perEntryMu by the FlagStreamAck handler.
func (e *relayEntry) onStreamAck(ackedSeq uint64) {
	e.perEntryMu.Lock()
	if e.unackedTail != nil {
		e.unackedTail.evictUpTo(ackedSeq)
	}
	if e.downBuffer != nil {
		e.downBuffer.evictUpTo(ackedSeq)
	}
	e.perEntryMu.Unlock()
}

// resendTail returns the unacked tail (seq order) so the relay-loop can
// re-enqueue it on the NEW binding when slot A died before acking (NEW-1,
// §5.3). Does NOT clear the buffer — the frames stay pending until B acks
// them. Caller resends under the same perEntryMu it holds.
func (e *relayEntry) resendTail() []pendingDownFrame {
	e.perEntryMu.Lock()
	defer e.perEntryMu.Unlock()
	if e.unackedTail == nil {
		return nil
	}
	return e.unackedTail.tailFrames()
}

// relayLoop is the per-stream egress→client pump for a migratable relay (F4).
// Unlike the legacy inline relay in runWebSocketSession (which captured one
// *core.Session by closure and died with its WS conn), this loop lives on the
// *relayEntry and reads e.bound.Load() on EVERY frame. When a MIGRATE/RESUME
// swaps the binding to a new slot's {session, writer} (Task 11), subsequent
// frames are transparently encrypted under the new session and enqueued on the
// new writer — the egress TCP conn (e.tc) is untouched. The loop is decoupled
// from any single WS session's `done`; it exits only on egress read error,
// credit close, or closeCh (the session-scoped channel that, for migratable
// sessions, fires on full teardown rather than per-slot rotation).
//
// migrateEnabled selects the wire format: when true, frames carry a per-stream
// monotonic downSeq (NewStreamDataChunkSeq, §3.1/F1) so the client reassembler
// can reorder across a migration boundary; when false the loop uses the legacy
// flat NewStreamDataChunk (no downSeq) — but in practice relayLoop is only ever
// started for migrateEnabled sessions, so the false branch exists for symmetry
// and direct unit-testing.
func (e *relayEntry) relayLoop(migrateEnabled bool, closeCh <-chan struct{}) {
	buf := make([]byte, 32768)
	for {
		limit := len(buf)
		if e.credit != nil {
			got := e.credit.waitForCredit(closeCh)
			if got <= 0 {
				// Credit closed (stream/session torn down) — exit the pump.
				return
			}
			if int(got) < limit {
				limit = int(got)
			}
		}

		n, err := e.tc.Read(buf[:limit])
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)

			// CRITICAL (Task 10 quality-review gate, NEW-1): the downSeq is
			// assigned EXACTLY ONCE per frame, and ONLY once the frame is
			// guaranteed to be either sent under a live binding or stored in
			// downBuffer. The legacy code took the seq before checking the
			// binding, so a drop-on-full downBuffer left a hole in the seq
			// sequence — a permanent reassembler stall on the client ("does not
			// recover"). routeDownFrame makes the whole decision (assign seq,
			// store-or-send) atomically under perEntryMu, blocking on full-buffer
			// backpressure (we stop reading the egress; the site's window
			// collapses; no byte dropped). It returns the binding+frame to send
			// directly, or nil if the frame was buffered / the stream torn down.
			b, frame, alive := e.routeDownFrame(data, closeCh)
			if !alive {
				// Stream torn down while blocked (closeCh fired or stClosing) —
				// exit the pump without leaving a half-assigned seq.
				return
			}
			if b != nil {
				e.enqueueDownFrame(b, migrateEnabled, frame)
			}
			e.credit.consume(n)
		}
		if err != nil {
			return
		}
	}
}

// routeDownFrame is the single, fully-serialized decision point for one
// downlink frame (NEW-1, Task 10 quality-review gate). Under perEntryMu it:
//
//  1. Tears down promptly if the stream is closing / closeCh fired (returns
//     alive=false; NO seq is assigned — the counter stays gapless).
//  2. If a binding is live AND downBuffer is empty → assigns the next seq,
//     records the frame in unackedTail (resend-on-A-death tail, §5.3), and
//     returns (binding, frame) so the caller sends it directly. The send
//     itself happens OUTSIDE the lock (caller) to avoid holding perEntryMu
//     across encrypt/enqueue.
//  3. Otherwise (no binding, OR binding present but downBuffer non-empty —
//     i.e. there are still buffered frames that MUST go out first to preserve
//     order) → assigns the next seq and pushes into downBuffer. If the buffer
//     is full it blocks on bufCond (backpressure) until reassociate drains it
//     or the stream is torn down. reassociate is the sole drainer of
//     downBuffer, so the loop never races a partial drain: a frame is either
//     fully buffered (to be flushed by reassociate in seq order) or fully sent
//     on the fast path when the buffer is verified empty.
//
// Returns (binding, frame, true) to send directly; (nil, _, true) when the
// frame was buffered; (nil, _, false) on teardown.
func (e *relayEntry) routeDownFrame(data []byte, closeCh <-chan struct{}) (*binding, pendingDownFrame, bool) {
	cond := e.bufCondOf()
	e.perEntryMu.Lock()
	defer e.perEntryMu.Unlock()
	for {
		select {
		case <-closeCh:
			return nil, pendingDownFrame{}, false
		default:
		}
		if e.state.Load() == stClosing {
			return nil, pendingDownFrame{}, false
		}

		b := e.bound.Load()
		bufferEmpty := e.downBuffer.byteLen() == 0
		if b != nil && b.session != nil && b.writer != nil && bufferEmpty {
			// Fast path: send directly under the current binding. Assign the seq
			// here (under the lock) so it stays strictly ordered with any
			// concurrent buffering decision.
			seq := e.downSeqCounter.Add(1)
			frame := pendingDownFrame{seq: seq, data: data}
			// Track for resend on slot-A death before ack (NEW-1, §5.3). Bounded
			// by one flow window; the credit gate guarantees in-flight ≤ window
			// so this push always fits.
			e.unackedTail.Push(frame)
			return b, frame, true
		}

		// Buffer path: no binding, or buffered frames still pending (order must
		// be preserved). Assign the seq only once the frame is accepted into the
		// buffer, so a full buffer never creates a gap.
		seq := e.downSeqCounter.Load() + 1
		if e.downBuffer.Push(pendingDownFrame{seq: seq, data: data}) {
			e.downSeqCounter.Store(seq)
			return nil, pendingDownFrame{}, true
		}
		// Buffer full — block (backpressure) until reassociate drains it or the
		// stream is torn down. cond.Wait releases perEntryMu while parked.
		cond.Wait()
	}
}

// reassociate switches the entry to a new (session, writer) pair, drains any
// downlink buffered during the no-binding window onto the new binding in seq
// order, and — when slot A is known-dead (aDead, §5.3) — resends the still-
// unacked tail on the new binding. downSeqCounter is NEVER reset (NEW-3): the
// counter is monotonic across every migration. Returns resumeDownSeq = the
// highest seq assigned before the binding switched, so the client knows how far
// the old slot's in-flight tail extends (§3.4 MIGRATE_OK).
//
// Concurrency: the binding is published with one atomic Store of the consistent
// {session, writer} pair (NEW-5) so the relay loop can never observe a torn
// pair. The buffer is drained under perEntryMu (held only for the snapshot, not
// for the enqueue) to avoid holding the lock across encrypt/enqueue. After the
// store + drain we Broadcast bufCond so a relay loop that blocked on a full
// downBuffer during the no-binding window wakes, sees the now-non-nil binding /
// freed buffer, and resumes — no deadlock because reassociate does not hold
// perEntryMu while enqueuing.
func (e *relayEntry) reassociate(sess *core.Session, w *core.WSAsyncWriter, migrateEnabled bool, aDead bool) uint64 {
	resumeDownSeq := e.downSeqCounter.Load()
	b := &binding{session: sess, writer: w}
	e.bound.Store(b)

	cond := e.bufCondOf()
	e.perEntryMu.Lock()
	buffered := e.downBuffer.drainAll()
	var resend []pendingDownFrame
	if aDead {
		resend = e.unackedTail.tailFrames()
	}
	// Broadcast UNDER perEntryMu so the wakeup can't be lost: a relay loop that
	// observed a full buffer is either (a) still holding perEntryMu about to
	// Wait — it will Wait and this Broadcast (serialized after its Wait by the
	// mutex) wakes it, or (b) already in Wait — Broadcast wakes it. Either way
	// it re-checks under the lock and finds the drained (empty) buffer. Closing
	// the lost-wakeup window is why drainAll + Broadcast share one lock hold.
	cond.Broadcast()
	e.perEntryMu.Unlock()

	// Drain buffered-during-no-binding first, then resend the unacked tail. The
	// client reassembler dedups by f.seq < expectedSeq (§5.4) so a frame that
	// arrived on both A (in-flight) and B (resend) is idempotent.
	for _, f := range buffered {
		e.enqueueDownFrame(b, migrateEnabled, f)
	}
	for _, f := range resend {
		e.enqueueDownFrame(b, migrateEnabled, f)
	}
	return resumeDownSeq
}

// toOrphaned transitions an active entry to orphaned and stamps the clock.
// Returns false if the entry was not active (already orphaned/closing) — the
// single-winner CAS guarantees exactly one caller performs the transition.
func (e *relayEntry) toOrphaned(now int64) bool {
	if e.state.CompareAndSwap(stActive, stOrphaned) {
		e.orphanedAt.Store(now)
		return true
	}
	return false
}

// launchGraceTimer arms the grace window for an orphaned relay. After `grace`
// elapses it tries CAS(stOrphaned → stClosing). If it WINS (no RESUME arrived),
// it closes the egress tc, removes the entry from the registry, broadcasts
// bufCond (so a relay loop blocked on a full downBuffer with no binding exits),
// and ticks the grace-expired metric if supplied. If it LOSES (a RESUME already
// flipped the entry back to stActive), it does nothing — F8: a losing timer must
// never tear down a reassociated relay. The timer runs in its own goroutine so
// the caller (WS-session cleanup) is not blocked.
func (r *relayRegistry) launchGraceTimer(e *relayEntry, grace time.Duration, onExpire func()) {
	go func() {
		time.Sleep(grace)
		if !e.state.CompareAndSwap(stOrphaned, stClosing) {
			// RESUME (or another transition) already moved the entry — no-op.
			return
		}
		// Winner: tear down the orphaned relay.
		r.remove(e.originClientID, e.globalStreamID)
		if e.tc != nil {
			e.tc.Close()
		}
		// Wake a relay loop blocked in bufferDownFrameBlocking so it re-checks
		// state==stClosing and exits without assigning a seq. Broadcast UNDER
		// perEntryMu to close the lost-wakeup window against the loop's
		// check-state-then-Wait sequence (same reasoning as reassociate).
		cond := e.bufCondOf()
		e.perEntryMu.Lock()
		cond.Broadcast()
		e.perEntryMu.Unlock()
		if onExpire != nil {
			onExpire()
		}
	}()
}

// enqueueDownFrame encrypts one downlink frame under the GIVEN binding's session
// and enqueues it on that binding's writer. The binding is read once by the
// caller (relayLoop) and passed in, so a concurrent migration cannot tear the
// {session, writer} pair mid-encrypt (NEW-5: binding is an atomic pair).
func (e *relayEntry) enqueueDownFrame(b *binding, migrateEnabled bool, f pendingDownFrame) {
	var chunk *core.Chunk
	if migrateEnabled {
		chunk = core.NewStreamDataChunkSeq(b.session.ID, b.session.NextSeqNum(), e.globalStreamID, f.seq, f.data)
	} else {
		chunk = core.NewStreamDataChunk(b.session.ID, b.session.NextSeqNum(), e.globalStreamID, f.data)
	}
	enc, err := b.session.EncryptChunk(chunk)
	core.PutBuffer(chunk.Payload)
	if err != nil {
		return
	}
	_ = b.writer.Enqueue(websocketBinaryMessage, enc)
}

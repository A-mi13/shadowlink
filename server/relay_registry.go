package server

import (
	"sync"
	"sync/atomic"

	"github.com/nixavpn/shadowlink/core"
)

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

	// Egress — survives slot changes.
	tc interface{ Close() error } // net.Conn; minimal iface keeps the struct testable

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

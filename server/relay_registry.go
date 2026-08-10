package server

import (
	"log/slog"
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

	// FD accounting (F5). holdsFD is true once admitOrphan has charged this
	// entry against the registry's orphan FD budget; evictIdleOrphan / the grace
	// timer decrement the budget only for entries that actually hold it.
	//
	// Atomic (not plain bool) because the charge (admitOrphan, on the WS-death
	// cleanup goroutine) and the release (releaseOrphanFD, which may run on a
	// concurrent RESUME goroutine the instant the entry becomes stOrphaned-
	// reachable) touch it from different goroutines. The charge is now ordered
	// BEFORE the stActive→stOrphaned publish (see websocket.go cleanup), so by
	// the time a RESUME can win CAS(stOrphaned→stActive) and call releaseOrphanFD
	// the flag is already true and atomically visible — no lost decrement, no
	// data race.
	holdsFD atomic.Bool

	// destClosed (F13): set by relayLoop when the egress TCP read hit EOF/err
	// WHILE the entry was orphaned (no live binding). A subsequent RESUME flushes
	// the remaining downBuffer and then signals end-of-stream to the client so a
	// dest-closed-during-grace stream is not left hanging. The flush+FIN marker
	// itself is finalized in the resume path; this flag is the durable record
	// that the destination is gone.
	destClosed atomic.Bool

	// lastDownlinkNs (F6 idleness): unix-nanos timestamp of the most recent
	// downlink frame routed for this stream. evictIdleOrphan uses it to pick the
	// least-recently-used IDLE orphan — a relay that has not pushed data for at
	// least evictIdleThreshold is a safe eviction target (a recently-active
	// orphan is mid-transfer and likely to RESUME). Updated on the relay-loop's
	// downlink path.
	lastDownlinkNs atomic.Int64

	// Bug#8 stream credit — lives here, survives migration (F9, §5.9).
	credit *streamCredit

	// closeCh is the relay's OWN lifetime signal (§5.5): closed exactly once when
	// the relay is PERMANENTLY torn down (grace-expiry, idle-eviction, admit-
	// reject, or full session teardown) — NOT on a per-slot WS death. relayLoop
	// gates its credit wait and teardown on this channel, so the egress pump
	// survives a slot rotation/death and keeps reading the egress into downBuffer
	// during the grace window (spec §5.5: "relay-goroutine тормозит чтение …
	// (tc.Read не вызывается)" — i.e. the loop stays alive, applying backpressure,
	// rather than exiting with the slot it was created on). Created lazily by
	// closeChOf; closed idempotently by closeReader.
	closeCh     chan struct{}
	closeChOnce sync.Once
	closeOnce   sync.Once

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

// closeChOf returns the relay's permanent-teardown channel, creating it once on
// first use. Lazy so the many relayEntry literals (tests + production) need not
// each wire it. relayLoop receives the channel returned here.
func (e *relayEntry) closeChOf() chan struct{} {
	e.closeChOnce.Do(func() {
		e.closeCh = make(chan struct{})
	})
	return e.closeCh
}

// closeReader signals permanent teardown of the relay: it closes the relay's
// own lifetime channel (waking relayLoop's credit wait) and closes the stream
// credit (Bug#8) so a relay loop parked in waitForCredit unblocks and exits.
// Idempotent — safe to call from the grace timer, idle-evict, admit-reject, and
// the session-teardown paths, which may race. The egress tc itself is closed by
// the caller (it must survive the orphan window, so closeReader does NOT touch
// it).
func (e *relayEntry) closeReader() {
	e.closeOnce.Do(func() {
		close(e.closeChOf())
		if e.credit != nil {
			e.credit.close()
		}
	})
}

// relayRegistry holds relays keyed (clientID, globalStreamID), living
// independently of any single WS session (§5.1). RWMutex guards the maps;
// per-entry mutation uses relayEntry.perEntryMu / atomics.
type relayRegistry struct {
	mu       sync.RWMutex
	byClient map[string]map[uint16]*relayEntry

	// Task 12 (F5/F6) — orphan DoS caps. An orphaned relay holds a real egress
	// socket open with no WS behind it (the grace window); without caps a peer
	// can spray CONNECTs then kill the WS to pin sockets. setLimits configures:
	//   maxOrphanedPerClient — most orphaned relays a single client may hold.
	//   maxOrphanedTotal     — global ceiling across all clients.
	//   orphanFDBudget       — max orphaned egress conns held at once, derived
	//                          from RLIMIT_NOFILE (or maxOrphanedTotal on Windows
	//                          dev where readFDSoftLimit()==0).
	// Written once via setLimits before any concurrent use; read-only thereafter
	// (no lock needed for the int fields — same write-once contract as the
	// startRotation lifecycle fields in client/connmanager.go).
	maxOrphanedPerClient int
	maxOrphanedTotal     int
	orphanFDBudget       int
	evictIdleThreshold   time.Duration

	// originDeathTeardown gates Bug #10 FlagStreamClose signalling (write-once at
	// init via setOriginDeathTeardown, read-only thereafter — same contract as the
	// setLimits int fields). Resolved from Config.originDeathTeardownEnabledOrDefault
	// in NewHandler.
	originDeathTeardown bool

	// orphanedFDInUse counts orphaned relays currently holding the FD budget.
	// Mutated atomically by admitOrphan (+1) and evictIdleOrphan / grace-timer
	// teardown (-1) so the budget check needs no registry lock.
	orphanedFDInUse atomic.Int64

	// Self-contained observability. Task 18 (§4.3) surfaces these through the
	// global server Metrics text/JSON exporters; for now they let tests and ops
	// reason about the gate without coupling the registry to *Metrics.
	orphanFDRejected     atomic.Uint64 // admitOrphan rejected on FD budget
	orphanedEvictedLimit atomic.Uint64 // idle orphans evicted to enforce a cap
}

const defaultEvictIdleThreshold = 2 * time.Second

func newRelayRegistry() *relayRegistry {
	return &relayRegistry{byClient: make(map[string]map[uint16]*relayEntry)}
}

// setLimits configures the orphan DoS caps (Task 12, F5/F6). fdBudget is the
// caller-supplied FD ceiling; pass readFDSoftLimit() (minus a headroom margin)
// from production wiring. A zero/negative fdBudget means "never hold an orphan"
// (admitOrphan always rejects) — used by tests and as a fail-safe. Call once
// before the registry is shared across goroutines.
func (r *relayRegistry) setLimits(perClient, total, fdBudget int) {
	r.maxOrphanedPerClient = perClient
	r.maxOrphanedTotal = total
	r.orphanFDBudget = fdBudget
	if r.evictIdleThreshold <= 0 {
		r.evictIdleThreshold = defaultEvictIdleThreshold
	}
}

// setOriginDeathTeardown configures the Bug #10 signal gate (write-once at init).
func (r *relayRegistry) setOriginDeathTeardown(enabled bool) {
	r.originDeathTeardown = enabled
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

// hasBoundEntriesForSession reports whether any relayEntry under clientID is
// still bound to sess — i.e. an orphaned relay in the Bug#9 grace window that a
// stream may RESUME onto. The server ghost-sweep (2026-06-01) consults this as
// its eviction gate: a session with a live bound relay MUST survive until the
// relay's grace timer either resumes it (binding moves elsewhere) or tears it
// down (entry removed), so we never reclaim a session mid-migration. Cheaper
// than entriesForSession (no slice allocation) since the sweep only needs the
// boolean.
func (r *relayRegistry) hasBoundEntriesForSession(clientID string, sess *core.Session) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.byClient[clientID] {
		if b := e.bound.Load(); b != nil && b.session == sess {
			return true
		}
	}
	return false
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

// admitOrphan is the admission gate the WS-death cleanup calls before deciding
// to HOLD an orphaned relay's egress conn open through the grace window
// (Task 12, F5/F6, §5.5). The relay was already registered at CONNECT, so the
// entry `e` is present in the map; admitOrphan answers "may this client keep
// holding the orphaned relays it now has, given the caps?" and charges the FD
// budget when it says yes.
//
// ORDERING (FD-race fix, T12 quality review): the WS-death cleanup now calls
// admitOrphan while `e` is still stActive — i.e. BEFORE toOrphaned publishes the
// stOrphaned state that makes the entry reachable by a concurrent RESUME. The
// charge (orphanedFDInUse+1, holdsFD=true) therefore completes before any RESUME
// can win CAS(stOrphaned→stActive) and call releaseOrphanFD, closing the window
// where releaseOrphanFD observed holdsFD==false and skipped the decrement (a
// bounded FD-counter leak). admitOrphan's decision does NOT depend on e's own
// state: the caps are evaluated against the live map count, and evictIdleOrphan
// excludes `e` via the except arg — so charging while e is stActive is sound.
//
// Decision order:
//  1. FD budget exhausted (orphanFDBudget<=0, or in-use already at the budget)
//     → reject. A zero budget (tests / fail-safe) always rejects.
//  2. Per-client cap exceeded → try evictIdleOrphan(clientID); if still over the
//     cap (no idle orphan to reclaim) → reject.
//  3. Global cap exceeded → try evictIdleOrphan("") (any client); if still over
//     → reject.
//  4. Otherwise charge the FD budget (+1), mark e.holdsFD, accept.
//
// Counting semantics: the caps are compared with `>` against the live map count
// (which INCLUDES e). With maxOrphanedPerClient=N, the Nth held orphan is
// allowed (count==N) and the (N+1)th (count==N+1) triggers eviction/reject.
// Returns true if the relay may be held; false means the caller must close the
// egress tc immediately (graceful degradation, §5.5).
func (r *relayRegistry) admitOrphan(clientID string, e *relayEntry) bool {
	if r.orphanFDBudget <= 0 {
		r.orphanFDRejected.Add(1)
		return false
	}
	if int(r.orphanedFDInUse.Load()) >= r.orphanFDBudget {
		r.orphanFDRejected.Add(1)
		return false
	}

	if r.maxOrphanedPerClient > 0 && r.countForClient(clientID) > r.maxOrphanedPerClient {
		r.evictIdleOrphanExcept(clientID, e)
		if r.countForClient(clientID) > r.maxOrphanedPerClient {
			return false
		}
	}

	if r.maxOrphanedTotal > 0 && r.totalCount() > r.maxOrphanedTotal {
		r.evictIdleOrphanExcept("", e)
		if r.totalCount() > r.maxOrphanedTotal {
			return false
		}
	}

	r.orphanedFDInUse.Add(1)
	e.holdsFD.Store(true)
	return true
}

// releaseOrphanFD returns the entry's charged FD-budget slot exactly once and
// clears holdsFD so any later teardown path (grace timer, eviction) won't
// double-decrement (Task 12, F5). Called when an orphan is reclaimed by a
// RESUME (back to stActive) or torn down.
//
// Concurrency: the clear is an atomic CompareAndSwap(true→false), so even if two
// teardown paths race (e.g. a RESUME's release and a losing grace-timer, or an
// evict and a RESUME) exactly ONE observes the true→false transition and
// decrements the budget. This no longer leans on the single-winner state CAS to
// serialize the read-modify-write — the FD charge is ordered before the
// stActive→stOrphaned publish, so a RESUME that wins the state CAS is guaranteed
// to see holdsFD==true here and reclaim the slot.
func (r *relayRegistry) releaseOrphanFD(e *relayEntry) {
	if e.holdsFD.CompareAndSwap(true, false) {
		r.orphanedFDInUse.Add(-1)
	}
}

// evictIdleOrphan reclaims the single least-recently-used IDLE orphaned relay
// to make room under the caps (Task 12, F6). scope!="" restricts the search to
// that clientID; "" searches globally. It NEVER touches an stActive entry (an
// active stream is mid-transfer) and NEVER touches an orphan that pushed data
// within evictIdleThreshold (a recently-active orphan is likely to RESUME).
//
// Mechanism mirrors launchGraceTimer's teardown so the two never race a
// double-close: the winning CompareAndSwap(stOrphaned→stClosing) is the single
// authority to close+remove an entry. We snapshot the victim under RLock, drop
// the registry lock, then CAS; only the CAS winner closes tc, removes the entry,
// decrements the FD budget, broadcasts bufCond (so a relay loop blocked in
// routeDownFrame sees stClosing and exits), and ticks the counter. Lock order
// is registry.mu (released) → per-entry CAS / perEntryMu — identical to Task 11,
// no inversion.
func (r *relayRegistry) evictIdleOrphan(scope string) {
	r.evictIdleOrphanExcept(scope, nil)
}

// evictIdleOrphanExcept is evictIdleOrphan with one entry excluded from the
// candidate set — used by admitOrphan so the relay being admitted (whose
// lastDownlink is still zero, i.e. trivially "idle") is never chosen as its own
// eviction victim. except==nil makes it behave exactly like evictIdleOrphan.
func (r *relayRegistry) evictIdleOrphanExcept(scope string, except *relayEntry) {
	now := time.Now().UnixNano()
	threshold := r.evictIdleThreshold
	if threshold <= 0 {
		threshold = defaultEvictIdleThreshold
	}
	cutoff := now - int64(threshold)

	r.mu.RLock()
	var victim *relayEntry
	var oldest int64
	consider := func(e *relayEntry) {
		if e == except {
			return // never evict the entry currently being admitted
		}
		if e.state.Load() != stOrphaned {
			return // never evict stActive / already-stClosing
		}
		last := e.lastDownlinkNs.Load()
		if last > cutoff {
			return // recently active — not idle
		}
		if victim == nil || last < oldest {
			victim = e
			oldest = last
		}
	}
	if scope != "" {
		for _, e := range r.byClient[scope] {
			consider(e)
		}
	} else {
		for _, m := range r.byClient {
			for _, e := range m {
				consider(e)
			}
		}
	}
	r.mu.RUnlock()

	if victim == nil {
		return
	}
	// Single-winner teardown (shared CAS authority with the grace timer).
	if !victim.state.CompareAndSwap(stOrphaned, stClosing) {
		return // grace timer / RESUME already moved it
	}
	r.remove(victim.originClientID, victim.globalStreamID)
	victim.closeReader()
	if victim.tc != nil {
		victim.tc.Close()
	}
	r.releaseOrphanFD(victim)
	// Wake any relay loop parked on a full downBuffer so it re-checks stClosing
	// and exits without leaving a half-assigned seq. Broadcast UNDER perEntryMu
	// closes the lost-wakeup window (same reasoning as reassociate / grace timer).
	cond := victim.bufCondOf()
	victim.perEntryMu.Lock()
	cond.Broadcast()
	victim.perEntryMu.Unlock()
	r.orphanedEvictedLimit.Add(1)
}

// onStreamAck releases the not-yet-acked tail up to ackedSeq (FlagStreamAck
// barrier, §5.4). Called under perEntryMu by the FlagStreamAck handler.
func (e *relayEntry) onStreamAck(ackedSeq uint64) {
	cond := e.bufCondOf()
	e.perEntryMu.Lock()
	if e.unackedTail != nil {
		e.unackedTail.evictUpTo(ackedSeq)
	}
	if e.downBuffer != nil {
		e.downBuffer.evictUpTo(ackedSeq)
	}
	// The evictions above may have freed space in a full downBuffer. A relay
	// loop parked on the full buffer (cond.Wait) won't re-check on its own —
	// Broadcast UNDER the held perEntryMu (same lost-wakeup-window close as
	// reassociate/grace-timer) so it re-evaluates and resumes buffering.
	cond.Broadcast()
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
			// F6 idleness: stamp the last-downlink clock so evictIdleOrphan can
			// distinguish a mid-transfer orphan (recently pushed data — likely to
			// RESUME) from a stalled one (safe to reclaim under cap pressure).
			e.lastDownlinkNs.Store(time.Now().UnixNano())
			e.credit.consume(n)
		}
		if err != nil {
			// Bug #10 Component 1: origin TCP read closed/errored. Record
			// destClosed UNCONDITIONALLY (was: only when stOrphaned). For an
			// active stream a later teardown / RESUME-fallback delivers the
			// client signal; for an orphaned one RESUME/grace does. Either way
			// the stream no longer hangs.
			e.destClosed.Store(true)
			// Part 1b (Bug #9 NEW-4 followup) — eager registry/FD release on a
			// NORMAL dest EOF over a LIVE binding is intentionally NOT done here.
			// TODO(bug9-1b): A relay whose downlink (dest→client) hit EOF on a
			// still-stActive slot leaves its relayEntry in the registry (and its
			// egress tc open) until the WS session dies, when entriesForSession
			// orphans it and the grace timer removes it. That is a bounded,
			// short-lived egress leak — NOT data loss, NOT a credit hang. We do
			// NOT close tc / remove the entry on this path because the egress TCP
			// is BIDIRECTIONAL: a dest read-EOF (download finished) does not imply
			// the uplink (client→dest, routed via streams[sid].Write on the reader
			// loop) is finished — a request body may still be uploading. Closing tc
			// or removing the registry entry here would break that half-open
			// uplink and would also race MIGRATE/RESUME/grace single-winner CAS.
			// A correct eager release needs a half-close-aware teardown (CloseRead
			// on tc, keep the write half, remove from registry only once BOTH
			// directions are done) tracked separately; the leak self-heals on
			// session teardown so it is not shippable-blocking.
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

// reassociate drains downlink buffered during the no-binding window onto the
// ALREADY-PUBLISHED binding `b` in seq order, and — when slot A is known-dead
// (aDead, §5.3) — resends the still-unacked tail. downSeqCounter is NEVER reset
// (NEW-3): the counter is monotonic across every migration. Returns
// resumeDownSeq = the highest seq assigned before the binding switched, so the
// client knows how far the old slot's in-flight tail extends (§3.4 MIGRATE_OK).
//
// NIT-1 (Bug #10): reassociate NO LONGER stores the binding — the caller
// publishes e.bound.Store(b) BEFORE calling reassociate (b1: before the stActive
// CAS). reassociate is now pure drain, so there is exactly ONE publication point
// for B.
//
// Concurrency: the buffer is drained AND flushed under perEntryMu — the lock is
// held across the encrypt/enqueue of the snapshot, because routeDownFrame's fast
// path is the competing producer on the same writer and must not interleave a
// higher seq into the middle of the flush (see the ORDERING note in the body).
// The Broadcast then happens under that same lock hold, so a relay loop blocked
// on a full downBuffer during the no-binding window wakes only after the flush is
// complete, sees the freed buffer and the live binding, and resumes in order.
//
// originDeathTeardown gates the Component-4 RESUME-fallback (Bug #10 Task 7):
// when true AND e.destClosed is set, after the drain a FlagStreamClose is sent
// on the new binding B. Threaded as a param because reassociate is a *relayEntry
// method with no registry reference.
func (e *relayEntry) reassociate(b *binding, migrateEnabled, aDead, originDeathTeardown bool) uint64 {
	resumeDownSeq := e.downSeqCounter.Load()

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
	//
	// Drain buffered-during-no-binding first, then resend the unacked tail. The
	// client reassembler dedups by f.seq < expectedSeq (§5.4) so a frame that
	// arrived on both A (in-flight) and B (resend) is idempotent.
	//
	// ORDERING (fixed 2026-08-10, caught under -race on Linux): the flush runs
	// STILL UNDER perEntryMu. Previously the lock was released before this loop,
	// which opened a reorder window: drainAll had already emptied downBuffer, so a
	// relayLoop woken by the Broadcast saw bufferEmpty==true plus a live binding,
	// took the fast path in routeDownFrame, and enqueued its fresh (higher) seq
	// onto the SAME writer while frames 1..N of this snapshot were still being
	// enqueued here. Two producers, one FIFO writer queue → interleaving, e.g.
	// enqueue order DRAIN:1 DRAIN:2 LOOP:4 DRAIN:3, which the client sees as
	// "seq gap: got seq=4 after 2". No frame was ever lost — purely order. Holding
	// the lock across the flush makes this snapshot atomic w.r.t. routeDownFrame,
	// which is the only other producer. Note the enqueue is non-blocking enough
	// for this: WSAsyncWriter.Enqueue only blocks when the outbound channel is
	// full, and the flow-control credit gate bounds in-flight downlink to one
	// window, so the flush cannot deadlock against the loop it is excluding.
	for _, f := range buffered {
		e.enqueueDownFrame(b, migrateEnabled, f)
	}
	for _, f := range resend {
		e.enqueueDownFrame(b, migrateEnabled, f)
	}
	cond.Broadcast()
	e.perEntryMu.Unlock()
	// Bug #10 Component 4 (RESUME-fallback): if the origin died while this relay
	// was orphaned (destClosed is set), the immediate FlagStreamClose either was
	// never sent (read-EOF orphaned path) or went to a dead writer ("both TCP
	// died at once"). Now that we have a LIVE binding B again, deliver the
	// stream-close on it so the client tears down the stream and retries.
	if originDeathTeardown && e.destClosed.Load() {
		chunk := core.NewStreamCloseChunk(b.session.ID, b.session.NextSeqNum(), e.globalStreamID)
		if enc, err := b.session.EncryptChunk(chunk); err == nil {
			_ = b.writer.Enqueue(websocketBinaryMessage, enc)
		}
		// NewStreamCloseChunk allocates a 2-byte heap slice (not pooled);
		// PutBuffer is a no-op here, kept for symmetry with signalStreamEnd.
		core.PutBuffer(chunk.Payload)
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
		//
		// Bug #10 note: a grace-expired orphan whose origin had died (destClosed)
		// is torn down here WITHOUT sending FlagStreamClose — intentionally. The
		// signal needs a live binding, and for an orphan that never got a RESUME
		// there is none (its WS slot is gone). The client learns of the break via
		// its OWN slot-death cleanup (handleSlotDeath → closeStream) when slot A
		// died, so there is no hang. The FlagStreamClose path matters for the
		// LIVE-slot symptom (origin dead but WS slot alive), which signalStreamEnd
		// (active branch) and the RESUME-fallback in reassociate already cover.
		r.remove(e.originClientID, e.globalStreamID)
		// Permanent teardown: stop the egress pump (closeCh + credit) so the
		// relayLoop exits, THEN close the egress tc. Ordering closeReader before
		// tc.Close is not strictly required (the loop also exits on tc read error)
		// but makes the intent explicit and unblocks a credit-parked loop.
		e.closeReader()
		if e.tc != nil {
			e.tc.Close()
		}
		// Task 12 (F5): release the FD budget this entry charged at admitOrphan
		// so a grace-expired relay frees its slot for the next orphan.
		r.releaseOrphanFD(e)
		// Wake a relay loop blocked in routeDownFrame so it re-checks
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

// signalStreamEnd is the centralized Bug #10 origin-death teardown. Called from
// BOTH uplink write-error paths (A=startWriter callback, B=registry-fallback)
// and (indirectly via destClosed) the relayLoop read-EOF path. Single-winner via
// CAS(stActive→stClosing):
//
//   - WON (was stActive, live WS slot): snapshot bound ONCE, send FlagStreamClose
//     on that live binding (session+writer from one snapshot), then permanent
//     teardown (remove + closeReader + releaseOrphanFD + tc.Close + broadcast).
//   - NOT stActive (orphaned/closing): do NOT CAS, do NOT remove — only
//     destClosed.Store(true) when stOrphaned (NIT-3, mirrors relayLoop read-EOF).
//     RESUME-fallback or the grace timer delivers the close on a live slot and
//     tears down.
//
// r.originDeathTeardown gates SENDING (YAML origin_death_teardown, default-off
// first canary). migrateEnabled is a defense-in-depth assert (HIGH-C): the helper
// is only reachable under migration paths; on a legacy session it logs and
// returns without sending.
func (r *relayRegistry) signalStreamEnd(e *relayEntry, migrateEnabled bool, pathTag string) {
	if !migrateEnabled {
		slog.Warn("bug10 helper reached on non-migration session", "stream", e.globalStreamID, "path", pathTag)
		return
	}

	if e.state.CompareAndSwap(stActive, stClosing) {
		// Won the CAS — we are the single teardown authority for this stream.
		b := e.bound.Load()
		if r.originDeathTeardown && b != nil && b.session != nil && b.writer != nil {
			chunk := core.NewStreamCloseChunk(b.session.ID, b.session.NextSeqNum(), e.globalStreamID)
			if enc, err := b.session.EncryptChunk(chunk); err == nil {
				_ = b.writer.Enqueue(websocketBinaryMessage, enc)
			}
			// NewStreamCloseChunk allocates a 2-byte heap slice (not pooled);
			// PutBuffer is a no-op here, kept for symmetry with enqueueDownFrame
			// in case the constructor later uses a pooled buffer.
			core.PutBuffer(chunk.Payload)
		}
		r.remove(e.originClientID, e.globalStreamID)
		e.closeReader()
		r.releaseOrphanFD(e)
		if e.tc != nil {
			e.tc.Close()
		}
		cond := e.bufCondOf()
		e.perEntryMu.Lock()
		cond.Broadcast()
		e.perEntryMu.Unlock()
		return
	}

	// Did not win CAS — entry is stOrphaned or stClosing. Record destClosed so
	// a later RESUME-fallback (Task 7) or grace timer can signal the client.
	// NIT-3: mirrors relayLoop read-EOF which only sets destClosed, never removes.
	if e.state.Load() == stOrphaned {
		e.destClosed.Store(true)
	}
}

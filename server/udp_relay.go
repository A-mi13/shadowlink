package server

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// defaultUDPRespCap is the per-flow response-byte ceiling (LOW-4, 2026-06-11).
// Guards against UDP amplification (DNS ANY, QUIC) — a single small client
// datagram cannot pull more than this many response bytes through one flow.
// 0 disables the cap. The default is intentionally off (0) so the cap is opt-in
// per deployment (see SetMaxResp / Open Question §2 in the impl spec); the
// handler/operator can raise or enable it after a field measurement.
const defaultUDPRespCap = 0

// flowKey identifies a UDP flow by the authenticated server-side session ID
// AND the client-supplied stream ID. sessionID comes from the authenticated
// core.Session (NOT from the wire) — this gives cross-session isolation
// WITHOUT any wire-format change: streamID stays exactly as transmitted in the
// UDP chunk; the composite key lives only in the server's NAT table.
type flowKey struct {
	sessionID uint32
	streamID  uint16
}

// udpFlow represents a single UDP "connection" (NAT binding) for a stream.
type udpFlow struct {
	conn       *net.UDPConn
	lastActive time.Time
	onReceive  func(data []byte)
	respBytes  int64 // LOW-4: cumulative response bytes for amplification cap
}

// UDPRelay manages a NAT table of UDP flows keyed by (sessionID, streamID).
// Each flow has its own UDP socket bound to a specific remote target. The
// composite key gives cross-session tenant isolation (C1a): two authenticated
// clients that both use streamID=1 land on distinct flows and never share a
// socket or onReceive callback.
type UDPRelay struct {
	mu      sync.RWMutex
	flows   map[flowKey]*udpFlow
	timeout time.Duration
	maxResp int64 // LOW-4: per-flow response-byte ceiling (0 = unlimited)

	// onCapped / onReaped are optional nil-safe metric hooks. They are set ONCE
	// via SetHooks at Handler construction time — before any goroutine that
	// reads them starts — so reading them lock-free here is race-free.
	onCapped func() // incremented when a response is dropped by the per-flow cap
	onReaped func() // incremented per flow reaped by the Cleanup idle ticker
}

// NewUDPRelay creates a new UDP relay with the given flow inactivity timeout.
func NewUDPRelay(timeout time.Duration) *UDPRelay {
	return &UDPRelay{
		flows:   make(map[flowKey]*udpFlow),
		timeout: timeout,
		maxResp: defaultUDPRespCap,
	}
}

// SetMaxResp sets the per-flow response-byte ceiling (LOW-4 amplification cap).
// 0 disables the cap. Safe to call before flows exist (e.g. right after New).
func (r *UDPRelay) SetMaxResp(n int64) {
	r.mu.Lock()
	r.maxResp = n
	r.mu.Unlock()
}

// SetHooks installs nil-safe metric callbacks. Call ONCE at init before the
// relay starts serving (before any readLoop / Cleanup goroutine runs) so the
// lock-free reads in readLoop/Cleanup are race-free.
func (r *UDPRelay) SetHooks(onCapped, onReaped func()) {
	r.onCapped = onCapped
	r.onReaped = onReaped
}

// Send sends data to targetAddr via the flow for (sessionID, streamID).
// If no flow exists, a new UDP connection is created and a readLoop goroutine
// is started. The onReceive callback is called with any data received from the
// remote side. sessionID MUST come from the authenticated server-side session
// (core.Session.ID), not from the wire — this is what isolates tenants.
func (r *UDPRelay) Send(sessionID uint32, streamID uint16, targetAddr string, data []byte, onReceive func([]byte)) error {
	key := flowKey{sessionID: sessionID, streamID: streamID}

	r.mu.Lock()
	if flow, exists := r.flows[key]; exists {
		// Update fields under the write lock to avoid data race with readLoop
		flow.lastActive = time.Now()
		flow.onReceive = onReceive
		conn := flow.conn
		r.mu.Unlock()

		_, err := conn.Write(data)
		return err
	}
	r.mu.Unlock()

	// Resolve target address
	raddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return err
	}

	// Dial creates a connected UDP socket — Write/Read go to/from raddr.
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}

	flow := &udpFlow{
		conn:       conn,
		lastActive: time.Now(),
		onReceive:  onReceive,
	}

	r.mu.Lock()
	// Double-check: another goroutine may have created the flow while we dialed.
	if existing, ok := r.flows[key]; ok {
		// Update fields under the lock to avoid data race with readLoop
		existing.lastActive = time.Now()
		existing.onReceive = onReceive
		r.mu.Unlock()
		conn.Close() // discard our duplicate
		_, err := existing.conn.Write(data)
		return err
	}
	r.flows[key] = flow
	r.mu.Unlock()

	// Start read loop for this flow
	go r.readLoop(key, flow)

	_, err = conn.Write(data)
	return err
}

// readLoop reads packets from the remote UDP socket and delivers them via onReceive.
// It exits when the connection is closed or the read deadline fires without data.
// On exit it closes the socket and removes its own map entry (C1b self-teardown)
// so a later Send never finds a stale flow with no live readLoop.
func (r *UDPRelay) readLoop(key flowKey, flow *udpFlow) {
	buf := core.GetBuffer(65535)
	defer core.PutBuffer(buf)
	for {
		flow.conn.SetReadDeadline(time.Now().Add(r.timeout))
		n, err := flow.conn.Read(buf)
		if n > 0 {
			// LOW-4: per-flow amplification ceiling. Accumulate response bytes
			// under the lock; once the cap is hit, drop the packet (do NOT
			// deliver, do NOT accumulate further) so a tiny request cannot pull
			// an unbounded response through this flow.
			r.mu.Lock()
			capped := r.maxResp > 0 && flow.respBytes+int64(n) > r.maxResp
			if !capped {
				flow.respBytes += int64(n)
			}
			r.mu.Unlock()
			if capped {
				slog.Debug("udp flow response cap hit", "stream_id", key.streamID, "session_id", key.sessionID)
				if r.onCapped != nil {
					r.onCapped()
				}
				continue
			}

			data := core.GetBuffer(n)
			data = data[:n]
			copy(data, buf[:n])

			r.mu.RLock()
			cb := flow.onReceive
			r.mu.RUnlock()

			if cb != nil {
				cb(data)
			}
			// cb is synchronous — data is fully consumed by this point.
			core.PutBuffer(data)

			r.mu.Lock()
			flow.lastActive = time.Now()
			r.mu.Unlock()
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				slog.Debug("udp flow read timeout", "stream_id", key.streamID, "session_id", key.sessionID)
			}
			// C1b self-teardown: close socket + delete map entry on exit so a
			// later Send never finds a stale flow with no live readLoop. The
			// identity check (cur == flow) guards against deleting a NEW flow
			// that reused the same key after a reconnect.
			r.mu.Lock()
			if cur, ok := r.flows[key]; ok && cur == flow {
				delete(r.flows, key)
			}
			r.mu.Unlock()
			flow.conn.Close()
			return
		}
	}
}

// Cleanup removes all flows that have been inactive for longer than the timeout.
func (r *UDPRelay) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for key, flow := range r.flows {
		if now.Sub(flow.lastActive) > r.timeout {
			flow.conn.Close()
			delete(r.flows, key)
			if r.onReaped != nil {
				r.onReaped()
			}
		}
	}
}

// FlowCount returns the number of active UDP flows.
func (r *UDPRelay) FlowCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.flows)
}

// RemoveFlow closes and removes the flow for the given (sessionID, streamID).
func (r *UDPRelay) RemoveFlow(sessionID uint32, streamID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := flowKey{sessionID: sessionID, streamID: streamID}
	if flow, ok := r.flows[key]; ok {
		flow.conn.Close()
		delete(r.flows, key)
	}
}

// RemoveSession closes and removes ALL flows belonging to sessionID.
// Called on session teardown (handleFin / idle session cleanup) so a dead
// session never leaves UDP sockets/NAT entries behind.
func (r *UDPRelay) RemoveSession(sessionID uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, flow := range r.flows {
		if key.sessionID == sessionID {
			flow.conn.Close()
			delete(r.flows, key)
		}
	}
}

// Close closes all flows and resets the NAT table.
func (r *UDPRelay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for key, flow := range r.flows {
		flow.conn.Close()
		delete(r.flows, key)
	}
}

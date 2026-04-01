package server

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// udpFlow represents a single UDP "connection" (NAT binding) for a stream.
type udpFlow struct {
	conn       *net.UDPConn
	lastActive time.Time
	onReceive  func(data []byte)
}

// UDPRelay manages a NAT table of UDP flows keyed by stream ID.
// Each flow has its own UDP socket bound to a specific remote target.
type UDPRelay struct {
	mu      sync.RWMutex
	flows   map[uint16]*udpFlow // streamID -> flow
	timeout time.Duration
}

// NewUDPRelay creates a new UDP relay with the given flow inactivity timeout.
func NewUDPRelay(timeout time.Duration) *UDPRelay {
	return &UDPRelay{
		flows:   make(map[uint16]*udpFlow),
		timeout: timeout,
	}
}

// Send sends data to targetAddr via the flow for streamID.
// If no flow exists for streamID, a new UDP connection is created and a
// readLoop goroutine is started. The onReceive callback is called with any
// data received from the remote side.
func (r *UDPRelay) Send(streamID uint16, targetAddr string, data []byte, onReceive func([]byte)) error {
	r.mu.Lock()
	flow, exists := r.flows[streamID]
	if exists {
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

	flow = &udpFlow{
		conn:       conn,
		lastActive: time.Now(),
		onReceive:  onReceive,
	}

	r.mu.Lock()
	// Double-check: another goroutine may have created the flow while we dialed.
	if existing, ok := r.flows[streamID]; ok {
		// Update fields under the lock to avoid data race with readLoop
		existing.lastActive = time.Now()
		existing.onReceive = onReceive
		r.mu.Unlock()
		conn.Close() // discard our duplicate
		_, err := existing.conn.Write(data)
		return err
	}
	r.flows[streamID] = flow
	r.mu.Unlock()

	// Start read loop for this flow
	go r.readLoop(streamID, flow)

	_, err = conn.Write(data)
	return err
}

// readLoop reads packets from the remote UDP socket and delivers them via onReceive.
// It exits when the connection is closed or the read deadline fires without data.
func (r *UDPRelay) readLoop(streamID uint16, flow *udpFlow) {
	buf := core.GetBuffer(65535)
	defer core.PutBuffer(buf)
	for {
		flow.conn.SetReadDeadline(time.Now().Add(r.timeout))
		n, err := flow.conn.Read(buf)
		if n > 0 {
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
			// Timeout or closed — exit the loop; Cleanup will remove the flow.
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				slog.Debug("udp flow read timeout", "stream_id", streamID)
			}
			return
		}
	}
}

// Cleanup removes all flows that have been inactive for longer than the timeout.
func (r *UDPRelay) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for id, flow := range r.flows {
		if now.Sub(flow.lastActive) > r.timeout {
			flow.conn.Close()
			delete(r.flows, id)
		}
	}
}

// FlowCount returns the number of active UDP flows.
func (r *UDPRelay) FlowCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.flows)
}

// RemoveFlow closes and removes the flow for the given streamID.
func (r *UDPRelay) RemoveFlow(streamID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if flow, ok := r.flows[streamID]; ok {
		flow.conn.Close()
		delete(r.flows, streamID)
	}
}

// Close closes all flows and resets the NAT table.
func (r *UDPRelay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, flow := range r.flows {
		flow.conn.Close()
		delete(r.flows, id)
	}
}

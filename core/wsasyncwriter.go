package core

import (
	"errors"
	"sync"
	"time"
)

// WSConnWriter is the minimal subset of *gorilla/websocket.Conn needed by
// WSAsyncWriter. Defined as an interface so the writer can be unit-tested
// without a real WS connection and shared between server and client packages.
type WSConnWriter interface {
	WriteMessage(messageType int, data []byte) error
	SetWriteDeadline(t time.Time) error
}

// wsOutboundMsg is one queued WS frame.
type wsOutboundMsg struct {
	msgType int
	data    []byte
}

// ErrWSWriterClosed is returned by Enqueue after the writer has been closed
// either gracefully (Close) or by an underlying write error (Run exit).
var ErrWSWriterClosed = errors.New("ws async writer: closed")

// WSAsyncWriter decouples WS frame producers from a potentially slow
// underlying connection. All goroutines that previously contended on a
// single writeMu+conn.WriteMessage now push into buffered channels; one
// dedicated goroutine drains them.
//
// Two priority levels:
//   - control (high): CONNECT, FIN, keepalive, ACK — latency-sensitive
//   - data (low): relay payload — throughput-sensitive
//
// The Run loop always drains all pending control messages before servicing
// data. This prevents 100 concurrent data streams from starving CONNECT
// requests which would otherwise wait 5+ seconds behind 32KB data chunks.
//
// The writer can be closed once. After close, Enqueue/EnqueueControl return
// ErrWSWriterClosed. Run returns the first underlying write error, or nil
// on graceful Close.
type WSAsyncWriter struct {
	conn         WSConnWriter
	control      chan wsOutboundMsg // high-priority: CONNECT, FIN, keepalive
	outbound     chan wsOutboundMsg // low-priority: data relay
	done         chan struct{}
	runDone      chan struct{} // closed when Run() returns — callers can wait on this
	closeOnce    sync.Once
	writeTimeout time.Duration
}

// NewWSAsyncWriter constructs a WSAsyncWriter with the given outbound data
// buffer capacity. bufSize controls how many data frames may be queued before
// Enqueue starts to block. The control channel gets a fixed 64-frame buffer
// (control messages are small and infrequent).
func NewWSAsyncWriter(conn WSConnWriter, bufSize int) *WSAsyncWriter {
	if bufSize < 1 {
		bufSize = 1
	}
	return &WSAsyncWriter{
		conn:         conn,
		control:      make(chan wsOutboundMsg, 64),
		outbound:     make(chan wsOutboundMsg, bufSize),
		done:         make(chan struct{}),
		runDone:      make(chan struct{}),
		writeTimeout: 30 * time.Second,
	}
}

// SetWriteTimeout overrides the per-frame write deadline. Must be called
// before Run. Default is 30 seconds.
func (w *WSAsyncWriter) SetWriteTimeout(d time.Duration) {
	if d > 0 {
		w.writeTimeout = d
	}
}

// Run blocks draining control and outbound channels to conn until Close is
// called or an underlying write returns an error. Control messages are always
// written before data messages (priority drain pattern).
//
// Returns nil on graceful close, or the first write error encountered.
// Closes runDone on exit so callers can wait for the writer to fully stop.
func (w *WSAsyncWriter) Run() error {
	defer close(w.runDone)

	for {
		// Phase 1: drain all pending control messages (non-blocking).
		// This ensures CONNECT/FIN/keepalive always jump ahead of data.
		for {
			select {
			case msg := <-w.control:
				if err := w.writeFrame(msg); err != nil {
					w.closeOnce.Do(func() { close(w.done) })
					return err
				}
			default:
				goto waitBoth
			}
		}

	waitBoth:
		// Phase 2: block until a message arrives on either channel.
		// If both are ready, Go's select picks randomly — but we loop back
		// to phase 1 after every control message, so sustained data traffic
		// cannot starve control.
		select {
		case msg := <-w.control:
			if err := w.writeFrame(msg); err != nil {
				w.closeOnce.Do(func() { close(w.done) })
				return err
			}
		case msg, ok := <-w.outbound:
			if !ok {
				return nil
			}
			if err := w.writeFrame(msg); err != nil {
				w.closeOnce.Do(func() { close(w.done) })
				return err
			}
		case <-w.done:
			return w.drainRemaining()
		}
	}
}

// RunDone returns a channel that is closed when Run() exits. Callers can
// wait on this to ensure no more writes will happen before closing the
// underlying connection.
func (w *WSAsyncWriter) RunDone() <-chan struct{} {
	return w.runDone
}

func (w *WSAsyncWriter) writeFrame(msg wsOutboundMsg) error {
	_ = w.conn.SetWriteDeadline(time.Now().Add(w.writeTimeout))
	return w.conn.WriteMessage(msg.msgType, msg.data)
}

// drainRemaining flushes queued messages (control first, then data) on
// graceful close so producers that already passed the closed-check don't
// get silently dropped.
func (w *WSAsyncWriter) drainRemaining() error {
	// Drain control first (priority).
	for {
		select {
		case msg := <-w.control:
			if err := w.writeFrame(msg); err != nil {
				return err
			}
		default:
			goto drainData
		}
	}
drainData:
	for {
		select {
		case msg := <-w.outbound:
			if err := w.writeFrame(msg); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// Enqueue schedules a data frame for writing. It blocks only if the outbound
// buffer is full (natural backpressure), and returns ErrWSWriterClosed if
// the writer has been closed.
func (w *WSAsyncWriter) Enqueue(msgType int, data []byte) error {
	// Fast path: writer already closed.
	select {
	case <-w.done:
		return ErrWSWriterClosed
	default:
	}

	// Copy so callers may reuse their buffers immediately after Enqueue
	// returns. Without this, a caller that pools its encrypted chunk could
	// recycle the buffer before Run consumes it from the channel.
	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case w.outbound <- wsOutboundMsg{msgType: msgType, data: cp}:
		return nil
	case <-w.done:
		return ErrWSWriterClosed
	}
}

// EnqueueControl schedules a control frame (CONNECT, FIN, keepalive) for
// writing with high priority. Control messages are always drained before
// data messages in the Run loop.
func (w *WSAsyncWriter) EnqueueControl(msgType int, data []byte) error {
	select {
	case <-w.done:
		return ErrWSWriterClosed
	default:
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case w.control <- wsOutboundMsg{msgType: msgType, data: cp}:
		return nil
	case <-w.done:
		return ErrWSWriterClosed
	}
}

// Close signals the writer to stop. Idempotent. Run will return after
// draining any frames currently buffered.
func (w *WSAsyncWriter) Close() {
	w.closeOnce.Do(func() { close(w.done) })
}

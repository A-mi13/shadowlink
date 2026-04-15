package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// maxStreamsPerSession limits concurrent multiplexed streams per WebSocket session
// to prevent resource exhaustion attacks.
const maxStreamsPerSession = 256

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  131072,
	WriteBufferSize: 131072,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// wsStream represents one multiplexed stream with async write buffer.
// Supports optimistic CONNECT: data can arrive before target TCP is established.
// In "pending" state (targetConn==nil), data is buffered in pendingBuf.
// When Activate() is called with the target conn, pending data is flushed.
type wsStream struct {
	targetConn net.Conn
	writeCh    chan []byte
	done       chan struct{}
	closeOnce  sync.Once

	// Optimistic CONNECT support: buffer data arriving before TCP dial completes.
	mu         sync.Mutex
	connected  bool     // true after Activate() — target TCP is ready
	pendingBuf [][]byte // data buffered while !connected (capped at pendingBufMax)
}

const pendingBufMax = 64 // max queued chunks before TCP dial completes

// newPendingWSStream creates a stream in "pending" state (no target conn yet).
// Data written via Write() is buffered until Activate() is called.
func newPendingWSStream() *wsStream {
	return &wsStream{
		writeCh: make(chan []byte, 256),
		done:    make(chan struct{}),
	}
}

func newWSStream(tc net.Conn) *wsStream {
	s := &wsStream{
		targetConn: tc,
		writeCh:    make(chan []byte, 256),
		done:       make(chan struct{}),
		connected:  true,
	}
	s.startWriter()
	return s
}

// Activate transitions stream from pending to connected: sets target conn,
// flushes buffered data, starts the writer goroutine.
func (s *wsStream) Activate(tc net.Conn) {
	s.mu.Lock()
	s.targetConn = tc
	s.connected = true
	pending := s.pendingBuf
	s.pendingBuf = nil
	s.mu.Unlock()

	// Flush buffered data to target
	for _, data := range pending {
		tc.Write(data)
		core.PutBuffer(data)
	}

	s.startWriter()
}

// startWriter launches the writer goroutine that drains writeCh to targetConn.
func (s *wsStream) startWriter() {
	// CRIT-5 fix: writer goroutine watches done channel to exit cleanly
	// without relying on close(writeCh) which races with Write().
	go func() {
		for {
			select {
			case data, ok := <-s.writeCh:
				if !ok {
					return
				}
				_, err := s.targetConn.Write(data)
				core.PutBuffer(data)
				if err != nil {
					s.Close()
					return
				}
			case <-s.done:
				// Drain: keep reading until channel is empty for 1ms
				drainTimer := time.NewTimer(time.Millisecond)
				defer drainTimer.Stop()
				for {
					select {
					case data := <-s.writeCh:
						core.PutBuffer(data)
						drainTimer.Reset(time.Millisecond)
					case <-drainTimer.C:
						return
					}
				}
			}
		}
	}()
}

func (s *wsStream) Write(data []byte) {
	cp := core.GetBuffer(len(data))
	cp = cp[:len(data)]
	copy(cp, data)

	s.mu.Lock()
	if !s.connected {
		// Pending state: buffer data until Activate()
		if len(s.pendingBuf) < pendingBufMax {
			s.pendingBuf = append(s.pendingBuf, cp)
		} else {
			core.PutBuffer(cp) // drop if buffer full
		}
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	select {
	case s.writeCh <- cp:
	case <-s.done:
		core.PutBuffer(cp)
	}
}

// CRIT-5 fix: don't close writeCh in Close() — let the writer goroutine
// exit via done channel. writeCh will be GC'd when no references remain.
func (s *wsStream) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		// Free any pending buffers
		s.mu.Lock()
		for _, b := range s.pendingBuf {
			core.PutBuffer(b)
		}
		s.pendingBuf = nil
		s.mu.Unlock()
		if s.targetConn != nil {
			s.targetConn.Close()
		}
	})
}

// handleWebSocket upgrades to WebSocket for full-duplex stream-multiplexed relay.
func (h *Handler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	tokenBytes, err := browser.ExtractSessionToken(r)
	if err != nil {
		h.decoy.ServeHTTP(w, r)
		return
	}

	session := h.findSession(tokenBytes)
	if session == nil {
		h.decoy.ServeHTTP(w, r)
		return
	}

	h.tunnelsMu.RLock()
	_, ok := h.tunnels[session.ID]
	h.tunnelsMu.RUnlock()
	if !ok {
		h.decoy.ServeHTTP(w, r)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	conn.SetReadLimit(256 * 1024) // 256KB — large enough for any encrypted chunk

	// Async write queue: decouples per-stream relay goroutines and CONNECT_OK
	// responses from a slow underlying TCP send buffer (CF egress under load).
	// Previously a single writeMu serialized every WriteMessage call, so a
	// CONNECT_OK could be queued behind a 32KB target relay write blocked on
	// the kernel send buffer — the client then timed out at 10s while the
	// server log already showed "CONNECT_OK sent". The queue absorbs bursts
	// (50+ simultaneous CONNECT_OK during system VPN start). Shared with the
	// client via core.WSAsyncWriter (same bottleneck existed symmetrically
	// on client ws_transport.go).
	writer := core.NewWSAsyncWriter(conn, 512)
	writeMsg := func(data []byte) error {
		return writer.Enqueue(websocket.BinaryMessage, data)
	}

	streams := make(map[uint16]*wsStream)
	streamsMu := &sync.Mutex{}

	done := make(chan struct{})
	var doneOnce sync.Once
	closeDone := func() { doneOnce.Do(func() { close(done) }) }

	// Writer goroutine: drains the outbound queue into the WS connection.
	// On underlying write error, signals shutdown so the reader and ping
	// goroutines exit cleanly.
	go func() {
		if err := writer.Run(); err != nil {
			slog.Warn("WS writer exit", "err", err)
		}
		closeDone()
	}()

	// WS-level pong handler — reset read deadline on pong
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Server-side WS ping every 20s — keeps CF proxy connection alive.
	// Routed through the same async writer so it cannot stall behind a slow
	// data write, and cannot itself stall data writes.
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := writer.EnqueueControl(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	// Reader: client WS → route to target streams
	go func() {
		defer closeDone()
		wsMessages := 0
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				slog.Warn("WS reader exit", "messages", wsMessages, "err", err)
				return
			}
			wsMessages++
			if msgType != websocket.BinaryMessage || len(data) == 0 {
				continue
			}

			chunk, err := session.DecryptChunkSafe(data)
			if err != nil {
				continue
			}
			if !session.AcceptSeqNum(chunk.SeqNum) {
				continue
			}

			switch chunk.Flags {
			case core.FlagData:
				streamID, payload := core.ParseStreamID(chunk.Payload)
				streamsMu.Lock()
				s := streams[streamID]
				streamsMu.Unlock()
				if s != nil && len(payload) > 0 {
					s.Write(payload) // async — never blocks!
				}

			case core.FlagConnect:
				streamID, targetBytes := core.ParseStreamID(chunk.Payload)
				target := string(targetBytes)
				if target == "" {
					continue
				}

				// SEC-H3 fix: limit concurrent streams per session to prevent resource exhaustion
				streamsMu.Lock()
				streamCount := len(streams)
				streamsMu.Unlock()
				slog.Info("WS CONNECT received", "stream", streamID, "target", target,
					"activeStreams", streamCount)
				if streamCount >= maxStreamsPerSession {
					slog.Warn("max streams per session exceeded", "limit", maxStreamsPerSession)
					errChunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, []byte("CONNECT_FAIL"))
					if enc, err := session.EncryptChunk(errChunk); err == nil {
						writeMsg(enc)
					}
					core.PutBuffer(errChunk.Payload)
					continue
				}

				// Optimistic CONNECT: create pending stream BEFORE dial so data
				// arriving from client is buffered (not dropped). This eliminates
				// the round-trip wait that blocks system VPN through CF CDN.
				pendingStream := newPendingWSStream()
				streamsMu.Lock()
				streams[streamID] = pendingStream
				streamsMu.Unlock()

				// ASYNC dial: SafeDial blocks up to 10s per target.
				go func(sid uint16, tgt string, s *wsStream) {
					// X-1 fix: check server-side block list before dialing
					if len(h.config.BlockDomains) > 0 {
						blockHost := tgt
						if bh, _, err := net.SplitHostPort(tgt); err == nil {
							blockHost = bh
						}
						if isBlockedDomain(blockHost, h.config.BlockDomains) {
							slog.Debug("blocked domain (ws)", "host", blockHost)
							s.Close()
							streamsMu.Lock()
							delete(streams, sid)
							streamsMu.Unlock()
							errChunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), sid, []byte("CONNECT_FAIL"))
							if enc, err := session.EncryptChunk(errChunk); err == nil {
								writeMsg(enc)
							}
							core.PutBuffer(errChunk.Payload)
							return
						}
					}

					dialStart := time.Now()
					slog.Info("WS CONNECT dial start", "stream", sid, "target", tgt)
					tc, err := SafeDial(context.Background(), tgt, 10*time.Second)
					dialElapsed := time.Since(dialStart).Round(time.Millisecond)
					if err != nil {
						slog.Warn("WS CONNECT dial FAIL", "stream", sid, "target", tgt,
							"elapsed", dialElapsed, "err", err)
						s.Close()
						streamsMu.Lock()
						delete(streams, sid)
						streamsMu.Unlock()
						resp := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), sid, []byte("CONNECT_FAIL"))
						if enc, err := session.EncryptChunk(resp); err == nil {
							writeMsg(enc)
						}
						core.PutBuffer(resp.Payload)
						return
					}
					slog.Info("WS CONNECT dial OK", "stream", sid, "target", tgt,
						"elapsed", dialElapsed)

					// Activate: set target conn, flush buffered data, start writer.
					s.Activate(tc)

					// Send CONNECT_OK (client may already be relaying — that's OK)
					resp := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), sid, []byte("CONNECT_OK"))
					if enc, err := session.EncryptChunk(resp); err == nil {
						writeMsg(enc)
					}
					core.PutBuffer(resp.Payload)
					slog.Info("WS CONNECT_OK sent", "stream", sid, "target", tgt)

					// Per-stream relay: target → WS (instant push)
					defer func() {
						if r := recover(); r != nil {
							slog.Error("panic recovered in ws stream relay", "error", r, "stream_id", sid)
						}
						s.Close()
						streamsMu.Lock()
						delete(streams, sid)
						streamsMu.Unlock()
					}()
					buf := make([]byte, 32768)
					for {
						n, err := tc.Read(buf)
						if n > 0 {
							resp := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), sid, buf[:n])
							enc, encErr := session.EncryptChunk(resp)
							core.PutBuffer(resp.Payload)
							if encErr != nil {
								return
							}
							if writeMsg(enc) != nil {
								return
							}
						}
						if err != nil {
							return
						}
					}
				}(streamID, target, pendingStream)

			case core.FlagFin:
				streamID, _ := core.ParseStreamID(chunk.Payload)
				streamsMu.Lock()
				if s := streams[streamID]; s != nil {
					s.Close()
					delete(streams, streamID)
				}
				streamsMu.Unlock()

			case core.FlagKeepalive:
				ack := &core.Chunk{SessionID: session.ID, SeqNum: session.NextSeqNum(), Flags: core.FlagAck}
				if enc, err := session.EncryptChunk(ack); err == nil {
					writeMsg(enc)
				}

			case core.FlagUDP:
				streamID, targetAddr, data, err := core.ParseUDPChunk(chunk.Payload)
				if err != nil {
					continue
				}

				// X-2 fix: SSRF protection for UDP targets — resolve hostname first to prevent DNS rebinding
				udpHost := targetAddr
				if uh, _, err := net.SplitHostPort(targetAddr); err == nil {
					udpHost = uh
				}
				if isBlockedDomain(udpHost, h.config.BlockDomains) {
					slog.Debug("blocked domain UDP target (ws)", "addr", targetAddr)
					continue
				}
				// Resolve hostname to IP to prevent DNS rebinding bypassing isPrivateIP
				resolvedAddr, resolveErr := net.ResolveUDPAddr("udp", targetAddr)
				if resolveErr != nil {
					slog.Debug("failed to resolve UDP target (ws)", "addr", targetAddr, "error", resolveErr)
					continue
				}
				if isPrivateIP(resolvedAddr.IP) {
					slog.Debug("blocked private UDP target (ws)", "addr", targetAddr, "resolved", resolvedAddr.IP)
					continue
				}
				// Use the resolved IP:port to prevent TOCTOU DNS rebinding
				resolvedTarget := resolvedAddr.String()

				if h.udpRelay != nil {
					h.udpRelay.Send(streamID, resolvedTarget, data, func(response []byte) {
						respChunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, response)
						if enc, err := session.EncryptChunk(respChunk); err == nil {
							writeMsg(enc)
						}
					})
				}
			}
		}
	}()

	<-done

	// Cleanup all streams
	streamsMu.Lock()
	for _, s := range streams {
		s.Close()
	}
	streamsMu.Unlock()

	// Stop the writer (idempotent; Run drains any in-flight queue then exits)
	// before closing the conn so an in-progress WriteMessage isn't aborted
	// mid-frame.
	writer.Close()
	conn.Close()
}

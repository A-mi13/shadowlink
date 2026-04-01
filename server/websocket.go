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
type wsStream struct {
	targetConn net.Conn
	writeCh    chan []byte
	done       chan struct{}
	closeOnce  sync.Once
}

func newWSStream(tc net.Conn) *wsStream {
	s := &wsStream{
		targetConn: tc,
		writeCh:    make(chan []byte, 256),
		done:       make(chan struct{}),
	}
	// CRIT-5 fix: writer goroutine watches done channel to exit cleanly
	// without relying on close(writeCh) which races with Write().
	// NEW-1 fix: after done fires, keep draining writeCh until empty for 1ms
	// to catch items queued by concurrent Write() calls racing with Close().
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
	return s
}

func (s *wsStream) Write(data []byte) {
	cp := core.GetBuffer(len(data))
	cp = cp[:len(data)]
	copy(cp, data)
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
		s.targetConn.Close()
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

	// Serialized writer
	writeMu := &sync.Mutex{}
	writeMsg := func(data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteMessage(websocket.BinaryMessage, data)
	}

	streams := make(map[uint16]*wsStream)
	streamsMu := &sync.Mutex{}

	done := make(chan struct{})

	// Reader: client WS → route to target streams
	go func() {
		defer close(done)
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
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
				if streamCount >= maxStreamsPerSession {
					slog.Warn("max streams per session exceeded", "limit", maxStreamsPerSession)
					errChunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, []byte("CONNECT_FAIL"))
					if enc, err := session.EncryptChunk(errChunk); err == nil {
						writeMsg(enc)
					}
					core.PutBuffer(errChunk.Payload)
					continue
				}

				// X-1 fix: check server-side block list before dialing (same as handler.go handleConnect)
				if len(h.config.BlockDomains) > 0 {
					blockHost := target
					if bh, _, err := net.SplitHostPort(target); err == nil {
						blockHost = bh
					}
					if isBlockedDomain(blockHost, h.config.BlockDomains) {
						slog.Debug("blocked domain (ws)", "host", blockHost)
						errChunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, []byte("CONNECT_FAIL"))
						if enc, err := session.EncryptChunk(errChunk); err == nil {
							writeMsg(enc)
						}
						core.PutBuffer(errChunk.Payload)
						continue
					}
				}

				tc, err := SafeDial(context.Background(), target, 10*time.Second)
				if err != nil {
					resp := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, []byte("CONNECT_FAIL"))
					if enc, err := session.EncryptChunk(resp); err == nil {
						writeMsg(enc)
					}
					core.PutBuffer(resp.Payload)
					continue
				}

				s := newWSStream(tc)
				streamsMu.Lock()
				streams[streamID] = s
				streamsMu.Unlock()

				// Per-stream relay: target → WS (instant push)
				go func(sid uint16, stream *wsStream) {
					defer func() {
						if r := recover(); r != nil {
							slog.Error("panic recovered in ws stream relay", "error", r, "stream_id", sid)
						}
						stream.Close()
						streamsMu.Lock()
						delete(streams, sid)
						streamsMu.Unlock()
					}()
					buf := make([]byte, 32768) // larger read buffer
					for {
						n, err := stream.targetConn.Read(buf)
						if n > 0 {
							resp := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), sid, buf[:n])
							enc, encErr := session.EncryptChunk(resp)
							core.PutBuffer(resp.Payload) // release pooled payload immediately
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
				}(streamID, s)

				resp := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, []byte("CONNECT_OK"))
				if enc, err := session.EncryptChunk(resp); err == nil {
					writeMsg(enc)
				}
				core.PutBuffer(resp.Payload)

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
	conn.Close()
}

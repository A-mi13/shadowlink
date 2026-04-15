package socks5

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
)

// HandleTCPConnect handles a SOCKS5 CONNECT command in poll mode.
// destAddr is already parsed. conn is NOT closed by this function (caller handles it).
func HandleTCPConnect(ctx context.Context, conn net.Conn, cl *client.Client, router *client.Router, destAddr string) {
	slog.Debug("SOCKS5 CONNECT", "dest", destAddr)

	// Apply routing rules: block / direct / tunnel
	switch router.Decide(destAddr) {
	case client.ActionBlock:
		conn.Write(ReplyNotAllowed)
		return
	case client.ActionDirect:
		DirectDial(conn, destAddr)
		return
	}

	// Multiplexed: allocate a stream within the shared session
	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded", "error", regErr)
		conn.Write(ReplyConnRefused)
		return
	}
	defer cl.UnregisterStream(streamID)

	if err := cl.ConnectToStream(ctx, streamID, destAddr); err != nil {
		conn.Write(ReplyConnRefused)
		return
	}

	conn.Write(ReplySuccess)

	// Two goroutines: uplink (SOCKS->server) + downlink (server->SOCKS)
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// Uplink: read from SOCKS client -> send as stream data
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 16384)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if err := cl.SendStream(ctx2, streamID, buf[:n]); err != nil {
				return
			}
		}
	}()

	// Background poller: sends poll requests to trigger server responses.
	// Runs independently so the downlink writer is never blocked by HTTP round-trips.
	go func() {
		pollTicker := time.NewTicker(20 * time.Millisecond)
		defer pollTicker.Stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-pollTicker.C:
			}
			cl.PollStreams(ctx2)
		}
	}()

	// Downlink: read from stream channel -> write to SOCKS client immediately.
	// Decoupled from polling — data arrives via both poll and uplink SendStream demux.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			select {
			case <-ctx2.Done():
				return
			case data, ok := <-incomingCh:
				if !ok || data == nil {
					return // channel closed by ResetStreams
				}
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(data); err != nil {
					return
				}
				// Drain more data if available without blocking
				draining := true
				for draining {
					select {
					case more, moreOk := <-incomingCh:
						if !moreOk || more == nil {
							return
						}
						if _, err := conn.Write(more); err != nil {
							return
						}
					default:
						draining = false
					}
				}
			}
		}
	}()

	wg.Wait()
}

// HandleTCPConnectWSPerStream handles a SOCKS5 CONNECT with a dedicated WS
// per TCP stream (VLESS+WS model). Each SOCKS5 connection gets its own
// WebSocket through CF CDN. Shared crypto session (one handshake before TUN).
// Seq_num: atomic increment on shared session — server's sliding window (4096)
// accepts out-of-order delivery across multiple concurrent WS connections.
func HandleTCPConnectWSPerStream(ctx context.Context, conn net.Conn, cl *client.Client, router *client.Router, destAddr string, cfg *PerStreamWSConfig) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in HandleTCPConnectWSPerStream", "error", r)
		}
	}()

	slog.Debug("SOCKS5 CONNECT (per-stream WS)", "dest", destAddr)

	switch router.Decide(destAddr) {
	case client.ActionBlock:
		conn.Write(ReplyNotAllowed)
		return
	case client.ActionDirect:
		DirectDial(conn, destAddr)
		return
	}

	// Shared session — one handshake done before TUN starts.
	// All per-stream WS reuse the same session + token.
	// Seq_num is atomic, server sliding window handles out-of-order.
	session := cl.Session()
	token := cl.Token()
	if session == nil || token == nil {
		conn.Write(ReplyConnRefused)
		return
	}

	client.Stats.SocksConnects.Add(1)

	// Acquire a WS for this stream. When a pool is configured, pull a pre-
	// warmed one (skips the ~250ms TCP+TLS+WS-upgrade cost that dominates CF
	// CDN per-stream mode). Otherwise fall back to opening a fresh one.
	var wst *client.WebSocketTransport
	if cfg.Pool != nil {
		acquireCtx, acquireCancel := context.WithTimeout(ctx, 5*time.Second)
		acquired, acquireErr := cfg.Pool.Acquire(acquireCtx)
		acquireCancel()
		if acquireErr != nil {
			slog.Debug("per-stream WS pool acquire failed", "dest", destAddr, "err", acquireErr)
			conn.Write(ReplyConnRefused)
			return
		}
		wst = acquired
		client.Stats.WsFromPool.Add(1)
	} else {
		wst = client.NewWebSocketTransport(cfg.ServerAddr, cfg.UseTLS, cfg.SkipVerify, cfg.LockedFP)
		if cfg.SNIHost != "" {
			wst.SetSNIHost(cfg.SNIHost)
		}
		if cfg.CFIP != "" {
			wst.SetCFIP(cfg.CFIP)
		}

		if err := wst.UpgradeToWS(token); err != nil {
			slog.Debug("per-stream WS upgrade failed", "dest", destAddr, "err", err)
			conn.Write(ReplyConnRefused)
			return
		}
		client.Stats.WsCreated.Add(1)
	}
	defer client.Stats.WsDied.Add(1)

	streamID := cl.NextStreamID()

	connectChunk := core.NewStreamConnectChunk(session.ID, session.NextSeqNum(), streamID, destAddr)
	encrypted, err := session.EncryptChunk(connectChunk)
	if err != nil {
		conn.Write(ReplyConnRefused)
		wst.Close()
		return
	}
	if err := wst.WriteControlMessage(encrypted); err != nil {
		conn.Write(ReplyConnRefused)
		wst.Close()
		return
	}

	slog.Debug("per-stream WS CONNECT sent", "dest", destAddr, "stream", streamID)
	conn.Write(ReplySuccess)

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	defer wst.Close()
	var wg sync.WaitGroup
	relayStart := time.Now()

	// Keepalive: prevent CF idle timeout (100s).
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-ticker.C:
				ka := core.NewKeepaliveChunk(session.ID, session.NextSeqNum())
				enc, _ := session.EncryptChunk(ka)
				if enc != nil {
					wst.WriteControlMessage(enc)
				}
			}
		}
	}()

	// Uplink: SOCKS client → encrypt → dedicated WS → server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		total := 0
		for {
			n, err := conn.Read(buf)
			if err != nil {
				slog.Info("per-stream uplink done", "dest", destAddr, "stream", streamID,
					"bytes", total, "elapsed", time.Since(relayStart).Round(time.Millisecond))
				select {
				case <-time.After(15 * time.Second):
				case <-ctx2.Done():
				}
				cancel()
				return
			}
			total += n
			client.Stats.UplinkBytes.Add(int64(n))
			chunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, buf[:n])
			enc, encErr := session.EncryptChunk(chunk)
			core.PutBuffer(chunk.Payload)
			if encErr != nil {
				return
			}
			if err := wst.WriteMessage(enc); err != nil {
				return
			}
		}
	}()

	// Downlink: dedicated WS → decrypt → SOCKS client.
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// gorilla "repeated read on failed websocket connection" —
				// happens when async writer closes conn while we're in ReadMessage.
				// Safe to swallow: the stream is already dead.
			}
		}()
		defer wg.Done()
		defer cancel()
		total := 0
		chunks := 0
		connectConfirmed := false
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			data, err := wst.ReadMessage(30 * time.Second)
			if err != nil {
				if ctx2.Err() != nil {
					return
				}
				if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
					continue
				}
				slog.Info("per-stream downlink done", "dest", destAddr, "stream", streamID,
					"bytes", total, "chunks", chunks, "elapsed", time.Since(relayStart).Round(time.Millisecond))
				return
			}

			decrypted, err := session.DecryptChunkSafe(data)
			if err != nil || len(decrypted.Payload) < 2 {
				continue
			}

			payload := decrypted.Payload[2:] // skip StreamID header

			if !connectConfirmed {
				msg := string(payload)
				if msg == "CONNECT_OK" {
					connectConfirmed = true
					slog.Debug("per-stream CONNECT_OK", "dest", destAddr, "stream", streamID)
					continue
				}
				if msg == "CONNECT_FAIL" {
					slog.Warn("per-stream CONNECT_FAIL", "dest", destAddr, "stream", streamID)
					return
				}
				connectConfirmed = true
			}

			total += len(payload)
			chunks++
			client.Stats.DownlinkBytes.Add(int64(len(payload)))
			if chunks <= 5 || chunks%100 == 0 {
				slog.Info("per-stream downlink data", "dest", destAddr, "stream", streamID,
					"chunk", chunks, "bytes", len(payload), "totalBytes", total)
			}
			if _, err := conn.Write(payload); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// HandleTCPConnectWS handles a SOCKS5 CONNECT command over WebSocket (full-duplex).
// Each CONNECT gets a StreamID. All streams share one WS connection.
// Server pushes data instantly -- no polling.
func HandleTCPConnectWS(ctx context.Context, conn net.Conn, cl *client.Client, wst client.StreamTransport, router *client.Router, destAddr string, srv *Server) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in HandleTCPConnectWS", "error", r)
		}
	}()

	slog.Debug("SOCKS5 CONNECT (WS)", "dest", destAddr)

	// Apply routing rules: block / direct / tunnel
	switch router.Decide(destAddr) {
	case client.ActionBlock:
		conn.Write(ReplyNotAllowed)
		return
	case client.ActionDirect:
		DirectDial(conn, destAddr)
		return
	}

	// DNS priority: port 53 (DNS-over-TCP) bypasses throttling.
	// Without DNS, nothing resolves → all CONNECTs fail in cascade.
	isDNS := strings.HasSuffix(destAddr, ":53")

	// acquiredSem tracks whether we hold the CONNECT semaphore (for defer release).
	acquiredSem := false

	if !isDNS {
		// Throttle: global semaphore limits concurrent pending WS CONNECTs.
		// This is the ONLY throttle — no per-slot backpressure (it causes reject storms).
		// Semaphore WAITS instead of rejecting, which is critical: apps retry rejected
		// CONNECTs instantly, creating a cascade. Waiting lets them drain naturally.
		if srv != nil && !srv.AcquireConnect(10*time.Second) {
			slog.Warn("WS CONNECT throttled (semaphore full)", "dest", destAddr)
			conn.Write(ReplyConnRefused)
			return
		}
		acquiredSem = true
	}

	// Deferred release: guarantees semaphore is freed on any exit path.
	defer func() {
		if acquiredSem && srv != nil {
			srv.ReleaseConnect()
		}
	}()

	// Allocate stream + register for incoming data
	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded", "error", regErr)
		conn.Write(ReplyConnRefused)
		return
	}
	// CloseStream sends per-stream FIN to server so it frees the stream slot.
	// Without this, streams leak on server until maxStreamsPerSession (256) → all CONNECTs fail.
	defer cl.CloseStream(streamID, wst)

	// Pool-aware: assign stream to a slot and use slot's session.
	if pa, ok := wst.(client.PoolAware); ok {
		pa.AssignStream(streamID)
		// ReleaseStream is called in CloseStream
	}

	// Track pending CONNECT on pool slot.
	// IncrPending here, DecrPending in downlink when CONNECT_OK arrives.
	// With the priority async writer, CONNECTs are always sent before data,
	// so the old 5-second backpressure loop is no longer needed.
	if pt, ok := wst.(client.PendingTracker); ok {
		pt.IncrPending(streamID)
	}

	// Send CONNECT and wait for result.
	// SplitTransport: use SendChunkSync to route through the upload pool (same connections as data).
	// WebSocket: use WriteMessage + channel (server pushes via WS — instant).
	if split, isSplit := wst.(*client.SplitTransport); isSplit {
		// SplitHTTP: CONNECT via upload pool POST — release semaphore early (sync request).
		acquiredSem = false
		if srv != nil {
			srv.ReleaseConnect()
		}
		session := client.StreamSession(wst, cl, streamID)
		if session == nil {
			conn.Write(ReplyConnRefused)
			return
		}
		connectChunk := core.NewStreamConnectChunk(session.ID, session.NextSeqNum(), streamID, destAddr)
		encrypted, err := session.EncryptChunk(connectChunk)
		if err != nil {
			conn.Write(ReplyConnRefused)
			return
		}
		connectStart := time.Now()
		encResp, err := split.SendChunkSync(encrypted)
		connectElapsed := time.Since(connectStart)
		if err != nil {
			slog.Warn("Split CONNECT failed", "dest", destAddr, "elapsed", connectElapsed, "err", err)
			conn.Write(ReplyConnRefused)
			return
		}
		respChunk, err := session.DecryptChunkSafe(encResp)
		if err != nil {
			slog.Warn("Split CONNECT decrypt failed", "dest", destAddr, "elapsed", connectElapsed, "err", err)
			conn.Write(ReplyConnRefused)
			return
		}
		if string(respChunk.Payload) != "CONNECT_OK" {
			slog.Warn("Split CONNECT rejected", "dest", destAddr, "resp", string(respChunk.Payload), "elapsed", connectElapsed)
			conn.Write(ReplyConnRefused)
			return
		}
		slog.Info("Split CONNECT OK", "dest", destAddr, "stream", streamID, "elapsed", connectElapsed)
	} else {
		// WebSocket (or WS pool): OPTIMISTIC CONNECT — send CONNECT chunk,
		// immediately reply SOCKS5 success, start relay. Server buffers data
		// until target TCP is established. This eliminates the round-trip wait
		// that blocks system VPN through CF CDN (matches VLESS+WS behavior).
		session := client.StreamSession(wst, cl, streamID)
		if session == nil {
			conn.Write(ReplyConnRefused)
			return
		}

		connectChunk := core.NewStreamConnectChunk(session.ID, session.NextSeqNum(), streamID, destAddr)
		encrypted, err := session.EncryptChunk(connectChunk)
		if err != nil {
			conn.Write(ReplyConnRefused)
			return
		}
		if err := client.StreamWriteControl(wst, streamID, encrypted); err != nil {
			slog.Debug("WS CONNECT write failed", "dest", destAddr, "err", err)
			conn.Write(ReplyConnRefused)
			return
		}

		// Release semaphore immediately — no waiting for CONNECT_OK.
		acquiredSem = false
		if srv != nil {
			srv.ReleaseConnect()
		}
	}

	// Reply SOCKS5 success immediately (optimistic for WS, confirmed for Split).
	slog.Debug("WS CONNECT sent", "dest", destAddr, "stream", streamID)
	conn.Write(ReplySuccess)

	// Session snapshot for data relay (pool-aware).
	session := client.StreamSession(wst, cl, streamID)
	if session == nil {
		return
	}

	// Full-duplex relay -- no polling!
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup

	relayStart := time.Now()

	// Uplink: SOCKS client -> encrypt -> WS -> server
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768) // large buffer -- let OS batch
		total := 0
		uploads := 0
		for {
			n, err := conn.Read(buf)
			if err != nil {
				slog.Info("uplink done", "dest", destAddr, "stream", streamID,
					"bytes", total, "uploads", uploads, "elapsed", time.Since(relayStart).Round(time.Millisecond))
				// Don't cancel immediately — give downlink time to receive the response.
				select {
				case <-time.After(15 * time.Second):
				case <-ctx2.Done():
				}
				cancel()
				return
			}
			total += n
			uploads++
			chunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, buf[:n])
			enc, encErr := session.EncryptChunk(chunk)
			core.PutBuffer(chunk.Payload) // release pooled payload after encryption
			if encErr != nil {
				slog.Warn("uplink encrypt error", "dest", destAddr, "err", encErr)
				return
			}
			if err := client.StreamWrite(wst, streamID, enc); err != nil {
				slog.Warn("uplink write error", "dest", destAddr, "stream", streamID, "err", err)
				return
			}
		}
	}()

	// Downlink: incoming channel <- WS demux (background reader fills this).
	// First message may be CONNECT_OK (optimistic) or CONNECT_FAIL — handle both.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		total := 0
		chunks := 0
		connectConfirmed := false
		// Safety: if we exit before CONNECT_OK, decrement pending.
		defer func() {
			if !connectConfirmed {
				if pt, ok := wst.(client.PendingTracker); ok {
					pt.DecrPending(streamID)
				}
			}
		}()
		for {
			select {
			case data, ok := <-incomingCh:
				if !ok || data == nil {
					slog.Info("downlink done (ch closed)", "dest", destAddr, "stream", streamID,
						"bytes", total, "chunks", chunks, "elapsed", time.Since(relayStart).Round(time.Millisecond))
					return
				}
				// Handle CONNECT_OK / CONNECT_FAIL from server (optimistic CONNECT).
				if !connectConfirmed {
					msg := string(data)
					if msg == "CONNECT_OK" {
						connectConfirmed = true
						// Decrement pending — CONNECT is no longer in-flight.
						// This frees the slot for new CONNECTs immediately
						// instead of waiting for the entire relay to finish.
						if pt, ok := wst.(client.PendingTracker); ok {
							pt.DecrPending(streamID)
						}
						slog.Debug("WS CONNECT_OK (optimistic)", "dest", destAddr, "stream", streamID)
						continue // don't relay this control message to SOCKS client
					}
					if msg == "CONNECT_FAIL" {
						if pt, ok := wst.(client.PendingTracker); ok {
							pt.DecrPending(streamID)
						}
						slog.Warn("WS CONNECT_FAIL (optimistic)", "dest", destAddr, "stream", streamID)
						return // close stream — server couldn't reach destination
					}
					// Not a control message — real data arrived before CONNECT_OK
					// (shouldn't happen, but handle gracefully).
					connectConfirmed = true
					if pt, ok := wst.(client.PendingTracker); ok {
						pt.DecrPending(streamID)
					}
				}
				total += len(data)
				chunks++
				if chunks <= 5 || chunks%100 == 0 {
					slog.Info("downlink data", "dest", destAddr, "stream", streamID,
						"chunk", chunks, "bytes", len(data), "totalBytes", total)
				}
				if _, err := conn.Write(data); err != nil {
					slog.Warn("downlink write error", "dest", destAddr, "stream", streamID, "err", err)
					return
				}
			case <-ctx2.Done():
				slog.Info("downlink cancelled", "dest", destAddr, "stream", streamID,
					"bytes", total, "chunks", chunks, "elapsed", time.Since(relayStart).Round(time.Millisecond))
				return
			}
		}
	}()

	wg.Wait()
}

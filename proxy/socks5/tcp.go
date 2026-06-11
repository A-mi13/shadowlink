package socks5

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
)

// wsReadyPoolAdapter wraps *client.WSReadyPool so it satisfies PoolAcquirer
// (which returns `any` to keep coalesce.go free of client/ imports). The
// type assertion in the consumer recovers *client.WebSocketTransport.
type wsReadyPoolAdapter struct {
	pool *client.WSReadyPool
}

func (a wsReadyPoolAdapter) Acquire(ctx context.Context) (any, error) {
	wst, err := a.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return wst, nil
}

// socks5CoalesceEnabled returns true unless SHADOWLINK_SOCKS5_COALESCE is set
// to one of the documented opt-out values. Default behavior is coalesce ON
// (mirrors pqEnabled() / SHADOWLINK_DATAPATH_BODYPREFIX semantics).
func socks5CoalesceEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_SOCKS5_COALESCE"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// coalesceWindow / coalesceMaxParallel — D3-tuned defaults. Field-tuning
// happens at deploy time via env (not yet exposed; keep literal until needed).
const (
	coalesceWindow      = 50 * time.Millisecond
	coalesceMaxParallel = 2
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

	// Tunnel path — считаем CONNECT (только реальный VPN-трафик).
	client.Stats.SocksConnects.Add(1)

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
	// Task D5 (cold-start metrics): poll-mode CONNECT_OK is the user-perceived
	// "tunnel ready" event. sync.Once on Client gates this so only the first
	// of all SOCKS5 paths (poll / per-stream WS / WS multiplex) wins the gauge.
	cl.MarkFirstStream()

	// Two goroutines: uplink (SOCKS->server) + downlink (server->SOCKS)
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// Uplink: read from SOCKS client -> send as stream data.
	// V4: per-iteration randomized read cap spreads upload chunk sizes
	// so TSPU can't fingerprint the VPN by POST body histogram.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 16384)
		for {
			limit := core.NextReadSize()
			if limit > len(buf) {
				limit = len(buf)
			}
			n, err := conn.Read(buf[:limit])
			if err != nil {
				return
			}
			client.Stats.UplinkBytes.Add(int64(n))
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
				client.Stats.DownlinkBytes.Add(int64(len(data)))
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
						client.Stats.DownlinkBytes.Add(int64(len(more)))
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

	client.Trace("SOCKS5 CONNECT (per-stream WS)", "dest", destAddr)

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
	//
	// D4: Acquires routed through cfg.AcquireWS — under the hood a process-
	// wide CoalescingDispatcher (50ms window, 2-in-flight) is shared across
	// all CONNECTs that point at the same Pool. Under a SOCKS5 burst
	// (system VPN — 50+ CONNECTs in seconds) this batches demand so the
	// underlying WSReadyPool isn't hammered with concurrent acquires that
	// all race to the same handful of ready slots.
	// SHADOWLINK_SOCKS5_COALESCE=0|false|no|off bypasses the dispatcher.
	var wst *client.WebSocketTransport
	if cfg.Pool != nil {
		acquireCtx, acquireCancel := context.WithTimeout(ctx, 5*time.Second)
		acquired, acquireErr := cfg.AcquireWS(acquireCtx)
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

		// D3: ws upgrade authenticates via a post-upgrade first frame built from
		// the active session — Authorization header is gone.
		if err := wst.UpgradeToWS(token, session); err != nil {
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

	client.Trace("per-stream WS CONNECT sent", "dest", destAddr, "stream", streamID)
	conn.Write(ReplySuccess)
	// Task D5 (cold-start metrics): the first SOCKS5 stream to reach
	// CONNECT_OK is the user-perceived "tunnel ready" event. sync.Once on
	// the Client guarantees only the first such event per Connect cycle
	// stamps the FirstStreamMS gauge — subsequent CONNECTs are no-ops.
	cl.MarkFirstStream()

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	defer wst.Close()
	var wg sync.WaitGroup
	relayStart := time.Now()

	// SEC-H5: idle-aware uplink teardown. The downlink goroutine stamps this
	// on every received frame; after uplink EOF the uplink goroutine waits for
	// downlinkIdleGrace of genuine downlink silence (not a fixed 15s) before
	// cancelling — mirroring tunnelTCPStream's waitForIdleOrCancel so a large
	// response body still streaming after the request finished is not severed
	// at a hard 15s mark.
	var lastDownlinkNs atomic.Int64
	lastDownlinkNs.Store(time.Now().UnixNano())

	// Keepalive: prevent CF idle timeout (100s). Log-normal jitter
	// (sigma=0.5, final-audit-2026-05-03 P1-3, upgraded from uniform ±30%
	// NEW-1 fix) so the per-stream relay loop does not emit encrypted
	// frames at a perfectly periodic 20s cadence AND the inter-frame
	// histogram matches real-world heavy-tailed network jitter — uniform
	// ±j leaves a flat-band signature an ML classifier can detect.
	go func() {
		for {
			select {
			case <-ctx2.Done():
				return
			case <-time.After(client.JitteredIntervalLogNormal(20*time.Second, 0.5)):
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
				// SEC-H5: wait for downlink idle (reset on every received
				// frame) instead of a fixed 15s, so an active response stream
				// survives past the request's completion.
				waitForIdleOrCancel(ctx2, &lastDownlinkNs, downlinkIdleGrace, downlinkIdlePoll)
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
					client.Trace("per-stream CONNECT_OK", "dest", destAddr, "stream", streamID)
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
			lastDownlinkNs.Store(time.Now().UnixNano()) // SEC-H5: keep uplink idle-grace alive
			client.Stats.DownlinkBytes.Add(int64(len(payload)))
			if chunks <= 5 || chunks%100 == 0 {
				client.Trace("per-stream downlink data", "dest", destAddr, "stream", streamID,
					"chunk", chunks, "bytes", len(payload), "totalBytes", total)
			}
			if _, err := conn.Write(payload); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// ───────────────────────────────────────────────────────────────────────────
// Bug #9 §5.4 — downlink reassembly (migration mode only).
//
// Under negotiated stream migration the server tags every FlagData downlink
// frame with a monotonic per-stream downSeq. Frames that were in-flight on an
// old slot at the moment of migration can race frames sent on the new slot, so
// they may arrive out of order. The downlink goroutine therefore funnels frames
// through a per-stream reassembler that re-orders by downSeq before conn.Write —
// otherwise the app's TCP byte stream (TLS records, HTTP bodies) gets corrupted,
// which is the exact symptom Bug #9 fixes. The legacy non-migration path is
// untouched (see tunnelTCPStream's `if !migrate` branch).

const (
	reassemblyGapTimeoutDefault = 2 * time.Second // NEW-1: hole-fill backstop
	reassemblyBufferDefault     = 4 << 20         // 4 MiB per-stream reorder cap
)

// reassemblyGapTimeout resolves the gap-timeout (env SHADOWLINK_REASSEMBLY_GAP_TIMEOUT,
// a time.Duration string). Empty/invalid/<=0 → 2s default (NEW-1).
func reassemblyGapTimeout() time.Duration {
	v := strings.TrimSpace(os.Getenv("SHADOWLINK_REASSEMBLY_GAP_TIMEOUT"))
	if v == "" {
		return reassemblyGapTimeoutDefault
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return reassemblyGapTimeoutDefault
	}
	return d
}

// reassemblyMaxBufferedFromEnv resolves the per-stream reorder byte cap
// (env SHADOWLINK_REASSEMBLY_BUFFER, bytes). Empty/invalid/<=0 → 4 MiB default.
func reassemblyMaxBufferedFromEnv() int {
	v := strings.TrimSpace(os.Getenv("SHADOWLINK_REASSEMBLY_BUFFER"))
	if v == "" {
		return reassemblyBufferDefault
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return reassemblyBufferDefault
	}
	return n
}

// downlinkReassemblyDeps carries the production hooks + tuning for
// downlinkReassemblyLoop. All hooks are optional (nil-safe) so the loop can be
// driven in isolation by tests. The loop owns ordering via the reassembler; the
// hooks only observe / credit / control.
type downlinkReassemblyDeps struct {
	gapTimeout  time.Duration
	maxBuffered int

	// onControl handles a seq==0 control frame (CONNECT_OK / CONNECT_FAIL).
	// Returns keepGoing=false to tear the stream down (CONNECT_FAIL).
	onControl func(msg []byte) (keepGoing bool)
	// onData is called after each successful conn.Write with the bytes written
	// (idle-stamp + DownlinkBytes stat + OnStreamConsumed credit live here).
	onData func(n int)
	// onFlush is called after a non-empty in-order run flushed to conn, with the
	// highest acked downSeq (reasm.expectedSeq-1) — sends the FlagStreamAck.
	onFlush func(ackedDownSeq uint64)
	// onWriteError is called when conn.Write fails; it drains incoming so the WS
	// demux is never blocked on a full channel, then the loop returns.
	onWriteError func()
}

// downlinkReassemblyLoop reads seq-tagged frames, reorders them by downSeq
// through reasm, and writes the in-order runs to conn. It is the migration-mode
// counterpart of the legacy downlink select-loop. peerFullClose may be nil
// (loopback / tests). The loop returns (tearing the stream down) on:
//   - ctx cancelled: the uplink goroutine's Read-EOF teardown cancels ctx2.
//     On the loopback-SOCKS5 path (socks5Replies==true) peerFullClose is nil,
//     so ctx.Done() is the ONLY teardown signal for a stream that finishes
//     cleanly without a reassembly gap — without this case the loop parks
//     forever on <-incoming and leaks the goroutine + its registration + the
//     512-frame buffer (Bug #9 T14 leak fix, symmetric with the legacy loop's
//     case <-ctx2.Done()).
//   - incoming channel closed
//   - reassembler overflow (degradation, NOT corruption)
//   - gap timeout: an unfillable hole did not close within gapTimeout (NEW-1) —
//     CRITICAL: this returns rather than hanging forever on a missing seq
//   - conn.Write error (after draining incoming)
//   - peerFullClose fires (app did a real FIN)
func downlinkReassemblyLoop(
	ctx context.Context,
	incoming <-chan client.StreamFrame,
	conn net.Conn,
	peerFullClose <-chan struct{},
	dep downlinkReassemblyDeps,
) {
	reasm := newReassembler(dep.maxBuffered)

	// Gap timer: armed only while a hole exists, disarmed the moment it closes.
	// Created stopped so a closed/empty stream never trips a spurious timeout.
	gapTimer := time.NewTimer(time.Hour)
	if !gapTimer.Stop() {
		<-gapTimer.C
	}
	gapArmed := false
	// disarm drains the channel on a failed Stop so a fired-but-unread timer
	// can't leak a stale tick into the next select iteration.
	disarm := func() {
		if gapArmed {
			if !gapTimer.Stop() {
				select {
				case <-gapTimer.C:
				default:
				}
			}
			gapArmed = false
		}
	}

	for {
		select {
		case f, ok := <-incoming:
			if !ok {
				disarm()
				return // channel closed → stream over
			}
			// Control frame (seq==0): CONNECT_OK / CONNECT_FAIL, never reordered.
			if f.Seq == 0 {
				if dep.onControl != nil {
					if !dep.onControl(f.Data) {
						disarm()
						return
					}
				}
				continue
			}
			out, st := reasm.push(f.Seq, f.Data)
			if st == reasmOverflow {
				client.Stats.StreamReassemblyOverflow.Add(1)
				disarm()
				return // degradation: unfillable backlog past the byte cap
			}
			for _, d := range out {
				if _, err := conn.Write(d); err != nil {
					if dep.onWriteError != nil {
						dep.onWriteError()
					}
					disarm()
					return
				}
				if dep.onData != nil {
					dep.onData(len(d))
				}
			}
			if len(out) > 0 && dep.onFlush != nil {
				// expectedSeq is the NEXT awaited seq; the highest delivered
				// in-order seq is expectedSeq-1.
				dep.onFlush(reasm.expectedSeq - 1)
			}
			// Arm/disarm the gap timer based on whether a hole now exists.
			if reasm.hasGap() {
				if !gapArmed {
					gapTimer.Reset(dep.gapTimeout)
					gapArmed = true
				}
			} else {
				disarm()
			}
		case <-gapTimer.C:
			// NEW-1: an unfillable hole. Break the stream rather than hang —
			// a hung downlink goroutine would freeze the app's connection forever.
			gapArmed = false
			client.Stats.StreamReassemblyGapTimeout.Add(1)
			return
		case <-peerFullClose:
			disarm()
			return // app did a full Close (real FIN)
		case <-ctx.Done():
			// ctx2 cancelled by the uplink goroutine on Read-EOF teardown.
			// On the loopback-SOCKS5 path this is the only teardown signal for
			// a cleanly-finished stream (peerFullClose is nil, incoming is not
			// closed by UnregisterStream). Disarm the gap timer and exit so the
			// goroutine + its 512-frame buffer are reclaimed (Bug #9 T14 leak).
			disarm()
			return
		}
	}
}

// wakeUplink unblocks the uplink goroutine (parked in conn.Read) when the
// downlink goroutine exits. cancel() alone does not wake a blocking Read and the
// relay conn is not otherwise closed on downlink exit, so without this the uplink
// goroutine keeps reading the app's request into a dead stream. CloseRead closes
// only the read half (idempotent); a conn without CloseRead falls back to full
// Close (downlink is already gone, so closing both halves is safe). socks5Replies
// is kept for symmetry/future gating; CloseRead is valid for both memConn and
// loopback *net.TCPConn.
func wakeUplink(conn net.Conn, socks5Replies bool) {
	if cr, ok := conn.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
		return
	}
	_ = conn.Close()
}

// HandleTCPConnectWS handles a SOCKS5 CONNECT command over WebSocket (full-duplex).
// Each CONNECT gets a StreamID. All streams share one WS connection.
// Server pushes data instantly -- no polling.
//
// This is the loopback-SOCKS5 front-end: it applies routing (block/direct) then
// delegates the tunnel relay to tunnelTCPStream. The in-process tun2socks dialer
// (Bug #5) calls tunnelTCPStream directly (routing already done by BypassDialer),
// so the relay core is shared and behavior-identical between both front-ends.
func HandleTCPConnectWS(ctx context.Context, conn net.Conn, cl *client.Client, wst client.StreamTransport, router *client.Router, destAddr string, srv *Server) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in HandleTCPConnectWS", "error", r)
		}
	}()

	client.Trace("SOCKS5 CONNECT (WS)", "dest", destAddr)

	// Apply routing rules: block / direct / tunnel
	switch router.Decide(destAddr) {
	case client.ActionBlock:
		conn.Write(ReplyNotAllowed)
		return
	case client.ActionDirect:
		DirectDial(conn, destAddr)
		return
	}

	tunnelTCPStream(ctx, conn, cl, wst, destAddr, srv, true)
}

// tunnelTCPStream is the shared TCP relay core: it tunnels `conn` to `destAddr`
// over the WS transport, having ALREADY decided the destination is tunnel-bound
// (no router.Decide here — callers do routing). Used by both the loopback SOCKS5
// front-end (HandleTCPConnectWS) and the in-process tun2socks dialer (Bug #5).
//
// ctx governs the relay lifetime: pass a long-lived (engine) context. The
// in-process dialer must NOT pass tun2socks' 5s dial-ctx here, or every stream
// would be torn down after 5s (review HIGH-5). conn may be a real socket
// (loopback listener) or a buffered memConn (in-process) — the relay is
// transport-agnostic and relies only on net.Conn + half-close semantics.
//
// socks5Replies controls whether SOCKS5 protocol replies (ReplySuccess /
// ReplyConnRefused / ReplyNotAllowed) are written to conn. The loopback SOCKS5
// front-end (HandleTCPConnectWS) passes true: its peer is a real SOCKS5 client
// that parses those reply bytes. The in-process tun2socks dialer passes false:
// tun2socks established the TCP flow itself and expects conn to carry ONLY raw
// application bytes — injecting the 10-byte SOCKS5 reply would prepend
// `05 00 00 01 ...` to the stream and corrupt the very first read (manifesting
// as "tls: first record does not look like a TLS handshake" / garbage downlink).
// On the !socks5Replies path a failed CONNECT is signalled the raw-stream way:
// the relay simply returns, the caller's defer closes the memConn, and the app
// side observes EOF.
func tunnelTCPStream(ctx context.Context, conn net.Conn, cl *client.Client, wst client.StreamTransport, destAddr string, srv *Server, socks5Replies bool) {
	// reply writes a SOCKS5 protocol reply to conn only when the front-end is a
	// real SOCKS5 client. No-op for the in-process (raw-stream) dialer.
	reply := func(b []byte) {
		if socks5Replies {
			conn.Write(b)
		}
	}

	// Tunnel path — считаем CONNECT. Block/Direct сюда не доходят (трафик
	// не идёт через VPN), их в этот счётчик не включаем.
	client.Stats.SocksConnects.Add(1)

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
			reply(ReplyConnRefused)
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

	// Bug #9 §5.4: if the transport negotiated stream migration, this stream's
	// downlink is seq-tagged and must run through the reassembler. We register a
	// seq channel and take the migration downlink path; otherwise everything is
	// byte-for-byte the legacy []byte channel + select-loop.
	migrate := false
	if me, ok := wst.(interface{ MigrationEnabled() bool }); ok {
		migrate = me.MigrationEnabled()
	}

	// Allocate stream + register for incoming data
	streamID := cl.NextStreamID()
	var incomingCh chan []byte
	var incomingSeqCh chan client.StreamFrame
	var regErr error
	if migrate {
		incomingSeqCh, regErr = cl.RegisterStreamSeq(streamID)
	} else {
		incomingCh, regErr = cl.RegisterStream(streamID)
	}
	if regErr != nil {
		slog.Warn("stream limit exceeded", "error", regErr)
		reply(ReplyConnRefused)
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
			reply(ReplyConnRefused)
			return
		}
		connectChunk := core.NewStreamConnectChunk(session.ID, session.NextSeqNum(), streamID, destAddr)
		encrypted, err := session.EncryptChunk(connectChunk)
		if err != nil {
			reply(ReplyConnRefused)
			return
		}
		connectStart := time.Now()
		encResp, err := split.SendChunkSync(encrypted)
		connectElapsed := time.Since(connectStart)
		if err != nil {
			slog.Warn("Split CONNECT failed", "dest", destAddr, "elapsed", connectElapsed, "err", err)
			reply(ReplyConnRefused)
			return
		}
		respChunk, err := session.DecryptChunkSafe(encResp)
		if err != nil {
			slog.Warn("Split CONNECT decrypt failed", "dest", destAddr, "elapsed", connectElapsed, "err", err)
			reply(ReplyConnRefused)
			return
		}
		if string(respChunk.Payload) != "CONNECT_OK" {
			slog.Warn("Split CONNECT rejected", "dest", destAddr, "resp", string(respChunk.Payload), "elapsed", connectElapsed)
			reply(ReplyConnRefused)
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
			reply(ReplyConnRefused)
			return
		}

		connectChunk := core.NewStreamConnectChunk(session.ID, session.NextSeqNum(), streamID, destAddr)
		encrypted, err := session.EncryptChunk(connectChunk)
		if err != nil {
			reply(ReplyConnRefused)
			return
		}
		if err := client.StreamWriteControl(wst, streamID, encrypted); err != nil {
			slog.Debug("WS CONNECT write failed", "dest", destAddr, "err", err)
			reply(ReplyConnRefused)
			return
		}

		// Release semaphore immediately — no waiting for CONNECT_OK.
		acquiredSem = false
		if srv != nil {
			srv.ReleaseConnect()
		}
	}

	// Reply SOCKS5 success immediately (optimistic for WS, confirmed for Split).
	client.Trace("WS CONNECT sent", "dest", destAddr, "stream", streamID)
	reply(ReplySuccess)
	// Task D5 (cold-start metrics): WS-multiplex CONNECT_OK fires the gauge
	// on the first stream of the Connect cycle. sync.Once on Client guarantees
	// idempotency across retries and concurrent CONNECTs.
	cl.MarkFirstStream()

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

	// lastDownlinkNs tracks the most recent downlink frame arrival so the
	// uplink goroutine's post-EOF grace timer is idle-aware: a long download
	// that is still actively streaming the response body must NOT be cancelled
	// just because the request (uplink) finished >15s ago. Stamped by the
	// downlink goroutine on every received frame; read by waitForIdleOrCancel.
	var lastDownlinkNs atomic.Int64
	lastDownlinkNs.Store(relayStart.UnixNano())

	// writeCloseDetector lets the in-process path distinguish a TCP half-close
	// (appConn.CloseWrite — uplink done, downlink still live) from a full close
	// (appConn.Close — real FIN). memConn satisfies it; real sockets (loopback)
	// do not, so the loopback path keeps its idle-grace behavior unchanged.
	type writeCloseDetector interface{ writeClosed() bool }
	connWriteClosed, hasWriteCloseDetector := conn.(writeCloseDetector)

	// fullCloseSignaler exposes a channel closed when the app end does a full
	// Close (real FIN). The downlink goroutine selects on it so a full Close
	// that arrives AFTER an earlier half-close (uplink goroutine already gone)
	// still tears the relay down — the leak window left by removing idle-grace
	// from the in-process path. nil for loopback (real sockets don't implement
	// it), where the select case is simply never ready.
	type fullCloseSignaler interface{ PeerFullCloseSignal() <-chan struct{} }
	var peerFullClose <-chan struct{}
	if fcs, ok := conn.(fullCloseSignaler); ok && !socks5Replies {
		peerFullClose = fcs.PeerFullCloseSignal()
	}

	// Uplink: SOCKS client -> encrypt -> WS -> server
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768) // large buffer -- let OS batch
		total := 0
		uploads := 0
		// uplinkSession is this goroutine's PRIVATE view of the stream's session.
		// It starts as the captured `session` and is re-resolved only here after
		// the migrate barrier (Bug #9 §5.3) — never write back to the shared
		// `session`, which the downlink goroutine reads concurrently (a shared
		// reassignment would be a data race).
		uplinkSession := session
		for {
			n, err := conn.Read(buf)
			if err != nil {
				slog.Info("uplink done", "dest", destAddr, "stream", streamID,
					"bytes", total, "uploads", uploads, "elapsed", time.Since(relayStart).Round(time.Millisecond),
					"err", err)

				// In-process tun2socks path: uplink EOF does NOT mean the stream
				// is over. tun2socks does appConn.CloseWrite() (TCP half-close)
				// as soon as the app finished sending its request — for an HTTP
				// keep-alive connection the downlink is still live and must keep
				// serving the response (and further pipelined requests). So we
				// distinguish:
				//   - half-close (writeClosed()==false): app sent its request and
				//     went quiet but the connection is alive. The uplink goroutine
				//     simply returns; the downlink goroutine keeps running. NO
				//     idle-grace, NO cancel — tun2socks owns the TCP lifecycle in
				//     TUN mode and will Close() on the real FIN.
				//   - full close (writeClosed()==true): app did appConn.Close()
				//     (real FIN). Cancel so the downlink goroutine, which may be
				//     blocked on incomingCh, also exits and the stream tears down.
				// The loopback SOCKS5 path (socks5Replies=true, real socket, no
				// writeCloseDetector) keeps the idle-grace behavior: there a Read
				// EOF means the client truly closed the socket.
				if !socks5Replies && hasWriteCloseDetector {
					if connWriteClosed.writeClosed() {
						cancel() // full close → tear the whole stream down
					}
					// half-close → leave downlink running; just stop reading uplink
					return
				}

				// Loopback path: idle-aware grace. The grace window resets on every
				// downlink frame, so an actively-streaming download (e.g. `claude
				// update`, npm/GitHub binaries) survives past 15s and is only torn
				// down after genuine downlink silence. Fixed 15s here previously
				// severed any download still in flight 15s after the request was
				// sent — see proxy/socks5/idle_grace.go for the full rationale.
				waitForIdleOrCancel(ctx2, &lastDownlinkNs, downlinkIdleGrace, downlinkIdlePoll)
				cancel()
				return
			}
			total += n
			uploads++
			client.Stats.UplinkBytes.Add(int64(n))
			// Bug #9 §5.3 uplink barrier: if a MIGRATE/RESUME for this stream is
			// in flight, hold the uplink off the OLD slot until the move resolves
			// (bounded by the ack window). Without this, uplink bytes can land on
			// the aging slot AFTER the server has re-homed the stream, de-syncing
			// the per-stream sequence. session must be re-read AFTER the barrier:
			// a successful migration re-pointed the stream to the new slot, so the
			// uplink chunk must be sealed under the new slot's session.
			if mb, ok := wst.(interface{ WaitStreamMigrateBarrier(streamID uint16) }); ok {
				mb.WaitStreamMigrateBarrier(streamID)
				if s := client.StreamSession(wst, cl, streamID); s != nil {
					uplinkSession = s
				}
			}
			chunk := core.NewStreamDataChunk(uplinkSession.ID, uplinkSession.NextSeqNum(), streamID, buf[:n])
			enc, encErr := uplinkSession.EncryptChunk(chunk)
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
		defer wakeUplink(conn, socks5Replies) // wake uplink (parked in conn.Read) on ANY downlink exit
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

		// Bug #9 §5.4 migration path: seq-tagged downlink runs through the
		// reassembler so frames split across an old+new slot are re-ordered
		// before conn.Write. The legacy path below is byte-for-byte unchanged.
		if migrate {
			dep := downlinkReassemblyDeps{
				gapTimeout:  reassemblyGapTimeout(),
				maxBuffered: reassemblyMaxBufferedFromEnv(),
				onControl: func(msg []byte) bool {
					// seq==0 control: CONNECT_OK / CONNECT_FAIL handling mirrors
					// the legacy connectConfirmed branch. Bug #9 Task 15: a
					// migration CONNECT_OK carries the 32-byte stream proof
					// ("CONNECT_OK"+proof) — capture it into per-stream storage so
					// a later MIGRATE/RESUME can replay it. The proof is the ONLY
					// thing that makes migration verifiable server-side.
					if proof, ok := client.ParseConnectOKProof(msg); ok {
						cl.StoreStreamProof(streamID, proof)
						if !connectConfirmed {
							connectConfirmed = true
							if pt, ok := wst.(client.PendingTracker); ok {
								pt.DecrPending(streamID)
							}
							client.Trace("WS CONNECT_OK+proof (optimistic)", "dest", destAddr, "stream", streamID)
						}
						return true
					}
					if !connectConfirmed {
						s := string(msg)
						if s == "CONNECT_OK" {
							connectConfirmed = true
							if pt, ok := wst.(client.PendingTracker); ok {
								pt.DecrPending(streamID)
							}
							client.Trace("WS CONNECT_OK (optimistic)", "dest", destAddr, "stream", streamID)
							return true
						}
						if s == "CONNECT_FAIL" {
							if pt, ok := wst.(client.PendingTracker); ok {
								pt.DecrPending(streamID)
							}
							slog.Warn("WS CONNECT_FAIL (optimistic)", "dest", destAddr, "stream", streamID)
							return false
						}
						// Unknown control before CONNECT_OK — treat as confirmed
						// (shouldn't happen with seq==0 reserved for control).
						connectConfirmed = true
						if pt, ok := wst.(client.PendingTracker); ok {
							pt.DecrPending(streamID)
						}
					}
					return true
				},
				onData: func(n int) {
					total += n
					chunks++
					lastDownlinkNs.Store(time.Now().UnixNano())
					client.Stats.DownlinkBytes.Add(int64(n))
					if chunks <= 5 || chunks%100 == 0 {
						client.Trace("downlink data", "dest", destAddr, "stream", streamID,
							"chunk", chunks, "bytes", n, "totalBytes", total)
					}
					// Bug #8: credit consumed bytes back so the server may send more.
					cl.OnStreamConsumed(streamID, n)
				},
				onFlush: func(ackedDownSeq uint64) {
					// FlagStreamAck barrier: tell the server it may release the
					// resend tail up to ackedDownSeq. Throttled (Task 15, F3): a
					// burst of in-order flushes coalesces into one wire frame —
					// the server uses the ack purely as a barrier, not per-frame.
					cl.SendStreamAckThrottled(wst, streamID, ackedDownSeq, false)
				},
				onWriteError: func() {
					slog.Warn("downlink write error", "dest", destAddr, "stream", streamID)
					// Consumer (local SOCKS5 client / app) is gone. The uplink
					// goroutine still sits in its grace before canceling ctx2,
					// during which the WS demux keeps routing frames to this
					// stream. Drain inline (blocking, like the legacy path) so the
					// demux is never blocked on a full channel; return when ctx2
					// is cancelled or the channel closes. RouteToStreamSeq is
					// itself non-blocking (records overflow), so a transient full
					// channel degrades rather than deadlocks.
					for {
						select {
						case _, ok := <-incomingSeqCh:
							if !ok {
								return
							}
						case <-ctx2.Done():
							return
						}
					}
				},
			}
			downlinkReassemblyLoop(ctx2, incomingSeqCh, conn, peerFullClose, dep)
			slog.Info("downlink done (migration)", "dest", destAddr, "stream", streamID,
				"bytes", total, "chunks", chunks, "elapsed", time.Since(relayStart).Round(time.Millisecond))
			return
		}

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
						client.Trace("WS CONNECT_OK (optimistic)", "dest", destAddr, "stream", streamID)
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
				// Refresh the idle-grace deadline: an actively-streaming
				// download keeps the uplink goroutine's post-EOF grace from
				// firing (fixes 15s mid-download cancellation).
				lastDownlinkNs.Store(time.Now().UnixNano())
				client.Stats.DownlinkBytes.Add(int64(len(data)))
				if chunks <= 5 || chunks%100 == 0 {
					client.Trace("downlink data", "dest", destAddr, "stream", streamID,
						"chunk", chunks, "bytes", len(data), "totalBytes", total)
				}
				if _, err := conn.Write(data); err != nil {
					slog.Warn("downlink write error", "dest", destAddr, "stream", streamID, "err", err)
					// Consumer (local SOCKS5 client) is gone. The uplink
					// goroutine still sits in its 15s grace before
					// canceling ctx2, during which the WS demux keeps
					// pushing frames into incomingCh. Without an active
					// reader the chan buffer (cap 512) fills and
					// RouteToStream starts recording per-stream overflow
					// (logged once aggregated at UnregisterStream, spec
					// 2026-05-23). Here we just keep reading so the demux
					// is not blocked on a full channel.
					for {
						select {
						case _, ok := <-incomingCh:
							if !ok {
								return
							}
						case <-ctx2.Done():
							return
						}
					}
				}
				// Bug #8: credit consumed bytes back so the server may send more.
				cl.OnStreamConsumed(streamID, len(data))
			case <-peerFullClose:
				// In-process app did a full Close (real FIN), possibly AFTER an
				// earlier half-close when the uplink goroutine had already
				// returned. Tear the stream down. nil channel (loopback) never
				// fires this case. peerFullClose only closes on appConn.Close,
				// never on appConn.CloseWrite, so keep-alive half-close is unaffected.
				slog.Info("downlink done (app full close)", "dest", destAddr, "stream", streamID,
					"bytes", total, "chunks", chunks, "elapsed", time.Since(relayStart).Round(time.Millisecond))
				return
			case <-ctx2.Done():
				slog.Info("downlink cancelled", "dest", destAddr, "stream", streamID,
					"bytes", total, "chunks", chunks, "elapsed", time.Since(relayStart).Round(time.Millisecond))
				return
			}
		}
	}()

	wg.Wait()
}

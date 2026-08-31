package server

import (
	"context"
	crand "crypto/rand"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nixavpn/shadowlink/core"
)

// maxStreamsPerSession limits concurrent multiplexed streams per WebSocket session
// to prevent resource exhaustion attacks.
const maxStreamsPerSession = 256

// wsReaderExitKind is the bounded vocabulary classifyWSReaderExitErr emits.
// Each value maps to a dedicated counter on server.Metrics. The set MUST
// stay in sync with the kind= labels in the Prometheus exporter and the
// shadowlink_ws_reader_exit_total {kind=...} histogram. Adding a new kind
// requires: (1) a new const here, (2) a new Metrics counter field, (3) a
// Snapshot field, (4) a Prometheus label. Five-prong update enforced so
// dashboards stay coherent with the code.
type wsReaderExitKind int

const (
	wsExitOther wsReaderExitKind = iota
	wsExitPeerEOF
	wsExitReset
	wsExitIOTimeout
	wsExitLocalClose
)

// String makes the kind self-describing in slog output. The labels match
// the Prometheus kind= values 1:1 so operators can correlate a WARN line
// with the histogram bucket without a translation table.
func (k wsReaderExitKind) String() string {
	switch k {
	case wsExitPeerEOF:
		return "peer_eof"
	case wsExitReset:
		return "reset"
	case wsExitIOTimeout:
		return "io_timeout"
	case wsExitLocalClose:
		return "local_close"
	default:
		return "other"
	}
}

// classifyWSReaderExitErr maps a server-side gorilla read error to the
// bounded label that feeds shadowlink_ws_reader_exit_total. Mirrors the
// client-side classifyWSReadError pattern but trims the label set to the
// four cases that answer the 2026-05-18 close-1006 forensics question:
// when the client logged `close 1006`, what did the server actually see?
//
// Order matters — most-specific patterns first:
//   - reset: hard TCP RST surfaced as "connection reset by peer" or
//     Windows "wsarecv: An existing connection was forcibly closed". A
//     middlebox hard-reset. Must come BEFORE peer_eof; the gorilla error
//     string sometimes contains both fragments.
//   - local_close: our own conn.Close() raced the read — "use of closed
//     network connection". Only this label says WE closed first.
//   - io_timeout: gorilla read deadline expired without any bytes from
//     the peer. Conn still half-open from our side but the peer stopped
//     forwarding — classic CF-edge / NAT black-hole signature.
//   - peer_eof: orderly FIN from the peer-side (gorilla "EOF" /
//     "unexpected EOF"). The peer (middlebox or CF or origin-side
//     stack) closed cleanly without sending a WS Close frame, so the
//     client's gorilla synthesises a close-1006 on the other side.
//     Strong evidence the teardown is structural network behaviour, not
//     a bug in either endpoint's WS framing.
//   - other: residual; a persistent non-zero rate indicates an
//     unclassified failure worth investigating.
func classifyWSReaderExitErr(err error) wsReaderExitKind {
	if err == nil {
		return wsExitOther
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection reset by peer"),
		strings.Contains(msg, "forcibly closed by the remote"),
		strings.Contains(msg, "wsarecv"):
		return wsExitReset
	case strings.Contains(msg, "use of closed network connection"):
		return wsExitLocalClose
	case strings.Contains(msg, "i/o timeout"):
		return wsExitIOTimeout
	case strings.Contains(msg, "EOF"):
		return wsExitPeerEOF
	default:
		return wsExitOther
	}
}

// noopUpgradeError suppresses gorilla's default 400-with-text response on
// failed WebSocket upgrade. We route the request through failClosedToDecoy
// instead so probe vectors cannot distinguish a WS endpoint from a random
// path. Closes A2-MED-6.
func noopUpgradeError(_ http.ResponseWriter, _ *http.Request, _ int, _ error) {}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  131072,
	WriteBufferSize: 131072,
	CheckOrigin:     func(r *http.Request) bool { return true },
	Error:           noopUpgradeError,
}

// firstFrameAuthTimeout bounds how long the server waits for a client's first
// WebSocket binary frame after the upgrade completes. 1500ms tolerates mobile
// RTT + CF edge variance while denying a slow-read channel to unauthenticated
// peers (which would otherwise pin a goroutine indefinitely).
const firstFrameAuthTimeout = 1500 * time.Millisecond

// firstFrameReadLimit is the max size of the first frame during auth. Large
// enough for [hint+token] (36 B) + encrypted keepalive/connect chunk (well
// under 1 KiB) with headroom. Callers must restore the session-level read
// limit after a successful return; see handleWebSocket.
const firstFrameReadLimit = 8 * 1024

// authenticateFirstFrame reads the first binary frame after WebSocket upgrade
// and performs body-prefix session auth. Returns the resolved session on
// success, nil on any failure (wrong frame type, bad length, unknown session,
// bad GCM tag, replayed seq_num, disallowed flag, or missing tunnel).
//
// Protocol: frame layout is [hint(4) || encrypted_session_token(32) || encrypted_chunk].
// Only FlagKeepalive is accepted as the first frame — this prevents early-data
// injection (FlagData) and sidesteps the half-dispatch problem of FlagConnect
// (seq_num would be consumed without the target actually dialed; callers would
// time out waiting for CONNECT_OK). Clients MUST send keepalive first, then
// FlagConnect through the relay loop. The session must already have an active
// tunnel (created by the handshake POST); orphan sessions are refused.
//
// DoS hygiene: a tight 8 KiB read limit and 1500ms deadline apply only during
// auth. On successful return, the caller (handleWebSocket) restores the normal
// 256 KiB read limit and removes the deadline.
func (h *Handler) authenticateFirstFrame(conn *websocket.Conn) (*core.Session, uint32, bool) {
	conn.SetReadLimit(firstFrameReadLimit)
	conn.SetReadDeadline(time.Now().Add(firstFrameAuthTimeout))
	defer conn.SetReadDeadline(time.Time{})

	msgType, data, err := conn.ReadMessage()
	if err != nil || msgType != websocket.BinaryMessage {
		return nil, 0, false
	}

	tokenLen := h.sessionTokenSize()
	if len(data) < tokenLen+core.MinChunk {
		return nil, 0, false
	}

	session := h.findSessionByHint(data[:tokenLen])
	if session == nil {
		return nil, 0, false
	}

	// Counted here as well as in the relay loop, so the two discard counters
	// describe every inbound frame on the WS transport rather than only the
	// post-auth ones. Without this, a session/key mismatch that shows up on the
	// very first frame — the shape the pooled-UDP defect took — would appear only
	// in the coarse WSFirstFrameAuthRejected bucket, which cannot distinguish it
	// from a stale token or a lost attach race.
	chunk, err := session.DecryptChunkSafe(data[tokenLen:])
	if err != nil {
		h.metrics.WSFramesUndecryptable.Add(1)
		return nil, 0, false
	}
	if !session.AcceptSeqNum(chunk.SeqNum) {
		h.metrics.WSFramesReplayed.Add(1)
		return nil, 0, false
	}

	if chunk.Flags != core.FlagKeepalive {
		return nil, 0, false
	}

	h.tunnelsMu.RLock()
	tunnel, ok := h.tunnels[session.ID]
	h.tunnelsMu.RUnlock()
	if !ok {
		return nil, 0, false
	}

	// A3-S-HIGH-2 (2026-04-25): gate concurrent WS attaches. CAS prevents
	// two WS upgrades from sharing one session — the second attempt loses
	// and falls into fakeAckAndClose (same wire shape as a bad-auth
	// rejection). Without this, an attacker holding a session token can
	// race the legit client and starve seq-num space / inject CONNECTs.
	if !tunnel.WSAttached.CompareAndSwap(false, true) {
		return nil, 0, false
	}

	// Server ghost-sweep (2026-06-01 pool-capacity-dip-fix): a fresh transport is
	// now attached to this session — clear any DetachedAt stamp left by a prior
	// WS teardown so CleanupDetachedGhosts does not reclaim a session a pool
	// reconnect just re-adopted. Ordered AFTER the WSAttached CAS so only the
	// winning attacher clears it.
	//
	// HIGH-4 / H-S3 (2026-06-11) TOCTOU fix: clearing DetachedAt with a bare
	// atomic Store left a window — the sweep's Phase-2 gate could observe
	// WSAttached==false (before this CAS won) and its lock-held DetachedAt read
	// could land before this Store, deleting the session out from under the
	// just-attached transport. ReattachClearDetached clears DetachedAt UNDER
	// sm.mu (the lock the sweep's delete also holds), serializing the two. If it
	// returns false the sweep already won and removed the session: undo the
	// attach latch and bail into fakeAckAndClose so the client reconnects
	// cleanly on a fresh session rather than serving a manager-unknown ghost.
	if !h.sessions.ReattachClearDetached(session.ID) {
		tunnel.WSAttached.Store(false)
		return nil, 0, false
	}

	// Bug #8: read FLOWCTL marker from the (decrypted) keepalive payload and,
	// if present & supported, emit a synchronous FLOWCTL-ack BEFORE the relay
	// loop starts (the first keepalive never reaches the reader-loop).
	//
	// Bug #9 §3.5: the same marker (V2) carries the client's migrate-capability
	// bit. We echo back negotiateMigration(serverEnabled, clientAdvertised) in
	// the ack so both peers agree. migrateEnabled is only ever true when flow
	// control negotiation also succeeds (the ack rides the same marker); a
	// legacy 11-byte marker parses with migrate=false (backwards compat).
	var effectiveWindow uint32
	var migrateEnabled bool
	if cw, migrateAdvertised, okFlow := core.ParseFlowCtlMarkerV2(chunk.Payload); okFlow {
		effectiveWindow = negotiateFlowWindow(cw, uint32(h.flowMaxWindow))
		if effectiveWindow > 0 {
			negotiatedMigrate := negotiateMigration(h.migrationEnabled, migrateAdvertised)
			ackSent := false
			ack := &core.Chunk{SessionID: session.ID, SeqNum: session.NextSeqNum(), Flags: core.FlagAck,
				Payload: core.BuildFlowCtlMarkerV2(effectiveWindow, negotiatedMigrate)}
			if enc, encErr := session.EncryptChunk(ack); encErr == nil {
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if werr := conn.WriteMessage(websocket.BinaryMessage, enc); werr == nil {
					ackSent = true
				}
				conn.SetWriteDeadline(time.Time{})
			}
			// Fail-open: if the ack did not reach the client, the client will NOT
			// enable flow control on its side (it never saw the ack). The server
			// MUST match that — otherwise it would gate on credit the client never
			// sends, stalling the stream after the first window. Disable flow for
			// this session so the relay runs ungated (same as an old client).
			// Migration likewise stays off — the client never read our echo, so it
			// must not believe migration was negotiated.
			if !ackSent {
				effectiveWindow = 0
			} else {
				migrateEnabled = negotiatedMigrate
			}
		}
	}

	// Refresh AttachedAt to the WS-attach moment. As of the 2026-05-18
	// revision (see core/session.go::AttachedAt history), AttachedAt is
	// already set to a non-zero value at handshake response flush, so this
	// store is not strictly necessary for orphan-cleanup correctness. We
	// keep it because the WS-attach timestamp is a more useful liveness
	// signal than the handshake timestamp — future telemetry that reports
	// "how long a session has been actively WS-bound" will read this
	// without needing a separate field.
	session.AttachedAt.Store(time.Now().UnixNano())

	return session, effectiveWindow, migrateEnabled
}

// fakeAckAndClose replies to a failed first-frame auth with a random binary
// frame (200-2000 B) followed by a normal WebSocket close, then tears the
// connection down. The goal is to match the wire trace of a successful auth
// path — an observer seeing an immediate RST / abrupt close after upgrade
// would have a cheap oracle distinguishing bad auth from good. ackJitter()
// further blends the close timing into the normal ACK distribution.
//
// The control-write deadline is short (500 ms) so a dead/slow client cannot
// pin this goroutine.
func (h *Handler) fakeAckAndClose(conn *websocket.Conn) {
	defer conn.Close()

	ackLen := 200 + mathrand.IntN(1801) // inclusive range [200, 2000]
	fakeAck := make([]byte, ackLen)
	_, _ = crand.Read(fakeAck)
	if err := conn.WriteMessage(websocket.BinaryMessage, fakeAck); err != nil {
		return
	}

	time.Sleep(ackJitter())

	closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	_ = conn.WriteControl(
		websocket.CloseMessage,
		closeMsg,
		time.Now().Add(500*time.Millisecond),
	)
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

	// onWriteErr (Bug #10): for a migration relay, startWriter calls this on an
	// origin write error INSTEAD of bare s.Close() — it routes the failure to
	// signalStreamEnd (closes egress + signals client). nil for non-migration
	// streams (legacy s.Close() teardown). Guarded by s.mu (set after Activate,
	// read in startWriter's error branch).
	onWriteErr func(err error)
}

const pendingBufMax = 64 // max queued chunks before TCP dial completes

// registerWSStreamLocked inserts s under streamID, enforcing both the
// per-session stream cap and the no-duplicate invariant. Returns false if the
// CONNECT must be rejected. Caller MUST hold the streams mutex.
//
// H-9 (раунд 18): the insert used to be unconditional
// (`streams[streamID] = pendingStream`), which broke two things at once.
// The overwritten stream was dropped from the map but its targetConn was never
// closed and its writer goroutine kept running (it only exits via s.done, and
// nothing held a reference to call Close()) — so every repeat leaked an FD and a
// goroutine. Worse, the cap check reads len(streams), which does not grow when
// the same key is rewritten, so maxStreamsPerSession never fired at all: a
// client looping FlagConnect(streamID=1) exhausted process FDs — including the
// listener — and took the server down for everyone.
//
// Policy is REJECT, not "close the old stream and take over". A legitimate
// client cannot produce a duplicate: NextStreamID (client/client.go:789) hands
// out IDs monotonically and skips any ID still live in either stream map. Taking
// over would instead hand an authenticated client a way to tear down its own
// in-flight connections by replaying a streamID.
func registerWSStreamLocked(streams map[uint16]*wsStream, streamID uint16, s *wsStream) bool {
	if _, dup := streams[streamID]; dup {
		return false
	}
	if len(streams) >= maxStreamsPerSession {
		return false
	}
	streams[streamID] = s
	return true
}

// registerPOSTStream is the POST-path counterpart of registerWSStreamLocked
// (handler.go CONNECT). Takes tunnel.mu itself. Same invariant, same rationale.
func registerPOSTStream(tunnel *Tunnel, streamID uint16, s *StreamConn) bool {
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	if tunnel.streams == nil {
		tunnel.streams = make(map[uint16]*StreamConn)
	}
	if _, dup := tunnel.streams[streamID]; dup {
		return false
	}
	if len(tunnel.streams) >= maxStreamsPerSession {
		return false
	}
	tunnel.streams[streamID] = s
	return true
}

// newPendingWSStream creates a stream in "pending" state (no target conn yet).
// Data written via Write() is buffered until Activate() is called.
func newPendingWSStream() *wsStream {
	return &wsStream{
		writeCh: make(chan []byte, 256),
		done:    make(chan struct{}),
	}
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
					// Bug #10 path A: for a migration relay, route the origin write
					// error to centralized teardown (signals FlagStreamClose on the
					// live slot + closes egress). For non-migration streams use the
					// legacy s.Close(). Read callback under s.mu to avoid a data
					// race with the setter in the CONNECT branch.
					s.mu.Lock()
					cb := s.onWriteErr
					s.mu.Unlock()
					if cb != nil {
						cb(err)
					} else {
						s.Close()
					}
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

// CloseKeepTarget tears down the stream's uplink writer goroutine and frees
// pending buffers but does NOT close targetConn (Bug #9 §5.5). It is used during
// session teardown for a migratable relay that was orphaned: the egress conn
// (== s.targetConn == relayEntry.tc) must SURVIVE the dying WS session so a
// reactive RESUME on another slot can keep reading it. Ownership of the egress
// transfers to the relayEntry's lifecycle (grace timer / closeReader). The
// closeOnce is consumed here so a later plain Close() on the same stream is a
// no-op and cannot close the preserved egress.
func (s *wsStream) CloseKeepTarget() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		for _, b := range s.pendingBuf {
			core.PutBuffer(b)
		}
		s.pendingBuf = nil
		s.mu.Unlock()
		// Intentionally NOT closing s.targetConn — the relayEntry owns it now.
	})
}

// handleWebSocket dispatches a WebSocket upgrade request. Two pre-upgrade
// gates run cheaply before Hijack: the URL must be in the WS whitelist
// (IsAllowedWSPath) and the client IP must be under its WSUpgrade rate
// budget. Both failures route to the decoy so an external observer cannot
// distinguish a bad URL or flood from a probe for a non-existent resource.
//
// Auth is body-prefix only: after the upgrade the client sends
// [hint+token+encrypted_chunk] as the first binary WS frame, and
// authenticateFirstFrame resolves it. On failure, fakeAckAndClose emits a
// random binary frame + normal close so the rejection blends into the timing
// distribution of a legitimate close.
//
// Post-auth, runWebSocketSession owns the per-session relay loop.
func (h *Handler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !IsAllowedWSPath(r.URL.Path) {
		// H-6 (раунд 18): this used to be a bare h.decoy.ServeHTTP(w, r) — the one
		// decoy serve in server/ that skipped BOTH decoyWithTimingParity and
		// failClosedToDecoy*. Every other path pays runSyntheticDispatch (3×
		// X25519 ScalarMult) + ackJitter(), so `GET /random-path` answered in
		// microseconds WITH an Upgrade header and in milliseconds without one,
		// bodies identical. "Adding Upgrade: websocket makes the server answer an
		// order of magnitude faster" is nonsense for static content behind nginx —
		// a free discriminator for an active probe.
		//
		// The comment that used to sit here ("no additional sanitation needed")
		// was written before timing-parity existed and stopped being true when it
		// landed. PathMismatch is the right reason label: it already exists, and
		// routing through failClosedToDecoyWithReason also sanitizes the URL echo
		// so the body length cannot depend on how long a path was probed.
		h.failClosedToDecoyWithReason(w, r, DecoyReasonPathMismatch)
		return
	}
	clientIP := h.clientIP(r)
	allowWS, remaining, retryAfter := h.rateLimiters.AllowWSUpgrade(clientIP)
	if allowWS {
		// Plan §C7 (May audit, 2026-05-02): WS-upgrade gate fires before
		// any clientID is known (no first-frame yet), so there is no
		// exemption interaction here — every allowed upgrade ticks the
		// consumed series, every reject ticks the rejected series.
		h.metrics.IncRatelimitBurstConsumed("ws_upgrade")
	}
	if !allowWS {
		// Pre-upgrade WS-path rate-limit hit: route through failClosedToDecoy
		// to sanitize URL-echo. Without this, decoy.ServeHTTP(w, r) would
		// serve a body whose length depends on r.URL.Path — leaking that
		// the client tried a known WS endpoint. A2-MED-6.
		//
		// Task A2 (May audit): emit X-SL-RL sentinel so client switches from
		// exp backoff to a fixed per-bucket cool-down. C5 (2026-05-02)
		// upgraded the wire format to verbose key=value (bucket / burst_left /
		// refill_in / exempt). Other failClosedToDecoy branches below (gorilla
		// Upgrade fail, etc.) keep the generic variant — they are not
		// rate-limit cases.
		//
		// §C4 note: WS-upgrade gate fires BEFORE the body-prefix first frame
		// is read, so the server has no clientID yet to consult the
		// exemption LRU. Exempt=0 stays here by design — a future
		// "WS first-frame exemption" would need to defer the rate-limit
		// gate until after authenticateFirstFrame, which trades the upgrade-
		// flood DoS protection for a smoother reconnect path. Not in scope
		// for §C4; the data-path exemption already covers post-attach
		// throughput, and the handshake exemption covers pool reconnect
		// handshakes.
		// Plan §C7 (May audit, 2026-05-02): bucket-empty rejection on the
		// WS-upgrade gate.
		h.metrics.IncRatelimitBurstRejected("ws_upgrade")
		h.failClosedToDecoyRateLimitedV2(w, r, RLSentinel{
			Bucket:    "ws_upgrade",
			BurstLeft: remaining,
			RefillIn:  retryAfter,
			Exempt:    0,
		})
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// gorilla's noopUpgradeError suppressed the default 400 response.
		// Sanitize via failClosedToDecoy so probe responses look identical
		// to random-path 200 decoy serves. A2-MED-6.
		h.failClosedToDecoyWithReason(w, r, DecoyReasonProtocolUnknown)
		return
	}

	// Wave 2.1 (2026-05-17, MINOR-V2-6): count WS upgrades that landed on a
	// retired-but-still-accepted path. Ticked AFTER a successful gorilla
	// Upgrade so probes that never complete the handshake do not skew the
	// rate — the cutoff decision needs the count of actually-attaching
	// clients still hashing to a legacy path.
	if _, legacy := legacyAcceptedWSPaths[r.URL.Path]; legacy {
		h.metrics.WSPathLegacyHits.Add(1)
	}

	session, flowWindow, migrateEnabled := h.authenticateFirstFrame(conn)
	if session == nil {
		// Also counted rather than logged (2026-08-31). fakeAckAndClose is
		// deliberately indistinguishable on the wire from a healthy close, so
		// without this counter a rejected first frame is invisible on both
		// ends: the client sees a slot that reached slotReady and then went
		// quiet (CLAUDE.md hard rule 12 documents exactly that confusion).
		// Every rejection reason funnels through here — unknown session, AEAD
		// failure, replayed seq, wrong flag, missing tunnel, lost attach race.
		h.metrics.WSFirstFrameAuthRejected.Add(1)
		h.fakeAckAndClose(conn)
		return
	}

	// Restore the relay read limit and hand off to the relay loop.
	conn.SetReadLimit(256 * 1024)

	// A3-S-HIGH-2 (2026-04-25): release the WSAttached latch when this
	// transport ends so a legitimate client reconnect can re-attach. The
	// release is keyed on the tunnel observed *now* — closeTunnel during
	// runWebSocketSession may have removed the tunnel from h.tunnels; in
	// that case the latch is moot (the tunnel is gone) and the client
	// will create a fresh handshake on next reconnect.
	defer func() {
		h.tunnelsMu.RLock()
		t, ok := h.tunnels[session.ID]
		h.tunnelsMu.RUnlock()
		if ok {
			t.WSAttached.Store(false)
		}
		// Server ghost-sweep (2026-06-01 pool-capacity-dip-fix): stamp the
		// detach time so CleanupDetachedGhosts can reclaim this session after a
		// short grace instead of waiting for the coarse idle timeout. The slot's
		// WS reader exited (TSPU age-cut close 1006 / io_timeout / peer_eof) and
		// runWebSocketSession returned — the transport is gone. A legitimate pool
		// reconnect re-adopting this same session clears the stamp back to 0 in
		// authenticateFirstFrame. Stamped unconditionally (even if the tunnel was
		// already removed by closeTunnel — the session may still linger in the
		// manager, and a stale DetachedAt on an already-removed session is inert).
		session.DetachedAt.Store(time.Now().UnixNano())
	}()

	h.runWebSocketSession(conn, session, flowWindow, migrateEnabled)
}

// migrateGracePeriod resolves how long the server keeps an orphaned relay alive
// after its WS slot dies, waiting for a RESUME on a live slot (§5.5, default 8s).
// Task 18 (§7) made it Config-driven (Config.MigrateGracePeriod, exposed via the
// -migrate-grace flag / SHADOWLINK_MIGRATE_GRACE env); the helper applies the 8s
// fail-safe default for any Config that left it unset.
func (h *Handler) migrateGracePeriod() time.Duration {
	return h.config.migrateGracePeriodOrDefault()
}

// handleMigrateOrResume processes a FlagMigrate (preemptive, §5.3) or FlagResume
// (reactive, §5.5) control frame. It runs on the reader goroutine of the NEW
// slot's WS session, so `session`/`writer` are that slot's binding.
//
// Flow (single-winner, F8):
//  1. Parse [globalStreamID][proof]; bad parse → silently drop (probe hygiene).
//  2. Find the relayEntry; absent → MIGRATE_FAIL(not_found).
//  3. Verify the HMAC stream proof in constant time against the relay's
//     originSessionNonce (§4.1). Mismatch → FAIL(bad_proof). This is what binds
//     a stream to the session that created it: a second device with the same
//     clientID cannot forge the proof without that session's nonce.
//  4. RESUME only: CAS(stOrphaned → stActive). If it fails the grace timer
//     already won (entry is closing/closed) → FAIL(grace_expired). MIGRATE
//     skips the CAS — the entry is still stActive (slot A is alive).
//  5. reassociate onto this slot's binding, draining downBuffer (and, for
//     RESUME where slot A is known-dead, resending the unacked tail). Reply
//     OK with resumeDownSeq.
func (h *Handler) handleMigrateOrResume(flag byte, payload []byte, clientID string, session *core.Session, writer *core.WSAsyncWriter, migrateEnabled bool) {
	sid, proof, perr := core.ParseMigrateFrame(payload)
	if perr != nil {
		return // malformed — drop without a reply (probe hygiene)
	}

	entry, ok := h.relayRegistry.find(clientID, sid)
	if !ok {
		h.metrics.MigrateFail.Add(1)
		h.metrics.MigrateFailNotFound.Add(1)
		h.enqueueMigrateFail(session, writer, flag, sid, core.MigrateReasonNotFound)
		return
	}

	// §4.1: recompute the per-client key from the server master key (stateless)
	// and verify the proof against the relay's origin session nonce in constant
	// time (F12 — crypto/hmac.Equal inside VerifyStreamProof, never bytes.Equal).
	perClientKey := core.DeriveServerPerClientKey(h.migrateMasterKey(), clientID)
	if !core.VerifyStreamProof(proof, perClientKey, clientID, sid, entry.originSessionNonce) {
		h.metrics.MigrateFail.Add(1)
		h.metrics.MigrateFailBadProof.Add(1)
		h.enqueueMigrateFail(session, writer, flag, sid, core.MigrateReasonBadProof)
		return
	}

	aDead := flag == core.FlagResume

	// b1 (Bug #10 BLOCKER-2): publish the binding onto the NEW live slot B BEFORE
	// flipping state to stActive. This eliminates the window where state==stActive
	// but bound still points at the dead slot A — in which an origin-death teardown
	// could win CAS(stActive→stClosing) and signal/close the relay the RESUME is
	// about to revive. After this Store, any origin-death winner from stActive
	// reads bound==B (live). NIT-2: ONLY bound.Store moves up here — releaseOrphanFD
	// / tail-resend metric / reassociate drain all stay AFTER the CAS (they are
	// correct only once the RESUME has actually won).
	b := &binding{session: session, writer: writer}
	entry.bound.Store(b)

	if flag == core.FlagResume {
		// Single-winner vs grace timer / evict. If CAS fails the entry is gone
		// (closing/closed) — RESUME is too late. (bound is already B but the entry
		// is being torn down by the single-winner; harmless — teardown closes the
		// whole entry regardless of binding.)
		if !entry.state.CompareAndSwap(stOrphaned, stActive) {
			h.metrics.MigrateFail.Add(1)
			h.metrics.MigrateFailGraceExpired.Add(1)
			h.enqueueMigrateFail(session, writer, flag, sid, core.MigrateReasonGraceExpired)
			return
		}
		// Task 12 (F5): the relay is bound to a live WS again — it is no longer an
		// orphan pinning a no-WS socket, so release the FD budget it charged at
		// admitOrphan. releaseOrphanFD is idempotent (clears holdsFD) so a later
		// grace-timer teardown of this same entry won't double-decrement.
		// FD budget released only now that RESUME genuinely won the entry.
		h.relayRegistry.releaseOrphanFD(entry)
	}

	// Task 18 (§4.3, §5.3): count the unacked-tail frames re-enqueued on the new
	// binding when slot A died before acking. resendTail snapshots the same set
	// reassociate(aDead=true) re-sends; it does NOT clear the buffer, so reading it
	// here is a side-effect-free observation. Only the aDead (RESUME) path resends.
	if aDead {
		h.metrics.MigrateTailResent.Add(uint64(len(entry.resendTail())))
	}
	resumeSeq := entry.reassociate(b, migrateEnabled, aDead, h.relayRegistry.originDeathTeardown)
	if flag == core.FlagResume {
		h.metrics.ResumeOK.Add(1)
	} else {
		h.metrics.MigrateOK.Add(1)
	}
	h.enqueueMigrateOK(session, writer, flag, sid, resumeSeq)
}

// migrateMasterKey returns the 32-byte server master-key material used to derive
// per-client migration keys (§4.1). Per spec it is "the same material used for
// the rest of the server crypto" — the server's static X25519 private key. It is
// never sent on the wire; the client only ever replays the opaque streamSecret
// the server handed it (encrypted) at CONNECT, so the client does not need it.
func (h *Handler) migrateMasterKey() []byte {
	if h.serverKey == nil {
		return make([]byte, 32) // fail-closed: VerifyStreamProof will reject
	}
	return h.serverKey.Private
}

// enqueueMigrateOK / enqueueMigrateFail build, encrypt under the NEW slot's
// session, and enqueue the MIGRATE/RESUME reply on the new slot's writer. The
// reply reuses the inbound flag (FlagMigrate/FlagResume) with a status-byte
// payload (§3.4 convention, core.BuildMigrateOK/Fail). Client parse: Task 15.
func (h *Handler) enqueueMigrateOK(session *core.Session, writer *core.WSAsyncWriter, flag byte, sid uint16, resumeDownSeq uint64) {
	chunk := &core.Chunk{SessionID: session.ID, SeqNum: session.NextSeqNum(), Flags: flag,
		Payload: core.BuildMigrateOK(sid, resumeDownSeq)}
	if enc, err := session.EncryptChunk(chunk); err == nil {
		_ = writer.Enqueue(websocket.BinaryMessage, enc)
	}
}

func (h *Handler) enqueueMigrateFail(session *core.Session, writer *core.WSAsyncWriter, flag byte, sid uint16, reason byte) {
	chunk := &core.Chunk{SessionID: session.ID, SeqNum: session.NextSeqNum(), Flags: flag,
		Payload: core.BuildMigrateFail(sid, reason)}
	if enc, err := session.EncryptChunk(chunk); err == nil {
		_ = writer.Enqueue(websocket.BinaryMessage, enc)
	}
}

// runWebSocketSession runs the per-session WebSocket relay: async writer,
// 20 s ping, pong-reset read deadlines, and the inbound dispatcher for
// data/connect/fin/keepalive/udp chunks. Returns when either side closes
// the connection.
func (h *Handler) runWebSocketSession(conn *websocket.Conn, session *core.Session, flowWindow uint32, migrateEnabled bool) {
	// Bug #8 flow control: flowWindow > 0 means client negotiated flow control
	// and we sent back a FLOWCTL-ack with effectiveWindow in authenticateFirstFrame.
	flowEnabled := flowWindow > 0
	// Bug #9 §3.5: migrateEnabled reflects negotiateMigration() — both server
	// config and client capability agreed. When false the relay stays on the
	// legacy (non-migratable) inline path (verbatim, zero behavior change). When
	// true, the CONNECT path registers a *relayEntry in h.relayRegistry and runs
	// the downlink on relayEntry.relayLoop (F4) — the egress conn survives a
	// WS-slot migration. MIGRATE/RESUME/grace handling lands in Task 11; §5.2
	// also means the per-stream watchdog must NOT close `tc` on `done` for
	// migration sessions (the CONNECT branch returns before that watchdog).
	credits := make(map[uint16]*streamCredit)
	creditsMu := &sync.Mutex{}
	if flowEnabled {
		h.metrics.FlowSessionsActive.Add(1)
		defer h.metrics.FlowSessionsActive.Add(-1)
	}

	// Bug #9 §5.3/§5.5: for a migration-negotiated session, resolve the clientID
	// once up front so the MIGRATE/RESUME/StreamAck handlers below can key the
	// relayRegistry without re-locking tunnelsMu per frame. The clientID is the
	// account identity established at handshake (same value the CONNECT path
	// registers relays under). For non-migration sessions this stays "" and the
	// handlers below are never reached (the client won't send those flags).
	var migrateClientID string
	if migrateEnabled {
		h.tunnelsMu.RLock()
		if t, ok := h.tunnels[session.ID]; ok {
			migrateClientID = t.ClientID
		}
		h.tunnelsMu.RUnlock()
	}

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

	// Server-side WS ping every ~45s with log-normal jitter (sigma=0.6) —
	// keeps CF proxy connection alive без FFT-visible periodic peak'а на
	// 45s AND defeats ML classifiers, отличающие uniform jitter через
	// KS-test против log-normal reference. Routed through the same async
	// writer so it cannot stall behind a slow data write. Final audit
	// 2026-05-03 P0-1 + P1-3. Median bumped 20s→45s, sigma 0.5→0.6 в
	// Wave 2.2 (2026-05-17) — снижение aggregate ping rate.
	//
	// CRITICAL — Wave 2.2 INFRASTRUCTURE PRECONDITION (2026-05-17 field
	// incident): nginx `proxy_read_timeout` / `proxy_send_timeout` MUST
	// be ≥180s before deploying this binary. Math: log-normal(45s, σ=0.6)
	// has 95%-ile ≈ 145s. Если nginx clip'ит на 60s (default), 5-10%
	// ping'ов «теряются» → reader EOF cascade → reconnect storm → ghost
	// sessions упираются в MaxClients → весь трафик уходит в decoy.
	// Validate via the post-deploy ops checklist in
	// docs/superpowers/plans/2026-05-17-pl1-ops-instructions.md.
	//
	// Также MaxClients должен быть ≥500 и SessionTimeout ≤90s, иначе
	// при любой сетевой деградации повторится тот же сценарий
	// (ghost-сессии накапливаются за SessionTimeout, любой transient
	// flap может пробить лимит).
	//
	// Opus review M-1 (2026-05-05): per-tick `time.After()` аллокировал
	// *Timer + chan на каждой итерации (GC pressure под тысячами concurrent
	// WS sessions). Замена на `time.NewTimer` + `Reset` — один Timer на
	// весь loop. Reset безопасен после `<-t.C` без drain'а (Go-канон).
	go func() {
		t := time.NewTimer(core.JitteredIntervalLogNormal(45*time.Second, 0.6))
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if err := writer.EnqueueControl(websocket.PingMessage, nil); err != nil {
					return
				}
				t.Reset(core.JitteredIntervalLogNormal(45*time.Second, 0.6))
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
				// 2026-05-18 forensics: classify the exit and tick the
				// matching counter. Cross-references against client-side
				// `close 1006` log lines answer "who closed first?" — a
				// peer_eof here confirms middlebox/origin tore down the
				// TCP, not our writer-side rotation.
				kind := classifyWSReaderExitErr(err)
				switch kind {
				case wsExitPeerEOF:
					h.metrics.WSReaderExitPeerEOF.Add(1)
				case wsExitReset:
					h.metrics.WSReaderExitReset.Add(1)
				case wsExitIOTimeout:
					h.metrics.WSReaderExitIOTimeout.Add(1)
				case wsExitLocalClose:
					h.metrics.WSReaderExitLocalClose.Add(1)
				default:
					h.metrics.WSReaderExitOther.Add(1)
				}
				slog.Warn("WS reader exit", "messages", wsMessages, "err", err, "kind", kind)
				return
			}
			wsMessages++
			if msgType != websocket.BinaryMessage || len(data) == 0 {
				continue
			}

			chunk, err := session.DecryptChunkSafe(data)
			if err != nil {
				// Counted, never logged: an attacker could otherwise flood our
				// disk, and a correct client never lands here. The counter is
				// what makes the drop visible — pooled UDP sealed frames with
				// the wrong session and this branch swallowed all of them
				// without a trace (fixed 2026-08-31).
				h.metrics.WSFramesUndecryptable.Add(1)
				continue
			}
			if !session.AcceptSeqNum(chunk.SeqNum) {
				h.metrics.WSFramesReplayed.Add(1)
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
				} else if s == nil && len(payload) > 0 && migrateEnabled && migrateClientID != "" {
					// Bug #9 BLOCKER B1 (final review 2026-06-01) — uplink
					// registry-fallback. The uplink (client→origin) is the only
					// per-stream path that stayed on the local per-slot streams[]
					// map after migration; downlink (relayLoop), WINDOW_UPDATE,
					// StreamAck and FIN all already resolve via the registry. When a
					// stream CONNECTed on slot A and then migrated to THIS slot B,
					// streams[streamID] is empty here (the wsStream lives on slot A),
					// so without this fallback the post-migration uplink was silently
					// dropped → the application protocol hangs.
					//
					// Symmetric to FlagWindowUpdate (:~1242) / FlagStreamAck (:~1275)
					// / FlagFin (:~1148): resolve the migrated relay by
					// (clientID, streamID) and write the uplink directly to its egress
					// conn (entry.tc) — the SAME net.Conn that was streams[sid].
					// targetConn on slot A (websocket.go:401), which survives the slot
					// rotation precisely so this can keep working.
					//
					// No reordering needed: the client's §5.3 uplink barrier
					// (WaitStreamMigrateBarrier) holds the uplink goroutine off the OLD
					// slot until the MIGRATE/RESUME resolves, so the client never sends
					// uplink on slot A and slot B concurrently — uplink is serialized
					// onto exactly one slot at a time. entry.tc has a single writer at
					// any moment; relayLoop only READS the egress (half-duplex by
					// direction) so there is no concurrent-write race. A blocking
					// tc.Write here applies natural backpressure to the WS reader of
					// this slot (same shape as wsStream's writer goroutine), and on
					// error we leave teardown to the FIN / grace / dest-EOF paths.
					if entry, ok := h.relayRegistry.find(migrateClientID, streamID); ok && entry.tc != nil {
						if _, werr := entry.tc.Write(payload); werr != nil {
							// Bug #10: origin TCP (entry.tc) died (broken pipe). Do NOT
							// just log-and-continue — that left the client uploading into
							// a dead origin forever (the hang). Centralized teardown
							// signals FlagStreamClose on the live WS slot (or records
							// destClosed if orphaned) so the client retries.
							slog.Warn("WS uplink registry-fallback write failed",
								"stream", streamID, "err", werr, "reason", "origin_write_broken_pipe")
							h.relayRegistry.signalStreamEnd(entry, migrateEnabled, "B")
						}
					}
				}

			case core.FlagConnect:
				streamID, targetBytes := core.ParseStreamID(chunk.Payload)
				target := string(targetBytes)
				if target == "" {
					continue
				}

				// Optimistic CONNECT: create pending stream BEFORE dial so data
				// arriving from client is buffered (not dropped). This eliminates
				// the round-trip wait that blocks system VPN through CF CDN.
				//
				// SEC-H3: cap concurrent streams per session. H-9 (раунд 18): the
				// cap check and the insert are now ONE critical section in
				// registerWSStreamLocked, which also rejects a duplicate streamID.
				// Previously the insert was unconditional, so a repeated streamID
				// silently overwrote a live stream (leaking its FD + writer
				// goroutine) and kept len(streams) at 1 — meaning the cap never
				// fired. See registerWSStreamLocked for the full rationale.
				pendingStream := newPendingWSStream()
				streamsMu.Lock()
				streamCount := len(streams)
				admitted := registerWSStreamLocked(streams, streamID, pendingStream)
				streamsMu.Unlock()
				slog.Info("WS CONNECT received", "stream", streamID, "target", target,
					"activeStreams", streamCount)
				if !admitted {
					slog.Warn("WS CONNECT rejected",
						"stream", streamID, "activeStreams", streamCount,
						"limit", maxStreamsPerSession,
						"reason", "duplicate streamID or per-session cap reached")
					errChunk := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), streamID, []byte("CONNECT_FAIL"))
					if enc, err := session.EncryptChunk(errChunk); err == nil {
						writeMsg(enc)
					}
					core.PutBuffer(errChunk.Payload)
					pendingStream.Close() // release the freshly created stream
					continue
				}

				// Bug #8: allocate per-stream credit bucket when flow control is active.
				if flowEnabled {
					creditsMu.Lock()
					credits[streamID] = newStreamCredit(int64(flowWindow))
					creditsMu.Unlock()
				}

				// ASYNC dial: SafeDial blocks up to 10s per target.
				// P1-8 fix (final audit 2026-05-03): bind the dial context
				// to the session's `done` channel so a client disconnect
				// during the 10s SafeDial budget cancels the dial instead
				// of leaking a goroutine for the full timeout window.
				// Mirrors the POST CONNECT pattern at handler.go:1228-1241
				// (A3-S-HIGH-3, 2026-04-25). Under the 8-slot WS pool
				// reconnect cascade observed during VPS throttle, every
				// rejected upgrade could otherwise leave a SafeDial in
				// kernel SYN backoff for ~10s past WS close.
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

					dialCtx, cancelDial := context.WithCancel(context.Background())
					defer cancelDial()
					go func() {
						select {
						case <-done:
							cancelDial()
						case <-dialCtx.Done():
						}
					}()

					dialStart := time.Now()
					slog.Info("WS CONNECT dial start", "stream", sid, "target", tgt)
					tc, err := h.safeDialFn(dialCtx, tgt, 10*time.Second)
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

					// P1-8: WS may have closed during the dial. If `done`
					// fired we still hold a freshly-dialed target conn —
					// close it and skip the relay setup so we don't wire
					// CONNECT_OK into a dead WS or leak the TCP socket.
					select {
					case <-done:
						tc.Close()
						s.Close()
						streamsMu.Lock()
						delete(streams, sid)
						streamsMu.Unlock()
						return
					default:
					}

					// Activate: set target conn, flush buffered data, start writer.
					s.Activate(tc)

					// Bug #9 §4.1 (Task 15): for a migration-negotiated session we
					// resolve the clientID up-front so we can both (a) append the
					// stream proof to CONNECT_OK and (b) register the relay below.
					// The proof = HMAC(perClientKey, clientID‖sid‖MigrateNonce) is
					// EXACTLY what handleMigrateOrResume re-derives and verifies in
					// constant time — the client cannot forge it, it only replays
					// the opaque token. Sending it on CONNECT_OK (encrypted under
					// the session) is what makes any later MIGRATE/RESUME verifiable;
					// without this the whole migration path dies at bad_proof.
					var clientID string
					if migrateEnabled {
						h.tunnelsMu.RLock()
						if t, ok := h.tunnels[session.ID]; ok {
							clientID = t.ClientID
						}
						h.tunnelsMu.RUnlock()
					}

					// Send CONNECT_OK (client may already be relaying — that's OK).
					// Wire convention (Task 15): legacy / non-migration → the bare
					// "CONNECT_OK" marker (10 bytes), preserved byte-for-byte so the
					// client's exact-match isStreamControlMsg keeps working.
					// Migration → "CONNECT_OK"+proof(32) (42 bytes); the client
					// detects the proof by fixed total length + marker prefix
					// (parseConnectOKProof) and still routes it as a seq==0 control.
					connectBody := []byte("CONNECT_OK")
					if migrateEnabled {
						perClientKey := core.DeriveServerPerClientKey(h.migrateMasterKey(), clientID)
						proof := core.ComputeStreamProof(perClientKey, clientID, sid, session.MigrateNonce)
						connectBody = append(connectBody, proof[:]...)
					}
					resp := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), sid, connectBody)
					if enc, err := session.EncryptChunk(resp); err == nil {
						writeMsg(enc)
					}
					core.PutBuffer(resp.Payload)
					slog.Info("WS CONNECT_OK sent", "stream", sid, "target", tgt, "migrate", migrateEnabled)

					// Bug #9 §5.1/§5.2 (F4, F11): for a migration-negotiated
					// session, the downlink relay does NOT live inline here —
					// it lives on a *relayEntry in h.relayRegistry, reads its
					// binding dynamically every frame, and survives a WS-slot
					// migration (the egress conn `tc` is moved, not the loop).
					// The uplink (client→target) still flows through this
					// session's reader-loop FlagData → s.Write(payload).
					//
					// We register under (clientID, sid): sid is the global
					// per-client streamID from the CONNECT payload (F11) and
					// clientID (resolved above) comes from the tunnel created at
					// handshake.
					if migrateEnabled {
						entry := &relayEntry{
							originClientID:     clientID,
							globalStreamID:     sid,
							originSessionNonce: session.MigrateNonce,
							tc:                 tc,
							downBuffer:         newBoundedBuffer(int(flowWindow)),
							unackedTail:        newBoundedBuffer(int(flowWindow)),
						}
						entry.state.Store(stActive)
						// Transfer the per-stream credit allocated at CONNECT
						// (flowEnabled implies migrateEnabled — migration only
						// negotiates when flow control did, see
						// authenticateFirstFrame). The SAME *streamCredit object
						// stays in `credits[sid]` so the reader-loop's
						// FlagWindowUpdate handler still replenishes it, and on
						// `entry.credit` so relayLoop gates on it. §5.9.
						if flowEnabled {
							creditsMu.Lock()
							entry.credit = credits[sid]
							creditsMu.Unlock()
						}
						entry.bound.Store(&binding{session: session, writer: writer})
						h.relayRegistry.add(clientID, sid, entry)

						// Bug #10 path A: wire the stream's writer-error to centralized
						// teardown. startWriter calls this on s.targetConn (==entry.tc)
						// write error instead of bare s.Close(), so the client gets a
						// FlagStreamClose and the egress is closed via signalStreamEnd.
						// The window between Activate (above, which started the writer
						// goroutine) and here is safe: a tc write error in that window
						// finds onWriteErr==nil and falls back to s.Close() — harmless,
						// the entry is stActive and a later RESUME re-delivers / the
						// grace timer reaps it. Set under s.mu; startWriter reads it under
						// s.mu too (closes the data race on the field).
						s.mu.Lock()
						s.onWriteErr = func(error) {
							h.relayRegistry.signalStreamEnd(entry, true /*migrateEnabled*/, "A")
						}
						s.mu.Unlock()

						// Bug #9 §5.5 (T20 e2e fix): the relay pump's lifetime is
						// the ENTRY's own closeCh, NOT this slot's `done`. If it
						// were bound to `done`, a sudden slot-A death would close
						// `done`, close the credit, and kill the egress pump — so a
						// reactive grace-RESUME onto slot B would find the egress no
						// longer being read and could only deliver bytes buffered
						// BEFORE the death (the rest of the download silently lost).
						// The spec (§5.5) requires the relay-goroutine to STAY ALIVE
						// across a slot death, keep reading the egress into
						// downBuffer (applying backpressure when full), so RESUME can
						// drain the buffer AND continue. entry.closeReader() is the
						// single permanent-teardown signal (grace-expiry, evict,
						// admit-reject, full session FIN).
						go entry.relayLoop(true /*migrateEnabled*/, entry.closeChOf())

						// The inline relay is replaced — this dial goroutine has
						// nothing more to do. The wsStream `s` remains in
						// `streams[sid]` for uplink; teardown of streams/credit
						// for migration relays is handled by the session-level
						// cleanup + Task 11 reassociate/grace logic.
						return
					}

					// T3 P3 (audit 2026-05-03): bind relay lifetime to `done`.
					// Без watchdog'а `tc.Read(buf)` блокируется до timeout'а
					// target conn'а, пока WS reader уже вышел и parent
					// cleanup закрыл streams. Goroutine'а dereference'ит
					// streams[sid] / delete(streams, sid) под streamsMu —
					// формально ОК (closure capture by ref + sync.Mutex),
					// но превращается в use-after-free если будущий patch
					// присвоит `streams = nil` в cleanup'е. Watchdog
					// закрывает `tc` на `<-done`, что unblock'ит Read и
					// позволит relay-deferу очистить streams[sid] до
					// parent'овского pickup'а.
					relayDone := make(chan struct{})
					go func() {
						select {
						case <-done:
							tc.Close()
						case <-relayDone:
						}
					}()

					// Per-stream relay: target → WS (instant push)
					defer func() {
						if r := recover(); r != nil {
							slog.Error("panic recovered in ws stream relay", "error", r, "stream_id", sid)
						}
						close(relayDone)
						s.Close()
						streamsMu.Lock()
						delete(streams, sid)
						streamsMu.Unlock()
						// Bug #8: close credit when relay exits (prevents waitForCredit leak).
						if flowEnabled {
							creditsMu.Lock()
							if cr := credits[sid]; cr != nil {
								cr.close()
								delete(credits, sid)
							}
							creditsMu.Unlock()
						}
					}()
					buf := make([]byte, 32768)
					for {
						limit := len(buf)
						if flowEnabled {
							creditsMu.Lock()
							cr := credits[sid]
							creditsMu.Unlock()
							if cr != nil {
								waitStart := time.Now()
								got := cr.waitForCredit(done)
								if waited := time.Since(waitStart); waited > time.Millisecond {
									h.metrics.FlowStreamCreditWaitsTotal.Add(1)
									h.metrics.FlowStreamCreditWaitMsTotal.Add(uint64(waited.Milliseconds()))
								}
								if got <= 0 {
									return
								}
								if int(got) < limit {
									limit = int(got)
								}
							}
						}
						n, err := tc.Read(buf[:limit])
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
							if flowEnabled {
								creditsMu.Lock()
								cr := credits[sid]
								creditsMu.Unlock()
								if cr != nil {
									cr.consume(n)
								}
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
				// Bug #8: close credit when client signals FIN.
				if flowEnabled {
					creditsMu.Lock()
					if cr := credits[streamID]; cr != nil {
						cr.close()
						delete(credits, streamID)
					}
					creditsMu.Unlock()
				}
				// Part 1b (Bug #9 NEW-4 followup) — registry teardown on FIN. A
				// FlagFin is the client's DEFINITIVE both-directions-done signal for
				// the stream, so unlike the dest-EOF path (which cannot tell whether
				// the uplink is still live) this IS the right moment to permanently
				// retire a migratable relay and free its registry slot + egress FD.
				// The FIN may arrive on ANY slot (origin or a slot the stream
				// migrated to), so we resolve the relay through the registry rather
				// than the local credits map. Single-winner teardown (shared CAS
				// authority with the grace timer / idle-evict): only the goroutine
				// that wins state→stClosing closes the reader (which closes the
				// shared credit, unparking relayLoop), closes the egress tc, frees
				// the FD budget, and removes the entry — so a concurrent grace timer
				// or RESUME never double-tears-down. If the CAS loses, that other
				// path already owns the teardown and we leave it alone.
				if migrateEnabled && migrateClientID != "" {
					if entry, ok := h.relayRegistry.find(migrateClientID, streamID); ok {
						prev := entry.state.Load()
						if (prev == stActive || prev == stOrphaned) &&
							entry.state.CompareAndSwap(prev, stClosing) {
							h.relayRegistry.remove(entry.originClientID, entry.globalStreamID)
							entry.closeReader()
							if entry.tc != nil {
								entry.tc.Close()
							}
							h.relayRegistry.releaseOrphanFD(entry)
							// Wake a relay loop parked on a full downBuffer so it
							// re-checks stClosing and exits without leaving a
							// half-assigned seq (same lost-wakeup close as grace-timer).
							cond := entry.bufCondOf()
							entry.perEntryMu.Lock()
							cond.Broadcast()
							entry.perEntryMu.Unlock()
						}
					}
				}

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
					h.udpRelay.Send(session.ID, streamID, resolvedTarget, data, func(response []byte) {
						respChunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, response)
						if enc, err := session.EncryptChunk(respChunk); err == nil {
							writeMsg(enc)
						}
					})
				}

			case core.FlagWindowUpdate:
				// Bug #8: client returning credit → replenish the per-stream bucket.
				wuStreamID, delta, perr := core.ParseWindowUpdate(chunk.Payload)
				if perr != nil {
					continue
				}
				creditsMu.Lock()
				cr := credits[wuStreamID]
				creditsMu.Unlock()
				// Bug #9 NEW-4 (T20-finding) — cross-slot credit replenishment.
				// The per-stream credit is a SINGLE object that lives on the
				// relayEntry (entry.credit) and is gated on by relayLoop. At
				// CONNECT it was also placed in the ORIGIN slot's `credits[sid]`
				// map. After a stream migrates to another slot, the client's
				// WINDOW_UPDATE frames arrive on the NEW slot's reader loop, whose
				// local `credits` map has no entry for this sid (the stream was
				// registered on the origin slot). Without finding the credit by its
				// real owner the relay's credit would drain to 0 and the egress
				// pump would park forever in waitForCredit after one window — any
				// transfer larger than the 2×window clamp would hang mid-flight.
				//
				// The registry is the single source of truth for a migratable
				// relay's credit: look the entry up by (clientID, sid) and top up
				// entry.credit directly. This works no matter which slot the
				// WINDOW_UPDATE landed on (origin slot before migration, or any
				// later slot), because the credit object is shared and the registry
				// outlives any single WS slot. Legacy (non-migration) flow control
				// is untouched: migrateClientID=="" sessions never enter this
				// branch and replenish via the local credits map exactly as before.
				if cr == nil && migrateEnabled && migrateClientID != "" {
					if entry, ok := h.relayRegistry.find(migrateClientID, wuStreamID); ok {
						cr = entry.credit
					}
				}
				if cr != nil {
					cr.add(delta, int64(flowWindow))
				}
				h.metrics.FlowWindowUpdatesRecv.Add(1)

			case core.FlagMigrate, core.FlagResume:
				// Bug #9 §5.3 (preemptive MIGRATE) / §5.5 (reactive RESUME).
				// The client presents [globalStreamID][proof]; we verify the
				// HMAC proof (§4.1, constant-time), CAS the state for RESUME
				// (single-winner vs the grace timer), reassociate the relay onto
				// THIS slot's {session, writer}, and reply OK/FAIL on this slot.
				// Only ever reached for migration-negotiated sessions.
				if !migrateEnabled {
					continue
				}
				h.handleMigrateOrResume(chunk.Flags, chunk.Payload, migrateClientID, session, writer, migrateEnabled)

			case core.FlagStreamAck:
				// Bug #9 §5.4: client confirms it has delivered downlink up to
				// ackedDownSeq in order → server may release the unacked tail of
				// that stream (frees the resend buffer).
				if !migrateEnabled {
					continue
				}
				sid, ackedSeq, aerr := core.ParseStreamAckFrame(chunk.Payload)
				if aerr != nil {
					continue
				}
				if entry, ok := h.relayRegistry.find(migrateClientID, sid); ok {
					entry.onStreamAck(ackedSeq)
				}

			default:
				h.metrics.UnknownFlag.Add(1)
			}
		}
	}()

	// Bug #8: wake all waiting relay goroutines when session is torn down so
	// they don't block forever in waitForCredit after done fires.
	//
	// Bug #9 §5.5 (T20 e2e fix): for a migration-negotiated session we must NOT
	// close the credit of a stream whose relay survives this slot's death — that
	// credit is the SAME object as entry.credit and closing it would kill the
	// egress pump the grace-RESUME relies on. Skip any sid that still has a relay
	// in the registry under this clientID; its credit is now owned by the entry
	// lifecycle (closeReader on grace-expiry / evict / RESUME-fail). Non-migration
	// sessions (migrateClientID == "") close every credit exactly as before.
	go func() {
		<-done
		creditsMu.Lock()
		for sid, cr := range credits {
			if migrateClientID != "" {
				if _, ok := h.relayRegistry.find(migrateClientID, sid); ok {
					continue // migratable relay owns this credit's lifetime
				}
			}
			cr.close()
		}
		creditsMu.Unlock()
	}()

	<-done

	// Bug #9 §5.5: WS-conn death for a migration session. For every relayEntry
	// still BOUND TO THIS session (i.e. the stream was NOT preemptively migrated
	// to another live slot — if it had been, its binding now points elsewhere
	// and we must leave it alone), transition it to orphaned and arm the grace
	// timer. We DO NOT close its egress tc here (that is the whole point of F4 —
	// the egress survives the slot so a RESUME on another slot can pick it up).
	// Streams already moved to another slot keep running there untouched.
	//
	// Ordering note: this runs BEFORE the streams[] cleanup below. The migration
	// CONNECT path stored the relay's tc on the relayEntry (not in streams[]),
	// so closing streams[] does not touch the egress conns of migratable relays.
	if migrateEnabled && migrateClientID != "" {
		now := time.Now().UnixNano()
		for _, e := range h.relayRegistry.entriesForSession(migrateClientID, session) {
			// FD-race fix (T12 quality review): CHARGE the orphan FD budget BEFORE
			// publishing stOrphaned. While the entry is still stActive a concurrent
			// RESUME cannot reclaim it (RESUME requires CAS stOrphaned→stActive), so
			// the holdsFD/orphanedFDInUse charge below completes before any RESUME
			// can run releaseOrphanFD. This closes the race where RESUME observed
			// holdsFD==false (charge not yet written) and skipped the decrement,
			// leaking the FD counter for the lifetime of the resumed relay.
			//
			// admitOrphan's decision is independent of e's own state (caps counted
			// against the live map, e excluded from its own eviction), so charging
			// while e is stActive is sound. Only entries still bound to THIS dying
			// session reach here (entriesForSession), and each is processed once.
			if e.state.Load() != stActive {
				// Already migrated away / torn down between the snapshot and now —
				// not ours to orphan.
				continue
			}

			// Bug #9 Task 12 (F5/F6, §5.5): admission gate BEFORE holding the egress
			// conn open through the grace window. An orphaned relay pins a real
			// socket with no WS behind it — the DoS surface caps (per-client /
			// global / FD budget) decide whether we may keep it. If rejected (or no
			// caps configured), close the egress now instead of holding it —
			// graceful degradation: the stream dies rather than letting a peer pin
			// sockets by spraying CONNECT-then-kill-WS. The reject path moves the
			// entry stActive→stClosing directly (never publishing stOrphaned), so a
			// rejected entry is never reachable by RESUME and never a zombie.
			if !h.relayRegistry.admitOrphan(migrateClientID, e) {
				if e.state.CompareAndSwap(stActive, stClosing) {
					h.relayRegistry.remove(e.originClientID, e.globalStreamID)
					// Permanent teardown: stop the egress pump (closeCh + credit)
					// then close the egress. The relay will not be RESUMEd.
					e.closeReader()
					if e.tc != nil {
						e.tc.Close()
					}
					cond := e.bufCondOf()
					e.perEntryMu.Lock()
					cond.Broadcast()
					e.perEntryMu.Unlock()
				}
				continue
			}

			// Admitted (FD charged). Now publish stOrphaned so a RESUME on another
			// slot can pick the relay up. toOrphaned should always win here (the
			// entry was verified stActive above and only this cleanup goroutine
			// touches an stActive entry bound to a dead session), but if it somehow
			// lost the CAS we must release the FD we just charged to avoid leaking
			// the counter, and skip arming the grace timer (someone else owns the
			// entry now).
			if !e.toOrphaned(now) {
				h.relayRegistry.releaseOrphanFD(e)
				continue
			}

			// Wake a relay loop that may be blocked on a full downBuffer with no
			// binding so it re-evaluates (it stays buffering during grace, but the
			// broadcast prevents a stale park if the buffer later frees via
			// ack-eviction). Then arm the grace teardown timer. Broadcast UNDER
			// perEntryMu for consistency with reassociate / grace-timer /
			// onStreamAck (closes any lost-wakeup window).
			cond := e.bufCondOf()
			e.perEntryMu.Lock()
			cond.Broadcast()
			e.perEntryMu.Unlock()
			h.relayRegistry.launchGraceTimer(e, h.migrateGracePeriod(), func() {
				h.metrics.MigrateGraceExpired.Add(1)
			})
		}
	}

	// Cleanup all streams. Bug #9 §5.5 (T20 e2e fix): a migratable relay that was
	// just orphaned (live entry still in the registry under this clientID) owns
	// its egress conn (== wsStream.targetConn) for the grace window — a plain
	// s.Close() here would close that egress and silently break a reactive
	// RESUME's continued downlink. For those streams we tear down only the uplink
	// writer (CloseKeepTarget) and leave the egress to the relayEntry lifecycle
	// (grace timer / closeReader). All other streams close fully as before.
	streamsMu.Lock()
	for sid, s := range streams {
		if migrateEnabled && migrateClientID != "" {
			if _, ok := h.relayRegistry.find(migrateClientID, sid); ok {
				s.CloseKeepTarget()
				continue
			}
		}
		s.Close()
	}
	streamsMu.Unlock()

	// Stop the writer (idempotent; Run drains any in-flight queue then exits)
	// before closing the conn so an in-progress WriteMessage isn't aborted
	// mid-frame. Wait for Run() to finish draining so conn.Close() never
	// races with a still-in-flight WriteMessage — mirrors the client-side
	// pattern in client/ws_transport.go:828-834. Without RunDone(), graceful
	// shutdown surfaced as a slog WARN ("write: connection reset" or
	// "websocket: close sent") because the conn closed under an in-progress
	// write of the final drain frame.
	writer.Close()
	<-writer.RunDone()
	conn.Close()
}

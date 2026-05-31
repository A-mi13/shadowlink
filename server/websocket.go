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

	chunk, err := session.DecryptChunkSafe(data[tokenLen:])
	if err != nil {
		return nil, 0, false
	}
	if !session.AcceptSeqNum(chunk.SeqNum) {
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
		// Direct decoy serve OK — non-WS path matches generic random-GET decoy
		// behavior; no additional sanitation needed (path is not WS-leaky).
		h.decoy.ServeHTTP(w, r)
		return
	}
	clientIP := ClientIPFromRequest(r, h.config.BehindProxy)
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
	}()

	h.runWebSocketSession(conn, session, flowWindow, migrateEnabled)
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

					// Send CONNECT_OK (client may already be relaying — that's OK)
					resp := core.NewStreamDataChunk(session.ID, session.NextSeqNum(), sid, []byte("CONNECT_OK"))
					if enc, err := session.EncryptChunk(resp); err == nil {
						writeMsg(enc)
					}
					core.PutBuffer(resp.Payload)
					slog.Info("WS CONNECT_OK sent", "stream", sid, "target", tgt)

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
					// clientID comes from the tunnel created at handshake.
					if migrateEnabled {
						var clientID string
						h.tunnelsMu.RLock()
						if t, ok := h.tunnels[session.ID]; ok {
							clientID = t.ClientID
						}
						h.tunnelsMu.RUnlock()

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

						// closeCh = session `done`: relayLoop exits when the
						// credit is closed on session teardown (the <-done
						// goroutine below closes every credit). Task 11 wires the
						// orphan transition that detaches a relay from a dying
						// slot WITHOUT killing the egress conn.
						go entry.relayLoop(true /*migrateEnabled*/, done)

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

			case core.FlagWindowUpdate:
				// Bug #8: client returning credit → replenish the per-stream bucket.
				wuStreamID, delta, perr := core.ParseWindowUpdate(chunk.Payload)
				if perr != nil {
					continue
				}
				creditsMu.Lock()
				cr := credits[wuStreamID]
				creditsMu.Unlock()
				if cr != nil {
					cr.add(delta, int64(flowWindow))
				}
				h.metrics.FlowWindowUpdatesRecv.Add(1)

			default:
				h.metrics.UnknownFlag.Add(1)
			}
		}
	}()

	// Bug #8: wake all waiting relay goroutines when session is torn down so
	// they don't block forever in waitForCredit after done fires.
	go func() {
		<-done
		creditsMu.Lock()
		for _, cr := range credits {
			cr.close()
		}
		creditsMu.Unlock()
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

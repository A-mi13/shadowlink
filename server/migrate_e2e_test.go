package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// migrate_e2e_test.go — Bug #9 Task 20. End-to-end integration tests for the
// FULL migration chain. Unlike the per-layer unit tests (Task 11 handler, Task
// 10 relay-loop, Task 15/17 client send/resume), these drive the REAL server
// chain front to back:
//
//   real gorilla WS client  →  httptest.Server(h.ServeHTTP)  →  handleWebSocket
//     →  authenticateFirstFrame (real FLOWCTL+migrate negotiation)
//     →  runWebSocketSession (real reader loop)
//     →  FlagConnect → real CONNECT path → relayRegistry.add + relayLoop
//     →  controllable origin (net.Pipe via injected safeDialFn)
//     →  downlink frames carry real per-stream downSeq (NewStreamDataChunkSeq)
//     →  client decrypts with the real session keys and feeds an e2e
//        reassembler whose contract mirrors proxy/socks5.reassembler
//        (expectedSeq starts at 1, reorder by seq, dedup seq<expected).
//
// Migration is triggered by the REAL wire control frames (FlagMigrate /
// FlagResume with a real HMAC proof captured from the real CONNECT_OK), NOT by
// faking the internal migrate path and NOT by waiting wall-clock. Byte
// integrity is asserted with sha256 over the exact origin bytes vs the exact
// bytes the client reassembled — the load-bearing assertion of this task.
//
// The "client" here is a thin WS reader + reassembler, which is precisely what
// the production client does (proxy/socks5 downlink goroutine). The server side
// is 100% production code.

// ───────────────────────────────────────────────────────────────────────────
// e2e reassembler — mirrors proxy/socks5.reassembler (unexported there)
// ───────────────────────────────────────────────────────────────────────────

type e2eReassembler struct {
	expectedSeq uint64
	pending     map[uint64][]byte
	out         []byte
	dups        int
}

func newE2EReassembler() *e2eReassembler {
	return &e2eReassembler{expectedSeq: 1, pending: make(map[uint64][]byte)}
}

func (r *e2eReassembler) push(seq uint64, data []byte) {
	if seq < r.expectedSeq {
		r.dups++
		return
	}
	if _, exists := r.pending[seq]; exists {
		r.dups++
		return
	}
	r.pending[seq] = append([]byte(nil), data...)
	for {
		nf, ok := r.pending[r.expectedSeq]
		if !ok {
			break
		}
		r.out = append(r.out, nf...)
		delete(r.pending, r.expectedSeq)
		r.expectedSeq++
	}
}

// ───────────────────────────────────────────────────────────────────────────
// e2e harness
// ───────────────────────────────────────────────────────────────────────────

type e2eHarness struct {
	t         *testing.T
	h         *Handler
	serverKey *core.KeyPair
	httpSrv   *httptest.Server
	host      string
	userID    []byte // pinned → every handshake yields the SAME clientID

	mu        sync.Mutex
	originSrv []net.Conn // server-side ends of injected origin pipes (test writes here)
	dialCh    chan net.Conn
}

func newE2EHarness(t *testing.T, migrationEnabled bool) *e2eHarness {
	t.Helper()
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	cfg := TestConfig()
	en := migrationEnabled
	cfg.StreamMigrationEnabled = &en
	cfg.FlowMaxWindow = 8 << 20 // 8 MiB — large enough not to throttle the test

	h := NewHandler(serverKey, cfg, "")
	disableBackpressureForTest(h)

	ha := &e2eHarness{
		t:         t,
		h:         h,
		serverKey: serverKey,
		userID:    make([]byte, 16),
		dialCh:    make(chan net.Conn, 16),
	}
	for i := range ha.userID {
		ha.userID[i] = byte(0x40 + i)
	}

	// Controllable origin: each CONNECT gets a fresh net.Pipe. The server relay
	// reads the client end (returned to safeDialFn); the test writes the server
	// end (published on dialCh so the test can grab it).
	h.safeDialFn = ha.dial

	srv := httptest.NewServer(h)
	ha.httpSrv = srv
	ha.host = strings.TrimPrefix(srv.URL, "http://")
	t.Cleanup(func() {
		srv.Close()
		ha.mu.Lock()
		for _, c := range ha.originSrv {
			c.Close()
		}
		ha.mu.Unlock()
	})
	return ha
}

// dial is the injected safeDialFn. It returns the client end of a fresh pipe to
// the relay and publishes the server end on dialCh for the test to write into.
func (ha *e2eHarness) dial(_ context.Context, _ string, _ time.Duration) (net.Conn, error) {
	srvSide, cliSide := net.Pipe()
	ha.mu.Lock()
	ha.originSrv = append(ha.originSrv, srvSide)
	ha.mu.Unlock()
	ha.dialCh <- srvSide
	return cliSide, nil
}

// waitOrigin blocks for the next origin server-side conn produced by a CONNECT.
func (ha *e2eHarness) waitOrigin(d time.Duration) net.Conn {
	ha.t.Helper()
	select {
	case c := <-ha.dialCh:
		return c
	case <-time.After(d):
		ha.t.Fatal("no origin conn produced by CONNECT within deadline")
		return nil
	}
}

// clientID returns the server-side clientID for this harness. handleHandshakeNew
// derives it as the decrypted userID bytes (no device suffix on this path), and
// the relay registry keys on exactly that string.
func (ha *e2eHarness) clientID() string { return string(ha.userID) }

// waitOrphaned blocks until the relay for (clientID, streamID) is observed in
// the stOrphaned state — i.e. the server's slot-A death cleanup has run and the
// grace window is armed. A RESUME sent before this point would race the
// orphan-publish and fail grace_expired (the relay is still stActive). This
// mirrors production timing: the client RESUMEs only after IT sees slot death,
// by which point the server has typically processed the same teardown.
func (ha *e2eHarness) waitOrphaned(t *testing.T, streamID uint16, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if e, ok := ha.h.relayRegistry.find(ha.clientID(), streamID); ok {
			if e.state.Load() == stOrphaned {
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("relay for stream %d never reached stOrphaned within %s", streamID, within)
}

// e2eSlot is one WS connection authenticated to its own server session. Several
// slots under the SAME clientID model the production WS pool.
//
// A single background reader goroutine owns conn.ReadMessage (started in
// dialSlot AFTER the auth ack is consumed). gorilla corrupts a Conn after a
// read-deadline timeout — so the test must NEVER drive ReadMessage with a
// deadline-and-retry loop. Instead the reader runs deadline-free until a real
// close/error, decrypts every frame, and fans them out onto typed channels the
// test consumes with its OWN timeouts. This is the clean WS-reader pattern the
// production client uses too.
type e2eSlot struct {
	conn    *websocket.Conn
	session *core.Session // CLIENT-side session object (same keys as the server's)
	seqMode bool          // true when migration was negotiated → data frames carry downSeq
	dataCh  chan seqFrame // seq>=1 stream data frames (seqMode)
	rawCh   chan []byte   // legacy [streamID][data] bodies, no downSeq (!seqMode)
	ctrlCh  chan []byte   // CONNECT_OK / CONNECT_FAIL control bodies (legacy data shape)
	replyCh chan []byte   // MIGRATE/RESUME reply payloads
	closeCh chan uint16   // Bug #10: FlagStreamClose stream IDs received from server
}

type seqFrame struct {
	streamID uint16
	seq      uint64
	data     []byte
}

// startReader launches the single deadline-free reader. It exits on any read
// error (close/RST/EOF) — never on a timeout, because no read deadline is set.
func (s *e2eSlot) startReader() {
	s.dataCh = make(chan seqFrame, 4096)
	s.rawCh = make(chan []byte, 4096)
	s.ctrlCh = make(chan []byte, 16)
	s.replyCh = make(chan []byte, 16)
	s.closeCh = make(chan uint16, 16) // Bug #10: surface FlagStreamClose stream IDs
	go func() {
		for {
			_, data, err := s.conn.ReadMessage()
			if err != nil {
				close(s.dataCh)
				close(s.rawCh)
				return
			}
			chunk, derr := s.session.DecryptChunkSafe(data)
			if derr != nil {
				continue
			}
			switch chunk.Flags {
			case core.FlagMigrate, core.FlagResume:
				select {
				case s.replyCh <- append([]byte(nil), chunk.Payload...):
				default:
				}
			case core.FlagStreamClose:
				// Bug #10: server signals origin death — surface the stream ID so
				// tests can assert prompt client notification.
				if sid, perr := core.ParseStreamCloseFrame(chunk.Payload); perr == nil {
					select {
					case s.closeCh <- sid:
					default:
					}
				}
			case core.FlagData:
				// Control frames (CONNECT_OK / CONNECT_FAIL) use the legacy data
				// shape ([streamID][body]) with NO downSeq and must be detected by
				// their marker BEFORE the seq parse — exactly like the production
				// client (parseConnectOKProof). A seq-tagged frame's first bytes
				// would otherwise be misread as a downSeq.
				csid, body := core.ParseStreamID(chunk.Payload)
				if isConnectControl(body) {
					select {
					case s.ctrlCh <- append([]byte{}, body...):
					default:
					}
					continue
				}
				if s.seqMode {
					sid, seq, payload, perr := core.ParseStreamDataSeq(chunk.Payload)
					if perr == nil && seq >= 1 {
						s.dataCh <- seqFrame{streamID: sid, seq: seq, data: append([]byte(nil), payload...)}
					}
				} else {
					// Legacy wire: [streamID][data], no downSeq — emit raw body.
					_ = csid
					s.rawCh <- append([]byte(nil), body...)
				}
			default:
			}
		}
	}()
}

// isConnectControl reports whether a legacy data body is a CONNECT_OK (bare or
// +proof) or CONNECT_FAIL marker.
func isConnectControl(body []byte) bool {
	const ok = "CONNECT_OK"
	if string(body) == ok || string(body) == "CONNECT_FAIL" {
		return true
	}
	if len(body) == len(ok)+32 && string(body[:len(ok)]) == ok {
		return true
	}
	return false
}

// handshake runs the real handshake POST against h (pinned userID → stable
// clientID) and returns the client session + token-with-hint for WS auth.
func (ha *e2eHarness) handshake() (*core.Session, []byte) {
	t := ha.t
	t.Helper()
	ch, state, err := core.NewClientHello(ha.userID, ha.serverKey.Public)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	ha.h.handleHandshakeNew(rec, httptest.NewRequest("POST", "/a", nil), ch.EphemeralPub, ch.EncryptedClientID)
	require.Equal(t, 200, rec.Code, "handshake must succeed: %s", rec.Body.String())

	shJSON, _, err := browser.ParseDownloadResponse(rec.Body.Bytes())
	require.NoError(t, err)
	var shWire struct {
		EphPub       []byte `json:"eph"`
		Token        []byte `json:"tok"`
		MaxConns     uint8  `json:"mc"`
		ChunkSize    uint16 `json:"cs"`
		ProtoVersion *uint8 `json:"_v"`
	}
	require.NoError(t, json.Unmarshal(shJSON, &shWire))
	require.NotNil(t, shWire.ProtoVersion)

	sess, err := core.CompleteHandshakeWithVersion(state, &core.ServerHello{
		EphemeralPub:          shWire.EphPub,
		EncryptedSessionToken: shWire.Token,
		MaxConnsPerClient:     shWire.MaxConns,
		ChunkSize:             shWire.ChunkSize,
	}, *shWire.ProtoVersion)
	require.NoError(t, err)
	token := browser.EncodeTokenWithHint(sess.ID, shWire.Token)
	return sess, token
}

// dialSlot opens a real WS connection, runs the first-frame keepalive auth with
// the V2 FLOWCTL marker (window + migrate bit), reads the negotiation ack, and
// returns the live slot. advertiseMigrate=false models a legacy/old client that
// never asks for migration.
func (ha *e2eHarness) dialSlot(advertiseMigrate bool, window uint32) *e2eSlot {
	t := ha.t
	t.Helper()
	sess, token := ha.handshake()

	wsPath := AllWSPaths()[0]
	c, resp, err := websocket.DefaultDialer.Dial("ws://"+ha.host+wsPath, nil)
	require.NoError(t, err, "WS dial must upgrade (resp=%v)", resp)

	// First frame: keepalive carrying a V2 FLOWCTL marker so the server runs the
	// real negotiateFlowWindow + negotiateMigration path and echoes the ack.
	ka := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     core.FlagKeepalive,
		Payload:   core.BuildFlowCtlMarkerV2(window, advertiseMigrate),
	}
	enc, err := sess.EncryptChunk(ka)
	require.NoError(t, err)
	authFrame := append(append([]byte{}, token...), enc...)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, authFrame))

	// Read the negotiation ack (FlagAck with V2 marker echoed back).
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, ackData, err := c.ReadMessage()
	require.NoError(t, err, "server must echo a FLOWCTL/migrate ack")
	c.SetReadDeadline(time.Time{})
	ackChunk, err := sess.DecryptChunkSafe(ackData)
	require.NoError(t, err)
	require.Equal(t, core.FlagAck, ackChunk.Flags)
	// The negotiated migrate bit in the echoed marker tells us the wire format
	// the server will use for this session's data frames (seq-tagged vs legacy).
	_, negotiatedMigrate, okMark := core.ParseFlowCtlMarkerV2(ackChunk.Payload)
	require.True(t, okMark, "negotiation ack must carry a V2 FLOWCTL marker")
	c.SetReadDeadline(time.Time{}) // reader runs deadline-free from here

	slot := &e2eSlot{conn: c, session: sess, seqMode: negotiatedMigrate}
	slot.startReader()
	return slot
}

// sendChunk encrypts a chunk under the slot session and writes it on the WS.
func (s *e2eSlot) sendChunk(t *testing.T, chunk *core.Chunk) {
	t.Helper()
	enc, err := s.session.EncryptChunk(chunk)
	require.NoError(t, err)
	require.NoError(t, s.conn.WriteMessage(websocket.BinaryMessage, enc))
}

// connect sends a real FlagConnect for streamID and waits (via the reader
// channels) for the CONNECT_OK control, returning the migration proof (or
// hasProof=false for a legacy/non-migration CONNECT_OK). Any seq data frames
// the reader fans out before CONNECT_OK are pushed into reasm so no byte is
// dropped if the server pushes data ahead of the OK.
func (s *e2eSlot) connect(t *testing.T, streamID uint16, target string, reasm *e2eReassembler) (proof [32]byte, hasProof bool) {
	t.Helper()
	s.sendChunk(t, core.NewStreamConnectChunk(s.session.ID, s.session.NextSeqNum(), streamID, target))

	const okMarker = "CONNECT_OK"
	deadline := time.After(5 * time.Second)
	for {
		select {
		case body := <-s.ctrlCh:
			if string(body) == "CONNECT_FAIL" {
				t.Fatalf("server replied CONNECT_FAIL for stream %d", streamID)
			}
			if len(body) == len(okMarker)+32 && string(body[:len(okMarker)]) == okMarker {
				copy(proof[:], body[len(okMarker):])
				return proof, true
			}
			if string(body) == okMarker {
				return proof, false
			}
		case f := <-s.dataCh:
			if f.streamID == streamID {
				reasm.push(f.seq, f.data)
			}
		case <-deadline:
			t.Fatal("CONNECT_OK not received within 5s")
		}
	}
}

// drainData pumps seq frames for streamID from the reader into reasm until no
// frame arrives for `idle` (the origin went quiet on this slot) or `max`
// elapses. It replenishes flow-control credit per frame so the relay never
// stalls. It NEVER touches conn deadlines (the background reader owns the read).
func (s *e2eSlot) drainData(streamID uint16, reasm *e2eReassembler, idle, max time.Duration) {
	overall := time.After(max)
	for {
		select {
		case f, ok := <-s.dataCh:
			if !ok {
				return // reader exited (conn closed)
			}
			if f.streamID != streamID {
				continue
			}
			reasm.push(f.seq, f.data)
			_ = s.windowUpdate(streamID, uint32(len(f.data)))
		case <-time.After(idle):
			return
		case <-overall:
			return
		}
	}
}

func (s *e2eSlot) windowUpdate(streamID uint16, delta uint32) error {
	chunk := core.NewWindowUpdateChunk(s.session.ID, s.session.NextSeqNum(), streamID, delta)
	enc, err := s.session.EncryptChunk(chunk)
	if err != nil {
		return err
	}
	return s.conn.WriteMessage(websocket.BinaryMessage, enc)
}

// drainRawInto pumps legacy (no-downSeq) data bodies from the reader, appending
// them to *out in arrival order, until idle/max elapses or `until` bytes are
// collected. Used by the compat tests where the wire carries no seq.
func (s *e2eSlot) drainRawInto(out *[]byte, until int, idle, max time.Duration) {
	overall := time.After(max)
	for len(*out) < until {
		select {
		case b, ok := <-s.rawCh:
			if !ok {
				return
			}
			*out = append(*out, b...)
		case <-time.After(idle):
			return
		case <-overall:
			return
		}
	}
}

// sendMigrate writes a real FlagMigrate/FlagResume on this slot and reads the
// OK/FAIL reply, returning resumeDownSeq (OK) or the reason (FAIL).
func (s *e2eSlot) sendMigrate(t *testing.T, flag byte, streamID uint16, proof [32]byte) (ok bool, resumeDownSeq uint64, reason byte) {
	t.Helper()
	chunk := &core.Chunk{
		SessionID: s.session.ID,
		SeqNum:    s.session.NextSeqNum(),
		Flags:     flag,
		Payload:   core.BuildMigrateFrame(streamID, proof),
	}
	s.sendChunk(t, chunk)

	select {
	case payload := <-s.replyCh:
		rok, _, rseq, rreason, perr := core.ParseMigrateReply(payload)
		require.NoError(t, perr)
		return rok, rseq, rreason
	case <-time.After(5 * time.Second):
		t.Fatal("MIGRATE/RESUME reply not received within 5s")
		return false, 0, 0
	}
}

func (s *e2eSlot) close() { _ = s.conn.Close() }

// writeOrigin writes the whole payload to the origin server-side conn in a
// goroutine (net.Pipe is synchronous) and closes it to signal EOF. Used by the
// compat tests where no migration boundary needs to bisect the stream.
func writeOrigin(c net.Conn, payload []byte, closeAfter bool) {
	go func() {
		writeOriginBlocking(c, payload)
		if closeAfter {
			c.Close()
		}
	}()
}

// writeOriginBlocking writes payload to c in 16 KiB pieces, blocking until every
// byte is flushed (net.Pipe write returns only once the relay has read it). The
// caller runs this in a goroutine when it must not block the test goroutine.
func writeOriginBlocking(c net.Conn, payload []byte) {
	const piece = 16 << 10
	for off := 0; off < len(payload); off += piece {
		end := off + piece
		if end > len(payload) {
			end = len(payload)
		}
		if _, err := c.Write(payload[off:end]); err != nil {
			return
		}
	}
}

// pacedOrigin drives a controllable origin: WritePhase blocks until that phase's
// bytes have been fully consumed by the relay (so the test KNOWS those bytes
// crossed the wire), letting a test interleave "send first half → migrate →
// send second half" and guarantee post-migration bytes traverse the NEW slot.
type pacedOrigin struct {
	conn net.Conn
}

// writePhase synchronously pushes payload[from:to] through the origin and
// returns only after the relay has drained it (net.Pipe write blocks until
// read). Run on a helper goroutine when the test must continue concurrently.
func (po *pacedOrigin) writePhase(from, to int, payload []byte) {
	writeOriginBlocking(po.conn, payload[from:to])
}

func (po *pacedOrigin) closeEOF() { po.conn.Close() }

// deterministicPayload builds n bytes with a position-dependent pattern so an
// out-of-order / lost / duplicated frame is caught by the sha256 comparison.
func deterministicPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte((i*1103515245 + 12345) >> 7)
	}
	return p
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

// TestE2E_PreemptiveMigration_NoByteLoss: origin streams >1 MiB on slot A; mid
// flight the client issues a real preemptive MIGRATE onto slot B; the rest of
// the download arrives on B; the reassembled bytes match the origin sha256
// exactly (no loss, no reorder across the migration boundary).
func TestE2E_PreemptiveMigration_NoByteLoss(t *testing.T) {
	ha := newE2EHarness(t, true)
	const streamID = uint16(0x21)
	const total = 1<<20 + 4096 // >1 MiB
	payload := deterministicPayload(total)
	want := sha256.Sum256(payload)

	slotA := ha.dialSlot(true, 1<<20)
	defer slotA.close()
	slotB := ha.dialSlot(true, 1<<20)
	defer slotB.close()

	reasm := newE2EReassembler()
	proof, hasProof := slotA.connect(t, streamID, "origin:443", reasm)
	require.True(t, hasProof, "migration CONNECT_OK must carry a proof")
	origin := &pacedOrigin{conn: ha.waitOrigin(3 * time.Second)}

	// PHASE 1: stream the first half from the origin and drain it on slot A. The
	// blocking write + drain loop guarantees these bytes are physically off the
	// relay (and on A) BEFORE we migrate — so the migration genuinely bisects an
	// in-flight stream rather than racing an already-finished download.
	const half = total / 2
	go origin.writePhase(0, half, payload)
	drainUntil(t, slotA, streamID, reasm, half, 5*time.Second)
	require.GreaterOrEqual(t, len(reasm.out), half, "phase-1 bytes must land on A before migration")
	bytesOnA := len(reasm.out)

	// Preemptive MIGRATE to B (real wire control frame + real proof).
	mOK := ha.h.metrics.MigrateOK.Load()
	ok, _, reason := slotB.sendMigrate(t, core.FlagMigrate, streamID, proof)
	require.True(t, ok, "preemptive MIGRATE must succeed, reason=0x%02x", reason)
	require.Equal(t, mOK+1, ha.h.metrics.MigrateOK.Load(), "MigrateOK metric must tick — the real handler ran")

	// PHASE 2: stream the rest. With A's binding replaced by B, these bytes can
	// only reach the client through slot B — proving migration carries the stream.
	go func() {
		origin.writePhase(half, total, payload)
		origin.closeEOF()
	}()

	// Drain B for the remainder; also drain A for any tiny in-flight tail that
	// was enqueued on A before the binding switched.
	deadline := time.Now().Add(8 * time.Second)
	for len(reasm.out) < total && time.Now().Before(deadline) {
		slotB.drainData(streamID, reasm, 250*time.Millisecond, 1*time.Second)
		if len(reasm.out) < total {
			slotA.drainData(streamID, reasm, 50*time.Millisecond, 200*time.Millisecond)
		}
	}

	require.Equal(t, total, len(reasm.out), "reassembled length mismatch (byte loss)")
	require.Greater(t, len(reasm.out), bytesOnA,
		"no bytes arrived after the migration — the migration carried nothing (test would be vacuous)")
	require.Equal(t, want, sha256.Sum256(reasm.out),
		"sha256 mismatch — bytes lost/reordered across the migration boundary")
}

// sendUplink writes one FlagData uplink frame (client→origin) for streamID on
// this slot. The wire format mirrors the production client's uplink path
// (proxy/socks5/tcp.go): a legacy NewStreamDataChunk ([streamID][data], NO
// downSeq) — uplink is never seq-tagged because the client serializes it onto a
// single slot at a time (the §5.3 uplink barrier holds it off the old slot until
// a migration resolves, so it never splits across slots → no reordering needed).
func (s *e2eSlot) sendUplink(t *testing.T, streamID uint16, data []byte) {
	t.Helper()
	chunk := core.NewStreamDataChunk(s.session.ID, s.session.NextSeqNum(), streamID, data)
	s.sendChunk(t, chunk)
}

// readOriginExactly reads exactly n bytes from the origin server-side conn (what
// the relay's uplink writes land on). It is the load-bearing assertion harness
// for uplink-after-migration: every byte the client sent uplink must arrive here
// in order. Fails the test if n bytes do not arrive within `within`.
func readOriginExactly(t *testing.T, c net.Conn, n int, within time.Duration) []byte {
	t.Helper()
	out := make([]byte, 0, n)
	buf := make([]byte, 32<<10)
	c.SetReadDeadline(time.Now().Add(within))
	defer c.SetReadDeadline(time.Time{})
	for len(out) < n {
		r, err := c.Read(buf)
		if r > 0 {
			out = append(out, buf[:r]...)
		}
		if err != nil {
			break
		}
	}
	return out
}

// TestE2E_UplinkAfterMigration_NoByteLoss is the load-bearing proof of BLOCKER
// B1 (final review 2026-06-01): after a stream migrates from slot A to slot B,
// UPLINK bytes (client→origin) sent on slot B must reach the origin. The bug:
// the FlagData uplink branch routed through slot B's LOCAL per-session streams[]
// map, which has no entry for a stream that CONNECTed on slot A → the bytes were
// silently dropped. Downlink survived migration (registry-backed relayLoop), but
// uplink had no registry-fallback (unlike WINDOW_UPDATE / StreamAck / FIN).
//
// The test sends uplink BEFORE migration (slot A → origin, proves the baseline
// path works) and AFTER migration (slot B → origin, the regression). The origin
// (a net.Pipe whose server side the test reads) must receive ALL uplink bytes in
// order — asserted by sha256 over the full concatenation.
//
// WITHOUT the fix the post-migration uplink is dropped at server/websocket.go
// (streams[sid]==nil on slot B) → readOriginExactly times out short → the length
// + sha256 asserts fail. WITH the registry-fallback the bytes route to entry.tc
// (the egress that survived the migration) and the origin receives them all.
func TestE2E_UplinkAfterMigration_NoByteLoss(t *testing.T) {
	ha := newE2EHarness(t, true)
	const streamID = uint16(0x71)
	const half = 64 << 10 // 64 KiB per phase (well under pendingBufMax flush + window)
	const total = 2 * half
	payload := deterministicPayload(total)
	want := sha256.Sum256(payload)

	slotA := ha.dialSlot(true, 1<<20)
	defer slotA.close()
	slotB := ha.dialSlot(true, 1<<20)
	defer slotB.close()

	reasm := newE2EReassembler()
	proof, hasProof := slotA.connect(t, streamID, "origin:443", reasm)
	require.True(t, hasProof, "migration CONNECT_OK must carry a proof")
	origin := ha.waitOrigin(3 * time.Second)

	// A background reader collects everything the relay writes uplink-ward to the
	// origin (net.Pipe write blocks until read, so we MUST drain it concurrently
	// or the relay's uplink write would deadlock).
	gotCh := make(chan []byte, 1)
	go func() { gotCh <- readOriginExactly(t, origin, total, 10*time.Second) }()

	// PHASE 1: uplink on slot A (the origin/baseline path). Send in small pieces
	// so the relay's uplink writer flushes them to the origin pipe.
	for off := 0; off < half; off += 16 << 10 {
		end := off + (16 << 10)
		if end > half {
			end = half
		}
		slotA.sendUplink(t, streamID, payload[off:end])
	}

	// Preemptive MIGRATE A→B (real wire control frame + real proof). After this
	// the server has re-homed the stream's binding to slot B and (pre-fix) slot
	// B's reader has no streams[streamID] entry for uplink.
	ok, _, reason := slotB.sendMigrate(t, core.FlagMigrate, streamID, proof)
	require.True(t, ok, "preemptive MIGRATE must succeed, reason=0x%02x", reason)

	// PHASE 2: uplink on slot B (the regression path). These bytes can only reach
	// the origin if the FlagData uplink branch falls back to the registry's
	// relayEntry.tc when the local streams[] map misses.
	for off := half; off < total; off += 16 << 10 {
		end := off + (16 << 10)
		if end > total {
			end = total
		}
		slotB.sendUplink(t, streamID, payload[off:end])
	}

	got := <-gotCh
	require.Equal(t, total, len(got),
		"uplink byte loss across the migration boundary — post-migration client→origin bytes were dropped (BLOCKER B1)")
	require.Greater(t, len(got), half,
		"no uplink bytes arrived after the migration — test would be vacuous")
	require.Equal(t, want, sha256.Sum256(got),
		"uplink sha256 mismatch — bytes lost/reordered across the migration boundary")
}

// drainUntil pulls seq frames for streamID from slot into reasm until reasm.out
// reaches atLeast in-order bytes or `within` elapses. It replenishes credit per
// frame. It is the test-side pump that lets a phase's writes be fully observed
// (and the bytes confirmed delivered on a specific slot) before the next action.
func drainUntil(t *testing.T, slot *e2eSlot, streamID uint16, reasm *e2eReassembler, atLeast int, within time.Duration) {
	t.Helper()
	overall := time.After(within)
	for len(reasm.out) < atLeast {
		select {
		case f, ok := <-slot.dataCh:
			if !ok {
				return
			}
			if f.streamID != streamID {
				continue
			}
			reasm.push(f.seq, f.data)
			_ = slot.windowUpdate(streamID, uint32(len(f.data)))
		case <-overall:
			return
		}
	}
}

// TestE2E_GraceResume_AfterSuddenSlotDeath: origin streams on slot A; slot A's
// WS conn is killed abruptly; within the grace window the client RESUMEs onto
// slot B; the buffered+resent downlink arrives in seq order; sha256 matches.
func TestE2E_GraceResume_AfterSuddenSlotDeath(t *testing.T) {
	ha := newE2EHarness(t, true)
	// Give a comfortable grace window so the RESUME wins the timer race.
	ha.h.config.MigrateGracePeriod = 5 * time.Second

	const streamID = uint16(0x33)
	const total = 512 << 10 // 512 KiB
	payload := deterministicPayload(total)
	want := sha256.Sum256(payload)

	slotA := ha.dialSlot(true, 1<<20)
	slotB := ha.dialSlot(true, 1<<20)
	defer slotB.close()

	reasm := newE2EReassembler()
	proof, hasProof := slotA.connect(t, streamID, "origin:80", reasm)
	require.True(t, hasProof)
	origin := &pacedOrigin{conn: ha.waitOrigin(3 * time.Second)}

	// PHASE 1: first third on A, drained before we kill A.
	const part = total / 3
	go origin.writePhase(0, part, payload)
	drainUntil(t, slotA, streamID, reasm, part, 5*time.Second)
	require.GreaterOrEqual(t, len(reasm.out), part, "phase-1 bytes must land on A before its death")
	bytesBeforeDeath := len(reasm.out)

	// Sudden death of slot A — abrupt TCP teardown, no WS close handshake. The
	// server orphans the relay (egress tc survives) and arms the grace timer.
	slotA.conn.UnderlyingConn().Close()
	_ = slotA.conn.Close()

	// Wait until the server has actually orphaned the relay before RESUMEing —
	// otherwise the RESUME races the orphan-publish and the CAS fails
	// grace_expired. (Production: client RESUMEs only after it sees slot death.)
	ha.waitOrphaned(t, streamID, 3*time.Second)

	// PHASE 2 (concurrent): keep streaming the rest from the origin WHILE the
	// relay is orphaned. With no binding these bytes pile into the server's
	// downBuffer (and unackedTail) — they must be drained onto B on RESUME with
	// no loss and in order. Run on a goroutine so the test can RESUME promptly.
	go func() {
		origin.writePhase(part, total, payload)
		origin.closeEOF()
	}()

	// RESUME onto slot B within grace — the real reactive path (§5.5).
	rOK := ha.h.metrics.ResumeOK.Load()
	ok, _, reason := slotB.sendMigrate(t, core.FlagResume, streamID, proof)
	require.True(t, ok, "RESUME within grace must succeed, reason=0x%02x", reason)
	require.Equal(t, rOK+1, ha.h.metrics.ResumeOK.Load(), "ResumeOK metric must tick — the real RESUME handler ran")

	deadline := time.Now().Add(10 * time.Second)
	for len(reasm.out) < total && time.Now().Before(deadline) {
		slotB.drainData(streamID, reasm, 300*time.Millisecond, 2*time.Second)
	}

	require.Equal(t, total, len(reasm.out), "byte loss after grace-resume")
	require.Greater(t, len(reasm.out), bytesBeforeDeath,
		"no bytes recovered after RESUME — the grace path carried nothing")
	require.Equal(t, want, sha256.Sum256(reasm.out), "sha256 mismatch after sudden-death RESUME")
}

// TestE2E_DoubleMigration_ABC_OrderPreserved: A→B→C. downSeq is monotonic
// through BOTH migrations and the reassembler delivers every byte in order.
func TestE2E_DoubleMigration_ABC_OrderPreserved(t *testing.T) {
	ha := newE2EHarness(t, true)
	const streamID = uint16(0x44)
	const total = 768 << 10
	payload := deterministicPayload(total)
	want := sha256.Sum256(payload)

	slotA := ha.dialSlot(true, 1<<20)
	defer slotA.close()
	slotB := ha.dialSlot(true, 1<<20)
	defer slotB.close()
	slotC := ha.dialSlot(true, 1<<20)
	defer slotC.close()

	reasm := newE2EReassembler()
	proof, hasProof := slotA.connect(t, streamID, "origin:443", reasm)
	require.True(t, hasProof)
	origin := &pacedOrigin{conn: ha.waitOrigin(3 * time.Second)}

	// PHASE 1 on A.
	const third = total / 3
	go origin.writePhase(0, third, payload)
	drainUntil(t, slotA, streamID, reasm, third, 5*time.Second)
	require.GreaterOrEqual(t, len(reasm.out), third, "phase-1 must land on A")
	onA := len(reasm.out)

	ok, _, _ := slotB.sendMigrate(t, core.FlagMigrate, streamID, proof)
	require.True(t, ok, "A→B migrate")

	// PHASE 2 on B.
	go origin.writePhase(third, 2*third, payload)
	drainUntil(t, slotB, streamID, reasm, 2*third, 5*time.Second)
	require.Greater(t, len(reasm.out), onA, "phase-2 must arrive after A→B migrate")
	onB := len(reasm.out)

	ok, _, _ = slotC.sendMigrate(t, core.FlagMigrate, streamID, proof)
	require.True(t, ok, "B→C migrate")

	// PHASE 3 on C — the rest.
	go func() {
		origin.writePhase(2*third, total, payload)
		origin.closeEOF()
	}()

	deadline := time.Now().Add(10 * time.Second)
	for len(reasm.out) < total && time.Now().Before(deadline) {
		slotC.drainData(streamID, reasm, 250*time.Millisecond, 1*time.Second)
		if len(reasm.out) < total {
			slotB.drainData(streamID, reasm, 40*time.Millisecond, 150*time.Millisecond)
			slotA.drainData(streamID, reasm, 40*time.Millisecond, 150*time.Millisecond)
		}
	}

	require.Equal(t, total, len(reasm.out), "byte loss across A→B→C")
	require.Greater(t, len(reasm.out), onB, "phase-3 must arrive after B→C migrate")
	require.Equal(t, want, sha256.Sum256(reasm.out), "sha256 mismatch across double migration")
	// expectedSeq advanced past the whole stream → strictly monotonic, gapless.
	require.Equal(t, uint64(0), uint64(len(reasm.pending)), "reassembler left a hole (gap) at end")
}

// TestE2E_MigrationLargeTransfer_CreditReplenished is the load-bearing proof of
// the Bug #9 NEW-4 credit-replenishment fix (T20-finding). It drives a transfer
// LARGER than 2×window (the streamCredit clamp) ACROSS a preemptive migration so
// the only way the download can finish is if the WINDOW_UPDATE frames the client
// sends ON SLOT B actually replenish the migrated relay's credit.
//
// The bug: at CONNECT the per-stream credit was shared into BOTH slot A's
// `credits[sid]` map AND entry.credit (same object). After migrating to slot B,
// the client's WINDOW_UPDATE frames arrive on slot B's reader loop, which looked
// up `credits[wuStreamID]` in slot B's OWN (empty for this sid) credits map →
// nil → no replenishment. entry.credit (gated on by relayLoop) therefore drained
// to 0 and the relay parked forever in waitForCredit. A transfer ≤ 2×window
// (the clamp ceiling) could still finish on the inherited credit (which is why
// the other e2e tests, all ≤ 2×window, never caught it); a transfer > 2×window
// hangs.
//
// With the fix (cross-slot registry lookup in the FlagWindowUpdate handler) the
// WINDOW_UPDATE on slot B finds the relayEntry via h.relayRegistry.find and tops
// up entry.credit, so the >2×window transfer completes and sha256 matches.
//
// WITHOUT the fix this test HANGS (relay parked) until the 30s deadline trips a
// require failure — i.e. it is a true red→green proof.
func TestE2E_MigrationLargeTransfer_CreditReplenished(t *testing.T) {
	ha := newE2EHarness(t, true)
	const streamID = uint16(0x88)
	// Small window so the 2×window credit clamp (=512 KiB) is far below the
	// total: the post-migration download CANNOT complete on the credit inherited
	// at the migration boundary — it must be replenished by slot-B WINDOW_UPDATEs.
	const window = 256 << 10  // 256 KiB → clamp ceiling 512 KiB
	const total = 3 << 20     // 3 MiB ≫ 2×window
	payload := deterministicPayload(total)
	want := sha256.Sum256(payload)

	slotA := ha.dialSlot(true, window)
	defer slotA.close()
	slotB := ha.dialSlot(true, window)
	defer slotB.close()

	reasm := newE2EReassembler()
	proof, hasProof := slotA.connect(t, streamID, "origin:443", reasm)
	require.True(t, hasProof, "migration CONNECT_OK must carry a proof")
	origin := &pacedOrigin{conn: ha.waitOrigin(3 * time.Second)}

	// PHASE 1: stream a small first chunk (< window) on slot A and drain it there,
	// sending WINDOW_UPDATEs so the relay keeps reading. This makes the migration
	// bisect a genuinely in-flight stream.
	const onAChunk = 128 << 10 // 128 KiB, comfortably under the window
	go origin.writePhase(0, onAChunk, payload)
	drainUntil(t, slotA, streamID, reasm, onAChunk, 10*time.Second)
	require.GreaterOrEqual(t, len(reasm.out), onAChunk, "phase-1 bytes must land on A before migration")
	bytesOnA := len(reasm.out)

	// Preemptive MIGRATE to slot B (real wire control frame + real proof).
	ok, _, reason := slotB.sendMigrate(t, core.FlagMigrate, streamID, proof)
	require.True(t, ok, "preemptive MIGRATE must succeed, reason=0x%02x", reason)

	// PHASE 2: stream the WHOLE remainder (≈ 2.875 MiB) — far more than the
	// 512 KiB credit clamp. The relay can only keep reading the origin if slot-B
	// WINDOW_UPDATEs replenish entry.credit. Run the origin write concurrently
	// because net.Pipe writes block on the relay reads (which themselves block on
	// credit) — so the writer can only make progress as credit is replenished.
	go func() {
		origin.writePhase(onAChunk, total, payload)
		origin.closeEOF()
	}()

	// Drain slot B with per-frame WINDOW_UPDATEs (drainData calls windowUpdate per
	// frame). WITHOUT the fix the relay stalls after ~512 KiB and reasm.out never
	// reaches total → the loop exhausts the 30s deadline and the require below
	// fails. WITH the fix the credit is topped up and the full 3 MiB arrives.
	deadline := time.Now().Add(30 * time.Second)
	for len(reasm.out) < total && time.Now().Before(deadline) {
		slotB.drainData(streamID, reasm, 500*time.Millisecond, 2*time.Second)
		if len(reasm.out) < total {
			slotA.drainData(streamID, reasm, 50*time.Millisecond, 200*time.Millisecond)
		}
	}

	require.Equal(t, total, len(reasm.out),
		"download stalled across the migration boundary — slot-B WINDOW_UPDATE did not replenish the migrated relay credit (Bug #9 NEW-4 regression)")
	require.Greater(t, len(reasm.out), bytesOnA,
		"no bytes arrived after the migration — test would be vacuous")
	require.Equal(t, want, sha256.Sum256(reasm.out),
		"sha256 mismatch — bytes lost/reordered across the migration boundary")
}

// TestE2E_Compat_NewClientOldServer: server StreamMigrationEnabled=false →
// capability off → the legacy relay path runs; a plain download works and the
// CONNECT_OK carries NO proof (no migration). The migrate-capability bit the
// client advertised must be refused.
func TestE2E_Compat_NewClientOldServer(t *testing.T) {
	ha := newE2EHarness(t, false) // server migration disabled
	const streamID = uint16(0x55)
	const total = 256 << 10
	payload := deterministicPayload(total)
	want := sha256.Sum256(payload)

	// Client advertises migrate=true, but the server must NOT negotiate it.
	slot := ha.dialSlot(true, 1<<20)
	defer slot.close()

	reasm := newE2EReassembler()
	proof, hasProof := slot.connect(t, streamID, "origin:443", reasm)
	require.False(t, hasProof, "old server must NOT issue a migration proof")
	require.False(t, slot.seqMode, "old server must NOT negotiate the seq wire format")
	_ = proof
	origin := ha.waitOrigin(3 * time.Second)
	writeOrigin(origin, payload, true)

	// Legacy path uses NewStreamDataChunk (no downSeq). The reader fans those
	// onto rawCh; concatenate in arrival order (single slot, no reorder).
	var got []byte
	slot.drainRawInto(&got, total, 500*time.Millisecond, 8*time.Second)
	require.Equal(t, total, len(got), "legacy download byte count mismatch")
	require.Equal(t, want, sha256.Sum256(got), "legacy download sha256 mismatch")

	// The migration registry must be empty — no relayEntry was created.
	require.Equal(t, 0, ha.h.relayRegistry.totalCount(), "old server must not register migratable relays")
}

// TestE2E_Compat_OldClientNewServer: the client does NOT advertise the migrate
// bit → the server keeps the legacy relay even though migration is enabled
// server-side. Download works; no proof; no relay registered.
func TestE2E_Compat_OldClientNewServer(t *testing.T) {
	ha := newE2EHarness(t, true) // server migration ENABLED
	const streamID = uint16(0x66)
	const total = 256 << 10
	payload := deterministicPayload(total)
	want := sha256.Sum256(payload)

	// Old client: advertiseMigrate=false.
	slot := ha.dialSlot(false, 1<<20)
	defer slot.close()

	reasm := newE2EReassembler()
	proof, hasProof := slot.connect(t, streamID, "origin:443", reasm)
	require.False(t, hasProof, "no-migrate client must NOT get a proof")
	require.False(t, slot.seqMode, "no-migrate client must NOT negotiate the seq wire format")
	_ = proof
	origin := ha.waitOrigin(3 * time.Second)
	writeOrigin(origin, payload, true)

	var got []byte
	slot.drainRawInto(&got, total, 500*time.Millisecond, 8*time.Second)
	require.Equal(t, total, len(got), "old-client download byte count mismatch")
	require.Equal(t, want, sha256.Sum256(got), "old-client download sha256 mismatch")
	require.Equal(t, 0, ha.h.relayRegistry.totalCount(), "no-migrate client must not register a relay")
}

// TestE2E_TailResentOnADeathBeforeAck: a preemptive MIGRATE to B happens, then
// slot A dies before the client could StreamAck the in-flight tail. The server
// resends the unacked tail on B; the client dedups overlapping seqs; final
// bytes are intact.
func TestE2E_TailResentOnADeathBeforeAck(t *testing.T) {
	ha := newE2EHarness(t, true)
	ha.h.config.MigrateGracePeriod = 5 * time.Second
	const streamID = uint16(0x77)
	const total = 512 << 10
	payload := deterministicPayload(total)
	want := sha256.Sum256(payload)

	slotA := ha.dialSlot(true, 1<<20)
	slotB := ha.dialSlot(true, 1<<20)
	defer slotB.close()

	reasm := newE2EReassembler()
	proof, hasProof := slotA.connect(t, streamID, "origin:443", reasm)
	require.True(t, hasProof)
	origin := &pacedOrigin{conn: ha.waitOrigin(3 * time.Second)}

	// PHASE 1: stream the first half and drain it on A. drainUntil sends window-
	// updates per frame but NEVER a StreamAck, so the server keeps the whole first
	// half in unackedTail (bounded by the flow window = 1 MiB; 256 KiB fits).
	// These bytes are already delivered in order on A.
	const half = total / 2
	go origin.writePhase(0, half, payload)
	drainUntil(t, slotA, streamID, reasm, half, 5*time.Second)
	require.GreaterOrEqual(t, len(reasm.out), half, "phase-1 must land (unacked) on A")

	// Kill A abruptly. The relay is orphaned with a populated unackedTail.
	slotA.conn.UnderlyingConn().Close()
	_ = slotA.conn.Close()
	ha.waitOrphaned(t, streamID, 3*time.Second)

	// PHASE 2 (concurrent): stream the rest while orphaned.
	go func() {
		origin.writePhase(half, total, payload)
		origin.closeEOF()
	}()

	// RESUME after A death (aDead=true) → server resends the unacked tail on B in
	// seq order, AHEAD of the still-buffered phase-2 frames. The client has
	// already delivered those seqs in order on A, so the reassembler must DEDUP
	// them (seq < expectedSeq) — proving the dedup path is exercised end-to-end.
	tailBefore := ha.h.metrics.MigrateTailResent.Load()
	ok, _, reason := slotB.sendMigrate(t, core.FlagResume, streamID, proof)
	require.True(t, ok, "RESUME after A death must succeed, reason=0x%02x", reason)
	require.Greater(t, ha.h.metrics.MigrateTailResent.Load(), tailBefore,
		"MigrateTailResent must tick — the unacked tail was re-enqueued on B")

	deadline := time.Now().Add(10 * time.Second)
	for len(reasm.out) < total && time.Now().Before(deadline) {
		slotB.drainData(streamID, reasm, 300*time.Millisecond, 2*time.Second)
	}

	require.Equal(t, total, len(reasm.out), "byte loss after tail-resend")
	require.Equal(t, want, sha256.Sum256(reasm.out), "sha256 mismatch after tail-resend")
	require.Greater(t, reasm.dups, 0,
		"reassembler deduped 0 frames — the resent tail did not overlap, so the dedup path was not exercised")
	t.Logf("reassembler deduped %d overlapping resent frames", reasm.dups)
}

// ───────────────────────────────────────────────────────────────────────────
// Bug #10 e2e tests — origin-death → FlagStreamClose client notification
// ───────────────────────────────────────────────────────────────────────────

// TestE2E_OriginDeath_SignalsClient_Bug10 is the direct end-to-end reproduction
// of Bug #10: with origin_death_teardown enabled, killing the origin TCP pipe
// and then triggering a write error (via an uplink frame that reaches the dead
// origin) must cause the server to send FlagStreamClose to the client, so the
// client is never left hanging waiting for a dead stream.
//
// Path exercised: startWriter path A (onWriteErr → signalStreamEnd). The
// uplink write hits the closed net.Pipe → broken-pipe error → signalStreamEnd
// wins CAS(stActive→stClosing) → sends FlagStreamClose on the live binding →
// client reader surfaces the stream ID on closeCh.
func TestE2E_OriginDeath_SignalsClient_Bug10(t *testing.T) {
	ha := newE2EHarness(t, true /*migrationEnabled*/)
	ha.h.relayRegistry.setOriginDeathTeardown(true)

	slot := ha.dialSlot(true, 1<<20)
	defer slot.close()
	reasm := newE2EReassembler()
	const streamID uint16 = 1
	_, _ = slot.connect(t, streamID, "origin:443", reasm)

	// Grab the server-side end of the origin net.Pipe. After Close() any further
	// write from the relay's startWriter goroutine to the client-side end returns
	// io.ErrClosedPipe — this is the "broken pipe" that triggers Bug #10.
	origin := ha.waitOrigin(2 * time.Second)
	origin.Close()

	// net.Pipe is synchronous and unbuffered. After origin.Close() the relay's
	// startWriter has the client-side end; its next Write returns ErrClosedPipe.
	// Sending an uplink frame causes the server's reader loop to write the payload
	// to the wsStream (s.Write), which drains into writeCh, and startWriter picks
	// it up and writes to targetConn (now closed) — triggering onWriteErr →
	// signalStreamEnd → FlagStreamClose.
	//
	// Send a few uplink frames to guarantee the broken-pipe path is hit (in case
	// the first frame is observed by the relay goroutine before the close fully
	// propagates in the OS scheduler).
	for i := 0; i < 5; i++ {
		slot.sendChunk(t, core.NewStreamDataChunk(slot.session.ID, slot.session.NextSeqNum(), streamID, []byte("GET / HTTP/1.1\r\n\r\n")))
		// Brief yield so the relay goroutine has a chance to attempt the write and
		// observe the pipe error.
		time.Sleep(5 * time.Millisecond)
		select {
		case sid := <-slot.closeCh:
			require.Equal(t, streamID, sid, "FlagStreamClose must carry the dead stream's ID")
			return // success — client received the signal promptly
		default:
		}
	}

	// Last chance: wait up to 3 more seconds after all uplink sends.
	select {
	case sid := <-slot.closeCh:
		require.Equal(t, streamID, sid, "FlagStreamClose must carry the dead stream's ID")
	case <-time.After(3 * time.Second):
		t.Fatal("client never received FlagStreamClose for the dead-origin stream (Bug #10 hang)")
	}
}

// TestE2E_OriginDeath_FlagOff_NoSignal_Bug10 asserts that with
// origin_death_teardown disabled (the default / pre-Bug-#10-fix state) the
// client does NOT receive FlagStreamClose, but the server still performs its
// internal teardown (signalStreamEnd removes the entry). The test verifies the
// flag correctly gates the send path.
func TestE2E_OriginDeath_FlagOff_NoSignal_Bug10(t *testing.T) {
	ha := newE2EHarness(t, true /*migrationEnabled*/)
	// Do NOT call setOriginDeathTeardown → default false.

	slot := ha.dialSlot(true, 1<<20)
	defer slot.close()
	reasm := newE2EReassembler()
	const streamID uint16 = 1
	_, _ = slot.connect(t, streamID, "origin:443", reasm)

	origin := ha.waitOrigin(2 * time.Second)
	origin.Close()

	// Send uplink to trigger the write error on the dead pipe.
	for i := 0; i < 5; i++ {
		slot.sendChunk(t, core.NewStreamDataChunk(slot.session.ID, slot.session.NextSeqNum(), streamID, []byte("GET / HTTP/1.1\r\n\r\n")))
		time.Sleep(5 * time.Millisecond)
	}

	// With the flag OFF the client must NOT receive FlagStreamClose in a
	// reasonable window. A 1.5s silence is the positive assertion.
	select {
	case sid := <-slot.closeCh:
		t.Fatalf("flag OFF must NOT send FlagStreamClose, but client received stream ID %d", sid)
	case <-time.After(1500 * time.Millisecond):
		// Expected: no signal delivered. Server still tears down internally.
	}
}

// TestE2E_b1_ResumeThenOriginDeath_SignalsLiveSlot is the function-level
// guard for the b1 fix (bound.Store before CAS in handleMigrateOrResume).
// After slot A dies and the stream is resumed onto live slot B, killing the
// origin must cause FlagStreamClose to arrive on slot B — NOT on the dead
// slot A. This proves the b1 ordering is correct: the binding is published on
// B before the stActive CAS, so signalStreamEnd (triggered by the uplink write
// error) snapshots the B binding and sends the close frame on B's writer.
func TestE2E_b1_ResumeThenOriginDeath_SignalsLiveSlot(t *testing.T) {
	ha := newE2EHarness(t, true /*migrationEnabled*/)
	ha.h.relayRegistry.setOriginDeathTeardown(true)
	ha.h.config.MigrateGracePeriod = 5 * time.Second

	slotA := ha.dialSlot(true, 1<<20)
	reasm := newE2EReassembler()
	const streamID uint16 = 1
	proof, hasProof := slotA.connect(t, streamID, "origin:443", reasm)
	require.True(t, hasProof, "migration CONNECT_OK must carry a proof")

	// Grab the origin before killing slot A so we can control it later.
	origin := ha.waitOrigin(2 * time.Second)

	// Kill slot A abruptly — the server orphans the relay and arms the grace timer.
	slotA.conn.UnderlyingConn().Close()
	_ = slotA.conn.Close()
	ha.waitOrphaned(t, streamID, 3*time.Second)

	// RESUME onto live slot B within the grace window.
	slotB := ha.dialSlot(true, 1<<20)
	defer slotB.close()
	ok, _, reason := slotB.sendMigrate(t, core.FlagResume, streamID, proof)
	require.True(t, ok, "RESUME must succeed onto live slot B, reason=0x%02x", reason)

	// Now kill the origin. The relay's startWriter (which targets the same tc)
	// will observe the broken pipe on the next uplink write and call
	// onWriteErr → signalStreamEnd, which snapshots the binding (now pointing at
	// slot B's session+writer after the RESUME) and sends FlagStreamClose on B.
	origin.Close()

	// Trigger the broken-pipe write by sending uplink on slot B.
	for i := 0; i < 5; i++ {
		slotB.sendChunk(t, core.NewStreamDataChunk(slotB.session.ID, slotB.session.NextSeqNum(), streamID, []byte("data")))
		time.Sleep(5 * time.Millisecond)
		select {
		case sid := <-slotB.closeCh:
			require.Equal(t, streamID, sid,
				"FlagStreamClose must carry the dead stream's ID on the LIVE slot B")
			// Verify slot A's closeCh is silent — the signal went to the live slot.
			select {
			case <-slotA.closeCh:
				// slotA conn is closed so this channel will never produce, fine.
			default:
			}
			return // success
		default:
		}
	}

	select {
	case sid := <-slotB.closeCh:
		require.Equal(t, streamID, sid,
			"after RESUME, origin-death must signal FlagStreamClose on the LIVE slot B (b1)")
	case <-time.After(3 * time.Second):
		t.Fatal("after RESUME, origin-death must signal FlagStreamClose on the LIVE slot B (b1)")
	}
}

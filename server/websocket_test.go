package server

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/nixavpn/shadowlink/core"
)

// TestWSPingInterval_MedianBumped — sanity check that JitteredIntervalLogNormal
// with the Wave 2.2 (45s, 0.6) params produces median ≈ 45s. Pinned ahead of
// the production change to catch param drift (Wave 2.2, 2026-05-17).
//
// DEPLOY GATE: do NOT ship this binary без выполнения infrastructure precondition
// в websocket.go::handleWebSocket (nginx proxy_read_timeout ≥180s, MaxClients ≥500,
// SessionTimeout ≤90s). 2026-05-17 field incident при дефолтном nginx 60s выдал
// reader-EOF cascade → max_clients overrun → decoy lockout всех клиентов.
func TestWSPingInterval_MedianBumped(t *testing.T) {
	const N = 1000
	const newMedianSec = 45.0
	samples := make([]float64, N)
	for i := 0; i < N; i++ {
		samples[i] = core.JitteredIntervalLogNormal(45*time.Second, 0.6).Seconds()
	}
	sort.Float64s(samples)
	gotMedian := samples[N/2]
	if gotMedian < newMedianSec*0.8 || gotMedian > newMedianSec*1.2 {
		t.Errorf("median = %.2fs, want ~%.2fs (±20%%)", gotMedian, newMedianSec)
	}
}

// wsAuthResult is the tuple returned by authenticateFirstFrame (session +
// negotiated window + negotiated migrate capability, Bug #9 §3.5).
type wsAuthResult struct {
	session    *core.Session
	flowWindow uint32
	migrateOK  bool
}

// wsAuthHarness wires a single-shot httptest server that upgrades the request
// and feeds authenticateFirstFrame with the resulting *websocket.Conn. The
// result (or nil) is published on resCh. Callers drive the client side of the
// pair by dialing srv.URL (converted to ws://).
type wsAuthHarness struct {
	srv    *httptest.Server
	wsURL  string
	resCh  chan wsAuthResult
	client *websocket.Conn
}

func newWSAuthHarness(t *testing.T, h *Handler) *wsAuthHarness {
	t.Helper()
	resCh := make(chan wsAuthResult, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			resCh <- wsAuthResult{}
			return
		}
		defer conn.Close()
		sess, fw, mig := h.authenticateFirstFrame(conn)
		resCh <- wsAuthResult{session: sess, flowWindow: fw, migrateOK: mig}
	}))
	return &wsAuthHarness{
		srv:   srv,
		wsURL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws",
		resCh: resCh,
	}
}

func (ha *wsAuthHarness) dial(t *testing.T) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial(ha.wsURL, nil)
	require.NoError(t, err, "dial WS harness")
	ha.client = c
	return c
}

func (ha *wsAuthHarness) close() {
	if ha.client != nil {
		ha.client.Close()
	}
	ha.srv.Close()
}

// waitResult blocks until authenticateFirstFrame returns or the overall
// deadline expires (test-level safety net).
func (ha *wsAuthHarness) waitResult(t *testing.T, overall time.Duration) (*core.Session, bool) {
	t.Helper()
	select {
	case r := <-ha.resCh:
		return r.session, true
	case <-time.After(overall):
		return nil, false
	}
}

func TestAuthenticateFirstFrame_ValidKeepalive(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	ha := newWSAuthHarness(t, h)
	defer ha.close()
	c := ha.dial(t)

	keepalive := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc, err := sess.EncryptChunk(keepalive)
	require.NoError(t, err)
	frame := append(append([]byte{}, tokenWithHint...), enc...)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, frame))

	got, ok := ha.waitResult(t, 3*time.Second)
	require.True(t, ok, "auth must return within 3s on valid first frame")
	require.NotNil(t, got, "keepalive first frame with valid token must authenticate")
	require.Equal(t, sess.ID, got.ID)
}

func TestAuthenticateFirstFrame_FlagConnectRejected(t *testing.T) {
	// FlagConnect would consume seq_num=0 without actually dialling the
	// target — the client would deadlock waiting for CONNECT_OK. Only
	// FlagKeepalive is allowed as the first frame; FlagConnect must arrive
	// through the relay loop instead.
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	ha := newWSAuthHarness(t, h)
	defer ha.close()
	c := ha.dial(t)

	connect := core.NewConnectChunk(sess.ID, sess.NextSeqNum(), "example.com:443")
	enc, err := sess.EncryptChunk(connect)
	require.NoError(t, err)
	frame := append(append([]byte{}, tokenWithHint...), enc...)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, frame))

	got, ok := ha.waitResult(t, 3*time.Second)
	require.True(t, ok)
	require.Nil(t, got, "FlagConnect as first frame must be rejected")
}

func TestAuthenticateFirstFrame_ReplayedSeqNumRejected(t *testing.T) {
	// AcceptSeqNum(0) succeeds on the first call, then flips the bitmap bit.
	// A replayed first frame with the same seq_num must fail the sliding-window
	// check — double-connect on the same session would otherwise succeed.
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	// Prime the server session bitmap so seq_num=0 is already consumed, the
	// same way a prior successful first frame would have left it.
	serverSess, ok := h.sessions.Get(sess.ID)
	require.True(t, ok, "server session must exist after handshake")
	require.True(t, serverSess.AcceptSeqNum(0), "primer must succeed before the replay attempt")

	ha := newWSAuthHarness(t, h)
	defer ha.close()
	c := ha.dial(t)

	// Client re-uses seq_num=0 — classic replay.
	ka := core.NewKeepaliveChunk(sess.ID, 0)
	enc, err := sess.EncryptChunk(ka)
	require.NoError(t, err)
	frame := append(append([]byte{}, tokenWithHint...), enc...)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, frame))

	got, ok := ha.waitResult(t, 3*time.Second)
	require.True(t, ok)
	require.Nil(t, got, "replayed seq_num=0 must fail AcceptSeqNum and auth")
}

func TestAuthenticateFirstFrame_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("timeout test waits ~1.5s — skip in -short mode")
	}
	h, _ := setupTestHandler(t)

	ha := newWSAuthHarness(t, h)
	defer ha.close()
	_ = ha.dial(t) // dial but never write — server must time out

	start := time.Now()
	got, ok := ha.waitResult(t, 4*time.Second)
	elapsed := time.Since(start)
	require.True(t, ok, "auth must not hang past its deadline")
	require.Nil(t, got, "timed-out auth must return nil")
	require.Greater(t, elapsed, 1200*time.Millisecond, "timeout fired too early: %v", elapsed)
	require.Less(t, elapsed, 2500*time.Millisecond, "timeout too loose: %v", elapsed)
}

func TestAuthenticateFirstFrame_NonBinaryRejected(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	ha := newWSAuthHarness(t, h)
	defer ha.close()
	c := ha.dial(t)

	keepalive := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc, err := sess.EncryptChunk(keepalive)
	require.NoError(t, err)
	frame := append(append([]byte{}, tokenWithHint...), enc...)
	// Wrong frame type: send as text even though bytes would otherwise be valid.
	require.NoError(t, c.WriteMessage(websocket.TextMessage, frame))

	got, ok := ha.waitResult(t, 3*time.Second)
	require.True(t, ok)
	require.Nil(t, got, "text-frame first message must be rejected (binary-only protocol)")
}

func TestAuthenticateFirstFrame_ShortPayloadRejected(t *testing.T) {
	h, _ := setupTestHandler(t)

	ha := newWSAuthHarness(t, h)
	defer ha.close()
	c := ha.dial(t)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, []byte{0x01, 0x02, 0x03}))

	got, ok := ha.waitResult(t, 3*time.Second)
	require.True(t, ok)
	require.Nil(t, got, "sub-tokenLen payload must not authenticate")
}

func TestAuthenticateFirstFrame_UnknownHintRejected(t *testing.T) {
	h, _ := setupTestHandler(t)

	ha := newWSAuthHarness(t, h)
	defer ha.close()
	c := ha.dial(t)

	// Random bytes sized to pass the length gate but carry no valid hint.
	frame := make([]byte, h.sessionTokenSize()+core.MinChunk+16)
	for i := range frame {
		frame[i] = byte(i * 31)
	}
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, frame))

	got, ok := ha.waitResult(t, 3*time.Second)
	require.True(t, ok)
	require.Nil(t, got, "random hint must not resolve to any session")
}

func TestAuthenticateFirstFrame_FlagDataRejected(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	ha := newWSAuthHarness(t, h)
	defer ha.close()
	c := ha.dial(t)

	// Build a FlagData chunk — legitimate session, but the wrong first-frame kind.
	// Early-data injection guard: only keepalive/connect are allowed here.
	data := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     core.FlagData,
		Payload:   []byte{0x00, 0x01, 0x02, 0x03},
	}
	enc, err := sess.EncryptChunk(data)
	require.NoError(t, err)
	frame := append(append([]byte{}, tokenWithHint...), enc...)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, frame))

	got, ok := ha.waitResult(t, 3*time.Second)
	require.True(t, ok)
	require.Nil(t, got, "FlagData first frame must be rejected")
}

// ---------- C4: handleWebSocket hybrid dispatch tests ----------
//
// Integration flavour: httptest.Server gives us a real hijackable response
// writer so wsUpgrader.Upgrade works end-to-end. Dial failures therefore
// correspond to the server returning a non-101 response (decoy path).

// newHandlerHTTPServer runs h.ServeHTTP on an httptest server, returning the
// host and a cleanup. The host lets callers build ws:// URLs with the right
// port; ws requests against this server go through ServeHTTP → handleWebSocket,
// exactly as in production.
func newHandlerHTTPServer(t *testing.T, h *Handler) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	host := strings.TrimPrefix(srv.URL, "http://")
	return host, srv.Close
}

func TestHandleWebSocket_PathWhitelist_RejectsNonPool(t *testing.T) {
	h, _ := setupTestHandler(t)
	host, stop := newHandlerHTTPServer(t, h)
	defer stop()

	// Non-pool path — upgrade must not happen, decoy HTML is served instead.
	_, resp, err := websocket.DefaultDialer.Dial("ws://"+host+"/not-in-pool", nil)
	require.Error(t, err, "dial to non-whitelisted path must fail the 101 upgrade")
	require.NotNil(t, resp, "decoy path must return a regular HTTP response, not a network error")
	require.NotEqual(t, http.StatusSwitchingProtocols, resp.StatusCode,
		"path not in pool must NOT upgrade — got status %d", resp.StatusCode)
}

// TestHandleWebSocket_AllPoolPaths_AcceptUpgrade is the CRIT-4 integration
// guard: every path the client may pick from the pool must be acceptable to
// IsAllowedWSPath and reach the WebSocket upgrade. If a single entry slips
// through to the decoy branch, the client will retry forever on slot bring-up.
//
// We do NOT drive a full first-frame auth here (that's covered by the happy-
// path tests above); we only assert the 101 Switching Protocols response,
// which proves the path passed the IsAllowedWSPath gate inside handleWebSocket.
func TestHandleWebSocket_AllPoolPaths_AcceptUpgrade(t *testing.T) {
	h, _ := setupTestHandler(t)
	host, stop := newHandlerHTTPServer(t, h)
	defer stop()

	for _, p := range AllWSPaths() {
		// Pool entries that include a query string are stored as a single
		// string for symmetry with the client URL builder. The matcher
		// accepts both the bare path and the path-with-query form, so the
		// dialer needs to send only the canonical (bare) shape — the query
		// would land on the request's r.URL.RawQuery and not affect path
		// matching.
		wsPath := p
		if i := strings.IndexByte(wsPath, '?'); i > 0 {
			wsPath = wsPath[:i]
		}

		conn, resp, err := websocket.DefaultDialer.Dial("ws://"+host+wsPath, nil)
		require.NoError(t, err, "pool path %q must upgrade (resp=%v)", wsPath, resp)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode,
			"pool path %q reached upgrade but server returned status %d", wsPath, resp.StatusCode)
		// We only care about the 101; the conn will sit waiting for an
		// auth first frame that never comes — server's 1500ms deadline
		// will close it eventually. Close immediately to avoid leaks.
		_ = conn.Close()
	}
}

func TestHandleWebSocket_PreUpgradeRateLimit_FallsToDecoy(t *testing.T) {
	// Force legacy path: test drains h.rateLimiters.WSUpgrade.Allow directly;
	// with bucket-on the HTTP path consumes the TokenBucket (separate state).
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	h, _ := setupTestHandler(t)

	// Drain the WSUpgrade limiter for loopback — httptest binds to 127.0.0.1
	// so both test and prod gate will see the same key.
	for range 30 {
		require.True(t, h.rateLimiters.WSUpgrade.Allow("127.0.0.1"))
	}
	// One more Allow() must now be denied — sanity anchor for the rate-limit
	// state before we exercise the HTTP path.
	require.False(t, h.rateLimiters.WSUpgrade.Allow("127.0.0.1"))

	host, stop := newHandlerHTTPServer(t, h)
	defer stop()

	wsPath := AllWSPaths()[0]
	_, _, err := websocket.DefaultDialer.Dial("ws://"+host+wsPath, nil)
	require.Error(t, err, "exhausted WSUpgrade limiter must keep the upgrade from happening")
}

func TestHandleWebSocket_NewAuth_HappyPath(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	host, stop := newHandlerHTTPServer(t, h)
	defer stop()

	// Pick any path from the WS pool — the pool no longer contains "/ws"
	// (CRIT-4). All allowed paths upgrade identically.
	wsPath := AllWSPaths()[0]
	c, resp, err := websocket.DefaultDialer.Dial("ws://"+host+wsPath, nil)
	require.NoError(t, err, "new-auth path must upgrade on %s (resp=%v)", wsPath, resp)
	defer c.Close()

	// First frame: body-prefix keepalive — authenticates and hands the
	// connection off to the relay loop. The relay loop does NOT echo an ACK
	// for the auth frame itself; callers send a second keepalive to probe
	// liveness.
	ka1 := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc1, err := sess.EncryptChunk(ka1)
	require.NoError(t, err)
	authFrame := append(append([]byte{}, tokenWithHint...), enc1...)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, authFrame))

	// Second keepalive — goes through the post-upgrade reader which is
	// plain encrypted chunks (no token prefix) and returns FlagAck.
	ka2 := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc2, err := sess.EncryptChunk(ka2)
	require.NoError(t, err)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, enc2))

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	msgType, ackData, err := c.ReadMessage()
	require.NoError(t, err, "expected ACK from relay loop after post-auth keepalive")
	require.Equal(t, websocket.BinaryMessage, msgType)

	ackChunk, err := sess.DecryptChunkSafe(ackData)
	require.NoError(t, err, "ACK must decrypt with session keys")
	require.Equal(t, core.FlagAck, ackChunk.Flags, "keepalive must be answered with FlagAck")
}

func TestHandleWebSocket_NewAuth_BadFirstFrame_FakeAcksAndCloses(t *testing.T) {
	h, _ := setupTestHandler(t)
	host, stop := newHandlerHTTPServer(t, h)
	defer stop()

	wsPath := AllWSPaths()[0]
	c, resp, err := websocket.DefaultDialer.Dial("ws://"+host+wsPath, nil)
	require.NoError(t, err, "pre-upgrade gates must not block a clean request (resp=%v)", resp)
	defer c.Close()

	// Send payload that passes the length gate but carries no valid hint.
	garbage := make([]byte, h.sessionTokenSize()+core.MinChunk+16)
	for i := range garbage {
		garbage[i] = byte(i * 17)
	}
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, garbage))

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	msgType, data, err := c.ReadMessage()
	require.NoError(t, err, "fakeAckAndClose must write one binary frame before closing")
	require.Equal(t, websocket.BinaryMessage, msgType)
	require.GreaterOrEqual(t, len(data), 200)
	require.LessOrEqual(t, len(data), 2000)

	_, _, err = c.ReadMessage()
	require.Error(t, err)
	require.True(t,
		websocket.IsCloseError(err, websocket.CloseNormalClosure),
		"expected CloseNormalClosure after fake ACK, got %T: %v", err, err)
}

func TestFakeAckAndClose_WritesRandomAckAndCloses(t *testing.T) {
	h, _ := setupTestHandler(t)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			close(done)
			return
		}
		h.fakeAckAndClose(conn)
		close(done)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(3 * time.Second))

	msgType, data, err := c.ReadMessage()
	require.NoError(t, err, "first read must yield the fake ACK frame")
	require.Equal(t, websocket.BinaryMessage, msgType, "fake ACK must be a binary frame")
	require.GreaterOrEqual(t, len(data), 200, "fake ACK size floor is 200 bytes")
	require.LessOrEqual(t, len(data), 2000, "fake ACK size ceiling is 2000 bytes")

	// Second read should observe a normal-closure control frame.
	_, _, err = c.ReadMessage()
	require.Error(t, err, "second read must surface a close error")
	require.True(t,
		websocket.IsCloseError(err, websocket.CloseNormalClosure),
		"expected CloseNormalClosure, got %T: %v", err, err)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fakeAckAndClose did not return within 3s")
	}
}

func TestFakeAckAndClose_TolerateClientGoneBeforeAck(t *testing.T) {
	// If the client vanishes before the ack is flushed, fakeAckAndClose must
	// still return promptly (no goroutine stuck on a dead socket).
	h, _ := setupTestHandler(t)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			close(done)
			return
		}
		// Give the client a beat to tear down TCP before the server touches the socket.
		time.Sleep(100 * time.Millisecond)
		h.fakeAckAndClose(conn)
		close(done)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	// Abrupt close — no close handshake, TCP RST-ish teardown.
	require.NoError(t, c.Close())

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fakeAckAndClose must not hang when client is gone")
	}
}

func TestAuthenticateFirstFrame_MissingTunnelRejected(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	// Simulate a session whose tunnel was torn down (e.g. double-dispatch race
	// or explicit teardown) — auth must refuse to attach to an orphan session.
	h.tunnelsMu.Lock()
	delete(h.tunnels, sess.ID)
	h.tunnelsMu.Unlock()

	ha := newWSAuthHarness(t, h)
	defer ha.close()
	c := ha.dial(t)

	keepalive := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc, err := sess.EncryptChunk(keepalive)
	require.NoError(t, err)
	frame := append(append([]byte{}, tokenWithHint...), enc...)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, frame))

	got, ok := ha.waitResult(t, 3*time.Second)
	require.True(t, ok)
	require.Nil(t, got, "session without tunnel must not authenticate")
}

// TestClassifyWSReaderExitErr pins the 2026-05-18 forensics contract:
// each error string the gorilla/websocket reader can surface must map to
// exactly the bucket we attribute it to. Dashboards depend on this mapping
// being stable — a regression here silently rewrites the "who closed the
// TCP first?" story.
func TestClassifyWSReaderExitErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want wsReaderExitKind
	}{
		// Hard TCP RST surfaced through the kernel. Linux/macOS:
		// "read tcp ...: connection reset by peer". Windows: "wsarecv:
		// An existing connection was forcibly closed by the remote host".
		{"linux_rst", testErr("read tcp 10.0.0.1:443: connection reset by peer"), wsExitReset},
		{"windows_rst", testErr("read tcp 10.0.0.1:443: wsarecv: An existing connection was forcibly closed by the remote host."), wsExitReset},

		// Our own conn.Close() raced the read.
		{"local_close", testErr("read tcp 10.0.0.1:443: use of closed network connection"), wsExitLocalClose},

		// Read deadline expired without bytes — CF-edge black-hole.
		{"deadline", testErr("read tcp 10.0.0.1:443: i/o timeout"), wsExitIOTimeout},

		// Peer-side orderly FIN. This is the bucket that confirms the
		// 2026-05-18 hypothesis: when client logs close-1006, server
		// records peer_eof, meaning the middlebox tore down between us.
		{"eof", testErr("EOF"), wsExitPeerEOF},
		{"unexpected_eof", testErr("unexpected EOF"), wsExitPeerEOF},

		// Residual.
		{"unknown", testErr("some other transport error"), wsExitOther},
		{"nil", nil, wsExitOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyWSReaderExitErr(tc.err)
			require.Equal(t, tc.want, got,
				"err=%v: kind classification regression — dashboards will silently mis-attribute teardowns", tc.err)
		})
	}
}

// TestClassifyWSReaderExitErr_OrderingInvariants documents the precedence
// the switch relies on. If a Windows error message happens to contain
// both "wsarecv" AND the substring "EOF" (rare but possible when gorilla
// chains errors), reset MUST win — that's a hard teardown, not an
// orderly close. Same for local_close before io_timeout: if the read
// deadline fires AND our Close() also raced, attribute to local_close
// because that's the bucket that flags our own bug.
func TestClassifyWSReaderExitErr_OrderingInvariants(t *testing.T) {
	// reset wins over EOF.
	resetWithEOF := testErr("read tcp 10.0.0.1:443: wsarecv: An existing connection was forcibly closed by the remote host. (EOF)")
	require.Equal(t, wsExitReset, classifyWSReaderExitErr(resetWithEOF),
		"reset must take precedence over EOF — hard teardown is more informative than orderly close")

	// local_close wins over io_timeout.
	closeWithTimeout := testErr("read tcp 10.0.0.1:443: use of closed network connection (i/o timeout)")
	require.Equal(t, wsExitLocalClose, classifyWSReaderExitErr(closeWithTimeout),
		"local_close must take precedence over io_timeout — our own Close() bug must surface")
}

// TestWSReaderExitKind_String pins the label strings — they double as
// Prometheus kind= values. A typo here would silently rename the
// dashboard bucket and break alerting queries.
func TestWSReaderExitKind_String(t *testing.T) {
	require.Equal(t, "peer_eof", wsExitPeerEOF.String())
	require.Equal(t, "reset", wsExitReset.String())
	require.Equal(t, "io_timeout", wsExitIOTimeout.String())
	require.Equal(t, "local_close", wsExitLocalClose.String())
	require.Equal(t, "other", wsExitOther.String())
}

// testErr is a small helper for constructing error values from string
// literals without pulling in errors.New everywhere in this file.
type testErr string

func (e testErr) Error() string { return string(e) }

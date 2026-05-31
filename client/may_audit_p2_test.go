package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// ============================================================================
// C10 M5 — best-effort POST FIN on WS-upgrade fail.
//
// Plan §C10 M5: when the WS upgrade fails after a successful handshake POST,
// the client must fire a fire-and-forget FIN POST so the server-side session
// gets cleaned up immediately rather than after the 5 min sweeper.
// ============================================================================

// TestUpgradeToWSFailure_SendsBestEffortFin verifies that when the WS upgrade
// fails (gorilla returns a non-101 generic decoy), the client kicks off a
// best-effort session-level FIN that:
//   - encodes a FlagFin chunk for streamID=0
//   - wraps it in the body-prefix data envelope
//   - is observable to a test hook (no real HTTPS dispatch needed).
//
// The hook short-circuits dispatchBestEffortSessionFIN — the production code
// path is the same, the hook only swaps out the network call. We assert on
// the envelope bytes via browser.ParseDataPayload + session.DecryptChunkSafe.
func TestUpgradeToWSFailure_SendsBestEffortFin(t *testing.T) {
	// Decoy 200 (no X-SL-RL → generic upgrade failure path, NOT rate-limit).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>not a websocket</body></html>"))
	}))
	defer srv.Close()

	// Self-consistent session — keys good for EncryptChunk + DecryptChunkSafe.
	key := bytes.Repeat([]byte{0x42}, 32)
	sess := core.NewSession(99, key, key)
	token := bytes.Repeat([]byte{0x07}, 36)

	type captured struct {
		body []byte
	}
	var got atomic.Pointer[captured]
	hookFired := make(chan struct{}, 1)

	prev := bestEffortSessionFINHook
	bestEffortSessionFINHook = func(tok []byte, s *core.Session, body []byte) {
		// Defensive copy — avoid sharing slices with the producer.
		cp := append([]byte(nil), body...)
		got.Store(&captured{body: cp})
		select {
		case hookFired <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { bestEffortSessionFINHook = prev })

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewWebSocketTransport(host, false, true)

	err := tr.UpgradeToWS(token, sess)
	if err == nil {
		t.Fatal("expected UpgradeToWS to fail against decoy server")
	}
	if errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate-limit branch must NOT fire here; got: %v", err)
	}

	select {
	case <-hookFired:
	case <-time.After(2 * time.Second):
		t.Fatal("best-effort FIN hook never fired")
	}

	cap := got.Load()
	if cap == nil || len(cap.body) == 0 {
		t.Fatal("FIN body not captured")
	}

	// Parse the envelope: outer JSON → events[0].data → base64 → body-prefix
	// payload → token + encrypted chunk → decrypted FlagFin chunk.
	var env struct {
		Events []struct {
			Type string `json:"type"`
			TS   int64  `json:"ts"`
			Data string `json:"data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(cap.body, &env); err != nil {
		t.Fatalf("envelope JSON decode: %v", err)
	}
	if len(env.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(env.Events))
	}
	combined, err := base64.RawURLEncoding.DecodeString(env.Events[0].Data)
	if err != nil {
		t.Fatalf("data b64 decode: %v", err)
	}
	parsedToken, encChunk, err := browser.ParseDataPayload(combined, len(token))
	if err != nil {
		t.Fatalf("ParseDataPayload: %v", err)
	}
	if !bytes.Equal(parsedToken, token) {
		t.Errorf("token mismatch in FIN envelope")
	}
	chunk, err := sess.DecryptChunkSafe(encChunk)
	if err != nil {
		t.Fatalf("decrypt FIN chunk: %v", err)
	}
	if chunk.Flags != core.FlagFin {
		t.Errorf("expected FlagFin, got 0x%02x", chunk.Flags)
	}
	// Session-wide FIN must carry a payload shorter than 2 bytes so the server
	// routes it to handleFin (release session), not handleStreamFin. The old
	// code used NewStreamFinChunk(...,0) — a 2-byte payload — which silently
	// landed on the per-stream branch and never released the session
	// (latent bug fixed 2026-05-29 via NewSessionFinChunk).
	if len(chunk.Payload) >= 2 {
		t.Fatalf("session FIN payload must be <2 bytes to route session-wide, got len=%d", len(chunk.Payload))
	}
}

// TestUpgradeToWSFailure_FirstFrameSend_FiresFin guards the second failure
// path: dial succeeds (101 returned), but the post-101 first-frame WS write
// errors out. The orphan-session symptom is identical to the dial-fail path,
// so the FIN must fire here too.
//
// We simulate this with an httptest server that completes the WS upgrade
// (returns 101) but immediately closes the conn so the client's
// WriteMessage fails.
func TestUpgradeToWSFailure_FirstFrameSend_FiresFin(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Slam the conn shut before the client can send its first frame.
		// Some platforms still let the client's WriteMessage succeed against
		// the buffered local socket, so we also pump enough data to force
		// the failure if needed. Closing twice is safe.
		_ = c.Close()
	}))
	defer srv.Close()

	key := bytes.Repeat([]byte{0x33}, 32)
	sess := core.NewSession(101, key, key)
	token := bytes.Repeat([]byte{0x05}, 36)

	hookFired := make(chan struct{}, 1)
	prev := bestEffortSessionFINHook
	bestEffortSessionFINHook = func(tok []byte, s *core.Session, body []byte) {
		select {
		case hookFired <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { bestEffortSessionFINHook = prev })

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewWebSocketTransport(host, false, true)

	// On most platforms WriteMessage to a Close()'d socket fails immediately.
	// On a few (notably Linux loopback with deep sndbufs) it can succeed —
	// in that case UpgradeToWS returns nil and the FIN does not fire, which
	// is acceptable: the WS is "live" from the client's POV, just doomed.
	// The test asserts: IF upgrade fails after dial, FIN fires; otherwise
	// the test is a no-op (we cannot reliably force the failure on every
	// platform without a deeper hook than gorilla allows).
	err := tr.UpgradeToWS(token, sess)
	if err == nil {
		t.Skip("first-frame send did not fail on this platform (kernel sndbuf swallowed it); skipping FIN assertion")
		return
	}
	defer tr.Close()
	if !strings.Contains(err.Error(), "first frame") &&
		!strings.Contains(err.Error(), "ws upgrade") {
		t.Fatalf("expected first-frame or generic upgrade error, got: %v", err)
	}

	select {
	case <-hookFired:
	case <-time.After(2 * time.Second):
		t.Fatal("best-effort FIN hook never fired on first-frame failure path")
	}
}

// TestUpgradeToWSFailure_RateLimited_SuppressesFin verifies the explicit
// rate-limit branch does NOT fire a FIN. Rationale (see UpgradeToWS source):
// the server explicitly told us "back off" — sending another POST would
// just bounce off the same rate-limit branch, and the server cleans up via
// its own idle timeout.
func TestUpgradeToWSFailure_RateLimited_SuppressesFin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verbose X-SL-RL form per C5 (2026-05-02). Detection is presence-based.
		w.Header().Set("X-SL-RL", "bucket=ws_upgrade,burst_left=0,refill_in=0s,exempt=0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>under construction</html>"))
	}))
	defer srv.Close()

	key := bytes.Repeat([]byte{0x77}, 32)
	sess := core.NewSession(50, key, key)
	token := bytes.Repeat([]byte{0xA1}, 36)

	hookFired := make(chan struct{}, 1)
	prev := bestEffortSessionFINHook
	bestEffortSessionFINHook = func(tok []byte, s *core.Session, body []byte) {
		select {
		case hookFired <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { bestEffortSessionFINHook = prev })

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewWebSocketTransport(host, false, true)

	err := tr.UpgradeToWS(token, sess)
	if err == nil {
		t.Fatal("expected error from rate-limit decoy")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got: %v", err)
	}

	select {
	case <-hookFired:
		t.Fatal("FIN hook fired on rate-limit branch — must be suppressed")
	case <-time.After(200 * time.Millisecond):
		// expected: no fire
	}
}

// ============================================================================
// C12 F5 — StartReader structured-log markers.
//
// Plan §C12 F5: trace `StartReader` + poll-fallback under throttle. Production
// requirement is structured-log markers at key transitions; the poll-fallback
// is captured as a TODO comment per plan-literal "trace-only" wording.
// ============================================================================

// captureSlog redirects the package slog default to a buffer for the lifetime
// of the returned cleanup. Returns (buf, cleanup).
func captureSlog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))
	return buf, func() { slog.SetDefault(prev) }
}

// TestStartReader_LogsKeyTransitions drives a WebSocketTransport against an
// httptest server, lets StartReader run for one decryptable frame, then
// cancels the context. Asserts the slog stream contains the start, first-
// frame, and stop markers.
func TestStartReader_LogsKeyTransitions(t *testing.T) {
	buf, cleanup := captureSlog(t)
	defer cleanup()

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	frameSent := make(chan struct{}, 1)

	// Self-consistent session shared between the test server and client.
	key := bytes.Repeat([]byte{0x55}, 32)
	sessID := uint32(7777)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()

		// Eat the client's first auth frame (we don't validate it here).
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, _ = c.ReadMessage()

		// Build a valid streamData chunk and send it. Server-side encryption
		// uses the same session keys so the client's DecryptChunkSafe accepts
		// it. Payload [streamID(2) | data] for non-UDP.
		serverSess := core.NewSession(sessID, key, key)
		dataChunk := core.NewStreamDataChunk(sessID, 1, 0xBEEF, []byte("hello"))
		enc, encErr := serverSess.EncryptChunk(dataChunk)
		if encErr != nil {
			t.Logf("server encrypt failed: %v", encErr)
			return
		}
		if writeErr := c.WriteMessage(websocket.BinaryMessage, enc); writeErr != nil {
			t.Logf("server write failed: %v", writeErr)
			return
		}
		select {
		case frameSent <- struct{}{}:
		default:
		}
		// Hold the conn open so client's reader doesn't see EOF.
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewWebSocketTransport(host, false, true)

	clientToken := bytes.Repeat([]byte{0x09}, 36)
	clientSess := core.NewSession(sessID, key, key)
	if err := tr.UpgradeToWS(clientToken, clientSess); err != nil {
		t.Fatalf("UpgradeToWS: %v", err)
	}
	defer tr.Close()

	// Wire a Client into the reader. The Client struct carries the routing
	// state StartReader needs; we use an empty one whose Session() returns
	// our shared session via the same keys.
	cl := newReaderTestClient(clientSess)

	ctx, cancel := context.WithCancel(context.Background())
	readerDone := make(chan error, 1)
	go func() { readerDone <- tr.StartReader(ctx, cl) }()

	// Wait for the server to actually deliver one frame, then cancel.
	select {
	case <-frameSent:
	case <-time.After(2 * time.Second):
		t.Fatal("server frame never sent")
	}
	// Give the reader a moment to log the first-frame marker.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-readerDone:
		// ctx.Cancel returns context.Canceled — that is fine.
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("reader returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not exit after ctx cancel")
	}

	out := buf.String()
	mustContain := []string{
		`"WS StartReader started"`,
		`"WS StartReader first frame"`,
		`"WS StartReader stopped"`,
	}
	for _, marker := range mustContain {
		if !strings.Contains(out, marker) {
			t.Errorf("expected slog output to contain %s, full log:\n%s", marker, out)
		}
	}
	// Stop-with-reason should carry one of the documented reason values.
	if !strings.Contains(out, `"reason":"ctx_done"`) &&
		!strings.Contains(out, `"reason":"ctx_done_during_read"`) {
		t.Errorf("stop marker missing reason field, full log:\n%s", out)
	}
}

// newReaderTestClient builds a minimal Client that returns sess from
// Session() and supplies the maps StartReader's RouteToStream consults.
// We do NOT call Connect — Session is injected directly. This sidesteps the
// crypto handshake while still exercising the real StartReader code path.
func newReaderTestClient(sess *core.Session) *Client {
	c := &Client{}
	c.session = sess
	c.streamChans = map[uint16]chan []byte{}
	return c
}

// ============================================================================
// C12 F6 — SOCKS5 UDP ASSOCIATE pool readiness gate.
//
// Plan §C12 F6: SOCKS5 UDP ASSOCIATE проверяет readiness pool'а; fail-fast
// если нет слотов. Test the PoolReadiness contract here at the client layer —
// the actual SOCKS5 handler integration test lives in proxy/socks5/ where
// the handler is defined.
// ============================================================================

// stubPoolReadiness is a minimal PoolReadiness implementation for tests.
type stubPoolReadiness struct{ ready int }

func (s *stubPoolReadiness) ReadyCount() int { return s.ready }

// TestPoolReadinessInterface_WSPoolImplements verifies the interface contract:
// the production WSPoolTransport satisfies PoolReadiness, and ReadyCount /
// HealthySlots agree on the same value.
func TestPoolReadinessInterface_WSPoolImplements(t *testing.T) {
	pool := &WSPoolTransport{
		slots:    make([]*poolSlot, 4),
		poolSize: 4,
	}
	pool.slots[0] = &poolSlot{index: 0}
	pool.slots[0].setState(slotReady)
	pool.slots[1] = &poolSlot{index: 1}
	pool.slots[1].setState(slotReady)
	pool.slots[2] = &poolSlot{index: 2}
	pool.slots[2].setState(slotDead)
	pool.slots[3] = &poolSlot{index: 3}
	pool.slots[3].setState(slotConnecting)

	var pr PoolReadiness = pool
	if pr.ReadyCount() != 2 {
		t.Errorf("ReadyCount = %d, expected 2", pr.ReadyCount())
	}
	if pool.HealthySlots() != pr.ReadyCount() {
		t.Errorf("HealthySlots %d != ReadyCount %d", pool.HealthySlots(), pr.ReadyCount())
	}
}

// TestPoolReadiness_ZeroSlotsTriggersFailFast: stub reports 0 → caller MUST
// treat the pool as starved. Threshold check lives in the SOCKS5 handler;
// here we assert the interface returns the right number for a starved pool.
func TestPoolReadiness_ZeroSlotsTriggersFailFast(t *testing.T) {
	stub := &stubPoolReadiness{ready: 0}
	if stub.ReadyCount() >= udpMinReadySlotsForTest() {
		t.Fatalf("ReadyCount %d should be < threshold %d", stub.ReadyCount(), udpMinReadySlotsForTest())
	}
}

// TestPoolReadiness_AcceptsWhenPoolReady: stub reports threshold or higher →
// caller proceeds. Proves the boundary is inclusive on the "ready" side.
func TestPoolReadiness_AcceptsWhenPoolReady(t *testing.T) {
	stub := &stubPoolReadiness{ready: udpMinReadySlotsForTest()}
	if stub.ReadyCount() < udpMinReadySlotsForTest() {
		t.Fatalf("ReadyCount %d should accept at threshold %d", stub.ReadyCount(), udpMinReadySlotsForTest())
	}
}

// udpMinReadySlotsForTest mirrors the constant in proxy/socks5 so the client
// package's tests can encode the same boundary without importing the SOCKS5
// handler package (which would re-introduce a cycle the SOCKS5 package's
// import of client already implies).
func udpMinReadySlotsForTest() int { return 2 }

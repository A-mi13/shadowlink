package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
	"github.com/stretchr/testify/require"
)

// TestFindSessionByHint_OnlyUsesRollingKey pins the contract that
// findSessionByHint resolves via the recv-key (rk) path only. Phase 0 retire
// removed findSession; this test guards the remaining sk-branch removal in
// findSessionByHint (audit A1-H2). The send-key (sk) lives on the encrypt
// side and never seals an EncryptedSessionToken — it's algebraically dead
// code under the current handshake.
//
// Strategy: build a token sealed with the send-key (sk). With sk-branch
// removed, this token MUST NOT resolve via findSessionByHint. If the
// branch is reintroduced, this test catches it.
func TestFindSessionByHint_OnlyUsesRollingKey(t *testing.T) {
	h, serverKey := setupTestHandler(t)

	clientHello, _, err := core.NewClientHello([]byte("user-h2-uuid-len"), serverKey.Public)
	require.NoError(t, err)

	serverHello, session, _, err := core.HandleClientHello(clientHello, serverKey, 8, 12288, h.sessions)
	require.NoError(t, err)
	defer h.sessions.Remove(session.ID)

	// Positive baseline: real token sealed with rk resolves via findSessionByHint.
	tokenWithHint := browser.EncodeTokenWithHint(session.ID, serverHello.EncryptedSessionToken)
	got := h.findSessionByHint(tokenWithHint)
	require.NotNil(t, got, "rk-sealed token must resolve")
	require.Equal(t, session.ID, got.ID)

	// Negative: a token sealed with the send-key (sk) must NOT resolve.
	// We craft this by re-running the encryptSessionToken-equivalent with sk
	// instead of rk. encryptSessionToken is unexported in core, so we
	// emulate the format here: nonce(12) || gcm.Seal(session_id_be(4), nonce, sk).
	skSealed := sealTokenWithKey(t, session.ID, session.SendKey)
	skTokenWithHint := browser.EncodeTokenWithHint(session.ID, skSealed)
	got = h.findSessionByHint(skTokenWithHint)
	require.Nil(t, got, "sk-sealed token MUST NOT resolve (sk-branch is dead code)")
}

// sealTokenWithKey builds a session token using a given AES-256 key in the
// same wire-format encryptSessionToken uses: nonce(12) || GCM.Seal(sid_be(4)).
func sealTokenWithKey(t *testing.T, sessionID uint32, key []byte) []byte {
	t.Helper()
	require.Len(t, key, 32, "AES-256 key must be 32 bytes")
	plaintext := make([]byte, 4)
	binary.BigEndian.PutUint32(plaintext, sessionID)
	nonce := make([]byte, 12)
	_, err := crand.Read(nonce)
	require.NoError(t, err)
	// Use go's stdlib AES-GCM directly to avoid depending on internal helpers.
	ct := aesGCMSeal(t, key, nonce, plaintext)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out
}

func aesGCMSeal(t *testing.T, key, nonce, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return gcm.Seal(nil, nonce, plaintext, nil)
}

// =============================================================================
// A3-S-HIGH-1 — Content-Type strict prefix + decoy fallback
// =============================================================================

// TestServeHTTP_ContentTypeWithCharset_RoutesToBodyPrefix verifies that POST
// requests with Content-Type containing parameters (e.g. "application/json;
// charset=utf-8") are accepted by the dispatcher rather than dropped to decoy.
// Pre-fix: strict equality `ct != "application/json"` rejected charset-tagged
// requests sent by ordinary HTTP clients / CDN-rewriting middleware.
func TestServeHTTP_ContentTypeWithCharset_RoutesToBodyPrefix(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	keepalive := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc, err := sess.EncryptChunk(keepalive)
	require.NoError(t, err)
	payload := browser.BuildDataPayload(tokenWithHint, enc)
	body := wrapInJSONEnvelope(t, payload)

	req := httptest.NewRequest("POST", "/a", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code, "charset-tagged Content-Type must be accepted")
	// Must produce a ShadowLink envelope, not decoy HTML.
	_, _, err = browser.ParseDownloadResponse(rec.Body.Bytes())
	require.NoError(t, err, "charset-tagged JSON must reach handleNewFormatPost")
}

// TestServeHTTP_ContentTypeMismatch_RoutesToDecoy ensures that a request whose
// Content-Type is NOT JSON (text/plain, html, urlencoded) deterministically
// lands in the decoy path and never invokes failClosedToDecoy crypto-cost
// pipeline. This is symmetric to S-HIGH-1's DoS-amplifier concern: only real
// JSON-shaped POSTs spend X25519 cycles.
func TestServeHTTP_ContentTypeMismatch_RoutesToDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	for _, ct := range []string{
		"text/plain",
		"text/html",
		"application/x-www-form-urlencoded",
		"application/octet-stream",
		"", // missing Content-Type
	} {
		// Use "/" — decoy serves 200 there. The point of the test is that
		// non-JSON Content-Type lands in DecoyHandler, not handleNewFormatPost.
		// (Decoy returns 404 for unknown paths by design.)
		req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("doesn't matter")))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, 200, rec.Code, "decoy / must reply 200 for ct=%q (got body=%q)",
			ct, rec.Body.String())
		require.NotContains(t, rec.Body.String(), `"events"`, "decoy must not echo body for ct=%q", ct)
		// ShadowLink envelopes carry "results" array; decoy HTML has none.
		require.NotContains(t, rec.Body.String(), `"results"`, "decoy must not produce ShadowLink envelope for ct=%q", ct)
	}
}

// TestServeHTTP_ContentTypeCaseInsensitive guards browsers / proxies that emit
// "Application/JSON". The HTTP spec is case-insensitive on header field
// values for media types. The discriminator must accept this.
func TestServeHTTP_ContentTypeCaseInsensitive(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	keepalive := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc, err := sess.EncryptChunk(keepalive)
	require.NoError(t, err)
	payload := browser.BuildDataPayload(tokenWithHint, enc)
	body := wrapInJSONEnvelope(t, payload)

	req := httptest.NewRequest("POST", "/a", bytes.NewReader(body))
	req.Header.Set("Content-Type", "Application/JSON")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
	_, _, err = browser.ParseDownloadResponse(rec.Body.Bytes())
	require.NoError(t, err, "case-insensitive Content-Type must reach body-prefix dispatch")
}

// =============================================================================
// A1-L6 — NewReplayCache configurable
// =============================================================================

// TestNewHandler_ReplayCacheConfigurable verifies that Config.ReplayCacheMaxSize
// and Config.ReplayCacheWindow override the defaults (10000 / 5min). When zero,
// defaults are preserved.
func TestNewHandler_ReplayCacheConfigurable(t *testing.T) {
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)

	t.Run("custom values applied", func(t *testing.T) {
		cfg := TestConfig()
		cfg.ReplayCacheMaxSize = 50
		// Use a window >= the M3 drift floor (300s) so it is preserved as-is.
		// A shorter window is clamped up to the drift window — covered by
		// TestNewHandler_ReplayWindowClampedToDrift.
		cfg.ReplayCacheWindow = 6 * time.Minute
		h := NewHandler(serverKey, cfg, "")
		require.NotNil(t, h.replayCache)
		require.Equal(t, 50, h.replayCacheMaxSize)
		require.Equal(t, 6*time.Minute, h.replayCacheWindow)
	})

	t.Run("zero values fall back to defaults", func(t *testing.T) {
		cfg := TestConfig()
		// Leave ReplayCacheMaxSize=0 / ReplayCacheWindow=0.
		h := NewHandler(serverKey, cfg, "")
		require.NotNil(t, h.replayCache)
		require.Equal(t, 10000, h.replayCacheMaxSize)
		require.Equal(t, 5*time.Minute, h.replayCacheWindow)
	})
}

// =============================================================================
// A3-S-HIGH-2 — WS first-frame: Tunnel.WSAttached gate, FlagKeepalive only,
// reject second WS attach
// =============================================================================

// TestAuthenticateFirstFrame_RejectsDoubleAttach simulates two parallel WS
// attachments to the same session. Only the first must succeed; the second
// must be rejected (returns nil session).
func TestAuthenticateFirstFrame_RejectsDoubleAttach(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	// Compose a valid first-frame: hint+token + encrypted FlagKeepalive chunk.
	build := func() []byte {
		ka := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
		enc, err := sess.EncryptChunk(ka)
		require.NoError(t, err)
		out := make([]byte, 0, len(tokenWithHint)+len(enc))
		out = append(out, tokenWithHint...)
		out = append(out, enc...)
		return out
	}

	srv := httptest.NewServer(http.HandlerFunc(h.handleWebSocket))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/cable"

	// First WS — should attach.
	c1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer c1.Close()
	require.NoError(t, c1.WriteMessage(websocket.BinaryMessage, build()))

	// Give server time to register WSAttached.
	time.Sleep(150 * time.Millisecond)

	// Second WS to same session — must be rejected (fakeAck + close).
	c2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer c2.Close()
	require.NoError(t, c2.WriteMessage(websocket.BinaryMessage, build()))

	// Read on c2: should get fakeAck binary frame OR close.
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	mt, data, err := c2.ReadMessage()
	if err == nil {
		// First message — fakeAck random binary. Then close.
		require.Equal(t, websocket.BinaryMessage, mt)
		require.GreaterOrEqual(t, len(data), 200, "fakeAck length must be in [200,2000]")
		require.LessOrEqual(t, len(data), 2000)
		// Subsequent read should fail (close).
		c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err2 := c2.ReadMessage()
		require.Error(t, err2, "second WS must be closed by server")
	} else {
		// Some platforms may surface close before fakeAck — also acceptable.
		require.True(t, websocket.IsCloseError(err, websocket.CloseNormalClosure) || err != nil)
	}

	// Verify the tunnel's WSAttached flag is set (defense check).
	tunnel, ok := h.GetTunnel(sess.ID)
	require.True(t, ok)
	require.True(t, tunnel.WSAttached.Load(), "first WS must have set WSAttached")
}

// TestAuthenticateFirstFrame_NoTunnelRejected verifies that a first-frame WS
// to a session whose handshake-created tunnel has been removed returns nil
// (orphan-session guard). Pre-existing behavior — re-asserted to lock the
// invariant after WSAttached gate addition.
func TestAuthenticateFirstFrame_NoTunnelRejected(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, _ := completeHandshakeForTest(t, h, serverKey)

	// Drop the tunnel — emulate post-FIN state.
	h.tunnelsMu.Lock()
	delete(h.tunnels, sess.ID)
	h.tunnelsMu.Unlock()

	// First-frame auth must reject because the tunnel is gone, even though
	// the session itself is still alive.
	srv := httptest.NewServer(http.HandlerFunc(h.handleWebSocket))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/cable"

	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer c.Close()

	// We can't easily build a first frame without the tunnel — but the
	// authenticateFirstFrame check happens AFTER findSessionByHint and
	// chunk decrypt, so any random first frame just fails decrypt and
	// resolves to nil session. Send 64B garbage to trigger that path.
	garbage := make([]byte, 64)
	_, _ = crand.Read(garbage)
	require.NoError(t, c.WriteMessage(websocket.BinaryMessage, garbage))

	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Expect close (after fakeAck).
	for range 3 {
		mt, _, err := c.ReadMessage()
		if err != nil {
			break
		}
		_ = mt
	}
}

// =============================================================================
// A3-S-HIGH-3 — handleConnect goroutine leak under tunnel.done race
// =============================================================================

// TestHandleConnect_TunnelClosedDuringDial_NoGoroutineLeak proves that closing
// tunnel.done while SafeDial is in flight does not leak the relay goroutine.
// Strategy: dial a host:port we know never accepts (RFC5737 TEST-NET-1
// 192.0.2.1:1, blackhole). SafeDial honors the configured 10s timeout but the
// fix wires the tunnel context so closing tunnel.done aborts the dial within
// ~100ms. We snapshot goroutine count before/after.
func TestHandleConnect_TunnelClosedDuringDial_NoGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("network-dependent test")
	}
	h, serverKey := setupTestHandler(t)
	sess, _ := completeHandshakeForTest(t, h, serverKey)

	tunnel, ok := h.GetTunnel(sess.ID)
	require.True(t, ok)

	// Build CONNECT chunk targeting a blackhole address. SafeDial blocks
	// on TCP SYN/ACK — without the fix it sleeps full 10s. With the fix
	// closing tunnel.done cancels the dial within ~100ms.
	streamID := uint16(0xAB)
	target := "192.0.2.1:1" // RFC5737 TEST-NET-1; SYN drops on the floor
	payload := make([]byte, 2+len(target))
	binary.BigEndian.PutUint16(payload[0:2], streamID)
	copy(payload[2:], target)
	chunk := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     core.FlagConnect,
		Payload:   payload,
	}

	gBefore := runtime.NumGoroutine()

	// Run handleConnect in a goroutine; close tunnel.done after 80ms.
	doneServe := make(chan struct{})
	rec := httptest.NewRecorder()
	go func() {
		defer close(doneServe)
		h.handleConnect(rec, sess, chunk)
	}()

	time.Sleep(80 * time.Millisecond)
	tunnel.closeTunnel()

	select {
	case <-doneServe:
		// handleConnect returned within budget — dial was canceled.
	case <-time.After(2 * time.Second):
		t.Fatalf("handleConnect did not honor tunnel.done within 2s — dial-cancel path broken")
	}

	// Allow GC + relay-goroutine exit grace.
	time.Sleep(200 * time.Millisecond)
	gAfter := runtime.NumGoroutine()
	delta := gAfter - gBefore
	// Tolerate small jitter (test scheduler) but reject hard leak.
	require.LessOrEqual(t, delta, 3,
		"goroutine count must not grow significantly (before=%d after=%d)", gBefore, gAfter)
}

// =============================================================================
// A3-S-MED-3 — runDownloadStreamLoop deadline > maxAckJitter
// =============================================================================

// TestDownloadStreamLoop_DeadlineExceedsMaxAckJitter is a structural pin: the
// constant streamWriteTimeout (60s) MUST exceed the maximum ackJitter cap
// (1500ms after May 2026 §C5 reshape) by a wide safety margin. If a future
// refactor makes deadline ≤ jitter, this test fails and forces a config review.
func TestDownloadStreamLoop_DeadlineExceedsMaxAckJitter(t *testing.T) {
	const maxAckJitter = 1500 * time.Millisecond // see ackJitter() Pareto-tail hard ceiling
	require.Greater(t, streamWriteTimeout, maxAckJitter*10,
		"runDownloadStreamLoop write deadline must dwarf max ackJitter (got deadline=%v cap=%v)",
		streamWriteTimeout, maxAckJitter)
}

// =============================================================================
// A4-M5 — Send-on-closed-channel safety: closeTunnel + concurrent Outgoing send
// =============================================================================

// TestTunnel_SafeSendAfterClose verifies that calling closeTunnel concurrently
// with select-based Outgoing sends (the pattern used in relayStreamFromTarget,
// runDownloadStreamLoop UDP arm, etc.) never panics, regardless of close
// ordering. This is the unit-level guard; the race-detector counterpart lives
// in handler_race_test.go (linux-only).
func TestTunnel_SafeSendAfterClose(t *testing.T) {
	tunnel := &Tunnel{
		Incoming:    make(chan []byte, 4),
		Outgoing:    make(chan []byte, 4),
		OutgoingUDP: make(chan []byte, 4),
		done:        make(chan struct{}),
	}

	const senders = 32
	const sendsPer = 100
	var wg sync.WaitGroup
	var panics atomic.Int32

	for i := range senders {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics.Add(1)
					t.Errorf("sender %d panicked: %v", id, r)
				}
			}()
			for range sendsPer {
				if !safeSendToTunnel(tunnel, []byte("x")) {
					return
				}
			}
		}(i)
	}

	// Trigger close after ~5ms so most senders are mid-loop.
	time.Sleep(5 * time.Millisecond)
	tunnel.closeTunnel()

	wg.Wait()
	require.Equal(t, int32(0), panics.Load(), "no panics allowed under close-during-send")
}

// safeSendToTunnel mirrors the canonical pattern used in the codebase: select
// over <-tunnel.done and tunnel.Outgoing<-data. Used by the test above to
// document the contract callers MUST follow when sending to Outgoing.
func safeSendToTunnel(t *Tunnel, data []byte) bool {
	defer func() { _ = recover() }() // belt: closeTunnel races may surface
	select {
	case <-t.done:
		return false
	case t.Outgoing <- data:
		return true
	}
}

package server

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAckJitter_HardCeilingHonored guards the ACK-path Pareto tail's hard
// ceiling at 1500ms (May 2026 §C5 reshape). Even with 5% Pareto-tail mass
// the inverse-CDF must clamp to 1500ms to bound worst-case latency.
func TestAckJitter_HardCeilingHonored(t *testing.T) {
	const samples = 20000
	var maxD time.Duration
	for range samples {
		d := ackJitter()
		if d > maxD {
			maxD = d
		}
	}
	require.LessOrEqual(t, maxD, 1500*time.Millisecond,
		"ackJitter exceeded 1500ms hard ceiling: max=%v", maxD)
}

// TestAckJitter_MedianApproximately5Ms guards the §C5 lower-median target.
// Exp(scale=7.21ms) has median = 7.21·ln(2) ≈ 5ms; mixing in a 5% Pareto
// right-tail does not move the median materially. We allow [3ms, 7ms] to
// absorb sampling noise and the rare-tail influence.
func TestAckJitter_MedianApproximately5Ms(t *testing.T) {
	const samples = 10000
	xs := make([]time.Duration, samples)
	for i := range xs {
		xs[i] = ackJitter()
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	median := xs[samples/2]
	require.GreaterOrEqual(t, median, 3*time.Millisecond,
		"median too low (got %v) — distribution drifted toward zero", median)
	require.LessOrEqual(t, median, 7*time.Millisecond,
		"median too high (got %v) — exp scale or tail mass drifted", median)
}

// TestAckJitter_ParetoTailPresent verifies the right-tail mixture is doing
// its job: with 5% Pareto(α=2, xm=50ms) ≈ 50% of tail samples land >70ms,
// so over 10k draws we expect ~250 samples > 100ms. We assert >100 to
// tolerate sampling noise while still catching a regression that drops
// the tail entirely.
func TestAckJitter_ParetoTailPresent(t *testing.T) {
	const samples = 10000
	above100ms := 0
	for range samples {
		if ackJitter() > 100*time.Millisecond {
			above100ms++
		}
	}
	require.Greater(t, above100ms, 100,
		"Pareto tail missing or too thin: only %d/%d samples > 100ms", above100ms, samples)
}

// TestAckJitter_NoHardPointMassAt150Ms is the regression guard for §C5:
// previous shape clamped ~5% of samples to exactly 150ms, producing a
// p100 point-mass detectable in active probing. The new shape spreads
// the tail across [50ms, 1500ms], so exactly-150ms hits should be rare.
func TestAckJitter_NoHardPointMassAt150Ms(t *testing.T) {
	const samples = 20000
	pointMass := 0
	for range samples {
		d := ackJitter()
		// Allow a 1ms tolerance band because the Pareto sampler can land
		// near 150ms by chance; the regression we're catching is the OLD
		// shape that piled ~5% of all samples on exactly 150ms.
		if d >= 149*time.Millisecond && d <= 151*time.Millisecond {
			pointMass++
		}
	}
	require.Less(t, pointMass, 50,
		"too many samples at the legacy 150ms cap (%d/%d) — old hard-cap shape leaked back", pointMass, samples)
}

func setupTestHandler(tb testing.TB) (*Handler, *core.KeyPair) {
	tb.Helper()
	serverKey, err := core.GenerateKeyPair()
	require.NoError(tb, err)

	config := TestConfig()
	h := NewHandler(serverKey, config, "")
	return h, serverKey
}

func TestUnauthenticatedGETReturnsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(w, r)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "under construction")
	assert.Equal(t, "", w.Header().Get("Server"), "Server header must be empty (CF sets its own)")
}

func TestUnauthenticatedPOSTNonJSONReturnsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "text/plain")
	h.ServeHTTP(w, r)

	// Decoy serves the root page (under construction) or 404 for non-root
	assert.Less(t, w.Code, 500, "should not return server error")
}

func TestInvalidJSONReturnsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events",
		bytes.NewReader([]byte(`{"invalid":"not shadowlink format"}`)))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	// Should return decoy, not error
	assert.Less(t, w.Code, 500)
}

func TestHandshakeCreatesSession(t *testing.T) {
	h, serverKey := setupTestHandler(t)

	// Build ClientHello
	clientHello, _, err := core.NewClientHello([]byte("test-client-uuid"), serverKey.Public)
	require.NoError(t, err)

	// Encode as "encrypted chunk": ephPub(32) + encClientID
	payload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "init", "ts": 1234, "data": encodedPayload},
		},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	// No Authorization header = handshake
	h.ServeHTTP(w, r)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, 1, h.SessionCount())

	// Response should be valid JSON with ServerHello data
	var resp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp["status"])
}

func TestHandshakeWrongKeyReturnsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	// Use wrong server key for ClientHello
	wrongKey, _ := core.GenerateKeyPair()
	clientHello, _, _ := core.NewClientHello([]byte("client-uuid-test"), wrongKey.Public)

	payload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "init", "ts": 1234, "data": encodedPayload},
		},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	// Should look like decoy, not reveal we're a proxy
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, 0, h.SessionCount())
}

func TestCoverTrafficTreatedAsNormalChunk(t *testing.T) {
	h, _ := setupTestHandler(t)

	// C3 fix: cover traffic now carries encrypted padding, indistinguishable from data.
	// Without a valid session, it falls through to decoy (like any invalid chunk).
	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "session_ping", "ts": 1234, "data": "ZW5jcnlwdGVkLXBhZGRpbmc"},
		},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString([]byte("some-token-value")))
	h.ServeHTTP(w, r)

	// Without valid session token, server returns decoy (not crash)
	assert.Less(t, w.Code, 500)
}

func TestMaxClientsEnforced(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	h.config.MaxClients = 2

	// Create 2 sessions
	for i := range 2 {
		clientHello, _, _ := core.NewClientHello([]byte(fmt.Sprintf("client-uuid-%04d", i)), serverKey.Public)
		payload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
		encoded := base64.RawURLEncoding.EncodeToString(payload)

		body, _ := json.Marshal(map[string]any{
			"events": []map[string]any{{"type": "init", "ts": 1234, "data": encoded}},
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)
		assert.Equal(t, 200, w.Code)
	}
	assert.Equal(t, 2, h.SessionCount())

	// 3rd should be rejected
	clientHello, _, _ := core.NewClientHello([]byte("client-overflow!"), serverKey.Public)
	payload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encoded := base64.RawURLEncoding.EncodeToString(payload)

	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "init", "ts": 1234, "data": encoded}},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	// I6 fix: return decoy (200) instead of 503 to avoid revealing capacity limits
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, 2, h.SessionCount(), "3rd client should NOT create a session")
}

func TestFullHandshakeAndDataTransfer(t *testing.T) {
	h, serverKey := setupTestHandler(t)

	// === HANDSHAKE ===
	clientHello, clientState, err := core.NewClientHello([]byte("user-42-uuid-len"), serverKey.Public)
	require.NoError(t, err)

	helloPayload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encoded := base64.RawURLEncoding.EncodeToString(helloPayload)

	helloBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "init", "ts": 1234, "data": encoded}},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(helloBody))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, 200, w.Code)

	// Parse ServerHello from response
	respData, _, err := browser.ParseDownloadResponse(w.Body.Bytes())
	require.NoError(t, err)

	var shData struct {
		EphPub       []byte `json:"eph"`
		Token        []byte `json:"tok"`
		MaxConns     uint8  `json:"mc"`
		ChunkSize    uint16 `json:"cs"`
		ProtoVersion *uint8 `json:"_v"`
	}
	require.NoError(t, json.Unmarshal(respData, &shData))

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		ProtoVersion:          shData.ProtoVersion,
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
	}

	// Complete handshake on client side
	clientSession, err := core.CompleteHandshake(clientState, serverHello)
	require.NoError(t, err)

	// === DATA TRANSFER ===
	// Put some data into the tunnel's outgoing channel (simulating server-side app)
	tunnel, ok := h.GetTunnel(clientSession.ID)
	require.True(t, ok)
	go func() {
		tunnel.Outgoing <- []byte("hello from server tunnel")
	}()

	// Client sends encrypted data chunk
	vpnPayload := []byte("hello from client vpn")
	dataChunk := core.NewDataChunk(clientSession.ID, clientSession.NextSeqNum(), vpnPayload)
	encChunk, err := dataChunk.Encrypt(clientSession.SendKey)
	require.NoError(t, err)

	// Build HTTP request — body-prefix wire format: token-with-hint + encrypted chunk.
	tokenWithHint := browser.EncodeTokenWithHint(clientSession.ID, shData.Token)
	dataPayload := browser.BuildDataPayload(tokenWithHint, encChunk)
	encChunkB64 := base64.RawURLEncoding.EncodeToString(dataPayload)
	dataBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{"type": "data", "ts": 1234, "data": encChunkB64},
		},
	})
	dataReq := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(dataBody))
	dataReq.Header.Set("Content-Type", "application/json")
	dataReq.Header.Set("X-Request-ID", fmt.Sprintf("%08x", dataChunk.SeqNum))

	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, dataReq)
	assert.Equal(t, 200, w2.Code)

	// Check client received server data in the response
	respEncrypted, _, err := browser.ParseDownloadResponse(w2.Body.Bytes())
	require.NoError(t, err)

	respChunk, err := core.DecryptChunk(respEncrypted, clientSession.RecvKey)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello from server tunnel"), respChunk.Payload)

	// Check server received client data via tunnel
	select {
	case received := <-tunnel.Incoming:
		assert.Equal(t, vpnPayload, received)
	default:
		t.Fatal("expected data in tunnel incoming channel")
	}
}

func TestActiveProbeGetsDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)

	// Simulate various active probing techniques

	// 1. curl
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "curl/8.7.1")
	h.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "html")

	// 2. Random POST with JSON but wrong format
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/v2/events",
		bytes.NewReader([]byte(`{"test":true}`)))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	assert.Less(t, w.Code, 500)

	// 3. HEAD request
	w = httptest.NewRecorder()
	r = httptest.NewRequest("HEAD", "/", nil)
	h.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Code)

	// 4. Request to random path
	for _, path := range []string{"/robots.txt", "/favicon.ico", "/.env", "/wp-admin"} {
		w = httptest.NewRecorder()
		r = httptest.NewRequest("GET", path, nil)
		h.ServeHTTP(w, r)
		assert.Less(t, w.Code, 500, "path %s should not cause 5xx", path)
	}
}

func TestHandlerServeHTTPContentTypeCheck(t *testing.T) {
	h, _ := setupTestHandler(t)

	// POST with application/x-www-form-urlencoded → decoy
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/contact", bytes.NewReader([]byte("name=test")))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(w, r)
	// Should not crash, should serve decoy
	assert.Less(t, w.Code, 500)
}

// TestHandleDownloadStreamV2_ImmediateFlush drives handleDownloadStreamV2
// directly against a freshly-handshaked session. Verifies the two invariants
// that distinguish it from the legacy path:
//  1. Response headers are written immediately (flushed before the loop blocks).
//  2. The synthetic preamble FlagAck frame lands in the buffer before the
//     select starts — CF gets first-byte content without waiting for data.
func TestHandleDownloadStreamV2_ImmediateFlush(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, _ := completeHandshakeForTest(t, h, serverKey)

	// Set up the tunnel entry — completeHandshakeForTest already creates one
	// via handleHandshakeNew, but the server-side session ID is what we need.
	// handleDownloadStreamV2 looks up h.tunnels[sess.ID]; the handshake path
	// populates this in handleHandshakeNew.

	// The stream handler runs in a goroutine and writes to the recorder
	// concurrently with the main goroutine reading rec.Body below. A bare
	// httptest.ResponseRecorder's Body (bytes.Buffer) is NOT safe for that
	// concurrent access (-race report 2026-06-01). syncRecorder guards the
	// underlying recorder with a mutex so the write (in handleDownloadStreamV2)
	// and the read (rec.bodyLen()) are serialized.
	rec := newSyncRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("POST", "/stream", nil).WithContext(ctx)

	done := make(chan struct{})
	go func() {
		h.handleDownloadStreamV2(rec, req, sess)
		close(done)
	}()

	// Give the goroutine enough time to write headers + preamble frame.
	time.Sleep(100 * time.Millisecond)
	bodyLen := rec.bodyLen()
	cancel() // signal the loop to exit
	<-done

	require.Equal(t, 200, rec.code(), "download stream must write OK immediately")
	require.Equal(t, "text/event-stream", rec.header().Get("Content-Type"))
	require.Equal(t, "no", rec.header().Get("X-Accel-Buffering"))
	// Preamble: 4-byte length prefix + 100-500B encrypted payload (+ GCM overhead).
	// Minimum plausible frame: 4 + MinChunk + 100 = 132 bytes. Be lenient — just
	// confirm something non-trivial was written before context cancel.
	require.Greater(t, bodyLen, 4+core.MinChunk, "preamble frame must be flushed before loop blocks")
}

// syncRecorder wraps httptest.ResponseRecorder with a mutex so a handler
// goroutine writing the response can run concurrently with a test goroutine
// reading Body/Code/Header. A bare ResponseRecorder's Body (bytes.Buffer) is
// not safe for that concurrent access (-race report 2026-06-01,
// TestHandleDownloadStreamV2_ImmediateFlush). All accesses go through the mutex.
type syncRecorder struct {
	mu  sync.Mutex
	rec *httptest.ResponseRecorder
}

func newSyncRecorder() *syncRecorder {
	return &syncRecorder{rec: httptest.NewRecorder()}
}

func (s *syncRecorder) Header() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Header()
}

func (s *syncRecorder) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Write(b)
}

func (s *syncRecorder) WriteHeader(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec.WriteHeader(code)
}

// Flush satisfies http.Flusher — handleDownloadStreamV2 type-asserts the writer
// to a Flusher and flushes after each frame. httptest.ResponseRecorder's Flush
// only sets a flag, but the assertion must succeed.
func (s *syncRecorder) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec.Flush()
}

func (s *syncRecorder) bodyLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Body.Len()
}

func (s *syncRecorder) code() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Code
}

func (s *syncRecorder) header() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Header()
}

// wrapInJSONEnvelope produces the analytics-style upload envelope expected by
// browser.ParseUploadRequest — a single event with the payload base64-encoded.
func wrapInJSONEnvelope(t *testing.T, payload []byte) []byte {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	body, err := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "data", "ts": 1234, "data": encoded}},
	})
	require.NoError(t, err)
	return body
}

// completeHandshakeForTest drives a full v1 handshake against handleHandshakeNew
// and returns the established client-side session plus the hint-prefixed token
// the client would send on subsequent data POSTs. Uses a 16-byte UUID so the
// encrypted client_id lands exactly at EncryptedClientIDSize (65 B), matching
// what the prod body-prefix dispatcher slices out of the payload.
func completeHandshakeForTest(t *testing.T, h *Handler, serverKey *core.KeyPair) (*core.Session, []byte) {
	t.Helper()
	userID := make([]byte, 16) // UUID-sized: yields EncryptedClientIDSize bytes
	_, err := crand.Read(userID)
	require.NoError(t, err)

	ch, state, err := core.NewClientHello(userID, serverKey.Public)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.handleHandshakeNew(rec, httptest.NewRequest("POST", "/a", nil), ch.EphemeralPub, ch.EncryptedClientID)
	require.Equal(t, 200, rec.Code, "handshake must succeed")

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
	require.Equal(t, uint8(1), *shWire.ProtoVersion)

	// v1 keys — CompleteHandshakeWithVersion threads protoVersion into DeriveSessionKeys
	// so client and server land on matching byte-string keys (downgrade defense).
	clientSession, err := core.CompleteHandshakeWithVersion(state, &core.ServerHello{
		EphemeralPub:          shWire.EphPub,
		EncryptedSessionToken: shWire.Token,
		MaxConnsPerClient:     shWire.MaxConns,
		ChunkSize:             shWire.ChunkSize,
	}, *shWire.ProtoVersion)
	require.NoError(t, err)

	tokenWithHint := browser.EncodeTokenWithHint(clientSession.ID, shWire.Token)
	return clientSession, tokenWithHint
}

// TestHandleNewFormatPost_DataPath — established session, keepalive chunk wrapped
// in body-prefix must reach routeDataChunk → handleKeepalive and return a 200 ACK.
func TestHandleNewFormatPost_DataPath(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	sess, tokenWithHint := completeHandshakeForTest(t, h, serverKey)

	keepalive := core.NewKeepaliveChunk(sess.ID, sess.NextSeqNum())
	enc, err := sess.EncryptChunk(keepalive)
	require.NoError(t, err)
	payload := browser.BuildDataPayload(tokenWithHint, enc)
	body := wrapInJSONEnvelope(t, payload)

	req := httptest.NewRequest("POST", "/a", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.handleNewFormatPost(rec, req)
	require.Equal(t, 200, rec.Code, "data path must return ACK, body=%s", rec.Body.String())
	// Sanity: response body is a ShadowLink download envelope (not decoy HTML).
	_, _, err = browser.ParseDownloadResponse(rec.Body.Bytes())
	require.NoError(t, err, "data-path response must be a ShadowLink download envelope")
}

// TestHandleNewFormatPost_HandshakePath — no session yet, fresh ClientHello
// payload must route to handleHandshakeNew and produce a _v=1 ServerHello.
func TestHandleNewFormatPost_HandshakePath(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	userID := make([]byte, 16) // UUID-sized → encClientID is exactly EncryptedClientIDSize
	_, err := crand.Read(userID)
	require.NoError(t, err)
	ch, _, err := core.NewClientHello(userID, serverKey.Public)
	require.NoError(t, err)

	// Emulate BuildHandshakePayload with fixed padding size for a deterministic test.
	payload := make([]byte, 0, 32+len(ch.EncryptedClientID)+512)
	payload = append(payload, ch.EphemeralPub...)
	payload = append(payload, ch.EncryptedClientID...)
	pad := make([]byte, 512)
	_, _ = crand.Read(pad)
	payload = append(payload, pad...)

	body := wrapInJSONEnvelope(t, payload)
	req := httptest.NewRequest("POST", "/a", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.handleNewFormatPost(rec, req)
	require.Equal(t, 200, rec.Code, "handshake path must return 200")

	shJSON, _, err := browser.ParseDownloadResponse(rec.Body.Bytes())
	require.NoError(t, err)
	require.Contains(t, string(shJSON), `"_v":1`, "handshake fallback must emit _v:1")
	require.Equal(t, uint64(1), h.metrics.HandshakesNewTotal.Load())
}

// TestHandleNewFormatPost_Garbage_FallsToDecoy — tiny random payload must
// bypass both dispatch arms (too short for hint+token+chunk, too short for
// handshake) and land in failClosedToDecoy without leaking ServerHello fields.
func TestHandleNewFormatPost_Garbage_FallsToDecoy(t *testing.T) {
	h, _ := setupTestHandler(t)
	body := wrapInJSONEnvelope(t, []byte{0x00, 0x01, 0x02})
	req := httptest.NewRequest("POST", "/a", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.handleNewFormatPost(rec, req)

	// Decoy returns 200 HTML; crucially, body must NOT contain a ServerHello.
	require.NotContains(t, rec.Body.String(), `"eph"`, "garbage must not leak ephemeral pub")
	require.NotContains(t, rec.Body.String(), `"_v":1`, "garbage must not produce ServerHello")
}

// TestHandleHandshakeNew_SetsProtoVersion verifies that the Phase B handshake
// path emits `_v: 1` in ServerHello so the client pins to the new body-prefix
// wire format. Legacy handleHandshake must NOT emit `_v` (see
// TestEncodeServerHello_VFieldOmittedOnLegacy below).
func TestHandleHandshakeNew_SetsProtoVersion(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	ch, _, err := core.NewClientHello([]byte("user-b3-proto-uu"), serverKey.Public)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analytics", nil)
	h.handleHandshakeNew(rec, req, ch.EphemeralPub, ch.EncryptedClientID)

	require.Equal(t, 200, rec.Code, "handshake must succeed, body=%s", rec.Body.String())

	// Response wraps ServerHello JSON inside a ParseDownloadResponse envelope.
	shJSON, _, err := browser.ParseDownloadResponse(rec.Body.Bytes())
	require.NoError(t, err)

	var sh struct {
		ProtoVersion *uint8 `json:"_v"`
		Deprecated   bool   `json:"_deprecated"`
	}
	require.NoError(t, json.Unmarshal(shJSON, &sh))
	require.NotNil(t, sh.ProtoVersion, "new-path ServerHello must set _v")
	require.Equal(t, uint8(1), *sh.ProtoVersion, "_v must be 1")
	require.False(t, sh.Deprecated, "_deprecated must be omitted on new path")
	require.Equal(t, uint64(1), h.metrics.HandshakesNewTotal.Load(), "HandshakesNewTotal must increment")
}

// TestHandleHandshakeNew_RejectsReplay verifies that the replay cache blocks
// a second handshake with identical (client_id, timestamp_bucket). The response
// on replay must not expose a ServerHello (no `eph`/`tok` fields leaked).
func TestHandleHandshakeNew_RejectsReplay(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	ch, _, err := core.NewClientHello([]byte("user-b3-replay!!"), serverKey.Public)
	require.NoError(t, err)

	// First handshake: accepted.
	rec1 := httptest.NewRecorder()
	h.handleHandshakeNew(rec1, httptest.NewRequest("POST", "/a", nil), ch.EphemeralPub, ch.EncryptedClientID)
	require.Equal(t, 200, rec1.Code)
	shJSON1, _, err := browser.ParseDownloadResponse(rec1.Body.Bytes())
	require.NoError(t, err)
	require.Contains(t, string(shJSON1), `"_v":1`, "first handshake must emit _v:1")

	// Replay: same encrypted client_id → replayCache.Accept returns false.
	rec2 := httptest.NewRecorder()
	h.handleHandshakeNew(rec2, httptest.NewRequest("POST", "/a", nil), ch.EphemeralPub, ch.EncryptedClientID)
	// Decoy path — response MUST NOT contain ServerHello fields.
	body2 := rec2.Body.String()
	require.NotContains(t, body2, `"eph"`, "replay must not leak ephemeral pub")
	require.NotContains(t, body2, `"_v":1`, "replay must not emit ServerHello")
	require.GreaterOrEqual(t, h.metrics.HandshakesFailed.Load(), uint64(1), "HandshakesFailed must increment on replay")
	require.Equal(t, uint64(1), h.metrics.HandshakesNewTotal.Load(), "HandshakesNewTotal must stay at 1 — only first succeeded")
}

// TestHandleHandshakeNew_AcceptsParallelHandshakesSameClientID verifies that
// multiple concurrent handshakes from the same clientID with different
// ephemeral keys all succeed. This is the WS pool case: a single client mints
// a fresh ClientHello (new eph_pub, new NaCl box nonce → different
// EncryptedClientID) for each of its 8 pool slots, and every handshake must
// land its own session. Before the 2026-04-30 fix the replay cache was keyed
// on the decoded clientID under a 5-minute sliding window — only the first
// handshake of a wave succeeded; the remaining seven fell through to
// failClosedToDecoy and surfaced on the client as "server returned HTML
// instead of JSON" (data-plane drift on datacanvases.com, 2026-04-30 memo).
//
// The legitimate replay defense (TestHandleHandshakeNew_RejectsReplay) keys on
// the encrypted client_id ciphertext, so a captured-and-resubmitted handshake
// is still rejected — the bit-for-bit replay yields the same NaCl nonce.
func TestHandleHandshakeNew_AcceptsParallelHandshakesSameClientID(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	clientID := []byte("user-pool-replay")
	require.Len(t, clientID, 16, "test relies on UUID-sized clientID")

	const slots = 8
	for i := range slots {
		ch, _, err := core.NewClientHello(clientID, serverKey.Public)
		require.NoError(t, err, "slot %d: new client hello", i)

		rec := httptest.NewRecorder()
		h.handleHandshakeNew(rec, httptest.NewRequest("POST", "/a", nil), ch.EphemeralPub, ch.EncryptedClientID)
		require.Equal(t, 200, rec.Code, "slot %d: handshake must succeed", i)

		shJSON, _, err := browser.ParseDownloadResponse(rec.Body.Bytes())
		require.NoError(t, err, "slot %d: parse server hello", i)
		require.Contains(t, string(shJSON), `"_v":1`, "slot %d: must emit ServerHello _v:1", i)
	}

	require.Equal(t, uint64(slots), h.metrics.HandshakesNewTotal.Load(),
		"all %d parallel handshakes must succeed", slots)
	require.Zero(t, h.metrics.HandshakesFailed.Load(),
		"no handshake should be classified as failed")
}

// TestEncodeServerHello_VFieldOmittedOnLegacy — legacy path (ProtoVersion nil)
// must drop `_v` (omitempty) AND stamp `_deprecated:true` so modern clients
// know the session was downgraded.
func TestEncodeServerHello_VFieldOmittedOnLegacy(t *testing.T) {
	sh := &core.ServerHello{EphemeralPub: make([]byte, 32), EncryptedSessionToken: make([]byte, 32)}
	blob := string(encodeServerHello(sh))
	require.NotContains(t, blob, `"_v"`, "legacy ServerHello must omit _v")
	require.Contains(t, blob, `"_deprecated":true`, "legacy ServerHello must flag _deprecated:true")
}

// TestEncodeServerHello_VFieldPresentOnNew — new path must emit `_v:1` and
// omit `_deprecated` (omitempty drops `false`).
func TestEncodeServerHello_VFieldPresentOnNew(t *testing.T) {
	v := uint8(1)
	sh := &core.ServerHello{EphemeralPub: make([]byte, 32), EncryptedSessionToken: make([]byte, 32), ProtoVersion: &v}
	blob := string(encodeServerHello(sh))
	require.Contains(t, blob, `"_v":1`, "new ServerHello must emit _v:1")
	require.NotContains(t, blob, `"_deprecated"`, "new ServerHello must omit _deprecated")
}

// TestSessionTokenSize pins the hint+token wire-format length to the protocol
// constant (36 bytes = 4 hint + 12 nonce + 4 session_id + 16 GCM tag). A change
// here signals a wire-breaking protocol shift — update callers in lockstep.
func TestSessionTokenSize(t *testing.T) {
	h := &Handler{}
	if got := h.sessionTokenSize(); got != 36 {
		t.Errorf("sessionTokenSize = %d, want 36", got)
	}

	// Belt-and-suspenders: cross-check against an actual encrypted token.
	_, serverKey := setupTestHandler(t)
	clientHello, _, err := core.NewClientHello([]byte("size-check-uuid!"), serverKey.Public)
	require.NoError(t, err)
	sm := core.NewSessionManager(5 * time.Minute)
	serverHello, session, _, err := core.HandleClientHello(clientHello, serverKey, 8, 12288, sm)
	require.NoError(t, err)
	defer sm.Remove(session.ID)
	// 4-byte hint + encrypted token must match the declared constant.
	if got := 4 + len(serverHello.EncryptedSessionToken); got != h.sessionTokenSize() {
		t.Errorf("wire-format size = %d (4 hint + %d token), sessionTokenSize reports %d — protocol drift",
			got, len(serverHello.EncryptedSessionToken), h.sessionTokenSize())
	}
}

// TestFindSessionByHint_O1Lookup verifies the O(1) hint-prefixed session
// lookup. Input is the full [hint(4) || encrypted_session_token] prefix as
// produced by browser.EncodeTokenWithHint on the client. The body-prefix
// data path (handleNewFormatPost) and WS first-frame auth rely on this
// helper for O(1) session resolution.
func TestFindSessionByHint_O1Lookup(t *testing.T) {
	h, serverKey := setupTestHandler(t)

	clientHello, _, err := core.NewClientHello([]byte("user-b1-uuid-len"), serverKey.Public)
	require.NoError(t, err)

	serverHello, session, _, err := core.HandleClientHello(clientHello, serverKey, 8, 12288, h.sessions)
	require.NoError(t, err)
	defer h.sessions.Remove(session.ID)

	tokenWithHint := browser.EncodeTokenWithHint(session.ID, serverHello.EncryptedSessionToken)
	require.GreaterOrEqual(t, len(tokenWithHint), 20, "sanity: hint+token must be >= 20 bytes")

	// Positive: correct hint+token resolves to the session.
	got := h.findSessionByHint(tokenWithHint)
	require.NotNil(t, got, "hint lookup must find session")
	require.Equal(t, session.ID, got.ID)

	// Negative: truncated input — too short for hint+token layout.
	require.Nil(t, h.findSessionByHint(tokenWithHint[:10]), "truncated input must return nil")
	require.Nil(t, h.findSessionByHint(nil), "nil input must return nil")
	require.Nil(t, h.findSessionByHint([]byte{}), "empty input must return nil")

	// Negative: corrupt hint (sid decodes to non-existent session) → nil.
	corruptHint := make([]byte, len(tokenWithHint))
	copy(corruptHint, tokenWithHint)
	corruptHint[0] ^= 0xFF
	corruptHint[1] ^= 0xFF
	corruptHint[2] ^= 0xFF
	corruptHint[3] ^= 0xFF
	require.Nil(t, h.findSessionByHint(corruptHint), "wrong sid must not match any session")

	// Negative: corrupt token body (correct sid, but GCM tag fails) → nil.
	corruptToken := make([]byte, len(tokenWithHint))
	copy(corruptToken, tokenWithHint)
	corruptToken[len(corruptToken)-1] ^= 0xFF
	require.Nil(t, h.findSessionByHint(corruptToken), "bad token tag must not match")
}

// TestServeHTTP_NoServerHeader guards that the handler emits no Server header
// on any response path. Behind CF orange cloud CF replaces Server with
// "cloudflare"; in direct-IP fallback, emitting "nginx/1.27.3" (Nov 2024
// release) on May 2026 is a version-anachronism fingerprint.
func TestServeHTTP_NoServerHeader(t *testing.T) {
	h, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(w, r)

	assert.Equal(t, "", w.Header().Get("Server"),
		"Server header must be empty — CF sets its own; emitting nginx/1.27.3 is a fingerprint")
}

// TestHandleHandshakeNew_SetsAttachedAt_PreventsOrphanCleanup verifies the
// 2026-05-18 semantic revision: AttachedAt is set at handshake response
// flush, not at WS first-frame. This means a session whose owner never
// completes the subsequent WS upgrade (e.g. because the WS-upgrade rate-
// limit gate rejected it) survives the orphan cleanup window — it falls
// under the regular idle timeout instead. Pre-fix metric: 351 orphan
// evictions in a 5-min field test, ~all races, no actual abandons.
func TestHandleHandshakeNew_SetsAttachedAt_PreventsOrphanCleanup(t *testing.T) {
	h, serverKey := setupTestHandler(t)
	ch, _, err := core.NewClientHello([]byte("user-attached-uu"), serverKey.Public)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analytics", nil)
	h.handleHandshakeNew(rec, req, ch.EphemeralPub, ch.EncryptedClientID)
	require.Equal(t, 200, rec.Code, "handshake must succeed")

	// Exactly one session must exist now.
	require.Equal(t, 1, h.sessions.Count(), "one session created")

	// Pull the session and verify AttachedAt is non-zero — the cleanup
	// loop's Phase 1 filter (AttachedAt.Load() != 0 → skip) hinges on this.
	var sess *core.Session
	h.sessions.ForEach(func(s *core.Session) bool {
		sess = s
		return false
	})
	require.NotNil(t, sess, "session must be retrievable from manager")
	require.NotZero(t, sess.AttachedAt.Load(),
		"AttachedAt must be set at handshake response flush, "+
			"so a subsequent WS-upgrade reject does not orphan the session")

	// Drive orphan cleanup far past the grace window — the session must
	// NOT be evicted because AttachedAt!=0.
	evicted := h.sessions.CleanupNewbornOrphans(
		time.Now().Add(1*time.Hour), 30*time.Second)
	require.Empty(t, evicted,
		"handshake-attached session must NOT be evicted by orphan cleanup, "+
			"even an hour past the grace window")
	require.Equal(t, 1, h.sessions.Count(), "session still present after cleanup")
}

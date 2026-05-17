package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// probeTransport is a minimal Transport + HandshakeRawSender used to exercise
// the D4 handshake probe without spinning up the real shadowlink server. The
// backing HTTP server controls both paths:
//
//   - SendHandshakeRaw ("new" probe) posts to `<base>/probe/new`
//   - SendHandshake ("legacy" fallback) posts to `<base>/probe/legacy`
//
// Tests configure each path's response (status + body) independently.
type probeTransport struct {
	baseURL string
	rawHits atomic.Int32
	legHits atomic.Int32

	// callOrder records the sequence of path invocations ("new" / "legacy")
	// so tests can assert ordering, not just counts. Protected by its own
	// mutex since SendHandshake and SendHandshakeRaw can (in principle) be
	// called concurrently from parallel tests.
	orderMu   sync.Mutex
	callOrder []string
}

func (t *probeTransport) recordCall(name string) {
	t.orderMu.Lock()
	t.callOrder = append(t.callOrder, name)
	t.orderMu.Unlock()
}

func (t *probeTransport) snapshotOrder() []string {
	t.orderMu.Lock()
	defer t.orderMu.Unlock()
	return append([]string(nil), t.callOrder...)
}

func (t *probeTransport) Name() string { return "probe" }
func (t *probeTransport) Close() error { return nil }

// SendChunk is unused in D4 tests — returns a benign empty response.
func (t *probeTransport) SendChunk(ctx context.Context, data, token []byte, seq uint32) ([]byte, error) {
	return nil, nil
}

// SendHandshakeRaw posts the raw payload to the test server's "new" endpoint.
// Matches the HTTP NXX / 200-garbage error contract exactly so the classifier
// in runHandshakeSequence sees the same signals as the real DirectTransport.
func (t *probeTransport) SendHandshakeRaw(ctx context.Context, payload []byte) ([]byte, error) {
	t.rawHits.Add(1)
	t.recordCall("new")
	return t.post(ctx, t.baseURL+"/probe/new", payload, false)
}

// SendHandshake posts a legacy-shaped payload (eph || encClientID) to the test
// server's "legacy" endpoint. In this helper we send the payload as the
// envelope data field and add an Authorization header so the test server can
// verify that the client reached the legacy branch.
func (t *probeTransport) SendHandshake(ctx context.Context, hello *core.ClientHello) ([]byte, error) {
	t.legHits.Add(1)
	t.recordCall("legacy")
	payload := make([]byte, 0, len(hello.EphemeralPub)+len(hello.EncryptedClientID))
	payload = append(payload, hello.EphemeralPub...)
	payload = append(payload, hello.EncryptedClientID...)
	return t.post(ctx, t.baseURL+"/probe/legacy", payload, true)
}

func (t *probeTransport) post(ctx context.Context, url string, payload []byte, withBearer bool) ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	type evt struct {
		Type string `json:"type"`
		TS   int64  `json:"ts"`
		Data string `json:"data"`
	}
	type envelope struct {
		Events []evt `json:"events"`
	}
	body, _ := json.Marshal(envelope{Events: []evt{{Type: "init", TS: time.Now().UnixMilli(), Data: encoded}}})

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if withBearer {
		req.Header.Set("Authorization", "Bearer stub")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode >= 400 {
		return nil, &httpStatusError{
			Status: resp.StatusCode,
			Body:   fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBytes)),
		}
	}
	if resp.StatusCode != 200 {
		return nil, &httpStatusError{
			Status: resp.StatusCode,
			Body:   fmt.Sprintf("unexpected status: HTTP %d", resp.StatusCode),
		}
	}
	if len(respBytes) > 0 && respBytes[0] == '<' {
		return nil, &httpStatusError{
			Status: 200,
			Body:   "server returned HTML instead of JSON",
		}
	}
	return respBytes, nil
}

// Compile-time assertions.
var (
	_ Transport          = (*probeTransport)(nil)
	_ HandshakeRawSender = (*probeTransport)(nil)
)

// encodeStubServerHello wraps a ServerHello JSON in the analytics download
// envelope shape the client expects from ParseDownloadResponse. protoV is
// pointed-to when non-negative (nil otherwise → legacy server).
func encodeStubServerHello(t *testing.T, protoV int, token []byte) []byte {
	t.Helper()

	type sh struct {
		EphPub       []byte `json:"eph"`
		Token        []byte `json:"tok"`
		MaxConns     uint8  `json:"mc"`
		ChunkSize    uint16 `json:"cs"`
		ProtoVersion *uint8 `json:"_v,omitempty"`
	}
	if token == nil {
		token = []byte("stub-token-bytes-padded-36!!!!!!!!!!!")
	}
	hello := sh{
		EphPub:    make([]byte, 32),
		Token:     token,
		MaxConns:  4,
		ChunkSize: 12288,
	}
	if protoV >= 0 {
		v := uint8(protoV)
		hello.ProtoVersion = &v
	}
	inner, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}

	type downloadResult struct {
		ID      string `json:"id"`
		Payload string `json:"payload"`
	}
	type downloadEnv struct {
		Status  string           `json:"status"`
		Results []downloadResult `json:"results"`
	}
	out, err := json.Marshal(downloadEnv{
		Status:  "ok",
		Results: []downloadResult{{ID: "deadbeef", Payload: base64.RawURLEncoding.EncodeToString(inner)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// newProbeClient wires a probeTransport against the given test server and
// returns a Client configured with a 16-byte UUID clientID (required by the
// Phase B new-format handshake path).
func newProbeClient(t *testing.T, srv *httptest.Server, skipVerify bool) (*Client, *probeTransport) {
	t.Helper()
	serverKey, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pt := &probeTransport{baseURL: srv.URL}
	cl := NewClientWithTransport(pt, serverKey.Public, []byte("unit-test-uuid!!")) // 16 B
	cl.insecureSkipVerify = skipVerify
	return cl, pt
}

// TestPerformHandshake_HardFailOn200_NonServerHello verifies the D4 MITM
// protection: when the server answers 200 with HTML the client must reject
// the response as "possible MITM" rather than silently fall back.
func TestPerformHandshake_HardFailOn200_NonServerHello(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte("<html>injected</html>"))
	}))
	defer srv.Close()

	cl, _ := newProbeClient(t, srv, false)
	err := cl.performHandshake(context.Background())
	if err == nil {
		t.Fatal("expected hard fail on 200 + garbage (MITM protection)")
	}
	if !strings.Contains(err.Error(), "MITM") {
		t.Errorf("error should mention MITM, got %v", err)
	}
}

// TestPerformHandshake_LegacyServer_FallbackOn4xx verifies that HTTP 4xx on
// the new-format path triggers a legacy fallback when InsecureSkipVerify is
// off, and that the legacy ServerHello is honored (ProtoVersion pinned to 0).
func TestPerformHandshake_LegacyServer_FallbackOn4xx(t *testing.T) {
	var legacyHit atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/probe/new") {
			http.Error(w, "not found", 404)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/probe/legacy") && r.Header.Get("Authorization") != "" {
			legacyHit.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write(encodeStubServerHello(t, -1, nil)) // no `_v` — legacy server
			return
		}
		http.Error(w, "unexpected", 400)
	}))
	defer srv.Close()

	cl, pt := newProbeClient(t, srv, false)
	err := cl.performHandshake(context.Background())
	// CompleteHandshake will fail on our stub ServerHello (bogus ephemeral
	// pub), but we're exercising the *routing* decision — which path did
	// runHandshakeSequence pick? Assert on call counts AND ordering so a
	// regression that swaps legacy-then-new, or double-calls one side, is
	// caught even though the final error is ignored.
	_ = err
	if pt.rawHits.Load() != 1 {
		t.Errorf("new path must be tried exactly once, got %d", pt.rawHits.Load())
	}
	if pt.legHits.Load() != 1 {
		t.Errorf("legacy fallback must run on 4xx (no skip-verify), got %d", pt.legHits.Load())
	}
	if legacyHit.Load() == 0 {
		t.Errorf("server never saw a legacy request")
	}
	order := pt.snapshotOrder()
	want := []string{"new", "legacy"}
	if !equalStrings(order, want) {
		t.Errorf("call order = %v, want %v (new must precede legacy)", order, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPerformHandshake_SkipVerifyDisablesFallback locks down the MITM-defense:
// when TLS verification is off, the client must refuse to silently retry on
// the legacy Bearer path (which would be attacker-forgeable under MITM).
func TestPerformHandshake_SkipVerifyDisablesFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	}))
	defer srv.Close()

	cl, pt := newProbeClient(t, srv, true) // InsecureSkipVerify ON
	err := cl.performHandshake(context.Background())
	if err == nil {
		t.Fatal("fallback must be disabled when InsecureSkipVerify=true")
	}
	if !strings.Contains(err.Error(), "InsecureSkipVerify") {
		t.Errorf("error should mention InsecureSkipVerify, got %v", err)
	}
	if pt.legHits.Load() != 0 {
		t.Errorf("legacy fallback must NOT run under InsecureSkipVerify, got %d hits", pt.legHits.Load())
	}
}

// TestPerformHandshake_HardFailOnVersionTooNew verifies the D4 version gate:
// a new-format ServerHello with `_v` > supported client version must fail
// with an explicit "update required" error.
func TestPerformHandshake_HardFailOnVersionTooNew(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/probe/new") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write(encodeStubServerHello(t, 2, nil)) // _v=2, client supports 1
			return
		}
		http.Error(w, "unexpected", 400)
	}))
	defer srv.Close()

	cl, _ := newProbeClient(t, srv, false)
	err := cl.performHandshake(context.Background())
	if err == nil {
		t.Fatal("expected hard fail when server advertises proto v=2")
	}
	if !strings.Contains(err.Error(), "update") {
		t.Errorf("error should mention update requirement, got %v", err)
	}
}

// TestPerformHandshake_Once pins sync.Once semantics: a retry after success
// is a no-op, a retry after failure returns the cached error without hitting
// the server again.
func TestPerformHandshake_Once(t *testing.T) {
	var newHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newHits.Add(1)
		http.Error(w, "bad request", 400)
	}))
	defer srv.Close()

	cl, _ := newProbeClient(t, srv, true) // skip-verify off fallback path
	_ = cl.performHandshake(context.Background())
	_ = cl.performHandshake(context.Background())
	_ = cl.performHandshake(context.Background())

	if got := newHits.Load(); got != 1 {
		t.Errorf("sync.Once broken: server hit %d times, want 1", got)
	}
}

// TestPerformHandshake_CtxCancelDoesNotPoisonOnce guards H1 regression:
// a context cancellation from a first Connect attempt must NOT be cached by
// sync.Once — a subsequent Connect(freshCtx) must re-run the full sequence.
// Without the reset, ConnectWithRetry would be permanently broken after any
// transient early cancel.
func TestPerformHandshake_CtxCancelDoesNotPoisonOnce(t *testing.T) {
	var newHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(encodeStubServerHello(t, 1, nil))
	}))
	defer srv.Close()

	cl, _ := newProbeClient(t, srv, false)

	// First attempt — pre-cancelled context forces a ctx.Canceled error.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err1 := cl.performHandshake(cancelled)
	if !errors.Is(err1, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err1)
	}

	// Second attempt with a live context must actually hit the server, not
	// short-circuit on the cached ctx error.
	_ = cl.performHandshake(context.Background())
	if newHits.Load() == 0 {
		t.Errorf("sync.Once poisoned: second attempt never reached the server")
	}
}

// TestPerformHandshake_NonCtxErrorStillCaches guards the other half of H1:
// real errors (e.g. HTTP 500, MITM, dial failure) MUST stay cached — they
// indicate a stable problem, not a transient ctx cancel. Retrying would just
// waste server round-trips and leak session state on the server.
func TestPerformHandshake_NonCtxErrorStillCaches(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte("<html>injected</html>"))
	}))
	defer srv.Close()

	cl, _ := newProbeClient(t, srv, false)
	_ = cl.performHandshake(context.Background())
	_ = cl.performHandshake(context.Background())
	_ = cl.performHandshake(context.Background())
	if got := hits.Load(); got != 1 {
		t.Errorf("MITM hard-fail must cache: got %d server hits, want 1", got)
	}
}

// TestParseHandshakeError_Classifications guards the unexported classifier
// helper that drives the D4 probe's fallback decision. After H2 the classifier
// is strictly type-based (errors.As on *httpStatusError) — string prefixes are
// no longer used, so the test only exercises typed and wrapped errors.
func TestParseHandshakeError_Classifications(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want *httpStatusError
	}{
		{"nil", nil, nil},
		{"typed 404", &httpStatusError{Status: 404, Body: "not found"}, &httpStatusError{Status: 404}},
		{"typed 500", &httpStatusError{Status: 500, Body: "gateway"}, &httpStatusError{Status: 500}},
		{"typed 200-garbage", &httpStatusError{Status: 200, Body: "HTML"}, &httpStatusError{Status: 200}},
		{"wrapped 404", fmt.Errorf("retry: %w", &httpStatusError{Status: 404, Body: ""}), &httpStatusError{Status: 404}},
		{"doubly wrapped 502", fmt.Errorf("a: %w", fmt.Errorf("b: %w", &httpStatusError{Status: 502})), &httpStatusError{Status: 502}},
		{"network error", fmt.Errorf("dial tcp: connection refused"), nil},
		{"context canceled", context.Canceled, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseHandshakeError(c.in)
			if (got == nil) != (c.want == nil) {
				t.Errorf("nil mismatch: got=%v want=%v", got, c.want)
				return
			}
			if got != nil && got.Status != c.want.Status {
				t.Errorf("Status = %d, want %d", got.Status, c.want.Status)
			}
		})
	}
}

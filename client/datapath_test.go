package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	urlpkg "net/url"
	"strings"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// startStdlibTestServer is a minimal stdlib net/http test server used by the
// SendChunk/SendChunkRawBody unit tests. Returned addr is "host:port" usable
// by NewDirectTransport.
func startStdlibTestServer(t *testing.T, h func(w nethttp.ResponseWriter, r *nethttp.Request)) (addr string, stop func()) {
	t.Helper()
	srv := httptest.NewServer(nethttp.HandlerFunc(h))
	u, err := urlpkg.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("parse test server URL: %v", err)
	}
	return u.Host, srv.Close
}

func TestParseDataPathBodyPrefixEnv(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		// Default ON: empty / unset env → body-prefix path active.
		{"", true},
		{"random-garbage", true},
		// Explicit on (legacy override values still accepted as truthy).
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"yes", true},
		{"YES", true},
		{"on", true},
		// Emergency disable: explicit falsy values restore legacy Authorization path.
		{"0", false},
		{"false", false},
		{"FALSE", false},
		{"no", false},
		{"NO", false},
		{"off", false},
		{"OFF", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := parseDataPathBodyPrefixEnv(tc.raw); got != tc.want {
				t.Fatalf("parseDataPathBodyPrefixEnv(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestBuildDataEnvelope(t *testing.T) {
	token := []byte{0x01, 0x02, 0x03, 0x04}
	enc := []byte{0xde, 0xad, 0xbe, 0xef}

	body, err := buildDataEnvelope(token, enc)
	if err != nil {
		t.Fatalf("buildDataEnvelope: %v", err)
	}

	// Body must be valid JSON of shape {"events":[{"type":...,"ts":<int64>,"data":"<base64url>"}]}
	var parsed struct {
		Events []struct {
			Type string `json:"type"`
			TS   int64  `json:"ts"`
			Data string `json:"data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, string(body))
	}
	if len(parsed.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(parsed.Events))
	}
	if parsed.Events[0].Type == "" {
		t.Fatalf("expected non-empty event type")
	}
	if parsed.Events[0].TS == 0 {
		t.Fatalf("expected non-zero ts")
	}
	// Decode the data field and assert it is tokenWithHint || enc
	decoded, err := base64.RawURLEncoding.DecodeString(parsed.Events[0].Data)
	if err != nil {
		t.Fatalf("decode data: %v", err)
	}
	// browser.BuildDataPayload prepends a 36-byte tokenWithHint; our fixture
	// passes a short token which BuildDataPayload accepts verbatim.
	want := browser.BuildDataPayload(token, enc)
	if !bytes.Equal(decoded, want) {
		t.Fatalf("decoded data mismatch:\n  got  %x\n  want %x", decoded, want)
	}
}

func TestBuildDataPostHeaders_NoAuthorization(t *testing.T) {
	h := buildDataPostHeaders("Mozilla/5.0 (X)", "https://example.com")

	// NOTE: keys are stored lowercase in the map literal to produce lowercase
	// wire bytes (W4 invariant — matches the shared `buildDataPostHeaders` contract).
	// fhttp's Header.Get canonicalizes the lookup key (content-type →
	// Content-Type), so positive-value assertions use direct map access.
	// Negative assertions (authorization absent) still work via Get because
	// the map has no entry under either regime.
	hGetLower := func(k string) string {
		if v, ok := h[k]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}

	if got := h.Get("authorization"); got != "" {
		t.Fatalf("authorization must be absent, got %q", got)
	}
	if got := hGetLower("content-type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	if got := hGetLower("user-agent"); got != "Mozilla/5.0 (X)" {
		t.Fatalf("user-agent = %q", got)
	}
	if got := hGetLower("origin"); got != "https://example.com" {
		t.Fatalf("origin = %q", got)
	}
	if got := hGetLower("referer"); got != "https://example.com/" {
		t.Fatalf("referer = %q", got)
	}
	// x-request-id must be present and 8 hex chars.
	xreq := hGetLower("x-request-id")
	if len(xreq) != 8 {
		t.Fatalf("x-request-id = %q, want 8 hex chars", xreq)
	}

	// Header order must NOT include "authorization".
	order, ok := h[http.HeaderOrderKey]
	if !ok {
		t.Fatalf("HeaderOrderKey missing")
	}
	for _, k := range order {
		if strings.EqualFold(k, "authorization") {
			t.Fatalf("HeaderOrderKey must not include authorization, got %v", order)
		}
	}

	// Expected order (must match cover traffic exactly for W4).
	want := []string{
		"content-type", "x-request-id", "user-agent",
		"accept", "accept-encoding", "accept-language",
		"origin", "referer", "cache-control",
	}
	if len(order) != len(want) {
		t.Fatalf("HeaderOrderKey len = %d, want %d (order=%v)", len(order), len(want), order)
	}
	for i, k := range want {
		if order[i] != k {
			t.Fatalf("HeaderOrderKey[%d] = %q, want %q (full=%v)", i, order[i], k, order)
		}
	}
}

func TestSendChunk_FlagOn_OmitsAuthorization(t *testing.T) {
	restore := withDataPathBodyPrefix(true)
	t.Cleanup(restore)

	reqCh := make(chan *nethttp.Request, 1)
	bodyCh := make(chan []byte, 1)

	handler := func(w nethttp.ResponseWriter, r *nethttp.Request) {
		b, _ := io.ReadAll(r.Body)
		reqCh <- r.Clone(r.Context())
		bodyCh <- b
		// Return a valid envelope so SendChunk's ParseDownloadResponse doesn't fatal.
		emptyResp, _ := buildDataEnvelope(nil, nil)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(emptyResp)
	}

	addr, stopSrv := startStdlibTestServer(t, handler)
	t.Cleanup(stopSrv)

	tr := NewDirectTransport(addr, false, true)
	t.Cleanup(func() { _ = tr.Close() })

	token := make([]byte, 36)
	for i := range token {
		token[i] = byte(i)
	}
	enc := []byte{0xaa, 0xbb, 0xcc}

	_, _ = tr.SendChunk(context.Background(), enc, token, 0)

	var capturedReq *nethttp.Request
	var capturedBody []byte
	select {
	case capturedReq = <-reqCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for request")
	}
	select {
	case capturedBody = <-bodyCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for body")
	}

	if capturedReq == nil {
		t.Fatalf("server did not receive request")
	}
	if got := capturedReq.Header.Get("authorization"); got != "" {
		t.Fatalf("SendChunk with flag on must NOT send Authorization, got %q", got)
	}
	if capturedReq.Method != "POST" {
		t.Fatalf("method = %q, want POST", capturedReq.Method)
	}
	var parsed struct {
		Events []struct {
			Data string `json:"data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(capturedBody, &parsed); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if len(parsed.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(parsed.Events))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parsed.Events[0].Data)
	if err != nil {
		t.Fatalf("decode data: %v", err)
	}
	want := browser.BuildDataPayload(token, enc)
	if !bytes.Equal(decoded, want) {
		t.Fatalf("body mismatch:\n  got  %x\n  want %x", decoded, want)
	}
}

func TestSendChunk_FlagOff_KeepsAuthorization(t *testing.T) {
	restore := withDataPathBodyPrefix(false)
	t.Cleanup(restore)

	reqCh := make(chan *nethttp.Request, 1)

	handler := func(w nethttp.ResponseWriter, r *nethttp.Request) {
		reqCh <- r.Clone(r.Context())
		emptyResp, _ := buildDataEnvelope(nil, nil)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(emptyResp)
	}

	addr, stopSrv := startStdlibTestServer(t, handler)
	t.Cleanup(stopSrv)

	tr := NewDirectTransport(addr, false, true)
	t.Cleanup(func() { _ = tr.Close() })

	token := make([]byte, 36)
	enc := []byte{0xaa, 0xbb, 0xcc}

	_, _ = tr.SendChunk(context.Background(), enc, token, 0)

	var capturedReq *nethttp.Request
	select {
	case capturedReq = <-reqCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for request")
	}

	if capturedReq == nil {
		t.Fatalf("server did not receive request")
	}
	authz := capturedReq.Header.Get("authorization")
	if authz == "" {
		t.Fatalf("SendChunk with flag off MUST send Authorization, got empty")
	}
	if !strings.HasPrefix(authz, "Bearer ") {
		t.Fatalf("authorization = %q, want Bearer prefix", authz)
	}
}

func TestSendChunkRawBody_FlagOn_OmitsAuthorization(t *testing.T) {
	restore := withDataPathBodyPrefix(true)
	t.Cleanup(restore)

	reqCh := make(chan *nethttp.Request, 1)
	bodyCh := make(chan []byte, 1)

	handler := func(w nethttp.ResponseWriter, r *nethttp.Request) {
		b, _ := io.ReadAll(r.Body)
		reqCh <- r.Clone(r.Context())
		bodyCh <- b
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"events":[]}`))
	}
	addr, stop := startStdlibTestServer(t, handler)
	t.Cleanup(stop)

	tr := NewDirectTransport(addr, false, true)
	t.Cleanup(func() { _ = tr.Close() })

	token := make([]byte, 36)
	for i := range token {
		token[i] = byte(i)
	}
	enc := []byte{1, 2, 3}
	_, _ = tr.SendChunkRawBody(context.Background(), enc, token, 0)

	var capturedReq *nethttp.Request
	var capturedBody []byte
	select {
	case capturedReq = <-reqCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for request")
	}
	select {
	case capturedBody = <-bodyCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for body")
	}

	if capturedReq == nil {
		t.Fatalf("server did not receive request")
	}
	if got := capturedReq.Header.Get("authorization"); got != "" {
		t.Fatalf("SendChunkRawBody flag on must omit Authorization, got %q", got)
	}
	if capturedReq.Method != "POST" {
		t.Fatalf("method = %q, want POST", capturedReq.Method)
	}

	// Verify envelope carries tokenWithHint || enc.
	var parsed struct {
		Events []struct {
			Data string `json:"data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(capturedBody, &parsed); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if len(parsed.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(parsed.Events))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parsed.Events[0].Data)
	if err != nil {
		t.Fatalf("decode data: %v", err)
	}
	want := browser.BuildDataPayload(token, enc)
	if !bytes.Equal(decoded, want) {
		t.Fatalf("body mismatch:\n  got  %x\n  want %x", decoded, want)
	}
}

func TestSendChunkRawBody_FlagOff_KeepsAuthorization(t *testing.T) {
	restore := withDataPathBodyPrefix(false)
	t.Cleanup(restore)

	reqCh := make(chan *nethttp.Request, 1)

	handler := func(w nethttp.ResponseWriter, r *nethttp.Request) {
		reqCh <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"events":[]}`))
	}
	addr, stop := startStdlibTestServer(t, handler)
	t.Cleanup(stop)

	tr := NewDirectTransport(addr, false, true)
	t.Cleanup(func() { _ = tr.Close() })

	token := make([]byte, 36)
	enc := []byte{1, 2, 3}
	_, _ = tr.SendChunkRawBody(context.Background(), enc, token, 0)

	var capturedReq *nethttp.Request
	select {
	case capturedReq = <-reqCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for request")
	}

	authz := capturedReq.Header.Get("authorization")
	if authz == "" {
		t.Fatalf("SendChunkRawBody flag off MUST send Authorization, got empty")
	}
	if !strings.HasPrefix(authz, "Bearer ") {
		t.Fatalf("authorization = %q, want Bearer prefix", authz)
	}
}

// TestDataPathBodyPrefix_DefaultOn locks Phase 0 T1.4 flip: an unset
// SHADOWLINK_DATAPATH_BODYPREFIX env var must yield body-prefix-enabled.
// Regression guard against accidental re-flip back to legacy default.
func TestDataPathBodyPrefix_DefaultOn(t *testing.T) {
	if !parseDataPathBodyPrefixEnv("") {
		t.Fatalf("Phase 0 T1.4 flip regressed: empty env must yield default-on body-prefix")
	}
	if parseDataPathBodyPrefixEnv("0") {
		t.Fatalf("emergency disable broken: SHADOWLINK_DATAPATH_BODYPREFIX=0 must yield off")
	}
}

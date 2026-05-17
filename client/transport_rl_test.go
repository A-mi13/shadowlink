package client

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/core"
)

// Phase 2.2 regression tests (2026-05-14): dual-carrier rate-limit detector
// integrated into DirectTransport.SendHandshake. These cover the P0 production
// bug: sticky reconnect loop caused by CF stripping X-SL-RL header while the
// old header-only detection left HTML decoys undetected.
//
// All tests use httptest.NewServer so we exercise the full SendHandshake path
// including the connManager.Do call and the body reading — not just the detector
// logic (which is covered separately in ratelimit_test.go).

// makeDecoyBodyWithMarker builds a minimal Schema.org HTML decoy body carrying
// a rate-limit marker in the JSON-LD identifier. Mirrors the server's
// SentinelEmitter output for testing purposes.
func makeDecoyBodyWithMarker(rlStateValue string) string {
	jsonLD := fmt.Sprintf(
		`{"@context":"https://schema.org","@type":"WebSite","identifier":{"@type":"PropertyValue","propertyID":"rl-state","value":%q}}`,
		rlStateValue,
	)
	return fmt.Sprintf(
		`<!DOCTYPE html><html><head><script type="application/ld+json">%s</script></head><body><p>Under construction</p></body></html>`,
		jsonLD,
	)
}

// TestSendHandshake_RateLimitedByBodyMarker_CFStripsHeader — P0 regression.
// Server returns 200 + decoy body with rl-state JSON-LD marker but NO
// X-SL-RL header (CF stripped it). The old code would fall through to the
// 200-OK path and try to parse the HTML body as a JSON handshake response,
// causing sticky reconnect loop. New code must detect via BodyMarkerCarrier.
func TestSendHandshake_RateLimitedByBodyMarker_CFStripsHeader(t *testing.T) {
	// Reset counter so this test is independent of run order.
	Stats.RateLimitDetectedByBody.Store(0)
	HandshakeDecoyReceived.Store(0)

	rlValue := "v1;bucket=handshake;refill_in=12;burst_left=0;exempt=0"
	// Pad to 80 bytes as the server's SentinelEmitter does.
	if len(rlValue) < 80 {
		rlValue = rlValue + strings.Repeat(";", 80-len(rlValue))
	}
	decoyBody := makeDecoyBodyWithMarker(rlValue)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CF strips X-SL-RL — no sentinel header, only the body marker.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, decoyBody)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewDirectTransport(host, false, true)
	defer tr.Close()

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	hello, _, err := core.NewClientHello([]byte("test-client-uuid"), kp.Public)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}

	_, sendErr := tr.SendHandshake(t.Context(), hello)

	if sendErr == nil {
		t.Fatal("expected error from SendHandshake, got nil")
	}
	if !errors.Is(sendErr, ErrRateLimited) {
		t.Errorf("errors.Is(err, ErrRateLimited) = false; got: %v", sendErr)
	}

	var rlErr *RateLimitError
	if !errors.As(sendErr, &rlErr) {
		t.Fatalf("errors.As(*RateLimitError) failed; got: %v", sendErr)
	}
	if rlErr.Signal == nil {
		t.Fatal("RateLimitError.Signal is nil")
	}
	if rlErr.Signal.RefillIn.Seconds() != 12 {
		t.Errorf("Signal.RefillIn: got %v, want 12s", rlErr.Signal.RefillIn)
	}
	if rlErr.Signal.Bucket != "handshake" {
		t.Errorf("Signal.Bucket: got %q, want \"handshake\"", rlErr.Signal.Bucket)
	}
	if rlErr.Signal.Carrier != "body" {
		t.Errorf("Signal.Carrier: got %q, want \"body\"", rlErr.Signal.Carrier)
	}

	if Stats.RateLimitDetectedByBody.Load() == 0 {
		t.Error("Stats.RateLimitDetectedByBody must be non-zero after body-marker detection")
	}
	if HandshakeDecoyReceived.Load() == 0 {
		t.Error("HandshakeDecoyReceived must be non-zero after body-marker detection")
	}
}

// TestSendHandshake_RateLimitedByHeader_LegacyServer — old-server scenario.
// Server returns 200 + X-SL-RL in legacy comma format (no body marker).
// HeaderCarrier must fire as fallback in the detector chain.
func TestSendHandshake_RateLimitedByHeader_LegacyServer(t *testing.T) {
	Stats.RateLimitDetectedByHeader.Store(0)
	HandshakeDecoyReceived.Store(0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Old server wire format: comma-separated, no body marker.
		w.Header().Set("X-SL-RL", "bucket=handshake,burst_left=0,refill_in=12s,exempt=0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "<html><body>Under construction</body></html>")
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewDirectTransport(host, false, true)
	defer tr.Close()

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	hello, _, err := core.NewClientHello([]byte("test-client-uuid"), kp.Public)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}

	_, sendErr := tr.SendHandshake(t.Context(), hello)

	if sendErr == nil {
		t.Fatal("expected error from SendHandshake, got nil")
	}
	if !errors.Is(sendErr, ErrRateLimited) {
		t.Errorf("errors.Is(err, ErrRateLimited) = false; got: %v", sendErr)
	}

	var rlErr *RateLimitError
	if !errors.As(sendErr, &rlErr) {
		t.Fatalf("errors.As(*RateLimitError) failed; got: %v", sendErr)
	}
	if rlErr.Signal == nil {
		t.Fatal("RateLimitError.Signal is nil")
	}
	if rlErr.Signal.Carrier != "header_legacy" {
		t.Errorf("Signal.Carrier: got %q, want \"header_legacy\"", rlErr.Signal.Carrier)
	}
	if rlErr.Signal.Bucket != "handshake" {
		t.Errorf("Signal.Bucket: got %q, want \"handshake\"", rlErr.Signal.Bucket)
	}

	if Stats.RateLimitDetectedByHeader.Load() == 0 {
		t.Error("Stats.RateLimitDetectedByHeader must be non-zero after header detection")
	}
}

// TestSendHandshake_RateLimitedByLifeline_CFStripsEverything — worst-case P0.
// CF strips both the X-SL-RL header AND the body marker (or the decoy template
// has no marker). Body is plain HTML. Detector lifeline fires with default 90s.
func TestSendHandshake_RateLimitedByLifeline_CFStripsEverything(t *testing.T) {
	Stats.RateLimitDetectedFallback.Store(0)
	HandshakeDecoyReceived.Store(0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No header, no body marker — just a plain HTML decoy page.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "<html><body>Under construction</body></html>")
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewDirectTransport(host, false, true)
	defer tr.Close()

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	hello, _, err := core.NewClientHello([]byte("test-client-uuid"), kp.Public)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}

	_, sendErr := tr.SendHandshake(t.Context(), hello)

	if sendErr == nil {
		t.Fatal("expected error from SendHandshake (lifeline should fire on HTML body), got nil")
	}
	if !errors.Is(sendErr, ErrRateLimited) {
		t.Errorf("errors.Is(err, ErrRateLimited) = false; got: %v", sendErr)
	}

	var rlErr *RateLimitError
	if !errors.As(sendErr, &rlErr) {
		t.Fatalf("errors.As(*RateLimitError) failed; got: %v", sendErr)
	}
	if rlErr.Signal == nil {
		t.Fatal("RateLimitError.Signal is nil")
	}
	if rlErr.Signal.Carrier != "fallback" {
		t.Errorf("Signal.Carrier: got %q, want \"fallback\"", rlErr.Signal.Carrier)
	}
	if rlErr.Signal.RefillIn.Seconds() != 90 {
		t.Errorf("Signal.RefillIn: got %v, want 90s", rlErr.Signal.RefillIn)
	}

	if Stats.RateLimitDetectedFallback.Load() == 0 {
		t.Error("Stats.RateLimitDetectedFallback must be non-zero after lifeline detection")
	}
	if HandshakeDecoyReceived.Load() == 0 {
		t.Error("HandshakeDecoyReceived must be non-zero after lifeline detection")
	}
}

// TestSendHandshake_NormalResponse_NoRateLimit — happy path guard.
// A real ShadowLink server is not available in this test, so we mock a valid
// JSON analytics response body to verify the detector doesn't fire on normal
// responses and SendHandshake returns the body without error.
func TestSendHandshake_NormalResponse_NoRateLimit(t *testing.T) {
	Stats.RateLimitDetectedByBody.Store(0)
	Stats.RateLimitDetectedByHeader.Store(0)
	Stats.RateLimitDetectedFallback.Store(0)

	// Minimal valid-looking JSON body (not a real ServerHello — we just need the
	// transport to pass the RL check and reach "return respBytes, nil").
	// The test asserts no rate-limit error is returned.
	jsonBody := `{"events":[],"status":"ok","_sl":"v1"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, jsonBody)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewDirectTransport(host, false, true)
	defer tr.Close()

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	hello, _, err := core.NewClientHello([]byte("test-client-uuid"), kp.Public)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}

	body, sendErr := tr.SendHandshake(t.Context(), hello)

	// Detector must not fire — the returned error (if any) must NOT be ErrRateLimited.
	if errors.Is(sendErr, ErrRateLimited) {
		t.Errorf("ErrRateLimited must NOT fire on normal JSON response; got: %v", sendErr)
	}
	// Body should be non-nil and non-empty on success path.
	if sendErr == nil && len(body) == 0 {
		t.Error("expected non-empty body on success, got empty")
	}

	// No RL counters should tick.
	if Stats.RateLimitDetectedByBody.Load() != 0 {
		t.Errorf("RateLimitDetectedByBody ticked on normal response: %d", Stats.RateLimitDetectedByBody.Load())
	}
	if Stats.RateLimitDetectedByHeader.Load() != 0 {
		t.Errorf("RateLimitDetectedByHeader ticked on normal response: %d", Stats.RateLimitDetectedByHeader.Load())
	}
	if Stats.RateLimitDetectedFallback.Load() != 0 {
		t.Errorf("RateLimitDetectedFallback ticked on normal response: %d", Stats.RateLimitDetectedFallback.Load())
	}
}

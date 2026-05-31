package client

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- parseRLStateValue tests ----

func TestParseRLStateValue_HappyPath(t *testing.T) {
	s := "v1;bucket=ws_upgrade;refill_in=30;burst_left=5;exempt=1"
	sig := parseRLStateValue(s)
	if sig == nil {
		t.Fatal("expected non-nil signal")
	}
	if sig.Bucket != "ws_upgrade" {
		t.Errorf("Bucket: got %q, want %q", sig.Bucket, "ws_upgrade")
	}
	if sig.RefillIn != 30*time.Second {
		t.Errorf("RefillIn: got %v, want 30s", sig.RefillIn)
	}
	if sig.BurstLeft != 5 {
		t.Errorf("BurstLeft: got %d, want 5", sig.BurstLeft)
	}
	if !sig.Exempt {
		t.Error("Exempt: want true")
	}
}

func TestParseRLStateValue_BaselineReturnsNil(t *testing.T) {
	// bucket=none → baseline, not a rate-limit signal
	s := "v1;bucket=none;refill_in=0;burst_left=100;exempt=0"
	sig := parseRLStateValue(s)
	if sig != nil {
		t.Errorf("expected nil for baseline, got %+v", sig)
	}
}

func TestParseRLStateValue_PaddedString(t *testing.T) {
	// Body carrier pads to 80 chars with trailing semicolons
	core := "v1;bucket=handshake;refill_in=60;burst_left=0;exempt=0"
	padded := core + strings.Repeat(";", 80-len(core))
	sig := parseRLStateValue(padded)
	if sig == nil {
		t.Fatal("expected non-nil signal for padded string")
	}
	if sig.Bucket != "handshake" {
		t.Errorf("Bucket: got %q, want %q", sig.Bucket, "handshake")
	}
	if sig.RefillIn != 60*time.Second {
		t.Errorf("RefillIn: got %v, want 60s", sig.RefillIn)
	}
	if sig.BurstLeft != 0 {
		t.Errorf("BurstLeft: got %d, want 0", sig.BurstLeft)
	}
}

func TestParseRLStateValue_InvalidVersion(t *testing.T) {
	cases := []string{
		"v2;bucket=data;refill_in=10;burst_left=3;exempt=0",
		"bucket=data;refill_in=10;burst_left=3;exempt=0", // no version token
		"",
		";;;",
	}
	for _, c := range cases {
		if sig := parseRLStateValue(c); sig != nil {
			t.Errorf("expected nil for %q, got %+v", c, sig)
		}
	}
}

// ---- parseRLStateLegacyHeader tests ----

func TestParseRLStateLegacyHeader_HappyPath(t *testing.T) {
	// Wire format from writeRateLimitSentinelV2
	s := "bucket=ws_upgrade,burst_left=3,refill_in=45s,exempt=0"
	sig := parseRLStateLegacyHeader(s)
	if sig == nil {
		t.Fatal("expected non-nil signal")
	}
	if sig.Bucket != "ws_upgrade" {
		t.Errorf("Bucket: got %q, want %q", sig.Bucket, "ws_upgrade")
	}
	if sig.BurstLeft != 3 {
		t.Errorf("BurstLeft: got %d, want 3", sig.BurstLeft)
	}
	if sig.RefillIn != 45*time.Second {
		t.Errorf("RefillIn: got %v, want 45s", sig.RefillIn)
	}
	if sig.Exempt {
		t.Error("Exempt: want false")
	}
}

func TestParseRLStateLegacyHeader_MissingFields(t *testing.T) {
	cases := []string{
		"",                        // empty
		"burst_left=3,refill_in=5s,exempt=0", // no bucket
		"bucket=none,burst_left=3,refill_in=5s,exempt=0", // bucket=none
	}
	for _, c := range cases {
		if sig := parseRLStateLegacyHeader(c); sig != nil {
			t.Errorf("expected nil for %q, got %+v", c, sig)
		}
	}
}

// ---- BodyMarkerCarrier tests ----

func makeBodyWithMarker(value string) []byte {
	json := fmt.Sprintf(`{"@context":"https://schema.org","@type":"WebSite","identifier":{"@type":"PropertyValue","propertyID":"rl-state","value":%q}}`, value)
	html := fmt.Sprintf(`<!DOCTYPE html><html><head><script type="application/ld+json">%s</script></head><body></body></html>`, json)
	return []byte(html)
}

func TestBodyMarkerCarrier_Detect_HappyPath(t *testing.T) {
	value := "v1;bucket=data;refill_in=20;burst_left=2;exempt=0"
	// Pad to 80 bytes as server would
	if len(value) < 80 {
		value = value + strings.Repeat(";", 80-len(value))
	}
	body := makeBodyWithMarker(value)
	ctx := &DetectionContext{BodyHead: body}
	sig := BodyMarkerCarrier{}.Detect(ctx)
	if sig == nil {
		t.Fatal("expected non-nil signal")
	}
	if sig.Bucket != "data" {
		t.Errorf("Bucket: got %q, want %q", sig.Bucket, "data")
	}
	if sig.RefillIn != 20*time.Second {
		t.Errorf("RefillIn: got %v, want 20s", sig.RefillIn)
	}
	if sig.BurstLeft != 2 {
		t.Errorf("BurstLeft: got %d, want 2", sig.BurstLeft)
	}
}

func TestBodyMarkerCarrier_Detect_BaselineReturnsNil(t *testing.T) {
	// bucket=none baseline: carrier should NOT fire
	value := "v1;bucket=none;refill_in=0;burst_left=100;exempt=0"
	if len(value) < 80 {
		value = value + strings.Repeat(";", 80-len(value))
	}
	body := makeBodyWithMarker(value)
	ctx := &DetectionContext{BodyHead: body}
	sig := BodyMarkerCarrier{}.Detect(ctx)
	if sig != nil {
		t.Errorf("expected nil for baseline, got %+v", sig)
	}
}

func TestBodyMarkerCarrier_Detect_WrongPropertyID(t *testing.T) {
	// propertyID=ISBN — not rl-state, should be ignored
	json := `{"@context":"https://schema.org","@type":"Book","identifier":{"@type":"PropertyValue","propertyID":"ISBN","value":"978-3-16-148410-0"}}`
	html := fmt.Sprintf(`<!DOCTYPE html><html><head><script type="application/ld+json">%s</script></head></html>`, json)
	ctx := &DetectionContext{BodyHead: []byte(html)}
	sig := BodyMarkerCarrier{}.Detect(ctx)
	if sig != nil {
		t.Errorf("expected nil for wrong propertyID, got %+v", sig)
	}
}

// ---- HeaderCarrier tests ----

func makeResponseWithHeader(key, val string) *http.Response {
	resp := &http.Response{Header: make(http.Header)}
	if val != "" {
		resp.Header.Set(key, val)
	}
	return resp
}

func TestHeaderCarrier_Detect_NewFormat(t *testing.T) {
	v := "v1;bucket=handshake;refill_in=15;burst_left=10;exempt=0"
	ctx := &DetectionContext{Response: makeResponseWithHeader("X-SL-RL", v)}
	sig := HeaderCarrier{}.Detect(ctx)
	if sig == nil {
		t.Fatal("expected non-nil signal")
	}
	if sig.Carrier != "header_v1" {
		t.Errorf("Carrier: got %q, want header_v1", sig.Carrier)
	}
	if sig.Bucket != "handshake" {
		t.Errorf("Bucket: got %q, want handshake", sig.Bucket)
	}
	if sig.RefillIn != 15*time.Second {
		t.Errorf("RefillIn: got %v, want 15s", sig.RefillIn)
	}
}

func TestHeaderCarrier_Detect_LegacyFormat(t *testing.T) {
	v := "bucket=ws_upgrade,burst_left=7,refill_in=30s,exempt=1"
	ctx := &DetectionContext{Response: makeResponseWithHeader("X-SL-RL", v)}
	sig := HeaderCarrier{}.Detect(ctx)
	if sig == nil {
		t.Fatal("expected non-nil signal")
	}
	if sig.Carrier != "header_legacy" {
		t.Errorf("Carrier: got %q, want header_legacy", sig.Carrier)
	}
	if sig.Bucket != "ws_upgrade" {
		t.Errorf("Bucket: got %q, want ws_upgrade", sig.Bucket)
	}
	if sig.BurstLeft != 7 {
		t.Errorf("BurstLeft: got %d, want 7", sig.BurstLeft)
	}
	if !sig.Exempt {
		t.Error("Exempt: want true")
	}
}

func TestHeaderCarrier_Detect_NoHeader(t *testing.T) {
	ctx := &DetectionContext{Response: makeResponseWithHeader("X-SL-RL", "")}
	sig := HeaderCarrier{}.Detect(ctx)
	if sig != nil {
		t.Errorf("expected nil with empty header, got %+v", sig)
	}

	// Also test nil response
	ctx2 := &DetectionContext{Response: nil}
	sig2 := HeaderCarrier{}.Detect(ctx2)
	if sig2 != nil {
		t.Errorf("expected nil with nil response, got %+v", sig2)
	}
}

// ---- RateLimitDetector tests ----

func newTestDetector() (*RateLimitDetector, *atomic.Uint64, *atomic.Uint64) {
	byBody := new(atomic.Uint64)
	byHeader := new(atomic.Uint64)
	d := &RateLimitDetector{
		carriers: []RateLimitCarrier{
			BodyMarkerCarrier{},
			HeaderCarrier{},
		},
		DetectedByBody:   byBody,
		DetectedByHeader: byHeader,
	}
	return d, byBody, byHeader
}

func TestRateLimitDetector_BodyWins(t *testing.T) {
	// Both body marker and X-SL-RL header present — body should win (first in chain)
	value := "v1;bucket=ws_upgrade;refill_in=30;burst_left=5;exempt=0"
	if len(value) < 80 {
		value = value + strings.Repeat(";", 80-len(value))
	}
	body := makeBodyWithMarker(value)

	resp := makeResponseWithHeader("X-SL-RL", "v1;bucket=handshake;refill_in=10;burst_left=1;exempt=0")
	ctx := &DetectionContext{Response: resp, BodyHead: body}

	d, byBody, byHeader := newTestDetector()
	sig := d.DetectCarriersOnly(ctx)
	if sig == nil {
		t.Fatal("expected signal")
	}
	if sig.Carrier != "body" {
		t.Errorf("Carrier: got %q, want body", sig.Carrier)
	}
	if sig.Bucket != "ws_upgrade" {
		t.Errorf("Bucket: got %q (body), want ws_upgrade", sig.Bucket)
	}
	if byBody.Load() != 1 {
		t.Errorf("DetectedByBody counter: got %d, want 1", byBody.Load())
	}
	if byHeader.Load() != 0 {
		t.Errorf("DetectedByHeader counter: got %d, want 0", byHeader.Load())
	}
}

func TestRateLimitDetector_HeaderFallback(t *testing.T) {
	// No body marker, but X-SL-RL header present
	ctx := &DetectionContext{
		Response: makeResponseWithHeader("X-SL-RL", "v1;bucket=data;refill_in=60;burst_left=0;exempt=0"),
		BodyHead: []byte(`{"status":"ok"}`), // JSON body — no HTML, no body marker
	}

	d, byBody, byHeader := newTestDetector()
	sig := d.DetectCarriersOnly(ctx)
	if sig == nil {
		t.Fatal("expected signal")
	}
	if sig.Carrier != "header_v1" {
		t.Errorf("Carrier: got %q, want header_v1", sig.Carrier)
	}
	if sig.Bucket != "data" {
		t.Errorf("Bucket: got %q, want data", sig.Bucket)
	}
	if byBody.Load() != 0 {
		t.Errorf("DetectedByBody: got %d, want 0", byBody.Load())
	}
	if byHeader.Load() != 1 {
		t.Errorf("DetectedByHeader: got %d, want 1", byHeader.Load())
	}
}

func TestRateLimitDetector_NotRateLimited(t *testing.T) {
	// Plain JSON response with no RL signals → nil
	resp := &http.Response{Header: make(http.Header)}
	ctx := &DetectionContext{
		Response: resp,
		BodyHead: []byte(`{"events":[],"status":"ok"}`),
	}
	d, byBody, byHeader := newTestDetector()
	sig := d.DetectCarriersOnly(ctx)
	if sig != nil {
		t.Errorf("expected nil, got %+v", sig)
	}
	if byBody.Load() != 0 || byHeader.Load() != 0 {
		t.Error("no counters should be incremented for non-RL response")
	}
}

// ---- RateLimitError tests ----

func TestRateLimitError_ErrorsIs(t *testing.T) {
	err := &RateLimitError{Signal: &RateLimitSignal{Bucket: "data", Carrier: "header_v1"}}
	if !errors.Is(err, ErrRateLimited) {
		t.Error("errors.Is(err, ErrRateLimited) should return true")
	}
	// Wrapping in fmt.Errorf should still work
	wrapped := fmt.Errorf("transport error: %w", err)
	if !errors.Is(wrapped, ErrRateLimited) {
		t.Error("errors.Is on wrapped error should return true")
	}
}

func TestRateLimitError_ErrorsAs(t *testing.T) {
	sig := &RateLimitSignal{Bucket: "ws_upgrade", Carrier: "body", RefillIn: 30 * time.Second}
	orig := &RateLimitError{Signal: sig}
	wrapped := fmt.Errorf("dial failed: %w", orig)

	var rlerr *RateLimitError
	if !errors.As(wrapped, &rlerr) {
		t.Fatal("errors.As should find *RateLimitError")
	}
	if rlerr.Signal == nil {
		t.Fatal("extracted Signal should not be nil")
	}
	if rlerr.Signal.Bucket != "ws_upgrade" {
		t.Errorf("Bucket: got %q, want ws_upgrade", rlerr.Signal.Bucket)
	}
	if rlerr.Signal.RefillIn != 30*time.Second {
		t.Errorf("RefillIn: got %v, want 30s", rlerr.Signal.RefillIn)
	}
}

func TestRateLimitError_NilSignal(t *testing.T) {
	err := &RateLimitError{Signal: nil}
	if err.Error() != "rate limited (no signal)" {
		t.Errorf("unexpected error string: %q", err.Error())
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Error("errors.Is should still work with nil Signal")
	}
}

// ---- Per-path counter tests (Phase 2, 2026-05-14) ----

// newTestDetectorWithStats creates a detector wired to a real statsRegistry
// so per-path counter increments can be verified.
func newTestDetectorWithStats() (*RateLimitDetector, *statsRegistry) {
	stats := &statsRegistry{}
	d := &RateLimitDetector{
		carriers: []RateLimitCarrier{
			BodyMarkerCarrier{},
			HeaderCarrier{},
		},
		DetectedByBody:   &stats.RateLimitDetectedByBody,
		DetectedByHeader: &stats.RateLimitDetectedByHeader,
		metrics:          stats,
	}
	return d, stats
}

func TestRateLimitDetector_PerPathCounters_BodyHandshake(t *testing.T) {
	// Body marker + Path="handshake" → aggregate +1 AND _Handshake +1, _WS stays 0.
	value := "v1;bucket=handshake;refill_in=30;burst_left=5;exempt=0"
	if len(value) < 80 {
		value = value + strings.Repeat(";", 80-len(value))
	}
	body := makeBodyWithMarker(value)
	d, stats := newTestDetectorWithStats()

	ctx := &DetectionContext{BodyHead: body, Path: "handshake"}
	sig := d.DetectCarriersOnly(ctx)
	if sig == nil {
		t.Fatal("expected signal")
	}
	if stats.RateLimitDetectedByBody.Load() != 1 {
		t.Errorf("aggregate body counter: got %d, want 1", stats.RateLimitDetectedByBody.Load())
	}
	if stats.RateLimitDetectedByBody_Handshake.Load() != 1 {
		t.Errorf("body_Handshake counter: got %d, want 1", stats.RateLimitDetectedByBody_Handshake.Load())
	}
	if stats.RateLimitDetectedByBody_WS.Load() != 0 {
		t.Errorf("body_WS counter: got %d, want 0", stats.RateLimitDetectedByBody_WS.Load())
	}
}

func TestRateLimitDetector_PerPathCounters_BodyWS(t *testing.T) {
	// Body marker + Path="ws_upgrade" → aggregate +1 AND _WS +1, _Handshake stays 0.
	value := "v1;bucket=ws_upgrade;refill_in=30;burst_left=5;exempt=0"
	if len(value) < 80 {
		value = value + strings.Repeat(";", 80-len(value))
	}
	body := makeBodyWithMarker(value)
	d, stats := newTestDetectorWithStats()

	ctx := &DetectionContext{BodyHead: body, Path: "ws_upgrade"}
	sig := d.DetectCarriersOnly(ctx)
	if sig == nil {
		t.Fatal("expected signal")
	}
	if stats.RateLimitDetectedByBody.Load() != 1 {
		t.Errorf("aggregate body counter: got %d, want 1", stats.RateLimitDetectedByBody.Load())
	}
	if stats.RateLimitDetectedByBody_WS.Load() != 1 {
		t.Errorf("body_WS counter: got %d, want 1", stats.RateLimitDetectedByBody_WS.Load())
	}
	if stats.RateLimitDetectedByBody_Handshake.Load() != 0 {
		t.Errorf("body_Handshake counter: got %d, want 0", stats.RateLimitDetectedByBody_Handshake.Load())
	}
}

func TestRateLimitDetector_PerPathCounters_HeaderHandshake(t *testing.T) {
	// Header carrier + Path="handshake" → aggregate +1 AND _Handshake +1, _WS stays 0.
	resp := makeResponseWithHeader("X-SL-RL", "v1;bucket=handshake;refill_in=15;burst_left=10;exempt=0")
	d, stats := newTestDetectorWithStats()

	ctx := &DetectionContext{Response: resp, BodyHead: []byte(`{"ok":true}`), Path: "handshake"}
	sig := d.DetectCarriersOnly(ctx)
	if sig == nil {
		t.Fatal("expected signal")
	}
	if stats.RateLimitDetectedByHeader.Load() != 1 {
		t.Errorf("aggregate header counter: got %d, want 1", stats.RateLimitDetectedByHeader.Load())
	}
	if stats.RateLimitDetectedByHeader_Handshake.Load() != 1 {
		t.Errorf("header_Handshake counter: got %d, want 1", stats.RateLimitDetectedByHeader_Handshake.Load())
	}
	if stats.RateLimitDetectedByHeader_WS.Load() != 0 {
		t.Errorf("header_WS counter: got %d, want 0", stats.RateLimitDetectedByHeader_WS.Load())
	}
}

func TestRateLimitDetector_PerPathCounters_HeaderWS(t *testing.T) {
	// Header carrier + Path="ws_upgrade" via DetectCarriersOnly → _WS +1, _Handshake stays 0.
	resp := makeResponseWithHeader("X-SL-RL", "v1;bucket=ws_upgrade;refill_in=30;burst_left=0;exempt=0")
	d, stats := newTestDetectorWithStats()

	ctx := &DetectionContext{Response: resp, BodyHead: []byte(`{"ok":true}`), Path: "ws_upgrade"}
	sig := d.DetectCarriersOnly(ctx)
	if sig == nil {
		t.Fatal("expected signal")
	}
	if stats.RateLimitDetectedByHeader.Load() != 1 {
		t.Errorf("aggregate header counter: got %d, want 1", stats.RateLimitDetectedByHeader.Load())
	}
	if stats.RateLimitDetectedByHeader_WS.Load() != 1 {
		t.Errorf("header_WS counter: got %d, want 1", stats.RateLimitDetectedByHeader_WS.Load())
	}
	if stats.RateLimitDetectedByHeader_Handshake.Load() != 0 {
		t.Errorf("header_Handshake counter: got %d, want 0", stats.RateLimitDetectedByHeader_Handshake.Load())
	}
}

func TestRateLimitDetector_PerPathCounters_EmptyPath_AggregateOnly(t *testing.T) {
	// Empty path (back-compat / test mode via newTestDetector) — aggregate ticks,
	// per-path counters do NOT increment (metrics=nil in newTestDetector).
	ctx := &DetectionContext{
		Response: makeResponseWithHeader("X-SL-RL", "v1;bucket=data;refill_in=60;burst_left=0;exempt=0"),
		BodyHead: []byte(`{"ok":true}`),
		// Path intentionally omitted
	}
	d, byBody, byHeader := newTestDetector()
	sig := d.DetectCarriersOnly(ctx)
	if sig == nil {
		t.Fatal("expected signal")
	}
	if byHeader.Load() != 1 {
		t.Errorf("aggregate header counter: got %d, want 1", byHeader.Load())
	}
	if byBody.Load() != 0 {
		t.Errorf("body counter: got %d, want 0", byBody.Load())
	}
	// Per-path counters: d.metrics is nil → no increment possible; test just
	// verifies no panic occurs with metrics=nil.
}

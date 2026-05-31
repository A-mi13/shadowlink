package client

import (
	"net/http"
	"testing"
)

// TestHandshakeDecoy_PlainDecoyIsNotRateLimit is the regression test for the
// lifeline false-positive bug (2026-05-29).
//
// Field evidence: the pl1 server's metrics showed ratelimit_burst_rejected_*=0
// and ratelimit_sentinel_emitted=0 for 14.6h of uptime, yet the client applied
// 48 fallback rate-limit cooldowns (bucket=unknown_via_fallback, 90s each) in a
// single session. Server logs showed the real cause: `decoy served
// reason=max_clients` — a PLAIN decoy with no X-SL-RL header and no Schema.org
// body marker. The old handshake path ran Detect() (with the HTML lifeline),
// which fired on any markerless HTML body and mislabelled it as rate-limited.
//
// Architectural fix: the handshake path must use the same marker-only detection
// the WS path already uses (DetectCarriersOnly, no lifeline). A genuine
// rate-limit decoy carries an explicit marker (X-SL-RL header OR body
// bucket=...); a plain decoy carries neither and must surface as a normal
// network error, not a 90s self-imposed cooldown.
//
// This test pins the contract at the detector layer: DetectCarriersOnly on a
// plain HTML decoy returns nil.
func TestHandshakeDecoy_PlainDecoyIsNotRateLimit(t *testing.T) {
	// A plain decoy page exactly as failClosedToDecoyWithReason emits it for
	// max_clients / protocol_unknown / auth_fail: real HTML, NO X-SL-RL header,
	// NO Schema.org rl-state marker.
	plainDecoy := []byte(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Crest Technologies</title></head>
<body><h1>Welcome</h1></body></html>`)
	resp := &http.Response{Header: make(http.Header)} // no X-SL-RL

	ctx := &DetectionContext{
		Response: resp,
		BodyHead: plainDecoy,
		Path:     "handshake",
	}

	d, byBody, byHeader := newTestDetector()

	sig := d.DetectCarriersOnly(ctx)
	if sig != nil {
		t.Fatalf("plain decoy must NOT be classified as rate-limit, got %+v "+
			"(this is the lifeline false-positive bug)", sig)
	}
	if byBody.Load() != 0 || byHeader.Load() != 0 {
		t.Errorf("no carrier should match a plain decoy, got body=%d header=%d",
			byBody.Load(), byHeader.Load())
	}
}

// TestHandshakeDecoy_RealRateLimitStillDetected guards the other side: a genuine
// rate-limit decoy (explicit X-SL-RL header) MUST still be detected on the
// handshake path after the lifeline is dropped. Removing the lifeline must not
// blind us to real server-directed rate-limiting.
func TestHandshakeDecoy_RealRateLimitStillDetected(t *testing.T) {
	resp := makeResponseWithHeader("X-SL-RL", "v1;bucket=handshake;refill_in=30;burst_left=0;exempt=0")
	ctx := &DetectionContext{
		Response: resp,
		BodyHead: []byte(`<!DOCTYPE html><html><body>ok</body></html>`),
		Path:     "handshake",
	}

	d, _, byHeader := newTestDetector()

	sig := d.DetectCarriersOnly(ctx)
	if sig == nil {
		t.Fatal("a real rate-limit decoy (X-SL-RL present) must still be detected")
	}
	if sig.Bucket != "handshake" {
		t.Errorf("Bucket: got %q, want handshake", sig.Bucket)
	}
	if byHeader.Load() != 1 {
		t.Errorf("DetectedByHeader: got %d, want 1", byHeader.Load())
	}
}

package client

// P0 regression suite — 2026-05-14 production incident: sticky reconnect loop
// when Cloudflare strips X-SL-RL header.
//
// # Failure chain (production, 2026-05-14)
//
//  1. Client sends handshake POST → server rate-limiter fires
//  2. Server emits HTTP 200 + X-SL-RL header + HTML decoy body
//  3. Cloudflare strips X-SL-RL (non-standard header policy)
//  4. Client receives 200 + HTML body, no X-SL-RL header
//  5. Old code: `respBytes[0] == '<'` → "HTML instead of JSON" (generic error)
//  6. reconnectLoop: generic error → exponential backoff, attempt grows 1,2,4,8…
//  7. Each retry hits the same wall → attempt=21 in production log, 60s cap
//
// # Fix chain
//   - Phase 1 (server):   emits body marker in Schema.org JSON-LD identifier
//   - Phase 2.1:          RateLimitDetector + carrier interfaces
//   - Phase 2.2 (client): detector reads body marker FIRST, header SECOND,
//     lifeline (90s default) THIRD — even if CF strips both
//
// Tests below are end-to-end: each drives the full SendHandshake path via an
// httptest.Server, not just the detector unit logic. The four scenarios are
// named after the exact production failure mode they guard against.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/core"
)

// p0FixtureStrings holds the hard-coded 80-byte wire-format strings used as
// test fixtures. init() below verifies each is exactly 80 bytes.
//
// Format: v1;bucket=<bucket>;refill_in=<secs>;burst_left=<n>;exempt=<0|1>[;…padding]
// Server pads with trailing ';' to exactly 80 bytes so CDN can't correlate on
// length variation. Client parser ignores empty entries between ';;'.
var p0FixtureStrings = struct {
	HandshakeRLState string // bucket=handshake, refill_in=12
	HeaderV1State    string // for X-SL-RL new-format header
}{
	// "v1;bucket=handshake;refill_in=12;burst_left=0;exempt=0" = 54 bytes → pad 26 semicolons
	HandshakeRLState: "v1;bucket=handshake;refill_in=12;burst_left=0;exempt=0;;;;;;;;;;;;;;;;;;;;;;;;;;",
	// Header V1 uses same format, sent as header value (no padding needed but pad anyway)
	HeaderV1State: "v1;bucket=handshake;refill_in=12;burst_left=0;exempt=0;;;;;;;;;;;;;;;;;;;;;;;;;;",
}

func init() {
	// Verify fixture strings are exactly 80 bytes — catches drift from format changes.
	if n := len(p0FixtureStrings.HandshakeRLState); n != 80 {
		panic(fmt.Sprintf("p0 fixture HandshakeRLState must be 80 bytes, got %d", n))
	}
	if n := len(p0FixtureStrings.HeaderV1State); n != 80 {
		panic(fmt.Sprintf("p0 fixture HeaderV1State must be 80 bytes, got %d", n))
	}
}

// makeP0DecoyBody returns a Schema.org JSON-LD HTML page embedding rlStateValue
// in the identifier.value field — mirrors Phase 1 server SentinelEmitter output.
func makeP0DecoyBody(rlStateValue string) string {
	jsonLD := fmt.Sprintf(
		`{"@context":"https://schema.org","@type":"WebSite","identifier":{"@type":"PropertyValue","propertyID":"rl-state","value":%q}}`,
		rlStateValue,
	)
	return fmt.Sprintf(
		`<!DOCTYPE html><html><head><script type="application/ld+json">%s</script></head><body><p>Service temporarily unavailable</p></body></html>`,
		jsonLD,
	)
}

// makeP0Transport returns a DirectTransport connected to the given httptest server URL.
func makeP0Transport(t *testing.T, srvURL string) *DirectTransport {
	t.Helper()
	host := strings.TrimPrefix(srvURL, "http://")
	tr := NewDirectTransport(host, false, true)
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// makeP0Hello generates a minimal ClientHello for testing — key exchange is
// not exercised (server returns decoy before reading body), but SendHandshake
// requires a valid struct.
func makeP0Hello(t *testing.T) *core.ClientHello {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	hello, _, err := core.NewClientHello([]byte("p0-reg-test-uuid"), kp.Public)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}
	return hello
}

// TestP0Regression_BodyMarkerSurvivesCFHeaderStrip is the PRIMARY scenario of
// the 2026-05-14 production P0 bug:
//
//   - Server emits 200 + Schema.org JSON-LD body marker (Phase 1 fix)
//   - CF strips X-SL-RL header (production condition)
//   - Client MUST detect via BodyMarkerCarrier and return *RateLimitError
//
// Before the fix: client saw HTML body, returned generic "HTML instead of JSON"
// error, reconnectLoop ran exponential backoff → attempt=21 in production log.
// After the fix: BodyMarkerCarrier fires → typed ErrRateLimited → fixed cooldown.
func TestP0Regression_BodyMarkerSurvivesCFHeaderStrip(t *testing.T) {
	Stats.RateLimitDetectedByBody.Store(0)
	HandshakeDecoyReceived.Store(0)

	decoyBody := makeP0DecoyBody(p0FixtureStrings.HandshakeRLState)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CF stripped X-SL-RL — deliberately omitted to reproduce production condition.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, decoyBody)
	}))
	defer srv.Close()

	tr := makeP0Transport(t, srv.URL)
	hello := makeP0Hello(t)

	_, sendErr := tr.SendHandshake(t.Context(), hello)

	if sendErr == nil {
		t.Fatal("expected ErrRateLimited from SendHandshake, got nil")
	}
	if !errors.Is(sendErr, ErrRateLimited) {
		t.Errorf("errors.Is(err, ErrRateLimited) = false; want true; got: %v", sendErr)
	}

	var rlErr *RateLimitError
	if !errors.As(sendErr, &rlErr) {
		t.Fatalf("errors.As(*RateLimitError) failed; got: %T %v", sendErr, sendErr)
	}
	if rlErr.Signal == nil {
		t.Fatal("RateLimitError.Signal must not be nil")
	}
	if rlErr.Signal.Bucket != "handshake" {
		t.Errorf("Signal.Bucket: got %q, want %q", rlErr.Signal.Bucket, "handshake")
	}
	if rlErr.Signal.RefillIn.Seconds() != 12 {
		t.Errorf("Signal.RefillIn: got %v, want 12s", rlErr.Signal.RefillIn)
	}
	if rlErr.Signal.Carrier != "body" {
		t.Errorf("Signal.Carrier: got %q, want %q", rlErr.Signal.Carrier, "body")
	}
	if Stats.RateLimitDetectedByBody.Load() == 0 {
		t.Error("Stats.RateLimitDetectedByBody must be non-zero after body-marker detection")
	}
	if HandshakeDecoyReceived.Load() == 0 {
		t.Error("HandshakeDecoyReceived must be non-zero after body-marker detection")
	}
}

// TestP0Regression_HeaderFallbackWhenBodyAbsent tests backwards compatibility
// with pre-Phase-1 servers: only X-SL-RL header (new v1 semicolon format),
// no Schema.org body marker. HeaderCarrier must fire as second carrier in chain.
func TestP0Regression_HeaderFallbackWhenBodyAbsent(t *testing.T) {
	Stats.RateLimitDetectedByHeader.Store(0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pre-Phase-1 server: X-SL-RL header, plain HTML body (no JSON-LD marker).
		w.Header().Set("X-SL-RL", p0FixtureStrings.HeaderV1State)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "<html><body>Service unavailable</body></html>")
	}))
	defer srv.Close()

	tr := makeP0Transport(t, srv.URL)
	hello := makeP0Hello(t)

	_, sendErr := tr.SendHandshake(t.Context(), hello)

	if sendErr == nil {
		t.Fatal("expected ErrRateLimited from SendHandshake, got nil")
	}
	if !errors.Is(sendErr, ErrRateLimited) {
		t.Errorf("errors.Is(err, ErrRateLimited) = false; got: %v", sendErr)
	}

	var rlErr *RateLimitError
	if !errors.As(sendErr, &rlErr) {
		t.Fatalf("errors.As(*RateLimitError) failed; got: %v", sendErr)
	}
	if rlErr.Signal == nil {
		t.Fatal("RateLimitError.Signal must not be nil")
	}
	if rlErr.Signal.Carrier != "header_v1" {
		t.Errorf("Signal.Carrier: got %q, want %q", rlErr.Signal.Carrier, "header_v1")
	}
	if rlErr.Signal.Bucket != "handshake" {
		t.Errorf("Signal.Bucket: got %q, want %q", rlErr.Signal.Bucket, "handshake")
	}
	if rlErr.Signal.RefillIn.Seconds() != 12 {
		t.Errorf("Signal.RefillIn: got %v, want 12s", rlErr.Signal.RefillIn)
	}
	if Stats.RateLimitDetectedByHeader.Load() == 0 {
		t.Error("Stats.RateLimitDetectedByHeader must be non-zero after header detection")
	}
}

// TestP0Regression_LegacyHeaderFormat tests backwards compatibility with the
// oldest server format: comma-separated X-SL-RL (pre-v1 semicolon format).
// Servers deployed before Phase 1 used this format. HeaderCarrier's legacy
// branch must parse it and set Carrier="header_legacy".
func TestP0Regression_LegacyHeaderFormat(t *testing.T) {
	Stats.RateLimitDetectedByHeader.Store(0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Oldest wire format: comma-separated, refill_in has "s" suffix.
		w.Header().Set("X-SL-RL", "bucket=handshake,burst_left=0,refill_in=12s,exempt=0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "<html><body>Service unavailable</body></html>")
	}))
	defer srv.Close()

	tr := makeP0Transport(t, srv.URL)
	hello := makeP0Hello(t)

	_, sendErr := tr.SendHandshake(t.Context(), hello)

	if sendErr == nil {
		t.Fatal("expected ErrRateLimited from SendHandshake, got nil")
	}
	if !errors.Is(sendErr, ErrRateLimited) {
		t.Errorf("errors.Is(err, ErrRateLimited) = false; got: %v", sendErr)
	}

	var rlErr *RateLimitError
	if !errors.As(sendErr, &rlErr) {
		t.Fatalf("errors.As(*RateLimitError) failed; got: %v", sendErr)
	}
	if rlErr.Signal == nil {
		t.Fatal("RateLimitError.Signal must not be nil")
	}
	if rlErr.Signal.Carrier != "header_legacy" {
		t.Errorf("Signal.Carrier: got %q, want %q", rlErr.Signal.Carrier, "header_legacy")
	}
	if rlErr.Signal.Bucket != "handshake" {
		t.Errorf("Signal.Bucket: got %q, want %q", rlErr.Signal.Bucket, "handshake")
	}
	if rlErr.Signal.RefillIn.Seconds() != 12 {
		t.Errorf("Signal.RefillIn: got %v, want 12s", rlErr.Signal.RefillIn)
	}
	if Stats.RateLimitDetectedByHeader.Load() == 0 {
		t.Error("Stats.RateLimitDetectedByHeader must be non-zero after legacy header detection")
	}
}

// TestP0Regression_LifelineWhenEverythingStripped is the APOCALYPTIC scenario:
// CF strips BOTH X-SL-RL AND the body marker. Body is plain HTML decoy without
// Schema.org JSON-LD. Lifeline activates: 90s default cooldown, bucket=unknown_via_fallback.
//
// This is the worst-case safety net. Even if the Phase 1 body marker and the
// header are both gone, the client must NOT fall through to exponential backoff
// and must NOT interpret this as a normal error that grows the attempt counter.
func TestP0Regression_LifelineWhenEverythingStripped(t *testing.T) {
	Stats.RateLimitDetectedFallback.Store(0)
	HandshakeDecoyReceived.Store(0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CF strips everything. Client sees 200 + HTML with no rate-limit signal.
		// Could also be a JSON-LD page with unrelated schema (e.g. ProductPage).
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><head>
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"Product","name":"Widget","offers":{"@type":"Offer","price":"9.99"}}
</script>
</head><body><p>Product page — not a rate-limit response</p></body></html>`)
	}))
	defer srv.Close()

	tr := makeP0Transport(t, srv.URL)
	hello := makeP0Hello(t)

	_, sendErr := tr.SendHandshake(t.Context(), hello)

	if sendErr == nil {
		t.Fatal("expected ErrRateLimited from SendHandshake (lifeline must fire on HTML body), got nil")
	}
	if !errors.Is(sendErr, ErrRateLimited) {
		t.Errorf("errors.Is(err, ErrRateLimited) = false; want true; got: %v", sendErr)
	}

	var rlErr *RateLimitError
	if !errors.As(sendErr, &rlErr) {
		t.Fatalf("errors.As(*RateLimitError) failed; got: %v", sendErr)
	}
	if rlErr.Signal == nil {
		t.Fatal("RateLimitError.Signal must not be nil")
	}
	if rlErr.Signal.Carrier != "fallback" {
		t.Errorf("Signal.Carrier: got %q, want %q", rlErr.Signal.Carrier, "fallback")
	}
	if rlErr.Signal.Bucket != "unknown_via_fallback" {
		t.Errorf("Signal.Bucket: got %q, want %q", rlErr.Signal.Bucket, "unknown_via_fallback")
	}
	if rlErr.Signal.RefillIn.Seconds() != 90 {
		t.Errorf("Signal.RefillIn: got %v, want 90s (lifeline default)", rlErr.Signal.RefillIn)
	}
	if Stats.RateLimitDetectedFallback.Load() == 0 {
		t.Error("Stats.RateLimitDetectedFallback must be non-zero after lifeline detection")
	}
	if HandshakeDecoyReceived.Load() == 0 {
		t.Error("HandshakeDecoyReceived must be non-zero — lifeline fires on HTML decoy")
	}
}

// TestP0Regression_ErrRateLimitedWrapChain asserts the error type contract
// that the reconnectLoop depends on: *RateLimitError must satisfy errors.Is
// with ErrRateLimited even when wrapped through fmt.Errorf(%w). This is what
// lets reconnectLoop detect the typed sentinel after it bubbles through
// transport layers — the production attempt=21 loop was caused by this path
// NOT returning the typed sentinel, falling through to exponential backoff.
func TestP0Regression_ErrRateLimitedWrapChain(t *testing.T) {
	for _, carrier := range []string{"body", "header_v1", "header_legacy", "fallback"} {
		t.Run("carrier="+carrier, func(t *testing.T) {
			sig := &RateLimitSignal{Bucket: "handshake", Carrier: carrier}
			inner := &RateLimitError{Signal: sig}

			// Simulate multi-level wrapping as transport.go + client.go do it.
			wrapped1 := fmt.Errorf("transport layer: %w", inner)
			wrapped2 := fmt.Errorf("client layer: %w", wrapped1)

			if !errors.Is(wrapped2, ErrRateLimited) {
				t.Errorf("carrier=%s: errors.Is must find ErrRateLimited through two wrap levels", carrier)
			}
			var rlErr *RateLimitError
			if !errors.As(wrapped2, &rlErr) {
				t.Errorf("carrier=%s: errors.As must find *RateLimitError through two wrap levels", carrier)
			}
			if rlErr != nil && rlErr.Signal.Carrier != carrier {
				t.Errorf("carrier=%s: extracted carrier mismatch: got %q", carrier, rlErr.Signal.Carrier)
			}
		})
	}
}

// NOTE: Test 5 (TestP0Regression_NoAttemptCounterGrowth) is intentionally NOT
// implemented in this file. The reconnectLoop integration test is already
// covered by TestReconnectLoop_AppliesCooldownOnRateLimit in
// ratelimit_sentinel_test.go — that test uses the connectSlotForTest hook to
// drive a rate-limit hit and asserts that (a) cooldown fires exactly once and
// (b) exponential backoff is bypassed. Adding a duplicate here would require
// touching the same test hooks and produce zero new coverage. The structural
// proof that attempt=21 is impossible lives in:
//   - TestSlotRateLimitedCooldown_RangeIsFixed (cooldown ≥ 126s > 60s backoff cap)
//   - TestReconnectLoop_AppliesCooldownOnRateLimit (typed sentinel → fixed cooldown)
//   - This file's Tests 1-4 (every path that could trigger backoff now returns
//     typed ErrRateLimited, not a generic error)

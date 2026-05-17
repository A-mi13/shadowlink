package client

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/core"
)

// fakeSessionRL returns a minimal valid *core.Session for RL tests.
func fakeSessionRL(t *testing.T) *core.Session {
	t.Helper()
	return core.NewSession(42, make([]byte, 32), make([]byte, 32))
}

// bodyMarkerPayload returns a minimal HTML body containing a Schema.org JSON-LD
// rl-state marker with the given value string (e.g. "v1;bucket=ws_upgrade;refill_in=90;burst_left=0;exempt=0").
func bodyMarkerPayload(value string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication","name":"App","identifier":{"@type":"PropertyValue","propertyID":"rl-state","value":%q}}</script>
</head><body><p>Service temporarily unavailable.</p></body></html>`, value)
}

// TestUpgradeToWS_RateLimitedByBodyMarker_CFStripsHeader exercises the Phase 2.3
// primary path: server returns 200 + Schema.org body marker, header X-SL-RL absent
// (simulating CF stripping the header). Asserts errors.Is(err, ErrRateLimited)
// and that errors.As extracts a non-nil signal.
func TestUpgradeToWS_RateLimitedByBodyMarker_CFStripsHeader(t *testing.T) {
	body := bodyMarkerPayload("v1;bucket=ws_upgrade;refill_in=90;burst_left=0;exempt=0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 200 with Schema.org body, but no X-SL-RL header.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, body)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	wst := NewWebSocketTransport(addr, false, true)
	token := make([]byte, 36)
	session := fakeSessionRL(t)

	err := wst.UpgradeToWS(token, session)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected errors.Is(err, ErrRateLimited)=true; got err=%v", err)
	}
	var rlErr *RateLimitError
	if !errors.As(err, &rlErr) {
		t.Fatalf("expected errors.As(*RateLimitError)=true; got err=%v", err)
	}
	if rlErr.Signal == nil {
		t.Fatal("RateLimitError.Signal is nil")
	}
	if rlErr.Signal.Carrier != "body" {
		t.Errorf("expected carrier=body, got %q", rlErr.Signal.Carrier)
	}
	if rlErr.Signal.Bucket != "ws_upgrade" {
		t.Errorf("expected bucket=ws_upgrade, got %q", rlErr.Signal.Bucket)
	}
}

// TestUpgradeToWS_RateLimitedByHeader exercises the header carrier path.
// Server returns 200 + X-SL-RL header (new semicolon format), body without marker.
func TestUpgradeToWS_RateLimitedByHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-SL-RL", "v1;bucket=ws_upgrade;refill_in=60;burst_left=0;exempt=0")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "<html><body>rate limited</body></html>")
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	wst := NewWebSocketTransport(addr, false, true)
	token := make([]byte, 36)
	session := fakeSessionRL(t)

	err := wst.UpgradeToWS(token, session)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected errors.Is(err, ErrRateLimited)=true; got err=%v", err)
	}
	var rlErr *RateLimitError
	if !errors.As(err, &rlErr) {
		t.Fatalf("expected errors.As(*RateLimitError)=true; got err=%v", err)
	}
	if rlErr.Signal == nil {
		t.Fatal("RateLimitError.Signal is nil")
	}
	if rlErr.Signal.Carrier != "header_v1" {
		t.Errorf("expected carrier=header_v1, got %q", rlErr.Signal.Carrier)
	}
}

// TestUpgradeToWS_PlainHTMLDecoy_NotRateLimit verifies Phase 2.3 no-lifeline design:
// WS upgrade path uses DetectCarriersOnly (no lifeline). A plain HTML decoy body
// (no Schema.org marker, no X-SL-RL) must NOT trigger ErrRateLimited — it is a
// generic network/CF error and should fall through to sendBestEffortSessionFIN.
// This is the inverse of the lifeline test: WS upgrade cannot use the lifeline
// because every non-101 response returns decoy HTML.
func TestUpgradeToWS_PlainHTMLDecoy_NotRateLimit(t *testing.T) {
	// Baseline-tagged body: has the JSON-LD block but value is "none" (baseline =
	// not a rate-limit signal). No X-SL-RL header. Decoy page shape.
	baselineBody := `<!DOCTYPE html><html><head>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication","name":"App","identifier":{"@type":"PropertyValue","propertyID":"rl-state","value":"none"}}</script>
</head><body><p>Hi</p></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, baselineBody)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	wst := NewWebSocketTransport(addr, false, true)
	token := make([]byte, 36)
	session := fakeSessionRL(t)

	err := wst.UpgradeToWS(token, session)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Must NOT be rate-limited — no positive carrier signal present.
	if errors.Is(err, ErrRateLimited) {
		t.Errorf("plain HTML decoy must NOT trigger ErrRateLimited on WS path; got %v", err)
	}
}

// TestUpgradeToWS_NormalNetworkError_NotRateLimit verifies that a plain
// connection-refused error (no resp) is NOT mistaken for a rate-limit and
// does NOT return ErrRateLimited. The underlying error must be wrapped.
func TestUpgradeToWS_NormalNetworkError_NotRateLimit(t *testing.T) {
	// Port 1 is effectively unreachable on all test hosts.
	wst := NewWebSocketTransport("127.0.0.1:1", false, true)
	token := make([]byte, 36)
	session := fakeSessionRL(t)

	err := wst.UpgradeToWS(token, session)
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
	if errors.Is(err, ErrRateLimited) {
		t.Errorf("connection refused should NOT be ErrRateLimited; got %v", err)
	}
}

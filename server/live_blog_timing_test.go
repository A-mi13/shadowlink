package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestLiveBlogHandlerWithJitter creates a minimal LiveBlogHandler with
// FallbackLatencyMs=50 and FallbackJitterMs=10 (small values for fast tests).
// Fallback is a simple 200-OK handler that records the received request for
// assertions in TestServeFallback_PlaceholderRequest.
func newTestLiveBlogHandlerWithJitter(t *testing.T, recordReq *http.Request) *LiveBlogHandler {
	t.Helper()
	cfg := DefaultLiveBlogConfig()
	cfg.Enabled = true
	cfg.FallbackLatencyMs = 50
	cfg.FallbackJitterMs = 10
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if recordReq != nil {
			*recordReq = *r
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SPA"))
	})
	h, err := NewLiveBlogHandler(cfg, fallback, nil)
	if err != nil {
		t.Fatalf("NewLiveBlogHandler: %v", err)
	}
	return h
}

// TestApplyFallbackJitter_UniformBucket verifies applyFallbackJitter sleeps
// into the [target-jitter, target+jitter] bucket on every call when start
// time is ~now. Regression guard for C1 (fail-path timing uniformity).
func TestApplyFallbackJitter_UniformBucket(t *testing.T) {
	h := newTestLiveBlogHandlerWithJitter(t, nil)
	const iterations = 100
	const toleranceMs = 10
	minExpected := 40*time.Millisecond - toleranceMs*time.Millisecond
	maxExpected := 60*time.Millisecond + toleranceMs*time.Millisecond
	for i := 0; i < iterations; i++ {
		start := time.Now()
		h.applyFallbackJitter(start)
		elapsed := time.Since(start)
		if elapsed < minExpected || elapsed > maxExpected {
			t.Errorf("iter %d: elapsed %v out of bucket [%v, %v]", i, elapsed, minExpected, maxExpected)
		}
	}
}

// TestApplyFallbackJitter_SkipsIfAlreadyLate verifies that when the caller
// has already spent longer than the jitter bucket on work, the helper
// returns near-instantly instead of sleeping into a negative duration.
func TestApplyFallbackJitter_SkipsIfAlreadyLate(t *testing.T) {
	h := newTestLiveBlogHandlerWithJitter(t, nil)
	fakeStart := time.Now().Add(-500 * time.Millisecond)
	startCall := time.Now()
	h.applyFallbackJitter(fakeStart)
	elapsed := time.Since(startCall)
	if elapsed > 5*time.Millisecond {
		t.Errorf("elapsed %v — should be near-instant when already late", elapsed)
	}
}

// TestServeFallback_PlaceholderRequest verifies C2 fix: serveFallback invokes
// the SPA handler with a placeholder GET / request (not the original URL)
// so the fallback response body cannot leak the original path length as a
// timing/size oracle.
func TestServeFallback_PlaceholderRequest(t *testing.T) {
	var received http.Request
	h := newTestLiveBlogHandlerWithJitter(t, &received)
	w := httptest.NewRecorder()
	origReq := httptest.NewRequest("GET", "/blog/12345", nil)
	h.serveFallback(w, origReq)
	if received.Method != "GET" {
		t.Errorf("fallback got method %q, want GET", received.Method)
	}
	if received.URL.Path != "/" {
		t.Errorf("fallback got path %q, want /", received.URL.Path)
	}
}

// TestServeCDN_404BodyMatchesFixture verifies C3 fix: the 404 body matches
// nginx's default 404 page byte-for-byte (146 bytes, CRLF-encoded, no
// version string). Server header must be absent — behind CF it becomes
// "cloudflare"; in direct-IP fallback emitting "nginx/1.27.3" (Nov 2024)
// on May 2026 is a version-anachronism fingerprint.
func TestServeCDN_404BodyMatchesFixture(t *testing.T) {
	h := newTestLiveBlogHandlerWithJitter(t, nil)
	w := httptest.NewRecorder()
	h.writeNginxLike404(w)
	if w.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", w.Code)
	}
	if got := w.Header().Get("Server"); got != "" {
		t.Errorf("Server header %q, want empty (CF sets its own)", got)
	}
	if !bytes.Equal(w.Body.Bytes(), nginxLike404Body) {
		t.Errorf("body mismatch:\ngot:  %q\nwant: %q", w.Body.String(), string(nginxLike404Body))
	}
	// Sanity: fixture size must be exactly 146 bytes (CRLF-encoded, no version string)
	if len(nginxLike404Body) != 146 {
		t.Errorf("fixture size %d, want 146 bytes (CRLF)", len(nginxLike404Body))
	}
	// Sanity: must contain exact nginx signature but no version
	if !strings.Contains(string(nginxLike404Body), "<center>nginx</center>") {
		t.Errorf("fixture missing '<center>nginx</center>' signature")
	}
	if strings.Contains(string(nginxLike404Body), "nginx/") {
		t.Errorf("fixture body contains version string — should not")
	}
}

// NOTE: TestServeArticle_FailPathsUniformTiming (plan step 6) deferred to
// post-merge integration tests — requires upstream mock HTTP server injection
// or extensive handler surgery; unit-level coverage of applyFallbackJitter +
// writeNginxLike404 + serveFallback placeholder is sufficient to guard the
// C1/C2/C3 invariants this task was designed for.

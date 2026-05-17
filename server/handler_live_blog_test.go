package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/core"
	"github.com/stretchr/testify/require"
)

// defaultHandlerTestConfig returns a Config suitable for handler live-blog
// integration tests. It mirrors the pattern used by setupTestHandler in
// handler_test.go.
func defaultHandlerTestConfig() Config {
	return TestConfig()
}

// newTestHandlerWithConfig constructs a Handler with the given config using
// a freshly generated server key. Matches the idiom from setupTestHandler
// in handler_test.go.
func newTestHandlerWithConfig(t *testing.T, cfg Config) *Handler {
	t.Helper()
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)
	return NewHandler(serverKey, cfg, "")
}

// TestHandler_GETBlogRoutesToLiveBlog verifies that an unauthenticated GET
// to /blog/1 is dispatched to the LiveBlogHandler (not the SPA decoy) and
// returns the live-blog upstream response body.
func TestHandler_GETBlogRoutesToLiveBlog(t *testing.T) {
	habr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>LIVEBLOG MARKER</body></html>"))
	}))
	defer habr.Close()

	cfg := defaultHandlerTestConfig()
	cfg.LiveBlog = LiveBlogConfig{Enabled: true, Upstream: habr.URL, CDNUpstream: "https://ignored"}
	h := newTestHandlerWithConfig(t, cfg)
	// SafeDial blocks 127.0.0.1; httptest binds there. Override DialContext
	// for this routing-only test (separate test exercises the SafeDial guard).
	if h.liveBlog != nil {
		allowLoopbackForTest(h.liveBlog)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/blog/1", nil))
	if rec.Code != 200 {
		t.Fatalf("status: %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "LIVEBLOG MARKER") {
		t.Errorf("live-blog not wired: %q", rec.Body.String())
	}
}

// TestHandler_POSTBlogPathStillRoutesToVPN verifies that POST /blog/1 with
// application/json Content-Type is handled by the VPN path (new-format post),
// not by live-blog. A random JSON body will fail the ShadowLink parse and
// land in failClosedToDecoy → SPA 200. The key assertion is that it must NOT
// return a 404 "page not found" from the live-blog handler.
func TestHandler_POSTBlogPathStillRoutesToVPN(t *testing.T) {
	cfg := defaultHandlerTestConfig()
	cfg.LiveBlog = LiveBlogConfig{Enabled: true, Upstream: "https://ignored", CDNUpstream: "https://ignored"}
	h := newTestHandlerWithConfig(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/blog/1", strings.NewReader(`{"x":1}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// handleNewFormatPost with invalid body → failClosedToDecoy → SPA 200.
	// Must not be a live-blog 404.
	if rec.Code == 404 && strings.Contains(rec.Body.String(), "page not found") {
		t.Errorf("live-blog intercepted POST: %q", rec.Body.String())
	}
}

// TestHandler_FailClosedToDecoy_NoUpstreamFetch verifies that failClosedToDecoy
// (triggered by an invalid POST+JSON body) does NOT reach the live-blog
// upstream. The upstream hit counter must remain 0.
func TestHandler_FailClosedToDecoy_NoUpstreamFetch(t *testing.T) {
	upstreamHits := 0
	habr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.Write([]byte("<html>x</html>"))
	}))
	defer habr.Close()

	cfg := defaultHandlerTestConfig()
	cfg.LiveBlog = LiveBlogConfig{Enabled: true, Upstream: habr.URL, CDNUpstream: "https://ignored"}
	h := newTestHandlerWithConfig(t, cfg)

	// Send a random POST+JSON — will fail to parse as ShadowLink, going
	// through failClosedToDecoy (which routes to h.decoy, the SPA, not live-blog).
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not_a_shadowlink_body"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if upstreamHits != 0 {
		t.Errorf("failClosedToDecoy triggered upstream fetch %d times", upstreamHits)
	}
}

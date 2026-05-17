package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"
)

// allowLoopbackForTest swaps the live-blog handler's DialContext to a plain
// net.Dialer so tests pointing Upstream/CDNUpstream at httptest.NewServer
// (which always binds 127.0.0.1) can still reach it. Production flow remains
// SafeDial-protected — A3-S-MED-5's SSRF guard is exercised separately by
// TestLiveBlogHandler_SafeDialBlocksPrivateIP.
func allowLoopbackForTest(h *LiveBlogHandler) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	h.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
}

func TestLiveBlogHandler_Matches(t *testing.T) {
	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled:     true,
		Upstream:    "https://habr.com",
		CDNUpstream: "https://dr.habracdn.net",
		// minimal fields — applyLiveBlogDefaults fills the rest internally
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewLiveBlogHandler: %v", err)
	}
	cases := []struct {
		path    string
		matches bool
	}{
		{"/blog", true},
		{"/blog/", true},
		{"/blog/723128", true},
		{"/blog/0", true},
		{"/blog/9999999999", true},
		{"/blog/abc", false},
		{"/blog/../admin", false},
		{"/blogger", false},
		{"/blog/1/extra", false},
		{"/_cdn/habr-web/main.css", true},
		{"/_cdn/x/y/z", true},
		{"/_cdn/", false},
		{"/", false},
		{"/assets/logo.svg", false},
	}
	for _, c := range cases {
		got := h.Matches(c.path)
		if got != c.matches {
			t.Errorf("Matches(%q) = %v, want %v", c.path, got, c.matches)
		}
	}
}

func TestLiveBlogCache_FreshHitReturnsBody(t *testing.T) {
	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: "https://habr.com", CDNUpstream: "https://dr.habracdn.net",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.cache = newTestCache(h.cfg.CacheTTL)
	h.cache.Add("/blog/1", cachedPage{
		body:        []byte("hello"),
		contentType: "text/html",
		status:      200,
		fetchedAt:   time.Now().UnixNano(),
	})
	entry, fresh, stale := h.lookupCache("/blog/1")
	if !fresh || stale || entry == nil {
		t.Fatalf("expected fresh hit, got fresh=%v stale=%v entry=%v", fresh, stale, entry)
	}
	if string(entry.body) != "hello" {
		t.Errorf("body wrong: %q", entry.body)
	}
}

func TestLiveBlogCache_StaleWithinGrace(t *testing.T) {
	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: "https://habr.com", CDNUpstream: "https://dr.habracdn.net",
		CacheTTL: 10 * time.Millisecond, CacheStaleGrace: time.Hour,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.cache = newTestCache(h.cfg.CacheTTL + h.cfg.CacheStaleGrace)
	h.cache.Add("/blog/1", cachedPage{
		body:      []byte("stale"),
		status:    200,
		fetchedAt: time.Now().Add(-time.Minute).UnixNano(),
	})
	time.Sleep(20 * time.Millisecond) // entry is now past TTL
	entry, fresh, stale := h.lookupCache("/blog/1")
	if fresh {
		t.Errorf("should not be fresh after TTL")
	}
	if !stale {
		t.Errorf("should be stale within grace")
	}
	if entry == nil || string(entry.body) != "stale" {
		t.Errorf("stale entry missing or wrong: %v", entry)
	}
}

func TestLiveBlogCache_MissReturnsNil(t *testing.T) {
	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: "https://habr.com", CDNUpstream: "https://dr.habracdn.net",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.cache = newTestCache(time.Hour)
	entry, fresh, stale := h.lookupCache("/blog/404")
	if entry != nil || fresh || stale {
		t.Errorf("expected pure miss, got entry=%v fresh=%v stale=%v", entry, fresh, stale)
	}
}

// newTestCache is a convenience builder mirroring NewLiveBlogHandler's
// production logic. Tests that don't care about LRU eviction use this.
func newTestCache(maxLife time.Duration) *lru.LRU[string, cachedPage] {
	return lru.NewLRU[string, cachedPage](1000, nil, maxLife)
}

func TestLiveBlog_FetchUpstreamOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ru/articles/1" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		if r.Header.Get("Cookie") != "" {
			t.Errorf("cookie leaked upstream: %q", r.Header.Get("Cookie"))
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("authorization leaked upstream")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Set-Cookie", "habr_session=xyz; Path=/")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: srv.URL, CDNUpstream: "https://ignored",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	allowLoopbackForTest(h)
	body, ct, status, err := h.fetchUpstreamArticle("1")
	if err != nil {
		t.Fatalf("fetchUpstreamArticle: %v", err)
	}
	if status != 200 {
		t.Errorf("status: %d", status)
	}
	if ct != "text/html; charset=utf-8" {
		t.Errorf("content-type: %q", ct)
	}
	if string(body) != "<html>ok</html>" {
		t.Errorf("body: %q", body)
	}
}

func TestLiveBlog_FetchUpstreamRejectsCrossHostRedirect(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("evil host should not be reached")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/stolen", http.StatusFound)
	}))
	defer srv.Close()

	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: srv.URL, CDNUpstream: "https://ignored",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	allowLoopbackForTest(h)
	_, _, _, err = h.fetchUpstreamArticle("1")
	if err == nil {
		t.Errorf("expected SSRF rejection, got no error")
	}
}

func TestLiveBlog_FetchUpstreamRespectsMaxBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 10 MB response, cap is 1 KB
		big := make([]byte, 10*1024*1024)
		for i := range big {
			big[i] = 'x'
		}
		w.Write(big)
	}))
	defer srv.Close()

	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: srv.URL, CDNUpstream: "https://ignored",
		MaxBodyBytes: 1024,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	allowLoopbackForTest(h)
	_, _, _, err = h.fetchUpstreamArticle("1")
	if err == nil {
		t.Errorf("expected body-too-large error")
	}
	if err != nil && !containsAny(err.Error(), "too large", "exceeded") {
		t.Errorf("unexpected error: %v", err)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestLiveBlog_ServeHTTP_CacheMissFetchesAndRewrites(t *testing.T) {
	habr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Set-Cookie", "habr_sess=leaky; Path=/")
		w.Write([]byte(`<html><head><title>Т / Хабр</title></head><body><p>про Хабр</p></body></html>`))
	}))
	defer habr.Close()

	metrics := NewMetrics()
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("SPA_FALLBACK_SHOULD_NOT_BE_CALLED"))
	})
	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: habr.URL, CDNUpstream: "https://ignored",
		TargetBrand: "DataCanvases",
	}, fallback, metrics)
	if err != nil {
		t.Fatal(err)
	}
	allowLoopbackForTest(h)

	req := httptest.NewRequest(http.MethodGet, "/blog/723128", nil)
	req.Header.Set("Cookie", "visitor=abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "Хабр") {
		t.Errorf("brand leaked: %q", body)
	}
	if !strings.Contains(body, "DataCanvases") {
		t.Errorf("brand not injected: %q", body)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("upstream cookie leaked")
	}
	if rec.Header().Get("Server") != "nginx/1.27.3" {
		t.Errorf("our Server header not set: %q", rec.Header().Get("Server"))
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Errorf("Cache-Control missing")
	}
	if metrics.DecoyLiveBlogUpstreamOK.Load() != 1 {
		t.Errorf("upstream_ok metric: %d", metrics.DecoyLiveBlogUpstreamOK.Load())
	}
	if metrics.DecoyLiveBlogCacheMisses.Load() != 1 {
		t.Errorf("cache_misses metric: %d", metrics.DecoyLiveBlogCacheMisses.Load())
	}

	// Second call — should hit cache.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/blog/723128", nil))
	if rec2.Code != 200 {
		t.Fatalf("cache hit status: %d", rec2.Code)
	}
	if metrics.DecoyLiveBlogCacheHits.Load() != 1 {
		t.Errorf("cache_hits metric after 2nd call: %d", metrics.DecoyLiveBlogCacheHits.Load())
	}
	if metrics.DecoyLiveBlogUpstreamOK.Load() != 1 {
		t.Errorf("upstream should NOT have been hit twice")
	}
}

// TestLiveBlog_ServeHTTP_StaleServedOnUpstreamTimeout verifies that when the
// upstream times out (dial error) and a stale cache entry exists within
// CacheStaleGrace, the handler serves the stale body (200) and increments
// StaleServed + UpstreamErr without touching FallbackSPA.
func TestLiveBlog_ServeHTTP_StaleServedOnUpstreamTimeout(t *testing.T) {
	// upstream that immediately times out
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // intentionally slow
	}))
	defer slow.Close()

	metrics := NewMetrics()
	var spaHits atomic.Int32
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spaHits.Add(1)
		w.WriteHeader(200)
		w.Write([]byte("SPA"))
	})

	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled:         true,
		Upstream:        slow.URL,
		CDNUpstream:     "https://ignored",
		UpstreamTimeout: 50 * time.Millisecond, // much shorter than sleep above
		CacheTTL:        10 * time.Millisecond,
		CacheStaleGrace: time.Hour,
	}, fallback, metrics)
	if err != nil {
		t.Fatal(err)
	}
	allowLoopbackForTest(h)

	// plant a stale entry (fetchedAt 2 minutes ago — past TTL but within grace)
	staleEntry := cachedPage{
		body:        []byte("<html>stale article</html>"),
		contentType: "text/html; charset=utf-8",
		status:      200,
		fetchedAt:   time.Now().Add(-2 * time.Minute).UnixNano(),
	}
	h.cache.Add("/blog/42", staleEntry)

	req := httptest.NewRequest(http.MethodGet, "/blog/42", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200 from stale serve, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "stale article") {
		t.Errorf("stale body not served: %q", rec.Body.String())
	}
	if metrics.DecoyLiveBlogStaleServed.Load() != 1 {
		t.Errorf("StaleServed metric: %d, want 1", metrics.DecoyLiveBlogStaleServed.Load())
	}
	if metrics.DecoyLiveBlogUpstreamErr.Load() != 1 {
		t.Errorf("UpstreamErr metric: %d, want 1", metrics.DecoyLiveBlogUpstreamErr.Load())
	}
	if spaHits.Load() != 0 {
		t.Errorf("FallbackSPA should not be called when stale entry available, got %d calls", spaHits.Load())
	}
	if metrics.DecoyLiveBlogFallbackSPA.Load() != 0 {
		t.Errorf("FallbackSPA metric: %d, want 0", metrics.DecoyLiveBlogFallbackSPA.Load())
	}
}

// TestLiveBlog_ServeHTTP_InvalidArticleIDIsHandlerMiss verifies that paths
// that do NOT match the article regexp (e.g. /blog/abc) are not handled by
// ServeHTTP at all — i.e., the handler should return 404 for those (they reach
// the default: branch which calls http.NotFound). Matches() must already
// return false for them, but we verify the ServeHTTP default branch as well.
func TestLiveBlog_ServeHTTP_InvalidArticleIDIsHandlerMiss(t *testing.T) {
	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled:     true,
		Upstream:    "https://habr.com",
		CDNUpstream: "https://ignored",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// /blog/abc does not match articleRe — Matches() returns false
	if h.Matches("/blog/abc") {
		t.Fatalf("Matches(/blog/abc) should be false")
	}

	// Calling ServeHTTP directly simulates the default: branch reaching 404.
	req := httptest.NewRequest(http.MethodGet, "/blog/abc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("expected 404 for /blog/abc, got %d", rec.Code)
	}
}

// TestLiveBlog_ServeHTTP_Upstream5xxFallsBackToSPA verifies that a 500 response
// from upstream (with no stale entry) results in serveFallback being called
// and the metrics UpstreamErr + FallbackSPA both incrementing.
func TestLiveBlog_ServeHTTP_Upstream5xxFallsBackToSPA(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("Internal Server Error"))
	}))
	defer upstream.Close()

	metrics := NewMetrics()
	var spaHits atomic.Int32
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spaHits.Add(1)
		w.WriteHeader(200)
		w.Write([]byte("SPA_FALLBACK"))
	})

	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled:     true,
		Upstream:    upstream.URL,
		CDNUpstream: "https://ignored",
	}, fallback, metrics)
	if err != nil {
		t.Fatal(err)
	}
	allowLoopbackForTest(h)

	req := httptest.NewRequest(http.MethodGet, "/blog/999", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// serveFallback should have been called → SPA returns 200
	if rec.Code != 200 {
		t.Fatalf("expected 200 from SPA fallback, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "SPA_FALLBACK") {
		t.Errorf("expected SPA body, got: %q", rec.Body.String())
	}
	if metrics.DecoyLiveBlogUpstreamErr.Load() != 1 {
		t.Errorf("UpstreamErr metric: %d, want 1", metrics.DecoyLiveBlogUpstreamErr.Load())
	}
	if metrics.DecoyLiveBlogFallbackSPA.Load() != 1 {
		t.Errorf("FallbackSPA metric: %d, want 1", metrics.DecoyLiveBlogFallbackSPA.Load())
	}
	if spaHits.Load() != 1 {
		t.Errorf("SPA handler calls: %d, want 1", spaHits.Load())
	}
	if metrics.DecoyLiveBlogStaleServed.Load() != 0 {
		t.Errorf("StaleServed metric: %d, want 0", metrics.DecoyLiveBlogStaleServed.Load())
	}
}

func TestLiveBlog_ServeHTTP_CDNProxiesAsset(t *testing.T) {
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/habr-web/build/main.css" {
			t.Errorf("cdn path: %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/css")
		w.Write([]byte("body { color: red; }"))
	}))
	defer cdn.Close()
	metrics := NewMetrics()
	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: "https://ignored.example", CDNUpstream: cdn.URL,
	}, nil, metrics)
	if err != nil {
		t.Fatal(err)
	}
	allowLoopbackForTest(h)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/_cdn/habr-web/build/main.css", nil))
	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	if rec.Body.String() != "body { color: red; }" {
		t.Errorf("body: %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/css" {
		t.Errorf("content-type: %q", rec.Header().Get("Content-Type"))
	}
	if metrics.DecoyLiveBlogCDNHits.Load() != 1 {
		t.Errorf("cdn_hits metric: %d", metrics.DecoyLiveBlogCDNHits.Load())
	}
}

// TestLiveBlog_ServeHTTP_UpstreamRateLimitedServesStaleOrFallback verifies
// that when the rate limiter denies a token, the handler either serves a stale
// cache entry (if one exists) or falls back to the SPA, and always increments
// UpstreamRateLimited.
func TestLiveBlog_ServeHTTP_UpstreamRateLimitedServesStaleOrFallback(t *testing.T) {
	// upstream that should never be hit
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called when rate limited")
		w.WriteHeader(200)
		w.Write([]byte("<html>should not see this</html>"))
	}))
	defer upstream.Close()

	metrics := NewMetrics()
	var spaHits atomic.Int32
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spaHits.Add(1)
		w.WriteHeader(200)
		w.Write([]byte("SPA_FALLBACK"))
	})

	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled:       true,
		Upstream:      upstream.URL,
		CDNUpstream:   "https://ignored",
		UpstreamRPS:   0.0001, // effectively zero — first call uses the burst
		UpstreamBurst: 1,
	}, fallback, metrics)
	if err != nil {
		t.Fatal(err)
	}
	allowLoopbackForTest(h)

	// Exhaust the burst token so the next Allow() call returns false.
	h.upstreamLimiter = rate.NewLimiter(rate.Limit(0.0001), 1)
	h.upstreamLimiter.Allow() // consume the single burst token

	// Sub-test A: no stale entry → SPA fallback
	t.Run("no_stale_falls_back_to_spa", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/blog/100", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if metrics.DecoyLiveBlogUpstreamRateLimited.Load() < 1 {
			t.Errorf("UpstreamRateLimited metric: %d, want >=1", metrics.DecoyLiveBlogUpstreamRateLimited.Load())
		}
		if spaHits.Load() < 1 {
			t.Errorf("SPA should have been called, got %d calls", spaHits.Load())
		}
		if metrics.DecoyLiveBlogFallbackSPA.Load() < 1 {
			t.Errorf("FallbackSPA metric: %d, want >=1", metrics.DecoyLiveBlogFallbackSPA.Load())
		}
	})

	// Sub-test B: stale entry present → serve stale, NOT SPA
	t.Run("stale_present_serves_stale", func(t *testing.T) {
		spaHits.Store(0)
		metrics.DecoyLiveBlogUpstreamRateLimited.Store(0)
		metrics.DecoyLiveBlogStaleServed.Store(0)
		metrics.DecoyLiveBlogFallbackSPA.Store(0)

		// fetchedAt must be > CacheTTL (default 1h) but < CacheTTL+CacheStaleGrace (default 25h)
		// so that lookupCache returns (entry, fresh=false, stale=true).
		staleEntry := cachedPage{
			body:        []byte("<html>stale rate-limit article</html>"),
			contentType: "text/html; charset=utf-8",
			status:      200,
			fetchedAt:   time.Now().Add(-2 * time.Hour).UnixNano(),
		}
		h.cache.Add("/blog/200", staleEntry)

		req := httptest.NewRequest(http.MethodGet, "/blog/200", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != 200 {
			t.Fatalf("expected 200 from stale serve, got %d body=%q", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "stale rate-limit article") {
			t.Errorf("stale body not served: %q", rec.Body.String())
		}
		if metrics.DecoyLiveBlogUpstreamRateLimited.Load() != 1 {
			t.Errorf("UpstreamRateLimited metric: %d, want 1", metrics.DecoyLiveBlogUpstreamRateLimited.Load())
		}
		if metrics.DecoyLiveBlogStaleServed.Load() != 1 {
			t.Errorf("StaleServed metric: %d, want 1", metrics.DecoyLiveBlogStaleServed.Load())
		}
		if spaHits.Load() != 0 {
			t.Errorf("SPA should NOT be called when stale available, got %d calls", spaHits.Load())
		}
		if metrics.DecoyLiveBlogFallbackSPA.Load() != 0 {
			t.Errorf("FallbackSPA metric: %d, want 0", metrics.DecoyLiveBlogFallbackSPA.Load())
		}
	})
}

// TestLiveBlogHandler_SafeDialBlocksPrivateIP covers A3-S-MED-5 closure:
// the live-blog HTTP client routes Transport.DialContext through SafeDial,
// so a fetch against any private/loopback host MUST refuse to dial. We use
// the production DialContext (no allowLoopbackForTest override) and point
// upstream at a real httptest server bound to 127.0.0.1 — fetchUpstream
// must surface a "private" error, not a successful 200.
func TestLiveBlogHandler_SafeDialBlocksPrivateIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should NOT be reached — SafeDial must block 127.0.0.1")
		w.WriteHeader(200)
		w.Write([]byte("<html>should-not-see-this</html>"))
	}))
	defer srv.Close()

	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: srv.URL, CDNUpstream: "https://ignored",
		UpstreamTimeout: 2 * time.Second,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// NOTE: deliberately NOT calling allowLoopbackForTest — we want the
	// production SafeDial guard to exercise.

	_, _, _, err = h.fetchUpstreamArticle("1")
	if err == nil {
		t.Fatalf("expected SafeDial to reject 127.0.0.1, got no error")
	}
	if !strings.Contains(err.Error(), "private") {
		t.Errorf("expected error to mention private IP, got: %v", err)
	}
}

// TestLiveBlogHandler_ServeHTTP_RecoversFromPanic exercises the outer
// defer-recover wrapper added to LiveBlogHandler.ServeHTTP for A3-I-MED-4.
// We force a panic by nil'ing out articleRe; the wrapper must convert it
// into a 500 response and tick DecoyLiveBlogServeHTTPPanic.
func TestLiveBlogHandler_ServeHTTP_RecoversFromPanic(t *testing.T) {
	metrics := NewMetrics()
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	h, err := NewLiveBlogHandler(LiveBlogConfig{
		Enabled: true, Upstream: "https://habr.com", CDNUpstream: "https://dr.habracdn.net",
	}, fallback, metrics)
	if err != nil {
		t.Fatal(err)
	}

	// Trigger a panic inside the dispatch switch: nil regex -> nil deref on MatchString.
	h.articleRe = nil

	req := httptest.NewRequest(http.MethodGet, "/blog/723128", nil)
	rec := httptest.NewRecorder()

	// Must not propagate panic out of ServeHTTP (test harness would fail).
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 after recovered panic, got %d", rec.Code)
	}
	if got := metrics.DecoyLiveBlogServeHTTPPanic.Load(); got != 1 {
		t.Errorf("DecoyLiveBlogServeHTTPPanic: got %d, want 1", got)
	}
}

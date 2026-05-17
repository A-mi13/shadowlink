package server

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// canaryArticleIDRe matches the permitted shape for a habr article ID used
// by the canary loop. Same as the path regex but applied to config values.
var canaryArticleIDRe = regexp.MustCompile(`^\d{1,10}$`)

//go:embed nginx_404.html
var nginxLike404Body []byte

// LiveBlogHandler serves reverse-proxied, brand-rewritten content from an
// upstream site (default habr.com) under /blog/* and /_cdn/*. See
// docs/superpowers/specs/2026-04-23-t13-live-decoy-design.md.
//
// Not safe to mutate after construction; Matches / ServeHTTP are called
// concurrently by the HTTP server.
type LiveBlogHandler struct {
	cfg             LiveBlogConfig
	upstreamURL     *url.URL
	cdnUpstreamURL  *url.URL
	httpClient      *http.Client
	cache           *lru.LRU[string, cachedPage]
	cdnCache        *lru.LRU[string, cachedPage]
	upstreamLimiter *rate.Limiter
	rewriter        *HTMLRewriter
	metrics         *Metrics
	fallback        http.Handler

	articleRe *regexp.Regexp
	cdnPrefix string

	// dialContext is the Transport.DialContext used by httpClient.
	// In production it wraps SafeDial (A3-S-MED-5) to refuse private/
	// loopback IPs. Unit tests may swap in net.Dialer.DialContext when
	// they need to talk to httptest.NewServer on 127.0.0.1.
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// safeDialContext is the production DialContext: route through SafeDial so
// the live-blog HTTP client refuses to connect to private/loopback/
// link-local IPs. Exposed as a package-level helper so tests that DO want
// the SSRF check (TestLiveBlogHandler_SafeDialBlocksPrivateIP) can reach it.
func safeDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("live_blog: unsupported dial network %q", network)
		}
		return SafeDial(ctx, addr, timeout)
	}
}

// cachedPage is the LRU entry: the fully-prepared response bytes plus the
// content type we'll emit and the wall-clock time we fetched it at. Headers
// like Server / X-Content-Type-Options are synthesized at serve time from the
// handler's baseline, not stored here.
type cachedPage struct {
	body        []byte
	contentType string
	status      int
	fetchedAt   int64 // unix-nanos for cheap age math without time.Time copies
}

// NewLiveBlogHandler validates config, builds HTTP client + caches + rewriter,
// and returns a handler ready to ServeHTTP. fallback is the SPA handler used
// on upstream-failure paths and is REQUIRED (non-nil) when Enabled.
func NewLiveBlogHandler(cfg LiveBlogConfig, fallback http.Handler, metrics *Metrics) (*LiveBlogHandler, error) {
	applyLiveBlogDefaults(&cfg)

	if cfg.FallbackLatencyMs < 0 {
		return nil, fmt.Errorf("live_blog: invalid fallback_latency_ms %d: must be >= 0", cfg.FallbackLatencyMs)
	}
	if cfg.FallbackJitterMs < 0 {
		return nil, fmt.Errorf("live_blog: invalid fallback_jitter_ms %d: must be >= 0", cfg.FallbackJitterMs)
	}
	if cfg.FallbackJitterMs > cfg.FallbackLatencyMs {
		return nil, fmt.Errorf("live_blog: fallback_jitter_ms (%d) must be <= fallback_latency_ms (%d)", cfg.FallbackJitterMs, cfg.FallbackLatencyMs)
	}

	if !canaryArticleIDRe.MatchString(cfg.CanaryArticleID) {
		return nil, fmt.Errorf("live_blog: invalid canary_article_id %q: must match ^\\d{1,10}$", cfg.CanaryArticleID)
	}

	upURL, err := url.Parse(cfg.Upstream)
	if err != nil || upURL.Host == "" {
		return nil, fmt.Errorf("live_blog: invalid upstream %q: %v", cfg.Upstream, err)
	}
	cdnURL, err := url.Parse(cfg.CDNUpstream)
	if err != nil || cdnURL.Host == "" {
		return nil, fmt.Errorf("live_blog: invalid cdn_upstream %q: %v", cfg.CDNUpstream, err)
	}

	h := &LiveBlogHandler{
		cfg:            cfg,
		upstreamURL:    upURL,
		cdnUpstreamURL: cdnURL,
		metrics:        metrics,
		fallback:       fallback,
		articleRe:      regexp.MustCompile(`^/blog/(\d{1,10})$`),
		cdnPrefix:      "/_cdn/",
	}

	// LRU entry lifetime = TTL + StaleGrace so stale-within-grace entries
	// remain present until we either refresh them or the grace expires.
	entryLife := cfg.CacheTTL + cfg.CacheStaleGrace
	h.cache = lru.NewLRU[string, cachedPage](cfg.CacheMaxEntries, nil, entryLife)
	h.cdnCache = lru.NewLRU[string, cachedPage](cfg.CacheMaxEntries, nil, entryLife)
	h.upstreamLimiter = rate.NewLimiter(rate.Limit(cfg.UpstreamRPS), cfg.UpstreamBurst)

	pinnedHost := upURL.Host
	pinnedCDNHost := cdnURL.Host
	// SSRF guard (A3-S-MED-5): wire Transport.DialContext through SafeDial
	// so the live-blog HTTP client refuses to connect to private/loopback/
	// link-local IPs even if upstream / cdn_upstream were ever pointed at
	// internal hosts (config tampering, DNS rebinding, malicious redirect
	// to a same-host private IP, etc.). SafeDial re-resolves and rejects
	// before the dial is issued.
	h.dialContext = safeDialContext(cfg.UpstreamTimeout)
	h.httpClient = &http.Client{
		Timeout: cfg.UpstreamTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return h.dialContext(ctx, network, addr)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("live_blog: too many redirects")
			}
			host := req.URL.Host
			if host != pinnedHost && host != pinnedCDNHost {
				return fmt.Errorf("live_blog: redirect to off-host %q refused", host)
			}
			return nil
		},
	}

	h.rewriter = NewHTMLRewriter(RewriterConfig{
		SourceHost:         upURL.Host,
		SourceHostSuffixes: []string{upURL.Host, cdnURL.Host},
		CDNProxyPrefix:     "/_cdn/",
		BrandFromTokens:    []string{"Хабр", "Habr", "habrahabr"},
		BrandTo:            cfg.TargetBrand,
		LogoImgClassMatch:  "tm-logo__image",
		StripTagSignatures: []TagSignature{
			{Tag: "header", ClassContains: "tm-header"},
			{Tag: "div", ClassContains: "comments-widget"},
			{Tag: "footer", ClassContains: "tm-footer"},
		},
		InternalPathRewrite: func(p string) string {
			// /ru/articles/123/ → /blog/123/, preserve trailing slash/query.
			const prefix = "/ru/articles/"
			if len(p) >= len(prefix) && p[:len(prefix)] == prefix {
				return "/blog/" + p[len(prefix):]
			}
			return p
		},
		TargetTitleSuffix: cfg.TargetTitleSuffix,
		TargetLogoPath:    cfg.TargetLogoPath,
		TargetFaviconPath: "/assets/favicon.ico",
		MaxOutputBytes:    cfg.MaxBodyBytes,
		MaxTagDepth:       200,
	})

	return h, nil
}

// Matches returns true iff path is inside the live-blog namespace (article,
// article index, or CDN asset). Path must be the raw URL path (already
// cleaned by http.ServeMux earlier in the chain).
func (h *LiveBlogHandler) Matches(path string) bool {
	if path == "/blog" || path == "/blog/" {
		return true
	}
	if h.articleRe.MatchString(path) {
		return true
	}
	if len(path) > len(h.cdnPrefix) && path[:len(h.cdnPrefix)] == h.cdnPrefix {
		return true
	}
	return false
}

// ServeHTTP routes matched paths and emits a branded response. Always writes
// 2xx / 404; 5xx and 429 upstream failures are rewritten into SPA fallback
// 200 to prevent a timing oracle that distinguishes live-blog from real
// origin.
//
// An outer defer-recover wrapper (A3-I-MED-4) catches panics from articleRe
// matching, the rewriter pipeline, or any nested handler. On recovery we
// log + tick the dedicated panic counter and emit a generic 500 so a single
// bad input cannot crash the listening goroutine.
func (h *LiveBlogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			if h.metrics != nil {
				h.metrics.DecoyLiveBlogServeHTTPPanic.Add(1)
			}
			path := ""
			if r != nil && r.URL != nil {
				path = r.URL.Path
			}
			slog.Error("live_blog ServeHTTP panic",
				"err", rec,
				"stack", string(debug.Stack()),
				"path", path,
			)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}()

	if h.metrics != nil {
		h.metrics.DecoyLiveBlogRequests.Add(1)
	}
	switch {
	case r.URL.Path == "/blog" || r.URL.Path == "/blog/":
		h.serveArticleIndex(w, r)
	case h.articleRe.MatchString(r.URL.Path):
		articleID := h.articleRe.FindStringSubmatch(r.URL.Path)[1]
		h.serveArticle(w, r, articleID)
	case len(r.URL.Path) > len(h.cdnPrefix) && r.URL.Path[:len(h.cdnPrefix)] == h.cdnPrefix:
		subpath := r.URL.Path[len(h.cdnPrefix):]
		h.serveCDN(w, r, subpath)
	default:
		http.NotFound(w, r)
	}
}

func (h *LiveBlogHandler) serveArticle(w http.ResponseWriter, r *http.Request, articleID string) {
	start := time.Now()
	key := "/blog/" + articleID

	// Step 1: fresh cache hit.
	if entry, fresh, _ := h.lookupCache(key); fresh && entry != nil {
		h.writeCached(w, entry)
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogCacheHits.Add(1)
		}
		return
	}

	// Step 2: rate-limiter check.
	if !h.upstreamLimiter.Allow() {
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogUpstreamRateLimited.Add(1)
		}
		if entry, _, stale := h.lookupCache(key); stale && entry != nil {
			h.writeCached(w, entry)
			if h.metrics != nil {
				h.metrics.DecoyLiveBlogStaleServed.Add(1)
			}
			return
		}
		h.applyFallbackJitter(start)
		h.serveFallback(w, r)
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogFallbackSPA.Add(1)
		}
		return
	}

	// Step 3: upstream fetch.
	body, _, status, err := h.fetchUpstreamArticle(articleID)
	switch {
	case err != nil || status >= 500 || status == 429:
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogUpstreamErr.Add(1)
		}
		if entry, _, stale := h.lookupCache(key); stale && entry != nil {
			h.writeCached(w, entry)
			if h.metrics != nil {
				h.metrics.DecoyLiveBlogStaleServed.Add(1)
			}
			return
		}
		h.applyFallbackJitter(start)
		h.serveFallback(w, r)
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogFallbackSPA.Add(1)
		}
		return
	case status == 404:
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogUpstreamErr.Add(1)
		}
		h.applyFallbackJitter(start)
		http.NotFound(w, r)
		return
	case status != 200:
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogUpstreamErr.Add(1)
			h.metrics.DecoyLiveBlogFallbackSPA.Add(1)
		}
		h.applyFallbackJitter(start)
		h.serveFallback(w, r)
		return
	}

	// Step 4: rewrite.
	out, rerr := h.rewriter.Rewrite(bytes.NewReader(body))
	if rerr != nil {
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogRewritePanic.Add(1)
			h.metrics.DecoyLiveBlogFallbackSPA.Add(1)
		}
		h.applyFallbackJitter(start)
		h.serveFallback(w, r)
		return
	}

	// Step 5: cache + serve.
	entry := cachedPage{
		body:        out,
		contentType: "text/html; charset=utf-8",
		status:      200,
		fetchedAt:   time.Now().UnixNano(),
	}
	h.cache.Add(key, entry)
	h.writeCached(w, &entry)
	if h.metrics != nil {
		h.metrics.DecoyLiveBlogCacheMisses.Add(1)
		h.metrics.DecoyLiveBlogUpstreamOK.Add(1)
	}
}

func (h *LiveBlogHandler) serveArticleIndex(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	key := "/blog/_index"

	// Step 1: fresh cache hit.
	if entry, fresh, _ := h.lookupCache(key); fresh && entry != nil {
		h.writeCached(w, entry)
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogCacheHits.Add(1)
		}
		return
	}

	// Step 2: rate-limiter check.
	if !h.upstreamLimiter.Allow() {
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogUpstreamRateLimited.Add(1)
		}
		if entry, _, stale := h.lookupCache(key); stale && entry != nil {
			h.writeCached(w, entry)
			if h.metrics != nil {
				h.metrics.DecoyLiveBlogStaleServed.Add(1)
			}
			return
		}
		h.applyFallbackJitter(start)
		h.serveFallback(w, r)
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogFallbackSPA.Add(1)
		}
		return
	}

	// Step 3: upstream fetch.
	body, _, status, err := h.fetchUpstreamIndex()
	switch {
	case err != nil || status >= 500 || status == 429:
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogUpstreamErr.Add(1)
		}
		if entry, _, stale := h.lookupCache(key); stale && entry != nil {
			h.writeCached(w, entry)
			if h.metrics != nil {
				h.metrics.DecoyLiveBlogStaleServed.Add(1)
			}
			return
		}
		h.applyFallbackJitter(start)
		h.serveFallback(w, r)
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogFallbackSPA.Add(1)
		}
		return
	case status == 404:
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogUpstreamErr.Add(1)
		}
		h.applyFallbackJitter(start)
		http.NotFound(w, r)
		return
	case status != 200:
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogUpstreamErr.Add(1)
			h.metrics.DecoyLiveBlogFallbackSPA.Add(1)
		}
		h.applyFallbackJitter(start)
		h.serveFallback(w, r)
		return
	}

	// Step 4: rewrite.
	out, rerr := h.rewriter.Rewrite(bytes.NewReader(body))
	if rerr != nil {
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogRewritePanic.Add(1)
			h.metrics.DecoyLiveBlogFallbackSPA.Add(1)
		}
		h.applyFallbackJitter(start)
		h.serveFallback(w, r)
		return
	}

	// Step 5: cache + serve.
	entry := cachedPage{
		body:        out,
		contentType: "text/html; charset=utf-8",
		status:      200,
		fetchedAt:   time.Now().UnixNano(),
	}
	h.cache.Add(key, entry)
	h.writeCached(w, &entry)
	if h.metrics != nil {
		h.metrics.DecoyLiveBlogCacheMisses.Add(1)
		h.metrics.DecoyLiveBlogUpstreamOK.Add(1)
	}
}

// writeCached writes the cached page body with our standardized response
// headers (decoy baseline + live-blog Cache-Control).
func (h *LiveBlogHandler) writeCached(w http.ResponseWriter, entry *cachedPage) {
	hdr := w.Header()
	hdr.Set("Content-Type", entry.contentType)
	hdr.Set("Cache-Control", "public, max-age=300")
	hdr.Set("Server", "nginx/1.27.3")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("X-Frame-Options", "SAMEORIGIN")
	hdr.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.WriteHeader(entry.status)
	w.Write(entry.body)
}

// serveFallback routes a request to the SPA decoy as a 200 OK response. Used
// for upstream-failure paths and rewriter panics. If the SPA handler is nil
// (only expected in unit tests that don't care), we emit a minimal 200.
//
// The SPA handler is invoked with a placeholder request (GET /) rather than
// the original r to prevent a size-oracle attack: a 404 fallback body that
// echoes the request path (e.g. /blog/<long-id>) would make response size
// correlate with request URL length, distinguishing live-blog 5xx-fallback
// traffic from real SPA hits. We preserve Host/TLS/RemoteAddr/Context from r
// so downstream middleware still sees a realistic request envelope.
func (h *LiveBlogHandler) serveFallback(w http.ResponseWriter, r *http.Request) {
	if h.fallback != nil {
		ph := httpPlaceholderRequest()
		if r != nil {
			ph.Host = r.Host
			ph.TLS = r.TLS
			ph.RemoteAddr = r.RemoteAddr
			ph = ph.WithContext(r.Context())
		}
		h.fallback.ServeHTTP(w, ph)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(`<!DOCTYPE html><html><body>Unavailable</body></html>`))
}

// serveCDN proxies habr's static CDN under /_cdn/*. No rewriting — opaque
// binary passthrough with our own response headers.
func (h *LiveBlogHandler) serveCDN(w http.ResponseWriter, r *http.Request, subpath string) {
	start := time.Now()
	// Minimal sanitization: reject path traversal + null bytes.
	if subpath == "" || strings.Contains(subpath, "..") || strings.ContainsAny(subpath, "\x00\r\n") {
		h.applyFallbackJitter(start)
		h.writeNginxLike404(w)
		return
	}
	key := h.cdnPrefix + subpath
	if entry, fresh, _ := h.lookupCDNCache(key); fresh && entry != nil {
		h.writeCachedCDN(w, entry)
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogCDNHits.Add(1)
		}
		return
	}
	if !h.upstreamLimiter.Allow() {
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogUpstreamRateLimited.Add(1)
			h.metrics.DecoyLiveBlogCDNErrors.Add(1)
		}
		h.applyFallbackJitter(start)
		h.writeNginxLike404(w)
		return
	}
	body, ct, status, err := h.fetchUpstreamCDN(subpath)
	if err != nil || status != 200 {
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogCDNErrors.Add(1)
		}
		h.applyFallbackJitter(start)
		h.writeNginxLike404(w)
		return
	}
	entry := cachedPage{
		body:        body,
		contentType: ct,
		status:      200,
		fetchedAt:   time.Now().UnixNano(),
	}
	h.cdnCache.Add(key, entry)
	h.writeCachedCDN(w, &entry)
	if h.metrics != nil {
		h.metrics.DecoyLiveBlogCDNHits.Add(1)
	}
}

// writeCachedCDN — CDN-flavored header set: longer Cache-Control, preserved
// upstream Content-Type (we don't know if it's CSS/JS/woff2/etc).
func (h *LiveBlogHandler) writeCachedCDN(w http.ResponseWriter, entry *cachedPage) {
	hdr := w.Header()
	if entry.contentType != "" {
		hdr.Set("Content-Type", entry.contentType)
	}
	hdr.Set("Cache-Control", "public, max-age=86400")
	hdr.Set("Server", "nginx/1.27.3")
	hdr.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(entry.status)
	w.Write(entry.body)
}

// lookupCache classifies the cache state for a path. Returns:
//   - entry: the cached page, if present (fresh OR stale), else nil
//   - fresh: true if age ≤ CacheTTL
//   - stale: true if CacheTTL < age ≤ CacheTTL + CacheStaleGrace
//
// Both fresh and stale can only be true for present entries; they're mutually
// exclusive. A pure miss returns (nil, false, false).
func (h *LiveBlogHandler) lookupCache(key string) (entry *cachedPage, fresh, stale bool) {
	e, ok := h.cache.Get(key)
	if !ok {
		return nil, false, false
	}
	age := time.Now().UnixNano() - e.fetchedAt
	ttl := h.cfg.CacheTTL.Nanoseconds()
	switch {
	case age <= ttl:
		return &e, true, false
	case age <= ttl+h.cfg.CacheStaleGrace.Nanoseconds():
		return &e, false, true
	default:
		return nil, false, false
	}
}

// lookupCDNCache — same as lookupCache but on the CDN cache (separate to keep
// eviction pressure isolated and because CDN entries have a longer lifetime).
func (h *LiveBlogHandler) lookupCDNCache(key string) (entry *cachedPage, fresh, stale bool) {
	e, ok := h.cdnCache.Get(key)
	if !ok {
		return nil, false, false
	}
	age := time.Now().UnixNano() - e.fetchedAt
	ttl := h.cfg.CacheTTL.Nanoseconds()
	switch {
	case age <= ttl:
		return &e, true, false
	case age <= ttl+h.cfg.CacheStaleGrace.Nanoseconds():
		return &e, false, true
	default:
		return nil, false, false
	}
}

// fetchUpstreamArticle fetches habr /ru/articles/<id> with size + header
// sanitization. Returned body is the raw upstream payload (no rewriting yet
// — caller chains through HTMLRewriter.Rewrite).
func (h *LiveBlogHandler) fetchUpstreamArticle(articleID string) (body []byte, contentType string, status int, err error) {
	return h.fetchUpstream(h.upstreamURL.ResolveReference(&url.URL{Path: "/ru/articles/" + articleID}).String(), h.cfg.MaxBodyBytes)
}

func (h *LiveBlogHandler) fetchUpstreamIndex() (body []byte, contentType string, status int, err error) {
	return h.fetchUpstream(h.upstreamURL.ResolveReference(&url.URL{Path: "/ru/top/"}).String(), h.cfg.MaxBodyBytes)
}

func (h *LiveBlogHandler) fetchUpstreamCDN(subpath string) (body []byte, contentType string, status int, err error) {
	return h.fetchUpstream(h.cdnUpstreamURL.ResolveReference(&url.URL{Path: "/" + subpath}).String(), h.cfg.CDNMaxBodyBytes)
}

// fetchUpstream runs a single GET with body-size capping and header
// sanitization. Sets a realistic Chrome UA; does not forward any client
// headers. Returns (body, content-type, status, err).
func (h *LiveBlogHandler) fetchUpstream(rawURL string, maxBody int) ([]byte, string, int, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", 0, err
	}
	// Server-side outbound to upstream (habr.com) — not wire-visible to TSPU.
	// Aligned with browser.LockedChromeUA() (Chrome/133) to keep the project's
	// Chrome major consistent across server-side requests too.
	req.Header.Set("User-Agent", browser.LockedChromeUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru,en;q=0.8")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, int64(maxBody)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", 0, err
	}
	if len(body) > maxBody {
		return nil, "", 0, fmt.Errorf("live_blog: upstream body too large (>%d)", maxBody)
	}
	return body, resp.Header.Get("Content-Type"), resp.StatusCode, nil
}

// writeNginxLike404 writes a 404 response that mimics nginx default 404 page
// (body + headers). Used for /_cdn/* fail/limit paths to fix body-signature
// oracle (C3 from T1.3 code review 2026-04-23).
func (h *LiveBlogHandler) writeNginxLike404(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx/1.27.3")
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(nginxLike404Body)))
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(nginxLike404Body)
}

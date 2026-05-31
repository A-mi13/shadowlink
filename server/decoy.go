package server

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DecoyHandler serves a static website to unauthenticated requests.
// This is the "real website" that TSPU active probes see.
// Key difference from VLESS+Reality: we HOST our own site, not proxy someone else's.
//
// Sub-phase B (Domain Diversity): supports per-Host decoy serving.
// When domainMap is non-empty, ServeHTTP picks a directory based on r.Host;
// each unique directory gets its own precomputed http.FileServer.
type DecoyHandler struct {
	defaultDir    string
	defaultServer http.Handler
	hasIndex      bool

	// domainMap maps Host (no port) → decoy directory path.
	// nil/empty → all requests served by defaultServer.
	domainMap map[string]string

	// perDirServers caches precomputed http.FileServer per unique directory
	// referenced by domainMap. Built once in NewDecoyHandler.
	perDirServers map[string]http.Handler

	// NEW: per-host persona (spec §2.4)
	domainPersona  map[string]string
	defaultPersona string
}

// DecoyHandlerConfig — persona-aware config for NewDecoyHandlerV2.
// Backwards compat: DomainPersona == nil → every host gets DefaultPersona.
type DecoyHandlerConfig struct {
	DefaultDir     string
	DomainMap      map[string]string
	DomainPersona  map[string]string
	DefaultPersona string
}

// NewDecoyHandlerV2 — persona-aware constructor. Wraps NewDecoyHandler.
func NewDecoyHandlerV2(cfg DecoyHandlerConfig) *DecoyHandler {
	d := NewDecoyHandler(cfg.DefaultDir, cfg.DomainMap)
	d.domainPersona = cfg.DomainPersona
	d.defaultPersona = cfg.DefaultPersona
	if d.defaultPersona == "" {
		d.defaultPersona = "saas"
	}
	return d
}

// resolvePersona returns the persona for a request Host.
func (d *DecoyHandler) resolvePersona(host string) string {
	if d.domainPersona != nil {
		h := host
		if i := indexByte(h, ':'); i >= 0 {
			h = h[:i]
		}
		if p, ok := d.domainPersona[h]; ok && p != "" {
			return p
		}
	}
	if d.defaultPersona != "" {
		return d.defaultPersona
	}
	return "saas"
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// NewDecoyHandler creates a handler serving static files from defaultDir.
// If defaultDir is empty or doesn't exist, serves a minimal default page.
//
// domainMap (optional) maps Host → directory for per-domain decoy serving.
// Pass nil to preserve legacy single-dir behaviour.
func NewDecoyHandler(defaultDir string, domainMap map[string]string) *DecoyHandler {
	d := &DecoyHandler{
		defaultDir:    defaultDir,
		domainMap:     domainMap,
		perDirServers: make(map[string]http.Handler),
	}

	var defaultDirOK bool
	d.defaultServer, defaultDirOK = buildDirServer(defaultDir)
	// hasIndex semantics retained: true if defaultDir served real files with index.html OR fallback is in use.
	if defaultDirOK {
		_, idxErr := os.Stat(filepath.Join(defaultDir, "index.html"))
		d.hasIndex = idxErr == nil
	} else {
		// fallback page always renders "/" → 200, treat as content.
		d.hasIndex = true
	}

	// Pre-build per-dir servers for every unique directory referenced by domainMap.
	// Skip empty values (treated as "use default" by resolveDecoyDir).
	seen := map[string]bool{defaultDir: true}
	for host, dir := range domainMap {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		srv, dirOK := buildDirServer(dir)
		if !dirOK {
			slog.Warn("decoy: configured directory unavailable, falling back to default page",
				"host", host, "dir", dir)
		}
		d.perDirServers[dir] = srv
	}

	return d
}

// buildDirServer constructs an http.Handler serving files from dir.
// If dir is empty or doesn't exist, returns the default minimal page and dirOK=false.
// Caller is responsible for computing hasIndex semantics separately.
func buildDirServer(dir string) (handler http.Handler, dirOK bool) {
	if dir != "" {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			srv := http.FileServer(http.Dir(dir))
			return srv, true
		}
	}
	return http.HandlerFunc(defaultDecoyPage), false
}

// ServeHTTP serves decoy with persona-specific headers + custom 404. Spec §2.4.
func (d *DecoyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	persona := d.resolvePersona(r.Host)
	switch persona {
	case "blog":
		setBlogHeaders(w)
	case "utility":
		setUtilityHeaders(w)
	case "saas":
		fallthrough
	default:
		setSaaSHeaders(w)
	}

	dir := d.defaultDir
	server := d.defaultServer
	if d.domainMap != nil {
		resolved := resolveDecoyDir(r.Host, d.domainMap, d.defaultDir)
		if resolved != d.defaultDir {
			if srv, ok := d.perDirServers[resolved]; ok {
				server = srv
				dir = resolved
			}
		}
	}

	// Linear-style SPA fallback: paths without a file extension (e.g. /pricing,
	// /about) are React Router routes — on reload FileServer would 404 because
	// no such file exists on disk. Serve index.html with 200 instead so the
	// SPA can take over routing client-side. Asset paths (foo.png, bar.css)
	// keep the 404 path through fourOhFourWrapper → custom 404.html.
	//
	// Detection: a request path "looks like asset" if its last segment contains
	// a dot. /api/foo → SPA fallback (no dot), /foo.png → asset → real 404.
	// /api/foo.json → asset (treat as real 404). Root "/" is handled by
	// FileServer itself (serves index.html for "/"), so we don't intercept it.
	wrap := &fourOhFourWrapper{
		ResponseWriter:  w,
		custom404Path:   filepath.Join(dir, "404.html"),
		spaFallbackPath: filepath.Join(dir, "index.html"),
		isSPARoute:      isSPARoute(r.URL.Path),
	}
	server.ServeHTTP(wrap, r)
}

// isSPARoute returns true if the path looks like a SPA route (no file ext in
// the last segment) — should serve index.html on 404 instead of custom 404.html.
// Empty path or "/" → false (root is handled by FileServer directly).
func isSPARoute(p string) bool {
	if p == "" || p == "/" {
		return false
	}
	last := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		last = p[i+1:]
	}
	// If last segment is empty (trailing slash), still treat as SPA route.
	if last == "" {
		return true
	}
	// A dot in the last segment = file extension = real asset.
	return !strings.Contains(last, ".")
}

func setSaaSHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'")
}

func setBlogHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'")
}

func setUtilityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// fourOhFourWrapper intercepts WriteHeader(404) from the FileServer and serves
// either index.html (SPA fallback, 200) or custom 404.html (real asset 404).
// Spec §2.4 + post-Wave-1-3 SPA reload fix.
type fourOhFourWrapper struct {
	http.ResponseWriter
	custom404Path   string
	spaFallbackPath string
	isSPARoute      bool
	intercepted     bool
}

func (w *fourOhFourWrapper) WriteHeader(status int) {
	if status == http.StatusNotFound && !w.intercepted {
		w.intercepted = true

		// SPA route reload: /pricing, /about etc. → serve index.html with 200
		// so React Router takes over. Real assets (foo.png) → custom 404 below.
		if w.isSPARoute {
			body, err := os.ReadFile(w.spaFallbackPath)
			if err == nil {
				w.ResponseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
				if w.ResponseWriter.Header().Get("Cache-Control") == "" {
					w.ResponseWriter.Header().Set("Cache-Control", "no-cache, must-revalidate")
				}
				w.ResponseWriter.WriteHeader(http.StatusOK)
				_, _ = w.ResponseWriter.Write(body)
				return
			}
			// index.html missing — fall through to 404 path below.
		}

		body, err := os.ReadFile(w.custom404Path)
		if err != nil {
			w.ResponseWriter.WriteHeader(status)
			return
		}
		w.ResponseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Don't overwrite Cache-Control if persona setter already chose one.
		if w.ResponseWriter.Header().Get("Cache-Control") == "" {
			w.ResponseWriter.Header().Set("Cache-Control", "public, max-age=300")
		}
		w.ResponseWriter.WriteHeader(http.StatusNotFound)
		_, _ = w.ResponseWriter.Write(body)
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *fourOhFourWrapper) Write(b []byte) (int, error) {
	if w.intercepted {
		// Suppress FileServer's default body since we already wrote custom.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// HasContent returns true if the decoy has actual content to serve.
func (d *DecoyHandler) HasContent() bool {
	return d.hasIndex
}

func defaultDecoyPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(200)
	w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:640px;margin:80px auto;padding:0 20px;color:#333;line-height:1.6}
h1{font-weight:400;color:#111}a{color:#0066cc}
</style>
</head>
<body>
<h1>Welcome</h1>
<p>This site is under construction. Check back soon for updates.</p>
<p>If you believe you've reached this page in error, please <a href="mailto:admin@example.com">contact us</a>.</p>
<footer><small>&copy; 2026</small></footer>
</body>
</html>`))
}

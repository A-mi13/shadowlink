package server

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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

// ServeHTTP serves the decoy site with proper headers matching a real web server.
// Selects the directory via Host header → domainMap lookup; falls back to defaultDir.
func (d *DecoyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add headers that a real nginx/caddy would send
	w.Header().Set("Server", "nginx/1.27.3")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	server := d.defaultServer
	if d.domainMap != nil {
		dir := resolveDecoyDir(r.Host, d.domainMap, d.defaultDir)
		if dir != d.defaultDir {
			if srv, ok := d.perDirServers[dir]; ok {
				server = srv
			}
		}
	}
	server.ServeHTTP(w, r)
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

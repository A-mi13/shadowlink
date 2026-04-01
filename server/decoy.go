package server

import (
	"net/http"
	"os"
	"path/filepath"
)

// DecoyHandler serves a static website to unauthenticated requests.
// This is the "real website" that TSPU active probes see.
// Key difference from VLESS+Reality: we HOST our own site, not proxy someone else's.
type DecoyHandler struct {
	fileServer http.Handler
	hasIndex   bool
}

// NewDecoyHandler creates a handler serving static files from dir.
// If dir is empty or doesn't exist, serves a minimal default page.
func NewDecoyHandler(dir string) *DecoyHandler {
	d := &DecoyHandler{}

	if dir != "" {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			d.fileServer = http.FileServer(http.Dir(dir))
			// Check if index.html exists
			_, err := os.Stat(filepath.Join(dir, "index.html"))
			d.hasIndex = err == nil
			return d
		}
	}

	// Fallback: minimal page that looks like a real site
	d.fileServer = http.HandlerFunc(defaultDecoyPage)
	d.hasIndex = true
	return d
}

// ServeHTTP serves the decoy site with proper headers matching a real web server.
func (d *DecoyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add headers that a real nginx/caddy would send
	w.Header().Set("Server", "nginx/1.27.3")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	d.fileServer.ServeHTTP(w, r)
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

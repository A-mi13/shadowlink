package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecoyHandlerServesStaticFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"),
		[]byte("<html><body>My Cool Site</body></html>"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "style.css"),
		[]byte("body{color:red}"), 0644))

	handler := NewDecoyHandler(dir, nil)
	assert.True(t, handler.HasContent())

	// Test index
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "My Cool Site")

	// Test CSS
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/style.css", nil))
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "color:red")
}

func TestDecoyHandlerDefaultPage(t *testing.T) {
	handler := NewDecoyHandler("", nil) // no dir

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "under construction")
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
}

func TestDecoyHandler404ForMissingFiles(t *testing.T) {
	handler := NewDecoyHandler("", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/nonexistent.js", nil))
	assert.Equal(t, 404, w.Code)
}

func TestDecoyHandlerSecurityHeaders(t *testing.T) {
	handler := NewDecoyHandler("", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	// Server header must be absent — behind CF it becomes "cloudflare";
	// in direct-IP fallback emitting "nginx/1.27.3" (Nov 2024) in May 2026
	// is a version-anachronism fingerprint.
	assert.Equal(t, "", w.Header().Get("Server"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"))
}

func TestDecoyHandlerNonexistentDir(t *testing.T) {
	handler := NewDecoyHandler("/path/that/does/not/exist", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	// Falls back to default page
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "under construction")
}

func TestDecoyHandlerGETAndHEAD(t *testing.T) {
	handler := NewDecoyHandler("", nil)

	// GET
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, 200, w.Code)

	// HEAD
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("HEAD", "/", nil))
	assert.Equal(t, 200, w.Code)
}

func TestDecoyHandlerServesPlausibleWebsite(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"),
		[]byte("<html><head><title>Blog</title></head><body><h1>My Blog</h1></body></html>"), 0644)

	handler := NewDecoyHandler(dir, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	handler.ServeHTTP(w, req)

	// Response should look like a normal website
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "", w.Header().Get("Server"), "Server header must be empty (CF sets its own)")
	body := w.Body.String()
	assert.Contains(t, body, "<html>")
	assert.Contains(t, body, "Blog")
}

func TestDecoyHandlerMultipleRequests(t *testing.T) {
	handler := NewDecoyHandler("", nil)

	// Simulate TSPU probing multiple endpoints
	paths := []string{"/", "/index.html", "/robots.txt", "/favicon.ico", "/.well-known/acme-challenge/test"}
	for _, p := range paths {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		// Should never return 5xx
		assert.Less(t, w.Code, 500, "path %s should not cause server error", p)
	}
}

func TestDecoyHandlerPOSTReturns404(t *testing.T) {
	handler := NewDecoyHandler("", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/api/test", nil))

	// POST to unknown path = 404 (not 405) — looks like normal web server
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDecoy_NoServerHeader guards that the decoy handler emits no Server
// header. Behind CF orange cloud CF replaces Server with "cloudflare"; in
// direct-IP or leak scenarios, emitting "nginx/1.27.3" (Nov 2024) on
// May 2026 is a version-anachronism fingerprint.
func TestDecoy_NoServerHeader(t *testing.T) {
	handler := NewDecoyHandler("", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, "", w.Header().Get("Server"),
		"Server header must be empty — CF sets its own; emitting nginx/1.27.3 is a fingerprint")
}

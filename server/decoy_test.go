package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestDecoyHandlerV2_PersonaResolution(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html>hello</html>"), 0644); err != nil {
		t.Fatal(err)
	}
	h := NewDecoyHandlerV2(DecoyHandlerConfig{
		DefaultDir:     tmp,
		DefaultPersona: "saas",
		DomainPersona: map[string]string{
			"myblog.io":    "blog",
			"jsontools.io": "utility",
		},
	})

	cases := []struct {
		host string
		want string
	}{
		{"datacanvases.com", "saas"},
		{"myblog.io", "blog"},
		{"jsontools.io", "utility"},
		{"unknown:8080", "saas"},
	}
	for _, c := range cases {
		got := h.resolvePersona(c.host)
		if got != c.want {
			t.Errorf("resolvePersona(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

func TestDecoyHandlerV2_BackwardsCompatNilPersonaMap(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html>x</html>"), 0644)
	h := NewDecoyHandlerV2(DecoyHandlerConfig{
		DefaultDir:     tmp,
		DefaultPersona: "saas",
	})
	if got := h.resolvePersona("any.host"); got != "saas" {
		t.Errorf("nil DomainPersona must default to saas, got %q", got)
	}
}

func TestDecoyHandlerV2_ServeHTTPStillWorks(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html>x</html>"), 0644)
	h := NewDecoyHandlerV2(DecoyHandlerConfig{DefaultDir: tmp, DefaultPersona: "saas"})

	req := httptest.NewRequest("GET", "http://x/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestDecoyHandlerV2_PersonaHeaders(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html>x</html>"), 0644)
	h := NewDecoyHandlerV2(DecoyHandlerConfig{
		DefaultDir:     tmp,
		DefaultPersona: "saas",
		DomainPersona: map[string]string{
			"blog.io":    "blog",
			"utility.io": "utility",
		},
	})

	cases := []struct {
		host           string
		mustHave       []string
		mustHaveValues map[string]string
		mustNotHave    []string
	}{
		{
			host:     "any.com",
			mustHave: []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "Referrer-Policy"},
			mustHaveValues: map[string]string{
				"X-Frame-Options": "SAMEORIGIN",
			},
			mustNotHave: []string{"X-Powered-By", "X-Region"},
		},
		{
			host:        "blog.io",
			mustHave:    []string{"Strict-Transport-Security", "Content-Security-Policy"},
			mustNotHave: []string{"X-Powered-By"},
		},
		{
			host:        "utility.io",
			mustHave:    []string{"Strict-Transport-Security", "X-Frame-Options"},
			mustNotHave: []string{"Content-Security-Policy", "X-Powered-By"},
		},
	}

	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+c.host+"/", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			for _, name := range c.mustHave {
				if w.Header().Get(name) == "" {
					t.Errorf("[%s] missing header %q", c.host, name)
				}
			}
			for name, want := range c.mustHaveValues {
				if got := w.Header().Get(name); got != want {
					t.Errorf("[%s] header %q = %q, want %q", c.host, name, got, want)
				}
			}
			for _, name := range c.mustNotHave {
				if w.Header().Get(name) != "" {
					t.Errorf("[%s] forbidden header %q present", c.host, name)
				}
			}
		})
	}
}

func TestDecoyHandlerV2_Custom404HTMLServed(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html>idx</html>"), 0644)
	_ = os.WriteFile(filepath.Join(tmp, "404.html"), []byte("<html>my-custom-404</html>"), 0644)

	h := NewDecoyHandlerV2(DecoyHandlerConfig{
		DefaultDir:     tmp,
		DefaultPersona: "saas",
	})

	req := httptest.NewRequest("GET", "http://any.com/nonexistent-asset.png", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "my-custom-404") {
		t.Errorf("expected custom 404.html body, got: %s", body)
	}
	if ct := w.Header().Get("Content-Type"); ct == "" || !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type should be text/html, got %q", ct)
	}
}

func TestDecoyHandlerV2_FallbackTo404WhenCustomMissing(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html>idx</html>"), 0644)

	h := NewDecoyHandlerV2(DecoyHandlerConfig{
		DefaultDir:     tmp,
		DefaultPersona: "saas",
	})

	req := httptest.NewRequest("GET", "http://any.com/nope.png", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 fallback, got %d", w.Code)
	}
}

// TestDecoyHandlerV2_SPAFallbackOnReload locks in the SPA-reload-friendly
// behavior: a request like GET /pricing (no extension in last segment) must
// serve index.html with 200 instead of a 404. Without this React Router can't
// take over routing on a hard browser reload because the browser sees a 404
// page before JS loads.
func TestDecoyHandlerV2_SPAFallbackOnReload(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html>spa-index</html>"), 0644)
	_ = os.WriteFile(filepath.Join(tmp, "404.html"), []byte("<html>my-custom-404</html>"), 0644)

	h := NewDecoyHandlerV2(DecoyHandlerConfig{
		DefaultDir:     tmp,
		DefaultPersona: "saas",
	})

	cases := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
	}{
		{"SPA route /pricing", "/pricing", http.StatusOK, "spa-index"},
		{"SPA route /about", "/about", http.StatusOK, "spa-index"},
		{"SPA route /docs/getting-started", "/docs/getting-started", http.StatusOK, "spa-index"},
		{"Asset .png → custom 404", "/missing.png", http.StatusNotFound, "my-custom-404"},
		{"Asset .css → custom 404", "/styles.css", http.StatusNotFound, "my-custom-404"},
		{"Asset deep .js → custom 404", "/assets/main.js", http.StatusNotFound, "my-custom-404"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://x"+c.path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != c.wantStatus {
				t.Errorf("[%s] status = %d, want %d", c.path, w.Code, c.wantStatus)
			}
			if !strings.Contains(w.Body.String(), c.wantBody) {
				t.Errorf("[%s] body missing %q; got %q", c.path, c.wantBody, w.Body.String())
			}
		})
	}
}

func TestDecoyHandlerV2_PersonaHeadersOn404(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html>x</html>"), 0644)
	_ = os.WriteFile(filepath.Join(tmp, "404.html"), []byte("<html>404-body</html>"), 0644)

	h := NewDecoyHandlerV2(DecoyHandlerConfig{
		DefaultDir:     tmp,
		DefaultPersona: "blog",
	})

	req := httptest.NewRequest("GET", "http://x/missing.png", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "404-body") {
		t.Errorf("expected custom 404 body, got %q", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "404 page not found") {
		t.Errorf("FileServer default 404 body leaked through wrapper: %q", w.Body.String())
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("persona headers should still be present on 404 response")
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Error("blog persona CSP missing on 404")
	}
}

// TestPersonaHeadersMatchNginxSnippets is a cross-module drift guard. Phase B
// writes /etc/nginx/snippets/{saas,blog,utility}-headers.conf in the parent
// nixavpn module. This test reads the committed snippet files via a relative
// path and asserts every header value emitted by setSaaS/Blog/UtilityHeaders
// matches what nginx will emit. Drift = stable cross-path fingerprint.
//
// If Phase B hasn't merged yet, the test skips (snippet files missing).
func TestPersonaHeadersMatchNginxSnippets(t *testing.T) {
	snippetsDir := "../../internal/deploy/snippets"
	cases := []struct {
		persona     string
		snippetFile string
		setFn       func(http.ResponseWriter)
	}{
		{"saas", "saas-headers.conf", setSaaSHeaders},
		{"blog", "blog-headers.conf", setBlogHeaders},
		{"utility", "utility-headers.conf", setUtilityHeaders},
	}

	for _, c := range cases {
		t.Run(c.persona, func(t *testing.T) {
			path := filepath.Join(snippetsDir, c.snippetFile)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("snippet not yet committed (Phase B not merged?): %s — %v", path, err)
				return
			}
			snippet := string(b)

			w := httptest.NewRecorder()
			c.setFn(w)

			for _, line := range strings.Split(snippet, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "add_header ") {
					continue
				}
				rest := strings.TrimPrefix(line, "add_header ")
				rest = strings.TrimSuffix(rest, ";")
				rest = strings.TrimSuffix(rest, " always")
				sp := strings.IndexByte(rest, ' ')
				if sp <= 0 {
					continue
				}
				name := rest[:sp]
				val := strings.TrimSpace(rest[sp+1:])
				val = strings.Trim(val, `"`)
				got := w.Header().Get(name)
				if got != val {
					t.Errorf("persona=%s header %q: Go=%q nginx=%q (drift!)",
						c.persona, name, got, val)
				}
			}
		})
	}
}

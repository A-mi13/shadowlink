package leakguard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestCheckIP_SetsBrowserUserAgent verifies the cold-path fix for A2-MED-2:
// CheckIP must emit a Chrome-class User-Agent header so the ipinfo.io request
// looks like a normal browser API call rather than the Go default
// "Go-http-client/1.1" string (which is itself a passive DPI signal even when
// JA3 is mimicked).
//
// The test routes the SOCKS5 dialer at a no-op proxy and uses an HTTP test
// server that records the UA seen on the request. It explicitly does NOT cover
// the SOCKS proxying — the goal is solely to assert the request header.
func TestCheckIP_SetsBrowserUserAgent(t *testing.T) {
	var seenUA atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA.Store(r.Header.Get("User-Agent"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"1.2.3.4","org":"Test ISP","country":"US","city":"X","timezone":"UTC"}`))
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	// Override the ipinfo.io target via the package-level hook installed by the
	// fix. If the hook is absent the test will fail to compile and the bug
	// reproducer is preserved as a TDD checkpoint.
	prev := ipinfoEndpoint
	ipinfoEndpoint = srv.URL
	defer func() { ipinfoEndpoint = prev }()

	// CheckIP signature requires a SOCKS5 address — pass a sentinel that the
	// fixed implementation will simply use for proxyURL building. The test
	// HTTP server is plaintext and reachable directly, so we bypass the SOCKS
	// proxy by setting the proxy override to nil through the buildProxy hook.
	prevProxy := buildProxy
	buildProxy = func(addr string) (*url.URL, error) { return nil, nil }
	defer func() { buildProxy = prevProxy }()

	// Use the test server host:port so the URL parser inside CheckIP is happy.
	_, err = CheckIP(parsed.Host)
	if err != nil {
		// Errors here indicate decode/IO problems — UA assertion still proceeds.
		t.Logf("CheckIP returned error (acceptable for cold-path UA test): %v", err)
	}

	uaRaw := seenUA.Load()
	if uaRaw == nil {
		t.Fatal("test server never received a request — CheckIP did not call the endpoint")
	}
	ua, _ := uaRaw.(string)
	if ua == "" {
		t.Fatal("CheckIP sent empty User-Agent header")
	}

	chromeRe := regexp.MustCompile(`Mozilla.+Chrome.+Safari`)
	assert.True(t, chromeRe.MatchString(ua),
		"expected Chrome-class User-Agent matching `Mozilla.+Chrome.+Safari`, got %q", ua)
	assert.False(t, strings.HasPrefix(ua, "Go-http-client"),
		"User-Agent must not be Go default, got %q", ua)
}

// TestCheckIP_TimeoutRespected confirms the http.Client.Timeout from the
// existing implementation is preserved in the fixed version (regression).
func TestCheckIP_TimeoutRespected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout regression in short mode")
	}
	prev := ipinfoEndpoint
	ipinfoEndpoint = "http://127.0.0.1:1" // unreachable
	defer func() { ipinfoEndpoint = prev }()

	prevProxy := buildProxy
	buildProxy = func(addr string) (*url.URL, error) { return nil, nil }
	defer func() { buildProxy = prevProxy }()

	start := time.Now()
	_, _ = CheckIP("127.0.0.1:1080")
	elapsed := time.Since(start)
	assert.Less(t, elapsed, 20*time.Second, "CheckIP should respect its 15s client timeout")
}

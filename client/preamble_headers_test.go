package client

import (
	"net/http"
	"strings"
	"testing"
)

// TestApplyChromeSubresourceHeaders verifies Sec-Fetch-Dest / Accept
// alignment with real Chrome subresource fetch semantics across the four
// classes WarmupRequests draws from (CSS, JS, image, fallback). Same-origin
// is the only Sec-Fetch-Site value (all paths in CoverPathsPool are
// same-origin against the decoy origin).
func TestApplyChromeSubresourceHeaders(t *testing.T) {
	cases := []struct {
		path       string
		wantDest   string
		wantAccept string
	}{
		{"/assets/main.css", "style", "text/css"},
		{"/assets/app.js", "script", "*/*"},
		{"/assets/hero.webp", "image", "image/"},
		{"/favicon.ico", "image", "image/"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com"+c.path, nil)
			applyChromeSubresourceHeaders(req, c.path)
			if got := req.Header.Get("Sec-Fetch-Dest"); got != c.wantDest {
				t.Errorf("Sec-Fetch-Dest = %q, want %q", got, c.wantDest)
			}
			if got := req.Header.Get("Accept"); !strings.Contains(got, c.wantAccept) {
				t.Errorf("Accept = %q, want to contain %q", got, c.wantAccept)
			}
			if got := req.Header.Get("Sec-Fetch-Site"); got != "same-origin" {
				t.Errorf("Sec-Fetch-Site = %q, want %q", got, "same-origin")
			}
		})
	}
}

// TestApplyChromeSubresourceHeaders_Fallback covers the default branch
// (no recognized extension): empty dest + cors mode, generic */* accept.
func TestApplyChromeSubresourceHeaders_Fallback(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/decide", nil)
	applyChromeSubresourceHeaders(req, "/decide")
	if got := req.Header.Get("Sec-Fetch-Dest"); got != "empty" {
		t.Errorf("Sec-Fetch-Dest = %q, want %q", got, "empty")
	}
	if got := req.Header.Get("Sec-Fetch-Mode"); got != "cors" {
		t.Errorf("Sec-Fetch-Mode = %q, want %q", got, "cors")
	}
	if got := req.Header.Get("Accept"); got != "*/*" {
		t.Errorf("Accept = %q, want %q", got, "*/*")
	}
}

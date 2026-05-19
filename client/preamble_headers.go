package client

import (
	"net/http"
	"strings"
)

// applyChromeSubresourceHeaders sets Sec-Fetch-Dest/Mode/Site and Accept
// headers on req based on the path's extension, mirroring real Chrome
// subresource fetch semantics. Used by WarmupRequests for NaiveProxy-style
// preamble traffic shape (Task 3.1, Wave 3 2026-05-17).
//
// Why: a real browser emitting <link rel="stylesheet" href="/app.css">
// sends `Accept: text/css,*/*;q=0.1` + `Sec-Fetch-Dest: style`; emitting
// the same path with the generic `Accept: application/json,...` header
// the warmup loop used to set is a browser-class anomaly readily caught
// by a passive HTTP/1.1 logger inspecting the pre-upgrade burst.
//
// Sec-Fetch-Site is always "same-origin" because every warmup path is
// same-origin against the decoy origin (see browser.CoverPathsPool).
func applyChromeSubresourceHeaders(req *http.Request, path string) {
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	switch {
	case strings.HasSuffix(path, ".css"):
		req.Header.Set("Accept", "text/css,*/*;q=0.1")
		req.Header.Set("Sec-Fetch-Dest", "style")
		req.Header.Set("Sec-Fetch-Mode", "no-cors")
	case strings.HasSuffix(path, ".js"):
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Sec-Fetch-Dest", "script")
		req.Header.Set("Sec-Fetch-Mode", "no-cors")
	case strings.HasSuffix(path, ".webp"),
		strings.HasSuffix(path, ".png"),
		strings.HasSuffix(path, ".jpg"),
		strings.HasSuffix(path, ".jpeg"),
		strings.HasSuffix(path, ".ico"),
		strings.HasSuffix(path, ".svg"):
		req.Header.Set("Accept", "image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Sec-Fetch-Dest", "image")
		req.Header.Set("Sec-Fetch-Mode", "no-cors")
	default:
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
	}
}

package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestDecoyTrafficGETsGoOutWithoutAuthorization verifies the two invariants
// DPI audit V5 depends on:
//  1. Requests are GET (not POST) — shifts the POST/GET ratio.
//  2. No Authorization header — server will route to the decoy static site
//     rather than the ShadowLink handler.
//
// Uses an httptest.Server with a short-cadence override so the test runs in
// reasonable time.
func TestDecoyTrafficGETsGoOutWithoutAuthorization(t *testing.T) {
	var getCount int32
	var sawAuth int32
	var sawPost int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			atomic.AddInt32(&getCount, 1)
		}
		if r.Method == "POST" {
			atomic.AddInt32(&sawPost, 1)
		}
		if r.Header.Get("Authorization") != "" {
			atomic.AddInt32(&sawAuth, 1)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><body>decoy</body></html>"))
	}))
	defer srv.Close()

	d := NewDecoyTraffic(srv.URL, srv.Client(), nil)
	// Fire one request immediately via sendOne so the test is fast and
	// deterministic — the loop() timing isn't what we're testing here.
	d.sendOne()
	d.sendOne()
	d.sendOne()

	if got := atomic.LoadInt32(&getCount); got != 3 {
		t.Fatalf("expected 3 GET requests, got %d", got)
	}
	if got := atomic.LoadInt32(&sawAuth); got != 0 {
		t.Fatalf("decoy GET must never carry Authorization, saw %d", got)
	}
	if got := atomic.LoadInt32(&sawPost); got != 0 {
		t.Fatalf("decoy generator must not emit POST, saw %d", got)
	}
}

// TestDecoyTrafficStartIsIdempotent verifies Start() can be called multiple
// times safely and only spawns one background goroutine. Stop() must still
// return in bounded time.
func TestDecoyTrafficStartIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewDecoyTraffic(srv.URL, srv.Client(), nil)
	d.Start()
	d.Start()
	d.Start()

	done := make(chan struct{})
	go func() {
		d.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s — likely duplicated goroutines leaked")
	}
}

// TestDecoyTrafficStopIsIdempotentAndQuick verifies Stop() terminates the
// background goroutine promptly and can be called multiple times without
// panicking.
func TestDecoyTrafficStopIsIdempotentAndQuick(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewDecoyTraffic(srv.URL, srv.Client(), nil)
	d.Start()

	done := make(chan struct{})
	go func() {
		d.Stop()
		d.Stop() // idempotent
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s — goroutine leaked")
	}
}

// TestDecoyTrafficPathAcceptHeaders verifies the Accept header is path-aware
// (a real browser sends image/* for .png, text/css for .css, etc). A single
// static Accept header across all paths would itself be a detectable pattern.
func TestDecoyTrafficPathAcceptHeaders(t *testing.T) {
	type capture struct {
		path   string
		accept string
		dest   string
	}
	var seen []capture
	var mu atomicMu

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, capture{
			path:   r.URL.Path,
			accept: r.Header.Get("Accept"),
			dest:   r.Header.Get("Sec-Fetch-Dest"),
		})
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewDecoyTraffic(srv.URL, srv.Client(), nil)
	// Fire enough requests to very likely cover each path category.
	for range 40 {
		d.sendOne()
	}

	mu.Lock()
	defer mu.Unlock()

	var sawCSS, sawJS, sawImage, sawAPI, sawDoc bool
	for _, c := range seen {
		switch {
		case strings.HasSuffix(c.path, ".css"):
			if c.accept == "" || c.dest != "style" {
				t.Errorf("css path %q got Accept=%q Dest=%q", c.path, c.accept, c.dest)
			}
			sawCSS = true
		case strings.HasSuffix(c.path, ".js"):
			if c.dest != "script" {
				t.Errorf("js path %q got Dest=%q", c.path, c.dest)
			}
			sawJS = true
		case strings.HasSuffix(c.path, ".png"), strings.HasSuffix(c.path, ".ico"):
			if c.dest != "image" {
				t.Errorf("image path %q got Dest=%q", c.path, c.dest)
			}
			sawImage = true
		case strings.HasPrefix(c.path, "/api/"):
			if c.dest != "empty" {
				t.Errorf("api path %q got Dest=%q", c.path, c.dest)
			}
			sawAPI = true
		default:
			if c.dest != "document" {
				t.Errorf("doc path %q got Dest=%q", c.path, c.dest)
			}
			sawDoc = true
		}
	}
	// With 40 requests over 13 paths it's extremely likely each category
	// appears — if not, path pool shrank and test must be updated.
	if !sawDoc {
		t.Error("no document-type decoy paths were sampled")
	}
	_ = sawCSS
	_ = sawJS
	_ = sawImage
	_ = sawAPI
}

// atomicMu is a zero-value-usable Mutex wrapper for test captures.
type atomicMu struct{ ch chan struct{} }

func (m *atomicMu) Lock() {
	if m.ch == nil {
		m.ch = make(chan struct{}, 1)
	}
	m.ch <- struct{}{}
}
func (m *atomicMu) Unlock() { <-m.ch }

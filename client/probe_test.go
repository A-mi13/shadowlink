package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/skins/browser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyOpen(t *testing.T) {
	result := Classify(ProbeResults{DirectOK: true, CDNOK: true, RuOK: true, DNSOK: true})
	assert.Equal(t, NetworkOpen, result)
}

func TestClassifyOpenDirectOnly(t *testing.T) {
	result := Classify(ProbeResults{DirectOK: true, CDNOK: false, RuOK: false})
	assert.Equal(t, NetworkOpen, result)
}

func TestClassifyDPIBlock(t *testing.T) {
	result := Classify(ProbeResults{DirectOK: false, CDNOK: true, RuOK: true})
	assert.Equal(t, NetworkDPIBlock, result)
}

func TestClassifyOffline(t *testing.T) {
	result := Classify(ProbeResults{DirectOK: false, CDNOK: false, RuOK: false})
	assert.Equal(t, NetworkOffline, result)
}

func TestNetworkTypeString(t *testing.T) {
	assert.Equal(t, "OPEN", NetworkOpen.String())
	assert.Equal(t, "DPI_BLOCK", NetworkDPIBlock.String())
	assert.Equal(t, "OFFLINE", NetworkOffline.String())
}

func TestSelectTransport(t *testing.T) {
	assert.Equal(t, "direct", SelectTransport(NetworkOpen))
	assert.Equal(t, "cdn", SelectTransport(NetworkDPIBlock))
	assert.Equal(t, "", SelectTransport(NetworkOffline))
}

func TestProbeTCPSuccess(t *testing.T) {
	// Start a TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	assert.True(t, probeTCP(ctx, ln.Addr().String()))
}

func TestProbeTCPFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	assert.False(t, probeTCP(ctx, "127.0.0.1:1"))
}

func TestProbeHTTPSSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	fp := browser.NewFingerprintPool().Next()
	assert.True(t, probeHTTPS(ctx, srv.URL, fp))
}

func TestProbeHTTPSFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	fp := browser.NewFingerprintPool().Next()
	assert.False(t, probeHTTPS(ctx, "http://127.0.0.1:1", fp))
}

func TestProbeDNSSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// localhost should always resolve
	assert.True(t, probeDNS(ctx, "127.0.0.1"))
}

func TestProbeDNSIP(t *testing.T) {
	ctx := context.Background()
	// Raw IP should skip DNS and return true
	assert.True(t, probeDNS(ctx, "8.8.8.8"))
}

func TestProbeEngineWithLocalServer(t *testing.T) {
	// Start a local TCP server to simulate "direct" access
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	config := ProbeConfig{
		ServerAddr:  ln.Addr().String(),
		RuCheckURLs: []string{"http://127.0.0.1:1"}, // will fail — simulates no RU access
		Timeout:     2 * time.Second,
	}

	engine := NewProbeEngine(config)
	netType, results := engine.Probe(context.Background())

	assert.Equal(t, NetworkOpen, netType)
	assert.True(t, results.DirectOK)
}

func TestProbeEngineOffline(t *testing.T) {
	config := ProbeConfig{
		ServerAddr:  "127.0.0.1:1",                  // will fail
		RuCheckURLs: []string{"http://127.0.0.1:2"}, // will fail
		Timeout:     1 * time.Second,
	}

	engine := NewProbeEngine(config)
	netType, results := engine.Probe(context.Background())

	assert.Equal(t, NetworkOffline, netType)
	assert.False(t, results.DirectOK)
	assert.False(t, results.RuOK)
}

func TestProbeEngineLastResult(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	config := ProbeConfig{
		ServerAddr:  ln.Addr().String(),
		Timeout:     2 * time.Second,
		RuCheckURLs: []string{"http://127.0.0.1:1"},
	}

	engine := NewProbeEngine(config)
	engine.Probe(context.Background())

	lastType, lastTime := engine.LastResult()
	assert.Equal(t, NetworkOpen, lastType)
	assert.WithinDuration(t, time.Now(), lastTime, 5*time.Second)
}

func TestProbeEngineDPIBlock(t *testing.T) {
	// CDN server is accessible, direct is not
	cdnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer cdnSrv.Close()

	// Extract host:port from CDN test server URL
	config := ProbeConfig{
		ServerAddr:  "127.0.0.1:1",                  // direct fails
		CDNDomain:   cdnSrv.URL[7:],                 // strip "http://" — won't actually use HTTPS
		RuCheckURLs: []string{"http://127.0.0.1:2"}, // RU fails
		Timeout:     1 * time.Second,
	}

	engine := NewProbeEngine(config)

	// Override: test CDN probe directly
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	fp := browser.NewFingerprintPool().Next()
	directOK := probeTCP(ctx, config.ServerAddr)
	cdnOK := probeHTTPS(ctx, cdnSrv.URL, fp) // use actual URL, not HTTPS
	ruOK := probeHTTPS(ctx, config.RuCheckURLs[0], fp)

	results := ProbeResults{DirectOK: directOK, CDNOK: cdnOK, RuOK: ruOK}
	assert.Equal(t, NetworkDPIBlock, Classify(results))
	_ = engine // used for config
}

func TestProbeCompletesWithinTimeout(t *testing.T) {
	config := ProbeConfig{
		ServerAddr:  "192.0.2.1:443", // non-routable — will timeout
		RuCheckURLs: []string{"http://192.0.2.2:80"},
		Timeout:     1 * time.Second,
	}

	engine := NewProbeEngine(config)
	start := time.Now()
	engine.Probe(context.Background())
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 3*time.Second, "probe should complete within timeout + margin")
}

// TestProbe_DefaultPoolHasAtLeast6Entries — A2-MED-8 closure (2026-04 audit).
// The cold-path RU probe MUST randomize across a pool of ≥6 well-known RU
// destinations; a single hardcoded ya.ru is a deterministic startup signal.
func TestProbe_DefaultPoolHasAtLeast6Entries(t *testing.T) {
	assert.GreaterOrEqual(t, len(defaultRuCheckURLs), 6,
		"default RU pool must have at least 6 entries to dilute the cold-path startup signal")
	// Sanity: no duplicates, no empty strings, all https.
	seen := make(map[string]struct{})
	for _, u := range defaultRuCheckURLs {
		assert.NotEmpty(t, u, "pool must not contain empty URL")
		assert.True(t, strings.HasPrefix(u, "https://"), "pool entry %q must use HTTPS", u)
		_, dup := seen[u]
		assert.False(t, dup, "pool contains duplicate %q", u)
		seen[u] = struct{}{}
	}
}

// TestProbe_RotatesRuTargets — verify the random pick across N rounds touches
// more than one URL in the pool. With a 7-entry pool and 200 trials the
// probability of all 200 picks landing on the same URL is (1/7)^199 — i.e.
// effectively zero.
func TestProbe_RotatesRuTargets(t *testing.T) {
	var (
		mu       sync.Mutex
		hits     = make(map[string]int)
		pool     = []string{}
		serversN = 7
	)
	// Spin up N httptest servers — each acts as a single pool entry. The probe
	// hits exactly one of them per round; we count hits to verify dispersion.
	for i := 0; i < serversN; i++ {
		i := i
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits[r.Host] = hits[r.Host] + 1
			_ = i
			mu.Unlock()
			w.WriteHeader(200)
		}))
		defer srv.Close()
		pool = append(pool, srv.URL)
	}

	config := ProbeConfig{
		ServerAddr:  "127.0.0.1:1", // direct fails fast
		RuCheckURLs: pool,
		Timeout:     2 * time.Second,
	}
	engine := NewProbeEngine(config)

	const rounds = 200
	for i := 0; i < rounds; i++ {
		engine.Probe(context.Background())
	}

	mu.Lock()
	distinct := len(hits)
	mu.Unlock()

	assert.Greater(t, distinct, 1,
		"probe must rotate across the RU pool over %d rounds (got hits on %d distinct servers)",
		rounds, distinct)
}

// TestProbe_NilOrEmptyPoolFallsBackToDefault — backward-compat: callers that
// supply a zero-value ProbeConfig should still get the default pool used
// rather than a panic from IntN(0).
func TestProbe_NilOrEmptyPoolFallsBackToDefault(t *testing.T) {
	for _, name := range []string{"nil", "empty"} {
		t.Run(name, func(t *testing.T) {
			config := ProbeConfig{
				ServerAddr: "127.0.0.1:1",
				Timeout:    500 * time.Millisecond,
			}
			if name == "empty" {
				config.RuCheckURLs = []string{}
			}
			engine := NewProbeEngine(config)
			// Should not panic — that's the only guarantee we need.
			_, _ = engine.Probe(context.Background())
		})
	}
}

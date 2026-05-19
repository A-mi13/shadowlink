package client

import (
	"context"
	"io"
	stdrand "math/rand"
	"math/rand/v2"
	stdhttp "net/http"
	"strings"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// DecoyTraffic mixes fake GET requests into the traffic profile while a VPN
// session is active.
//
// 2026-04 DPI audit vector V5: the live transport emits 100% POST requests
// during a session — zero GET, zero OPTIONS. A real browser on a SPA shows
// roughly 70% GET, 20% POST, 10% OPTIONS. TSPU-class ML classifiers catch
// the 100% POST pattern deterministically. This generator shifts the ratio
// into a realistic range by interleaving GETs to decoy paths at a randomized
// 15-45 s cadence.
//
// The GETs are sent without an Authorization header, so the server's
// ShadowHandler routes them through to the decoy static site — no special
// server-side handling required.
type DecoyTraffic struct {
	baseURL    string
	httpClient *stdhttp.Client
	fpPool     *browser.FingerprintPool

	// decoyPaths are picked per request. Distribution is weighted: a real
	// browser hits / and /favicon.ico more often than deep paths, so we
	// bias toward shallow paths.
	decoyPaths []string

	// ua is picked once at construction. A real browser holds one UA for
	// the life of a tab — rotating per request against a single TLS
	// fingerprint is itself detectable.
	ua string

	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewDecoyTraffic creates a decoy traffic generator. httpClient SHOULD be the
// same *http.Client that SplitTransport uses for uploads so that fake GETs
// share the TCP/TLS profile (same dialer, same pinned CF IP, same cert pool).
// If fpPool is nil, requests still go out but without fingerprint-matched UA.
//
// Lifecycle contract: call Start() exactly once when the session is ready to
// emit traffic; call Stop() (or SplitTransport.Close()) exactly once to end.
// The generator is inert until Start().
func NewDecoyTraffic(baseURL string, httpClient *stdhttp.Client, fpPool *browser.FingerprintPool) *DecoyTraffic {
	ua := defaultUA
	if fpPool != nil {
		if fp := fpPool.Next(); fp != nil {
			ua = fp.UserAgent()
		}
	}
	return &DecoyTraffic{
		baseURL:    baseURL,
		httpClient: httpClient,
		fpPool:     fpPool,
		decoyPaths: defaultDecoyPaths(),
		ua:         ua,
		stopCh:     make(chan struct{}),
	}
}

// defaultDecoyPaths returns a pool of paths a real SPA would fetch. Order
// does not matter — pickDecoyPath samples with a weight that biases shallow
// paths.
func defaultDecoyPaths() []string {
	return []string{
		"/",
		"/",
		"/",
		"/favicon.ico",
		"/favicon.ico",
		"/robots.txt",
		"/about",
		"/contact",
		"/privacy",
		"/assets/main.css",
		"/assets/app.js",
		"/assets/logo.png",
		"/api/v1/config",
	}
}

// Start launches the background loop. Subsequent calls are no-ops.
// Stop() (or owner's Close()) must be called to terminate the goroutine.
func (d *DecoyTraffic) Start() {
	d.startOnce.Do(func() {
		d.wg.Add(1)
		go d.loop()
	})
}

// Stop signals the background loop to terminate and waits for it to exit.
// Safe to call multiple times.
func (d *DecoyTraffic) Stop() {
	d.stopOnce.Do(func() { close(d.stopCh) })
	d.wg.Wait()
}

func (d *DecoyTraffic) loop() {
	defer d.wg.Done()

	// Initial jitter before the first GET so it doesn't land adjacent to
	// handshake/upgrade traffic — that would itself be a pattern.
	startupDelay := time.Duration(3+rand.IntN(7)) * time.Second
	select {
	case <-d.stopCh:
		return
	case <-time.After(startupDelay):
	}

	// Per-loop RNG: deterministic startup, runtime-seeded for unpredictable
	// intervals. Not goroutine-shared so no mutex needed.
	rng := stdrand.New(stdrand.NewSource(time.Now().UnixNano()))
	// Bimodal Markov state (Task 3.2 — Opus MAJOR-2 fix). Real browser cadence
	// alternates burst-phases (rapid asset fetches ~250ms apart) with quiet-
	// phases (idle tab, ~60s background polls). Single-mode log-normal showed
	// an FFT-detectable spectral peak; bimodal+Markov destroys that peak.
	state := browser.DecoyStateBurst
	for {
		var interval time.Duration
		interval, state = browser.NextDecoyIntervalBimodal(state, rng)
		select {
		case <-d.stopCh:
			return
		case <-time.After(interval):
		}
		d.sendOne()
	}
}

// sendOne fires a single fake GET. Errors are swallowed — the goal is traffic
// shape, not reliability. A failed GET still contributes a TCP/TLS handshake
// to the wire profile.
func (d *DecoyTraffic) sendOne() {
	if len(d.decoyPaths) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	path := d.decoyPaths[rand.IntN(len(d.decoyPaths))]
	req, err := stdhttp.NewRequestWithContext(ctx, "GET", d.baseURL+path, nil)
	if err != nil {
		return
	}

	// Path-specific Accept headers — a real browser sends different Accept
	// for CSS, JS, images, XHR. Deterministic Accept across all requests
	// would itself be a pattern.
	accept := "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
	switch {
	case strings.HasSuffix(path, ".css"):
		accept = "text/css,*/*;q=0.1"
	case strings.HasSuffix(path, ".js"):
		accept = "application/javascript,*/*;q=0.1"
	case strings.HasSuffix(path, ".png"), strings.HasSuffix(path, ".ico"), strings.HasSuffix(path, ".jpg"):
		accept = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
	case strings.HasSuffix(path, ".txt"):
		accept = "text/plain,*/*;q=0.1"
	case strings.HasPrefix(path, "/api/"):
		accept = "application/json, text/plain, */*"
	}

	req.Header.Set("User-Agent", d.ua)
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	// Sec-Fetch-* headers a real browser attaches — omission itself is
	// detectable on modern DPI. Values chosen per the heuristics Chrome
	// uses for same-origin navigations.
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Dest", decoyFetchDest(path))
	req.Header.Set("Referer", d.baseURL+"/")
	// 2026-05-02 wire-trigger followup NEW-2.
	browser.ApplyChromeCHUAForUA(req.Header, d.ua)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return
	}
	// Drain a reasonable amount — real browser reads the whole decoy page.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
}

// decoyFetchDest returns a plausible Sec-Fetch-Dest for a given path suffix.
func decoyFetchDest(path string) string {
	switch {
	case strings.HasSuffix(path, ".css"):
		return "style"
	case strings.HasSuffix(path, ".js"):
		return "script"
	case strings.HasSuffix(path, ".png"), strings.HasSuffix(path, ".jpg"), strings.HasSuffix(path, ".ico"):
		return "image"
	case strings.HasPrefix(path, "/api/"):
		return "empty"
	default:
		return "document"
	}
}

// defaultUA is a conservative fallback when no fingerprint pool is supplied.
// Mirrors browser.LockedChromeUA() (Chrome/133) so this fallback path stays
// consistent with the rest of the wire surfaces.
var defaultUA = browser.LockedChromeUA()

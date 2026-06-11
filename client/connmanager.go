package client

import (
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// ConnManager manages persistent TLS connections with browser-identical fingerprinting.
// It uses bogdanfinn/tls-client which provides:
//   - uTLS for browser-identical TLS ClientHello (JA3)
//   - Browser-identical HTTP/2 SETTINGS frames (INITIAL_WINDOW_SIZE=6291456, etc.)
//   - Correct pseudo-header ordering (:method, :authority, :scheme, :path)
//   - Connection flow WINDOW_UPDATE matching Chrome
//
// This solves the C1 audit finding: Go's http2.Transport sends Go-specific SETTINGS
// that DPI can fingerprint. tls-client sends Chrome-identical h2 frames.
type ConnManager struct {
	serverAddr    string
	skipVerify    bool
	noTimeout     bool // no HTTP client timeout (for persistent streams)
	timeoutSec    int  // HTTP client timeout (default 10s, configurable per ConnManager)
	allowHTTP2    bool // allow HTTP/2 multiplexing (default false = force HTTP/1.1 for compat)
	fpPool        *browser.FingerprintPool
	lockedProfile *browser.Fingerprint // persistent fingerprint (nil = use pool rotation)
	useTLS        bool

	mu          sync.RWMutex
	tlsClient   tls_client.HttpClient // tls-client with Chrome profile (TLS mode)
	stdClient   *stdHTTPClient        // standard net/http for non-TLS testing
	fingerprint *browser.Fingerprint  // locked for this connection's lifetime
	createdAt   time.Time

	// minRotation, maxRotation, lifecycle: write-once at init (NewConnManager),
	// read-only thereafter. May-audit C11.1 closure (2026-05-02): startRotation
	// reads these fields without holding cm.mu.RLock — that is intentional
	// because the values are immutable post-construction. If a setter is ever
	// added (e.g. SetRotationBounds, SetLifecycle), introduce an RWMutex around
	// these fields AND update TestConnManagerLifecycle_DocsImmutable to assert
	// the new synchronization contract.
	minRotation   time.Duration
	maxRotation   time.Duration
	lifecycle     *browser.SessionLifecycle
	warmupDone    bool
	warmupEnabled bool
	stopCh        chan struct{}
	stopped       bool

	echEnabled bool
	echDomain  string
	echCache   *ECHConfig

	sniOverride string      // TLS ServerName override (full-direct mode OR DomainPool pick)
	domainPool  *DomainPool // optional: rotates sniOverride per reconnect
}

// stdHTTPClient wraps standard net/http for non-TLS testing.
type stdHTTPClient struct {
	inner *http.Client
}

// ConnManagerConfig configures the connection manager.
type ConnManagerConfig struct {
	ServerAddr    string
	UseTLS        bool
	SkipVerify    bool
	NoTimeout     bool // If true, HTTP client has no timeout (for persistent streams)
	TimeoutSec    int  // HTTP client timeout in seconds. 0 = use default (10s). NoTimeout overrides this.
	AllowHTTP2    bool // If true, allow HTTP/2 multiplexing (for CDN upload). Default false = force HTTP/1.1.
	FPPool        *browser.FingerprintPool
	LockedProfile *browser.Fingerprint // If set, use this fingerprint instead of rotating
	MinRotation   time.Duration        // default 2m (mimicry: shorter rotation defeats connection-duration fingerprinting)
	MaxRotation   time.Duration        // default 8m
	ECHEnabled    bool
	ECHDomain     string
	SNIOverride   string // TLS ServerName override. Set when dialing origin IP with CF-domain SNI (full-direct mode).
}

// NewConnManager creates a connection manager and establishes the first connection.
// ForceHTTP1 defaults to true if not explicitly set — existing callers that don't
// set it get HTTP/1.1 (backward-compatible). SplitTransport sets ForceHTTP1=false
// for upload to enable HTTP/2 multiplexing through Cloudflare CDN.
func NewConnManager(config ConnManagerConfig) *ConnManager {
	if config.MinRotation == 0 {
		config.MinRotation = 2 * time.Minute
	}
	if config.MaxRotation == 0 {
		config.MaxRotation = 8 * time.Minute
	}

	timeoutSec := config.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 10 // default
	}

	cm := &ConnManager{
		serverAddr:    config.ServerAddr,
		skipVerify:    config.SkipVerify,
		noTimeout:     config.NoTimeout,
		timeoutSec:    timeoutSec,
		allowHTTP2:    config.AllowHTTP2,
		fpPool:        config.FPPool,
		lockedProfile: config.LockedProfile,
		useTLS:        config.UseTLS,
		minRotation:   config.MinRotation,
		maxRotation:   config.MaxRotation,
		lifecycle:     browser.NewSessionLifecycle(),
		warmupEnabled: true,
		stopCh:        make(chan struct{}),
		echEnabled:    config.ECHEnabled,
		echDomain:     config.ECHDomain,
		sniOverride:   config.SNIOverride,
	}

	cm.connect()

	if config.MinRotation > 0 {
		cm.startRotation()
	}

	return cm
}

// WarmupDelay applies a one-time 200-800ms delay on first connect,
// mimicking SDK initialization time. Not applied on reconnect.
func (cm *ConnManager) WarmupDelay() {
	cm.mu.Lock()
	if !cm.warmupEnabled || cm.warmupDone {
		cm.mu.Unlock()
		return
	}
	cm.warmupDone = true
	cm.mu.Unlock()

	delay := time.Duration(200+rand.IntN(600)) * time.Millisecond
	time.Sleep(delay)
}

// SetDomainPool installs a domain pool that drives sniOverride on each reconnect.
// Passing nil clears the pool. Note: clearing does NOT revert sniOverride to the
// value passed in ConnManagerConfig — the field stays at whatever the last Pick
// wrote. Callers that want to fully revert should set sniOverride explicitly via
// a future setter, or accept that the last picked domain remains until the next
// non-pool change.
func (cm *ConnManager) SetDomainPool(p *DomainPool) {
	cm.mu.Lock()
	cm.domainPool = p
	cm.mu.Unlock()
}

// DomainPoolSize returns the number of domains in the rotation pool.
// Returns 0 if no pool is installed. Read-only accessor for tests and
// metrics — does not affect Pick state.
func (cm *ConnManager) DomainPoolSize() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.domainPool == nil {
		return 0
	}
	return cm.domainPool.Size()
}

// connect creates a new tls-client with the locked or rotated browser profile.
func (cm *ConnManager) connect() {
	// DomainPool integration: if pool is set, pick a fresh domain to use as SNI.
	// Pool's own mutex serializes Pick — it's safe to call while we hold cm.mu.
	if cm.domainPool != nil {
		if d := cm.domainPool.Pick(); d != "" {
			cm.sniOverride = d
		}
	}

	var fp *browser.Fingerprint
	if cm.lockedProfile != nil {
		fp = cm.lockedProfile // persistent per-user fingerprint (weekly rotation)
	} else {
		fp = cm.fpPool.Next() // random rotation (legacy, for tests)
	}
	cm.fingerprint = fp
	cm.createdAt = time.Now()

	if cm.useTLS {
		// Use tls-client with Chrome profile — browser-identical TLS + HTTP/2
		// Timeout per ConnManager: upload pool uses 20s (CF CDN can be slow),
		// default 10s for general use, 0 for persistent streams.
		ts := cm.timeoutSec
		if cm.noTimeout {
			ts = 0 // no timeout for persistent streams (SplitHTTP download)
		}
		opts := []tls_client.HttpClientOption{
			tls_client.WithTimeoutSeconds(ts),
			tls_client.WithClientProfile(profileForFingerprint(fp)),
		}
		// HTTP/1.1 vs HTTP/2: ForceHTTP1=true (default) keeps h1 for compat with direct nginx.
		// ForceHTTP1=false enables HTTP/2 multiplexing — critical for CDN upload throughput.
		// tls-client Chrome 133 profile sends Chrome-identical h2 SETTINGS (DPI-safe).
		if !cm.allowHTTP2 {
			opts = append(opts, tls_client.WithForceHttp1())
		}
		if cm.skipVerify {
			opts = append(opts, tls_client.WithInsecureSkipVerify())
		}
		// Full-direct mode: override SNI so the TLS ClientHello carries the CF
		// domain name even when the TCP connection goes to the origin IP. This
		// requires skipVerify (enforced by caller) because the certificate is
		// for the domain, not the IP.
		if cm.sniOverride != "" {
			opts = append(opts, tls_client.WithServerNameOverwrite(cm.sniOverride))
		}

		client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
		if err != nil {
			cm.tlsClient = nil
			stdTimeout := 30 * time.Second
			if cm.noTimeout {
				stdTimeout = 0
			}
			cm.stdClient = &stdHTTPClient{inner: &http.Client{Timeout: stdTimeout}}
			return
		}
		cm.tlsClient = client
		cm.stdClient = nil

		// ECH: resolve and cache ECH config for CDN mode.
		// Chrome 133+ profiles already include GREASE ECH via BoringGREASEECH().
		// With a real ECHConfigList the TLS handshake would need utls-level changes.
		// For MVP we resolve and cache the config, logging success for observability,
		// and prepare for utls integration. GREASE ECH already provides partial protection.
		if cm.echEnabled && cm.echDomain != "" {
			if cm.echCache == nil || cm.echCache.IsExpired() {
				if echBytes, err := ResolveECHConfig(cm.echDomain); err == nil {
					cm.echCache = &ECHConfig{
						ConfigList: echBytes,
						ResolvedAt: time.Now(),
						TTL:        5 * time.Minute,
					}
					slog.Info("ECH config resolved", "domain", cm.echDomain, "size", len(echBytes))
				} else {
					slog.Warn("ECH resolution failed, using GREASE ECH", "error", err)
				}
			}
		}
	} else {
		// Non-TLS: use bogdanfinn/fhttp client directly (for testing)
		stdTimeout := 30 * time.Second
		if cm.noTimeout {
			stdTimeout = 0
		}
		cm.stdClient = &stdHTTPClient{
			inner: &http.Client{Timeout: stdTimeout},
		}
		cm.tlsClient = nil
	}
}

// profileForFingerprint maps our fingerprint name to a tls-client profile.
//
// 2026-05-02 wire-trigger followup (F2 lockstep): all Chrome surfaces (uTLS
// JA4, bogdanfinn H2 SETTINGS, User-Agent string, sec-ch-ua header) now
// align to a single Chrome major — `browser.LockedChromeMajor` (133).
// Previously the bogdanfinn hot path returned Chrome_146 by default and
// only fell back to Chrome_133 when SHADOWLINK_TLS_PQ=0 (May-audit C2
// closure for opt-out symmetry). Per-major mismatch (uTLS=133, bogdanfinn=
// 146, UA=134, defaultUA=131) was an ML-classifier signal that no real
// Chrome client emits. Anchoring everything to 133 closes the quad.
//
// utls upstream lacks HelloChrome_135+ so 133 is the highest non-PSK ID we
// can pin to. Bumping the lockstep major requires upstream catching up
// AND a coordinated bump of `browser.LockedChromeMajor` + tests.
//
// PQ status: bogdanfinn Chrome_133 ships without MLKEM in key_share —
// matching the cold-path HelloChrome_133 default. The cold-path
// pqClientHelloSpec safety-bridge prepends MLKEM when SHADOWLINK_TLS_PQ
// is enabled; the bogdanfinn hot-path does NOT honor PQ and emits stock
// Chrome_133 always. Wire effect: with PQ default-on, cold-path emits
// MLKEM keyshare while hot-path does not — same JA3/JA4 cipher list, same
// extensions, only key_share content differs. This is acceptable because
// the cold-path is a small fraction of total handshakes (one per slot
// reconnect + initial handshake) and a passive ML classifier sees both
// flavors as "Chrome 133 family". With PQ off both paths emit identical
// stock Chrome_133.
//
// C4 (2026-06-09): the hot-path bogdanfinn H2 profile is now read from the
// selected browser profile (fp.Profile().BogdanfinnID) so it stays in lockstep
// with the cold-path uTLS ClientHelloID and the User-Agent. For a Chrome
// fingerprint this is profiles.Chrome_133; for Firefox, profiles.Firefox_147.
// Nil fingerprint falls back to the locked Chrome profile. (Prior to C4 this
// always returned Chrome_133 regardless of fp.Name(); the population-FP work
// re-enabled non-Chrome profiles when the operator weights them in.)
func profileForFingerprint(fp *browser.Fingerprint) profiles.ClientProfile {
	if fp == nil {
		return browser.LockedBogdanfinnChromeProfile()
	}
	return fp.Profile().BogdanfinnID
}

// Do executes an HTTP request using the active tls-client.
// Auto-rotates on connection errors — CF CDN kills persistent HTTP connections after ~20s,
// so a fresh TLS connection is needed to recover.
func (cm *ConnManager) Do(req *http.Request) (*http.Response, error) {
	cm.mu.RLock()
	tc := cm.tlsClient
	sc := cm.stdClient
	cm.mu.RUnlock()

	var resp *http.Response
	var err error

	if tc != nil {
		resp, err = tc.Do(req)
	} else if sc != nil {
		resp, err = sc.inner.Do(req)
	} else {
		return nil, io.EOF
	}

	// Connection-level errors (timeout, reset, EOF) mean the underlying TCP connection is dead.
	// HTTP errors (4xx, 5xx) return a valid response with no error — won't trigger rotation.
	// Force rotate so the next request through this CM gets a fresh TLS connection.
	if err != nil {
		// DomainPool integration: mark the current SNI domain as failed before
		// rotating so the next connect() picks a different alive domain from the pool.
		// Capture under RLock (no nested-lock risk: DomainPool has its own mutex).
		cm.mu.RLock()
		pool := cm.domainPool
		failedSNI := cm.sniOverride
		cm.mu.RUnlock()
		if pool != nil && failedSNI != "" {
			pool.MarkFailed(failedSNI)
		}
		cm.rotate()
	}

	return resp, err
}

// ActiveFingerprint returns the fingerprint locked to the current connection.
func (cm *ConnManager) ActiveFingerprint() *browser.Fingerprint {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.fingerprint
}

// startRotation runs a background goroutine that periodically rotates the connection.
// Uses SessionLifecycle for realistic session duration and gap timing when using default
// rotation config (>= 2 min). Falls back to raw min/max jitter for non-default configs
// (e.g., fast rotation in tests).
func (cm *ConnManager) startRotation() {
	useLifecycle := cm.minRotation >= 2*time.Minute

	go func() {
		for {
			var interval time.Duration
			var gapMs int
			if useLifecycle {
				intervalSec := cm.lifecycle.NextActiveInterval()
				interval = time.Duration(intervalSec) * time.Second
				gapMs = cm.lifecycle.NextGapDuration()
			} else {
				// Use raw min/max jitter (test-friendly fast rotation)
				spread := cm.maxRotation - cm.minRotation
				if spread <= 0 {
					spread = cm.minRotation
				}
				interval = cm.minRotation + spread/2
				gapMs = 10 // minimal gap for non-lifecycle configs
			}

			rotTimer := time.NewTimer(interval)
			select {
			case <-rotTimer.C:
				gapTimer := time.NewTimer(time.Duration(gapMs) * time.Millisecond)
				select {
				case <-gapTimer.C:
					cm.rotate()
				case <-cm.stopCh:
					gapTimer.Stop()
					return
				}
			case <-cm.stopCh:
				rotTimer.Stop()
				return
			}
		}
	}()
}

// rotate creates a new connection with a fresh fingerprint and swaps it in.
func (cm *ConnManager) rotate() {
	cm.mu.Lock()
	oldTC := cm.tlsClient
	cm.connect()
	cm.mu.Unlock()

	// Close idle connections on old client after grace period for in-flight requests.
	// Short grace: 10s timeout means in-flight requests resolve quickly.
	if oldTC != nil {
		time.AfterFunc(2*time.Second, func() {
			oldTC.CloseIdleConnections()
		})
	}
}

// Close stops rotation and closes all connections.
func (cm *ConnManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if !cm.stopped {
		cm.stopped = true
		close(cm.stopCh)
	}

	if cm.tlsClient != nil {
		cm.tlsClient.CloseIdleConnections()
	}
	return nil
}

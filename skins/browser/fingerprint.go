package browser

import (
	"math/rand/v2"
	"sync"
)

// Browser profile names.
const (
	ProfileChrome  = "chrome"
	ProfileSafari  = "safari"
	ProfileFirefox = "firefox"
)

// Fingerprint represents a browser TLS profile with a matching User-Agent.
// M1 audit fix: fingerprint and UA must be paired — Chrome TLS → Chrome UA.
// Actual TLS handshake is done by bogdanfinn/tls-client (browser-identical h2 SETTINGS).
type Fingerprint struct {
	name      string
	userAgent string
}

// NewFingerprint creates a fingerprint for the given browser profile.
func NewFingerprint(profile string) *Fingerprint {
	uaMu.RLock()
	defer uaMu.RUnlock()

	fp := &Fingerprint{name: profile}
	switch profile {
	case ProfileChrome:
		fp.userAgent = chromeUA
	case ProfileSafari:
		fp.userAgent = safariUA
	case ProfileFirefox:
		fp.userAgent = firefoxUA
	default:
		fp.userAgent = chromeUA
	}
	return fp
}

// Name returns the profile name.
func (f *Fingerprint) Name() string {
	return f.name
}

// UserAgent returns the User-Agent string matching this fingerprint's browser.
func (f *Fingerprint) UserAgent() string {
	return f.userAgent
}

// UpdateUserAgents updates UA strings for all profiles.
// Called when the server provides fresh UA versions in ServerHello.
// Map keys: "chrome", "safari", "firefox". Values: full UA strings.
// M5 audit fix: thread-safe via mutex.
func UpdateUserAgents(uas map[string]string) {
	uaMu.Lock()
	defer uaMu.Unlock()
	for profile, ua := range uas {
		if ua == "" {
			continue
		}
		switch profile {
		case ProfileChrome:
			chromeUA = ua
		case ProfileSafari:
			safariUA = ua
		case ProfileFirefox:
			firefoxUA = ua
		}
	}
}

// Default UA strings — updated via UpdateUserAgents from server.
// Protected by uaMu for concurrent access (M5 audit fix).
var (
	uaMu      sync.RWMutex
	chromeUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
	safariUA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15"
	firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"
)

// FingerprintPool selects browser fingerprints using weighted random distribution.
// H2 audit fix: weighted random matches real browser market share.
type FingerprintPool struct {
	profiles []*Fingerprint
	weights  []int // cumulative weights
	total    int
}

// NewFingerprintPool creates a pool with Chrome, Safari, and Firefox profiles.
// Weights: ~65% Chrome, 20% Safari, 15% Firefox.
func NewFingerprintPool() *FingerprintPool {
	return &FingerprintPool{
		profiles: []*Fingerprint{
			NewFingerprint(ProfileChrome),
			NewFingerprint(ProfileSafari),
			NewFingerprint(ProfileFirefox),
		},
		weights: []int{65, 85, 100},
		total:   100,
	}
}

// Next returns a fingerprint selected by weighted random distribution.
func (p *FingerprintPool) Next() *Fingerprint {
	r := rand.IntN(p.total)
	for i, w := range p.weights {
		if r < w {
			return p.profiles[i]
		}
	}
	return p.profiles[0]
}

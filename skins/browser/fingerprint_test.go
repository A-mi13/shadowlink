package browser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChromeFingerprint(t *testing.T) {
	fp := NewFingerprint(ProfileChrome)
	assert.Equal(t, "chrome", fp.Name())
	assert.Contains(t, fp.UserAgent(), "Chrome/")
}

func TestSafariFingerprint(t *testing.T) {
	fp := NewFingerprint(ProfileSafari)
	assert.Equal(t, "safari", fp.Name())
	assert.Contains(t, fp.UserAgent(), "Safari/605")
}

func TestFirefoxFingerprint(t *testing.T) {
	fp := NewFingerprint(ProfileFirefox)
	assert.Equal(t, "firefox", fp.Name())
	assert.Contains(t, fp.UserAgent(), "Firefox/")
}

func TestFingerprintRotation(t *testing.T) {
	pool := NewFingerprintPool()
	seen := map[string]int{}
	for range 1000 {
		fp := pool.Next()
		seen[fp.Name()]++
	}
	// H2 fix: weighted random (65% Chrome, 20% Safari, 15% Firefox)
	assert.Equal(t, 3, len(seen), "should use all 3 profiles")
	assert.Greater(t, seen[ProfileChrome], seen[ProfileSafari])
	assert.Greater(t, seen[ProfileSafari], seen[ProfileFirefox])
	assert.Greater(t, seen[ProfileChrome], 500, "Chrome should be >50%")
	assert.Less(t, seen[ProfileFirefox], 250, "Firefox should be <25%")
}

func TestUnknownProfileFallsToChrome(t *testing.T) {
	fp := NewFingerprint("unknown")
	assert.Equal(t, "unknown", fp.Name())
	assert.Contains(t, fp.UserAgent(), "Chrome/")
}

func TestPickUserAgent(t *testing.T) {
	ua := PickUserAgent()
	assert.Contains(t, ua, "Mozilla")
	assert.NotEmpty(t, ua)
}

func TestUpdateUserAgents(t *testing.T) {
	// Save originals
	origChrome := chromeUA

	// Update
	UpdateUserAgents(map[string]string{
		"chrome": "Mozilla/5.0 TestChrome/999",
	})

	fp := NewFingerprint(ProfileChrome)
	assert.Equal(t, "Mozilla/5.0 TestChrome/999", fp.UserAgent())

	// Restore
	UpdateUserAgents(map[string]string{
		"chrome": origChrome,
	})
}

func TestFingerprintUserAgentPairing(t *testing.T) {
	pool := NewFingerprintPool()
	for range 50 {
		fp := pool.Next()
		switch fp.Name() {
		case ProfileChrome:
			assert.Contains(t, fp.UserAgent(), "Chrome/")
		case ProfileSafari:
			assert.Contains(t, fp.UserAgent(), "Safari/605")
		case ProfileFirefox:
			assert.Contains(t, fp.UserAgent(), "Firefox/")
		}
	}
}

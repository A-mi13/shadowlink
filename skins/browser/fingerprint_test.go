package browser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// 2026-05-05: non-Chrome fingerprints retired. TSPU блокирует Safari/Firefox/Edge,
// Chrome — единственный fp, стабильно проходящий через РФ-DPI. Тесты на Safari/
// Firefox удалены вместе с константами ProfileSafari / ProfileFirefox.

func TestChromeFingerprint(t *testing.T) {
	fp := NewFingerprint(ProfileChrome)
	assert.Equal(t, "chrome", fp.Name())
	assert.Contains(t, fp.UserAgent(), "Chrome/")
}

// TestFingerprintRotation — pool теперь single-entry: каждый Next() возвращает Chrome.
func TestFingerprintRotation(t *testing.T) {
	pool := NewFingerprintPool()
	seen := map[string]int{}
	for range 1000 {
		fp := pool.Next()
		seen[fp.Name()]++
	}
	assert.Equal(t, 1, len(seen), "pool должен содержать только Chrome")
	assert.Equal(t, 1000, seen[ProfileChrome], "все Next() должны возвращать Chrome")
}

// TestUnknownProfileFallsToChrome — любое имя профиля нормализуется до Chrome.
// 2026-05-05: NewFingerprint(...) теперь возвращает имя ProfileChrome
// независимо от входного аргумента (legacy "safari"/"firefox" из persisted
// state-файлов или старых call-sites).
func TestUnknownProfileFallsToChrome(t *testing.T) {
	for _, name := range []string{"unknown", "safari", "firefox", "edge", ""} {
		fp := NewFingerprint(name)
		assert.Equal(t, ProfileChrome, fp.Name(), "input %q должен normalize до Chrome", name)
		assert.Contains(t, fp.UserAgent(), "Chrome/")
	}
}

func TestPickUserAgent(t *testing.T) {
	ua := PickUserAgent()
	assert.Contains(t, ua, "Mozilla")
	assert.NotEmpty(t, ua)
}

func TestUpdateUserAgents(t *testing.T) {
	// Save originals
	uaMu.RLock()
	origChrome := chromeUA
	uaMu.RUnlock()

	// Update — chrome key обновляется, остальные тихо игнорируются.
	UpdateUserAgents(map[string]string{
		"chrome":  "Mozilla/5.0 TestChrome/999",
		"safari":  "Mozilla/5.0 IgnoredSafari/0",
		"firefox": "Mozilla/5.0 IgnoredFirefox/0",
	})

	fp := NewFingerprint(ProfileChrome)
	assert.Equal(t, "Mozilla/5.0 TestChrome/999", fp.UserAgent())

	// Restore
	UpdateUserAgents(map[string]string{
		"chrome": origChrome,
	})
}

// TestFingerprintUserAgentPairing — после ретайра non-Chrome pool отдаёт только Chrome,
// и UA должна содержать Chrome/.
func TestFingerprintUserAgentPairing(t *testing.T) {
	pool := NewFingerprintPool()
	for range 50 {
		fp := pool.Next()
		assert.Equal(t, ProfileChrome, fp.Name())
		assert.Contains(t, fp.UserAgent(), "Chrome/")
	}
}

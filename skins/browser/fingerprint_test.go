package browser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// 2026-05-05: non-Chrome fingerprints retired. TSPU блокирует Safari/Firefox/Edge,
// Chrome — единственный fp, стабильно проходящий через РФ-DPI. Тесты на Safari/
// Firefox удалены вместе с константами ProfileSafari / ProfileFirefox.

func TestChromeFingerprint(t *testing.T) {
	// NewFingerprint(legacy "chrome") резолвится в chrome133 через LookupProfile.
	fp := NewFingerprint(ProfileChrome)
	assert.Equal(t, ProfileChrome133, fp.Name())
	assert.True(t, IsChromeFamily(fp.Name()))
	assert.Contains(t, fp.UserAgent(), "Chrome/")
}

// TestFingerprintRotation — pool теперь single-entry: каждый Next() возвращает Chrome-family.
func TestFingerprintRotation(t *testing.T) {
	pool := NewFingerprintPool()
	seen := map[string]int{}
	for range 1000 {
		fp := pool.Next()
		seen[fp.Name()]++
	}
	assert.Equal(t, 1, len(seen), "pool должен содержать только один профиль")
	assert.Equal(t, 1000, seen[ProfileChrome133], "все Next() должны возвращать chrome133")
}

// TestUnknownProfileFallsToChrome — любое имя профиля нормализуется до Chrome-family.
// NewFingerprint(...) возвращает chrome133 независимо от входного аргумента
// (legacy "safari"/"firefox"/"chrome" из persisted state-файлов).
func TestUnknownProfileFallsToChrome(t *testing.T) {
	for _, name := range []string{"unknown", "safari", "firefox", "edge", ""} {
		fp := NewFingerprint(name)
		assert.Equal(t, ProfileChrome133, fp.Name(), "input %q должен normalize до chrome133", name)
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
		assert.Equal(t, ProfileChrome133, fp.Name())
		assert.Contains(t, fp.UserAgent(), "Chrome/")
	}
}

func TestFingerprint_CarriesProfile(t *testing.T) {
	fp := NewFingerprintForProfile("chrome131")
	if fp.Profile().Name != ProfileChrome131 {
		t.Errorf("Profile().Name = %q, want chrome131", fp.Profile().Name)
	}
	if fp.UserAgent() == "" {
		t.Error("UA must come from profile")
	}
}

func TestFingerprint_UnknownProfileFallsBackChrome(t *testing.T) {
	fp := NewFingerprintForProfile("netscape")
	if fp.Profile().Name != ProfileChrome133 {
		t.Errorf("unknown profile must fall back to chrome133, got %q", fp.Profile().Name)
	}
}

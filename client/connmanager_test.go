package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"

	"github.com/nixavpn/shadowlink/skins/browser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnManagerDo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	fpPool := browser.NewFingerprintPool()
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr:  ts.Listener.Addr().String(),
		UseTLS:      false,
		FPPool:      fpPool,
		MinRotation: 0,
	})
	defer cm.Close()

	req, _ := fhttp.NewRequest("GET", ts.URL+"/test", nil)
	resp, err := cm.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "ok", string(body))
}

func TestConnManagerFingerprintLocked(t *testing.T) {
	fpPool := browser.NewFingerprintPool()
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr:  "127.0.0.1:1234",
		UseTLS:      false,
		FPPool:      fpPool,
		MinRotation: 0,
	})
	defer cm.Close()

	fp1 := cm.ActiveFingerprint()
	fp2 := cm.ActiveFingerprint()

	assert.Equal(t, fp1.Name(), fp2.Name())
	assert.NotEmpty(t, fp1.UserAgent())
	assert.Equal(t, fp1.UserAgent(), fp2.UserAgent())
}

// TestConnManagerRotation — после ретайра non-Chrome 2026-05-05 pool single-entry,
// поэтому имя fp не меняется между ротациями. Тест переписан: проверяем, что
// rotation по-прежнему происходит (createdAt обновляется), а fp.Name() стабильно
// держит ProfileChrome.
func TestConnManagerRotation(t *testing.T) {
	fpPool := browser.NewFingerprintPool()
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr:  "127.0.0.1:1234",
		UseTLS:      false,
		FPPool:      fpPool,
		MinRotation: 50 * time.Millisecond,
		MaxRotation: 100 * time.Millisecond,
	})
	defer cm.Close()

	cm.mu.RLock()
	initialCreated := cm.createdAt
	cm.mu.RUnlock()

	rotated := false
	for i := 0; i < 40; i++ {
		time.Sleep(150 * time.Millisecond)
		cm.mu.RLock()
		nowCreated := cm.createdAt
		cm.mu.RUnlock()
		if !nowCreated.Equal(initialCreated) {
			rotated = true
			break
		}
	}
	assert.True(t, rotated, "connect() должен запускаться повторно при ротации")
	assert.Equal(t, browser.ProfileChrome, cm.ActiveFingerprint().Name(),
		"имя fp должно остаться Chrome после ротации (pool single-entry)")
}

func TestConnManagerClose(t *testing.T) {
	fpPool := browser.NewFingerprintPool()
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr:  "127.0.0.1:1234",
		UseTLS:      false,
		FPPool:      fpPool,
		MinRotation: 50 * time.Millisecond,
		MaxRotation: 100 * time.Millisecond,
	})

	err := cm.Close()
	assert.NoError(t, err)

	err = cm.Close()
	assert.NoError(t, err)
}

func TestConnManagerHTTP1Fallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("h1"))
	}))
	defer ts.Close()

	fpPool := browser.NewFingerprintPool()
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr: ts.Listener.Addr().String(),
		UseTLS:     false,
		FPPool:     fpPool,
	})
	defer cm.Close()

	for i := range 5 {
		req, _ := fhttp.NewRequest("GET", ts.URL+"/test", nil)
		resp, err := cm.Do(req)
		require.NoError(t, err, "request %d", i)
		resp.Body.Close()
		assert.Equal(t, 200, resp.StatusCode)
	}
}

func TestConnManagerUserAgentMatchesFingerprint(t *testing.T) {
	fpPool := browser.NewFingerprintPool()
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr: "127.0.0.1:1234",
		UseTLS:     false,
		FPPool:     fpPool,
	})
	defer cm.Close()

	fp := cm.ActiveFingerprint()
	ua := fp.UserAgent()
	name := fp.Name()

	// 2026-05-05: pool единый — только Chrome.
	assert.Equal(t, browser.ProfileChrome, name)
	assert.Contains(t, ua, "Chrome/")
}

// TestConnManagerSetDomainPool_SNIRotation — after SetDomainPool + rotate(),
// sniOverride is set to one of the pool domains. Uses non-TLS mode (no real dial).
func TestConnManagerSetDomainPool_SNIRotation(t *testing.T) {
	fpPool := browser.NewFingerprintPool()
	cm := NewConnManager(ConnManagerConfig{
		ServerAddr:  "127.0.0.1:1234",
		UseTLS:      false,
		FPPool:      fpPool,
		MinRotation: 0, // no background rotation goroutine
	})
	defer cm.Close()

	domains := []string{"alpha.example.com", "beta.example.com"}
	pool := NewDomainPool(domains, time.Minute)
	cm.SetDomainPool(pool)

	// Trigger a reconnect so connect() runs with the pool installed.
	cm.rotate()

	// Inspect sniOverride — same package so unexported field is accessible.
	cm.mu.RLock()
	got := cm.sniOverride
	cm.mu.RUnlock()

	found := false
	for _, d := range domains {
		if got == d {
			found = true
			break
		}
	}
	assert.True(t, found, "sniOverride %q should be one of the pool domains %v", got, domains)
	assert.NotEmpty(t, got, "sniOverride must not be empty after SetDomainPool + rotate")
}

// TestConnManagerSetDomainPool_MarkFailedOnError — after installing a 2-domain pool,
// simulate the MarkFailed path (as called by Do() on error). Confirms the failed
// domain lands in the pool's blacklist and the next Pick returns a different domain.
// No real TCP dial needed — we test the pool interaction directly.
func TestConnManagerSetDomainPool_MarkFailedOnError(t *testing.T) {
	fpPool := browser.NewFingerprintPool()
	domains := []string{"x.example.com", "y.example.com"}
	pool := NewDomainPool(domains, time.Minute)

	cm := NewConnManager(ConnManagerConfig{
		ServerAddr:  "127.0.0.1:1234",
		UseTLS:      false,
		FPPool:      fpPool,
		MinRotation: 0,
	})
	defer cm.Close()

	// Install pool and run connect() once so sniOverride is set.
	cm.SetDomainPool(pool)
	cm.rotate()

	cm.mu.RLock()
	sni := cm.sniOverride
	cm.mu.RUnlock()
	require.NotEmpty(t, sni, "sniOverride must be set after rotate with pool")

	// Simulate the Do() error path: MarkFailed the current SNI domain.
	pool.MarkFailed(sni)

	assert.Equal(t, 1, pool.BlacklistSize(), "failed domain should be blacklisted")

	// After MarkFailed the next Pick should return the other domain.
	next := pool.Pick()
	assert.NotEmpty(t, next)
	assert.NotEqual(t, sni, next, "Pick after MarkFailed should return a different domain")
}

// TestProfileForFingerprint_AlwaysReturnsLockedChrome closes the 2026-05-02
// wire-trigger followup F2 (Chrome major lockstep): the bogdanfinn hot-path
// MUST return browser.LockedBogdanfinnChromeProfile() (Chrome_133) for the
// Chrome fingerprint regardless of SHADOWLINK_TLS_PQ. Previously the path
// returned Chrome_146 by default (PQ on) and Chrome_133 only when PQ was
// disabled — producing a (uTLS=133, bogdanfinn=146) mismatch on the
// default-on path that no real Chrome client emits.
func TestProfileForFingerprint_AlwaysReturnsLockedChrome(t *testing.T) {
	expected := browser.LockedBogdanfinnChromeProfile()
	for _, v := range []string{"", "1", "0", "yes", "false", "no", "off", "garbage"} {
		t.Run(v, func(t *testing.T) {
			if v == "" {
				old, had := os.LookupEnv("SHADOWLINK_TLS_PQ")
				os.Unsetenv("SHADOWLINK_TLS_PQ")
				t.Cleanup(func() {
					if had {
						os.Setenv("SHADOWLINK_TLS_PQ", old)
					} else {
						os.Unsetenv("SHADOWLINK_TLS_PQ")
					}
				})
			} else {
				t.Setenv("SHADOWLINK_TLS_PQ", v)
			}
			fp := browser.NewFingerprint(browser.ProfileChrome)
			got := profileForFingerprint(fp)
			if got.GetClientHelloStr() != expected.GetClientHelloStr() {
				t.Errorf("env=%q: expected %s, got %s",
					v, expected.GetClientHelloStr(), got.GetClientHelloStr())
			}
		})
	}
}

// TestProfileForFingerprint_LegacyNamesNormalize — на 2026-05-05 non-Chrome
// fp retired. NewFingerprint("safari") и NewFingerprint("firefox") теперь
// нормализуются до Chrome (см. browser.NewFingerprint), и hot-path возвращает
// LockedBogdanfinnChromeProfile() для любого входа.
func TestProfileForFingerprint_LegacyNamesNormalize(t *testing.T) {
	expected := browser.LockedBogdanfinnChromeProfile()
	for _, legacyName := range []string{"safari", "firefox", "edge", "ios"} {
		t.Run(legacyName, func(t *testing.T) {
			fp := browser.NewFingerprint(legacyName)
			got := profileForFingerprint(fp)
			if got.GetClientHelloStr() != expected.GetClientHelloStr() {
				t.Errorf("legacy=%q: expected %s, got %s",
					legacyName, expected.GetClientHelloStr(), got.GetClientHelloStr())
			}
		})
	}
}

// TestConnManagerLifecycle_DocsImmutable closes may-audit C11.1 (audit
// Track 4 §3.1, MEDIUM): the lifecycle / minRotation / maxRotation fields
// are written exactly once in NewConnManager and read in startRotation.
// We don't take a lock around the read because the values are immutable
// post-init. This test pins that contract by:
//  1. asserting the contract comment exists, и
//  2. scanning for setter signatures that would break the contract — if
//     any such setter is added later (`SetLifecycle`, `SetMinRotation`,
//     `SetMaxRotation`, `SetRotationBounds`), this test fails until the
//     synchronization strategy is reworked + the comment updated.
//
// Holistic review I-4 (2026-05-02): comment-only check was insufficient —
// a future setter could be merged without anyone touching the comment.
func TestConnManagerLifecycle_DocsImmutable(t *testing.T) {
	src, err := os.ReadFile("connmanager.go")
	if err != nil {
		t.Skipf("cannot read connmanager.go: %v", err)
	}
	body := string(src)
	if !strings.Contains(body, "write-once at init") {
		t.Errorf("connmanager.go missing 'write-once at init' contract comment for lifecycle/minRotation/maxRotation")
	}
	forbiddenSetters := []string{
		"func (cm *ConnManager) SetLifecycle",
		"func (cm *ConnManager) SetMinRotation",
		"func (cm *ConnManager) SetMaxRotation",
		"func (cm *ConnManager) SetRotationBounds",
	}
	for _, sig := range forbiddenSetters {
		if strings.Contains(body, sig) {
			t.Errorf("connmanager.go has forbidden setter %q — adding a setter breaks the C11.1 'write-once' invariant; either remove the setter or rewrite startRotation to load lifecycle/minRotation/maxRotation under sync (atomic.Pointer or sync.RWMutex) and update the contract comment", sig)
		}
	}
}

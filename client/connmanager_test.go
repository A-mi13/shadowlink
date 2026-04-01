package client

import (
	"io"
	"net/http"
	"net/http/httptest"
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

	initialFP := cm.ActiveFingerprint().Name()

	// Poll until fingerprint changes (weighted random — may take a few rotations)
	changed := false
	for i := 0; i < 40; i++ {
		time.Sleep(150 * time.Millisecond)
		if cm.ActiveFingerprint().Name() != initialFP {
			changed = true
			break
		}
	}
	assert.True(t, changed, "fingerprint should change after rotation")
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

	switch name {
	case browser.ProfileChrome:
		assert.Contains(t, ua, "Chrome/")
	case browser.ProfileSafari:
		assert.Contains(t, ua, "Safari/605")
	case browser.ProfileFirefox:
		assert.Contains(t, ua, "Firefox/")
	default:
		t.Fatalf("unknown profile: %s", name)
	}
}

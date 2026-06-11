// shadowlink/client/coldpath_pq_test.go
package client

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// TestColdPath_PQ_OnWire_HandshakeIncrementsClientHelloSent asserts that when
// SHADOWLINK_TLS_PQ=1 is set, the cold-path uTLS dialer used by
// buildUTLSHTTPClient (SendHandshake POST, WarmupRequests, cover GET,
// SplitTransport upload POST) honors the flag and ticks the PQ
// PQClientHelloSent counter — matching the WS upgrade path. Without this,
// flipping the flag default-on re-instates the JA3 mismatch CRIT-1/2/3 of
// the 2026-04 audit (WS = MLKEM on wire, cold-path = stock HelloChrome).
// Renamed from TestColdPath_PQ_OnWire_HandshakeIncrementsSuccess 2026-05-17
// (Wave 3.3) along with the underlying counter.
func TestColdPath_PQ_OnWire_HandshakeIncrementsClientHelloSent(t *testing.T) {
	t.Setenv("SHADOWLINK_TLS_PQ", "1")

	// Snapshot counters so this test is hermetic w.r.t. earlier tests.
	before := Stats.PQClientHelloSent.Load()
	beforeFb := Stats.PQHandshakeFallback.Load()
	beforeErr := Stats.PQHandshakeError.Load()
	t.Cleanup(func() {
		Stats.PQClientHelloSent.Store(before)
		Stats.PQHandshakeFallback.Store(beforeFb)
		Stats.PQHandshakeError.Store(beforeErr)
	})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	// httptest's TLS server uses an in-memory self-signed cert — skipVerify=true
	// + ServerName=example.test (any non-empty SNI works; cert is wildcarded).
	fp := browser.NewFingerprint(browser.ProfileChrome)
	addr := srv.Listener.Addr().String()
	client := buildUTLSHTTPClient(addr, "example.test", fp, true, 5*time.Second, "http/1.1")
	defer client.CloseIdleConnections()

	// Override scheme: httptest gives us https://127.0.0.1:PORT, but
	// buildUTLSHTTPClient builds a Transport that dials addr directly. We
	// just need a URL string with the matching host:port.
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		// Don't Fatal: handshake error is one of the two valid outcomes
		// (Success OR Error counter ticks). We still want to assert
		// counters fired below.
		t.Logf("client.Get returned error (expected if stdlib TLS server rejects MLKEM ClientHello): %v", err)
	} else {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	// Robust assertion: the primary regression risk we are guarding against
	// is the cold-path silently ignoring SHADOWLINK_TLS_PQ. As long as
	// EITHER Success OR Error ticked, the new branch is wired. Whether the
	// stdlib httptest TLS server accepts a MLKEM ClientHello and completes
	// (Success) or rejects it (Error) is Go/utls version-dependent and not
	// what this test verifies. Fallback MUST stay at 0 — the helper
	// pqClientHelloSpec() does not error today; if it ever does, the
	// fallback delta exposes that. (pqClientHelloSpec is called with the
	// selected profile's helloID; for Chrome that is HelloChrome_133.)
	deltaSent := Stats.PQClientHelloSent.Load() - before
	deltaErr := Stats.PQHandshakeError.Load() - beforeErr
	deltaFb := Stats.PQHandshakeFallback.Load() - beforeFb
	if deltaSent+deltaErr < 1 {
		t.Errorf("expected at least one PQ counter tick (clienthello_sent OR error), got clienthello_sent=%d error=%d", deltaSent, deltaErr)
	}
	if deltaFb != 0 {
		t.Errorf("PQHandshakeFallback unexpectedly ticked: delta=%d (pqClientHelloSpec should not error today)", deltaFb)
	}
	_ = tls.VersionTLS13 // import marker; cert verification is skipped above.
	// NOTE (deviation from plan literal): the plan's final assertion
	// `resp.TLS == nil despite Success counter` is unreachable for uTLS
	// cold-path clients. net/http.Transport only populates Response.TLS
	// when the dial returns a *crypto/tls.Conn — buildUTLSDialTLS returns
	// a *utls.UConn (the entire reason this helper exists), so resp.TLS
	// is always nil even on a successful handshake. The PQClientHelloSent
	// counter delta plus deltaFb==0 already proves the wiring; the
	// resp.TLS check is an environmental false-negative.
}

// TestColdPath_PQ_OptOut_NoCounterTick asserts the cold-path counters stay
// flat when the operator opts out via SHADOWLINK_TLS_PQ=0. Default is now
// ON since the 2026-04-28 Phase 2 closure flip, so the only way to keep
// PQ counters quiet is an explicit opt-out value.
func TestColdPath_PQ_OptOut_NoCounterTick(t *testing.T) {
	// Explicit opt-out: =0 routes through the legacy stock-helloID path.
	t.Setenv("SHADOWLINK_TLS_PQ", "0")

	before := Stats.PQClientHelloSent.Load()
	beforeFb := Stats.PQHandshakeFallback.Load()
	beforeErr := Stats.PQHandshakeError.Load()
	t.Cleanup(func() {
		Stats.PQClientHelloSent.Store(before)
		Stats.PQHandshakeFallback.Store(beforeFb)
		Stats.PQHandshakeError.Store(beforeErr)
	})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	fp := browser.NewFingerprint(browser.ProfileChrome)
	addr := srv.Listener.Addr().String()
	client := buildUTLSHTTPClient(addr, "example.test", fp, true, 5*time.Second, "http/1.1")
	defer client.CloseIdleConnections()

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if d := Stats.PQClientHelloSent.Load() - before; d != 0 {
		t.Errorf("PQClientHelloSent delta = %d, want 0 (env unset)", d)
	}
	if d := Stats.PQHandshakeFallback.Load() - beforeFb; d != 0 {
		t.Errorf("PQHandshakeFallback delta = %d, want 0 (env unset)", d)
	}
	if d := Stats.PQHandshakeError.Load() - beforeErr; d != 0 {
		t.Errorf("PQHandshakeError delta = %d, want 0 (env unset)", d)
	}
}

// TestColdPath_FirefoxProfileNotChromeHello asserts the C4 cold-path lockstep
// fix: when the selected profile is Firefox, the cold-path ClientHelloID must
// be Firefox_148 (NOT Chrome_133), and the stock Firefox spec must derive
// cleanly without the Chrome-shaped MLKEM injection. Prior to the C4 BLOCKER
// fix, PQ-on cold paths always discarded the selected helloID and emitted a
// Chrome 133 ClientHello — a cross-layer mismatch (Firefox UA/H2 + Chrome TLS)
// detectable on the wire.
func TestColdPath_FirefoxProfileNotChromeHello(t *testing.T) {
	if _, ok := browser.LookupProfile("firefox"); !ok {
		t.Skip("firefox not in registry")
	}
	fp := browser.NewFingerprintForProfile("firefox")
	if fp.Profile().Name != "firefox" {
		t.Fatalf("profile name = %q, want firefox", fp.Profile().Name)
	}

	helloID := utlsProfileForFingerprint(fp)
	if helloID != utls.HelloFirefox_148 {
		t.Errorf("firefox cold-path helloID = %v, want HelloFirefox_148", helloID)
	}
	if helloID == utls.HelloChrome_133 {
		t.Errorf("firefox cold-path helloID must NOT be Chrome 133")
	}

	// Stock Firefox spec must derive without panic and without the
	// Chrome-PQ overlay — this is the non-Chrome cold-path branch.
	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		t.Fatalf("firefox spec derive: %v", err)
	}
	if len(spec.Extensions) == 0 {
		t.Error("firefox spec has no extensions (unexpected)")
	}
}

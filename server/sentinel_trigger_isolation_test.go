package server

// sentinel_trigger_isolation_test.go — Task 1.5
//
// Enforces the spec v4 §4.7.1 invariant: SentinelEmitter.Emit (and therefore
// the body-marker carrier) MUST be called ONLY from rate-limit branches.
// Non-rate-limit branches (auth_fail, replay_detected, malformed/body_invalid,
// max_clients, protocol_unknown/unauth_visitor, handshake_fail) MUST NOT emit
// the body marker.
//
// Approach B: direct function calls to failClosedToDecoyRateLimitedV2 and
// failClosedToDecoyWithReason, bypassing HTTP routing. Rationale: tests the
// EXACT invariant at the dispatch function level, not the HTTP path level.
// Faster, deterministic, no WS/HTTP routing setup required.
//
// Test inventory:
//
//   Positive (body marker SHOULD appear):
//     TestTriggerIsolation_RateLimitedHandshake_EmitsBody
//
//   Negative (body marker MUST NOT appear — one per non-rl reason):
//     TestTriggerIsolation_AuthFail_DoesNotEmitBody
//     TestTriggerIsolation_ReplayDetected_DoesNotEmitBody
//     TestTriggerIsolation_MaxClients_DoesNotEmitBody
//     TestTriggerIsolation_BodyInvalid_DoesNotEmitBody
//     TestTriggerIsolation_ProtocolUnknown_DoesNotEmitBody
//     TestTriggerIsolation_HandshakeFail_DoesNotEmitBody
//
//   Counter invariant:
//     TestTriggerIsolation_Counters_OnlyRateLimitIncrementsBody

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupHandlerWithEmitter returns a Handler with a wired SentinelEmitter backed
// by a real snapshot (so body-marker substitution can actually fire) and a fresh
// Metrics instance so counter assertions are deterministic per test.
func setupHandlerWithEmitter(t *testing.T) (*Handler, *Metrics) {
	t.Helper()

	h, _ := setupTestHandler(t)

	// Fresh metrics so counters start at zero.
	m := NewMetrics()
	h.metrics = m

	// Build a snapshot and wire the emitter.
	_, snaps := makeSentinelTestSnap(t, "index.html")
	h.sentinelEmitter = NewSentinelEmitter(snaps, m)

	return h, m
}

// rlSig returns a canonical rate-limit RLSentinel for the handshake bucket.
func rlSig() RLSentinel {
	return RLSentinel{
		Bucket:    "handshake",
		BurstLeft: 0,
		RefillIn:  5 * time.Second,
		Exempt:    0,
	}
}

// bodyHasRLStateMarker returns true if the body contains the JSON-LD
// application/ld+json block with a non-baseline rl-state value.
// It checks for the structural markers only — not the exact value — so the
// test is robust against value-format changes.
func bodyHasRLStateMarker(body string) bool {
	return strings.Contains(body, `"rl-state"`) &&
		strings.Contains(body, "bucket=")
}

// =============================================================================
// Positive test — rate-limit path SHOULD emit body marker
// =============================================================================

// TestTriggerIsolation_RateLimitedHandshake_EmitsBody calls
// failClosedToDecoyRateLimitedV2 with a real SentinelEmitter wired and verifies
// that the response body contains the rl-state body marker with the injected
// rate-limit info, and that RateLimitEmittedByBody is incremented to 1.
func TestTriggerIsolation_RateLimitedHandshake_EmitsBody(t *testing.T) {
	h, m := setupHandlerWithEmitter(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/a", nil)

	h.failClosedToDecoyRateLimitedV2(w, r, rlSig())

	body := w.Body.String()

	// Body must contain the JSON-LD rl-state marker with injected bucket label.
	require.True(t, bodyHasRLStateMarker(body),
		"rate-limit path MUST emit body marker with rl-state propertyID and bucket label; body=%q", body)

	// JSON-LD script tag must be present.
	assert.Contains(t, body, `<script type="application/ld+json">`,
		"body must still contain JSON-LD script tag")

	// Header must be present (dual-carrier).
	xlrl := w.Header().Get("X-SL-RL")
	require.NotEmpty(t, xlrl, "X-SL-RL header must be set by rate-limit path")
	assert.Contains(t, xlrl, "bucket=handshake")

	// Counter must be 1.
	assert.EqualValues(t, 1, m.RateLimitEmittedByBody.Load(),
		"RateLimitEmittedByBody must be 1 after rate-limit Emit")
	assert.EqualValues(t, 0, m.RateLimitEmittedByBodyMissing.Load(),
		"RateLimitEmittedByBodyMissing must stay 0 on the happy path")
}

// =============================================================================
// Negative tests — non-rate-limit paths MUST NOT emit body marker
// =============================================================================

// assertNoBodyMarker is the shared negative-path assertion. It verifies that:
//   - The response body does NOT contain the substituted rl-state marker
//     (i.e., "bucket=" is absent — the body marker was not injected).
//   - The X-SL-RL header is absent (non-rl paths never emit it).
//   - RateLimitEmittedByBody remains 0.
//   - RateLimitEmittedByBodyMissing remains 0.
func assertNoBodyMarker(t *testing.T, w *httptest.ResponseRecorder, m *Metrics, pathName string) {
	t.Helper()

	body := w.Body.String()

	// The injected body marker contains "bucket=" — baseline HTML never does.
	assert.False(t, strings.Contains(body, "bucket="),
		"%s: body MUST NOT contain 'bucket=' (body marker must not be injected); body=%q",
		pathName, body)

	// Non-rl paths do not emit X-SL-RL at all.
	xlrl := w.Header().Get("X-SL-RL")
	assert.Empty(t, xlrl,
		"%s: X-SL-RL header MUST be absent on non-rate-limit paths; got %q", pathName, xlrl)

	// Counter assertions: sentinel emitter must never have been called.
	assert.EqualValues(t, 0, m.RateLimitEmittedByBody.Load(),
		"%s: RateLimitEmittedByBody must stay 0 on non-rate-limit path", pathName)
	assert.EqualValues(t, 0, m.RateLimitEmittedByBodyMissing.Load(),
		"%s: RateLimitEmittedByBodyMissing must stay 0 on non-rate-limit path", pathName)
}

// TestTriggerIsolation_AuthFail_DoesNotEmitBody verifies that the auth_fail
// path (DecoyReasonAuthFail) does not invoke the SentinelEmitter body marker.
func TestTriggerIsolation_AuthFail_DoesNotEmitBody(t *testing.T) {
	h, m := setupHandlerWithEmitter(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/a", nil)

	h.failClosedToDecoyWithReason(w, r, DecoyReasonAuthFail)

	assertNoBodyMarker(t, w, m, "auth_fail")
}

// TestTriggerIsolation_ReplayDetected_DoesNotEmitBody verifies that the
// replay_detected path does not invoke the SentinelEmitter body marker.
func TestTriggerIsolation_ReplayDetected_DoesNotEmitBody(t *testing.T) {
	h, m := setupHandlerWithEmitter(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/a", nil)

	h.failClosedToDecoyWithReason(w, r, DecoyReasonReplayDetected)

	assertNoBodyMarker(t, w, m, "replay_detected")
}

// TestTriggerIsolation_MaxClients_DoesNotEmitBody verifies that the max_clients
// overload path does not invoke the SentinelEmitter body marker.
func TestTriggerIsolation_MaxClients_DoesNotEmitBody(t *testing.T) {
	h, m := setupHandlerWithEmitter(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/a", nil)

	h.failClosedToDecoyWithReason(w, r, DecoyReasonMaxClients)

	assertNoBodyMarker(t, w, m, "max_clients")
}

// TestTriggerIsolation_BodyInvalid_DoesNotEmitBody verifies that the
// malformed/body_invalid path does not invoke the SentinelEmitter body marker.
func TestTriggerIsolation_BodyInvalid_DoesNotEmitBody(t *testing.T) {
	h, m := setupHandlerWithEmitter(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/a", nil)

	h.failClosedToDecoyWithReason(w, r, DecoyReasonBodyInvalid)

	assertNoBodyMarker(t, w, m, "body_invalid")
}

// TestTriggerIsolation_ProtocolUnknown_DoesNotEmitBody verifies that the
// unauth_visitor / ws_upgrade_fail path (DecoyReasonProtocolUnknown) does not
// invoke the SentinelEmitter body marker.
func TestTriggerIsolation_ProtocolUnknown_DoesNotEmitBody(t *testing.T) {
	h, m := setupHandlerWithEmitter(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/cable", nil)

	h.failClosedToDecoyWithReason(w, r, DecoyReasonProtocolUnknown)

	assertNoBodyMarker(t, w, m, "protocol_unknown")
}

// TestTriggerIsolation_HandshakeFail_DoesNotEmitBody verifies that the
// handshake_fail path (device-limit, HandleClientHelloWithVersion failure) does
// not invoke the SentinelEmitter body marker.
func TestTriggerIsolation_HandshakeFail_DoesNotEmitBody(t *testing.T) {
	h, m := setupHandlerWithEmitter(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/a", nil)

	h.failClosedToDecoyWithReason(w, r, DecoyReasonHandshakeFail)

	assertNoBodyMarker(t, w, m, "handshake_fail")
}

// =============================================================================
// Counter invariant across all paths
// =============================================================================

// TestTriggerIsolation_Counters_OnlyRateLimitIncrementsBody runs both the
// rate-limit path and every non-rate-limit reason through a single shared
// Metrics instance and asserts:
//   - RateLimitEmittedByBody == 1  (exactly the one rate-limit call)
//   - RateLimitEmittedByBodyMissing == 0  (emitter found the snapshot every time)
//   - RateLimitSentinelEmitted == 1  (header carrier only from rate-limit path)
//
// This is the definitive counter-invariant test for the §4.7.1 spec.
func TestTriggerIsolation_Counters_OnlyRateLimitIncrementsBody(t *testing.T) {
	h, m := setupHandlerWithEmitter(t)

	// Helper so we can declare w,r inline.
	call := func(reason DecoyReason) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/a", nil)
		h.failClosedToDecoyWithReason(w, r, reason)
		_ = w
	}

	// === Non-rate-limit paths (must not touch emitter) ===
	nonRLReasons := []DecoyReason{
		DecoyReasonAuthFail,
		DecoyReasonReplayDetected,
		DecoyReasonMaxClients,
		DecoyReasonBodyInvalid,
		DecoyReasonProtocolUnknown,
		DecoyReasonHandshakeFail,
		DecoyReasonDeviceLimit,
		DecoyReasonBackpressure,
		DecoyReasonVersionUnsupported,
	}
	for _, reason := range nonRLReasons {
		call(reason)
	}

	// Counters must still be zero after all non-rl paths.
	require.EqualValues(t, 0, m.RateLimitEmittedByBody.Load(),
		"RateLimitEmittedByBody must be 0 after all non-rate-limit paths")
	require.EqualValues(t, 0, m.RateLimitEmittedByBodyMissing.Load(),
		"RateLimitEmittedByBodyMissing must be 0 after all non-rate-limit paths")
	require.EqualValues(t, 0, m.RateLimitSentinelEmitted.Load(),
		"RateLimitSentinelEmitted must be 0 after all non-rate-limit paths")

	// === Rate-limit path (exactly one call) ===
	{
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/a", nil)
		h.failClosedToDecoyRateLimitedV2(w, r, rlSig())
		_ = w
	}

	// After the single rate-limit call, body counter must be exactly 1.
	assert.EqualValues(t, 1, m.RateLimitEmittedByBody.Load(),
		"RateLimitEmittedByBody must be exactly 1 after one rate-limit call")
	assert.EqualValues(t, 0, m.RateLimitEmittedByBodyMissing.Load(),
		"RateLimitEmittedByBodyMissing must stay 0 (snapshot is present)")
	assert.EqualValues(t, 1, m.RateLimitSentinelEmitted.Load(),
		"RateLimitSentinelEmitted must be 1 — emitter called exactly once")
}

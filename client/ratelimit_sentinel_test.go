package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/nixavpn/shadowlink/core"
)

// Task A2 (May audit, 2026-05-01): when the server emits `X-SL-RL: 1` in the
// decoy response that aborts a WS upgrade or handshake POST, the client must
// surface a typed sentinel error (ErrRateLimited) so reconnectLoop can switch
// from exp backoff to a fixed cool-down (180s ± 30%).

// TestErrRateLimited_IsTyped exists to guard the contract: tests and callers
// match the sentinel via errors.Is, NOT string-matching. A future refactor
// must keep the typed wrapper for the cooldown branch to fire.
func TestErrRateLimited_IsTyped(t *testing.T) {
	wrapped := fmt.Errorf("ws upgrade: %w", ErrRateLimited)
	require.True(t, errors.Is(wrapped, ErrRateLimited),
		"errors.Is must walk fmt.Errorf(%%w) wrap chain to ErrRateLimited")
}

// TestUpgradeToWS_DetectsXSLRLHeader: spin up an httptest server that mimics
// the rate-limit decoy response — 200 + verbose X-SL-RL header instead of
// the WS upgrade 101. UpgradeToWS must propagate ErrRateLimited up the call
// chain. Detection is by header presence, not value equality (C5 verbose
// format introduced 2026-05-02).
func TestUpgradeToWS_DetectsXSLRLHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mimic server's failClosedToDecoyRateLimitedV2: 200 + verbose X-SL-RL + decoy body.
		w.Header().Set("X-SL-RL", "bucket=ws_upgrade,burst_left=0,refill_in=0s,exempt=0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>under construction</body></html>"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	// Plain http transport (useTLS=false) so we exercise the WS dial path
	// without touching uTLS. UpgradeToWS uses gorilla's dialer — gorilla
	// returns the *http.Response on non-101 status codes alongside the error.
	tr := NewWebSocketTransport(host, false, true)

	// Build a minimal first-frame payload — must satisfy length gate, but the
	// server returns 200 before reading any body so contents do not matter.
	dummyToken := make([]byte, 32)
	for i := range dummyToken {
		dummyToken[i] = byte(i)
	}
	sess := core.NewSession(7, make([]byte, 32), make([]byte, 32))

	err := tr.UpgradeToWS(dummyToken, sess)
	require.Error(t, err, "UpgradeToWS must error when server returns 200 instead of 101")
	require.True(t, errors.Is(err, ErrRateLimited),
		"UpgradeToWS must surface ErrRateLimited when X-SL-RL: 1 is present, got: %v", err)
}

// TestUpgradeToWS_NoXSLRLHeader_ReturnsGenericError: if the upgrade fails for
// any other reason (no sentinel), the returned error must NOT match
// ErrRateLimited — that would cause reconnectLoop to over-eagerly cool down
// for ordinary network failures.
func TestUpgradeToWS_NoXSLRLHeader_ReturnsGenericError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 + decoy but NO X-SL-RL header — looks like the generic decoy /
		// CF middlebox error.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>404</body></html>"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewWebSocketTransport(host, false, true)

	dummyToken := make([]byte, 32)
	sess := core.NewSession(11, make([]byte, 32), make([]byte, 32))
	err := tr.UpgradeToWS(dummyToken, sess)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrRateLimited),
		"generic upgrade failure must NOT alias to ErrRateLimited (would over-cool slots)")
}

// TestSlotRateLimitedCooldown_RangeIsFixed verifies the cool-down stays in
// the documented [126s, 234s] envelope = 180s ± 30%. Plan invariant:
//
//   - reconnectLoop applies a fixed cool-down (NOT exp) on rate-limit sentinel
//   - 180s ± 30% jitter properly randomized per call
//   - does not overlap with normal slotBackoffDuration range
//     (slotBackoff caps at 60s, so 126s floor is well clear)
func TestSlotRateLimitedCooldown_RangeIsFixed(t *testing.T) {
	const samples = 500
	const lo = 126 * time.Second
	const hi = 234 * time.Second

	minSeen, maxSeen := time.Hour, time.Duration(0)
	for range samples {
		d := slotRateLimitedCooldown()
		require.GreaterOrEqual(t, d, lo, "below 126s floor")
		require.LessOrEqual(t, d, hi, "above 234s ceiling")
		if d < minSeen {
			minSeen = d
		}
		if d > maxSeen {
			maxSeen = d
		}
	}

	// Spread sanity: the jitter window is 108s wide, so 500 draws should
	// produce a min-max gap of at least 30s. A regression where the cool-down
	// becomes constant (0% jitter) would collapse this gap to 0.
	require.Greater(t, maxSeen-minSeen, 30*time.Second,
		"cool-down jitter must spread across draws — got min=%v max=%v",
		minSeen, maxSeen)

	// Non-overlap with regular slotBackoffDuration: that range caps at 60s,
	// the cool-down floor is 126s. The two MUST stay disjoint.
	require.Greater(t, lo, 60*time.Second,
		"cool-down floor must be strictly above slotBackoffDuration cap (60s)")
}

// TestSlotRateLimitedCooldown_IndependentDraws: two consecutive draws must
// (with overwhelming probability) be different — sanity check that the
// random source isn't accidentally seeded once.
func TestSlotRateLimitedCooldown_IndependentDraws(t *testing.T) {
	a := slotRateLimitedCooldown()
	b := slotRateLimitedCooldown()
	require.NotEqual(t, a, b,
		"two cool-down draws must differ with overwhelming probability")
}

// TestSleepWithCancelRespectsCtxDone: the cool-down must not block forever
// on shutdown. The helper that paces the cool-down inside reconnectLoop
// must return promptly on ctx.Done().
func TestSleepWithCancelRespectsCtxDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// 5s cool-down — but we cancel after 50ms. Must return well before
		// the 5s would have elapsed.
		sleepWithCancel(ctx, 5*time.Second)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("sleepWithCancel did not respect ctx.Done()")
	}
}

// TestReconnectLoop_AppliesCooldownOnRateLimit: integration-shaped test —
// drive a reconnectLoop where connectSlot returns ErrRateLimited and observe
// that the next reconnect attempt waits at least the cool-down floor (126s)
// before firing again. We use a fake connectSlot via a hook to keep the test
// hermetic and fast — the floor check is achieved by polling Stats.RateLimited.
//
// We simulate a single attempt: rate-limit hit → cool-down scheduled. We
// don't wait the full 126s (that would make CI excruciating); we instead
// assert that the cool-down counter ticked AND the slot did NOT reconnect
// inside a short window.
func TestReconnectLoop_AppliesCooldownOnRateLimit(t *testing.T) {
	// Reset the package-level counter so the test is independent of order.
	Stats.RateLimitedFromServer.Store(0)

	cooldownInvocations := 0
	prev := slotRateLimitedCooldownForTest
	slotRateLimitedCooldownForTest = func() time.Duration {
		cooldownInvocations++
		// Override to 100ms so the test stays fast — the production helper
		// returns 126-234s. The floor envelope is asserted in
		// TestSlotRateLimitedCooldown_RangeIsFixed independently.
		return 100 * time.Millisecond
	}
	defer func() { slotRateLimitedCooldownForTest = prev }()

	// Also accelerate slotBackoffDuration so attempt-0 backoff (normally
	// 5-10s) doesn't dominate the test wall-clock. The 5-10s envelope is
	// covered separately by TestSlotBackoffDuration_RangesPerAttempt.
	prevBackoff := slotBackoffDurationForTest
	slotBackoffDurationForTest = func(int) time.Duration {
		return 10 * time.Millisecond
	}
	defer func() { slotBackoffDurationForTest = prevBackoff }()

	// Build a minimal pool — bypass full Connect by constructing the struct
	// directly and forcing connectSlot through a stub.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stubAttempts := 0
	stub := func() error {
		stubAttempts++
		if stubAttempts <= 1 {
			return ErrRateLimited
		}
		// Second attempt: succeed so the loop exits.
		return nil
	}

	prevStub := getConnectSlotForTest()
	setConnectSlotForTest(stub)
	defer func() { setConnectSlotForTest(prevStub) }()

	p := &WSPoolTransport{
		poolSize: 1,
		slots:    []*poolSlot{nil},
		ctx:      ctx,
		cancel:   cancel,
	}
	p.log = newDiscardLogger()

	done := make(chan struct{})
	go func() {
		p.reconnectLoop(0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnectLoop did not exit within 5s")
	}

	require.Equal(t, 1, cooldownInvocations,
		"cool-down helper must be called exactly once for the single rate-limit hit")
	require.Equal(t, int64(1), Stats.RateLimitedFromServer.Load(),
		"Stats.RateLimitedFromServer must tick exactly once per rate-limit event "+
			"(single decision point in reconnectLoop; UpgradeToWS / SendHandshake "+
			"must NOT also increment, else one event double-counts)")
	require.Equal(t, 2, stubAttempts,
		"after cool-down the loop must retry connectSlot once and then exit on success")
}

// ---- Phase 2 fix: reconnectLoop must honor Signal.RefillIn ----

// reconnectLoopWithSignal is a shared helper that drives reconnectLoop with a
// single rate-limit hit (via *RateLimitError with the given signal), measures
// the cooldown that was slept (via sleepWithCancelForTest seam if available,
// else via wall-clock), and returns. We implement it by hooking the
// slotRateLimitedCooldownForTest + connectSlotForTest seams.
//
// This function DOES NOT measure sleep duration directly (sleepWithCancel has
// no seam). Instead it confirms the correct cooldown calculation by observing
// that the fallback stub is NOT called when a signal is present (vs. IS called
// when absent).

// reconnectLoopHelper runs reconnectLoop with one rate-limit error followed by
// success. Returns whether slotRateLimitedCooldownForTest was invoked.
//
// When the server-directed cooldown path fires (no fallback), the cooldown
// duration may be >5s (e.g. clamp(12s) * 1.30 ≈ 15.6s). To keep CI fast the
// helper cancels the pool ctx after 100ms so sleepWithCancel unblocks quickly.
// After cancellation the loop retries and returns nil on attempt 2, exiting.
func reconnectLoopHelper(t *testing.T, connectErr error) (fallbackInvoked bool) {
	t.Helper()
	Stats.RateLimitedFromServer.Store(0)

	var fallbackCount int
	prev := slotRateLimitedCooldownForTest
	slotRateLimitedCooldownForTest = func() time.Duration {
		fallbackCount++
		return 50 * time.Millisecond // fast for CI
	}
	defer func() { slotRateLimitedCooldownForTest = prev }()

	prevBackoff := slotBackoffDurationForTest
	slotBackoffDurationForTest = func(int) time.Duration { return 5 * time.Millisecond }
	defer func() { slotBackoffDurationForTest = prevBackoff }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempts := 0
	stub := func() error {
		attempts++
		if attempts == 1 {
			// Cancel the context shortly after the rate-limit error is returned.
			// This ensures sleepWithCancel unblocks promptly regardless of how
			// long the computed cooldown is (server-directed paths may compute
			// 5s–30min; we don't want CI to wait that long).
			go func() { time.Sleep(100 * time.Millisecond); cancel() }()
			return connectErr
		}
		return nil
	}
	prevStub := getConnectSlotForTest()
	setConnectSlotForTest(stub)
	defer func() { setConnectSlotForTest(prevStub) }()

	p := &WSPoolTransport{
		poolSize: 1,
		slots:    []*poolSlot{nil},
		ctx:      ctx,
		cancel:   cancel,
	}
	p.log = newDiscardLogger()

	done := make(chan struct{})
	go func() {
		p.reconnectLoop(0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnectLoop did not exit within 5s")
	}
	return fallbackCount > 0
}

// TestReconnectLoop_HonorsRefillInFromSignal: Signal.RefillIn=12s → reconnectLoop
// must use the server-directed value (NOT fallback). The cooldown must land in
// [12s * 0.70, 12s * 1.30] = [8.4s, 15.6s] after ±30% jitter + clamp.
// We verify indirectly: fallback stub must NOT be called when Signal carries RefillIn > 0.
func TestReconnectLoop_HonorsRefillInFromSignal(t *testing.T) {
	sig := &RateLimitSignal{
		Carrier:  "body",
		Bucket:   "handshake",
		RefillIn: 12 * time.Second,
	}
	connectErr := &RateLimitError{Signal: sig}

	fallbackUsed := reconnectLoopHelper(t, connectErr)
	require.False(t, fallbackUsed,
		"fallback slotRateLimitedCooldown must NOT be called when Signal.RefillIn > 0")
}

// TestReconnectLoop_RefillInClampedToFloor: Signal.RefillIn=1s is below the
// 5s floor — clampRefillIn must snap it up. Fallback must NOT fire.
func TestReconnectLoop_RefillInClampedToFloor(t *testing.T) {
	sig := &RateLimitSignal{
		Carrier:  "header_v1",
		Bucket:   "ws_upgrade",
		RefillIn: 1 * time.Second, // below rateLimitRefillFloor (5s)
	}
	connectErr := &RateLimitError{Signal: sig}

	fallbackUsed := reconnectLoopHelper(t, connectErr)
	require.False(t, fallbackUsed,
		"fallback must NOT fire when Signal.RefillIn > 0 (even if below floor — clamp handles it)")
}

// TestReconnectLoop_RefillInClampedToCeil: Signal.RefillIn=2h is above the
// 30-min ceiling — clampRefillIn must snap it down. Fallback must NOT fire.
// reconnectLoopHelper cancels the pool ctx after 100ms so the test stays fast.
func TestReconnectLoop_RefillInClampedToCeil(t *testing.T) {
	sig := &RateLimitSignal{
		Carrier:  "fallback",
		Bucket:   "handshake",
		RefillIn: 2 * time.Hour, // above rateLimitRefillCeil (30m)
	}
	connectErr := &RateLimitError{Signal: sig}

	fallbackUsed := reconnectLoopHelper(t, connectErr)
	require.False(t, fallbackUsed,
		"fallback must NOT fire when Signal.RefillIn > 0 (even clamped to ceil)")
}

// TestReconnectLoop_NoSignal_UsesFallback: errors.Is matches ErrRateLimited but
// the error is NOT *RateLimitError (i.e. errors.As fails) → fallback path must
// fire with slotRateLimitedCooldownForTest.
func TestReconnectLoop_NoSignal_UsesFallback(t *testing.T) {
	// Wrap ErrRateLimited directly without the *RateLimitError wrapper so that
	// errors.Is succeeds but errors.As(*RateLimitError) fails.
	connectErr := fmt.Errorf("transport: %w", ErrRateLimited)

	fallbackUsed := reconnectLoopHelper(t, connectErr)
	require.True(t, fallbackUsed,
		"fallback slotRateLimitedCooldown must be called when errors.As(*RateLimitError) fails")
}

// TestClampRefillIn_FloorCeilIdentity: unit tests for the clampRefillIn helper.
func TestClampRefillIn_FloorCeilIdentity(t *testing.T) {
	require.Equal(t, rateLimitRefillFloor, clampRefillIn(0),
		"zero should clamp to floor")
	require.Equal(t, rateLimitRefillFloor, clampRefillIn(1*time.Second),
		"1s below floor → floor")
	require.Equal(t, rateLimitRefillFloor, clampRefillIn(rateLimitRefillFloor),
		"exactly floor → floor")
	require.Equal(t, 60*time.Second, clampRefillIn(60*time.Second),
		"mid-range value passes through unchanged")
	require.Equal(t, rateLimitRefillCeil, clampRefillIn(rateLimitRefillCeil),
		"exactly ceil → ceil")
	require.Equal(t, rateLimitRefillCeil, clampRefillIn(2*time.Hour),
		"2h above ceil → ceil")
}

// _ = websocket.Dialer pins the gorilla import even if a future edit removes
// the harness dial — keeps go vet quiet without an opportunistic cleanup.
var _ = websocket.Dialer{}

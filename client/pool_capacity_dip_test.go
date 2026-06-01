package client

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Pool capacity-dip fix (spec 2026-06-01-pool-capacity-dip-fix-design.md)
//
// Root cause: a routine TSPU age-cut (a mature direct-TCP slot closed 1006 by
// the middlebox) was handled as deathCauseNatural → 5-10s exponential backoff
// reconnect AND fed the meltdown detector. Under the cascade of mature-slot
// cuts the pool's live capacity dipped and quiet streams' downlink froze.
//
// Fix: classify the mature close-1006 as deathCauseAgeCut → fast reconnect
// (small jitter only, not the 5-10s exponential), and do NOT feed meltdown.
// ---------------------------------------------------------------------------

// fakeAgeCutClose1006 returns an error whose classifyWSReadError lands in the
// close_other (close-1006 family) bucket — the on-wire signature of a TSPU
// age-cut.
func fakeAgeCutClose1006() error {
	return errors.New("websocket: close 1006 (abnormal closure): unexpected EOF")
}

// TestIsAgeCut_MatureClose1006 pins the classification contract:
//   - close 1006 at a mature age (>= ageCutMinAgeMs) → age-cut (true)
//   - close 1006 at a young age (< ageCutMinAgeMs) → NOT age-cut (real failure)
//   - a non-1006 terminal error at a mature age → NOT age-cut
func TestIsAgeCut_MatureClose1006(t *testing.T) {
	close1006 := fakeAgeCutClose1006()

	require.True(t, isAgeCut(close1006, ageCutMinAgeMs),
		"close 1006 exactly at the min-age floor must count as an age-cut")
	require.True(t, isAgeCut(close1006, 120_000),
		"close 1006 at 120s (TSPU cut window) must count as an age-cut")

	require.False(t, isAgeCut(close1006, 20_000),
		"close 1006 at 20s is a young-slot failure, not an age-cut (be conservative)")
	require.False(t, isAgeCut(close1006, ageCutMinAgeMs-1),
		"just under the floor must NOT qualify as an age-cut")

	// A genuine non-1006 terminal error at a mature age is a real failure.
	resetErr := errors.New("read tcp: connection reset by peer")
	require.False(t, isAgeCut(resetErr, 120_000),
		"a TCP RST is a genuine failure regardless of age, not an age-cut")

	require.False(t, isAgeCut(nil, 120_000), "nil error is never an age-cut")
}

// TestIsClose1006 pins the helper that detects the close-1006 family via the
// existing classifyWSReadError vocabulary.
func TestIsClose1006(t *testing.T) {
	require.True(t, isClose1006(fakeAgeCutClose1006()),
		"close 1006 must be recognized as the close_other family")
	require.False(t, isClose1006(errors.New("read tcp: connection reset by peer")),
		"a TCP RST is reset_by_peer, not close_other")
	require.False(t, isClose1006(nil), "nil is not a close 1006")
}

// newAgeCutTestPool builds a minimal pool wired for handleSlotDeath dispatch
// tests (live ctx for the reconnect goroutine, non-zero meltdown window for the
// recentDeaths decrement timer). Pool size 1, single slot installed at idx 0.
func newAgeCutTestPool(t *testing.T, slot *poolSlot) (*WSPoolTransport, *Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool := &WSPoolTransport{
		slots:             make([]*poolSlot, 1),
		poolSize:          1,
		log:               slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	pool.slots[0] = slot
	return pool, &Client{}
}

// TestAgeCut_NoMeltdownFeed — Lever 3: a cascade of age-cuts must NOT advance
// the meltdown counter (recordSlotDeath is skipped), while genuine young-slot
// natural deaths still feed it.
func TestAgeCut_NoMeltdownFeed(t *testing.T) {
	// N age-cut deaths in a row leave recentDeaths untouched.
	for i := 0; i < 5; i++ {
		slot := &poolSlot{index: 0}
		slot.setState(slotReady)
		pool, cl := newAgeCutTestPool(t, slot)
		// Pre-cancel so the spawned reconnectLoopFast exits at its ctx-check
		// before attempting a real connectSlot on this unwired test pool.
		pool.cancel()
		pool.handleSlotDeath(cl, 0, deathCauseAgeCut)
		require.Equal(t, slotDead, slot.getState(),
			"age-cut death must still flip the slot to slotDead")
		require.Zero(t, pool.recentDeaths.Load(),
			"age-cut MUST NOT advance the meltdown counter — a steady cascade of "+
				"routine TSPU cuts must never trip the meltdown cooldown")
		require.Zero(t, pool.meltdownUntil.Load(),
			"age-cut MUST NOT engage the meltdown cooldown")
	}

	// Contrast: a young-slot natural death DOES feed the meltdown counter.
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	pool, cl := newAgeCutTestPool(t, slot)
	pool.handleSlotDeath(cl, 0, deathCauseNatural)
	require.Equal(t, int32(1), pool.recentDeaths.Load(),
		"natural death MUST still advance the meltdown counter (real instability)")
}

// TestNaturalDeath_StillExponentialAndMeltdown — regression guard: the
// pre-existing natural path is unchanged. A young-slot 1006 routed as natural
// still feeds meltdown.
func TestNaturalDeath_StillExponentialAndMeltdown(t *testing.T) {
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	pool, cl := newAgeCutTestPool(t, slot)

	pool.handleSlotDeath(cl, 0, deathCauseNatural)
	require.Equal(t, slotDead, slot.getState())
	require.Equal(t, int32(1), pool.recentDeaths.Load(),
		"natural death must feed the meltdown detector (CF/TSPU storm protection)")
}

// TestAgeCut_FastReconnect_UsesFastInitialDelay — Lever 1: the age-cut
// reconnect path must use the near-zero fast initial delay (<= ageCutReconnectJitter),
// NOT the 5-10s slotBackoffDuration(0) exponential. We drive reconnectLoop with
// a fast-installed backoff shim that records which attempt indices it was asked
// for, and a connectSlot hook that succeeds immediately, then assert the loop's
// fast path was taken by observing the ageCut-reconnect counter and that the
// fast loop never consulted slotBackoffDuration for attempt 0.
func TestAgeCut_FastReconnect_UsesFastInitialDelay(t *testing.T) {
	// Record which attempt numbers slotBackoffDuration is consulted for.
	var mu sync.Mutex
	var attemptsSeen []int
	setSlotBackoffDurationForTest(func(attempt int) time.Duration {
		mu.Lock()
		attemptsSeen = append(attemptsSeen, attempt)
		mu.Unlock()
		return time.Millisecond // fast so the test never sleeps the 5-10s real curve
	})
	t.Cleanup(func() { setSlotBackoffDurationForTest(nil) })

	slot := &poolSlot{index: 0}
	slot.setState(slotDead) // recycle guard sees a dead slot → proceeds to connect
	pool, _ := newAgeCutTestPool(t, slot)

	// connectSlot succeeds on the first try, then cancels the pool ctx so the
	// spawned slotReader (the test slot has no real transport) exits at its
	// ctx-check before it can panic-recover into a follow-on natural reconnect
	// that would consult slotBackoffDuration(0) and pollute attemptsSeen.
	connectCalls := int32(0)
	setConnectSlotForTest(func() error {
		atomic.AddInt32(&connectCalls, 1)
		pool.cancel()
		return nil
	})
	t.Cleanup(func() { setConnectSlotForTest(nil) })

	before := Stats.AgeCutReconnectsTotal.Load()

	done := make(chan struct{})
	go func() {
		pool.reconnectLoopFast(0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("reconnectLoopFast did not complete within 3s")
	}

	require.Equal(t, int32(1), atomic.LoadInt32(&connectCalls),
		"fast reconnect must connect exactly once on a clean attempt-0 success")
	require.Greater(t, Stats.AgeCutReconnectsTotal.Load(), before,
		"a successful fast reconnect must increment AgeCutReconnectsTotal")

	// The fast path MUST NOT consult slotBackoffDuration(0) (the 5-10s curve)
	// on attempt 0 — it uses ageCutReconnectJitter instead. If attempt 0 was
	// ever asked for, the fast path regressed back into the exponential.
	mu.Lock()
	defer mu.Unlock()
	for _, a := range attemptsSeen {
		require.NotEqual(t, 0, a,
			"fast reconnect must NOT use slotBackoffDuration(attempt=0) — that is "+
				"the 5-10s exponential the dip fix removes; it uses ageCutReconnectJitter")
	}
}

// TestAgeCut_FastReconnect_FallsIntoExponentialOnFailure — Lever 1 safety: when
// the attempt-0 fast connect FAILS (genuine origin problem), the loop must fall
// into the SAME exponential ladder from attempt=1 (a real outage still backs
// off). We make connectSlot fail once then succeed, and assert slotBackoffDuration
// WAS consulted for attempt 1 (the exponential kicked in) and AgeCutReconnectFail
// was incremented for the failed attempt-0.
func TestAgeCut_FastReconnect_FallsIntoExponentialOnFailure(t *testing.T) {
	var mu sync.Mutex
	var attemptsSeen []int
	setSlotBackoffDurationForTest(func(attempt int) time.Duration {
		mu.Lock()
		attemptsSeen = append(attemptsSeen, attempt)
		mu.Unlock()
		return time.Millisecond
	})
	t.Cleanup(func() { setSlotBackoffDurationForTest(nil) })

	slot := &poolSlot{index: 0}
	slot.setState(slotDead)
	pool, _ := newAgeCutTestPool(t, slot)

	calls := int32(0)
	setConnectSlotForTest(func() error {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			return errors.New("dial origin: connection refused")
		}
		pool.cancel() // success on attempt 1 → stop the spawned slotReader follow-on
		return nil
	})
	t.Cleanup(func() { setConnectSlotForTest(nil) })

	beforeFail := Stats.AgeCutReconnectFail.Load()

	done := make(chan struct{})
	go func() {
		pool.reconnectLoopFast(0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("reconnectLoopFast did not complete within 3s")
	}

	require.Equal(t, int32(2), atomic.LoadInt32(&calls),
		"fast connect failed once then succeeded → two connect attempts")
	require.Greater(t, Stats.AgeCutReconnectFail.Load(), beforeFail,
		"a failed attempt-0 fast connect must increment AgeCutReconnectFail")

	// The exponential ladder must have been consulted for attempt 1.
	mu.Lock()
	defer mu.Unlock()
	require.Contains(t, attemptsSeen, 1,
		"after the fast attempt-0 failed, the loop must fall into the exponential "+
			"ladder from attempt=1 (a real outage backs off)")
}

// TestCapacityDip_Counter — Lever 4 observability: recordCapacityDip increments
// the canary counter.
func TestCapacityDip_Counter(t *testing.T) {
	pool, _ := newAgeCutTestPool(t, &poolSlot{index: 0})
	before := Stats.CapacityDipTotal.Load()
	pool.recordCapacityDip()
	require.Equal(t, before+1, Stats.CapacityDipTotal.Load(),
		"recordCapacityDip must increment CapacityDipTotal")
}

// TestAgeCut_DoesNotSendFIN — the age-cut transport is already dead (TSPU cut
// it externally), so handleSlotDeath must NOT attempt a FIN on the dead socket
// (same as natural). We install a counting transport and assert no control
// write happened.
func TestAgeCut_DoesNotSendFIN(t *testing.T) {
	ct := &countingTransport{}
	slot := &poolSlot{index: 0, transport: ct, session: newTestSlotSession(t, 7)}
	slot.setState(slotReady)
	pool, cl := newAgeCutTestPool(t, slot)
	// Pre-cancel so the spawned reconnectLoopFast exits at its ctx-check before
	// attempting a real connectSlot on this unwired test pool.
	pool.cancel()

	pool.handleSlotDeath(cl, 0, deathCauseAgeCut)

	require.Zero(t, ct.controlWrites,
		"age-cut transport is dead — handleSlotDeath must NOT send a session FIN "+
			"(crypto-dead socket; FIN would be a no-op write at best)")
}

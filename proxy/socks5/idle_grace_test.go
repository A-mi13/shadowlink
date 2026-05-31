package socks5

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestWaitForIdleOrCancel_FiresAfterGraceWithNoActivity verifies the baseline
// case: no downlink activity after the call begins → the function returns
// after roughly `grace`, signalling the relay should be cancelled. This is the
// behaviour the old fixed `time.After(15s)` provided.
func TestWaitForIdleOrCancel_FiresAfterGraceWithNoActivity(t *testing.T) {
	ctx := context.Background()
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	grace := 60 * time.Millisecond
	poll := 10 * time.Millisecond

	start := time.Now()
	waitForIdleOrCancel(ctx, &lastActivity, grace, poll)
	elapsed := time.Since(start)

	if elapsed < grace {
		t.Fatalf("returned too early: elapsed=%v want>=%v", elapsed, grace)
	}
	if elapsed > grace+150*time.Millisecond {
		t.Fatalf("returned too late: elapsed=%v want<~%v", elapsed, grace)
	}
}

// TestWaitForIdleOrCancel_ActivityExtendsDeadline is the core regression test
// for the bug: an active download keeps refreshing lastActivity, so the grace
// timer must NOT fire while data is flowing. Here we refresh activity for
// 5 poll cycles, then stop — the function must only return ~grace AFTER the
// last refresh, not `grace` after the call started.
func TestWaitForIdleOrCancel_ActivityExtendsDeadline(t *testing.T) {
	ctx := context.Background()
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	grace := 60 * time.Millisecond
	poll := 10 * time.Millisecond

	// Keep the stream "active" for 250ms by refreshing lastActivity every
	// 20ms (well under the 60ms grace). With the old fixed-timer logic the
	// relay would have been cancelled at ~60ms; with idle-aware logic it must
	// stay alive the whole time.
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				lastActivity.Store(time.Now().UnixNano())
			}
		}
	}()

	start := time.Now()
	// Stop refreshing after 250ms; the function should still be waiting.
	time.AfterFunc(250*time.Millisecond, func() { close(stop) })

	waitForIdleOrCancel(ctx, &lastActivity, grace, poll)
	elapsed := time.Since(start)

	// Must have survived well past the original grace window (60ms) because
	// activity kept extending the deadline. Lower bound: last refresh (~250ms)
	// + grace (60ms) = ~310ms.
	if elapsed < 250*time.Millisecond {
		t.Fatalf("grace fired during active download: elapsed=%v, want>=250ms "+
			"(activity should have extended the deadline)", elapsed)
	}
}

// TestWaitForIdleOrCancel_ReturnsOnContextCancel verifies that ctx cancellation
// (e.g. the downlink goroutine finished and called cancel()) makes the function
// return promptly, regardless of the grace timer.
func TestWaitForIdleOrCancel_ReturnsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	grace := 10 * time.Second // long, so only ctx cancel can end the wait fast
	poll := 10 * time.Millisecond

	time.AfterFunc(40*time.Millisecond, cancel)

	start := time.Now()
	waitForIdleOrCancel(ctx, &lastActivity, grace, poll)
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("did not return promptly on ctx cancel: elapsed=%v", elapsed)
	}
}

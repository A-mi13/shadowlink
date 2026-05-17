//go:build loadtest

package server

import (
	"testing"
	"time"
)

// TestBroadcastStreamClose_10kSessions_Under2s is the master spec exit
// criterion for T1.7 (Phase 2): one BroadcastStreamClose over 10k tunnels
// must complete in under 2 seconds wall-clock. Tunnels are equipped with a
// background drainer (registerTestTunnelWithBufferedDraining) so the per-
// tunnel send arm always succeeds — exercising the happy path, not the
// timeout-saturated path covered by TestBroadcastStreamClose_TotalDeadline.
//
// Gated behind the `loadtest` build tag so default `go test` doesn't pay the
// 10k-handshake cost on every run. CI runs this nightly.
func TestBroadcastStreamClose_10kSessions_Under2s(t *testing.T) {
	const N = 10000
	h := newTestHandler(t)
	for i := 0; i < N; i++ {
		h.registerTestTunnelWithBufferedDraining(t, 64)
	}

	start := time.Now()
	enq := h.BroadcastStreamClose("load_test")
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("10k drain took %v, master spec SLA <2s", elapsed)
	}
	if enq < N*9/10 {
		t.Errorf("enqueued = %d, want ~%d (>=90%% of %d)", enq, N*9/10, N)
	}
	t.Logf("10k drain: enqueued=%d, elapsed=%v", enq, elapsed)
}

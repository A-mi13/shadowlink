//go:build linux

package server

import (
	"sync"
	"testing"
	"time"
)

// TestBroadcastStreamClose_RaceWithSessionExpire stresses the read path of
// h.tunnels / h.sessions against concurrent expiry+broadcast under -race.
// CGO is required to enable the race detector; CI is the enforcement
// boundary. Windows dev hosts without gcc fall back to plain `go test` and
// the build tag keeps this file out of that path.
//
// T1.7 (Phase 2, 2026-04-26).
func TestBroadcastStreamClose_RaceWithSessionExpire(t *testing.T) {
	const N = 1000
	h := newTestHandler(t)
	for i := 0; i < N; i++ {
		h.registerTestTunnel(t)
	}

	// Iteration-counted termination keeps the test deterministic: ~210ms
	// wall-clock with 30 iters of 7ms broadcast, no wall-clock sleep
	// heuristic. Cleanup runs at 5ms cadence to stay slightly out of phase
	// with the broadcast cadence so race-windows interleave both ways.
	const iterations = 30

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			// Cleanup is the production session-expiry loop; race target
			// is the read of h.tunnels in BroadcastStreamClose vs. the
			// concurrent map write inside the session manager.
			h.sessions.Cleanup()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			h.BroadcastStreamClose("race_test")
			time.Sleep(7 * time.Millisecond)
		}
	}()

	wg.Wait()
}

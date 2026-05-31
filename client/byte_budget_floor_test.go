package client

import (
	"testing"
	"time"
)

// TestByteBudgetRotationAllowed_RateFloor is the regression test for the
// high-throughput rotation storm (Bug #4, 2026-05-29).
//
// Field evidence: downloading at ~50 MB/s burned a slot's 8 MiB byte budget in
// ~0.16s, so every slot in the pool tried to rotate several times per second.
// Replacement slots could not finish their handshake (~0.5-1s) before the next
// rotation fired, producing 25× "drain skipped — no free cell" and collapsing
// pool downlink from 38 MB/s to 95 KB/s mid-download.
//
// Root cause: byte budget is a proxy for "how long a TCP has lived" — the
// anti-TSPU goal (rotate before the censor's per-flow counter trips). At low
// throughput 8 MiB ≈ minutes; at high throughput it's a fraction of a second,
// which gives no anti-TSPU benefit (the TCP is brand new in wall-clock terms)
// while wrecking throughput. The fix re-anchors the floor to TIME: a slot may
// not rotate on byte budget until it has lived at least minInterval, regardless
// of how fast the budget was consumed. The age budget (2 min) remains the upper
// bound, so TCPs still rotate well within any TSPU window.
func TestByteBudgetRotationAllowed_RateFloor(t *testing.T) {
	minInterval := 10 * time.Second

	tests := []struct {
		name    string
		slotAge time.Duration
		want    bool
	}{
		{"fresh slot, budget burned in 160ms — must NOT rotate", 160 * time.Millisecond, false},
		{"1s old — still under floor, must NOT rotate", 1 * time.Second, false},
		{"just under floor", 9*time.Second + 900*time.Millisecond, false},
		{"exactly at floor — may rotate", 10 * time.Second, true},
		{"well past floor — may rotate", 45 * time.Second, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := byteBudgetRotationAllowed(tc.slotAge, minInterval)
			if got != tc.want {
				t.Errorf("byteBudgetRotationAllowed(age=%v, floor=%v) = %v, want %v",
					tc.slotAge, minInterval, got, tc.want)
			}
		})
	}
}

// TestByteBudgetRotationAllowed_DisabledFloor verifies that a zero/negative
// minInterval disables the floor entirely (every call allowed) — preserves the
// pre-fix behaviour for configs that opt out.
func TestByteBudgetRotationAllowed_DisabledFloor(t *testing.T) {
	if !byteBudgetRotationAllowed(0, 0) {
		t.Error("floor=0 must allow rotation (feature disabled)")
	}
	if !byteBudgetRotationAllowed(1*time.Millisecond, 0) {
		t.Error("floor=0 must allow rotation regardless of age")
	}
}

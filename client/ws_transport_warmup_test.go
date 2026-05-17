package client

import (
	"math"
	mrand "math/rand"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// TestWarmupRequests_CountInRange verifies chooseWarmupCount always lands
// inside [1, 4] when the path pool has at least 4 entries.
func TestWarmupRequests_CountInRange(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	maxPaths := len(browser.DefaultCoverPaths())
	if maxPaths < 4 {
		t.Fatalf("defaultCoverPaths must hold ≥4 entries; have %d", maxPaths)
	}
	for i := 0; i < 5000; i++ {
		c := chooseWarmupCount(rng, maxPaths)
		if c < 1 || c > 4 {
			t.Fatalf("count %d outside [1, 4]", c)
		}
	}
}

// TestWarmupRequests_CountClampsToMax exercises the small-pool branch.
func TestWarmupRequests_CountClampsToMax(t *testing.T) {
	rng := mrand.New(mrand.NewSource(2))
	for max := 0; max <= 4; max++ {
		for i := 0; i < 200; i++ {
			c := chooseWarmupCount(rng, max)
			if max == 0 {
				if c != 0 {
					t.Fatalf("max=0: expected 0, got %d", c)
				}
				continue
			}
			if c < 1 || c > max {
				t.Fatalf("max=%d: count %d outside [1, %d]", max, c, max)
			}
		}
	}
}

// TestWarmupRequests_OrderEntropy proves the shuffle+count combination
// produces enough variety to break "same burst every reconnect" detection.
// Over 1000 trials we want both ≥100 distinct (count, path-order) tuples
// and an entropy ≥4.0 bits over the observed distribution.
func TestWarmupRequests_OrderEntropy(t *testing.T) {
	const trials = 1000
	pool := browser.DefaultCoverPaths()
	if len(pool) == 0 {
		t.Fatal("empty path pool")
	}

	tally := make(map[string]int, trials)
	rng := mrand.New(mrand.NewSource(99))
	for i := 0; i < trials; i++ {
		// Mirror the WarmupRequests body: shuffle a fresh copy, choose
		// count, then concatenate the prefix into a key. This is the
		// exact tuple a passive observer would log.
		paths := append([]string(nil), pool...)
		rng.Shuffle(len(paths), func(a, b int) { paths[a], paths[b] = paths[b], paths[a] })
		count := chooseWarmupCount(rng, len(paths))

		var sb strings.Builder
		for j := 0; j < count; j++ {
			sb.WriteString(paths[j])
			sb.WriteByte('|')
		}
		tally[sb.String()]++
	}

	if len(tally) < 100 {
		t.Errorf("only %d distinct burst signatures over %d trials; want ≥100", len(tally), trials)
	}

	var entropy float64
	for _, c := range tally {
		p := float64(c) / float64(trials)
		entropy -= p * math.Log2(p)
	}
	if entropy < 4.0 {
		t.Errorf("burst entropy %.3f bits < 4.0", entropy)
	}
}

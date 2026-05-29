package client

import "testing"

func TestEffectiveStickyMaxSlots(t *testing.T) {
	cases := []struct {
		name       string
		poolSize   int
		cfgMax     int
		wantResult int
	}{
		{"auto half of 6", 6, 0, 3},
		{"auto half of 8", 8, 0, 4},
		{"auto poolSize 2 → min 1", 2, 0, 1},
		{"auto odd 5 → 2", 5, 0, 2},
		{"explicit 1", 6, 1, 1},
		{"explicit cap above half", 6, 5, 5},
		{"negative → disabled (0)", 6, -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &WSPoolTransport{poolSize: tc.poolSize, stickyMaxSlots: tc.cfgMax}
			if got := p.effectiveStickyMaxSlots(); got != tc.wantResult {
				t.Errorf("poolSize=%d cfgMax=%d: got %d, want %d",
					tc.poolSize, tc.cfgMax, got, tc.wantResult)
			}
		})
	}
}

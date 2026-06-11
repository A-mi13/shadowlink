package client

import (
	"bytes"
	"testing"
)

// TestStats_AgeCutByProfile verifies that IncAgeCut routes increments to the
// correct per-profile counter (chrome / firefox / other).
// Deltas are used so the test is immune to non-zero global state from other
// tests running in the same process.
func TestStats_AgeCutByProfile(t *testing.T) {
	beforeChrome := Stats.AgeCutChrome.Load()
	beforeFirefox := Stats.AgeCutFirefox.Load()

	Stats.IncAgeCut("firefox")
	Stats.IncAgeCut("chrome")
	Stats.IncAgeCut("chrome")

	if got := Stats.AgeCutChrome.Load() - beforeChrome; got != 2 {
		t.Errorf("AgeCutChrome delta = %d, want 2", got)
	}
	if got := Stats.AgeCutFirefox.Load() - beforeFirefox; got != 1 {
		t.Errorf("AgeCutFirefox delta = %d, want 1", got)
	}
}

// TestStats_AgeCutUnknownProfileNoPanic verifies that an unrecognised profile
// name does not panic and falls into the AgeCutOther bucket.
func TestStats_AgeCutUnknownProfileNoPanic(t *testing.T) {
	beforeOther := Stats.AgeCutOther.Load()

	Stats.IncAgeCut("netscape") // unknown profile → other

	if got := Stats.AgeCutOther.Load() - beforeOther; got < 1 {
		t.Errorf("unknown profile must increment AgeCutOther by ≥1, delta = %d", got)
	}
}

// TestStats_SetActiveProfile verifies that SetActiveProfile sets exactly one
// gauge to 1 and clears the others on each call.
func TestStats_SetActiveProfile(t *testing.T) {
	Stats.SetActiveProfile("firefox")
	if Stats.ActiveProfileFirefox.Load() != 1 || Stats.ActiveProfileChrome.Load() != 0 {
		t.Error("firefox active gauge must be 1, chrome 0")
	}
	Stats.SetActiveProfile("chrome")
	if Stats.ActiveProfileChrome.Load() != 1 || Stats.ActiveProfileFirefox.Load() != 0 {
		t.Error("chrome active gauge must be 1, firefox 0")
	}
}

// TestStats_AgeCutMetricsExposed asserts that all three per-profile age-cut
// counters appear in the Prometheus text exposition produced by WritePromMetrics.
func TestStats_AgeCutMetricsExposed(t *testing.T) {
	var buf bytes.Buffer
	WritePromMetrics(&buf)

	for _, series := range []string{
		"shadowlink_age_cut_by_profile_total{profile=\"chrome\"}",
		"shadowlink_age_cut_by_profile_total{profile=\"firefox\"}",
		"shadowlink_age_cut_by_profile_total{profile=\"other\"}",
	} {
		if !bytes.Contains(buf.Bytes(), []byte(series)) {
			t.Errorf("WritePromMetrics missing series %q", series)
		}
	}
}

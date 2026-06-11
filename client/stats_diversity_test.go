package client

import "testing"

func TestSetActiveProfile_Chrome131(t *testing.T) {
	Stats.SetActiveProfile("chrome131")
	if Stats.ActiveProfileChrome131.Load() != 1 {
		t.Error("chrome131 gauge not set")
	}
	if Stats.ActiveProfileChrome133.Load() != 0 {
		t.Error("chrome133 gauge should be 0")
	}
	// Aggregate generic chrome gauge тоже = 1 для любого chrome-family.
	if Stats.ActiveProfileChrome.Load() != 1 {
		t.Error("aggregate chrome gauge should be 1 for chrome131")
	}
	Stats.SetActiveProfile("chrome133")
	if Stats.ActiveProfileChrome131.Load() != 0 {
		t.Error("chrome131 gauge not cleared on switch")
	}
	if Stats.ActiveProfileChrome133.Load() != 1 {
		t.Error("chrome133 gauge not set on switch")
	}
}

func TestSetActiveProfile_LegacyChromeAlias(t *testing.T) {
	Stats.SetActiveProfile("chrome") // legacy → chrome133
	if Stats.ActiveProfileChrome133.Load() != 1 {
		t.Error("legacy chrome alias should set chrome133 gauge")
	}
	if Stats.ActiveProfileChrome.Load() != 1 {
		t.Error("legacy chrome alias should set aggregate gauge")
	}
}

func TestIncAgeCut_DiversityProfiles(t *testing.T) {
	before := Stats.AgeCutChrome.Load()
	Stats.IncAgeCut("chrome120")
	Stats.IncAgeCut("chrome131")
	Stats.IncAgeCut("chrome133")
	if got := Stats.AgeCutChrome.Load(); got != before+3 {
		t.Errorf("AgeCutChrome = %d, want %d (diversity profiles must map to chrome cohort)", got, before+3)
	}
}

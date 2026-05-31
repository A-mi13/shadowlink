package core

import "testing"

func TestFlowCtlMarker_MigrateBit_RoundTrip(t *testing.T) {
	p := BuildFlowCtlMarkerV2(1<<20, true)
	win, migrate, ok := ParseFlowCtlMarkerV2(p)
	if !ok {
		t.Fatal("V2 marker did not parse")
	}
	if win != 1<<20 {
		t.Errorf("window = %d, want %d", win, 1<<20)
	}
	if !migrate {
		t.Error("migrate bit lost")
	}
}

func TestFlowCtlMarker_MigrateBitOff(t *testing.T) {
	p := BuildFlowCtlMarkerV2(4096, false)
	_, migrate, ok := ParseFlowCtlMarkerV2(p)
	if !ok || migrate {
		t.Fatalf("ok=%v migrate=%v, want ok=true migrate=false", ok, migrate)
	}
}

func TestFlowCtlMarker_LegacyParsesAsNoMigrate(t *testing.T) {
	old := BuildFlowCtlMarker(2048)
	win, migrate, ok := ParseFlowCtlMarkerV2(old)
	if !ok || win != 2048 || migrate {
		t.Fatalf("legacy compat broke: ok=%v win=%d migrate=%v", ok, win, migrate)
	}
}

func TestFlowCtlMarker_OldParserIgnoresExtraByte(t *testing.T) {
	p := BuildFlowCtlMarkerV2(777, true)
	win, ok := ParseFlowCtlMarker(p)
	if !ok || win != 777 {
		t.Fatalf("old parser on V2 marker: ok=%v win=%d", ok, win)
	}
}

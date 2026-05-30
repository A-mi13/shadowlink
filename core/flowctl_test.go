package core

import "testing"

func TestFlowCtlMarker_RoundTrip(t *testing.T) {
	p := BuildFlowCtlMarker(1 << 20) // 1 MiB
	win, ok := ParseFlowCtlMarker(p)
	if !ok {
		t.Fatal("ParseFlowCtlMarker: not recognized")
	}
	if win != 1<<20 {
		t.Fatalf("window = %d, want %d", win, 1<<20)
	}
}

func TestParseFlowCtlMarker_Rejects(t *testing.T) {
	if _, ok := ParseFlowCtlMarker(nil); ok {
		t.Fatal("nil payload should not parse as marker")
	}
	if _, ok := ParseFlowCtlMarker([]byte("FLOWCT")); ok {
		t.Fatal("short payload should not parse")
	}
	if _, ok := ParseFlowCtlMarker([]byte("XXXXXXX\x00\x00\x00\x01")); ok {
		t.Fatal("wrong magic should not parse")
	}
}

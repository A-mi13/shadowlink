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

func TestNegotiationMatrix(t *testing.T) {
	// клиент шлёт маркер 1MiB, сервер max 1MiB → min = 1MiB
	clientMarker := BuildFlowCtlMarker(1 << 20)
	cw, ok := ParseFlowCtlMarker(clientMarker)
	if !ok {
		t.Fatal("server must parse client marker")
	}
	serverMax := uint32(1 << 20)
	eff := cw
	if eff > serverMax {
		eff = serverMax
	}
	ack := BuildFlowCtlMarker(eff)
	got, ok := ParseFlowCtlMarker(ack)
	if !ok || got != 1<<20 {
		t.Fatalf("client ack parse = (%d,%v), want 1MiB,true", got, ok)
	}

	// клиент 4MiB, сервер max 1MiB → eff = 1MiB (min)
	cw2, _ := ParseFlowCtlMarker(BuildFlowCtlMarker(4 << 20))
	eff2 := cw2
	if eff2 > serverMax {
		eff2 = serverMax
	}
	if eff2 != 1<<20 {
		t.Fatalf("min negotiation = %d, want 1MiB", eff2)
	}

	// старый клиент: пустой keepalive payload → сервер не видит маркер → off
	if _, ok := ParseFlowCtlMarker(nil); ok {
		t.Fatal("empty payload must not look like marker (old client → off)")
	}
	// старый сервер: ack без маркера (nil/обычный keepalive ack) → клиент видит off
	if _, ok := ParseFlowCtlMarker([]byte{}); ok {
		t.Fatal("empty ack must not parse (old server → off)")
	}
}

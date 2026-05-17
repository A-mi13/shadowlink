package bypassroute

import (
	"net/netip"
	"testing"
)

func TestEmbedded_KnownRUIPsMatch(t *testing.T) {
	tr, err := Load(Source{Embedded: true})
	if err != nil {
		t.Fatal(err)
	}
	known := []string{
		"213.180.193.1",  // Yandex
		"87.250.250.242", // Yandex
		"217.69.139.202", // Mail.ru
		"95.142.206.0",   // VK
		"77.88.8.8",      // Yandex DNS
	}
	for _, ip := range known {
		if !tr.Match(netip.MustParseAddr(ip)) {
			t.Errorf("expected RU IP %s to match embedded snapshot", ip)
		}
	}
}

func TestEmbedded_NonRUIPsMiss(t *testing.T) {
	tr, err := Load(Source{Embedded: true})
	if err != nil {
		t.Fatal(err)
	}
	nonRU := []string{
		"1.1.1.1",        // Cloudflare
		"8.8.8.8",        // Google DNS
		"13.107.42.14",   // Microsoft
		"104.21.55.42",   // CF (datacanvases.com type)
		"104.222.177.67", // pl1 server
	}
	for _, ip := range nonRU {
		if tr.Match(netip.MustParseAddr(ip)) {
			t.Errorf("non-RU IP %s should NOT match", ip)
		}
	}
}

func TestEmbedded_SizeReasonable(t *testing.T) {
	if EmbeddedSize() < 5000 || EmbeddedSize() > 20000 {
		t.Errorf("EmbeddedSize() = %d, want range [5000, 20000]", EmbeddedSize())
	}
}

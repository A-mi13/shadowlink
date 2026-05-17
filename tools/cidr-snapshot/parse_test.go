package main

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParse_BasicRU(t *testing.T) {
	in := strings.NewReader(`# header
ripencc|RU|ipv4|213.180.193.0|256|20020101|allocated
ripencc|RU|ipv4|87.250.224.0|8192|20030101|allocated
ripencc|US|ipv4|8.8.8.0|256|20100101|allocated
ripencc|RU|ipv6|2a02::|32|20100101|allocated
`)
	out, err := ParseRIPELines(in, "RU")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d prefixes, want 2: %v", len(out), out)
	}
	if out[0].String() != "213.180.193.0/24" {
		t.Errorf("[0] = %s", out[0])
	}
	if out[1].String() != "87.250.224.0/19" {
		t.Errorf("[1] = %s", out[1])
	}
}

func TestRangeToCIDRs_NonPowerOfTwo(t *testing.T) {
	got := rangeToCIDRs(netip.MustParseAddr("1.2.3.0"), 384)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %v", len(got), got)
	}
	if got[0].String() != "1.2.3.0/24" || got[1].String() != "1.2.4.0/25" {
		t.Errorf("got %v", got)
	}
}

package cidrblob

import (
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("213.180.193.0/24"),
		netip.MustParsePrefix("87.250.250.0/19"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	blob, err := Encode(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(blob) != len(in)*5 {
		t.Fatalf("blob size = %d, want %d", len(blob), len(in)*5)
	}
	out, err := Decode(blob)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("count mismatch %d vs %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Fatalf("idx %d: %s != %s", i, out[i], in[i])
		}
	}
}

func TestDecode_RejectsOddLength(t *testing.T) {
	if _, err := Decode([]byte{1, 2, 3, 4}); err == nil {
		t.Fatal("expected error on length 4")
	}
}

func TestEncode_RejectsIPv6(t *testing.T) {
	v6 := netip.MustParsePrefix("2001:db8::/32")
	if _, err := Encode([]netip.Prefix{v6}); err == nil {
		t.Fatal("expected error for IPv6")
	}
}

package bypassroute

import (
	"net/netip"
	"testing"
)

func TestTrie_Match_Basic(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("213.180.193.0/24"))
	cases := []struct {
		ip   string
		want bool
	}{
		{"213.180.193.0", true},
		{"213.180.193.255", true},
		{"213.180.194.0", false},
		{"213.180.192.255", false},
		{"1.1.1.1", false},
	}
	for _, c := range cases {
		got := tr.Match(netip.MustParseAddr(c.ip))
		if got != c.want {
			t.Errorf("Match(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestTrie_LongestPrefixMatch(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("0.0.0.0/0"))
	if !tr.Match(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("0/0 should match anything")
	}
	tr.Insert(netip.MustParsePrefix("10.0.0.0/8"))
	if !tr.Match(netip.MustParseAddr("10.5.5.5")) {
		t.Fatal("10/8 should match 10.5.5.5")
	}
}

func TestTrie_Slash32(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("8.8.8.8/32"))
	if !tr.Match(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("/32 exact match should hit")
	}
	if tr.Match(netip.MustParseAddr("8.8.8.9")) {
		t.Fatal("/32 must not match neighbor")
	}
}

func TestTrie_Size(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("1.0.0.0/8"))
	tr.Insert(netip.MustParsePrefix("2.0.0.0/8"))
	tr.Insert(netip.MustParsePrefix("1.0.0.0/8")) // duplicate, idempotent
	if tr.Size() != 2 {
		t.Errorf("Size = %d, want 2", tr.Size())
	}
}

func TestTrie_IPv6Skipped(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("2001:db8::/32"))
	if tr.Match(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("v6 prefix must not affect v4 match")
	}
}

func BenchmarkTrie_Match(b *testing.B) {
	tr := New()
	for i := range 10000 {
		ip := netip.AddrFrom4([4]byte{byte(i >> 8), byte(i), 0, 0})
		tr.Insert(netip.PrefixFrom(ip, 24))
	}
	target := netip.MustParseAddr("1.2.3.4")
	b.ResetTimer()
	for b.Loop() {
		_ = tr.Match(target)
	}
}

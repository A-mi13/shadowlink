package bypassroute

import (
	"net/netip"
	"testing"
)

func TestReservedRanges_AllParse(t *testing.T) {
	for _, r := range reservedRanges {
		if _, err := netip.ParsePrefix(r.cidr); err != nil {
			t.Errorf("reservedRanges entry %q failed to parse: %v", r.cidr, err)
		}
		if r.why == "" {
			t.Errorf("reservedRanges entry %q has empty why-comment", r.cidr)
		}
	}
}

func TestIsReservedIPv4(t *testing.T) {
	cases := []struct {
		ip       string
		reserved bool
		note     string
	}{
		{"169.254.169.254", true, "AWS/GCP/Azure metadata — main motivating case"},
		{"169.254.0.1", true, "link-local edge"},
		{"169.254.255.255", true, "link-local edge"},
		{"127.0.0.1", true, "loopback"},
		{"10.0.0.1", true, "RFC1918 /8"},
		{"192.168.1.1", true, "RFC1918 /16"},
		{"172.16.0.1", true, "RFC1918 /12 lower edge"},
		{"172.31.255.255", true, "RFC1918 /12 upper edge"},
		{"172.32.0.1", false, "just outside RFC1918 /12"},
		{"224.0.0.1", true, "multicast"},
		{"239.255.255.250", true, "multicast (SSDP)"},
		{"255.255.255.255", true, "limited broadcast"},
		{"0.0.0.1", true, "RFC1122 this-network"},

		{"8.8.8.8", false, "Google DNS — public"},
		{"1.1.1.1", false, "Cloudflare DNS — public"},
		{"104.222.177.67", false, "pl1 origin"},
		{"213.180.193.5", false, "Yandex"},
	}
	for _, c := range cases {
		addr := netip.MustParseAddr(c.ip)
		got := isReservedIPv4(addr)
		if got != c.reserved {
			t.Errorf("isReservedIPv4(%q) = %v, want %v (%s)", c.ip, got, c.reserved, c.note)
		}
	}
}

func TestIsReservedIPv4_RejectsIPv6(t *testing.T) {
	v6 := netip.MustParseAddr("fe80::1")
	if isReservedIPv4(v6) {
		t.Fatal("isReservedIPv4 must return false for raw IPv6 (caller is responsible for Unmap)")
	}
}

//go:build windows

package leakguard

import "testing"

// Task 7 — locale-independent DNS backup parser (PowerShell CSV).

func TestParsePSGetDns_LocaleIndependent(t *testing.T) {
	// CSV-вывод одинаков на RU и EN Windows (InterfaceIndex числовой)
	csv := `"InterfaceIndex","ServerAddresses"
"12","{8.8.8.8, 1.1.1.1}"
"5","{}"`
	entries := parsePSGetDns(csv)
	if len(entries) != 2 {
		t.Fatalf("len=%d", len(entries))
	}
	if entries[0].InterfaceName != "12" {
		t.Fatalf("index parse: %q", entries[0].InterfaceName)
	}
	if len(entries[0].Servers) != 2 {
		t.Fatalf("servers parse: %v", entries[0].Servers)
	}
	if entries[0].Servers[0] != "8.8.8.8" || entries[0].Servers[1] != "1.1.1.1" {
		t.Fatalf("server values: %v", entries[0].Servers)
	}
	if len(entries[1].Servers) != 0 {
		t.Fatalf("DHCP iface must have empty servers (L2): %v", entries[1].Servers)
	}
}

func TestParsePSGetDns_IgnoresIPv6AndBlanks(t *testing.T) {
	csv := `"InterfaceIndex","ServerAddresses"

"3","{1.1.1.1}"
"garbage","{2.2.2.2}"`
	entries := parsePSGetDns(csv)
	// "garbage" index is non-numeric → skipped; blank line skipped.
	if len(entries) != 1 {
		t.Fatalf("len=%d want 1: %v", len(entries), entries)
	}
	if entries[0].InterfaceName != "3" {
		t.Fatalf("index=%q", entries[0].InterfaceName)
	}
}

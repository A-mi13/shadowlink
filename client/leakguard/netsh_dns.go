//go:build windows

package leakguard

import (
	"strconv"
	"strings"
)

// parsePSGetDns parses the CSV produced by:
//
//	Get-DnsClientServerAddress -AddressFamily IPv4 |
//	  Select-Object InterfaceIndex,ServerAddresses |
//	  ConvertTo-Csv -NoTypeInformation
//
// The output is locale-independent: InterfaceIndex is numeric, so it works on
// RU-localized Windows where `netsh ... show dns` headers are translated (L1).
// ServerAddresses is a PowerShell array rendered as "{a, b}" (empty "{}" means
// the interface uses DHCP — we keep the entry with empty Servers, L2).
//
// Returned DNSEntry.InterfaceName holds the numeric index (as string) so that
// Set/Reset can target -InterfaceIndex N locale-independently.
func parsePSGetDns(csv string) []DNSEntry {
	var entries []DNSEntry
	lines := strings.Split(csv, "\n")
	for i, raw := range lines {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		// Skip header row.
		if i == 0 && strings.Contains(line, "InterfaceIndex") {
			continue
		}
		idx, servers, ok := parsePSGetDnsRow(line)
		if !ok {
			continue
		}
		entries = append(entries, DNSEntry{InterfaceName: idx, Servers: servers})
	}
	return entries
}

// parsePSGetDnsRow parses a single CSV data row: "12","{8.8.8.8, 1.1.1.1}".
// Returns the numeric interface index, the server list, and ok=false for rows
// whose first field is not a valid numeric index.
func parsePSGetDnsRow(line string) (idx string, servers []string, ok bool) {
	// CSV fields are double-quoted; split on `","` after stripping outer quotes.
	trimmed := strings.TrimPrefix(line, `"`)
	trimmed = strings.TrimSuffix(trimmed, `"`)
	parts := strings.SplitN(trimmed, `","`, 2)
	if len(parts) != 2 {
		return "", nil, false
	}
	idx = strings.TrimSpace(parts[0])
	if _, err := strconv.Atoi(idx); err != nil {
		return "", nil, false
	}
	servers = parsePSServerSet(parts[1])
	return idx, servers, true
}

// parsePSServerSet extracts IPv4 addresses from a PowerShell array literal like
// "{8.8.8.8, 1.1.1.1}" or "{}". Empty set → nil (DHCP-managed interface).
func parsePSServerSet(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, tok := range strings.Split(s, ",") {
		ip := strings.TrimSpace(tok)
		if ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

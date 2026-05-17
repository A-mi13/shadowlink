package bypassroute

import (
	"net/netip"
	"testing"
)

// TestSnapshotCoverage_KnownRussianIPs is a diagnostic test that verifies
// whether the embedded RIPE RU CIDR snapshot covers IPs commonly seen in
// real-world bypass logs (MTS, Yandex, Telegram MTProto).
//
// This is NOT a hard-failing assertion test — it prints per-IP coverage so
// gaps in the snapshot can be identified and remediated by either:
//   - regenerating the snapshot via tools/cidr-snapshot/
//   - adding admin override entries via /api/admin/shadowlink/bypass-cidrs.
func TestSnapshotCoverage_KnownRussianIPs(t *testing.T) {
	prefixes, err := loadEmbedded()
	if err != nil {
		t.Fatalf("loadEmbedded: %v", err)
	}

	tr := New()
	for _, p := range prefixes {
		tr.Insert(p)
	}

	t.Logf("Total prefixes in snapshot: %d (size=%d unique in trie)", len(prefixes), tr.Size())

	type tc struct {
		ip   string
		desc string
	}
	cases := []tc{
		{"91.105.192.100", "PJSC MTS, AS25513 — RU"},
		{"149.154.167.51", "Telegram MTProto — RU/EU mix"},
		{"5.255.255.5", "Yandex — RU"},
		{"77.88.8.8", "Yandex DNS — RU"},
		{"213.180.193.1", "Yandex — RU"},
	}

	matched := 0
	missed := 0
	for _, c := range cases {
		ip, err := netip.ParseAddr(c.ip)
		if err != nil {
			t.Errorf("ParseAddr(%q): %v", c.ip, err)
			continue
		}
		hit := tr.Match(ip)
		if hit {
			// Find the most-specific covering prefix for diagnostic clarity.
			var coveringPrefix string
			for _, p := range prefixes {
				if p.Contains(ip) {
					if coveringPrefix == "" || p.Bits() > netip.MustParsePrefix(coveringPrefix).Bits() {
						coveringPrefix = p.String()
					}
				}
			}
			t.Logf("MATCH   %-16s (%s) → covered by %s", c.ip, c.desc, coveringPrefix)
			matched++
		} else {
			t.Logf("MISS    %-16s (%s) → NOT in snapshot", c.ip, c.desc)
			missed++
		}
	}

	t.Logf("Summary: %d matched, %d missed of %d test IPs", matched, missed, len(cases))
}

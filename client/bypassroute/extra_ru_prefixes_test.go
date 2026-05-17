package bypassroute

import (
	"net/netip"
	"testing"
)

// TestExtraRussianPrefixes_AllParse ensures every hardcoded entry parses.
// Без этого опечатка молча выпала бы из bypass trie.
func TestExtraRussianPrefixes_AllParse(t *testing.T) {
	for _, s := range extraRussianPrefixes {
		if _, err := netip.ParsePrefix(s); err != nil {
			t.Errorf("extraRussianPrefixes contains invalid prefix %q: %v", s, err)
		}
	}
	got := extraRussianNetipPrefixes()
	if len(got) != len(extraRussianPrefixes) {
		t.Errorf("extraRussianNetipPrefixes() returned %d, want %d (silent parse failure?)",
			len(got), len(extraRussianPrefixes))
	}
}

// TestLoad_BaselineSnapshotCoversYandex — Yandex IP'ы должны matched
// из RIPE-RU baseline (без extras). Регрессионный pin: если RIPE
// snapshot потеряет Yandex blocks, тест упадёт.
//
// Telegram + MTS из extras retired 2026-05-05 evening — bypass для них
// ломает доступ (TSPU блокирует Telegram на физическом интерфейсе).
// См. extra_ru_prefixes.go для контекста.
func TestLoad_BaselineSnapshotCoversYandex(t *testing.T) {
	resolved, err := Load(Source{Embedded: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := []string{
		"5.255.255.5",   // Yandex (RIPE-RU baseline)
		"77.88.8.8",     // Yandex DNS (RIPE-RU baseline)
		"213.180.193.1", // Yandex (RIPE-RU baseline)
	}
	for _, ipStr := range cases {
		ip := netip.MustParseAddr(ipStr)
		if !resolved.Match(ip) {
			t.Errorf("Match(%s) = false, want true (RIPE baseline)", ipStr)
		}
	}
}

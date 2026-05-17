package bypassroute

import (
	"fmt"
	"net/netip"
)

// AdminOverride represents admin-managed deviations from embedded baseline.
//
// SigVersion records the HMAC scope under which this override was last
// verified (loaded from cache or fetched from server). Used by FetchAdminOverride
// to detect downgrade attacks: once a client has accepted a v2 signature,
// the next response from the same server must also carry v2 — otherwise a
// MITM may have stripped the cli_v=2 query / sig version header. Values:
// "" (uninitialized — no prior session), "1" (legacy v1 scope = body only),
// "2" (P2-1 scope = etag+body). Final-audit-2026-05-03 P2-1 + Opus review I-2.
type AdminOverride struct {
	Etag       string
	Adds       []netip.Prefix
	Excludes   []netip.Prefix
	SigVersion string
}

// Source describes which inputs to merge into the resulting trie.
type Source struct {
	Embedded bool
	Override *AdminOverride
}

// Resolved is an include/exclude trie pair: include minus exclude semantics.
type Resolved struct {
	include *Trie
	exclude *Trie
}

// Match returns true iff include matches AND exclude does not match.
func (r *Resolved) Match(ip netip.Addr) bool {
	if r.include == nil {
		return false
	}
	if !r.include.Match(ip) {
		return false
	}
	if r.exclude != nil && r.exclude.Match(ip) {
		return false
	}
	return true
}

// Size returns include size.
func (r *Resolved) Size() int {
	if r.include == nil {
		return 0
	}
	return r.include.Size()
}

// Excludes returns count of exclusion prefixes.
func (r *Resolved) Excludes() int {
	if r.exclude == nil {
		return 0
	}
	return r.exclude.Size()
}

// Load builds a Resolved trie pair from sources.
//
// Когда `src.Embedded` истинно, в trie сначала кладутся RIPE-NCC RU
// prefix'ы (~11k entries из embedded blob), затем поверх — manually
// curated `extraRussianPrefixes` для дыр RIPE delegated-stats (Telegram
// MTProto, MTS user pools и т.п. — см. соседний файл `extra_ru_prefixes.go`).
// Field-test 2026-05-05 показал что без этого Telegram целиком уходит
// через VPN.
func Load(src Source) (*Resolved, error) {
	include := New()
	exclude := New()
	if src.Embedded {
		prefixes, err := loadEmbedded()
		if err != nil {
			return nil, fmt.Errorf("load embedded: %w", err)
		}
		for _, p := range prefixes {
			include.Insert(p)
		}
		for _, p := range extraRussianNetipPrefixes() {
			include.Insert(p)
		}
	}
	if src.Override != nil {
		for _, p := range src.Override.Adds {
			include.Insert(p)
		}
		for _, p := range src.Override.Excludes {
			exclude.Insert(p)
		}
	}
	return &Resolved{include: include, exclude: exclude}, nil
}

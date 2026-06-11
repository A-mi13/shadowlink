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
	// prefixes records every IPv4 include prefix inserted at Load time, in
	// insertion order. Used by SnapshotPrefixes to export the RU CIDR list for
	// leakguard split-tunnel allow-rules WITHOUT walking the trie. Excludes are
	// applied at snapshot time (skip prefixes whose network is excluded).
	prefixes []netip.Prefix
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
	var prefixes []netip.Prefix
	insert := func(p netip.Prefix) {
		if !p.Addr().Is4() {
			return
		}
		include.Insert(p)
		prefixes = append(prefixes, p)
	}
	if src.Embedded {
		embedded, err := loadEmbedded()
		if err != nil {
			return nil, fmt.Errorf("load embedded: %w", err)
		}
		for _, p := range embedded {
			insert(p)
		}
		for _, p := range extraRussianNetipPrefixes() {
			insert(p)
		}
	}
	if src.Override != nil {
		for _, p := range src.Override.Adds {
			insert(p)
		}
		for _, p := range src.Override.Excludes {
			exclude.Insert(p)
		}
	}
	return &Resolved{include: include, exclude: exclude, prefixes: prefixes}, nil
}

// SnapshotPrefixes returns the IPv4 include prefixes (RU CIDR baseline + admin
// adds) with excluded prefixes removed, for use by leakguard split-tunnel
// allow-rules. Returns a fresh copy; safe to mutate. nil Resolved → nil.
//
// "Excluded" here means the prefix's network address is matched by the exclude
// trie — a conservative drop that keeps fully-excluded prefixes out of the
// allow-list (firewall fail-secure: when in doubt, do not allow).
func SnapshotPrefixes(r *Resolved) []netip.Prefix {
	if r == nil {
		return nil
	}
	seen := make(map[netip.Prefix]struct{}, len(r.prefixes))
	out := make([]netip.Prefix, 0, len(r.prefixes))
	for _, p := range r.prefixes {
		if r.exclude != nil && r.exclude.Match(p.Addr()) {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

package dnsproxy

import (
	"net/netip"

	"github.com/miekg/dns"
)

// snapshotMatcher reports whether an IP is in the RU CIDR snapshot.
// In production this is resolved.Match (bypassroute.Resolved); in tests a
// synthetic set. The narrow function type keeps arbitrate independent of
// *bypassroute.Resolved (whose fields are unexported and cannot be synthesized
// from this package), which is what makes the arbitration logic testable.
type snapshotMatcher func(netip.Addr) bool

// branch identifies which upstream answer arbitrate selected. Exposed for
// metrics/logging in the proxy layer.
type branch int

const (
	branchYandex             branch = iota // ветка 1: честный RU-сайт (Y и CF согласны) → Yandex (direct, быстро), отдаётся только Y∩C (DNS-L1)
	branchCloudflareCensored               // ветка 2: цензура (Y в snapshot, но Y∩C=∅) → Cloudflare
	branchCloudflareForeign                // ветка 3: иностранный (ни один Y-IP не в snapshot) → Cloudflare
	branchYandexGeo                        // ветка 4 (DNS-M7): geo-restricted RU — CF NOERROR-пуст с зарубежной точки, Yandex даёт честный (не stub) in-snapshot IP → Yandex
)

// String renders the branch for logs/metrics labels.
func (b branch) String() string {
	switch b {
	case branchYandex:
		return "yandex"
	case branchCloudflareCensored:
		return "cloudflare_censored"
	case branchCloudflareForeign:
		return "cloudflare_foreign"
	case branchYandexGeo:
		return "yandex_geo"
	default:
		return "unknown"
	}
}

// arbitrate selects which answer to return by comparing the A records of the
// Yandex (y) and Cloudflare (c) responses against the RU CIDR snapshot.
//
// Let Y be the set of IPv4 addresses in y's Answer A records and C the same for
// c. match reports snapshot membership. The decision:
//
//  1. Some IP of Y is in the snapshot AND (Y∩C)\stubs ≠ ∅ → honest RU site
//     (Yandex and Cloudflare agree) → return (y narrowed to the intersection,
//     branchYandex). Goes direct, fast. DNS-L1 (2026-06-12): the served answer
//     carries ONLY the agreed records — an injector that ADDS a stub alongside
//     the real answer (Y={stub, real}, C={real}) cannot smuggle the stub to
//     the client; known stub IPs are excluded from the intersection too.
//  2. Some IP of Y is in the snapshot BUT Y∩C = ∅ → censorship: Yandex handed
//     back an RKN stub (which itself sits inside the RU snapshot) while
//     Cloudflare returned the real CDN IP → return (c, branchCloudflareCensored).
//  4. DNS-M7 (2026-06-12) subcase of the divergence: C is EMPTY (NOERROR-NODATA
//     from CF's foreign vantage — geo-DNS/ACL, typical for RU gov/bank zones)
//     while Yandex resolves to an in-snapshot IP that is NOT a known stub →
//     trust Yandex → return (y, branchYandexGeo). Under real RKN poisoning CF
//     returns a non-empty foreign IP, so the censorship scenario never lands
//     here; a stub answer with empty C falls through to branch 2 (stub filter).
//  3. No IP of Y is in the snapshot → foreign site → return (c, branchCloudflareForeign).
//
// Only A records (*dns.A) in the Answer section contribute to Y and C; other RR
// types (CNAME, etc.) are ignored, so a CNAME→A chain still counts its trailing
// A records. When branch 1 narrows the answer, non-A RRs (the CNAME chain) are
// preserved so the served message stays internally consistent.
//
// Edge cases: an empty Y (NODATA on A) trivially satisfies "no Yandex IP in the
// snapshot" → branch 3. If Y is in the snapshot but C is empty AND Y carries a
// stub, branch 2 returns the empty c — the proxy layer (T5) owns the fallback
// decision for empty answers; arbitrate does not.
//
// Precondition: y and c are both non-nil and both successful. Upstream-error
// fallback lives in proxy.go (T5), not here.
func arbitrate(y, c *dns.Msg, match snapshotMatcher) (*dns.Msg, branch) {
	ySet := a4Set(y)
	cSet := a4Set(c)

	yInSnapshot := false
	for ip := range ySet {
		if match(ip) {
			yInSnapshot = true
			break
		}
	}

	if !yInSnapshot {
		// Ветка 3: ни один IP Yandex не в RU snapshot → иностранный сайт.
		return c, branchCloudflareForeign
	}

	if keep := intersectMinusStubs(ySet, cSet); len(keep) > 0 {
		// Ветка 1: Y в snapshot И (Y∩C)\stubs ≠ ∅ → честный RU-сайт, Y и CF
		// согласны. DNS-L1: отдаём ТОЛЬКО согласованные A-записи — подсаженная
		// рядом с честным ответом заглушка не доезжает до клиента.
		return filterAnswerA(y, keep, ySet), branchYandex
	}

	if len(cSet) == 0 && !setContainsStub(ySet) {
		// Ветка 4 (DNS-M7): CF пуст (geo-DNS/ACL с зарубежной точки), Yandex
		// дал честный in-snapshot IP без заглушек → доверяем Yandex. Без этой
		// подветки легитимный RU-сайт с geo-ограниченным авторитетным DNS
		// становился недостижим (клиент получал пустой ответ CF), хотя честный
		// ответ был на руках.
		return y, branchYandexGeo
	}

	// Ветка 2: Y в snapshot, но согласованных записей нет → цензура.
	return c, branchCloudflareCensored
}

// intersectMinusStubs returns A∩B minus known stub IPs — the set of records
// both upstreams agree on and that are safe to serve (DNS-L1).
func intersectMinusStubs(a, b map[netip.Addr]struct{}) map[netip.Addr]struct{} {
	// Iterate the smaller set for fewer lookups.
	if len(b) < len(a) {
		a, b = b, a
	}
	out := make(map[netip.Addr]struct{}, len(a))
	for ip := range a {
		if _, ok := b[ip]; ok && !isStubIP(ip) {
			out[ip] = struct{}{}
		}
	}
	return out
}

// filterAnswerA returns msg narrowed to the A records whose IPv4 is in keep.
// Non-A RRs (CNAME chains, etc.) are preserved so the answer stays internally
// consistent. full is the complete A-set of msg: when keep covers it entirely
// nothing would be filtered, and msg is returned as-is (no copy).
func filterAnswerA(msg *dns.Msg, keep, full map[netip.Addr]struct{}) *dns.Msg {
	if len(keep) == len(full) {
		return msg
	}
	out := msg.Copy()
	filtered := out.Answer[:0]
	for _, rr := range out.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			// CNAME и прочие не-A записи сохраняем — A-записи зависят от цепочки.
			filtered = append(filtered, rr)
			continue
		}
		v4 := a.A.To4()
		if v4 == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(v4)
		if !ok {
			continue
		}
		if _, in := keep[addr]; in {
			filtered = append(filtered, rr)
		}
	}
	out.Answer = filtered
	return out
}

// a4Set extracts the set of IPv4 addresses from the A records in msg's Answer
// section. Non-A RRs are ignored. Addresses that fail IPv4 conversion are
// skipped. The returned set uses netip.Addr keys for equality-based comparison.
func a4Set(msg *dns.Msg) map[netip.Addr]struct{} {
	set := make(map[netip.Addr]struct{}, len(msg.Answer))
	for _, rr := range msg.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		v4 := a.A.To4()
		if v4 == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(v4)
		if !ok {
			continue
		}
		set[addr] = struct{}{}
	}
	return set
}

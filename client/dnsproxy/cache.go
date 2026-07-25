// Package dnsproxy implements a local split-DNS forwarder with response
// caching for the ShadowLink client.
package dnsproxy

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// TTL clamp bounds applied on put. Values outside this range are clamped so
// that overly short TTLs do not thrash the upstream and overly long TTLs do
// not pin stale answers.
const (
	minCacheTTL = 30 * time.Second
	maxCacheTTL = time.Hour
)

// unarbitratedCacheTTL — жёсткий короткий срок жизни кэш-записи для ответов,
// принятых БЕЗ двустороннего арбитража: Yandex-only ветки (CF упал; CF ответил
// NXDOMAIN при RU split-horizon). Defense-in-depth DNS-H2(b), 2026-06-12: даже
// НЕИЗВЕСТНАЯ отравленная запись (stub вне knownStubIPs) не залипнет в кэше на
// upstream-TTL (до часа) — максимум 30с до повторной сверки с CF, когда туннель
// восстановится. Фиксированное значение, НЕ клампится от TTL upstream'а —
// именно потому, что upstream здесь не доверен в одиночку.
const unarbitratedCacheTTL = 30 * time.Second

// maxCacheEntries — DNS-M3 (2026-06-12): жёсткий потолок числа записей в кэше.
// Без лимита one-shot уникальные имена (длинная браузерная сессия, DNS-SD,
// DGA-софт) копились бы бесконечно: просроченная запись удалялась только при
// повторном get того же ключа, а maxCacheTTL ограничивает свежесть, не память.
// 4096 записей × ~сотни байт = единицы МБ в худшем случае — достаточно для
// клиентского forwarder'а и безопасно для 8h+ VPN-сессий.
const maxCacheEntries = 4096

// cacheKey identifies a cached record: lowercased FQDN plus qtype.
type cacheKey struct {
	name  string // lowercased FQDN (trailing dot, like dns.Fqdn)
	qtype uint16 // dns.TypeA, etc.
}

// cacheEntry holds a ready answer together with the moment it was stored and
// the moment it expires. The stored msg is never mutated after insertion;
// get returns a TTL-adjusted copy.
type cacheEntry struct {
	msg       *dns.Msg
	storedAt  time.Time
	expiresAt time.Time
}

// dnsCache is a thread-safe TTL cache of DNS responses.
//
// TTL handling:
//   - On put, the cache lifetime is min(Answer RR TTLs) clamped to
//     [minCacheTTL, maxCacheTTL]. Negative answers — NXDOMAIN, or NOERROR
//     with an empty Answer (NODATA) — use the RFC 2308 lifetime instead:
//     min(SOA TTL, SOA MINIMUM) from the authority section, same clamp;
//     without an SOA they fall back to minCacheTTL (DNS-H1, 2026-06-12).
//     The negative cache keeps repeated lookups for non-existent records
//     cheap (no dual-resolve / uTLS DoH handshake per repeat query).
//   - On get, every RR TTL in the returned copy is decremented by the elapsed
//     time since storage (decrement-on-read), mirroring how a resolver ages
//     records. Expired entries are treated as a miss and pruned lazily.
type dnsCache struct {
	mu      sync.Mutex
	entries map[cacheKey]cacheEntry

	// now is injectable for deterministic testing; defaults to time.Now.
	now func() time.Time
}

// newDNSCache returns an empty cache backed by the real clock.
func newDNSCache() *dnsCache {
	return &dnsCache{
		entries: make(map[cacheKey]cacheEntry),
		now:     time.Now,
	}
}

// get returns a copy of the cached answer with TTLs decremented by the time
// elapsed since storage, plus a hit flag. Expired entries are not returned
// (miss) and are pruned lazily.
func (c *dnsCache) get(key cacheKey) (*dns.Msg, bool) {
	now := c.now()

	c.mu.Lock()
	entry, ok := c.entries[key]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	if !now.Before(entry.expiresAt) {
		// Expired — prune lazily.
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}
	c.mu.Unlock()

	// Build a TTL-adjusted copy without mutating the cached msg.
	out := entry.msg.Copy()
	delta := now.Sub(entry.storedAt)
	if delta < 0 {
		delta = 0
	}
	elapsed := uint32(delta / time.Second)
	decrementRRTTLs(out.Answer, elapsed)
	decrementRRTTLs(out.Ns, elapsed)
	decrementRRTTLs(out.Extra, elapsed)

	return out, true
}

// put stores a response. The cache lifetime is the minimum TTL across Answer
// RRs, clamped to [minCacheTTL, maxCacheTTL]. Negative answers (NXDOMAIN /
// NODATA) take the RFC 2308 SOA-derived lifetime — see cacheLifetime.
func (c *dnsCache) put(key cacheKey, msg *dns.Msg) {
	c.putWithLifetime(key, msg, clampTTL(cacheLifetime(msg)))
}

// putWithLifetime stores a response with an explicit, caller-chosen cache
// lifetime, bypassing the upstream-TTL derivation and clamp entirely. Used
// for unarbitrated answers (DNS-H2 b — see unarbitratedCacheTTL): there the
// lifetime is a trust-policy decision, not a property of the upstream answer.
func (c *dnsCache) putWithLifetime(key cacheKey, msg *dns.Msg, lifetime time.Duration) {
	if msg == nil {
		return
	}

	now := c.now()

	// Store a defensive copy and normalize every RR TTL to the effective
	// lifetime. This keeps the answer's visible TTL consistent with how long
	// the entry actually lives, so decrement-on-read counts down from the
	// effective value rather than the raw upstream TTL.
	stored := msg.Copy()
	// DNS-M1 (2026-06-12): вырезаем OPT (EDNS0) из Extra перед сохранением.
	// Ttl-поле OPT — это extended-RCODE/version/DO/Z-флаги (RFC 6891 §6.1.3),
	// НЕ время жизни: TTL-нормализация ниже и decrement-on-read в get портили
	// бы EDNS-заголовок, а клиент без EDNS0 в запросе вообще не должен получать
	// OPT в ответе. Кэшу forwarder'а OPT не нужен. Вырезаем именно TypeOPT
	// (а не зануляем весь Extra): остальные записи Extra (например glue-A) —
	// обычные RR с настоящими TTL, их обработка корректна и пусть остаётся.
	stored.Extra = stripOPT(stored.Extra)
	clampedSecs := uint32(lifetime / time.Second)
	setRRTTLs(stored.Answer, clampedSecs)
	setRRTTLs(stored.Ns, clampedSecs)
	setRRTTLs(stored.Extra, clampedSecs)

	c.mu.Lock()
	// DNS-M3 (2026-06-12): при вставке НОВОГО ключа в полный кэш освобождаем
	// одну ячейку. Перезапись существующего ключа места не требует.
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxCacheEntries {
		c.evictOneLocked(now)
	}
	c.entries[key] = cacheEntry{
		msg:       stored,
		storedAt:  now,
		expiresAt: now.Add(lifetime),
	}
	c.mu.Unlock()
}

// evictOneLocked освобождает одну ячейку кэша (вызывается под c.mu).
// DNS-M3 (2026-06-12): сначала дешёвый проход в поисках просроченной записи —
// её удаление бесплатно по смыслу. Если все живы — удаляем псевдослучайную
// (первую по итерации map; порядок итерации Go-map рандомизирован). LRU здесь
// избыточен: лимит 4096 при типичной рабочей нагрузке клиентского forwarder'а
// почти не достигается, а случайное выселение при переполнении статистически
// чаще выкидывает one-shot мусор, чем горячие имена (их быстро вернёт resolve).
func (c *dnsCache) evictOneLocked(now time.Time) {
	for k, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, k)
			return
		}
	}
	for k := range c.entries {
		delete(c.entries, k)
		return
	}
}

// sweep удаляет все просроченные записи; возвращает число удалённых и размер
// кэша после уборки (одним захватом мьютекса — пара консистентна для лога).
// DNS-M3 (2026-06-12): периодическая уборка (подвешена на тикер runBranchLog,
// ~5 мин) — иначе просроченная запись жила бы до повторного get того же ключа,
// то есть для one-shot имён вечно. Полный проход под мьютексом допустим:
// ≤4096 записей — микросекунды.
func (c *dnsCache) sweep() (removed, remaining int) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, k)
			removed++
		}
	}
	return removed, len(c.entries)
}

// size возвращает текущее число записей в кэше (наблюдаемость DNS-M3).
func (c *dnsCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// stripOPT возвращает rrs без OPT-псевдозаписей (фильтрация in-place — caller
// передаёт собственную копию). DNS-M1 (2026-06-12).
func stripOPT(rrs []dns.RR) []dns.RR {
	filtered := rrs[:0]
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		filtered = append(filtered, rr)
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

// cacheLifetime picks the raw (pre-clamp) lifetime for msg: positive answers
// use the minimum Answer TTL; negative answers — NXDOMAIN, or NOERROR with an
// empty Answer (NODATA) — use the RFC 2308 SOA-derived negative TTL.
func cacheLifetime(msg *dns.Msg) time.Duration {
	if msg.Rcode == dns.RcodeNameError || len(msg.Answer) == 0 {
		return negativeTTL(msg)
	}
	return minAnswerTTL(msg)
}

// negativeTTL derives the negative-cache lifetime per RFC 2308 §5: the SOA
// record in the authority section caps it at min(SOA TTL, SOA MINIMUM).
// Returns 0 when no SOA is present — clampTTL maps that to minCacheTTL.
func negativeTTL(msg *dns.Msg) time.Duration {
	for _, rr := range msg.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		ttl := soa.Hdr.Ttl
		if soa.Minttl < ttl {
			ttl = soa.Minttl
		}
		return time.Duration(ttl) * time.Second
	}
	return 0
}

// minAnswerTTL returns the smallest TTL across the Answer section, or 0 if the
// Answer section is empty, which clampTTL maps to minCacheTTL.
func minAnswerTTL(msg *dns.Msg) time.Duration {
	if len(msg.Answer) == 0 {
		return 0
	}
	lowest := ^uint32(0)
	for _, rr := range msg.Answer {
		if ttl := rr.Header().Ttl; ttl < lowest {
			lowest = ttl
		}
	}
	return time.Duration(lowest) * time.Second
}

// clampTTL restricts d to [minCacheTTL, maxCacheTTL].
func clampTTL(d time.Duration) time.Duration {
	if d < minCacheTTL {
		return minCacheTTL
	}
	if d > maxCacheTTL {
		return maxCacheTTL
	}
	return d
}

// setRRTTLs assigns ttl to each RR header TTL. OPT is skipped — its Ttl field
// packs EDNS flags, not a lifetime (DNS-M1 defense-in-depth, 2026-06-12: put
// уже вырезает OPT, но если он просочится другим путём — не испортим).
func setRRTTLs(rrs []dns.RR, ttl uint32) {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		rr.Header().Ttl = ttl
	}
}

// decrementRRTTLs reduces each RR header TTL by elapsed seconds, flooring at 0.
// OPT is skipped — its Ttl field packs EDNS flags, not a lifetime (DNS-M1).
func decrementRRTTLs(rrs []dns.RR, elapsed uint32) {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		if h.Ttl > elapsed {
			h.Ttl -= elapsed
		} else {
			h.Ttl = 0
		}
	}
}

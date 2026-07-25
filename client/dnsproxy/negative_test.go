package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// soaRR builds an SOA record for the authority section of negative answers
// (RFC 2308 shape). ttl is the record TTL, minTTL the SOA MINIMUM field.
func soaRR(t *testing.T, ttl, minTTL uint32) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf(
		"test. %d IN SOA ns.test. hostmaster.test. 1 7200 3600 1209600 %d", ttl, minTTL))
	if err != nil {
		t.Fatalf("не удалось собрать SOA-запись: %v", err)
	}
	return rr
}

// nxdomainMsg builds an NXDOMAIN response with an SOA record in the authority
// section — the shape a real recursive resolver returns for a nonexistent name.
func nxdomainMsg(t *testing.T, name string, qtype uint16, soaTTL, soaMinTTL uint32) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Response = true
	m.Rcode = dns.RcodeNameError
	m.Ns = append(m.Ns, soaRR(t, soaTTL, soaMinTTL))
	return m
}

// nodataMsg builds a NOERROR response with an empty Answer and an SOA in the
// authority section (NODATA, RFC 2308 type 2 shape).
func nodataMsg(t *testing.T, name string, qtype uint16, soaTTL, soaMinTTL uint32) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	m.Ns = append(m.Ns, soaRR(t, soaTTL, soaMinTTL))
	return m
}

// hasSOA reports whether the authority section carries an SOA record.
func hasSOA(m *dns.Msg) bool {
	for _, rr := range m.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

// DNS-H1 + DNS-I-3: a genuinely nonexistent name (both upstreams answer
// NXDOMAIN) must reach the client as NXDOMAIN, with the SOA authority intact —
// NOT degrade to SERVFAIL. This is the regression test for SetReply resetting
// the rcode in ServeDNS.
func TestServeDNS_NXDOMAIN_PropagatedToClient(t *testing.T) {
	y := &mockResolver{resp: nxdomainMsg(t, "nope.test", dns.TypeA, 3600, 300)}
	c := &mockResolver{resp: nxdomainMsg(t, "nope.test", dns.TypeA, 3600, 300)}
	f := newTestForwarder(matchSet(), y, c)

	q := aQuery("nope.test")
	q.Id = 4242
	w := &captureWriter{}
	f.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	if w.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("ожидался NXDOMAIN, получен %s", dns.RcodeToString[w.msg.Rcode])
	}
	if !hasSOA(w.msg) {
		t.Fatal("в NXDOMAIN-ответе должна сохраниться SOA-запись (authority)")
	}
	// SetReply-нормализация (Id/Response) НЕ должна затирать rcode (DNS-I-3).
	if w.msg.Id != q.Id || !w.msg.Response {
		t.Fatalf("ответ должен быть нормализован под запрос: Id=%d (want %d) Response=%v",
			w.msg.Id, q.Id, w.msg.Response)
	}
}

// DNS-H1: a repeat query for the nonexistent name must be served from the
// negative cache — upstreams are NOT called again (no dual-resolve storm,
// no fresh uTLS DoH handshake per lookup).
func TestServeDNS_NXDOMAIN_NegativeCached(t *testing.T) {
	y := &mockResolver{resp: nxdomainMsg(t, "nope.test", dns.TypeA, 3600, 300)}
	c := &mockResolver{resp: nxdomainMsg(t, "nope.test", dns.TypeA, 3600, 300)}
	f := newTestForwarder(matchSet(), y, c)

	f.ServeDNS(&captureWriter{}, aQuery("nope.test"))
	yc, cc := y.callCount(), c.callCount()
	if yc == 0 || cc == 0 {
		t.Fatalf("первый запрос должен дёрнуть оба резолвера, y=%d c=%d", yc, cc)
	}

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("nope.test"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("второй запрос: ожидался NXDOMAIN из кэша, получено %+v", w.msg)
	}
	if y.callCount() != yc || c.callCount() != cc {
		t.Fatalf("второй запрос должен быть из negative cache (без вызовов): y %d→%d c %d→%d",
			yc, y.callCount(), cc, c.callCount())
	}
}

// DNS-H1: Cloudflare (the trusted uncensored upstream) says NXDOMAIN while
// Yandex hands back some non-RU A record → trust CF, return NXDOMAIN.
func TestServeDNS_CFNXDOMAIN_YandexForeignA_NXDOMAINWins(t *testing.T) {
	match := matchSet("89.221.226.6") // ни один Yandex-IP не в snapshot
	y := &mockResolver{resp: answerA(t, "ghost.test", "142.250.1.1")}
	c := &mockResolver{resp: nxdomainMsg(t, "ghost.test", dns.TypeA, 3600, 300)}
	f := newTestForwarder(match, y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("ghost.test"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("ожидался NXDOMAIN от CF, получено %+v", w.msg)
	}
}

// DNS-H1 exception: CF says NXDOMAIN but Yandex positively resolves the name
// to an RU-classified IP (RU split-horizon) → trust Yandex, same trust model
// as the CF-down branch.
func TestHandleQuery_CFNXDOMAIN_YandexRU_TrustYandex(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "ru-internal.test", "87.250.250.242")}
	c := &mockResolver{resp: nxdomainMsg(t, "ru-internal.test", dns.TypeA, 3600, 300)}
	f := newTestForwarder(match, y, c)

	resp, err := f.handleQuery(context.Background(), aQuery("ru-internal.test"),
		cacheKey{name: dns.Fqdn("ru-internal.test"), qtype: dns.TypeA})
	if err != nil {
		t.Fatalf("ожидался успех (Yandex RU), получена ошибка: %v", err)
	}
	if got := firstA(t, resp); got != "87.250.250.242" {
		t.Fatalf("CF NXDOMAIN + Yandex RU: ожидался Yandex 87.250.250.242, получен %s", got)
	}
}

// SERVFAIL rcode from CF (now visible through the raw DoH path) is NOT a
// usable answer — the ladder must fall to the yOK && !cOK branch and serve
// the RU-classified Yandex answer.
func TestHandleQuery_CFRcodeServfail_TreatedAsFailure(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "ya.test", "87.250.250.242")}
	cfFail := new(dns.Msg)
	cfFail.SetQuestion(dns.Fqdn("ya.test"), dns.TypeA)
	cfFail.Response = true
	cfFail.Rcode = dns.RcodeServerFailure
	c := &mockResolver{resp: cfFail}
	f := newTestForwarder(match, y, c)

	resp, err := f.handleQuery(context.Background(), aQuery("ya.test"),
		cacheKey{name: dns.Fqdn("ya.test"), qtype: dns.TypeA})
	if err != nil {
		t.Fatalf("ожидался успех (Yandex RU при CF SERVFAIL-rcode), получена ошибка: %v", err)
	}
	if got := firstA(t, resp); got != "87.250.250.242" {
		t.Fatalf("ожидался Yandex 87.250.250.242, получен %s", got)
	}
}

// Yandex-only NXDOMAIN (CF dead) is NOT trusted — RKN censorship can answer
// NXDOMAIN too. Fail-closed: SERVFAIL, not cached.
func TestHandleQuery_YandexNXDOMAIN_CFDown_FailClosed(t *testing.T) {
	y := &mockResolver{resp: nxdomainMsg(t, "x.test", dns.TypeA, 3600, 300)}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(matchSet(), y, c)

	_, err := f.handleQuery(context.Background(), aQuery("x.test"),
		cacheKey{name: dns.Fqdn("x.test"), qtype: dns.TypeA})
	if err == nil {
		t.Fatal("Yandex-only NXDOMAIN: ожидался fail-closed SERVFAIL (err), получен nil")
	}
}

// NODATA (NOERROR + пустой Answer + SOA) propagated to the client and served
// from cache on repeat.
func TestServeDNS_NODATA_PropagatedAndCached(t *testing.T) {
	y := &mockResolver{resp: nodataMsg(t, "nodata.test", dns.TypeA, 3600, 120)}
	c := &mockResolver{resp: nodataMsg(t, "nodata.test", dns.TypeA, 3600, 120)}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("nodata.test"))
	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	if w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) != 0 {
		t.Fatalf("ожидался NOERROR/NODATA, получено rcode=%s answers=%d",
			dns.RcodeToString[w.msg.Rcode], len(w.msg.Answer))
	}
	if !hasSOA(w.msg) {
		t.Fatal("NODATA-ответ должен сохранить SOA в authority")
	}

	yc, cc := y.callCount(), c.callCount()
	f.ServeDNS(&captureWriter{}, aQuery("nodata.test"))
	if y.callCount() != yc || c.callCount() != cc {
		t.Fatalf("повторный NODATA должен быть из кэша: y %d→%d c %d→%d",
			yc, y.callCount(), cc, c.callCount())
	}
}

// Non-A path (forwardCloudflare): NXDOMAIN for an MX query propagated and
// negatively cached; Yandex never called.
func TestServeDNS_NonA_NXDOMAIN_PropagatedAndCached(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "nope.test", "1.2.3.4")}
	c := &mockResolver{resp: nxdomainMsg(t, "nope.test", dns.TypeMX, 3600, 300)}
	f := newTestForwarder(matchSet(), y, c)

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn("nope.test"), dns.TypeMX)
	w := &captureWriter{}
	f.ServeDNS(w, q)
	if w.msg == nil || w.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("MX NXDOMAIN: ожидался NXDOMAIN, получено %+v", w.msg)
	}
	if y.callCount() != 0 {
		t.Fatalf("MX: Yandex не должен вызываться, y=%d", y.callCount())
	}

	cc := c.callCount()
	q2 := new(dns.Msg)
	q2.SetQuestion(dns.Fqdn("nope.test"), dns.TypeMX)
	w2 := &captureWriter{}
	f.ServeDNS(w2, q2)
	if w2.msg == nil || w2.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("MX NXDOMAIN повтор: ожидался NXDOMAIN из кэша, получено %+v", w2.msg)
	}
	if c.callCount() != cc {
		t.Fatalf("MX NXDOMAIN повтор должен быть из кэша, c %d→%d", cc, c.callCount())
	}
}

// Non-A path: SERVFAIL rcode from CF must NOT be cached or returned as-is —
// it is an upstream failure (SERVFAIL to client via error path).
func TestForwardCloudflare_ServfailRcode_NotCached(t *testing.T) {
	cfFail := new(dns.Msg)
	cfFail.SetQuestion(dns.Fqdn("mail.test"), dns.TypeMX)
	cfFail.Response = true
	cfFail.Rcode = dns.RcodeServerFailure
	c := &mockResolver{resp: cfFail}
	f := newTestForwarder(matchSet(), &mockResolver{}, c)

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn("mail.test"), dns.TypeMX)
	if _, err := f.forwardCloudflare(context.Background(), q,
		cacheKey{name: dns.Fqdn("mail.test"), qtype: dns.TypeMX}); err == nil {
		t.Fatal("SERVFAIL-rcode от CF: ожидалась ошибка, получен nil")
	}
	if _, ok := f.cache.get(cacheKey{name: dns.Fqdn("mail.test"), qtype: dns.TypeMX}); ok {
		t.Fatal("SERVFAIL не должен кэшироваться")
	}
}

// --- negative cache TTL semantics (RFC 2308) ---

// NXDOMAIN is stored and served with rcode + authority intact; the lifetime is
// min(SOA TTL, SOA MINIMUM) — here MINIMUM=300 < TTL=3600 → 300s.
func TestCache_NXDOMAIN_SOAMinTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("nope.test"), qtype: dns.TypeA}

	c.put(key, nxdomainMsg(t, "nope.test", dns.TypeA, 3600, 300))

	got, ok := c.get(key)
	if !ok {
		t.Fatal("ожидался hit сразу после put")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Fatalf("кэш должен сохранять rcode NXDOMAIN, получен %s", dns.RcodeToString[got.Rcode])
	}
	if !hasSOA(got) {
		t.Fatal("кэш должен сохранять SOA в authority")
	}

	// На 299-й секунде ещё hit, SOA TTL декрементирован.
	clk.advance(299 * time.Second)
	got, ok = c.get(key)
	if !ok {
		t.Fatal("ожидался hit на 299s (negative TTL = 300s)")
	}
	if ttl := got.Ns[0].Header().Ttl; ttl != 1 {
		t.Fatalf("SOA TTL должен декрементироваться: ожидался 1, получено %d", ttl)
	}
	// На 301-й — miss.
	clk.advance(2 * time.Second)
	if _, ok := c.get(key); ok {
		t.Fatal("ожидался miss после истечения negative TTL (300s)")
	}
}

// SOA MINIMUM below the cache floor is clamped up to minCacheTTL (30s).
func TestCache_NXDOMAIN_SOAMinClampedLower(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("nope.test"), qtype: dns.TypeA}

	c.put(key, nxdomainMsg(t, "nope.test", dns.TypeA, 3600, 5))

	clk.advance(29 * time.Second)
	if _, ok := c.get(key); !ok {
		t.Fatal("ожидался hit на 29s (clamp до minCacheTTL=30s)")
	}
	clk.advance(2 * time.Second)
	if _, ok := c.get(key); ok {
		t.Fatal("ожидался miss после 31s")
	}
}

// NXDOMAIN without an SOA falls back to minCacheTTL.
func TestCache_NXDOMAIN_NoSOA_MinTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("nope.test"), qtype: dns.TypeA}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("nope.test"), dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeNameError
	c.put(key, m)

	if _, ok := c.get(key); !ok {
		t.Fatal("ожидался hit сразу после put")
	}
	clk.advance(31 * time.Second)
	if _, ok := c.get(key); ok {
		t.Fatal("ожидался miss после 31s (minCacheTTL без SOA)")
	}
}

// NODATA with an SOA uses the RFC 2308 SOA-derived lifetime too (not the
// blanket minCacheTTL): MINIMUM=120 → hit at 119s, miss at 121s.
func TestCache_NODATA_SOAMinTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("nodata.test"), qtype: dns.TypeA}

	c.put(key, nodataMsg(t, "nodata.test", dns.TypeA, 3600, 120))

	clk.advance(119 * time.Second)
	if _, ok := c.get(key); !ok {
		t.Fatal("ожидался hit на 119s (negative TTL из SOA MINIMUM=120)")
	}
	clk.advance(2 * time.Second)
	if _, ok := c.get(key); ok {
		t.Fatal("ожидался miss после 121s")
	}
}

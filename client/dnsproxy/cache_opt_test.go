package dnsproxy

// DNS-M1 (2026-06-12): OPT (EDNS0) псевдозапись не должна (а) храниться в кэше,
// (б) портиться TTL-хелперами (её Ttl — это extended-RCODE/version/DO/Z-флаги,
// RFC 6891 §6.1.3, НЕ время жизни), (в) отдаваться клиенту, который сам не
// присылал EDNS0 (нарушение RFC: OPT в ответе только при OPT в запросе).

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// makeOPT строит OPT-псевдозапись с осмысленной кодировкой Ttl:
// version=1 → Ttl = 1<<16. Любая «TTL-арифметика» над этим полем ломает
// EDNS-version — тесты ловят именно это.
func makeOPT() *dns.OPT {
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Hdr.Ttl = uint32(1) << 16 // version=1, остальные биты 0
	return opt
}

// makeMsgWithOPT — ответ с одной A-записью и OPT в Extra (как от upstream'а).
func makeMsgWithOPT(name string, ttl uint32) *dns.Msg {
	m := makeMsg(name, ttl)
	m.Extra = append(m.Extra, makeOPT())
	return m
}

func hasOPT(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			return true
		}
	}
	return false
}

// put должен вырезать OPT из Extra; A-запись и её TTL-обработка не меняются.
func TestCache_StripsOPTOnPut(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("example.com"), qtype: dns.TypeA}

	c.put(key, makeMsgWithOPT("example.com", 60))

	got, ok := c.get(key)
	if !ok {
		t.Fatal("ожидался hit")
	}
	if hasOPT(got.Extra) {
		t.Fatal("OPT не должен храниться в кэше / отдаваться из него")
	}
	// A-запись на месте, TTL-обработка не изменилась (elapsed=0 → 60).
	if ttl := answerTTL(t, got); ttl != 60 {
		t.Fatalf("A TTL не должен пострадать от вырезания OPT: ожидался 60, получено %d", ttl)
	}
}

// Defense-in-depth: setRRTTLs не трогает Ttl-поле OPT (там флаги, не TTL).
func TestSetRRTTLs_SkipsOPT(t *testing.T) {
	opt := makeOPT()
	a := makeMsg("example.com", 300).Answer[0]
	rrs := []dns.RR{a, opt}

	setRRTTLs(rrs, 30)

	if opt.Hdr.Ttl != uint32(1)<<16 {
		t.Fatalf("setRRTTLs испортил OPT.Ttl (EDNS version/flags): получено %d", opt.Hdr.Ttl)
	}
	if a.Header().Ttl != 30 {
		t.Fatalf("обычные RR должны получить TTL=30, получено %d", a.Header().Ttl)
	}
}

// Defense-in-depth: decrementRRTTLs не трогает Ttl-поле OPT.
func TestDecrementRRTTLs_SkipsOPT(t *testing.T) {
	opt := makeOPT()
	a := makeMsg("example.com", 300).Answer[0]
	rrs := []dns.RR{a, opt}

	decrementRRTTLs(rrs, 10)

	if opt.Hdr.Ttl != uint32(1)<<16 {
		t.Fatalf("decrementRRTTLs испортил OPT.Ttl (EDNS version/flags): получено %d", opt.Hdr.Ttl)
	}
	if a.Header().Ttl != 290 {
		t.Fatalf("обычные RR должны декрементироваться до 290, получено %d", a.Header().Ttl)
	}
}

// withOPTExtra навешивает OPT на ответ мок-резолвера (имитация upstream EDNS).
func withOPTExtra(m *dns.Msg) *dns.Msg {
	m.Extra = append(m.Extra, makeOPT())
	return m
}

// ServeDNS: клиент БЕЗ EDNS0 в запросе не должен получить OPT в ответе —
// ни на пути свежего резолва, ни на cache-hit пути.
func TestServeDNS_NoOPTForNonEDNSClient(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: withOPTExtra(answerA(t, "site.test", "89.221.226.6"))}
	c := &mockResolver{resp: withOPTExtra(answerA(t, "site.test", "104.18.41.41"))}
	f := newTestForwarder(match, y, c)

	// Запрос без EDNS0 (SetQuestion не добавляет OPT).
	q := aQuery("site.test")
	if q.IsEdns0() != nil {
		t.Fatal("тестовый запрос не должен содержать OPT")
	}

	// 1-й запрос — свежий резолв (upstream-ответ несёт OPT).
	w := &captureWriter{}
	f.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	if hasOPT(w.msg.Extra) {
		t.Fatal("свежий резолв: OPT не должен отдаваться клиенту без EDNS0")
	}

	// 2-й запрос — cache hit, тоже без OPT.
	w2 := &captureWriter{}
	f.ServeDNS(w2, aQuery("site.test"))
	if w2.msg == nil {
		t.Fatal("ответ на cache-hit не записан")
	}
	if hasOPT(w2.msg.Extra) {
		t.Fatal("cache hit: OPT не должен отдаваться клиенту без EDNS0")
	}
}

// Прямой unit-тест хелпера stripOPTForClient — независимо от кэш-слоя
// (в ServeDNS-тесте выше put уже вырезал OPT, так что cache-hit ветка хелпера
// там вакуумна; здесь обе ветки пинятся напрямую).
func TestStripOPTForClient(t *testing.T) {
	// Клиент без EDNS0 → OPT вырезается.
	resp := withOPTExtra(answerA(t, "site.test", "1.2.3.4"))
	stripOPTForClient(resp, aQuery("site.test"))
	if hasOPT(resp.Extra) {
		t.Fatal("клиент без EDNS0: OPT должен быть вырезан из ответа")
	}

	// Клиент с EDNS0 → OPT в ответе сохраняется.
	respEDNS := withOPTExtra(answerA(t, "site.test", "1.2.3.4"))
	qEDNS := aQuery("site.test")
	qEDNS.SetEdns0(1232, false)
	stripOPTForClient(respEDNS, qEDNS)
	if !hasOPT(respEDNS.Extra) {
		t.Fatal("клиент с EDNS0: OPT в ответе должен сохраниться")
	}
}

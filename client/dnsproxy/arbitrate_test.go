package dnsproxy

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// msgWithA builds a *dns.Msg whose Answer section holds an A record per IP in
// ips. The query name is fixed (irrelevant to arbitrate, which only inspects
// the Answer A records). Non-parseable IPs fail the test.
func msgWithA(t *testing.T, ips ...string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.test"), dns.TypeA)
	for _, ip := range ips {
		rr, err := dns.NewRR("example.test. 60 IN A " + ip)
		if err != nil {
			t.Fatalf("не удалось собрать A-запись для %q: %v", ip, err)
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}

// msgWithCNAMEAndA builds a CNAME→A chain: a CNAME RR followed by A records.
// Used to verify arbitrate ignores the CNAME but still counts the A records.
func msgWithCNAMEAndA(t *testing.T, target string, ips ...string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.test"), dns.TypeA)
	cname, err := dns.NewRR("example.test. 60 IN CNAME " + target)
	if err != nil {
		t.Fatalf("не удалось собрать CNAME: %v", err)
	}
	m.Answer = append(m.Answer, cname)
	for _, ip := range ips {
		rr, err := dns.NewRR(dns.Fqdn(target) + " 60 IN A " + ip)
		if err != nil {
			t.Fatalf("не удалось собрать A-запись для %q: %v", ip, err)
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}

// snapMatcher returns a snapshotMatcher backed by a fixed set of "Russian"
// IPs — a synthetic stand-in for bypassroute.Resolved.Match without touching
// its private fields.
func snapMatcher(ips ...string) snapshotMatcher {
	set := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		set[netip.MustParseAddr(ip)] = true
	}
	return func(a netip.Addr) bool { return set[a] }
}

// Branch 1: honest RU site — Yandex and Cloudflare agree and the IP is in the
// snapshot → return the Yandex answer (direct, fast).
func TestArbitrate_Branch1_RUHonest(t *testing.T) {
	match := snapMatcher("89.221.226.6", "87.250.250.242")
	y := msgWithA(t, "87.250.250.242")
	c := msgWithA(t, "87.250.250.242")

	got, br := arbitrate(y, c, match)
	if br != branchYandex {
		t.Fatalf("ожидалась branchYandex, получена %v", br)
	}
	if got != y {
		t.Fatalf("ожидался возврат ответа Yandex (y), получен другой *dns.Msg")
	}
}

// Branch 2 — REGRESSION (LinkedIn censorship): Yandex returns the RKN stub
// (89.221.226.6, which IS in the RU snapshot), Cloudflare returns the real CDN
// IP (not in snapshot). Answers diverge → return the Cloudflare answer.
// This is the headline case the whole arbitration exists for.
func TestArbitrate_Branch2_Censored_LinkedInRegression(t *testing.T) {
	// 89.221.226.6 — РКН-заглушка, САМА попадает в RU snapshot (подтверждённый риск).
	match := snapMatcher("89.221.226.6", "87.250.250.242")
	y := msgWithA(t, "89.221.226.6")  // Yandex → заглушка
	c := msgWithA(t, "104.18.41.41")  // Cloudflare → реальный CDN LinkedIn

	got, br := arbitrate(y, c, match)
	if br != branchCloudflareCensored {
		t.Fatalf("LinkedIn-регресс: ожидалась branchCloudflareCensored, получена %v", br)
	}
	if got != c {
		t.Fatalf("LinkedIn-регресс: ожидался возврат ответа Cloudflare (c), получен другой *dns.Msg")
	}
}

// Branch 3: foreign site — no Yandex IP is in the snapshot → return Cloudflare.
func TestArbitrate_Branch3_Foreign(t *testing.T) {
	match := snapMatcher("89.221.226.6", "87.250.250.242")
	y := msgWithA(t, "142.250.1.1")
	c := msgWithA(t, "142.250.1.2")

	got, br := arbitrate(y, c, match)
	if br != branchCloudflareForeign {
		t.Fatalf("ожидалась branchCloudflareForeign, получена %v", br)
	}
	if got != c {
		t.Fatalf("ожидался возврат ответа Cloudflare (c), получен другой *dns.Msg")
	}
}

// Branch 1 with partial overlap: Yandex has an in-snapshot IP (1.1.1.1) AND the
// intersection Y∩C is non-empty (2.2.2.2) → honest RU → branchYandex. DNS-L1
// (2026-06-12): served answer is narrowed to the intersection — 1.1.1.1 (Yandex-only)
// and 3.3.3.3 (CF-only) must NOT appear in the answer handed to the client.
func TestArbitrate_Branch1_PartialOverlap(t *testing.T) {
	match := snapMatcher("1.1.1.1")
	y := msgWithA(t, "1.1.1.1", "2.2.2.2")
	c := msgWithA(t, "2.2.2.2", "3.3.3.3")

	got, br := arbitrate(y, c, match)
	if br != branchYandex {
		t.Fatalf("ожидалась branchYandex (частичное пересечение), получена %v", br)
	}
	set := a4Set(got)
	if len(set) != 1 {
		t.Fatalf("ожидалась ровно одна A-запись (пересечение), получено %d", len(set))
	}
	if _, ok := set[netip.MustParseAddr("2.2.2.2")]; !ok {
		t.Fatal("ожидался 2.2.2.2 (Y∩C) в отдаваемом ответе")
	}
}

// DNS-L1 — partial poisoning: инжектор ПОДСАДИЛ заглушку рядом с честным
// ответом. ySet={stub, real}, cSet={real} → пересечение непустое → branchYandex,
// но отдаваемый ответ обязан содержать ТОЛЬКО пересечение — заглушка не доезжает
// до клиента (ОС часто берёт первую запись).
func TestArbitrate_PartialPoisoning_ServesIntersectionOnly(t *testing.T) {
	match := snapMatcher("89.221.226.6")
	y := msgWithA(t, "89.221.226.6", "104.18.41.41") // заглушка подсажена первой
	c := msgWithA(t, "104.18.41.41")

	got, br := arbitrate(y, c, match)
	if br != branchYandex {
		t.Fatalf("ожидалась branchYandex (пересечение непустое), получена %v", br)
	}
	set := a4Set(got)
	if _, ok := set[netip.MustParseAddr("89.221.226.6")]; ok {
		t.Fatal("заглушка 89.221.226.6 НЕ должна попасть в отдаваемый ответ")
	}
	if _, ok := set[netip.MustParseAddr("104.18.41.41")]; !ok || len(set) != 1 {
		t.Fatalf("ожидался только 104.18.41.41, получено множество из %d", len(set))
	}
}

// DNS-L1: при фильтрации по пересечению CNAME-цепочка сохраняется — отдаваемый
// msg остаётся внутренне согласованным (A-записи зависят от CNAME).
func TestArbitrate_FilteredAnswerKeepsCNAME(t *testing.T) {
	match := snapMatcher("89.221.226.6")
	y := msgWithCNAMEAndA(t, "real-cdn.example.", "89.221.226.6", "104.18.41.41")
	c := msgWithA(t, "104.18.41.41")

	got, br := arbitrate(y, c, match)
	if br != branchYandex {
		t.Fatalf("ожидалась branchYandex, получена %v", br)
	}
	hasCNAME := false
	for _, rr := range got.Answer {
		if _, ok := rr.(*dns.CNAME); ok {
			hasCNAME = true
		}
		if a, ok := rr.(*dns.A); ok && a.A.String() == "89.221.226.6" {
			t.Fatal("заглушка не должна остаться в отфильтрованном ответе")
		}
	}
	if !hasCNAME {
		t.Fatal("CNAME должен сохраниться в отфильтрованном ответе")
	}
}

// DNS-M7 — geo-restricted RU: Yandex даёт честный in-snapshot IP, CF с
// зарубежной точки отвечает NOERROR-пусто (geo-DNS/ACL). Раньше: censored →
// клиент получал пустой ответ CF. Теперь: branchYandexGeo → Yandex.
func TestArbitrate_GeoRU_CFEmpty_TrustYandex(t *testing.T) {
	match := snapMatcher("87.250.250.242")
	y := msgWithA(t, "87.250.250.242")
	c := msgWithA(t) // NOERROR-пусто

	got, br := arbitrate(y, c, match)
	if br != branchYandexGeo {
		t.Fatalf("ожидалась branchYandexGeo, получена %v", br)
	}
	if got != y {
		t.Fatalf("ожидался возврат ответа Yandex (y), получен другой *dns.Msg")
	}
}

// Yandex returned NODATA (empty A set) → trivially "no Yandex IP in snapshot" →
// branch 3 (foreign/CF).
func TestArbitrate_YandexEmpty_NODATA(t *testing.T) {
	match := snapMatcher("89.221.226.6", "87.250.250.242")
	y := msgWithA(t) // пусто
	c := msgWithA(t, "142.250.1.2")

	got, br := arbitrate(y, c, match)
	if br != branchCloudflareForeign {
		t.Fatalf("ожидалась branchCloudflareForeign при пустом Yandex, получена %v", br)
	}
	if got != c {
		t.Fatalf("ожидался возврат ответа Cloudflare (c), получен другой *dns.Msg")
	}
}

// Yandex отдал ЗАГЛУШКУ (in-snapshot), Cloudflare пуст → geo-подветка DNS-M7
// НЕ срабатывает (stub-фильтр) → branch 2 (censored → CF). c returned even
// though it is empty; the proxy layer (T5) decides fallback for empty answers.
// Это stub-guard кейс синергии DNS-M7 × DNS-H2: без фильтра geo-подветка
// отдавала бы блок-страницу при пустом CF.
func TestArbitrate_YandexInSnapshot_CloudflareEmpty(t *testing.T) {
	match := snapMatcher("89.221.226.6")
	y := msgWithA(t, "89.221.226.6")
	c := msgWithA(t) // пусто

	got, br := arbitrate(y, c, match)
	if br != branchCloudflareCensored {
		t.Fatalf("ожидалась branchCloudflareCensored (CF пуст), получена %v", br)
	}
	if got != c {
		t.Fatalf("ожидался возврат ответа Cloudflare (c, пусть пустой), получен другой *dns.Msg")
	}
}

// CNAME→A chain on the Yandex side: the CNAME RR must be ignored, the trailing
// A records must still drive the decision. Here the A record is in the snapshot
// and matches Cloudflare → branch 1.
func TestArbitrate_IgnoresCNAME(t *testing.T) {
	match := snapMatcher("87.250.250.242")
	y := msgWithCNAMEAndA(t, "yandex-cdn.example.", "87.250.250.242")
	c := msgWithA(t, "87.250.250.242")

	got, br := arbitrate(y, c, match)
	if br != branchYandex {
		t.Fatalf("ожидалась branchYandex (CNAME проигнорирован, A учтён), получена %v", br)
	}
	if got != y {
		t.Fatalf("ожидался возврат ответа Yandex (y), получен другой *dns.Msg")
	}
}

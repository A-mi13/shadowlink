package dnsproxy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// cachedLifetime достаёт фактический срок жизни кэш-записи (expiresAt-storedAt)
// — различает обычный put (TTL upstream'а с клампом) и жёсткий короткий
// putWithLifetime для неарбитрированных ответов (DNS-H2 b).
func cachedLifetime(t *testing.T, f *Forwarder, key cacheKey) time.Duration {
	t.Helper()
	f.cache.mu.Lock()
	defer f.cache.mu.Unlock()
	e, ok := f.cache.entries[key]
	if !ok {
		t.Fatal("ожидалась запись в кэше, не найдена")
	}
	return e.expiresAt.Sub(e.storedAt)
}

// --- stub-IP set (DNS-H2 a) ---

// Builtin-список обязан содержать подтверждённую РКН-заглушку.
func TestStubIPSet_DefaultContainsRKNStub(t *testing.T) {
	if !isStubIP(netip.MustParseAddr("89.221.226.6")) {
		t.Fatal("89.221.226.6 (РКН-заглушка) должна входить в builtin stub-set")
	}
}

// Env-расширение: валидные IP добавляются к builtin, мусор пропускается без паники.
func TestStubIPSet_EnvAppend(t *testing.T) {
	set := buildStubIPSet(" 1.2.3.4 , garbage, , 5.6.7.8")
	for _, want := range []string{"89.221.226.6", "1.2.3.4", "5.6.7.8"} {
		if _, ok := set[netip.MustParseAddr(want)]; !ok {
			t.Fatalf("ожидался %s в stub-set, отсутствует", want)
		}
	}
	if len(set) != 3 {
		t.Fatalf("ожидалось ровно 3 записи (builtin + 2 env), получено %d", len(set))
	}
}

// --- DNS-H2: CF упал + Yandex отдал заглушку ---

// THE missing test из аудита: CF недоступен, Yandex возвращает stub-IP
// (который САМ в RU snapshot → yandexIsRU=true). Заглушка должна быть
// отвергнута → честный SERVFAIL, НЕ закэширована — блок-страница никогда
// не отдаётся клиенту и не залипает в кэше до восстановления туннеля.
func TestHandleQuery_CFfail_YandexStub_SERVFAIL(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "linkedin.test", "89.221.226.6")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(match, y, c)

	key := cacheKey{name: dns.Fqdn("linkedin.test"), qtype: dns.TypeA}
	_, err := f.handleQuery(context.Background(), aQuery("linkedin.test"), key)
	if err == nil {
		t.Fatal("CF fail + Yandex=stub: ожидался SERVFAIL (err), получен nil")
	}
	if _, ok := f.cache.get(key); ok {
		t.Fatal("отвергнутая заглушка НЕ должна кэшироваться")
	}
}

// Yandex-ответ, СОДЕРЖАЩИЙ stub среди прочих IP, отвергается целиком
// (без CF для сверки невозможно отличить честные записи от подсаженных).
func TestHandleQuery_CFfail_YandexMixedWithStub_SERVFAIL(t *testing.T) {
	match := matchSet("89.221.226.6", "87.250.250.242")
	y := &mockResolver{resp: answerA(t, "mixed.test", "87.250.250.242", "89.221.226.6")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(match, y, c)

	_, err := f.handleQuery(context.Background(), aQuery("mixed.test"),
		cacheKey{name: dns.Fqdn("mixed.test"), qtype: dns.TypeA})
	if err == nil {
		t.Fatal("CF fail + Yandex=[real, stub]: ожидался SERVFAIL (err), получен nil")
	}
}

// --- DNS-H2 b: короткий TTL для неарбитрированных ответов ---

// CF упал, Yandex отдал честный RU IP — ответ отдаётся (существующее
// поведение), но кэшируется на ЖЁСТКИЕ 30с, а не на upstream-TTL (60с в моке):
// неизвестная отравленная запись не залипнет до часа.
func TestHandleQuery_CFfail_YandexRU_ShortTTL(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "ya.test", "87.250.250.242")} // TTL 60 в моке
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(match, y, c)

	key := cacheKey{name: dns.Fqdn("ya.test"), qtype: dns.TypeA}
	resp, err := f.handleQuery(context.Background(), aQuery("ya.test"), key)
	if err != nil {
		t.Fatalf("ожидался успех (Yandex RU), получена ошибка: %v", err)
	}
	if got := firstA(t, resp); got != "87.250.250.242" {
		t.Fatalf("ожидался 87.250.250.242, получен %s", got)
	}
	if lt := cachedLifetime(t, f, key); lt != unarbitratedCacheTTL {
		t.Fatalf("неарбитрированный ответ: ожидался срок кэша %v, получен %v", unarbitratedCacheTTL, lt)
	}
}

// --- DNS-H2 c: stub-фильтр в split-horizon исключении (Block 3) ---

// CF=NXDOMAIN + Yandex=stub (RU-classified): заглушке нельзя доверять и здесь
// — пропагируем NXDOMAIN от CF, заглушка клиенту не отдаётся.
func TestHandleQuery_CFNXDOMAIN_YandexStub_NXDOMAINPropagated(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "ghost.test", "89.221.226.6")}
	c := &mockResolver{resp: nxdomainMsg(t, "ghost.test", dns.TypeA, 3600, 300)}
	f := newTestForwarder(match, y, c)

	resp, err := f.handleQuery(context.Background(), aQuery("ghost.test"),
		cacheKey{name: dns.Fqdn("ghost.test"), qtype: dns.TypeA})
	if err != nil {
		t.Fatalf("ожидался NXDOMAIN-ответ, получена ошибка: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("ожидался NXDOMAIN от CF, получен %s", dns.RcodeToString[resp.Rcode])
	}
	if len(a4Set(resp)) != 0 {
		t.Fatal("в пропагированном NXDOMAIN не должно быть A-записей (заглушки)")
	}
}

// Split-horizon исключение для честного RU IP продолжает работать, но
// доверие Yandex'у здесь тоже неарбитрированное → короткий TTL.
func TestHandleQuery_CFNXDOMAIN_YandexRU_ShortTTL(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "ru-internal.test", "87.250.250.242")}
	c := &mockResolver{resp: nxdomainMsg(t, "ru-internal.test", dns.TypeA, 3600, 300)}
	f := newTestForwarder(match, y, c)

	key := cacheKey{name: dns.Fqdn("ru-internal.test"), qtype: dns.TypeA}
	resp, err := f.handleQuery(context.Background(), aQuery("ru-internal.test"), key)
	if err != nil {
		t.Fatalf("ожидался успех (split-horizon Yandex RU), получена ошибка: %v", err)
	}
	if got := firstA(t, resp); got != "87.250.250.242" {
		t.Fatalf("ожидался Yandex 87.250.250.242, получен %s", got)
	}
	if lt := cachedLifetime(t, f, key); lt != unarbitratedCacheTTL {
		t.Fatalf("split-horizon ответ: ожидался срок кэша %v, получен %v", unarbitratedCacheTTL, lt)
	}
}

// --- DNS-M7: geo-restricted RU домен (CF NOERROR-пустой) ---

// Yandex даёт честный RU IP, CF с зарубежной точки видит NOERROR-пустоту
// (geo-DNS/ACL, типично для gov/bank зон). Раньше это падало в censored-ветку
// и клиент получал ПУСТОЙ ответ CF. Теперь: доверяем Yandex (stub-фильтр
// пройден), кэшируем обычно (ответ арбитрирован против пустого CF).
func TestHandleQuery_GeoRU_CFEmpty_ServesYandex(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "gosuslugi.test", "87.250.250.242")} // TTL 60
	c := &mockResolver{resp: answerA(t, "gosuslugi.test")}                   // NOERROR, пустой Answer
	f := newTestForwarder(match, y, c)

	key := cacheKey{name: dns.Fqdn("gosuslugi.test"), qtype: dns.TypeA}
	resp, err := f.handleQuery(context.Background(), aQuery("gosuslugi.test"), key)
	if err != nil {
		t.Fatalf("geo-RU: ожидался успех, получена ошибка: %v", err)
	}
	if got := firstA(t, resp); got != "87.250.250.242" {
		t.Fatalf("geo-RU: ожидался Yandex 87.250.250.242, получен %s", got)
	}
	// Кэш обычный (60с из TTL мока), НЕ короткий — ветка арбитрирована.
	if lt := cachedLifetime(t, f, key); lt != 60*time.Second {
		t.Fatalf("geo-RU: ожидался обычный срок кэша 60s, получен %v", lt)
	}
	// Наблюдаемость: своя ветка, не censored.
	if yb, censored, foreign, geo := f.BranchCounts(); geo != 1 || yb != 0 || censored != 0 || foreign != 0 {
		t.Fatalf("BranchCounts после geo: ожидалось (0,0,0,1), получено (%d,%d,%d,%d)", yb, censored, foreign, geo)
	}
}

// SYNERGY DNS-M7 × DNS-H2: CF пуст, Yandex отдал ЗАГЛУШКУ (она in-snapshot!)
// — geo-подветка НЕ должна её отдать; падаем в censored (пустой CF), как раньше.
func TestHandleQuery_GeoStub_CFEmpty_NotServed(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "blocked.test", "89.221.226.6")}
	c := &mockResolver{resp: answerA(t, "blocked.test")} // NOERROR, пустой Answer
	f := newTestForwarder(match, y, c)

	resp, err := f.handleQuery(context.Background(), aQuery("blocked.test"),
		cacheKey{name: dns.Fqdn("blocked.test"), qtype: dns.TypeA})
	if err != nil {
		t.Fatalf("ожидался ответ (пустой CF, censored-ветка), получена ошибка: %v", err)
	}
	if len(a4Set(resp)) != 0 {
		t.Fatal("заглушка не должна отдаваться через geo-подветку при пустом CF")
	}
	if _, censored, _, geo := f.BranchCounts(); censored != 1 || geo != 0 {
		t.Fatalf("ожидалась censored-ветка (1), не geo (%d/%d)", censored, geo)
	}
}

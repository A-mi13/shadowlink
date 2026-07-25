package dnsproxy

// INT-H2 (2026-06-12): bootstrap-deadlock CDN-режима. После setTUNDNS системный
// резолвер = forwarder; DoH-нога идёт ЧЕРЕЗ туннель. Если все WS-слоты мертвы,
// reconnect требует резолва серверного CDN-домена: CF-нога падает (туннеля нет),
// Yandex отвечает, но домен иностранный → yandexIsRU=false → ветка yOK && !cOK
// отдавала SERVFAIL → reconnect не может зарезолвить сервер → туннель не
// восстанавливается НИКОГДА (стабильный deadlock до ручного рестарта).
// Фикс: bootstrap-whitelist — для ИЗВЕСТНОГО серверного домена ветка
// «Yandex-only при недоступном CF» разрешена без RU-арбитража (его IP всё равно
// получает /32 escape; анти-poisoning: stub-rejection остаётся, кэш — короткий
// unarbitratedCacheTTL).

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Bootstrap-домен + CF упал + Yandex даёт ИНОСТРАННЫЙ ответ → ответ отдан
// клиенту (не SERVFAIL), посчитан как unarbitrated, залогирован INFO,
// закэширован с unarbitratedCacheTTL: повтор в пределах TTL — из кэша
// (Yandex вызван один раз), после истечения — свежий резолв.
func TestBootstrap_CFDown_ForeignYandex_ServedAndCached(t *testing.T) {
	old := slog.Default()
	h := &recordingHandler{}
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(old)

	clk := &fakeClock{t: time.Unix(1000, 0)}
	match := matchSet("87.250.250.242") // серверный IP НЕ в snapshot (foreign)
	y := &mockResolver{resp: answerA(t, "cdn.example.com", "104.222.177.67")}
	c := &mockResolver{err: errors.New("cf down (tunnel dead)")}
	f := newTestForwarder(match, y, c)
	f.cache = newTestCache(clk)
	WithBootstrapDomains("cdn.example.com")(f)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("cdn.example.com"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("bootstrap: ожидался NOERROR с Yandex-ответом, получено %+v", w.msg)
	}
	if got := firstA(t, w.msg); got != "104.222.177.67" {
		t.Fatalf("bootstrap: ожидался Yandex IP 104.222.177.67, получен %s", got)
	}
	if nx, unarb := f.ServeCounts(); nx != 0 || unarb != 1 {
		t.Fatalf("bootstrap: ожидалось (nxdomain=0, unarbitrated=1), получено (%d,%d)", nx, unarb)
	}
	if h.count(bootstrapAcceptLogMsg) != 1 {
		t.Fatalf("bootstrap: ожидалась 1 INFO-строка %q, получено %d", bootstrapAcceptLogMsg, h.count(bootstrapAcceptLogMsg))
	}

	// Повтор в пределах unarbitratedCacheTTL — из кэша (Yandex не дёргается).
	yc := y.callCount()
	f.ServeDNS(&captureWriter{}, aQuery("cdn.example.com"))
	if y.callCount() != yc {
		t.Fatalf("bootstrap: повтор в пределах TTL должен быть из кэша, y %d→%d", yc, y.callCount())
	}

	// После истечения unarbitratedCacheTTL — свежий резолв (запись не залипает).
	clk.advance(unarbitratedCacheTTL + time.Second)
	f.ServeDNS(&captureWriter{}, aQuery("cdn.example.com"))
	if y.callCount() != yc+1 {
		t.Fatalf("bootstrap: после истечения TTL ожидался свежий резолв, y %d→%d", yc, y.callCount())
	}
}

// Bootstrap-домен + CF упал + ответ Yandex = известный stub-IP → ОТВЕРГНУТ
// (SERVFAIL) и НЕ закэширован: заглушка бесполезна для reconnect и не должна
// отравить кэш.
func TestBootstrap_CFDown_StubAnswer_Rejected(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "cdn.example.com", "89.221.226.6")} // builtin stub
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(match, y, c)
	WithBootstrapDomains("cdn.example.com")(f)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("cdn.example.com"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("bootstrap stub: ожидался SERVFAIL, получено %+v", w.msg)
	}
	// Не закэширован: повтор снова дёргает Yandex.
	yc := y.callCount()
	f.ServeDNS(&captureWriter{}, aQuery("cdn.example.com"))
	if y.callCount() != yc+1 {
		t.Fatalf("bootstrap stub: SERVFAIL не должен кэшироваться, y %d→%d", yc, y.callCount())
	}
	if _, unarb := f.ServeCounts(); unarb != 0 {
		t.Fatalf("bootstrap stub: unarbitrated не должен инкрементиться, получено %d", unarb)
	}
}

// Bootstrap-домен + CF упал + Yandex отвечает NXDOMAIN → fail-closed SERVFAIL:
// РКН-цензура умеет отвечать NXDOMAIN'ом, а пустой ответ для reconnect бесполезен.
func TestBootstrap_CFDown_YandexNXDOMAIN_Rejected(t *testing.T) {
	y := &mockResolver{resp: nxdomainMsg(t, "cdn.example.com", dns.TypeA, 3600, 300)}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(matchSet(), y, c)
	WithBootstrapDomains("cdn.example.com")(f)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("cdn.example.com"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("bootstrap NXDOMAIN: ожидался SERVFAIL (fail-closed), получено %+v", w.msg)
	}
}

// НЕ-bootstrap иностранный домен + CF упал → SERVFAIL: прежнее fail-closed
// поведение лестницы пиннится (relaxation действует ТОЛЬКО на bootstrap-домены).
func TestBootstrap_NonBootstrapForeign_CFDown_SERVFAIL(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "google.test", "142.250.1.1")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(match, y, c)
	WithBootstrapDomains("cdn.example.com")(f) // другой домен

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("google.test"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("non-bootstrap foreign + CF down: ожидался SERVFAIL, получено %+v", w.msg)
	}
}

// Bootstrap-домен + CF ЖИВ → обычная арбитражная лестница без изменений:
// censored-сценарий по-прежнему выбирает CF-ответ, serve-счётчики не двигаются.
func TestBootstrap_CFUp_NormalArbitration(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "cdn.example.com", "89.221.226.6")} // стаб в snapshot
	c := &mockResolver{resp: answerA(t, "cdn.example.com", "104.18.41.41")} // реальный CDN
	f := newTestForwarder(match, y, c)
	WithBootstrapDomains("cdn.example.com")(f)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("cdn.example.com"))
	if got := firstA(t, w.msg); got != "104.18.41.41" {
		t.Fatalf("bootstrap + CF up: арбитраж должен выбрать CF 104.18.41.41, получен %s", got)
	}
	if _, censored, _, _ := f.BranchCounts(); censored != 1 {
		t.Fatalf("bootstrap + CF up: ожидалась censored-ветка (=1), получено %d", censored)
	}
	if nx, unarb := f.ServeCounts(); nx != 0 || unarb != 0 {
		t.Fatalf("bootstrap + CF up: serve-счётчики не должны двигаться, получено (%d,%d)", nx, unarb)
	}
}

// Регистронезависимость: сконфигурирован "cdn.example.com", запрос
// "CDN.Example.COM." — должен совпасть.
func TestBootstrap_CaseInsensitive(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "CDN.Example.COM", "104.222.177.67")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(matchSet(), y, c)
	WithBootstrapDomains("cdn.example.com")(f)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("CDN.Example.COM"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("bootstrap case-insensitive: ожидался NOERROR, получено %+v", w.msg)
	}
	if got := firstA(t, w.msg); got != "104.222.177.67" {
		t.Fatalf("bootstrap case-insensitive: ожидался 104.222.177.67, получен %s", got)
	}
}

// cfOnly-режим (nil snapshot) + bootstrap-домен + CF упал → Yandex-fallback
// работает (со stub-rejection и коротким кэшем).
func TestBootstrap_CFOnly_CFDown_YandexFallback(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "cdn.example.com", "104.222.177.67")}
	c := &mockResolver{err: errors.New("cf down")}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c),
		WithBootstrapDomains("cdn.example.com"))

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("cdn.example.com"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("cfOnly bootstrap: ожидался Yandex-fallback NOERROR, получено %+v", w.msg)
	}
	if got := firstA(t, w.msg); got != "104.222.177.67" {
		t.Fatalf("cfOnly bootstrap: ожидался 104.222.177.67, получен %s", got)
	}
	if _, unarb := f.ServeCounts(); unarb != 1 {
		t.Fatalf("cfOnly bootstrap: ожидался unarbitrated=1, получено %d", unarb)
	}
}

// cfOnly + bootstrap + ответ Yandex = stub → отвергнут (SERVFAIL).
func TestBootstrap_CFOnly_StubRejected(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "cdn.example.com", "89.221.226.6")}
	c := &mockResolver{err: errors.New("cf down")}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c),
		WithBootstrapDomains("cdn.example.com"))

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("cdn.example.com"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("cfOnly bootstrap stub: ожидался SERVFAIL, получено %+v", w.msg)
	}
}

// cfOnly + НЕ-bootstrap домен + CF упал → SERVFAIL и Yandex НЕ вызывается
// вовсе — регрессия plaintext-утечки M-4 запрещена.
func TestBootstrap_CFOnly_NonBootstrap_YandexNeverCalled(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "site.test", "1.2.3.4")}
	c := &mockResolver{err: errors.New("cf down")}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c),
		WithBootstrapDomains("cdn.example.com"))

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("site.test"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("cfOnly non-bootstrap: ожидался SERVFAIL, получено %+v", w.msg)
	}
	if y.callCount() != 0 {
		t.Fatalf("cfOnly non-bootstrap: Yandex НЕ должен вызываться (M-4), y=%d", y.callCount())
	}
}

// cfOnly + bootstrap + CF ЖИВ → нормальный CF-путь, Yandex не трогается
// (plaintext-утечки нет, пока CF здоров).
func TestBootstrap_CFOnly_CFUp_YandexNeverCalled(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "cdn.example.com", "9.9.9.9")}
	c := &mockResolver{resp: answerA(t, "cdn.example.com", "104.18.41.41")}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c),
		WithBootstrapDomains("cdn.example.com"))

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("cdn.example.com"))
	if got := firstA(t, w.msg); got != "104.18.41.41" {
		t.Fatalf("cfOnly bootstrap + CF up: ожидался CF 104.18.41.41, получен %s", got)
	}
	if y.callCount() != 0 {
		t.Fatalf("cfOnly bootstrap + CF up: Yandex не должен вызываться, y=%d", y.callCount())
	}
}

// Пустая опция (без доменов) — поведение идентично сегодняшнему: CF down +
// foreign Yandex → SERVFAIL через handleQuery.
func TestBootstrap_EmptyOption_NoBehaviorChange(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "google.test", "142.250.1.1")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(match, y, c)
	WithBootstrapDomains()(f) // пусто

	_, err := f.handleQuery(context.Background(), aQuery("google.test"),
		cacheKey{name: dns.Fqdn("google.test"), qtype: dns.TypeA})
	if err == nil {
		t.Fatal("пустая опция: ожидался SERVFAIL (поведение без изменений)")
	}
}

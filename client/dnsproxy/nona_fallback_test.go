package dnsproxy

// Единственная точка отказа DoH, пункт 3 (2026-08-26): Yandex-фолбэк для не-A
// запросов при недоступном CF.
//
// Асимметрия, которую правка лечит: у A-пути при упавшем CF есть ветка
// «Yandex-only» (proxy.go, yOK && !cOK), обставленная защитами — yandexIsRU +
// containsStubIP + короткий unarbitratedCacheTTL. У не-A пути не было НИЧЕГО:
// forwardCloudflare → ошибка → errAllUpstreamsFailed → мгновенный SERVFAIL.
//
// ⚠ ГЛАВНОЕ ПРОЕКТНОЕ РЕШЕНИЕ ЭТОГО ФАЙЛА — фолбэк делается НЕ ДЛЯ ВСЕХ типов.
// Защиты A-пути опираются на РАЗБОР A-ЗАПИСЕЙ (a4Set → match/isStubIP) и на
// не-A типы не переносятся: у MX/TXT нет IP, чтобы сверить их с RU-снапшотом,
// а у HTTPS/SVCB IP есть, но лежат внутри SvcParam ipv4hint, куда a4Set не
// смотрит вовсе. Поэтому:
//
//	MX, TXT, SRV, PTR, NS, SOA, CNAME → фолбэк ЕСТЬ (не маршрутизируют трафик
//	    напрямую; худший исход подмены — неверный хост//текст, который дальше
//	    всё равно резолвится и проверяется по A-пути с арбитражем и TLS);
//	HTTPS/SVCB (type 65) → фолбэка НЕТ, fail-closed. Эта запись НЕСЁТ
//	    МАРШРУТИЗИРУЮЩИЕ ДАННЫЕ (ipv4hint/ipv6hint + ALPN + ECH), то есть
//	    подменённый ответ уводит соединение на чужой IP ровно как отравленная
//	    A-запись, но stub-фильтр его не видит: ipv4hint — это не *dns.A.
//	    Плюс подменённый ech= может СНЯТЬ ECH (downgrade). Клиент при SERVFAIL
//	    на type-65 штатно откатывается на A/AAAA — то есть цена fail-closed
//	    здесь околонулевая, а цена ошибки высокая.

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mxQuery / answerMX — не-A запрос без маршрутизирующих данных.
func mxQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeMX)
	return q
}

func answerMX(t *testing.T, name, mx string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeMX)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	rr, err := dns.NewRR(dns.Fqdn(name) + " 60 IN MX 10 " + dns.Fqdn(mx))
	if err != nil {
		t.Fatalf("не удалось собрать MX-запись: %v", err)
	}
	m.Answer = append(m.Answer, rr)
	return m
}

func txtQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	return q
}

func answerTXT(t *testing.T, name, text string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	rr, err := dns.NewRR(dns.Fqdn(name) + ` 60 IN TXT "` + text + `"`)
	if err != nil {
		t.Fatalf("не удалось собрать TXT-запись: %v", err)
	}
	m.Answer = append(m.Answer, rr)
	return m
}

// CF упал, Yandex жив → MX-запрос обслуживается Yandex'ом вместо SERVFAIL.
// Это и есть снятие единственной точки отказа для не-A пути.
func TestNonA_CFDown_MXServedByYandex(t *testing.T) {
	y := &mockResolver{resp: answerMX(t, "mail.test", "mx1.mail.test")}
	c := &mockResolver{err: errors.New("cf down: connection reset")}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, mxQuery("mail.test"))

	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("при живом Yandex ожидался NOERROR, получен %s", dns.RcodeToString[w.msg.Rcode])
	}
	if len(w.msg.Answer) == 0 {
		t.Fatal("ожидалась MX-запись от Yandex")
	}
	if y.callCount() == 0 {
		t.Fatal("Yandex должен быть вызван как фолбэк при упавшем CF")
	}
}

// То же для TXT.
func TestNonA_CFDown_TXTServedByYandex(t *testing.T) {
	y := &mockResolver{resp: answerTXT(t, "txt.test", "v=spf1 -all")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, txtQuery("txt.test"))

	if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) == 0 {
		t.Fatalf("TXT должен обслуживаться Yandex при упавшем CF, получено %+v", w.msg)
	}
}

// ⚠ КЛЮЧЕВОЙ ТЕСТ БЕЗОПАСНОСТИ: HTTPS/SVCB (type 65) фолбэка НЕ получает.
// Запись несёт ipv4hint/ALPN/ECH — то есть маршрутизирующие данные, которые
// stub-фильтр (a4Set → *dns.A) не видит, а RU-снапшот не с чем сверить.
// Молчаливый переход на нефильтрованный Yandex здесь мог бы увести соединение
// на чужой IP и снять ECH. Fail-closed: SERVFAIL, клиент откатится на A.
func TestNonA_CFDown_HTTPSNotFallenBackToYandex(t *testing.T) {
	y := &mockResolver{resp: answerHTTPS(t, "svc.test")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, httpsQuery("svc.test"))

	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("type-65 при упавшем CF обязан быть fail-closed (SERVFAIL): "+
			"запись несёт ipv4hint/ECH, которые нечем проверить; получено %s",
			dns.RcodeToString[w.msg.Rcode])
	}
	if y.callCount() != 0 {
		t.Fatalf("Yandex НЕ должен опрашиваться на type-65 (маршрутизирующая "+
			"запись без возможности арбитража), y=%d", y.callCount())
	}
}

// Неарбитрированный не-A ответ обязан кэшироваться КОРОТКО
// (unarbitratedCacheTTL), как и его A-аналог: подменённый ответ не должен
// залипать. TTL записи 60s > 30s, поэтому на 45-й секунде запись обязана уже
// протухнуть — если бы её положили с обычным TTL-клампом, был бы cache hit.
func TestNonA_YandexFallback_CachedWithUnarbitratedTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	y := &mockResolver{resp: answerMX(t, "mail.test", "mx1.mail.test")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(matchSet(), y, c)
	f.cache = newTestCache(clk)

	f.ServeDNS(&captureWriter{}, mxQuery("mail.test"))
	yc := y.callCount()
	if yc == 0 {
		t.Fatal("прогрев: Yandex должен был ответить")
	}

	clk.advance(45 * time.Second) // > unarbitratedCacheTTL(30s), < TTL записи(60s)
	f.ServeDNS(&captureWriter{}, mxQuery("mail.test"))
	if y.callCount() == yc {
		t.Fatal("неарбитрированный не-A ответ должен жить не дольше " +
			"unarbitratedCacheTTL (30s) — иначе подмена залипает в кэше")
	}
}

// Оба апстрима упали → честный SERVFAIL (фолбэк не выдумывает ответ).
func TestNonA_BothDown_SERVFAIL(t *testing.T) {
	y := &mockResolver{err: errors.New("yandex down")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, mxQuery("mail.test"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("при отказе обоих ожидался SERVFAIL, получено %+v", w.msg)
	}
}

// Пока CF ЖИВ, Yandex на не-A пути не трогается вовсе — фолбэк не должен
// превращаться в постоянную plaintext-утечку имён (это был смысл M-4).
func TestNonA_CFHealthy_YandexNeverQueried(t *testing.T) {
	y := &mockResolver{resp: answerMX(t, "mail.test", "mx1.mail.test")}
	c := &mockResolver{resp: answerMX(t, "mail.test", "mx-real.mail.test")}
	f := newTestForwarder(matchSet(), y, c)

	f.ServeDNS(&captureWriter{}, mxQuery("mail.test"))
	if y.callCount() != 0 {
		t.Fatalf("при живом CF Yandex не должен опрашиваться (утечка имён), y=%d", y.callCount())
	}
}

// SERVFAIL/REFUSED от Yandex — не ответ: фолбэк не должен выдавать его за успех.
func TestNonA_YandexSERVFAIL_NotServed(t *testing.T) {
	sf := new(dns.Msg)
	sf.SetQuestion(dns.Fqdn("mail.test"), dns.TypeMX)
	sf.Response = true
	sf.Rcode = dns.RcodeServerFailure

	y := &mockResolver{resp: sf}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, mxQuery("mail.test"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("SERVFAIL от Yandex не должен подаваться как валидный ответ, получено %+v", w.msg)
	}
}

// В cfOnly-режиме (нет RU-снапшота) не-A фолбэка на Yandex быть не должно:
// весь смысл cfOnly — Yandex не трогается никогда (M-4, утечка имён).
func TestNonA_CFOnlyMode_NoYandexFallback(t *testing.T) {
	y := &mockResolver{resp: answerMX(t, "mail.test", "mx1.mail.test")}
	c := &mockResolver{err: errors.New("cf down")}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c)) // nil snapshot → cfOnly

	w := &captureWriter{}
	f.ServeDNS(w, mxQuery("mail.test"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("cfOnly: ожидался SERVFAIL, получено %+v", w.msg)
	}
	if y.callCount() != 0 {
		t.Fatalf("cfOnly: Yandex не должен вызываться даже как не-A фолбэк, y=%d", y.callCount())
	}
}

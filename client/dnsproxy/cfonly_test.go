package dnsproxy

// M-4 (2026-06-12): nil/пустой RU snapshot → matcher всегда false → арбитраж
// математически всегда выбирает CF-ветку, а ответ Yandex не может быть
// использован НИКОГДА. Раньше dual-resolve всё равно слал каждое A-имя
// plaintext'ом в Yandex — чистая утечка имён + ожидание двух upstream'ов.
// cfOnly-режим пропускает Yandex-ногу целиком.

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/nixavpn/shadowlink/client/bypassroute"
)

// nil snapshot: Yandex не вызывается вовсе, ответ — от CF, кэшируется.
func TestCFOnly_NilSnapshot_YandexNeverQueried(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "site.test", "9.9.9.9")}
	c := &mockResolver{resp: answerA(t, "site.test", "104.18.41.41")}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c))

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("site.test"))
	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	if got := firstA(t, w.msg); got != "104.18.41.41" {
		t.Fatalf("cfOnly: ожидался CF-ответ 104.18.41.41, получен %s", got)
	}
	if y.callCount() != 0 {
		t.Fatalf("cfOnly: Yandex НЕ должен вызываться (plaintext-утечка имени), y=%d", y.callCount())
	}

	// Повтор — из кэша, без новых вызовов CF (и по-прежнему без Yandex).
	cc := c.callCount()
	f.ServeDNS(&captureWriter{}, aQuery("site.test"))
	if c.callCount() != cc {
		t.Fatalf("cfOnly: повтор должен быть из кэша, c %d→%d", cc, c.callCount())
	}
	if y.callCount() != 0 {
		t.Fatalf("cfOnly: Yandex не должен вызываться и на повторе, y=%d", y.callCount())
	}

	// Ветки арбитража в cfOnly недостижимы — счётчики нулевые.
	if yb, censored, foreign, geo := f.BranchCounts(); yb+censored+foreign+geo != 0 {
		t.Fatalf("cfOnly: ветки арбитража недостижимы, BranchCounts=(%d,%d,%d,%d)",
			yb, censored, foreign, geo)
	}
}

// Непустой, но ПУСТОЙ по содержимому snapshot (Size()==0) эквивалентен nil:
// matcher всегда false → тот же cfOnly-режим.
func TestCFOnly_EmptySnapshot_TreatedAsNil(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "site.test", "9.9.9.9")}
	c := &mockResolver{resp: answerA(t, "site.test", "104.18.41.41")}
	f := NewForwarder("127.0.0.1:0", &bypassroute.Resolved{}, WithResolvers(y, c))

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("site.test"))
	if got := firstA(t, w.msg); got != "104.18.41.41" {
		t.Fatalf("пустой snapshot: ожидался CF-ответ, получен %s", got)
	}
	if y.callCount() != 0 {
		t.Fatalf("пустой snapshot: Yandex не должен вызываться, y=%d", y.callCount())
	}
}

// NXDOMAIN от CF в cfOnly пропагируется клиенту и попадает в negative cache —
// семантика идентична non-A CF-пути (forwardCloudflare).
func TestCFOnly_NXDOMAIN_PropagatedAndCached(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "nope.test", "1.2.3.4")}
	c := &mockResolver{resp: nxdomainMsg(t, "nope.test", dns.TypeA, 3600, 300)}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c))

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("nope.test"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("cfOnly: ожидался NXDOMAIN от CF, получено %+v", w.msg)
	}
	if y.callCount() != 0 {
		t.Fatalf("cfOnly NXDOMAIN: Yandex не должен вызываться, y=%d", y.callCount())
	}

	cc := c.callCount()
	w2 := &captureWriter{}
	f.ServeDNS(w2, aQuery("nope.test"))
	if w2.msg == nil || w2.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("cfOnly NXDOMAIN повтор: ожидался NXDOMAIN из кэша, получено %+v", w2.msg)
	}
	if c.callCount() != cc {
		t.Fatalf("cfOnly NXDOMAIN повтор должен быть из negative cache, c %d→%d", cc, c.callCount())
	}
}

// CF упал в cfOnly → честный SERVFAIL (Yandex-fallback'а нет и быть не должно:
// его ответ всё равно не может быть использован при always-false matcher'е).
func TestCFOnly_CFFail_SERVFAIL(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "x.test", "1.2.3.4")}
	c := &mockResolver{err: errors.New("cf down")}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c))

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("x.test"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("cfOnly CF-fail: ожидался SERVFAIL, получено %+v", w.msg)
	}
	if y.callCount() != 0 {
		t.Fatalf("cfOnly CF-fail: Yandex не должен вызываться, y=%d", y.callCount())
	}
}

// Ответ CF в cfOnly авторитетен (доверенный upstream через туннель) → обычный
// TTL-кламп, НЕ unarbitratedCacheTTL=30s: на 45-й секунде (upstream TTL=60)
// всё ещё cache hit.
func TestCFOnly_CachedWithNormalTTLClamp(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	y := &mockResolver{resp: answerA(t, "site.test", "1.2.3.4")}
	c := &mockResolver{resp: answerA(t, "site.test", "104.18.41.41")} // TTL=60 (answerA)
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c))
	f.cache = newTestCache(clk)

	f.ServeDNS(&captureWriter{}, aQuery("site.test"))
	cc := c.callCount()

	clk.advance(45 * time.Second) // > unarbitratedCacheTTL (30s), < TTL (60s)
	f.ServeDNS(&captureWriter{}, aQuery("site.test"))
	if c.callCount() != cc {
		t.Fatalf("cfOnly: на 45s (TTL=60 > unarbitratedCacheTTL=30s) ожидался cache hit, c %d→%d",
			cc, c.callCount())
	}
}

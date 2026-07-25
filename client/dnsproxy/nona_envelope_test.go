package dnsproxy

// F-2 (2026-06-12, final batch review): singleflight + семафор (DNS-L5)
// покрывали только A-путь (handleQuery); non-A/non-AAAA запросы (браузеры шлют
// type-65 HTTPS рядом почти с каждым A) шли через forwardCloudflare БЕЗ дедупа
// и без bound'а конкурентности — N идентичных HTTPS-запросов = N upstream-
// вызовов, flood уникальных имён = неограниченные параллельные DoH-вызовы.
// Фикс: non-A путь проходит через ТОТ ЖЕ конверт «cache → singleflight →
// семафор» (handleNonA); cacheKey уже включает qtype — пространство ключей
// компонуется без коллизий с A-путём.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// httpsQuery строит запрос type-65 (HTTPS RR) — основной non-A тип реального
// браузерного трафика.
func httpsQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeHTTPS)
	return q
}

// answerHTTPS строит ответ с HTTPS-записью (для мок-резолверов).
func answerHTTPS(t *testing.T, name string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeHTTPS)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	rr, err := dns.NewRR(dns.Fqdn(name) + ` 60 IN HTTPS 1 . alpn="h2"`)
	if err != nil {
		t.Fatalf("не удалось собрать HTTPS-запись: %v", err)
	}
	m.Answer = append(m.Answer, rr)
	return m
}

// Конкурентные ИДЕНТИЧНЫЕ HTTPS-запросы через ServeDNS (пиннит и dispatch
// ServeDNS → конверт) сливаются в ОДИН upstream-вызов; Yandex не трогается.
func TestServeDNS_HTTPS_Singleflight_DedupsConcurrentIdentical(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "sfh.test", "1.2.3.4")}
	c := &mockResolver{resp: answerHTTPS(t, "sfh.test"), delay: 100 * time.Millisecond}
	f := newTestForwarder(matchSet(), y, c)

	const n = 8
	var wg sync.WaitGroup
	writers := make([]*captureWriter, n)
	for i := 0; i < n; i++ {
		writers[i] = &captureWriter{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f.ServeDNS(writers[i], httpsQuery("sfh.test"))
		}(i)
	}
	wg.Wait()

	for i, w := range writers {
		if w.msg == nil {
			t.Fatalf("caller %d: ответ не записан", i)
		}
		if w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) == 0 {
			t.Fatalf("caller %d: ожидался NOERROR с HTTPS-записью, rcode=%v answers=%d",
				i, w.msg.Rcode, len(w.msg.Answer))
		}
	}
	if got := c.callCount(); got != 1 {
		t.Fatalf("singleflight non-A: upstream должен вызываться ровно 1 раз, c=%d", got)
	}
	if got := y.callCount(); got != 0 {
		t.Fatalf("non-A путь не должен звать Yandex, y=%d", got)
	}
}

// Каждый вызывающий non-A пути получает СВОЮ копию ответа — мутация одной
// копии не видна другой (общий *dns.Msg из singleflight никому не отдаётся).
func TestHandleNonA_PerCallerCopiesIndependent(t *testing.T) {
	c := &mockResolver{resp: answerHTTPS(t, "cp.test"), delay: 50 * time.Millisecond}
	f := newTestForwarder(matchSet(), &mockResolver{}, c)
	key := cacheKey{name: dns.Fqdn("cp.test"), qtype: dns.TypeHTTPS}

	const n = 4
	var wg sync.WaitGroup
	resps := make([]*dns.Msg, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resps[i], errs[i] = f.handleNonA(context.Background(), httpsQuery("cp.test"), key)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
		if resps[i] == nil {
			t.Fatalf("caller %d: nil-ответ", i)
		}
	}
	if resps[0] == resps[1] {
		t.Fatal("callers должны получать собственные копии, а не общий *dns.Msg")
	}
	resps[0].Answer = nil
	if len(resps[1].Answer) == 0 {
		t.Fatal("мутация копии одного caller'а не должна влиять на копию другого")
	}
}

// Семафор ограничивает одновременные non-A резолвы: при узком тестовом
// семафоре (4) и 16 уникальных HTTPS-именах max in-flight на CF-резолвере
// не превышает 4; запросы сверх лимита ЖДУТ (не дропаются).
func TestHandleNonA_SemaphoreBoundsUpstreamConcurrency(t *testing.T) {
	c := &countingResolver{delay: 30 * time.Millisecond}
	f := newTestForwarder(matchSet(), &countingResolver{}, c)
	const bound = 4
	f.resolveSem = make(chan struct{}, bound) // тестовый узкий семафор

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("h%d.test", i)
			_, errs[i] = f.handleNonA(context.Background(), httpsQuery(name),
				cacheKey{name: dns.Fqdn(name), qtype: dns.TypeHTTPS})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("запрос %d должен дождаться пермита и успешно завершиться: %v", i, err)
		}
	}
	if got := c.maxInflight(); got > bound {
		t.Fatalf("cloudflare non-A: max in-flight %d > семафор %d", got, bound)
	}
}

// Cache-hit non-A пути НЕ проходит через семафор: при семафоре без пермитов
// закэшированный HTTPS-ответ возвращается мгновенно.
func TestHandleNonA_CacheHitSkipsSemaphore(t *testing.T) {
	c := &mockResolver{resp: answerHTTPS(t, "hith.test")}
	f := newTestForwarder(matchSet(), &mockResolver{}, c)
	key := cacheKey{name: dns.Fqdn("hith.test"), qtype: dns.TypeHTTPS}

	// Прогреваем кэш с нормальным семафором.
	if _, err := f.handleNonA(context.Background(), httpsQuery("hith.test"), key); err != nil {
		t.Fatalf("прогрев кэша: %v", err)
	}

	// Семафор без пермитов: любой проход через него завис бы до ctx-таймаута.
	f.resolveSem = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	resp, err := f.handleNonA(ctx, httpsQuery("hith.test"), key)
	if err != nil {
		t.Fatalf("cache hit должен вернуться без семафора: %v", err)
	}
	if resp == nil {
		t.Fatal("cache hit: nil-ответ")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("cache hit должен быть мгновенным, занял %v", elapsed)
	}
}

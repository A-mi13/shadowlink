package dnsproxy

// DNS-L5 (2026-06-12): singleflight по ключу кэша + семафор на upstream-резолвы.
// N конкурентных одинаковых запросов = один dual-resolve (не N×2 с uTLS-
// хендшейками); flood уникальных имён не порождает неограниченные горутины
// с сокетами. Cache-hit и синтетические пути семафор/singleflight не трогают.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// countingResolver — мок, считающий текущую/максимальную одновременную
// глубину Resolve (для проверки семафора).
type countingResolver struct {
	mu    sync.Mutex
	cur   int
	max   int
	delay time.Duration
}

func (r *countingResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	r.mu.Lock()
	r.cur++
	if r.cur > r.max {
		r.max = r.cur
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.cur--
		r.mu.Unlock()
	}()

	select {
	case <-time.After(r.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	out := new(dns.Msg)
	out.SetReply(q)
	rr, err := dns.NewRR(q.Question[0].Name + " 60 IN A 198.51.100.1")
	if err != nil {
		return nil, err
	}
	out.Answer = append(out.Answer, rr)
	return out, nil
}

func (r *countingResolver) maxInflight() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.max
}

// Конкурентные ИДЕНТИЧНЫЕ запросы сливаются в один dual-resolve; каждый
// вызывающий получает СВОЮ копию ответа (общий *dns.Msg никому не отдаётся —
// per-client мутации в ServeDNS на общем msg были бы гонкой).
func TestHandleQuery_Singleflight_DedupsConcurrentIdentical(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "sf.test", "89.221.226.6"), delay: 100 * time.Millisecond}
	c := &mockResolver{resp: answerA(t, "sf.test", "104.18.41.41"), delay: 100 * time.Millisecond}
	f := newTestForwarder(matchSet("89.221.226.6"), y, c)
	key := cacheKey{name: dns.Fqdn("sf.test"), qtype: dns.TypeA}

	const n = 8
	var wg sync.WaitGroup
	resps := make([]*dns.Msg, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resps[i], errs[i] = f.handleQuery(context.Background(), aQuery("sf.test"), key)
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
	if y.callCount() != 1 || c.callCount() != 1 {
		t.Fatalf("singleflight: upstream должен вызываться ровно 1 раз, y=%d c=%d", y.callCount(), c.callCount())
	}

	// Независимость копий: указатели различны, мутация одной не видна другой.
	if resps[0] == resps[1] {
		t.Fatal("callers должны получать собственные копии, а не общий *dns.Msg")
	}
	resps[0].Answer = nil
	if len(resps[1].Answer) == 0 {
		t.Fatal("мутация копии одного caller'а не должна влиять на копию другого")
	}
	if got := firstA(t, resps[1]); got != "104.18.41.41" {
		t.Fatalf("копия второго caller'а повреждена: ожидался 104.18.41.41, получен %s", got)
	}
}

// Семафор ограничивает число ОДНОВРЕМЕННЫХ upstream-резолвов: при узком
// тестовом семафоре (4) и 16 уникальных именах max in-flight на каждом
// резолвере не превышает 4; запросы сверх лимита ЖДУТ (не дропаются).
func TestHandleQuery_SemaphoreBoundsUpstreamConcurrency(t *testing.T) {
	y := &countingResolver{delay: 30 * time.Millisecond}
	c := &countingResolver{delay: 30 * time.Millisecond}
	f := newTestForwarder(matchSet(), y, c)
	const bound = 4
	f.resolveSem = make(chan struct{}, bound) // тестовый узкий семафор

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("u%d.test", i)
			_, errs[i] = f.handleQuery(context.Background(), aQuery(name),
				cacheKey{name: dns.Fqdn(name), qtype: dns.TypeA})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("запрос %d должен дождаться пермита и успешно завершиться: %v", i, err)
		}
	}
	if got := y.maxInflight(); got > bound {
		t.Fatalf("yandex: max in-flight %d > семафор %d", got, bound)
	}
	if got := c.maxInflight(); got > bound {
		t.Fatalf("cloudflare: max in-flight %d > семафор %d", got, bound)
	}
}

// Дефолтная ёмкость семафора — именованная константа (64).
func TestNewForwarder_SemaphoreDefaultCapacity(t *testing.T) {
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(&mockResolver{}, &mockResolver{}))
	if f.resolveSem == nil {
		t.Fatal("NewForwarder должен инициализировать семафор резолвов")
	}
	if got := cap(f.resolveSem); got != maxConcurrentResolves {
		t.Fatalf("ёмкость семафора: ожидалось %d, получено %d", maxConcurrentResolves, got)
	}
}

// Cache-hit путь НЕ проходит через семафор: при семафоре без пермитов
// закэшированный ответ возвращается мгновенно.
func TestHandleQuery_CacheHitSkipsSemaphore(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "hit.test", "89.221.226.6")}
	c := &mockResolver{resp: answerA(t, "hit.test", "104.18.41.41")}
	f := newTestForwarder(matchSet("89.221.226.6"), y, c)
	key := cacheKey{name: dns.Fqdn("hit.test"), qtype: dns.TypeA}

	// Прогреваем кэш с нормальным семафором.
	if _, err := f.handleQuery(context.Background(), aQuery("hit.test"), key); err != nil {
		t.Fatalf("прогрев кэша: %v", err)
	}

	// Семафор без пермитов: любой проход через него завис бы до ctx-таймаута.
	f.resolveSem = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	resp, err := f.handleQuery(ctx, aQuery("hit.test"), key)
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

// Синтетические пути (AAAA NODATA, DoH-pin, FormErr) не трогают ни семафор,
// ни upstream: при семафоре без пермитов все три отвечают сразу.
func TestServeDNS_SyntheticPathsSkipSemaphore(t *testing.T) {
	y := &mockResolver{}
	c := &mockResolver{}
	f := newTestForwarder(matchSet(), y, c)
	f.resolveSem = make(chan struct{}) // нет пермитов

	w1 := &captureWriter{}
	f.ServeDNS(w1, aaaaQuery("x.test"))
	if w1.msg == nil || w1.msg.Rcode != dns.RcodeSuccess {
		t.Fatal("AAAA NODATA должен отвечать без семафора")
	}

	w2 := &captureWriter{}
	f.ServeDNS(w2, aQuery("cloudflare-dns.com"))
	if w2.msg == nil || firstA(t, w2.msg) != "1.1.1.1" {
		t.Fatal("DoH-pin должен отвечать без семафора")
	}

	w3 := &captureWriter{}
	f.ServeDNS(w3, new(dns.Msg)) // без Question → FormErr
	if w3.msg == nil || w3.msg.Rcode != dns.RcodeFormatError {
		t.Fatal("FormErr должен отвечать без семафора")
	}

	if y.callCount() != 0 || c.callCount() != 0 {
		t.Fatalf("синтетические пути не должны звать upstream: y=%d c=%d", y.callCount(), c.callCount())
	}
}

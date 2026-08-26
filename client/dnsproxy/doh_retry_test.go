package dnsproxy

// Единственная точка отказа DoH, пункт 2 (2026-08-26): один ретрай на
// ТРАНСПОРТНОЙ ошибке DoH.
//
// До правки dohResolver.Resolve делал ровно один вызов DoHQueryRawWith и
// возвращал ошибку сразу (upstream.go:123-125). Любой единичный RST на
// TLS-хендшейке (ровно то, что РКН начал делать с DoH в августе 2026) убивал
// весь DNS-запрос, хотя вторая попытка по второму апстриму прошла бы.
//
// Ключевое различие, которое эти тесты и держат: ретрай допустим ТОЛЬКО на
// транспортном отказе. Валидный DNS-ответ с любым Rcode (NXDOMAIN / NODATA /
// даже SERVFAIL) — это УСПЕХ уровня транспорта (DNS-H1, ech.go): решение о том,
// что делать с rcode, принимает лестница в proxy.go, а не резолвер. Ретрай на
// NXDOMAIN удваивал бы трафик к origin на каждом несуществующем имени (браузеры
// генерируют их пачками) и ничего бы не чинил.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// scriptedTransport — DoH-транспорт, отдающий заранее заданную
// последовательность исходов (по одному на попытку). Позволяет отличить
// «сколько раз позвали» от «что вернули», чего mockResolver не умеет: он
// отдаёт один и тот же исход на каждый вызов.
type scriptedTransport struct {
	mu    sync.Mutex
	calls int
	// outcomes[i] — исход i-й попытки; за пределами списка берётся последний.
	outcomes []dohOutcome
	// upstreams фиксирует, к какому апстриму шла каждая попытка (индекс вызова
	// → метка апстрима). Нужен для проверки, что ретрай уходит на ВТОРОЙ
	// резолвер, а не долбит первый.
	upstreams []string
}

type dohOutcome struct {
	msg *dns.Msg
	err error
}

func (s *scriptedTransport) query(_ context.Context, q *dns.Msg, upstream string) (*dns.Msg, error) {
	s.mu.Lock()
	i := s.calls
	s.calls++
	s.upstreams = append(s.upstreams, upstream)
	s.mu.Unlock()

	if len(s.outcomes) == 0 {
		return nil, errors.New("scriptedTransport: пустой сценарий")
	}
	out := s.outcomes[len(s.outcomes)-1]
	if i < len(s.outcomes) {
		out = s.outcomes[i]
	}
	if out.err != nil {
		return nil, out.err
	}
	resp := out.msg.Copy()
	rc := resp.Rcode
	resp.SetReply(q)
	resp.Rcode = rc
	return resp, nil
}

func (s *scriptedTransport) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *scriptedTransport) upstreamAt(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.upstreams) {
		return ""
	}
	return s.upstreams[i]
}

// newScriptedDoHResolver собирает dohResolver поверх сценария — минуя реальный
// uTLS-клиент и сеть.
func newScriptedDoHResolver(t *testing.T, s *scriptedTransport) *dohResolver {
	t.Helper()
	return &dohResolver{
		query:     s.query,
		upstreams: testDoHUpstreams(),
	}
}

// testDoHUpstreams — два апстрима для тестов (значения не важны, важно, что их
// два и они различимы).
func testDoHUpstreams() []dohUpstream {
	return []dohUpstream{
		{ip: "1.1.1.1", sni: "cloudflare-dns.com", label: "primary"},
		{ip: "9.9.9.9", sni: "dns.quad9.net", label: "secondary"},
	}
}

// ТРАНСПОРТНАЯ ошибка первой попытки → ровно ОДИН ретрай, и он уходит на ВТОРОЙ
// апстрим. Именно ради смены апстрима ретрай и существует: повтор к тому же
// зарезанному эндпоинту воспроизвёл бы тот же RST.
func TestDoHResolver_TransportError_RetriesOnceOnSecondUpstream(t *testing.T) {
	s := &scriptedTransport{outcomes: []dohOutcome{
		{err: errors.New("doh query failed: connection reset by peer")},
		{msg: answerA(t, "site.test", "104.18.41.41")},
	}}
	r := newScriptedDoHResolver(t, s)

	resp, err := r.Resolve(context.Background(), aQuery("site.test"))
	if err != nil {
		t.Fatalf("после успешного ретрая ошибки быть не должно: %v", err)
	}
	if resp == nil {
		t.Fatal("после успешного ретрая ожидался ответ")
	}
	if got := firstA(t, resp); got != "104.18.41.41" {
		t.Fatalf("ожидался ответ второй попытки, получен %s", got)
	}
	if got := s.callCount(); got != 2 {
		t.Fatalf("ожидалось ровно 2 попытки (первая + один ретрай), получено %d", got)
	}
	if got := s.upstreamAt(0); got != "primary" {
		t.Fatalf("первая попытка должна идти на основной апстрим, пошла на %q", got)
	}
	if got := s.upstreamAt(1); got != "secondary" {
		t.Fatalf("ретрай должен уходить на ВТОРОЙ апстрим (иначе повторится тот же "+
			"рез на хендшейке), пошёл на %q", got)
	}
}

// Транспортная ошибка на ОБЕИХ попытках → ошибка наружу, и попыток ровно 2
// (ретрай ОДИН, а не лестница): бюджет overallTimeout 4s не резиновый.
func TestDoHResolver_BothTransportErrors_FailsAfterExactlyTwoAttempts(t *testing.T) {
	s := &scriptedTransport{outcomes: []dohOutcome{
		{err: errors.New("doh query failed: connection reset by peer")},
		{err: errors.New("doh query failed: i/o timeout")},
	}}
	r := newScriptedDoHResolver(t, s)

	if _, err := r.Resolve(context.Background(), aQuery("site.test")); err == nil {
		t.Fatal("при отказе обоих апстримов ожидалась ошибка")
	}
	if got := s.callCount(); got != 2 {
		t.Fatalf("ретрай должен быть ровно ОДИН (2 попытки всего), получено %d", got)
	}
}

// ГЛАВНЫЙ инвариант: NXDOMAIN — это УСПЕХ уровня транспорта (DNS-H1). Ретрая
// быть не должно, ответ пропагируется как есть. Ретрай здесь удваивал бы
// трафик к origin на каждом несуществующем имени.
func TestDoHResolver_NXDOMAIN_NoRetry(t *testing.T) {
	nx := nxdomainMsg(t, "nope.test", dns.TypeA, 3600, 300)
	s := &scriptedTransport{outcomes: []dohOutcome{
		{msg: nx},
		{msg: answerA(t, "nope.test", "1.2.3.4")}, // не должно быть достигнуто
	}}
	r := newScriptedDoHResolver(t, s)

	resp, err := r.Resolve(context.Background(), aQuery("nope.test"))
	if err != nil {
		t.Fatalf("NXDOMAIN — валидный ответ, не ошибка: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("NXDOMAIN должен пропагироваться как есть, получено %+v", resp)
	}
	if got := s.callCount(); got != 1 {
		t.Fatalf("на валидном DNS-ответе (NXDOMAIN) ретрая быть НЕ должно, попыток %d", got)
	}
}

// NOERROR-NODATA (пустой Answer) — тоже валидный ответ уровня транспорта.
func TestDoHResolver_NODATA_NoRetry(t *testing.T) {
	nodata := new(dns.Msg)
	nodata.SetQuestion(dns.Fqdn("empty.test"), dns.TypeA)
	nodata.Response = true
	nodata.Rcode = dns.RcodeSuccess // Answer пуст

	s := &scriptedTransport{outcomes: []dohOutcome{
		{msg: nodata},
		{msg: answerA(t, "empty.test", "1.2.3.4")},
	}}
	r := newScriptedDoHResolver(t, s)

	resp, err := r.Resolve(context.Background(), aQuery("empty.test"))
	if err != nil {
		t.Fatalf("NODATA — валидный ответ: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("NODATA должен пропагироваться как есть, получено %+v", resp)
	}
	if got := s.callCount(); got != 1 {
		t.Fatalf("на NODATA ретрая быть НЕ должно, попыток %d", got)
	}
}

// SERVFAIL от апстрима — тоже валидный DNS-ответ на уровне ТРАНСПОРТА, и
// ретраить его здесь нельзя. Отказом его признаёт лестница (usableRcode в
// proxy.go), а не резолвер. Тест держит именно границу ответственности:
// «плохой rcode» и «транспорт не доехал» — разные вещи.
func TestDoHResolver_SERVFAIL_NoRetry(t *testing.T) {
	sf := new(dns.Msg)
	sf.SetQuestion(dns.Fqdn("bad.test"), dns.TypeA)
	sf.Response = true
	sf.Rcode = dns.RcodeServerFailure

	s := &scriptedTransport{outcomes: []dohOutcome{
		{msg: sf},
		{msg: answerA(t, "bad.test", "1.2.3.4")},
	}}
	r := newScriptedDoHResolver(t, s)

	resp, err := r.Resolve(context.Background(), aQuery("bad.test"))
	if err != nil {
		t.Fatalf("SERVFAIL возвращается как ответ, а не как ошибка резолвера: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("SERVFAIL должен пропагироваться в лестницу как есть, получено %+v", resp)
	}
	if got := s.callCount(); got != 1 {
		t.Fatalf("на SERVFAIL резолвер ретраить НЕ должен (это решает лестница), попыток %d", got)
	}
}

// Отменённый/истёкший ctx НЕ должен тратить вторую попытку: бюджет уже исчерпан,
// ретрай гарантированно упрётся в тот же дедлайн и только задержит SERVFAIL.
func TestDoHResolver_ContextExpired_DoesNotRetry(t *testing.T) {
	s := &scriptedTransport{outcomes: []dohOutcome{
		{err: context.DeadlineExceeded},
		{msg: answerA(t, "slow.test", "1.2.3.4")},
	}}
	r := newScriptedDoHResolver(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // бюджет исчерпан ещё до вызова

	if _, err := r.Resolve(ctx, aQuery("slow.test")); err == nil {
		t.Fatal("при отменённом ctx ожидалась ошибка")
	}
	if got := s.callCount(); got > 1 {
		t.Fatalf("при исчерпанном бюджете ретрая быть не должно, попыток %d", got)
	}
}

// Ретрай обязан УКЛАДЫВАТЬСЯ В БЮДЖЕТ вызывающего. Лестница даёт резолверу
// perUpstreamTimeout (3s) внутри overallTimeout (4s); если бы обе попытки
// делили этот бюджет поровну без учёта дедлайна, вторая попытка на медленном
// апстриме гарантированно упиралась бы в overall и клиент получал бы SERVFAIL
// на 4-й секунде вместо честного ответа.
//
// Здесь проверяется поведенческое свойство: при ctx с коротким дедлайном
// Resolve возвращается ДО его истечения, а не после.
func TestDoHResolver_RetryRespectsCallerDeadline(t *testing.T) {
	const budget = 300 * time.Millisecond
	s := &scriptedTransport{outcomes: []dohOutcome{
		{err: errors.New("doh query failed: connection reset by peer")},
		{err: errors.New("doh query failed: connection reset by peer")},
	}}
	r := newScriptedDoHResolver(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	_, err := r.Resolve(ctx, aQuery("site.test"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("при отказе обоих апстримов ожидалась ошибка")
	}
	if elapsed > budget {
		t.Fatalf("Resolve с ретраем вышел за бюджет вызывающего: %v > %v", elapsed, budget)
	}
}

package dnsproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockResolver реализует Resolver: возвращает заданный ответ/ошибку и считает
// число вызовов (для проверки кэша и того, что AAAA не резолвится upstream'ом).
type mockResolver struct {
	mu    sync.Mutex
	resp  *dns.Msg
	err   error
	calls int
	// delay имитирует медленный upstream (для проверки конкурентности/таймаутов).
	delay time.Duration
	// lastQ — последний запрос, как его увидел upstream (DNS-M2c: проверка
	// прикрепления нашего EDNS0 к upstream-копии).
	lastQ *dns.Msg
}

func (m *mockResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m.mu.Lock()
	m.calls++
	m.lastQ = q
	delay := m.delay
	m.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.err != nil {
		return nil, m.err
	}
	// Возвращаем копию с подставленным вопросом запроса, как настоящий резолвер.
	// SetReply трогает только header/question — Answer первой копии остаётся валиден.
	// SetReply сбрасывает Rcode в Success — восстанавливаем его, как делает
	// настоящий резолвер (NXDOMAIN/SERVFAIL в моках должны доходить до лестницы).
	out := m.resp.Copy()
	rc := out.Rcode
	out.SetReply(q)
	out.Rcode = rc
	return out, nil
}

func (m *mockResolver) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// lastQuery возвращает последний запрос, переданный в Resolve (DNS-M2c).
func (m *mockResolver) lastQuery() *dns.Msg {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastQ
}

// answerA строит ответ-сообщение с A-записями (для мок-резолверов).
func answerA(t *testing.T, name string, ips ...string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	for _, ip := range ips {
		rr, err := dns.NewRR(dns.Fqdn(name) + " 60 IN A " + ip)
		if err != nil {
			t.Fatalf("не удалось собрать A-запись %q: %v", ip, err)
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}

// matchSet — снапшот-matcher над фиксированным множеством IP.
func matchSet(ips ...string) snapshotMatcher {
	set := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		set[netip.MustParseAddr(ip)] = true
	}
	return func(a netip.Addr) bool { return set[a] }
}

// captureWriter — минимальный мок dns.ResponseWriter, захватывает WriteMsg.
type captureWriter struct {
	msg *dns.Msg
}

func (w *captureWriter) LocalAddr() net.Addr        { return nil }
func (w *captureWriter) RemoteAddr() net.Addr       { return nil }
func (w *captureWriter) WriteMsg(m *dns.Msg) error  { w.msg = m; return nil }
func (w *captureWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *captureWriter) Close() error               { return nil }
func (w *captureWriter) TsigStatus() error          { return nil }
func (w *captureWriter) TsigTimersOnly(bool)        {}
func (w *captureWriter) Hijack()                    {}

// newTestForwarder собирает forwarder с мок-резолверами и заданным matcher'ом.
func newTestForwarder(match snapshotMatcher, yandex, cloudflare Resolver) *Forwarder {
	f := &Forwarder{
		listen:             "127.0.0.1:0",
		match:              match,
		yandex:             yandex,
		cloudflare:         cloudflare,
		cache:              newDNSCache(),
		perUpstreamTimeout: 3 * time.Second,
		overallTimeout:     4 * time.Second,
		resolveSem:         make(chan struct{}, maxConcurrentResolves),
	}
	return f
}

func aQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return q
}

func aaaaQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	return q
}

func firstA(t *testing.T, m *dns.Msg) string {
	t.Helper()
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	t.Fatalf("в ответе нет A-записи: %+v", m)
	return ""
}

// 1. A, оба ок, ветка censored (LinkedIn): Yandex→стаб в snapshot, CF→реальный CDN.
func TestServeDNS_A_BranchCensored(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "linkedin.test", "89.221.226.6")}
	c := &mockResolver{resp: answerA(t, "linkedin.test", "104.18.41.41")}
	f := newTestForwarder(match, y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("linkedin.test"))
	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	if got := firstA(t, w.msg); got != "104.18.41.41" {
		t.Fatalf("ветка censored: ожидался CF IP 104.18.41.41, получен %s", got)
	}
	// Наблюдаемость: censored-ветка должна инкрементить только свой счётчик.
	if y, censored, foreign, geo := f.BranchCounts(); censored != 1 || y != 0 || foreign != 0 || geo != 0 {
		t.Fatalf("BranchCounts после censored: ожидалось (0,1,0,0), получено (%d,%d,%d,%d)", y, censored, foreign, geo)
	}
}

// 2. A, оба ок, ветка Yandex (RU honest): совпадающие IP в snapshot → Yandex.
func TestServeDNS_A_BranchYandex(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "ya.test", "87.250.250.242")}
	c := &mockResolver{resp: answerA(t, "ya.test", "87.250.250.242")}
	f := newTestForwarder(match, y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("ya.test"))
	if got := firstA(t, w.msg); got != "87.250.250.242" {
		t.Fatalf("ветка Yandex: ожидался 87.250.250.242, получен %s", got)
	}
	// Наблюдаемость: yandex-ветка должна инкрементить только свой счётчик.
	if y, censored, foreign, geo := f.BranchCounts(); y != 1 || censored != 0 || foreign != 0 || geo != 0 {
		t.Fatalf("BranchCounts после yandex: ожидалось (1,0,0,0), получено (%d,%d,%d,%d)", y, censored, foreign, geo)
	}
}

// 3. A, оба ок, foreign → CF.
func TestServeDNS_A_BranchForeign(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "google.test", "142.250.1.1")}
	c := &mockResolver{resp: answerA(t, "google.test", "142.250.1.2")}
	f := newTestForwarder(match, y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("google.test"))
	if got := firstA(t, w.msg); got != "142.250.1.2" {
		t.Fatalf("ветка foreign: ожидался CF 142.250.1.2, получен %s", got)
	}
}

// 4. AAAA → пустой NOERROR; резолверы не вызываются.
func TestServeDNS_AAAA_EmptyNOERROR(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "x.test", "1.2.3.4")}
	c := &mockResolver{resp: answerA(t, "x.test", "5.6.7.8")}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aaaaQuery("x.test"))
	if w.msg == nil {
		t.Fatal("ответ AAAA не записан")
	}
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA: ожидался RcodeSuccess (NODATA), получен %v", w.msg.Rcode)
	}
	if len(w.msg.Answer) != 0 {
		t.Fatalf("AAAA: ожидался пустой Answer, получено %d записей", len(w.msg.Answer))
	}
	if !w.msg.RecursionAvailable {
		t.Fatal("AAAA: ожидался RecursionAvailable=true")
	}
	if y.callCount() != 0 || c.callCount() != 0 {
		t.Fatalf("AAAA: резолверы НЕ должны вызываться, y=%d c=%d", y.callCount(), c.callCount())
	}
}

// 5. Yandex fail, CF ok → CF.
func TestHandleQuery_YandexFail_CFok(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{err: errors.New("yandex down")}
	c := &mockResolver{resp: answerA(t, "site.test", "104.18.41.41")}
	f := newTestForwarder(match, y, c)

	resp, err := f.handleQuery(context.Background(), aQuery("site.test"), cacheKey{name: dns.Fqdn("site.test"), qtype: dns.TypeA})
	if err != nil {
		t.Fatalf("ожидался успех (CF), получена ошибка: %v", err)
	}
	if got := firstA(t, resp); got != "104.18.41.41" {
		t.Fatalf("Yandex fail/CF ok: ожидался 104.18.41.41, получен %s", got)
	}
}

// 6. CF fail, Yandex ok & RU-classified → Yandex.
func TestHandleQuery_CFfail_YandexRU(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "ya.test", "87.250.250.242")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(match, y, c)

	resp, err := f.handleQuery(context.Background(), aQuery("ya.test"), cacheKey{name: dns.Fqdn("ya.test"), qtype: dns.TypeA})
	if err != nil {
		t.Fatalf("ожидался успех (Yandex RU), получена ошибка: %v", err)
	}
	if got := firstA(t, resp); got != "87.250.250.242" {
		t.Fatalf("CF fail/Yandex RU: ожидался 87.250.250.242, получен %s", got)
	}
}

// 7. CF fail, Yandex ok & НЕ RU-classified → SERVFAIL (err).
func TestHandleQuery_CFfail_YandexForeign_SERVFAIL(t *testing.T) {
	match := matchSet("87.250.250.242") // ya IP, не совпадает с ответом
	y := &mockResolver{resp: answerA(t, "google.test", "142.250.1.1")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(match, y, c)

	_, err := f.handleQuery(context.Background(), aQuery("google.test"), cacheKey{name: dns.Fqdn("google.test"), qtype: dns.TypeA})
	if err == nil {
		t.Fatal("CF fail/Yandex foreign: ожидалась ошибка (SERVFAIL), получен nil")
	}
}

// 8. Оба fail → SERVFAIL.
func TestHandleQuery_BothFail_SERVFAIL(t *testing.T) {
	y := &mockResolver{err: errors.New("y down")}
	c := &mockResolver{err: errors.New("c down")}
	f := newTestForwarder(matchSet(), y, c)

	_, err := f.handleQuery(context.Background(), aQuery("x.test"), cacheKey{name: dns.Fqdn("x.test"), qtype: dns.TypeA})
	if err == nil {
		t.Fatal("оба fail: ожидалась ошибка (SERVFAIL), получен nil")
	}
}

// ServeDNS при SERVFAIL пишет ответ с Rcode=ServerFailure (клиент не висит).
func TestServeDNS_BothFail_WritesSERVFAIL(t *testing.T) {
	y := &mockResolver{err: errors.New("y down")}
	c := &mockResolver{err: errors.New("c down")}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("x.test"))
	if w.msg == nil {
		t.Fatal("ответ не записан при ошибке")
	}
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("ожидался SERVFAIL, получен %v", w.msg.Rcode)
	}
}

// 9. cache hit: первый запрос резолвит, второй идентичный — из кэша.
func TestHandleQuery_CacheHit(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "site.test", "89.221.226.6")}
	c := &mockResolver{resp: answerA(t, "site.test", "104.18.41.41")}
	f := newTestForwarder(match, y, c)

	key := cacheKey{name: dns.Fqdn("site.test"), qtype: dns.TypeA}
	if _, err := f.handleQuery(context.Background(), aQuery("site.test"), key); err != nil {
		t.Fatalf("первый запрос: %v", err)
	}
	yc1, cc1 := y.callCount(), c.callCount()
	if yc1 == 0 || cc1 == 0 {
		t.Fatalf("первый запрос должен дёрнуть оба резолвера, y=%d c=%d", yc1, cc1)
	}

	if _, err := f.handleQuery(context.Background(), aQuery("site.test"), key); err != nil {
		t.Fatalf("второй запрос: %v", err)
	}
	if y.callCount() != yc1 || c.callCount() != cc1 {
		t.Fatalf("второй запрос должен быть из кэша (без вызовов): y %d→%d c %d→%d",
			yc1, y.callCount(), cc1, c.callCount())
	}
}

// 10. Нет Question → не паника, ответ с ошибкой.
func TestServeDNS_NoQuestion(t *testing.T) {
	f := newTestForwarder(matchSet(), &mockResolver{}, &mockResolver{})
	w := &captureWriter{}
	r := new(dns.Msg)
	r.Id = 42
	f.ServeDNS(w, r) // не должно паниковать
	if w.msg == nil {
		t.Fatal("ответ на пустой вопрос не записан")
	}
	if w.msg.Rcode == dns.RcodeSuccess {
		t.Fatalf("на запрос без вопроса ожидалась ошибка, получен %v", w.msg.Rcode)
	}
}

// Не-A/не-AAAA (например MX) форвардится на Cloudflare без арбитража, но кэшируется.
func TestServeDNS_MX_ForwardsToCloudflare(t *testing.T) {
	mx := new(dns.Msg)
	mx.SetQuestion(dns.Fqdn("mail.test"), dns.TypeMX)
	mx.Response = true
	rr, err := dns.NewRR("mail.test. 60 IN MX 10 mx.mail.test.")
	if err != nil {
		t.Fatalf("MX RR: %v", err)
	}
	mx.Answer = append(mx.Answer, rr)

	y := &mockResolver{resp: answerA(t, "mail.test", "1.2.3.4")}
	c := &mockResolver{resp: mx}
	f := newTestForwarder(matchSet(), y, c)

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn("mail.test"), dns.TypeMX)
	w := &captureWriter{}
	f.ServeDNS(w, q)
	if w.msg == nil || len(w.msg.Answer) == 0 {
		t.Fatal("MX: ответ не записан")
	}
	if _, ok := w.msg.Answer[0].(*dns.MX); !ok {
		t.Fatalf("MX: ожидалась MX-запись, получено %T", w.msg.Answer[0])
	}
	if y.callCount() != 0 {
		t.Fatalf("MX: Yandex не должен вызываться (арбитраж только для A), y=%d", y.callCount())
	}
	// Второй запрос — из кэша.
	cc := c.callCount()
	q2 := new(dns.Msg)
	q2.SetQuestion(dns.Fqdn("mail.test"), dns.TypeMX)
	f.ServeDNS(&captureWriter{}, q2)
	if c.callCount() != cc {
		t.Fatalf("MX: второй запрос должен быть из кэша, c %d→%d", cc, c.callCount())
	}
}

// B1 слой 2: A-запрос на ИМЯ DoH-резолвера (cloudflare-dns.com) должен сразу
// вернуть пиннутый 1.1.1.1 БЕЗ вызова резолверов — разрыв DoH-петли.
func TestServeDNS_DoHResolverName_PinnedNoUpstream(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "cloudflare-dns.com", "9.9.9.9")}
	c := &mockResolver{resp: answerA(t, "cloudflare-dns.com", "9.9.9.9")}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("cloudflare-dns.com"))
	if w.msg == nil {
		t.Fatal("ответ на cloudflare-dns.com не записан")
	}
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("ожидался NOERROR, получен %v", w.msg.Rcode)
	}
	if got := firstA(t, w.msg); got != "1.1.1.1" {
		t.Fatalf("guard: ожидался пиннутый 1.1.1.1, получен %s", got)
	}
	// Должны присутствовать обе пиннутые A-записи (1.1.1.1 + 1.0.0.1).
	if len(w.msg.Answer) != len(dohResolverIPs) {
		t.Fatalf("ожидалось %d A-записей, получено %d", len(dohResolverIPs), len(w.msg.Answer))
	}
	// КЛЮЧЕВОЕ: ни один upstream не вызван (иначе петля).
	if y.callCount() != 0 || c.callCount() != 0 {
		t.Fatalf("guard: резолверы НЕ должны вызываться, y=%d c=%d", y.callCount(), c.callCount())
	}
}

// B1 слой 2: проверка регистронезависимости имени (CLOUDFLARE-DNS.COM.).
func TestServeDNS_DoHResolverName_CaseInsensitive(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "cloudflare-dns.com", "9.9.9.9")}
	c := &mockResolver{resp: answerA(t, "cloudflare-dns.com", "9.9.9.9")}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("CLOUDFLARE-DNS.COM"))
	if got := firstA(t, w.msg); got != "1.1.1.1" {
		t.Fatalf("guard (upper-case): ожидался 1.1.1.1, получен %s", got)
	}
	if y.callCount() != 0 || c.callCount() != 0 {
		t.Fatalf("guard (upper-case): резолверы не должны вызываться, y=%d c=%d", y.callCount(), c.callCount())
	}
}

// N2: DefaultYandexIPs — единый источник истины; defaultYandexServers выводятся
// из него добавлением порта.
func TestDefaultYandexIPs_SourceOfTruth(t *testing.T) {
	ips := DefaultYandexIPs()
	want := []string{"77.88.8.8", "77.88.8.1"}
	if !reflect.DeepEqual(ips, want) {
		t.Fatalf("DefaultYandexIPs drift: got=%v want=%v", ips, want)
	}
	// defaultYandexServers = IP + ":53" в том же порядке.
	wantServers := []string{"77.88.8.8:53", "77.88.8.1:53"}
	if !reflect.DeepEqual(defaultYandexServers, wantServers) {
		t.Fatalf("defaultYandexServers drift: got=%v want=%v", defaultYandexServers, wantServers)
	}
	// Возврат — копия (мутация вызывающим не влияет на источник).
	ips[0] = "0.0.0.0"
	if DefaultYandexIPs()[0] != "77.88.8.8" {
		t.Fatal("DefaultYandexIPs должен возвращать копию (источник мутирован)")
	}
}

// Start/Stop smoke на реальном эфемерном сокете (идемпотентность Stop).
func TestForwarder_StartStop(t *testing.T) {
	f := NewForwarder("127.0.0.1:0", nil,
		WithResolvers(&mockResolver{resp: answerA(t, "x.test", "1.2.3.4")},
			&mockResolver{resp: answerA(t, "x.test", "5.6.7.8")}))
	if err := f.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Повторный Start идемпотентен (не должен падать/дублировать).
	if err := f.Start(); err != nil {
		t.Fatalf("повторный Start: %v", err)
	}
	if err := f.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Повторный Stop идемпотентен.
	if err := f.Stop(); err != nil {
		t.Fatalf("повторный Stop: %v", err)
	}
}

// I2: branch-log горутина стартует в Start и гаснет в Stop без паники/leak.
// Stop дожидается выхода горутины (WaitGroup) — повторный Start/Stop безопасен.
func TestForwarder_BranchLogGoroutine_StartStop(t *testing.T) {
	f := NewForwarder("127.0.0.1:0", nil,
		WithResolvers(&mockResolver{}, &mockResolver{}))

	if err := f.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// После Start канал должен существовать (горутина запущена).
	f.mu.Lock()
	stop := f.branchLogStop
	f.mu.Unlock()
	if stop == nil {
		t.Fatal("branchLogStop должен быть установлен после Start")
	}

	// Stop гасит горутину и ждёт её — не должно зависнуть/паниковать.
	if err := f.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	f.mu.Lock()
	if f.branchLogStop != nil {
		f.mu.Unlock()
		t.Fatal("branchLogStop должен быть nil после Stop")
	}
	f.mu.Unlock()

	// Повторный Stop — no-op (stop уже nil, без double-close паники).
	if err := f.Stop(); err != nil {
		t.Fatalf("повторный Stop: %v", err)
	}

	// Перезапуск после Stop поднимает новую горутину чисто.
	if err := f.Start(); err != nil {
		t.Fatalf("повторный Start: %v", err)
	}
	if err := f.Stop(); err != nil {
		t.Fatalf("Stop после restart: %v", err)
	}
}

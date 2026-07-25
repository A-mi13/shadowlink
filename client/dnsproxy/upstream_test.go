package dnsproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// compile-time interface implementation checks.
var (
	_ Resolver = (*plainUDPResolver)(nil)
	_ Resolver = (*dohResolver)(nil)
)

// startStubDNS launches a local UDP dns.Server that answers an A query for
// answerName with answerIP. It returns the bound "host:port" address and a
// shutdown func. The function blocks until the server is ready to serve.
func startStubDNS(t *testing.T, answerName, answerIP string) (addr string, shutdown func()) {
	t.Helper()

	// Bind a UDP socket on an ephemeral port to learn the address and hand it
	// to the dns.Server via PacketConn (avoids the readiness race).
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не удалось открыть UDP-сокет для stub: %v", err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(answerName, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		rr, rrErr := dns.NewRR(answerName + " 60 IN A " + answerIP)
		if rrErr != nil {
			t.Errorf("не удалось собрать RR: %v", rrErr)
			return
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: mux}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }

	go func() {
		_ = srv.ActivateAndServe()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("stub DNS-сервер не стартовал вовремя")
	}

	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func queryFor(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return q
}

func TestPlainUDPResolver_Resolve(t *testing.T) {
	const name = "example.test."
	const ip = "203.0.113.7"
	addr, shutdown := startStubDNS(t, name, ip)
	defer shutdown()

	r := newPlainUDPResolver([]string{addr}, 2*time.Second)
	resp, err := r.Resolve(context.Background(), queryFor(name))
	if err != nil {
		t.Fatalf("Resolve вернул ошибку: %v", err)
	}
	if resp == nil {
		t.Fatalf("Resolve вернул nil-ответ без ошибки")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("ожидалась 1 A-запись, получено %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("ответ не является A-записью: %T", resp.Answer[0])
	}
	if a.A.String() != ip {
		t.Fatalf("ожидался IP %s, получен %s", ip, a.A.String())
	}
}

func TestPlainUDPResolver_Failover(t *testing.T) {
	const name = "example.test."
	const ip = "203.0.113.8"
	liveAddr, shutdown := startStubDNS(t, name, ip)
	defer shutdown()

	// Первый сервер — закрытый порт (никто не слушает), второй — живой stub.
	deadAddr := closedUDPAddr(t)

	r := newPlainUDPResolver([]string{deadAddr, liveAddr}, 1*time.Second)
	resp, err := r.Resolve(context.Background(), queryFor(name))
	if err != nil {
		t.Fatalf("ожидался успех со второго сервера, получена ошибка: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("ожидался валидный ответ от живого stub, получено: %+v", resp)
	}
}

func TestPlainUDPResolver_AllDead(t *testing.T) {
	dead1 := closedUDPAddr(t)
	dead2 := closedUDPAddr(t)

	r := newPlainUDPResolver([]string{dead1, dead2}, 500*time.Millisecond)
	resp, err := r.Resolve(context.Background(), queryFor("example.test."))
	if err == nil {
		t.Fatalf("ожидалась ошибка при всех мёртвых серверах, получен nil")
	}
	if resp != nil {
		t.Fatalf("при ошибке ответ должен быть nil, получен %+v", resp)
	}
}

func TestPlainUDPResolver_EmptyServers(t *testing.T) {
	r := newPlainUDPResolver(nil, 500*time.Millisecond)
	resp, err := r.Resolve(context.Background(), queryFor("example.test."))
	if err == nil {
		t.Fatalf("ожидалась ошибка при пустом списке серверов, получен nil")
	}
	if resp != nil {
		t.Fatalf("при ошибке ответ должен быть nil, получен %+v", resp)
	}
}

// dohResolver покрывается только compile-time проверкой интерфейса и
// конструктором: реальный client.DoHQuery захардкожен на cloudflare-dns.com
// и ходит в сеть, изолированно его без рефакторинга не протестировать.
// Поведение DoH покрывается полевым тестом.
func TestNewDoHResolver_NotNil(t *testing.T) {
	if newDoHResolver() == nil {
		t.Fatalf("newDoHResolver вернул nil")
	}
}

// startStubDNSRcode launches a local UDP dns.Server that answers EVERY query
// with the given rcode and no answer records (SERVFAIL/REFUSED/NXDOMAIN stubs
// for the failover tests). Returns the bound address and a shutdown func.
func startStubDNSRcode(t *testing.T, rcode int) (addr string, shutdown func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не удалось открыть UDP-сокет для rcode-stub: %v", err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, rcode)
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: mux}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }

	go func() {
		_ = srv.ActivateAndServe()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("rcode-stub DNS-сервер не стартовал вовремя")
	}

	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

// DNS-L-3: SERVFAIL от первого сервера НЕ считается успехом — failover должен
// дойти до второго (живого) сервера и вернуть его ответ.
func TestPlainUDPResolver_FailoverOnServfail(t *testing.T) {
	const name = "example.test."
	const ip = "203.0.113.9"
	failAddr, shutdownFail := startStubDNSRcode(t, dns.RcodeServerFailure)
	defer shutdownFail()
	liveAddr, shutdownLive := startStubDNS(t, name, ip)
	defer shutdownLive()

	r := newPlainUDPResolver([]string{failAddr, liveAddr}, 1*time.Second)
	resp, err := r.Resolve(context.Background(), queryFor(name))
	if err != nil {
		t.Fatalf("ожидался успех со второго сервера после SERVFAIL первого: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("ожидался валидный ответ от живого stub, получено: %+v", resp)
	}
}

// DNS-L-3: REFUSED тоже триггерит failover.
func TestPlainUDPResolver_FailoverOnRefused(t *testing.T) {
	const name = "example.test."
	const ip = "203.0.113.10"
	refusedAddr, shutdownRefused := startStubDNSRcode(t, dns.RcodeRefused)
	defer shutdownRefused()
	liveAddr, shutdownLive := startStubDNS(t, name, ip)
	defer shutdownLive()

	r := newPlainUDPResolver([]string{refusedAddr, liveAddr}, 1*time.Second)
	resp, err := r.Resolve(context.Background(), queryFor(name))
	if err != nil {
		t.Fatalf("ожидался успех со второго сервера после REFUSED первого: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("ожидался валидный ответ от живого stub, получено: %+v", resp)
	}
}

// DNS-L-3: все серверы вернули SERVFAIL → ошибка (НЕ ответ): для лестницы yOK
// означает «Yandex дал осмысленный ответ» — SERVFAIL-only им не является.
func TestPlainUDPResolver_AllServfail_Error(t *testing.T) {
	fail1, shutdown1 := startStubDNSRcode(t, dns.RcodeServerFailure)
	defer shutdown1()
	fail2, shutdown2 := startStubDNSRcode(t, dns.RcodeServerFailure)
	defer shutdown2()

	r := newPlainUDPResolver([]string{fail1, fail2}, 1*time.Second)
	resp, err := r.Resolve(context.Background(), queryFor("example.test."))
	if err == nil {
		t.Fatal("все SERVFAIL: ожидалась ошибка, получен nil")
	}
	if resp != nil {
		t.Fatalf("при ошибке ответ должен быть nil, получен %+v", resp)
	}
}

// DNS-L-3: NXDOMAIN — валидный ответ (имя не существует), failover НЕ должен
// перескакивать на второй сервер.
func TestPlainUDPResolver_NXDOMAIN_NoFailover(t *testing.T) {
	const name = "example.test."
	nxAddr, shutdownNX := startStubDNSRcode(t, dns.RcodeNameError)
	defer shutdownNX()
	liveAddr, shutdownLive := startStubDNS(t, name, "203.0.113.11")
	defer shutdownLive()

	r := newPlainUDPResolver([]string{nxAddr, liveAddr}, 1*time.Second)
	resp, err := r.Resolve(context.Background(), queryFor(name))
	if err != nil {
		t.Fatalf("NXDOMAIN — валидный ответ, ошибка не ожидалась: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("ожидался NXDOMAIN от первого сервера (без failover), получено: %+v", resp)
	}
}

// closedUDPAddr возвращает адрес "127.0.0.1:port", на котором гарантированно
// никто не слушает (порт занимался эфемерно и сразу освобождён).
func closedUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не удалось зарезервировать порт: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

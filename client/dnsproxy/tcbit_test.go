package dnsproxy

// DNS-M2 (2026-06-12): TC-бит и UDP-лимиты.
// (a) upstream: Truncated по plain-UDP → ретрай по TCP к тому же серверу;
//     при отказе TCP — фолбэк на урезанный UDP-ответ (лучше, чем ничего);
// (b) downstream: перед финальным WriteMsg ответ режется Truncate'ом под
//     UDP-лимит клиента (EDNS0 UDPSize, floor 512; без EDNS0 — 512);
// (c) к upstream-копии запроса без клиентского EDNS0 прикрепляется НАШ
//     EDNS0 OPT (udpsize 1232, без DO) — иначе Yandex ограничен 512 байтами
//     и multi-record ответы реально режутся.

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startStubDNSTruncated поднимает UDP-stub, отвечающий Truncated-ответом
// (partialIPs) на answerName. При withTCP=true на ТОМ ЖЕ порту поднимается
// TCP-stub с полным ответом (fullIPs) — имитация настоящего резолвера,
// который по TCP отдаёт всё. withTCP=false оставляет TCP-порт закрытым
// (фолбэк-тест: TCP-ретрай должен быстро упасть).
func startStubDNSTruncated(t *testing.T, answerName string, partialIPs, fullIPs []string, withTCP bool) (addr string, shutdown func()) {
	t.Helper()

	pc, tcpListener := bindUDPTCPPair(t, withTCP)

	answerWith := func(ips []string, truncated bool) dns.HandlerFunc {
		return func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Truncated = truncated
			for _, ip := range ips {
				rr, rrErr := dns.NewRR(answerName + " 60 IN A " + ip)
				if rrErr != nil {
					t.Errorf("не удалось собрать RR: %v", rrErr)
					return
				}
				m.Answer = append(m.Answer, rr)
			}
			_ = w.WriteMsg(m)
		}
	}

	udpMux := dns.NewServeMux()
	udpMux.HandleFunc(answerName, answerWith(partialIPs, true))
	udpSrv := &dns.Server{PacketConn: pc, Handler: udpMux}
	udpStarted := make(chan struct{})
	udpSrv.NotifyStartedFunc = func() { close(udpStarted) }
	go func() { _ = udpSrv.ActivateAndServe() }()
	select {
	case <-udpStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("UDP TC-stub не стартовал вовремя")
	}

	shutdowns := []func(){func() { _ = udpSrv.Shutdown() }}

	if withTCP {
		l := tcpListener
		tcpMux := dns.NewServeMux()
		tcpMux.HandleFunc(answerName, answerWith(fullIPs, false))
		tcpSrv := &dns.Server{Listener: l, Handler: tcpMux}
		tcpStarted := make(chan struct{})
		tcpSrv.NotifyStartedFunc = func() { close(tcpStarted) }
		go func() { _ = tcpSrv.ActivateAndServe() }()
		select {
		case <-tcpStarted:
		case <-time.After(2 * time.Second):
			t.Fatalf("TCP TC-stub не стартовал вовремя")
		}
		shutdowns = append(shutdowns, func() { _ = tcpSrv.Shutdown() })
	}

	return pc.LocalAddr().String(), func() {
		for _, fn := range shutdowns {
			fn()
		}
	}
}

// bindUDPTCPPair атомарно подбирает пару «UDP + TCP на одном номере порта».
// Нельзя просто забиндить UDP :0 и потом TCP на тот же порт одной попыткой:
// на Windows excluded port ranges (резервы Hyper-V/WinNAT) для UDP и TCP
// РАЗНЫЕ, и TCP-bind на случайно выбранный UDP-порт спорадически падает с
// "access permissions" (полевой флак 2026-06-12). Ретраим подбор пары целиком.
// При withTCP=false возвращается только UDP-сокет (tcpListener == nil).
func bindUDPTCPPair(t *testing.T, withTCP bool) (net.PacketConn, net.Listener) {
	t.Helper()

	const pairAttempts = 20
	var lastErr error
	for attempt := 0; attempt < pairAttempts; attempt++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("не удалось открыть UDP-сокет для TC-stub: %v", err)
		}
		if !withTCP {
			return pc, nil
		}
		l, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, l
		}
		lastErr = err
		_ = pc.Close() // порт не годится для пары — пробуем следующий
	}
	t.Fatalf("не удалось подобрать UDP+TCP пару портов за %d попыток: %v", pairAttempts, lastErr)
	return nil, nil
}

// (a) Truncated-ответ по UDP → ретрай по TCP к тому же серверу, используется
// полный TCP-ответ.
func TestPlainUDPResolver_TCBit_RetriesOverTCP(t *testing.T) {
	const name = "tc.test."
	addr, shutdown := startStubDNSTruncated(t, name,
		[]string{"203.0.113.1"},
		[]string{"203.0.113.1", "203.0.113.2", "203.0.113.3"},
		true)
	defer shutdown()

	r := newPlainUDPResolver([]string{addr}, 2*time.Second)
	resp, err := r.Resolve(context.Background(), queryFor(name))
	if err != nil {
		t.Fatalf("Resolve вернул ошибку: %v", err)
	}
	if resp.Truncated {
		t.Fatal("ожидался полный TCP-ответ без TC-бита")
	}
	if len(resp.Answer) != 3 {
		t.Fatalf("ожидался полный ответ (3 A-записи) с TCP-ретрая, получено %d", len(resp.Answer))
	}
}

// (a) TCP-ретрай упал (порт закрыт) → фолбэк на урезанный UDP-ответ:
// подмножество A-записей лучше, чем SERVFAIL.
func TestPlainUDPResolver_TCBit_TCPFail_FallsBackToTruncated(t *testing.T) {
	const name = "tcfail.test."
	addr, shutdown := startStubDNSTruncated(t, name, []string{"203.0.113.7"}, nil, false)
	defer shutdown()

	r := newPlainUDPResolver([]string{addr}, 1*time.Second)
	resp, err := r.Resolve(context.Background(), queryFor(name))
	if err != nil {
		t.Fatalf("ожидался фолбэк на урезанный UDP-ответ, получена ошибка: %v", err)
	}
	if !resp.Truncated {
		t.Fatal("фолбэк-ответ должен сохранить TC-бит (он урезан)")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("ожидалась 1 A-запись из урезанного UDP-ответа, получено %d", len(resp.Answer))
	}
}

// manyARecords строит ответ с count A-записями — раздувает пакет далеко
// за 512 байт (для downstream-Truncate тестов).
func manyARecords(t *testing.T, name string, count int) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	for i := 0; i < count; i++ {
		ip := fmt.Sprintf("198.51.%d.%d", i/250, i%250+1)
		rr, err := dns.NewRR(dns.Fqdn(name) + " 60 IN A " + ip)
		if err != nil {
			t.Fatalf("не удалось собрать A-запись %q: %v", ip, err)
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}

// (b) Клиент БЕЗ EDNS0 → раздутый ответ режется до 512 байт с TC-битом.
// Раньше WriteMsg либо молча падал (клиент висел до таймаута), либо ответ
// уходил больше, чем клиент способен принять.
func TestServeDNS_TruncatesOversizedAnswerForNonEDNSClient(t *testing.T) {
	big := manyARecords(t, "big.test", 100)
	y := &mockResolver{resp: big}
	c := &mockResolver{resp: big}
	f := newTestForwarder(matchSet(), y, c)

	q := aQuery("big.test") // без EDNS0
	w := &captureWriter{}
	f.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	packed, err := w.msg.Pack()
	if err != nil {
		t.Fatalf("урезанный ответ должен паковаться: %v", err)
	}
	if len(packed) > dns.MinMsgSize {
		t.Fatalf("ответ %d байт > %d для клиента без EDNS0", len(packed), dns.MinMsgSize)
	}
	if !w.msg.Truncated {
		t.Fatal("TC-бит должен быть выставлен при урезании ответа")
	}
}

// (b) Клиент С EDNS0 и большим буфером (4096) → ответ НЕ режется.
func TestServeDNS_NoTruncateForEDNSClientWithLargeBuffer(t *testing.T) {
	big := manyARecords(t, "big.test", 100)
	y := &mockResolver{resp: big}
	c := &mockResolver{resp: big}
	f := newTestForwarder(matchSet(), y, c)

	q := aQuery("big.test")
	q.SetEdns0(4096, false)
	w := &captureWriter{}
	f.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	if w.msg.Truncated {
		t.Fatal("ответ не должен урезаться: клиент объявил буфер 4096")
	}
	if got := len(w.msg.Answer); got != 100 {
		t.Fatalf("ожидались все 100 A-записей, получено %d", got)
	}
}

// (c) Клиент не прислал EDNS0 → upstream-копия запроса несёт НАШ OPT
// (udpsize 1232, без DO) на ОБОИХ путях (Yandex + CF); клиентский msg
// при этом не загрязняется.
func TestHandleQuery_AttachesOwnEDNS0ToUpstreamCopy(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "e.test", "1.2.3.4")}
	c := &mockResolver{resp: answerA(t, "e.test", "1.2.3.4")}
	f := newTestForwarder(matchSet(), y, c)

	q := aQuery("e.test")
	if _, err := f.handleQuery(context.Background(), q, cacheKey{name: dns.Fqdn("e.test"), qtype: dns.TypeA}); err != nil {
		t.Fatalf("handleQuery: %v", err)
	}

	for label, m := range map[string]*mockResolver{"yandex": y, "cloudflare": c} {
		uq := m.lastQuery()
		if uq == nil {
			t.Fatalf("%s: upstream-запрос не зафиксирован", label)
		}
		opt := uq.IsEdns0()
		if opt == nil {
			t.Fatalf("%s: upstream-запрос должен нести наш EDNS0 OPT", label)
		}
		if got := opt.UDPSize(); got != upstreamEDNSBufSize {
			t.Fatalf("%s: ожидался udpsize %d, получен %d", label, upstreamEDNSBufSize, got)
		}
		if opt.Do() {
			t.Fatalf("%s: DO-бит не должен выставляться", label)
		}
	}

	// Клиентский запрос остаётся без OPT — мутация только на копии.
	if q.IsEdns0() != nil {
		t.Fatal("клиентский запрос не должен быть загрязнён нашим OPT")
	}
}

// (c) Клиентский OPT (4096 + DO) проходит к upstream'у как есть — наш OPT
// не подменяет и не дублирует его.
func TestHandleQuery_ClientOPTPassedThroughUpstream(t *testing.T) {
	y := &mockResolver{resp: answerA(t, "edns.test", "1.2.3.4")}
	c := &mockResolver{resp: answerA(t, "edns.test", "1.2.3.4")}
	f := newTestForwarder(matchSet(), y, c)

	q := aQuery("edns.test")
	q.SetEdns0(4096, true)
	if _, err := f.handleQuery(context.Background(), q, cacheKey{name: dns.Fqdn("edns.test"), qtype: dns.TypeA}); err != nil {
		t.Fatalf("handleQuery: %v", err)
	}

	for label, m := range map[string]*mockResolver{"yandex": y, "cloudflare": c} {
		uq := m.lastQuery()
		opt := uq.IsEdns0()
		if opt == nil {
			t.Fatalf("%s: клиентский OPT должен пройти к upstream'у", label)
		}
		if got := opt.UDPSize(); got != 4096 {
			t.Fatalf("%s: клиентский udpsize 4096 должен пройти как есть, получен %d", label, got)
		}
		if !opt.Do() {
			t.Fatalf("%s: клиентский DO-бит должен пройти как есть", label)
		}
	}
}

// (c) Non-A путь (forwardCloudflare, например TXT) тоже получает наш EDNS0.
func TestForwardCloudflare_AttachesOwnEDNS0(t *testing.T) {
	txt := new(dns.Msg)
	txt.SetQuestion(dns.Fqdn("txt.test"), dns.TypeTXT)
	txt.Response = true
	rr, err := dns.NewRR(`txt.test. 60 IN TXT "v=test"`)
	if err != nil {
		t.Fatalf("TXT RR: %v", err)
	}
	txt.Answer = append(txt.Answer, rr)

	c := &mockResolver{resp: txt}
	f := newTestForwarder(matchSet(), &mockResolver{}, c)

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn("txt.test"), dns.TypeTXT)
	key := cacheKey{name: dns.Fqdn("txt.test"), qtype: dns.TypeTXT}
	if _, err := f.forwardCloudflare(context.Background(), q, key); err != nil {
		t.Fatalf("forwardCloudflare: %v", err)
	}

	uq := c.lastQuery()
	if uq == nil {
		t.Fatal("upstream-запрос не зафиксирован")
	}
	opt := uq.IsEdns0()
	if opt == nil {
		t.Fatal("non-A путь: upstream-запрос должен нести наш EDNS0 OPT")
	}
	if got := opt.UDPSize(); got != upstreamEDNSBufSize {
		t.Fatalf("non-A путь: ожидался udpsize %d, получен %d", upstreamEDNSBufSize, got)
	}
	if q.IsEdns0() != nil {
		t.Fatal("клиентский запрос не должен быть загрязнён нашим OPT")
	}
}

// F-3 (2026-06-13): forwarder слушает TCP на f.listen — клиентский TCP-ретрай
// после TC=1 (или DNS-over-TCP напрямую) должен получить ответ, а не connection
// refused. Поднимаем живой forwarder на конкретном loopback-порту и стучимся
// dns.Client{Net:"tcp"}.
func TestForwarder_ServesOverTCP(t *testing.T) {
	addr := freeLoopbackUDPAddr(t)
	f := NewForwarder(addr, nil,
		WithResolvers(
			&mockResolver{resp: answerA(t, "tcp-serve.test", "1.2.3.4")},
			&mockResolver{resp: answerA(t, "tcp-serve.test", "1.2.3.4")}))
	if err := f.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = f.Stop() }()

	cl := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	resp, _, err := cl.Exchange(aQuery("tcp-serve.test"), addr)
	if err != nil {
		t.Fatalf("TCP-обмен с forwarder'ом упал (нет TCP-листенера?): %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("ожидался успешный A-ответ по TCP, got rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
}

// F-3: если TCP-bind не удался (порт уже занят TCP-листенером), Start обязан
// откатить уже поднятый UDP и вернуть ошибку — startSplitDNS на это отступит
// к следующему адресу-кандидату. Полуслушающий forwarder (UDP есть, TCP refused)
// недопустим.
func TestForwarder_Start_TCPBindFails_RollsBackUDP(t *testing.T) {
	addr := freeLoopbackUDPAddr(t)

	// Занимаем TCP-порт заранее — Start не сможет поднять на нём TCP-листенер.
	blocker, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("не удалось занять TCP-порт для теста (окружение): %v", err)
	}
	defer func() { _ = blocker.Close() }()

	f := NewForwarder(addr, nil, WithResolvers(&mockResolver{}, &mockResolver{}))
	f.startWaitTimeout = 500 * time.Millisecond
	if err := f.Start(); err == nil {
		_ = f.Stop()
		t.Fatal("ожидалась ошибка Start: TCP-bind на занятом порту должен провалиться")
	}

	// UDP откатан в фоне — порт освобождается. Поллинг с дедлайном.
	deadline := time.Now().Add(3 * time.Second)
	for {
		pc, perr := net.ListenPacket("udp", addr)
		if perr == nil {
			_ = pc.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP-порт %s не освободился за 3s — откат UDP не сработал: %v", addr, perr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Серверные поля обнулены (Start не присвоил частичное состояние).
	f.mu.Lock()
	nilled := f.udpServer == nil && f.tcpServer == nil
	f.mu.Unlock()
	if !nilled {
		t.Fatal("после неудачного Start udpServer/tcpServer должны быть nil")
	}
}

// F-4 (2026-06-13): stale TC-бит из фолбэка retryTCP не должен доезжать до
// клиента, если итоговый ответ влезает в его буфер. Имитируем: upstream-ответ
// помечен Truncated=true, но мал. После ServeDNS клиент без EDNS0 должен
// получить TC=0 (ServeDNS сбрасывает флаг перед Truncate; урезания нет → TC=0).
func TestServeDNS_ClearsStaleTruncatedFlag(t *testing.T) {
	small := answerA(t, "stale-tc.test", "1.2.3.4")
	small.Truncated = true // stale-флаг как из retryTCP-фолбэка
	y := &mockResolver{resp: small}
	c := &mockResolver{resp: small}
	f := newTestForwarder(matchSet(), y, c)

	w := &captureWriter{}
	f.ServeDNS(w, aQuery("stale-tc.test"))
	if w.msg == nil {
		t.Fatal("ответ не записан")
	}
	if w.msg.Truncated {
		t.Fatal("stale TC-бит должен быть сброшен: ответ мал и влезает в буфер клиента")
	}
	if len(w.msg.Answer) == 0 {
		t.Fatal("A-запись должна сохраниться")
	}
}

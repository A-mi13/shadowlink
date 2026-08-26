package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/nixavpn/shadowlink/client/bypassroute"
	"golang.org/x/sync/singleflight"
)

// defaultYandexServers — RU plain-UDP резолверы (Yandex DNS), failover по порядку.
// Derived from the single source of truth DefaultYandexIPs() (N2, 2026-06-11):
// the escape-route list in tunnel.go and these resolver targets must never drift,
// or a Yandex IP would be queried without a /32 escape route → UDP loops into the
// TUN. Built here by appending the DNS port to each bare IP.
var defaultYandexServers = yandexServersWithPort(dnsPort)

const (
	defaultPerUpstreamTimeout = 3 * time.Second
	defaultOverallTimeout     = 4 * time.Second
)

// dnsPort — стандартный DNS-порт, навешиваемый на bare Yandex IP для plain-UDP.
const dnsPort = "53"

// upstreamEDNSBufSize — UDP-размер буфера, объявляемый в НАШЕМ EDNS0 OPT на
// upstream-копии запроса, когда клиент свой EDNS0 не прислал (DNS-M2c,
// 2026-06-12). Windows DNS Client часто шлёт без EDNS0 — тогда Yandex ограничен
// классическими 512 байтами и multi-record ответы реально режутся (TC-бит →
// лишний TCP-ретрай). 1232 — анти-фрагментационный максимум (DNS Flag Day 2020).
// DO-бит не выставляем — DNSSEC-валидацию forwarder не делает.
const upstreamEDNSBufSize = 1232

// maxConcurrentResolves — ёмкость семафора одновременных upstream-резолвов
// (DNS-L5, 2026-06-12). Каждый резолв = uTLS DoH-запрос к 1.1.1.1 + UDP-сокет
// к Yandex; miekg dns.Server плодит горутину на каждый UDP-пакет, и локальный
// flood уникальных имён без лимита раздувал бы число горутин/сокетов
// неограниченно. Запросы сверх лимита ЖДУТ пермит (уважая overallTimeout),
// а не дропаются; cache-hit и синтетические пути семафор не трогают.
const maxConcurrentResolves = 64

const (
	// dohResolverHost — FQDN (с финальной точкой) DoH-резолвера, имя которого
	// НИКОГДА не должно резолвиться через сам forwarder. Defense-in-depth слой 2
	// B1-фикса (2026-06-11): если запрос на это имя долетел до forwarder'а (слой 1
	// — IP-пиннинг DoH-клиента — где-то протёк), мы рвём цикл здесь, отвечая
	// напрямую пиннутыми A-записями, БЕЗ ухода в upstream.
	dohResolverHost = "cloudflare-dns.com."
	// dohResolverTTL — TTL для синтетических A-записей пиннутого ответа (секунды).
	dohResolverTTL = 300
)

// dohResolverIPs — пиннутые A-адреса DoH-резолвера (Cloudflare 1.1.1.1/1.0.0.1).
// Совпадают с dohServerIP клиента (1.1.1.1); 1.0.0.1 добавлен как вторичный edge.
var dohResolverIPs = []string{"1.1.1.1", "1.0.0.1"}

// DefaultYandexIPs returns the bare Yandex DNS resolver IPs (no port). This is
// the single source of truth (N2, 2026-06-11) shared by the dnsproxy plain-UDP
// resolvers (defaultYandexServers, port appended) and the tunnel.go escape-route
// list (used as-is). A copy is returned so callers cannot mutate the backing array.
func DefaultYandexIPs() []string {
	return []string{"77.88.8.8", "77.88.8.1"}
}

// yandexServersWithPort appends ":<port>" to each bare IP from DefaultYandexIPs,
// producing the plain-UDP resolver targets.
func yandexServersWithPort(port string) []string {
	ips := DefaultYandexIPs()
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip + ":" + port
	}
	return out
}

// errAllUpstreamsFailed возвращается из handleQuery когда ни одна ветка
// fallback-лестницы не дала доверенного ответа → ServeDNS пишет SERVFAIL.
var errAllUpstreamsFailed = errors.New("dnsproxy: оба upstream недоступны или ответ не доверен")

// Forwarder is a local split-DNS forwarder. It listens on UDP and, for every A
// query, concurrently queries Yandex (plain-UDP, direct) and Cloudflare (DoH,
// tunnel), arbitrates the answers against the RU CIDR snapshot, and returns the
// selected one.
//
// AAAA queries receive an empty NOERROR (IPv6 is disabled by LeakGuard); non-A
// /non-AAAA queries (MX/TXT/HTTPS/…) are forwarded straight to Cloudflare
// without arbitration (foreign-over-tunnel is the safe default for non-RU). All
// answers are cached.
type Forwarder struct {
	listen string          // адрес UDP listener ("127.0.0.1:53" / "198.18.0.1:53")
	match  snapshotMatcher // RU snapshot matcher (в проде resolved.Match)

	// cfOnly — M-4 (2026-06-12): RU snapshot отсутствует/пуст → matcher всегда
	// false → арбитраж математически всегда выбирает CF-ветку, а ответ Yandex
	// не может быть использован НИКОГДА. В этом режиме Yandex-нога пропускается
	// целиком (см. resolveUncached) — раньше каждый A-запрос всё равно уходил
	// plaintext'ом в Yandex: чистая утечка имён + ожидание двух upstream'ов.
	cfOnly bool

	// bootstrapDomains — INT-H2 (2026-06-12): whitelist канонизированных FQDN
	// (dns.CanonicalName: lowercase + финальная точка) серверных доменов, для
	// которых разрешена ветка «Yandex-only при недоступном CF» БЕЗ требования
	// yandexIsRU. Закрывает bootstrap-deadlock CDN-режима: все WS-слоты мертвы
	// → DoH-нога CF (через туннель) падает → reconnect не может зарезолвить
	// серверный (иностранный) домен → туннель не восстанавливается никогда.
	// Серверному домену анти-цензурный арбитраж не нужен: его IP всё равно
	// получает /32 escape-маршрут (в CDN-режиме /16 sweep покрывает ротацию CF
	// edge). Stub-rejection и короткий unarbitratedCacheTTL сохраняются —
	// заглушка РКН бесполезна для reconnect и не должна отравить кэш.
	// Пустой/nil → поведение идентично прежнему. Write-once в NewForwarder
	// (опцией), дальше read-only — синхронизация не нужна.
	bootstrapDomains map[string]struct{}

	yandex     Resolver
	cloudflare Resolver
	cache      *dnsCache

	perUpstreamTimeout time.Duration // дедлайн на отдельный upstream-вызов
	overallTimeout     time.Duration // общий дедлайн на handleQuery

	// sf дедуплицирует конкурентные ИДЕНТИЧНЫЕ запросы (DNS-L5): N параллельных
	// резолвов одного имени (браузер бьёт пачкой) сливаются в один dual-resolve;
	// результат копируется per-caller — общий *dns.Msg никому не отдаётся.
	sf singleflight.Group
	// resolveSem ограничивает число одновременных upstream-резолвов (DNS-L5);
	// ёмкость maxConcurrentResolves (в тестах подменяется на более узкий).
	resolveSem chan struct{}

	// Per-branch arbitration counters (anti-censorship observability). Bumped
	// whenever arbitrate returns a branch; exported via BranchCounts for future
	// telemetry wiring (T6). Atomic — handleQuery runs per UDP request.
	branchYandexTotal   atomic.Uint64
	branchCensoredTotal atomic.Uint64
	branchForeignTotal  atomic.Uint64
	branchGeoTotal      atomic.Uint64

	// Serve-пути ВНЕ лестницы арбитража (наблюдаемость ревью блоков 3/4,
	// 2026-06-12) — раньше не учитывались никакими счётчиками:
	// serveNXDOMAINTotal — NXDOMAIN от CF, отданный коротким замыканием до
	// лестницы (DNS-H1); serveUnarbitratedTotal — Yandex-only ответы, принятые
	// без сверки с CF и закэшированные с unarbitratedCacheTTL (DNS-H2: ветка
	// yOK && !cOK + RU-исключение внутри NXDOMAIN short-circuit).
	serveNXDOMAINTotal     atomic.Uint64
	serveUnarbitratedTotal atomic.Uint64

	mu sync.Mutex // защищает udpServer/tcpServer (идемпотентность Start/Stop)
	// F-3 (2026-06-13, final batch review): forwarder слушает И UDP, И TCP на
	// f.listen. Раньше был только UDP: не-EDNS клиент, получив Truncate(512) с
	// TC=1 (после DNS-M2c, где upstream-копия анонсирует 1232 и multi-record
	// ответы перестали резаться у Yandex — крупные ответы доезжают и режутся уже
	// нами под клиентский 512), по RFC ретраит запрос по TCP на 198.18.0.1:53 →
	// connection refused (TCP-листенера не было) → резолв имени падал на
	// единственном TUN-резолвере. Оба сервера живут в одном lifecycle-конверте.
	udpServer *dns.Server
	tcpServer *dns.Server

	// branchLogStop сигналит горутине периодического snapshot-лога branch counts
	// (I2, 2026-06-11) завершиться. Закрывается в Stop под mu; nil когда forwarder
	// не запущен. branchLogWG ждёт фактического выхода горутины перед возвратом из
	// Stop — горутина не утекает.
	branchLogStop chan struct{}
	branchLogWG   sync.WaitGroup

	// branchLogEvery — период тикера runBranchLog. В проде = branchLogInterval;
	// поле существует как test seam (DNS-M3, 2026-06-12: на тикер подвешен
	// cache.sweep — тест укорачивает период вместо ожидания 313s). Write-once
	// в NewForwarder / до Start, дальше read-only — синхронизация не нужна.
	branchLogEvery time.Duration

	// startWaitTimeout — сколько Start ждёт сигнала NotifyStartedFunc. В проде
	// 5s (NewForwarder); поле — test seam для DNS-M5 (2026-06-12). Write-once
	// до Start, дальше read-only.
	startWaitTimeout time.Duration
	// startNotifyDelay — test seam (DNS-M5): искусственная задержка сигнала
	// "started" для воспроизведения таймаута Start на реально стартующем
	// сервере. В проде всегда 0.
	startNotifyDelay time.Duration
}

// branchLogInterval — базовый период snapshot-лога branch counts (I2). ~5 минут;
// выбран нечётный к :00 для лёгкого ухода от round-минуты (анти-FFT в духе проекта).
const branchLogInterval = 313 * time.Second

// defaultStartWaitTimeout — прод-значение startWaitTimeout (ожидание
// NotifyStartedFunc в Start).
const defaultStartWaitTimeout = 5 * time.Second

// Option is a functional option for the Forwarder constructor.
type Option func(*Forwarder)

// WithResolvers injects the resolvers (used to inject mock resolvers in tests).
// By default the real Yandex plain-UDP and Cloudflare DoH resolvers are used.
func WithResolvers(yandex, cloudflare Resolver) Option {
	return func(f *Forwarder) {
		f.yandex = yandex
		f.cloudflare = cloudflare
	}
}

// WithBootstrapDomains регистрирует серверные домены для bootstrap-whitelist
// (INT-H2, 2026-06-12): для них Yandex-only ответ при недоступном CF принимается
// без RU-арбитража (stub-rejection и unarbitratedCacheTTL сохраняются). Имена
// канонизируются (case-insensitive FQDN); пустые строки пропускаются. Без
// вызова / с пустым списком поведение forwarder'а не меняется.
func WithBootstrapDomains(domains ...string) Option {
	return func(f *Forwarder) {
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if f.bootstrapDomains == nil {
				f.bootstrapDomains = make(map[string]struct{}, len(domains))
			}
			f.bootstrapDomains[dns.CanonicalName(d)] = struct{}{}
		}
	}
}

// WithTimeouts overrides the per-upstream and overall timeouts.
func WithTimeouts(perUpstream, overall time.Duration) Option {
	return func(f *Forwarder) {
		if perUpstream > 0 {
			f.perUpstreamTimeout = perUpstream
		}
		if overall > 0 {
			f.overallTimeout = overall
		}
	}
}

// NewForwarder creates a forwarder. snapshot is the RU CIDR snapshot; its Match
// becomes the arbitration matcher. A nil or empty snapshot (Size()==0) enables
// the cfOnly mode: every query goes straight to Cloudflare over the tunnel and
// Yandex is never contacted (M-4, 2026-06-12) — with an always-false matcher
// the Yandex answer could never win arbitration anyway, so dual-resolving was
// a pure plaintext name leak plus latency.
func NewForwarder(listen string, snapshot *bypassroute.Resolved, opts ...Option) *Forwarder {
	f := &Forwarder{
		listen:             listen,
		cache:              newDNSCache(),
		perUpstreamTimeout: defaultPerUpstreamTimeout,
		overallTimeout:     defaultOverallTimeout,
		branchLogEvery:     branchLogInterval,
		startWaitTimeout:   defaultStartWaitTimeout,
		resolveSem:         make(chan struct{}, maxConcurrentResolves),
	}

	if snapshot != nil && snapshot.Size() > 0 {
		f.match = snapshot.Match
	} else {
		// M-4 (2026-06-12): nil/пустой snapshot — включаем cfOnly. Yandex-резолвер
		// ниже всё равно создаётся (дёшево, сокетов не открывает), но НЕ вызывается.
		f.match = func(netip.Addr) bool { return false }
		f.cfOnly = true
	}

	for _, opt := range opts {
		opt(f)
	}

	// Дефолтные резолверы, если не инъектированы опцией.
	if f.yandex == nil {
		f.yandex = newPlainUDPResolver(defaultYandexServers, f.perUpstreamTimeout)
	}
	if f.cloudflare == nil {
		f.cloudflare = newDoHResolver()
	}

	return f
}

// Start brings up the UDP AND TCP dns.Servers on f.listen with the Forwarder
// itself as the Handler. Idempotent: calling it again while already running is
// a no-op. If the TCP bind fails after UDP succeeded, the UDP server is shut
// down and Start errors — a half-listening forwarder (UDP up, TCP refused) is
// worse than the loopback-candidate fallback startSplitDNS retries on error
// (F-3, 2026-06-13).
func (f *Forwarder) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.udpServer != nil {
		return nil
	}

	udp, err := f.startDNSServer("udp")
	if err != nil {
		return err
	}
	tcp, err := f.startDNSServer("tcp")
	if err != nil {
		// UDP поднялся, TCP — нет: гасим UDP, чтобы не остаться полуслушающими.
		// Фоновый Shutdown (как в startDNSServer-таймауте): не держим Start на
		// возможной блокировке Shutdown.
		go func() { _ = udp.Shutdown() }()
		return fmt.Errorf("dnsproxy: TCP-листенер не поднялся (UDP откатываем): %w", err)
	}

	f.udpServer = udp
	f.tcpServer = tcp

	// I2 (2026-06-11): периодический snapshot-лог branch counts — единственный
	// полевой сигнал, что censored-ветка реально срабатывает (фича лечит цензуру).
	// Лёгкий тикер; гасится в Stop через branchLogStop + WaitGroup (не течёт).
	f.branchLogStop = make(chan struct{})
	f.branchLogWG.Add(1)
	go f.runBranchLog(f.branchLogStop)

	return nil
}

// startDNSServer поднимает один dns.Server (net="udp"|"tcp") на f.listen с
// Forwarder'ом как Handler и возвращает его, только когда сокет реально
// привязан (NotifyStartedFunc). Несёт всю DNS-M5/L-4-семантику ожидания —
// общая для UDP и TCP, вынесена сюда чтобы не дублироваться (F-3).
func (f *Forwarder) startDNSServer(net string) (*dns.Server, error) {
	srv := &dns.Server{
		Net:     net,
		Addr:    f.listen,
		Handler: f,
	}

	// ListenAndServe блокирует — поднимаем в горутине. Готовность сигналим
	// через NotifyStartedFunc, чтобы вернуться только когда сокет привязан.
	started := make(chan struct{})
	var startErr error
	// startNotifyDelay — test seam (DNS-M5): имитация медленного старта.
	// Захватываем в локальную ДО спавна горутины: NotifyStartedFunc позднего
	// сервера может пережить возврат Start по таймауту, и чтение поля оттуда
	// гонялось бы с записью теста «перед следующим Start» (нет happens-before).
	notifyDelay := f.startNotifyDelay
	srv.NotifyStartedFunc = func() {
		if notifyDelay > 0 {
			time.Sleep(notifyDelay)
		}
		close(started)
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			// Если сервер не успел стартовать — пробросим ошибку через канал.
			select {
			case <-started:
				// L-4 (2026-06-12): сервер УЖЕ работал и умер в РАНТАЙМЕ (сокет
				// погиб: адрес TUN снят, сброс стека). Раньше ошибка глоталась
				// молча — forwarder исчезал, а TUN DNS продолжал указывать на
				// 198.18.0.1:53 → полный DNS-outage без единой строки в логе.
				// Штатный Stop сюда НЕ попадает: после graceful Shutdown
				// serveUDP/serveTCP miekg/dns возвращает nil. Авторестарт
				// сознательно вне скоупа. Юнит-тест ветки потребовал бы тяжёлого
				// рефакторинга (listener создаётся внутри ListenAndServe и
				// снаружи недоступен) — покрытие сознательно опущено.
				slog.Error("split-DNS forwarder упал в рантайме", "net", net, "err", err)
			default:
				startErr = err
				close(started)
			}
		}
	}()

	startTimeout := f.startWaitTimeout
	if startTimeout <= 0 {
		startTimeout = defaultStartWaitTimeout // оборонительно: Forwarder собран не через NewForwarder
	}
	select {
	case <-started:
	case <-time.After(startTimeout):
		// DNS-M5 (2026-06-12): таймаут НЕ означает, что сервер мёртв — он мог
		// стартовать секундой позже и навсегда занять :53 БЕЗ хендла (srv не
		// сохранён → Stop был no-op, горутина и сокет утекали, следующий bind
		// на адрес падал вечно). Гасим поздний старт гарантированно и в фоне
		// (Shutdown может блокироваться на lock сервера — не держим Start):
		// Shutdown на уже стартовавшем сервере останавливает его сразу; на ещё
		// не стартовавшем возвращает ошибку — тогда ждём фактического исхода
		// ListenAndServe (started закрывается и при успехе, и при ошибке bind'а)
		// и гасим после. Горутина не утекает, кроме патологии «bind завис
		// навсегда» — там припаркованная горутина строго лучше утёкшего сервера.
		// Двойного Shutdown-паника нет: повторный Shutdown — ошибка-no-op.
		go func() {
			if err := srv.Shutdown(); err != nil {
				<-started
				_ = srv.Shutdown()
			}
		}()
		return nil, errors.New("dnsproxy: forwarder не стартовал вовремя (" + net + ")")
	}
	if startErr != nil {
		return nil, startErr
	}
	return srv, nil
}

// runBranchLog periodically emits a snapshot of the per-branch arbitration
// counts (I2 observability). It exits when stop is closed. A dedicated stop
// channel is captured by value so a concurrent Stop→Start cycle cannot make
// this goroutine observe a re-created channel.
//
// DNS-M3 (2026-06-12): тот же тик переиспользуется как периодическая уборка
// кэша (sweep просроченных записей) — отдельная горутина не плодится, период
// ~5 мин достаточен. Число убранных записей и текущий размер кэша добавлены
// в существующую slog-строку (cache_swept / cache_size) — дешёвый сигнал для
// канареек, что кэш не растёт монотонно.
func (f *Forwarder) runBranchLog(stop chan struct{}) {
	defer f.branchLogWG.Done()
	ticker := time.NewTicker(f.branchLogEvery)
	defer ticker.Stop()
	// I-6 (2026-06-12): тик, на котором НИЧЕГО не изменилось (все счётчики
	// прежние, sweep ничего не убрал, размер кэша тот же), строку не эмитит —
	// раньше идентичные INFO-строки шли всю ночь (~92 за 8h сессию простоя).
	// Первый тик логируется всегда (baseline для канареек). Sweep при этом
	// выполняется КАЖДЫЙ тик — условен только вывод строки.
	var (
		loggedOnce bool
		last       [6]uint64
		lastSize   int
	)
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			swept, cacheSize := f.cache.sweep()
			y, censored, foreign, geo := f.BranchCounts()
			nxdomain, unarbitrated := f.ServeCounts()
			cur := [6]uint64{y, censored, foreign, geo, nxdomain, unarbitrated}
			if loggedOnce && swept == 0 && cur == last && cacheSize == lastSize {
				continue
			}
			slog.Info("split-DNS branch counts",
				"yandex", y, "censored", censored, "foreign", foreign, "geo", geo,
				"nxdomain", nxdomain, "unarbitrated", unarbitrated,
				"cache_swept", swept, "cache_size", cacheSize)
			loggedOnce, last, lastSize = true, cur, cacheSize
		}
	}
}

// Stop shuts both servers down. Idempotent.
func (f *Forwarder) Stop() error {
	f.mu.Lock()
	udp := f.udpServer
	tcp := f.tcpServer
	f.udpServer = nil
	f.tcpServer = nil
	stop := f.branchLogStop
	f.branchLogStop = nil
	f.mu.Unlock()

	// Гасим branch-log горутину и дожидаемся её выхода (не течёт). Идемпотентно:
	// при повторном Stop stop уже nil → пропускаем.
	if stop != nil {
		close(stop)
		f.branchLogWG.Wait()
	}

	// Сначала гасим оба dns.Server: Shutdown ждёт выхода активных ServeDNS-
	// хендлеров (miekg ведёт wg) — после него никто не вернёт соединение в пул.
	var shutdownErr error
	if udp != nil {
		if err := udp.Shutdown(); err != nil {
			shutdownErr = err
		}
	}
	if tcp != nil {
		if err := tcp.Shutdown(); err != nil && shutdownErr == nil {
			shutdownErr = err
		}
	}

	// DNS-M6 (2026-06-12): сбрасываем idle keep-alive соединения DoH-резолвера
	// — сокеты к 1.1.1.1 не должны жить после остановки forwarder'а. СТРОГО
	// ПОСЛЕ srv.Shutdown(): иначе in-flight хендлер вернул бы соединение в пул
	// уже после очистки, и оно жило бы до IdleConnTimeout (90s). Через
	// type assertion: мок-резолверы в тестах Close не обязаны иметь.
	// CloseIdleConnections идемпотентен, повторный Stop безопасен; клиент
	// остаётся рабочим для Start-после-Stop (новый запрос откроет соединение).
	if closer, ok := f.cloudflare.(interface{ Close() }); ok {
		closer.Close()
	}

	return shutdownErr
}

// ServeDNS implements dns.Handler. It handles only the first question
// (r.Question[0]).
func (f *Forwarder) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// Нет вопросов → FormErr, клиент не висит.
	if len(r.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(resp)
		return
	}

	q := r.Question[0]

	// B1 слой 2 (2026-06-11) — разрыв DoH-петли на уровне самого forwarder'а.
	// Запрос на ИМЯ DoH-резолвера (cloudflare-dns.com) НИКОГДА не должен уходить
	// в upstream: его CF-ветка зовёт DoHQuery, который (если слой-1 IP-пиннинг
	// где-то протёк) снова резолвил бы это же имя → рекурсия. Отвечаем сразу
	// пиннутыми A-записями, БЕЗ вызова резолверов. AAAA на это имя падает в
	// общую AAAA-ветку ниже (пустой NOERROR — IPv6 выключен), что тоже не зовёт
	// upstream, так что цикла нет ни для A, ни для AAAA.
	if q.Qtype == dns.TypeA && strings.EqualFold(dns.CanonicalName(q.Name), dohResolverHost) {
		resp := buildDoHResolverPinReply(r, q.Name)
		_ = w.WriteMsg(resp)
		return
	}

	// AAAA → пустой NOERROR (NODATA). IPv6 выключен LeakGuard'ом; пустой NOERROR
	// (а не NXDOMAIN) заставляет браузер чисто откатиться на A. Upstream НЕ вызываем.
	if q.Qtype == dns.TypeAAAA {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = false
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeSuccess
		// Answer пустой (NODATA).
		_ = w.WriteMsg(resp)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), f.overallTimeout)
	defer cancel()

	key := cacheKey{name: dns.CanonicalName(q.Name), qtype: q.Qtype}

	var (
		resp *dns.Msg
		err  error
	)
	if q.Qtype == dns.TypeA {
		// A-запросы проходят через арбитраж Yandex vs Cloudflare.
		resp, err = f.handleQuery(ctx, r, key)
	} else {
		// Не-A/не-AAAA (MX/TXT/HTTPS/…) — geo-смысла для арбитража нет.
		// Форвардим на Cloudflare (foreign-через-туннель — безопасный дефолт
		// для не-RU) через ОБЩИЙ конверт cache → singleflight → семафор (F-2,
		// 2026-06-12, final batch review): браузеры шлют type-65 HTTPS рядом
		// почти с каждым A — без конверта этот путь был unbounded.
		resp, err = f.handleNonA(ctx, r, key)
	}

	if err != nil || resp == nil {
		fail := new(dns.Msg)
		fail.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(fail)
		return
	}

	// Нормализуем заголовок ответа под исходный запрос (Id/Question/Response).
	// DNS-I-3 (2026-06-12): SetReply сбрасывает Rcode в Success — сохраняем
	// rcode лестницы, иначе NXDOMAIN доезжал бы до клиента как NOERROR.
	rc := resp.Rcode
	resp.SetReply(r)
	resp.Rcode = rc
	resp.RecursionAvailable = true
	// DNS-M1 (2026-06-12): OPT в ответе допустим только если клиент сам прислал
	// EDNS0 (RFC 6891) — строгие stub-резолверы бракуют такой ответ как FORMERR.
	// Это ЕДИНСТВЕННЫЙ WriteMsg-путь, по которому течёт upstream Extra (и свежий
	// резолв, и cache hit сходятся сюда); остальные WriteMsg в ServeDNS —
	// синтетические ответы (FormErr / DoH-pin / AAAA-NODATA / SERVFAIL) без
	// upstream OPT.
	stripOPTForClient(resp, r)
	// DNS-M2b (2026-06-12): режем ответ под UDP-лимит клиента ПЕРЕД записью —
	// раздутый ответ (CF через DoH не ограничен 512 байтами) либо не паковался
	// (WriteMsg-ошибка глоталась `_ =` → клиент висел до таймаута), либо уходил
	// больше, чем клиент способен принять. Порядок строго ПОСЛЕ stripOPT:
	// Truncate считает размер сообщения вместе с Extra — иначе вырезаемый OPT
	// занимал бы бюджет и Answer резался бы зря. Truncate сам выставляет TC-бит
	// при урезании; resp здесь всегда наша per-caller копия — мутация безопасна.
	//
	// F-4 (2026-06-13, final batch review): сбрасываем stale TC-бит ПЕРЕД
	// Truncate. Источник: фолбэк retryTCP (upstream.go) при провале TCP-ретрая
	// возвращает урезанный UDP-ответ Yandex с Truncated=true; этот флаг переживал
	// арбитраж и SetReply (тот его не трогает) и доезжал до клиента даже когда
	// итоговый (суженный пересечением) ответ влезает в его буфер — провоцируя
	// бессмысленный клиентский TCP-ретрай. Truncate ниже сам поднимет TC-бит
	// заново, если урезание реально потребуется.
	resp.Truncated = false
	resp.Truncate(clientUDPBufSize(r))
	_ = w.WriteMsg(resp)
}

// clientUDPBufSize — UDP-лимит клиента для Truncate (DNS-M2b): UDPSize из
// клиентского EDNS0 OPT (floor dns.MinMsgSize — RFC 6891 трактует анонс <512
// как 512), без EDNS0 — классические 512 байт.
func clientUDPBufSize(r *dns.Msg) int {
	if opt := r.IsEdns0(); opt != nil {
		if s := int(opt.UDPSize()); s > dns.MinMsgSize {
			return s
		}
	}
	return dns.MinMsgSize
}

// stripOPTForClient удаляет OPT из resp.Extra, если клиентский запрос r не
// содержал EDNS0 OPT (DNS-M1, 2026-06-12). Кэш OPT уже не хранит (put вырезает),
// но свежий upstream-ответ возвращается клиенту напрямую, до кэширования —
// этот хелпер закрывает и его. resp здесь всегда наша копия (upstream-резолверы
// и cache.get отдают свежие копии) — мутация безопасна.
func stripOPTForClient(resp, r *dns.Msg) {
	if r.IsEdns0() != nil {
		return
	}
	resp.Extra = stripOPT(resp.Extra)
}

// upstreamQuery возвращает сообщение для отправки upstream'у: копию r, к
// которой прикреплён НАШ EDNS0 OPT (udpsize 1232, без DO), если клиент свой
// EDNS0 не прислал (DNS-M2c, 2026-06-12) — иначе upstream ограничен 512
// байтами и multi-record ответы режутся. Клиентский OPT, если он есть,
// проходит как есть. Мутируется ТОЛЬКО копия — клиентский r остаётся
// нетронутым: его OPT-статус управляет stripOPTForClient и Truncate на
// обратном пути. Синтетические пути (FormErr / DoH-pin / AAAA NODATA)
// upstream не зовут и сюда не попадают.
func upstreamQuery(r *dns.Msg) *dns.Msg {
	out := r.Copy()
	if out.IsEdns0() == nil {
		out.SetEdns0(upstreamEDNSBufSize, false)
	}
	return out
}

// forwardCloudflare резолвит non-A запрос через Cloudflare (DoH, туннель) с кэшем.
func (f *Forwarder) forwardCloudflare(ctx context.Context, r *dns.Msg, key cacheKey) (*dns.Msg, error) {
	if cached, ok := f.cache.get(key); ok {
		return cached, nil
	}

	uctx, cancel := context.WithTimeout(ctx, f.perUpstreamTimeout)
	defer cancel()

	resp, err := f.cloudflare.Resolve(uctx, upstreamQuery(r))
	if err != nil || resp == nil || !usableRcode(resp) {
		// SERVFAIL/REFUSED от CF = отказ upstream'а (не кэшируем). NXDOMAIN и
		// NOERROR-NODATA — осмысленные ответы: пропагируем и кэшируем (DNS-H1).
		// I-4 (2026-06-12): не теряем первопричину отказа (timeout? HTTP-код?
		// unpack? rcode?) — errAllUpstreamsFailed обезличен, а caller (ServeDNS)
		// пишет клиенту SERVFAIL и ошибку дальше не разбирает, поэтому Debug-лог
		// здесь — достаточный минимум (обёртка %w смысла не имеет).
		rcode := ""
		if resp != nil {
			rcode = dns.RcodeToString[resp.Rcode]
		}
		slog.Debug("dnsproxy: Cloudflare upstream отказ", "name", key.name, "err", err, "rcode", rcode)
		return nil, errAllUpstreamsFailed
	}
	f.cache.put(key, resp)
	return resp, nil
}

// usableRcode reports whether an upstream answer carries a meaningful DNS
// outcome: NOERROR (possibly NODATA) or NXDOMAIN. Anything else (SERVFAIL,
// REFUSED, …) means the upstream could not answer — the ladder must treat it
// as an upstream failure, not as an (empty) answer (DNS-H1, 2026-06-12).
func usableRcode(msg *dns.Msg) bool {
	return msg.Rcode == dns.RcodeSuccess || msg.Rcode == dns.RcodeNameError
}

// resolveResult — результат одного конкурентного upstream-вызова.
type resolveResult struct {
	msg *dns.Msg
	err error
}

// sfKeyString — строковый ключ singleflight, выведенный из cacheKey (DNS-L5).
func sfKeyString(key cacheKey) string {
	return key.name + "|" + strconv.FormatUint(uint64(key.qtype), 10)
}

// handleQuery резолвит A-запрос: cache → singleflight+семафор → конкурентный
// dual-resolve (Yandex+CF) → арбитраж/fallback-лестница → cache.put → копия
// per-caller. SERVFAIL не кэшируется; NXDOMAIN/NODATA — осмысленные ответы,
// пропагируются и кэшируются (negative cache, DNS-H1).
func (f *Forwarder) handleQuery(ctx context.Context, q *dns.Msg, key cacheKey) (*dns.Msg, error) {
	return f.resolveCachedSF(ctx, key, func() (*dns.Msg, error) {
		return f.resolveUncached(ctx, q, key)
	})
}

// handleNonA — F-2 (2026-06-12, final batch review): non-A/non-AAAA путь
// (MX/TXT/HTTPS/…) через ТОТ ЖЕ конверт cache → singleflight → семафор, что и
// A-путь. Раньше forwardCloudflare вызывался из ServeDNS напрямую — без дедупа
// и без bound'а конкурентности, хотя браузеры шлют type-65 HTTPS рядом почти
// с каждым A (≈половина реальной нагрузки шла unbounded-путём). cacheKey уже
// включает qtype, поэтому пространство singleflight-ключей компонуется с
// A-путём без коллизий. Сам резолв остаётся CF-only (forwardCloudflare),
// семантика не меняется.
func (f *Forwarder) handleNonA(ctx context.Context, q *dns.Msg, key cacheKey) (*dns.Msg, error) {
	return f.resolveCachedSF(ctx, key, func() (*dns.Msg, error) {
		resp, err := f.forwardCloudflare(ctx, q, key)
		if err == nil {
			return resp, nil
		}
		// CF отказал — пробуем Yandex, но ТОЛЬКО для типов, где это безопасно
		// (см. nonAFallbackAllowed). Единственная точка отказа, пункт 3.
		return f.tryServeNonAFallback(ctx, q, key, err)
	})
}

// nonAFallbackAllowed сообщает, допустим ли Yandex-фолбэк для типа запроса при
// недоступном CF.
//
// ⚠ ЭТО НЕ СПИСОК УДОБСТВА, А ГРАНИЦА МОДЕЛИ ДОВЕРИЯ. У A-пути неарбитрированный
// Yandex-ответ обставлен двумя проверками — yandexIsRU (хоть один A-IP в
// RU-снапшоте) и containsStubIP (известная заглушка РКН). Обе работают через
// a4Set, то есть разбирают ЗАПИСИ ТИПА A. Для не-A типов их применить не к чему,
// и это меняет цену подмены по типам:
//
//   - MX / TXT / SRV / PTR / NS / SOA / CNAME — фолбэк РАЗРЕШЁН. Эти записи не
//     маршрутизируют трафик сами по себе: подменённый MX/SRV/CNAME даёт имя,
//     которое клиент затем резолвит ЧЕРЕЗ НАШ ЖЕ A-путь — там арбитраж и
//     stub-фильтр никуда не делись, — а дальше упирается в проверку TLS-серта.
//     Подменённый TXT портит SPF/верификацию домена, но соединение никуда не
//     уводит. То есть подмена ловится ниже по стеку.
//
//   - HTTPS / SVCB (type 65) — фолбэк ЗАПРЕЩЁН, fail-closed. Эта запись несёт
//     МАРШРУТИЗИРУЮЩИЕ данные: ipv4hint/ipv6hint уводят соединение на указанный
//     IP в обход A-пути (то есть в обход арбитража), и при этом они НЕ видны
//     stub-фильтру — ipv4hint лежит в SvcParam, а не в *dns.A, поэтому a4Set о
//     нём не знает и containsStubIP на нём слеп. Вдобавок подменённый параметр
//     ech= снимает ECH (downgrade), а alpn= может сбить протокол. Цена
//     fail-closed при этом почти нулевая: на SERVFAIL по type-65 клиент штатно
//     откатывается на A/AAAA и соединение всё равно устанавливается — просто
//     без SVCB-оптимизации. Асимметрия «высокая цена ошибки / нулевая цена
//     отказа» и решает вопрос.
//
// AAAA сюда не доходит (ServeDNS отвечает NODATA раньше), A — тем более
// (у него своя лестница).
func nonAFallbackAllowed(qtype uint16) bool {
	switch qtype {
	case dns.TypeMX, dns.TypeTXT, dns.TypeSRV, dns.TypePTR, dns.TypeNS, dns.TypeSOA, dns.TypeCNAME:
		return true
	default:
		// HTTPS/SVCB и всё незнакомое — fail-closed. Умолчание намеренно
		// закрытое: новый тип записи может нести маршрутизирующие данные, и
		// «разрешить по умолчанию» означало бы тихо расширить доверие.
		return false
	}
}

// tryServeNonAFallback обслуживает не-A запрос Yandex'ом при недоступном CF.
// Возвращает исходную ошибку CF, если фолбэк неприменим или не удался.
//
// Защиты повторяют неарбитрированный A-путь настолько, насколько это осмысленно
// для не-A типов: тип из белого списка, cfOnly-режим исключён, ответ обязан быть
// NOERROR с непустым Answer, кэш — жёсткий короткий unarbitratedCacheTTL, плюс
// учёт в serveUnarbitratedTotal (тот же счётчик, что у A-пути: это ровно то же
// доверие без сверки).
func (f *Forwarder) tryServeNonAFallback(ctx context.Context, q *dns.Msg, key cacheKey, cfErr error) (*dns.Msg, error) {
	if !nonAFallbackAllowed(key.qtype) {
		return nil, cfErr
	}
	// cfOnly (нет RU-снапшота) — Yandex не трогаем НИКОГДА (M-4): без снапшота
	// его ответ и на A-пути не мог бы быть использован, а plaintext-запрос в
	// него — чистая утечка имени.
	if f.cfOnly {
		return nil, cfErr
	}

	uctx, cancel := context.WithTimeout(ctx, f.perUpstreamTimeout)
	defer cancel()

	resp, err := f.yandex.Resolve(uctx, upstreamQuery(q))
	if err != nil || resp == nil || !usableRcode(resp) || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		// Пустой/отказной ответ Yandex ничего не чинит: NXDOMAIN от него без
		// сверки с CF не доверяем (РКН умеет отвечать NXDOMAIN'ом), а NODATA
		// бесполезен. Отдаём исходную ошибку CF → SERVFAIL.
		return nil, cfErr
	}

	f.serveUnarbitratedTotal.Add(1)
	f.cache.putWithLifetime(key, resp, unarbitratedCacheTTL)
	slog.Debug("split-DNS: не-A запрос обслужен Yandex-фолбэком (CF недоступен)",
		"name", key.name, "qtype", dns.TypeToString[key.qtype])
	return resp, nil
}

// resolveCachedSF — общий конверт «cache-get → singleflight → семафор» для
// обоих serve-путей (DNS-L5 + F-2, 2026-06-12). resolve — собственно резолв
// после cache-miss; исполняется только лидером singleflight под семафором и
// сам кладёт результат в кэш.
func (f *Forwarder) resolveCachedSF(ctx context.Context, key cacheKey, resolve func() (*dns.Msg, error)) (*dns.Msg, error) {
	// 1. Cache hit — мимо singleflight и семафора (мгновенный путь;
	//    cache.get отдаёт свежую копию).
	if cached, ok := f.cache.get(key); ok {
		return cached, nil
	}

	// DNS-L5 (2026-06-12): singleflight по ключу кэша — N конкурентных
	// одинаковых запросов = ОДИН резолв вместо N upstream-вызовов.
	// Семафор ВНУТРИ fn: пермит берёт только лидер (присоединившиеся ждут
	// результат, не пермит); ожидание уважает ctx (overallTimeout), запросы
	// сверх лимита не дропаются. Известный нюанс singleflight: fn исполняется
	// с ctx ЛИДЕРА — все ctx здесь однотипны (overallTimeout из ServeDNS),
	// так что присоединившиеся ждут не дольше своего бюджета ± разница стартов.
	v, err, _ := f.sf.Do(sfKeyString(key), func() (any, error) {
		select {
		case f.resolveSem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		defer func() { <-f.resolveSem }()
		return resolve()
	})
	if err != nil {
		return nil, err
	}
	shared, ok := v.(*dns.Msg)
	if !ok || shared == nil {
		return nil, errAllUpstreamsFailed
	}
	// Результат singleflight шарится всеми ожидавшими — отдаём каждому СВОЮ
	// копию: per-client мутации в ServeDNS (SetReply / rcode / stripOPT /
	// Truncate) на общем *dns.Msg были бы гонкой и порчей чужих ответов.
	return shared.Copy(), nil
}

// resolveUncached — собственно резолв после cache-miss (вызывается только
// лидером singleflight под семафором): конкурентный dual-resolve →
// арбитраж/fallback-лестница → cache.put.
func (f *Forwarder) resolveUncached(ctx context.Context, q *dns.Msg, key cacheKey) (*dns.Msg, error) {
	// M-4 (2026-06-12): cfOnly — Yandex-нога пропускается целиком (см. поле
	// cfOnly). Переиспользуем CF-only путь non-A форвардинга: идентичная
	// rcode/NXDOMAIN-семантика; без Yandex арбитража нет — ответы CF
	// авторитетны (доверенный upstream через туннель) и кэшируются с ОБЫЧНЫМ
	// TTL-клампом, не unarbitratedCacheTTL.
	//
	// INT-H2 (2026-06-12): исключение — bootstrap-домен. Сначала CF (дёшево,
	// нормальный путь, никакой plaintext-утечки пока туннель жив); если CF
	// упал — для bootstrap-домена пробуем Yandex plain-UDP (stub-rejection +
	// unarbitratedCacheTTL + INFO-лог внутри tryServeBootstrap). Не-bootstrap
	// запросы сохраняют сегодняшнее поведение в точности: Yandex не трогается
	// НИКОГДА (фикс утечки M-4 не регрессирует).
	if f.cfOnly {
		resp, err := f.forwardCloudflare(ctx, q, key)
		if err == nil {
			return resp, nil
		}
		if !f.isBootstrapDomain(key.name) {
			return nil, err
		}
		uctx, cancel := context.WithTimeout(ctx, f.perUpstreamTimeout)
		defer cancel()
		yMsg, yErr := f.yandex.Resolve(uctx, upstreamQuery(q))
		if yErr == nil && yMsg != nil {
			if served, ok := f.tryServeBootstrap(key, yMsg); ok {
				return served, nil
			}
		}
		return nil, errAllUpstreamsFailed
	}

	// 2. Конкурентный резолв обоих upstream'ов. Каждая горутина пишет свой
	//    результат в собственную ячейку — общего изменяемого состояния нет,
	//    гонок нет (проверить под -race на Linux; Windows без gcc — пропускаем).
	var yRes, cRes resolveResult
	var wg sync.WaitGroup
	wg.Add(2)

	// upstreamQuery (DNS-M2c) даёт каждому upstream'у СВОЮ копию запроса с
	// нашим EDNS0 OPT (udpsize 1232), если клиент свой не прислал.
	go func() {
		defer wg.Done()
		uctx, cancel := context.WithTimeout(ctx, f.perUpstreamTimeout)
		defer cancel()
		yRes.msg, yRes.err = f.yandex.Resolve(uctx, upstreamQuery(q))
	}()
	go func() {
		defer wg.Done()
		uctx, cancel := context.WithTimeout(ctx, f.perUpstreamTimeout)
		defer cancel()
		cRes.msg, cRes.err = f.cloudflare.Resolve(uctx, upstreamQuery(q))
	}()
	wg.Wait()

	// SERVFAIL/REFUSED rcode приравнивается к отказу upstream'а: «ответ» без
	// ответа не должен проходить лестницу как валидный (DNS-H1). Для Yandex это
	// belt-and-suspenders: plainUDPResolver при all-SERVFAIL возвращает error,
	// а не msg; реально rcode-фильтр срабатывает только на DoHQueryRaw.
	yOK := yRes.err == nil && yRes.msg != nil && usableRcode(yRes.msg)
	cOK := cRes.err == nil && cRes.msg != nil && usableRcode(cRes.msg)

	// 3. DNS-H1 (2026-06-12): NXDOMAIN от Cloudflare — доверенного нецензурируемого
	//    upstream'а — означает, что имени действительно нет. Пропагируем NXDOMAIN
	//    клиенту и кладём в negative cache, вместо деградации в SERVFAIL: ОС
	//    трактует SERVFAIL как «резолвер сломан» (ретраи, suffix-search, DNS-SD,
	//    happy-eyeballs), а некэшируемый SERVFAIL превращал каждый повторный
	//    запрос несуществующего имени в свежий dual-resolve с полным uTLS
	//    хендшейком к 1.1.1.1 через туннель. Исключение: Yandex положительно
	//    резолвит имя в RU-classified IP (RU split-horizon, CF зону не видит) —
	//    доверяем Yandex, та же модель доверия, что в ветке yOK && !cOK ниже.
	//    DNS-H2 (2026-06-12): заглушка САМА RU-classified (yandexIsRU(stub)=true)
	//    — ответ с известным stub-IP исключению не доверяется, проваливаемся в
	//    пропагирование NXDOMAIN от CF. Доверие здесь неарбитрированное →
	//    короткий жёсткий TTL (см. unarbitratedCacheTTL).
	if cOK && cRes.msg.Rcode == dns.RcodeNameError {
		if yOK && yRes.msg.Rcode == dns.RcodeSuccess && f.yandexIsRU(yRes.msg) && !containsStubIP(yRes.msg) {
			// Неарбитрированный Yandex-serve (RU-исключение) — учитываем
			// (наблюдаемость блоков 3/4, 2026-06-12).
			f.serveUnarbitratedTotal.Add(1)
			f.cache.putWithLifetime(key, yRes.msg, unarbitratedCacheTTL)
			return yRes.msg, nil
		}
		// NXDOMAIN short-circuit (DNS-H1) — учитываем (наблюдаемость блоков 3/4).
		f.serveNXDOMAINTotal.Add(1)
		f.cache.put(key, cRes.msg)
		return cRes.msg, nil
	}

	// 4. Fallback-лестница (план §4).
	var chosen *dns.Msg
	switch {
	case yOK && cOK:
		// Оба успешны → арбитраж. Ветка нужна для наблюдаемости анти-цензурного
		// пути — фиксируем счётчик и Debug-лог (домен + выбранная ветка).
		var br branch
		chosen, br = arbitrate(yRes.msg, cRes.msg, f.match)
		f.recordBranch(key.name, br)
	case !yOK && cOK:
		// Yandex упал, CF жив → CF (foreign-через-туннель безопасен).
		chosen = cRes.msg
	case yOK && !cOK:
		// CF упал, Yandex жив → отдаём Yandex ТОЛЬКО если он RU-classified
		// (какой-то его A-IP в snapshot): на RU-сайтах цензуры нет. Иначе
		// не-RU IP без CF для сверки не доверяем → SERVFAIL. Yandex-only
		// NXDOMAIN сюда тоже попадает и НЕ доверяется (пустой A-set →
		// yandexIsRU=false): РКН-цензура умеет отвечать и NXDOMAIN'ом —
		// без CF для сверки fail-closed.
		// DNS-H2 (2026-06-12): заглушка блок-страницы САМА входит в RU snapshot
		// (yandexIsRU(stub)=true) — раньше при упавшем CF она проходила эту
		// ветку и залипала в кэше до часа (липкий ERR_CERT после восстановления
		// туннеля). Ответ с известным stub-IP отвергается целиком → честный
		// SERVFAIL; недоверенный (Yandex-only) ответ с известной блок-страницей
		// не отдаём никогда. (CF-ветки не фильтруются: CF — trust anchor; stub
		// от CF означал бы, что имя реально указывает туда.) Принятый честный
		// RU-ответ неарбитрирован (CF для сверки нет) → жёсткий короткий TTL,
		// чтобы и НЕИЗВЕСТНАЯ заглушка не залипла (defense in depth).
		if f.yandexIsRU(yRes.msg) && !containsStubIP(yRes.msg) {
			// Неарбитрированный Yandex-serve (CF упал) — учитываем
			// (наблюдаемость блоков 3/4, 2026-06-12).
			f.serveUnarbitratedTotal.Add(1)
			f.cache.putWithLifetime(key, yRes.msg, unarbitratedCacheTTL)
			return yRes.msg, nil
		}
		// INT-H2 (2026-06-12): bootstrap-whitelist — для ИЗВЕСТНОГО серверного
		// домена принимаем Yandex-ответ БЕЗ требования yandexIsRU (серверный
		// домен иностранный, RU-арбитраж для него не имеет смысла, а его IP всё
		// равно получает /32 escape). Без этого падение всех WS-слотов = вечный
		// deadlock: reconnect не может зарезолвить сервер → туннель (и CF-нога)
		// никогда не восстанавливаются. Stub-rejection, NXDOMAIN/пустой-ответ
		// fail-closed и короткий unarbitratedCacheTTL — внутри tryServeBootstrap.
		if served, ok := f.tryServeBootstrap(key, yRes.msg); ok {
			return served, nil
		}
		return nil, errAllUpstreamsFailed
	default:
		// Оба упали → SERVFAIL. Нет plaintext CF:53 fallback (вернул бы цензуру/leak).
		return nil, errAllUpstreamsFailed
	}

	if chosen == nil {
		return nil, errAllUpstreamsFailed
	}

	// 5. Кэшируем успешный ответ перед возвратом (SERVFAIL не кэшируется —
	//    ранние return выше его не достигают).
	f.cache.put(key, chosen)
	return chosen, nil
}

// buildDoHResolverPinReply builds the synthetic A reply for the DoH resolver's
// own name — the forwarder-side layer 2 of the two-layer B1 DoH-loop guard
// (I-1, 2026-06-12: comment encoding repaired). qName is the original question name (kept
// verbatim so the answer's owner matches the query casing). It returns a
// NOERROR response carrying one A record per dohResolverIPs entry. Malformed
// entries are skipped (defensive — the list is a compile-time constant).
func buildDoHResolverPinReply(r *dns.Msg, qName string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = false
	resp.RecursionAvailable = true
	resp.Rcode = dns.RcodeSuccess
	for _, ip := range dohResolverIPs {
		addr := net.ParseIP(ip)
		if addr == nil {
			continue
		}
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   qName,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    dohResolverTTL,
			},
			A: addr,
		})
	}
	return resp
}

// recordBranch increments the per-branch arbitration counter and emits a
// Debug log with the queried domain and the chosen branch. Called whenever
// arbitrate returns a branch.
func (f *Forwarder) recordBranch(domain string, br branch) {
	switch br {
	case branchYandex:
		f.branchYandexTotal.Add(1)
	case branchCloudflareCensored:
		f.branchCensoredTotal.Add(1)
	case branchCloudflareForeign:
		f.branchForeignTotal.Add(1)
	case branchYandexGeo:
		f.branchGeoTotal.Add(1)
	}
	slog.Debug("dnsproxy arbitrate", "domain", domain, "branch", br.String())
}

// BranchCounts returns the cumulative per-branch arbitration counts (yandex,
// censored, foreign, geo — DNS-M7 geo-restricted RU subcase). This is the hook
// point for wiring arbitration observability into metrics/telemetry (T6/prod).
func (f *Forwarder) BranchCounts() (yandex, censored, foreign, geo uint64) {
	return f.branchYandexTotal.Load(), f.branchCensoredTotal.Load(),
		f.branchForeignTotal.Load(), f.branchGeoTotal.Load()
}

// ServeCounts returns the cumulative counts of the two serve paths that bypass
// the arbitration ladder (наблюдаемость ревью блоков 3/4, 2026-06-12):
// nxdomain — NXDOMAIN от CF, отданный коротким замыканием до лестницы (DNS-H1);
// unarbitrated — Yandex-only ответы, принятые без сверки с CF и закэшированные
// с unarbitratedCacheTTL (DNS-H2: ветка yOK && !cOK + RU-исключение внутри
// NXDOMAIN short-circuit). Отдельный метод (а не расширение BranchCounts) —
// сигнатура BranchCounts сохранена для существующих вызовов.
func (f *Forwarder) ServeCounts() (nxdomain, unarbitrated uint64) {
	return f.serveNXDOMAINTotal.Load(), f.serveUnarbitratedTotal.Load()
}

// bootstrapAcceptLogMsg — INFO-строка принятия bootstrap-домена по Yandex-only
// (INT-H2). Полевой сигнал recovery-пути; спам естественно ограничен
// кэшированием с unarbitratedCacheTTL (одна строка ≤ раз в 30с на домен).
const bootstrapAcceptLogMsg = "split-DNS: bootstrap-домен принят по Yandex-only (CF недоступен)"

// isBootstrapDomain reports whether the canonical qname (cacheKey.name is
// already dns.CanonicalName'd by ServeDNS) is in the bootstrap whitelist (INT-H2).
func (f *Forwarder) isBootstrapDomain(name string) bool {
	_, ok := f.bootstrapDomains[name]
	return ok
}

// tryServeBootstrap — INT-H2 (2026-06-12): принимает Yandex-only ответ для
// bootstrap-домена при недоступном CF. Общий для лестницы (yOK && !cOK) и
// cfOnly-fallback'а. Условия приёма:
//   - qname в bootstrap-whitelist;
//   - Rcode == NOERROR и есть хотя бы одна A-запись: NXDOMAIN/NODATA отвергаются
//     fail-closed — РКН умеет отвечать NXDOMAIN'ом, а пустой ответ бесполезен
//     для reconnect (его кэширование лишь блокировало бы recovery-ретраи);
//   - ни один A-IP не является известной заглушкой (та же stub-семантика, что
//     в ветке yOK && !cOK): заглушка бесполезна для reconnect и не должна
//     отравить кэш.
//
// Принятый ответ неарбитрирован → учитывается в serveUnarbitratedTotal и
// кэшируется с жёстким коротким unarbitratedCacheTTL (та же модель доверия,
// что существующий неарбитрированный путь), плюс одна INFO-строка.
func (f *Forwarder) tryServeBootstrap(key cacheKey, msg *dns.Msg) (*dns.Msg, bool) {
	if !f.isBootstrapDomain(key.name) {
		return nil, false
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, false
	}
	set := a4Set(msg)
	if len(set) == 0 || setContainsStub(set) {
		return nil, false
	}
	f.serveUnarbitratedTotal.Add(1)
	f.cache.putWithLifetime(key, msg, unarbitratedCacheTTL)
	slog.Info(bootstrapAcceptLogMsg, "domain", key.name)
	return msg, true
}

// yandexIsRU сообщает, классифицируется ли ответ Yandex как RU — хотя бы один
// его A-IP попадает в snapshot.
func (f *Forwarder) yandexIsRU(msg *dns.Msg) bool {
	for ip := range a4Set(msg) {
		if f.match(ip) {
			return true
		}
	}
	return false
}

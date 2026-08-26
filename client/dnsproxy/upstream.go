package dnsproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nixavpn/shadowlink/client"
)

// Resolver резолвит DNS-запрос. Реализуется plain-UDP (Yandex) и DoH (Cloudflare).
// Интерфейс введён для тест-инъекции мок-резолверов в forwarder.
type Resolver interface {
	Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// plainUDPResolver резолвит через plain UDP к списку RU-серверов (Yandex).
// При ошибке первого сервера пробует следующий (failover по списку).
type plainUDPResolver struct {
	servers   []string    // "77.88.8.8:53", "77.88.8.1:53"
	client    *dns.Client // UDP, с таймаутом
	tcpClient *dns.Client // TCP — ретрай при TC-бите (DNS-M2)
}

// newPlainUDPResolver создаёт UDP-резолвер по списку серверов с per-exchange
// таймаутом. servers перебираются по порядку до первого успеха (failover).
func newPlainUDPResolver(servers []string, timeout time.Duration) *plainUDPResolver {
	return &plainUDPResolver{
		servers: servers,
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		},
	}
}

// Resolve перебирает серверы по порядку, возвращая первый осмысленный ответ.
// Если все серверы упали (или список пуст) — возвращается последняя ошибка,
// обёрнутая. При ошибке ответ всегда nil (никогда nil-nil).
//
// DNS-L-3 (2026-06-12): SERVFAIL/REFUSED от сервера — НЕ успех, пробуем
// следующий (раньше первый же SERVFAIL «съедал» failover на 77.88.8.1).
// Если ВСЕ серверы упали или вернули SERVFAIL/REFUSED — возвращаем ошибку,
// а НЕ последний ответ: в лестнице proxy.go yOK означает «Yandex дал
// осмысленный ответ»; SERVFAIL-only результат с пустым A-set ломал бы
// yandexIsRU-семантику (выглядел бы как foreign-ответ). NXDOMAIN при этом —
// валидный ответ («имени нет»), failover на него не срабатывает.
func (r *plainUDPResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if len(r.servers) == 0 {
		return nil, fmt.Errorf("plain-UDP resolver: список серверов пуст")
	}

	var lastErr error
	for _, server := range r.servers {
		resp, _, err := r.client.ExchangeContext(ctx, q, server)
		switch {
		case err != nil:
			lastErr = err
		case resp == nil:
			lastErr = fmt.Errorf("сервер %s вернул nil-ответ без ошибки", server)
		case resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused:
			lastErr = fmt.Errorf("сервер %s вернул %s", server, dns.RcodeToString[resp.Rcode])
		case resp.Truncated:
			// DNS-M2 (2026-06-12): TC-бит = UDP-ответ урезан под лимит буфера
			// (multi-record имена при 512-байтном лимите). Урезанный ответ —
			// ПОДМНОЖЕСТВО A-записей: пропускать его в арбитраж как полный
			// нельзя (искажённый ySet → возможна неверная ветка + кэш ≥30с).
			// Ретраим обмен по TCP к ТОМУ ЖЕ серверу за полным ответом.
			return r.retryTCP(ctx, q, server, resp), nil
		default:
			return resp, nil
		}
	}

	return nil, fmt.Errorf("plain-UDP resolver: все upstream-серверы недоступны: %w", lastErr)
}

// retryTCP повторяет обмен по TCP к тому же серверу после Truncated UDP-ответа
// (DNS-M2, 2026-06-12). Выбор при отказе TCP: возвращаем УРЕЗАННЫЙ UDP-ответ,
// а не ошибку — подмножество A-записей лучше, чем ничего (для арбитража
// частичный ySet безопаснее полного отсутствия Yandex-ветки: лестница в
// proxy.go при !yOK деградирует жёстче, чем при неполном наборе; Yandex
// urезает с начала набора, а не подменяет записи). TCP-ответ с SERVFAIL/
// REFUSED приравнивается к отказу TCP — тоже фолбэк на урезанный.
func (r *plainUDPResolver) retryTCP(ctx context.Context, q *dns.Msg, server string, truncated *dns.Msg) *dns.Msg {
	full, _, err := r.tcpClient.ExchangeContext(ctx, q, server)
	if err != nil || full == nil ||
		full.Rcode == dns.RcodeServerFailure || full.Rcode == dns.RcodeRefused {
		return truncated
	}
	return full
}

// maxDoHAttempts — сколько DoH-попыток допускается на ОДИН запрос: первая плюс
// ровно один ретрай. Не «по числу апстримов» и не лестница: см. dohAttemptContext
// о том, почему бюджет не позволяет большего.
const maxDoHAttempts = 2

// dohAttemptContext нарезает бюджет вызывающего между попытками.
//
// ⚠ ТАЙМИНГИ ОБОСНОВАНЫ ЯВНО (hard rule 8 — «не менять на глаз»; здесь это не
// константы ротации, но принцип тот же). Наблюдаемые величины НЕ трогаются:
// perUpstreamTimeout остаётся 3s, overallTimeout — 4s. Менять их и не пришлось,
// и вот арифметика, почему наивный ретрай был бы неверен:
//
//	лестница даёт резолверу uctx = min(perUpstream, остаток overall) = 3s;
//	две последовательные попытки по 3s = 6s > 4s overall.
//
// То есть при неизменных константах вторая попытка на молчащем (не rejecting, а
// именно чёрная дыра) апстриме ГАРАНТИРОВАННО упиралась бы в overallTimeout, и
// клиент получал бы SERVFAIL на 4-й секунде — ровно тот отказ, который ретрай
// должен был предотвратить. Поэтому попытки делят ОСТАТОК бюджета, а не берут
// по полному perUpstream каждая:
//
//	дедлайн попытки = now + остаток_ctx / оставшиеся_попытки
//
// При остатке 3s это 1.5s на попытку — достаточно для TCP+TLS+POST к живому
// анкасту (в поле DoH-RTT сотни мс), и обе попытки укладываются в бюджет.
// Деление, а не константа: если вызывающий даст другой бюджет (тесты, будущая
// адаптация per-AS), логика подстроится, а не превратится в зашитое число —
// ровно то, чего требует правило «пороги выводить из наблюдений, а не зашивать».
//
// Последняя попытка забирает весь остаток (делитель 1), чтобы не резать её зря.
// Если у ctx дедлайна нет вовсе — не выдумываем свой: возвращаем ctx как есть
// (у uTLS-клиента собственный 5s Timeout, он и ограничит).
func dohAttemptContext(ctx context.Context, attempt, attempts int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	remainingAttempts := attempts - attempt
	if !ok || remainingAttempts <= 1 {
		return context.WithCancel(ctx)
	}
	share := time.Until(deadline) / time.Duration(remainingAttempts)
	if share <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, share)
}

// dohUpstream — один DoH-эндпоинт: пиннутый IP + SNI для проверки сертификата
// + метка для логов. Клиент создаётся лениво (при первом обращении к этому
// апстриму), чтобы резервный апстрим не открывал сокетов, пока основной жив.
type dohUpstream struct {
	ip    string // литеральный IP для дозвона (без порта) — DNS не задействован
	sni   string // TLS ServerName; сертификат апстрима обязан быть валиден для него
	label string // короткая метка для slog (не для сети)
}

// dohQueryFunc — транспорт одного DoH-запроса к конкретному апстриму. Введён
// как test seam: тесты подменяют его сценарием, не поднимая uTLS и сеть.
type dohQueryFunc func(ctx context.Context, q *dns.Msg, upstream string) (*dns.Msg, error)

// dohResolver резолвит через DoH поверх uTLS-туннеля, с одним ретраем на
// ТРАНСПОРТНОЙ ошибке и переключением на резервный апстрим.
//
// DNS-M6 (2026-06-12): резолвер держит долгоживущие keep-alive HTTP-клиенты
// (по одному на апстрим) — раньше каждый Resolve строил свежий uTLS-клиент
// (полный TCP+TLS хендшейк к 1.1.1.1 через пул слотов на КАЖДОЕ имя страницы;
// поведенчески неправдоподобно — реальный браузер держит одно DoH-соединение).
// http.Client конкурентно-безопасен; uTLS-дайлер создаёт состояние per-dial.
//
// Единственная точка отказа, пункт 2 (2026-08-26): раньше здесь был ровно один
// вызов DoHQueryRawWith, и единичный RST на TLS-хендшейке (ровно то, что РКН
// начал делать с DoH к CF/Google в августе 2026) убивал весь DNS-запрос.
// Теперь при ТРАНСПОРТНОМ отказе делается ОДИН ретрай — и обязательно на
// ДРУГОЙ апстрим: повтор к тому же зарезанному эндпоинту воспроизвёл бы тот же
// рез. Ретрая на валидном DNS-ответе (любой Rcode) НЕТ — см. Resolve.
type dohResolver struct {
	upstreams []dohUpstream

	// query — транспорт (прод: queryUpstream поверх uTLS-клиентов). Test seam.
	query dohQueryFunc

	// mu защищает clients: ленивое создание клиента на апстрим.
	mu      sync.Mutex
	clients map[string]*http.Client
}

// newDoHResolver создаёт DoH-резолвер по списку апстримов клиента. Таймаут
// навязывается извне через ctx; сам резолвер дедлайн не выставляет (uTLS
// DoH-клиенты имеют собственный). Сокеты не открываются до первого запроса.
func newDoHResolver() *dohResolver {
	r := &dohResolver{
		upstreams: dohUpstreamsFromClient(),
		clients:   make(map[string]*http.Client, 2),
	}
	r.query = r.queryUpstream
	return r
}

// dohUpstreamsFromClient переносит список апстримов из пакета client (там же
// живут IP-пины и их route-сторожа) в локальный тип.
func dohUpstreamsFromClient() []dohUpstream {
	src := client.DoHUpstreams()
	out := make([]dohUpstream, 0, len(src))
	for _, u := range src {
		out = append(out, dohUpstream{ip: u.IP, sni: u.SNI, label: u.Label})
	}
	return out
}

// clientFor лениво создаёт (и кэширует) keep-alive uTLS-клиент для апстрима.
// Резервный апстрим не открывает ни одного сокета, пока к нему не обратились.
func (r *dohResolver) clientFor(u dohUpstream) *http.Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[u.ip]; ok {
		return c
	}
	c := client.NewDoHKeepAliveClientFor(u.ip, u.sni)
	r.clients[u.ip] = c
	return c
}

// queryUpstream — прод-транспорт: один DoH-запрос к апстриму с его клиентом.
func (r *dohResolver) queryUpstream(ctx context.Context, q *dns.Msg, label string) (*dns.Msg, error) {
	u, ok := r.upstreamByLabel(label)
	if !ok {
		return nil, fmt.Errorf("dnsproxy: неизвестный DoH-апстрим %q", label)
	}
	// Host/URL — имя ИМЕННО этого апстрима (см. dohRequestURLFor в ech.go).
	return client.DoHQueryRawWithHost(ctx, q, r.clientFor(u), u.sni)
}

func (r *dohResolver) upstreamByLabel(label string) (dohUpstream, bool) {
	for _, u := range r.upstreams {
		if u.label == label {
			return u, true
		}
	}
	return dohUpstream{}, false
}

// Resolve делегирует запрос в client.DoHQueryRawWith (через туннель) с
// переиспользуемым keep-alive клиентом (DNS-M6), с ОДНИМ ретраем на
// транспортной ошибке.
//
// DNS-H1: raw-вариант возвращает NXDOMAIN/NODATA как валидный *dns.Msg (а не
// ошибку) — лестница в proxy.go сама решает, что с rcode делать (пропагировать
// NXDOMAIN + negative cache vs трактовать SERVFAIL как отказ upstream'а).
//
// ⚠ ГРАНИЦА ОТВЕТСТВЕННОСТИ, на которой держится корректность ретрая: ретрай
// делается ТОЛЬКО когда транспорт не доехал (err != nil) — RST, таймаут, HTTP
// != 200, unpack failure. Любой РАСПАКОВАННЫЙ DNS-ответ, включая NXDOMAIN,
// NODATA и даже SERVFAIL, — это УСПЕХ уровня транспорта и возвращается сразу.
// Ретрай на плохом rcode удваивал бы трафик к origin на каждом несуществующем
// имени (браузеры генерируют их пачками) и не чинил бы ничего: отказом такой
// ответ признаёт usableRcode в proxy.go, а не этот слой.
func (r *dohResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if len(r.upstreams) == 0 {
		return nil, fmt.Errorf("dnsproxy: список DoH-апстримов пуст")
	}

	var lastErr error
	// Ровно две попытки максимум: основной апстрим, затем резервный. Лестницы
	// по всем апстримам нет намеренно — бюджет вызывающего (perUpstreamTimeout
	// внутри overallTimeout) не резиновый, см. dohAttemptContext.
	attempts := len(r.upstreams)
	if attempts > maxDoHAttempts {
		attempts = maxDoHAttempts
	}
	for i := 0; i < attempts; i++ {
		// Бюджет уже исчерпан — вторая попытка гарантированно упрётся в тот же
		// дедлайн и лишь задержит SERVFAIL. Выходим с последней ошибкой.
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}

		u := r.upstreams[i]
		actx, cancel := dohAttemptContext(ctx, i, attempts)
		resp, err := r.query(actx, q, u.label)
		cancel()

		if err == nil {
			if i > 0 {
				// Полевой сигнал, что резервный апстрим реально спасает запрос.
				slog.Debug("dnsproxy: DoH-запрос вытянул резервный апстрим",
					"upstream", u.label, "attempt", i+1)
			}
			return resp, nil
		}
		lastErr = err
		slog.Debug("dnsproxy: DoH-апстрим не ответил (транспортный отказ)",
			"upstream", u.label, "attempt", i+1, "err", err)
	}

	return nil, fmt.Errorf("dnsproxy: DoH недоступен по всем апстримам: %w", lastErr)
}

// Close сбрасывает idle keep-alive соединения всех созданных клиентов (DNS-M6).
// Вызывается из Forwarder.Stop — сокеты к резолверам не должны жить после
// остановки forwarder'а. Идемпотентен; клиенты остаются рабочими (новый запрос
// откроет новое соединение).
func (r *dohResolver) Close() {
	r.mu.Lock()
	clients := make([]*http.Client, 0, len(r.clients))
	for _, c := range r.clients {
		clients = append(clients, c)
	}
	r.mu.Unlock()
	for _, c := range clients {
		c.CloseIdleConnections()
	}
}

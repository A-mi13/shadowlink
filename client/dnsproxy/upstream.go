package dnsproxy

import (
	"context"
	"fmt"
	"net/http"
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

// dohResolver резолвит через Cloudflare DoH поверх uTLS-туннеля.
//
// DNS-M6 (2026-06-12): резолвер держит ОДИН долгоживущий keep-alive HTTP-клиент
// на весь свой lifecycle — раньше каждый Resolve строил свежий uTLS-клиент
// (полный TCP+TLS хендшейк к 1.1.1.1 через пул слотов на КАЖДОЕ имя страницы;
// поведенчески неправдоподобно — реальный браузер держит одно DoH-соединение).
// http.Client конкурентно-безопасен; uTLS-дайлер создаёт состояние per-dial.
type dohResolver struct {
	client *http.Client // долгоживущий keep-alive uTLS DoH-клиент (DNS-M6)
}

// newDoHResolver создаёт DoH-резолвер. Таймаут навязывается извне через ctx;
// сам резолвер дедлайн не выставляет (uTLS DoH-клиент имеет собственный).
// Клиент создаётся сразу (дёшево — сеть трогается только первым запросом).
func newDoHResolver() *dohResolver {
	return &dohResolver{client: client.NewDoHKeepAliveClient()}
}

// Resolve делегирует запрос в client.DoHQueryRawWith (Cloudflare 1.1.1.1 через
// туннель) с переиспользуемым keep-alive клиентом (DNS-M6). DNS-H1:
// raw-вариант возвращает NXDOMAIN/NODATA как валидный *dns.Msg (а не ошибку)
// — лестница в proxy.go сама решает, что с rcode делать (пропагировать
// NXDOMAIN + negative cache vs трактовать SERVFAIL как отказ upstream'а).
func (r *dohResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	return client.DoHQueryRawWith(ctx, q, r.client)
}

// Close сбрасывает idle keep-alive соединения клиента (DNS-M6). Вызывается из
// Forwarder.Stop — сокеты к 1.1.1.1 не должны жить после остановки forwarder'а.
// Идемпотентен; клиент остаётся рабочим (новый запрос откроет новое соединение).
func (r *dohResolver) Close() {
	r.client.CloseIdleConnections()
}

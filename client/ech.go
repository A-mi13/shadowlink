package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// dohServerIP — Cloudflare 1.1.1.1 DoH endpoint IP. The DoH client dials this
// literal IP (no DNS) so resolving the resolver's own name can never happen.
//
// B1 (2026-06-11 split-DNS final review): this is now a HARD pin, not a hint.
// Previously buildUTLSHTTPClient ignored its first arg (cfIP="") and dialed
// whatever host the request URL pointed at — `cloudflare-dns.com` — via DNS.
// In the split-DNS forwarder that name lookup re-enters the forwarder (TUN-DNS
// is the forwarder once setTUNDNS runs) → Cloudflare branch → DoHQuery → resolve
// `cloudflare-dns.com` → loop (cascade timeouts → SERVFAIL). Pinning the dial to
// the literal 1.1.1.1 removes the DNS step entirely.
//
// ⚠ HOW this connect reaches CF, stated precisely (the earlier wording said
// "routed through the tunnel by BypassDialer" and misled a 2026-08-26 review
// into believing the Go code routes it): the dialer here is a BARE net.Dialer
// (utls_http.go buildUTLSHTTPClientCommon) — no BypassDialer, no tun2socks in
// this call path. Reaching CF over the tunnel is a property of the OS ROUTING
// TABLE, not of this code, and only in TUN/SystemVPN mode:
//   - no /32 escape route exists for this IP (tunnel.go buildEscapePlan), and
//   - the /16 sweep is skipped under origin-pin,
//
// so the 0/1+128/1 split routes swallow the packet into the TUN, where
// tun2socks hands it to BypassDialer, which classifies non-RU → routeTunnel.
// In plain SOCKS5 mode (no TUN) there are no split routes and this dial goes
// DIRECT from the physical NIC, putting a cleartext ClientHello with SNI
// cloudflare-dns.com on the wire. Guards: TestDoHServerIP_HasNoEscapeRoute
// (cmd/nixavpn-client) and TestDoHServerIP_NotInRUTrie (client/bypassroute).
const dohServerIP = "1.1.1.1"

// dohSNI — the ServerName presented in the TLS handshake. Cloudflare's 1.1.1.1
// DoH endpoint serves a cert valid for `cloudflare-dns.com` and `one.one.one.one`;
// we use `cloudflare-dns.com` because it's the canonical public name.
const dohSNI = "cloudflare-dns.com"

// DoHServerIP exposes the pinned DoH dial target to other packages so route- and
// trie-level guards can assert against the LIVE constant instead of a parallel
// literal. Same single-source-of-truth role dnsproxy.DefaultYandexIPs() plays for
// the Yandex escape routes (invariant N2) — but with the OPPOSITE sign: Yandex
// MUST have a /32 escape (plain UDP, direct by design), while this IP must have
// NONE, because its protection is that it falls through to the tunnel.
//
// Why an accessor is needed at all: the DoH dialer is a bare net.Dialer
// (utls_http.go buildUTLSHTTPClientCommon) — nothing in Go code routes it. It
// reaches CF through the tunnel only because the OS routing table has no escape
// for it, so the 0/1+128/1 split routes swallow it into the TUN. That protection
// is emergent from three independent decisions and is not visible at this call
// site; see TestDoHServerIP_HasNoEscapeRoute (cmd/nixavpn-client) and
// TestDoHServerIP_NotInRUTrie (client/bypassroute) for the guards.
func DoHServerIP() string { return dohServerIP }

// dohBackupServerIP / dohBackupSNI — РЕЗЕРВНЫЙ DoH-апстрим: AdGuard unfiltered.
//
// ⚠ ЗАЧЕМ ВООБЩЕ ВТОРОЙ АПСТРИМ (2026-08-26). До этой правки 1.1.1.1 был
// ЕДИНСТВЕННЫМ DoH-резолвером клиента, без ретрая: любой отказ на нём —
// мгновенный SERVFAIL всему не-A трафику и половине A-пути. В августе 2026 РКН
// начала резать DoH/DoT к Google и Cloudflare ИМЕННО на TLS-хендшейке (TCP
// встаёт, после ClientHello — RST либо тишина); подтверждено прессой и
// множественными репортами по Ростелеком/Дом.ру/Таттелеком/SkyNet.
//
// ⚠ ПОЧЕМУ НЕ 1.0.0.1 («второй edge того же CF») — и это главный водораздел:
// он защищает от ДРУГОЙ угрозы, чем нужно. Второй edge лечит отказ ОДНОГО
// анкаст-узла (локальная авария, кривой BGP-путь), потому что 1.0.0.1 — это
// та же сеть, тот же оператор, тот же сертификат и тот же SNI
// `cloudflare-dns.com`. А режут нас именно по этим признакам: в августовской
// блокировке 1.1.1.1 И 1.0.0.1 названы вместе. Резерв, который выходит из
// строя одновременно с основным, резервом не является — от блокировки CF он
// не спасает вовсе. Поэтому нужен ДРУГОЙ оператор, а 1.0.0.1 как «третий
// эшелон от аварии» сознательно не добавлен: лишний апстрим = лишний класс
// TLS-хендшейков на wire, а бюджет ретрая всё равно только один (maxDoHAttempts).
//
// ⚠ ПОЧЕМУ НЕ GOOGLE: 8.8.8.8/dns.google режут той же мерой и в тех же
// сообщениях — это один класс отказа с CF, то есть тоже не резерв.
//
// ⚠ ПОЧЕМУ НЕ YANDEX: технически DoH у него работает, но это резолвер
// оператора в юрисдикции противника — намерение обхода утекало бы туда
// напрямую. Yandex в этом проекте живёт на СВОЁМ месте (plain-UDP нога
// арбитража, где его ответ проверяется по RU-снапшоту), и переносить его в
// доверенную DoH-роль нельзя.
//
// ⚠ ПОЧЕМУ НЕ QUAD9, хотя по «политическим» признакам он был лучшим кандидатом
// (швейцарский фонд, свой AS19281, непересекающееся IP-пространство): он
// ФИЗИЧЕСКИ НЕ РАБОТАЕТ с нашим клиентом. Замер 2026-08-26 (dial литерального
// IP без DNS + SNI + ALPN ровно как у нас):
//
//	9.9.9.10  dns10.quad9.net → HTTP 505 Version Not Supported
//	149.112.112.10            → HTTP 505
//	9.9.9.9   dns.quad9.net   → HTTP 505
//
// Причина: Quad9 обслуживает DoH только по HTTP/2, а наш uTLS-клиент жёстко
// пиннит ALPN `http/1.1` (utls_http.go, ForceAttemptHTTP2=false). Перевести
// DoH на HTTP/2 нельзя — hard rule 4: Go `net/http` шлёт non-browser HTTP/2
// SETTINGS, и это JA3-риск ровно того класса, который проект лечит. То есть
// выбор упирается не в репутацию оператора, а в ALPN. Mullvad (194.242.2.2)
// отпал по той же причине (h2-only: ALPN не согласуется, соединение рвётся),
// DNS4EU (86.54.11.100) — `tls: no application protocol`.
//
// ПОЧЕМУ ADGUARD unfiltered: из всех кандидатов, проверенных живым дозвоном,
// по `http/1.1` отвечают ТОЛЬКО Cloudflare, AdGuard и OpenDNS. Из этих трёх:
//   - OpenDNS отпадает — он назывался вместе с Google/Cloudflare в прежних
//     блокировках Ростелекома (риск общей мишени, то есть снова один класс
//     отказа) и вдобавок фильтрует по security-спискам;
//   - AdGuard — отдельная организация, собственный AS212772, сеть 94.140.14.0/24
//     не пересекается ни с Cloudflare (AS13335), ни с Google. Вариант
//     `unfiltered.` выбран сознательно: у дефолтного `dns.adguard-dns.com`
//     включена фильтрация рекламы, а чужая фильтрация для нас — чужие NXDOMAIN,
//     которые мы пропагировали бы клиенту как истину.
//
// ⚠ ЗАМЕРЕНО 2026-08-26 (не из документации): 94.140.14.140 и 94.140.14.141
// при ALPN `http/1.1` отдают HTTP 200 `application/dns-message` с валидным
// DNS-ответом, сертификат проходит системную валидацию для
// `unfiltered.adguard-dns.com` на обоих IP.
//
// ⚠ ЧЕГО ЗАМЕР НЕ ПОКАЗЫВАЕТ, и это надо держать вместе с числами:
//  1. Достижимость изнутри РФ с абонентского AS НЕ проверена — дозвон шёл с
//     машины разработчика. Для прод-пути (TUN, выход через туннель) это как раз
//     нужная точка замера, но для plain-SOCKS5 режима без TUN — нет.
//  2. Юрисдикция AdGuard — компания кипрская, но с российскими корнями. Для
//     угрозы «блокировка по диапазону» это нейтрально (нас интересует только
//     независимость отказа от CF), но для угрозы «утечка намерения обхода»
//     он слабее швейцарского Quad9. Компромисс принят сознательно: резерв,
//     который возвращает 505 на каждый запрос, не защищает вообще ни от чего.
//  3. Исследование te-st.org (07.08.2026) видело аномальные ОТВЕТЫ (подмена IP)
//     у AdGuard с российских нод — там же и у Google/Cloudflare/NextDNS.
//     Причина не установлена (авторы склоняются к resolver-side логике, а не к
//     ТСПУ). Это довод не доверять резерву БЕЗ проверки, и он у нас есть: на
//     A-пути ответ проходит арбитраж по RU-снапшоту, а stub-IP отбраковываются.
//  4. Слух «Quad9 тоже режут» (ntc.party #23007) — ложная тревога, автор сам
//     закрыл тему (виновата была локальная служба). На выбор не влиял: Quad9
//     отпал по ALPN, а не по слухам.
const (
	dohBackupServerIP = "94.140.14.140"
	dohBackupSNI      = "unfiltered.adguard-dns.com"
)

// DoHUpstream — один DoH-эндпоинт для внешних потребителей (dnsproxy строит по
// этому списку свои резолверы, route-сторожа — свои проверки).
type DoHUpstream struct {
	IP    string
	SNI   string
	Label string
}

// DoHUpstreams возвращает DoH-апстримы в порядке предпочтения: основной
// (Cloudflare), затем резервный (AdGuard unfiltered). Единый источник истины —
// тот же, что DoHServerIP() играет для основного IP.
//
// ⚠ Здесь стоял «резервный (Quad9)» — комментарий врал о механизме: Quad9 был
// кандидатом, но отвергнут замером (HTTP 505 на нашем ALPN http/1.1, см. выше).
// Исправлено ревью 2026-08-26.
//
// ⚠ КАЖДЫЙ IP В ЭТОМ СПИСКЕ несёт то же требование, что и основной: у него не
// должно быть /32-escape маршрута и он не должен попадать в RU-trie, иначе его
// TLS-хендшейк уйдёт открытым текстом с физического NIC (SNI dns10.quad9.net
// виден так же хорошо, как cloudflare-dns.com). Сторожа проверяют ВЕСЬ список,
// а не только первый элемент: TestDoHUpstreams_HaveNoEscapeRoute
// (cmd/nixavpn-client) и TestDoHUpstreams_NotInRUTrie (client/bypassroute).
func DoHUpstreams() []DoHUpstream {
	return []DoHUpstream{
		{IP: dohServerIP, SNI: dohSNI, Label: "cloudflare"},
		{IP: dohBackupServerIP, SNI: dohBackupSNI, Label: "adguard"},
	}
}

// NewDoHKeepAliveClientFor — тот же долгоживущий keep-alive uTLS DoH-клиент,
// что NewDoHKeepAliveClient, но для ПРОИЗВОЛЬНОГО апстрима (IP-пин + SNI).
// Нужен, чтобы у каждого апстрима был свой клиент со своим пулом соединений:
// один клиент на два разных IP невозможен — пин задаётся при сборке дайлера.
func NewDoHKeepAliveClientFor(ip, sni string) *http.Client {
	fp := browser.NewFingerprint(browser.ProfileChrome)
	return buildUTLSHTTPClientPinnedKeepAlive(ip, sni, fp, false, 5*time.Second, "http/1.1")
}

// newDoHClient constructs the HTTP client used for DNS-over-HTTPS queries to
// Cloudflare's 1.1.1.1 endpoint.
//
// A2-MED-1 (2026-04 audit) cure: the previous implementation built a vanilla
// `&http.Client{Timeout: 5 * time.Second}` and POSTed to `https://1.1.1.1/dns-query`,
// emitting the canonical Go-stdlib JA3 from the same client IP that minutes
// later spoke Chrome/Safari/Firefox JA3 over the ShadowLink data path. Even
// though 1.1.1.1 itself is benign, the JA3 inconsistency is a passive
// fingerprint signal for any observer who can co-locate the DoH and VPN flows.
//
// This unifies the DoH client onto the same uTLS dialer used by the data path
// (see buildUTLSHTTPClient + ws_transport / split_transport).
//
// B1 (2026-06-11): the client now dials the LITERAL 1.1.1.1 via
// buildUTLSHTTPClientPinned — no DNS lookup of `cloudflare-dns.com`. This is
// the cure for the split-DNS forwarder loop (see dohServerIP doc).
//
// ⚠ 2026-08-26: после удаления ECH-ветки продовых call-site'ов у one-shot пути
// (newDoHClient → DoHQueryRaw) в репозитории не осталось — это публичная
// обёртка «запрос без keep-alive», сохранённая намеренно. Держатель горячего
// DNS-пути — NewDoHKeepAliveClient + DoHQueryRawWith (client/dnsproxy).
func newDoHClient() *http.Client {
	// Pick a Chrome fingerprint for DoH. Chrome is the most common browser
	// fingerprint, so a Chrome JA3 hitting 1.1.1.1 is the highest-volume
	// background traffic to blend into.
	fp := browser.NewFingerprint(browser.ProfileChrome)
	return buildUTLSHTTPClientPinned(dohServerIP, dohSNI, fp, false, 5*time.Second, "http/1.1")
}

// NewDoHKeepAliveClient возвращает долгоживущий DoH-клиент с ВКЛЮЧЁННЫМ
// keep-alive для dnsproxy-форвардера. DNS-M6 (2026-06-12): one-shot клиент на
// каждый DNS-запрос = полный TCP+uTLS хендшейк к 1.1.1.1 через туннель на
// КАЖДОЕ имя страницы (шторм Chrome-ClientHello по пулу слотов) и поведенчески
// неправдоподобен — реальный браузер держит одно DoH-соединение. Вызывающий
// держит ОДИН инстанс на весь свой lifecycle и обязан звать
// CloseIdleConnections при остановке (Forwarder.Stop → dohResolver.Close).
// Тот же IP-пин 1.1.1.1 и тот же Chrome-fingerprint, что у newDoHClient;
// one-shot путь (DoHQueryRaw → newDoHClient) НЕ переводится и остаётся
// без keep-alive, как был.
func NewDoHKeepAliveClient() *http.Client {
	fp := browser.NewFingerprint(browser.ProfileChrome)
	return buildUTLSHTTPClientPinnedKeepAlive(dohServerIP, dohSNI, fp, false, 5*time.Second, "http/1.1")
}

// DoHQueryRaw sends an arbitrary DNS message over DNS-over-HTTPS to Cloudflare
// (1.1.1.1) and returns the parsed response dns.Msg regardless of its Rcode.
// The query is routed via the uTLS DoH client — see newDoHClient.
//
// DNS-H1 (2026-06-12): the dnsproxy forwarder needs NXDOMAIN / NOERROR-NODATA
// back as valid *dns.Msg responses (to propagate and negative-cache them), so
// the Rcode check lives in the DoHQuery wrapper below, NOT here. An error from
// DoHQueryRaw means transport/protocol failure only (HTTP error, unpack
// failure) — a parsed DNS answer with any Rcode is a success at this layer.
//
// NEW-2: the request is assembled by hand (not http.Client.Post) so that the
// Chrome User-Agent + sec-ch-ua header set can be attached; stdlib Post sends
// no UA, which would leave a uTLS Chrome ClientHello followed by a UA-less POST.
func DoHQueryRaw(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// One-shot клиент per-call — поведение сохранено как есть (DNS-M6 меняет
	// только dnsproxy-путь через DoHQueryRawWith).
	httpClient := newDoHClient()
	defer httpClient.CloseIdleConnections()
	return DoHQueryRawWith(ctx, m, httpClient)
}

// DoHQueryRawWith — тело DoHQueryRaw с клиентом от вызывающего. DNS-M6
// (2026-06-12): dnsproxy-форвардер передаёт сюда свой ЕДИНСТВЕННЫЙ
// долгоживущий keep-alive клиент (NewDoHKeepAliveClient) — соединение к
// 1.1.1.1 переиспользуется между запросами вместо хендшейка на каждый.
// CloseIdleConnections здесь НЕ вызывается — lifecycle клиента принадлежит
// вызывающему. http.Client безопасен для конкурентного использования;
// uTLS-дайлер под ним создаёт всё состояние per-dial (см. buildUTLSDialTLS).
func DoHQueryRawWith(ctx context.Context, m *dns.Msg, httpClient *http.Client) (*dns.Msg, error) {
	return DoHQueryRawWithHost(ctx, m, httpClient, dohSNI)
}

// dohRequestURLFor собирает RFC 8484 URL для КОНКРЕТНОГО апстрима.
//
// ⚠ Зачем отдельный хелпер, а не константа: у каждого апстрима своё имя, и
// Host/URL обязан совпадать с тем, куда мы реально дозвонились. Хардкод одного
// имени на все апстримы (как было до 2026-08-26, когда апстрим был один)
// отправил бы на резервный IP запрос с `Host: cloudflare-dns.com` — чужой Host
// на чужом сервере это в лучшем случае 404, а на wire — явная аномалия:
// SNI и Host расходятся, чего у настоящего браузера не бывает.
func dohRequestURLFor(sni string) string {
	return "https://" + sni + "/dns-query"
}

// DoHQueryRawWithHost — тело DoHQueryRawWith с ЯВНЫМ именем апстрима (оно
// определяет URL и Host). Нужен резервному апстриму: его клиент пиннут на
// другой IP и предъявляет другой SNI, поэтому и запрос обязан быть адресован
// его собственному имени.
func DoHQueryRawWithHost(ctx context.Context, m *dns.Msg, httpClient *http.Client, sni string) (*dns.Msg, error) {
	// Pack the DNS message for DoH POST
	packed, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("dns pack failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohRequestURLFor(sni), bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("doh build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", browser.LockedChromeUA())
	browser.ApplyChromeCHUA(req.Header)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh query returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("doh read failed: %w", err)
	}

	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, fmt.Errorf("dns unpack failed: %w", err)
	}

	return r, nil
}

// ⚠ УДАЛЕНО 2026-08-26: ResolveECHConfig / ECHConfig / IsExpired / DoHQuery.
// Ветка «реальный ECHConfigList из DNS HTTPS-записи» была мёртвой по построению:
// она исполнялась только при `cdn=` + `ech=1` БЕЗ `origin=` и БЕЗ `sni=`, то есть
// в чистом CDN-режиме, запрещённом hard rule 1 (прод = DIRECT к голому origin IP).
// Обе full-direct ветки engine обнуляют CDNDomain, мобильный фасад поле ECH не
// пробрасывает вовсе, а сам код по собственному комментарию только резолвил и
// кэшировал конфиг, НИКОГДА не применяя его в TLS: сетевой DoH-запрос делался,
// результат не использовался. GREASE ECH из Chrome-профиля (BoringGREASEECH)
// к этой ветке отношения не имеет и остаётся на месте.
//
// Строгая обёртка DoHQuery (Rcode != Success → ошибка) удалена вместе с ней:
// её единственным потребителем был ResolveECHConfig. Форвардеру dnsproxy нужен
// ровно противоположный контракт — NXDOMAIN/NODATA как валидный ответ, — и он
// ходит через DoHQueryRawWith.

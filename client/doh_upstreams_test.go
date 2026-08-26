package client

// Единственная точка отказа DoH, пункт 1 (2026-08-26): резервный DoH-апстрим.
//
// До правки dohServerIP=1.1.1.1 был ЕДИНСТВЕННЫМ DoH-резолвером без ретрая.
// В августе 2026 РКН начала резать DoH к Cloudflare И Google на TLS-хендшейке
// — то есть основной апстрим отказывает целиком, а не деградирует.

import (
	"net/http"
	"strings"
	"testing"
)

// Апстримов должно быть минимум два, иначе «резерв» — пустое слово. Плюс
// порядок: основной первым (менять предпочтение молча нельзя).
func TestDoHUpstreams_HasBackupAndOrder(t *testing.T) {
	ups := DoHUpstreams()
	if len(ups) < 2 {
		t.Fatalf("резервного DoH-апстрима нет: получено %d (единственная точка отказа)", len(ups))
	}
	if ups[0].IP != DoHServerIP() {
		t.Errorf("первым должен идти основной апстрим %s, получен %s", DoHServerIP(), ups[0].IP)
	}
	for i, u := range ups {
		if u.IP == "" || u.SNI == "" || u.Label == "" {
			t.Errorf("апстрим %d заполнен не полностью: %+v", i, u)
		}
	}
}

// ГЛАВНОЕ свойство резерва: он должен быть в ДРУГОЙ сети, чем основной.
// Резерв в том же /16 (например 1.0.0.1 к 1.1.1.1 — оба Cloudflare) выходит из
// строя вместе с основным при блокировке по диапазону/оператору, а именно так
// РКН и режет. Этот тест краснеет, если кто-то «упростит» резерв до второго
// edge того же провайдера.
func TestDoHUpstreams_BackupIsDifferentNetwork(t *testing.T) {
	ups := DoHUpstreams()
	primary := ups[0]

	for _, u := range ups[1:] {
		if sameSlash16(primary.IP, u.IP) {
			t.Errorf("резервный апстрим %s лежит в одном /16 с основным %s — "+
				"блокировка по диапазону вынесет оба, это не резерв", u.IP, primary.IP)
		}
		if u.SNI == primary.SNI {
			t.Errorf("резервный апстрим повторяет SNI основного (%s) — блокировка "+
				"по SNI вынесет оба", u.SNI)
		}
	}
}

// Резервом НЕ должен быть Google: его режут той же мерой и в тех же отчётах,
// что и Cloudflare, — это один класс отказа, а не резерв.
func TestDoHUpstreams_BackupIsNotGoogle(t *testing.T) {
	for _, u := range DoHUpstreams() {
		switch u.IP {
		case "8.8.8.8", "8.8.4.4":
			t.Errorf("апстрим %s (Google) режется той же мерой, что Cloudflare — "+
				"как резерв от этой угрозы бесполезен", u.IP)
		}
		if strings.Contains(u.SNI, "dns.google") {
			t.Errorf("апстрим с SNI %s (Google) — тот же класс отказа, что CF", u.SNI)
		}
	}
}

// Резервом НЕ должен быть резолвер в юрисдикции противника: DoH-апстрим —
// доверенная роль (его ответы попадают в кэш без арбитража на не-A пути), и
// намерение обхода утекало бы туда напрямую. Yandex в проекте живёт на своём
// месте — plain-UDP ногой арбитража, где его ответ проверяется по RU-снапшоту.
func TestDoHUpstreams_BackupIsNotRussianResolver(t *testing.T) {
	for _, u := range DoHUpstreams() {
		if strings.HasPrefix(u.IP, "77.88.8.") || strings.Contains(u.SNI, "yandex") {
			t.Errorf("апстрим %s/%s — резолвер в юрисдикции противника; в доверенной "+
				"DoH-роли недопустим", u.IP, u.SNI)
		}
	}
}

// sameSlash16 сравнивает первые два октета IPv4.
func sameSlash16(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	if len(as) < 2 || len(bs) < 2 {
		return false
	}
	return as[0] == bs[0] && as[1] == bs[1]
}

// Клиент для резервного апстрима обязан быть таким же uTLS-клиентом, как
// основной (Chrome JA3, keep-alive): резерв, уходящий на wire со stdlib-JA3,
// сам по себе сигнал — ровно тот дефект, что чинил A2-MED-1.
func TestNewDoHKeepAliveClientFor_UsesUTLSTransport(t *testing.T) {
	for _, u := range DoHUpstreams() {
		c := NewDoHKeepAliveClientFor(u.IP, u.SNI)
		if c == nil {
			t.Fatalf("апстрим %s: nil-клиент", u.Label)
		}
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("апстрим %s: Transport должен быть *http.Transport, получен %T", u.Label, c.Transport)
		}
		if tr.DialTLSContext == nil {
			t.Errorf("апстрим %s: DialTLSContext не выставлен — запрос уйдёт со "+
				"stdlib-JA3 вместо Chrome (A2-MED-1)", u.Label)
		}
		if tr.DisableKeepAlives {
			t.Errorf("апстрим %s: keep-alive должен быть ВКЛЮЧЁН (DNS-M6) — иначе "+
				"хендшейк на каждое имя", u.Label)
		}
	}
}

// Запрос к апстриму обязан нести Host/URL ЭТОГО апстрима. Хардкод одного имени
// на все апстримы отправил бы на резервный AdGuard запрос с Host:
// cloudflare-dns.com —
// чужой Host на чужом IP это в лучшем случае 404, в худшем — явная аномалия
// в логах посредника.
func TestDoHRequestURLFor_MatchesUpstreamSNI(t *testing.T) {
	for _, u := range DoHUpstreams() {
		got := dohRequestURLFor(u.SNI)
		if !strings.Contains(got, u.SNI) {
			t.Errorf("апстрим %s: URL %q не содержит его собственного имени %s",
				u.Label, got, u.SNI)
		}
		if !strings.HasPrefix(got, "https://") {
			t.Errorf("апстрим %s: URL %q должен быть https", u.Label, got)
		}
	}
}

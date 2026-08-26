package dnsproxy

// DNS-M6 (2026-06-12): dohResolver держит ОДИН долгоживущий keep-alive
// uTLS HTTP-клиент на весь свой lifecycle — каждый DNS-запрос больше не
// порождает свежий TCP+TLS хендшейк к 1.1.1.1 через туннель (страница =
// десятки параллельных имён = шторм Chrome-ClientHello; реальный браузер
// держит ОДНО DoH-соединение). Forwarder.Stop гасит idle-соединения,
// чтобы сокеты не жили после остановки.

import (
	"net/http"
	"sync/atomic"
	"testing"
)

// dohResolver держит по ОДНОМУ долгоживящему keep-alive клиенту НА АПСТРИМ и
// переиспользует его между запросами (DNS-M6). С появлением резервного
// апстрима (2026-08-26) клиентов стало несколько — по одному на IP-пин, потому
// что пин задаётся при сборке дайлера и один клиент два разных IP обслужить не
// может, — но свойство «клиент переиспользуется, а не создаётся на запрос»
// сохранено, и именно оно здесь проверяется.
func TestDoHResolver_HoldsKeepAliveClientPerUpstream(t *testing.T) {
	r := newDoHResolver()
	if len(r.upstreams) < 2 {
		t.Fatalf("ожидался резервный апстрим, получено %d", len(r.upstreams))
	}

	for _, u := range r.upstreams {
		c := r.clientFor(u)
		if c == nil {
			t.Fatalf("апстрим %s: клиент не создан", u.label)
		}
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("апстрим %s: ожидался *http.Transport, получен %T", u.label, c.Transport)
		}
		if tr.DisableKeepAlives {
			t.Fatalf("DNS-M6: keep-alive должен быть ВКЛЮЧЁН у DoH-клиента (%s)", u.label)
		}
		// Тот же апстрим обязан отдавать ТОТ ЖЕ инстанс — иначе keep-alive
		// бессмысленен: каждый запрос открывал бы новое соединение.
		if again := r.clientFor(u); again != c {
			t.Fatalf("апстрим %s: клиент должен переиспользоваться, получены разные инстансы", u.label)
		}
	}
}

// Резервный апстрим не должен открывать НИ ОДНОГО сокета, пока основной жив:
// клиент создаётся лениво, при первом обращении именно к нему. Иначе на wire
// появлялся бы лишний класс TLS-хендшейков (к 94.140.14.140) даже когда
// Cloudflare прекрасно отвечает.
func TestDoHResolver_BackupClientCreatedLazily(t *testing.T) {
	r := newDoHResolver()
	if len(r.clients) != 0 {
		t.Fatalf("до первого запроса клиентов быть не должно, есть %d", len(r.clients))
	}

	r.clientFor(r.upstreams[0]) // трогаем ТОЛЬКО основной
	if _, ok := r.clients[r.upstreams[1].ip]; ok {
		t.Fatal("клиент резервного апстрима создан, хотя к нему не обращались — " +
			"это лишний класс хендшейков на wire")
	}
}

// closableResolver — мок Resolver с Close-флагом (seam для проверки, что
// Forwarder.Stop закрывает DoH-клиент cloudflare-резолвера).
type closableResolver struct {
	mockResolver
	closed atomic.Bool
}

func (r *closableResolver) Close() { r.closed.Store(true) }

// Forwarder.Stop должен звать Close на cloudflare-резолвере (если тот его
// реализует) — idle keep-alive сокеты к 1.1.1.1 не утекают после Stop.
func TestForwarder_StopClosesCloudflareResolver(t *testing.T) {
	c := &closableResolver{}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(&mockResolver{}, c))
	if err := f.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := f.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !c.closed.Load() {
		t.Fatal("Stop должен закрывать DoH-клиент cloudflare-резолвера (Close)")
	}
}

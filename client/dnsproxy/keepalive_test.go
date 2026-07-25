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

// dohResolver хранит долгоживущий клиент с ВКЛЮЧЁННЫМ keep-alive (один
// инстанс на всё время жизни резолвера; Resolve переиспользует его).
func TestNewDoHResolver_HoldsSingleKeepAliveClient(t *testing.T) {
	r := newDoHResolver()
	if r.client == nil {
		t.Fatal("dohResolver должен держать долгоживущий HTTP-клиент")
	}
	tr, ok := r.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("ожидался *http.Transport, получен %T", r.client.Transport)
	}
	if tr.DisableKeepAlives {
		t.Fatal("DNS-M6: keep-alive должен быть ВКЛЮЧЁН у DoH-клиента форвардера")
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

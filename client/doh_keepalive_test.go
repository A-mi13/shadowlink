package client

// DNS-M6 (2026-06-12): два DoH-клиента с разным lifecycle.
// ECH bootstrap путь остаётся one-shot (DisableKeepAlives=true, как был);
// dnsproxy-форвардер получает долгоживущий keep-alive клиент через
// NewDoHKeepAliveClient — реальный браузер держит ОДНО DoH-соединение,
// а не свежий Chrome-ClientHello на каждый DNS-запрос.

import (
	"net/http"
	"testing"
)

// ECH/one-shot путь не изменился: keep-alive выключен, клиент строится
// per-call (newDoHClient внутри DoHQueryRaw, как было).
func TestNewDoHClient_OneShot_KeepAlivesDisabled(t *testing.T) {
	c := newDoHClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("ожидался *http.Transport, получен %T", c.Transport)
	}
	if !tr.DisableKeepAlives {
		t.Fatal("ECH/one-shot DoH-клиент должен остаться без keep-alive")
	}
}

// Долгоживущий клиент для dnsproxy: keep-alive включён.
func TestNewDoHKeepAliveClient_KeepAlivesEnabled(t *testing.T) {
	c := NewDoHKeepAliveClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("ожидался *http.Transport, получен %T", c.Transport)
	}
	if tr.DisableKeepAlives {
		t.Fatal("DNS-M6: NewDoHKeepAliveClient должен включать keep-alive")
	}
}

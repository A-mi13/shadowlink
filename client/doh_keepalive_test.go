package client

// DNS-M6 (2026-06-12): два DoH-клиента с разным lifecycle.
// One-shot путь остаётся без keep-alive (DisableKeepAlives=true, как был);
// dnsproxy-форвардер получает долгоживущий keep-alive клиент через
// NewDoHKeepAliveClient — реальный браузер держит ОДНО DoH-соединение,
// а не свежий Chrome-ClientHello на каждый DNS-запрос.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One-shot путь не изменился: keep-alive выключен, клиент строится per-call
// (newDoHClient внутри DoHQueryRaw, как было).
func TestNewDoHClient_OneShot_KeepAlivesDisabled(t *testing.T) {
	c := newDoHClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("ожидался *http.Transport, получен %T", c.Transport)
	}
	if !tr.DisableKeepAlives {
		t.Fatal("one-shot DoH-клиент должен остаться без keep-alive")
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

// TestNewDoHClient_UsesUTLSTransport проверяет, что DoH-клиент ходит через
// uTLS-дайлер (выставлен DialTLSContext), а не через стандартный TLS-раундтриппер
// Go.
//
// A2-MED-1 (аудит 2026-04): прежняя реализация строила `&http.Client{}` на месте
// и звала `httpClient.Post("https://1.1.1.1/dns-query", ...)`. Это даёт
// каноничный JA3 стандартной библиотеки Go с того же IP, который минутами позже
// говорит Chrome-JA3 по data-path — бесплатная нестыковка отпечатков для любого
// пассивного наблюдателя, способного сопоставить DoH- и ShadowLink-потоки.
//
// ⚠ Переехал сюда из client/ech_test.go 2026-08-26: тот файл удалён вместе с
// ECH-веткой, но САМ сторож к ECH отношения не имеет — он про JA3 DoH-клиента,
// а DoH жив и обслуживает dnsproxy. Терять его при удалении ECH нельзя.
func TestNewDoHClient_UsesUTLSTransport(t *testing.T) {
	c := newDoHClient()
	require.NotNil(t, c, "newDoHClient обязан вернуть не-nil *http.Client")

	tr, ok := c.Transport.(*http.Transport)
	require.True(t, ok, "Transport DoH-клиента обязан быть *http.Transport (получен %T)", c.Transport)
	require.NotNil(t, tr.DialTLSContext, "DialTLSContext обязан быть выставлен — это и доказывает uTLS-путь (A2-MED-1)")
	assert.True(t, tr.DisableKeepAlives, "DoH-клиент обязан выключать keep-alive (гигиена JA3 на холодном пути)")
}

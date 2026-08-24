package client

import (
	"context"
	nethttp "net/http"
	"testing"
	"time"
)

// boolPtr — локальный хелпер для *bool-полей конфига.
func boolPtr(b bool) *bool { return &b }

// TestResolveDataPathBodyPrefix проверяет приоритет «дефолт(env) → явное поле».
// Это ядро правки: package-var остаётся дефолтом, ClientConfig.DataPathBodyPrefix
// побеждает, когда задан.
func TestResolveDataPathBodyPrefix(t *testing.T) {
	// Зафиксировать дефолт в известное состояние на время теста.
	restore := withDataPathBodyPrefix(true)
	t.Cleanup(restore)

	if got := resolveDataPathBodyPrefix(nil); got != true {
		t.Fatalf("nil override при дефолте=true: got %v, want true (должен браться дефолт)", got)
	}
	if got := resolveDataPathBodyPrefix(boolPtr(false)); got != false {
		t.Fatalf("override=false при дефолте=true: got %v, want false (override обязан победить)", got)
	}

	// Перевернуть дефолт и повторить — убеждаемся, что nil действительно следует
	// за дефолтом, а не за константой.
	restore2 := withDataPathBodyPrefix(false)
	t.Cleanup(restore2)
	if got := resolveDataPathBodyPrefix(nil); got != false {
		t.Fatalf("nil override при дефолте=false: got %v, want false", got)
	}
	if got := resolveDataPathBodyPrefix(boolPtr(true)); got != true {
		t.Fatalf("override=true при дефолте=false: got %v, want true", got)
	}
}

// captureAuthorization поднимает тестовый сервер, ловит один запрос и возвращает
// его Authorization-заголовок. Пустая строка = body-prefix путь, "Bearer …" =
// legacy путь. Различие на ПРОВОДЕ — тот же метод, что у существующих тестов.
func captureAuthorization(t *testing.T, send func(tr *DirectTransport, token, enc []byte)) string {
	t.Helper()
	authCh := make(chan string, 1)
	handler := func(w nethttp.ResponseWriter, r *nethttp.Request) {
		select {
		case authCh <- r.Header.Get("authorization"):
		default:
		}
		emptyResp, _ := buildDataEnvelope(nil, nil)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(emptyResp)
	}
	addr, stop := startStdlibTestServer(t, handler)
	t.Cleanup(stop)

	tr := NewDirectTransport(addr, false, true)
	t.Cleanup(func() { _ = tr.Close() })

	token := make([]byte, 36)
	enc := []byte{0x11, 0x22, 0x33}
	send(tr, token, enc)

	select {
	case a := <-authCh:
		return a
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout: сервер не получил запрос")
		return ""
	}
}

// clientTransportWithConfig строит Client через публичный NewClient с заданным
// ClientConfig и достаёт его *DirectTransport. Тем самым проверяется РЕАЛЬНЫЙ
// путь проброса config → transport, а не приватный конструктор в обход.
func clientTransportWithConfig(t *testing.T, addr string, cfg ClientConfig) *DirectTransport {
	t.Helper()
	cfg.ServerAddr = addr
	cfg.UseTLS = false
	cfg.SkipVerify = true
	cfg.ServerPubKey = make([]byte, 32)
	cfg.ClientID = make([]byte, 16)
	cl := NewClient(cfg)
	tr, ok := cl.transport.(*DirectTransport)
	if !ok {
		t.Fatalf("ожидался *DirectTransport, получен %T", cl.transport)
	}
	return tr
}

// TestClientConfig_DataPathBodyPrefix_OverridesEnvDefault — СТОРОЖ С ВЛАСТЬЮ.
// Дефолт (env) выставлен в ON, а поле конфига — в OFF. Если проброс работает,
// на проводе появится Authorization: Bearer (legacy путь), несмотря на дефолт.
// Проверяется через NewClient → transport → SendChunk, то есть весь публичный
// путь.
//
// Власть: если откатить правку (вернуть чтение глобала defaultDataPathBodyPrefix
// в SendChunk, либо убрать проброс bodyPrefix в NewClient), транспорт будет
// читать дефолт=ON и Authorization исчезнет — тест покраснеет. Проверено порчей,
// см. отчёт.
func TestClientConfig_DataPathBodyPrefix_OverridesEnvDefault(t *testing.T) {
	// Дефолт (env) = body-prefix ON. Поле конфига переворачивает его в OFF.
	restore := withDataPathBodyPrefix(true)
	t.Cleanup(restore)

	authCh := make(chan string, 1)
	handler := func(w nethttp.ResponseWriter, r *nethttp.Request) {
		select {
		case authCh <- r.Header.Get("authorization"):
		default:
		}
		emptyResp, _ := buildDataEnvelope(nil, nil)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(emptyResp)
	}
	addr, stop := startStdlibTestServer(t, handler)
	t.Cleanup(stop)

	tr := clientTransportWithConfig(t, addr, ClientConfig{
		DataPathBodyPrefix: boolPtr(false), // override: legacy Bearer, вопреки дефолту ON
	})
	t.Cleanup(func() { _ = tr.Close() })

	token := make([]byte, 36)
	enc := []byte{0xaa, 0xbb, 0xcc}
	_, _ = tr.SendChunk(context.Background(), enc, token, 0)

	var authz string
	select {
	case authz = <-authCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout: сервер не получил запрос")
	}
	if authz == "" {
		t.Fatalf("override=false обязан вернуть legacy путь с Authorization, а его нет — проброс config→transport не работает")
	}
}

// TestClientConfig_DataPathBodyPrefix_NilFollowsDefault проверяет обратную
// сторону: nil-поле НЕ ломает поведение CLI — берётся дефолт. Дефолт OFF → на
// проводе Authorization присутствует; дефолт ON → отсутствует. Это гарантия
// пункта 2 задачи (CLI продолжает работать через env без правок).
func TestClientConfig_DataPathBodyPrefix_NilFollowsDefault(t *testing.T) {
	t.Run("default_off_nil_field", func(t *testing.T) {
		restore := withDataPathBodyPrefix(false)
		t.Cleanup(restore)
		authz := captureAuthorization(t, func(tr *DirectTransport, token, enc []byte) {
			// Транспорт из captureAuthorization создаётся публичным конструктором,
			// который читает дефолт — эквивалент nil-поля в NewClient.
			_, _ = tr.SendChunk(context.Background(), enc, token, 0)
		})
		if authz == "" {
			t.Fatalf("дефолт OFF + nil-поле: ожидался legacy Authorization, а его нет")
		}
	})
	t.Run("default_on_nil_field", func(t *testing.T) {
		restore := withDataPathBodyPrefix(true)
		t.Cleanup(restore)
		authz := captureAuthorization(t, func(tr *DirectTransport, token, enc []byte) {
			_, _ = tr.SendChunk(context.Background(), enc, token, 0)
		})
		if authz != "" {
			t.Fatalf("дефолт ON + nil-поле: Authorization должен отсутствовать, got %q", authz)
		}
	})
}

// TestDirectTransport_BodyPrefixSnapshot проверяет, что транспорт снимает флаг на
// КОНСТРУИРОВАНИИ и не подвержен последующей смене дефолта — свойство, на котором
// держится совместимость withDataPathBodyPrefix со старыми тестами.
func TestDirectTransport_BodyPrefixSnapshot(t *testing.T) {
	restore := withDataPathBodyPrefix(false)
	tr := newDirectTransportBP("127.0.0.1:1", false, true, true) // явный ON вопреки дефолту OFF
	t.Cleanup(func() { _ = tr.Close() })
	restore() // вернуть дефолт — на снимок влиять не должно
	if !tr.dataPathBodyPrefix {
		t.Fatalf("транспорт не сохранил явный bodyPrefix=true (снимок на конструировании потерян)")
	}
}

package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// MEDIUM «Management API без таймаутов» (раунд 18): mgmtSrv создавался как голый
// &http.Server{Addr, Handler} — ни ReadHeaderTimeout, ни ReadTimeout, ни
// WriteTimeout, ни MaxHeaderBytes, тогда как основной сервер их имеет.
//
// Ключ проверяется в ManagementHandler.ServeHTTP, то есть ПОСЛЕ дочитывания
// заголовков net/http → pre-auth slowloris пинит горутины неаутентифицированным
// peer'ом. Bind по умолчанию loopback, но -mgmt-bind выводит порт наружу,
// поэтому «только localhost» защитой не является.
//
// Post-auth: три POST-хендлера читали тело через json.NewDecoder(r.Body) без
// MaxBytesReader. Минимальная длина ManagementKey не проверялась вовсе.

func TestManagement_ServerHasTimeouts(t *testing.T) {
	cfg := TestConfig()
	cfg.ManagementPort = 65000
	cfg.ManagementKey = strings.Repeat("k", minManagementKeyLen)

	key, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	s2, err := New(cfg, key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s2.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { s2.Stop() })

	if s2.mgmtSrv == nil {
		t.Fatal("mgmtSrv не создан при ManagementPort > 0")
	}
	if s2.mgmtSrv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout не задан — pre-auth slowloris пинит горутины")
	}
	if s2.mgmtSrv.ReadTimeout == 0 {
		t.Error("ReadTimeout не задан")
	}
	if s2.mgmtSrv.WriteTimeout == 0 {
		t.Error("WriteTimeout не задан")
	}
	if s2.mgmtSrv.IdleTimeout == 0 {
		t.Error("IdleTimeout не задан")
	}
	if s2.mgmtSrv.MaxHeaderBytes == 0 {
		t.Error("MaxHeaderBytes не задан — заголовки не ограничены")
	}
	// Строже основного сервера: там ReadHeaderTimeout = 10s.
	if s2.mgmtSrv.ReadHeaderTimeout > 10*time.Second {
		t.Errorf("ReadHeaderTimeout=%v — не строже основного сервера",
			s2.mgmtSrv.ReadHeaderTimeout)
	}
}

// Тело управляющего запроса должно быть ограничено.
func TestManagement_BodyIsBounded(t *testing.T) {
	const key = "test-management-key-long-enough-x"
	ca := NewClientAuth([]string{"u1:d1"})
	mh := NewManagementHandler(ca, NewMetrics(), key)

	// Тело заметно больше лимита.
	huge := bytes.Repeat([]byte("a"), mgmtMaxBodyBytes*2)
	body := append([]byte(`{"client_id":"`), huge...)
	body = append(body, []byte(`"}`)...)

	r := httptest.NewRequest(http.MethodPost, "/manage/clients", bytes.NewReader(body))
	r.Header.Set("X-Management-Key", key)
	w := httptest.NewRecorder()

	mh.ServeHTTP(w, r)

	// MaxBytesReader обрывает чтение → декодер видит ошибку → 400.
	if w.Code == http.StatusOK {
		t.Errorf("тело %d байт принято при лимите %d — MaxBytesReader не применён",
			len(body), mgmtMaxBodyBytes)
	}
	// И клиент НЕ должен был быть добавлен.
	if ca.IsAuthorized(string(huge)) {
		t.Error("клиент из переразмерного тела добавлен")
	}
}

// Нормальный запрос в пределах лимита обязан работать (контроль).
func TestManagement_NormalRequestStillWorks(t *testing.T) {
	const key = "test-management-key-long-enough-x"
	ca := NewClientAuth([]string{"u1:d1"})
	mh := NewManagementHandler(ca, NewMetrics(), key)

	r := httptest.NewRequest(http.MethodPost, "/manage/clients",
		strings.NewReader(`{"client_id":"u42:d1"}`))
	r.Header.Set("X-Management-Key", key)
	w := httptest.NewRecorder()

	mh.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("нормальный запрос отклонён: код %d, тело %q", w.Code, w.Body.String())
	}
	if !ca.IsAuthorized("u42:d1") {
		t.Error("клиент не добавлен нормальным запросом")
	}
}

// Короткий ключ при НЕ-loopback bind должен валить старт (fail-fast).
func TestManagement_ShortKeyRejectedOnPublicBind(t *testing.T) {
	cfg := TestConfig()
	cfg.ManagementPort = 65001
	cfg.ManagementBind = "0.0.0.0"
	cfg.ManagementKey = "short"

	key, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	s, err := New(cfg, key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Start(); err == nil {
		s.Stop()
		t.Error("короткий ключ на публичном bind должен валить старт")
	} else if !strings.Contains(err.Error(), "too short") {
		t.Errorf("неожиданная ошибка: %v", err)
	}
}

// На loopback короткий ключ старт не валит (осознанный компромисс: не ронять
// унаследованные конфиги), но должен быть WARN — проверяем сам факт запуска.
func TestManagement_ShortKeyAllowedOnLoopbackWithWarn(t *testing.T) {
	cfg := TestConfig()
	cfg.ManagementPort = 65002
	cfg.ManagementBind = "127.0.0.1"
	cfg.ManagementKey = "short"

	key, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	s, err := New(cfg, key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Start(); err != nil {
		t.Errorf("на loopback короткий ключ не должен валить старт: %v", err)
		return
	}
	t.Cleanup(func() { s.Stop() })
}

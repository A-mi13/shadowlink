package bypassroute

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testHMACKey = []byte("test-hmac-key-32-bytes-padding!!")

// signBody возвращает hex(HMAC-SHA256(key, body)).
func signBody(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// makeServerBody конструирует пару (HTTP-тело, HMAC-подпись) в legacy v1
// формате, который старый сервер выдаёт в /api/v1/client/shadowlink/bypass
// (без X-Bypass-Signature-Version header'а). Используется для тестов
// backward-compat + ошибочных путей.
func makeServerBody(t *testing.T, etag string, adds, excludes []entryDTO) (body []byte, sig string) {
	t.Helper()
	if adds == nil {
		adds = make([]entryDTO, 0)
	}
	if excludes == nil {
		excludes = make([]entryDTO, 0)
	}
	checkBody, err := json.Marshal(struct {
		Adds     []entryDTO `json:"adds"`
		Excludes []entryDTO `json:"excludes"`
	}{adds, excludes})
	if err != nil {
		t.Fatalf("marshal check body: %v", err)
	}
	sig = signBody(testHMACKey, checkBody)

	respBody, err := json.Marshal(fetchResponse{
		Etag:     etag,
		Adds:     adds,
		Excludes: excludes,
	})
	if err != nil {
		t.Fatalf("marshal response body: %v", err)
	}
	return respBody, sig
}

// makeServerBodyV2 конструирует пару (HTTP-тело, HMAC-подпись) в v2 формате:
// HMAC over {etag, adds, excludes}. Каноничный Marshal через sigBodyV2 совпадает
// с server-side bypassSignedPayloadV2.
func makeServerBodyV2(t *testing.T, etag string, adds, excludes []entryDTO) (body []byte, sig string) {
	t.Helper()
	if adds == nil {
		adds = make([]entryDTO, 0)
	}
	if excludes == nil {
		excludes = make([]entryDTO, 0)
	}
	checkBody, err := json.Marshal(sigBodyV2{Etag: etag, Adds: adds, Excludes: excludes})
	if err != nil {
		t.Fatalf("marshal v2 check body: %v", err)
	}
	sig = signBody(testHMACKey, checkBody)

	respBody, err := json.Marshal(fetchResponse{
		Etag:     etag,
		Adds:     adds,
		Excludes: excludes,
	})
	if err != nil {
		t.Fatalf("marshal response body: %v", err)
	}
	return respBody, sig
}

// TestFetchAdminOverride_HappyPath_LegacyV1Server — старый сервер не понимает
// query ?cli_v=2 и не присылает X-Bypass-Signature-Version. Клиент должен
// fallback'нуться на v1 verify (HMAC over {adds, excludes}) и принять ответ.
// Backward-compat тест: gradual rollout, новый клиент должен работать с
// pre-P2-1 сервером.
func TestFetchAdminOverride_HappyPath_LegacyV1Server(t *testing.T) {
	adds := []entryDTO{{CIDR: "100.99.99.0/24", Action: "add"}}
	excludes := []entryDTO{}
	body, sig := makeServerBody(t, "deadbeef", adds, excludes)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/client/shadowlink/bypass" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("expected Bearer token, got %q", got)
		}
		// Клиент ВСЕГДА шлёт cli_v=2 — старый сервер просто игнорирует.
		if got := r.URL.Query().Get("cli_v"); got != "2" {
			t.Errorf("expected cli_v=2 in query, got %q", got)
		}
		w.Header().Set("ETag", "deadbeef")
		w.Header().Set("X-Bypass-Signature", sig)
		// Намеренно НЕ пишем X-Bypass-Signature-Version — эмулируем legacy server.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	ov, err := FetchAdminOverride(srv.Client(), srv.URL, "test-token", "", testHMACKey, "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if ov == nil {
		t.Fatal("expected non-nil override")
	}
	if ov.Etag != "deadbeef" {
		t.Errorf("etag: want deadbeef, got %q", ov.Etag)
	}
	if len(ov.Adds) != 1 {
		t.Fatalf("adds: want 1, got %d", len(ov.Adds))
	}
	if ov.Adds[0].String() != "100.99.99.0/24" {
		t.Errorf("adds[0]: want 100.99.99.0/24, got %s", ov.Adds[0])
	}
	if len(ov.Excludes) != 0 {
		t.Errorf("excludes: want 0, got %d", len(ov.Excludes))
	}
}

// TestFetchAdminOverride_HappyPath_V2Server — новый сервер отдаёт v2 scope.
// HMAC покрывает {etag, adds, excludes}. Клиент видит header
// X-Bypass-Signature-Version=2, использует v2 verify и принимает ответ.
func TestFetchAdminOverride_HappyPath_V2Server(t *testing.T) {
	adds := []entryDTO{{CIDR: "100.99.99.0/24", Action: "add"}}
	excludes := []entryDTO{{CIDR: "192.168.0.0/16", Action: "exclude"}}
	body, sig := makeServerBodyV2(t, "v2etag", adds, excludes)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cli_v"); got != "2" {
			t.Errorf("expected cli_v=2 in query, got %q", got)
		}
		w.Header().Set("ETag", "v2etag")
		w.Header().Set("X-Bypass-Signature", sig)
		w.Header().Set("X-Bypass-Signature-Version", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	ov, err := FetchAdminOverride(srv.Client(), srv.URL, "test-token", "", testHMACKey, "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if ov == nil {
		t.Fatal("expected non-nil override")
	}
	if ov.Etag != "v2etag" {
		t.Errorf("etag: want v2etag, got %q", ov.Etag)
	}
	if len(ov.Adds) != 1 || ov.Adds[0].String() != "100.99.99.0/24" {
		t.Errorf("adds: want [100.99.99.0/24], got %v", ov.Adds)
	}
	if len(ov.Excludes) != 1 || ov.Excludes[0].String() != "192.168.0.0/16" {
		t.Errorf("excludes: want [192.168.0.0/16], got %v", ov.Excludes)
	}
}

// TestFetchAdminOverride_V2_TamperedEtag_Rejected — критичный security тест.
// Сервер подписал v2 с etag="v2etag", MITM подменил etag в response body на
// "forgedetag" → подпись больше не сходится, fetch должен fail'нуться.
// Закрывает freshness/rollback oracle (P2-1 final-audit T1 §P2).
func TestFetchAdminOverride_V2_TamperedEtag_Rejected(t *testing.T) {
	adds := []entryDTO{{CIDR: "100.99.99.0/24", Action: "add"}}
	excludes := []entryDTO{}
	// Подпись посчитана над оригинальным etag.
	_, sig := makeServerBodyV2(t, "v2etag", adds, excludes)
	// Body отправляем с подменённым etag — MITM swap.
	tamperedBody, err := json.Marshal(fetchResponse{Etag: "forgedetag", Adds: adds, Excludes: excludes})
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "forgedetag")
		w.Header().Set("X-Bypass-Signature", sig)
		w.Header().Set("X-Bypass-Signature-Version", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tamperedBody)
	}))
	defer srv.Close()

	_, err = FetchAdminOverride(srv.Client(), srv.URL, "tok", "", testHMACKey, "")
	if err == nil {
		t.Fatal("expected signature mismatch on tampered etag, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Errorf("expected signature error, got %v", err)
	}
}

// TestFetchAdminOverride_UnknownSigVersion_Rejected — anti-downgrade проверка.
// MITM/buggy server присылает X-Bypass-Signature-Version=99 (неизвестное).
// Клиент должен reject'ить, а не silently fallback'нуться на v1.
func TestFetchAdminOverride_UnknownSigVersion_Rejected(t *testing.T) {
	body, sig := makeServerBody(t, "etag1", nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Bypass-Signature", sig)
		w.Header().Set("X-Bypass-Signature-Version", "99")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := FetchAdminOverride(srv.Client(), srv.URL, "tok", "", testHMACKey, "")
	if err == nil {
		t.Fatal("expected error on unknown sig version, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "version") {
		t.Errorf("expected error to mention version, got %v", err)
	}
}

func TestFetchAdminOverride_NotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("etag"); got != "abcd1234" {
			t.Errorf("expected etag query param abcd1234, got %q", got)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	ov, err := FetchAdminOverride(srv.Client(), srv.URL, "test-token", "abcd1234", testHMACKey, "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if ov != nil {
		t.Errorf("expected nil override on 304, got %+v", ov)
	}
}

func TestFetchAdminOverride_BadSignature(t *testing.T) {
	body, _ := makeServerBody(t, "etag1", nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Bypass-Signature", "0000000000000000000000000000000000000000000000000000000000000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := FetchAdminOverride(srv.Client(), srv.URL, "tok", "", testHMACKey, "")
	if err == nil {
		t.Fatal("expected signature error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Errorf("expected error to mention 'signature', got %v", err)
	}
}

func TestFetchAdminOverride_MissingSignature(t *testing.T) {
	body, _ := makeServerBody(t, "etag1", nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := FetchAdminOverride(srv.Client(), srv.URL, "tok", "", testHMACKey, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "missing") {
		t.Errorf("expected error to mention 'missing', got %v", err)
	}
}

// TestFetchAdminOverride_StickyV2_RejectsDowngrade verifies that once a
// client has accepted a v2 signature from a server (recorded in
// previousSigVersion), any subsequent v1 reply from that server is
// treated as a downgrade attack (MITM stripped cli_v=2 query) and
// rejected. Closes Opus review I-2 for P2-1.
func TestFetchAdminOverride_StickyV2_RejectsDowngrade(t *testing.T) {
	// Server replies with a perfectly valid v1 (legacy) response — but
	// since the client previously saw v2, it must refuse.
	// makeServerBody returns (response_body, hmac_sig) where sig is over
	// the v1 canonical scope. We need sig over canonical v1 body for
	// successful HMAC verify (otherwise the test fails on signature
	// mismatch before the downgrade check runs).
	body, v1Sig := makeServerBody(t, "etag-old", nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Bypass-Signature", v1Sig)
		// Deliberately omit X-Bypass-Signature-Version → reads as v1.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := FetchAdminOverride(srv.Client(), srv.URL, "tok", "", testHMACKey, "2")
	if err == nil {
		t.Fatal("expected downgrade error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "downgrade") {
		t.Errorf("expected error to mention 'downgrade', got %v", err)
	}
}

// TestFetchAdminOverride_StickyV2_AllowsV2 — sticky-v2 must NOT block a
// legitimate v2 reply when the client has previously seen v2.
func TestFetchAdminOverride_StickyV2_AllowsV2(t *testing.T) {
	body, v2Sig := makeServerBodyV2(t, "etag-fresh", nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Bypass-Signature", v2Sig)
		w.Header().Set("X-Bypass-Signature-Version", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	ov, err := FetchAdminOverride(srv.Client(), srv.URL, "tok", "", testHMACKey, "2")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if ov == nil {
		t.Fatal("expected non-nil override")
	}
}

func TestFetchAdminOverride_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchAdminOverride(srv.Client(), srv.URL, "tok", "", testHMACKey, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected error to mention 'status 500', got %v", err)
	}
}

func TestPersistAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p1 := netip.MustParsePrefix("10.0.0.0/8")
	p2 := netip.MustParsePrefix("192.168.1.0/24")
	pe := netip.MustParsePrefix("172.16.0.0/12")

	src := &AdminOverride{
		Etag:     "rev42",
		Adds:     []netip.Prefix{p1, p2},
		Excludes: []netip.Prefix{pe},
	}
	if err := PersistOverride(dir, src, testHMACKey); err != nil {
		t.Fatalf("persist: %v", err)
	}
	// Sanity: файл создан с правильным именем.
	if _, err := os.Stat(filepath.Join(dir, "bypass-overrides.bin")); err != nil {
		t.Fatalf("cache file stat: %v", err)
	}

	loaded, err := LoadCachedOverride(dir, testHMACKey)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Etag != "rev42" {
		t.Errorf("etag: want rev42, got %q", loaded.Etag)
	}
	if len(loaded.Adds) != 2 {
		t.Fatalf("adds count: want 2, got %d", len(loaded.Adds))
	}
	if len(loaded.Excludes) != 1 {
		t.Fatalf("excludes count: want 1, got %d", len(loaded.Excludes))
	}
	if loaded.Adds[0] != p1 || loaded.Adds[1] != p2 {
		t.Errorf("adds content mismatch: %v vs [%v %v]", loaded.Adds, p1, p2)
	}
	if loaded.Excludes[0] != pe {
		t.Errorf("excludes content mismatch: %v vs %v", loaded.Excludes[0], pe)
	}
}

func TestLoadCached_TamperDetected(t *testing.T) {
	dir := t.TempDir()
	src := &AdminOverride{
		Etag: "tampered",
		Adds: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	if err := PersistOverride(dir, src, testHMACKey); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// Прямая порча байт: меняем первое вхождение "10.0.0.0/8" на "10.0.0.1/8"
	// (валидный для unmarshal, но изменит body и сломает HMAC).
	path := filepath.Join(dir, "bypass-overrides.bin")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	idx := strings.Index(string(raw), "10.0.0.0/8")
	if idx < 0 {
		t.Fatal("could not locate prefix in cache for tampering")
	}
	// Заменяем "10.0.0.0/8" → "10.0.0.1/8" (тот же размер, валидный CIDR,
	// но другой adds-список → другой HMAC).
	tampered := append([]byte{}, raw...)
	copy(tampered[idx:], []byte("10.0.0.1/8"))
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	_, err = LoadCachedOverride(dir, testHMACKey)
	if err == nil {
		t.Fatal("expected signature error after tampering, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Errorf("expected error to mention 'signature', got %v", err)
	}
}

func TestLoadCached_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadCachedOverride(dir, testHMACKey)
	if err == nil {
		t.Fatal("expected error for missing cache file, got nil")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist error, got %v", err)
	}
}

func TestPersistOverride_NilOverride(t *testing.T) {
	dir := t.TempDir()
	err := PersistOverride(dir, nil, testHMACKey)
	if err == nil {
		t.Fatal("expected error for nil override, got nil")
	}
}

// TestLoadCached_LegacyV1_StillAccepted — кэш, записанный старым клиентом
// (sig_v отсутствует / "" / "1"), должен по-прежнему load'иться без ошибки.
// Backward-compat для апгрейда клиента: старый cache не выкидывается.
func TestLoadCached_LegacyV1_StillAccepted(t *testing.T) {
	dir := t.TempDir()
	// Конструируем legacy v1 файл вручную: HMAC over {adds, excludes} БЕЗ etag.
	adds := []string{"10.0.0.0/8"}
	excludes := []string{"172.16.0.0/12"}
	body, err := json.Marshal(stringSigBodyV1{Adds: adds, Excludes: excludes})
	if err != nil {
		t.Fatalf("marshal v1 sig body: %v", err)
	}
	mac := hmac.New(sha256.New, testHMACKey)
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	legacy := cachedOverride{
		Etag:      "legacyV1etag",
		Adds:      adds,
		Excludes:  excludes,
		Signature: sig,
		// SigVersion намеренно пустой → legacy.
	}
	out, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	path := filepath.Join(dir, "bypass-overrides.bin")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write legacy cache: %v", err)
	}

	loaded, err := LoadCachedOverride(dir, testHMACKey)
	if err != nil {
		t.Fatalf("load legacy v1 cache: %v", err)
	}
	if loaded.Etag != "legacyV1etag" {
		t.Errorf("etag mismatch: want legacyV1etag, got %q", loaded.Etag)
	}
	if len(loaded.Adds) != 1 || loaded.Adds[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("adds: want [10.0.0.0/8], got %v", loaded.Adds)
	}
}

// TestLoadCached_V2_TamperedEtag_Rejected — критичный security тест для
// disk cache: attacker подменяет etag в JSON (например, чтобы trigger
// rollback на сервере при следующем GET). HMAC v2 покрывает etag → load fail.
func TestLoadCached_V2_TamperedEtag_Rejected(t *testing.T) {
	dir := t.TempDir()
	src := &AdminOverride{
		Etag: "originalEtag",
		Adds: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	if err := PersistOverride(dir, src, testHMACKey); err != nil {
		t.Fatalf("persist: %v", err)
	}

	path := filepath.Join(dir, "bypass-overrides.bin")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Замена etag в файле: "originalEtag" → "tamperedEtag" (тот же размер).
	if !strings.Contains(string(raw), "originalEtag") {
		t.Fatal("expected originalEtag in cache JSON")
	}
	tampered := []byte(strings.Replace(string(raw), "originalEtag", "tamperedEtag", 1))
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	_, err = LoadCachedOverride(dir, testHMACKey)
	if err == nil {
		t.Fatal("expected signature error after etag tampering, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Errorf("expected signature error, got %v", err)
	}
}

// TestLoadCached_UnknownSigVersion_Rejected — anti-downgrade.
func TestLoadCached_UnknownSigVersion_Rejected(t *testing.T) {
	dir := t.TempDir()
	bogus := cachedOverride{
		Etag:       "x",
		Adds:       []string{},
		Excludes:   []string{},
		Signature:  "deadbeef",
		SigVersion: "99",
	}
	out, err := json.Marshal(bogus)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "bypass-overrides.bin")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = LoadCachedOverride(dir, testHMACKey)
	if err == nil {
		t.Fatal("expected error for unknown sig version, got nil")
	}
}

// TestPersistOverride_WritesV2Format — sanity: новый persist всегда пишет sig_v=2.
func TestPersistOverride_WritesV2Format(t *testing.T) {
	dir := t.TempDir()
	src := &AdminOverride{Etag: "e", Adds: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if err := PersistOverride(dir, src, testHMACKey); err != nil {
		t.Fatalf("persist: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "bypass-overrides.bin"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(raw), `"sig_v":"2"`) {
		t.Errorf("expected sig_v=2 in persisted cache, got %s", string(raw))
	}
}

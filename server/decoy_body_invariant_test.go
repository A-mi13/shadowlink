package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Раунд 18 / C-2 и H-5: инвариант «любой ответ выглядит как decoy».
//
// C-2: SentinelEmitter при отсутствии снапшота записывал только заголовок и
// возвращался, а вызывающий делал early return → Go отдавал 200 с
// Content-Length: 0. «Сайт, который после серии быстрых запросов начинает
// отдавать пустое тело» — детерминированный оракул без знания протокола.
// Путь достижим в проде: при ошибке LoadDecoySnapshots main.go оставляет
// snapshots=nil, но emitter создаёт (задокументированная graceful degradation).
//
// H-5: httpPlaceholderRequest() выбрасывал Host вместе с путём, поэтому в
// multi-domain деплое fail-closed ответ приходил из default-каталога, а
// обычный GET с тем же Host — из каталога этого хоста. Разные тела и
// security-заголовки = бинарный дискриминатор для зонда.

// setupMultiDomainDecoy готовит два каталога decoy с различимым содержимым и
// возвращает handler, у которого blog.example.com замаплен на второй каталог.
func setupMultiDomainDecoy(tb testing.TB) *DecoyHandler {
	tb.Helper()

	defaultDir := tb.TempDir()
	blogDir := tb.TempDir()

	require.NoError(tb, os.WriteFile(
		filepath.Join(defaultDir, "index.html"),
		[]byte("<html><body>DEFAULT-PERSONA-PAGE</body></html>"), 0o644))
	require.NoError(tb, os.WriteFile(
		filepath.Join(blogDir, "index.html"),
		[]byte("<html><body>BLOG-PERSONA-PAGE</body></html>"), 0o644))

	return NewDecoyHandlerV2(DecoyHandlerConfig{
		DefaultDir:     defaultDir,
		DomainMap:      map[string]string{"blog.example.com": blogDir},
		DomainPersona:  map[string]string{"blog.example.com": "blog"},
		DefaultPersona: "saas",
	})
}

// Ни один путь rate-limit-ответа не должен отдавать пустое тело, даже когда
// снапшотов нет.
func TestRateLimitedDecoy_NeverEmptyBody_NilSnapshots(t *testing.T) {
	h, _ := setupTestHandler(t)
	h.decoy = setupMultiDomainDecoy(t)
	// Прод-состояние «graceful degradation»: emitter есть, снапшотов нет.
	h.sentinelEmitter = NewSentinelEmitter(nil, h.metrics)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v2/batch", nil)
	h.failClosedToDecoyRateLimitedV2(w, r, RLSentinel{Bucket: "ws_upgrade"})

	require.NotEmpty(t, w.Header().Get("X-SL-RL"),
		"X-SL-RL всё ещё должен проставляться")
	assert.NotEmpty(t, w.Body.Bytes(),
		"тело НЕ должно быть пустым: 200 + Content-Length 0 = оракул (C-2)")
	assert.Contains(t, w.Body.String(), "PERSONA-PAGE",
		"тело должно приходить от decoy-обработчика")
}

// Тот же инвариант, когда снапшот есть: тело пишет сам emitter.
func TestRateLimitedDecoy_NeverEmptyBody_WithSnapshot(t *testing.T) {
	h, _ := setupTestHandler(t)
	h.decoy = setupMultiDomainDecoy(t)

	_, snaps := makeSentinelTestSnap(t, "index.html")
	h.sentinelEmitter = NewSentinelEmitter(snaps, h.metrics)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v2/batch", nil)
	h.failClosedToDecoyRateLimitedV2(w, r, RLSentinel{Bucket: "ws_upgrade"})

	require.NotEmpty(t, w.Header().Get("X-SL-RL"))
	assert.NotEmpty(t, w.Body.Bytes(), "тело обязано быть записано emitter'ом")
}

// H-5: fail-closed ответ на Host: blog.example.com обязан приходить из
// каталога этого хоста, а не из default — иначе зонд сравнивает два ответа с
// одним Host и получает дискриминатор.
func TestFailClosedToDecoy_PreservesHostPersona(t *testing.T) {
	h, _ := setupTestHandler(t)
	h.decoy = setupMultiDomainDecoy(t)

	// Эталон: обычный GET через сам decoy-обработчик.
	wRef := httptest.NewRecorder()
	rRef := httptest.NewRequest(http.MethodGet, "/", nil)
	rRef.Host = "blog.example.com"
	h.decoy.ServeHTTP(wRef, rRef)
	require.Contains(t, wRef.Body.String(), "BLOG-PERSONA-PAGE",
		"предусловие: обычный GET на blog.example.com отдаёт каталог блога")

	// Fail-closed путь с тем же Host обязан отдать то же самое.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v2/batch", nil)
	r.Host = "blog.example.com"
	h.failClosedToDecoyWithReason(w, r, DecoyReasonBodyInvalid)

	assert.Contains(t, w.Body.String(), "BLOG-PERSONA-PAGE",
		"fail-closed обязан резолвить персону по Host, а не уходить в default (H-5)")
	assert.NotContains(t, w.Body.String(), "DEFAULT-PERSONA-PAGE",
		"ответ из default-каталога при заданном Host = дискриминатор")
}

// Тот же инвариант на rate-limit-пути с пустыми снапшотами.
func TestRateLimitedDecoy_PreservesHostPersona(t *testing.T) {
	h, _ := setupTestHandler(t)
	h.decoy = setupMultiDomainDecoy(t)
	h.sentinelEmitter = NewSentinelEmitter(nil, h.metrics)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/socket.io/", nil)
	r.Host = "blog.example.com"
	h.failClosedToDecoyRateLimitedV2(w, r, RLSentinel{Bucket: "ws_upgrade"})

	assert.Contains(t, w.Body.String(), "BLOG-PERSONA-PAGE",
		"Host обязан сохраняться и на rate-limit-пути")
}

// Путь при этом обязан санитизироваться: размер тела не должен зависеть от
// URL запроса (иначе URL-эхо выдаёт режим отказа).
func TestDecoyRequestFor_SanitizesPathKeepsHost(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v2/batch?x=1", nil)
	r.Host = "shop.example.com"

	req := decoyRequestFor(r)
	require.NotNil(t, req)
	assert.Equal(t, "shop.example.com", req.Host, "Host обязан сохраняться")
	assert.Equal(t, "/", req.URL.Path, "путь обязан санитизироваться в \"/\"")
	assert.Empty(t, req.URL.RawQuery, "query не должен эхоиться")
}

// decoyRequestFor вызывается и там, где запроса нет.
func TestDecoyRequestFor_NilSafe(t *testing.T) {
	req := decoyRequestFor(nil)
	require.NotNil(t, req)
	assert.Equal(t, "/", req.URL.Path)
}

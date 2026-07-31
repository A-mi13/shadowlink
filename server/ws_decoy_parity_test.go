package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// H-6 (раунд 18): WS-путь для не-whitelisted URL обходил timing-parity.
//
// `handleWebSocket` начинался с `if !IsAllowedWSPath(...) { h.decoy.ServeHTTP(w, r) }`
// — единственный вызов decoy в server/, минующий и decoyWithTimingParity, и
// failClosedToDecoy*. Остальные пути платят runSyntheticDispatch (3× X25519
// ScalarMult) + ackJitter().
//
// Наблюдаемое следствие: `GET /random-path` с заголовком `Upgrade: websocket`
// отвечал на порядок быстрее, чем тот же GET без `Upgrade`, при идентичных телах.
// «Добавление Upgrade ускоряет ответ в 10 раз» — бессмыслица для статики за nginx,
// то есть готовый дискриминатор для активного зонда.
//
// Замер до фикса: runSyntheticDispatch ≈ 179 мкс, ackJitter до 63 мс. Основной
// вклад даёт jitter, а не ScalarMult (в аудите цена оценивалась как «~5 ms»).

// medianDuration — существующий хелпер из handler_probe_test.go.

// Не-whitelisted WS-путь обязан платить тот же тайминг, что обычный decoy-путь.
func TestWSDecoyParity_NonWhitelistedPathPaysTiming(t *testing.T) {
	h := newTestHandler(t)
	h.runSyntheticDispatch() // прогрев cold-RNG

	const samples = 9
	wsTimes := make([]time.Duration, 0, samples)
	plainTimes := make([]time.Duration, 0, samples)

	for i := 0; i < samples; i++ {
		// Ветка A: не-whitelisted путь + Upgrade: websocket.
		reqWS := httptest.NewRequest(http.MethodGet, "/definitely-not-a-ws-path", nil)
		reqWS.Header.Set("Upgrade", "websocket")
		reqWS.Header.Set("Connection", "Upgrade")
		reqWS.Header.Set("Sec-WebSocket-Version", "13")
		reqWS.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		wRec := httptest.NewRecorder()
		start := time.Now()
		h.handleWebSocket(wRec, reqWS)
		wsTimes = append(wsTimes, time.Since(start))

		// Ветка B: тот же путь без Upgrade — обычный decoy с timing-parity.
		reqPlain := httptest.NewRequest(http.MethodGet, "/definitely-not-a-ws-path", nil)
		pRec := httptest.NewRecorder()
		start = time.Now()
		h.decoyWithTimingParity(pRec, reqPlain)
		plainTimes = append(plainTimes, time.Since(start))
	}

	wsMed := medianDuration(wsTimes)
	plainMed := medianDuration(plainTimes)
	t.Logf("медиана: WS-путь=%v  обычный decoy=%v", wsMed, plainMed)

	// Ключевой инвариант: WS-ветка не должна отвечать существенно быстрее.
	// Порог мягкий (в 4 раза) — цель поймать разрыв на порядок, а не шум
	// планировщика. До фикса WS-ветка укладывалась в микросекунды против
	// десятков миллисекунд.
	if wsMed*4 < plainMed {
		t.Errorf("WS-путь отвечает несоразмерно быстрее: %v против %v — "+
			"добавление заголовка Upgrade служит дискриминатором", wsMed, plainMed)
	}

	// Отдельно: ветка обязана платить хотя бы стоимость synthetic dispatch.
	if wsMed < 50*time.Microsecond {
		t.Errorf("WS-путь отвечает за %v — synthetic dispatch не выполняется", wsMed)
	}
}

// Санитизация: тело ответа не должно зависеть от длины запрошенного пути,
// иначе длина утекает даже при одинаковом тайминге.
func TestWSDecoyParity_BodyDoesNotEchoPath(t *testing.T) {
	h := newTestHandler(t)

	newReq := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		return r
	}

	short := httptest.NewRecorder()
	h.handleWebSocket(short, newReq("/a"))

	long := httptest.NewRecorder()
	h.handleWebSocket(long, newReq("/a-very-long-path-that-should-not-affect-the-body-length-at-all-nope"))

	if short.Body.Len() != long.Body.Len() {
		t.Errorf("длина тела зависит от пути: %d против %d — путь утекает через размер ответа",
			short.Body.Len(), long.Body.Len())
	}
	if short.Code != long.Code {
		t.Errorf("код ответа зависит от пути: %d против %d", short.Code, long.Code)
	}
	// Тело не должно быть пустым (регрессия C-2: пустое тело = оракул).
	if short.Body.Len() == 0 {
		t.Error("тело пустое — регрессия C-2 (оракул по нулевому Content-Length)")
	}
}

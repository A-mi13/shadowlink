package client

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nixavpn/shadowlink/core"
)

// TestUpgradeToWS_FlowCtlAckTimeout_IsTerminal — таймаут чтения FLOWCTL-ack
// обязан валить UpgradeToWS, а не отдавать соединение читателю слота.
//
// Полевой дефект 2026-08-10 (два прогона, 14 событий): ackErr молча
// игнорировался — считали метрику FlowNegotiationTimeout и возвращали nil. Но
// readErr в gorilla ЛИПКИЙ (`for c.readErr == nil` conn.go:1008,
// `return noFrame, nil, c.readErr` conn.go:1033), и SetReadDeadline его не
// очищает. Поэтому slotReader на первом же ReadMessage получал закешированный
// таймаут МГНОВЕННО, при slot_age_ms=0.
//
// Связь в поле однозначная: все 14 нулевых возрастов имели anomaly=io_timeout,
// и ни один io_timeout не имел age>0. Все — свежие слоты-замены дренажа.
// Последствия: сводка slotobs отравлена (age_min_ms=0, age_p10_ms=0, cv_age
// раздут 0.08 → 0.50), плюс ложный cause=natural кормил meltdown-детектор и
// давал ~10 с простоя ячейки вместо fast-reconnect.
//
// Сервер здесь принимает upgrade и НЕ отвечает ack — ровно полевой сценарий.
func TestUpgradeToWS_FlowCtlAckTimeout_IsTerminal(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}

	accepted := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		select {
		case accepted <- struct{}{}:
		default:
		}
		// Молчим: ack не отправляем. Держим соединение открытым дольше
		// negotiationAckTimeout, чтобы клиент упёрся именно в дедлайн чтения,
		// а не в закрытие сокета (иначе тест проверял бы другой путь).
		time.Sleep(negotiationAckTimeout + 2*time.Second)
		_ = c.Close()
	}))
	defer srv.Close()

	key := bytes.Repeat([]byte{0x51}, 32)
	sess := core.NewSession(7, key, key)
	token := bytes.Repeat([]byte{0x09}, 36)

	// FIN-хук: сеть не нужна, а без подмены UpgradeToWS полез бы в HTTPS.
	prev := bestEffortSessionFINHook
	bestEffortSessionFINHook = func([]byte, *core.Session, []byte) {}
	t.Cleanup(func() { bestEffortSessionFINHook = prev })

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewWebSocketTransport(host, false, true)
	// Окно > 0 включает синхронное чтение ack — тот самый путь.
	tr.flowDesiredWindow = 1 << 20

	start := time.Now()
	err := tr.UpgradeToWS(token, sess)
	elapsed := time.Since(start)

	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("сервер не принял upgrade — тест проверяет не тот путь")
	}

	if err == nil {
		t.Fatal("UpgradeToWS вернул nil при таймауте ack: соединение с липким " +
			"readErr уйдёт slotReader'у и умрёт при slot_age_ms=0, дав ложный " +
			"cause=natural и отравив выборку slotobs")
	}
	if !strings.Contains(err.Error(), "flowctl ack") {
		t.Errorf("ошибка = %q, ожидалось упоминание flowctl ack "+
			"(иначе упали по другой причине и тест не сторожит дефект)", err)
	}
	// Дедлайн обязан отработать: не мгновенный отказ и не зависание.
	if elapsed < negotiationAckTimeout {
		t.Errorf("вернулись за %v, быстрее negotiationAckTimeout %v — "+
			"упали до чтения ack, путь не проверен", elapsed, negotiationAckTimeout)
	}
}

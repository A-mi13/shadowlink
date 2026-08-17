package client

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nixavpn/shadowlink/core"
)

// TestUpgradeToWS_UndecryptableAck_IsTerminal — ack, который ПРИШЁЛ, но не
// расшифровался, обязан валить UpgradeToWS так же, как таймаут ack.
//
// # Механизм полевого дефекта (прогон 20260817-092533, 13 событий)
//
// Сервер при ПРОВАЛЕ first-frame auth не рвёт соединение, а маскирует отказ:
// server/websocket.go:601 → fakeAckAndClose (server/websocket.go:274) пишет
// 200–2000 байт СЛУЧАЙНЫХ данных, спит ackJitter() и отправляет
// CloseNormalClosure. Это сделано намеренно, чтобы отказ auth не отличался на
// wire от штатного закрытия (иначе у активного пробинга был бы бесплатный
// оракул), и трогать серверную сторону нельзя.
//
// Клиент же читал этот кадр в ветке синхронного FLOWCTL-ack
// (ws_transport.go ~553) и обрабатывал так:
//
//	ackErr == nil        → терминальная ветка НЕ срабатывает
//	DecryptChunkSafe fail → flowControlEnabled остаётся false
//	                     → тикается FlowNegotiationTimeout и всё
//
// То есть UpgradeToWS возвращал nil на соединении, которое сервер уже отверг и
// закрывает. connectSlot (ws_pool.go:3035-3054) штампует startedAtNs, бампает
// generation и ставит slotReady, connectReserveSlot (ws_pool_drain.go:846)
// спавнит slotReader — и тот на первом же ReadMessage получает
// `websocket: close 1000 (normal)` при slot_age_ms=0.
//
// # Почему это баг ЖИЗНЕННОГО ЦИКЛА, а не шум наблюдений
//
// Пул считает ГОТОВЫМ слот, который сервер отверг. Следствия шире статистики:
//   - ёмкость пула фиктивна: ячейка занята соединением, через которое ничего
//     нельзя передать, и AssignStream мог бы отдать ей стрим;
//   - ложная атрибуция cause=natural (isAgeCut даёт natural при age<floor)
//     кормит meltdown-детектор и даёт экспоненциальный backoff вместо
//     fast-reconnect — в прогоне 08-17 все 13 событий получили backoff 6.9–9.8 с
//     простоя ячейки;
//   - выборка slotobs отравлена: 13 наблюдений с AgeMs=0 дали age_min_ms=0,
//     age_p10_ms=0 и cv_age=1.3143 вместо ~0.08 по чистым наблюдениям.
//
// Это ровно тот же дефект, что закрывали 2026-08-10 для ТАЙМАУТА ack (см.
// TestUpgradeToWS_FlowCtlAckTimeout_IsTerminal и комментарий на
// ws_transport.go:573). Тогда терминальной сделали только ветку `ackErr != nil`,
// а «ack пришёл, но чужой» осталась дырой — и в поле она проявилась через другой
// серверный путь.
//
// Сервер здесь воспроизводит fakeAckAndClose: случайный бинарный кадр + close 1000.
func TestUpgradeToWS_UndecryptableAck_IsTerminal(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}

	accepted := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		select {
		case accepted <- struct{}{}:
		default:
		}
		// Дочитываем first frame, как делает authenticateFirstFrame.
		_, _, _ = c.ReadMessage()

		// fakeAckAndClose: 200-2000 байт случайных данных. Расшифровать их
		// нельзя — GCM-тег не сойдётся.
		fake := make([]byte, 512)
		_, _ = rand.Read(fake)
		if err := c.WriteMessage(websocket.BinaryMessage, fake); err != nil {
			return
		}
		_ = c.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(500*time.Millisecond),
		)
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

	err := tr.UpgradeToWS(token, sess)

	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("сервер не принял upgrade — тест проверяет не тот путь")
	}

	if err == nil {
		t.Fatal("UpgradeToWS вернул nil на ack, который не расшифровался: " +
			"сервер отверг first-frame auth (fakeAckAndClose) и закрывает " +
			"соединение, а пул поставит ячейку в slotReady и отдаст её slotReader — " +
			"тот умрёт при slot_age_ms=0 с ложным cause=natural, получит " +
			"экспоненциальный backoff вместо fast-reconnect и отравит выборку slotobs")
	}
	if !strings.Contains(err.Error(), "flowctl ack") {
		t.Errorf("ошибка = %q, ожидалось упоминание flowctl ack "+
			"(иначе упали по другой причине и тест не сторожит дефект)", err)
	}
}

// Успешное согласование не должно быть сломано ужесточением: ack с валидным
// FlagAck и разбираемым маркером обязан по-прежнему включать flow control.
//
// Без этой половины правка «любой нерасшифрованный ack терминален» могла бы
// пройти как «любой ack терминален», и пул перестал бы подниматься вовсе.
func TestUpgradeToWS_ValidAck_StillNegotiates(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}

	const serverWindow = 1 << 20

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, _, _ = c.ReadMessage()

		// Отвечаем так, как сервер отвечает при УСПЕШНОЙ auth: FlagAck с
		// маркером FLOWCTL v2, зашифрованный ключами той же сессии.
		key := bytes.Repeat([]byte{0x51}, 32)
		srvSess := core.NewSession(7, key, key)
		ack := &core.Chunk{
			SessionID: srvSess.ID,
			SeqNum:    srvSess.NextSeqNum(),
			Flags:     core.FlagAck,
			Payload:   core.BuildFlowCtlMarkerV2(serverWindow, false),
		}
		enc, encErr := srvSess.EncryptChunk(ack)
		if encErr != nil {
			return
		}
		_ = c.WriteMessage(websocket.BinaryMessage, enc)
		// Держим соединение, чтобы клиент дошёл до конца UpgradeToWS.
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	key := bytes.Repeat([]byte{0x51}, 32)
	sess := core.NewSession(7, key, key)
	token := bytes.Repeat([]byte{0x09}, 36)

	prev := bestEffortSessionFINHook
	bestEffortSessionFINHook = func([]byte, *core.Session, []byte) {}
	t.Cleanup(func() { bestEffortSessionFINHook = prev })

	host := strings.TrimPrefix(srv.URL, "http://")
	tr := NewWebSocketTransport(host, false, true)
	tr.flowDesiredWindow = serverWindow

	if err := tr.UpgradeToWS(token, sess); err != nil {
		t.Fatalf("UpgradeToWS с ВАЛИДНЫМ ack вернул ошибку %v — ужесточение "+
			"сломало штатный путь согласования, пул не поднимется", err)
	}
	if !tr.flowControlEnabled {
		t.Error("flowControlEnabled = false при валидном ack — согласование не состоялось")
	}
	t.Cleanup(func() { _ = tr.Close() })
}

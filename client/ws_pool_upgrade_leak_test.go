package client

import (
	"os"
	"regexp"
	"testing"
)

// Сторож на утечку горутины при отказе UpgradeToWS в connectSlot.
//
// Механизм утечки: NewWebSocketTransport (ws_transport.go:99) создаёт свой
// ConnManager, а NewConnManager при MinRotation > 0 безусловно поднимает
// горутину startRotation (connmanager.go:124). Её stopCh закрывается только
// из ConnManager.Close(), который зовётся из WebSocketTransport.Close().
// Поэтому ранний выход из connectSlot после создания транспорта обязан звать
// wst.Close(), иначе горутина с log-normal таймером живёт до конца процесса.
// В полевом прогоне 094311 таких отказов было 41 за 8 ч.
//
// Почему тест читает ИСХОДНИК, а не считает горутины: путь требует живого
// сервера, отвечающего на handshake и роняющего upgrade, — на юните это
// означало бы подмену половины стека, а тест на runtime.NumGoroutine()
// флейковал бы под -shuffle из-за фоновых горутин других тестов (в этом
// проекте тайминговые тесты исторически флейкуют, см. skill testing-rules).
// Проверка на исходнике ловит именно тот регресс, который здесь возможен:
// удаление Close при правке соседних строк.
func TestConnectSlot_ClosesTransportOnUpgradeFailure(t *testing.T) {
	src, err := os.ReadFile("ws_pool.go")
	if err != nil {
		t.Fatalf("чтение ws_pool.go: %v", err)
	}

	// Блок отказа upgrade: от проверки ошибки UpgradeToWS до возврата ошибки.
	// Ищем именно этот участок, а не наличие "wst.Close()" где угодно в файле.
	re := regexp.MustCompile(`(?s)if err := wst\.UpgradeToWS\([^)]*\); err != nil \{(.*?)\n\t\}`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatal("не найден блок обработки ошибки UpgradeToWS в connectSlot — " +
			"проверить, не переписан ли путь; сторож на утечку горутины стал слепым")
	}

	block := string(m[1])
	if !regexp.MustCompile(`wst\.Close\(\)`).MatchString(block) {
		t.Errorf("в ветке отказа UpgradeToWS нет wst.Close() — утечка горутины "+
			"ConnManager.startRotation (её stopCh закрывается только из Close). "+
			"Блок:\n%s", block)
	}
}

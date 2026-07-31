package server

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// MEDIUM device-limit (раунд 18): два независимых дефекта в одной паре функций.
//
// (а) TOCTOU. CheckDeviceLimit брала RLock, читала, отпускала; регистрация шла
//     отдельным вызовом OnSessionCreated двадцатью строками ниже
//     (handler.go:724 → :744). N одновременных handshake проходили проверку до
//     первого append и превышали лимит на N-1. Замер до фикса: 5 из 5 при лимите 2.
//
// (б) Fast-path «реконнект всегда разрешён»:
//         if _, has := ca.clientSession[clientID]; has { return true }
//     давал одному clientID НЕОГРАНИЧЕННОЕ число сессий. OnSessionCreated при
//     каждом вызове делал append в activeSessions[userID] и ПЕРЕЗАПИСЫВАЛ
//     clientSession[clientID] — старый sessionID оставался в activeSessions
//     навсегда, потому что OnSessionDestroyed для него уже не находил пары.
//     Замер до фикса: 50 сессий при лимите 2, 50 записей накоплено.
//     Один пользователь занимал все MaxClients=500 → остальные получали decoy.
//
// Асимметрия, делавшая (б) возможной: лимит считается по userID, а fast-path
// ключевался по полному clientID.
//
// Фикс: AdmitSession — одна операция под Lock, проверка И регистрация вместе.
// Реконнект того же clientID ЗАМЕНЯЕТ свою прежнюю сессию, а не добавляет новую.

func TestDeviceLimit_ReconnectDoesNotAccumulate(t *testing.T) {
	ca := NewClientAuth([]string{"u1:d1"})
	ca.defaultMax = 2

	const clientID = "u1:d1"
	for i := 0; i < 50; i++ {
		if !ca.AdmitSession(clientID, uint32(1000+i)) {
			t.Fatalf("итерация %d: реконнект того же clientID должен быть разрешён", i)
		}
	}

	userID := parseUserID(clientID)
	ca.mu.RLock()
	n := len(ca.activeSessions[userID])
	sid := ca.clientSession[clientID]
	ca.mu.RUnlock()

	if n != 1 {
		t.Errorf("после 50 реконнектов одного clientID в activeSessions %d записей, ожидалась 1", n)
	}
	if sid != 1049 {
		t.Errorf("clientSession указывает на %d, ожидался последний sessionID 1049", sid)
	}
}

// Лимит обязан соблюдаться для РАЗНЫХ устройств одного пользователя.
func TestDeviceLimit_EnforcedAcrossDevices(t *testing.T) {
	ca := NewClientAuth([]string{"u1:d1", "u1:d2", "u1:d3", "u1:d4", "u1:d5"})
	ca.defaultMax = 2

	admitted := 0
	for i := 1; i <= 5; i++ {
		if ca.AdmitSession(fmt.Sprintf("u1:d%d", i), uint32(i)) {
			admitted++
		}
	}
	if admitted != 2 {
		t.Errorf("допущено %d устройств, ожидался лимит 2", admitted)
	}
}

// (а) TOCTOU: конкурентные handshake не должны суммарно превысить лимит.
func TestDeviceLimit_NoTOCTOUUnderConcurrency(t *testing.T) {
	const (
		limit   = 3
		devices = 40
	)
	ids := make([]string, devices)
	for i := range ids {
		ids[i] = fmt.Sprintf("u9:d%d", i)
	}
	ca := NewClientAuth(ids)
	ca.defaultMax = limit

	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0

	start := make(chan struct{})
	for i := 0; i < devices; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // максимизируем шанс гонки
			if ca.AdmitSession(ids[i], uint32(i+1)) {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if admitted != limit {
		t.Errorf("конкурентно допущено %d сессий при лимите %d — TOCTOU", admitted, limit)
	}

	ca.mu.RLock()
	n := len(ca.activeSessions["u9"])
	ca.mu.RUnlock()
	if n != limit {
		t.Errorf("в activeSessions %d записей при лимите %d", n, limit)
	}
}

// Освобождение места: после OnSessionDestroyed новое устройство должно пройти.
func TestDeviceLimit_SlotFreedAfterDestroy(t *testing.T) {
	ca := NewClientAuth([]string{"u2:d1", "u2:d2", "u2:d3"})
	ca.defaultMax = 2

	if !ca.AdmitSession("u2:d1", 1) {
		t.Fatal("d1 должен пройти")
	}
	if !ca.AdmitSession("u2:d2", 2) {
		t.Fatal("d2 должен пройти")
	}
	if ca.AdmitSession("u2:d3", 3) {
		t.Fatal("d3 должен быть отклонён — лимит 2")
	}

	ca.OnSessionDestroyed("u2:d1", 1)

	if !ca.AdmitSession("u2:d3", 3) {
		t.Error("после освобождения слота d3 должен пройти")
	}
	ca.mu.RLock()
	n := len(ca.activeSessions["u2"])
	ca.mu.RUnlock()
	if n != 2 {
		t.Errorf("в activeSessions %d записей, ожидалось 2", n)
	}
}

// Open mode — без whitelist лимит не применяется (сохраняем поведение).
func TestDeviceLimit_OpenModeUnlimited(t *testing.T) {
	ca := NewClientAuth(nil)
	for i := 0; i < 20; i++ {
		if !ca.AdmitSession(fmt.Sprintf("u3:d%d", i), uint32(i)) {
			t.Fatalf("open mode должен допускать всех, отказ на %d", i)
		}
	}
}

// Сторож интеграции: прод-путь handshake обязан идти через AdmitSession.
//
// Тесты выше проверяют атомарность самой функции, но не то, что handler ею
// пользуется. Без этого сторожа возврат к раздельной паре
// CheckDeviceLimit(...) ... OnSessionCreated(...) в handler.go прошёл бы
// незамеченным — ровно та регрессия, которую закрывает раунд 18.
func TestDeviceLimit_HandlerUsesAdmitSession(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("не прочитан handler.go: %v", err)
	}
	code := string(src)

	if !strings.Contains(code, "h.clientAuth.AdmitSession(") {
		t.Error("handler.go больше не вызывает AdmitSession — квота проверяется неатомарно")
	}
	// Комментарии могут упоминать старые имена; ищем именно вызовы.
	if strings.Contains(code, "h.clientAuth.OnSessionCreated(") {
		t.Error("handler.go снова вызывает OnSessionCreated напрямую — " +
			"проверка и регистрация разъехались, TOCTOU вернулся")
	}
	if strings.Contains(code, "h.clientAuth.CheckDeviceLimit(") {
		t.Error("handler.go снова вызывает CheckDeviceLimit — " +
			"это read-only проверка, она racy на пути допуска")
	}
}

// Per-user лимит из userLimits перекрывает defaultMax.
func TestDeviceLimit_PerUserLimitRespected(t *testing.T) {
	ca := NewClientAuth([]string{"u4:d1", "u4:d2", "u4:d3", "u4:d4"})
	ca.defaultMax = 1
	ca.SetUserLimit("u4", 3)

	admitted := 0
	for i := 1; i <= 4; i++ {
		if ca.AdmitSession(fmt.Sprintf("u4:d%d", i), uint32(i)) {
			admitted++
		}
	}
	if admitted != 3 {
		t.Errorf("допущено %d, ожидался per-user лимит 3", admitted)
	}
}

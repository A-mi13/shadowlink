package dnsproxy

// DNS-M5 (2026-06-12): Start при 5s-таймауте ожидания NotifyStartedFunc раньше
// возвращал ошибку, НЕ сохранив srv в f.server. Если сервер стартовал на
// 6-й секунде, он жил без хендла: Stop был no-op (f.server == nil), горутина
// и сокет 198.18.0.1:53/127.0.0.1:53 утекали навсегда — следующий bind на этот
// адрес падал вечно. Фикс: на таймауте поздний сервер гарантированно гасится.

import (
	"net"
	"testing"
	"time"
)

// freeLoopbackUDPAddr выделяет свободный loopback UDP-адрес: биндим :0,
// читаем фактический адрес, освобождаем. Стандартная техника; гонка с чужим
// процессом за порт на loopback пренебрежимо редка.
func freeLoopbackUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не удалось выделить свободный UDP-порт: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// Таймаут Start (seam: startWaitTimeout=10ms, startNotifyDelay=100ms имитирует
// медленный старт) → ошибка, f.server остаётся nil, НО поздно стартовавший
// сервер гасится: порт снова биндится. До фикса сервер жил вечно без хендла
// и порт оставался занят.
func TestForwarder_StartTimeout_ShutsDownLateServer(t *testing.T) {
	addr := freeLoopbackUDPAddr(t)
	f := NewForwarder(addr, nil, WithResolvers(&mockResolver{}, &mockResolver{}))
	f.startWaitTimeout = 10 * time.Millisecond
	f.startNotifyDelay = 100 * time.Millisecond

	if err := f.Start(); err == nil {
		_ = f.Stop()
		t.Fatal("ожидалась ошибка таймаута Start")
	}

	// Сервер не присвоен — Stop остаётся идемпотентным no-op без паники.
	f.mu.Lock()
	srvNil := f.udpServer == nil && f.tcpServer == nil
	f.mu.Unlock()
	if !srvNil {
		t.Fatal("udpServer/tcpServer должны остаться nil после таймаута Start")
	}
	if err := f.Stop(); err != nil {
		t.Fatalf("Stop после таймаута Start: %v", err)
	}

	// Ключевая проверка DNS-M5: порт освобождается (поздний сервер погашен).
	deadline := time.Now().Add(3 * time.Second)
	for {
		pc, err := net.ListenPacket("udp", addr)
		if err == nil {
			_ = pc.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("порт %s не освободился за 3s после таймаута Start (сервер утёк): %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// После таймаут-ошибки Start forwarder можно поднять заново на том же адресе
// (порт освобождён, состояние чистое) — обычный Start/Stop-цикл работает.
func TestForwarder_StartTimeout_RestartableAfterwards(t *testing.T) {
	addr := freeLoopbackUDPAddr(t)
	f := NewForwarder(addr, nil, WithResolvers(&mockResolver{}, &mockResolver{}))
	f.startWaitTimeout = 10 * time.Millisecond
	f.startNotifyDelay = 100 * time.Millisecond

	if err := f.Start(); err == nil {
		_ = f.Stop()
		t.Fatal("ожидалась ошибка таймаута Start")
	}

	// Снимаем seam-задержку и ретраим Start до освобождения порта поздним
	// shutdown'ом (поллинг с дедлайном — без фиксированного sleep).
	f.startNotifyDelay = 0
	f.startWaitTimeout = 5 * time.Second
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := f.Start()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("повторный Start не прошёл за 3s: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := f.Stop(); err != nil {
		t.Fatalf("Stop после успешного рестарта: %v", err)
	}
}

package server

import (
	"net"
	"sync"
	"testing"
)

// H-9 (раунд 18): повторный FlagConnect с уже занятым streamID.
//
// Прежнее поведение: `streams[streamID] = pendingStream` безусловно перезатирал
// запись. Два следствия:
//
//	(а) старый объект терялся из map, но targetConn НЕ закрывался, writer-горутина
//	    продолжала жить (выход только по s.done, а Close() уже никто не вызовет —
//	    ссылки нет) → утечка FD + горутин на каждую итерацию;
//	(б) проверка лимита стоит ПЕРЕД вставкой и смотрит на len(streams), поэтому при
//	    повторном использовании одного streamID размер map остаётся 1 →
//	    maxStreamsPerSession=256 не срабатывал НИКОГДА.
//
// Замер до фикса: 1000 CONNECT(streamID=1) → map size 1, отказов 0, потеряно 999
// соединений. Аутентифицированный клиент исчерпывал FD процесса, включая
// listener → отказ для ВСЕХ клиентов.
//
// Легитимный клиент дубликат не пришлёт: NextStreamID (client/client.go:789)
// выдаёт ID монотонно и проверяет незанятость в ОБЕИХ картах. Поэтому политика —
// отклонять дубликат, а не закрывать старый стрим: закрытие дало бы клиенту
// способ рвать свои же соединения по чужому streamID.

// wsStreamsRegisterDup моделирует контракт вставки на WS-пути.
func TestStreamDuplicate_WSPathRejects(t *testing.T) {
	var mu sync.Mutex
	streams := make(map[uint16]*wsStream)

	const streamID uint16 = 1
	c1, srv1 := net.Pipe()
	defer c1.Close()
	defer srv1.Close()

	// Первый CONNECT — принят.
	first := newPendingWSStream()
	mu.Lock()
	ok := registerWSStreamLocked(streams, streamID, first)
	mu.Unlock()
	if !ok {
		t.Fatal("первый CONNECT должен быть принят")
	}
	first.Activate(c1)

	// Второй CONNECT с тем же streamID — обязан быть отклонён.
	second := newPendingWSStream()
	mu.Lock()
	ok = registerWSStreamLocked(streams, streamID, second)
	mu.Unlock()
	if ok {
		t.Error("дубликат streamID должен быть ОТКЛОНЁН, а не перезатирать запись")
	}

	// Старый стрим обязан остаться в map и остаться живым.
	mu.Lock()
	got := streams[streamID]
	size := len(streams)
	mu.Unlock()
	if got != first {
		t.Error("после отклонённого дубликата в map должен остаться ПЕРВЫЙ стрим")
	}
	if size != 1 {
		t.Errorf("размер map = %d, ожидался 1", size)
	}
	select {
	case <-first.done:
		t.Error("первый стрим не должен быть закрыт отклонённым дубликатом")
	default:
	}
	first.Close()
}

// Главное следствие (б): лимит обязан срабатывать несмотря на повторный ID.
func TestStreamDuplicate_LimitNowEnforced(t *testing.T) {
	var mu sync.Mutex
	streams := make(map[uint16]*wsStream)

	const iterations = 1000
	accepted, rejected := 0, 0
	var leaked []*wsStream

	for i := 0; i < iterations; i++ {
		const streamID uint16 = 1 // клиент всегда шлёт один и тот же
		s := newPendingWSStream()
		mu.Lock()
		ok := registerWSStreamLocked(streams, streamID, s)
		mu.Unlock()
		if ok {
			accepted++
			leaked = append(leaked, s)
		} else {
			rejected++
			s.Close() // отклонённый — сразу освобождаем
		}
	}

	t.Logf("принято=%d отклонено=%d размер map=%d", accepted, rejected, len(streams))
	if accepted != 1 {
		t.Errorf("принято %d CONNECT с одним streamID, ожидался ровно 1", accepted)
	}
	if rejected != iterations-1 {
		t.Errorf("отклонено %d, ожидалось %d", rejected, iterations-1)
	}
	for _, s := range leaked {
		s.Close()
	}
}

// POST-путь (handler.go) использует другой тип — StreamConn. Тот же инвариант.
func TestStreamDuplicate_POSTPathRejects(t *testing.T) {
	tunnel := &Tunnel{streams: make(map[uint16]*StreamConn)}

	const streamID uint16 = 7
	c1, srv1 := net.Pipe()
	defer c1.Close()
	defer srv1.Close()

	first := &StreamConn{StreamID: streamID, TargetConn: c1}
	if !registerPOSTStream(tunnel, streamID, first) {
		t.Fatal("первый CONNECT должен быть принят")
	}

	second := &StreamConn{StreamID: streamID}
	if registerPOSTStream(tunnel, streamID, second) {
		t.Error("дубликат streamID на POST-пути должен быть ОТКЛОНЁН")
	}

	tunnel.mu.Lock()
	got := tunnel.streams[streamID]
	tunnel.mu.Unlock()
	if got != first {
		t.Error("в map должен остаться ПЕРВЫЙ стрим")
	}
}

// Лимит на POST-пути срабатывает на РАЗНЫХ streamID (контроль: не сломали).
func TestStreamDuplicate_POSTLimitStillWorks(t *testing.T) {
	tunnel := &Tunnel{streams: make(map[uint16]*StreamConn)}

	accepted := 0
	for i := 0; i < maxStreamsPerSession+50; i++ {
		id := uint16(i + 1)
		if registerPOSTStream(tunnel, id, &StreamConn{StreamID: id}) {
			accepted++
		}
	}
	if accepted != maxStreamsPerSession {
		t.Errorf("принято %d стримов, ожидался лимит %d", accepted, maxStreamsPerSession)
	}
}

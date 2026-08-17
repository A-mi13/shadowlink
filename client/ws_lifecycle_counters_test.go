package client

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestWsDied_CountsPoolSlotDeaths — сторож против мёртвого счётчика ws_died,
// который читается в ОПАСНУЮ сторону (полевой прогон 2026-08-17, лог
// nixavpn-DEBUG-20260817-092533).
//
// Что было: инкременты Stats.WsDied / Stats.WsCreated жили ТОЛЬКО в
// proxy/socks5/tcp.go — на экспериментальном пути «один websocket на стрим»,
// которым архитектура WS-пула не пользуется. За 9.5 ч прогона строка
// `shadowlink client stats (delta)` напечатала ws_died=0 в каждом из 6847
// тиков, тогда как в том же логе 3848 `WS pool slot reader started` и 43
// `WS pool slot reader error`. То есть поле утверждало «ни одно соединение не
// умерло» при 43 умерших — в отличие от большинства дефектов этого класса,
// врёт в опасную сторону: оператор читает ноль как здоровье.
//
// Тест проверяет ПАРУ инвариантов, потому что односторонняя проверка ловит
// только половину:
//  1. смерть слота по ЛЮБОЙ причине увеличивает ws_died ровно на 1 —
//     handleSlotDeath закрывает транспорт на всех четырёх причинах, значит
//     соединения к origin не стало ни в одной из них;
//  2. повторный вызов на том же слоте НЕ увеличивает — иначе счётчик раздуется
//     2-3× на одном отказе (ридер и писатель видят одну смерть одновременно;
//     на этом же CAS'е tryMarkDead держится meltdown-детектор).
func TestWsDied_CountsPoolSlotDeaths(t *testing.T) {
	for _, cause := range []slotDeathCause{
		deathCauseNatural,
		deathCauseAgeCut,
		deathCausePreemptiveRotation,
		deathCauseDrainTeardown,
	} {
		cl := &Client{streamChans: make(map[uint16]chan []byte)}
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // pre-cancel: случайно взлетевший reconnectLoop выйдет сразу

		p := &WSPoolTransport{
			poolSize:          2,
			ctx:               ctx,
			cancel:            cancel,
			log:               newDiscardLogger(),
			meltdownThreshold: 100,
			meltdownWindow:    5 * time.Second,
		}
		p.slots = make([]*poolSlot, 4)
		p.client = cl

		slot := &poolSlot{}
		slot.setState(slotReady)
		slot.startedAtNs.Store(time.Now().Add(-10 * time.Second).UnixNano())
		p.slots[0] = slot

		before := Stats.WsDied.Load()
		p.handleSlotDeath(cl, 0, cause)
		if got := Stats.WsDied.Load() - before; got != 1 {
			t.Errorf("cause=%v: ws_died вырос на %d, ожидалось 1 — смерть слота "+
				"не попадает в счётчик, и строка статистики печатает 0 при "+
				"реально умерших соединениях", cause, got)
		}

		// Идемпотентность: второй вызов отбивается tryMarkDead.
		p.slots[0] = slot
		before = Stats.WsDied.Load()
		p.handleSlotDeath(cl, 0, cause)
		if got := Stats.WsDied.Load() - before; got != 0 {
			t.Errorf("cause=%v: повторный handleSlotDeath добавил %d — двойной "+
				"счёт одной смерти (инкремент стоит до CAS tryMarkDead)", cause, got)
		}
	}
}

// TestWsCreated_CountsPoolSlotConnects — сторож на второй половине пары:
// подъём соединения к origin обязан считаться на пути ПУЛА, а не только на
// per-stream пути.
//
// Тест читает исходник, а не гоняет connectSlot: connectSlot делает реальный
// handshake POST + WS upgrade, а поведенческая проверка через сеть здесь
// заменяется точным требованием к call-site. Что именно требуется:
//   - инкремент Stats.WsCreated стоит ВНУТРИ connectSlot ПОСЛЕ успешного
//     UpgradeToWS (соединение существует), а не на входе — иначе счётчик
//     считал бы попытки, включая отказы origin и ErrCellOccupied;
//   - в connectSlot ровно один инкремент (все четыре вызывающих —
//     Connect fan-out, reconnectLoopInner, legacy rotation, connectReserveSlot —
//     проходят через него, поэтому дубль дал бы кратный перечёт).
func TestWsCreated_CountsPoolSlotConnects(t *testing.T) {
	src, err := os.ReadFile("ws_pool.go")
	if err != nil {
		t.Fatalf("read ws_pool.go: %v", err)
	}
	// Файлы репозитория с CRLF — нормализуем, иначе сторож ловит перевод строки,
	// а не механизм.
	code := strings.ReplaceAll(string(src), "\r\n", "\n")

	start := strings.Index(code, "func (p *WSPoolTransport) connectSlot(")
	if start < 0 {
		t.Fatal("connectSlot не найдена — тест устарел, обновить сторож")
	}
	end := strings.Index(code[start:], "\nfunc ")
	if end < 0 {
		t.Fatal("не найден конец connectSlot")
	}
	body := code[start : start+end]

	if n := strings.Count(body, "Stats.WsCreated.Add(1)"); n != 1 {
		t.Fatalf("connectSlot содержит %d инкрементов Stats.WsCreated, нужен ровно 1: "+
			"0 — счётчик снова мёртв на пути пула (ws_created=0 при 3848 поднятых "+
			"соединениях в прогоне 20260817), >1 — кратный перечёт", n)
	}

	upgrade := strings.Index(body, "UpgradeToWS(slot.token, slot.session)")
	inc := strings.Index(body, "Stats.WsCreated.Add(1)")
	if upgrade < 0 {
		t.Fatal("вызов UpgradeToWS в connectSlot не найден — тест устарел")
	}
	if inc < upgrade {
		t.Error("Stats.WsCreated инкрементится ДО успешного UpgradeToWS — счётчик " +
			"будет считать попытки, а не существующие соединения к origin")
	}
}

// TestStatsDeltaLine_NoUndefinedWsFromPoolField — сторож против возврата поля
// ws_from_pool в строку `shadowlink client stats (delta)`.
//
// Величина «WS переиспользован из прогретого пула» определена только в
// экспериментальном per-stream режиме (WSReadyPool.Acquire); в архитектуре
// WS-пула стримы мультиплексируются по слотам, переиспользования соединения на
// стрим не существует, и поле печатало вечный 0. Ноль, у которого нет
// определения, читается как «переиспользования нет» — то есть как наблюдение.
// В per-stream режиме величина выводится как socks_connects − ws_created, так
// что удаление поля не теряет информации.
func TestStatsDeltaLine_NoUndefinedWsFromPoolField(t *testing.T) {
	src, err := os.ReadFile("stats.go")
	if err != nil {
		t.Fatalf("read stats.go: %v", err)
	}
	if strings.Contains(string(src), `"ws_from_pool"`) {
		t.Error(`поле "ws_from_pool" вернулось в строку статистики: в архитектуре ` +
			`WS-пула величина не определена и печатает вечный 0`)
	}
}

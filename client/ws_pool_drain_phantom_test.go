package client

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Фантомный счётчик стримов (P1, замер 2026-08-11).
//
// slot.streams — атомарный счётчик; streamMap — карта привязок. При утечке
// декремента счётчик держит привязки, которых в карте уже нет. Тогда в
// drainWatchdog закрываются ОБЕ ранние ветки выхода:
//
//   - `oldSlot.streams.Load() == 0` → false (счётчик протёк)
//   - `allStreamsIdle` → false, потому что при пустой карте возвращается
//     `found && allIdle`, а found=false
//
// Дренаж доезжает до sticky-дедлайна и держит ячейку весь teardown_cap.
//
// Масштаб по полю (лог nixavpn-DEBUG-20260811-145918, 3ч38м):
//
//	408 из 431 sticky-teardown имели remaining_streams>0 при diag_total=0
//	396 из них — ровно drain_duration=25s (полный sticky-предел)
//	natural finish: 0 из 158 с таким расхождением
//
// Корреляция полная: фантом ⇒ слот всегда доезжает до backstop. Воспроизводится
// во всех пяти сохранённых прогонах (08-07: 424/440, 08-08: 546/556,
// 08-10: 179/194 и 134/146). Правка sticky 15s→25s (2026-08-07) баг не создала,
// а сделала его дороже: те же фантомы стали держать ячейку 25s вместо 15s.
//
// Здесь чинится ПОСЛЕДСТВИЕ, а не причина утечки: карта — ground truth,
// счётчик — производное. Причину (путь, которым запись уходит из streamMap
// мимо декремента) надо искать отдельно, под -race на сервере: на
// Windows-dev гонки не ловятся (CLAUDE.md hard rule 6).

// Тик-ветка: счётчик врёт, карта пуста → слот обязан порваться сразу,
// а не ждать 25s sticky-предела.
func TestDrainWatchdog_PhantomStreamCounter_TicketBranchTearsDown(t *testing.T) {
	logBuf := &syncBuffer{}

	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		GracefulDrain:      true,
		DrainHardCap:       15 * time.Second, // поле: слот доезжал бы до sticky
		StickyMaxDrainAge:  25 * time.Second,
		DrainIdleThreshold: 100 * time.Millisecond,
	})
	p.ctx = t.Context()
	p.log = slog.New(slog.NewTextHandler(logBuf, nil))

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	// Фантом: счётчик держит 1, в streamMap для этого слота НИЧЕГО нет.
	// Ровно топовая пара из поля (rem=1, diag=0 — 280 случаев из 431).
	oldSlot.streams.Store(1)
	oldSlot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[0] = oldSlot

	beforeNatural := Stats.DrainNaturalFinishTotal.Load()
	beforeSticky := Stats.DrainStickyBackstopAgeTotal.Load()
	beforePhantom := Stats.DrainPhantomCounterTotal.Load()

	start := time.Now()
	p.drainWatchdog(cl, 0, oldSlot, start, "test")
	elapsed := time.Since(start)

	// До фикса: висел бы до дедлайна 15s, затем sticky-ветка до 25s.
	// После: рвётся через два тика подряд (подтверждение против гонки
	// AssignStream), то есть примерно за drainPollInterval.
	if elapsed >= 3*time.Second {
		t.Errorf("teardown занял %v — фантомный счётчик снова держит слот", elapsed)
	}
	if got := Stats.DrainStickyBackstopAgeTotal.Load(); got != beforeSticky {
		t.Errorf("DrainStickyBackstopAgeTotal вырос (%d→%d): слот ушёл в sticky-backstop, "+
			"хотя стримов нет ни одного", beforeSticky, got)
	}
	if got := Stats.DrainPhantomCounterTotal.Load(); got != beforePhantom+1 {
		t.Errorf("DrainPhantomCounterTotal = %d, want %d", got, beforePhantom+1)
	}
	// Фантом — НЕ natural finish: стримы не завершились сами, мы порвали
	// слот по расхождению. Смешение исказило бы долю штатных дренажей
	// (в поле это 408 событий из 431).
	if got := Stats.DrainNaturalFinishTotal.Load(); got != beforeNatural {
		t.Errorf("DrainNaturalFinishTotal вырос (%d→%d): фантом не должен считаться "+
			"штатным завершением дренажа", beforeNatural, got)
	}
}

// Диагностика обязана назвать расхождение вслух. Молчаливый фикс оставил бы
// причину утечки ненайденной — а это ровно H-15: контур работает, но о нём
// нельзя сказать, что он работает.
func TestDrainWatchdog_PhantomStreamCounter_LogsMismatch(t *testing.T) {
	logBuf := &syncBuffer{}

	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		GracefulDrain:      true,
		DrainHardCap:       15 * time.Second,
		StickyMaxDrainAge:  25 * time.Second,
		DrainIdleThreshold: 100 * time.Millisecond,
	})
	p.ctx = t.Context()
	p.log = slog.New(slog.NewTextHandler(logBuf, nil))

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(3)
	oldSlot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[0] = oldSlot

	p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test")

	out := logBuf.String()
	if !strings.Contains(out, "phantom stream counter") {
		t.Errorf("лог обязан назвать расхождение счётчика и карты:\n%s", out)
	}
	if !strings.Contains(out, "counter_streams=3") {
		t.Errorf("лог обязан показать величину расхождения:\n%s", out)
	}
}

// Гонка AssignStream: inc счётчика идёт ПЕРЕД публикацией записи в
// streamMap (ws_pool.go, «streams.Add MUST precede streamMap.Store», spec
// §2.5 — чтобы наблюдатель, увидевший запись, гарантированно видел счётчик).
//
// В окне между этими двумя операциями здоровый новый стрим выглядит ровно
// как фантом: счётчик>0, в карте пусто. Наивный предикат порвал бы слот, а
// handleSlotDeath не закрыл бы канал ещё не опубликованного стрима — тот
// повис бы на мёртвом транспорте до таймаута.
//
// Отличие фантома от гонки — во времени: утёкший декремент необратим и
// держится вечно, окно inc→Store живёт наносекунды. Поэтому решение
// требует ДВУХ наблюдений подряд.
func TestDrainWatchdog_PhantomFix_IgnoresAssignStreamWindow(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		GracefulDrain:      true,
		DrainHardCap:       15 * time.Second,
		StickyMaxDrainAge:  25 * time.Second,
		DrainIdleThreshold: 100 * time.Millisecond,
	})
	p.ctx = t.Context()
	p.log = slog.New(slog.DiscardHandler)

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[0] = oldSlot

	beforePhantom := Stats.DrainPhantomCounterTotal.Load()

	// Имитируем окно AssignStream: счётчик уже поднят, записи ещё нет.
	oldSlot.streams.Store(1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test")
	}()

	// Окно закрывается через один тик — публикуем запись, как сделал бы
	// AssignStream. Слот к этому моменту рвать было НЕЛЬЗЯ.
	time.Sleep(drainPollInterval + 100*time.Millisecond)
	storeStreamForTestWithAge(p, 1, 0, 0)

	// Даём watchdog ещё пару тиков на то, чтобы увидеть опубликованный стрим.
	time.Sleep(2 * drainPollInterval)

	if got := Stats.DrainPhantomCounterTotal.Load(); got != beforePhantom {
		t.Errorf("окно AssignStream засчитано фантомом (DrainPhantomCounterTotal %d→%d): "+
			"живой стрим порван до публикации в streamMap", beforePhantom, got)
	}

	p.cancel()
	<-done
}

// Обратная сторона: слот с РЕАЛЬНЫМ активным стримом рвать нельзя.
// Без этого теста фикс превратился бы в «рвать всё подряд» и убил бы
// sticky-механизм, ради которого закачки переживают ротацию.
func TestDrainWatchdog_PhantomFix_DoesNotTouchRealStreams(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:                2,
		ServerAddr:          "127.0.0.1:0",
		GracefulDrain:       true,
		DrainHardCap:        600 * time.Millisecond,
		StickyMaxDrainAge:   10 * time.Second,
		StickyMaxTotalBytes: 1 << 30,
		DrainIdleThreshold:  100 * time.Millisecond,
	})
	p.ctx = t.Context()
	p.log = slog.New(slog.DiscardHandler)

	oldSlot := &poolSlot{}
	oldSlot.setState(slotDraining)
	oldSlot.streams.Store(1)
	oldSlot.startedAtNs.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	p.slots[0] = oldSlot

	// Живая ёмкость: без неё stickyQuotaAvailable отказывает по
	// readyCapacityFloor, и тест падал бы по причине, не связанной с
	// фантомом (quota_denied вместо продления).
	for i := 1; i < len(p.slots); i++ {
		ready := &poolSlot{}
		ready.setState(slotReady)
		p.slots[i] = ready
	}

	// Настоящий стрим в карте, пишет прямо сейчас — не фантом.
	storeStreamForTestWithAge(p, 1, 0, 0)

	beforePhantom := Stats.DrainPhantomCounterTotal.Load()
	beforeExtended := Stats.DrainStickyExtendedTotal.Load()

	// Держим стрим ЖИВЫМ всё время наблюдения: иначе он состарится за
	// idle-порог (100ms) и дренаж уйдёт в finishIdle — законный путь, но
	// не тот, который здесь проверяется.
	stopHeartbeat := make(chan struct{})
	go func() {
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-tick.C:
				// Освежаем lastWriteNs — тот же приём, что в других
				// тестах активного стрима.
				storeStreamForTestWithAge(p, 1, 0, 0)
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.drainWatchdog(cl, 0, oldSlot, time.Now(), "test")
	}()

	// Ждём срабатывания дедлайна (600ms) опросом, а не жёстким сном:
	// фиксированные 900ms дают всего 300ms запаса и флейкуют на
	// загруженной машине.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if Stats.DrainStickyExtendedTotal.Load() > beforeExtended {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := Stats.DrainPhantomCounterTotal.Load(); got != beforePhantom {
		t.Errorf("живой стрим засчитан фантомом (DrainPhantomCounterTotal %d→%d)",
			beforePhantom, got)
	}
	if got := Stats.DrainStickyExtendedTotal.Load(); got <= beforeExtended {
		t.Errorf("активный стрим не продлил дренаж (DrainStickyExtendedTotal %d→%d) — "+
			"фикс фантома задел живой sticky-путь", beforeExtended, got)
	}

	close(stopHeartbeat)
	p.cancel()
	<-done
}

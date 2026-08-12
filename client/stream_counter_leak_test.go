package client

import (
	"sync"
	"testing"
)

// stream_counter_leak_test.go — spec 2026-06-01 stream-counter-leak-fix.
//
// poolSlot.streams must stay == the number of live streamMap entries pointing at
// THAT slot object. The leak: rebindStreamToSlot mutated the counter BY INDEX,
// so when connectSlot swapped the object at srcIdx between the inc and the dec,
// the dec missed and the inc stranded on the live target → active_streams drift
// (observed 1397 vs physical max 80). Fix: mutate captured *poolSlot pointers +
// floor-clamp dec.

// poolLiveStreamSum sums streams.Load() across all non-nil slots — mirrors
// emitHealthSummary's active_streams (ws_pool.go:1744), the metric that drifted.
func poolLiveStreamSum(p *WSPoolTransport) int32 {
	var sum int32
	for _, s := range p.slots {
		if s != nil {
			sum += s.streams.Load()
		}
	}
	return sum
}

// TestRebind_CounterPairedOnSameSlots — baseline: a normal rebind (no object
// swap) moves exactly one unit from src to target; live sum is unchanged.
func TestRebind_CounterPairedOnSameSlots(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	_ = cl
	p.slots[0].state.Store(int32(slotReady))
	p.slots[1].state.Store(int32(slotReady))
	p.slots[0].streams.Store(1) // stream lives on slot 0
	p.streamMap.Store(uint16(50), newStreamEntry(0))

	before := poolLiveStreamSum(p)
	p.rebindStreamToSlot(50, 1)

	if got := p.slots[0].streams.Load(); got != 0 {
		t.Errorf("src slot streams = %d, want 0", got)
	}
	if got := p.slots[1].streams.Load(); got != 1 {
		t.Errorf("target slot streams = %d, want 1", got)
	}
	if got := poolLiveStreamSum(p); got != before {
		t.Errorf("live sum drifted: before=%d after=%d (want equal)", before, got)
	}
	if v, ok := p.streamMap.Load(uint16(50)); ok {
		if e := v.(*streamEntry); e.slotIdx != 1 {
			t.Errorf("entry slotIdx = %d, want 1 (re-pointed)", e.slotIdx)
		}
	}
}

// TestRebind_ConcurrentSrcReplacement_NoDrift — THE regression, concurrent form.
// While rebinds move streams off slot 0, a competing goroutine repeatedly
// replaces the object at slot 0 with a fresh poolSlot{streams:0} (exactly what
// connectSlot does after a close-1006 death). On the buggy by-index code, a dec
// that races a replacement lands on the new zero object while the inc strands on
// the live target → the live-stream sum drifts upward (the 1397 leak). The fix
// captures the src pointer under reserveMu (coherent with the replacement lock)
// so inc and dec always pair on the same object.
//
// Invariant after quiescence: the live sum must equal the number of live
// streamMap entries (every counted unit is backed by a real binding), and no
// slot counter is negative. Run repeatedly + under -race to expose the window.
func TestRebind_ConcurrentSrcReplacement_NoDrift(t *testing.T) {
	p, cl := newResumeTestPool(t, 3)
	_ = cl
	for i := 0; i < 3; i++ {
		p.slots[i].state.Store(int32(slotReady))
	}

	const N = 200
	// Seed N streams on slot 0.
	for id := 1; id <= N; id++ {
		p.slots[0].streams.Add(1)
		p.streamMap.Store(uint16(id), newStreamEntry(0))
	}

	var wg sync.WaitGroup
	// Goroutine A: migrate every stream off slot 0 onto slot 1 or 2.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for id := 1; id <= N; id++ {
			target := 1 + (id % 2)
			p.rebindStreamToSlot(uint16(id), target)
		}
	}()
	// Goroutine B: churn slot 0's object as connectSlot would on death+reconnect.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			p.reserveMu.Lock()
			ns := &poolSlot{index: 0}
			ns.setState(slotReady)
			p.slots[0] = ns
			p.reserveMu.Unlock()
		}
	}()
	wg.Wait()

	// Count live entries and the live counter sum.
	var liveEntries int32
	p.streamMap.Range(func(_, _ any) bool { liveEntries++; return true })
	sum := poolLiveStreamSum(p)

	// No counter may be negative.
	for i, s := range p.slots {
		if s != nil && s.streams.Load() < 0 {
			t.Errorf("slot %d counter negative: %d", i, s.streams.Load())
		}
	}
	// The live sum must not EXCEED the live entry count (the leak symptom is an
	// excess of counted units over real bindings). Under the buggy code the sum
	// drifts above liveEntries; the fix keeps sum <= liveEntries.
	if sum > liveEntries {
		t.Errorf("stream-counter drift: live sum=%d > live entries=%d (leak)", sum, liveEntries)
	}
}

// TestDecStreamsFloor_NeverNegative — the floor clamp.
func TestDecStreamsFloor_NeverNegative(t *testing.T) {
	s := &poolSlot{}
	s.streams.Store(0)
	decStreamsFloor(s)
	if got := s.streams.Load(); got != 0 {
		t.Errorf("decStreamsFloor at 0 = %d, want 0 (no underflow)", got)
	}
	s.streams.Store(2)
	decStreamsFloor(s)
	if got := s.streams.Load(); got != 1 {
		t.Errorf("decStreamsFloor at 2 = %d, want 1", got)
	}
}

// TestReleaseStream_AfterSlotReplaced_NoNegative — if the slot object at the
// stream's idx was replaced (death+reconnect) before ReleaseStream, the dec must
// not drive the fresh object negative.
func TestReleaseStream_AfterSlotReplaced_NoNegative(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	_ = cl
	p.slots[0].state.Store(int32(slotReady))
	// Stream assigned to slot 0 on object O1 (streams=1).
	p.slots[0].streams.Store(1)
	p.streamMap.Store(uint16(70), newStreamEntry(0))

	// Slot 0 dies + reconnects: fresh object O2 with streams=0.
	p.slots[0] = &poolSlot{index: 0}
	p.slots[0].state.Store(int32(slotReady))

	p.ReleaseStream(70)

	if got := p.slots[0].streams.Load(); got < 0 {
		t.Errorf("ReleaseStream drove replaced slot negative: %d", got)
	}
}

// ============================================================================
// Вторая утечка декремента: handleStreamClose (найдена 2026-08-12)
// ============================================================================
//
// Правка 2026-06-01 выше закрыла утечку на пути rebindStreamToSlot. Но осталась
// вторая, по другому пути, и именно она давала фантомный счётчик в поле.
//
// AssignStream делает streams.Add(1) + streamMap.Store. Освобождение идёт двумя
// путями, и декремент был только в одном:
//
//	ReleaseStream     — Load, decStreamsFloor, Delete   ← декремент ЕСТЬ
//	handleStreamClose — Delete                          ← декремента НЕ БЫЛО
//
// Второй путь не редкость: сервер присылает FlagStreamClose при смерти origin
// TCP (ws_pool.go:3719) — это штатное завершение стрима. Плюс ветка
// неразбираемого migration-кадра (:4139).
//
// Полевая цена: counter_streams>0 при map_streams=0 в 28.1% дренажей прогона
// 110200 и 34.4% прогона 140930 (z=2.48, доля РОСЛА). Фикс 2026-08-11 лечил
// последствие — слот перестал висеть весь teardown_cap, — но расхождение
// оставалось. Это его причина.
//
// Исключение: handleSlotDeath (:4196) зовёт closeStream в цикле, но затем делает
// streams.Store(0). Там декремент был бы двойным учётом — сторожевой тест ниже.
func TestHandleStreamClose_DecrementsCounter(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	p.slots[0].state.Store(int32(slotReady))

	const sid = uint16(4242)
	p.slots[0].streams.Store(1)
	p.streamMap.Store(sid, newStreamEntry(0))

	p.handleStreamClose(cl, sid)

	if _, ok := p.streamMap.Load(sid); ok {
		t.Error("запись осталась в streamMap после handleStreamClose")
	}
	if got := p.slots[0].streams.Load(); got != 0 {
		t.Errorf("счётчик слота = %d после handleStreamClose, ожидался 0 — "+
			"это и есть утечка, дающая фантомный счётчик", got)
	}
}

// Двойное закрытие не должно уводить счётчик ниже нуля.
func TestHandleStreamClose_DoubleCloseNoNegative(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	p.slots[0].state.Store(int32(slotReady))

	const sid = uint16(777)
	p.slots[0].streams.Store(1)
	p.streamMap.Store(sid, newStreamEntry(0))

	p.handleStreamClose(cl, sid)
	p.handleStreamClose(cl, sid) // записи в карте уже нет

	if got := p.slots[0].streams.Load(); got != 0 {
		t.Errorf("счётчик = %d после двойного закрытия, ожидался 0", got)
	}
}

// Закрытие неизвестного стрима не трогает чужие счётчики.
func TestHandleStreamClose_UnknownStreamLeavesCountersAlone(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	p.slots[0].streams.Store(3)
	p.slots[1].streams.Store(2)

	p.handleStreamClose(cl, 9999)

	if got := p.slots[0].streams.Load(); got != 3 {
		t.Errorf("slot0 streams=%d, ожидалось 3", got)
	}
	if got := p.slots[1].streams.Load(); got != 2 {
		t.Errorf("slot1 streams=%d, ожидалось 2", got)
	}
}

// Декремент по ЗАХВАЧЕННОМУ указателю, не по индексу: если ячейку подменили
// между Assign и закрытием, свежий обнулённый объект не должен уйти в минус.
// Тот же довод, что в ReleaseStream (F3, 2026-06-01).
func TestHandleStreamClose_SurvivesCellReplacement(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	p.slots[0].state.Store(int32(slotReady))

	const sid = uint16(555)
	p.slots[0].streams.Store(1)
	p.streamMap.Store(sid, newStreamEntry(0))

	// death+reconnect: свежий объект с нулевым счётчиком.
	p.reserveMu.Lock()
	fresh := &poolSlot{index: 0}
	fresh.setState(slotReady)
	p.slots[0] = fresh
	p.reserveMu.Unlock()

	p.handleStreamClose(cl, sid)

	if got := fresh.streams.Load(); got < 0 {
		t.Errorf("свежая ячейка ушла в минус: streams=%d", got)
	}
}

// Инвариант, который ломался в поле: после серии штатных FlagStreamClose сумма
// счётчиков обязана совпасть с числом записей в карте (обе нули).
func TestHandleStreamClose_CounterMatchesMapAfterCloses(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	p.slots[0].state.Store(int32(slotReady))
	p.slots[1].state.Store(int32(slotReady))

	const n = 50
	for i := 0; i < n; i++ {
		idx := i % 2
		p.slots[idx].streams.Add(1)
		p.streamMap.Store(uint16(1000+i), newStreamEntry(idx))
	}
	for i := 0; i < n; i++ {
		p.handleStreamClose(cl, uint16(1000+i))
	}

	var mapCount int
	p.streamMap.Range(func(_, _ any) bool { mapCount++; return true })

	if mapCount != 0 {
		t.Errorf("в карте осталось %d записей", mapCount)
	}
	if sum := poolLiveStreamSum(p); sum != 0 {
		t.Errorf("сумма счётчиков = %d при пустой карте — фантом (%d стримов закрыто)", sum, n)
	}
}

// Сторож двойного учёта: handleSlotDeath обнуляет счётчик через Store(0) ПОСЛЕ
// закрытия стримов, поэтому декремент в handleStreamClose на этом пути не должен
// давать отрицательных значений.
func TestHandleStreamClose_SlotDeathPathNoDoubleCount(t *testing.T) {
	p, cl := newResumeTestPool(t, 2)
	p.slots[0].state.Store(int32(slotReady))

	// Три стрима на слоте 0.
	for i := 0; i < 3; i++ {
		p.slots[0].streams.Add(1)
		p.streamMap.Store(uint16(300+i), newStreamEntry(0))
	}
	// Эмулируем то, что делает handleSlotDeath: закрыть стримы, затем Store(0).
	for i := 0; i < 3; i++ {
		p.handleStreamClose(cl, uint16(300+i))
	}
	p.slots[0].streams.Store(0)

	if got := p.slots[0].streams.Load(); got != 0 {
		t.Errorf("счётчик = %d, ожидался 0 (двойной учёт или остаток)", got)
	}
}

// TestNextStreamID_SkipsIDInFramesChans — F4: NextStreamID must not hand out an
// ID already live in streamFramesChans (migration-mode streams register there,
// not in streamChans). A collision makes AssignStream's dup-guard skip the inc.
func TestNextStreamID_SkipsIDInFramesChans(t *testing.T) {
	cl := &Client{}
	cl.streamChans = make(map[uint16]chan []byte)
	cl.streamFramesChans = make(map[uint16]chan StreamFrame)
	// Force the counter so the next allocation would collide with an ID that is
	// only present in the frames map.
	cl.streamCounter = 99
	cl.streamFramesChans[100] = make(chan StreamFrame, 1)

	id := cl.NextStreamID()
	if id == 100 {
		t.Errorf("NextStreamID returned %d which is live in streamFramesChans (collision)", id)
	}
}

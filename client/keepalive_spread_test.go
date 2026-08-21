package client

import (
	"context"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// Разнесение keepalive по слотам.
//
// Проблема: nextKeepaliveDelay джиттерует МОМЕНТ пробуждения (log-normal,
// base 5 с) — это хорошо и уже защищено. Но sendKeepaliveToAllSlots проходит по
// всем слотам в одном цикле без задержек, поэтому на wire уходит синхронный
// burst из 8 фреймов к одному origin в пределах миллисекунд. Для наблюдателя,
// считающего соединения, «8 TLS-сессий оживают одновременно» — это шаблон,
// который джиттер периода не устраняет: он двигает burst целиком.
//
// Инвариант, который правка НЕ должна нарушить (Bug #9): максимальное время
// молчания слота ограничено, иначе сервер/посредник сочтёт соединение мёртвым.
// Разнос обязан быть заметно меньше самого интервала keepalive.

// TestKeepaliveSpread_NeverExtendsSilenceBeyondCutFloor — центральный сторож
// правки разноса.
//
// Запас до порога реза по тишине РОВНО НУЛЕВОЙ: худшее молчание слота = base*2
// = 10 с (сэмплер усечён в [base/2, base*2]), а middleboxSilentCutFloor = 10 с.
// Bug #9 держится на этом равенстве без зазора — в поле слоты умирали при
// last_write_age_ms 10000-15000. Поэтому разнос обязан ВЫЧИТАТЬСЯ из интервала,
// а не добавляться: первая версия правки спала перед каждой записью и давала
// 10.4 с, то есть возвращала ровно тот баг, от которого защищает Bug #9.
func TestKeepaliveSpread_NeverExtendsSilenceBeyondCutFloor(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 8, ServerAddr: "127.0.0.1:0"})

	maxGap := p.keepaliveBase * 2
	if maxGap > middleboxSilentCutFloor {
		t.Fatalf("предпосылка теста сломана: base*2 = %v уже выше порога %v",
			maxGap, middleboxSilentCutFloor)
	}

	// Проверка идёт по ТЕОРЕТИЧЕСКОЙ границе сэмплера, а не по максимуму
	// выборки: за 20 000 тяг log-normal доходит лишь до ~9.6 с из 10 с
	// возможных, поэтому эмпирический максимум + 400 мс укладывается в порог
	// даже у дефектной версии — такой тест был бы слепым (проверено:
	// он проходил и без вычитания).
	maxSamplerDraw := p.keepaliveBase * 2
	if maxSamplerDraw+keepaliveSpreadMax > middleboxSilentCutFloor {
		if !keepaliveDelayCompensatesSpread(p) {
			t.Errorf("максимум сэмплера %v + проход %v = %v превышает порог реза "+
				"по тишине %v, и nextKeepaliveDelay НЕ компенсирует проход — "+
				"слот может быть срезан за тишину до прихода keepalive",
				maxSamplerDraw, keepaliveSpreadMax,
				maxSamplerDraw+keepaliveSpreadMax, middleboxSilentCutFloor)
		}
	}

	// ⚠ ГЛАВНАЯ проверка, и её отсутствие пропустило P0 (ревью 2026-08-19):
	// компенсация вычитает ОДИН keepaliveSpreadMax, поэтому корректна только
	// если полное время прохода тоже ограничено одним keepaliveSpreadMax
	// НЕЗАВИСИМО от числа слотов. Первая версия спала кумулятивно
	// (`spread - delay` на каждом слоте), проход стоил Σ по слотам: замер дал
	// max 2.8 с при 8 слотах и худшее молчание 12.4 с против порога 10 с.
	// Сторож этого не видел, потому что считал один разнос вместо poolSize.
	//
	// Инвариант: время прохода = МАКСИМУМ абсолютных смещений, а не их сумма.
	// Проверяется на числе слотов вплоть до полной ёмкости массива (2*poolSize).
	for _, slots := range []int{1, 4, 8, 16} {
		var worstPass time.Duration
		const passes = 20000
		for range passes {
			offsets := make([]time.Duration, 0, slots)
			for i := 0; i < slots; i++ {
				offsets = append(offsets, keepaliveSlotDelay(i))
			}
			// Модель прохода: сон до абсолютных моментов, значит длительность
			// равна наибольшему смещению. Кумулятивная версия дала бы сумму.
			var pass time.Duration
			for _, o := range offsets {
				if o > pass {
					pass = o
				}
			}
			if pass > worstPass {
				worstPass = pass
			}
		}
		if worstPass > keepaliveSpreadMax {
			t.Errorf("slots=%d: проход %v превышает keepaliveSpreadMax %v — "+
				"смещения складываются вместо параллельного окна",
				slots, worstPass, keepaliveSpreadMax)
		}
		if worst := maxSamplerDraw - keepaliveSpreadMax + worstPass; worst > middleboxSilentCutFloor {
			t.Errorf("slots=%d: худшее молчание %v превышает порог реза %v",
				slots, worst, middleboxSilentCutFloor)
		}
	}

	// И проверка на РЕАЛЬНОМ проходе, а не на модели: выше считалась формула
	// «проход = максимум смещений», но она описывает мою реализацию, а не
	// проверяет её. Кумулятивная версия прошла бы модельный тест, если бы
	// модель повторяла её ошибку. Поэтому здесь измеряется фактическая
	// длительность sendKeepaliveToAllSlots на пуле из 8 готовых слотов.
	t.Run("реальный проход ограничен окном", func(t *testing.T) {
		pool := NewWSPoolTransport(&Client{streamChans: make(map[uint16]chan []byte)},
			WSPoolConfig{Size: 8, ServerAddr: "127.0.0.1:0"})
		pool.ctx = context.Background()
		// Слоты обязаны быть ПОЛНОСТЬЮ готовыми (transport + session), иначе
		// они отфильтровываются при построении очереди — до разноса, — и тест
		// измеряет пустой проход. Первая версия этой проверки ставила nil
		// transport и давала worst=0s, то есть не проверяла ничего.
		for i := range pool.slots {
			s := &poolSlot{index: i}
			s.transport = &countingTransport{}
			s.session = core.NewSession(uint32(i+1), make([]byte, 32), make([]byte, 32))
			s.setState(slotReady)
			pool.slots[i] = s
		}
		ready := 0
		for _, s := range pool.slots {
			if s != nil && s.getState() == slotReady && s.transport != nil && s.session != nil {
				ready++
			}
		}
		if ready < 8 {
			t.Fatalf("готовых слотов %d, ожидалось >= 8 — проход не отработает разнос", ready)
		}

		var worst time.Duration
		for range 20 {
			start := time.Now()
			pool.sendKeepaliveToAllSlots()
			if d := time.Since(start); d > worst {
				worst = d
			}
		}
		// Допуск на планировщик: окно + 20 %. Кумулятивная версия дала бы
		// ~1.6 с в среднем при 8 слотах, то есть промахнулась бы на порядок.
		limit := keepaliveSpreadMax + keepaliveSpreadMax/5
		if worst > limit {
			t.Errorf("фактический проход %v превышает допуск %v (окно %v) — "+
				"смещения складываются", worst, limit, keepaliveSpreadMax)
		}
		t.Logf("фактический проход при 8 слотах: worst=%v (окно %v)", worst, keepaliveSpreadMax)
	})

	// Эмпирическая проверка компенсации: верхняя граница выборки после
	// вычитания обязана быть ниже, чем без него. Сравниваем с максимумом
	// сырого сэмплера, полученным тем же числом тяг.
	const draws = 20000
	var worstDelay time.Duration
	for i := 0; i < draws; i++ {
		if d := p.nextKeepaliveDelay(); d > worstDelay {
			worstDelay = d
		}
	}
	var worstRaw time.Duration
	for i := 0; i < draws; i++ {
		if d := JitteredIntervalLogNormal(p.keepaliveBase, keepaliveSigma); d > worstRaw {
			worstRaw = d
		}
	}
	// Компенсация обязана быть заметной: пауза цикла ниже сырого сэмплера
	// примерно на время прохода (допуск на разброс выборок — половина разноса).
	if worstDelay > worstRaw-keepaliveSpreadMax/2 {
		t.Errorf("пауза цикла (max %v) не отличается от сырого сэмплера (max %v) "+
			"на время прохода %v — компенсация не применяется",
			worstDelay, worstRaw, keepaliveSpreadMax)
	}

	// И нижняя граница: пауза не должна проваливаться ниже минимального
	// интервала сэмплера, иначе это лишние кадры к origin (P0 — policing по
	// числу и частоте).
	minInterval := p.keepaliveBase / 2
	for i := 0; i < draws; i++ {
		if d := p.nextKeepaliveDelay(); d < minInterval {
			t.Fatalf("пауза %v ниже минимального интервала %v — вычитание "+
				"разноса не клампится", d, minInterval)
		}
	}
}

// TestKeepalive_ReachesDrainingSlots — слот в дренаже обязан получать keepalive.
//
// Полевой замер 2026-08-20 (лог nixavpn-DEBUG-20260820-121231, 10 ч 37 м): ВСЕ
// пять взрослых резов (close 1006, возрасты 88.4-108.8 с) пришли в слоты,
// находившиеся в дренаже, через 8.9-22.3 с после `drain started`, и в трёх
// случаях `last_write_age_ms` был 11.4 / 18.3 / 28.2 с — то есть выше порога
// реза по тишине (10 с), под которым весь Bug #9 и настроен.
//
// Причина: sendKeepaliveToAllSlots фильтровал по `getState() != slotReady`, а
// дренируемый слот живёт после этого ещё до stickyMaxDrainAge (25 с в поле).
// Слот с малым трафиком в дренаже замолкал ровно в момент перехода.
//
// ⚠ Почему это НЕ ломает дренаж (проверено по коду, а не предположено): дренаж
// закрывается по `lastWriteNs` КАЖДОГО СТРИМА (allStreamsIdle, stream_entry.go),
// а keepalive — кадр уровня слота, стримов он не касается. Транспорт при входе в
// дренаж жив, закрытие только в tearDown, поэтому кадру есть куда уйти.
//
// ⚠ Сторож проверяет ВЛАСТЬ, а не зелёный цвет: считается фактический
// controlWrites на стабе. Мёртвые состояния проверяются тем же проходом — иначе
// «пишем всем подряд» тоже прошло бы тест.
func TestKeepalive_ReachesDrainingSlots(t *testing.T) {
	pool := NewWSPoolTransport(&Client{streamChans: make(map[uint16]chan []byte)},
		WSPoolConfig{Size: 4, ServerAddr: "127.0.0.1:0"})
	pool.ctx = context.Background()

	// По одному слоту на каждое интересующее состояние. Полностью готовые
	// (transport + session), иначе фильтр отсеет их ДО проверки состояния и тест
	// измерит пустой проход — на этом уже наступали выше в этом файле.
	states := []slotState{slotReady, slotDraining, slotDead, slotConnecting}
	transports := make([]*countingTransport, len(states))
	for i, st := range states {
		ct := &countingTransport{}
		transports[i] = ct
		s := &poolSlot{index: i}
		s.transport = ct
		s.session = core.NewSession(uint32(i+1), make([]byte, 32), make([]byte, 32))
		s.setState(st)
		pool.slots[i] = s
	}
	for i := len(states); i < len(pool.slots); i++ {
		pool.slots[i] = nil
	}

	pool.sendKeepaliveToAllSlots()

	// slotReady — контроль предпосылки: если он не получил кадр, сломан сам
	// проход, и вывод о дренаже был бы недействителен.
	if transports[0].controlWrites == 0 {
		t.Fatal("предпосылка сломана: slotReady не получил keepalive — " +
			"проход не отработал, о дренаже судить нельзя")
	}

	if transports[1].controlWrites == 0 {
		t.Error("слот в slotDraining НЕ получил keepalive: он молчит весь дренаж " +
			"(до stickyMaxDrainAge = 25 с) при пороге реза по тишине 10 с — " +
			"ровно тот путь, на котором в поле 2026-08-20 легли все 5 резов")
	}

	// Мёртвые состояния keepalive получать не должны: запись в них дала бы
	// ложную ошибку в логе, а на wire — кадр в закрытое соединение.
	for i, st := range []slotState{slotDead, slotConnecting} {
		if got := transports[i+2].controlWrites; got != 0 {
			t.Errorf("слот в состоянии %v получил %d keepalive-кадров, ожидалось 0 — "+
				"фильтр состояний ослаблен слишком широко", st, got)
		}
	}
}

// keepaliveDelayCompensatesSpread — компенсирует ли nextKeepaliveDelay время
// прохода. Проверяется поведением, а не чтением исходника: сравниваются
// распределения паузы цикла и сырого сэмплера на одинаковом числе тяг.
//
// Порог — четверть разноса: полное вычитание сдвигает всю выборку на
// keepaliveSpreadMax, поэтому даже при разбросе тяг разница средних заметна
// намного сильнее этого порога.
func keepaliveDelayCompensatesSpread(p *WSPoolTransport) bool {
	const draws = 5000
	var sumDelay, sumRaw time.Duration
	for i := 0; i < draws; i++ {
		sumDelay += p.nextKeepaliveDelay()
		sumRaw += JitteredIntervalLogNormal(p.keepaliveBase, keepaliveSigma)
	}
	meanDelay := sumDelay / draws
	meanRaw := sumRaw / draws
	return meanRaw-meanDelay > keepaliveSpreadMax/4
}

// Задержка для слота обязана лежать в [0, keepaliveSpreadMax) и НЕ быть
// детерминированной функцией индекса: idx*step — это лестница, то есть тот же
// шаблон, только растянутый (ровно этим болел Connect fan-out).
func TestKeepaliveSlotDelay_InRangeAndNotALadder(t *testing.T) {
	const slots = 8
	const samples = 200

	seen := make([]map[time.Duration]int, slots)
	for i := range seen {
		seen[i] = make(map[time.Duration]int)
	}

	for s := 0; s < samples; s++ {
		for idx := 0; idx < slots; idx++ {
			d := keepaliveSlotDelay(idx)
			if d < 0 || d >= keepaliveSpreadMax {
				t.Fatalf("slot %d: задержка %v вне [0, %v)", idx, d, keepaliveSpreadMax)
			}
			seen[idx][d]++
		}
	}

	// Каждый индекс обязан давать РАЗНЫЕ значения между вызовами: одно
	// значение на индекс означало бы детерминированную лестницу.
	for idx := 0; idx < slots; idx++ {
		if len(seen[idx]) < samples/10 {
			t.Errorf("slot %d: всего %d различных задержек на %d вызовов — "+
				"похоже на детерминированную функцию индекса, а не на джиттер",
				idx, len(seen[idx]), samples)
		}
	}
}

// Слот 0 не должен быть привилегированным: если для idx==0 задержка всегда 0,
// то первый слот остаётся якорем burst'а и шаблон «8 оживают вместе» частично
// сохраняется — наблюдателю достаточно самого раннего кадра.
func TestKeepaliveSlotDelay_ZeroIndexIsJitteredToo(t *testing.T) {
	var nonZero int
	for i := 0; i < 200; i++ {
		if keepaliveSlotDelay(0) > 0 {
			nonZero++
		}
	}
	if nonZero == 0 {
		t.Error("slot 0 всегда получает задержку 0 — он остаётся якорем burst'а")
	}
}

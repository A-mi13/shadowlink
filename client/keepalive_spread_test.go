package client

import (
	"testing"
	"time"
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
	//
	// Инвариант формулируется на константах: «максимум сэмплера ПЛЮС полное
	// время прохода не превышает порог реза». Единственный способ его
	// выполнить — вычитать время прохода из интервала.
	maxSamplerDraw := p.keepaliveBase * 2
	if maxSamplerDraw+keepaliveSpreadMax > middleboxSilentCutFloor {
		// Дефектная конфигурация: либо разнос добавляется к интервалу, либо
		// вычитание не покрывает полное время прохода.
		if !keepaliveDelayCompensatesSpread(p) {
			t.Errorf("максимум сэмплера %v + проход %v = %v превышает порог реза "+
				"по тишине %v, и nextKeepaliveDelay НЕ компенсирует проход — "+
				"слот может быть срезан за тишину до прихода keepalive",
				maxSamplerDraw, keepaliveSpreadMax,
				maxSamplerDraw+keepaliveSpreadMax, middleboxSilentCutFloor)
		}
	}

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

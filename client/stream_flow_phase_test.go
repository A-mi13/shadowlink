package client

import (
	"math"
	"testing"
	"time"
)

// Фаза отправок credit-sender'а: WINDOW_UPDATE — это РЕАЛЬНЫЕ байты на wire
// (uplink-фрейм к origin), а расписание им задаёт time.NewTicker(8ms) в
// startCreditSender. Джиттер в том цикле есть, но он приложен к ПОРОГУ
// (thresholdRatio 0.4-0.6), а не к периоду пробуждения — ровно тот дефект,
// который в этом проекте уже ловили на rotationWatchdogTick: «джиттер к
// порогу не размазывает фазу, она квантуется тиком проверки» (CLAUDE.md
// hard rule 9). Там лечение состояло в замене Ticker на Timer с перевзводом
// на tick + uniform[0, tick).
//
// Тест замеряет vector strength моментов отправки на периоде тика. Он НЕ
// утверждает, что решётка наблюдаема цензором — это отдельный вопрос
// (нужен pcap, см. tools/firstpackets -phase). Он фиксирует свойство кода:
// квантуется ли момент отправки периодом тикера.
//
// ⚠ Существующие тесты creditSender этого поймать не могли: они зовут
// creditSenderTick напрямую, минуя тикер, то есть проверяют решение «слать
// или нет», а не момент отправки.

// vectorStrengthPhase — длина среднего вектора фаз для моментов ts (в
// секундах), свёрнутых по периоду period. R=1 — идеальная решётка,
// R~1/sqrt(n) — равномерная фаза. Дубликат величины из tools/firstpackets
// намеренный: инструмент — отдельный main-пакет, тянуть его в client нельзя.
func vectorStrengthPhase(ts []float64, period float64) float64 {
	if len(ts) < 2 || period <= 0 {
		return 0
	}
	var sc, ss float64
	for _, t := range ts {
		ph := 2 * math.Pi * math.Mod(t, period) / period
		sc += math.Cos(ph)
		ss += math.Sin(ph)
	}
	return math.Hypot(sc, ss) / float64(len(ts))
}

// TestCreditSender_SendPhaseIsQuantizedByTicker документирует НАБЛЮДАЕМОЕ
// свойство: моменты отправки WINDOW_UPDATE привязаны к сетке тикера 8 мс.
//
// Тест намеренно НЕ падает при обнаружении решётки: constanta не менялась
// (hard rule 8 — тайминговые константы не править «на глаз»), а поведение
// фиксируется, чтобы правка не прошла молча. Он падает, только если сетка
// ИСЧЕЗЛА — тогда кто-то починил фазу, и это надо отразить в CLAUDE.md,
// либо если механизм перестал слать вовсе.
func TestCreditSender_SendPhaseIsQuantizedByTicker(t *testing.T) {
	if testing.Short() {
		t.Skip("замер фазы требует ~1.5 с реального времени")
	}

	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 1 << 20
	c.streamFlow = map[uint16]*streamFlowState{9: {window: 1 << 20}}

	start := time.Now()
	var sends []float64
	done := make(chan struct{})

	c.flowSendForTest = func(streamID uint16, delta uint32) bool {
		select {
		case <-done:
		default:
			sends = append(sends, time.Since(start).Seconds())
		}
		return true
	}

	c.startCreditSender()
	defer c.stopCreditSender()

	// Насыщаем поток так, чтобы порог creditFlushFloor (32 KiB) был перекрыт
	// к каждому тику: тогда решение «слать» принимается всегда и остаётся
	// только момент пробуждения — то есть ровно фаза тикера.
	feed := time.NewTicker(1 * time.Millisecond)
	defer feed.Stop()
	deadline := time.After(1200 * time.Millisecond)
loop:
	for {
		select {
		case <-feed.C:
			c.OnStreamConsumed(9, 64*1024)
		case <-deadline:
			break loop
		}
	}
	close(done)

	if len(sends) < 20 {
		t.Fatalf("отправок всего %d — механизм не слал, замер фазы невозможен", len(sends))
	}

	const tick = 0.008
	r := vectorStrengthPhase(sends, tick)
	noise := 1 / math.Sqrt(float64(len(sends)))
	t.Logf("отправок n=%d, R@%.3fs=%.4f, шум=%.4f", len(sends), tick, r, noise)

	// Интервалы: при насыщении гейт «не чаще раза в тик» даёт константу.
	var minD, maxD = math.MaxFloat64, 0.0
	for i := 1; i < len(sends); i++ {
		d := sends[i] - sends[i-1]
		minD = math.Min(minD, d)
		maxD = math.Max(maxD, d)
	}
	t.Logf("интервалы между отправками: min=%.4fs max=%.4fs (тик %.3fs)", minD, maxD, tick)

	// Сторож: если решётка исчезла, значит цикл переписан — обновить
	// CLAUDE.md hard rule 9 и этот тест. Порог 0.2 — тот же критерий фазы.
	if r < 0.2 {
		t.Fatalf("решётка тикера ИСЧЕЗЛА (R=%.4f < 0.2 при n=%d). Если цикл "+
			"переведён на Timer с джиттером — обновить hard rule 9 в CLAUDE.md "+
			"и этот сторож", r, len(sends))
	}
}

// Джиттер thresholdRatio к фазе отправки отношения не имеет: параметр в
// creditSenderTick сохранён для совместимости подписи и порог не гейтит
// (см. комментарий в stream_flow.go:166 `_ = thresholdRatio`). Тест
// фиксирует это, чтобы «джиттер 40-60%» в докстринге startCreditSender не
// читался как защита фазы.
func TestCreditSender_ThresholdRatioDoesNotGateSend(t *testing.T) {
	for _, ratio := range []float64{0.0, 0.4, 0.6, 1.0, 100.0} {
		c := &Client{}
		c.flowControlEnabled = true
		c.flowWindow = 1 << 20
		c.streamFlow = map[uint16]*streamFlowState{3: {window: 1 << 20}}
		c.streamFlow[3].pendingDelta.Store(creditFlushFloor) // ровно порог

		sent := false
		c.flowSendForTest = func(uint16, uint32) bool { sent = true; return true }
		c.creditSenderTick(ratio)

		if !sent {
			t.Fatalf("ratio=%v: не отправлено, хотя pendingDelta == creditFlushFloor; "+
				"значит thresholdRatio ГЕЙТИТ отправку, и докстринг про "+
				"«jittered 40-60%% threshold» описывает живой механизм", ratio)
		}
	}
}

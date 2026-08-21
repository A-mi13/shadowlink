package client

import (
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Фаза отправок credit-sender'а: WINDOW_UPDATE — это РЕАЛЬНЫЕ байты на wire
// (uplink-фрейм к origin), поэтому период их отправки виден цензору.
//
// История дефекта и его лечения:
//  1. расписание задавал time.NewTicker(8ms). Джиттер в цикле был, но приложен
//     к ПОРОГУ (thresholdRatio 0.4-0.6), а не к периоду пробуждения — тот же
//     дефект, что ловили на rotationWatchdogTick: «джиттер к порогу не
//     размазывает фазу, она квантуется тиком проверки» (CLAUDE.md hard rule 9);
//  2. свойство кода замерено 2026-08-18: R@8мс ≈ 0.95-0.99 внутри процесса;
//  3. НАБЛЮДАЕМОСТЬ подтверждена на проводе 2026-08-19 (pcap, pktmon, 1.6 млн
//     кадров): uplink payload 71 Б → R@8мс = 0.9445 при n=21 991, при том что
//     соседние размеры (75/65/99 Б) чисты. 71 Б = 6 Б WINDOW_UPDATE + AES-GCM +
//     WS-фрейм + TCP/IP;
//  4. исправлено: time.Timer с перевзводом на nextCreditSenderWakeup()
//     (tick + uniform[0, tick)), константа 8 мс НЕ менялась (hard rule 8).
//
// Тесты ниже разделены по смыслу: ..._JitteredWakeupBreaksGrid отвечает за
// ФАЗУ (R + слепой скан + отсутствие credit-stall), ..._WakeupIsNotAFixedTicker
// — за ИСТОЧНИК (интервалы различаются, в коде нет NewTicker).
//
// ⚠ Прежние тесты creditSender этого поймать не могли: они зовут
// creditSenderTick напрямую, минуя таймер, то есть проверяют решение «слать
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

// TestCreditSender_WakeupIsNotAFixedTicker — сторож на ИСТОЧНИК джиттера.
//
// История: этот тест раньше назывался ..._SendPhaseIsQuantizedByTicker и
// фиксировал ДЕФЕКТ — решётку 8 мс, которую тогда ещё не лечили (константу не
// правили по hard rule 8, пока не было доказательства наблюдаемости). После
// замера на проводе 2026-08-19 (payload 71 Б → R@8мс = 0.9445, соседние размеры
// чисты) дефект подтвердился как наблюдаемый и был исправлен: цикл переведён на
// time.Timer с перевзводом на nextCreditSenderWakeup().
//
// Теперь тест сторожит обратное свойство — что период НЕ постоянен. Проверка
// идёт по интервалам, а не по R: разделение с
// TestCreditSender_JitteredWakeupBreaksGrid намеренное — тот отвечает за фазу,
// этот за источник (интервалы обязаны РАЗЛИЧАТЬСЯ, у тикера они равны).
func TestCreditSender_WakeupIsNotAFixedTicker(t *testing.T) {
	if testing.Short() {
		t.Skip("замер фазы требует ~1.5 с реального времени")
	}

	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 1 << 20
	c.streamFlow = map[uint16]*streamFlowState{9: {window: 1 << 20}}

	start := time.Now()

	// Мьютекс обязателен: flowSendForTest зовётся из горутины credit-sender'а
	// (sendWindowUpdate ← creditSenderTick ← горутина startCreditSender), а
	// слайс читается телом теста. Без него это гонка данных, и замер
	// невалиден независимо от того, что цифра выглядит правдоподобно. На
	// Windows -race недоступен (нет gcc), поэтому такую гонку локальный
	// зелёный прогон НЕ покажет — hard rule 6.
	var mu sync.Mutex
	var sends []float64

	c.flowSendForTest = func(streamID uint16, delta uint32) bool {
		elapsed := time.Since(start).Seconds()
		mu.Lock()
		sends = append(sends, elapsed)
		mu.Unlock()
		return true
	}

	c.startCreditSender()

	// Насыщаем поток так, чтобы порог creditFlushFloor (32 KiB) был перекрыт
	// к каждому тику: тогда решение «слать» принимается всегда и остаётся
	// только момент пробуждения — то есть ровно фаза тикера.
	//
	// ⚠ Насыщение здесь ИСКУССТВЕННОЕ (64 KiB/мс ≈ 64 МБ/с), и возражение
	// «R = 0.99 — артефакт насыщения» напрашивается само. Оно проверено и
	// НЕ подтвердилось: замер 2026-08-18 на четырёх скоростях (подача 3 с,
	// подвыборка TestCreditRealRates, в дерево не коммичена) дал
	//
	//   0.22 МБ/с (средний в поле) — n=18,  R = 0.9771, интервалы 152-207 мс
	//   1 МБ/с    (p95 интервалов) — n=75,  R = 0.9892, интервалы 32-57 мс
	//   4 МБ/с    (порог за тик)   — n=195, R = 0.9714, интервалы 7-17 мс
	//   20 МБ/с   (пик)            — n=374, R = 0.9574, интервалы 6.5-9.4 мс
	//
	// То есть throughput меняет ЧАСТОТУ отправок, но не их ФАЗУ: каждая
	// отправка всё равно происходит на пробуждении тикера, поэтому лежит на
	// сетке 8 мс при любой скорости. Решётка сохраняется, редеет только
	// плотность её заполнения.
	//
	// Чего этот тест всё равно НЕ доказывает: что решётка наблюдаема
	// цензором. Измеряются моменты вызова колбэка внутри процесса, а не
	// уход пакета в сеть, — между ними ещё шифрование, WS-фрейминг, TCP и
	// возможная коалесценция. Для наблюдаемости нужен pcap
	// (tools/firstpackets -phase).
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

	// Останов ДО чтения слайса, а не через defer: иначе последний тик мог бы
	// дописать в sends во время подсчёта.
	//
	// stopCreditSender только закрывает канал и НЕ дожидается выхода
	// горутины (stream_flow.go:124) — та может быть в середине тика и
	// дописать ещё одну отметку после возврата. Поэтому читаем копию под
	// мьютексом, а не полагаемся на «после stop писателя нет».
	c.stopCreditSender()

	mu.Lock()
	sends = append([]float64(nil), sends...)
	mu.Unlock()

	if len(sends) < 20 {
		t.Fatalf("отправок всего %d — механизм не слал, замер фазы невозможен", len(sends))
	}

	const tick = 0.008

	// Интервалы между отправками при насыщении. У time.NewTicker они равны
	// периоду с точностью до дрожания планировщика; у jittered-таймера
	// размазаны по [tick, 2*tick).
	var minD, maxD, sumD = math.MaxFloat64, 0.0, 0.0
	for i := 1; i < len(sends); i++ {
		d := sends[i] - sends[i-1]
		minD = math.Min(minD, d)
		maxD = math.Max(maxD, d)
		sumD += d
	}
	meanD := sumD / float64(len(sends)-1)
	spread := maxD - minD
	t.Logf("отправок n=%d, интервалы min=%.4fs mean=%.4fs max=%.4fs, разброс=%.4fs",
		len(sends), minD, meanD, maxD, spread)

	// Разброс обязан быть сопоставим с величиной джиттера (до tick). Порог
	// половина тика: дрожание планировщика на тикере давало разброс ~2 мс
	// (замер: 6.5-9.1 мс), джиттер даёт ~8 мс (8.6-16.5 мс).
	if spread < tick/2 {
		t.Errorf("разброс интервалов %.4f с меньше половины тика — период похож "+
			"на ПОСТОЯННЫЙ. Проверить, не вернулся ли time.NewTicker вместо "+
			"nextCreditSenderWakeup()", spread)
	}

	// Средний интервал обязан превышать сам тик: у постоянного тикера он равен
	// периоду, у джиттерованного — примерно 1.5x.
	if meanD < tick*1.15 {
		t.Errorf("средний интервал %.4f с ≈ тик %.3f с — джиттер не применяется",
			meanD, tick)
	}

	// И проверка на источник в исходнике: поведенческие проверки выше остаются
	// зелёными, даже если цикл перестанет звать nextCreditSenderWakeup, а
	// джиттер приедет откуда-то ещё. Тот же приём, что у
	// TestRotationWatchdogLoop_UsesJitteredTimerNotTicker.
	src, err := os.ReadFile("stream_flow.go")
	if err != nil {
		t.Fatalf("чтение stream_flow.go: %v", err)
	}
	body := string(src)
	if strings.Contains(body, "time.NewTicker(creditSenderInterval)") {
		t.Error("в stream_flow.go вернулся time.NewTicker(creditSenderInterval) — " +
			"постоянный период даёт решётку на wire (замерено на проводе)")
	}
	if !strings.Contains(body, "nextCreditSenderWakeup()") {
		t.Error("startCreditSender больше не зовёт nextCreditSenderWakeup()")
	}
}

// TestCreditSender_JitteredWakeupBreaksGrid — сторож на ЛЕЧЕНИЕ фазы.
//
// Решётка 125 Гц была подтверждена на проводе (замер 2026-08-19, pcap: payload
// 71 Б → R@8мс = 0.9445 при n=21 991, соседние размеры чисты). Лечение — то же,
// что применялось к rotationWatchdogTick: Timer с перевзводом на
// tick + uniform[0, tick), джиттер сэмплируется ЗАНОВО каждый взвод.
//
// Тест требует ОБА свойства сразу, потому что починить фазу и незаметно вернуть
// credit-stall — реальный риск: 8 мс выбраны как cheap tick, а из-за задержки
// возврата credits сервер уже вставал в waitForCredit, слот простаивал и его
// жали с close 1006 (см. комментарий creditSenderTick).
func TestCreditSender_JitteredWakeupBreaksGrid(t *testing.T) {
	if testing.Short() {
		t.Skip("замер фазы требует ~1.5 с реального времени")
	}

	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 1 << 20
	c.streamFlow = map[uint16]*streamFlowState{9: {window: 1 << 20}}

	start := time.Now()
	var mu sync.Mutex
	var sends []float64

	c.flowSendForTest = func(streamID uint16, delta uint32) bool {
		elapsed := time.Since(start).Seconds()
		mu.Lock()
		sends = append(sends, elapsed)
		mu.Unlock()
		return true
	}

	c.startCreditSender()

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
	c.stopCreditSender()

	mu.Lock()
	sends = append([]float64(nil), sends...)
	mu.Unlock()

	if len(sends) < 20 {
		t.Fatalf("отправок всего %d — механизм не слал, замер невозможен", len(sends))
	}

	const tick = 0.008
	r := vectorStrengthPhase(sends, tick)
	noise := 1 / math.Sqrt(float64(len(sends)))
	t.Logf("n=%d R@%.3fs=%.4f шум=%.4f", len(sends), tick, r, noise)

	// Свойство 1: решётки нет. Критерий тот же, что для фазы ротации.
	if r >= 0.2 {
		t.Errorf("решётка на периоде тика жива: R = %.4f >= 0.2 (n=%d). "+
			"Джиттер должен быть на ПЕРИОДЕ пробуждения, а не на пороге", r, len(sends))
	}

	// Свойство 2: слепой скан — линия не переехала на другой масштаб. Именно так
	// провалилась первая попытка лечения watchdog: срезка тика убила линию на
	// 0.2 Гц и подняла пик на 2 Гц.
	bestR, bestP := 0.0, 0.0
	for p := 0.002; p <= 0.100; p += 0.0005 {
		if rr := vectorStrengthPhase(sends, p); rr > bestR {
			bestR, bestP = rr, p
		}
	}
	t.Logf("слепой скан 2-100 мс: max R=%.4f @ %.4f с", bestR, bestP)
	if bestR >= 0.35 {
		t.Errorf("линия переехала на другой период: max R = %.4f @ %.4f с", bestR, bestP)
	}

	// Свойство 3: credits не задержаны. Интервал между отправками при насыщении
	// не должен превышать 2×tick — это верхняя граница jittered-взвода. Если
	// сюда попадёт watchdog (200 мс), значит поток встал.
	var maxGap float64
	for i := 1; i < len(sends); i++ {
		if g := sends[i] - sends[i-1]; g > maxGap {
			maxGap = g
		}
	}
	t.Logf("максимальный интервал между отправками: %.4f с", maxGap)
	if maxGap > 0.050 {
		t.Errorf("credits задержаны: максимальный интервал %.4f с при tick %.3f с — "+
			"проверить, не вернулся ли credit-stall", maxGap, tick)
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

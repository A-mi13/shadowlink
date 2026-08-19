package main

// Режим -phase: замер периодичности НА ПРОВОДЕ по SYN/FIN, а не по метками лога.
//
// Зачем отдельно от анализа логов. Все замеры фазы в этом проекте (прогоны
// 2026-08-13/14/18) считали vector strength по временам, которые печатает
// slog. Такой замер не видит остаточную линию тоньше ~10 мс и, главное, мерит
// момент, когда СТРОКА попала в лог, а не когда пакет ушёл в сеть. Цензор
// смотрит на второе. pktmon даёт таймстампы ядра, поэтому этот режим отвечает
// на тот же вопрос без посредника.
//
// Что именно считается:
//   - SYN к origin  — момент открытия соединения (аналог `reader started`);
//   - FIN/RST       — момент закрытия (аналог close);
//   - inter-arrival — интервалы между SYN, для поиска шаблона по ИНТЕРВАЛУ,
//     который фазовым критерием не снимается (см. CLAUDE.md hard rule 9:
//     «медиана close − start = 0.500 с ровно — это шаблон, а не периодичность»).
//
// Критерий — R < 0.2 на периоде тика (hard rule 9). Доля событий в модальном
// окне сетки НЕ используется намеренно: она падает автоматически при любом
// тике меньше секунды, то есть измеряет нашу ручку, а не наблюдаемость.

import (
	"fmt"
	"math"
	"sort"
)

// vectorStrength возвращает длину среднего вектора фаз (Rayleigh R) для
// моментов ts, свёрнутых по периоду period.
//
// R = 1 — все события в одной фазе (идеальная решётка); R ~ 1/sqrt(n) —
// равномерная фаза. Ожидаемый шум обязан считаться от n и сравниваться с
// результатом: R = 0.05 при n = 100 (шум 0.1) линией НЕ является.
//
// n < 2 возвращает 0, а не 1: на одном событии фаза определена, но вывода о
// периодичности из неё не следует, и R = 1 на n = 1 читался бы как решётка.
func vectorStrength(ts []float64, period float64) float64 {
	if len(ts) < 2 || period <= 0 {
		return 0
	}
	var sumCos, sumSin float64
	for _, t := range ts {
		// math.Mod, а не t/period - int(t/period): при больших t (uptime в
		// секундах от начала захвата) целая часть теряет точность float64.
		frac := math.Mod(t, period) / period
		ph := 2 * math.Pi * frac
		sumCos += math.Cos(ph)
		sumSin += math.Sin(ph)
	}
	n := float64(len(ts))
	return math.Hypot(sumCos, sumSin) / n
}

// scanResult — максимум слепого скана.
type scanResult struct {
	Period float64
	R      float64
	N      int
}

// scanPeriods ищет максимум R по сетке периодов [from, to] с шагом step.
//
// Слепой скан нужен потому, что правка одного тика в этом проекте уже дважды
// переносила линию на другой масштаб, а не убирала её: срезка watchdog-тика
// 5 с → 500 мс убила линию на 0.2 Гц и подняла пик на 2 Гц. Проверять только
// ожидаемый период значит не увидеть переезд.
//
// ⚠ Возвращённый Period — НЕ обязательно истинный период решётки, а лишь
// первый её делитель в диапазоне: события, лежащие на сетке 500 мс, лежат
// также на сетках 250, 125, 100 и 50 мс, и R там строго 1.0 (проверено
// TestScanPeriods_FindsTrueGrid). Читать результат как «линия есть, истинный
// период кратен найденному», а не как измерение периода. Обратное неверно —
// на периоде БОЛЬШЕ истинного линия исчезает, что и отделяет делители от
// произвольных периодов.
func scanPeriods(ts []float64, from, to, step float64) scanResult {
	best := scanResult{N: len(ts)}
	if len(ts) < 2 || step <= 0 || from <= 0 || to < from {
		return best
	}
	for p := from; p <= to; p += step {
		if r := vectorStrength(ts, p); r > best.R {
			best.R = r
			best.Period = p
		}
	}
	return best
}

// phaseSeries — один набор событий одного смысла.
type phaseSeries struct {
	name string
	ts   []float64 // секунды от начала захвата, возрастают
}

// smallUplinkMaxPayload — верхняя граница «мелкого» uplink-пакета.
//
// Управляющие кадры (WINDOW_UPDATE, StreamAck) на проводе занимают десятки
// байт: 6 Б payload NewWindowUpdateChunk (core/chunk.go:305) плюс AES-GCM,
// WS-фрейм и TCP/IP дают ~71 Б. 120 — запас, чтобы поймать и соседние
// управляющие формы, но отсечь данные (MTU-размерные пакеты).
//
// Зачем отдельная серия: замер 2026-08-19 показал, что линия 125 Гц
// присутствует ровно у ОДНОГО размера (71 Б, R = 0.944), а на смеси всех
// мелких пакетов размывается до 0.311. Разбивка по размеру — это то, что
// отличает «линия у класса пакетов» от «шум в трафике».
const smallUplinkMaxPayload = 120

// collectPhaseSeries раскладывает пакеты на серии SYN и FIN/RST к origin.
//
// Направление важно: SYN от нас к origin — это НАШЕ открытие соединения, а
// SYN-ACK обратно им не является. Фильтр по dst, а не по флагу вообще.
func collectPhaseSeries(packets []packet, origin [4]byte) []phaseSeries {
	var synTS, finTS, allTS []float64

	// haveT0 — отдельный флаг, а НЕ `t0 == 0` как sentinel. При sentinel'е
	// пакет с tsMicros == 0 сбрасывал минимум, следующий пакет безусловно
	// перезаписывал его своим значением, и `ts - t0` на uint64 уходил в
	// underflow: вместо секунд получалось ~1.8e13, причём молча — vectorStrength
	// честно считал по мусору. Найдено ревью 2026-08-18, сторож —
	// TestWirePhase_ZeroTimestampDoesNotUnderflow.
	var t0 uint64
	var haveT0 bool
	for _, p := range packets {
		if !haveT0 || p.tsMicros < t0 {
			t0 = p.tsMicros
			haveT0 = true
		}
	}
	toSec := func(ts uint64) float64 {
		// t0 — минимум по всем пакетам, поэтому ts >= t0 всегда; проверка
		// оставлена как страховка от будущей правки выбора t0 (например
		// «минимум только по пакетам к origin»), которая это сломает молча.
		if ts < t0 {
			return 0
		}
		return float64(ts-t0) / 1e6
	}

	for _, p := range packets {
		if p.dstIP != origin {
			continue
		}
		// Флаги проверяются НЕЗАВИСИМО, а не через switch: пакет с SYN+FIN
		// (или SYN+RST) при switch попал бы только в серию открытий, и момент
		// закрытия потерялся бы молча. В нормальном трафике такой пакет не
		// встречается, но серия закрытий — это ровно то, где ищут рез
		// посредника, и терять там события нельзя.
		ts := toSec(p.tsMicros)
		counted := false
		if p.syn {
			synTS = append(synTS, ts)
			counted = true
		}
		if p.fin || p.rst {
			finTS = append(finTS, ts)
			counted = true
		}
		if counted {
			allTS = append(allTS, ts)
		}
	}
	sort.Float64s(synTS)
	sort.Float64s(finTS)
	sort.Float64s(allTS)
	return []phaseSeries{
		{name: "SYN к origin (открытие)", ts: synTS},
		{name: "FIN/RST к origin (закрытие)", ts: finTS},
		{name: "SYN+FIN вместе", ts: allTS},
	}
}

// collectUplinkBySize группирует моменты отправки МЕЛКИХ uplink-пакетов к
// origin по размеру payload.
//
// Отдельно от SYN/FIN, потому что решётка credit-sender'а (8 мс) живёт не в
// открытиях соединений, а в потоке управляющих кадров, и проявляется только
// при разбивке по размеру: на смеси она размывается.
func collectUplinkBySize(packets []packet, origin [4]byte) (bySize map[int][]float64, all []float64) {
	var t0 uint64
	var haveT0 bool
	for _, p := range packets {
		if !haveT0 || p.tsMicros < t0 {
			t0 = p.tsMicros
			haveT0 = true
		}
	}

	bySize = make(map[int][]float64)
	for _, p := range packets {
		if p.dstIP != origin {
			continue
		}
		if p.payload <= 0 || p.payload > smallUplinkMaxPayload {
			continue
		}
		ts := 0.0
		if p.tsMicros >= t0 {
			ts = float64(p.tsMicros-t0) / 1e6
		}
		bySize[p.payload] = append(bySize[p.payload], ts)
		all = append(all, ts)
	}
	for k := range bySize {
		sort.Float64s(bySize[k])
	}
	sort.Float64s(all)
	return bySize, all
}

// reportPhase печатает замер по всем сериям.
//
// tick — период, на котором критерий R < 0.2 обязателен (в проде 0.5 с:
// rotationWatchdogTick). Остальные периоды проверяет слепой скан.
func reportPhase(packets []packet, origin [4]byte, tick float64) {
	series := collectPhaseSeries(packets, origin)

	fmt.Printf("Замер фазы НА ПРОВОДЕ (pktmon), origin %d.%d.%d.%d\n",
		origin[0], origin[1], origin[2], origin[3])
	fmt.Printf("Критерий: R < 0.2 на периоде тика %.3f с (CLAUDE.md hard rule 9).\n", tick)
	fmt.Println("Шум = 1/sqrt(n): R того же порядка линией НЕ является.")
	fmt.Println()

	anyData := false
	for _, s := range series {
		n := len(s.ts)
		if n < 2 {
			fmt.Printf("%-30s n=%-6d — недостаточно событий для вывода\n", s.name, n)
			continue
		}
		anyData = true
		r := vectorStrength(s.ts, tick)
		noise := 1 / math.Sqrt(float64(n))
		verdict := "линии нет"
		switch {
		case r >= 0.2:
			verdict = "ЛИНИЯ ЕСТЬ (критерий нарушен)"
		case r > 3*noise:
			verdict = "выше 3x шума — смотреть"
		}
		fmt.Printf("%-30s n=%-6d R@%.3fs=%.4f  шум=%.4f  %s\n",
			s.name, n, tick, r, noise, verdict)

		best := scanPeriods(s.ts, 0.05, 6.0, 0.005)
		bverdict := "линий нет во всём диапазоне"
		if best.R >= 0.2 {
			bverdict = "ЛИНИЯ (проверить этот период)"
		}
		fmt.Printf("%-30s   слепой скан 0.05-6.0s: max R=%.4f @ %.3fs — %s\n",
			"", best.R, best.Period, bverdict)

		// Интервалы: шаблон по интервалу фазовым критерием не снимается,
		// поэтому печатается отдельно как факт, а не как вердикт.
		//
		// Разница существенна и наблюдалась на этом же инструменте: серия с
		// постоянным интервалом даёт «линии нет» на периоде тика и при этом
		// высокий R в слепом скане на своём интервале. Абсолютная фаза
		// размазана, но расстояние между событиями — константа, а цензору
		// достаточно второго (CLAUDE.md hard rule 9: «медиана close − start
		// = 0.500 с ровно — это шаблон, а не периодичность»).
		if n >= 3 {
			d := make([]float64, 0, n-1)
			for i := 1; i < n; i++ {
				d = append(d, s.ts[i]-s.ts[i-1])
			}
			sort.Float64s(d)
			p50 := d[len(d)/2]
			fmt.Printf("%-30s   интервалы: p50=%.3fs p90=%.3fs min=%.3fs max=%.3fs\n",
				"", p50, d[int(float64(len(d))*0.9)], d[0], d[len(d)-1])

			// Насколько интервал постоянен. CV считается на самих интервалах:
			// низкий CV при размазанной абсолютной фазе — это шаблон, который
			// критерий R на тике пропускает по построению.
			var mean float64
			for _, v := range d {
				mean += v
			}
			mean /= float64(len(d))
			if mean > 0 {
				var ss float64
				for _, v := range d {
					ss += (v - mean) * (v - mean)
				}
				cv := math.Sqrt(ss/float64(len(d))) / mean
				note := ""
				if cv < 0.1 && r < 0.2 {
					note = "  ← интервал почти постоянен при размазанной фазе: ШАБЛОН, критерий R его не видит"
				}
				fmt.Printf("%-30s   интервал CV=%.3f%s\n", "", cv, note)
			}
		}
		fmt.Println()
	}

	if !anyData {
		fmt.Println("Событий SYN/FIN к origin в захвате нет.")
		fmt.Println("Проверьте: -origin совпадает с IP из лога? Захват шёл при работающем клиенте?")
		fmt.Println("⚠ Если файл большой и pktmon отчитался о миллионах пакетов, а здесь n=0 —")
		fmt.Println("  это НЕ пустой захват, а нераспознанный формат кадра (см. dot11.go).")
	}

	reportUplinkGrid(packets, origin, tick)
}

// reportUplinkGrid печатает замер решётки у мелких uplink-пакетов с разбивкой
// по размеру payload.
//
// Порог значимости — R >= 0.2 (тот же критерий) И n >= 200: на малых выборках
// высокий R получается случайно, а вывод о решётке по десяткам событий уже
// приводил в этом проекте к ложным заключениям.
func reportUplinkGrid(packets []packet, origin [4]byte, tick float64) {
	bySize, all := collectUplinkBySize(packets, origin)
	if len(all) < 2 {
		return
	}

	fmt.Println("--- Мелкие uplink-пакеты к origin (управляющие кадры) ---")
	fmt.Printf("Здесь ищется решётка credit-sender (8 мс) и ack-гейта (50 мс):\n")
	fmt.Printf("это РЕАЛЬНЫЕ байты, а не открытия соединений.\n\n")

	for _, t := range []float64{0.008, 0.05, tick} {
		r := vectorStrength(all, t)
		fmt.Printf("%-30s n=%-6d R@%.3fs=%.4f  шум=%.4f\n",
			"все размеры вместе", len(all), t, r, 1/math.Sqrt(float64(len(all))))
	}

	// Разбивка: решётка обычно принадлежит ОДНОМУ классу пакетов, и на смеси
	// она размывается. Сортируем по частоте, чтобы редкие размеры не шумели.
	type sizeRow struct {
		size int
		n    int
		r8   float64
	}
	var rows []sizeRow
	for size, ts := range bySize {
		if len(ts) < 200 {
			continue
		}
		rows = append(rows, sizeRow{size, len(ts), vectorStrength(ts, 0.008)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })

	if len(rows) == 0 {
		fmt.Println("\n(размеров с n >= 200 нет — выборка мала для разбивки)")
		return
	}
	fmt.Println("\nпо размеру payload (только n >= 200):")
	for _, row := range rows {
		noise := 1 / math.Sqrt(float64(row.n))
		mark := ""
		if row.r8 >= 0.2 {
			mark = "  ← ЛИНИЯ 125 Гц"
		}
		fmt.Printf("  payload=%-4d n=%-6d R@8мс=%.4f  шум=%.4f%s\n",
			row.size, row.n, row.r8, noise, mark)
	}
}

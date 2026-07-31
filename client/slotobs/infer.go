package slotobs

import (
	"fmt"
	"slices"
	"time"
)

// Инференс порога ротации из наблюдений (P0 шаг 2, 2026-07-31).
//
// Шаг 1 (Recorder/Summarize) только описывает данные. Здесь делается вывод:
// какая ось является триггером и какой порог из неё следует. Разделение
// сохранено намеренно — описание данных проверяемо само по себе, а вывод несёт
// допущения, и их надо держать на виду.
//
// Главное свойство: функция обязана уметь ответить «не знаю». Полевой замер
// 2026-07-31 показал, почему это не формальность — в выборку попали три смерти
// с AgeMs=0 (моментальный io_timeout при подключении, не рез посредника). Они
// подняли CV возраста с 0.18 до 0.4546 и почти замаскировали разницу между
// осями. Инференс, который «всегда что-то возвращает», выдал бы на этих данных
// уверенный, но неверный порог.

// Verdict — что удалось вывести из выборки.
type Verdict struct {
	// Axis — ось, по которой режет цензор. AxisUnknown, если данных мало или
	// разделение между осями недостаточно выражено.
	Axis Axis

	// Threshold — рекомендуемый порог ротации ПО ВЫБРАННОЙ ОСИ: возраст, если
	// Axis == AxisAge, иначе байты. Ноль при AxisUnknown.
	//
	// Это НЕ наблюдённый порог смерти, а безопасная точка ротации: p10 смертей
	// минус запас. Ротировать надо раньше самой ранней смерти, а не по медиане.
	Threshold Threshold

	// Samples — сколько наблюдений участвовало в выводе ПОСЛЕ отсева шума.
	Samples int

	// Rejected — сколько наблюдений отброшено как шум и почему.
	Rejected RejectionStats

	// Reason — человекочитаемое объяснение, почему получился такой вердикт.
	// Обязательно и при AxisUnknown: контур, про который нельзя сказать,
	// работает ли он, — это болезнь H-15, повторять её нельзя.
	Reason string
}

// Axis — ось, по которой цензор принимает решение о разрыве.
type Axis int

const (
	// AxisUnknown — вывод не сделан. Вызывающий ОБЯЗАН сохранить текущее
	// поведение, а не подставлять ноль или «какое-нибудь» значение.
	AxisUnknown Axis = iota
	// AxisAge — рез по возрасту соединения.
	AxisAge
	// AxisBytes — рез по объёму переданных вниз данных.
	AxisBytes
)

func (a Axis) String() string {
	switch a {
	case AxisAge:
		return "age"
	case AxisBytes:
		return "down_bytes"
	default:
		return "unknown"
	}
}

// Threshold — выведенный порог. Заполнено только одно поле, по Axis.
type Threshold struct {
	Age   time.Duration
	Bytes int64
}

// RejectionStats — учёт отсеянного шума. Публикуется, чтобы было видно, на чём
// основан вывод: молчаливый отсев так же опасен, как его отсутствие.
type RejectionStats struct {
	// ZeroAge — наблюдения с нулевым возрастом. Слот, умерший в момент
	// подключения, не может быть жертвой age-cut: это отказ сети/сервера.
	ZeroAge int
	// LocalClose — наши собственные Close(), не действия посредника.
	LocalClose int
	// Timeout — истёк НАШ read deadline. Возможный признак реза, но
	// неотличимый от обычного столла, поэтому в вывод порога не берём.
	Timeout int
}

// Total возвращает общее число отброшенных наблюдений.
func (r RejectionStats) Total() int { return r.ZeroAge + r.LocalClose + r.Timeout }

// Параметры инференса. Значения намеренно консервативны: цена ложного
// «уверен» — ротация не в том месте, цена «не знаю» — сохранение текущего
// поведения, что заведомо не хуже.
const (
	// MinSamplesForInference — ниже этого выборка не даёт устойчивых
	// перцентилей. 12 — тот же порог, что у логирования сводки.
	MinSamplesForInference = 12

	// axisSeparationFactor — во сколько раз CV одной оси должен быть НИЖЕ
	// другой, чтобы признать её триггером. 2.0 подобрано с запасом: на полевых
	// данных фактическое отношение было 12x при чистой выборке и 5x при
	// зашумлённой, то есть 2.0 отсекает шум, но не отбрасывает реальный сигнал.
	axisSeparationFactor = 2.0

	// thresholdSafetyFraction — какую долю от p10 наблюдённых смертей брать
	// как порог ротации. 0.8 даёт 20% запаса на дисперсию сети и на то, что
	// p10 по конечной выборке смещён вверх относительно истинного минимума.
	thresholdSafetyFraction = 0.8

	// maxCVForConfidence — если даже у «тихой» оси CV выше этого, порога как
	// такового нет: смерти разбросаны, и подгонять под них бессмысленно.
	maxCVForConfidence = 1.0
)

// Infer выводит ось и порог из наблюдений рекордера.
//
// Никогда не паникует и никогда не возвращает порог, в который сам не уверен:
// при недостатке данных или слабом разделении осей возвращается AxisUnknown с
// заполненным Reason.
func (r *Recorder) Infer() Verdict {
	obs := r.Snapshot()

	clean, rej := filterNoise(obs)
	v := Verdict{Samples: len(clean), Rejected: rej}

	if len(clean) < MinSamplesForInference {
		v.Reason = "недостаточно наблюдений после отсева шума: " +
			fmt.Sprint(len(clean)) + " из " + fmt.Sprint(len(obs)) +
			", нужно " + fmt.Sprint(MinSamplesForInference)
		return v
	}

	ages := make([]int64, 0, len(clean))
	bytesv := make([]int64, 0, len(clean))
	for _, o := range clean {
		ages = append(ages, o.AgeMs)
		bytesv = append(bytesv, o.DownBytes)
	}
	ageCV, bytesCV := cvInt64(ages), cvInt64(bytesv)

	// Ось с МЕНЬШИМ разбросом и есть та, по которой стоит жёсткий порог:
	// цензор режет по своей оси в узком коридоре, а по чужой значения
	// расползаются, потому что ни на что не влияют.
	switch {
	case ageCV > 0 && ageCV*axisSeparationFactor < bytesCV:
		v.Axis = AxisAge
	case bytesCV > 0 && bytesCV*axisSeparationFactor < ageCV:
		v.Axis = AxisBytes
	default:
		v.Reason = "оси не разделяются: CV возраста " + fmt.Sprintf("%.3f", ageCV) +
			" против CV байтов " + fmt.Sprintf("%.3f", bytesCV) +
			" (нужна разница в " + fmt.Sprintf("%.1f", axisSeparationFactor) + "x)"
		return v
	}

	chosen, chosenCV := ages, ageCV
	if v.Axis == AxisBytes {
		chosen, chosenCV = bytesv, bytesCV
	}
	if chosenCV > maxCVForConfidence {
		v.Axis = AxisUnknown
		v.Reason = "у выбранной оси слишком большой разброс (CV " + fmt.Sprintf("%.3f", chosenCV) +
			" > " + fmt.Sprintf("%.1f", maxCVForConfidence) + ") — устойчивого порога нет"
		return v
	}

	slices.Sort(chosen)
	p10 := percentileInt64(chosen, 10)
	safe := int64(float64(p10) * thresholdSafetyFraction)

	if v.Axis == AxisAge {
		v.Threshold.Age = time.Duration(safe) * time.Millisecond
		v.Reason = "рез по возрасту (CV " + fmt.Sprintf("%.3f", ageCV) + " против " + fmt.Sprintf("%.3f", bytesCV) +
			" по байтам); p10 смертей " + fmt.Sprint(p10) + "ms, порог = " +
			fmt.Sprintf("%.0f%%", thresholdSafetyFraction*100) + " от p10"
	} else {
		v.Threshold.Bytes = safe
		v.Reason = "рез по объёму (CV " + fmt.Sprintf("%.3f", bytesCV) + " против " + fmt.Sprintf("%.3f", ageCV) +
			" по возрасту); p10 смертей " + fmt.Sprint(p10) + "B, порог = " +
			fmt.Sprintf("%.0f%%", thresholdSafetyFraction*100) + " от p10"
	}
	return v
}

// filterNoise убирает наблюдения, которые не являются резом посредника.
//
// Это не косметика: полевой замер 2026-07-31 показал, что три наблюдения с
// AgeMs=0 поднимают CV возраста с 0.18 до 0.4546 — то есть шум почти скрыл
// разделение осей и мог бы привести к вердикту «оси не разделяются» на данных,
// где разделение фактически 12-кратное.
func filterNoise(obs []Observation) (clean []Observation, rej RejectionStats) {
	for _, o := range obs {
		switch {
		case o.AgeMs <= 0:
			// Смерть в момент подключения — сетевой отказ, не age-cut.
			rej.ZeroAge++
		case o.CloseKind == "closed_local":
			// Наш собственный Close(), поведение посредника тут ни при чём.
			rej.LocalClose++
		case o.CloseKind == "io_timeout":
			// Истёк НАШ read deadline. Может быть резом, а может — обычным
			// столлом; неотличимо, поэтому в вывод порога не берём.
			rej.Timeout++
		default:
			clean = append(clean, o)
		}
	}
	return clean, rej
}

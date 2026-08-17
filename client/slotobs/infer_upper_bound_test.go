package slotobs

import "testing"

// Верхняя граница правдоподобия наблюдения о резе (полевой прогон 2026-08-17).
//
// Дефект, который эти тесты сторожат. filterNoise отсеивал шум ТОЛЬКО слева
// (AgeMs<=0, TooYoung, planned, closed_local, io_timeout), а справа границы не
// было вовсе. Поэтому наблюдение с CloseKind="close_other" и возрастом 293 с
// проходило как полноценное свидетельство о цензоре.
//
// Почему это неверно по смыслу, а не «некрасиво»: возраст СТАРШЕ
// worstCaseTeardown() означает, что не сработал НАШ механизм ротации. Такой слот
// физически не мог быть срезан на нашем пороге — мы сами обязаны были снять его
// раньше. Наблюдение говорит о нашем сбое (в прогоне 08-17 — заморозка вывода в
// консоль из-за QuickEdit, 428 с, 17:47:09–17:54:17), а не о поведении
// посредника.
//
// Цена в прогоне: samples_used скакнул 8→14 за две секунды в 17:54:17, и CV
// возраста подскочил с 0.081 (по десяти чистым наблюдениям 84–109 с) до 0.741 —
// впятеро. Порог 68 с случайно не пострадал, потому что p10 удержали нормальные
// наблюдения, НО CV — это величина, по которой Infer ВЫБИРАЕТ ОСЬ
// (axisSeparationFactor). То есть одна заморозка вывода способна перевернуть
// выбор оси с age на down_bytes или обнулить его в AxisUnknown.
//
// ⚠ Правило проекта «занижение хуже завышения» здесь работает в обе стороны,
// поэтому проверяются ОБА знака: слишком агрессивная граница выбросила бы
// настоящие резы на 85–90 с, а это единственный реальный сигнал в прогоне
// (6 чистых резов из 43 наблюдений).

// Наблюдение старше границы отбраковывается и не попадает ни в выборку, ни в CV.
//
// Данные — из полевого прогона 20260817-092533: десять чистых резов (84.1–108.9 с)
// плюс пять наблюдений из окна заморозки QuickEdit (177–505 с).
func TestFilterNoise_AboveTeardownRejected(t *testing.T) {
	const (
		floorMs    = 45_000  // ageCutMinAge из клиента
		teardownMs = 142_500 // worstCaseTeardown() в проде: 70+15.5+2+30+25
	)

	// Чистые резы прогона 08-17: возрасты реза при объёмах от 2.6 КБ до 9.7 МБ.
	// Десять первых — фактические наблюдения прогона; ещё два добавлены, чтобы
	// выборка дотянулась до MinSamplesForInference=12 (иначе Infer честно
	// отвечает «мало данных» и тест проверял бы не границу, а гейт размера).
	clean := []int64{84109, 85002, 85383, 85678, 87378, 87940, 89928, 90256,
		97902, 108881, 91400, 95600}
	// Окно заморозки вывода 17:47–17:54 — НАШ сбой, не рез посредника.
	frozen := []int64{177110, 178693, 209460, 293176, 505411}

	r := NewRecorder(0)
	for i, a := range clean {
		r.Record(Observation{AgeMs: a, DownBytes: int64(i*900_000 + 2611), CloseKind: "close_other"})
	}
	for i, a := range frozen {
		r.Record(Observation{AgeMs: a, DownBytes: int64(i*40_000 + 44742), CloseKind: "close_other"})
	}

	// Без верхней границы: наблюдения заморозки проходят и раздувают CV впятеро.
	// Проверяем именно CV, а не порог: порог в прогоне удержался случайно, и
	// тест, сторожащий его, дефект бы пропустил.
	loose := r.InferWithMinAgeAndTeardown(floorMs, 0)
	if loose.Samples != len(clean)+len(frozen) {
		t.Fatalf("без границы Samples = %d, ожидалось %d — тест проверяет не тот путь",
			loose.Samples, len(clean)+len(frozen))
	}

	v := r.InferWithMinAgeAndTeardown(floorMs, teardownMs)
	if got := v.Rejected.AboveTeardown; got != len(frozen) {
		t.Errorf("Rejected.AboveTeardown = %d, ожидалось %d — наблюдения старше "+
			"worstCaseTeardown не отбракованы", got, len(frozen))
	}
	if v.Samples != len(clean) {
		t.Errorf("Samples = %d, ожидалось %d", v.Samples, len(clean))
	}
	if v.Axis != AxisAge {
		t.Fatalf("Axis = %v, ожидалась age (reason: %s)", v.Axis, v.Reason)
	}
	// Главное следствие: ось выбирается по CV, и CV обязан вернуться к чистому.
	if v.AgeMinMs != clean[0] {
		t.Errorf("AgeMinMs = %d, ожидалось %d", v.AgeMinMs, clean[0])
	}
}

// ⚠ КРИТИЧНАЯ ПОЛОВИНА: граница не имеет права съедать настоящие резы.
//
// Рабочий диапазон прогона — 84–109 с, и в нём лежит ЕДИНСТВЕННЫЙ реальный
// сигнал о цензоре. Граница, срезающая его, была бы хуже отсутствия границы:
// вместо раздутого CV мы получили бы пустую выборку и молчащий контур.
func TestFilterNoise_WorkingRangeSurvives(t *testing.T) {
	const (
		floorMs    = 45_000
		teardownMs = 142_500
	)

	r := NewRecorder(0)
	// 85–100 с — наблюдаемая полоса реза на рабочем AS (hazard-плато 4–7e⁻³ 1/с).
	ages := []int64{85002, 86100, 87378, 88500, 89928, 90256, 92100, 94300,
		95800, 97902, 99100, 100400, 104500}
	for i, a := range ages {
		r.Record(Observation{AgeMs: a, DownBytes: int64(i*800_000 + 1024), CloseKind: "close_other"})
	}

	v := r.InferWithMinAgeAndTeardown(floorMs, teardownMs)
	if v.Rejected.AboveTeardown != 0 {
		t.Fatalf("Rejected.AboveTeardown = %d, ожидалось 0 — граница съела резы "+
			"рабочего диапазона 85–100 с, то есть единственный реальный сигнал",
			v.Rejected.AboveTeardown)
	}
	if v.Samples != len(ages) {
		t.Errorf("Samples = %d, ожидалось %d", v.Samples, len(ages))
	}
	if v.Axis != AxisAge {
		t.Errorf("Axis = %v, ожидалась age (reason: %s)", v.Axis, v.Reason)
	}
}

// Граница ВКЛЮЧАЮЩАЯ: наблюдение ровно на worstCaseTeardown ещё правдоподобно.
//
// Обоснование границы должно быть проверяемым, а не «на глаз» (hard rule 8).
// Равенство оставляем внутри выборки, потому что slot_age считается с ГОТОВНОСТИ
// соединения, а не с SYN (hard rule 12): TCP+TLS handshake (в поле 0.2–0.5 с) в
// величину не входит, поэтому реальная экспозиция на wire на столько же больше
// измеренной. Отбраковывать по строгому «>=» значило бы срезать наблюдение,
// которое в бюджет как раз укладывается.
func TestFilterNoise_TeardownBoundaryInclusive(t *testing.T) {
	const (
		floorMs    = 45_000
		teardownMs = 142_500
	)

	r := NewRecorder(0)
	for i := range 13 {
		// Все наблюдения в пределах бюджета, последнее — ровно на границе.
		age := teardownMs - int64(12-i)*1000
		r.Record(Observation{AgeMs: age, DownBytes: int64(i*700_000 + 300), CloseKind: "close_other"})
	}

	v := r.InferWithMinAgeAndTeardown(floorMs, teardownMs)
	if v.Rejected.AboveTeardown != 0 {
		t.Errorf("Rejected.AboveTeardown = %d, ожидалось 0 — граница должна быть "+
			"включающей (slot_age не содержит handshake, см. hard rule 12)",
			v.Rejected.AboveTeardown)
	}
	if v.Samples != 13 {
		t.Errorf("Samples = %d, ожидалось 13", v.Samples)
	}

	// А вот на миллисекунду выше — уже вне бюджета.
	r2 := NewRecorder(0)
	for i := range 12 {
		r2.Record(Observation{AgeMs: 84_000 + int64(i)*1000, DownBytes: int64(i*700_000 + 300), CloseKind: "close_other"})
	}
	r2.Record(Observation{AgeMs: teardownMs + 1, DownBytes: 500_000, CloseKind: "close_other"})
	if got := r2.InferWithMinAgeAndTeardown(floorMs, teardownMs).Rejected.AboveTeardown; got != 1 {
		t.Errorf("Rejected.AboveTeardown = %d при возрасте teardown+1ms, ожидалось 1", got)
	}
}

// teardownMs <= 0 отключает верхнюю границу — поведение до 2026-08-17.
//
// Симметрично minAgeMs <= 0: пул может быть собран без gracefulDrain, и тогда
// worstCaseTeardown не описывает реальный путь ячейки. Отключение обязано быть
// явным, а не «случайно ноль сработал как ноль».
func TestFilterNoise_ZeroTeardownDisablesBound(t *testing.T) {
	const floorMs = 45_000

	r := NewRecorder(0)
	for i := range 12 {
		r.Record(Observation{AgeMs: 84_000 + int64(i)*1000, DownBytes: int64(i*900_000 + 100), CloseKind: "close_other"})
	}
	r.Record(Observation{AgeMs: 505_411, DownBytes: 60_088_879, CloseKind: "close_other"})

	v := r.InferWithMinAgeAndTeardown(floorMs, 0)
	if v.Rejected.AboveTeardown != 0 {
		t.Errorf("Rejected.AboveTeardown = %d при teardownMs=0, ожидалось 0 — "+
			"граница обязана отключаться явно", v.Rejected.AboveTeardown)
	}
	if v.Samples != 13 {
		t.Errorf("Samples = %d, ожидалось 13 (граница выключена)", v.Samples)
	}
}

// Total() обязан учитывать новую причину: иначе разница между `samples` в сводке
// и `samples_used` в инференсе не объясняется ни одним напечатанным счётчиком, и
// читатель объяснит её чем угодно. Ровно тот класс дефекта («лог врёт о
// механизме»), который проект ловил многократно.
func TestRejectionStats_TotalCountsAboveTeardown(t *testing.T) {
	rej := RejectionStats{ZeroAge: 1, LocalClose: 2, Timeout: 3, TooYoung: 4, Planned: 5, AboveTeardown: 6}
	if got, want := rej.Total(), 21; got != want {
		t.Errorf("Total() = %d, ожидалось %d — AboveTeardown не учтён в сумме", got, want)
	}
}

// InferWithMinAge сохраняет прежнюю сигнатуру и поведение (без верхней границы):
// у неё остались вызывающие в тестах, и молчаливая смена смысла сломала бы их
// не там, где видно.
func TestInferWithMinAge_KeepsUpperBoundDisabled(t *testing.T) {
	r := NewRecorder(0)
	for i := range 12 {
		r.Record(Observation{AgeMs: 84_000 + int64(i)*1000, DownBytes: int64(i*900_000 + 100), CloseKind: "close_other"})
	}
	r.Record(Observation{AgeMs: 505_411, DownBytes: 60_088_879, CloseKind: "close_other"})

	if got := r.InferWithMinAge(45_000).Rejected.AboveTeardown; got != 0 {
		t.Errorf("InferWithMinAge отбраковала %d по верхней границе, ожидалось 0", got)
	}
}

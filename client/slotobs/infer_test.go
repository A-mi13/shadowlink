package slotobs

import (
	"testing"
	"time"
)

// Полевые данные 2026-07-31, провайдер по месту, 19 age-cut за 17 минут.
// Источник: nixavpn-DEBUG-20260731-155722.log, строки "slot reader error".
// Пары (slot_age_ms, down_bytes) — как их записал рекордер в бою.
//
// Эта выборка — регрессионный эталон: инференс на ней ОБЯЗАН выдать ось
// возраста и порог в разумном коридоре. Если однажды выдаст другое, значит
// логика поехала, а не сеть изменилась.
var fieldDeaths2026_07_31 = []Observation{
	{AgeMs: 85275, DownBytes: 0, CloseKind: "close_other"},
	{AgeMs: 88073, DownBytes: 162, CloseKind: "close_other"},
	{AgeMs: 88844, DownBytes: 13365, CloseKind: "close_other"},
	{AgeMs: 92333, DownBytes: 12880, CloseKind: "close_other"},
	{AgeMs: 99664, DownBytes: 1710253, CloseKind: "close_other"},
	{AgeMs: 100281, DownBytes: 9896, CloseKind: "close_other"},
	{AgeMs: 104410, DownBytes: 5230692, CloseKind: "close_other"},
	{AgeMs: 106583, DownBytes: 10333620, CloseKind: "close_other"},
	{AgeMs: 106675, DownBytes: 10946, CloseKind: "close_other"},
	{AgeMs: 110838, DownBytes: 11583, CloseKind: "close_other"},
	{AgeMs: 112992, DownBytes: 79708, CloseKind: "close_other"},
	{AgeMs: 114056, DownBytes: 339834, CloseKind: "close_other"},
	{AgeMs: 115626, DownBytes: 30828, CloseKind: "close_other"},
	{AgeMs: 116440, DownBytes: 11160, CloseKind: "close_other"},
	{AgeMs: 122876, DownBytes: 15740, CloseKind: "close_other"},
	{AgeMs: 125705, DownBytes: 8474, CloseKind: "close_other"},
	{AgeMs: 150310, DownBytes: 259230, CloseKind: "close_other"},
	{AgeMs: 153022, DownBytes: 80673, CloseKind: "close_other"},
	{AgeMs: 154737, DownBytes: 11770657, CloseKind: "other"},
}

// Шум из той же сессии: три смерти в момент подключения. Именно они подняли
// CV возраста с 0.18 до 0.4546 в первой (неотфильтрованной) сводке.
var fieldNoise2026_07_31 = []Observation{
	{AgeMs: 0, DownBytes: 0, CloseKind: "io_timeout"},
	{AgeMs: 0, DownBytes: 0, CloseKind: "io_timeout"},
	{AgeMs: 0, DownBytes: 0, CloseKind: "io_timeout"},
}

func recorderWith(obs ...[]Observation) *Recorder {
	r := NewRecorder(256)
	for _, batch := range obs {
		for _, o := range batch {
			r.Record(o)
		}
	}
	return r
}

// ГЛАВНЫЙ тест: на реальных данных вывод должен совпасть с ручным расчётом.
func TestInfer_FieldData_DetectsAgeAxis(t *testing.T) {
	r := recorderWith(fieldDeaths2026_07_31)
	v := r.Infer()

	t.Logf("вердикт: ось=%s порог=%v samples=%d", v.Axis, v.Threshold.Age, v.Samples)
	t.Logf("причина: %s", v.Reason)

	if v.Axis != AxisAge {
		t.Fatalf("ось=%s, на полевых данных ожидалась age", v.Axis)
	}
	// Ручной расчёт: p10 = 88073ms, 80% от него = 70458ms ≈ 70s.
	if v.Threshold.Age < 60*time.Second || v.Threshold.Age > 80*time.Second {
		t.Errorf("порог %v вне ожидаемого коридора 60..80s (p10=88s, 80%% от него ~70s)",
			v.Threshold.Age)
	}
	// Порог обязан быть НИЖЕ самой ранней смерти — иначе он бесполезен.
	if v.Threshold.Age >= 85275*time.Millisecond {
		t.Errorf("порог %v не ниже самой ранней смерти 85.275s", v.Threshold.Age)
	}
	if v.Reason == "" {
		t.Error("Reason пуст — вердикт без объяснения непроверяем (болезнь H-15)")
	}
}

// Шум не должен ломать вывод: именно на этом первая сводка почти потеряла сигнал.
func TestInfer_FieldData_NoiseFiltered(t *testing.T) {
	r := recorderWith(fieldDeaths2026_07_31, fieldNoise2026_07_31)
	v := r.Infer()

	t.Logf("вердикт с шумом: ось=%s порог=%v samples=%d отброшено=%+v",
		v.Axis, v.Threshold.Age, v.Samples, v.Rejected)

	if v.Axis != AxisAge {
		t.Errorf("ось=%s — шум сбил вывод, хотя должен быть отфильтрован", v.Axis)
	}
	if v.Rejected.ZeroAge != 3 {
		t.Errorf("отброшено по нулевому возрасту %d, ожидалось 3", v.Rejected.ZeroAge)
	}
	if v.Samples != len(fieldDeaths2026_07_31) {
		t.Errorf("в выводе участвовало %d наблюдений, ожидалось %d",
			v.Samples, len(fieldDeaths2026_07_31))
	}
}

// Обратная гипотеза: рез по объёму должен распознаваться так же уверенно.
func TestInfer_VolumeCutDetected(t *testing.T) {
	r := NewRecorder(64)
	// Объём кластеризован у 18 КБ, возраст гуляет на два порядка.
	vols := []int64{17800, 18200, 18050, 17950, 18100, 18000, 17900, 18150,
		17850, 18250, 18000, 17750}
	ages := []int64{4000, 210000, 35000, 900000, 12000, 78000, 300000, 5000,
		150000, 22000, 460000, 8000}
	for i := range vols {
		r.Record(Observation{AgeMs: ages[i], DownBytes: vols[i], CloseKind: "reset_by_peer"})
	}
	v := r.Infer()
	t.Logf("вердикт: ось=%s порог=%dB — %s", v.Axis, v.Threshold.Bytes, v.Reason)

	if v.Axis != AxisBytes {
		t.Fatalf("ось=%s, ожидалась down_bytes", v.Axis)
	}
	if v.Threshold.Bytes <= 0 || v.Threshold.Bytes >= 17750 {
		t.Errorf("порог %dB должен быть ниже минимального наблюдения 17750B",
			v.Threshold.Bytes)
	}
	if v.Threshold.Age != 0 {
		t.Errorf("при осях-байтах Threshold.Age должен быть 0, получено %v", v.Threshold.Age)
	}
}

// Мало данных → «не знаю», а НЕ случайный порог.
func TestInfer_InsufficientSamples(t *testing.T) {
	r := NewRecorder(64)
	for i := 0; i < MinSamplesForInference-1; i++ {
		r.Record(Observation{AgeMs: 130000, DownBytes: 20000, CloseKind: "close_other"})
	}
	v := r.Infer()
	if v.Axis != AxisUnknown {
		t.Errorf("при %d наблюдениях ось=%s, ожидалось unknown",
			MinSamplesForInference-1, v.Axis)
	}
	if v.Threshold.Age != 0 || v.Threshold.Bytes != 0 {
		t.Error("при AxisUnknown порог обязан быть нулевым — вызывающий сохраняет текущее поведение")
	}
	if v.Reason == "" {
		t.Error("Reason пуст")
	}
	t.Logf("причина: %s", v.Reason)
}

// Пустой рекордер — не паника, а «не знаю».
func TestInfer_Empty(t *testing.T) {
	v := NewRecorder(8).Infer()
	if v.Axis != AxisUnknown || v.Samples != 0 {
		t.Errorf("на пустых данных получено ось=%s samples=%d", v.Axis, v.Samples)
	}
}

// Оси не разделяются (обе шумят одинаково) → «не знаю».
func TestInfer_NoSeparation(t *testing.T) {
	r := NewRecorder(64)
	// И возраст, и объём разбросаны сопоставимо.
	for i := 0; i < 20; i++ {
		r.Record(Observation{
			AgeMs:     int64(10000 + i*20000),
			DownBytes: int64(1000 + i*2000),
			CloseKind: "close_other",
		})
	}
	v := r.Infer()
	t.Logf("вердикт: ось=%s — %s", v.Axis, v.Reason)
	if v.Axis != AxisUnknown {
		t.Errorf("ось=%s, при сопоставимом разбросе ожидалось unknown", v.Axis)
	}
}

// Все наблюдения — шум → «не знаю», без деления на ноль.
func TestInfer_AllNoise(t *testing.T) {
	r := NewRecorder(32)
	for i := 0; i < 20; i++ {
		r.Record(Observation{AgeMs: 0, CloseKind: "io_timeout"})
	}
	v := r.Infer()
	if v.Axis != AxisUnknown {
		t.Errorf("ось=%s на чистом шуме", v.Axis)
	}
	if v.Rejected.ZeroAge != 20 {
		t.Errorf("отброшено %d, ожидалось 20", v.Rejected.ZeroAge)
	}
}

// closed_local — наши собственные закрытия, не поведение посредника.
func TestInfer_LocalCloseRejected(t *testing.T) {
	r := recorderWith(fieldDeaths2026_07_31)
	for i := 0; i < 5; i++ {
		r.Record(Observation{AgeMs: 1000, DownBytes: 50, CloseKind: "closed_local"})
	}
	v := r.Infer()
	if v.Rejected.LocalClose != 5 {
		t.Errorf("closed_local отброшено %d, ожидалось 5", v.Rejected.LocalClose)
	}
	if v.Axis != AxisAge {
		t.Errorf("ось=%s — наши закрытия сбили вывод", v.Axis)
	}
}

// Стабильность: один и тот же набор даёт один и тот же вердикт.
func TestInfer_Deterministic(t *testing.T) {
	first := recorderWith(fieldDeaths2026_07_31).Infer()
	for i := 0; i < 5; i++ {
		v := recorderWith(fieldDeaths2026_07_31).Infer()
		if v.Axis != first.Axis || v.Threshold.Age != first.Threshold.Age {
			t.Fatalf("вердикт нестабилен: %s/%v против %s/%v",
				v.Axis, v.Threshold.Age, first.Axis, first.Threshold.Age)
		}
	}
}

// Порог обязан быть ниже p10 — иначе ротация происходит после части смертей.
func TestInfer_ThresholdBelowP10(t *testing.T) {
	r := recorderWith(fieldDeaths2026_07_31)
	v := r.Infer()
	s := r.Summarize()
	if int64(v.Threshold.Age/time.Millisecond) >= s.AgeP10 {
		t.Errorf("порог %v не ниже p10 %dms", v.Threshold.Age, s.AgeP10)
	}
}

// AgeMinMs обязан считаться по ОЧИЩЕННОЙ выборке, а не по сырой.
//
// Полевой замер 2026-08-07 показал цену ошибки: в выборку попало наблюдение
// `close 1000 (normal)` с возрастом 2 мс — штатное закрытие слота при старте,
// не рез посредника. Summary.AgeMin (сырой) стал 2 мс, и проверка бюджета
// показала дефицит −2m24s на ровном месте, обесценив WARN.
//
// Минимум, с которым сравнивается worst-case teardown, обязан приходить из тех
// же данных, на которых построен порог.
func TestInfer_AgeMinExcludesNoise(t *testing.T) {
	r := NewRecorder(0)

	// Шум: мгновенное штатное закрытие. filterNoise режет его по AgeMs <= 0
	// только если возраст нулевой, поэтому берём именно ненулевой-но-крошечный
	// с локальным закрытием — как в поле.
	r.Record(Observation{AgeMs: 2, DownBytes: 0, CloseKind: "closed_local"})

	// Реальные резы по возрасту, разброс по байтам широкий.
	ages := []int64{82338, 83469, 86320, 88309, 92223, 94031,
		96500, 99200, 101400, 104524, 108900, 112300, 126019}
	for i, a := range ages {
		r.Record(Observation{
			AgeMs:     a,
			DownBytes: int64(i*900_000 + 1756),
			CloseKind: "close_other",
		})
	}

	v := r.Infer()
	if v.Axis != AxisAge {
		t.Fatalf("Axis = %v, ожидалась age (reason: %s)", v.Axis, v.Reason)
	}
	if v.AgeMinMs != 82338 {
		t.Errorf("AgeMinMs = %d, ожидалось 82338 — минимум взят из сырой выборки "+
			"вместе с шумом", v.AgeMinMs)
	}
	if v.Rejected.LocalClose != 1 {
		t.Errorf("Rejected.LocalClose = %d, ожидалось 1", v.Rejected.LocalClose)
	}

	// Сырой Summary честно показывает 2 мс — это не баг, а разные величины.
	if got := r.Summarize().AgeMin; got != 2 {
		t.Errorf("Summary.AgeMin = %d, ожидалось 2 (сырой минимум включает шум)", got)
	}
}

// При AxisUnknown минимум не публикуется: нет вывода — нет и величины, с которой
// что-то сравнивать.
func TestInfer_AgeMinZeroWhenNoVerdict(t *testing.T) {
	r := NewRecorder(0)
	for range 3 {
		r.Record(Observation{AgeMs: 90000, DownBytes: 5000, CloseKind: "close_other"})
	}
	v := r.Infer()
	if v.Axis != AxisUnknown {
		t.Fatalf("Axis = %v, ожидалась unknown при %d наблюдениях", v.Axis, v.Samples)
	}
	if v.AgeMinMs != 0 {
		t.Errorf("AgeMinMs = %d при AxisUnknown, ожидался 0", v.AgeMinMs)
	}
}

// Дыра, которую НЕ закрывал прежний filterNoise: наблюдение с ненулевым, но
// заведомо доцензурным возрастом и обычным CloseKind.
//
// Полевой замер 2026-08-07: `close 1000 (normal)` при старте слота дал
// AgeMs=2, CloseKind="close_other". Прежний фильтр резал только AgeMs<=0,
// поэтому наблюдение проходило и становилось минимумом. Итог — age_min=2ms в
// 67 строках лога из 74 и WARN о превышении бюджета, срабатывающий всегда.
func TestInfer_TooYoungRejected(t *testing.T) {
	const floorMs = 45_000 // ageCutMinAge из клиента

	r := NewRecorder(0)
	r.Record(Observation{AgeMs: 2, DownBytes: 0, CloseKind: "close_other"})
	r.Record(Observation{AgeMs: 1200, DownBytes: 900, CloseKind: "close_other"})

	ages := []int64{82338, 83469, 86320, 88309, 92223, 94031,
		96500, 99200, 101400, 104524, 108900, 112300, 126019}
	for i, a := range ages {
		r.Record(Observation{
			AgeMs:     a,
			DownBytes: int64(i*900_000 + 1756),
			CloseKind: "close_other",
		})
	}

	// Без порога шум проходит фильтр и портит выборку. Здесь он вдобавок ломает
	// сам вывод: два наблюдения с крошечным возрастом раздувают CV возраста
	// настолько, что оси перестают разделяться и Infer честно отвечает «не знаю».
	// Это лучше неверного порога, но означает, что контур молчит — а данных
	// достаточно, и молчать он не должен.
	if noFloor := r.InferWithMinAge(0); noFloor.Axis != AxisUnknown {
		t.Errorf("без порога Axis = %v, ожидался unknown (шум ломает разделение); "+
			"AgeMinMs=%d", noFloor.Axis, noFloor.AgeMinMs)
	}

	v := r.InferWithMinAge(floorMs)
	if v.Axis != AxisAge {
		t.Fatalf("Axis = %v, ожидалась age (reason: %s)", v.Axis, v.Reason)
	}
	if v.Rejected.TooYoung != 2 {
		t.Errorf("Rejected.TooYoung = %d, ожидалось 2", v.Rejected.TooYoung)
	}
	if v.AgeMinMs != 82338 {
		t.Errorf("AgeMinMs = %d, ожидалось 82338 — доцензурные смерти не отсеяны",
			v.AgeMinMs)
	}
	if v.Samples != len(ages) {
		t.Errorf("Samples = %d, ожидалось %d", v.Samples, len(ages))
	}
}

// Порог не должен съедать нормальные наблюдения: смерть ровно на границе — это
// уже age-cut по определению самой границы.
func TestInfer_TooYoungBoundaryInclusive(t *testing.T) {
	const floorMs = 45_000

	r := NewRecorder(0)
	for i := range 14 {
		r.Record(Observation{
			AgeMs:     floorMs + int64(i)*1000,
			DownBytes: int64(i*800_000 + 500),
			CloseKind: "close_other",
		})
	}
	v := r.InferWithMinAge(floorMs)
	if v.Rejected.TooYoung != 0 {
		t.Errorf("Rejected.TooYoung = %d, ожидалось 0 — граница исключающая",
			v.Rejected.TooYoung)
	}
	if v.AgeMinMs != floorMs {
		t.Errorf("AgeMinMs = %d, ожидалось %d", v.AgeMinMs, floorMs)
	}
}

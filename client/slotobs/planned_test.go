package slotobs

import "testing"

// Плановые ротации живут в ОТДЕЛЬНОМ ринге (2026-08-12).
//
// Зачем отдельный, а не метка в общем: полевой замер 20260812-110200 дал 740
// плановых дренажей против 8 резов за 2 часа — соотношение ~92:1. В общем ринге
// на 512 записей плановые вытеснили бы все наблюдения о резе за ~20 минут, и
// Summarize начал бы описывать НАШ СОБСТВЕННЫЙ порог ротации вместо поведения
// посредника. Это хуже текущего молчания: молчание видно, а подмена — нет.

// Резы и плановые не должны вытеснять друг друга ни в какую сторону.
func TestPlanned_DoesNotEvictCuts(t *testing.T) {
	r := NewRecorder(8)

	r.Record(Observation{AgeMs: 90_000, DownBytes: 1234, CloseKind: "close_other"})

	// Плановых кладём вдесятеро больше ёмкости ринга: если бы они шли в общий
	// буфер, единственное наблюдение о резе было бы затёрто многократно.
	for i := 0; i < 80; i++ {
		r.RecordPlanned(Observation{AgeMs: 75_000, CloseKind: ClosePlannedRotation})
	}

	if got := r.Len(); got != 1 {
		t.Fatalf("рез вытеснен плановыми: Len()=%d, ожидался 1", got)
	}
	s := r.Summarize()
	if s.Count != 1 {
		t.Fatalf("Summarize по резам засорён плановыми: Count=%d, ожидался 1", s.Count)
	}
	if s.AgeMin != 90_000 {
		t.Fatalf("AgeMin=%d — в выборку резов попала плановая ротация", s.AgeMin)
	}
	if s.ByCloseKind[ClosePlannedRotation] != 0 {
		t.Fatalf("ByCloseKind содержит плановые: %v", s.ByCloseKind)
	}
}

// Обратное направление: поток резов не должен вымывать плановые.
func TestPlanned_CutsDoNotEvictPlanned(t *testing.T) {
	r := NewRecorder(4)
	r.RecordPlanned(Observation{AgeMs: 70_000, CloseKind: ClosePlannedRotation})
	for i := 0; i < 40; i++ {
		r.Record(Observation{AgeMs: 90_000, CloseKind: "close_other"})
	}
	if got := r.LenPlanned(); got != 1 {
		t.Fatalf("плановая вытеснена резами: LenPlanned()=%d, ожидался 1", got)
	}
}

// Существующий контур (Summarize/Infer) обязан остаться побитово прежним —
// иначе правка наблюдаемости стала бы правкой поведения ротации.
func TestPlanned_InferIgnoresPlanned(t *testing.T) {
	r := NewRecorder(0)

	// Ровно MinSamplesForInference чистых резов по возрасту: узкий разброс по
	// возрасту, широкий по байтам -> ось age.
	for i := 0; i < MinSamplesForInference; i++ {
		r.Record(Observation{
			AgeMs:     int64(90_000 + i*100),
			DownBytes: int64(1_000 * (i + 1) * (i + 1)),
			CloseKind: "close_other",
		})
	}
	want := r.InferWithMinAge(30_000)
	if want.Axis != AxisAge {
		t.Fatalf("предусловие не выполнено: Axis=%v, Reason=%q", want.Axis, want.Reason)
	}

	// Заливаем плановые — вывод не должен шевельнуться.
	for i := 0; i < 500; i++ {
		r.RecordPlanned(Observation{AgeMs: 75_000, CloseKind: ClosePlannedRotation})
	}
	got := r.InferWithMinAge(30_000)

	if got.Axis != want.Axis || got.Threshold.Age != want.Threshold.Age {
		t.Fatalf("плановые повлияли на вывод порога: было axis=%v thr=%v, стало axis=%v thr=%v",
			want.Axis, want.Threshold.Age, got.Axis, got.Threshold.Age)
	}
	if got.Samples != want.Samples || got.AgeMinMs != want.AgeMinMs {
		t.Fatalf("плановые попали в очищенную выборку: samples %d->%d, age_min %d->%d",
			want.Samples, got.Samples, want.AgeMinMs, got.AgeMinMs)
	}
}

// filterNoise обязан отбрасывать плановые, даже если они попадут в ринг резов
// (защита от будущей ошибки на вызывающей стороне: перепутать Record и
// RecordPlanned легко, и цена этого — порог, выведенный из своего же порога).
func TestPlanned_FilterNoiseRejectsPlannedInCutRing(t *testing.T) {
	r := NewRecorder(0)
	for i := 0; i < MinSamplesForInference; i++ {
		r.Record(Observation{
			AgeMs:     int64(90_000 + i*100),
			DownBytes: int64(1_000 * (i + 1) * (i + 1)),
			CloseKind: "close_other",
		})
	}
	// Плановая, ошибочно попавшая в ринг резов.
	r.Record(Observation{AgeMs: 75_000, CloseKind: ClosePlannedRotation})

	v := r.InferWithMinAge(30_000)
	if v.Samples != MinSamplesForInference {
		t.Fatalf("плановая не отсеяна filterNoise: samples=%d, ожидалось %d",
			v.Samples, MinSamplesForInference)
	}
	if v.Rejected.Planned != 1 {
		t.Fatalf("Rejected.Planned=%d, ожидался 1 (отсев должен быть ВИДЕН, а не молчаливым)",
			v.Rejected.Planned)
	}
}

// Hazard-кривая: доля срезанных среди доживших до полосы. Именно её отсутствие
// привело к ложному выводу «окно сжалось до 83-87с» — при том, что до 100с
// почти ничего не доезжало (survivorship bias, разбор 2026-08-12).
func TestHazard_ComputesRateAmongSurvivors(t *testing.T) {
	r := NewRecorder(0)

	// 10 плановых на 95с: дожили до полосы 80-90 и ПРОЖИЛИ её целиком
	// (сняты уже после 90с), поэтому идут в знаменатель с полным весом.
	for i := 0; i < 10; i++ {
		r.RecordPlanned(Observation{AgeMs: 95_000, CloseKind: ClosePlannedRotation})
	}
	// 2 реза на 85с — оба внутри полосы 80-90.
	for i := 0; i < 2; i++ {
		r.Record(Observation{AgeMs: 85_000, CloseKind: "close_other"})
	}

	h := r.Hazard(80_000, 90_000)
	if h.Reached != 12 {
		t.Fatalf("Reached=%d, ожидалось 12 (все 12 соединений дожили до 80с)", h.Reached)
	}
	if h.Cut != 2 {
		t.Fatalf("Cut=%d, ожидалось 2", h.Cut)
	}
	if h.CensoredIn != 0 {
		t.Fatalf("CensoredIn=%d, ожидался 0 (все плановые прожили полосу целиком)", h.CensoredIn)
	}
	if got := h.Rate(); got < 0.166 || got > 0.167 {
		t.Fatalf("Rate()=%.4f, ожидалось ~0.1667 (2 из 12)", got)
	}
}

// Плановая ротация ВНУТРИ полосы — цензурирование справа: слот дожил до начала
// полосы, но прожил её лишь частично, потому что сняли его мы сами.
//
// Считать такое наблюдение полноценным «дожившим» — значит раздуть знаменатель
// и ЗАНИЗИТЬ риск. Ревью 2026-08-12 показало цену на данных, повторяющих поле
// (100 плановых равномерно 80–90с, 5 резов): наивный расчёт даёт Rate=0.0476
// против actuarial 0.0909, то есть занижение в 1.91 раза — и занижение именно в
// той полосе, где ищется порог ротации. По памяти проекта «занижение хуже
// завышения»: читатель решил бы, что риск на 80–90с приемлем.
//
// Поправка actuarial (она же Kaplan-Meier для сгруппированных интервалов):
// цензурированные внутри полосы входят в знаменатель с весом 1/2.
func TestHazard_CensoredWithinBandGetsHalfWeight(t *testing.T) {
	r := NewRecorder(0)

	// Полевой профиль: плановые режутся НАМИ внутри полосы интереса.
	for i := 0; i < 100; i++ {
		r.RecordPlanned(Observation{AgeMs: int64(80_000 + i*100), CloseKind: ClosePlannedRotation})
	}
	for i := 0; i < 5; i++ {
		r.Record(Observation{AgeMs: 85_000, CloseKind: "close_other"})
	}

	h := r.Hazard(80_000, 90_000)
	if h.Reached != 105 {
		t.Fatalf("Reached=%d, ожидалось 105", h.Reached)
	}
	if h.CensoredIn != 100 {
		t.Fatalf("CensoredIn=%d, ожидалось 100 (все плановые сняты внутри полосы)", h.CensoredIn)
	}
	// eff = 105 - 0.5*100 = 55; 5/55 = 0.0909
	if got := h.Rate(); got < 0.0905 || got > 0.0913 {
		t.Fatalf("Rate()=%.4f, ожидалось ~0.0909 (actuarial). "+
			"Наивные 0.0476 занижают риск вдвое", got)
	}
}

// Actuarial-поправка СМЕЩЕНА, когда цензурирование сидит у нижней кромки полосы,
// и именно так устроена наша прод-конфигурация.
//
// Тест выше (CensoredWithinBandGetsHalfWeight) строит цензуру РАВНОМЕРНО по
// полосе — там вес 1/2 корректен. Здесь воспроизводится поле: порог ротации
// 70s+stagger, плановые массово снимаются на 80.2s, то есть проживают в полосе
// 80-90s всего 0.2s, а не 5s. Замер 2026-08-14 по 622 восстановленным ротациям
// (nixavpn-DEBUG-20260813-153638): p75 = p90 = 80.2s.
//
// Что защищаем: RateByExposure обязан быть СУЩЕСТВЕННО выше Rate(). Если кто-то
// «упростит» экспозицию обратно к весам, тест это поймает.
func TestHazard_ExposureBeatsActuarialAtBandEdge(t *testing.T) {
	r := NewRecorder(0)

	// 100 плановых на 80.2с — прожили в полосе по 0.2с каждый.
	for i := 0; i < 100; i++ {
		r.RecordPlanned(Observation{AgeMs: 80_200, CloseKind: ClosePlannedRotation})
	}
	// 2 реза на 85с — прожили в полосе по 5с.
	for i := 0; i < 2; i++ {
		r.Record(Observation{AgeMs: 85_000, CloseKind: "close_other"})
	}

	h := r.Hazard(80_000, 90_000)

	// Экспозиция: 100*0.2с + 2*5с = 20 + 10 = 30с.
	if h.ExposureMs != 30_000 {
		t.Fatalf("ExposureMs=%d, ожидалось 30000 (100*200мс + 2*5000мс)", h.ExposureMs)
	}
	// 2 реза / 30с = 0.0667 1/с.
	got := h.RateByExposure()
	if got < 0.066 || got > 0.067 {
		t.Fatalf("RateByExposure()=%.5f, ожидалось ~0.0667 (2 реза на 30с)", got)
	}
	// Actuarial: eff = 102 - 50 = 52; 2/52 = 0.0385 — и это НЕ интенсивность,
	// а доля, то есть сравнивать напрямую нельзя. Сравниваем с вероятностью
	// прохода полосы: 1-exp(-0.0667*10) = 0.487 против 0.0385, разрыв ~12x.
	if h.Rate() >= got {
		t.Fatalf("Rate()=%.4f не ниже RateByExposure()=%.5f — смещение у кромки "+
			"перестало воспроизводиться, проверьте расчёт экспозиции", h.Rate(), got)
	}
}

// Дожившие до конца полосы дают полную ширину экспозиции, умершие внутри — от
// кромки до смерти. Прямая проверка арифметики, без полевых профилей.
func TestHazard_ExposureAccountsPartialAndFullPasses(t *testing.T) {
	r := NewRecorder(0)
	// Прожил полосу целиком (умер за её пределами): вклад = вся ширина 10с.
	r.RecordPlanned(Observation{AgeMs: 150_000, CloseKind: ClosePlannedRotation})
	// Умер ровно на середине: вклад 5с.
	r.Record(Observation{AgeMs: 85_000, CloseKind: "close_other"})
	// Не дожил до полосы: вклад 0, в Reached не входит.
	r.RecordPlanned(Observation{AgeMs: 70_000, CloseKind: ClosePlannedRotation})

	h := r.Hazard(80_000, 90_000)
	if h.Reached != 2 {
		t.Fatalf("Reached=%d, ожидалось 2 (не доживший не считается)", h.Reached)
	}
	if h.ExposureMs != 15_000 {
		t.Fatalf("ExposureMs=%d, ожидалось 15000 (10с полный проход + 5с частичный)",
			h.ExposureMs)
	}
}

// Пустая экспозиция — «нет данных», а не «нулевой риск». Деления на ноль быть
// не должно.
func TestHazard_RateByExposureEmptyIsNotZeroRisk(t *testing.T) {
	r := NewRecorder(0)
	// Ровно на нижней кромке: дожил, но экспозиция 0.
	r.RecordPlanned(Observation{AgeMs: 80_000, CloseKind: ClosePlannedRotation})

	h := r.Hazard(80_000, 90_000)
	if h.Reached != 1 {
		t.Fatalf("Reached=%d, ожидалось 1", h.Reached)
	}
	if h.ExposureMs != 0 {
		t.Fatalf("ExposureMs=%d, ожидался 0", h.ExposureMs)
	}
	if got := h.RateByExposure(); got != 0 {
		t.Fatalf("RateByExposure()=%v при нулевой экспозиции — деление на ноль", got)
	}
}

// Насыщение ринга обязано быть ВИДНО, а не выводиться читателем из третьих чисел.
//
// Замер PROBE 2026-08-13: плановых 1256 при ёмкости 512 (переполнен), резов 126
// (нет). Числитель полный, знаменатель обрезан последними 512 → логировалось
// rate=0.0367 против 0.0178 по экспозиции, завышение ×2.06, и это было прочитано
// как реальный риск. CutShare про ловушку предупреждает, Hazard не предупреждал.
func TestHazard_RingSaturationIsVisible(t *testing.T) {
	r := NewRecorder(8) // маленькая ёмкость, чтобы переполнить дёшево

	// Ринг резов не насыщен, плановых — тоже.
	r.Record(Observation{AgeMs: 85_000, CloseKind: "close_other"})
	if h := r.Hazard(80_000, 90_000); h.RingSaturated {
		t.Fatalf("RingSaturated=true при ненасыщенных рингах")
	}

	// Переполняем ринг плановых: 12 записей при ёмкости 8.
	for i := 0; i < 12; i++ {
		r.RecordPlanned(Observation{AgeMs: 95_000, CloseKind: ClosePlannedRotation})
	}
	h := r.Hazard(80_000, 90_000)
	if !h.RingSaturated {
		t.Fatalf("RingSaturated=false при переполненном ринге плановых — " +
			"смещение доли останется невидимым в логе")
	}
	// Пожизненные счётчики обязаны помнить то, что ринг забыл: без них
	// восстановить масштаб искажения нечем.
	if got := r.TotalPlanned(); got != 12 {
		t.Fatalf("TotalPlanned()=%d, ожидалось 12 (ринг забыл, счётчик — нет)", got)
	}
}

// Резы внутри полосы в CensoredIn не входят: они не цензурированы, они и есть
// событие. Иначе поправка съела бы сама себя.
func TestHazard_CutsAreNotCensored(t *testing.T) {
	r := NewRecorder(0)
	for i := 0; i < 4; i++ {
		r.Record(Observation{AgeMs: 85_000, CloseKind: "close_other"})
	}
	h := r.Hazard(80_000, 90_000)
	if h.CensoredIn != 0 {
		t.Fatalf("CensoredIn=%d — рез посчитан как цензурированный", h.CensoredIn)
	}
	if got := h.Rate(); got != 1.0 {
		t.Fatalf("Rate()=%.4f, ожидалось 1.0 (все 4 дошедших срезаны)", got)
	}
}

// Патологический случай: цензурированных столько, что эффективный знаменатель
// вырождается. Rate не должен уходить в бесконечность или отрицательное.
func TestHazard_DegenerateEffectiveDenominator(t *testing.T) {
	r := NewRecorder(0)
	r.RecordPlanned(Observation{AgeMs: 85_000, CloseKind: ClosePlannedRotation})

	h := r.Hazard(80_000, 90_000)
	// Reached=1, CensoredIn=1 -> eff = 1 - 0.5 = 0.5, Cut=0 -> Rate=0
	if got := h.Rate(); got != 0 {
		t.Fatalf("Rate()=%v при нулевом Cut", got)
	}
	if h.Reached != 1 || h.CensoredIn != 1 {
		t.Fatalf("Reached=%d CensoredIn=%d, ожидалось 1/1", h.Reached, h.CensoredIn)
	}
}

// Полоса, до которой не дожил никто, обязана давать Reached=0 и Rate=0, а не
// делить на ноль и не выдавать «0% риска» как факт.
func TestHazard_EmptyBandIsNotZeroRisk(t *testing.T) {
	r := NewRecorder(0)
	r.RecordPlanned(Observation{AgeMs: 80_000, CloseKind: ClosePlannedRotation})

	h := r.Hazard(100_000, 110_000)
	if h.Reached != 0 {
		t.Fatalf("Reached=%d, ожидался 0", h.Reached)
	}
	if h.Rate() != 0 {
		t.Fatalf("Rate()=%v на пустой полосе — деление на ноль", h.Rate())
	}
}

// Доля «срезано посредником» — то, что skill прямо называет невыводимым из
// цензурированной выборки. С отдельным рингом плановых знаменатель появляется.
func TestCutShare_DenominatorIncludesPlanned(t *testing.T) {
	r := NewRecorder(0)
	for i := 0; i < 95; i++ {
		r.RecordPlanned(Observation{AgeMs: 75_000, CloseKind: ClosePlannedRotation})
	}
	for i := 0; i < 5; i++ {
		r.Record(Observation{AgeMs: 90_000, CloseKind: "close_other"})
	}
	share, total := r.CutShare()
	if total != 100 {
		t.Fatalf("total=%d, ожидалось 100", total)
	}
	if share < 0.049 || share > 0.051 {
		t.Fatalf("share=%.4f, ожидалось ~0.05", share)
	}
}

func TestCutShare_NoDataIsNotZeroShare(t *testing.T) {
	r := NewRecorder(0)
	share, total := r.CutShare()
	if total != 0 || share != 0 {
		t.Fatalf("share=%v total=%d на пустой выборке", share, total)
	}
}

// Нулевой Recorder (`&Recorder{}`) не должен паниковать на записи плановых.
//
// Экспортируемого способа получить такой Recorder нет — NewRecorder нормализует
// capacity<=0 до DefaultCapacity. Но sync.Mutex в структуре делает нулевое
// значение внешне пригодным к использованию, и ленивая инициализация выглядела
// защитой от этого случая, не будучи ею: make([]Observation, 0) давал панику
// index out of range на первой записи (ревью 2026-08-12).
func TestRecordPlanned_ZeroValueRecorderDoesNotPanic(t *testing.T) {
	r := &Recorder{}
	r.RecordPlanned(Observation{AgeMs: 75_000})
	if got := r.LenPlanned(); got != 1 {
		t.Fatalf("LenPlanned()=%d после записи в нулевой Recorder", got)
	}
}

// Конкурентная запись в ОБА ринга плюс чтение агрегатов.
//
// На Windows без -race (hard rule 6) тест докажет лишь отсутствие паники и
// сохранность счётчиков, но под -race в CI/Linux он поймал бы забытую
// блокировку. Весь смысл рекордера — конкурентные смерти слотов, каждая в своей
// горутине, поэтому пробел здесь стоило закрыть (ревью 2026-08-12).
func TestRecorder_ConcurrentBothRings(t *testing.T) {
	r := NewRecorder(64)
	const n = 200

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			r.Record(Observation{AgeMs: 90_000, CloseKind: "close_other"})
		}
	}()
	go func() {
		for i := 0; i < n; i++ {
			r.RecordPlanned(Observation{AgeMs: 75_000})
		}
	}()
	// Читатель работает одновременно с писателями.
	for i := 0; i < 50; i++ {
		_ = r.Hazard(70_000, 80_000)
		_, _ = r.CutShare()
		_ = r.Summarize()
	}
	<-done

	if got := r.Total(); got != n {
		t.Errorf("Total()=%d, ожидалось %d", got, n)
	}
	// Плановый писатель мог не закончить — проверяем лишь непротиворечивость.
	if lp, tp := r.LenPlanned(), r.TotalPlanned(); uint64(lp) > tp {
		t.Errorf("LenPlanned()=%d больше TotalPlanned()=%d", lp, tp)
	}
}

func TestRecorder_ResetClearsPlanned(t *testing.T) {
	r := NewRecorder(0)
	r.RecordPlanned(Observation{AgeMs: 75_000, CloseKind: ClosePlannedRotation})
	r.Reset()
	if got := r.LenPlanned(); got != 0 {
		t.Fatalf("LenPlanned()=%d после Reset", got)
	}
	if got := r.TotalPlanned(); got != 0 {
		t.Fatalf("TotalPlanned()=%d после Reset", got)
	}
}

// TotalPlanned считает пожизненно, включая затёртые — иначе «сколько ротаций
// было» не отличить от «сколько влезло в ринг».
func TestRecorder_TotalPlannedCountsOverwritten(t *testing.T) {
	r := NewRecorder(4)
	for i := 0; i < 10; i++ {
		r.RecordPlanned(Observation{AgeMs: 75_000, CloseKind: ClosePlannedRotation})
	}
	if got := r.TotalPlanned(); got != 10 {
		t.Fatalf("TotalPlanned()=%d, ожидалось 10", got)
	}
	if got := r.LenPlanned(); got != 4 {
		t.Fatalf("LenPlanned()=%d, ожидалось 4 (ёмкость ринга)", got)
	}
}

package client

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client/slotobs"
)

// Гейт логирования сводки НЕ должен глушить адаптер (2026-08-12).
//
// Полевой разбор 20260812-110200: за 1ч58м набралось 8 наблюдений против порога
// minSlotDeathSamplesToLog=12, поэтому logSlotDeathSummary вышла по раннему
// return — а вместе с ней НЕ вызвался ageAdapter.Observe, потому что он стоял
// ниже того же гейта. Следствие: адаптация порога per-AS не исполнялась ни
// секунды, и лог об этом не сообщил ничем. Порог остался конфигурационным.
//
// Требование: недостаток данных обязан быть СКАЗАН, а не выражен молчанием.
// Это тот же H-15 — контур, про который нельзя сказать, работает ли он.
func TestSlotDeathGate_BelowThresholdStillSpeaks(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(64),
		maxSlotAge:        75 * time.Second,
		stickyMaxDrainAge: DefaultStickyMaxDrainAge,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	// Ровно полевая ситуация: наблюдений меньше порога, но они ЕСТЬ.
	for i := 0; i < 8; i++ {
		p.slotDeaths.Record(slotobs.Observation{
			AgeMs: int64(85_000 + i*1000), DownBytes: int64(i * 1024), CloseKind: "close_other",
		})
	}

	logSlotDeathSummary()
	out := buf.String()

	// Распределение по-прежнему молчит: на 8 точках CV — шум, и печать
	// пригласила бы читать порог с восьми точек.
	if strings.Contains(out, "slot death distribution") {
		t.Errorf("сводка залогирована при 8 образцах (порог %d):\n%s", minSlotDeathSamplesToLog, out)
	}

	// Но САМ ФАКТ нехватки данных обязан быть в логе, с числами.
	if !strings.Contains(out, "slot death observability") {
		t.Fatalf("при нехватке данных контур молчит — это H-15:\n%s", out)
	}
	for _, want := range []string{"samples=8", "required=12", "applied_max_slot_age=1m15s"} {
		if !strings.Contains(out, want) {
			t.Errorf("в строке нехватки данных нет %q:\n%s", want, out)
		}
	}
}

// Строка нехватки данных обязана быть РЕДКОЙ.
//
// logSlotDeathSummary зовётся из StartStatsLogger каждые 5s
// (engine_shadowlink.go:216), поэтому безусловная печать дала бы 720 строк в час
// при нехватке данных. Это ровно тот шум, от которого лечились в b0ad357:
// «предупреждение, которое срабатывает на три порядка чаще предсказанного
// отказа, читатель перестаёт читать — а это тот же H-15, только через шум».
//
// Дросселирование по ИЗМЕНЕНИЮ состояния, а не по времени: пока samples и
// применённый порог те же, повторять нечего.
func TestSlotDeathGate_InsufficientLineIsThrottled(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(64),
		maxSlotAge:        75 * time.Second,
		stickyMaxDrainAge: DefaultStickyMaxDrainAge,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	for i := 0; i < 8; i++ {
		p.slotDeaths.Record(slotobs.Observation{AgeMs: 85_000, CloseKind: "close_other"})
	}

	// Десять тиков подряд без изменения состояния — строка должна быть ОДНА.
	for i := 0; i < 10; i++ {
		logSlotDeathSummary()
	}
	if got := strings.Count(buf.String(), "slot death observability"); got != 1 {
		t.Errorf("строка напечатана %d раз за 10 тиков без изменений — шум 720 строк/час", got)
	}

	// Появилось новое наблюдение — состояние изменилось, сказать надо.
	buf.Reset()
	p.slotDeaths.Record(slotobs.Observation{AgeMs: 86_000, CloseKind: "close_other"})
	logSlotDeathSummary()
	if got := strings.Count(buf.String(), "slot death observability"); got != 1 {
		t.Errorf("при изменении samples строка не напечатана (got=%d) — потеря наблюдаемости", got)
	}
}

// Hazard обязан попадать в ЛОГ, а не оставаться мёртвым кодом.
//
// Ревью 2026-08-12: функция не вызывалась нигде в проде (только в тестах), при
// том что SKILL.md уже подал hazard-кривую как «правильную величину» и на этом
// основании отменил прежнюю оценку окна 84–118с. Величина, которую никто не
// читает, — не наблюдаемость; это тот же дефект, что и лечит вся правка.
func TestSlotDeathGate_HazardCurveIsLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(512),
		maxSlotAge:        75 * time.Second,
		ageCutMinAge:      30 * time.Second,
		stickyMaxDrainAge: DefaultStickyMaxDrainAge,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	// Достаточная выборка резов, чтобы дойти до полного вывода, плюс плановые
	// как знаменатель.
	ages := []int64{85275, 88073, 88844, 92333, 99664, 100281, 104410, 106583,
		106675, 110838, 112992, 114056}
	vols := []int64{0, 162, 13365, 12880, 1710253, 9896, 5230692, 10333620,
		10946, 11583, 79708, 339834}
	for i := range ages {
		p.slotDeaths.Record(slotobs.Observation{
			AgeMs: ages[i], DownBytes: vols[i], CloseKind: "close_other",
		})
	}
	for i := 0; i < 300; i++ {
		p.slotDeaths.RecordPlanned(slotobs.Observation{AgeMs: int64(78_000 + i*20)})
	}

	logSlotDeathSummary()
	out := buf.String()

	if !strings.Contains(out, "slot death hazard") {
		t.Fatalf("hazard-кривая не попала в лог — величина остаётся мёртвым кодом:\n%s", out)
	}
}

// Hazard обязан печататься и НИЖЕ порога инференса.
//
// Полевой прогон 20260812-140930 (1ч43м): 6 резов против порога 12, и строка
// `slot death hazard` не появилась ни разу — вызов стоял ПОСЛЕ раннего return
// гейта. То есть я повторил ровно тот дефект, который этой серией правок и
// лечил: величину заперли за порогом, который в поле не достигается.
//
// Hazard от порога инференса не зависит по смыслу: он считается по знаменателю
// из ПЛАНОВЫХ ротаций (их 601 за прогон), а не по резам. Порог 12 существует
// для CV и перцентилей смертей, к hazard он отношения не имеет.
func TestSlotDeathGate_HazardLoggedBelowInferenceThreshold(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(512),
		maxSlotAge:        75 * time.Second,
		ageCutMinAge:      30 * time.Second,
		stickyMaxDrainAge: DefaultStickyMaxDrainAge,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	// Полевая ситуация: резов МЕНЬШЕ порога, плановых много.
	for i := 0; i < 6; i++ {
		p.slotDeaths.Record(slotobs.Observation{AgeMs: int64(85_000 + i*500), CloseKind: "close_other"})
	}
	for i := 0; i < 601; i++ {
		p.slotDeaths.RecordPlanned(slotobs.Observation{AgeMs: int64(76_000 + i*10)})
	}

	logSlotDeathSummary()
	out := buf.String()

	// Сводка и вывод порога молчат — данных правда мало.
	if strings.Contains(out, "slot death distribution") {
		t.Errorf("сводка напечатана при 6 резах (порог %d):\n%s", minSlotDeathSamplesToLog, out)
	}
	// А hazard — нет: его знаменатель есть.
	if !strings.Contains(out, "slot death hazard") {
		t.Fatalf("hazard заперт за порогом инференса — повтор того же дефекта:\n%s", out)
	}

	// И он тоже обязан дросселироваться: вызов идёт каждые 5s, а кривая меняется
	// только при новых наблюдениях. Иначе перенос выше гейта вернул бы 720
	// строк/час — тот же шум, что лечили в 9563dad.
	buf.Reset()
	for i := 0; i < 10; i++ {
		logSlotDeathSummary()
	}
	if got := strings.Count(buf.String(), "slot death hazard"); got != 0 {
		t.Errorf("hazard напечатан %d раз за 10 тиков без новых наблюдений — шум", got)
	}

	// Новое наблюдение — кривая изменилась, печатаем.
	buf.Reset()
	p.slotDeaths.Record(slotobs.Observation{AgeMs: 88_000, CloseKind: "close_other"})
	logSlotDeathSummary()
	if got := strings.Count(buf.String(), "slot death hazard"); got != 1 {
		t.Errorf("при новом резе hazard не напечатан (got=%d) — потеря наблюдаемости", got)
	}
	// Полосы и поправка на цензурирование обязаны быть видны: без CensoredIn
	// читатель не отличит честный знаменатель от раздутого.
	for _, want := range []string{"band_", "reached", "cut", "censored_in", "rate"} {
		if !strings.Contains(out, want) {
			t.Errorf("в hazard-строке нет %q:\n%s", want, out)
		}
	}
}

// Пустая выборка — тоже состояние, о котором надо сказать: «резов не было»
// и «адаптер на конфиге» это разные утверждения, но оба содержательные.
func TestSlotDeathGate_ZeroSamplesSpeaks(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(64),
		maxSlotAge:        75 * time.Second,
		stickyMaxDrainAge: DefaultStickyMaxDrainAge,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	logSlotDeathSummary()
	if out := buf.String(); !strings.Contains(out, "slot death observability") {
		t.Fatalf("при нулевой выборке контур молчит:\n%s", out)
	}
}

// Плановые ротации обязаны быть видны в строке нехватки данных: именно они
// объясняют, ПОЧЕМУ резов мало. Без них читатель не отличит «сеть спокойна»
// от «клиент не работает».
func TestSlotDeathGate_ReportsPlannedDenominator(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(512),
		maxSlotAge:        75 * time.Second,
		stickyMaxDrainAge: DefaultStickyMaxDrainAge,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	for i := 0; i < 8; i++ {
		p.slotDeaths.Record(slotobs.Observation{AgeMs: 85_000, CloseKind: "close_other"})
	}
	for i := 0; i < 740; i++ {
		p.slotDeaths.RecordPlanned(slotobs.Observation{AgeMs: 75_000})
	}

	logSlotDeathSummary()
	out := buf.String()

	// Две доли раздельно: несмещённая по пожизненным счётчикам и смещённая по
	// содержимому рингов. Под одним именем `cut_share` их путали (ревью
	// 2026-08-12): 8/748=0.0107 не сходилось с показанным 0.0154.
	for _, want := range []string{
		"planned_rotations=740",
		"cut_share_lifetime=0.0107",
		"cut_share_ring=0.0154",
		"cut_share_ring_denom=520",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в строке нехватки данных нет %q:\n%s", want, out)
		}
	}
}

// Рост числа плановых ротаций обязан пробивать дроссель: именно это число
// объясняет, почему резов мало. Иначе знаменатель растёт молча.
func TestSlotDeathGate_PlannedGrowthBreaksThrottle(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(512),
		maxSlotAge:        75 * time.Second,
		stickyMaxDrainAge: DefaultStickyMaxDrainAge,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	for i := 0; i < 8; i++ {
		p.slotDeaths.Record(slotobs.Observation{AgeMs: 85_000, CloseKind: "close_other"})
	}
	logSlotDeathSummary()

	// Ещё сотня плановых при тех же 8 резах — состояние изменилось.
	buf.Reset()
	for i := 0; i < 100; i++ {
		p.slotDeaths.RecordPlanned(slotobs.Observation{AgeMs: 75_000})
	}
	logSlotDeathSummary()
	if !strings.Contains(buf.String(), "slot death observability") {
		t.Error("рост плановых не пробил дроссель — знаменатель растёт молча")
	}

	// Но единичная плановая внутри той же сотни — не повод печатать снова.
	buf.Reset()
	p.slotDeaths.RecordPlanned(slotobs.Observation{AgeMs: 75_000})
	logSlotDeathSummary()
	if strings.Contains(buf.String(), "slot death observability") {
		t.Error("печать на каждую плановую ротацию — вернулся шум")
	}
}

// Адаптер получает наблюдение и при достаточной выборке — то есть разделение
// гейтов не сломало нормальный путь.
func TestSlotDeathGate_AboveThresholdStillAdapts(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(64),
		maxSlotAge:        75 * time.Second,
		stickyMaxDrainAge: DefaultStickyMaxDrainAge,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	ages := []int64{85275, 88073, 88844, 92333, 99664, 100281, 104410, 106583,
		106675, 110838, 112992, 114056}
	vols := []int64{0, 162, 13365, 12880, 1710253, 9896, 5230692, 10333620,
		10946, 11583, 79708, 339834}
	for i := range ages {
		p.slotDeaths.Record(slotobs.Observation{
			AgeMs: ages[i], DownBytes: vols[i], CloseKind: "close_other",
		})
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	logSlotDeathSummary()
	out := buf.String()

	if !strings.Contains(out, "slot death distribution") {
		t.Fatalf("сводка не залогирована при достаточной выборке:\n%s", out)
	}
	if !strings.Contains(out, "slot death inference") {
		t.Fatalf("вывод порога не залогирован при достаточной выборке:\n%s", out)
	}
	// При достаточной выборке строка нехватки данных не нужна — иначе шум.
	if strings.Contains(out, "slot death observability") {
		t.Errorf("строка нехватки данных напечатана при достаточной выборке:\n%s", out)
	}
}

// Пул без адаптера не должен ронять stats-логгер.
//
// Adapter.Observe/Stats/Threshold nil-safe по коду (adapt.go), но защита не была
// засторожена, а &WSPoolTransport{} с ageAdapter==nil в тестах уже живёт
// (slot_death_metrics_test.go). Ревью 2026-08-12: nil-safety держалась только на
// чтении adapt.go.
func TestSlotDeathGate_NilAdapterDoesNotPanic(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{slotDeaths: slotobs.NewRecorder(64)} // ageAdapter == nil
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	// Ниже порога — путь через строку нехватки данных.
	p.slotDeaths.Record(slotobs.Observation{AgeMs: 85_000, CloseKind: "close_other"})
	logSlotDeathSummary()

	// И выше порога — полный путь с Observe/Stats.
	for i := 0; i < minSlotDeathSamplesToLog; i++ {
		p.slotDeaths.Record(slotobs.Observation{
			AgeMs: int64(90_000 + i*100), DownBytes: int64(1000 * (i + 1) * (i + 1)),
			CloseKind: "close_other",
		})
	}
	logSlotDeathSummary()
}

// Адаптер должен получать Observe даже когда инференс вернул AxisUnknown:
// Observe на AxisUnknown сбрасывает счётчик подтверждений, и пропуск вызова
// оставил бы кандидата «подвешенным» между прогонами.
func TestSlotDeathGate_AdapterObservesOnUnknownAxis(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(64),
		maxSlotAge:        75 * time.Second,
		stickyMaxDrainAge: DefaultStickyMaxDrainAge,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	// Мало данных → AxisUnknown. Вызов не должен паниковать и должен оставить
	// порог конфигурационным.
	for i := 0; i < 3; i++ {
		p.slotDeaths.Record(slotobs.Observation{AgeMs: 85_000, CloseKind: "close_other"})
	}
	logSlotDeathSummary()

	applied, configured, changes, _ := p.ageAdapter.Stats()
	if applied != configured {
		t.Errorf("порог сдвинут при недостаточных данных: applied=%v configured=%v", applied, configured)
	}
	if changes != 0 {
		t.Errorf("changes=%d при недостаточных данных, ожидался 0", changes)
	}
}

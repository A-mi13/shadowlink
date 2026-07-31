package client

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client/slotobs"
)

// Раунд 18 P0 (переформулирован 2026-07-31): экспорт распределения смертей слотов.
//
// Существующие счётчики (age_cut_reconnects_total и др.) отвечают «сколько раз»,
// но не «где порог». Порог сейчас — константа (ageCutMinAgeMs / MaxSlotAge), не
// подтверждённая ни одним источником; см. client/slotobs и FIELD-CHECKS.md §2.

// Пустая выборка не должна ломать scrape — метрики обязаны быть с нулями.
func TestSlotDeathMetrics_EmptyIsScrapeable(t *testing.T) {
	SetGlobalPoolForStats(nil)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	var buf bytes.Buffer
	emitSlotDeathDistribution(&buf)
	out := buf.String()

	for _, want := range []string{
		"shadowlink_slot_death_samples 0",
		`shadowlink_slot_death_age_ms{quantile="0.1"} 0`,
		`shadowlink_slot_death_cv{axis="age"} 0.000000`,
		`shadowlink_slot_death_cv{axis="down_bytes"} 0.000000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("вывод не содержит %q\n%s", want, out)
		}
	}
	// NaN/Inf в выводе сломали бы парсер Prometheus.
	if strings.Contains(out, "NaN") || strings.Contains(out, "Inf") {
		t.Errorf("вывод содержит NaN/Inf:\n%s", out)
	}
}

// С данными: перцентили и CV должны попадать в вывод.
func TestSlotDeathMetrics_ReportsDistribution(t *testing.T) {
	p := &WSPoolTransport{slotDeaths: slotobs.NewRecorder(64)}
	// Рез по возрасту: возраст кластеризован, объём разбросан.
	ages := []int64{129_000, 130_500, 131_000, 129_800}
	vols := []int64{2 << 10, 900 << 10, 40 << 10, 5 << 20}
	for i := range ages {
		p.slotDeaths.Record(slotobs.Observation{
			AgeMs:     ages[i],
			DownBytes: vols[i],
			CloseKind: "close_other",
		})
	}

	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	var buf bytes.Buffer
	emitSlotDeathDistribution(&buf)
	out := buf.String()

	if !strings.Contains(out, "shadowlink_slot_death_samples 4") {
		t.Errorf("не отражено число образцов:\n%s", out)
	}
	if !strings.Contains(out, `shadowlink_slot_death_by_close_kind{kind="close_other"} 4`) {
		t.Errorf("не отражена разбивка по close_kind:\n%s", out)
	}
	// Возрастной CV должен быть много меньше байтового — это и есть сигнал оси.
	if !strings.Contains(out, `shadowlink_slot_death_cv{axis="age"} 0.00`) {
		t.Errorf("ожидался низкий CV по возрасту:\n%s", out)
	}
	if strings.Contains(out, "NaN") || strings.Contains(out, "Inf") {
		t.Errorf("вывод содержит NaN/Inf:\n%s", out)
	}
}

// Порядок меток close_kind должен быть детерминированным: карта в Go
// итерируется случайно, а нестабильный порядок строк ломает diff'ы и пин
// alert-правил на список серий.
func TestSlotDeathMetrics_StableLabelOrder(t *testing.T) {
	p := &WSPoolTransport{slotDeaths: slotobs.NewRecorder(16)}
	for _, k := range []string{"close_other", "reset_by_peer", "io_timeout", "eof"} {
		p.slotDeaths.Record(slotobs.Observation{CloseKind: k})
	}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	var first bytes.Buffer
	emitSlotDeathDistribution(&first)
	for i := 0; i < 5; i++ {
		var next bytes.Buffer
		emitSlotDeathDistribution(&next)
		if next.String() != first.String() {
			t.Fatal("порядок строк нестабилен между вызовами")
		}
	}

	// Все метки словаря должны присутствовать, даже нулевые: иначе серия
	// «пропадает» из scrape и график рвётся.
	out := first.String()
	for _, kind := range frameAnomalyReasons {
		if !strings.Contains(out, `kind="`+kind+`"`) {
			t.Errorf("метка kind=%q отсутствует в выводе", kind)
		}
	}
}

// Полный экспортёр должен включать новые серии (проверяем интеграцию, а не
// только сам хелпер).
func TestSlotDeathMetrics_WiredIntoExporter(t *testing.T) {
	p := &WSPoolTransport{slotDeaths: slotobs.NewRecorder(8)}
	p.slotDeaths.Record(slotobs.Observation{AgeMs: 130_000, DownBytes: 18_000, CloseKind: "reset_by_peer"})
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	var buf bytes.Buffer
	WritePromMetrics(&buf)
	out := buf.String()

	for _, want := range []string{
		"shadowlink_slot_death_samples",
		"shadowlink_slot_death_age_ms",
		"shadowlink_slot_death_down_bytes",
		"shadowlink_slot_death_cv",
		"shadowlink_slot_death_by_close_kind",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("экспортёр не отдаёт серию %q", want)
		}
	}
}

// Сторож: запись наблюдения должна стоять в точке смерти слота, рядом с тем же
// лог-сайтом, откуда берутся значения.
//
// Реальный reader-цикл требует живого WS-соединения, поэтому unit-тестом его не
// покрыть; без сторожа удаление вызова (или его отрыв от источника данных) прошло
// бы незамеченным — метрики просто остались бы нулевыми, и это выглядело бы как
// «обрывов нет», а не как «мы перестали их считать». Худший вид тихого отказа
// для диагностической подсистемы.
func TestSlotDeathMetrics_RecordWiredAtDeathSite(t *testing.T) {
	src, err := os.ReadFile("ws_pool.go")
	if err != nil {
		t.Fatalf("не прочитан ws_pool.go: %v", err)
	}
	code := string(src)

	if !strings.Contains(code, "p.slotDeaths.Record(slotobs.Observation{") {
		t.Fatal("ws_pool.go не записывает наблюдения — телеметрия смерти слота отключена")
	}

	// Вызов должен использовать те же поля, что и лог-строка рядом: если он
	// начнёт брать данные из другого места, наблюдения разойдутся с логами и
	// сверять их станет нельзя.
	idx := strings.Index(code, "p.slotDeaths.Record(slotobs.Observation{")
	block := code[idx:min(idx+400, len(code))]
	for _, field := range []string{
		"AgeMs:          slotAgeMs",
		"DownBytes:      slot.downBytes.Load()",
		"LastWriteAgeMs: lastWriteAgeMs",
		"CloseKind:      anomaly",
	} {
		if !strings.Contains(block, field) {
			t.Errorf("наблюдение не заполняет %q из локального контекста смерти", field)
		}
	}

	// И оно должно стоять ПОСЛЕ лог-строки, то есть в той же ветке терминальной
	// ошибки, а не где-то ещё.
	logIdx := strings.Index(code, `p.log.Warn("WS pool slot reader error"`)
	if logIdx < 0 {
		t.Fatal("не найден лог-сайт смерти слота — изменилась структура, сверьте сторож")
	}
	if idx < logIdx {
		t.Error("запись наблюдения стоит ВНЕ ветки терминальной ошибки reader'а")
	}
}

// Лог-канал: на клиенте Prometheus-экспортёр недостижим (WritePromMetrics не
// вызывается нигде в cmd/, линковщик его выбрасывает, endpoint'а нет), поэтому
// сводка обязана попадать в лог — иначе рекордер собирает данные, которые никто
// не может прочитать.
func TestSlotDeathSummary_LoggedViaStatsLogger(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{slotDeaths: slotobs.NewRecorder(64)}
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	// Ниже порога — тишина: на паре образцов CV это шум, а печать пригласила бы
	// считать порог по двум точкам.
	for i := 0; i < minSlotDeathSamplesToLog-1; i++ {
		p.slotDeaths.Record(slotobs.Observation{AgeMs: 130_000, DownBytes: 20_000, CloseKind: "close_other"})
	}
	logSlotDeathSummary()
	if strings.Contains(buf.String(), "slot death distribution") {
		t.Errorf("сводка залогирована при %d образцах (порог %d)",
			minSlotDeathSamplesToLog-1, minSlotDeathSamplesToLog)
	}

	// Добираем до порога — должна появиться, с определённой осью.
	ages := []int64{129_000, 130_500, 131_000, 129_800}
	vols := []int64{2 << 10, 900 << 10, 40 << 10, 5 << 20}
	for i := 0; i < 4; i++ {
		p.slotDeaths.Record(slotobs.Observation{
			AgeMs: ages[i], DownBytes: vols[i], CloseKind: "close_other",
		})
	}
	buf.Reset()
	logSlotDeathSummary()
	out := buf.String()

	if !strings.Contains(out, "slot death distribution") {
		t.Fatalf("сводка не залогирована при достаточной выборке:\n%s", out)
	}
	for _, want := range []string{"age_p50_ms", "down_p50_kb", "cv_age", "cv_down_bytes", "tighter_axis"} {
		if !strings.Contains(out, want) {
			t.Errorf("в лог-строке нет поля %q:\n%s", want, out)
		}
	}
	// Возраст кластеризован → ось должна определиться как age.
	if !strings.Contains(out, "tighter_axis=age") {
		t.Errorf("ожидалось tighter_axis=age при кластеризованном возрасте:\n%s", out)
	}
}

// Строка вывода порога должна нести И выведенное значение, И фактически
// применённое — иначе по логу нельзя понять, адаптировался клиент или нет.
//
// До шага 3 строка помечалась «advisory, not applied»; после того как
// автоприменение появилось, эта пометка стала бы ложью, поэтому тест требует
// именно пару applied/configured.
func TestSlotDeathSummary_LogsInferenceAdvisory(t *testing.T) {
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
	// Полевой профиль: возраст кластеризован, объём разбросан → ось age.
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

	if !strings.Contains(out, "slot death inference") {
		t.Fatalf("строка вывода порога отсутствует:\n%s", out)
	}
	for _, want := range []string{
		"axis=age", "samples_used=12", "reason=",
		"applied_max_slot_age=", "configured_max_slot_age=", "worst_case_teardown=",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в строке вывода нет %q:\n%s", want, out)
		}
	}
}

// Без пула логгер не должен паниковать и не должен ничего писать.
func TestSlotDeathSummary_NoPoolSilent(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	SetGlobalPoolForStats(nil)
	logSlotDeathSummary()
	if buf.Len() != 0 {
		t.Errorf("без пула не должно быть вывода:\n%s", buf.String())
	}
}

// Пул без рекордера (например, собранный в старом тесте) не должен паниковать.
func TestSlotDeathMetrics_NilRecorderSafe(t *testing.T) {
	p := &WSPoolTransport{} // slotDeaths == nil
	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	var buf bytes.Buffer
	emitSlotDeathDistribution(&buf)
	if !strings.Contains(buf.String(), "shadowlink_slot_death_samples 0") {
		t.Errorf("nil-рекордер должен давать нули:\n%s", buf.String())
	}
}

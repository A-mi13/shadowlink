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

	for _, want := range []string{"planned_rotations=740", "cut_share="} {
		if !strings.Contains(out, want) {
			t.Errorf("в строке нехватки данных нет %q:\n%s", want, out)
		}
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

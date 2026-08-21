package main

import (
	"math"
	"testing"
)

// Величины проверяются против аналитически известных ответов, а не против
// «того, что вернул код» — иначе тест фиксирует баг вместо контракта.
//
// Опорные значения:
//   - идеальная решётка (все события в одной фазе) → R = 1
//   - равномерная фаза → R ~ 1/sqrt(n) (шум), заведомо < 0.2
//
// 0.2 — критерий из CLAUDE.md (hard rule 9): «критерий фазы — R < 0.2 на
// периоде тика, а НЕ доля в модальном окне сетки».
func TestVectorStrength_PerfectGridIsOne(t *testing.T) {
	// 200 событий строго кратны периоду 0.5 с → фаза всегда 0.
	var ts []float64
	for i := 0; i < 200; i++ {
		ts = append(ts, float64(i)*0.5)
	}
	got := vectorStrength(ts, 0.5)
	if math.Abs(got-1.0) > 1e-9 {
		t.Fatalf("идеальная решётка: R = %.6f, ожидалось 1.0", got)
	}
}

func TestVectorStrength_UniformPhaseIsNoise(t *testing.T) {
	// Равномерно размазанная фаза: 1000 событий с шагом, несоизмеримым
	// с периодом. R должен упасть до уровня шума и пройти критерий 0.2.
	const n = 1000
	var ts []float64
	for i := 0; i < n; i++ {
		ts = append(ts, float64(i)*0.31830988618) // 1/pi — иррациональный шаг
	}
	got := vectorStrength(ts, 0.5)
	noise := 1.0 / math.Sqrt(n)
	if got > 0.2 {
		t.Fatalf("равномерная фаза: R = %.4f, критерий R < 0.2 не выполнен", got)
	}
	// Не требуем точного равенства шуму — требуем тот же порядок.
	if got > 10*noise {
		t.Fatalf("равномерная фаза: R = %.4f превышает 10x шум (%.4f)", got, noise)
	}
}

// Решётка, размазанная лишь ЧАСТИЧНО, — тот случай, который метод обязан
// поймать. Если доля привязанных событий велика, R обязан вылезти за критерий.
func TestVectorStrength_PartialGridIsDetected(t *testing.T) {
	// 50 % событий жёстко на сетке, 50 % — равномерно.
	var ts []float64
	for i := 0; i < 500; i++ {
		ts = append(ts, float64(i)*0.5) // на сетке
	}
	for i := 0; i < 500; i++ {
		ts = append(ts, float64(i)*0.31830988618) // размазаны
	}
	got := vectorStrength(ts, 0.5)
	if got < 0.2 {
		t.Fatalf("частичная решётка (50%%): R = %.4f, метод её не увидел", got)
	}
}

// Период, не равный истинному, не должен давать ложную линию.
func TestVectorStrength_WrongPeriodShowsNoLine(t *testing.T) {
	var ts []float64
	for i := 0; i < 1000; i++ {
		ts = append(ts, float64(i)*0.5)
	}
	// Ищем на 0.31 с решётку, которой там нет.
	got := vectorStrength(ts, 0.31)
	if got > 0.2 {
		t.Fatalf("несуществующая линия на 0.31 с: R = %.4f", got)
	}
}

func TestVectorStrength_EmptyAndSingle(t *testing.T) {
	if got := vectorStrength(nil, 0.5); got != 0 {
		t.Fatalf("пустая выборка: R = %v, ожидался 0", got)
	}
	// Одно событие даёт R = 1 математически, но это артефакт n=1, а не
	// решётка. Функция обязана вернуть 0, чтобы вывод не строился на n=1.
	if got := vectorStrength([]float64{1.234}, 0.5); got != 0 {
		t.Fatalf("n=1: R = %v, ожидался 0 (вывод на одном событии невозможен)", got)
	}
}

// Слепой скан обязан ОБНАРУЖИВАТЬ решётку. Но период, который он вернёт, —
// не обязательно истинный: сетка 0.5 с лежит также на сетке 0.25, 0.125,
// 0.1, 0.05 с (любой делитель), и R там тоже строго 1.0 — проверено
// аналитически. Поэтому утверждать можно только «линия есть», а величину
// периода надо читать как «истинный период кратен найденному».
func TestScanPeriods_FindsTrueGrid(t *testing.T) {
	var ts []float64
	for i := 0; i < 400; i++ {
		ts = append(ts, float64(i)*0.5)
	}
	best := scanPeriods(ts, 0.05, 2.0, 0.005)
	if best.R < 0.9 {
		t.Fatalf("скан не нашёл решётку: max R = %.4f при period = %.3f", best.R, best.Period)
	}
	// Найденный период обязан быть делителем истинного 0.5 с (с точностью
	// до шага сетки скана), иначе это ложная линия.
	ratio := 0.5 / best.Period
	if math.Abs(ratio-math.Round(ratio)) > 1e-6 {
		t.Fatalf("скан нашёл период %.3f — не делитель истинных 0.5 с (0.5/p = %.4f)",
			best.Period, ratio)
	}
}

// Кратность в обратную сторону: на периоде БОЛЬШЕ истинного линии быть не
// должно (сетка 0.5 с не лежит на сетке 1.0 с). Это отделяет делители от
// произвольных периодов и не даёт читать любой высокий R как решётку.
func TestVectorStrength_MultipleOfGridShowsNoLine(t *testing.T) {
	var ts []float64
	for i := 0; i < 400; i++ {
		ts = append(ts, float64(i)*0.5)
	}
	if got := vectorStrength(ts, 1.0); got > 0.2 {
		t.Fatalf("на периоде 1.0 с (кратном 0.5) R = %.4f, ожидалось отсутствие линии", got)
	}
}

func TestScanPeriods_NoLineOnUniform(t *testing.T) {
	const n = 2000
	var ts []float64
	for i := 0; i < n; i++ {
		ts = append(ts, float64(i)*0.31830988618)
	}
	best := scanPeriods(ts, 0.05, 2.0, 0.005)
	// На равномерной выборке максимум скана — шум. Порог 0.2 (критерий) с
	// запасом: скан по многим периодам сам поднимает максимум.
	if best.R > 0.2 {
		t.Fatalf("ложная линия на равномерной выборке: R = %.4f @ %.3f с", best.R, best.Period)
	}
}

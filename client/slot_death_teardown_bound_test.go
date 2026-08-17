package client

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client/slotobs"
)

// Сторожа для верхней границы правдоподобия наблюдения (прогон 2026-08-17).
//
// Задача границы разобрана в slotobs/infer.go (InferWithMinAgeAndTeardown) и в
// slotobs/infer_upper_bound_test.go. Здесь проверяется КЛИЕНТСКАЯ половина: что
// граница действительно берётся из worstCaseTeardown, а не из константы по месту,
// и что отбраковка ВИДНА в логе.

// Граница обязана приходить из worstCaseTeardown() — единственного источника
// истины о бюджете (hard rule 8).
//
// Тест сравнивает inferTeardownBoundMs с суммой, которую возвращает
// worstCaseTeardown, и делает это на ДВУХ разных конфигурациях: совпадение на
// одной могло бы оказаться случайным (ровно так лог однажды печатал
// `adaptedAge + stickyMaxDrainAge` и был прав по совпадению при hard_cap==sticky).
func TestInferTeardownBound_ComesFromWorstCaseTeardown(t *testing.T) {
	for _, tc := range []struct {
		name string
		pool *WSPoolTransport
	}{
		{
			name: "прод-подобная конфигурация",
			pool: &WSPoolTransport{
				maxSlotAge:        70 * time.Second,
				stickyMaxDrainAge: 25 * time.Second,
				drainHardCap:      15 * time.Second,
				gracefulDrain:     true,
				staggerStep:       time.Second,
				staggerOffsetCap:  15 * time.Second,
				poolSize:          8,
				ageAdapter:        slotobs.NewAdapter(70 * time.Second),
			},
		},
		{
			name: "иные слагаемые: другой sticky и порог",
			pool: &WSPoolTransport{
				maxSlotAge:        50 * time.Second,
				stickyMaxDrainAge: 40 * time.Second,
				drainHardCap:      20 * time.Second,
				gracefulDrain:     true,
				staggerStep:       2 * time.Second,
				staggerOffsetCap:  10 * time.Second,
				poolSize:          4,
				ageAdapter:        slotobs.NewAdapter(50 * time.Second),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, _, total := tc.pool.worstCaseTeardown()
			if got, want := tc.pool.inferTeardownBoundMs(), total.Milliseconds(); got != want {
				t.Errorf("inferTeardownBoundMs = %d, worstCaseTeardown = %d — "+
					"граница считается не из единственного источника истины, и при "+
					"правке любого слагаемого разъедется молча", got, want)
			}
		})
	}
}

// Без gracefulDrain граница ОБЯЗАНА быть выключена.
//
// Условие применимости, а не перестраховка: в legacy-ветке worstCaseTeardown не
// содержит `deferred` и `tear` (в проде 30+25 = 55 с, 39 % бюджета), потому что
// дренажа нет вовсе. Бюджет тогда описывает «порог + stagger + свип», и граница из
// него оказывается УЖЕ наблюдаемых резов: на конфигурации 75 + 7.5 + 2 = 84.5 с она
// отбраковала бы весь полевой профиль 85.3–114.1 с, то есть выбросила бы
// единственный реальный сигнал о цензоре.
//
// Дефект был найден прогоном (TestSlotDeathSummary_LogsInferenceAdvisory
// покраснел), а не предположен, — поэтому тест сторожит именно его.
func TestInferTeardownBound_DisabledWithoutGracefulDrain(t *testing.T) {
	p := &WSPoolTransport{
		maxSlotAge:        75 * time.Second,
		stickyMaxDrainAge: 25 * time.Second,
		drainHardCap:      15 * time.Second,
		gracefulDrain:     false, // legacy hard-rotation
		staggerStep:       time.Second,
		staggerOffsetCap:  15 * time.Second,
		poolSize:          8,
		ageAdapter:        slotobs.NewAdapter(75 * time.Second),
	}
	if got := p.inferTeardownBoundMs(); got != 0 {
		t.Errorf("inferTeardownBoundMs = %d при gracefulDrain=false, ожидался 0 — "+
			"бюджет без дренажа не содержит teardown-слагаемых и как граница "+
			"отбраковал бы настоящие резы", got)
	}

	// Симметрия: с дренажом граница действует.
	p.gracefulDrain = true
	if got := p.inferTeardownBoundMs(); got <= 0 {
		t.Errorf("inferTeardownBoundMs = %d при gracefulDrain=true, ожидалось > 0 — "+
			"в проде граница обязана действовать", got)
	}
}

// Отбраковка по верхней границе ОБЯЗАНА быть напечатана.
//
// Молчаливая отбраковка — это исчезновение наблюдений из samples_used без
// объяснения, то есть ровно дефект «лог врёт о механизме», который в проекте
// ловили многократно. Счётчик стоит в той же строке, что rejected_zero_age /
// rejected_timeout / rejected_too_young / rejected_planned.
func TestSlotDeathInference_LogsAboveTeardownRejection(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := &WSPoolTransport{
		slotDeaths:        slotobs.NewRecorder(64),
		maxSlotAge:        70 * time.Second,
		stickyMaxDrainAge: 25 * time.Second,
		drainHardCap:      15 * time.Second,
		gracefulDrain:     true,
		staggerStep:       time.Second,
		staggerOffsetCap:  15 * time.Second,
		poolSize:          8,
		ageCutMinAge:      45 * time.Second,
		ageAdapter:        slotobs.NewAdapter(70 * time.Second),
	}

	// Чистые резы прогона 08-17 плюс наблюдения окна заморозки вывода.
	clean := []int64{84109, 85002, 85383, 85678, 87378, 87940, 89928, 90256,
		97902, 108881, 91400, 95600}
	for i, a := range clean {
		p.slotDeaths.Record(slotobs.Observation{
			AgeMs: a, DownBytes: int64(i*900_000 + 2611), CloseKind: "close_other",
		})
	}
	frozen := []int64{177110, 209460, 293176}
	for i, a := range frozen {
		p.slotDeaths.Record(slotobs.Observation{
			AgeMs: a, DownBytes: int64(i*40_000 + 44742), CloseKind: "close_other",
		})
	}

	SetGlobalPoolForStats(p)
	t.Cleanup(func() { SetGlobalPoolForStats(nil) })

	logSlotDeathSummary()
	out := buf.String()

	if !strings.Contains(out, "slot death inference") {
		t.Fatalf("строка вывода порога отсутствует:\n%s", out)
	}
	if !strings.Contains(out, "rejected_above_teardown=3") {
		t.Errorf("в строке нет rejected_above_teardown=3 — отбраковка молчаливая, "+
			"и разницу между samples в сводке и samples_used объяснить нечем:\n%s", out)
	}
	// Сама граница тоже печатается: без неё читатель не может проверить, ПОЧЕМУ
	// отбраковано именно столько.
	if !strings.Contains(out, "teardown_bound=") {
		t.Errorf("в строке нет teardown_bound= — величину границы не с чем сверить:\n%s", out)
	}
	// И чистые наблюдения должны остаться: граница не имеет права съедать резы.
	if !strings.Contains(out, "samples_used=12") {
		t.Errorf("samples_used != 12 — граница задела чистые наблюдения:\n%s", out)
	}
}

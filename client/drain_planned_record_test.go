package client

import (
	"os"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/client/slotobs"
)

// Плановые ротации обязаны попадать в slotobs — иначе выборка остаётся
// цензурированной, а знаменателя для доли «срезано посредником» не существует
// (2026-08-12).
//
// Сторож на ИСХОДНЫЙ КОД, а не на поведение: поднять полный дренаж в unit-тесте
// значит поднять пул, клиент, сокеты и watchdog-горутины — тест был бы
// таймингозависимым, а такие в этом репозитории исторически флейкуют под
// -shuffle (см. skill testing-rules). Проверяемое утверждение здесь
// структурное: «в tearDown есть вызов RecordPlanned», и статическая проверка
// отвечает на него точно.
//
// Конвенция такого сторожа уже применяется в slot_death_metrics_test.go
// (TestSlotDeathRecord_AtReaderErrorSite).
func TestDrainPlanned_RecordedInTearDown(t *testing.T) {
	src, err := os.ReadFile("ws_pool_drain.go")
	if err != nil {
		t.Fatalf("не прочитан ws_pool_drain.go: %v", err)
	}
	code := string(src)

	idx := strings.Index(code, "tearDown := func(cause finishCause)")
	if idx < 0 {
		t.Fatal("не найден tearDown в drainWatchdog — тест устарел, обновить якорь")
	}
	// Границей берём вызов handleSlotDeath: им заканчивается tearDown.
	end := strings.Index(code[idx:], "p.handleSlotDeath(cl, oldIdx, deathCauseDrainTeardown)")
	if end < 0 {
		t.Fatal("не найден конец tearDown (handleSlotDeath) — тест устарел")
	}
	body := code[idx : idx+end]

	if !strings.Contains(body, "RecordPlanned(") {
		t.Error("tearDown не пишет плановую ротацию в slotobs: выборка останется " +
			"цензурированной, а cut_share — невыводимым")
	}
	// Ринг резов трогать нельзя: попадание плановой в Record отравило бы
	// перцентили и вывод порога.
	if strings.Contains(body, "slotDeaths.Record(") {
		t.Error("tearDown пишет в РИНГ РЕЗОВ (Record вместо RecordPlanned) — " +
			"порог был бы выведен из нашего же порога")
	}
	// Возраст обязателен: без него наблюдение не даёт ни знаменателя для
	// hazard-полосы, ни вклада в cut_share по возрастной оси.
	if !strings.Contains(body, "startedAtNs") {
		t.Error("в плановом наблюдении нет возраста слота (startedAtNs) — " +
			"hazard-кривую посчитать нельзя")
	}
}

// Фантомный дренаж — НЕ плановая ротация в смысле наблюдаемости: слот порван
// нами по расхождению счётчика, но и не срезан посредником. Он должен попадать
// в плановые (мы инициировали разрыв), а НЕ в резы.
//
// Проверяем, что вызов стоит на общем пути tearDown, а не под конкретной
// причиной — иначе часть путей выхода потеряется молча.
func TestDrainPlanned_RecordOnCommonPath(t *testing.T) {
	src, err := os.ReadFile("ws_pool_drain.go")
	if err != nil {
		t.Fatalf("не прочитан ws_pool_drain.go: %v", err)
	}
	code := string(src)

	idx := strings.Index(code, "tearDown := func(cause finishCause)")
	if idx < 0 {
		t.Fatal("не найден tearDown — тест устарел")
	}
	end := strings.Index(code[idx:], "p.handleSlotDeath(cl, oldIdx, deathCauseDrainTeardown)")
	if end < 0 {
		t.Fatal("не найден конец tearDown — тест устарел")
	}
	body := code[idx : idx+end]

	rec := strings.Index(body, "RecordPlanned(")
	if rec < 0 {
		t.Fatal("RecordPlanned отсутствует (покрыто соседним тестом)")
	}
	// switch по cause заканчивается на закрывающей скобке перед
	// DrainDurationSeconds — вызов должен быть ПОСЛЕ него, на общем пути.
	common := strings.Index(body, "Stats.DrainDurationSeconds.Observe")
	if common < 0 {
		t.Fatal("не найден общий путь (DrainDurationSeconds) — тест устарел")
	}
	if rec < common {
		t.Error("RecordPlanned вызывается внутри switch по причине — часть путей " +
			"выхода (sticky/phantom/hard cap) не попадёт в выборку")
	}
}

// Живая проверка самого рекордера на данных, повторяющих полевое соотношение:
// 740 плановых против 8 резов не должны вытеснить резы (это уже покрыто в
// slotobs, здесь — что клиентский код видит те же величины).
func TestDrainPlanned_FieldRatioKeepsCuts(t *testing.T) {
	r := slotobs.NewRecorder(512)
	for i := 0; i < 8; i++ {
		r.Record(slotobs.Observation{AgeMs: 85_000, CloseKind: "close_other"})
	}
	for i := 0; i < 740; i++ {
		r.RecordPlanned(slotobs.Observation{AgeMs: 75_000})
	}
	if got := r.Len(); got != 8 {
		t.Fatalf("резы вытеснены: Len()=%d, ожидалось 8", got)
	}
	// CutShare считает по СОДЕРЖИМОМУ рингов, а 740 плановых в ринг на 512 не
	// влезают — 228 самых старых затёрты. Это документированное ограничение
	// (см. докстринг CutShare), и оно смещает долю в сторону более редкого
	// события: 8/(8+512) = 1.54% против истинных 8/748 = 1.07%.
	share, total := r.CutShare()
	if total != 520 {
		t.Fatalf("знаменатель cut_share=%d, ожидалось 520 (8 резов + ёмкость ринга 512)", total)
	}
	if share < 0.015 || share > 0.016 {
		t.Fatalf("cut_share=%.4f, ожидалось ~0.0154", share)
	}

	// Абсолютный счёт не забывает — именно его надо брать для доли за прогон.
	if got := r.TotalPlanned(); got != 740 {
		t.Fatalf("TotalPlanned()=%d, ожидалось 740", got)
	}
	if got := r.Total(); got != 8 {
		t.Fatalf("Total()=%d, ожидалось 8", got)
	}
	trueShare := float64(r.Total()) / float64(r.Total()+r.TotalPlanned())
	if trueShare < 0.010 || trueShare > 0.011 {
		t.Fatalf("истинная доля по Total*=%.4f, ожидалось ~0.0107", trueShare)
	}
}

package slotobs

import (
	"testing"
	"time"
)

// ageVerdict — вердикт с осью возраста и заданным порогом.
func ageVerdict(threshold time.Duration) Verdict {
	return Verdict{
		Axis:      AxisAge,
		Threshold: Threshold{Age: threshold},
		Samples:   50,
		Reason:    "тест",
	}
}

// Порог не меняется до накопления подтверждений: одна выборка — не причина
// менять поведение (смена сети, разовый сбой оператора).
func TestAdapter_RequiresConfirmations(t *testing.T) {
	a := NewAdapter(75 * time.Second)

	for i := 1; i < adaptConfirmations; i++ {
		if a.Observe(ageVerdict(66 * time.Second)) {
			t.Fatalf("порог изменён после %d подтверждений, нужно %d", i, adaptConfirmations)
		}
		if got := a.Threshold(); got != 75*time.Second {
			t.Fatalf("порог %v до подтверждения, ожидался 75s", got)
		}
	}
	if !a.Observe(ageVerdict(66 * time.Second)) {
		t.Fatal("порог не изменился после достаточных подтверждений")
	}
	if got := a.Threshold(); got != 66*time.Second {
		t.Errorf("порог %v, ожидался 66s", got)
	}
}

// Полевые данные: три прогона дали 70.5 / 69.1 / 66.3 s. Адаптер должен принять
// сжатие и не выйти за потолок.
func TestAdapter_FieldMeasurements(t *testing.T) {
	a := NewAdapter(75 * time.Second)
	// Порог из третьего прогона, подтверждённый трижды.
	for range adaptConfirmations {
		a.Observe(ageVerdict(66284 * time.Millisecond))
	}
	got := a.Threshold()
	t.Logf("порог после адаптации: %v (конфиг 75s)", got)

	if got >= 75*time.Second {
		t.Errorf("порог %v не сжался ниже конфигурации", got)
	}
	// Ключевое: worst-case teardown = порог + sticky(15s) должен уйти ниже
	// самой ранней наблюдённой смерти 82.9s.
	worst := got + 15*time.Second
	if worst >= 82900*time.Millisecond {
		t.Errorf("worst-case %v не ниже самой ранней смерти 82.9s — разрыв не закрыт", worst)
	}
	t.Logf("worst-case teardown = %v против самой ранней смерти 82.9s", worst)
}

// АДАПТАЦИЯ ТОЛЬКО СЖИМАЕТ: вывод «можно дольше» не должен поднимать порог
// выше сконфигурированного. Ошибка в эту сторону = попадание под рез.
func TestAdapter_NeverExceedsConfigured(t *testing.T) {
	a := NewAdapter(75 * time.Second)
	for range adaptConfirmations * 3 {
		a.Observe(ageVerdict(300 * time.Second))
	}
	if got := a.Threshold(); got != 75*time.Second {
		t.Errorf("порог %v превысил конфигурацию 75s", got)
	}
}

// Пол: ниже minAdaptiveAge не опускаемся — частая ротация сама становится
// сигналом для counting-детектора (⚠ источник не найден, сверка 2026-08-07 —
// см. комментарий к Adapter в adapt.go).
func TestAdapter_RespectsFloor(t *testing.T) {
	a := NewAdapter(75 * time.Second)
	for range adaptConfirmations * 2 {
		a.Observe(ageVerdict(2 * time.Second))
	}
	if got := a.Threshold(); got != minAdaptiveAge {
		t.Errorf("порог %v ниже пола %v", got, minAdaptiveAge)
	}
}

// Гистерезис: сжатие сразу, расширение малым шагом.
func TestAdapter_HysteresisAsymmetric(t *testing.T) {
	a := NewAdapter(75 * time.Second)

	// Сжатие до 40s — сразу и целиком.
	for range adaptConfirmations {
		a.Observe(ageVerdict(40 * time.Second))
	}
	if got := a.Threshold(); got != 40*time.Second {
		t.Fatalf("сжатие: порог %v, ожидался 40s (сразу и целиком)", got)
	}

	// Расширение до 70s — шагами по releaseStep, не одним прыжком.
	for range adaptConfirmations {
		a.Observe(ageVerdict(70 * time.Second))
	}
	got := a.Threshold()
	if got != 40*time.Second+releaseStep {
		t.Errorf("расширение: порог %v, ожидался шаг %v (одним прыжком нельзя — "+
			"можно проскочить обратно в окно реза)", got, 40*time.Second+releaseStep)
	}
}

// Байтовая ось к порогу по возрасту не применяется: величина не той размерности.
func TestAdapter_IgnoresBytesAxis(t *testing.T) {
	a := NewAdapter(75 * time.Second)
	for range adaptConfirmations * 2 {
		a.Observe(Verdict{Axis: AxisBytes, Threshold: Threshold{Bytes: 18000}, Reason: "байты"})
	}
	if got := a.Threshold(); got != 75*time.Second {
		t.Errorf("порог %v изменён по байтовой оси", got)
	}
}

// AxisUnknown сохраняет текущее поведение — «не знаю» не повод менять порог.
func TestAdapter_UnknownAxisKeepsCurrent(t *testing.T) {
	a := NewAdapter(75 * time.Second)
	for range adaptConfirmations * 2 {
		a.Observe(Verdict{Axis: AxisUnknown, Reason: "мало данных"})
	}
	if got := a.Threshold(); got != 75*time.Second {
		t.Errorf("порог %v изменён при AxisUnknown", got)
	}
}

// Смена кандидата сбрасывает счётчик: дёргающийся вывод не должен накапливаться.
func TestAdapter_ChangingTargetResetsCount(t *testing.T) {
	a := NewAdapter(75 * time.Second)
	a.Observe(ageVerdict(60 * time.Second))
	a.Observe(ageVerdict(50 * time.Second)) // другой кандидат → сброс
	a.Observe(ageVerdict(60 * time.Second)) // снова первый, но счётчик с нуля
	if got := a.Threshold(); got != 75*time.Second {
		t.Errorf("порог %v изменён при неустойчивом выводе", got)
	}
}

// Ротация по возрасту выключена (configured<=0) → адаптер ничего не делает.
func TestAdapter_DisabledWhenRotationOff(t *testing.T) {
	a := NewAdapter(0)
	for range adaptConfirmations * 2 {
		a.Observe(ageVerdict(60 * time.Second))
	}
	if got := a.Threshold(); got != 0 {
		t.Errorf("порог %v при выключенной ротации", got)
	}
}

// nil-приёмник безопасен: пул может быть собран без адаптера.
func TestAdapter_NilSafe(t *testing.T) {
	var a *Adapter
	if got := a.Threshold(); got != 0 {
		t.Errorf("nil-адаптер вернул %v", got)
	}
	if a.Observe(ageVerdict(60 * time.Second)) {
		t.Error("nil-адаптер сообщил об изменении")
	}
	if _, _, _, reason := a.Stats(); reason == "" {
		t.Error("nil-адаптер должен объяснять своё состояние")
	}
}

// Наблюдаемость: Stats обязан объяснять, почему порог такой.
func TestAdapter_StatsExplainState(t *testing.T) {
	a := NewAdapter(75 * time.Second)

	cur, cfg, changes, reason := a.Stats()
	if cur != 75*time.Second || cfg != 75*time.Second || changes != 0 {
		t.Errorf("до адаптации: current=%v configured=%v changes=%d", cur, cfg, changes)
	}
	if reason == "" {
		t.Error("Reason пуст до адаптации — состояние непроверяемо (болезнь H-15)")
	}

	for range adaptConfirmations {
		a.Observe(Verdict{
			Axis:      AxisAge,
			Threshold: Threshold{Age: 66 * time.Second},
			Reason:    "рез по возрасту (CV 0.221 против 2.133)",
		})
	}
	cur, _, changes, reason = a.Stats()
	if cur != 66*time.Second || changes != 1 {
		t.Errorf("после адаптации: current=%v changes=%d", cur, changes)
	}
	if reason != "рез по возрасту (CV 0.221 против 2.133)" {
		t.Errorf("Reason не сохранён: %q", reason)
	}
}

// Округление: порог не должен дрожать на миллисекундах.
func TestAdapter_QuantizesThreshold(t *testing.T) {
	a := NewAdapter(75 * time.Second)
	for range adaptConfirmations {
		a.Observe(ageVerdict(66284 * time.Millisecond))
	}
	got := a.Threshold()
	if got%quantum != 0 {
		t.Errorf("порог %v не округлён до %v", got, quantum)
	}
	if got != 66*time.Second {
		t.Errorf("порог %v, ожидался 66s (округление вниз от 66.284s)", got)
	}
}

// Конкурентность: Observe и Threshold вызываются из разных горутин.
func TestAdapter_ConcurrentAccess(t *testing.T) {
	a := NewAdapter(75 * time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 500 {
			a.Observe(ageVerdict(60 * time.Second))
		}
	}()
	for range 500 {
		_ = a.Threshold()
		_, _, _, _ = a.Stats()
	}
	<-done
}

package client

import (
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client/slotobs"
)

// Бюджет ротации: worst-case teardown обязан считаться ЦЕЛИКОМ.
//
// Почему этот файл существует (полевой разбор 2026-08-07)
//
// stats.go печатал `worst_case_teardown = adaptedAge + stickyMaxDrainAge` и был
// прав только по совпадению: в поле стояли hard_cap == sticky == 15s. Из расчёта
// выпали ДВА слагаемых:
//
//	stagger — slotStaggerOffset прибавляется к порогу в rotationWatchdogSweep
//	          (ws_pool.go), до +cap+step/2. При cap=45s, step=6s это +48s.
//	sweep   — watchdog тикает раз в rotationWatchdogTick, слот ждёт до +5s.
//
// Плюс из двух teardown-пределов брался не тот: дедлайн стоит на drainHardCap.
//
// Цена ошибки: при applied_max_slot_age=69s лог показывал 84s, а реальность для
// ячеек idx 8..15 была 69+45+5+15 = 134s при наблюдаемом p10 смертей 84s. То
// есть 8 ячеек из 16 физически не могли дожить до собственной плановой ротации —
// их рвал посредник, и это выглядело как «TSPU агрессивнее, чем думали», а не
// как арифметическая ошибка у нас.
//
// Класс отказа — H-15: механизм существует, лог о нём рассказывает, но
// рассказывает неправду.

// TestWorstCaseTeardown_IncludesStaggerAndSweep — регрессия на саму формулу.
func TestWorstCaseTeardown_IncludesStaggerAndSweep(t *testing.T) {
	p := &WSPoolTransport{
		poolSize:          8,
		maxSlotAge:        75 * time.Second,
		staggerStep:       6 * time.Second,
		staggerOffsetCap:  45 * time.Second,
		gracefulDrain:     true,
		drainHardCap:      15 * time.Second,
		stickyMaxDrainAge: 15 * time.Second,
	}
	p.slots = make([]*poolSlot, p.poolSize*2)

	base, stagger, sweep, deferred, tear, total := p.worstCaseTeardown()

	if base != 75*time.Second {
		t.Errorf("base = %v, want 75s (адаптер не подключён → сконфигурированный порог)", base)
	}
	// cap=45s + jitter до +step/2=3s.
	if want := 48 * time.Second; stagger != want {
		t.Errorf("stagger = %v, want %v (cap 45s + step/2 3s)", stagger, want)
	}
	if sweep != rotationWatchdogTick {
		t.Errorf("sweep = %v, want %v", sweep, rotationWatchdogTick)
	}
	if tear != 15*time.Second {
		t.Errorf("teardown cap = %v, want 15s", tear)
	}
	// Отсрочка при «no free cell» — 9 таких событий за 11 минут в поле.
	if deferred != drainRevertBackoff {
		t.Errorf("deferred = %v, want %v", deferred, drainRevertBackoff)
	}

	// Ключевое утверждение: сумма НЕ равна наивным base+sticky.
	naive := base + p.stickyMaxDrainAge
	if total == naive {
		t.Fatalf("worst-case %v совпал с наивным base+sticky %v — "+
			"stagger и sweep снова выпали из расчёта", total, naive)
	}
	if want := 75*time.Second + 48*time.Second + 5*time.Second +
		drainRevertBackoff + 15*time.Second; total != want {
		t.Errorf("worst-case = %v, want %v", total, want)
	}
	t.Logf("наивная формула дала бы %v, честная = %v (расхождение %v)",
		naive, total, total-naive)
}

// TestWorstCaseTeardown_UsesAdaptedThreshold — если адаптер сжал порог, бюджет
// обязан считаться от сжатого значения, иначе он завышен и WARN не сработает
// там, где должен.
func TestWorstCaseTeardown_UsesAdaptedThreshold(t *testing.T) {
	p := &WSPoolTransport{
		poolSize:         8,
		maxSlotAge:       75 * time.Second,
		staggerStep:      6 * time.Second,
		staggerOffsetCap: 45 * time.Second,
	}
	p.slots = make([]*poolSlot, p.poolSize*2)
	p.ageAdapter = slotobs.NewAdapter(75 * time.Second)

	base, _, _, _, _, _ := p.worstCaseTeardown()
	if base != 75*time.Second {
		t.Fatalf("без подтверждённого вывода base = %v, want 75s", base)
	}

	// Скармливаем устойчивый вердикт: адаптер требует adaptConfirmations подряд.
	v := slotobs.Verdict{
		Axis:      slotobs.AxisAge,
		Threshold: slotobs.Threshold{Age: 54 * time.Second},
		Reason:    "тестовый вердикт",
	}
	for i := 0; i < 8; i++ {
		p.ageAdapter.Observe(v)
	}

	base2, _, _, _, _, _ := p.worstCaseTeardown()
	if base2 >= 75*time.Second {
		t.Errorf("после сжатия адаптером base = %v, ожидалось меньше 75s", base2)
	}
	t.Logf("base после адаптации: %v", base2)
}

// TestWorstCaseTeardown_TeardownCapPicksLarger — из hard_cap и sticky в бюджет
// должен входить БОЛЬШИЙ, потому что дедлайн стоит на hard_cap, а sticky
// продлевает дренаж только когда он больше.
func TestWorstCaseTeardown_TeardownCapPicksLarger(t *testing.T) {
	cases := []struct {
		name     string
		hardCap  time.Duration
		sticky   time.Duration
		wantTear time.Duration
	}{
		{"sticky больше — продлевает", 15 * time.Second, 25 * time.Second, 25 * time.Second},
		{"sticky равен — недостижим", 15 * time.Second, 15 * time.Second, 15 * time.Second},
		{"sticky меньше — недостижим", 15 * time.Second, 5 * time.Second, 15 * time.Second},
		{"sticky выключен", 15 * time.Second, -1, 15 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &WSPoolTransport{
				poolSize:          8,
				maxSlotAge:        60 * time.Second,
				gracefulDrain:     true,
				drainHardCap:      c.hardCap,
				stickyMaxDrainAge: c.sticky,
			}
			p.slots = make([]*poolSlot, p.poolSize*2)
			_, _, _, _, tear, _ := p.worstCaseTeardown()
			if tear != c.wantTear {
				t.Errorf("teardown cap = %v, want %v", tear, c.wantTear)
			}
		})
	}
}

// TestStaggerSpan_BoundsActualOffsets — staggerSpan обязан быть ВЕРХНЕЙ границей
// того, что реально возвращает slotStaggerOffset. Если span занижен, бюджет
// систематически оптимистичен, и WARN промолчит при реальном дефиците.
func TestStaggerSpan_BoundsActualOffsets(t *testing.T) {
	p := &WSPoolTransport{
		poolSize:         8,
		staggerStep:      6 * time.Second,
		staggerOffsetCap: 45 * time.Second,
	}
	p.slots = make([]*poolSlot, p.poolSize*2)

	span := p.staggerSpan()
	for idx := range p.slots {
		// Джиттер случайный — прогоняем каждую ячейку многократно.
		for i := 0; i < 200; i++ {
			if got := p.slotStaggerOffset(idx); got > span {
				t.Fatalf("slotStaggerOffset(%d) = %v > staggerSpan %v", idx, got, span)
			}
		}
	}
	t.Logf("staggerSpan = %v при %d ячейках", span, len(p.slots))
}

// TestStaggerSpan_NoCapUsesFullLadder — без cap'а лестница не ограничена, и span
// обязан это отражать: иначе высокие idx выпадут из бюджета молча.
func TestStaggerSpan_NoCapUsesFullLadder(t *testing.T) {
	p := &WSPoolTransport{
		poolSize:    8,
		staggerStep: 6 * time.Second,
		// staggerOffsetCap = 0 → legacy unbounded ladder
	}
	p.slots = make([]*poolSlot, p.poolSize*2)

	// maxIdx = 15 → 15*6s = 90s, плюс step/2 = 3s.
	if want, got := 93*time.Second, p.staggerSpan(); got != want {
		t.Errorf("staggerSpan без cap = %v, want %v", got, want)
	}
}

// TestRotationBudget_FieldConfigIsNegative — воспроизведение полевой
// конфигурации 2026-08-07. Тест ФИКСИРУЕТ дефицит, а не требует его отсутствия:
// на этих настройках бюджет отрицательный, и это ровно то, что показал замер.
//
// Если правка сделает запас положительным — тест упадёт, и это правильный
// сигнал обновить ожидание вместе с обоснованием.
func TestRotationBudget_FieldConfigIsNegative(t *testing.T) {
	const observedAgeMin = 83242 * time.Millisecond // slot=15, cause=age_cut

	p := &WSPoolTransport{
		poolSize:          8,
		maxSlotAge:        75 * time.Second,
		staggerStep:       6 * time.Second,
		staggerOffsetCap:  45 * time.Second,
		gracefulDrain:     true,
		drainHardCap:      15 * time.Second,
		stickyMaxDrainAge: 15 * time.Second,
	}
	p.slots = make([]*poolSlot, p.poolSize*2)
	p.ageAdapter = slotobs.NewAdapter(75 * time.Second)

	// Полевое значение applied_max_slot_age = 69s.
	v := slotobs.Verdict{
		Axis:      slotobs.AxisAge,
		Threshold: slotobs.Threshold{Age: 69 * time.Second},
		Reason:    "полевой вердикт 2026-08-07",
	}
	for i := 0; i < 8; i++ {
		p.ageAdapter.Observe(v)
	}

	base, stagger, sweep, deferred, tear, total := p.worstCaseTeardown()
	margin := observedAgeMin - total

	t.Logf("base=%v stagger=%v sweep=%v deferred=%v tear=%v → worst=%v",
		base, stagger, sweep, deferred, tear, total)
	t.Logf("самая ранняя наблюдённая смерть = %v, запас = %v", observedAgeMin, margin)

	if margin > 0 {
		t.Errorf("запас %v положительный — полевая конфигурация больше не "+
			"воспроизводится; обнови ожидание вместе с обоснованием правки", margin)
	}

	// Наивная формула показывала 84s и выглядела «впритык». Честная — сильно хуже.
	naive := base + p.stickyMaxDrainAge
	if naive >= total {
		t.Fatalf("наивная %v не меньше честной %v — формула сломана", naive, total)
	}
	t.Logf("наивная формула скрывала %v дефицита", total-naive)
}

// Lockstep: ячейки не должны получать ОДИНАКОВЫЙ stagger-offset.
//
// Замер 2026-08-07 показал дефект конфигурации: при step=6s и cap=45s лестница
// min(idx*step, cap) упирается в потолок с idx=8, поэтому восемь ячеек из
// шестнадцати получают одинаковую базу 45s и ротируются синхронно. В логе это
// видно как пачки drain в одну секунду. Stagger существует ровно затем, чтобы
// такого не было: всплеск одновременных TCP-хендшейков к origin IP — тот самый
// counting-сигнал, от которого он защищает.
//
// Тест проверяет БАЗУ (без джиттера), потому что джиттер ±step/2 маскирует
// проблему в наблюдении, но не устраняет её: средние моменты ротации совпадают.
func TestStaggerLadder_NoLockstepAtFieldConfig(t *testing.T) {
	ladderBase := func(idx int, step, cap time.Duration) time.Duration {
		if idx <= 0 {
			return 0
		}
		b := time.Duration(idx) * step
		if cap > 0 && b > cap {
			b = cap
		}
		return b
	}

	countClamped := func(cells int, step, cap time.Duration) (distinct, maxSame int) {
		seen := map[time.Duration]int{}
		for idx := range cells {
			seen[ladderBase(idx, step, cap)]++
		}
		for _, n := range seen {
			if n > maxSame {
				maxSame = n
			}
		}
		return len(seen), maxSame
	}

	const cells = 16 // 2*poolSize при poolSize=8

	t.Run("прежние дефолты — lockstep", func(t *testing.T) {
		distinct, maxSame := countClamped(cells, 6*time.Second, 45*time.Second)
		t.Logf("step=6s cap=45s → различных значений %d из %d, худший кластер %d",
			distinct, cells, maxSame)
		if maxSame < 2 {
			t.Error("ожидался lockstep на прежних дефолтах — воспроизведение дефекта")
		}
	})

	t.Run("новая конфигурация — лестница без клампа", func(t *testing.T) {
		const step, cap = 1 * time.Second, 15 * time.Second
		distinct, maxSame := countClamped(cells, step, cap)
		t.Logf("step=1s cap=15s → различных значений %d из %d, худший кластер %d",
			distinct, cells, maxSame)
		if distinct != cells {
			t.Errorf("различных offset'ов %d, ожидалось %d — кламп срабатывает, "+
				"lockstep сохранился", distinct, cells)
		}
		// Инвариант конфигурации: лестница обязана укладываться в cap.
		if want := time.Duration(cells-1) * step; want > cap {
			t.Errorf("лестница %v выше cap %v — старшие ячейки склеятся", want, cap)
		}
	})
}

// staggerSpan обязан падать вместе с cap — иначе бюджет считается по старому
// потолку и WARN не увидит улучшения.
func TestStaggerSpan_ShrinksWithCap(t *testing.T) {
	mk := func(step, cap time.Duration) *WSPoolTransport {
		p := &WSPoolTransport{poolSize: 8, staggerStep: step, staggerOffsetCap: cap}
		p.slots = make([]*poolSlot, p.poolSize*2)
		return p
	}
	old := mk(6*time.Second, 45*time.Second).staggerSpan()
	nw := mk(1*time.Second, 15*time.Second).staggerSpan()

	if want := 48 * time.Second; old != want {
		t.Errorf("прежний span = %v, want %v", old, want)
	}
	if want := 15*time.Second + 500*time.Millisecond; nw != want {
		t.Errorf("новый span = %v, want %v", nw, want)
	}
	t.Logf("span: %v → %v (бюджет освобождает %v)", old, nw, old-nw)
}

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
	// sweepPhaseJitter здесь 0 (литерал, не NewWSPoolTransport) → слагаемое
	// размазывания фазы не участвует, sweep равен чистому тику.
	if sweep != rotationWatchdogTick {
		t.Errorf("sweep = %v, want %v", sweep, rotationWatchdogTick)
	}
	if tear != 15*time.Second {
		t.Errorf("teardown cap = %v, want 15s", tear)
	}
	// Отсрочка — ХУДШАЯ из ветвей, no-free-cell (30s), а не частая storm-brake
	// (5s): слот уже перешагнул порог, но возвращён в slotReady, продолжает
	// принимать стримы и 30s запрещён к ротации. См. worstCaseTeardown.
	if deferred != drainRevertBackoff {
		t.Errorf("deferred = %v, want %v (no-free-cell — худшая ветвь)",
			deferred, drainRevertBackoff)
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

	// Сторож против замены суммы на max(deferred, tear). Попытка была 2026-08-10:
	// в одном вызове startDrain это действительно взаимоисключающие ветки, но
	// бюджет моделирует полный путь ячейки, где отсрочка НЕ отменяет ротацию —
	// слот платит deferred, потом на следующем заходе tear.
	//
	// ⚠ Прежняя полевая опора («p90=118s и max=122s, n=766, пробивают
	// max()=111.5s») на новых данных неверна: p90=85–86s в трёх прогонах
	// подряд, см. разбор в ws_pool.go у worstCaseTeardown. Довод держится не на
	// перцентилях, а на СВОЙСТВЕ КОДА — слагаемые расходуются последовательно.
	// Из замеров max()=111.5s пробивает только max=127.6s (прогон 08-11).
	hold := deferred
	if tear > hold {
		hold = tear
	}
	if maxForm := base + stagger + sweep + hold; total == maxForm {
		t.Errorf("worst-case %v равен max-форме — deferred и tear перестали "+
			"складываться; занижение на %v, при этом наблюдённый p90 её пробивает",
			total, deferred+tear-hold)
	}
	t.Logf("наивная формула дала бы %v, честная = %v (расхождение %v); "+
		"max-форма дала бы %v", naive, total, total-naive,
		base+stagger+sweep+hold)
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

// Гейт строки о дефиците бюджета обязан висеть на ОЧИЩЕННОМ минимуме.
//
// ⚠ Сама строка с 2026-08-10 печатается на уровне INFO («rotation budget below
// observed cut window»), а не WARN: она утверждает прогноз, а не отказ. Гейт от
// этого не изменился — он про наличие дефицита, поэтому тест актуален.
//
// Полевой разбор 2026-08-10 (86 минут, 1.39 ГБ): дефицит держался весь прогон —
// последняя строка `slot death inference` в 17:20:48 печатает
// margin_to_age_min=-1m3.789s. Но WARN замолчал в 16:36:13 и больше не появился:
// в 16:36:18 в СЫРУЮ выборку попала смерть с age_ms=0 (`cause=natural`, close при
// старте слота), age_min_ms в snapshot прыгнул 78711 → 0, и гейт `s.AgeMin > 0`
// заглушил предупреждение. Итог — 237 WARN вместо ~772: контур замолчал не потому,
// что бюджет сошёлся, а потому, что сравнивал с полем, которое сам же объявил
// ненадёжным двадцатью строками выше (v.AgeMinMs vs s.AgeMin).
//
// Класс отказа — снова H-15: молчание, неотличимое от здоровья.
func TestRotationBudgetWarn_GateUsesCleanMinNotRaw(t *testing.T) {
	r := slotobs.NewRecorder(64)

	// Настоящие резы посредника — полевые возрасты 2026-08-10 (cause=age_cut).
	// Байты гуляют на порядки при узком коридоре возраста: это и даёт axis=age.
	ages := []int64{78711, 82791, 83594, 84558, 86939, 86955, 87252, 87331,
		87501, 87605, 88864, 89348, 90487}
	for i, age := range ages {
		r.Record(slotobs.Observation{
			AgeMs:     age,
			DownBytes: int64(1<<uint(i%20)) * 977, // разброс на порядки → CV байтов велик
			CloseKind: "close_other",
		})
	}
	// Шум: слот, умерший в момент подключения. Именно он обнулял СЫРОЙ минимум.
	r.Record(slotobs.Observation{
		AgeMs: 0, DownBytes: 0, CloseKind: "close_other",
	})

	s := r.Summarize()
	v := r.InferWithMinAge(0)

	if s.AgeMin != 0 {
		t.Fatalf("сырой минимум = %d, ожидался 0 — фикстура не воспроизводит поле", s.AgeMin)
	}
	if v.AgeMinMs <= 0 {
		t.Fatalf("очищенный минимум = %d, ожидался > 0 — фильтр шума не сработал", v.AgeMinMs)
	}

	// Полевой дефицит: worst_case 2m21.5s против age_min_clean 1m18.711s.
	const margin = -1*time.Minute - 2789*time.Millisecond

	// Главное утверждение: при живом дефиците и зашумлённой сырой выборке WARN
	// обязан звучать. Гейт на s.AgeMin здесь молчал — это и была регрессия.
	if !shouldWarnRotationBudget(v.AgeMinMs, margin) {
		t.Error("WARN подавлен при отрицательном запасе — гейт снова смотрит " +
			"на сырой минимум вместо очищенного (H-15, поле 2026-08-10)")
	}
	if shouldWarnRotationBudget(s.AgeMin, margin) {
		t.Error("гейт по сырому минимуму сработал — фикстура не воспроизводит " +
			"полевое замолчание, тест перестал сторожить регрессию")
	}

	// Обратная сторона: при положительном запасе WARN не должен звучать, иначе
	// «исправление» выродится в постоянный шум.
	if shouldWarnRotationBudget(v.AgeMinMs, 5*time.Second) {
		t.Error("WARN при положительном запасе — гейт потерял смысл")
	}
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

// Дросселирование строк о бюджете (2026-08-13).
//
// Замер age-wall probe (2ч40м, порог 150s): 1782 строки «rotation budget below
// observed cut window» и 176 строк «upper bound is no longer an upper bound».
// Обе горели на каждом тике StartStatsLogger (5s) при НЕИЗМЕННОМ структурном
// дефиците: worstCaseTeardown()=142.5s против age_min_clean=82.59s, дефицит
// 59.91s. Гейты сработали корректно — дефект в том, что WARN, горящий всегда,
// не значит ничего (H-15 наоборот: там молчание приняли за здоровье, здесь
// непрерывный крик перестают читать).
//
// Инвариант: гейт НЕ ослаблен (условие срабатывания то же), но повтор
// неизменного состояния не печатается.
func TestBudgetLogThrottle_SilentWhileStateUnchanged(t *testing.T) {
	var th budgetLogThrottle
	const deficit = 59910 * time.Millisecond

	if !th.shouldLog(true, deficit, rotationBudgetLogEpsilon) {
		t.Fatal("первое срабатывание обязано печататься — иначе дефицит не увидят вовсе")
	}

	// Полевой сценарий: 1781 повтор того же состояния. Дефицит дрожит на
	// сотни миллисекунд от переоценки перцентилей — это не изменение.
	printed := 0
	for i := range 1781 {
		jitter := time.Duration(i%7) * 100 * time.Millisecond
		if th.shouldLog(true, deficit+jitter, rotationBudgetLogEpsilon) {
			printed++
		}
	}
	if printed != 0 {
		t.Errorf("напечатано %d повторов неизменного состояния — троттлинг не работает, "+
			"строка снова выродится в 1782 строки за прогон", printed)
	}
}

// Сдвиг дефицита больше epsilon — это НОВОСТЬ, её печатать обязательно.
// Иначе троттлинг превратится в глушилку и повторит H-15 уже по-настоящему.
func TestBudgetLogThrottle_LogsMaterialChange(t *testing.T) {
	var th budgetLogThrottle
	const deficit = 59910 * time.Millisecond

	th.shouldLog(true, deficit, rotationBudgetLogEpsilon)

	if th.shouldLog(true, deficit+4*time.Second, rotationBudgetLogEpsilon) {
		t.Error("сдвиг меньше epsilon напечатан — порог значимости не работает")
	}
	if !th.shouldLog(true, deficit+9*time.Second, rotationBudgetLogEpsilon) {
		t.Error("сдвиг больше epsilon НЕ напечатан — реальное изменение бюджета проглочено")
	}
	// Сдвиг в другую сторону (адаптер сжал порог) — тоже новость.
	if !th.shouldLog(true, deficit, rotationBudgetLogEpsilon) {
		t.Error("сокращение дефицита не напечатано — улучшение так же значимо, как ухудшение")
	}
}

// Возврат в норму обязан печататься: без него последняя строка в логе
// навсегда останется тревожной, и читатель не узнает, что дефицит исчез.
func TestBudgetLogThrottle_LogsReturnToNormal(t *testing.T) {
	var th budgetLogThrottle

	th.shouldLog(true, 59910*time.Millisecond, rotationBudgetLogEpsilon)

	if !th.shouldLog(false, 5*time.Second, rotationBudgetLogEpsilon) {
		t.Fatal("возврат в норму не напечатан — исчезновение дефицита осталось невидимым")
	}
	// В норме молчим, сколько бы тиков ни прошло.
	for range 100 {
		if th.shouldLog(false, 5*time.Second, rotationBudgetLogEpsilon) {
			t.Fatal("печать в нормальном состоянии — шум вернулся с другой стороны")
		}
	}
	// А новое ухудшение снова печатается.
	if !th.shouldLog(true, 30*time.Second, rotationBudgetLogEpsilon) {
		t.Error("повторное появление дефицита не напечатано — троттлинг залип")
	}
}

// Гейт не должен быть ослаблен троттлингом: shouldWarnRotationBudget отвечает
// за то, ЕСТЬ ли дефицит, троттлинг — только за частоту печати. Разъезд этих
// двух ответственностей и был бы починкой симптома вместо причины.
func TestBudgetLogThrottle_DoesNotWeakenGate(t *testing.T) {
	const margin = -59910 * time.Millisecond
	if !shouldWarnRotationBudget(82590, margin) {
		t.Error("гейт перестал видеть полевой дефицит 2026-08-13 " +
			"(worst_case 142.5s против age_min_clean 82.59s)")
	}
	if shouldWarnRotationBudget(82590, 5*time.Second) {
		t.Error("гейт сработал при положительном запасе")
	}
}

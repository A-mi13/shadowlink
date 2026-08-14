package client

import (
	"math"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Фаза ротаций на wire и бюджет свипа.
//
// # История, без которой эти тесты выглядят произвольными
//
// Замер 2026-08-14 (лог nixavpn-DEBUG-20260813-153638, 2.04ч): все 588
// age-ротаций легли в ОДНУ фазу 5-секундной сетки rotationWatchdogTick,
// σ фазы 0.0001s, дрейфа за 2 часа нет; 92.2% TCP-connect'ов — в одном
// односекундном окне. Комментарий к slotStaggerOffset утверждал, что additive
// grid jitter разрушает спектральный пик; замер показал, что пик лишь переехал
// на 1/tick и стал предельно узким.
//
// Первая попытка починки была ОТКАЧЕНА в тот же день: слоту выдавалась разовая
// отсрочка uniform[0, 4s) через nextDrainAttemptNs. Она не работала, и это
// свойство КОДА, а не выборки — единственный читатель nextDrainAttemptNs это сам
// свип, а свип просыпается только по тикеру. Отсрочка короче тика не «истекает»,
// её сравнивают со следующим тиком, поэтому дренаж происходил ровно на следующем
// тике, в той же фазе, с вероятностью 1.
//
// ⚠ Урок для тестов, а не только для кода. Тесты той попытки были ЗЕЛЁНЫМИ: они
// вручную ставили nextDrainAttemptNs в прошлое и звали rotationWatchdogSweep(),
// то есть эмулировали подтиковое пробуждение, которого в проде не существует.
// Они прошли бы и при полностью сломанной фиче. Поэтому здесь НЕ проверяется
// «свип отложил и потом сработал» — такая проверка ничего не значит, пока свип
// вызывается вручную. Проверяется то, что действительно определяет фазу: период
// тикера и его вклад в бюджет.

// TestRotationWatchdogTick_SubSecondForPhaseSpreading — период тикера обязан быть
// заметно меньше секунды, иначе фаза ротаций видна на wire.
//
// Почему тест на константу, а не на поведение: фазу определяет ИМЕННО период
// тикера (см. историю выше), а проверить фазу в юнит-тесте нельзя — для этого
// нужен прогон с часами. Тест фиксирует решение и ловит откат константы к 5s,
// который вернул бы 92.2% connect'ов в одно окно.
//
// Второе утверждение — про соотношение с stagger-джиттером. Срезка тика работает
// потому, что амплитуда уже существующего джиттера (±step/2 = ±0.5s при step=1s)
// стала СРАВНИМА с квантом сетки; при тике 5s джиттер был в 10 раз меньше кванта
// и размазать фазу не мог физически.
func TestRotationWatchdogTick_SubSecondForPhaseSpreading(t *testing.T) {
	require.Less(t, rotationWatchdogTick, time.Second,
		"тик watchdog'а определяет фазу новых TLS-соединений на wire: при 5s все "+
			"588 ротаций легли в одну фазу (σ 0.0001s, 92.2%% в одном 1s-окне)")

	// Прод-конфигурация: staggerStep=1s → амплитуда джиттера порога ±0.5s.
	// Требование «квант не больше амплитуды» осталось со времён, когда фазу
	// пытались размазать джиттером ПОРОГА. Замер 2026-08-14 показал, что так не
	// работает вовсе (R на периоде тика не изменился: 0.598 → 0.553), и фаза
	// теперь развязана джиттером на самом ПРОБУЖДЕНИИ — см.
	// TestRotationWatchdogLoop_WakeupsAreNotOnAGrid. Условие оставлено как
	// дополнительная страховка: пока оно держится, джиттер порога тоже вносит
	// вклад, а не только выбирает тик.
	const prodStaggerStep = time.Second
	require.LessOrEqual(t, rotationWatchdogTick, prodStaggerStep/2,
		"квант сетки должен быть не больше амплитуды stagger-джиттера (±step/2)")
}

// TestWorstCaseTeardown_SweepCountsTickTwice — тик расходуется ДВАЖДЫ.
//
// Путь ячейки проходит через свип два раза: обнаружение (перешагнул порог сразу
// после тика → ждёт до целого периода) и повторная попытка, если startDrain
// отложил ротацию через nextDrainAttemptNs — прочитать эту отсрочку может только
// свип, то есть только на очередном тике.
//
// Прежняя формула считала один тик и была занижена ровно на период. Это H-15 с
// другой стороны: слагаемое `deferred` в бюджете есть, но БЕЗ тика, через который
// отсрочка физически не может рассосаться. Занижение бюджета в этом проекте
// считается хуже завышения — бюджет обязан быть верхней границей.
func TestSweepWorstCase_CoversJitteredWakeups(t *testing.T) {
	// 2 пробуждения × (tick + максимум джиттера = tick) = 4 × tick.
	require.Equal(t, 4*rotationWatchdogTick, sweepWorstCase(),
		"бюджет обязан брать ВЕРХНЮЮ границу интервала пробуждения (tick+jitter), "+
			"а не средний 1.5×tick: занижение бюджета хуже завышения")
	require.Equal(t, 2*time.Second, sweepWorstCase(),
		"при tick=500ms вклад свипа = 2s; если упало — перечитать обоснование "+
			"у rotationWatchdogTick, а не подгонять число")
}

// TestRotationWatchdogLoop_WakeupsAreNotOnAGrid — джиттер на пробуждении реально
// применяется и берётся заново.
//
// Прямо измерить моменты пробуждения из юнит-теста нельзя (цикл бесконечный и
// живёт на своём тайминге), поэтому проверяется распределение интервала сна.
//
// ⚠ Исправлено ревью 2026-08-14: тест держал СВОЮ КОПИЮ формулы
// (`tick + rand.Float64()*tick` прямо здесь) и проверял её, а не цикл. Снятие
// джиттера в самом rotationWatchdogLoop тест бы не заметил — он остался бы
// зелёным на собственном выражении. Теперь зовётся nextWatchdogWakeup() —
// ровно та функция, которую вызывает цикл, — поэтому вторая правда исключена.
//
// Тест ловит два конкретных отказа:
//
//  1. джиттер убрали/занулили → все интервалы равны tick, решётка вернулась;
//  2. джиттер сэмплируется ОДИН раз и переиспользуется → интервалы равны между
//     собой, то есть решётка с другим шагом. Это «single-sample reused»
//     антипаттерн, разобранный у slotStaggerOffset.
func TestRotationWatchdogLoop_WakeupsAreNotOnAGrid(t *testing.T) {
	const n = 200
	seen := make(map[time.Duration]int, n)
	var min, max time.Duration = 1 << 62, 0
	for i := 0; i < n; i++ {
		d := nextWatchdogWakeup()
		seen[d]++
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	require.Greater(t, len(seen), n/2,
		"интервалы пробуждения повторяются — джиттер либо снят, либо сэмплирован "+
			"один раз и переиспользован; решётка на wire вернётся")
	require.GreaterOrEqual(t, min, rotationWatchdogTick,
		"интервал не может быть короче базового тика")
	require.Less(t, max, 2*rotationWatchdogTick,
		"интервал не может достигать 2×tick — иначе sweepWorstCase занижен")
	// Разброс должен покрывать существенную часть периода, иначе размазывание
	// номинально: при джиттере в 1% фаза остаётся приколоченной.
	require.Greater(t, max-min, rotationWatchdogTick/2,
		"разброс интервалов мал — фаза останется различимой")
}

// Свип обязан просыпаться по перевзводимому time.Timer, а НЕ по time.Ticker.
//
// # Почему это сторож на уровне ИСХОДНИКА, а не на поведении
//
// Замер прогона 161915 показал, что джиттер этого цикла — ЯКОРЬ ФАЗЫ ВСЕГО ПУЛА,
// а не только моментов connect. Ticker дренажа (drainPollInterval) создаётся
// ВНУТРИ каждого drainWatchdog, поэтому его фаза наследуется от startDrain, а
// startDrain зовётся из свипа. Проверено на логе: сетка дренажа относительно
// старта жива на 100% (R((close−drain_start) mod 500ms) = 1.0000, 1575/1575 в
// бине 0-50ms, и на подвыборке многотиковых дренажей n=208 тоже R=1.0000), а
// абсолютная фаза close на wire — шум (R=0.0447 при 1/√n=0.0256). Фаза старта
// дренажа распределена равномерно: гистограмма по 50ms-бинам 185/144/187/165/
// 146/159/154/131/141/163.
//
// Следствие: возврат ЭТОГО цикла к time.NewTicker немедленно проявит решётку
// 500 мс в моментах close, хотя код дренажа не изменится (наблюдалось в прогоне
// 115514: R=0.8933 по close при жёстком свипе и том же drainPollInterval).
// Взаимные ссылки в комментариях эту связь описывают, но не защищают: рефакторинг
// «упростим цикл до тикера» пройдёт и build, и vet, и все поведенческие тесты —
// TestRotationWatchdogLoop_WakeupsAreNotOnAGrid проверяет nextWatchdogWakeup()
// изолированно и останется зелёным, даже если ЦИКЛ перестанет её вызывать.
//
// Поэтому сторож читает исходник. Это грубо, но дешевле, чем 4-часовой полевой
// прогон, которым эта регрессия обнаруживается иначе.
func TestRotationWatchdogLoop_UsesJitteredTimerNotTicker(t *testing.T) {
	src, err := os.ReadFile("ws_pool.go")
	require.NoError(t, err, "не читается ws_pool.go — сторож фазы свипа бесполезен")

	body := funcBodySource(t, string(src), "func (p *WSPoolTransport) rotationWatchdogLoop()")

	require.NotContains(t, body, "time.NewTicker",
		"rotationWatchdogLoop вернулся к time.NewTicker — фаза пула снова "+
			"приколочена к сетке, и решётка 500мс проявится в моментах close БЕЗ "+
			"единой правки в дренаже (прогон 115514: R=0.8933). Джиттер этого "+
			"цикла — якорь фазы для drainPollInterval, см. его комментарий")
	require.Contains(t, body, "nextWatchdogWakeup()",
		"rotationWatchdogLoop больше не зовёт nextWatchdogWakeup() — джиттер фазы "+
			"снят; тест на саму функцию этого не поймает, она останется корректной")
	require.Contains(t, body, "time.NewTimer",
		"ожидался перевзводимый time.NewTimer: джиттер обязан сэмплироваться "+
			"ЗАНОВО на каждый взвод, иначе это решётка с другим шагом")
}

// funcBodySource возвращает КОД тела функции по её сигнатуре: от строки с
// сигнатурой до закрывающей `}` в нулевой колонке, с вырезанными комментариями.
//
// ⚠ Комментарии вырезаются обязательно, и это не косметика. Первая версия
// сторожа падала на здоровом коде: комментарий у rotationWatchdogLoop разбирает
// антипаттерн и потому СОДЕРЖИТ строку «time.NewTicker». Сторож, читающий
// исходник вместе с комментариями, запрещал бы документировать то, от чего он
// защищает, — и был бы снят как флейкующий при первой же правке комментария.
//
// Строковые литералы не вырезаются: в телах проверяемых функций их нет, а
// полноценный лексер здесь не нужен (go/ast — оверкилл на одну проверку).
func funcBodySource(t *testing.T, src, signature string) string {
	t.Helper()
	i := strings.Index(src, signature)
	require.GreaterOrEqual(t, i, 0,
		"не найдена сигнатура %q — тест устарел и молча ничего не проверяет "+
			"(это опаснее его отсутствия): обновить сторож", signature)
	rest := src[i:]
	end := regexp.MustCompile(`(?m)^\}`).FindStringIndex(rest[len(signature):])
	require.NotNil(t, end, "не найден конец функции %q", signature)
	body := rest[:len(signature)+end[1]]

	// Убрать //-комментарии (построчно) и /* */-блоки.
	body = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(body, "")
	lines := strings.Split(body, "\n")
	for i, ln := range lines {
		if c := strings.Index(ln, "//"); c >= 0 {
			lines[i] = ln[:c]
		}
	}
	return strings.Join(lines, "\n")
}

func TestWorstCaseTeardown_SweepCountsTickTwice(t *testing.T) {
	p := &WSPoolTransport{
		poolSize:          8,
		maxSlotAge:        70 * time.Second,
		staggerStep:       time.Second,
		staggerOffsetCap:  15 * time.Second,
		gracefulDrain:     true,
		drainHardCap:      15 * time.Second,
		stickyMaxDrainAge: 25 * time.Second,
	}
	p.slots = make([]*poolSlot, p.poolSize*2)

	base, stagger, sweep, deferred, tear, total := p.worstCaseTeardown()

	require.Equal(t, sweepWorstCase(), sweep,
		"слагаемое обязано приходить из sweepWorstCase() — единственного источника")
	require.Equal(t, base+stagger+sweep+deferred+tear, total,
		"итог обязан быть суммой напечатанных слагаемых — иначе лог врёт о механизме")

	// Регрессия на конкретную арифметику прода: 70 + 15.5 + 2 + 30 + 25.
	// Если тик или джиттер изменятся, строка упадёт и заставит перечитать
	// обоснование, а не молча принять другие накладные.
	require.Equal(t, 15500*time.Millisecond, stagger, "cap 15s + step/2")
	require.Equal(t, 2*time.Second, sweep, "2 пробуждения × (500ms + 500ms джиттера)")
	require.Equal(t, 142500*time.Millisecond, total)
}

// TestNormalizeFloorFraction — кламп доли пола storm-brake.
//
// Ручка выведена в env 2026-08-14 ради A/B (разбор: 3 реза из 4 в прогоне
// следуют за отложкой capacity floor). Мусор из env не должен глушить ротацию
// молча: доля >= 1 означала бы «все слоты обязаны быть ready», то есть любая
// ротация запрещала бы следующую и пул перестал бы ротировать вовсе.
func TestNormalizeFloorFraction(t *testing.T) {
	cases := []struct {
		name string
		in   float64
		want float64
	}{
		{"ноль → константа", 0, readyCapacityFloorFraction},
		{"отрицательное → константа", -0.5, readyCapacityFloorFraction},
		{"NaN → константа", math.NaN(), readyCapacityFloorFraction},
		{"половина — валидна", 0.5, 0.5},
		{"дефолт проходит как есть", 0.75, 0.75},
		{"единица клампится", 1.0, 0.95},
		{"больше единицы клампится", 3.0, 0.95},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, normalizeFloorFraction(c.in))
		})
	}
}

// TestReadyCapacityFloor_HonoursConfiguredFraction — доля обязана доходить до
// самого пола, а не оставаться декоративным полем конфига.
//
// Второе утверждение не менее важно: при нулевом поле (транспорт, собранный
// литералом — так делает часть тестов пакета) поведение обязано остаться
// прежним, иначе правка молча сдвинула бы storm-brake во всём наборе.
func TestReadyCapacityFloor_HonoursConfiguredFraction(t *testing.T) {
	// poolSize=8: floor(8*0.5)=4 против дефолтного floor(8*0.75)=6.
	p := &WSPoolTransport{poolSize: 8, readyCapacityFloorFraction: 0.5}
	require.Equal(t, 4, p.readyCapacityFloor(),
		"настроенная доля должна доходить до пола")

	legacy := &WSPoolTransport{poolSize: 8}
	require.Equal(t, 6, legacy.readyCapacityFloor(),
		"нулевое поле обязано сохранять прежний пол (константа 0.75)")

	// Пол не может съесть весь пул: readyCapacityFloor режет до poolSize-1.
	high := &WSPoolTransport{poolSize: 8, readyCapacityFloorFraction: 0.95}
	require.Equal(t, 7, high.readyCapacityFloor(),
		"пол обязан оставлять пулу хотя бы один слот запаса")
}

// TestEffectiveFloorFraction_IsLoggable — применённая доля обязана быть
// наблюдаемой, иначе A/B по ней неподтверждаем.
//
// Ревью S8: до 2026-08-14 применённая доля не логировалась нигде, а сам floor был
// виден ТОЛЬКО внутри строки отказа гейта — то есть исчезал ровно в том
// сценарии, который A/B считает успехом (capacity_floor_deferred_total → 0).
// А envFloatDefault молча возвращает дефолт на любой мусор (`0,5`, `50%`),
// поэтому «успешный» прогон был неотличим от «настройка не применилась».
func TestEffectiveFloorFraction_IsLoggable(t *testing.T) {
	configured := &WSPoolTransport{poolSize: 8, readyCapacityFloorFraction: 0.5}
	require.Equal(t, 0.5, configured.effectiveFloorFraction(),
		"логируемая доля обязана совпадать с той, из которой посчитан пол")

	legacy := &WSPoolTransport{poolSize: 8}
	require.Equal(t, readyCapacityFloorFraction, legacy.effectiveFloorFraction(),
		"при нулевом поле логировать надо константу, а не ноль — иначе читатель "+
			"решит, что пол выключен")

	// Согласованность с самим полом: доля и floor не должны расходиться.
	require.Equal(t,
		int(math.Floor(float64(configured.poolSize)*configured.effectiveFloorFraction())),
		configured.readyCapacityFloor(),
		"напечатанная доля и напечатанный пол обязаны быть об одном и том же")
}

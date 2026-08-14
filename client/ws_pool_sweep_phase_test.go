package client

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Подтиковое размазывание фазы дренажа (sweepPhaseJitter, ws_pool.go).
//
// Что защищаем и почему это не «ещё один джиттер». Замер 2026-08-14 по логу
// nixavpn-DEBUG-20260813-153638 (2.04ч): все 588 age-ротаций легли в ОДНУ фазу
// 5-секундной сетки rotationWatchdogTick, σ фазы = 0.0001s, дрейфа за 2 часа
// нет; 92.2% TCP-connect'ов — в одном односекундном окне этой фазы. То есть
// комментарий к slotStaggerOffset про размазанный FFT-пик описывал механизм,
// который НЕ исполняется: stagger прибавляется к порогу, а порог проверяется
// только на тике, поэтому подтиковая фаза не размазывается вообще.
//
// Три свойства, каждое из которых ломает фичу целиком, если не выполнено:
//
//  1. отсрочка выдаётся ОДИН раз за жизнь слота. Иначе свип перевзводил бы её
//     каждый тик и слот не ротировался бы НИКОГДА — ручка размазывания стала бы
//     выключателем ротации;
//  2. после истечения отсрочки ротация ДОЛЖНА состояться;
//  3. отсрочка не превышает тик, иначе она накапливается и слагаемое в
//     worstCaseTeardown перестаёт быть верхней границей (урок H-15).

// newPhaseJitterPool — пул с одним перезревшим ready-слотом и включённым
// размазыванием. Возраст задаётся заведомо больше порога, чтобы тест проверял
// именно ветку отсрочки, а не арифметику порога (её держат
// TestRotationWatchdogSweep_*).
func newPhaseJitterPool(t *testing.T, jitter time.Duration) (*WSPoolTransport, *poolSlot) {
	t.Helper()
	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	slot.streams.Store(0) // idle → ротация не отложится по активным стримам
	slot.startedAtNs.Store(time.Now().Add(-3 * time.Minute).UnixNano())

	pool, _ := newRotationTestPool(t, slot)
	pool.client = &Client{}
	pool.maxSlotAge = 2 * time.Minute
	pool.sweepPhaseJitter = jitter
	return pool, slot
}

// TestSweepPhaseJitter_DefersFirstSweepThenRotates — свойства 1 и 2 вместе:
// первый свип не рвёт слот, а ставит отсрочку; после её истечения рвёт.
func TestSweepPhaseJitter_DefersFirstSweepThenRotates(t *testing.T) {
	pool, slot := newPhaseJitterPool(t, 4*time.Second)

	before := time.Now().UnixNano()
	pool.rotationWatchdogSweep()

	require.Equal(t, slotReady, slot.getState(),
		"первый свип обязан ОТЛОЖИТЬ дренаж, а не выполнить его — иначе фаза "+
			"остаётся приколоченной к тику")
	require.True(t, slot.phaseJitterApplied.Load(),
		"флаг однократности должен быть выставлен на первом же заходе")

	deadline := slot.nextDrainAttemptNs.Load()
	require.Greater(t, deadline, before,
		"отсрочка должна быть в будущем")
	require.LessOrEqual(t, deadline, before+int64(4*time.Second)+int64(time.Second),
		"отсрочка не может превышать sweepPhaseJitter (+запас на медленный CI)")

	// Отсрочка истекла — тот же слот, тот же свип.
	slot.nextDrainAttemptNs.Store(time.Now().Add(-time.Millisecond).UnixNano())
	pool.rotationWatchdogSweep()

	require.Equal(t, slotDead, slot.getState(),
		"после истечения отсрочки ротация обязана состояться")
}

// TestSweepPhaseJitter_AppliedOncePerSlot — свойство 1 в чистом виде, и это
// главный регресс-тест файла.
//
// Сценарий отказа, который он ловит: отсрочка ставится без проверки
// phaseJitterApplied. Тогда каждый тик сдвигает дедлайн вперёд, слот стареет
// неограниченно и умирает от посредника вместо плановой ротации — то есть
// правка против периодического сигнала оборачивается ростом резов.
func TestSweepPhaseJitter_AppliedOncePerSlot(t *testing.T) {
	pool, slot := newPhaseJitterPool(t, 4*time.Second)

	pool.rotationWatchdogSweep()
	require.Equal(t, slotReady, slot.getState(), "первый свип откладывает")
	first := slot.nextDrainAttemptNs.Load()

	// Второй свип ПРИ ЖИВОЙ отсрочке: должен пройти мимо (continue по
	// nextDrainAttemptNs) и не сдвинуть дедлайн.
	pool.rotationWatchdogSweep()
	require.Equal(t, first, slot.nextDrainAttemptNs.Load(),
		"свип внутри окна отсрочки не имеет права её перевзводить")

	// Отсрочка истекла — второй раз джиттер не выдаётся, слот рвётся.
	slot.nextDrainAttemptNs.Store(time.Now().Add(-time.Millisecond).UnixNano())
	pool.rotationWatchdogSweep()
	require.Equal(t, slotDead, slot.getState(),
		"второй отсрочки быть не должно: иначе слот не ротируется никогда")
}

// TestSweepPhaseJitter_DisabledPreservesLegacyBehavior — отрицательное значение
// возвращает поведение до 2026-08-14 РОВНО, без «почти».
//
// Зачем отдельный выключатель, когда есть 0: ручка не бесплатна — она платит
// возрастом (до +jitter), а возраст в полосе 80-85s несёт hazard 2.1% на проход
// против нуля ниже 80s. Оператор должен иметь способ вернуть прежнее поведение
// для A/B, а 0 занят дефолтом.
func TestSweepPhaseJitter_DisabledPreservesLegacyBehavior(t *testing.T) {
	pool, slot := newPhaseJitterPool(t, -1)

	pool.rotationWatchdogSweep()

	require.Equal(t, slotDead, slot.getState(),
		"при выключенном размазывании перезревший слот рвётся на первом свипе")
	require.False(t, slot.phaseJitterApplied.Load(),
		"выключенная ручка не должна трогать флаг")
	require.Zero(t, slot.nextDrainAttemptNs.Load(),
		"выключенная ручка не должна ставить отсрочку")
}

// TestNewWSPoolTransport_SweepPhaseJitterNormalization — нормализация ручки:
// 0 → дефолт, отрицательное → выключено, больше тика → кламп тиком.
//
// Кламп сверху существен: отсрочка длиннее rotationWatchdogTick не рассасывается
// на следующем тике, начинает накапливаться, и слагаемое sweep в
// worstCaseTeardown перестаёт быть верхней границей.
func TestNewWSPoolTransport_SweepPhaseJitterNormalization(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"ноль → дефолт", 0, sweepPhaseJitterDefault},
		{"отрицательное → выключено (сохраняется как есть)", -1, -1},
		{"в пределах тика → как задано", 2 * time.Second, 2 * time.Second},
		{"больше тика → кламп тиком", 30 * time.Second, rotationWatchdogTick},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewWSPoolTransport(&Client{}, WSPoolConfig{
				Size:             2,
				ServerAddr:       "127.0.0.1:0",
				SweepPhaseJitter: c.in,
			})
			defer p.Close()
			require.Equal(t, c.want, p.sweepPhaseJitter)
		})
	}
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
// Второе утверждение теста не менее важно: при нулевом поле (транспорт, собранный
// литералом — так делают многие тесты в пакете) поведение обязано остаться
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

// TestWorstCaseTeardown_IncludesSweepPhaseJitter — бюджет обязан знать о новом
// слагаемом.
//
// Это прямая регрессия на H-15: механизм, о котором лог рассказывает неправду,
// хуже отсутствующего. Если размазывание добавляет до 4s возраста, а
// worstCaseTeardown их не считает, проверка «бюджет против p10 смертей» снова
// начнёт врать — на этот раз в сторону занижения, которое по памяти проекта
// хуже завышения.
func TestWorstCaseTeardown_IncludesSweepPhaseJitter(t *testing.T) {
	newPool := func(jitter time.Duration) *WSPoolTransport {
		p := &WSPoolTransport{
			poolSize:          8,
			maxSlotAge:        70 * time.Second,
			staggerStep:       time.Second,
			staggerOffsetCap:  15 * time.Second,
			gracefulDrain:     true,
			drainHardCap:      15 * time.Second,
			stickyMaxDrainAge: 25 * time.Second,
			sweepPhaseJitter:  jitter,
		}
		p.slots = make([]*poolSlot, p.poolSize*2)
		return p
	}

	_, _, sweepOff, _, _, totalOff := newPool(-1).worstCaseTeardown()
	require.Equal(t, rotationWatchdogTick, sweepOff,
		"при выключенной ручке sweep = чистый тик")

	_, _, sweepOn, _, _, totalOn := newPool(4 * time.Second).worstCaseTeardown()
	require.Equal(t, rotationWatchdogTick+4*time.Second, sweepOn,
		"включённая ручка обязана попасть в слагаемое sweep")
	require.Equal(t, totalOff+4*time.Second, totalOn,
		"вклад ручки обязан дойти до итога, а не потеряться по пути")
}

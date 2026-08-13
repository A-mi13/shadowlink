package client

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Наблюдательный счётчик смертей слотов (P2, замер 2026-08-11).
//
// Зачем отдельно от recentDeaths: тот кормит meltdown-кулдаун и намеренно НЕ
// считает age-cut — иначе штатный каскад резов ставил бы пул на паузу и
// углублял просадку (см. диспетчер причин в handleSlotDeath). Решение верное
// исполнительно, но оно ослепило наблюдателя.
//
// Полевой случай 2026-08-11 15:48: origin стал недоступен, 8 слотов умерли за
// 3.6 с, пул лёг целиком (health: alive=0, active_streams=0, 45 отказов
// "no ready slots"). Шесть из восьми смертей имели возраст 55-79 с, то есть
// выше ageCutMinAge=45s, и были классифицированы как age_cut — meltdown
// увидел только 2 при пороге 6 и напечатал meltdowns_1m=0. У оператора не
// осталось НИ ОДНОГО поля, по которому виден полный отказ пула.
//
// Этот счётчик ничего не исполняет: он только считает все смерти независимо
// от причины. Разведение наблюдаемости и исполнения — прямое требование
// урока H-15 (контур, про который нельзя сказать, работает ли он).

func newDeathCounterTestPool(t *testing.T) *WSPoolTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &WSPoolTransport{
		ctx: ctx,
		log: slog.New(slog.DiscardHandler),
	}
}

// Счётчик обязан расти на ЛЮБОЙ причине — в этом весь его смысл.
func TestBumpSlotDeaths1m_CountsEveryCause(t *testing.T) {
	p := newDeathCounterTestPool(t)

	require.EqualValues(t, 0, p.slotDeaths1m.Load(), "стартовое значение")

	for _, cause := range []slotDeathCause{
		deathCauseNatural,
		deathCauseAgeCut,
		deathCausePreemptiveRotation,
	} {
		p.bumpSlotDeaths1m(cause)
	}

	assert.EqualValues(t, 3, p.slotDeaths1m.Load(),
		"все причины должны считаться: иначе полный отказ пула снова окажется невидим")
}

// Ключевой инвариант: наблюдательный счётчик НЕ трогает исполнительный.
// Если они срастутся, age-cut начнёт кормить кулдаун — тот самый регресс,
// от которого ветку age_cut и отделяли.
func TestBumpSlotDeaths1m_DoesNotFeedMeltdown(t *testing.T) {
	p := newDeathCounterTestPool(t)

	for range 20 {
		p.bumpSlotDeaths1m(deathCauseAgeCut)
	}

	assert.EqualValues(t, 20, p.slotDeaths1m.Load())
	assert.EqualValues(t, 0, p.recentDeaths.Load(),
		"recentDeaths кормит кулдаун и обязан остаться нетронутым")
	assert.EqualValues(t, 0, p.meltdownUntil.Load(),
		"кулдаун не должен взводиться от наблюдательного счётчика")
}

// Разделение плановых ротаций и резов посредника (2026-08-13).
//
// Агрегат `slot_deaths_1m` дважды подряд стал источником НЕВЕРНОГО диагноза:
// аудит 2026-08-13 и разбор инженера в тот же день прочли значение 18 как
// «перегрузка/meltdown», хотя это был штатный темп ротации. Причина —
// bumpSlotDeaths1m вызывается в handleSlotDeath ДО ветвления по причине, а
// плановый дренаж заходит туда с deathCauseDrainTeardown. Замер 2026-08-13
// дал пропорцию: 1326 плановых ротаций против 125 резов, то есть счётчик на
// 91% состоял из здоровой работы, а имя рядом с rotations_1m читалось как
// «пул умирает».
//
// Главное утверждение теста: плановый teardown НЕ увеличивает счётчик резов.
func TestBumpSlotDeaths1m_PlannedTeardownIsNotACut(t *testing.T) {
	p := newDeathCounterTestPool(t)

	for range 7 {
		p.bumpSlotDeaths1m(deathCauseDrainTeardown)
	}
	p.bumpSlotDeaths1m(deathCausePreemptiveRotation)

	assert.EqualValues(t, 0, p.slotCuts1m.Load(),
		"плановый teardown/ротация попали в счётчик резов — именно это дважды "+
			"дало диагноз «пул умирает» на здоровом пуле")
	assert.EqualValues(t, 8, p.slotTeardowns1m.Load(),
		"наши собственные снятия слота должны считаться отдельно")
}

// Обратная сторона: рез посредника и падение сети обязаны попадать в
// slot_cuts_1m. Полный отказ пула 2026-08-11 (origin лёг, 6 смертей из 8
// классифицированы как age_cut) должен быть виден ИМЕННО здесь — если он
// уедет в teardowns, счётчик снова ослепнет, только с другой стороны.
func TestBumpSlotDeaths1m_CutsCountedSeparately(t *testing.T) {
	p := newDeathCounterTestPool(t)

	p.bumpSlotDeaths1m(deathCauseNatural)
	for range 6 {
		p.bumpSlotDeaths1m(deathCauseAgeCut)
	}

	assert.EqualValues(t, 7, p.slotCuts1m.Load(),
		"natural + age_cut решены НЕ нами — это резы")
	assert.EqualValues(t, 0, p.slotTeardowns1m.Load(),
		"рез посредника не должен выглядеть как наша плановая ротация")
}

// Агрегат обязан остаться суммой разбивки: он сохранён для совместимости, и
// расхождение означало бы, что одна из веток инкрементит мимо.
func TestBumpSlotDeaths1m_AggregateEqualsSplit(t *testing.T) {
	p := newDeathCounterTestPool(t)

	for _, cause := range []slotDeathCause{
		deathCauseNatural,
		deathCauseAgeCut,
		deathCausePreemptiveRotation,
		deathCauseDrainTeardown,
	} {
		p.bumpSlotDeaths1m(cause)
	}

	assert.EqualValues(t, 4, p.slotDeaths1m.Load(), "агрегат считает все причины")
	assert.EqualValues(t, 2, p.slotCuts1m.Load())
	assert.EqualValues(t, 2, p.slotTeardowns1m.Load())
	assert.EqualValues(t, p.slotDeaths1m.Load(),
		p.slotCuts1m.Load()+p.slotTeardowns1m.Load(),
		"агрегат разъехался с разбивкой")
}

// Health-строка не должна печатать агрегат под старым именем: именно имя
// `slot_deaths_1m` рядом с `rotations_1m` и порождало неверное чтение.
func TestPoolHealth_DoesNotPrintAmbiguousAggregate(t *testing.T) {
	src, err := os.ReadFile("ws_pool.go")
	require.NoError(t, err)
	code := string(src)

	assert.NotContains(t, code, `"slot_deaths_1m"`,
		"агрегат снова печатается под именем, которое дважды прочли как «пул умирает»")
	assert.Contains(t, code, `"slot_cuts_1m"`,
		"резы посредника обязаны быть видны отдельным полем")
	assert.Contains(t, code, `"slot_teardowns_1m"`,
		"плановые снятия обязаны быть видны отдельным полем")
}

// Распад окна: goroutine обязана выходить по ctx, а не течь таймерами.
// Тот же контракт, что у bumpRotations1m.
func TestBumpSlotDeaths1m_DecaysAndExitsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &WSPoolTransport{ctx: ctx, log: slog.New(slog.DiscardHandler)}

	p.bumpSlotDeaths1m(deathCauseNatural)
	require.EqualValues(t, 1, p.slotDeaths1m.Load())
	require.EqualValues(t, 1, p.slotCuts1m.Load())

	// Отмена ctx завершает decay-goroutine БЕЗ декремента — счётчик
	// остаётся, но горутина не висит до конца окна.
	cancel()
	time.Sleep(50 * time.Millisecond)
	assert.EqualValues(t, 1, p.slotDeaths1m.Load(),
		"выход по ctx не должен декрементить: пул уже останавливается")
	assert.EqualValues(t, 1, p.slotCuts1m.Load(),
		"разбивка обязана следовать тому же контракту распада, что и агрегат")
}

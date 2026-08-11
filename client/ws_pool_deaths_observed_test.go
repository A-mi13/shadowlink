package client

import (
	"context"
	"log/slog"
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

// Распад окна: goroutine обязана выходить по ctx, а не течь таймерами.
// Тот же контракт, что у bumpRotations1m.
func TestBumpSlotDeaths1m_DecaysAndExitsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &WSPoolTransport{ctx: ctx, log: slog.New(slog.DiscardHandler)}

	p.bumpSlotDeaths1m(deathCauseNatural)
	require.EqualValues(t, 1, p.slotDeaths1m.Load())

	// Отмена ctx завершает decay-goroutine БЕЗ декремента — счётчик
	// остаётся, но горутина не висит до конца окна.
	cancel()
	time.Sleep(50 * time.Millisecond)
	assert.EqualValues(t, 1, p.slotDeaths1m.Load(),
		"выход по ctx не должен декрементить: пул уже останавливается")
}

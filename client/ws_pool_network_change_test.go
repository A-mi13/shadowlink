package client

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Обработка смены сети (P0, 2026-08-24). При переключении Wi-Fi↔LTE /
// Wi-Fi↔Ethernet / выходе из сна слоты держат TCP со СТАРОГО локального адреса
// и зависают до TCP-таймаута — RST никто не пришлёт. NetworkChanged() рвёт их
// сами и запускает разнесённый быстрый реконнект, не дожидаясь чтения/keepalive.
//
// Тесты детерминированы (hard rule 6: -race на Windows недоступен): состояние
// проверяется напрямую сразу после вызова, потому что teardown (пометка dead,
// закрытие транспорта, классификация) в handleSlotDeath выполняется СИНХРОННО
// до `go reconnectLoopNetworkChange`. Спавнящиеся реконнект-горутины
// нейтрализуются хуком connectSlot, отменяющим ctx.

func newNetworkChangeTestPool(t *testing.T, size int) (*WSPoolTransport, *Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &WSPoolTransport{
		slots:             make([]*poolSlot, size),
		poolSize:          size,
		log:               slog.New(slog.DiscardHandler),
		ctx:               ctx,
		cancel:            cancel,
		meltdownWindow:    15 * time.Second,
		meltdownThreshold: 3,
		meltdownCooldown:  10 * time.Second,
		meltdownLimiter:   newMeltdownLimiter(),
	}
	p.initRevivalSignal()
	for i := 0; i < size; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		p.slots[i] = s
	}
	return p, &Client{}
}

// neutralizeReconnect: спавнящийся реконнект отменяет ctx и уходит, не касаясь
// сети. Быстрый backoff-шим — на случай, если цепочка успеет тикнуть.
func neutralizeReconnect(t *testing.T, p *WSPoolTransport) {
	t.Helper()
	setSlotBackoffDurationForTest(func(int) time.Duration { return time.Millisecond })
	setConnectSlotForTest(func() error {
		p.cancel()
		return nil
	})
	t.Cleanup(func() {
		// ctx гасим ДО очистки хуков: спавнящиеся реконнект-горутины спят в
		// sleepWithCancel(ctx) и проверяют ctx.Done() — отмена выведет их прежде,
		// чем мы снимем хук. Иначе проснувшаяся горутина увидела бы hook==nil и
		// позвала бы РЕАЛЬНЫЙ connectSlot на неподключённом пуле (nil-паника).
		p.cancel()
		time.Sleep(20 * time.Millisecond) // дать горутинам выйти по ctx
		setConnectSlotForTest(nil)
		setSlotBackoffDurationForTest(nil)
	})
}

// Власть №1: NetworkChanged рвёт КАЖДЫЙ живой слот. Если тело перестанет звать
// teardown (регресс «обработки нет нигде»), ни один слот не станет slotDead.
func TestNetworkChanged_TearsDownAllLiveSlots(t *testing.T) {
	p, _ := newNetworkChangeTestPool(t, 8)
	neutralizeReconnect(t, p)

	p.NetworkChanged()

	for i, s := range p.slots {
		require.Equal(t, slotDead, s.getState(),
			"слот %d должен быть снят при смене сети — иначе висит на старом пути до TCP-таймаута", i)
	}
}

// Власть №2: уже мёртвый слот НЕ трогается повторно; живые рвутся.
func TestNetworkChanged_SkipsDeadSlots(t *testing.T) {
	p, _ := newNetworkChangeTestPool(t, 3)
	neutralizeReconnect(t, p)
	p.slots[1].setState(slotDead)

	p.NetworkChanged()

	assert.Equal(t, slotDead, p.slots[0].getState(), "живой слот 0 снят")
	assert.Equal(t, slotDead, p.slots[1].getState(), "мёртвый слот 1 остался мёртвым")
	assert.Equal(t, slotDead, p.slots[2].getState(), "живой слот 2 снят")
}

// Власть №3: смена сети НЕ кормит meltdown-детектор (это не отказ origin).
// Направь кто-то её через deathCauseNatural — recentDeaths стал бы ненулевым.
func TestNetworkChanged_DoesNotFeedMeltdown(t *testing.T) {
	p, _ := newNetworkChangeTestPool(t, 8)
	neutralizeReconnect(t, p)

	p.NetworkChanged()

	require.Zero(t, p.recentDeaths.Load(),
		"смена сети НЕ должна кормить meltdown — иначе cooldown запрёт все реконнекты")
	require.Zero(t, p.meltdownUntil.Load(),
		"смена сети НЕ должна включать meltdown-cooldown")
}

// Власть №4: смена сети классифицируется как НАШ teardown, а не рез посредника.
func TestNetworkChanged_ClassifiedAsTeardownNotCut(t *testing.T) {
	p, _ := newNetworkChangeTestPool(t, 5)
	neutralizeReconnect(t, p)

	cutsBefore := p.slotCuts1m.Load()
	teardownsBefore := p.slotTeardowns1m.Load()

	p.NetworkChanged()

	assert.Equal(t, cutsBefore, p.slotCuts1m.Load(),
		"смена сети НЕ рез посредника — slotCuts1m трогать нельзя")
	assert.Equal(t, teardownsBefore+5, p.slotTeardowns1m.Load(),
		"5 снятых по нашему решению слотов должны попасть в slotTeardowns1m")
}

// Власть №5: NetworkChanged взводит recentMeltdownNs (оживляет spread-гейт), но
// НЕ трогает meltdownUntil.
func TestNetworkChanged_ArmsSpreadGateWithoutCooldown(t *testing.T) {
	p, _ := newNetworkChangeTestPool(t, 2)
	neutralizeReconnect(t, p)
	require.Zero(t, p.recentMeltdownNs.Load(), "предусловие: гейт ещё не взведён")

	before := time.Now().UnixNano()
	p.NetworkChanged()
	after := time.Now().UnixNano()

	stamp := p.recentMeltdownNs.Load()
	require.NotZero(t, stamp, "recentMeltdownNs должен быть взведён — иначе spread-гейт мёртв")
	assert.GreaterOrEqual(t, stamp, before)
	assert.LessOrEqual(t, stamp, after)
}

// Власть №6: NetworkChanged будит слоты в backoff через signalNetworkRevival —
// waiter просыпается сразу, а не досиживает паузу.
func TestNetworkChanged_WakesBackoffWaiters(t *testing.T) {
	p, _ := newNetworkChangeTestPool(t, 1)
	p.slots[0].setState(slotDead) // чтобы NetworkChanged его не рвал — важен путь пробуждения

	done := make(chan bool, 1)
	go func() { done <- p.waitBackoffOrRevival(30 * time.Second) }()
	time.Sleep(50 * time.Millisecond)

	p.NetworkChanged()

	select {
	case revived := <-done:
		assert.True(t, revived, "waiter должен проснуться по сигналу смены сети, а не досидеть 30s")
	case <-time.After(2 * time.Second):
		t.Fatal("NetworkChanged не разбудил слот в backoff — простой затянется")
	}
}

// Власть №7: reconnectLoopNetworkChange разносит по reconnectJitterOffset(idx).
// Форменный сторож: при удалении вызова из тела метода — краснеет.
func TestReconnectLoopNetworkChange_UsesJitterOffsetSpread(t *testing.T) {
	body := readMethodBody(t, "func (p *WSPoolTransport) reconnectLoopNetworkChange(")
	assert.Contains(t, body, "reconnectJitterOffset(idx)",
		"network-change реконнект обязан разносить по решётке reconnectJitterOffset — "+
			"иначе 8 одинаковых JA4 уйдут к origin в одну миллисекунду (hard rule 11)")
}

// Власть №8: NetworkChanged НЕ сбрасывает лестницу сам — только будит сигналом,
// а гейт lastWasRateLimited внутри reconnectLoopInner решает сам (запрет 2026-05-18).
func TestNetworkChanged_DoesNotResetLadderItself(t *testing.T) {
	body := stripLineComments(readMethodBody(t, "func (p *WSPoolTransport) NetworkChanged()"))

	assert.Contains(t, body, "signalNetworkRevival()",
		"NetworkChanged обязан будить backoff через signalNetworkRevival")
	// Проверяем ИСПОЛНЯЕМЫЙ код (комментарии сняты): метод не должен ни писать
	// lastWasRateLimited, ни обнулять attempt — это обошло бы гейт reconnectLoopInner
	// (запрет 2026-05-18: per-carrier рейт-лимит нельзя сбрасывать сменой сети).
	assert.NotContains(t, body, "lastWasRateLimited",
		"NetworkChanged не должен трогать lastWasRateLimited — сброс гейтится в reconnectLoopInner")
	assert.NotContains(t, body, "attempt =",
		"NetworkChanged не должен обнулять attempt напрямую — только будить сигналом")
}

// Власть №9: NetworkChanged — no-op на остановленном пуле (ctx отменён):
// слоты не рвутся, реконнекты не спавнятся.
func TestNetworkChanged_NoOpAfterPoolStop(t *testing.T) {
	p, _ := newNetworkChangeTestPool(t, 4)

	var connectCalls int32
	setConnectSlotForTest(func() error {
		atomic.AddInt32(&connectCalls, 1)
		return nil
	})
	t.Cleanup(func() { setConnectSlotForTest(nil) })

	p.cancel()
	p.NetworkChanged()

	time.Sleep(100 * time.Millisecond)
	assert.Zero(t, atomic.LoadInt32(&connectCalls),
		"на остановленном пуле NetworkChanged не должен инициировать реконнекты")
	for i, s := range p.slots {
		assert.Equal(t, slotReady, s.getState(),
			"на остановленном пуле слот %d не должен рваться — работы не осталось", i)
	}
}

// readMethodBody возвращает исходный текст тела метода от его сигнатуры до
// первой строки, состоящей ровно из "}" (закрытие метода верхнего уровня).
// Останавливаться на "\nfunc (" нельзя: между методами лежат doc-комментарии
// СЛЕДУЮЩЕГО метода, и их слова попали бы в проверяемое тело (именно так тело
// NetworkChanged захватывало lastWasRateLimited из докстринга reconnectLoopInner).
func readMethodBody(t *testing.T, signature string) string {
	t.Helper()
	src, err := os.ReadFile("ws_pool.go")
	require.NoError(t, err)
	body := string(src)
	idx := strings.Index(body, signature)
	require.NotEqual(t, -1, idx, "сигнатура %q не найдена — форма кода изменилась", signature)
	rest := body[idx:]
	// Закрытие метода — строка "}" в нулевой колонке. \r учитываем для CRLF.
	end := strings.Index(rest, "\n}")
	require.NotEqual(t, -1, end, "не удалось найти закрытие метода %q", signature)
	return rest[:end]
}

// stripLineComments выкидывает //-комментарии, чтобы форменные проверки смотрели
// на исполняемый код, а не на слова в пояснениях (комментарий метода законно
// упоминает lastWasRateLimited, объясняя, ПОЧЕМУ его не трогает).
func stripLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i != -1 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

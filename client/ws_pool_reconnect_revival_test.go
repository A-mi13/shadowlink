package client

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Сброс backoff-лестницы по сигналу «сеть вернулась» (P4, замер 2026-08-11).
//
// Полевой случай: origin стал недоступен в 15:48:34, слоты пошли по лестнице
// 5s·2^N. Origin вернулся к 15:49:19 (health показал alive=2, дальше 8, 12),
// но слоты 2 и 11 уже сидели на attempt=3 с паузой 60s и простояли лишние
// ~50 секунд по УЖЕ ЗДОРОВОЙ сети. Ёмкость пула восстанавливалась не потому,
// что сеть медленно оживала, а потому что мы её не спрашивали.
//
// Сигнал в системе уже есть: успешный connect любого другого слота. Лестница
// нужна против шторма хендшейков к origin (ws_pool.go, обоснование
// reconnectJitterWindow), поэтому сброс НЕ отменяет её, а лишь прерывает
// текущее ожидание: слот просыпается и пробует снова с attempt=0.

func newRevivalTestPool(t *testing.T) (*WSPoolTransport, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &WSPoolTransport{
		ctx: ctx,
		log: slog.New(slog.DiscardHandler),
	}
	p.initRevivalSignal()
	return p, cancel
}

// Ожидание должно прерваться сигналом, а не досидеть до конца.
func TestWaitBackoffOrRevival_WakesOnRevival(t *testing.T) {
	p, _ := newRevivalTestPool(t)

	start := time.Now()
	done := make(chan bool, 1)
	go func() {
		done <- p.waitBackoffOrRevival(30 * time.Second)
	}()

	time.Sleep(50 * time.Millisecond)
	p.signalNetworkRevival()

	select {
	case revived := <-done:
		assert.True(t, revived, "должен вернуть true — проснулись по сигналу")
	case <-time.After(2 * time.Second):
		t.Fatal("ожидание не прервалось сигналом — слот досиживает мёртвую паузу")
	}
	assert.Less(t, time.Since(start), 2*time.Second,
		"проснуться надо сразу, а не по истечении 30s")
}

// Без сигнала лестница обязана работать как раньше: досидеть паузу целиком.
// Иначе сброс превратится в обход защиты от шторма хендшейков.
func TestWaitBackoffOrRevival_ExpiresWithoutSignal(t *testing.T) {
	p, _ := newRevivalTestPool(t)

	start := time.Now()
	revived := p.waitBackoffOrRevival(120 * time.Millisecond)

	assert.False(t, revived, "без сигнала — обычное истечение таймера")
	assert.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond,
		"паузу надо выдержать: лестница защищает origin от шторма")
}

// Отмена ctx обязана прерывать ожидание — иначе остановка пула повиснет
// на 60-секундной паузе.
func TestWaitBackoffOrRevival_ExitsOnContextCancel(t *testing.T) {
	p, cancel := newRevivalTestPool(t)

	done := make(chan bool, 1)
	go func() {
		done <- p.waitBackoffOrRevival(30 * time.Second)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ожидание не прервалось по ctx — остановка пула повиснет")
	}
}

// Сигнал не должен копиться: он означает «сеть жива СЕЙЧАС», а не «когда-то
// был успех». Иначе слот, зашедший в ожидание через час, мгновенно проснулся
// бы на старом сигнале и обошёл лестницу.
func TestSignalNetworkRevival_DoesNotAccumulate(t *testing.T) {
	p, _ := newRevivalTestPool(t)

	for range 10 {
		p.signalNetworkRevival()
	}

	// Никто не ждал в момент сигналов → следующее ожидание идёт по таймеру.
	start := time.Now()
	revived := p.waitBackoffOrRevival(120 * time.Millisecond)

	require.False(t, revived, "старые сигналы не должны будить будущие ожидания")
	assert.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond)
}

// Сброс лестницы НЕ должен применяться после ErrRateLimited.
//
// Комментарий в reconnectLoopInner (2026-05-18) прямо запрещает `attempt = -1`
// после рейт-лимита: старое поведение заставляло следующую попытку идти с
// паузой attempt=0 (5-10s), она под давлением серверного TokenBucket снова
// упиралась в рейт-лимит, и цикл не заканчивался.
//
// Сигнал «сеть вернулась» открывает тот же вход заново: рейт-лимит бывает
// per-carrier/bucket, поэтому соседний слот может успешно подключиться и
// разбудить зажатый — а тот обнулит лестницу и пойдёт на новый отказ.
// Пробуждение само по себе безвредно; вредно именно обнуление.
func TestReconnectLadder_NotResetAfterRateLimit(t *testing.T) {
	src, err := os.ReadFile("ws_pool.go")
	require.NoError(t, err)

	// Проверяем форму кода, а не поведение: воспроизвести серверный
	// рейт-лимит в юните значит поднять сервер с TokenBucket, а сторожить
	// надо ровно одну строчку — гейт на сбросе.
	body := string(src)
	idx := strings.Index(body, "if p.waitBackoffOrRevival(d)")
	require.NotEqual(t, -1, idx, "вызов waitBackoffOrRevival не найден — форма кода изменилась")

	// Окно с запасом: гейт стоит сразу за вызовом, но перед ним развёрнутое
	// обоснование запрета 2026-05-18 — оно длиннее самого кода.
	gate := body[idx:min(idx+1600, len(body))]
	if !strings.Contains(gate, "lastWasRateLimited") {
		t.Errorf("сброс лестницы не гейтится по rate-limit — возвращён регресс 2026-05-18 "+
			"(бесконечный цикл под серверным TokenBucket). Фрагмент:\n%s", gate)
	}
}

// Один успех будит ВСЕ ждущие слоты: восстановление origin — событие
// общее для пула, а не для одной ячейки.
func TestSignalNetworkRevival_WakesAllWaiters(t *testing.T) {
	p, _ := newRevivalTestPool(t)

	const waiters = 5
	done := make(chan bool, waiters)
	for range waiters {
		go func() { done <- p.waitBackoffOrRevival(30 * time.Second) }()
	}
	time.Sleep(100 * time.Millisecond)

	p.signalNetworkRevival()

	for i := range waiters {
		select {
		case revived := <-done:
			assert.True(t, revived, "waiter %d должен проснуться по сигналу", i)
		case <-time.After(2 * time.Second):
			t.Fatalf("waiter %d не проснулся — сигнал разбудил не всех", i)
		}
	}
}

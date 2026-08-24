package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/proxy/socks5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStream — минимальная реализация client.StreamTransport для проверок
// жизненного цикла. Считает Close(), поэтому «закрыт ли ИМЕННО этот объект» —
// наблюдаемое состояние, а не догадка. Именно это делает тесты ниже
// детерминированными: на Windows -race недоступен (hard rule 6), и полагаться на
// детектор гонок нельзя.
type fakeStream struct {
	name    string
	closes  atomic.Int32
	reader  func(ctx context.Context) error
	writeMu sync.Mutex
	writes  int
}

func (f *fakeStream) WriteMessage(_ []byte) error {
	f.writeMu.Lock()
	f.writes++
	f.writeMu.Unlock()
	return nil
}

func (f *fakeStream) StartReader(ctx context.Context, _ *client.Client) error {
	if f.reader != nil {
		return f.reader(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeStream) Close() error {
	f.closes.Add(1)
	return nil
}

func (f *fakeStream) closed() bool { return f.closes.Load() > 0 }

var _ client.StreamTransport = (*fakeStream)(nil)

// newTestEngine собирает движок без сети: Connect не вызывается, поля
// расставляются напрямую. Проверяется поведение Close()/setStream, а не
// handshake.
func newTestEngine(t *testing.T) (*ShadowLinkEngine, context.CancelFunc) {
	t.Helper()
	e, err := NewShadowLinkEngine(&Config{SOCKS: "127.0.0.1:0"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.engineCtx = ctx
	return e, cancel
}

// TestClose_ClosesCurrentTransportNotStale — сторож дефекта №1.
//
// Дефект: streamReaderLoop переставлял e.stream без синхронизации, а Close()
// читал поле без блокировки и без ожидания ридера. Наблюдаемое последствие —
// закрывается СТАРЫЙ транспорт, новый остаётся висеть: утечка TLS-соединения к
// origin (P0-класс, hard rule 11).
//
// Тест воспроизводит это ДЕТЕРМИНИРОВАННО, без гонки: ридер переставляет
// транспорт и сигналит об этом; Close() зовётся строго после сигнала. Если
// Close() не дожидается ридера / читает поле мимо лока — при откате правки
// свежий транспорт остаётся незакрытым, и утверждение краснеет.
func TestClose_ClosesCurrentTransportNotStale(t *testing.T) {
	e, _ := newTestEngine(t)

	old := &fakeStream{name: "old"}
	fresh := &fakeStream{name: "fresh"}

	swapped := make(chan struct{})

	// Ридер имитирует реконнект одиночного WS: один раз переставляет транспорт
	// на свежий (ровно как боевой цикл в ветке single-WS) и после этого живёт до
	// отмены контекста. Возвращать ошибку здесь НЕЛЬЗЯ: боевой цикл на ней
	// уходит в настоящий UpgradeToWebSocket, а сети в тесте нет.
	var once sync.Once
	old.reader = func(ctx context.Context) error {
		once.Do(func() {
			e.setStream(fresh)
			close(swapped)
		})
		<-ctx.Done()
		return ctx.Err()
	}

	e.setStream(old)
	e.spawnStreamReader(e.engineCtx)

	select {
	case <-swapped:
	case <-time.After(2 * time.Second):
		t.Fatal("ридер не переставил транспорт")
	}

	require.NoError(t, e.Close())

	assert.True(t, fresh.closed(),
		"Close() обязан закрыть ТЕКУЩИЙ транспорт: иначе свежее TLS-соединение к origin остаётся висеть")
	assert.Equal(t, int32(0), old.closes.Load(),
		"старый транспорт закрывает сам ридер при реконнекте, Close() не должен закрывать его повторно")

	// Поле обязано быть снято под локом, а не просто прочитано. Это отдельное
	// требование, а не украшение: пока Close() лишь читал e.stream, припозднившийся
	// ридер мог поставить туда новый транспорт, и тот оставался бы закрыт никем.
	// Обнуление делает такую потерю невозможной по построению.
	assert.Nil(t, e.getStream(),
		"после Close() поле транспорта обязано быть снято под локом")
	assert.Equal(t, int32(1), fresh.closes.Load(),
		"текущий транспорт закрывается ровно один раз")
}

// TestClose_WaitsForStreamReader — вторая половина сторожа дефекта №1, и
// формулировать её надо аккуратно, иначе тест меряет не то.
//
// Соблазн проверить «Close() закрыл транспорт X» здесь не работает: ридер имеет
// право переставить транспорт на новый, и тогда X перестаёт быть текущим
// законно. Настоящий инвариант другой и он про утечку: **после возврата Close()
// не должно остаться НИ ОДНОГО незакрытого транспорта**. Именно он ломался, пока
// Close() не ждал ридера — тот ставил свежий WS уже после закрытия старого, и
// свежее TLS-соединение к origin оставалось висеть навсегда.
//
// Ридер здесь имитирует худший случай: просыпается по отмене и переставляет
// транспорт с задержкой, то есть гарантированно ПОЗЖЕ, чем Close() успел бы
// прочитать поле без ожидания.
func TestClose_WaitsForStreamReader(t *testing.T) {
	e, _ := newTestEngine(t)

	cur := &fakeStream{name: "cur"}
	late := &fakeStream{name: "late"}

	started := make(chan struct{})
	cur.reader = func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond)
		e.setStream(late)
		return ctx.Err()
	}

	e.setStream(cur)
	e.spawnStreamReader(e.engineCtx)
	<-started

	start := time.Now()
	require.NoError(t, e.Close())
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond,
		"Close() обязан дождаться выхода streamReaderLoop — иначе он читает поле до последней записи ридера")
	assert.True(t, late.closed(),
		"транспорт, поставленный ридером на выходе, обязан быть закрыт: без ожидания ридера Close() прочитал бы поле раньше этой записи и свежее TLS-соединение к origin осталось бы висеть")
	assert.Less(t, elapsed, streamReaderShutdownGrace+time.Second,
		"ожидание обязано быть ограничено сверху: зависший ридер не должен запирать Close()")
}

// TestClose_BoundedByGraceWhenReaderHangs — потолок ожидания. Ридер, зависший
// как в UpgradeToWebSocket (до HandshakeTimeout = 10 с), не должен запирать
// Close(): на iOS весь бюджет stopTunnel исчисляется секундами.
func TestClose_BoundedByGraceWhenReaderHangs(t *testing.T) {
	e, _ := newTestEngine(t)

	hung := &fakeStream{name: "hung"}
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })

	started := make(chan struct{})
	hung.reader = func(_ context.Context) error {
		close(started)
		<-blocked // игнорирует отмену контекста — ровно как зависший handshake
		return nil
	}

	e.setStream(hung)
	e.spawnStreamReader(e.engineCtx)
	<-started

	start := time.Now()
	require.NoError(t, e.Close())
	elapsed := time.Since(start)

	assert.Less(t, elapsed, streamReaderShutdownGrace+2*time.Second,
		"Close() обязан завершиться по таймауту, а не ждать зависший ридер вечно")
	assert.True(t, hung.closed(), "транспорт закрывается даже при зависшем ридере")
}

// TestSpawnStreamReader_AllLiveSpawnsAreTracked — сторож на то, что счётчик
// вообще имеет власть: без Add/Done в spawnStreamReader Wait() возвращается
// мгновенно и все проверки выше стали бы зелёными пустышками.
func TestSpawnStreamReader_TracksGoroutine(t *testing.T) {
	e, cancel := newTestEngine(t)
	defer cancel()

	st := &fakeStream{name: "tracked"}
	gate := make(chan struct{})
	st.reader = func(ctx context.Context) error {
		<-gate
		// Отменяем контекст сами: боевой цикл выходит ТОЛЬКО по ctx.Done, а на
		// простом возврате уходит в реконнект-ветку, которой в тесте нет сети.
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	e.setStream(st)
	e.spawnStreamReader(e.engineCtx)

	assert.False(t, e.waitStreamReaders(150*time.Millisecond),
		"пока ридер жив, ожидание обязано истечь по таймауту — иначе streamWG ничего не считает")

	close(gate)
	assert.True(t, e.waitStreamReaders(2*time.Second),
		"после выхода ридера ожидание обязано завершиться успехом")
}

// TestClose_Idempotent — предусловие дефекта №3: defer-cleanup в Connect зовёт
// Close(), и следом его же зовёт вызывающий по своему defer. До правки второй
// проход закрывал уже закрытый listener и повторно закрывал транспорты.
func TestClose_Idempotent(t *testing.T) {
	e, _ := newTestEngine(t)

	st := &fakeStream{name: "single"}
	e.setStream(st)

	// Настоящий SOCKS5-сервер с поднятым листенером: именно на нём повторный
	// Close() и проявлялся.
	srv := &socks5.Server{Addr: "127.0.0.1:0"}
	e.socks = srv
	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	go func() { _ = srv.ListenAndServe(srvCtx) }()
	require.Eventually(t, func() bool { return srv.ListenAddr() != nil },
		2*time.Second, 10*time.Millisecond, "листенер не поднялся")

	require.NotPanics(t, func() {
		require.NoError(t, e.Close())
		require.NoError(t, e.Close())
		require.NoError(t, e.Close())
	})

	assert.Equal(t, int32(1), st.closes.Load(),
		"транспорт обязан закрываться РОВНО один раз: повторное закрытие WS-пула шлёт лишние session-FIN")

	// ⚠ Проверка счётчика выше сама по себе НЕ доказывает гейт: Close() обнуляет
	// поле транспорта, поэтому второй проход не нашёл бы его и без гейта. Власть
	// над гейтом даёт только прямая проверка того, что второй проход НЕ делает
	// работу — а это наблюдаемо по числу пройденных тел Close().
	//
	// Почему гейт всё же нужен, раз повторное закрытие транспорта безвредно:
	// тела Close() не идемпотентны целиком. readyPool.Close() и pollWG.Wait()
	// зовутся по полям, которые не обнуляются, а cl.Close() дергает транспорт
	// клиента повторно. Гейт закрывает весь класс сразу, а не по одному месту.
	assert.Equal(t, int32(1), e.closeRuns.Load(),
		"тело Close() обязано исполниться РОВНО один раз: без гейта повторный вызов заново закрывает readyPool и клиента")
}

// TestConnect_ClosesEngineOnEarlyFailure — сторож дефекта №3.
//
// Дефект: ранние return в Connect звали только cancel(), но не закрывали уже
// поднятый client.Client / WS-пул / горутины. Отменённый контекст сам по себе не
// шлёт session-FIN и не рвёт TLS, поэтому на сервере оставались ghost-сессии.
//
// Точку отказа выбираем самую дешёвую и не требующую сети: пустой ShadowLink →
// Connect обязан вернуть ошибку. Проверка сути — что путь неуспеха проходит
// через Close(): после него движок помечен закрытым.
func TestConnect_FailureMarksEngineClosed(t *testing.T) {
	e, err := NewShadowLinkEngine(&Config{
		SOCKS: "127.0.0.1:0",
		// Неверный pubkey — отказ наступает до какого-либо сетевого обращения,
		// но УЖЕ внутри Connect, то есть по общему пути возврата.
		ShadowLink: &ShadowLinkConfig{Server: "127.0.0.1:1", PubKey: "zz-not-hex"},
	})
	require.NoError(t, err)

	require.Error(t, e.Connect(context.Background()))
}

// TestConnect_CleanupRunsOnFailureAfterClientConnected проверяет ГЛАВНОЕ в
// дефекте №3 — что defer-cleanup стоит на пути, где ресурсы уже подняты.
//
// Прямого способа поднять реальный client.Client без сервера нет, поэтому
// проверяется механизм: путь неуспеха обязан пройти через Close(), а Close() —
// закрыть транспорт. Подставляем транспорт до вызова и ломаем Connect на
// отсутствующем сервере.
func TestConnect_CleanupClosesTransportOnFailure(t *testing.T) {
	e, err := NewShadowLinkEngine(&Config{
		SOCKS:      "127.0.0.1:0",
		ShadowLink: &ShadowLinkConfig{Server: "127.0.0.1:1", PubKey: "00"},
	})
	require.NoError(t, err)

	st := &fakeStream{name: "preexisting"}
	e.setStream(st)

	require.Error(t, e.Connect(context.Background()),
		"подключение к закрытому порту обязано провалиться")

	assert.True(t, st.closed(),
		"путь неуспеха Connect обязан проходить через Close(): иначе висят client.Client, WS-пул и горутины")
	assert.True(t, e.closed.Load(), "движок обязан быть помечен закрытым")
}

// TestSetStream_AfterCloseClosesTransportInsteadOfInstalling — сторож остаточного
// окна дефекта №1, которое ожидание ридера НЕ закрывает.
//
// Ожидание ограничено сверху (streamReaderShutdownGrace), поэтому зависший ридер
// имеет право проснуться уже ПОСЛЕ Close() и позвать setStream с новым
// транспортом. Владельца у такого транспорта не остаётся: Close() уже прошёл, и
// закрыть его больше некому — это и есть утечка TLS-соединения к origin.
//
// Требование: после Close() установка не проходит, а транспорт закрывается на
// месте.
func TestSetStream_AfterCloseClosesTransportInsteadOfInstalling(t *testing.T) {
	e, _ := newTestEngine(t)

	first := &fakeStream{name: "first"}
	e.setStream(first)
	require.NoError(t, e.Close())
	require.True(t, first.closed())

	// Ровно то, что делает припозднившийся ридер в ветке single-WS.
	late := &fakeStream{name: "late-after-close"}
	e.setStream(late)

	assert.True(t, late.closed(),
		"транспорт, поставленный после Close(), обязан быть закрыт немедленно: иначе он остаётся висеть без владельца")
	assert.Nil(t, e.getStream(),
		"после Close() поле не должно принимать новые значения")
}

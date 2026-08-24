package mobile

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/engine"
)

// fakeEngine подменяет движок на путях жизненного цикла. Настоящий движок в
// этих тестах бесполезен: проверяются свойства ФАСАДА (идемпотентность,
// уничтожение движка на Stop, отсечение устаревших результатов), и поднятие
// туннеля их не показывает, а прячет за сетью.
type fakeEngine struct {
	id int

	connectErr   error
	connectGate  chan struct{} // если не nil — Connect ждёт закрытия
	connectCalls atomic.Int32
	closeCalls   atomic.Int32

	addr      net.Addr
	errCh     chan error
	readySlot atomic.Int32

	// netChangeCalls считает пробросы NetworkChanged. Счётчик нужен именно
	// здесь: сам факт «фасад дёрнул движок» иначе не наблюдаем, а без него
	// сторож проверял бы только то, что метод не паникует.
	netChangeCalls atomic.Int32
}

func (f *fakeEngine) NetworkChanged() { f.netChangeCalls.Add(1) }

func newFakeEngine(id int) *fakeEngine {
	f := &fakeEngine{
		id:    id,
		addr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000 + id},
		errCh: make(chan error, 1),
	}
	f.readySlot.Store(8)
	return f
}

func (f *fakeEngine) Connect(ctx context.Context) error {
	f.connectCalls.Add(1)
	if f.connectGate != nil {
		select {
		case <-f.connectGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.connectErr
}

func (f *fakeEngine) Close() error {
	f.closeCalls.Add(1)
	return nil
}

func (f *fakeEngine) ErrorCh() <-chan error { return f.errCh }

func (f *fakeEngine) SOCKSListenAddr() net.Addr {
	if f.connectErr != nil {
		return nil
	}
	return f.addr
}

func (f *fakeEngine) ReadySlots() int { return int(f.readySlot.Load()) }

// testConfig — минимальный валидный конфиг (ключ ненастоящий, но правильной
// длины: валидатор проверяет форму, а не принадлежность).
func testConfig() *Config {
	c := NewConfig()
	c.ServerAddr = "203.0.113.7:443"
	c.PubKeyHex = "aa" + fmt.Sprintf("%062x", 1)
	c.SNI = "example.com"
	c.UseTLS = true
	return c
}

// newTestSession возвращает сессию с подменённым конструктором движка и список
// всех созданных им движков — по нему видно, сколько их было и какие закрыты.
func newTestSession(t *testing.T, prepare func(*fakeEngine)) (*Session, *[]*fakeEngine) {
	t.Helper()
	s, err := NewSession(testConfig())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	var created []*fakeEngine
	s.newEngine = func(*engine.Config) (sessionEngine, error) {
		f := newFakeEngine(len(created))
		if prepare != nil {
			prepare(f)
		}
		created = append(created, f)
		return f, nil
	}
	return s, &created
}

// Двойной тап по кнопке подключения — обычный сценарий, а второй движок означал
// бы вдвое больше TLS-соединений к origin (P0-класс).
func TestSession_StartIsIdempotent(t *testing.T) {
	s, created := newTestSession(t, nil)

	if err := s.Start(); err != nil {
		t.Fatalf("первый Start: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("второй Start: %v", err)
	}
	if got := len(*created); got != 1 {
		t.Fatalf("движков создано %d, ожидался 1 — повторный Start поднял второй туннель", got)
	}
	if got := (*created)[0].connectCalls.Load(); got != 1 {
		t.Fatalf("Connect вызван %d раз, ожидался 1", got)
	}
	if s.State() != StateConnected {
		t.Fatalf("state=%s, ожидалось connected", s.State())
	}
	_ = s.Stop()
}

// engine.Close() необратим: Connect после него не предусмотрен. Значит Start
// после Stop ОБЯЗАН строить новый движок, иначе вторая сессия молча не
// поднимется.
func TestSession_StartAfterStopCreatesNewEngine(t *testing.T) {
	s, created := newTestSession(t, nil)

	if err := s.Start(); err != nil {
		t.Fatalf("Start #1: %v", err)
	}
	first := (*created)[0]
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if first.closeCalls.Load() != 1 {
		t.Fatalf("Stop не закрыл движок (closeCalls=%d)", first.closeCalls.Load())
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start #2: %v", err)
	}
	if got := len(*created); got != 2 {
		t.Fatalf("движков создано %d, ожидалось 2 — Stop не уничтожил старый", got)
	}
	second := (*created)[1]
	if second == first {
		t.Fatal("второй Start переиспользовал закрытый движок")
	}
	if second.connectCalls.Load() != 1 {
		t.Fatalf("новый движок не подключался: connectCalls=%d", second.connectCalls.Load())
	}
	_ = s.Stop()
}

// Уход приложения в фон до завершения подключения и повторный Stop — штатный
// путь жизненного цикла, а не краевой случай.
func TestSession_StopBeforeStartDoesNotPanic(t *testing.T) {
	s, created := newTestSession(t, nil)

	if err := s.Stop(); err != nil {
		t.Fatalf("Stop до Start вернул ошибку: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("повторный Stop вернул ошибку: %v", err)
	}
	if s.State() != StateIdle {
		t.Fatalf("state=%s, ожидалось idle", s.State())
	}
	if len(*created) != 0 {
		t.Fatalf("Stop создал движок: %d", len(*created))
	}
}

// Порт наружу отдаётся ФАКТИЧЕСКИЙ (bind на :0), поэтому до листенера его
// значение — ноль, а не «то, что записано в конфиге».
func TestSession_SocksPortLifecycle(t *testing.T) {
	s, created := newTestSession(t, nil)

	if got := s.SocksPort(); got != 0 {
		t.Fatalf("до Start SocksPort=%d, ожидался 0", got)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	want := int32((*created)[0].addr.(*net.TCPAddr).Port)
	if got := s.SocksPort(); got != want {
		t.Fatalf("SocksPort=%d, ожидался фактический порт листенера %d", got, want)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := s.SocksPort(); got != 0 {
		t.Fatalf("после Stop SocksPort=%d, ожидался 0", got)
	}
}

// State() опрашивается UI на каждом кадре, а Start держит мьютекс всё время
// подключения (замеренный fan-out 2.4 с, при зависшем handshake до 10 с). Если
// State возьмёт тот же мьютекс, интерфейс встанет вместе с подключением.
func TestSession_StateDoesNotBlockDuringStart(t *testing.T) {
	gate := make(chan struct{})
	s, _ := newTestSession(t, func(f *fakeEngine) { f.connectGate = gate })
	// Момент входа в connecting узнаём через колбэк, а не опросом State(): под
	// испорченной реализацией сам опрос и зависал бы, и тест ловил бы дефект
	// таймаутом всего прогона вместо внятного сообщения.
	h := &recordingHandler{}
	s.SetEventHandler(h)

	done := make(chan error, 1)
	go func() { done <- s.Start() }()
	waitFor(t, 2*time.Second, func() bool { return h.hasState(StateConnecting) })

	// Замер: State обязан вернуться, пока Connect ещё висит.
	got := make(chan string, 1)
	go func() { got <- s.State() }()
	select {
	case st := <-got:
		if st != StateConnecting {
			t.Fatalf("State=%s во время подключения, ожидалось connecting", st)
		}
	case <-time.After(time.Second):
		close(gate) // отпускаем Start, иначе прогон повиснет на утёкшей горутине
		t.Fatal("State() заблокировался на время Start — состояние читается под мьютексом переходов")
	}

	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("Start: %v", err)
	}
	_ = s.Stop()
}

// Неудачный Connect не должен оставлять за собой живой движок: на мобильном
// Start случается десятки раз за жизнь процесса, и каждый оставленный движок —
// это TLS-соединения к origin, то есть накопление P0-класса.
func TestSession_FailedStartClosesEngine(t *testing.T) {
	boom := errors.New("origin недоступен")
	s, created := newTestSession(t, func(f *fakeEngine) { f.connectErr = boom })
	h := &recordingHandler{}
	s.SetEventHandler(h)

	err := s.Start()
	if err == nil {
		t.Fatal("Start вернул nil при неудачном Connect")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("ошибка не обёрнута: %v", err)
	}
	if s.State() != StateFailed {
		t.Fatalf("state=%s, ожидалось failed", s.State())
	}
	if got := (*created)[0].closeCalls.Load(); got != 1 {
		t.Fatalf("движок после неудачного Connect не закрыт (closeCalls=%d)", got)
	}
	if got := s.SocksPort(); got != 0 {
		t.Fatalf("SocksPort=%d после неудачи, ожидался 0", got)
	}
	waitFor(t, time.Second, func() bool { return h.errCount() > 0 })
}

// Из failed сессия обязана подниматься новым Start — иначе объект после первой
// же сетевой неудачи становится мусором, а платформе нечего пересоздавать:
// NewSession она делает один раз.
func TestSession_StartAfterFailureIsAllowed(t *testing.T) {
	var failFirst atomic.Bool
	failFirst.Store(true)
	s, created := newTestSession(t, func(f *fakeEngine) {
		if failFirst.Swap(false) {
			f.connectErr = errors.New("первый раз мимо")
		}
	})

	if err := s.Start(); err == nil {
		t.Fatal("первый Start должен был упасть")
	}
	if err := s.Start(); err != nil {
		t.Fatalf("повторный Start после failed: %v", err)
	}
	if len(*created) != 2 {
		t.Fatalf("движков %d, ожидалось 2", len(*created))
	}
	if s.State() != StateConnected {
		t.Fatalf("state=%s, ожидалось connected", s.State())
	}
	_ = s.Stop()
}

// Фатальный сигнал движка, пришедший ПОСЛЕ Stop, не должен воскрешать сессию в
// failed: пользователь уже отключился, и красный экран после этого — ложь.
//
// ⚠ Этот тест измеряет ОТМЕНУ КОНТЕКСТА, а не проверку поколения: проверено
// порчей кода — с вырезанной проверкой `stale` он остаётся зелёным, потому что
// watchEngine успевает выйти по ctx.Done(). Проверку поколения сторожит
// отдельный тест ниже; без разделения мы имели бы один зелёный тест на два
// разных механизма и ложную уверенность в обоих.
func TestSession_ErrorAfterStopDoesNotResurrectSession(t *testing.T) {
	s, created := newTestSession(t, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	eng := (*created)[0]
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	eng.errCh <- errors.New("поздний сигнал")

	time.Sleep(50 * time.Millisecond)
	if s.State() != StateIdle {
		t.Fatalf("state=%s после Stop, ожидалось idle", s.State())
	}
}

// Проверка ПОКОЛЕНИЯ, отдельно от отмены контекста.
//
// Момент, ради которого она существует: если ошибка уже лежит в буфере errCh, а
// контекст только что отменили, select выбирает ветку СЛУЧАЙНО — и в половине
// случаев наблюдатель остановленной сессии допишет failed поверх состояния уже
// перезапущенной. Тест воспроизводит это детерминированно: контекст живой,
// поколение устаревшее.
func TestSession_StaleGenerationErrorIsIgnored(t *testing.T) {
	s, _ := newTestSession(t, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Stop() }()

	s.mu.Lock()
	staleGen := s.gen - 1 // поколение, которого сессия уже не ждёт
	s.mu.Unlock()

	eng := newFakeEngine(99)
	done := make(chan struct{})
	go func() {
		s.watchEngine(context.Background(), staleGen, eng)
		close(done)
	}()
	eng.errCh <- errors.New("ошибка из прошлой сессии")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("наблюдатель не вышел на устаревшем поколении")
	}
	if s.State() != StateConnected {
		t.Fatalf("state=%s — ошибка из прошлого поколения перебила состояние живой сессии", s.State())
	}
}

// Наблюдатель обязан выходить по отмене контекста, а не висеть на канале ошибок
// до конца процесса.
//
// Отдельный тест, потому что проверка поколения этот дефект НЕ показывает
// (проверено порчей кода: с вырезанной веткой ctx.Done() оба теста выше
// остаются зелёными — состояние-то верное). Цена дефекта не в состоянии, а в
// накоплении: Start/Stop на мобильном происходят десятки раз за жизнь процесса,
// и каждая пара оставляла бы по горутине с ссылкой на закрытый движок.
func TestSession_WatchEngineExitsOnContextCancel(t *testing.T) {
	s, _ := newTestSession(t, nil)
	eng := newFakeEngine(0)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		s.watchEngine(ctx, 1, eng)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("наблюдатель не вышел по отмене контекста — горутина остаётся жить после Stop")
	}
}

// Живой SOCKS5-порт при нулевом пуле — это «приложения получают зависшие
// сокеты», а не работающий VPN. Разница обязана быть видна снаружи.
func TestSession_DegradedWhenPoolHasNoReadySlots(t *testing.T) {
	oldPoll, oldDeg := healthPollInterval, degradedAfter
	healthPollInterval, degradedAfter = 5*time.Millisecond, 20*time.Millisecond
	defer func() { healthPollInterval, degradedAfter = oldPoll, oldDeg }()

	s, created := newTestSession(t, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	eng := (*created)[0]

	eng.readySlot.Store(0)
	waitFor(t, 2*time.Second, func() bool { return s.State() == StateDegraded })

	eng.readySlot.Store(3)
	waitFor(t, 2*time.Second, func() bool { return s.State() == StateConnected })
	_ = s.Stop()
}

// Креды генерируются внутри и на каждую сессию свои: снаружи их задать нельзя
// (иначе платформа выставит слабые), а на Android этот порт доступен любому
// приложению устройства.
func TestSession_CredentialsAreGeneratedPerSession(t *testing.T) {
	s1, err := NewSession(testConfig())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	s2, err := NewSession(testConfig())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if s1.SocksUser() == "" || s1.SocksPass() == "" {
		t.Fatal("пустые креды SOCKS5 — прокси доступен без аутентификации")
	}
	if len(s1.SocksPass()) < 16 {
		t.Fatalf("пароль длиной %d — слишком короткий", len(s1.SocksPass()))
	}
	if s1.SocksPass() == s2.SocksPass() {
		t.Fatal("пароль одинаков у двух сессий — он не случайный")
	}
}

// Креды обязаны доехать до движка: сгенерировать их и не передать — ровно тот
// случай, когда геттеры выглядят правдоподобно, а листенер стоит открытым.
func TestSession_CredentialsReachEngineConfig(t *testing.T) {
	s, err := NewSession(testConfig())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	var got *engine.Config
	s.newEngine = func(ec *engine.Config) (sessionEngine, error) {
		got = ec
		return newFakeEngine(0), nil
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Stop() }()

	if got.ProxyUser != s.SocksUser() || got.ProxyPass != s.SocksPass() {
		t.Fatalf("движок получил user=%q pass=%q, а фасад отдаёт наружу %q/%q",
			got.ProxyUser, got.ProxyPass, s.SocksUser(), s.SocksPass())
	}
	if got.ProxyPass == "" {
		t.Fatal("движок поднимет SOCKS5 без пароля")
	}
}

// waitFor опрашивает условие до таймаута. Детерминированной альтернативы нет:
// наблюдатели здоровья и ошибок по построению асинхронны (hard rule 6 — -race
// на Windows недоступен, поэтому свойства проверяются состоянием, а не гонками).
func waitFor(t *testing.T, limit time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("условие не выполнилось за отведённое время")
}

// NetworkChanged обязан ДОЕЗЖАТЬ до движка, а не только считаться.
//
// Что ловит этот сторож. Метод легко написать так, что он выглядит рабочим:
// инкремент счётчика, никаких паник, тест «не упало» зелёный. Но смысл вызова
// в том, чтобы ядро порвало слоты и разнесло реконнект — без пробоса восемь
// слотов после смены сети зависают со старым адресом до TCP-таймаута, а дальше
// backoff, вырождающийся в 60 с. То есть молчаливая пустышка стоит десятков
// секунд простоя туннеля, и отличить её от рабочего метода можно только
// наблюдая вызов на стороне движка.
func TestSession_NetworkChangedReachesEngine(t *testing.T) {
	s, created := newTestSession(t, nil)

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop() })

	if len(*created) != 1 {
		t.Fatalf("ожидался один движок, создано %d", len(*created))
	}
	eng := (*created)[0]

	s.NetworkChanged()
	s.NetworkChanged()

	if got := eng.netChangeCalls.Load(); got != 2 {
		t.Fatalf("движок получил %d вызовов NetworkChanged, ожидалось 2 — "+
			"сигнал платформы не доезжает до ядра", got)
	}
}

// Вне подключения сигнал платформы не должен ронять процесс: ОС шлёт смену сети
// когда ей угодно, в том числе до Start и после Stop, а паника в Go на мобильном
// убивает всё приложение, а не только VPN.
func TestSession_NetworkChangedSafeOutsideConnection(t *testing.T) {
	s, _ := newTestSession(t, nil)

	s.NetworkChanged() // до Start

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	s.NetworkChanged() // после Stop
}

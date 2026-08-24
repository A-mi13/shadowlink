package mobile

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/engine"
)

// Состояния сессии. Строки, а не константы Go: gobind не переносит именованные
// типы-перечисления через границу языка внятным образом, а строку понимают обе
// платформы.
const (
	StateIdle       = "idle"
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateDegraded   = "degraded"
	StateFailed     = "failed"
)

// Внутреннее представление состояния — int32 в atomic, чтобы State() не ждал
// мьютекса. Причина конкретная: Start() держит мьютекс всё время подключения
// (fan-out восьми слотов — замеренные 2.4 с, а при зависшем handshake до 10 с),
// и UI, опрашивающий State() на каждом кадре, встал бы вместе с ним.
const (
	stIdle int32 = iota
	stConnecting
	stConnected
	stDegraded
	stFailed
)

func stateName(v int32) string {
	switch v {
	case stConnecting:
		return StateConnecting
	case stConnected:
		return StateConnected
	case stDegraded:
		return StateDegraded
	case stFailed:
		return StateFailed
	default:
		return StateIdle
	}
}

// sessionEngine — то, чем Session пользуется от движка.
//
// Интерфейс, а не *engine.ShadowLinkEngine, ради тестируемости жизненного
// цикла: идемпотентность Start/Stop и «Start после Stop создаёт НОВЫЙ движок»
// — свойства фасада, и проверять их поднятием настоящего туннеля значило бы не
// проверять их вовсе.
type sessionEngine interface {
	Connect(ctx context.Context) error
	Close() error
	ErrorCh() <-chan error
	SOCKSListenAddr() net.Addr
	ReadySlots() int
	// NetworkChanged рвёт слоты и разносит реконнект при смене сети. Вне
	// режима пула — no-op на стороне движка, а не ошибка здесь.
	NetworkChanged()
}

// Проверка на этапе компиляции: настоящий движок обязан оставаться пригодным
// для фасада. Без неё смена сигнатуры в engine/ обнаружилась бы только когда
// кто-то соберёт .aar.
var _ sessionEngine = (*engine.ShadowLinkEngine)(nil)

// Session — одно подключение. Объект переиспользуемый: Stop() возвращает его в
// idle, а следующий Start() поднимает всё заново.
type Session struct {
	// mu сериализует ПЕРЕХОДЫ (Start/Stop), но не чтение состояния.
	mu sync.Mutex

	state atomic.Int32
	// port хранится отдельно от движка, потому что читается снаружи в любой
	// момент, в том числе пока mu занят Start'ом.
	port atomic.Int32

	cfg  *Config
	user string
	pass string

	// eng ненулевой только между успешным Start и Stop. Stop его УНИЧТОЖАЕТ:
	// engine.Close() необратим (отменяет контекст, закрывает пул, транспорт и
	// клиента), Connect после него не предусмотрен. Поэтому Start после Stop
	// строит новый движок, а не переиспользует старый.
	eng    sessionEngine
	cancel context.CancelFunc

	// gen отсекает результат подключения, которое уже никому не нужно: между
	// стартом горутины и её завершением платформа могла успеть нажать Stop и
	// снова Start. Без поколения старый Connect дописал бы своё состояние
	// поверх нового.
	gen uint64

	events *dispatcher

	// newEngine — точка подмены в тестах. В проде это конструктор движка.
	newEngine func(*engine.Config) (sessionEngine, error)

	// networkChanges считает вызовы NetworkChanged. См. комментарий метода:
	// счётчик существует, потому что делать метод молчаливой пустышкой хуже,
	// чем показать, что сигнал приходит, а обработать его пока нечем.
	networkChanges atomic.Int64
}

// NewSession проверяет конфиг и готовит сессию. Сеть не трогает — подключение
// начинается со Start.
func NewSession(cfg *Config) (*Session, error) {
	if cfg == nil {
		return nil, fmt.Errorf("session: config is nil")
	}
	snapshot := cfg.clone()
	user, pass := generateProxyCredentials()
	// Ранняя валидация: кривой pubkey должен приехать в вызывающего здесь,
	// синхронно, а не асинхронным OnError через полсекунды после Start.
	if _, err := buildEngineConfig(snapshot, user, pass); err != nil {
		return nil, err
	}
	s := &Session{
		cfg:    snapshot,
		user:   user,
		pass:   pass,
		events: newDispatcher(),
	}
	s.newEngine = func(ec *engine.Config) (sessionEngine, error) {
		return engine.NewShadowLinkEngine(ec)
	}
	s.state.Store(stIdle)
	return s, nil
}

// SetEventHandler подключает приёмник событий. nil отключает мост и снимает
// ссылку на Java-объект (та же утечка Activity, что и у SetLogger).
func (s *Session) SetEventHandler(h EventHandler) { s.events.setEvents(h) }

// State возвращает текущее состояние: idle|connecting|connected|degraded|failed.
// Не блокируется никогда — в том числе во время Start.
func (s *Session) State() string { return stateName(s.state.Load()) }

// SocksPort возвращает ФАКТИЧЕСКИЙ порт локального SOCKS5 или 0, пока листенера
// нет (до Start, во время подключения, после Stop).
//
// Порт фактический, а не заданный: фасад биндится на 127.0.0.1:0, потому что
// любой заранее выбранный порт на телефоне может быть занят другим
// VPN-приложением.
func (s *Session) SocksPort() int32 { return s.port.Load() }

// SocksUser/SocksPass — креды локального прокси. Генерируются внутри на каждую
// сессию: снаружи их задать нельзя, иначе платформа смогла бы выставить слабые
// или пустые, а на Android этот порт доступен любому приложению устройства.
func (s *Session) SocksUser() string { return s.user }
func (s *Session) SocksPass() string { return s.pass }

// Start поднимает туннель. Идемпотентен: повторный вызов в состояниях
// connecting/connected/degraded — no-op, а не второй движок (двойной тап по
// кнопке — обычное дело, а второй движок означал бы вдвое больше TLS-соединений
// к origin, что относится к P0-классу).
//
// Блокируется на время подключения. Это осознанная цена за то, что ошибка
// конфигурации и отказ сети возвращаются вызывающему как ошибка, а не теряются
// в асинхронном колбэке; платформа обязана звать Start не из UI-потока.
// Готовность ПУЛА при этом не ожидается — движок возвращает управление, как
// только поднялся SOCKS5-листенер, а слоты дозаполняются фоном.
func (s *Session) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state.Load() {
	case stConnecting, stConnected, stDegraded:
		return nil // уже поднято или поднимается
	}

	ec, err := buildEngineConfig(s.cfg, s.user, s.pass)
	if err != nil {
		s.setState(stFailed)
		return err
	}
	eng, err := s.newEngine(ec)
	if err != nil {
		s.setState(stFailed)
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.gen++
	gen := s.gen
	s.eng = eng
	s.cancel = cancel
	s.setState(stConnecting)

	if err := eng.Connect(ctx); err != nil {
		cancel()
		_ = eng.Close()
		s.eng = nil
		s.cancel = nil
		s.setState(stFailed)
		s.emitError(err.Error())
		return fmt.Errorf("session: подключение не удалось: %w", err)
	}

	if addr := eng.SOCKSListenAddr(); addr != nil {
		if _, port, splitErr := net.SplitHostPort(addr.String()); splitErr == nil {
			var p int
			_, _ = fmt.Sscanf(port, "%d", &p)
			s.port.Store(int32(p))
		}
	}
	s.setState(stConnected)

	go s.watchEngine(ctx, gen, eng)
	go s.watchHealth(ctx, gen, eng)
	return nil
}

// Stop останавливает туннель и УНИЧТОЖАЕТ движок. Идемпотентен и безопасен до
// первого Start.
//
// Close() зовётся под тем же мьютексом, что и Start, намеренно: если отпустить
// замок раньше, платформенный сценарий «Stop → сразу Start» (уход и возврат из
// фона) даст перекрытие двух движков, а SetGlobalPoolForStats(nil) на закрытии
// старого пула безусловен и обнулит указатель, который успел выставить новый —
// наблюдаемость слотов умрёт молча.
func (s *Session) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	eng, cancel := s.eng, s.cancel
	s.eng, s.cancel = nil, nil
	s.gen++ // всё, что подключалось до этого момента, больше не относится к сессии
	s.port.Store(0)

	if cancel != nil {
		cancel()
	}
	var err error
	if eng != nil {
		err = eng.Close()
	}
	s.setState(stIdle)
	return err
}

// NetworkChanged — сигнал от платформы о смене сети (Wi-Fi↔LTE,
// ConnectivityManager.NetworkCallback / NWPathMonitor).
//
// Зачем он нужен: без него восемь слотов держат TCP со старого адреса и не
// падают, а ЗАВИСАЮТ до TCP-таймаута — RST слать некому. Смерть заметит только
// ридер или keepalive, дальше экспоненциальный backoff, который при attempt ≥ 4
// вырождается ровно в 60 с. Туннель встаёт на десятки секунд, а ОС знала о
// смене сети мгновенно.
//
// Зовётся из UI-потока платформы, поэтому не блокирует: движок разрывает слоты
// и разносит реконнект сам (client.WSPoolTransport.NetworkChanged).
//
// Безопасен вне подключения: до Start и после Stop движка нет, вызов
// проглатывается. Счётчик ведётся для диагностики — платформа может звать метод
// заметно чаще, чем реально меняется сеть.
func (s *Session) NetworkChanged() {
	s.networkChanges.Add(1)

	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()

	if eng == nil {
		return
	}
	// Движок сам решает, есть ли под ним пуловый транспорт: вне режима пула
	// это no-op, а не ошибка.
	eng.NetworkChanged()
}

// setState публикует состояние и уведомляет платформу. Зовётся под mu на путях
// Start/Stop и без него из наблюдателей — состояние атомарно, а порядок
// уведомлений гарантируется единственностью горутины-диспетчера.
func (s *Session) setState(v int32) {
	if s.state.Swap(v) == v {
		return // не тревожим платформу повторами одного и того же
	}
	s.events.emit(dispatchEvent{kind: kindState, msg: stateName(v)})
}

func (s *Session) emitError(msg string) {
	s.events.emit(dispatchEvent{kind: kindError, msg: msg})
}

// watchEngine превращает единственный фатальный сигнал движка в состояние
// failed и OnError.
//
// Своего автореконнекта здесь НЕТ и быть не должно: реконнект уже есть уровнем
// ниже и он бесконечный, а второй контур поверх удвоил бы число соединений к
// origin — ровно тот P0-класс, ради которого существует ротация.
func (s *Session) watchEngine(ctx context.Context, gen uint64, eng sessionEngine) {
	select {
	case <-ctx.Done():
		return
	case err := <-eng.ErrorCh():
		if err == nil {
			return
		}
		s.mu.Lock()
		stale := s.gen != gen
		s.mu.Unlock()
		if stale {
			return // сессию уже остановили или перезапустили
		}
		s.setState(stFailed)
		s.emitError(err.Error())
	}
}

// healthPollInterval / degradedAfter — параметры наблюдателя здоровья.
//
// К тайминговому контуру протокола (hard rule 8) отношения не имеют: опрос
// читает уже посчитанный счётчик готовых слотов и на провод ничего не шлёт.
// Переменные, а не константы, ровно для одного: тест должен проверять ЛОГИКУ
// перехода в degraded, а не ждать пятнадцать секунд.
var (
	healthPollInterval = 5 * time.Second
	degradedAfter      = 15 * time.Second
)

// watchHealth отличает «сессия жива» от «туннель работает».
//
// Различие не теоретическое: SOCKS5-порт продолжает принимать соединения и при
// нулевом пуле, приложения получают зависшие сокеты, а фатальной ошибки движок
// в пуловом режиме не сигналит вовсе (ветка реконнекта для пула молча
// возвращается). Без этого наблюдателя State() показывал бы connected ровно
// там, где наблюдаемость нужнее всего.
func (s *Session) watchHealth(ctx context.Context, gen uint64, eng sessionEngine) {
	t := time.NewTicker(healthPollInterval)
	defer t.Stop()
	var zeroSince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		stale := s.gen != gen
		s.mu.Unlock()
		if stale {
			return
		}
		switch cur := s.state.Load(); cur {
		case stConnected, stDegraded:
		default:
			continue // failed/idle обслуживают другие пути
		}
		ready := eng.ReadySlots()
		if ready < 0 {
			continue // транспорт не пуловый — здоровье не наблюдаемо
		}
		if ready > 0 {
			zeroSince = time.Time{}
			s.setState(stConnected)
			continue
		}
		if zeroSince.IsZero() {
			zeroSince = time.Now()
			continue
		}
		if time.Since(zeroSince) >= degradedAfter {
			s.setState(stDegraded)
		}
	}
}

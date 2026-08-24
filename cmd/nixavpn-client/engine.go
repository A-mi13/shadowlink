package main

import (
	"context"
	"fmt"

	"github.com/nixavpn/shadowlink/engine"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

// toEngineConfig отдаёт движку только те поля, которые он читает.
//
// Мост существует не ради красоты: CLI-шный Config несёт *VLESSConfig и
// *APIConfig, а VLESS тянет за собой xray-core. Передача полного конфига
// связала бы пакет engine с этой зависимостью и раздула бы будущий мобильный
// артефакт. Поля перечислены явно, чтобы добавление нового в CLI не протекало
// в движок молча.
func toEngineConfig(cfg *Config) *engine.Config {
	// nil пробрасывается как nil: NewShadowLinkEngine отвергает его ошибкой,
	// поэтому глушить случай здесь нечем и не нужно.
	if cfg == nil {
		return nil
	}
	return &engine.Config{
		SOCKS:      cfg.SOCKS,
		SystemVPN:  cfg.SystemVPN,
		ProxyUser:  cfg.ProxyUser,
		ProxyPass:  cfg.ProxyPass,
		ShadowLink: cfg.ShadowLink,
	}
}

// Engine — абстракция VPN-протокола.
// Каждый engine подключается к серверу и выставляет SOCKS5 на localhost.
type Engine interface {
	// Connect подключается к серверу и запускает SOCKS5 прокси.
	Connect(ctx context.Context) error
	// SOCKSAddr возвращает адрес SOCKS5 прокси (например "127.0.0.1:1080").
	SOCKSAddr() string
	// Name возвращает имя протокола для логов.
	Name() string
	// Close закрывает соединение и останавливает SOCKS5.
	Close() error
}

// ErrorSignaller — опциональный интерфейс: engine, который его реализует,
// сообщает о собственной фатальной смерти (W8-контур: main дожидается либо
// сигнала ОС, либо этого канала, и завершает процесс).
//
// Зачем интерфейс, а не type assertion на конкретный тип: до 2026-08-24
// main.go делал `eng.(*ShadowLinkEngine)`, и при переносе движка в отдельный
// пакет промах assertion'а не был бы замечен компилятором — comma-ok молча
// вернул бы false, engineErr остался бы nil, и клиент перестал бы выходить при
// смерти SOCKS5. Именованный интерфейс + compile-time проверка ниже делают эту
// связь наблюдаемой для компилятора, а не для читателя.
type ErrorSignaller interface {
	// ErrorCh возвращает канал, в который приходит ПЕРВАЯ фатальная ошибка
	// движка. Канал буферизован (1) и пишется под sync.Once — то есть сигнал
	// одноразовый и терминальный, а не поток ошибок.
	ErrorCh() <-chan error
}

// Реализации ErrorSignaller. Проверка на этапе компиляции: если движок
// перестанет удовлетворять интерфейсу (переименование метода, смена сигнатуры,
// перенос в другой пакет), сборка упадёт здесь, а не деградирует молча в main.
var _ ErrorSignaller = (*engine.ShadowLinkEngine)(nil)

// InProcessDialerProvider проверяется по той же причине, что и ErrorSignaller:
// main.go берёт его через type assertion с comma-ok (main.go:241), поэтому
// промах отключил бы in-process dialer молча — TUN-трафик пошёл бы через
// loopback-сокет, чего Bug #5 как раз и избегает.
//
// Engine в этом списке — сторож-ТАВТОЛОГИЯ, и это осознанно (ревью 2026-08-24
// проверило удалением строки): NewEngine ниже возвращает Engine, поэтому
// присваиваемость уже проверяется компилятором на return. Строка оставлена как
// декларация намерения, но новой информации не несёт — не считать её защитой.
var (
	_ Engine                  = (*engine.ShadowLinkEngine)(nil)
	_ InProcessDialerProvider = (*engine.ShadowLinkEngine)(nil)
)

// InProcessDialerProvider — опциональный интерфейс (Bug #5). Engine, который его
// реализует, отдаёт in-process tun2socks dialer: TUN-трафик туннелируется через
// WS напрямую in-process, без loopback-сокета к SOCKS5 (устраняет Windows
// ephemeral port exhaustion на высокой скорости). Реализован только
// *ShadowLinkEngine; VLESS его не реализует и продолжает работать через loopback.
// Возвращает nil если dialer недоступен (например движок ещё не Connect'нут).
type InProcessDialerProvider interface {
	InProcessDialer() proxy.Dialer
}

// NewEngine создаёт engine по имени протокола.
func NewEngine(protocol string, cfg *Config) (Engine, error) {
	switch protocol {
	case "shadowlink":
		return engine.NewShadowLinkEngine(toEngineConfig(cfg))
	case "vless":
		return NewVLESSEngine(cfg)
	default:
		return nil, fmt.Errorf("неизвестный протокол: %s", protocol)
	}
}

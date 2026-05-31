package main

import (
	"context"
	"fmt"

	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

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
		return NewShadowLinkEngine(cfg)
	case "vless":
		return NewVLESSEngine(cfg)
	default:
		return nil, fmt.Errorf("неизвестный протокол: %s", protocol)
	}
}

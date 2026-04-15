package main

import (
	"context"
	"fmt"
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

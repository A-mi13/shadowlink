// Package engine содержит транспортный движок ShadowLink: подключение к
// серверу, WS-пул, SOCKS5-прокси и роутинг.
//
// Пакет намеренно НЕ содержит платформенной обвязки (TUN, leakguard, split-DNS,
// разбор CLI-флагов) — она остаётся в cmd/nixavpn-client. Благодаря этому
// engine собирается под android/arm64 и ios/arm64 и может служить основой
// gomobile-фасада (см. docs/superpowers/specs/2026-08-24-mobile-facade-design.md).
package engine

import "github.com/nixavpn/shadowlink/client"

// Config — то, что движку РЕАЛЬНО нужно от вызывающего.
//
// Это НЕ полный конфиг клиента: у CLI своя структура с полями protocol/vless/api
// и YAML-тегами верхнего уровня. Движок читает отсюда ровно пять полей, и сузить
// тип было обязательно, а не косметично: полный main.Config несёт *VLESSConfig,
// который тянет engine_vless.go, а тот — xray-core со всей его транзитивной
// массой. Для мобильного .aar это неприемлемо по размеру, поэтому VLESS остаётся
// целиком на стороне CLI.
//
// Вызывающий (CLI или мобильный фасад) конвертирует свою структуру в эту.
type Config struct {
	// SOCKS — адрес, на котором движок поднимает SOCKS5 ("127.0.0.1:1080").
	// Пустая строка означает, что листенер не поднимается.
	//
	// Выбор адреса остаётся за вызывающим намеренно: CLI берёт случайный порт
	// (сокрытие характерного 1080), мобильный фасад — ":0" с последующим
	// опросом фактического порта.
	SOCKS string

	// SystemVPN включает режим системного VPN. Движок использует его как
	// признак того, что трафик идёт через TUN, а не только через SOCKS5:
	// от этого зависят выбор транспорта и политика реконнекта. Сам TUN
	// поднимает вызывающий.
	SystemVPN bool

	// ProxyUser/ProxyPass — credentials SOCKS5. Защищают от того, чтобы
	// локальным прокси воспользовался посторонний процесс на той же машине.
	// Генерируются вызывающим на каждый запуск.
	ProxyUser string
	ProxyPass string

	// ShadowLink — параметры протокола. nil означает отсутствие конфигурации:
	// Connect вернёт ошибку.
	ShadowLink *ShadowLinkConfig

	// ClientID — идентичность клиента в handshake, ровно 16 байт. Пустое или
	// иной длины значение означает «сгенерировать UUIDv4 на этот Connect»
	// (поведение CLI до 2026-08-24 и после — он поля не задаёт).
	//
	// Поле заведено ради мобильного фасада: там процесс переживает много
	// подключений подряд, и UUID на каждый Connect давал бы новую идентичность
	// при каждом возврате из фона. Движок значение НЕ интерпретирует.
	ClientID []byte

	// StateDir — каталог, где персистится состояние fingerprint-профиля
	// (fp-state.bin, client.ClientConfig.FPCacheDir). Пустая строка = не
	// сохранять: профиль выбирается заново на каждый старт.
	//
	// Для мобильных это не косметика: переизбираемый профиль означает дрейф
	// отпечатка между запусками, а уникальность и есть сигнал (hard rule 2).
	// CLI поле не заполняет — персист там до сих пор мёртв (§4.5 спеки).
	StateDir string
}

// ShadowLinkConfig holds ShadowLink protocol connection settings.
//
// YAML-теги сохранены: структура десериализуется напрямую из клиентского
// конфига на стороне CLI (cmd/nixavpn-client/config.go).
type ShadowLinkConfig struct {
	Server     string                `yaml:"server"`
	PubKey     string                `yaml:"pubkey"`
	WebSocket  bool                  `yaml:"websocket"`
	TLS        bool                  `yaml:"tls"`
	Auto       bool                  `yaml:"auto"`
	CDN        string                `yaml:"cdn,omitempty"`
	Routing    *client.RoutingConfig `yaml:"routing,omitempty"`
	Origin     string                `yaml:"origin,omitempty"`       // origin IP for direct WS (bypass CF CDN)
	SNI        string                `yaml:"sni,omitempty"`          // TLS ServerName override for full-direct mode (IP host + domain SNI)
	CFIP       string                `yaml:"cfip,omitempty"`         // specific Cloudflare edge IP (bypass DNS for WS)
	WSPool     bool                  `yaml:"ws_pool,omitempty"`      // enable WS pool (default true for CDN+WS)
	WSPoolSize int                   `yaml:"ws_pool_size,omitempty"` // pool size (default 8; ready-pool в per-stream режиме — 6)
	// FlowWindow — окно flow control на стрим, байты. 0 = env
	// SHADOWLINK_FLOW_WINDOW, затем дефолт 1 МиБ. Потолок 6 МиБ.
	//
	// Ручка нужна встроенным клиентам: до 2026-09-01 окно задавалось ТОЛЬКО
	// переменной окружения, а мобильный фасад живёт внутри чужого процесса
	// (на iOS — в extension), где выставить env практически нечем. Величина не
	// косметическая: она задаёт потолок ОДНОГО потока (окно / RTT), и серверный
	// -flow-max-window его не поднимает — согласование берёт min(клиент, сервер).
	FlowWindow uint64 `yaml:"flow_window,omitempty"`
	// BackupServers are fallback "host:port" endpoints tried in order when
	// the primary Server handshake fails (ТСПУ blocks the CF SNI, DNS
	// poisoning, etc.). Must share the same X25519 pubkey.
	BackupServers []string `yaml:"backup_servers,omitempty"`
	// CDNs is the SNI rotation pool (DomainPool). Distinct from BackupServers
	// (alternative host:port endpoints). When non-empty, the engine installs a
	// DomainPool on the transport's ConnManager and rotates SNI per reconnect
	// against this list. Max enforced by client.maxCDNs (=8) on URL parsing.
	CDNs []string `yaml:"cdns,omitempty"`
}

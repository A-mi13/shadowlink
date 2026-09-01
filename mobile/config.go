// Package mobile — плоский фасад ShadowLink для gomobile (.aar / .xcframework).
//
// Форма API продиктована gobind, а не вкусом: он не умеет структуры по
// значению (отсюда *Config и конструкторы), не умеет слайсы кроме []byte
// (отсюда JSON-строка для routing), не умеет context.Context (создаётся
// внутри Start) и маппит Go-шный int в Java long (отсюда int32 у размерных
// полей). Дизайн и обоснования — docs/superpowers/specs/2026-08-24-mobile-facade-design.md.
//
// Граница API — SOCKS5 на 127.0.0.1, а не TUN fd: этот режим не тянет gVisor
// (0 пакетов против 41 у tun2socks/v2/engine) и одинаково годится Android и
// iOS. Заворачивание трафика остаётся за платформой.
package mobile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/engine"
)

// Config — параметры подключения, которые задаёт платформа.
//
// Поля публичные: gobind сам делает из них геттеры/сеттеры (cfg.setServerAddr
// в Java, cfg.serverAddr в Swift), писать их руками не нужно. Размерные поля
// объявлены int32 намеренно — Go-шный int на 64-битном Android приезжает в
// Java как long.
type Config struct {
	// ServerAddr — "host:port" сервера. В прод-конфигурации это голый origin IP
	// (hard rule 1: никакого CDN/domain fronting), а доменное имя приезжает
	// отдельно в SNI.
	ServerAddr string

	// PubKeyHex — X25519-ключ сервера, 64 hex-символа (как в sl://-ссылке).
	PubKeyHex string

	// ClientIDHex — 32 hex-символа (16 байт). НЕПРОЗРАЧНАЯ строка: фасад её не
	// интерпретирует и в HKDF-info она попадает как есть.
	//
	// Задаёт платформа и хранит между запусками — иначе идентичность клиента
	// меняется на каждый возврат приложения из фона. Значение должно быть
	// СЛУЧАЙНЫМ (сгенерированный один раз UUID), а не производным от аккаунта:
	// подписи в handshake нет, и предсказуемый ID ослабил бы аутентификацию
	// сервера (§4.4 спеки). Пустая строка = случайный UUID на каждый Start.
	ClientIDHex string

	// SNI — доменное имя в TLS ServerName при подключении к IP из ServerAddr
	// (режим full-direct).
	SNI string

	// CDN — домен, за которым стоит origin. Оставлен для совместимости формата
	// ссылки; прод-режим — direct к origin (hard rule 1).
	CDN string

	// UseTLS включает TLS. Выключать имеет смысл только в лабораторных стендах.
	UseTLS bool

	// WSPoolSize — число слотов WS-пула. 0 = дефолт движка (8).
	//
	// Уменьшение снижает и энергопотребление, и число TCP-соединений к origin,
	// но одновременно и выживаемость пула, поэтому менять его «на глаз» нельзя
	// (hard rule 8) — только с замером.
	WSPoolSize int32

	// FlowWindowKB — окно flow control на стрим, в КИЛОБАЙТАХ. 0 = дефолт
	// движка (1 МиБ). Потолок 6 МиБ (6144); большее значение будет прижато.
	//
	// В килобайтах, а не в байтах, потому что gobind не переносит uint64 через
	// границу языка, а int32 в байтах упёрся бы в 2 ГиБ и провоцировал бы
	// путаницу единиц на стороне платформы.
	//
	// Зачем ручка. Окно задаёт потолок скорости ОДНОГО потока: окно / RTT.
	// Замер команды NixaVPN 2026-09-01 — один поток ~23 Мбит/с при RTT 241 мс,
	// туннель целиком ~187 Мбит/с на 8 потоках; это и есть 1 МиБ / 241 мс с
	// поправкой на возврат кредитов. До этой правки величина задавалась ТОЛЬКО
	// переменной окружения SHADOWLINK_FLOW_WINDOW, которую в extension на iOS
	// выставить нечем, то есть на мобильных ручки не было вовсе.
	//
	// ⚠ Серверный -flow-max-window потолок НЕ поднимает: согласование берёт
	// min(клиент, сервер), поэтому меньшая сторона связывает всегда.
	//
	// ⚠ Поднимать не «на всякий случай»: больший буфер — больше памяти на
	// стрим, а бюджет NEPacketTunnelProvider ограничен (50 MiB с iOS 15) и
	// пики приходятся на переподключение. Менять с замером.
	FlowWindowKB int32

	// StateDir — каталог приложения для персистентного состояния (fp-state.bin).
	// Пустая строка означает, что fingerprint-профиль будет переизбираться на
	// каждом старте — на мобильных это работает против hard rule 2.
	StateDir string

	// routing/bypass приватные: gobind экспортирует только публичные поля
	// поддерживаемых типов, а слайсы и вложенные структуры он не умеет.
	// Заполняются методами SetRouting/AddBypass.
	routing *client.RoutingConfig
}

// NewConfig возвращает пустой конфиг. В Java превращается в `new Config()`.
func NewConfig() *Config { return &Config{} }

// SetRouting принимает правила маршрутизации JSON-строкой:
//
//	{"bypass":["*.ru","*.рф"],"block":["ads.example"],"force":["*.example.com"]}
//
// JSON вместо полей потому, что gobind не переносит через границу языка ни
// слайсы строк, ни вложенные структуры. Ошибка возвращается на разборе, а не
// молча на Start: конфиг с опечаткой должен ломаться там, где его задают.
//
// Параметр назван spec, а не json, чтобы не затенить пакет encoding/json.
func (c *Config) SetRouting(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		c.routing = nil
		return nil
	}
	var rc client.RoutingConfig
	if err := json.Unmarshal([]byte(spec), &rc); err != nil {
		return fmt.Errorf("routing: неразбираемый JSON: %w", err)
	}
	c.routing = &rc
	return nil
}

// AddBypass добавляет один паттерн в bypass-список — путь для простых случаев,
// где собирать JSON на стороне платформы неоправданно.
func (c *Config) AddBypass(pattern string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return
	}
	if c.routing == nil {
		c.routing = &client.RoutingConfig{}
	}
	c.routing.Bypass = append(c.routing.Bypass, pattern)
}

// clone делает снимок конфига на момент NewSession. Без него платформа могла
// бы менять поля объекта после старта, и Start после Stop поднялся бы с
// параметрами, которых пользователь не видел.
func (c *Config) clone() *Config {
	cp := *c
	if c.routing != nil {
		rc := *c.routing
		rc.Bypass = append([]string(nil), c.routing.Bypass...)
		rc.Block = append([]string(nil), c.routing.Block...)
		rc.Force = append([]string(nil), c.routing.Force...)
		cp.routing = &rc
	}
	return &cp
}

// socksBindAddr — адрес листенера SOCKS5 фасада.
//
// Порт 0, а не фиксированный: на телефоне 1080 (и любой другой заранее
// выбранный) может быть занят другим VPN-приложением, и net.Listen упадёт.
// Фактический порт вычитывается из листенера через Session.SocksPort().
// Хост строго loopback — bind на 0.0.0.0 отдал бы прокси всей сети.
const socksBindAddr = "127.0.0.1:0"

// buildEngineConfig валидирует конфиг платформы и переводит его в конфиг движка.
//
// Валидация здесь, а не в Connect, потому что ошибки этого класса (кривой hex,
// адрес без порта) — это ошибки вызывающего, и он должен получить их
// синхронно, из NewSession, а не асинхронным OnError через полсекунды.
func buildEngineConfig(cfg *Config, user, pass string) (*engine.Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config: nil")
	}
	if strings.TrimSpace(cfg.ServerAddr) == "" {
		return nil, fmt.Errorf("config: ServerAddr не задан")
	}
	if _, _, err := net.SplitHostPort(cfg.ServerAddr); err != nil {
		return nil, fmt.Errorf("config: ServerAddr должен быть host:port: %w", err)
	}
	pub, err := hex.DecodeString(strings.TrimSpace(cfg.PubKeyHex))
	if err != nil {
		return nil, fmt.Errorf("config: PubKeyHex не hex: %w", err)
	}
	if len(pub) != 32 {
		return nil, fmt.Errorf("config: PubKeyHex должен быть 32 байта (64 hex), получено %d", len(pub))
	}
	var clientID []byte
	if s := strings.TrimSpace(cfg.ClientIDHex); s != "" {
		clientID, err = hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("config: ClientIDHex не hex: %w", err)
		}
		if len(clientID) != 16 {
			return nil, fmt.Errorf("config: ClientIDHex должен быть 16 байт (32 hex), получено %d", len(clientID))
		}
	}
	if cfg.WSPoolSize < 0 {
		return nil, fmt.Errorf("config: WSPoolSize отрицательный: %d", cfg.WSPoolSize)
	}
	if cfg.FlowWindowKB < 0 {
		return nil, fmt.Errorf("config: FlowWindowKB отрицательный: %d", cfg.FlowWindowKB)
	}

	return &engine.Config{
		SOCKS: socksBindAddr,
		// SystemVPN=false: TUN поднимает платформа, движку об этом знать
		// нечего — он отдаёт SOCKS5 и на этом его роль кончается.
		SystemVPN: false,
		ProxyUser: user,
		ProxyPass: pass,
		ClientID:  clientID,
		StateDir:  cfg.StateDir,
		ShadowLink: &engine.ShadowLinkConfig{
			Server: cfg.ServerAddr,
			PubKey: strings.TrimSpace(cfg.PubKeyHex),
			// WebSocket и WSPool включены жёстко, и это не «разумный дефолт».
			// Без них WST остаётся nil, и данные идут poll-режимом с тикерами
			// по 20 мс (proxy/socks5/tcp.go, udp.go) — то есть решётка 50 Гц на
			// проводе плюс шифрованный кадр на каждый тик. Отдавать такой режим
			// мобильному пользователю нельзя, а конфигурировать нечего.
			WebSocket:  true,
			WSPool:     true,
			TLS:        cfg.UseTLS,
			CDN:        strings.TrimSpace(cfg.CDN),
			SNI:        strings.TrimSpace(cfg.SNI),
			WSPoolSize: int(cfg.WSPoolSize),
			FlowWindow: uint64(cfg.FlowWindowKB) * 1024,
			Routing:    cfg.routing,
		},
	}, nil
}

// generateProxyCredentials создаёт случайные креды SOCKS5 на одну сессию.
//
// Механизм скопирован с десктопа (cmd/nixavpn-client/main.go) намеренно и с
// одним отличием в мотивации: на Android слушающий 127.0.0.1:PORT доступен
// ЛЮБОМУ приложению устройства, поэтому неаутентифицированный прокси означал бы
// открытый выход в туннель для соседнего приложения. Креды не приходят снаружи
// (нельзя выставить слабые) и не переживают перезапуск.
func generateProxyCredentials() (user, pass string) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "nix", hex.EncodeToString(b)
}

package mobile

import (
	"strings"
	"testing"
)

func TestConfig_SetRoutingParsesJSON(t *testing.T) {
	c := NewConfig()
	if err := c.SetRouting(`{"bypass":["*.ru","*.рф"],"block":["ads.example"],"force":["*.example.com"]}`); err != nil {
		t.Fatalf("SetRouting: %v", err)
	}
	if c.routing == nil {
		t.Fatal("routing не заполнен")
	}
	if len(c.routing.Bypass) != 2 || c.routing.Bypass[0] != "*.ru" {
		t.Fatalf("bypass=%v", c.routing.Bypass)
	}
	if len(c.routing.Block) != 1 || len(c.routing.Force) != 1 {
		t.Fatalf("block=%v force=%v", c.routing.Block, c.routing.Force)
	}
}

// Опечатка в правилах должна ломаться там, где её сделали, а не молча превращать
// туннель в «всё мимо роутера».
func TestConfig_SetRoutingRejectsBrokenJSON(t *testing.T) {
	c := NewConfig()
	if err := c.SetRouting(`{"bypass":[`); err == nil {
		t.Fatal("битый JSON принят без ошибки")
	}
	if c.routing != nil {
		t.Fatal("после ошибки разбора routing всё равно заполнен")
	}
}

func TestConfig_AddBypassAccumulates(t *testing.T) {
	c := NewConfig()
	c.AddBypass("*.ru")
	c.AddBypass("  ")
	c.AddBypass("*.by")
	if c.routing == nil || len(c.routing.Bypass) != 2 {
		t.Fatalf("bypass=%v, ожидалось 2 непустых правила", c.routing)
	}
}

// Снимок конфига на момент NewSession: иначе платформа меняет поля объекта уже
// после старта, и следующий Start поднимется с параметрами, которых
// пользователь не выбирал.
func TestConfig_SessionSnapshotIsIndependent(t *testing.T) {
	c := testConfig()
	c.AddBypass("*.ru")
	s, err := NewSession(c)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	c.ServerAddr = "198.51.100.9:8443"
	c.AddBypass("*.kz")

	if s.cfg.ServerAddr != "203.0.113.7:443" {
		t.Fatalf("сессия увидела изменённый ServerAddr: %s", s.cfg.ServerAddr)
	}
	if len(s.cfg.routing.Bypass) != 1 {
		t.Fatalf("сессия увидела изменённый bypass: %v", s.cfg.routing.Bypass)
	}
}

func TestBuildEngineConfig_Validation(t *testing.T) {
	valid := testConfig()
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"пустой адрес", func(c *Config) { c.ServerAddr = "" }, "ServerAddr"},
		{"адрес без порта", func(c *Config) { c.ServerAddr = "203.0.113.7" }, "host:port"},
		{"pubkey не hex", func(c *Config) { c.PubKeyHex = "zz" }, "hex"},
		{"pubkey короткий", func(c *Config) { c.PubKeyHex = "aabb" }, "32 байта"},
		{"clientID не 16 байт", func(c *Config) { c.ClientIDHex = "aabb" }, "16 байт"},
		{"отрицательный пул", func(c *Config) { c.WSPoolSize = -1 }, "WSPoolSize"},
		{"отрицательное окно", func(c *Config) { c.FlowWindowKB = -1 }, "FlowWindowKB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := *valid
			tc.mut(&c)
			_, err := buildEngineConfig(&c, "nix", "pass")
			if err == nil {
				t.Fatalf("конфиг принят, ожидалась ошибка про %s", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ошибка %q не про %s", err, tc.want)
			}
		})
	}
}

// Форма транспорта — не «разумный дефолт», а требование: без WebSocket/WSPool
// движок оставляет WST == nil, и данные идут poll-режимом с тикерами по 20 мс,
// то есть решёткой 50 Гц на проводе плюс шифрованный кадр на каждый тик.
func TestBuildEngineConfig_ForcesPooledWebSocketTransport(t *testing.T) {
	ec, err := buildEngineConfig(testConfig(), "nix", "pass")
	if err != nil {
		t.Fatalf("buildEngineConfig: %v", err)
	}
	if !ec.ShadowLink.WebSocket {
		t.Fatal("WebSocket выключен — транспорт свалится в poll-режим (тикеры 20 мс)")
	}
	if !ec.ShadowLink.WSPool {
		t.Fatal("WSPool выключен")
	}
	if ec.SystemVPN {
		t.Fatal("SystemVPN включён — TUN поднимает платформа, движку это поле не нужно")
	}
}

// Bind на :0 и строго на loopback. Фиксированный порт на телефоне падает при
// занятом 1080, а нелокальный host отдал бы прокси всей сети.
func TestBuildEngineConfig_BindsEphemeralLoopbackPort(t *testing.T) {
	ec, err := buildEngineConfig(testConfig(), "nix", "pass")
	if err != nil {
		t.Fatalf("buildEngineConfig: %v", err)
	}
	if ec.SOCKS != "127.0.0.1:0" {
		t.Fatalf("SOCKS=%q, ожидался 127.0.0.1:0", ec.SOCKS)
	}
}

// StateDir доезжает до FPCacheDir клиента: без него профиль отпечатка
// переизбирается на каждом старте, а дрейф отпечатка — это сигнал (hard rule 2).
func TestBuildEngineConfig_PassesStateDirAndClientID(t *testing.T) {
	c := testConfig()
	c.StateDir = "/data/data/app/files"
	c.ClientIDHex = "000102030405060708090a0b0c0d0e0f"
	ec, err := buildEngineConfig(c, "nix", "pass")
	if err != nil {
		t.Fatalf("buildEngineConfig: %v", err)
	}
	if ec.StateDir != "/data/data/app/files" {
		t.Fatalf("StateDir=%q", ec.StateDir)
	}
	if len(ec.ClientID) != 16 || ec.ClientID[15] != 0x0f {
		t.Fatalf("ClientID=%v", ec.ClientID)
	}
}

// Пустой ClientIDHex — законный случай (платформа ещё не сгенерировала свой):
// движок возьмёт UUID на этот запуск.
func TestBuildEngineConfig_EmptyClientIDIsAllowed(t *testing.T) {
	ec, err := buildEngineConfig(testConfig(), "nix", "pass")
	if err != nil {
		t.Fatalf("buildEngineConfig: %v", err)
	}
	if ec.ClientID != nil {
		t.Fatalf("ClientID=%v, ожидался nil", ec.ClientID)
	}
}

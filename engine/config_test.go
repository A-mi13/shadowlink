package engine

import "testing"

// TestNewShadowLinkEngine_NilConfigRejected: конструктор обязан вернуть ошибку,
// а не запаниковать.
//
// Он разыменовывает cfg сразу (cfg.SOCKS), поэтому до этой правки nil давал
// панику в вызывающем. На стороне CLI такой вызов не возникает — конфиг всегда
// загружен, — но пакет теперь публичный, и второй его потребитель (мобильный
// фасад) получает конфиг с другой стороны языковой границы, где nil приходит
// от gomobile-обёртки штатно, а паника в Go роняет весь процесс приложения.
func TestNewShadowLinkEngine_NilConfigRejected(t *testing.T) {
	eng, err := NewShadowLinkEngine(nil)
	if err == nil {
		t.Fatal("ожидалась ошибка на nil-конфиге, получено nil")
	}
	if eng != nil {
		t.Fatalf("при ошибке движок обязан быть nil, получен %T", eng)
	}
}

// TestNewShadowLinkEngine_SocksAddrFromConfig фиксирует связь, на которую
// опирается CLI: NewTunnel берёт адрес через SOCKSAddr() (main.go:225), а тот
// возвращает socksAddr, выставленный ЗДЕСЬ и больше нигде не перезаписываемый.
// Если поле перестанет заполняться из конфига, SystemVPN-путь начнёт строить
// туннель на пустой адрес — а он тестами не покрыт (нужны админские права).
func TestNewShadowLinkEngine_SocksAddrFromConfig(t *testing.T) {
	const want = "127.0.0.1:31337"
	eng, err := NewShadowLinkEngine(&Config{SOCKS: want})
	if err != nil {
		t.Fatalf("NewShadowLinkEngine: %v", err)
	}
	if got := eng.SOCKSAddr(); got != want {
		t.Fatalf("SOCKSAddr() = %q, ожидалось %q", got, want)
	}
}

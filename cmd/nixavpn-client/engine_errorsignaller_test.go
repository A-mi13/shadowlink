package main

import "testing"

// TestNewEngine_ShadowLinkSignalsErrors: движок, полученный через NewEngine,
// обязан отдавать НЕ-nil канал ошибок через ErrorSignaller.
//
// Что именно сторожится. В main.go W8-контур выглядит так:
//
//	if sig, ok := eng.(ErrorSignaller); ok { engineErr = sig.ErrorCh() }
//	select { case <-sigCh: ...; case err := <-engineErr: ... }
//
// Промах здесь НЕ ломает сборку: comma-ok вернёт false, engineErr останется
// nil, а чтение из nil-канала блокируется вечно — то есть select тихо
// выродится в ожидание одного лишь сигнала ОС, и клиент перестанет завершаться
// при смерти SOCKS5 или исчерпании реконнектов. Симптом в поле — «VPN висит
// мёртвым, но процесс жив», без единой строки в логе.
//
// Compile-time `var _ ErrorSignaller = (*ShadowLinkEngine)(nil)` в engine.go
// ловит только смену сигнатуры типа. Этот тест закрывает вторую половину:
// что через фабрику приходит именно такой движок и канал у него живой.
func TestNewEngine_ShadowLinkSignalsErrors(t *testing.T) {
	eng, err := NewEngine("shadowlink", &Config{})
	if err != nil {
		t.Fatalf("NewEngine(shadowlink): %v", err)
	}

	sig, ok := eng.(ErrorSignaller)
	if !ok {
		t.Fatalf("движок %T не реализует ErrorSignaller — W8-контур в main.go "+
			"молча выродится в ожидание только SIGINT", eng)
	}
	if sig.ErrorCh() == nil {
		t.Fatal("ErrorCh() == nil: чтение из nil-канала блокируется вечно, " +
			"смерть движка не будет замечена")
	}
}

// TestNewEngine_UnknownProtocolFails фиксирует, что фабрика не отдаёт молча
// nil-движок на неизвестном протоколе: main.go разыменовывает результат сразу.
func TestNewEngine_UnknownProtocolFails(t *testing.T) {
	eng, err := NewEngine("no-such-protocol", &Config{})
	if err == nil {
		t.Fatal("ожидалась ошибка на неизвестном протоколе, получено nil")
	}
	if eng != nil {
		t.Fatalf("при ошибке движок обязан быть nil, получен %T", eng)
	}
}

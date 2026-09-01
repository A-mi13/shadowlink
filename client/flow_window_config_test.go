package client

import "testing"

// Окно flow control до 2026-09-01 задавалось ТОЛЬКО переменной окружения, что
// делало его недостижимым для встроенных клиентов (мобильный фасад работает
// внутри чужого процесса, на iOS — в extension). Величина при этом задаёт
// потолок скорости одного потока: окно / RTT.
//
// Эти тесты проверяют приоритет источников и клампы на самом конструкторе пула,
// а не на промежуточном звене: именно p.flowDesiredWindow уходит в
// wst.flowDesiredWindow и дальше на wire.

func TestWSPoolConfig_FlowWindowOverridesEnv(t *testing.T) {
	t.Setenv("SHADOWLINK_FLOW_WINDOW", "1048576") // 1 МиБ через env

	p := NewWSPoolTransport(nil, WSPoolConfig{
		Size:       1,
		ServerAddr: "203.0.113.7:443",
		FlowWindow: 4 << 20, // 4 МиБ явным конфигом
	})
	defer p.Close()

	if got := p.flowDesiredWindow; got != 4<<20 {
		t.Fatalf("flowDesiredWindow = %d, ожидалось %d — явный конфиг должен "+
			"побеждать переменную окружения", got, 4<<20)
	}
}

func TestWSPoolConfig_FlowWindowFallsBackToEnv(t *testing.T) {
	t.Setenv("SHADOWLINK_FLOW_WINDOW", "2097152") // 2 МиБ

	p := NewWSPoolTransport(nil, WSPoolConfig{
		Size:       1,
		ServerAddr: "203.0.113.7:443",
		// FlowWindow не задан — env остаётся рабочим путём для существующих
		// развёртываний и полевых замеров.
	})
	defer p.Close()

	if got := p.flowDesiredWindow; got != 2<<20 {
		t.Fatalf("flowDesiredWindow = %d, ожидалось %d — env должен работать "+
			"при незаданном конфиге", got, 2<<20)
	}
}

func TestWSPoolConfig_FlowWindowClampedToCeiling(t *testing.T) {
	p := NewWSPoolTransport(nil, WSPoolConfig{
		Size:       1,
		ServerAddr: "203.0.113.7:443",
		FlowWindow: 64 << 20, // заведомо выше потолка
	})
	defer p.Close()

	if got := p.flowDesiredWindow; got != maxFlowWindow {
		t.Fatalf("flowDesiredWindow = %d, ожидался потолок %d: окно/minChunk "+
			"обязано умещаться в ёмкость incomingCh (512)", got, maxFlowWindow)
	}
}

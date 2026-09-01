package mobile

import "testing"

// Окно flow control задаёт потолок скорости ОДНОГО потока (окно / RTT). До
// 2026-09-01 оно читалось только из переменной окружения SHADOWLINK_FLOW_WINDOW
// (client/stream_flow.go), а мобильный фасад живёт внутри чужого процесса — на
// iOS в NEPacketTunnelProvider, — где выставить env практически нечем. То есть
// ручки на мобильных не было вовсе, и наблюдаемый командой NixaVPN потолок
// ~23 Мбит/с на поток при RTT 241 мс изменить было нечем.
//
// Тест ведёт величину через ВСЮ цепочку (mobile.Config → engine.Config), потому
// что порвать её может любое звено, и порвётся она молча: поле останется, а
// эффекта не будет.
func TestBuildEngineConfig_FlowWindowReachesEngine(t *testing.T) {
	c := testConfig()
	c.FlowWindowKB = 4096 // 4 МиБ

	ec, err := buildEngineConfig(c, "nix", "pass")
	if err != nil {
		t.Fatalf("конфиг отвергнут: %v", err)
	}

	const want = uint64(4096) * 1024
	if got := ec.ShadowLink.FlowWindow; got != want {
		t.Fatalf("FlowWindow = %d, ожидалось %d — килобайты фасада должны "+
			"превращаться в байты движка", got, want)
	}
}

// Ноль обязан означать «дефолт движка», а не «окно нулевое»: нулевое окно в
// пуле выключает flow control целиком (client/ws_pool.go, 0 → off), то есть
// незаполненное поле фасада меняло бы протокол.
func TestBuildEngineConfig_ZeroFlowWindowMeansDefault(t *testing.T) {
	c := testConfig()
	c.FlowWindowKB = 0

	ec, err := buildEngineConfig(c, "nix", "pass")
	if err != nil {
		t.Fatalf("конфиг отвергнут: %v", err)
	}
	if got := ec.ShadowLink.FlowWindow; got != 0 {
		t.Fatalf("FlowWindow = %d, ожидался 0 — движок сам подставит дефолт", got)
	}
}

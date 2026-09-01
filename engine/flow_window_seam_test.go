package engine

// Сторож стыка «engine → WSPoolConfig» для окна flow control.
//
// Цепочка ручки состоит из трёх звеньев:
//
//	mobile.Config.FlowWindowKB → engine.Config.ShadowLink.FlowWindow
//	                           → client.WSPoolConfig.FlowWindow
//	                           → p.flowDesiredWindow → wire
//
// Концы цепочки покрыты (mobile.TestBuildEngineConfig_FlowWindowReachesEngine и
// client.TestWSPoolConfig_FlowWindow*), а вот СТЫК между ними — единственная
// строка присваивания в литерале WSPoolConfig внутри Connect() — до 2026-09-01
// не был покрыт ничем. Проверено удалением этой строки: `go build` проходит,
// и весь набор engine/, mobile/, client/ остаётся ЗЕЛЁНЫМ. То есть ручку можно
// было потерять целиком, не уронив ни одного теста: поле в конфиге осталось бы,
// документация продолжила бы обещать эффект, а окно молча брало бы дефолт.
//
// Это ровно тот класс дефекта, что записан в памяти проекта как «дефект на стыке
// двух правок»: обе стороны корректны по отдельности, приёмка каждой из них
// проходит, а дыра сидит между ними.
//
// Литерал лежит в Connect(), которому нужен живой сетевой путь, поэтому
// поведенческого теста здесь не построить без прод-подключения. Сторож читает
// ИСХОДНИК — тот же приём, что у TestRotationWatchdogLoop_UsesJitteredTimerNotTicker
// (см. CLAUDE.md, правило 9), и по той же причине: проверяемое свойство
// структурное, а не наблюдаемое из юнит-теста.

import (
	"os"
	"regexp"
	"testing"
)

// TestEngine_PassesFlowWindowToPool — власть проверена порчей: удаление строки
// `FlowWindow: slCfg.FlowWindow,` из литерала WSPoolConfig немедленно красит
// этот тест (и не красит больше ни одного).
func TestEngine_PassesFlowWindowToPool(t *testing.T) {
	src, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatalf("не прочитать engine.go: %v", err)
	}

	// Допускаем любое форматирование выравнивания gofmt между именем поля и
	// значением — иначе сторож ловил бы переформатирование, а не потерю ручки.
	re := regexp.MustCompile(`FlowWindow:\s+slCfg\.FlowWindow,`)
	if !re.Match(src) {
		t.Fatal("в литерале client.WSPoolConfig нет `FlowWindow: slCfg.FlowWindow` — " +
			"окно flow control перестало доезжать из конфига до пула. " +
			"Поле engine.ShadowLinkConfig.FlowWindow при этом останется на месте, " +
			"mobile-фасад продолжит его принимать, а окно молча возьмёт дефолт 1 МиБ: " +
			"именно та ручка, отсутствие которой сделало замеры окна у команды " +
			"NixaVPN (2026-09-01) заведомо бессмысленными")
	}
}

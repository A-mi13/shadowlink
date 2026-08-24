//go:build gomobileguard

package mobile

import (
	"os/exec"
	"strings"
	"testing"
)

// Сторож совместимости с gobind: пакет обязан оставаться пригодным для
// экспорта на Java/Swift.
//
// Почему за build-тегом, а не в обычном прогоне: gobind — ВНЕШНИЙ бинарь, и
// тест, который при его отсутствии делает t.Skip, зелен всегда и не сторожит
// ничего. Поэтому здесь противоположный выбор: отсутствие инструмента — это
// падение, а сам тест запускается явной целью:
//
//	go test -tags gomobileguard ./mobile/
//
// В обычном прогоне он не участвует, и это ЗАФИКСИРОВАННЫЙ пробел, а не
// замаскированный скипом.
func TestGobind_PackageIsBindable(t *testing.T) {
	out, err := exec.Command("gobind", "-lang=java", "github.com/nixavpn/shadowlink/mobile").CombinedOutput()
	if err != nil {
		t.Fatalf("gobind не отработал: %v\n%s", err, out)
	}
	java := string(out)
	// Проверяем не факт запуска, а состав API: молчаливая потеря типа — это
	// ровно тот отказ, ради которого сторож существует (gobind пропускает
	// неподдерживаемое с предупреждением, а не с ошибкой).
	for _, want := range []string{
		"class Session", "class Config",
		"interface Logger", "interface EventHandler",
		"socksPort", "networkChanged",
	} {
		if !strings.Contains(java, want) {
			t.Errorf("в сгенерированном Java-API нет %q — тип или метод молча не экспортировался", want)
		}
	}
}

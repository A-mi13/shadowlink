package server

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// UA в ServerHello: по одному на КАЖДЫЙ профиль пула (найдено 2026-07-31).
//
// Раньше здесь стоял единственный литерал `"chrome": ...Chrome/133...`, тогда как
// клиент выбирает профиль из 133/131/120 с весами 60/30/10 (DefaultFPWeights).
// Валидация isValidUAForProfile (client/client.go) требует совпадения мажора,
// поэтому клиент с chrome131/chrome120 отвергал серверный UA:
//
//	WARN rejected UA from server: profile mismatch  selected=chrome131
//
// В ~40% запусков механизм UpdateUserAgents не работал, а WARN выглядел как
// ошибка при диагностике. Сама защита вела себя правильно (сервер не должен
// иметь возможности перефингерпринтить клиента) — расходились источники UA.

func TestServerHelloUA_CoversEveryPoolProfile(t *testing.T) {
	uas := browser.ProfileUAs()
	if len(uas) == 0 {
		t.Fatal("ProfileUAs() пуст — сервер не отдаст ни одного UA")
	}

	// Каждый профиль, который клиент может выбрать по дефолтным весам, обязан
	// получить свой UA — иначе он снова будет отвергнут.
	for name := range browser.DefaultFPWeights() {
		ua, ok := uas[name]
		if !ok {
			t.Errorf("профиль %q входит в DefaultFPWeights, но UA для него нет — "+
				"клиент с этим профилем отвергнет серверный UA", name)
			continue
		}
		p, found := browser.LookupProfile(name)
		if !found {
			t.Errorf("профиль %q не найден в реестре", name)
			continue
		}
		// Тот же критерий, что у клиентской валидации: мажор в UA должен
		// совпадать с мажором профиля.
		want := "Chrome/" + strconv.Itoa(p.Major) + "."
		if !strings.Contains(ua, want) {
			t.Errorf("UA профиля %q не содержит %q: %s", name, want, ua)
		}
	}
}

// Форма UA должна проходить клиентскую валидацию: длина, ASCII, Mozilla/.
// Дублируем критерии сознательно — client не импортируется сюда (был бы цикл),
// а разъехавшиеся требования дадут ровно ту же тихую поломку.
func TestServerHelloUA_PassesClientValidationShape(t *testing.T) {
	for name, ua := range browser.ProfileUAs() {
		if len(ua) < 80 || len(ua) > 200 {
			t.Errorf("%s: длина UA %d вне диапазона 80..200, который принимает клиент",
				name, len(ua))
		}
		for i := 0; i < len(ua); i++ {
			if ua[i] < 0x20 || ua[i] > 0x7E {
				t.Errorf("%s: не-ASCII байт на позиции %d", name, i)
				break
			}
		}
		if !strings.Contains(ua, "Mozilla/") {
			t.Errorf("%s: нет Mozilla/ — клиент отвергнет", name)
		}
		for _, bad := range []string{"<", ">", "\n", "\r"} {
			if strings.Contains(ua, bad) {
				t.Errorf("%s: запрещённый символ %q", name, bad)
			}
		}
	}
}

// Non-Chrome UA не должны попадать в ServerHello: с 2026-05-05 они сняты
// (TSPU блокирует Safari/Firefox/Edge первыми), и отдавать их значило бы
// предлагать клиенту заведомо палящий профиль.
func TestServerHelloUA_ChromeOnly(t *testing.T) {
	for name, ua := range browser.ProfileUAs() {
		if strings.Contains(ua, "Firefox/") {
			t.Errorf("%s: Firefox UA в ServerHello (профиль снят 2026-05-05)", name)
		}
		if strings.Contains(ua, "Version/") && strings.Contains(ua, "Safari/") &&
			!strings.Contains(ua, "Chrome/") {
			t.Errorf("%s: Safari UA в ServerHello (профиль снят 2026-05-05)", name)
		}
		if !browser.IsChromeFamily(name) {
			t.Errorf("%s: не Chrome-family профиль в ServerHello", name)
		}
	}
}

// Сторож: handler не должен вернуться к литеральному UA.
func TestServerHelloUA_NoHardcodedLiteral(t *testing.T) {
	raw, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("не прочитан handler.go: %v", err)
	}
	src := string(raw)
	if !strings.Contains(src, "UA: browser.ProfileUAs()") {
		t.Error("handler.go не использует browser.ProfileUAs() — UA снова из литерала, " +
			"и профили пула кроме одного будут отвергаться клиентом")
	}
	// Литеральный UA рядом с полем UA — признак возврата старого кода.
	if i := strings.Index(src, "UA: map[string]string{"); i >= 0 {
		t.Error("handler.go снова строит UA литеральной картой")
	}
}

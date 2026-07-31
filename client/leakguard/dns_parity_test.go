package leakguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/client/dnsproxy"
)

// H-13 (раунд 18): правило allow для plain-UDP/53 к RU-резолверам существовало
// ТОЛЬКО в rules_windows.go. Linux и Darwin не имели его вообще, при этом
// setupRoutes (cmd/nixavpn-client/tunnel.go) ставит /32 escape-маршруты для
// Yandex БЕЗУСЛОВНО на всех платформах → пакеты уходили мимо TUN и упирались
// в финальный `drop` (nft/iptables) / `block out all` (pf). Yandex-нога
// арбитража была мертва при поднятом kill-switch, dnsproxy всегда получал !yOK
// и деградировал в CF-only. Fail-secure по направлению, но анти-цензурная
// функция не работала на двух платформах из трёх.
//
// Почему дрейф не замечали (§7.4): тесты генераторов правил лежат в файлах с
// build-тегами (rules_windows_test.go / rules_linux_test.go /
// rules_darwin_test.go) и проверяют КАЖДУЮ платформу по отдельности. При такой
// раскладке отсутствие правила на двух платформах структурно невидимо. Этот
// файл НАМЕРЕННО без build-тега: он проверяет план и исходники всех платформ
// сразу, на любой ОС.

func TestKillSwitchPlan_DNSAllowPopulatedOnEveryPlatform(t *testing.T) {
	plan := BuildKillSwitchPlan(LeakGuardConfig{
		ServerPort: 443,
		TunName:    "tun0",
	}, true)

	if len(plan.DNSAllow) == 0 {
		t.Fatal("plan.DNSAllow пуст — RU-резолверы не попадут в allow ни на одной платформе")
	}

	want := dnsproxy.DefaultYandexIPs()
	if len(plan.DNSAllow) != len(want) {
		t.Errorf("в DNSAllow %d записей, в DefaultYandexIPs %d — источник истины разъехался",
			len(plan.DNSAllow), len(want))
	}
	for _, ip := range want {
		found := false
		for _, got := range plan.DNSAllow {
			if got == ip {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("резолвер %s отсутствует в plan.DNSAllow", ip)
		}
	}
}

// Сторож паритета: каждый генератор правил обязан использовать plan.DNSAllow.
//
// Проверка идёт по исходникам, а не по вызову функций, ровно потому что
// генераторы разведены build-тегами и на одной ОС компилируется только один.
// Именно эта невидимость и дала H-13 прожить до 18-го раунда.
func TestKillSwitchRules_DNSAllowUsedByAllPlatforms(t *testing.T) {
	platforms := []struct {
		file string
		note string
	}{
		{"rules_windows.go", "netsh advfirewall"},
		{"rules_linux.go", "nft + iptables"},
		{"rules_darwin.go", "pfctl"},
	}

	for _, p := range platforms {
		src, err := os.ReadFile(filepath.Clean(p.file))
		if err != nil {
			t.Fatalf("не прочитан %s: %v", p.file, err)
		}
		if !strings.Contains(string(src), "plan.DNSAllow") {
			t.Errorf("%s (%s) не использует plan.DNSAllow — RU-резолверы упрутся "+
				"в финальный drop/block, split-DNS деградирует в CF-only", p.file, p.note)
		}
	}
}

// Linux: правило обязано стоять ДО финального drop, иначе оно бесполезно.
// Порядок в nft/iptables — не декоративный инвариант.
func TestKillSwitchRules_LinuxDNSBeforeDrop(t *testing.T) {
	src, err := os.ReadFile("rules_linux.go")
	if err != nil {
		t.Fatalf("не прочитан rules_linux.go: %v", err)
	}
	code := string(src)

	dnsIdx := strings.Index(code, "plan.DNSAllow")
	if dnsIdx < 0 {
		t.Fatal("plan.DNSAllow не найден в rules_linux.go")
	}
	// Финальный drop добавляется последним; в исходнике он ниже DNS-цикла.
	dropIdx := strings.Index(code, `"output", "drop"`)
	if dropIdx < 0 {
		t.Fatal("финальный nft drop не найден")
	}
	if dnsIdx > dropIdx {
		t.Error("DNS-allow добавляется ПОСЛЕ финального drop — правило не сработает")
	}
}

// Darwin: то же для `block out all`.
func TestKillSwitchRules_DarwinDNSBeforeBlock(t *testing.T) {
	src, err := os.ReadFile("rules_darwin.go")
	if err != nil {
		t.Fatalf("не прочитан rules_darwin.go: %v", err)
	}
	code := string(src)

	dnsIdx := strings.Index(code, "plan.DNSAllow")
	blockIdx := strings.Index(code, `"block out all"`)
	if dnsIdx < 0 || blockIdx < 0 {
		t.Fatal("не найден DNSAllow или block out all в rules_darwin.go")
	}
	if dnsIdx > blockIdx {
		t.Error("DNS-pass добавляется ПОСЛЕ `block out all` — правило не сработает")
	}
}

// Источник истины: literal-IP резолверов не должны появляться в генераторах
// правил напрямую — только через план. Иначе добавление третьего резолвера в
// dnsproxy опять молча разъедется с firewall-правилами.
func TestKillSwitchRules_NoHardcodedResolverLiterals(t *testing.T) {
	files := []string{"rules_windows.go", "rules_linux.go", "rules_darwin.go", "rules.go"}
	for _, f := range files {
		src, err := os.ReadFile(filepath.Clean(f))
		if err != nil {
			t.Fatalf("не прочитан %s: %v", f, err)
		}
		code := string(src)
		for _, ip := range dnsproxy.DefaultYandexIPs() {
			// rules.go legitimately обращается к dnsproxy.DefaultYandexIPs();
			// литерал IP не должен встречаться нигде.
			if strings.Contains(code, `"`+ip+`"`) {
				t.Errorf("%s содержит литерал резолвера %q — используйте plan.DNSAllow", f, ip)
			}
		}
	}
}

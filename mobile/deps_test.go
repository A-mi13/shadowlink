package mobile

import (
	"os/exec"
	"strings"
	"testing"
)

// Сторож изоляции зависимостей.
//
// Смысл не в размере артефакта вообще, а в трёх конкретных связях, каждая из
// которых появляется МОЛЧА — импортом одной функции в engine/ или client/:
//
//   - leakguard: под Android это guard_linux.go с iptables/systemctl. Он
//     компилируется, но не работает — зелёная сборка тут ничего не значит.
//     Приезжает он не сам: стрелка направлена в другую сторону (leakguard
//     зависит от client), поэтому связь возникнет ровно тогда, когда кто-нибудь
//     потянет обратно, например dnsproxy.DefaultYandexIPs().
//   - dnsproxy: НЕ дубль предыдущего пункта, хотя и связан с ним. leakguard
//     стерегут за платформенные вызовы; здесь причина другая и она про wire.
//     Форвардер несёт DoH-ногу (client/ech.go, пин на 1.1.1.1, SNI
//     cloudflare-dns.com) с ГОЛЫМ net.Dialer: в туннель она попадает не кодом,
//     а таблицей маршрутов ОС — split-маршруты 0/1+128/1 десктопного TUN
//     (см. TestDoHServerIP_HasNoEscapeRoute в cmd/nixavpn-client). У мобильного
//     фасада этих маршрутов нет по построению: TUN поднимает платформа, а
//     SystemVPN=false (config.go). Значит форвардер, приехавший сюда молча,
//     слал бы открытый ClientHello с физического интерфейса — ровно ту
//     сигнатуру, которую РКН начал резать в августе 2026 (DoH/DoT к CF и
//     Google рвутся на хендшейке). Сегодня связи нет: dnsproxy импортируют
//     только cmd/nixavpn-client/tunnel.go (под cfg.SystemVPN) и leakguard/rules.go
//     (ради одной DefaultYandexIPs()) — проверено 2026-08-26. Тест держит это
//     свойство, пока фасад развивается.
//   - tun2socks/v2/engine: за ним стоит gVisor, а gVisor — главный потребитель
//     памяти. Для iOS-extension это прямой путь к jetsam.
//   - xray-core: приезжает вместе с VLESS-конфигом CLI и по размеру неприемлем.
//
// Тест обязан ПАДАТЬ, а не скипаться, если go list не отработал: сторож,
// который молча зеленеет при отсутствии инструмента, не сторожит ничего.
func TestMobile_DoesNotPullPlatformOrGVisorPackages(t *testing.T) {
	deps := listDeps(t)

	forbidden := []string{
		"github.com/nixavpn/shadowlink/client/leakguard",
		"github.com/nixavpn/shadowlink/client/dnsproxy",
		"github.com/xjasonlyu/tun2socks/v2/engine",
		"gvisor.dev/gvisor",
		"github.com/xtls/xray-core",
	}
	for _, bad := range forbidden {
		for _, d := range deps {
			if d == bad || strings.HasPrefix(d, bad+"/") {
				t.Errorf("mobile тянет запрещённую зависимость %s", d)
			}
		}
	}
}

// tun2socksBaseline — ЗАМЕРЕННОЕ число пакетов tun2socks в дереве mobile/ на
// 2026-08-24. Они приезжают не из фасада: proxy/socks5 импортирует
// tun2socks/v2/proxy и metadata сам (inprocess.go), ради in-process dialer'а,
// который нужен только десктопному TUN-пути. Развязка требует выноса
// inprocess.go в отдельный пакет с экспортом внутренностей Server — то есть это
// отдельная работа, а не правка фасада.
//
// Число зафиксировано как ПОТОЛОК, а не как факт-справка: пока оно не растёт,
// новых транзитивных кусков tun2socks (а вместе с ними и риска зацепить engine
// с gVisor) в артефакте не появилось.
const tun2socksBaseline = 14

func TestMobile_Tun2socksFootprintDoesNotGrow(t *testing.T) {
	deps := listDeps(t)
	n := 0
	for _, d := range deps {
		if strings.HasPrefix(d, "github.com/xjasonlyu/tun2socks/v2") {
			n++
		}
	}
	if n > tun2socksBaseline {
		t.Fatalf("пакетов tun2socks в дереве mobile/: %d, замеренный потолок %d — что-то новое из tun2socks въехало в артефакт", n, tun2socksBaseline)
	}
	if n == 0 {
		t.Fatalf("пакетов tun2socks ноль — либо развязку сделали (обнови baseline и комментарий), либо go list вернул не то")
	}
}

func listDeps(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	return strings.Fields(string(out))
}

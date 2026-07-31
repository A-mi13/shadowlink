package client

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Тайминговый бюджет ротации — пересчитан 2026-07-31 ПО ЗАМЕРУ.
//
// Замер (телеметрия client/slotobs, 19 age-cut за одну полевую сессию,
// лог nixavpn-DEBUG-20260731-155722.log):
//
//	ось реза  = ВОЗРАСТ — CV возраста 0.18 против CV байтов 2.20 (х12)
//	окно      = 85.3s .. 154.7s, медиана 110.8s
//	объём     = НЕ триггер: смерти и на 0 КБ, и на 11.2 МБ
//
// Прежний тюнинг исходил из окна «~130–190s» и считал 75+45=120s безопасным.
// Замер это опроверг: НИЖНЯЯ граница 85.3s, и 14 смертей из 19 случились
// раньше 120s — то есть внутри нашего же worst-case teardown. Следствие в
// логе: 36 sticky-backstop teardown, 136 принудительно оборванных стримов.
//
// Почему урезан именно sticky, а не MAX_SLOT_AGE: снижение MAX_SLOT_AGE
// поднимает число соединений на origin IP (75s → ~384/час, 50s → ~576/час) и
// усиливает host-profiling (FOCI 2026). Лечить age-cut ценой counting-детектора
// нельзя. А sticky урезать безопасно, потому что миграция работает: 320
// успешных переездов стрима, 0 отказов, 5 реальных потерь данных.

// worstCaseTeardownBudget — предел суммарного возраста слота: ротация по
// maxSlotAge плюс удержание дренажа sticky-backstop'ом.
const measuredEarliestAgeCut = 85300 * time.Millisecond

func TestStickyDrainBudget_DefaultDerivedFromMeasurement(t *testing.T) {
	if DefaultStickyMaxDrainAge != 15*time.Second {
		t.Errorf("DefaultStickyMaxDrainAge=%v, ожидалось 15s (см. замер в шапке файла)",
			DefaultStickyMaxDrainAge)
	}

	// Прод-значение MAX_SLOT_AGE задаётся через env в connect-vpn-*.bat; здесь
	// сверяем бюджет для того значения, на котором проводился замер.
	const maxSlotAge = 75 * time.Second
	worst := maxSlotAge + DefaultStickyMaxDrainAge

	t.Logf("worst-case teardown = %v (maxSlotAge %v + sticky %v)", worst, maxSlotAge, DefaultStickyMaxDrainAge)
	t.Logf("самая ранняя измеренная смерть = %v", measuredEarliestAgeCut)

	// Прежние 45s давали 120s — заведомо внутрь окна. Регрессия к такому
	// значению должна ловиться.
	if worst >= 120*time.Second {
		t.Errorf("worst-case teardown %v — внутри измеренного окна реза (85..155s); "+
			"это состояние до фикса 2026-07-31", worst)
	}

	// Честно фиксируем, что полного запаса НЕТ: 90s > 85.3s. Тест не требует
	// положительного запаса (при maxSlotAge=75s он недостижим), но требует,
	// чтобы разрыв не рос.
	if worst > measuredEarliestAgeCut+10*time.Second {
		t.Errorf("worst-case %v превышает самую раннюю смерть %v более чем на 10s — "+
			"бюджет разъехался с замером", worst, measuredEarliestAgeCut)
	}
}

// Дефолт не должен дублироваться литералом в cmd/ — раньше там лежала вторая
// копия 10m, и правка в одном месте не затрагивала другое.
func TestStickyDrainBudget_SingleSourceOfDefault(t *testing.T) {
	src, err := os.ReadFile("../cmd/nixavpn-client/engine_shadowlink.go")
	if err != nil {
		t.Fatalf("не прочитан engine_shadowlink.go: %v", err)
	}
	code := string(src)

	if !strings.Contains(code, "client.DefaultStickyMaxDrainAge") {
		t.Error("cmd/ не ссылается на client.DefaultStickyMaxDrainAge — " +
			"дефолт снова задублирован")
	}
	// Литерал 10*time.Minute рядом с STICKY означает возврат старого дубля.
	idx := strings.Index(code, "SHADOWLINK_STICKY_MAX_DRAIN_AGE")
	if idx >= 0 {
		window := code[idx:min(idx+200, len(code))]
		if strings.Contains(window, "10*time.Minute") {
			t.Error("рядом с SHADOWLINK_STICKY_MAX_DRAIN_AGE снова литерал 10*time.Minute")
		}
	}
}

// Сторож на bat-файлы: тюнинг живёт там, и рассинхрон с кодом молча вернёт
// прежнее поведение (env перекрывает дефолт).
func TestStickyDrainBudget_LaunchScriptsMatchMeasurement(t *testing.T) {
	for _, name := range []string{
		"../bin/connect-vpn-DEBUG.bat",
		"../bin/connect-vpn-graceful-drain.bat",
	} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Logf("%s недоступен (%v) — пропуск; файл в .gitignore", name, err)
			continue
		}
		code := string(raw)

		if !strings.Contains(code, "SHADOWLINK_STICKY_MAX_DRAIN_AGE=15s") {
			t.Errorf("%s: STICKY_MAX_DRAIN_AGE не 15s — расходится с замером", name)
		}
		if strings.Contains(code, "SHADOWLINK_STICKY_MAX_DRAIN_AGE=45s") {
			t.Errorf("%s: вернулось прежнее 45s (worst-case 120s внутри окна реза)", name)
		}
		if !strings.Contains(code, "SHADOWLINK_DRAIN_HARD_CAP=15s") {
			t.Errorf("%s: DRAIN_HARD_CAP не 15s — worst-case teardown выше задуманного", name)
		}
		for _, bad := range []string{
			"SHADOWLINK_DRAIN_HARD_CAP=90s", // worst-case 165s
			"SHADOWLINK_DRAIN_HARD_CAP=30s", // worst-case 105s, наблюдалось в прогоне
		} {
			if strings.Contains(code, bad) {
				t.Errorf("%s: %s — worst-case выше 90s", name, bad)
			}
		}
	}
}

// hard_cap и sticky обязаны быть согласованы, и это НЕ вкусовое требование.
//
// Механика (наступал на это 2026-07-31): deadline дренажа ставится на hard_cap,
// и только по его СРАБАТЫВАНИЮ проверяется ветка `drainAge >= stickyMaxDrainAge`.
// Поэтому sticky МЕНЬШЕ hard_cap не участвует вовсе — рвёт hard_cap, а sticky
// выглядит применённым (в логе даже пишется sticky_outcome=age_backstop).
//
// Во втором полевом прогоне это дало 101 teardown с drain_duration=30s при
// заявленном sticky=15s: worst-case был 75+30=105s вместо задуманных 90s, и
// правка sticky не имела эффекта.
func TestStickyDrainBudget_HardCapNotBelowSticky(t *testing.T) {
	for _, name := range []string{
		"../bin/connect-vpn-DEBUG.bat",
		"../bin/connect-vpn-graceful-drain.bat",
	} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Logf("%s недоступен — пропуск (файл в .gitignore)", name)
			continue
		}
		code := string(raw)
		hardCap := envDurationFromBat(code, "SHADOWLINK_DRAIN_HARD_CAP")
		sticky := envDurationFromBat(code, "SHADOWLINK_STICKY_MAX_DRAIN_AGE")
		if hardCap == 0 || sticky == 0 {
			t.Errorf("%s: не удалось прочитать hard_cap=%v sticky=%v", name, hardCap, sticky)
			continue
		}
		t.Logf("%s: hard_cap=%v sticky=%v -> эффективный teardown=%v",
			name, hardCap, sticky, min(hardCap, sticky))
		if sticky < hardCap {
			t.Errorf("%s: sticky (%v) МЕНЬШЕ hard_cap (%v) — sticky не участвует, "+
				"рвёт hard_cap; правка sticky будет без эффекта", name, sticky, hardCap)
		}
	}
}

// Сторож шага 3: адаптер обязан участвовать в вычислении порога ротации.
//
// Без него адаптер тихо перестанет влиять — он продолжит считать и логировать
// порог, но ротация поедет по константе. Ровно тот класс отказа, который раунд 18
// вылавливал: механизм существует, лог о нём рассказывает, поведения не меняет.
func TestStickyDrainBudget_AdapterWiredIntoRotation(t *testing.T) {
	src, err := os.ReadFile("ws_pool.go")
	if err != nil {
		t.Fatalf("не прочитан ws_pool.go: %v", err)
	}
	code := string(src)

	if !strings.Contains(code, "p.ageAdapter.Threshold()") {
		t.Fatal("ws_pool.go не спрашивает порог у адаптера — шаг 3 отключён, " +
			"ротация идёт по константе")
	}
	// Вызов должен стоять там, где считается effectiveMaxAge, а не где-нибудь.
	idx := strings.Index(code, "effectiveMaxAge :=")
	adaptIdx := strings.Index(code, "p.ageAdapter.Threshold()")
	if idx < 0 {
		t.Fatal("не найдено вычисление effectiveMaxAge — изменилась структура")
	}
	if adaptIdx > idx {
		t.Error("адаптер спрашивается ПОСЛЕ вычисления effectiveMaxAge — значение не применится")
	}
	// И вердикт должен куда-то скармливаться, иначе порог никогда не сдвинется.
	statsSrc, err := os.ReadFile("stats.go")
	if err != nil {
		t.Fatalf("не прочитан stats.go: %v", err)
	}
	if !strings.Contains(string(statsSrc), "ageAdapter.Observe(") {
		t.Error("никто не вызывает ageAdapter.Observe — адаптер не получает данных " +
			"и порог останется сконфигурированным навсегда")
	}
}

// envDurationFromBat достаёт значение `set VAR=<duration>` из bat-файла.
func envDurationFromBat(code, key string) time.Duration {
	needle := "set " + key + "="
	i := strings.Index(code, needle)
	if i < 0 {
		return 0
	}
	rest := code[i+len(needle):]
	if j := strings.IndexAny(rest, "\r\n"); j >= 0 {
		rest = rest[:j]
	}
	d, err := time.ParseDuration(strings.TrimSpace(rest))
	if err != nil {
		return 0
	}
	return d
}

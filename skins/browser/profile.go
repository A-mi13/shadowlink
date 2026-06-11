package browser

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/refraction-networking/utls"
)

// BrowserProfile — согласованный набор всех 4 fingerprint-поверхностей одного
// браузера (lockstep). Реестр заполняется в init(); добавление браузера = одна
// запись + прохождение validateProfile (валидатор добавляется в следующей задаче).
type BrowserProfile struct {
	Name         string                 // "chrome120" | "chrome131" | "chrome133" | "firefox" — ключ реестра / persist
	Family       string                 // "chrome" | "firefox" — класс для policy-веток (PQ, sec-ch-ua, UA-валидация)
	Major        int                    // 120 / 131 / 133 / 148 — для валидации и логов
	UTLSHelloID  utls.ClientHelloID     // cold-path ClientHello
	BogdanfinnID profiles.ClientProfile // hot-path H2 SETTINGS
	UAString     string                 // User-Agent
	CHUA         func() [][2]string     // sec-ch-ua; Firefox = nil (не шлёт)
	PQKeyShare   bool                   // true → профиль несёт X25519MLKEM768 в key_share (cold+hot)
}

// profileRegistry is written exclusively in init(); LookupProfile is safe for concurrent reads.
var profileRegistry = map[string]BrowserProfile{}

// LookupProfile возвращает профиль по имени и флаг наличия.
//
// Legacy-алиас: старые persisted state и call-site'ы используют "chrome".
// Резолвим в новейший доступный chrome-major (chrome133), чтобы не ресэмплить
// и не ломать обратную совместимость.
func LookupProfile(name string) (BrowserProfile, bool) {
	if p, ok := profileRegistry[name]; ok {
		return p, true
	}
	if name == ProfileChrome {
		if p, ok := profileRegistry[ProfileChrome133]; ok {
			return p, true
		}
	}
	return BrowserProfile{}, false
}

// IsChromeFamily сообщает, относится ли профиль с данным именем к семейству
// Chrome. Безопасно для неизвестных имён (false). Legacy "chrome" резолвится
// через LookupProfile fallback в chrome133 (chrome-family).
func IsChromeFamily(name string) bool {
	p, ok := LookupProfile(name)
	return ok && p.Family == FamilyChrome
}

// DefaultFPWeights возвращает зашитые в код дефолтные веса популяции
// Chrome-профилей. Используется, когда сервер не прислал fingerprint_weights
// (пустой YAML — текущая прод-реальность). Только Chrome-family: Firefox
// исключён из RU-дефолта (банится первым). Веса отражают разброс по 3
// доступным в utls v1.8.3 major (120/131/133), а НЕ абсолютную популяцию
// (потолок 133 = CRIT-3, отдельный roadmap-форк).
func DefaultFPWeights() map[string]int {
	return map[string]int{
		ProfileChrome133: 60, // новейший доступный — основная масса
		ProfileChrome131: 30, // PQ-несущий, недавний
		ProfileChrome120: 10, // не-PQ хвост — разброс key_share-конфигурации
	}
}

func init() {
	register(BrowserProfile{
		Name:         ProfileChrome133,
		Family:       FamilyChrome,
		Major:        133,
		UTLSHelloID:  utls.HelloChrome_133,
		BogdanfinnID: profiles.Chrome_133,
		UAString:     ChromeUAForMajor(133),
		CHUA:         ChromeCHUAForMajor(133),
		PQKeyShare:   true, // utls+bogdanfinn оба несут X25519MLKEM768
	})
	register(BrowserProfile{
		Name:         ProfileChrome131,
		Family:       FamilyChrome,
		Major:        131,
		UTLSHelloID:  utls.HelloChrome_131,
		BogdanfinnID: profiles.Chrome_131,
		UAString:     ChromeUAForMajor(131),
		CHUA:         ChromeCHUAForMajor(131),
		PQKeyShare:   true, // оба пути несут MLKEM
	})
	register(BrowserProfile{
		Name:         ProfileChrome120,
		Family:       FamilyChrome,
		Major:        120,
		UTLSHelloID:  utls.HelloChrome_120,
		BogdanfinnID: profiles.Chrome_120,
		UAString:     ChromeUAForMajor(120),
		CHUA:         ChromeCHUAForMajor(120),
		PQKeyShare:   false, // classic key_share {X25519} на обоих путях
	})
	registerFirefoxIfEnabled() // Task 5 — за build-tag sl_firefox
}

// validateProfile проверяет lockstep-инвариант: все 4 поверхности согласованы.
// Невалидный профиль НЕ попадает в реестр (fail-fast на старте).
func validateProfile(p BrowserProfile) error {
	if p.Name == "" {
		return fmt.Errorf("profile: empty name")
	}
	if p.UAString == "" {
		return fmt.Errorf("profile %q: empty UA", p.Name)
	}
	// Lockstep-поверхности не должны быть нулевыми (LOW из ревью A5): защита от
	// профиля без TLS-ClientHello или без H2-профиля — иначе рассинхрон провода.
	if p.UTLSHelloID.Client == "" {
		return fmt.Errorf("profile %q: empty UTLSHelloID", p.Name)
	}
	// bogdanfinn zero-value ClientProfile.GetClientHelloStr() возвращает "-", не "".
	if s := p.BogdanfinnID.GetClientHelloStr(); s == "" || s == "-" {
		return fmt.Errorf("profile %q: empty BogdanfinnID", p.Name)
	}
	switch p.Family {
	case FamilyChrome:
		if !strings.Contains(p.UAString, "Chrome/") || strings.Contains(p.UAString, "Firefox/") {
			return fmt.Errorf("profile %q: UA must contain Chrome/ and not Firefox/", p.Name)
		}
		if p.CHUA == nil {
			return fmt.Errorf("profile %q: CHUA must be non-nil (real Chrome emits sec-ch-ua)", p.Name)
		}
		// MED: числовая сверка major по всем извлекаемым поверхностям.
		if uaMaj, ok := extractMajorFromUA(p.UAString); !ok || uaMaj != p.Major {
			return fmt.Errorf("profile %q: UA major %d != Major %d", p.Name, uaMaj, p.Major)
		}
		if chuaMaj, ok := extractMajorFromCHUA(p.CHUA); !ok || chuaMaj != p.Major {
			return fmt.Errorf("profile %q: sec-ch-ua major %d != Major %d", p.Name, chuaMaj, p.Major)
		}
		if bMaj, ok := extractMajorFromBogdanfinn(p.BogdanfinnID); ok && bMaj != p.Major {
			return fmt.Errorf("profile %q: bogdanfinn major %d != Major %d", p.Name, bMaj, p.Major)
		}
	case FamilyFirefox:
		if !strings.Contains(p.UAString, "Firefox/") {
			return fmt.Errorf("profile %q: UA must contain Firefox/", p.Name)
		}
		if strings.Contains(p.UAString, "Chrome/") {
			return fmt.Errorf("profile %q: UA must NOT contain Chrome/ (cross-layer mismatch)", p.Name)
		}
		if p.CHUA != nil {
			return fmt.Errorf("profile %q: CHUA must be nil (Firefox does not send sec-ch-ua)", p.Name)
		}
		// Firefox Major (148) намеренно != bogdanfinn (147) — числовую сверку
		// не делаем (см. спека §5 known gap).
	default:
		return fmt.Errorf("profile %q: unknown Family %q, no validation rule", p.Name, p.Family)
	}
	return nil
}

// extractMajorFromUA вытаскивает Chrome major из UA ("Chrome/131.0.0.0" → 131).
func extractMajorFromUA(ua string) (int, bool) {
	const tag = "Chrome/"
	i := strings.Index(ua, tag)
	if i < 0 {
		return 0, false
	}
	rest := ua[i+len(tag):]
	j := strings.IndexByte(rest, '.')
	if j < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[:j])
	if err != nil {
		return 0, false
	}
	return n, true
}

// extractMajorFromCHUA вытаскивает major из sec-ch-ua "Google Chrome";v="131".
func extractMajorFromCHUA(chua func() [][2]string) (int, bool) {
	if chua == nil {
		return 0, false
	}
	for _, kv := range chua() {
		if kv[0] != "sec-ch-ua" {
			continue
		}
		marker := `"Google Chrome";v="`
		i := strings.Index(kv[1], marker)
		if i < 0 {
			return 0, false
		}
		rest := kv[1][i+len(marker):]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			return 0, false
		}
		n, err := strconv.Atoi(rest[:j])
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// extractMajorFromBogdanfinn пытается вытащить major из строки клиент-hello
// bogdanfinn-профиля. Формат у bogdanfinn v1.14.0 — "Chrome-133" / "Chrome-131"
// (дефис, проверено в module cache 2026-06-11). Берём завершающую цепочку цифр,
// что устойчиво к смене разделителя ('-' / '_'). Возвращает ok=false, если в
// строке нет завершающих цифр (тогда сверка bogdanfinn-major пропускается — не
// фейлим на профилях, чья строка не следует конвенции).
func extractMajorFromBogdanfinn(p profiles.ClientProfile) (int, bool) {
	s := p.GetClientHelloStr() // напр. "Chrome-133"
	end := len(s)
	start := end
	for start > 0 && s[start-1] >= '0' && s[start-1] <= '9' {
		start--
	}
	if start == end {
		return 0, false // нет завершающих цифр
	}
	n, err := strconv.Atoi(s[start:end])
	if err != nil {
		return 0, false
	}
	return n, true
}

// register добавляет профиль в реестр. Panic на невалидном профиле — fail-fast
// при старте, чтобы рассинхрон 4 поверхностей не попал в продакшн-бинарь.
func register(p BrowserProfile) {
	if err := validateProfile(p); err != nil {
		panic("browser: invalid profile in registry: " + err.Error())
	}
	profileRegistry[p.Name] = p
}

// ChooseProfileName делает weighted-random выбор имени профиля по весам.
// Кандидаты фильтруются по реестру (вес неизвестного профиля игнорируется) и
// по положительности (вес <= 0 не участвует). Пустой результирующий набор →
// безопасный дефолт "chrome". seed делает выбор воспроизводимым в тестах;
// прод-вызов передаёт RandomSeed().
// Кандидаты сортируются по имени перед выбором для полного детерминизма по seed
// (обход map в Go случаен, сортировка устраняет скрытую недетерминированность).
func ChooseProfileName(weights map[string]int, seed uint64) string {
	type cand struct {
		name string
		w    int
	}
	var cands []cand
	total := 0
	for name, w := range weights {
		if w <= 0 {
			continue
		}
		if _, ok := profileRegistry[name]; !ok {
			continue
		}
		cands = append(cands, cand{name, w})
		total += w
	}
	if total == 0 || len(cands) == 0 {
		return ProfileChrome133
	}
	// Сортируем по имени для детерминизма: порядок обхода map случаен,
	// сортировка гарантирует одинаковый результат при одном seed.
	sort.Slice(cands, func(i, j int) bool { return cands[i].name < cands[j].name })
	r := int(seed % uint64(total))
	for _, c := range cands {
		if r < c.w {
			return c.name
		}
		r -= c.w
	}
	return ProfileChrome133
}

// RandomSeed — прод-источник энтропии для ChooseProfileName.
func RandomSeed() uint64 { return rand.Uint64() }

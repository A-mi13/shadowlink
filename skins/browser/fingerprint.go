package browser

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/refraction-networking/utls"
)

// Browser profile names.
//
// 2026-05-05: non-Chrome profiles retired. TSPU начал блокировать non-Chrome
// uTLS-фингерпринты (Safari/Firefox/Edge), оставлен только Chrome — он
// единственный стабильно проходит через РФ-DPI. Константы ProfileSafari /
// ProfileFirefox удалены вместе с их веткой в Pool/NewFingerprint/UpdateUserAgents.
const (
	// Family-метки — класс браузера для policy-веток (PQ, sec-ch-ua, UA-валидация).
	FamilyChrome  = "chrome"
	FamilyFirefox = "firefox"

	// Имена-ключи реестра diversity-профилей (persist-значения fp-state.bin).
	ProfileChrome120 = "chrome120"
	ProfileChrome131 = "chrome131"
	ProfileChrome133 = "chrome133"

	// ProfileChrome — legacy-алиас. Сохранён для обратной совместимости с
	// существующими call-site'ами и persisted state. Резолвится в chrome133
	// (новейший доступный) через LookupProfile fallback (Task 6).
	ProfileChrome = "chrome"
)

// LockedChromeMajor is the single Chrome major used everywhere a Chrome
// fingerprint surface is exposed: uTLS ClientHello, bogdanfinn H2 SETTINGS,
// User-Agent string, and the sec-ch-ua header value.
//
// Pinned at 133 because that's the highest non-PSK ClientHello spec available
// in refraction-networking/utls v1.8.3 — HelloChrome_135+ does not exist
// upstream as of 2026-05. Bumping this constant requires:
//  1. utls upstream shipping HelloChrome_<new> in u_parrots.go
//  2. bogdanfinn/tls-client exposing profiles.Chrome_<new>
//  3. coordinated bump of LockedChromeMajor + tests + JA4 fixture refresh
//
// The 4-surface lockstep (uTLS + bogdanfinn + UA + sec-ch-ua) is more
// important than version-recency: a passive observer running a JA4 + H2
// SETTINGS + UA + sec-ch-ua consistency check sees ANY mismatch as an
// instant fingerprint, while a single-major mismatch with real-world
// Chrome 138-141 in 2026-05 looks like a long-tail-unupdated install
// (~1-2% of real Chrome traffic). Consistency wins until utls catches up.
const LockedChromeMajor = 133

// LockedChromeMajorString is the decimal string form of LockedChromeMajor —
// useful inline for the sec-ch-ua header building.
var LockedChromeMajorString = strconv.Itoa(LockedChromeMajor)

// LockedUTLSChromeID returns the uTLS ClientHelloID for the locked Chrome
// major. Cold-path dialers (split_transport_tls, ws_transport upgrade,
// utls_http for SendHandshake/Warmup, probe.probeHTTPS, ECH DoH client)
// consume this to keep JA3/JA4 consistent.
func LockedUTLSChromeID() utls.ClientHelloID {
	return utls.HelloChrome_133
}

// LockedBogdanfinnChromeProfile returns the bogdanfinn TLS profile for the
// locked Chrome major. ConnManager hot path consumes this for H2 SETTINGS
// and TLS extension ordering.
func LockedBogdanfinnChromeProfile() profiles.ClientProfile {
	return profiles.Chrome_133
}

// ChromeUAForMajor строит User-Agent для заданного Chrome major. Базовый
// билдер для per-major diversity-профилей (chrome120/131/133).
func ChromeUAForMajor(major int) string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" +
		strconv.Itoa(major) + ".0.0.0 Safari/537.36"
}

// ChromeCHUAForMajor строит sec-ch-ua набор для заданного Chrome major.
// Возвращает билдер-функцию (как поле CHUA в BrowserProfile).
func ChromeCHUAForMajor(major int) func() [][2]string {
	v := strconv.Itoa(major)
	return func() [][2]string {
		return [][2]string{
			{"sec-ch-ua", `"Chromium";v="` + v + `", "Not(A:Brand";v="99", "Google Chrome";v="` + v + `"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
		}
	}
}

// LockedChromeUA returns the User-Agent string for the locked Chrome major.
// Used by every HTTP request (handshake POST, WarmupRequests, decoy_traffic,
// LeakGuard CheckIP, server-side exportClientConfig). Тонкая обёртка над
// ChromeUAForMajor(LockedChromeMajor) — обратная совместимость call-sites.
func LockedChromeUA() string {
	return ChromeUAForMajor(LockedChromeMajor)
}

// chuaHeaderSetter is the minimal interface every http header type
// (net/http, bogdanfinn/fhttp, http.Header maps used in websocket.Dialer)
// satisfies for our Set call. Defining it here lets ApplyChromeCHUA work
// across both stdlib and bogdanfinn request types without an import cycle.
type chuaHeaderSetter interface {
	Set(key, value string)
}

// ApplyChromeCHUA writes the locked Chrome sec-ch-ua header set onto h.
//
// 2026-05-05: non-Chrome fingerprints retired, so this helper is now an
// unconditional Chrome emitter — но wrappers ApplyChromeCHUAFor* сохранены
// для обратной совместимости с существующими call-sites.
func ApplyChromeCHUA(h chuaHeaderSetter) {
	for _, kv := range LockedChromeCHUA() {
		h.Set(kv[0], kv[1])
	}
}

// ApplyChromeCHUAForFingerprint writes the locked Chrome sec-ch-ua headers
// when fp identifies as a Chrome profile. With non-Chrome profiles retired
// 2026-05-05 the only legitimate name is ProfileChrome; nil and unknown
// names are silent no-ops (defensive: future code paths might construct
// a Fingerprint via a path we haven't audited).
func ApplyChromeCHUAForFingerprint(h chuaHeaderSetter, fp *Fingerprint) {
	if fp == nil || !IsChromeFamily(fp.Name()) {
		return
	}
	// Emit sec-ch-ua matching the fingerprint's actual Chrome major (diversity:
	// chrome120/131/133 each emit their own version), not the locked default.
	if fp.Profile().CHUA != nil {
		for _, kv := range fp.Profile().CHUA() {
			h.Set(kv[0], kv[1])
		}
		return
	}
	ApplyChromeCHUA(h)
}

// ApplyChromeCHUAForUA inspects a User-Agent string and emits sec-ch-ua
// headers when the UA looks Chromium-family. Use this at sites where the
// caller passes a UA string but not the Fingerprint object.
//
// Detection: presence of "Chrome/" — Firefox/Safari UAs don't include it.
// Edge etc. (also Chromium) match too; this is correct because real Edge
// also emits sec-ch-ua headers (with its own brand value, not modeled
// here). The only false-positive risk is bots that spoof "Chrome/" without
// the rest of the Chromium feature set — out of scope for our UA pool.
func ApplyChromeCHUAForUA(h chuaHeaderSetter, ua string) {
	if !strings.Contains(ua, "Chrome/") {
		return
	}
	ApplyChromeCHUA(h)
}

// LockedChromeCHUA returns the sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform
// header values that real Chrome on Windows emits on every HTTPS request.
// Real Chrome since v90 sends these unconditionally on non-navigation
// sub-resources; their absence on a connection that simultaneously presents
// a Chrome JA4 fingerprint is a browser-class contradiction.
//
// Returns three (key, value) pairs as a slice so callers can iterate without
// allocating a map. Order matches Chrome's emission order:
//
//	sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform
//
// Brand quoting and "Not(A:Brand" string are part of the public Chrome
// brand-substitution scheme — do NOT change them.
func LockedChromeCHUA() [][2]string {
	return ChromeCHUAForMajor(LockedChromeMajor)()
}

// Fingerprint represents a browser TLS profile with a matching User-Agent.
// 2026-05-05: только Chrome остался — все non-Chrome fp заблокированы TSPU.
// Тип сохранён, чтобы не ломать сигнатуры transport/connmanager/ws_transport.
type Fingerprint struct {
	name      string
	userAgent string
	profile   BrowserProfile // выбранный профиль (lockstep-источник всех поверхностей)
}

// NewFingerprint creates a fingerprint for the given browser profile.
//
// 2026-05-05: только ProfileChrome обрабатывается специально, любое
// другое имя fall-through на Chrome (включая ранее поддерживаемые
// "safari" / "firefox" — оставлены как backward-compat shim для legacy
// state-файлов с persisted profile name).
func NewFingerprint(profile string) *Fingerprint {
	uaMu.RLock()
	defer uaMu.RUnlock()

	_ = profile // legacy parameter: всегда Chrome
	// Legacy-алиас "chrome" резолвится через LookupProfile в chrome133.
	p, _ := LookupProfile(ProfileChrome)
	ua := p.UAString
	// chromeUA может быть переопределён сервером (UpdateUserAgents) — уважаем.
	if chromeUA != "" {
		ua = chromeUA
	}
	fp := &Fingerprint{
		name:      p.Name,
		userAgent: ua,
		profile:   p,
	}
	return fp
}

// NewFingerprintForProfile создаёт Fingerprint для имени профиля из реестра.
// Неизвестное имя → безопасный fallback на chrome.
func NewFingerprintForProfile(name string) *Fingerprint {
	p, ok := LookupProfile(name)
	if !ok {
		p, _ = LookupProfile(ProfileChrome133)
	}
	return &Fingerprint{
		name:      p.Name,
		userAgent: p.UAString,
		profile:   p,
	}
}

// Name returns the profile name.
func (f *Fingerprint) Name() string {
	return f.name
}

// UserAgent returns the User-Agent string matching this fingerprint's browser.
func (f *Fingerprint) UserAgent() string {
	return f.userAgent
}

// Profile возвращает выбранный browser-профиль (lockstep-источник).
func (f *Fingerprint) Profile() BrowserProfile { return f.profile }

// UpdateUserAgents updates UA strings for all profiles.
// Called when the server provides fresh UA versions in ServerHello.
//
// 2026-05-05: только "chrome" key обрабатывается. Любые другие keys
// (включая ранее поддерживаемые "safari" / "firefox") тихо игнорируются.
// Server-side cleanup в exportClientConfig тоже отправляет только chrome.
// M5 audit fix: thread-safe via mutex.
func UpdateUserAgents(uas map[string]string) {
	uaMu.Lock()
	defer uaMu.Unlock()
	for profile, ua := range uas {
		if ua == "" {
			continue
		}
		if profile == ProfileChrome {
			chromeUA = ua
		}
	}
}

// Default UA strings — updated via UpdateUserAgents from server.
// Protected by uaMu for concurrent access (M5 audit fix).
//
// 2026-05-05: safariUA / firefoxUA удалены. Только Chrome.
var (
	uaMu     sync.RWMutex
	chromeUA = LockedChromeUA()
)

// FingerprintPool selects browser fingerprints.
//
// 2026-05-05: pool сжат до одного Chrome профиля. Поле weights/total оставлено
// для совместимости со старым тестом, но Next() теперь всегда возвращает Chrome.
type FingerprintPool struct {
	profiles []*Fingerprint
}

// NewFingerprintPool creates a pool with только Chrome profile.
// Non-Chrome fingerprints retired 2026-05-05 (TSPU блокирует Safari/Firefox/Edge).
func NewFingerprintPool() *FingerprintPool {
	return &FingerprintPool{
		profiles: []*Fingerprint{
			NewFingerprint(ProfileChrome),
		},
	}
}

// NewFingerprintPoolForProfile создаёт пул с единственным выбранным профилем.
func NewFingerprintPoolForProfile(name string) *FingerprintPool {
	return &FingerprintPool{profiles: []*Fingerprint{NewFingerprintForProfile(name)}}
}

// Next returns the locked Chrome fingerprint. The pool is single-entry now;
// the previous weighted-random rotation across Chrome/Safari/Firefox was
// retired 2026-05-05 (TSPU blocks non-Chrome).
func (p *FingerprintPool) Next() *Fingerprint {
	if len(p.profiles) == 0 {
		// Defensive: каллер не должен сюда дойти, но не падаем — отдаём свежий Chrome.
		return NewFingerprint(ProfileChrome)
	}
	return p.profiles[rand.IntN(len(p.profiles))]
}

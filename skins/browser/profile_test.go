package browser

import (
	"testing"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/refraction-networking/utls"
)

func TestChooseProfile_FiltersUnknownAndZero(t *testing.T) {
	// Только chrome133 имеет положительный вес и есть в реестре; chrome131=0 и
	// несуществующий safari отфильтрованы.
	weights := map[string]int{ProfileChrome133: 100, ProfileChrome131: 0, "safari": 5}
	for i := 0; i < 1000; i++ {
		if name := ChooseProfileName(weights, uint64(i)); name != ProfileChrome133 {
			t.Fatalf("iter %d: got %q, want chrome133", i, name)
		}
	}
}

func TestChooseProfile_EmptyWeightsFallsBackChrome(t *testing.T) {
	if ChooseProfileName(nil, 0) != ProfileChrome133 {
		t.Error("nil weights → want chrome133")
	}
	if ChooseProfileName(map[string]int{}, 0) != ProfileChrome133 {
		t.Error("empty weights → want chrome133")
	}
	if ChooseProfileName(map[string]int{ProfileChrome133: 0, ProfileChrome131: 0}, 0) != ProfileChrome133 {
		t.Error("all-zero weights → want chrome133")
	}
}

func TestChooseProfile_DistributionApprox(t *testing.T) {
	if _, ok := LookupProfile("firefox"); !ok {
		t.Skip("firefox not in registry (gate not passed) — distribution test N/A")
	}
	weights := map[string]int{ProfileChrome133: 90, "firefox": 10}
	ff := 0
	const N = 10000
	for i := 0; i < N; i++ {
		if ChooseProfileName(weights, uint64(i)*2654435761) != ProfileChrome133 {
			ff++
		}
	}
	if ff < 700 || ff > 1300 {
		t.Errorf("firefox count = %d, want ~1000 (chrome:90/firefox:10)", ff)
	}
}

func TestRegistry_ChromeProfileExists(t *testing.T) {
	// Legacy "chrome" резолвится в chrome133 (новейший доступный major).
	p, ok := LookupProfile("chrome")
	if !ok {
		t.Fatal("chrome profile must exist in registry")
	}
	if p.Name != ProfileChrome133 {
		t.Errorf("Name = %q, want chrome133 (legacy alias)", p.Name)
	}
	if p.Family != FamilyChrome {
		t.Errorf("Family = %q, want chrome", p.Family)
	}
	if p.Major != LockedChromeMajor {
		t.Errorf("Major = %d, want %d", p.Major, LockedChromeMajor)
	}
	if p.CHUA == nil {
		t.Error("chrome CHUA must be non-nil")
	}
	if p.UTLSHelloID != utls.HelloChrome_133 {
		t.Errorf("UTLSHelloID mismatch, want HelloChrome_133")
	}
	if p.BogdanfinnID.GetClientHelloStr() != profiles.Chrome_133.GetClientHelloStr() {
		t.Errorf("BogdanfinnID mismatch, want Chrome_133 (got %q)", p.BogdanfinnID.GetClientHelloStr())
	}
}

func TestRegistry_UnknownProfile(t *testing.T) {
	if _, ok := LookupProfile("netscape"); ok {
		t.Error("unknown profile must not be found")
	}
}

func TestValidateProfile_RejectsUAMismatch(t *testing.T) {
	// Firefox-профиль с Chrome-UA = рассинхрон, валидатор должен отклонить.
	bad := BrowserProfile{
		Name:     "firefox",
		Family:   FamilyFirefox,
		Major:    148,
		UAString: "Mozilla/5.0 ... Chrome/133.0.0.0 Safari/537.36",
		CHUA:     nil,
	}
	if err := validateProfile(bad); err == nil {
		t.Error("validateProfile must reject Firefox profile carrying a Chrome UA")
	}
}

func TestValidateProfile_RejectsChromeNilCHUA(t *testing.T) {
	bad := BrowserProfile{Name: "chrome", Family: FamilyChrome, Major: 133, UAString: LockedChromeUA(), CHUA: nil}
	if err := validateProfile(bad); err == nil {
		t.Error("chrome profile with nil CHUA must be rejected")
	}
}

func TestValidateProfile_AcceptsChrome(t *testing.T) {
	good, _ := LookupProfile("chrome")
	if err := validateProfile(good); err != nil {
		t.Errorf("registered chrome profile must be valid, got %v", err)
	}
}

func TestRegistry_KnownGaps(t *testing.T) {
	// Safari/Edge никогда не в реестре без парной версии (спека §4.3).
	for _, name := range []string{"safari", "edge"} {
		if _, ok := LookupProfile(name); ok {
			t.Errorf("%s must NOT be in registry — no lockstep pair available", name)
		}
	}
	if _, ok := LookupProfile("firefox"); !ok {
		t.Log("firefox not registered: H2-pairing gate pending controller decision")
	}
}

func TestRegistry_FirefoxProfile(t *testing.T) {
	p, ok := LookupProfile("firefox")
	if !ok {
		t.Skip("firefox gated behind sl_firefox build-tag — absent in default RU build")
	}
	if p.Major != 148 {
		t.Errorf("firefox Major = %d, want 148", p.Major)
	}
	if p.CHUA != nil {
		t.Error("firefox CHUA must be nil (does not send sec-ch-ua)")
	}
	if p.UTLSHelloID != utls.HelloFirefox_148 {
		t.Error("firefox UTLSHelloID must be HelloFirefox_148")
	}
	if p.BogdanfinnID.GetClientHelloStr() != profiles.Firefox_147.GetClientHelloStr() {
		t.Errorf("firefox BogdanfinnID mismatch, want Firefox_147 (got %q)", p.BogdanfinnID.GetClientHelloStr())
	}
	if err := validateProfile(p); err != nil {
		t.Errorf("firefox profile must pass validateProfile: %v", err)
	}
}

package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// FPState — персистентное состояние fingerprint клиента. Хранит выбранный
// профиль (имя, не версию) и кэш весов от сервера для холодного старта.
// Построено по образцу bypassroute/admin_cache.go (atomic tmp+rename, 0600),
// но БЕЗ HMAC: файл локальный, его подмена = self-harm, не атака на флот.
type FPState struct {
	ProfileName   string         `json:"profile"`
	CachedWeights map[string]int `json:"weights,omitempty"`
}

func fpStateFilePath(dir string) string {
	return filepath.Join(dir, "fp-state.bin")
}

// SaveFPState атомарно пишет состояние (tmp + rename), права 0600, dir 0700.
func SaveFPState(dir string, st FPState) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	out, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeRawFPState(dir, out)
}

func writeRawFPState(dir string, out []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	final := fpStateFilePath(dir)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ResolveProfile определяет активный профиль при старте.
//  1. Есть persist + профиль в реестре → используем (fresh=false).
//  2. Нет persist / профиль не в реестре / файл битый → бросок кости по весам,
//     перезапись state (fresh=true).
//
// Единый weighted-random (browser.ChooseProfileName) для initial и resample.
// seed — для тестов; прод передаёт browser.RandomSeed().
func ResolveProfile(dir string, weights map[string]int, seed uint64) (name string, fresh bool) {
	if st, err := LoadFPState(dir); err == nil {
		if _, ok := browser.LookupProfile(st.ProfileName); ok {
			return st.ProfileName, false // legacy "chrome" зарезолвится в chrome133
		}
		// профиль убран из реестра (бан-релиз) → ресэмпл
	}
	if len(weights) == 0 {
		// Пустой серверный YAML (текущая прод-реальность) → зашитые в код
		// дефолты, а НЕ chrome-100% монокультура.
		weights = browser.DefaultFPWeights()
	}
	chosen := browser.ChooseProfileName(weights, seed)
	_ = SaveFPState(dir, FPState{ProfileName: chosen, CachedWeights: weights})
	return chosen, true
}

// resolveProfileWithEnv оборачивает ResolveProfile аварийным выключателем.
// SHADOWLINK_FP_POOL=0/false/no/off → принудительный Chrome 100%, игнор весов
// и persist. Позволяет вырубить популяционную мимикрию без передеплоя сервера.
func resolveProfileWithEnv(dir string, weights map[string]int, seed uint64) string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_FP_POOL"))) {
	case "0", "false", "no", "off":
		return browser.ProfileChrome133 // явный новейший доступный major
	}
	name, _ := ResolveProfile(dir, weights, seed)
	return name
}

// LoadFPState читает состояние. Ошибка если файла нет или JSON битый.
func LoadFPState(dir string) (FPState, error) {
	var st FPState
	raw, err := os.ReadFile(fpStateFilePath(dir))
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, err
	}
	return st, nil
}

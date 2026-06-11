package client

import (
	"path/filepath"
	"testing"

	"github.com/nixavpn/shadowlink/skins/browser"
)

func TestFPState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := FPState{ProfileName: "firefox", CachedWeights: map[string]int{"chrome": 80, "firefox": 20}}
	if err := SaveFPState(dir, st); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadFPState(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.ProfileName != "firefox" {
		t.Errorf("ProfileName = %q, want firefox", got.ProfileName)
	}
	if got.CachedWeights["firefox"] != 20 {
		t.Errorf("weights[firefox] = %d, want 20", got.CachedWeights["firefox"])
	}
}

func TestFPState_MissingFileIsError(t *testing.T) {
	if _, err := LoadFPState(filepath.Join(t.TempDir(), "nonexistent")); err == nil {
		t.Error("loading from empty dir must return error (no file)")
	}
}

func TestFPState_CorruptFileIsError(t *testing.T) {
	dir := t.TempDir()
	if err := writeRawFPState(dir, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFPState(dir); err == nil {
		t.Error("corrupt file must return error")
	}
}

func TestResolveProfile_PersistedWins(t *testing.T) {
	dir := t.TempDir()
	_ = SaveFPState(dir, FPState{ProfileName: "chrome"})
	name, fresh := ResolveProfile(dir, map[string]int{"chrome": 50, "firefox": 50}, 123)
	if name != "chrome" {
		t.Errorf("persisted chrome must win, got %q", name)
	}
	if fresh {
		t.Error("persisted profile must not be marked fresh")
	}
}

func TestResolveProfile_FirstRunRollsAndPersists(t *testing.T) {
	dir := t.TempDir()
	name, fresh := ResolveProfile(dir, map[string]int{browser.ProfileChrome133: 100}, 0)
	if name != browser.ProfileChrome133 {
		t.Errorf("first run with chrome133:100 → %q", name)
	}
	if !fresh {
		t.Error("first run must be marked fresh")
	}
	got, err := LoadFPState(dir)
	if err != nil || got.ProfileName != browser.ProfileChrome133 {
		t.Errorf("first-run choice must be persisted, got %+v err=%v", got, err)
	}
}

func TestResolveProfile_PersistedNotInRegistryResamples(t *testing.T) {
	dir := t.TempDir()
	_ = SaveFPState(dir, FPState{ProfileName: "safari"}) // не в реестре
	name, fresh := ResolveProfile(dir, map[string]int{browser.ProfileChrome133: 100}, 0)
	if name != browser.ProfileChrome133 {
		t.Errorf("invalid persisted profile must resample to chrome133, got %q", name)
	}
	if !fresh {
		t.Error("resample must be marked fresh (rewrite state)")
	}
}

func TestFPPoolDisabled_ForcesChrome(t *testing.T) {
	t.Setenv("SHADOWLINK_FP_POOL", "0")
	dir := t.TempDir()
	_ = SaveFPState(dir, FPState{ProfileName: "firefox"}) // даже persisted firefox
	name := resolveProfileWithEnv(dir, map[string]int{"firefox": 100}, 0)
	if name != browser.ProfileChrome133 {
		t.Errorf("SHADOWLINK_FP_POOL=0 must force chrome133, got %q", name)
	}
}

func TestFPPoolEnabled_NormalResolve(t *testing.T) {
	t.Setenv("SHADOWLINK_FP_POOL", "") // не задан → нормальная работа
	dir := t.TempDir()
	_ = SaveFPState(dir, FPState{ProfileName: "chrome"})
	name := resolveProfileWithEnv(dir, map[string]int{"chrome": 100}, 0)
	if name != "chrome" {
		t.Errorf("normal resolve persisted chrome → %q", name)
	}
}

// Убеждаемся, что browser импорт используется (compile-time).
var _ = browser.RandomSeed

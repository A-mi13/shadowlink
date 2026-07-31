package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// H-18 (раунд 18): SessionTimeout/CleanupInterval были захардкожены в
// cmd/shadowlink-server/main.go как 5m/30s сразу ПОСЛЕ DefaultConfig(), то есть
// значения 90s/10s из DefaultConfig отменялись двумя строками. 5m/30s — ровно
// те значения, которые ретроспектива инцидента 2026-05-17 (докблок
// DefaultConfig) называет причиной decoy lockout. Ни YAML-, ни CLI-ключа не
// существовало → прод гарантированно работал на 5m/30s, изменить нельзя было без
// пересборки, а комментарий в config.go описывал неприменяемые значения.

func TestSessionTimeout_DefaultsMatchIncidentRetrospective(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.SessionTimeout != 90*time.Second {
		t.Errorf("SessionTimeout=%v, ретроспектива 2026-05-17 требует 90s", cfg.SessionTimeout)
	}
	if cfg.CleanupInterval != 10*time.Second {
		t.Errorf("CleanupInterval=%v, ретроспектива 2026-05-17 требует 10s", cfg.CleanupInterval)
	}
}

func TestSessionTimeout_ConfigurableViaYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "session_timeout_sec: 120\ncleanup_interval_sec: 15\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("запись конфига: %v", err)
	}

	fc, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)

	if cfg.SessionTimeout != 120*time.Second {
		t.Errorf("SessionTimeout=%v, ожидалось 120s из YAML", cfg.SessionTimeout)
	}
	if cfg.CleanupInterval != 15*time.Second {
		t.Errorf("CleanupInterval=%v, ожидалось 15s из YAML", cfg.CleanupInterval)
	}
}

// Отсутствие ключей не должно затирать дефолты.
func TestSessionTimeout_AbsentYAMLKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("max_clients: 42\n"), 0o600); err != nil {
		t.Fatalf("запись конфига: %v", err)
	}

	fc, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	cfg := DefaultConfig()
	fc.ApplyTo(&cfg)

	if cfg.SessionTimeout != 90*time.Second {
		t.Errorf("SessionTimeout=%v — отсутствующий ключ затёр дефолт", cfg.SessionTimeout)
	}
	if cfg.CleanupInterval != 10*time.Second {
		t.Errorf("CleanupInterval=%v — отсутствующий ключ затёр дефолт", cfg.CleanupInterval)
	}
}

// Ноль/отрицательное игнорируются: session_timeout_sec: 0 означало бы
// «сессии не истекают никогда», cleanup_interval_sec: 0 — busy-loop в sweeper'е.
func TestSessionTimeout_NonPositiveIgnored(t *testing.T) {
	for _, body := range []string{
		"session_timeout_sec: 0\ncleanup_interval_sec: 0\n",
		"session_timeout_sec: -5\ncleanup_interval_sec: -1\n",
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("запись конфига: %v", err)
		}
		fc, err := LoadConfigFile(path)
		if err != nil {
			t.Fatalf("LoadConfigFile: %v", err)
		}
		cfg := DefaultConfig()
		fc.ApplyTo(&cfg)

		if cfg.SessionTimeout <= 0 {
			t.Errorf("SessionTimeout=%v при YAML %q — неположительное значение применено",
				cfg.SessionTimeout, body)
		}
		if cfg.CleanupInterval <= 0 {
			t.Errorf("CleanupInterval=%v при YAML %q — неположительное значение применено",
				cfg.CleanupInterval, body)
		}
	}
}

// Сторож: main.go не должен снова затирать значения после DefaultConfig().
//
// Именно так дефект и выглядел — не как отсутствие функциональности, а как две
// строки присваивания, отменяющие ретроспективу инцидента. Unit-тесты на
// DefaultConfig и YAML этого не видели: они не читают main.go.
func TestSessionTimeout_MainDoesNotHardcode(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "cmd", "shadowlink-server", "main.go"))
	if err != nil {
		t.Fatalf("не прочитан main.go: %v", err)
	}
	code := string(src)

	// Ищем присваивания, а не упоминания в комментариях.
	for _, bad := range []string{
		"config.SessionTimeout =",
		"config.CleanupInterval =",
	} {
		for _, line := range strings.Split(code, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue // комментарий, объясняющий историю — это норма
			}
			if !strings.Contains(trimmed, bad) {
				continue
			}
			// Допустимо только внутри explicitly[...] гейта CLI-флага.
			if strings.Contains(code, `explicitly["session-timeout"]`) &&
				strings.Contains(trimmed, "time.Duration(") {
				continue
			}
			t.Errorf("main.go содержит безусловное присваивание %q: %q — "+
				"значения DefaultConfig снова отменяются", bad, trimmed)
		}
	}

	// И наоборот: возможность переопределения должна существовать.
	if !strings.Contains(code, `explicitly["session-timeout"]`) {
		t.Error("main.go не применяет -session-timeout — настраиваемости нет")
	}
	if !strings.Contains(code, `explicitly["cleanup-interval"]`) {
		t.Error("main.go не применяет -cleanup-interval — настраиваемости нет")
	}
}

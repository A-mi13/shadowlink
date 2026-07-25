package main

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestSplitTunnelEnabledFromEnv(t *testing.T) {
	cases := map[string]bool{
		"":        false, // default OFF (fail-secure)
		"0":       false,
		"off":     false,
		"garbage": false,
		"1":       true,
		"true":    true,
		"YES":     true,
		"On":      true,
	}
	for in, want := range cases {
		t.Setenv("SHADOWLINK_SPLIT_TUNNEL", in)
		if got := splitTunnelEnabledFromEnv(); got != want {
			t.Errorf("splitTunnelEnabledFromEnv(%q)=%v want %v", in, got, want)
		}
	}
	_ = os.Unsetenv("SHADOWLINK_SPLIT_TUNNEL")
}

func TestSplitDNSEnabledFromEnv(t *testing.T) {
	// t.Setenv forbids t.Parallel — keep this serial.
	cases := []struct {
		name     string
		env      string
		bypassOn bool
		want     bool
	}{
		{"unset follows bypass on", "", true, true},
		{"unset follows bypass off", "", false, false},
		{"explicit 0 disables despite bypass on", "0", true, false},
		{"explicit false disables despite bypass on", "false", true, false},
		{"explicit no disables", "no", true, false},
		{"explicit off disables", "off", true, false},
		{"explicit 1 enables despite bypass off", "1", false, true},
		{"explicit true enables despite bypass off", "true", false, true},
		{"explicit yes enables despite bypass off", "yes", false, true},
		{"explicit on enables despite bypass off", "on", false, true},
		{"mixed case ON enables", "ON", false, true},
		{"mixed case Off disables", "Off", true, false},
		{"garbage follows bypass on", "garbage", true, true},
		{"garbage follows bypass off", "garbage", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SHADOWLINK_SPLIT_DNS", tc.env)
			if got := splitDNSEnabledFromEnv(tc.bypassOn); got != tc.want {
				t.Errorf("splitDNSEnabledFromEnv(env=%q, bypassOn=%v)=%v want %v",
					tc.env, tc.bypassOn, got, tc.want)
			}
		})
	}
	_ = os.Unsetenv("SHADOWLINK_SPLIT_DNS")
}

// LG-L3 — a garbage SHADOWLINK_SPLIT_DNS value keeps the follow-bypass
// behaviour (pinned above) but must be VISIBLE: exactly the unrecognized
// branch logs a Warn; canonical values and unset stay silent.
func TestSplitDNSEnabledFromEnv_GarbageWarns(t *testing.T) {
	captureWarns := func(fn func()) string {
		var sb strings.Builder
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&sb, &slog.HandlerOptions{Level: slog.LevelDebug})))
		defer slog.SetDefault(prev)
		fn()
		return sb.String()
	}

	t.Setenv("SHADOWLINK_SPLIT_DNS", "garbage")
	out := captureWarns(func() {
		if got := splitDNSEnabledFromEnv(true); got != true {
			t.Fatalf("garbage must follow bypass (on), got %v", got)
		}
	})
	if !strings.Contains(out, "WARN") || !strings.Contains(out, "SHADOWLINK_SPLIT_DNS") {
		t.Fatalf("garbage value must log a Warn naming the env var; logs=%q", out)
	}

	// Canonical values and unset must NOT warn.
	for _, v := range []string{"", "0", "false", "no", "off", "1", "true", "yes", "on", "ON", "Off"} {
		t.Setenv("SHADOWLINK_SPLIT_DNS", v)
		out := captureWarns(func() { _ = splitDNSEnabledFromEnv(false) })
		if strings.Contains(out, "WARN") {
			t.Fatalf("canonical value %q must not warn; logs=%q", v, out)
		}
	}
	_ = os.Unsetenv("SHADOWLINK_SPLIT_DNS")
}

// Раунд 18 / C-3: default инвертирован на strict=ON (fail-secure). Прежняя
// версия теста утверждала, что пустое значение даёт false — то есть
// закрепляла fail-open как ожидаемое поведение.
func TestLeakguardStrictFromEnv(t *testing.T) {
	cases := map[string]bool{
		// Аварийный opt-out — единственный способ получить fail-open.
		"0":     false,
		"false": false,
		"no":    false,
		"off":   false,
		"OFF":   false, // регистронезависимо
		" 0 ":   false, // пробелы обрезаются
		// Default и всё нераспознанное → strict.
		"":        true,
		"1":       true,
		"true":    true,
		"on":      true,
		"garbage": true, // мусор НЕ должен ослаблять защиту
	}
	for in, want := range cases {
		t.Setenv("SHADOWLINK_LEAKGUARD_STRICT", in)
		if got := leakguardStrictFromEnv(); got != want {
			t.Errorf("leakguardStrictFromEnv(%q)=%v want %v", in, got, want)
		}
	}
}

// Отдельно и явно: при полностью неустановленной переменной защита включена.
func TestLeakguardStrict_DefaultIsFailSecure(t *testing.T) {
	t.Setenv("SHADOWLINK_LEAKGUARD_STRICT", "")
	if err := os.Unsetenv("SHADOWLINK_LEAKGUARD_STRICT"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if !leakguardStrictFromEnv() {
		t.Error("без переменной окружения strict-режим обязан быть ВКЛЮЧЁН (fail-secure, C-3)")
	}
}

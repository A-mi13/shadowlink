package client

import (
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// TestAsyncWriterExitLog_ReportsEffectiveTimeout — сторож против поля
// writeTimeout=0s в строке `ws async writer exit` (разбор прогона 2026-08-17).
//
// Что было: логировалось t.writeTimeout — КОНФИГУРИРОВАННОЕ значение. В
// direct-режиме оно не задано (0), а дедлайн на кадр всё равно действует: 30 с
// по умолчанию внутри core.WSAsyncWriter (ws_pool.go: `viaCF: 5-8s, direct: 0
// (→ 30s default)`). Поле читалось как «записи идут без дедлайна» и уже стоило
// времени при разборе прогона: писательские смерти списывали на что угодно,
// кроме сработавшего дедлайна.
//
// Стало: в лог идёт ЭФФЕКТИВНОЕ значение, взятое у того самого объекта, который
// его и применяет (w.WriteTimeout()), плюс конфигурированное отдельным полем.
// Второго источника числа 30s в коде нет — иначе при смене дефолта лог начнёт
// врать снова, ровно как сейчас.
func TestAsyncWriterExitLog_ReportsEffectiveTimeout(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	cases := []struct {
		name       string
		configured time.Duration
		wantEff    time.Duration
	}{
		// direct-режим: ручка не задана, дедлайн есть.
		{"direct_unset", 0, core.DefaultWSWriteTimeout},
		// viaCF: ручка задана, эффективное значение равно ей.
		{"via_cf_6s", 6 * time.Second, 6 * time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &syncBuffer{}
			slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))

			w := core.NewWSAsyncWriter(nil, 4)
			if tc.configured > 0 {
				w.SetWriteTimeout(tc.configured)
			}
			logAsyncWriterExit(w, tc.configured, errors.New("boom"))

			got := buf.String()
			if !strings.Contains(got, "write_timeout_effective="+tc.wantEff.String()) {
				t.Errorf("нет эффективного дедлайна %v в строке — читатель решит, "+
					"что записи идут без дедлайна:\n%s", tc.wantEff, got)
			}
			if !strings.Contains(got, "write_timeout_configured="+tc.configured.String()) {
				t.Errorf("нет конфигурированного значения %v — два разных смысла "+
					"должны быть различимы явно:\n%s", tc.configured, got)
			}
		})
	}
}

// TestAsyncWriterExitLog_NoSecondHardcodedDefault — сторож против второго
// источника дефолта 30s.
//
// Требование из разбора: величину брать из того же места, где она применяется.
// Если дефолт снова окажется зашит в client/ (литералом или собственной
// константой), лог разъедется с поведением при первой же смене дефолта — то
// есть дефект вернётся в исходном виде.
func TestAsyncWriterExitLog_NoSecondHardcodedDefault(t *testing.T) {
	src, err := os.ReadFile("ws_transport.go")
	if err != nil {
		t.Fatalf("read ws_transport.go: %v", err)
	}
	// Файлы репозитория с CRLF — нормализуем, иначе сторож ловит перевод строки,
	// а не механизм.
	code := strings.ReplaceAll(string(src), "\r\n", "\n")

	start := strings.Index(code, "func logAsyncWriterExit(")
	if start < 0 {
		t.Fatal("logAsyncWriterExit не найдена — тест устарел, обновить сторож")
	}
	end := strings.Index(code[start:], "\n}\n")
	if end < 0 {
		t.Fatal("не найден конец logAsyncWriterExit")
	}
	body := code[start : start+end]

	if !strings.Contains(body, "w.WriteTimeout()") {
		t.Error("строка выхода писателя больше не спрашивает эффективное значение " +
			"у самого writer'а (w.WriteTimeout()) — источник числа разошёлся с тем, " +
			"кто дедлайн применяет")
	}
	if strings.Contains(body, "time.Second") || strings.Contains(body, "DefaultWSWriteTimeout") {
		t.Error("в logAsyncWriterExit появилась своя копия дефолта — при смене " +
			"core.DefaultWSWriteTimeout лог снова начнёт врать")
	}

	// И в самом core значение обязано быть одно: константа.
	coreSrc, err := os.ReadFile("../core/wsasyncwriter.go")
	if err != nil {
		t.Fatalf("read core/wsasyncwriter.go: %v", err)
	}
	if n := strings.Count(string(coreSrc), "30 * time.Second"); n != 1 {
		t.Errorf("в core/wsasyncwriter.go %d литералов 30 * time.Second, нужен 1 "+
			"(объявление DefaultWSWriteTimeout)", n)
	}
}

package dnsproxy

// I-6 (2026-06-12): runBranchLog писал идентичную INFO-строку каждые ~313s даже
// при полном простое (~92 строки за 8h сессию). Теперь тик без изменений
// (счётчики не двигались, sweep ничего не убрал, размер кэша прежний) строку
// не эмитит; sweep при этом выполняется каждый тик.

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// recordingHandler — slog.Handler, собирающий сообщения INFO+ (захват логов
// runBranchLog; пакет пишет через slog.Default()).
type recordingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *recordingHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.msgs {
		if m == msg {
			n++
		}
	}
	return n
}

const branchLogMsg = "split-DNS branch counts"

// pollUntil поллит cond до дедлайна (без фиксированного sleep-гадания).
func pollUntil(t *testing.T, d time.Duration, cond func() bool, failMsg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(failMsg)
}

// Без трафика логируется только ПЕРВЫЙ тик (baseline); дальнейшие идентичные
// тики молчат. После запроса (счётчик ветки + размер кэша изменились) следующий
// тик снова логирует — и опять замолкает.
func TestRunBranchLog_SkipsIdenticalIdleTicks(t *testing.T) {
	old := slog.Default()
	h := &recordingHandler{}
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(old)

	y := &mockResolver{resp: answerA(t, "ya.test", "87.250.250.242")}
	c := &mockResolver{resp: answerA(t, "ya.test", "87.250.250.242")}
	f := NewForwarder("127.0.0.1:0", nil, WithResolvers(y, c))
	// Для движения branch-счётчиков нужен арбитраж — отключаем cfOnly-режим,
	// который NewForwarder включает при nil snapshot (white-box, тот же пакет).
	f.cfOnly = false
	f.match = matchSet("87.250.250.242")
	f.branchLogEvery = 20 * time.Millisecond

	if err := f.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer f.Stop()

	// Первый (baseline) тик логируется даже при простое.
	pollUntil(t, 2*time.Second, func() bool { return h.count(branchLogMsg) >= 1 },
		"первый тик branch-log не залогирован за 2s")

	// Несколько идентичных тиков подряд — новых строк быть не должно.
	time.Sleep(150 * time.Millisecond) // ~7 тиков по 20ms
	if got := h.count(branchLogMsg); got != 1 {
		t.Fatalf("идентичные idle-тики не должны логироваться: ожидалась 1 строка, получено %d", got)
	}

	// Запрос двигает yandex-счётчик (и размер кэша) → следующий тик логирует.
	f.ServeDNS(&captureWriter{}, aQuery("ya.test"))
	pollUntil(t, 2*time.Second, func() bool { return h.count(branchLogMsg) >= 2 },
		"после запроса следующий тик branch-log не залогирован за 2s")

	// И снова тишина при простое (кэш-запись живёт 60s — sweep пуст).
	time.Sleep(150 * time.Millisecond)
	if got := h.count(branchLogMsg); got != 2 {
		t.Fatalf("после повторного простоя ожидалось 2 строки, получено %d", got)
	}
}

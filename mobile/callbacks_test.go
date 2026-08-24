package mobile

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingHandler struct {
	mu     sync.Mutex
	states []string
	errs   []string
}

func (h *recordingHandler) OnStateChange(state string) {
	h.mu.Lock()
	h.states = append(h.states, state)
	h.mu.Unlock()
}

func (h *recordingHandler) OnError(msg string) {
	h.mu.Lock()
	h.errs = append(h.errs, msg)
	h.mu.Unlock()
}

func (h *recordingHandler) hasState(want string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.states {
		if s == want {
			return true
		}
	}
	return false
}

func (h *recordingHandler) errCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.errs)
}

// blockingLogger имитирует худший реальный колбэк: реализация на платформе,
// которая ушла в ожидание (взяла замок UI-потока, полезла в файл, встала на
// сетевом вызове).
type blockingLogger struct {
	release chan struct{}
	calls   atomic.Int32
}

func (b *blockingLogger) Log(_, _ string) {
	b.calls.Add(1)
	<-b.release
}

// Главное свойство контракта колбэков: зависший колбэк платформы НЕ
// останавливает горутину ядра.
//
// Цена ошибки здесь не косметическая. Log() зовётся в том числе из ридера
// слота; остановленный ридер = тишина на слоте, а тишина на слоте — это рез
// посредником (hard rule 15). То есть медленный UI ломал бы туннель.
func TestDispatcher_SlowCallbackNeverBlocksCore(t *testing.T) {
	b := &blockingLogger{release: make(chan struct{})}
	defer close(b.release)

	d := newDispatcher()
	d.setLogger(b)

	// Первое событие уводит диспетчер в зависший колбэк, следующие
	// dispatchQueue заполняют буфер, дальше начинается дроп.
	const n = dispatchQueue * 3
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			d.emit(dispatchEvent{kind: kindLog, level: "INFO", msg: "x"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emit заблокировался на зависшем колбэке — горутина ядра встала бы вместе с ним")
	}

	if d.dropped.Load() == 0 {
		t.Fatal("при переполнении очереди не зафиксировано ни одного дропа — переполнение обслужено блокировкой")
	}
}

// Паника внутри Go-обёртки колбэка не должна ронять процесс и обязана оставлять
// диспетчер живым: наблюдаемость может деградировать, туннель — нет.
type panickingHandler struct{ calls atomic.Int32 }

func (p *panickingHandler) OnStateChange(string) {
	p.calls.Add(1)
	panic("колбэк платформы упал")
}
func (p *panickingHandler) OnError(string) { p.calls.Add(1) }

func TestDispatcher_PanicInCallbackDoesNotKillDispatcher(t *testing.T) {
	p := &panickingHandler{}
	d := newDispatcher()
	d.setEvents(p)

	d.emit(dispatchEvent{kind: kindState, msg: StateConnecting})
	d.emit(dispatchEvent{kind: kindState, msg: StateConnected})

	deadline := time.Now().Add(2 * time.Second)
	for p.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := p.calls.Load(); got < 2 {
		t.Fatalf("после паники в колбэке диспетчер обработал %d событий из 2 — горутина умерла", got)
	}
}

type collectingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (c *collectingLogger) Log(level, msg string) {
	c.mu.Lock()
	c.lines = append(c.lines, level+" "+msg)
	c.mu.Unlock()
}

func (c *collectingLogger) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.lines)
}

// Фильтр по уровню обязан стоять ДО перехода границы языков. Иначе при
// -log=debug ядро оплачивает JNI-переход на каждой из тысяч строк, чтобы Java
// их отбросила.
func TestLogBridge_LevelFiltersBeforeCallback(t *testing.T) {
	prev := slog.Default()
	defer func() { slog.SetDefault(prev) }()

	c := &collectingLogger{}
	SetLogger(c)
	defer SetLogger(nil)
	SetLogLevel("error")

	slog.Info("это не должно доехать")
	slog.Debug("и это тоже")
	time.Sleep(50 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("при уровне error доставлено %d строк ниже порога", got)
	}

	slog.Error("а это должно", "k", "v")
	deadline := time.Now().Add(2 * time.Second)
	for c.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.lines) == 0 {
		t.Fatal("строка уровня error до платформы не доехала")
	}
	if want := "ERROR а это должно k=v"; c.lines[0] != want {
		t.Fatalf("строка %q, ожидалось %q", c.lines[0], want)
	}
}

// Уровень trace нужен для полевой диагностики и обязан отличаться от debug:
// прогоны идут с ним, и потеря уровня means потеря половины диагностики.
func TestLogLevel_ParsesFullCLISet(t *testing.T) {
	cases := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"мусор":   slog.LevelInfo,
		"quiet":   slog.LevelWarn,
		"warn":    slog.LevelWarn,
		"error":   slog.LevelError,
		"debug":   slog.LevelDebug,
		" TRACE ": slog.Level(-8),
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Fatalf("parseLevel(%q)=%v, ожидалось %v", in, got, want)
		}
	}
	if parseLevel("trace") >= parseLevel("debug") {
		t.Fatal("trace не ниже debug — уровень потерян")
	}
}

// SetLogger(nil) обязан снимать ссылку на объект платформы: глобальная
// JNI-ссылка на Activity переживёт саму Activity.
func TestSetLoggerNil_DropsReferenceAndSilencesBridge(t *testing.T) {
	prev := slog.Default()
	defer func() { slog.SetDefault(prev) }()

	c := &collectingLogger{}
	SetLogger(c)
	SetLogLevel("info")
	SetLogger(nil)

	slog.Info("после отключения")
	time.Sleep(50 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("после SetLogger(nil) доставлено %d строк", got)
	}
	logDisp().mu.Lock()
	l := logDisp().logger
	logDisp().mu.Unlock()
	if l != nil {
		t.Fatal("ссылка на логгер платформы осталась в диспетчере")
	}
}

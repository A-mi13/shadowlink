package mobile

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/nixavpn/shadowlink/client"
)

// Контракт колбэков — самое опасное место фасада, поэтому механизм описан здесь
// целиком.
//
// Log() и OnStateChange() зовутся из ЛЮБОЙ горутины ядра: ридеров всех восьми
// слотов, streamReaderLoop, StartStatsLogger. Прямой вызов Java-объекта оттуда
// даёт два отказа, и оба тяжёлые:
//
//  1. Необработанное Java-исключение внутри колбэка — это JNI abort, то есть
//     падение процесса, а не ошибка в Go. gobind его не ловит.
//  2. Блокировка внутри колбэка останавливает ГОРУТИНУ ЯДРА. Если она пришла из
//     ридера слота, слот перестаёт читать и писать; тишина на слоте — это рез
//     посредником (hard rule 15, консервативный порог 10 с). То есть медленный
//     UI-колбэк ломает туннель.
//
// Отсюда конструкция: между ядром и JNI стоит буферизованный канал и одна
// горутина-диспетчер. Отправка в канал НЕблокирующая — при переполнении
// событие дропается и считается. Дроп сообщений хуже, чем зависший слот,
// быть не может: сообщения — наблюдаемость, слот — продукт.
//
// Дополнительно: фильтр по уровню стоит в slog.HandlerOptions, то есть ДО
// перехода границы языков. При -log=debug ядро печатает тысячи строк в час, и
// платить JNI-переходом за каждую, чтобы Java её отбросила, нельзя.

// Logger принимает строки лога ядра. Реализуется на стороне платформы.
//
// Вызывается НЕ из UI-потока: реализация обязана сама делать
// runOnUiThread/Handler.post, если трогает View.
type Logger interface {
	Log(level, msg string)
}

// EventHandler получает изменения состояния сессии и фатальные ошибки.
// Те же требования к реализации, что и у Logger.
type EventHandler interface {
	OnStateChange(state string)
	OnError(msg string)
}

// dispatchQueue — размер буфера между ядром и колбэком.
//
// 256 выбрано как «переживает всплеск stats+keepalive, не растёт бесконтрольно».
// Точное число значения не имеет: смысл конструкции в том, что переполнение
// приводит к дропу, а не к блокировке ядра, и это свойство от размера не зависит.
const dispatchQueue = 256

type dispatchKind int

const (
	kindLog dispatchKind = iota
	kindState
	kindError
)

type dispatchEvent struct {
	kind  dispatchKind
	level string
	msg   string
}

// dispatcher — единственный мост в сторону платформы. Один на процесс для
// логов и один на сессию для событий.
type dispatcher struct {
	ch chan dispatchEvent

	mu     sync.Mutex
	logger Logger
	events EventHandler

	dropped atomic.Int64
	// delivered считает доставленные события. Нужен тестам: без него «колбэк
	// не позвали» и «колбэк позвали, но он ничего не сделал» неразличимы.
	delivered atomic.Int64
}

func newDispatcher() *dispatcher {
	d := &dispatcher{ch: make(chan dispatchEvent, dispatchQueue)}
	go d.run()
	return d
}

// run — единственная горутина, которая пересекает границу языка.
//
// Она живёт столько же, сколько владелец диспетчера. Для логгера это процесс,
// для событий — Session, а Session на мобильном одна на процесс. Останавливать
// её нечем намеренно: канал остановки понадобился бы ровно для того, чтобы
// закрыть его в момент, когда ядро ещё может писать, то есть ради паники на
// закрытом канале.
func (d *dispatcher) run() {
	for ev := range d.ch {
		d.deliver(ev)
	}
}

// deliver зовёт платформенный колбэк. Паника здесь — это паника В GO-обёртке
// (например nil-указатель внутри сгенерированной gobind прокладки); гасим её,
// потому что ронять из-за наблюдаемости туннель нельзя. Java-исключение таким
// способом НЕ ловится — оно убивает процесс через JNI abort, и защиты от него
// на стороне Go не существует, только требование к реализации не бросать.
func (d *dispatcher) deliver(ev dispatchEvent) {
	defer func() {
		if r := recover(); r != nil {
			d.dropped.Add(1)
		}
	}()

	d.mu.Lock()
	logger, events := d.logger, d.events
	d.mu.Unlock()

	switch ev.kind {
	case kindLog:
		if logger != nil {
			logger.Log(ev.level, ev.msg)
			d.delivered.Add(1)
		}
	case kindState:
		if events != nil {
			events.OnStateChange(ev.msg)
			d.delivered.Add(1)
		}
	case kindError:
		if events != nil {
			events.OnError(ev.msg)
			d.delivered.Add(1)
		}
	}
}

// emit — точка, которую зовёт ядро. Обязана возвращаться немедленно при любом
// состоянии потребителя.
func (d *dispatcher) emit(ev dispatchEvent) {
	select {
	case d.ch <- ev:
	default:
		d.dropped.Add(1)
	}
}

func (d *dispatcher) setLogger(l Logger) {
	d.mu.Lock()
	d.logger = l
	d.mu.Unlock()
}

func (d *dispatcher) setEvents(h EventHandler) {
	d.mu.Lock()
	d.events = h
	d.mu.Unlock()
}

// --- глобальный логгер ---

var (
	logOnce       sync.Once
	logDispatcher *dispatcher
	logLevelVar   = new(slog.LevelVar)
)

func logDisp() *dispatcher {
	logOnce.Do(func() { logDispatcher = newDispatcher() })
	return logDispatcher
}

// SetLogger направляет лог ядра на платформу.
//
// ГЛОБАЛЕН ПО ПРОЦЕССУ: под ним лежит slog.SetDefault, а slog — процесс-глобал.
// Уровня «на сессию» не существует, и обещать его в полях Config было бы
// описанием несуществующего механизма.
//
// SetLogger(nil) отключает мост и ОБЯЗАТЕЛЕН при завершении работы: иначе
// глобальная ссылка на Java-объект переживёт Activity и утянет за собой её
// Context — классическая утечка на Android.
func SetLogger(l Logger) {
	d := logDisp()
	d.setLogger(l)
	if l == nil {
		slog.SetDefault(slog.New(slog.NewTextHandler(discardWriter{}, nil)))
		return
	}
	slog.SetDefault(slog.New(&bridgeHandler{d: d, level: logLevelVar}))
}

// SetLogLevel задаёт порог логирования: info|quiet|warn|error|debug|trace.
// Неизвестное значение трактуется как info — тем же образом, что и в CLI
// (parseLogLevel), чтобы опечатка в настройках не глушила лог целиком.
//
// Глобален по той же причине, что и SetLogger.
func SetLogLevel(level string) {
	logLevelVar.Set(parseLevel(level))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "quiet", "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	case "debug":
		return slog.LevelDebug
	case "trace":
		return client.LevelTrace
	default:
		return slog.LevelInfo
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// bridgeHandler — slog.Handler, который вместо записи в поток кладёт запись в
// очередь диспетчера. Handle не форматирует ничего лишнего: атрибуты
// приклеиваются к сообщению как key=value, потому что на той стороне границы
// структурная запись всё равно станет строкой.
type bridgeHandler struct {
	d     *dispatcher
	level *slog.LevelVar
	attrs []slog.Attr
	group string
}

func (h *bridgeHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *bridgeHandler) Handle(_ context.Context, r slog.Record) error {
	msg := r.Message
	appendAttr := func(a slog.Attr) bool {
		msg += " " + a.Key + "=" + a.Value.String()
		return true
	}
	for _, a := range h.attrs {
		appendAttr(a)
	}
	r.Attrs(appendAttr)
	h.d.emit(dispatchEvent{kind: kindLog, level: levelName(r.Level), msg: msg})
	return nil
}

func (h *bridgeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &cp
}

func (h *bridgeHandler) WithGroup(name string) slog.Handler {
	cp := *h
	cp.group = name
	return &cp
}

func levelName(l slog.Level) string {
	switch {
	case l <= client.LevelTrace:
		return "TRACE"
	case l < slog.LevelInfo:
		return "DEBUG"
	case l < slog.LevelWarn:
		return "INFO"
	case l < slog.LevelError:
		return "WARN"
	default:
		return "ERROR"
	}
}

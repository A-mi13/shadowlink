package slotobs

import (
	"sync"
	"time"
)

// Адаптивный порог ротации (P0 шаг 3, 2026-07-31).
//
// Шаг 1 наблюдает, шаг 2 выводит, шаг 3 — ПРИМЕНЯЕТ. Разделение сохранено, потому
// что применение несёт риски, которых нет у наблюдения: порог, дёргающийся на
// каждой смене сети, хуже статичной константы.
//
// Что решает: зашитые 75 s против выведенных 66–71 s по трём полевым выборкам.
// Остаточный разрыв — worst-case teardown 90 s при самой ранней наблюдённой
// смерти 82.9 s. Никакая правка константы его не закрывает: у другого
// провайдера окно другое (ACM IMC 2022 — ТСПУ неоднородна по регионам).
//
// Ключевые свойства, каждое от конкретного риска:
//
//   - НИКОГДА не расширяет порог выше сконфигурированного. Адаптация только
//     сжимает. Ошибка вывода в сторону «можно дольше» стоила бы попадания под
//     рез; в сторону «надо короче» — лишь чуть более частой ротации.
//   - Гистерезис: сжимает быстро, отпускает медленно и малыми шагами. Без него
//     порог колеблется на смене Wi-Fi/LTE, и каждая осцилляция — это всплеск
//     новых соединений на origin IP, то есть предполагаемый корм host-profiling.
//     ⚠ Источник НЕ найден (сверка 2026-08-07): ссылка «FOCI 2026» вела к работе
//     «Geedge Cases» — она про утечку Geedge Networks, а не про детектирование
//     по числу соединений; в списке FOCI 2026 такой работы нет. Довод держится
//     на здравом смысле, а не на публикации, и замером пока не проверен.
//   - Пол (floor): не опускается ниже minAdaptiveAge, иначе ротация станет
//     чаще, чем нужно, и counting-детектор получит ровно тот сигнал, от
//     которого мы уходим.
//   - Требует подтверждения: порог меняется только если вывод устойчив
//     confirmations раз подряд. Одна выборка — не причина менять поведение.
type Adapter struct {
	// configured — порог из конфигурации (SHADOWLINK_MAX_SLOT_AGE). Потолок:
	// адаптация никогда не поднимает порог выше него.
	configured time.Duration

	mu sync.Mutex
	// current — действующий порог. Равен configured, пока вывод не подтверждён.
	current time.Duration
	// pendingTarget / pendingCount — кандидат и сколько раз подряд он подтвердился.
	pendingTarget time.Duration
	pendingCount  int
	// changes — сколько раз порог фактически менялся (наблюдаемость).
	changes int
	// lastReason — почему current именно такой. Пустая строка = не адаптировался.
	lastReason string
}

const (
	// minAdaptiveAge — пол адаптации. Ниже этого ротация учащается настолько,
	// что число соединений на origin IP само становится сигналом: при 8 слотах
	// 30 s дают ~960 conn/час против ~384 при 75 s.
	minAdaptiveAge = 30 * time.Second

	// adaptConfirmations — сколько подряд одинаковых выводов нужно, чтобы
	// сдвинуть порог. Защита от разовой аномалии: одна плохая выборка (смена
	// сети, кратковременный сбой оператора) не должна менять поведение.
	adaptConfirmations = 3

	// releaseStep — максимальный шаг РАСШИРЕНИЯ порога за одно изменение.
	// Сжатие происходит сразу и целиком (риск асимметричен: под резом лучше
	// оказаться раньше), расширение — по чуть-чуть, чтобы не проскочить обратно
	// в окно реза, если сеть только показалась спокойной.
	releaseStep = 5 * time.Second

	// quantum — округление порога вниз. Без него порог дрожал бы на единицах
	// миллисекунд от выборки к выборке, а каждое изменение — это событие,
	// которое надо логировать и объяснять.
	quantum = time.Second
)

// NewAdapter создаёт адаптер с заданным потолком. configured <= 0 означает
// «ротация по возрасту выключена» — тогда адаптер тоже ничего не делает.
func NewAdapter(configured time.Duration) *Adapter {
	return &Adapter{configured: configured, current: configured}
}

// Threshold возвращает действующий порог ротации. Безопасен для nil-приёмника,
// чтобы вызывающий не был обязан проверять (пул может быть собран без адаптера).
func (a *Adapter) Threshold() time.Duration {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current
}

// Stats возвращает состояние адаптера для логов/метрик.
//
// Наблюдаемость — обязательное требование, а не удобство: адаптивный контур, про
// который нельзя сказать, работает ли он и почему, повторил бы H-15
// (BackpressureCheck, который «защищал» и не срабатывал никогда).
func (a *Adapter) Stats() (current, configured time.Duration, changes int, reason string) {
	if a == nil {
		return 0, 0, 0, "adapter disabled"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastReason == "" {
		return a.current, a.configured, a.changes, "не адаптировался (нет подтверждённого вывода)"
	}
	return a.current, a.configured, a.changes, a.lastReason
}

// Observe скармливает адаптеру свежий вывод инференса и возвращает true, если
// действующий порог изменился.
//
// Вызывать периодически (например, из stats-логгера). Идемпотентен по смыслу:
// повторный вызов с тем же вердиктом лишь наращивает счётчик подтверждений.
func (a *Adapter) Observe(v Verdict) bool {
	if a == nil || a.configured <= 0 {
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Ось не выведена или это не возраст — держим текущее поведение.
	// Байтовая ось к порогу ПО ВОЗРАСТУ отношения не имеет: применять её здесь
	// значило бы подставить величину не той размерности.
	if v.Axis != AxisAge || v.Threshold.Age <= 0 {
		a.pendingTarget, a.pendingCount = 0, 0
		return false
	}

	target := v.Threshold.Age.Truncate(quantum)

	// Потолок: адаптация только сжимает. Вывод «можно дольше» игнорируем —
	// цена ошибки в эту сторону несопоставимо выше.
	if target > a.configured {
		target = a.configured
	}
	// Пол: ниже minAdaptiveAge частота ротации сама становится сигналом.
	if target < minAdaptiveAge {
		target = minAdaptiveAge
	}

	if target == a.current {
		a.pendingTarget, a.pendingCount = 0, 0
		return false
	}

	// Накапливаем подтверждения для КОНКРЕТНОГО кандидата.
	if target != a.pendingTarget {
		a.pendingTarget, a.pendingCount = target, 1
		return false
	}
	a.pendingCount++
	if a.pendingCount < adaptConfirmations {
		return false
	}

	prev := a.current
	if target < a.current {
		// Сжатие — сразу и целиком.
		a.current = target
	} else {
		// Расширение — малым шагом, не перескакивая цель.
		a.current += releaseStep
		if a.current > target {
			a.current = target
		}
	}
	a.pendingTarget, a.pendingCount = 0, 0
	a.changes++
	a.lastReason = v.Reason
	return a.current != prev
}

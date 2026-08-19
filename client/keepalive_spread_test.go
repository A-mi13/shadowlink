package client

import (
	"testing"
	"time"
)

// Разнесение keepalive по слотам.
//
// Проблема: nextKeepaliveDelay джиттерует МОМЕНТ пробуждения (log-normal,
// base 5 с) — это хорошо и уже защищено. Но sendKeepaliveToAllSlots проходит по
// всем слотам в одном цикле без задержек, поэтому на wire уходит синхронный
// burst из 8 фреймов к одному origin в пределах миллисекунд. Для наблюдателя,
// считающего соединения, «8 TLS-сессий оживают одновременно» — это шаблон,
// который джиттер периода не устраняет: он двигает burst целиком.
//
// Инвариант, который правка НЕ должна нарушить (Bug #9): максимальное время
// молчания слота ограничено, иначе сервер/посредник сочтёт соединение мёртвым.
// Разнос обязан быть заметно меньше самого интервала keepalive.

// TestKeepaliveSpread_BoundedByInterval — разнос не должен приближаться к
// периоду keepalive, иначе он съест запас по молчанию слота.
func TestKeepaliveSpread_BoundedByInterval(t *testing.T) {
	// keepaliveSpreadMax — верхняя граница разноса по всем слотам.
	// Сравниваем с МИНИМАЛЬНЫМ возможным интервалом keepalive: log-normal
	// сэмплер усечён снизу (см. JitteredIntervalLogNormal), и разнос обязан
	// оставаться много меньше даже самого короткого окна.
	minInterval := keepaliveDefaultBase / 2 // sanity floor сэмплера
	if keepaliveSpreadMax >= minInterval/2 {
		t.Fatalf("keepaliveSpreadMax = %v слишком велик против минимального "+
			"интервала keepalive %v: разнос съедает запас по молчанию слота",
			keepaliveSpreadMax, minInterval)
	}
}

// Задержка для слота обязана лежать в [0, keepaliveSpreadMax) и НЕ быть
// детерминированной функцией индекса: idx*step — это лестница, то есть тот же
// шаблон, только растянутый (ровно этим болел Connect fan-out).
func TestKeepaliveSlotDelay_InRangeAndNotALadder(t *testing.T) {
	const slots = 8
	const samples = 200

	seen := make([]map[time.Duration]int, slots)
	for i := range seen {
		seen[i] = make(map[time.Duration]int)
	}

	for s := 0; s < samples; s++ {
		for idx := 0; idx < slots; idx++ {
			d := keepaliveSlotDelay(idx)
			if d < 0 || d >= keepaliveSpreadMax {
				t.Fatalf("slot %d: задержка %v вне [0, %v)", idx, d, keepaliveSpreadMax)
			}
			seen[idx][d]++
		}
	}

	// Каждый индекс обязан давать РАЗНЫЕ значения между вызовами: одно
	// значение на индекс означало бы детерминированную лестницу.
	for idx := 0; idx < slots; idx++ {
		if len(seen[idx]) < samples/10 {
			t.Errorf("slot %d: всего %d различных задержек на %d вызовов — "+
				"похоже на детерминированную функцию индекса, а не на джиттер",
				idx, len(seen[idx]), samples)
		}
	}
}

// Слот 0 не должен быть привилегированным: если для idx==0 задержка всегда 0,
// то первый слот остаётся якорем burst'а и шаблон «8 оживают вместе» частично
// сохраняется — наблюдателю достаточно самого раннего кадра.
func TestKeepaliveSlotDelay_ZeroIndexIsJitteredToo(t *testing.T) {
	var nonZero int
	for i := 0; i < 200; i++ {
		if keepaliveSlotDelay(0) > 0 {
			nonZero++
		}
	}
	if nonZero == 0 {
		t.Error("slot 0 всегда получает задержку 0 — он остаётся якорем burst'а")
	}
}

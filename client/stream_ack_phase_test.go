package client

import (
	"math"
	"sync"
	"testing"
	"time"
)

// Фаза StreamAck: гейт «не чаще раза в T от последней отправки» — не тикер, но
// при непрерывном насыщении он даёт интервалы РОВНО T, то есть
// самосинхронизирующуюся линию с фазой, привязанной к началу насыщения.
//
// Почему это отдельный класс от credit-sender'а: там был явный time.NewTicker,
// здесь периодичность возникает из логики троттлинга. Ack — тоже реальные байты
// к origin (FlagStreamAck через тот же control-канал, что WINDOW_UPDATE), и
// вызывается по приходу данных (proxy/socks5/tcp.go, onFlush).
//
// ⚠ Замером по логу это НЕ снималось: моменты SendStreamAck в лог не пишутся.
// Поэтому проверка здесь — на seam'е streamAckSendForTest.

// TestStreamAck_ThrottleGridUnderSaturation документирует наличие или
// отсутствие линии 20 Гц при насыщении.
//
// Тест не падает на факте линии сам по себе — он измеряет и логирует, а падает,
// если линия ЖЁСТКАЯ (R >= 0.5): такую видно на wire, и это повод лечить, а не
// фиксировать. Порог выше, чем 0.2 для фазы ротации, намеренно: у гейта по
// событию фаза частично задаётся приходом данных, поэтому умеренный R ожидаем.
func TestStreamAck_ThrottleGridUnderSaturation(t *testing.T) {
	if testing.Short() {
		t.Skip("замер требует ~1.2 с реального времени")
	}

	c := &Client{}
	start := time.Now()

	var mu sync.Mutex
	var sends []float64
	c.streamAckSendForTest = func(streamID uint16, ackedDownSeq uint64) bool {
		elapsed := time.Since(start).Seconds()
		mu.Lock()
		sends = append(sends, elapsed)
		mu.Unlock()
		return true
	}

	// Непрерывное насыщение: зовём чаще, чем окно троттла, — так же, как это
	// делает onFlush при полной загрузке downlink. Гейт пропустит примерно
	// каждый T-й вызов, и вопрос лишь в том, ложатся ли пропуски на сетку.
	stop := time.After(1200 * time.Millisecond)
	feed := time.NewTicker(2 * time.Millisecond)
	defer feed.Stop()
	var seq uint64
loop:
	for {
		select {
		case <-feed.C:
			seq++
			c.sendStreamAckThrottled(nil, 7, seq, false)
		case <-stop:
			break loop
		}
	}

	mu.Lock()
	got := append([]float64(nil), sends...)
	mu.Unlock()

	if len(got) < 10 {
		t.Fatalf("отправок %d — гейт не пропускал, замер невозможен", len(got))
	}

	const window = 0.050
	r := vectorStrengthPhase(got, window)
	noise := 1 / math.Sqrt(float64(len(got)))

	var minD, maxD, sumD = math.MaxFloat64, 0.0, 0.0
	for i := 1; i < len(got); i++ {
		d := got[i] - got[i-1]
		minD = math.Min(minD, d)
		maxD = math.Max(maxD, d)
		sumD += d
	}
	meanD := sumD / float64(len(got)-1)

	t.Logf("n=%d R@%.3fs=%.4f шум=%.4f; интервалы min=%.4f mean=%.4f max=%.4f",
		len(got), window, r, noise, minD, meanD, maxD)

	if r >= 0.5 {
		t.Errorf("жёсткая линия 20 Гц на ack: R = %.4f при n=%d (шум %.4f). "+
			"Гейт по метке последней отправки при насыщении даёт интервалы ровно "+
			"%.0f мс — лечится джиттером окна, как у credit-sender", r, len(got), noise, window*1000)
	}
}

// Джиттер окна не должен ломать САМ троттлинг: подряд идущие вызовы обязаны
// коалесцироваться, иначе вместо одной линии получим поток мелких фреймов —
// это хуже решётки (DPI-гигиена, см. комментарий streamAckThrottleInterval).
func TestStreamAck_ThrottleStillCoalesces(t *testing.T) {
	c := &Client{}
	var n int
	c.streamAckSendForTest = func(uint16, uint64) bool { n++; return true }

	// Первый вызов проходит всегда (нет предыдущей метки), последующие в
	// пределах окна обязаны коалесцироваться.
	for i := 0; i < 50; i++ {
		c.sendStreamAckThrottled(nil, 3, uint64(i), false)
	}
	if n != 1 {
		t.Fatalf("отправок %d, ожидалась 1: троттлинг не коалесцирует burst", n)
	}

	// forced обязан проходить мимо гейта — на нём держится освобождение
	// resend-хвоста сервера после MIGRATE_OK.
	c.sendStreamAckThrottled(nil, 3, 99, true)
	if n != 2 {
		t.Fatalf("отправок %d, ожидалось 2: forced не прошёл сквозь гейт", n)
	}
}

// Окно обязано истекать: после сдвига метки в прошлое следующий вызов проходит.
// Сторож на случай, если джиттер окна будет реализован так, что окно
// перестанет истекать вовсе.
func TestStreamAck_WindowExpires(t *testing.T) {
	c := &Client{}
	var n int
	c.streamAckSendForTest = func(uint16, uint64) bool { n++; return true }

	c.sendStreamAckThrottled(nil, 5, 1, false)
	if n != 1 {
		t.Fatalf("первый ack не прошёл (n=%d)", n)
	}
	c.sendStreamAckThrottled(nil, 5, 2, false)
	if n != 1 {
		t.Fatalf("второй ack прошёл внутри окна (n=%d)", n)
	}

	// Сдвигаем метку заведомо дальше любого разумного джиттерованного окна.
	c.forceStreamAckClockForTest(5, time.Now().Add(-time.Second))
	c.sendStreamAckThrottled(nil, 5, 3, false)
	if n != 2 {
		t.Fatalf("ack не прошёл после истечения окна (n=%d)", n)
	}
}

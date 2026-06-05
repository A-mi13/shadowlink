package socks5

import (
	"io"
	"testing"
	"time"
)

// halfCloseWrite is a test helper: tun2socks calls appConn.CloseWrite() via an
// interface assertion (the conn is typed net.Conn). Mirror that here.
func halfCloseWrite(t *testing.T, c interface{ CloseWrite() error }) {
	t.Helper()
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
}

// TestMemConn_HalfCloseKeepsDownlinkAlive reproduces the Bug #8 field symptom:
// after tun2socks does appConn.CloseWrite() (TCP half-close — the app finished
// sending its HTTP request), the relay MUST still be able to write the download
// response into the downlink direction. The field log shows the opposite: an
// active 13.7 MB download (connectConfirmed=true, fullClose=false) gets
// "io: read/write on closed pipe" on the relay's downlink conn.Write right
// after the uplink goroutine saw EOF (half-close).
//
// memConn pairing (newMemPipe):
//   appConn (a): rd=d2, wr=d1   — handed to tun2socks
//   ourConn (b): rd=d1, wr=d2   — the relay (tunnelTCPStream conn)
// Uplink   = app→server = d1 (appConn.Write / ourConn.Read)
// Downlink = server→app = d2 (ourConn.Write / appConn.Read)
func TestMemConn_HalfCloseKeepsDownlinkAlive(t *testing.T) {
	appConn, ourConn := newMemPipe()

	// tun2socks half-close after the app sent its request: it calls
	// appConn.CloseWrite() on the uplink direction.
	if hc, ok := appConn.(interface{ CloseWrite() error }); ok {
		if err := hc.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	} else {
		t.Fatal("appConn missing CloseWrite")
	}

	// The relay's uplink goroutine reads ourConn until EOF (uplink direction d1
	// now closed) — this is the expected half-close signal.
	buf := make([]byte, 64)
	if _, err := ourConn.Read(buf); err != io.EOF {
		t.Fatalf("ourConn.Read after appConn.CloseWrite: got %v, want io.EOF", err)
	}

	// CRITICAL: the relay must STILL be able to write downlink (server→app).
	// This is what tunnelTCPStream's downlink goroutine does on every chunk.
	if _, err := ourConn.Write([]byte("downlink response chunk")); err != nil {
		t.Fatalf("downlink ourConn.Write after half-close FAILED: %v "+
			"(this is the Bug #8 'closed pipe' — half-close killed downlink)", err)
	}

	// And the app must be able to read it.
	n, err := appConn.Read(buf)
	if err != nil {
		t.Fatalf("appConn.Read downlink after half-close: %v", err)
	}
	if string(buf[:n]) != "downlink response chunk" {
		t.Fatalf("downlink payload mismatch: %q", buf[:n])
	}
}

// TestMemConn_CloseReadKillsDownlink documents what happens if tun2socks calls
// appConn.CloseRead() (which it does on the downlink goroutine's exit):
// appConn.rd = d2 = the downlink direction. Closing it makes the relay's
// ourConn.Write(d2) return ErrClosedPipe. This test pins that behavior so the
// fix (and its rationale) is explicit.
func TestMemConn_CloseReadKillsDownlink(t *testing.T) {
	appConn, ourConn := newMemPipe()

	if hc, ok := appConn.(interface{ CloseRead() error }); ok {
		if err := hc.CloseRead(); err != nil {
			t.Fatalf("CloseRead: %v", err)
		}
	} else {
		t.Fatal("appConn missing CloseRead")
	}

	// After appConn.CloseRead(), the relay writing downlink hits a closed pipe.
	_, err := ourConn.Write([]byte("downlink"))
	if err == nil {
		t.Fatal("expected downlink write to fail after appConn.CloseRead (d2 closed)")
	}
	t.Logf("downlink write after appConn.CloseRead → %v (expected: closed pipe)", err)
}

// Bug 2026-06-02: после half-close (CloseWrite от tun2socks) read-deadline на
// downlink-стороне app-end ДОЛЖЕН игнорироваться — long-poll downlink молчит
// легитимно, пока модель «думает». Иначе tun2socks 60s tcpWaitTimeout рвёт стрим.
func TestMemConn_HalfClose_IgnoresPriorReadDeadline(t *testing.T) {
	app, _ := newMemPipe() // app-end отдаётся tun2socks; relay-end здесь не нужен

	// Эмулируем tun2socks unidirectionalStream после upload-EOF:
	//   68: appConn.CloseWrite()   (uplink полу-закрыт)
	// Дедлайн взведён ДО CloseWrite — проверяем, что CloseWrite его нейтрализует.
	_ = app.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	halfCloseWrite(t, app.(interface{ CloseWrite() error }))

	// downlink молчит дольше дедлайна.
	done := make(chan error, 1)
	go func() {
		b := make([]byte, 16)
		_, err := app.Read(b) // должен БЛОКИРОВАТЬСЯ, не таймаутить
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("Read вернулся раньше времени (immune не сработал): err=%v", err)
	case <-time.After(200 * time.Millisecond):
		// Ожидаемо: Read всё ещё блокируется через 200ms (дедлайн был 50ms).
	}
}

// Точный порядок tun2socks unidirectionalStream: CloseWrite() (tcp.go:68) ТОГДА
// SetReadDeadline(now+60s) (tcp.go:72). Дедлайн, поставленный ПОСЛЕ CloseWrite,
// должен быть проигнорирован (иначе строка 72 возвращает 60s-таймер обратно).
func TestMemConn_HalfClose_IgnoresLaterReadDeadline(t *testing.T) {
	app, _ := newMemPipe()

	halfCloseWrite(t, app.(interface{ CloseWrite() error }))            // tcp.go:68
	_ = app.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) // tcp.go:72 — no-op

	done := make(chan error, 1)
	go func() {
		b := make([]byte, 16)
		_, err := app.Read(b)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("Read вернулся раньше времени (later-deadline no-op не сработал): err=%v", err)
	case <-time.After(200 * time.Millisecond):
		// Ожидаемо: дедлайн проигнорирован, Read блокируется.
	}
}

// immune НЕ должен мешать настоящему full close: после CloseWrite()+Close()
// app.Read обязан немедленно вернуть EOF (real FIN от приложения).
func TestMemConn_HalfClose_FullCloseStillTearsDown(t *testing.T) {
	app, _ := newMemPipe()

	halfCloseWrite(t, app.(interface{ CloseWrite() error }))
	_ = app.SetReadDeadline(time.Now().Add(time.Hour)) // no-op в immune
	_ = app.Close()                                    // full close → rd.close()

	done := make(chan error, 1)
	go func() {
		b := make([]byte, 16)
		_, err := app.Read(b)
		done <- err
	}()

	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("ожидался io.EOF после full Close, получено: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read завис после full Close — immune ошибочно блокирует teardown")
	}
}

// Без CloseWrite (соединение не полу-закрыто) read-deadline должен работать
// штатно — мы не сломали обычный таймаут для не-half-closed соединений.
func TestMemConn_NoHalfClose_ReadDeadlineStillFires(t *testing.T) {
	app, _ := newMemPipe()

	_ = app.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	b := make([]byte, 16)
	start := time.Now()
	_, err := app.Read(b)
	elapsed := time.Since(start)

	netErr, ok := err.(interface{ Timeout() bool })
	if !ok || !netErr.Timeout() {
		t.Fatalf("ожидался timeout error, получено: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("дедлайн не сработал вовремя: elapsed=%v", elapsed)
	}
}

// relay-end (isAppEnd==false) НЕ участвует в immune-логике: его read-deadline
// работает штатно. immune-флаг привязан к isAppEnd, поэтому relay-end SetReadDeadline
// должен таймаутить как обычно. (Здесь НЕ делаем CloseWrite на app: это закрыло бы
// d1 = направление, которое relay читает, и relay.Read вернул бы EOF, а не timeout —
// отдельная корректная семантика, не относящаяся к immune.)
func TestMemConn_RelayEnd_ReadDeadlineUnaffected(t *testing.T) {
	_, relay := newMemPipe()

	_ = relay.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	b := make([]byte, 16)
	_, err := relay.Read(b)

	netErr, ok := err.(interface{ Timeout() bool })
	if !ok || !netErr.Timeout() {
		t.Fatalf("relay-end read-deadline должен срабатывать, получено: %v", err)
	}
}

// immune блокирует только TIMEOUT, не доставку: после CloseWrite relay пишет
// downlink-данные, app.Read обязан их получить (long-poll ответ доходит).
func TestMemConn_HalfClose_DownlinkDataStillDelivered(t *testing.T) {
	app, relay := newMemPipe()
	halfCloseWrite(t, app.(interface{ CloseWrite() error }))
	_ = app.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) // no-op

	want := []byte("hello-from-server")
	go func() {
		time.Sleep(150 * time.Millisecond) // дольше «дедлайна» — данные приходят после
		_, _ = relay.Write(want)
	}()

	b := make([]byte, len(want))
	got, err := app.Read(b)
	if err != nil {
		t.Fatalf("Read вернул ошибку вместо данных: %v", err)
	}
	if string(b[:got]) != string(want) {
		t.Fatalf("downlink данные искажены: got=%q want=%q", b[:got], want)
	}
}

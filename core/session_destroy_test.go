package core

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// H-11 (раунд 18): Destroy() обязан выводить сессию из строя, а не только
// занулять ключи.
//
// Прежнее поведение: ZeroBytes зануляет байты НА МЕСТЕ, не меняя длину, поэтому
// после Destroy() SendKey — это 32 нулевых байта, а не nil. aes.NewCipher(32
// нуля) успешно создаёт шифр, значит EncryptChunk уходил в fallback-ветку и
// шифровал полезную нагрузку под ПУБЛИЧНО ИЗВЕСТНЫМ нулевым ключом. Симметрично
// DecryptChunkSafe ПРИНИМАЛ кадры, зашифрованные нулевым ключом — destroyed
// сессия становилась приёмником для любого, кто знает, что она уничтожена.
//
// Комментарий client/ws_transport.go утверждал «empty key → AES-GCM init fails →
// soft-fail by contract» — ложная предпосылка: ключ не пустой, init не падает.
//
// Эти тесты падают при откате фикса.

func newTestKeys() ([]byte, []byte) {
	return bytes.Repeat([]byte{0xAB}, 32), bytes.Repeat([]byte{0xCD}, 32)
}

func TestDestroy_EncryptFailsClosed(t *testing.T) {
	sk, rk := newTestKeys()
	s := NewSession(1, sk, rk)

	// Базовая линия: до Destroy шифрование работает.
	if _, err := s.EncryptChunk(NewStreamDataChunk(1, 1, 1, []byte("ok"))); err != nil {
		t.Fatalf("до Destroy шифрование должно работать: %v", err)
	}

	s.Destroy()

	out, err := s.EncryptChunk(NewStreamDataChunk(1, 2, 1, []byte("secret-payload")))
	if err == nil {
		t.Fatalf("EncryptChunk после Destroy() вернул %d байт вместо ошибки — "+
			"полезная нагрузка зашифрована под all-zero ключом", len(out))
	}
	if !errors.Is(err, ErrSessionDestroyed) {
		t.Errorf("ожидалась ErrSessionDestroyed, получено: %v", err)
	}
}

func TestDestroy_DecryptFailsClosed(t *testing.T) {
	sk, rk := newTestKeys()
	s := NewSession(2, sk, rk)

	// Кадр, который злоумышленник шифрует нулевым ключом.
	zeroKey := make([]byte, 32)
	peer := NewSession(3, zeroKey, zeroKey)
	evilCT, err := peer.EncryptChunk(NewStreamDataChunk(3, 1, 1, []byte("attacker-frame")))
	if err != nil {
		t.Fatalf("подготовка кадра: %v", err)
	}

	s.Destroy()

	got, err := s.DecryptChunkSafe(evilCT)
	if err == nil {
		t.Fatalf("destroyed-сессия ПРИНЯЛА кадр под нулевым ключом: payload=%q", got.Payload)
	}
	if !errors.Is(err, ErrSessionDestroyed) {
		t.Errorf("ожидалась ErrSessionDestroyed, получено: %v", err)
	}
}

// Идемпотентность: повторный Destroy не должен паниковать.
func TestDestroy_Idempotent(t *testing.T) {
	sk, rk := newTestKeys()
	s := NewSession(4, sk, rk)
	s.Destroy()
	s.Destroy()
	s.Destroy()
	if !s.IsDestroyed() {
		t.Error("IsDestroyed() = false после Destroy()")
	}
}

// InitSendEpoch на destroyed-сессии не должен воскрешать её.
func TestDestroy_InitSendEpochAfterDestroy(t *testing.T) {
	sk, rk := newTestKeys()
	s := NewSession(5, sk, rk)
	s.Destroy()

	if err := s.InitSendEpoch(); err == nil {
		t.Error("InitSendEpoch() после Destroy() должен возвращать ошибку")
	}
	if _, err := s.EncryptChunk(NewStreamDataChunk(5, 1, 1, []byte("x"))); err == nil {
		t.Error("EncryptChunk после Destroy+InitSendEpoch должен падать")
	}
}

// Rekey на destroyed-сессии не должен воскрешать её.
func TestDestroy_RekeyAfterDestroy(t *testing.T) {
	sk, rk := newTestKeys()
	s := NewSession(6, sk, rk)
	s.Destroy()

	newSend := bytes.Repeat([]byte{0x11}, 32)
	newRecv := bytes.Repeat([]byte{0x22}, 32)
	if err := s.Rekey(newSend, newRecv); err == nil {
		t.Error("Rekey() после Destroy() должен возвращать ошибку, иначе сессия воскресает")
	}
	if _, err := s.EncryptChunk(NewStreamDataChunk(6, 1, 1, []byte("x"))); err == nil {
		t.Error("EncryptChunk после Destroy+Rekey должен падать")
	}
}

// Все четыре пути зануления ключей обязаны выводить сессию из строя,
// а не только Destroy(): исторически блок ZeroBytes был скопирован
// четыре раза, и фикс только в Destroy() оставил бы три дыры.
func TestDestroy_ExpirySweepAlsoDisables(t *testing.T) {
	sk, rk := newTestKeys()
	s := NewSession(7, sk, rk)

	// isExpiredAndDestroy — путь Cleanup().
	s.mu.Lock()
	s.lastActivity = time.Now().Add(-time.Hour)
	s.mu.Unlock()

	if !s.isExpiredAndDestroy(time.Minute) {
		t.Fatal("сессия должна была истечь")
	}
	if !s.IsDestroyed() {
		t.Error("isExpiredAndDestroy обнулил ключи, но не вывел сессию из строя")
	}
	if _, err := s.EncryptChunk(NewStreamDataChunk(7, 1, 1, []byte("x"))); err == nil {
		t.Error("EncryptChunk после expiry-sweep должен падать")
	}
}

func TestDestroy_NewbornOrphanSweepDisables(t *testing.T) {
	sm := NewSessionManager(time.Minute)
	sk, rk := newTestKeys()
	s := NewSession(8, sk, rk)
	s.CreatedAt = time.Now().Add(-time.Hour) // никогда не аттачился
	sm.mu.Lock()
	sm.sessions[8] = s
	sm.mu.Unlock()

	evicted := sm.CleanupNewbornOrphans(time.Now(), time.Minute)
	if len(evicted) != 1 {
		t.Fatalf("ожидалось вытеснение 1 сессии, получено %d", len(evicted))
	}
	if !s.IsDestroyed() {
		t.Error("newborn-orphan sweep обнулил ключи, но не вывел сессию из строя")
	}
}

// Конкурентный доступ: отложенный Destroy() через 5с в client/client.go:1461
// пересекается с живыми in-flight SOCKS5-хендлерами. Гонки быть не должно,
// а результат должен быть однозначным: либо успех, либо ErrSessionDestroyed.
func TestDestroy_ConcurrentWithEncrypt(t *testing.T) {
	sk, rk := newTestKeys()
	s := NewSession(9, sk, rk)
	if err := s.InitSendEpoch(); err != nil {
		t.Fatalf("InitSendEpoch: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, err := s.EncryptChunk(NewStreamDataChunk(9, 1, 1, []byte("payload")))
				if err != nil && !errors.Is(err, ErrSessionDestroyed) {
					t.Errorf("неожиданная ошибка: %v", err)
					return
				}
			}
		}()
	}

	time.Sleep(10 * time.Millisecond)
	s.Destroy()
	time.Sleep(10 * time.Millisecond)
	close(stop)
	wg.Wait()

	// После Destroy все последующие попытки обязаны падать.
	if _, err := s.EncryptChunk(NewStreamDataChunk(9, 1, 1, []byte("x"))); !errors.Is(err, ErrSessionDestroyed) {
		t.Errorf("после Destroy ожидалась ErrSessionDestroyed, получено %v", err)
	}
}

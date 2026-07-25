package core

import (
	"math/rand"
	"testing"
)

// Раунд 18 / CRITICAL-1: sliding-window anti-replay.
//
// shiftBitmap сдвигал историю в сторону МЛАДШИХ битов (`>>=`), тогда как
// соглашение setBit/getBit — «бит diff = seq на diff позиций старше highest»,
// то есть при продвижении окна вперёд история обязана уезжать в СТАРШИЕ биты.
// Из-за инверсии история стиралась, и повторы принимались.
//
// Тесты ниже падают при откате фикса — это их назначение. Прежний
// TestSessionSlidingWindowEdge закреплял баг (принимал seq=0 дважды) и был
// переписан в TestSlidingWindowEdge_ReplayAtEdgeRejected.

// Монотонный приём с последующим полным реплеем: ни один повтор не должен пройти.
func TestSlidingWindow_MonotonicThenReplayAllRejected(t *testing.T) {
	// n < WindowSize (16384), поэтому вся история остаётся в окне и каждый
	// повтор обязан быть отклонён. 200 > 64 — задействуются обе ветки сдвига.
	const n = 200
	s := NewSession(1, make([]byte, 32), make([]byte, 32))

	for seq := uint32(1); seq <= n; seq++ {
		if !s.AcceptSeqNum(seq) {
			t.Fatalf("первичный приём seq=%d отклонён", seq)
		}
	}

	for seq := uint32(1); seq <= n; seq++ {
		if s.AcceptSeqNum(seq) {
			t.Errorf("реплей принят: seq=%d (highest=%d)", seq, n)
		}
	}
}

// Точная механика сдвига на один: после accept(k+1) бит для k должен уехать
// с позиции 0 на позицию 1, а не исчезнуть.
func TestSlidingWindow_ShiftPreservesHistory(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))

	s.AcceptSeqNum(5)
	if !s.getBit(0) {
		t.Fatal("после accept(5) бит diff=0 должен стоять")
	}

	s.AcceptSeqNum(6)
	if !s.getBit(0) {
		t.Error("после accept(6) бит для seq=6 (diff=0) должен стоять")
	}
	if !s.getBit(1) {
		t.Error("после accept(6) бит для seq=5 (diff=1) потерян — история не сдвинулась")
	}
}

// Реплей ровно на краю окна: seq=0 после продвижения на WindowSize-1 всё ещё
// внутри окна, значит повтор обязан быть отклонён. Это переписанный
// TestSessionSlidingWindowEdge — прежняя версия утверждала обратное.
func TestSlidingWindowEdge_ReplayAtEdgeRejected(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))

	if !s.AcceptSeqNum(0) {
		t.Fatal("accept(0) должен пройти")
	}
	if !s.AcceptSeqNum(WindowSize - 1) {
		t.Fatal("accept(WindowSize-1) должен пройти")
	}
	if s.AcceptSeqNum(0) {
		t.Error("реплей seq=0 принят: diff=WindowSize-1 всё ещё внутри окна")
	}
}

// Дыры в нумерации: пропущенные seq должны приниматься при доставке
// с опозданием, но только один раз.
func TestSlidingWindow_OutOfOrderAcceptedOnceEach(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))

	if !s.AcceptSeqNum(10) {
		t.Fatal("accept(10) должен пройти")
	}
	for _, seq := range []uint32{3, 7, 9} {
		if !s.AcceptSeqNum(seq) {
			t.Errorf("опоздавший seq=%d отклонён, хотя внутри окна", seq)
		}
		if s.AcceptSeqNum(seq) {
			t.Errorf("повтор опоздавшего seq=%d принят", seq)
		}
	}
}

// Сдвиг на кратное 64 задействует только пословное копирование, на
// некратное — обе ветки. Проверяем оба класса.
func TestSlidingWindow_WordAlignedAndUnalignedShifts(t *testing.T) {
	for _, jump := range []uint32{1, 63, 64, 65, 127, 128, WindowSize - 1} {
		t.Run("", func(t *testing.T) {
			s := NewSession(1, make([]byte, 32), make([]byte, 32))
			if !s.AcceptSeqNum(0) {
				t.Fatal("accept(0)")
			}
			if !s.AcceptSeqNum(jump) {
				t.Fatalf("accept(%d)", jump)
			}
			// seq=0 теперь на позиции diff=jump. Внутри окна → повтор отклоняется.
			if jump < WindowSize && s.AcceptSeqNum(0) {
				t.Errorf("jump=%d: реплей seq=0 принят (diff=%d < WindowSize)", jump, jump)
			}
		})
	}
}

// Property-тест: случайная перестановка не даёт принять ни один seq дважды.
func TestSlidingWindow_PropertyNoDoubleAccept(t *testing.T) {
	rng := rand.New(rand.NewSource(20260725))

	for iter := 0; iter < 200; iter++ {
		s := NewSession(1, make([]byte, 32), make([]byte, 32))
		const span = 300
		perm := rng.Perm(span)

		accepted := make(map[int]bool, span)
		for _, v := range perm {
			seq := uint32(v)
			if s.AcceptSeqNum(seq) {
				if accepted[v] {
					t.Fatalf("iter=%d: seq=%d принят повторно", iter, seq)
				}
				accepted[v] = true
			}
		}
		// Повторный прогон той же перестановки: всё уже виденное — реплей.
		for _, v := range perm {
			if s.AcceptSeqNum(uint32(v)) && accepted[v] {
				t.Fatalf("iter=%d: seq=%d принят во втором прогоне", iter, v)
			}
		}
	}
}

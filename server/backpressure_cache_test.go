package server

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// H-15 (раунд 18), часть «цена»: runtime.ReadMemStats — stop-the-world, и он
// вызывался на КАЖДОМ handshake (handler.go:646), до всей криптографии, без
// кэша. Замер: ~10.8 мкс на вызов. Дешёвый мусорный POST давал гарантированную
// STW-паузу, тормозящую все горутины включая активные relay'и — функция,
// задуманная как защита от перегрузки, сама её усиливала.
//
// ВАЖНО про часть «условие недостижимо»: это утверждение находки **опровергнуто
// замером**. Аудит рассуждал «Alloc < Sys всегда, отношение 0.3–0.6, значит
// ветки high/crit не срабатывают». Арифметика верна, вывод — нет: когда heap
// доминирует в Sys, отношение стремится к 1. Под давлением 512 MiB замер дал
// max(Alloc/Sys) = **0.983**, то есть выше обоих порогов (0.8 / 0.9). Ветки
// достижимы, просто порог плавающий. Поэтому пороговая логика НЕ переписывалась
// — исправлена только цена вызова.

func TestBackpressure_ReadMemStatsIsCached(t *testing.T) {
	m := NewMetrics()

	var calls atomic.Int64
	m.memStatsFn = func(ms *runtime.MemStats) {
		calls.Add(1)
		ms.Alloc = 100 << 20
		ms.Sys = 1000 << 20
	}

	const iterations = 500
	for i := 0; i < iterations; i++ {
		m.BackpressureCheck(8)
	}

	got := calls.Load()
	t.Logf("%d вызовов BackpressureCheck → %d чтений memstats", iterations, got)
	if got >= int64(iterations) {
		t.Errorf("memstats прочитан %d раз на %d вызовов — кэша нет, STW на каждом handshake",
			got, iterations)
	}
	// Один-два чтения в пределах TTL — норма.
	if got == 0 {
		t.Error("memstats не прочитан ни разу — состояние не обновляется вообще")
	}
}

// Кэш обязан истекать: после TTL значение перечитывается.
func TestBackpressure_CacheExpires(t *testing.T) {
	m := NewMetrics()

	var calls atomic.Int64
	m.memStatsFn = func(ms *runtime.MemStats) {
		calls.Add(1)
		ms.Alloc = 100 << 20
		ms.Sys = 1000 << 20
	}

	m.BackpressureCheck(8)
	first := calls.Load()

	// Сдвигаем метку кэша в прошлое, имитируя истечение TTL.
	m.memStatsAt.Store(time.Now().Add(-2 * backpressureCacheTTL).UnixNano())

	m.BackpressureCheck(8)
	if calls.Load() <= first {
		t.Error("после истечения TTL memstats должен перечитываться")
	}
}

// Пороговая логика не должна пострадать от кэширования.
func TestBackpressure_ThresholdsStillWork(t *testing.T) {
	cases := []struct {
		name       string
		alloc, sys uint64
		wantReject bool
	}{
		{"здоровый heap", 100 << 20, 1000 << 20, false},
		{"выше high (0.8)", 850 << 20, 1000 << 20, false},
		{"выше crit (0.9)", 950 << 20, 1000 << 20, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := NewMetrics()
			m.memStatsFn = func(ms *runtime.MemStats) {
				ms.Alloc = c.alloc
				ms.Sys = c.sys
			}
			_, reject := m.BackpressureCheck(8)
			if reject != c.wantReject {
				t.Errorf("Alloc=%d Sys=%d → reject=%v, ожидалось %v",
					c.alloc, c.sys, reject, c.wantReject)
			}
		})
	}
}

// Конкурентный доступ: кэш не должен порождать гонку.
func TestBackpressure_ConcurrentSafe(t *testing.T) {
	m := NewMetrics()
	m.memStatsFn = func(ms *runtime.MemStats) {
		ms.Alloc = 100 << 20
		ms.Sys = 1000 << 20
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				m.BackpressureCheck(8)
			}
		}()
	}
	wg.Wait()
}

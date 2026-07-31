package slotobs

import (
	"fmt"
	"sync"
	"testing"
)

func TestRecorder_RingBounded(t *testing.T) {
	r := NewRecorder(8)
	for i := 0; i < 100; i++ {
		r.Record(Observation{AgeMs: int64(i)})
	}
	if got := r.Len(); got != 8 {
		t.Errorf("Len()=%d, ожидалось 8 (граница кольца)", got)
	}
	if got := r.Total(); got != 100 {
		t.Errorf("Total()=%d, ожидалось 100", got)
	}
}

// Snapshot обязан отдавать наблюдения от старых к новым — иначе перцентили
// считаются по неверному порядку при обёрнутом кольце.
func TestRecorder_SnapshotOldestFirst(t *testing.T) {
	r := NewRecorder(4)
	for i := 1; i <= 6; i++ { // 1..6 в кольцо на 4 → останутся 3,4,5,6
		r.Record(Observation{AgeMs: int64(i)})
	}
	snap := r.Snapshot()
	if len(snap) != 4 {
		t.Fatalf("len(snapshot)=%d, ожидалось 4", len(snap))
	}
	want := []int64{3, 4, 5, 6}
	for i, w := range want {
		if snap[i].AgeMs != w {
			t.Errorf("snapshot[%d].AgeMs=%d, ожидалось %d (порядок нарушен)",
				i, snap[i].AgeMs, w)
		}
	}
}

func TestRecorder_SnapshotBeforeWrap(t *testing.T) {
	r := NewRecorder(10)
	for i := 1; i <= 3; i++ {
		r.Record(Observation{AgeMs: int64(i)})
	}
	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("len=%d, ожидалось 3", len(snap))
	}
	if snap[0].AgeMs != 1 || snap[2].AgeMs != 3 {
		t.Errorf("порядок до обёртывания нарушен: %v", snap)
	}
}

func TestRecorder_EmptySummary(t *testing.T) {
	r := NewRecorder(4)
	s := r.Summarize()
	if s.Count != 0 {
		t.Errorf("Count=%d на пустом рекордере", s.Count)
	}
	if r.Snapshot() != nil {
		t.Error("Snapshot() на пустом рекордере должен быть nil")
	}
}

// ГЛАВНЫЙ тест пакета: CV должен различать две конкурирующие гипотезы.
//
// Если цензор режет по ВОЗРАСТУ, то возраст смерти кластеризуется у порога, а
// объём разбросан (зависит от того, сколько успели скачать). И наоборот.
// Именно на этом различении строится шаг 2 (вывод оси), поэтому метрика обязана
// работать до того, как на неё что-то опирается.
func TestSummarize_DistinguishesAgeCutFromVolumeCut(t *testing.T) {
	t.Run("рез по возрасту", func(t *testing.T) {
		r := NewRecorder(64)
		// Возраст жёстко около 130с, объём гуляет на два порядка.
		ages := []int64{129_000, 130_500, 131_000, 129_800, 130_200, 130_900}
		vols := []int64{2 << 10, 900 << 10, 40 << 10, 5 << 20, 18 << 10, 300 << 10}
		for i := range ages {
			r.Record(Observation{AgeMs: ages[i], DownBytes: vols[i], CloseKind: "close_other"})
		}
		s := r.Summarize()
		t.Logf("AgeCV=%.4f BytesCV=%.4f", s.AgeCV, s.BytesCV)
		if s.AgeCV >= s.BytesCV {
			t.Errorf("при резе по возрасту AgeCV (%.4f) должен быть МЕНЬШЕ BytesCV (%.4f)",
				s.AgeCV, s.BytesCV)
		}
	})

	t.Run("рез по объёму", func(t *testing.T) {
		r := NewRecorder(64)
		// Объём жёстко около 18 КБ, возраст гуляет.
		vols := []int64{17_800, 18_200, 18_050, 17_950, 18_100, 18_000}
		ages := []int64{4_000, 210_000, 35_000, 900_000, 12_000, 78_000}
		for i := range vols {
			r.Record(Observation{AgeMs: ages[i], DownBytes: vols[i], CloseKind: "reset"})
		}
		s := r.Summarize()
		t.Logf("AgeCV=%.4f BytesCV=%.4f", s.AgeCV, s.BytesCV)
		if s.BytesCV >= s.AgeCV {
			t.Errorf("при резе по объёму BytesCV (%.4f) должен быть МЕНЬШЕ AgeCV (%.4f)",
				s.BytesCV, s.AgeCV)
		}
	})
}

func TestSummarize_Percentiles(t *testing.T) {
	r := NewRecorder(16)
	// 10 значений 10..100 мс, объём 100..1000.
	for i := 1; i <= 10; i++ {
		r.Record(Observation{AgeMs: int64(i * 10), DownBytes: int64(i * 100)})
	}
	s := r.Summarize()
	if s.Count != 10 {
		t.Fatalf("Count=%d", s.Count)
	}
	// nearest-rank: p50 при n=10 → индекс 50*9/100 = 4 → пятое значение (50).
	if s.AgeP50 != 50 {
		t.Errorf("AgeP50=%d, ожидалось 50", s.AgeP50)
	}
	if s.AgeP10 > s.AgeP50 || s.AgeP50 > s.AgeP90 {
		t.Errorf("перцентили не монотонны: p10=%d p50=%d p90=%d",
			s.AgeP10, s.AgeP50, s.AgeP90)
	}
	if s.BytesP10 > s.BytesP50 || s.BytesP50 > s.BytesP90 {
		t.Errorf("байтовые перцентили не монотонны: %d/%d/%d",
			s.BytesP10, s.BytesP50, s.BytesP90)
	}
}

func TestSummarize_SingleObservation(t *testing.T) {
	r := NewRecorder(4)
	r.Record(Observation{AgeMs: 42, DownBytes: 4242, CloseKind: "io_timeout"})
	s := r.Summarize()
	if s.Count != 1 || s.AgeP10 != 42 || s.AgeP90 != 42 {
		t.Errorf("одно наблюдение: Count=%d p10=%d p90=%d", s.Count, s.AgeP10, s.AgeP90)
	}
	// CV на одном образце неопределён → 0, а не NaN.
	if s.AgeCV != 0 || s.BytesCV != 0 {
		t.Errorf("CV на одном образце должен быть 0, получено %f/%f", s.AgeCV, s.BytesCV)
	}
}

func TestSummarize_ByCloseKind(t *testing.T) {
	r := NewRecorder(32)
	for i := 0; i < 5; i++ {
		r.Record(Observation{CloseKind: "close_other"})
	}
	for i := 0; i < 3; i++ {
		r.Record(Observation{CloseKind: "reset"})
	}
	r.Record(Observation{CloseKind: "io_timeout"})

	s := r.Summarize()
	if s.ByCloseKind["close_other"] != 5 {
		t.Errorf("close_other=%d, ожидалось 5", s.ByCloseKind["close_other"])
	}
	if s.ByCloseKind["reset"] != 3 {
		t.Errorf("reset=%d, ожидалось 3", s.ByCloseKind["reset"])
	}
	if s.ByCloseKind["io_timeout"] != 1 {
		t.Errorf("io_timeout=%d, ожидалось 1", s.ByCloseKind["io_timeout"])
	}
}

// Нулевые значения не должны давать NaN/Inf — иначе они утекут в метрики.
func TestSummarize_ZeroValuesNoNaN(t *testing.T) {
	r := NewRecorder(8)
	for i := 0; i < 4; i++ {
		r.Record(Observation{AgeMs: 0, DownBytes: 0})
	}
	s := r.Summarize()
	if s.AgeCV != 0 || s.BytesCV != 0 {
		t.Errorf("нулевые данные должны давать CV=0, получено %f/%f", s.AgeCV, s.BytesCV)
	}
}

func TestRecorder_Reset(t *testing.T) {
	r := NewRecorder(4)
	r.Record(Observation{AgeMs: 1})
	r.Reset()
	if r.Len() != 0 || r.Total() != 0 || r.Snapshot() != nil {
		t.Error("Reset не очистил рекордер")
	}
}

// Каждый слот умирает на своей горутине, поэтому Record вызывается конкурентно.
func TestRecorder_ConcurrentRecord(t *testing.T) {
	r := NewRecorder(128)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				r.Record(Observation{
					AgeMs:     int64(g*1000 + i),
					CloseKind: fmt.Sprintf("kind%d", g%3),
				})
			}
		}(g)
	}
	// Читаем параллельно с записью — snapshot обязан быть консистентным.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = r.Summarize()
		}
	}()
	wg.Wait()

	if got := r.Total(); got != 1600 {
		t.Errorf("Total()=%d, ожидалось 1600", got)
	}
	if got := r.Len(); got != 128 {
		t.Errorf("Len()=%d, ожидалось 128", got)
	}
}

func TestNewRecorder_DefaultCapacity(t *testing.T) {
	for _, c := range []int{0, -1} {
		r := NewRecorder(c)
		for i := 0; i < DefaultCapacity+10; i++ {
			r.Record(Observation{})
		}
		if got := r.Len(); got != DefaultCapacity {
			t.Errorf("NewRecorder(%d): Len()=%d, ожидался DefaultCapacity=%d",
				c, got, DefaultCapacity)
		}
	}
}

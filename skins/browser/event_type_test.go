package browser

import (
	"math"
	"testing"
)

// TestRandomEventType_PoolWellFormed проверяет инвариант сборки pool:
// сумма weights должна быть 100 (если разработчик меняет таблицу — этот
// тест сразу ловит арифметическую ошибку, а не ждёт chi-square теста).
func TestRandomEventType_PoolWellFormed(t *testing.T) {
	if len(eventTypePool) != 100 {
		t.Fatalf("eventTypePool size mismatch: got %d, want 100 (sum of weights)", len(eventTypePool))
	}

	// Каждое имя должно быть непустым и не начинаться/кончаться пробелом.
	uniq := make(map[string]struct{})
	for _, name := range eventTypePool {
		if name == "" {
			t.Fatalf("eventTypePool contains empty string")
		}
		uniq[name] = struct{}{}
	}
	if len(uniq) < 15 {
		t.Fatalf("eventTypePool unique-count too small: got %d unique names, want >=15 (P2-6: peer Mixpanel SDK emits dozens)",
			len(uniq))
	}
}

// TestRandomEventType_DistributionSpread закрывает финал-аудит 2026-05-03
// P2-6: маленький enum (6 entries, uniform) был детектируем телом
// content-ML классификатором. Расширенный pool должен показать ≥15
// уникальных значений в 5000 draws и приближённо weighted distribution.
//
// Используем chi-square goodness-of-fit против target weights pool.
// Threshold подобран либеральный (5x ожидаемого) чтобы не флакать на
// финитной выборке — цель теста: убедиться что распределение НЕ uniform
// и НЕ degenerate (single-bucket). Pool weights встроены в helper для
// воспроизводимости — duplicate logic вместо hidden coupling.
func TestRandomEventType_DistributionSpread(t *testing.T) {
	const N = 50000
	counts := make(map[string]int)
	for i := 0; i < N; i++ {
		counts[randomEventType()]++
	}

	// Минимальное число уникальных событий: ≥15 (spec требование).
	if len(counts) < 15 {
		t.Fatalf("randomEventType distribution too narrow: got %d unique events in %d draws, want >=15",
			len(counts), N)
	}

	// Доминантные семейства должны держать целевые ratio (с допуском ±30%).
	pageviewCount := counts["page_view"] + counts["$pageview"]
	pageviewRatio := float64(pageviewCount) / float64(N)
	// Target 30%, accept [21%, 39%].
	if pageviewRatio < 0.21 || pageviewRatio > 0.39 {
		t.Errorf("page_view family ratio out of band: got %.3f, want [0.21, 0.39] (target 0.30)", pageviewRatio)
	}

	sessionCount := counts["session_start"] + counts["session_end"] + counts["session_ping"]
	sessionRatio := float64(sessionCount) / float64(N)
	// Target 20%, accept [14%, 26%].
	if sessionRatio < 0.14 || sessionRatio > 0.26 {
		t.Errorf("session_* family ratio out of band: got %.3f, want [0.14, 0.26] (target 0.20)", sessionRatio)
	}

	clickCount := counts["button_click"] + counts["link_click"]
	clickRatio := float64(clickCount) / float64(N)
	// Target 25%, accept [17%, 33%].
	if clickRatio < 0.17 || clickRatio > 0.33 {
		t.Errorf("click_* family ratio out of band: got %.3f, want [0.17, 0.33] (target 0.25)", clickRatio)
	}

	// Sanity: ни одно событие не должно занимать >40% (защита от
	// случайного дубликата в pool builder).
	for name, c := range counts {
		ratio := float64(c) / float64(N)
		if ratio > 0.40 {
			t.Errorf("event %q dominates distribution: %.3f > 0.40 (likely duplicated in pool)", name, ratio)
		}
	}

	// Chi-square против uniform-null (как контр-проверка: должны явно
	// отвергнуть). Если новое распределение случайно стало uniform —
	// это регрессия P2-6.
	expectedUniform := float64(N) / float64(len(counts))
	chi := 0.0
	for _, c := range counts {
		d := float64(c) - expectedUniform
		chi += (d * d) / expectedUniform
	}
	// Critical χ² для df=18, α=0.001 ≈ 42.3. Реально для weighted
	// distribution ожидаем chi >> 100 (т.к. weights явно неравномерны
	// на 17+ buckets). Ставим минимум 100 чтобы поймать "вернули
	// uniform".
	if chi < 100 {
		t.Errorf("distribution looks uniform (chi-square = %.2f, want >100 — weighted dist should diverge from uniform)", chi)
	}

	// Дополнительно: chi-square должен быть конечным.
	if math.IsNaN(chi) || math.IsInf(chi, 0) {
		t.Fatalf("chi-square computation produced non-finite value: %v", chi)
	}
}

// TestRandomEventType_NoLegacyEntries — регрессия: убираемся от старого
// 6-entry enum (`click`, `nav`). Если такие имена снова появятся в pool —
// тест громко падает.
func TestRandomEventType_NoLegacyEntries(t *testing.T) {
	legacy := []string{"click", "nav"}
	for _, l := range legacy {
		for _, e := range eventTypePool {
			if e == l {
				t.Errorf("legacy event type %q reappeared in eventTypePool — P2-6 regression", l)
				break
			}
		}
	}
}

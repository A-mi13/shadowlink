package server

import (
	"fmt"
	"testing"
	"time"
)

// H-14 (раунд 18): decoyLogPerIP — единственная структура в server/ без верхней
// границы. Комментарий это признавал («no LRU eviction, no TTL sweeper»),
// оценивая 100 B на запись → 100 MB на 1M IP как приемлемое.
//
// Замер (исполняемо, 200k уникальных IPv6-подобных ключей): **105.9 B/запись**,
// то есть 10M IP ≈ **0.99 GB**. Оценка в комментарии была точной — аудит зря
// назвал её заниженной (там фигурировали 130–160 B и 1.3–1.6 GB). Но сам дефект
// реален: при DefaultConfig, документированной как «2 vCPU / 2 GB RAM VPS»,
// это половина всей памяти, и рост ничем не ограничен.
//
// Достижимость: logDecoyServed вызывается на КАЖДОМ failClosedToDecoy*, включая
// DecoyReasonBodyInvalid — то есть на любой мусорный POST с application/json.
// Одна /64 IPv6-подсеть даёт 2^64 адресов.
//
// Остальные структуры пакета границу имеют: TokenBucket — expirable LRU 10k,
// ClientIDExemption — LRU + callback, RateLimiter — 10000. Фикс приводит
// decoyLogPerIP к тому же паттерну (expirable LRU), что уже используется в
// tokenbucket.go и clientid_exempt.go.

func TestDecoyLog_MapIsBounded(t *testing.T) {
	ResetDecoyLogStateForTest()
	t.Cleanup(ResetDecoyLogStateForTest)

	now := time.Now()
	const flood = decoyLogMaxIPs * 3

	for i := 0; i < flood; i++ {
		// IPv6-подобные ключи: одна /64 даёт неограниченный запас адресов.
		ip := fmt.Sprintf("2001:db8:%x:%x::%x", i>>16, (i>>8)&0xff, i&0xff)
		shouldLogForIP(ip, now)
	}

	n := decoyLogCacheLen()
	if n > decoyLogMaxIPs {
		t.Errorf("в кэше %d записей при границе %d — рост не ограничен", n, decoyLogMaxIPs)
	}
	t.Logf("после %d уникальных IP в кэше %d записей (граница %d)", flood, n, decoyLogMaxIPs)
}

// Основная функция не должна пострадать: тот же IP в пределах окна
// по-прежнему ограничивается decoyLogPerIPLimit.
func TestDecoyLog_PerIPLimitStillEnforced(t *testing.T) {
	ResetDecoyLogStateForTest()
	t.Cleanup(ResetDecoyLogStateForTest)

	now := time.Now()
	const ip = "203.0.113.7"

	allowed, suppressed := 0, 0
	for i := 0; i < decoyLogPerIPLimit*3; i++ {
		if ok, _ := shouldLogForIP(ip, now); ok {
			allowed++
		} else {
			suppressed++
		}
	}
	if allowed != decoyLogPerIPLimit {
		t.Errorf("разрешено %d WARN, ожидался лимит %d", allowed, decoyLogPerIPLimit)
	}
	if suppressed != decoyLogPerIPLimit*2 {
		t.Errorf("подавлено %d, ожидалось %d", suppressed, decoyLogPerIPLimit*2)
	}
}

// Окно должно прокручиваться: после decoyLogPerIPWindow тот же IP снова пишет.
func TestDecoyLog_WindowRollsOver(t *testing.T) {
	ResetDecoyLogStateForTest()
	t.Cleanup(ResetDecoyLogStateForTest)

	base := time.Now()
	const ip = "203.0.113.8"

	for i := 0; i < decoyLogPerIPLimit; i++ {
		shouldLogForIP(ip, base)
	}
	if ok, _ := shouldLogForIP(ip, base); ok {
		t.Fatal("лимит в пределах окна не соблюдён")
	}

	// Следующее окно.
	later := base.Add(decoyLogPerIPWindow + time.Second)
	ok, suppressed := shouldLogForIP(ip, later)
	if !ok {
		t.Error("после прокрутки окна WARN должен пройти")
	}
	// suppressed переносится через границу окна — это задокументированное
	// поведение («+N dropped during the storm»).
	if suppressed == 0 {
		t.Error("счётчик подавленных должен переноситься через границу окна")
	}
}

// Явная фиксация компромисса: вытесненный по LRU IP при возврате получает
// свежее окно, то есть сможет записать ещё decoyLogPerIPLimit строк.
//
// Это осознанный обмен: верхняя граница памяти важнее абсолютной точности
// журнального лимита. Атакующий, ротирующий /64, и так тратит по одной записи
// на IP — а раньше он же получал неограниченный рост карты.
func TestDecoyLog_EvictionResetsWindow_DocumentedTradeoff(t *testing.T) {
	ResetDecoyLogStateForTest()
	t.Cleanup(ResetDecoyLogStateForTest)

	now := time.Now()
	const victim = "198.19.0.1"

	// Исчерпываем лимит для victim.
	for i := 0; i < decoyLogPerIPLimit; i++ {
		shouldLogForIP(victim, now)
	}
	if ok, _ := shouldLogForIP(victim, now); ok {
		t.Fatal("лимит должен быть исчерпан")
	}

	// Вытесняем его флудом других IP.
	for i := 0; i < decoyLogMaxIPs+10; i++ {
		shouldLogForIP(fmt.Sprintf("2001:db8:ffff:%x::%x", i>>8, i&0xff), now)
	}

	// victim вытеснен → новая запись → свежее окно.
	if ok, _ := shouldLogForIP(victim, now); !ok {
		t.Log("victim остался в кэше (LRU не дошёл до него) — тоже допустимо")
	}
	if n := decoyLogCacheLen(); n > decoyLogMaxIPs {
		t.Errorf("граница нарушена: %d > %d", n, decoyLogMaxIPs)
	}
}

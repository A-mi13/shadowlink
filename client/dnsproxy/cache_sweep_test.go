package dnsproxy

// DNS-M3 (2026-06-12): кэш ограничен по числу записей (maxCacheEntries) с
// eviction'ом при переполнении (просроченные выселяются первыми) и периодическим
// sweep'ом просроченных записей, подвешенным на тикер runBranchLog.

import (
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func keyFor(name string) cacheKey {
	return cacheKey{name: dns.Fqdn(name), qtype: dns.TypeA}
}

// Кэш никогда не превышает maxCacheEntries; свежая запись после переполнения
// доступна (eviction освобождает место, а не отбрасывает новую запись).
func TestCache_BoundedSize(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)

	for i := 0; i < maxCacheEntries+10; i++ {
		name := "host" + strconv.Itoa(i) + ".example"
		c.put(keyFor(name), makeMsg(name, 3600))
		if got := c.size(); got > maxCacheEntries {
			t.Fatalf("размер кэша превысил лимит после put #%d: %d > %d", i, got, maxCacheEntries)
		}
	}
	if got := c.size(); got != maxCacheEntries {
		t.Fatalf("ожидался размер ровно %d, получено %d", maxCacheEntries, got)
	}

	// Последняя положенная запись должна быть достижима.
	lastName := "host" + strconv.Itoa(maxCacheEntries+9) + ".example"
	if _, ok := c.get(keyFor(lastName)); !ok {
		t.Fatal("свежеположенная запись должна быть в кэше после eviction'а")
	}
}

// Повторный put существующего ключа не должен триггерить eviction
// (перезапись на месте, размер не растёт).
func TestCache_RewriteExistingKeyNoEviction(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)

	for i := 0; i < maxCacheEntries; i++ {
		name := "host" + strconv.Itoa(i) + ".example"
		c.put(keyFor(name), makeMsg(name, 3600))
	}
	// Перезапись существующего ключа при полном кэше.
	c.put(keyFor("host0.example"), makeMsg("host0.example", 3600))
	if got := c.size(); got != maxCacheEntries {
		t.Fatalf("перезапись не должна менять размер: ожидалось %d, получено %d", maxCacheEntries, got)
	}
	// Все записи на месте (ничего не выселено) — спот-чек пары ключей.
	if _, ok := c.get(keyFor("host0.example")); !ok {
		t.Fatal("перезаписанный ключ должен остаться в кэше")
	}
	if _, ok := c.get(keyFor("host1.example")); !ok {
		t.Fatal("сосед перезаписанного ключа не должен быть выселен")
	}
}

// При переполнении eviction предпочитает просроченную запись живой.
func TestCache_EvictionPrefersExpired(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)

	// Одна запись с нулевым lifetime — просрочена сразу же.
	c.putWithLifetime(keyFor("expired.example"), makeMsg("expired.example", 60), 0)
	// Остальные — живые на час.
	for i := 0; i < maxCacheEntries-1; i++ {
		name := "live" + strconv.Itoa(i) + ".example"
		c.put(keyFor(name), makeMsg(name, 3600))
	}
	if got := c.size(); got != maxCacheEntries {
		t.Fatalf("преднастройка: ожидался полный кэш %d, получено %d", maxCacheEntries, got)
	}

	// Новый put при полном кэше → выселяется именно просроченная.
	c.put(keyFor("new.example"), makeMsg("new.example", 3600))

	if got := c.size(); got != maxCacheEntries {
		t.Fatalf("после eviction размер должен остаться %d, получено %d", maxCacheEntries, got)
	}
	if _, ok := c.get(keyFor("new.example")); !ok {
		t.Fatal("новая запись должна быть в кэше")
	}
	// Просроченная должна быть выселена (get вернул бы miss и так, поэтому
	// проверяем размер + наличие живых: ни одна живая не пострадала).
	if _, ok := c.get(keyFor("live0.example")); !ok {
		t.Fatal("живая запись не должна быть выселена при наличии просроченной")
	}
	if _, ok := c.get(keyFor("live" + strconv.Itoa(maxCacheEntries-2) + ".example")); !ok {
		t.Fatal("живая запись (хвост) не должна быть выселена при наличии просроченной")
	}
}

// sweep удаляет только просроченные записи и возвращает их количество.
func TestCache_Sweep(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)

	// 3 короткоживущие (clamp → 30s) + 2 долгоживущие (1h).
	for i := 0; i < 3; i++ {
		name := "short" + strconv.Itoa(i) + ".example"
		c.put(keyFor(name), makeMsg(name, 5))
	}
	for i := 0; i < 2; i++ {
		name := "long" + strconv.Itoa(i) + ".example"
		c.put(keyFor(name), makeMsg(name, 3600))
	}

	clk.advance(31 * time.Second) // короткие просрочены, длинные живы

	removed, remaining := c.sweep()
	if removed != 3 {
		t.Fatalf("sweep должен удалить 3 просроченные записи, удалил %d", removed)
	}
	if remaining != 2 {
		t.Fatalf("после sweep ожидалось 2 живые записи, получено %d", remaining)
	}
	if _, ok := c.get(keyFor("long0.example")); !ok {
		t.Fatal("живая запись не должна удаляться sweep'ом")
	}
	if _, ok := c.get(keyFor("short0.example")); ok {
		t.Fatal("просроченная запись должна быть удалена sweep'ом")
	}

	// Повторный sweep — ничего не удаляет.
	if removed, _ := c.sweep(); removed != 0 {
		t.Fatalf("повторный sweep не должен ничего удалять, удалил %d", removed)
	}
}

// Тикер branch-log горутины вызывает sweep кэша (seam: укороченный интервал
// вместо ожидания 313s; без фиксированного sleep — поллинг с дедлайном).
func TestForwarder_BranchLogTick_SweepsCache(t *testing.T) {
	f := NewForwarder("127.0.0.1:0", nil,
		WithResolvers(&mockResolver{}, &mockResolver{}))
	f.branchLogEvery = 5 * time.Millisecond

	// Просроченная сразу запись (lifetime=0): sweep обязан её удалить.
	f.cache.putWithLifetime(keyFor("stale.example"), makeMsg("stale.example", 60), 0)
	if got := f.cache.size(); got != 1 {
		t.Fatalf("преднастройка: ожидалась 1 запись, получено %d", got)
	}

	if err := f.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer f.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.cache.size() == 0 {
			return // sweep сработал по тику
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("тикер branch-log не вызвал sweep за 2s: размер кэша %d", f.cache.size())
}

# Impl C2 — IPv6 leak в bypass-роутинге (зеркало Bug #7 для IPv6)

Дата: 2026-06-11. Находка: **C2** (`docs/audit/2026-06-11/agent5-socks5-leakguard.md`).
Метод: TDD (тест → RED → импл → GREEN). Файлы изолированы в `client/bypassroute/`.

## Проблема
`route()` для `!addr.Is4()` безусловно возвращал `routeTunnel` — весь IPv6-reserved
(loopback, link-local, multicast, ULA, IPv6 cloud-metadata) уходил в туннель → серверные
CONNECT_FAIL и аналог Bug #7 (port exhaustion) на IPv6. `isReservedIPv4`/`isUnreachableReserved`
для IPv6 возвращали `false`.

## Что реализовано

### Классы IPv6 (зеркало IPv4 drop/direct)
**DROP** (unreachable-by-design — сокет НЕ открывается, возвращается `errDropUnreachable`):
- `::1/128` — loopback
- `::/128` — unspecified
- `fe80::/10` — link-local (SLAAC/mDNS-источники)
- `ff00::/8` — multicast (включая `ff02::fb` mDNS)
- `fd00:ec2::254/128` — AWS IMDS IPv6 metadata (per-VM-local, недостижим на не-cloud хосте)

**DIRECT** (reachable LAN — через `proxy.NewDirect()`, мимо туннеля):
- `fc00::/7` — ULA (v6-аналог RFC1918)

**TUNNEL**: любой публичный/нераспознанный IPv6 (GUA `2001:db8::1`, CF `2606:4700::1111` и т.д.).

### Изменения в коде
- `client/bypassroute/reserved.go`: добавлен `reservedRangesV6` (6 префиксов, drop/direct),
  ленивая сборка `buildReservedV6` (sync.Once) в два слайса `netip.Prefix`
  (`reservedPrefixesV6` + `unreachablePfxV6`). Новые функции `isReservedIPv6` /
  `isUnreachableReservedIPv6` (через `netip.Prefix.Contains`, т.к. существующий `Trie`
  IPv4-only). Drop-подмножество проверяется ОТДЕЛЬНО — гарантирует, что metadata `/128`
  (внутри ULA `/7`) классифицируется как DROP независимо от порядка списка.
- `client/bypassroute/dialer.go`: в `route()` ветка `!addr.Is4()` теперь применяет
  drop/direct/tunnel вместо безусловного tunnel. Fail-safe сохранён: невалидный/нераспознанный
  IPv6 → routeTunnel (не leak).
- `client/bypassroute/dialer_ipv6_test.go` (новый): 7 тестов — drop/direct/tunnel по TCP и UDP,
  nil-Resolved guarantee, unit-покрытие классификаторов.

## Статус сборки/проверок
- `go test ./client/bypassroute/...` — **PASS** (все, включая 7 новых IPv6-тестов и
  преэкзистентные IPv4 Bug#7-тесты).
- `go build ./client/bypassroute/...` — **OK**.
- `go vet ./client/bypassroute/...` — **CLEAN**.
- `gofmt -l` по трём моим файлам — **чисто** (применён gofmt; в dialer.go reflow
  существующего numbered-list комментария в doc `route()`, без изменения логики).
- `go build ./...` (весь модуль) — падает в `server/handler.go` + `server/websocket.go`
  (`udpRelay.Send` сигнатура) — это **преэкзистентная незавершённая работа Блока A**
  (UDP-relay изоляция), НЕ связано с C2. Мои файлы в `client/bypassroute/` к server-пакету
  отношения не имеют.
- `go test -race` НЕ запускался: на Windows требует cgo/gcc (известное ограничение проекта,
  race гоняется на Linux/CI). Новый код read-only после init (sync.Once) — гонок не вносит.

## Риски / отклонения
1. **IPv6 не имеет DIRECT-пути за пределами ULA.** Админ-override / RIPE-RU trie — IPv4-only
   (`Trie` хранит 4-байтовые ключи, v6 молча пропускает). Поэтому публичный IPv6 всегда
   TUNNEL, без bypass для .ru по v6. Это намеренно (fail-safe в сторону туннеля, не leak);
   bypass .ru по IPv6 — отдельная задача, если понадобится.
2. **`fec0::/10` (site-local, deprecated RFC 3879) НЕ добавлен** — устаревший диапазон,
   на практике не встречается; если всплывёт в логах, добавить как DROP.
3. **gofmt тронул doc-комментарий `route()`** (reflow numbered list под новые правила gofmt),
   т.к. редактирование файла активировало проверку всего файла. Логика не менялась — только
   отступ маркеров списка в комментарии.

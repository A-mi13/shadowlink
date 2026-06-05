# Half-open зависание стрима при graceful age-cut drain — design

**Date:** 2026-06-04 (v2 — переработана после опус-ревью v1: 2 BLOCKER / 3 HIGH)
**Status:** DESIGN v2 — pending opus-review → plan
**Класс:** клиентский фикс (migrate_watchdog scheduling + proxy/socks5/tcp.go relay). Сервер НЕ меняется.

## Симптом (воспроизведён устойчиво, диаг-сборка)

Через ShadowLink ответ приложения (Claude Code в терминале, claude.ai, любой HTTP keep-alive) **зависает: спиннер крутится, токены/данные не растут, ответ обрывается**. Без протокола — стабильно. Полевой лог: `nixavpn-DEBUG-20260604-122130.log`.

## Корневая причина (доказана с трёх сторон: клиент + сервер pl1 + воспроизведение)

**ДВОЙНОЙ корень.** Это НЕ Bug #10 (origin жив, 0 broken pipe на сервере в окне зависания).

### Корень (A) — превентивная миграция планируется ОДНОКРАТНЫМ snapshot'ом; поздние стримы не покрыты

**ВАЖНО (исправление v1, BLOCKER-1):** превентивная миграция стримов со стареющего слота УЖЕ СУЩЕСТВУЕТ — `scheduleSlotMigration` (migrate_watchdog.go), вызывается из watchdog-sweep (ws_pool.go:1809-1814) при пересечении `migrationThresholdNs` (~60s, до age-drain ~120s). Постановка v1 «миграции в drain нет» была **фактически неверна**. Реальный корень тоньше:

`scheduleSlotMigration` устроена так (migrate_watchdog.go:176-211):
1. CAS `slot.migrationScheduled false→true` — **один раз за жизнь слота** (per-slot гейт).
2. `streamMap.Range` — **snapshot активных стримов В ЭТОТ МОМЕНТ** (~60s), каждому планирует `time.AfterFunc(offset, migrateStream)`.
3. Если стримов 0 — флаг сбрасывается (re-arm для случая «стримы привяжутся позже»). Но если был ≥1 стрим → флаг остаётся `true` НАВСЕГДА для этого слота.

**Дыра:** стрим, который сделал CONNECT на стареющий слот **ПОСЛЕ** того как `scheduleSlotMigration` отработала (флаг уже `true`, scheduled>0), **НИКОГДА не получит preemptive AfterFunc-миграцию**. Он доживает на слоте до age-drain → `startDrain(reason=age)` → `drainWatchdog` natural-finish → `handleSlotDeath` → `resumeStreamOnDeath` шлёт RESUME **ПОСЛЕ** `transport.Close()`.

Сервер на этот поздний RESUME отвечает **FAIL** (метрики pl1 сошлись с клиентским `res_kind=1`=migrateResultFail 100%): `migrate_fail{not_found}=207`, `{grace_expired}=123`, `bad_proof=0`, `resume_ok=9`. Почему FAIL: `resumeStreamOnDeath` (Bug #9 Task 17) рассчитан на ВНЕЗАПНУЮ смерть слота (relay становится orphan в grace-окне). А age-drain — ПЛАНОВОЕ закрытие: relay либо уже не orphan (`not_found`), либо grace истёк (`grace_expired`). → downlink стрима рвётся.

**Класс жертв (точно):** стримы, появившиеся на стареющем слоте в окне между `scheduleSlotMigration` (~60s) и age-drain (~120s) — типично новые CONNECT'ы при активном использовании (Claude Code открывает новые стримы постоянно). Подтверждено: 207+123 FAIL за сессию.

### Корень (B) — uplink-goroutine виснет после закрытия downlink

В `relayStream` (proxy/socks5/tcp.go) две goroutine на стрим:
- **downlink-goroutine:** при выходе `defer cancel()` (tcp.go:935) отменяет ctx2.
- **uplink-goroutine:** заблокирована в `conn.Read(buf)` (tcp.go:859) — НЕ слушает ctx2, `conn` при выходе downlink НЕ закрывается. `cancel()` её не будит.

→ uplink виснет минутами (полевой лог: 15+ стримов uplink elapsed 3-7 мин ПОСЛЕ downlink done; до 3m26s), читая запрос приложения вхолостую. Приложение (Claude Code) держит HTTP/2 keep-alive стрим, ждёт downlink-ответа, которого больше нет → **спиннер**.

**Асимметрия (намеренная только в одну сторону):** uplink-EOF (приложение CloseWrite) → uplink return, downlink живёт ✅ (keep-alive, tcp.go:882-888). НО downlink-done → cancel() НЕ будит uplink ❌ (дыра).

**Связь корней:** (A) обрывает downlink стрима, который приложение держит → (B) оставляет uplink висеть → симптом. Чинить ОБА: (A) чтобы поздние стримы тоже мигрировали (downlink не рвётся); (B) страховка — при ЛЮБОМ закрытии downlink uplink не виснет (работает даже когда A не помог: нет target-слота / migration off / origin реально умер).

## Решение

### Компонент (A) — re-arm scheduling: перенести migration-гейт с per-slot на per-stream

**Подход (выбран юзером): починить корень в существующем пути** — `scheduleSlotMigration` должна планировать миграцию КАЖДОГО стрима стареющего слота, включая появившихся ПОСЛЕ первого вызова, без дублирования таймеров. НЕ дублировать миграцию в startDrain (то было бы позже и грубее).

**Механика:**
- Заменить per-slot гейт `slot.migrationScheduled` на **per-stream гейт**: новое поле `streamEntry.migrationScheduled atomic.Bool` (рядом с `migrating`).
- В watchdog-sweep: когда слот выше migration-threshold (ws_pool.go:1809) И MigrateCapable И есть стримы — на КАЖДОМ тике (5s) вызывать обновлённую `scheduleSlotMigration`, которая `streamMap.Range` по стримам слота и для каждого, у кого `migrationScheduled` ещё false, делает CAS false→true и планирует AfterFunc. Стримы, уже запланированные (флаг true) или мигрирующие (`migrating` true) — пропускаются. Поздний стрим, привязавшийся к aging-слоту, на следующем тике (≤5s) получит свой AfterFunc.
- **Идемпотентность:** per-stream CAS гарантирует ровно один AfterFunc на стрим за его жизнь на этом слоте — нет дублей таймеров несмотря на вызов каждые 5s. (Текущий per-slot CAS существовал именно чтобы не плодить таймеры каждый тик; per-stream CAS даёт ту же защиту + покрывает поздние стримы.)
- **Сброс флага:** `streamEntry` пересоздаётся при rebind на новый слот (migrating→OK ставит свежий entry с `migrationScheduled=false`) — на новом слоте стрим снова кандидат, когда тот состарится. Слотовый `slot.migrationScheduled` (ws_pool.go:458, сброс :2143) — удалить или оставить как no-op (решить в плане; чище удалить).

**Что это даёт:** поздние стримы (60-120s) мигрируют превентивно по живому слоту → RESUME не ловит not_found/grace_expired → downlink не рвётся. `migrate_fail{not_found,grace_expired}` должны резко упасть.

**HIGH-3 (cascade-таргет):** `migrateStream` использует `selectYoungTargetSlot` (youngest ready). При cascade age-cut (все соседи near-age — типично в РФ) youngest ready может сам быть near-age → стрим мигрирует на слот, который скоро сам пойдёт в drain → повторная миграция. Это **деградация, не дыра**: повторная миграция отработает на следующем тике (per-stream re-arm покрывает и это — на новом слоте флаг false). Если живого target нет вовсе — стрим остаётся, fallback на (B). Задокументировать как принятую деградацию.

**Риск регресса Bug #9:** `migrateStream`/`scheduleSlotMigration` — стабилизированные примитивы. Изменение — перенос гейта per-slot→per-stream (та же идемпотентность, шире покрытие). Race на Linux обязателен. Существующие migrate-watchdog тесты не должны сломаться (обновить те, что пинят per-slot флаг).

### Компонент (B) — uplink-goroutine просыпается при закрытии downlink (страховка)

**BLOCKER-2 (исправление v1):** НЕ точечные вставки перед логами (downlink выходит многими return-путями: migration :1043, legacy ch-closed :1052, CONNECT_FAIL :1073, peerFullClose :1125, ctx.Done :1129, write-error drain :1108). Вместо этого — **одно централизованное `defer` в downlink-goroutine**, рядом с `defer cancel()` (tcp.go:935):

```go
go func() {
    defer wg.Done()
    defer cancel()
    defer wakeUplink(conn, socks5Replies) // одно место — покрывает ВСЕ выходы
    ...
}()
```

**HIGH-1 (примитив) = `CloseRead`** (НЕ SetReadDeadline — тот оставляет «мёртвый» deadline на recycled conn). `conn` здесь — relay-end `ourConn`; `CloseRead()` закрывает read-сторону (d1) → uplink `conn.Read` возвращает EOF/ErrClosedPipe → uplink выходит. Идемпотентно.

**HIGH-2 (интерфейс-гард + фолбэк):**
```go
func wakeUplink(conn net.Conn, socks5Replies bool) {
    if cr, ok := conn.(interface{ CloseRead() error }); ok {
        _ = cr.CloseRead()
        return
    }
    _ = conn.Close() // фолбэк (downlink уже мёртв — грубее, но безопасно)
}
```
memConn реализует `CloseRead`. Loopback (`*net.TCPConn`) тоже. Обёрнутый conn без CloseRead → Close-фолбэк.

**НЕ сломать:**
- **Keep-alive half-close (uplink-EOF→downlink живёт):** (B) трогает обратное направление. В half-close uplink УЖЕ вышел (tcp.go:882-888) ДО выхода downlink — wakeUplink на уже-вышедшую goroutine безвреден (CloseRead идемпотентен). immune-флаг memConn (downlinkDeadlineImmune) — только app-end; relay-end CloseRead не затронут.
- **Loopback/socks5Replies:** CloseRead валиден для TCPConn; гард+фолбэк покрывает.
- **Двойное закрытие:** CloseRead идемпотентен; conn.Close под sync.Once (memConn) / TCPConn допускает повторный Close с ошибкой (игнор).

## Инварианты / нюансы

- **(B) — страховка, работает ДАЖЕ если (A) не помог:** нет target-слота, migration off, origin реально умер (Bug #10). Гарантия: downlink закрыт → uplink не виснет → приложение получает обрыв → retry.
- **Связь с Bug #10 (NIT-4):** ортогонально. Bug #10 шлёт FlagStreamClose (server→client downlink) при смерти origin; (B) будит uplink (client-side) при закрытии downlink. В цепочке: origin умер → Bug#10 закрыл downlink demux → (B) разбудил uplink → relay чисто завершился. Дополняют.
- **MEDIUM-4 (остаточная взаимоблокировка):** если downlink-goroutine сама зависнет в `conn.Write(d)` (d2 buffer full, app не читает) — defer-wake (B) не выполнится (goroutine не вышла). Узкий сценарий (app завис, не читает, downlink пишет). Митигаторы: gap-timeout (tcp.go:572) и reassembly-overflow (:541) дают downlink пути выхода при наличии входящих фреймов. На полностью тихом канале downlink сидит в select без таймера — но тогда и conn.Write не вызывается (нечего писать). Принять как known-limitation, задокументировать.

## Тесты (TDD)

- **(A) unit (migrate_watchdog):** стрим, привязавшийся к aging-слоту ПОСЛЕ первого scheduleSlotMigration → на следующем тике получает AfterFunc-миграцию (per-stream re-arm). Через migrateStreamHook. Уже-запланированный стрим (флаг true) НЕ планируется повторно (нет дубля таймера). migrating-стрим пропускается.
- **(A) регресс:** существующие migrate-watchdog тесты (обновить пинящие per-slot флаг); emergency-evict не сломан; resumeStreamOnDeath fallback работает для не-мигрировавших.
- **(B) unit (proxy/socks5):** downlink-goroutine вышла → uplink в conn.Read на memConn просыпается (CloseRead→EOF) → relay завершается (wg.Wait не виснет). Все выходы downlink (migration, legacy ch-closed, ctx) → wake срабатывает (defer). По образцу memconn_halfclose_test.go.
- **(B) full-keepalive (NIT-2):** обе стороны открыты (НЕ half-close), downlink закрыт извне, uplink в Read → wake. (отличать от half-close где uplink уже вышел).
- **(B) keep-alive не сломан:** uplink-EOF half-close → downlink продолжает (регресс).
- **(B) loopback:** socks5Replies путь (real socket / без CloseRead) → Close-фолбэк.
- **Bug#10+B цепочка (NIT-4):** origin умер → FlagStreamClose закрыл downlink → (B) разбудил uplink → relay завершился.
- **e2e:** поздний стрим на aging-слоте → мигрирует превентивно (A), downlink продолжается; если не мигрировал → uplink не виснет (B).
- **race:** `go test -race` на Linux/pl1 (сердце Bug #9 — watchdog/migrate + relay goroutines).

## Метрики (канарейка)

- Переиспользовать `MigrateScheduled` (растёт за счёт поздних стримов после фикса A) — НЕ плодить новый счётчик (NIT-1).
- Ожидание: `migrate_fail{not_found}` и `{grace_expired}` РЕЗКО падают; `resume_ok`/preemptive-migrate растёт; uplink elapsed после downlink-done → секунды, не минуты.

## Объём / деплой

- Файлы: `client/stream_entry.go` (поле migrationScheduled per-stream), `client/migrate_watchdog.go` (re-arm scheduling per-stream — A), `client/ws_pool.go` (удалить/занопить slot.migrationScheduled, watchdog вызов), `proxy/socks5/tcp.go` (defer wakeUplink — B), + тесты. memconn.go — без изменений (CloseRead уже есть).
- **Только клиент.** Сервер НЕ меняется (FAIL на поздний RESUME — корректное серверное поведение).
- Пересборка клиента + race на Linux + полевой ретест (keep-alive диалог с паузами + новые стримы на aging-слоте) + канарейка.
- Коммит — с пачкой (Bug#10 + 60s half-close + emergency-evict + этот фикс), по плану юзера.

## Доказательная база

- Клиент: `res_kind=1`=migrateResultFail 100% RESUME-on-death при age-drain; uplink elapsed 3-7мин после downlink-done (15+ стримов); «uplink without lastWriteNs stamp»=0.
- Сервер pl1: `migrate_fail{not_found}=207, grace_expired=123, bad_proof=0`, 0 broken pipe (не Bug#10).
- Воспроизведено: зависание 12:23-12:27 МСК, лог `nixavpn-DEBUG-20260604-122130.log`.
- Код подтверждён: scheduleSlotMigration per-slot CAS однократный snapshot (migrate_watchdog.go:176-211); uplink conn.Read без ctx (tcp.go:859); defer cancel без conn-wake (tcp.go:935).

## Обязательные требования к ПЛАНУ (из опус-ревью v2, APPROVED-WITH-NITS)

Опус-ревью v2 = **APPROVED-WITH-NITS (0 BLOCKER / 0 HIGH / 2 MEDIUM / 5 NIT)**, отчёт
`docs/halfopen-spec-review-v2-opus-2026-06-04.md`. Дизайн корректен. План ОБЯЗАН учесть:

- **MEDIUM-1 (контракт возврата A):** перенос гейта per-slot→per-stream меняет семантику возврата
  `scheduleSlotMigration`: теперь `true` ⇔ «запланирован ≥1 НОВЫЙ стрим на этом проходе» (а не «слот
  обработан впервые»). Документировать новый контракт явно. Переписать `TestScheduleSlotMigration_Idempotent`
  (migrate_watchdog_test.go:187) в позитивный тест ценности re-arm: «поздний стрим, привязавшийся ПОСЛЕ
  первого прохода, получает AfterFunc на втором проходе; уже-запланированный — НЕТ (нет дубля таймера)».
  Инвариант «exactly once per stream» сохраняется через per-stream CAS.
- **MEDIUM-2 (Range-фильтр A):** в обновлённой `scheduleSlotMigration` Range-фильтр ОБЯЗАН быть
  `slotIdx==aging && !e.migrating.Load() && e.migrationScheduled.CompareAndSwap(false,true)`. Пропуск
  `!migrating` = лишний AfterFunc на mid-move стрим (безвреден — short-circuit на migrating-CAS в
  migrateStream:243, но грязно). Тесты на оба гейта + два interleaving-инварианта (защищены существующим
  single-winner migrating CAS, код НЕ добавлять, только подтвердить тестом):
  - (a) AfterFunc арм-нут ДО rebind, fired ПОСЛЕ → не двойная миграция / не отрицательный счётчик
    (single-winner migrating CAS + srcIdx==targetIdx guard защищают).
  - (b) конкурентный watchdog tick во время migrating → mid-move стрим не получает второй move.
- NIT (учесть): переиспользовать `MigrateScheduled` метрику (не плодить новый счётчик); тесты —
  full-keepalive wake (не half-close), Bug#10+B цепочка, loopback Close-фолбэк.

## Журнал ревизий
- **v1:** постановка (A) «миграции в drain нет» + (B) точечные вставки. Опус-ревью: 2 BLOCKER (A игнорит scheduleSlotMigration; B точечно вместо defer) / 3 HIGH / 4 MEDIUM / 5 NIT.
- **v2 (этот документ):** (A) переформулирован — корень = однократный snapshot scheduleSlotMigration не покрывает поздние стримы; фикс = re-arm per-stream (BLOCKER-1). (B) = defer wakeUplink в downlink-goroutine, примитив CloseRead+гард+фолбэк (BLOCKER-2/HIGH-1/HIGH-2). Cascade-таргет (HIGH-3) и взаимоблокировка (MEDIUM-4) задокументированы. Метрика переиспользована (NIT-1). **Опус-ревью v2 = APPROVED-WITH-NITS (0 BLOCKER/0 HIGH), 2 MEDIUM → требования к плану выше.**

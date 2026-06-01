# Bug #9 — Stream Migration: Финальное системное ревью реализации (целиком)

**Дата:** 2026-06-01
**Ветка:** new-version (~21 коммит, 96929d4..d8e9bf2)
**Скоуп ревью:** интеграционная целостность фичи на стыках 21 задачи. НЕ повтор поштучных ревью — поиск системных проблем на границах задач, end-to-end путь байта, согласованность состояний, capability-gate, анти-DPI, граничные стыки, остаточные TODO, staged-deploy.
**Спека:** docs/superpowers/specs/2026-05-31-bug9-stream-migration-design.md (REVISED-v3).
**Build:** `go build ./...` PASS. Миграционные тесты `go test ./server/ ./core/ -run Migrat|Relay|...` PASS.

---

## ВЕРДИКТ: SHIP-WITH-NOTES (B1 RESOLVED 2026-06-01, коммит 23fa197)

Изначальный BLOCKER B1 (uplink молча теряется после миграции) **ЗАКРЫТ корректно** — см. раздел «B1 RESOLVED» ниже. Верификационное ревью (2026-06-01) подтвердило: фикс архитектурно симметричен остальным registry-fallback'ам, новых системных дыр на стыке не внёс, регрессионный тест non-vacuous (падает без фикса на 65536/131072 байт, проходит с фиксом). Остаются НЕ-блокирующие known-gaps, обязательные перед прод (`-race -count=3` на Linux, perf-acceptance NEW-4) — см. раздел «осталось перед прод». Это операционные пред-деплой шаги, не код-блокеры.

### B1 RESOLVED (верификация 2026-06-01)

**Фикс (websocket.go:810-844):** в FlagData uplink branch добавлен registry-fallback — когда `s == nil && len(payload)>0 && migrateEnabled && migrateClientID != ""` (т.е. локальная per-slot мапа промахнулась на мигрированном стриме), резолвится relay через `h.relayRegistry.find(migrateClientID, streamID)` и пишется `entry.tc.Write(payload)`. `entry.tc` — тот же egress-`net.Conn` что был `s.targetConn` на слоте A (websocket.go:1020 `tc: tc`), переживающий ротацию слота.

Проверено по 5 пунктам:

1. **Закрыт корректно.** Fallback срабатывает РОВНО когда `s == nil` (мигрированный стрим, локальной записи нет). `entry.tc` = origin-conn пережившая миграцию (один объект, set-once на CONNECT, никогда не niled/replaced — reassociate меняет только binding session/writer, не tc). Legacy non-migration (`migrateClientID == ""`) НЕ задет — `else if` гейтится на непустой clientID, до find не доходит, поведение строго прежнее (`s.Write` или drop как раньше).

2. **Uplink целостность.** Барьер §5.3 (`WaitStreamMigrateBarrier`) держит клиентский uplink-goroutine off старого слота до резолва MIGRATE/RESUME → uplink сериализован на ОДИН слот в каждый момент → `entry.tc` имеет единственного писателя, нет cross-slot конкуренции, нет переупорядочки. relayLoop только ЧИТАЕТ egress (`e.tc.Read`, relay_registry.go:572) — half-duplex по направлению, гонки записи нет. Порядок сохранён (тест sha256 over concat подтверждает).

3. **Тест non-vacuous (verified).** `TestE2E_UplinkAfterMigration_NoByteLoss` (migrate_e2e_test.go:655) шлёт uplink ДО (slot A, baseline) и ПОСЛЕ (slot B, регрессия) реальной wire-MIGRATE; origin (net.Pipe, дренируется concurrent reader) получает ВСЕ 131072 байт, sha256 совпадает. **Revert-проба подтвердила:** с занейтраленным fallback тест ПАДАЕТ — "uplink byte loss", таймаут на 65536/131072 (ровно симптом B1). С фиксом — PASS.

4. **Новой дыры нет.** Если entry в stClosing/grace (FIN/grace/evict выиграли CAS и вызвали `entry.tc.Close()`), `entry.tc.Write` в закрытый TCP-conn возвращает `error` (use of closed network connection), НЕ паникует — error логируется (`slog.Warn`), payload теряется (приемлемо: стрим уже рвётся через FIN/grace, teardown владеет другой путь). `entry.tc != nil` всегда true (set-once), TOCTOU-паники нет. Backpressure: blocking `tc.Write` тормозит WS-reader этого слота (та же форма что writer-goroutine у wsStream) — приемлемо.

5. **Симметрия полная (исчерпывающая проверка switch).** Все 8 case-веток reader-loop проверены: `FlagData`(uplink, ТЕПЕРЬ с fallback ✓), `FlagConnect`(регистрирует relay ✓), `FlagFin`(:1182 registry-teardown ✓), `FlagKeepalive`(не per-stream, ack ✓), `FlagUDP`(не migratable, отдельный relay ✓), `FlagWindowUpdate`(:1276 registry-fallback ✓), `FlagMigrate/FlagResume`(:1286 handleMigrateOrResume через registry ✓), `FlagStreamAck`(:1309 registry.find ✓). **Не осталось НИ ОДНОЙ per-stream inbound-ветки без registry-fallback на мигрированном слоте.** FlagData был последней дырой — она закрыта. Корень B1 (асимметрия uplink vs остальные) устранён исчерпывающе.

**Build PASS, `go test ./server/ -run TestE2E -v` PASS (вкл. новый тест), `go test ./...` все пакеты ok.**

---

### Изначальная формулировка BLOCKER (исторически, для контекста)

Одна **BLOCKER-уровня** системная дыра на стыке Task 4 (CONNECT регистрирует relay) и uplink-датапата сервера: **после ЛЮБОЙ миграции (упреждающей ИЛИ grace-resume) uplink клиент→назначение молча теряется сервером.** Downlink защищён registry, uplink — нет. Для основного юзкейса (долгие интерактивные стримы: AI-агент, polling, любой request/response) это воспроизводит ровно тот симптом «зависает и не восстанавливается», который Bug#9 призван лечить. Поштучные ревью не поймали, потому что каждая задача корректна изолированно — дыра именно НА СТЫКЕ downlink-registry (Task 4/10/11) и uplink-per-slot-map (древний датапат, не тронутый миграцией). **→ ИСПРАВЛЕНО коммитом 23fa197, см. выше.**

---

## Системные находки по severity

### BLOCKER (1)

#### B1. Uplink молча теряется после миграции — разрыв контракта downlink-registry ↔ uplink-per-slot-map
**Файлы:** `server/websocket.go:803-810` (FlagData uplink branch), `server/websocket.go:696` (`streams := make(map[uint16]*wsStream)`), `proxy/socks5/tcp.go:910-926` (client uplink → slot B), `client/migrate_watchdog.go:315-334` (`rebindStreamToSlot`).

**Цепочка (доказана кодом):**
1. CONNECT стрима 42 приходит на слот A → `streams[42]` создаётся **в локальной per-WS-session мапе слота A** (websocket.go:696, :840). Для migration-сессии downlink выносится на `relayEntry.relayLoop` (registry), а uplink ОСТАЁТСЯ на `s.Write(payload)` через `streams[42]` слота A (websocket.go:809, :975 коммент «uplink still flows through this session's reader-loop»).
2. Клиент мигрирует стрим 42 на слот B: `sendMigrate` → сервер `reassociate` (downlink binding → B) → MIGRATE_OK → клиент `rebindStreamToSlot(42, B)` ставит свежий `streamEntry(slotIdx=B)`.
3. Клиентский uplink (tcp.go:910-923): после барьера ре-резолвит `uplinkSession` = сессия B, шифрует под B, `StreamWrite` → `WriteMessageForStream(42)` → роутит на **слот B**.
4. На сервере reader-loop **слота B** дешифрует (ключ B — ОК), `FlagData` → `s := streams[42]` в **локальной мапе слота B**. CONNECT был на A → в мапе B записи 42 НЕТ → `s == nil` → **байты молча выброшены** (websocket.go:808 `if s != nil`).

**Нет registry-fallback** в FlagData uplink branch (в отличие от FlagWindowUpdate :1242, FlagStreamAck :1275, FlagFin :1148, которые ВСЕ резолвят через `relayRegistry.find`). Uplink — единственный per-stream путь, оставшийся на per-slot мапе и НЕ переключённый на registry.

**Последствие:** download-only стрим (origin→client, напр. видео-push) переживёт миграцию. НО любой стрим с трафиком клиент→сервер ПОСЛЕ миграции (HTTP-запрос в long-poll, сообщение агенту, тело POST, gRPC-стрим, TLS-записи прикладного уровня) — uplink дропается, прикладной протокол виснет. Спека §1 прямо называет это основным профилем боли (291/371 долгие интерактивные). Деградация ХУЖЕ текущего поведения для этих стримов: сейчас стрим рвётся явно (close), после фикса — виснет тихо (uplink в чёрную дыру, downlink жив, gap-timeout не срабатывает т.к. downlink-seq не дырявит).

**Почему не поймано:** e2e-тест `TestE2E_PreemptiveMigration_NoByteLoss` (migrate_e2e_test.go:543) и grace-resume тест проверяют ТОЛЬКО downlink (origin streams → client, sha256). НЕТ ни одного теста «клиент шлёт байты ПОСЛЕ миграции → origin их получил». `pacedOrigin` (тест-харнес) гоняет origin→client. Uplink-after-migration — слепое пятно тестов и поштучных ревью.

**Фикс (архитектурный, ~локальный):** в FlagData uplink branch (websocket.go:803-810) при `s == nil && migrateEnabled && migrateClientID != ""` резолвить relay через `h.relayRegistry.find(migrateClientID, streamID)` и писать `entry.tc.Write(payload)` (с учётом backpressure/ошибки). `migrateClientID` уже доступен в reader-loop (websocket.go:673-677). По симметрии с уже сделанными FlagWindowUpdate/StreamAck/FIN registry-fallback'ами. Требует решить, кто сериализует запись в `entry.tc` (uplink reader B vs… только reader пишет в write-half, relayLoop читает read-half — half-duplex по направлениям, гонки нет, но нужен аккуратный учёт ошибки записи = teardown). Также: при упреждающей миграции до MIGRATE_OK uplink ещё на A (`s` слота A валиден) — fallback нужен только когда локальная мапа промахнулась.

---

### Системные находки — НЕ блокеры

Прочие стыки проверены и **целостны** (см. ниже). Системных HIGH/MEDIUM сверх B1 не обнаружено. Ниже — наблюдения уровня LOW/полировки и подтверждённые known-gaps (раздел «осталось перед прод»).

#### L1 (LOW). `unackedTail.Push` в fast-path игнорирует переполнение
`relay_registry.go:679` (`e.unackedTail.Push(frame)` в routeDownFrame fast-path) — возврат `false` (буфер полон) игнорируется. Комментарий утверждает «credit gate guarantees in-flight ≤ window so this push always fits». Это верно ПОКА unackedTail чистится FlagStreamAck вовремя. Если клиент задержал ack (throttle 50ms + форс после MIGRATE_OK), а credit пополнился cross-slot WINDOW_UPDATE'ом до прихода ack — теоретически возможно in-flight > содержимое tail. Push молча не добавит кадр в tail → при смерти A до ack этот кадр НЕ перепошлётся → дыра → gap-timeout рвёт стрим (деградация, НЕ повреждение — реассемблер не отдаст дырявый префикс). Не блокер (деградация безопасна), но стоит залогировать/счётчик на drop из tail, чтобы канарейка увидела.

#### L2 (LOW, информативно). session-mu contention (NEW-4) — принятый риск, замер не сделан
`enqueueDownFrame` → `b.session.NextSeqNum()` берёт `s.mu.Lock()`. При концентрации многих мигрировавших стримов на одном слоте B — contention (спека §8 принимает риск, требует нагрузочный замер в §6). Нагрузочный perf-acceptance НЕ прогнан (см. «осталось»). Не корректностная проблема.

---

## End-to-end целостность данных (пункты 1-4)

**ИТОГ: ЦЕЛА В ОДНОМ НАПРАВЛЕНИИ (downlink), НАРУШЕНА В ДРУГОМ (uplink) → НЕ цела end-to-end.**

1. **Целостность downlink (origin→client): ЦЕЛА.** Контракт server-downSeq ↔ client-expectedSeq согласован. `relayLoop.routeDownFrame` присваивает seq РОВНО ОДИН РАЗ атомарно под perEntryMu, store-or-send без дыр (закрыт Task10-gate). `downSeqCounter` монотонен через reassociate (NEW-3, `reassociate` НЕ трогает counter — relay_registry.go:714). Клиентский реассемблер (tcp.go:493 `downlinkReassemblyLoop`) стартует expectedSeq=1, control=seq0 в отдельную ветку, дедуп `seq<expected`, gap-timeout backstop. `unackedTail` + перепосыл при aDead (reassociate:722). Wire-формат `NewStreamDataChunkSeq`/`ParseStreamDataSeq` round-trip корректен, guard `<10` (chunk.go:230). Тесты NoByteLoss/A→B→C/grace-resume PASS.

2. **Credit lifecycle через миграцию: ЗАМКНУТ.** Один `*streamCredit` шарится: `credits[sid]` (origin slot) + `entry.credit` (registry) — websocket.go:998-1002. relayLoop гейтит на `entry.credit` (relay_registry.go:561). Cross-slot WINDOW_UPDATE (T21, websocket.go:1242): если локальная `credits` промахнулась И migration → registry.find → top-up `entry.credit`. Цикл замкнут: окно негоциируется (Bug#8) → relayLoop gate → клиент OnStreamConsumed шлёт WU → приходит на ЛЮБОЙ слот → registry находит owner → пополнение. На session teardown credit мигрировавшего стрима НЕ закрывается (websocket.go:1299 skip if in registry). Логика корректна end-to-end. **(Оговорка: проверено для downlink-credit; uplink не имеет своего credit-gate — Bug#8 окно односторонне на downlink, так что B1 не связан с credit.)**

3. **Состояния согласованы: ДА для downlink/relay lifecycle.** server state (stActive/stOrphaned/stClosing CAS) ↔ client `migrating` flag ↔ slot lifecycle — single-winner CAS везде (grace-timer vs RESUME vs evict vs FIN-teardown — общий авторитет CAS, relay_registry.go:489/768, websocket.go:1151/1353/583). FD-budget charge упорядочен ПЕРЕД stOrphaned-publish (T12 fix). `entriesForSession` исключает уже-мигрировавшие (binding≠session). **НО** рассогласование ВОЗМОЖНО косвенно через B1: сервер думает relay жив (registry, downlink течёт), клиент шлёт uplink в него — а сервер uplink дропает. Это не рассинхрон СОСТОЯНИЯ, а дыра ДАТАПАТА, но симптоматически = «сервер думает жив, прикладной стрим мёртв».

4. **Capability-gate сквозной: СОГЛАСОВАН.** `migrateEnabled` негоциируется в FLOWCTL V2 marker (websocket.go:203-227), fail-open: ack не дошёл → `migrateEnabled=false` обеими сторонами. Сервер: формат чанка (`enqueueDownFrame` migrateEnabled), CONNECT-регистрация relay (websocket.go:981), handlers гейтят `if !migrateEnabled continue` (:1259,:1268). Клиент: `migrateEnabled.Load()` гейтит seq-канал (`RegisterStreamSeq` vs `RegisterStream`, tcp.go:699), реассемблер, watchdog, барьер. **Нет пути рассинхрона формата:** формат seq гейтится тем же per-session negotiated-битом, внутри сессии не меняется. migrateEnabled (pool-wide, не откатывается) vs migrateCapable (runtime health, hysteresis откат) разделены корректно — откат capability НЕ меняет wire-формат, только перестаёт ПЫТАТЬСЯ мигрировать (деградация к Bug#8).

---

## Known-gaps / TODO перед прод (пункт 7)

1. **[RESOLVED ✅] B1 — uplink-after-migration drop.** Закрыт коммитом 23fa197 (registry-fallback в FlagData branch) + e2e-тест `TestE2E_UplinkAfterMigration_NoByteLoss` (non-vacuous, revert-verified). НЕ блокер более.
2. **[HIGH перед прод] `-race -count=3` НЕ прогнан** (Windows без gcc, CLAUDE.md требует Linux/CI). Фича XL с новой конкурентностью (atomic binding, bufCond, CAS-машина, cross-goroutine FD-charge). Прогнать `go test -race -count=3 ./core/ ./client/ ./server/` на Linux ОБЯЗАТЕЛЬНО.
3. **[MEDIUM] session-mu contention (NEW-4) — нагрузочный perf-acceptance НЕ сделан** (спека §6 требует: сотни стримов на один слот B, замер contention на NextSeqNum + throughput-регрессия). Митигация наготове (atomic sendSeq / spread по слотам), но замер не проведён.
4. **[LOW] `MigrateTailBufferedBytes` gauge мёртв (T18).** Объявлен (metrics.go:245), экспортируется (:844), но в проде НИКОГДА не пишется (`.Store/.Add` только в тестах). Канарейка увидит вечный 0 → не сможет мониторить размер unacked-tail. Либо запитать из `unackedTail.byteLen()`, либо удалить gauge.
5. **[LOW] dest-EOF registry-removal TODO (bug9-1b).** `relayLoop` (relay_registry.go:611-627): при dest-EOF на ЖИВОМ stActive-слоте relayEntry НЕ удаляется до смерти сессии → bounded короткоживущий egress-leak (НЕ потеря данных, НЕ credit-hang — self-heal на teardown). Документирован как не-блокер. Корректный half-close-aware teardown — отдельная задача.
6. **[LOW] L1 — unackedTail.Push overflow drop** не залогирован (см. выше).
7. **[INFO] Анти-DPI FFT/ACF acceptance** — стат-тесты в коде стабилизированы (T21 de-flake d8e9bf2), но полевая канарейка с FFT-проверкой таймстемпов миграций (§6) — это полевой шаг, не код.

---

## Анти-DPI целостность (пункт 5): НЕ обнаружено нового wire-сигнала

- MIGRATE/RESUME/StreamAck в зашифрованном payload, длина reply фиксирована по статусу (OK 11б / FAIL 4б — chunk.go:434/443), reason-коды не варьируют длину. seq = 8б внутри шифротекста.
- Порог миграции jitter U(0.7,1.0) per-slot (ws_pool.go:344-362, «smears onset across 18s band»), spread стримов U(0,8s) (migrate_watchdog), молодой-слот select. Залпа нет.
- Новый слот создаётся штатным пулом (тот же uTLS Chrome 133). Связка частей НЕ даёт предсказуемого паттерна MIGRATE-фреймов: они идут вперемешку с data в одном шифро-канале. Системно нового сигнала от композиции не вижу. Подтверждение — полевой FFT/ACF (deferred, не код).

---

## Граничные стыки (пункт 6): корректны (кроме сквозного B1)

- **Миграция во время flow-control throttle:** credit шарится, relayLoop park/unpark на `entry.credit`, cross-slot WU пополняет — миграция не теряет окно. OK.
- **Миграция во время drain (Bug#6 sticky):** `migrating` флаг (stream_entry.go:22) — drainTeardown/handleSlotDeath пропускают close streamChan для migrating-стрима; migrating НЕ считается active для sticky-backstop. Приоритет миграции над drain. OK (узкое окно закрыто флагом).
- **Миграция во время byte_budget ротации (Bug#8):** упреждающий порог 60s ≪ sticky-backstop — стримы уезжают раньше. Координация §5.7 реализована. OK.
- Двойная миграция A→B→C, MIGRATE на умирающий B, гонка MIGRATE vs close A — state-машина CAS обрабатывает (миграция-в-orphaned→RESUME-семантика). OK.

---

## Staged-deploy совместимость (пункт 8): БЕЗОПАСНА (новый клиент ↔ старый pl1)

**ДА, обратная совместимость для staged rollout подтверждена кодом.**

- Новый клиент анонсирует migrate-бит в FLOWCTL V2 marker. Старый сервер pl1 (без Bug#9) парсит marker как legacy/V1 → migrate-бит не эхо-подтверждён → клиент `migrateEnabled=false` (fail-open, websocket.go:224 эквивалент на клиенте). Миграция OFF.
- migrateEnabled=false → клиент идёт по `RegisterStream` (legacy []byte chan), НЕ seq-формат, НЕ watchdog, НЕ барьер. Поведение строго = Bug#8 сейчас.
- Даже при ошибочной capability — per-stream fail-safe (F3): MIGRATE без OK/FAIL за 1.5s → деградация к обрыву + hysteresis снимает capability после 3 timeout. Клиент не виснет.
- Per-session гейт формата → смешанный парк (старые+новые бинари) безопасен.
- **Порядок staged deploy остаётся прежним: сервер pl1 ПЕРВЫМ** (чтобы новый клиент мог реально негоциировать migration), затем клиент. До передеплоя сервера новый клиент работает как Bug#8. **НО** — деплоить сервер с НЕисправленным B1 нельзя: как только обе стороны на новом коде и миграция включится, uplink-after-migration сломается. B1 — пре-деплой блокер для ОБЕИХ сторон.

---

## Резюме приоритетов

1. Исправить B1 (uplink registry-fallback в FlagData branch) + e2e-тест uplink-after-migration.
2. Прогнать `-race -count=3` на Linux.
3. Нагрузочный perf-acceptance (NEW-4 contention) ИЛИ задокументировать как post-canary-watch.

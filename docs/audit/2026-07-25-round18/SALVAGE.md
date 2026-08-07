# Спасённое знание — из 139 удаляемых docs (раунд 18, 2026-07-25)

Все источники читаются через `git show HEAD:<путь>` (в рабочем дереве файлов уже
нет). Здесь — то, чего **нет больше нигде**: обоснования констант, полевая
эмпирика, отрицательные результаты и ловушки. Порядок — по убыванию ценности.

---

## 1. Вывод anti-TSPU тайминговых констант

Skill `anti-tspu-tuning` пишет про эти флаги просто «tuned». Арифметика —
только здесь.

| Параметр | Было | Стало | Причина |
|---|---|---|---|
| `_MAX_SLOT_AGE` | 120s | **75s** | базовый рез |
| `_STAGGER_STEP` | 15s | **6s** | разброс низких индексов |
| `_STAGGER_OFFSET_CAP` | — | **45s** | idx≥8 упираются в 75+45=120s |
| `DRAIN_HARD_CAP` | 90s | **30s** | худший teardown 150s |
| `migrationThresholdBase` | 60s | **45s** | запас до age-cut idx=0 |
| `_AGE_CUT_MIN_AGE` | 60s | **45s** | окно классификации не должно схлопнуться против 75s |

**Ловушка, без которой правка ломает всё** (это был BLOCKER-1 в ревью спеки):
`slotStaggerOffset(idx)` получает **реальный** индекс uniform-cells 0..15, а не
0..7. Спека ошибочно утверждала «разброс 8 слотов = 7×6s = 42s → 75–117s, всё
под 130s». Фактически при `MaxSlotAge=75s, step=6s`:

```
idx= 0: 75 +  0 =  75s
idx=11: 75 + 66 = 141s   ← в логе slot=11 замёрз на 132756ms
idx=15: 75 + 90 = 165s   ← ЦЕНТР окна заморозки 130–190с
```

Доказательство из поля: `slot=11 slot_age_ms=132756 last_write_age_ms=15436 ←
заморозка`. Обратите внимание: `last_write_age_ms=15436` — слот был **активен**,
это подтверждает рез именно по возрасту, а не по тишине.

Поэтому cap применяется к `base` **до** jitter (`effectiveMaxAge = maxSlotAge +
staggerOffsetNs`, `ws_pool.go:1857`):

| idx | base | после cap | +jitter ±3s | effectiveMaxAge |
|---|---|---|---|---|
| 0 | 0 | 0 | ранний возврат | 75s |
| 7 | 42s | 42s | 39–45s | 114–120s |
| 8 | 48s | **45s (cap)** | 42–48s | 117–123s |
| 15 | 90s | **45s (cap)** | 42–48s | 117–123s |

Запас до 130s — 7 секунд. Регрессия закреплена
`TestSlotStaggerOffset_Capped` (`client/ws_pool_test.go:1365`), который ассертит
`75s + g15 < 130s` напрямую. Migration: base 45s
(`migrate_watchdog.go:40`) × U(0.7,1.0) = 31.5–45s, тик watchdog 5s.

**Хрупкий инвариант без кодовой защиты:** худший teardown =
effectiveMaxAge (≤123s) + drainHardCap (30s) = **≤153s** — край окна заморозки.
Стримы выживают там только потому, что `migrateEnabled=true` тянет
`resumeStreamOnDeath`. Гарда нет: выключат миграцию
(`SHADOWLINK_STREAM_MIGRATION=0`), оставив hard cap 30s — teardown попадёт в
окно. Этот флаг не документирован ни в CLAUDE.md, ни в skill (см. §9).

## 2. Серверный rate-limit — операционный риск в текущем состоянии

Ускоренная ротация (6s stagger вместо 15s) жжёт токены быстрее. Дизайн требует
**`ws_upgrade` burst=90 / refill=120** и **`handshake` burst=80 / refill=300**.

Факт: `server/ratelimiters.go:85,104-108` до сих пор содержит fallback
**`ws_upgrade burst=18 / refill=30`** — ровно те значения, которые в поле дали
4× HTTP 429 ещё на **старой** каденции 15s. YAML с 90/120 в репозитории нет
(генератор — `internal/deploy/steps_shadowlink.go` в дереве NixaVPN).

Дизайн прямо предупреждает: клиентский тюнинг небезопасен в этом состоянии —
429 → слоты не пересоздаются → просадка ёмкости. Числа валидны только для
direct single-client-per-IP; CF/NAT требует пересчёта.

## 3. Root cause Bug #8 — выживший протокол приписывает фикс не туда

`docs/protocols/flow-control-v2.md` утверждает, что причина была во flow-control.
**Неверно.** Реальная причина: в `slotReaderWithClient` блок byte_budget стоял
физически **выше** единственного `DecryptChunkSafe`+`RouteToStream`, и кадр, сам
пересёкший `byteBudget`, выбрасывался через `continue` → дырка в TCP-потоке →
`SEC_E_DECRYPT_FAILURE`. `StreamBufferOverflowsTotal` показывал 0, потому что
путь потери не инструментирован.

**Инвариант:** на любой непустой data-кадр reader обязан выполнить ровно один
`DecryptChunkSafe`+`RouteToStream` **до** любого `continue`/`return` по причинам
ротации.

Проверено и **отвергнуто** (не искать заново): коллизия индексов слотов, двойной
reader, реордеринг seqNum, `AcceptSeqNum`.

## 4. Количественная модель flow-control

Измерено: `wait(W) ≈ 148ms + 377/W(MiB)`. **Пол 148 ms не зависит от окна** —
значит это не BDP, а батчинг порога (`pendingDelta >= jitter*window`, jitter
U[0.4,0.6] → при 4 MiB удерживается 1.6–2.4 MiB). Следствие: наращивание
`SHADOWLINK_FLOW_WINDOW` никогда не дойдёт до RTT (8 MiB→195ms, 16 MiB→172ms).

**Потолок флага:** инвариант `cap(incomingCh) >= effectiveWindow / minChunkSize`;
чанк ≈12 KiB, cap=512 → **безопасный максимум ~6 MiB**. Текущие 4 MiB ≈ 341
кадр. Единственное место, где записан потолок.

## 5. tun2socks v2.6.0 — версионно-зависимые ловушки

Повторно кусали проект, поэтому фиксируются явно:

- `unidirectionalStream` **безусловно** вызывает `src.CloseRead()` при EOF
  аплинка. Для большого GET запрос крошечный → `RcvClosed=true` в первые мс →
  Chrome пишет байт в переиспользованный keep-alive сокет → gVisor отвечает
  **RST**.
- `tcpWaitTimeout=60s` ставится один раз через `SetReadDeadline` после half-close
  и **не перевзводится** → long-poll/SSE/Claude Code умирают ровно на 60.000s.
- `DialContext` даёт ctx с `tcpConnectTimeout=5s`: relay-горутины обязаны жить на
  engine-ctx, иначе **все** TCP рвутся через 5s.
- Переполнение send-буфера gVisor — **молчаливая блокировка, НЕ RST**. «Поднять
  буфер» невозможно: в `engine.Key` v2.6.0 такого поля нет.

## 6. Keepalive = 5s

`SHADOWLINK_KEEPALIVE_INTERVAL` отсутствует и в CLAUDE.md, и в skill — при том
что это один из важнейших флагов.

`JitteredIntervalLogNormal(base, 0.5)` усекает в `[base/2, base*2]`. Было 20s →
худший разрыв 40s > наблюдаемого молчаливого реза 10–15s. base=5s → максимум
10s == пол реза. **Ниже опускать нельзя:** живой idle-браузер пингует раз в
15–30s, дальнейшее ужатие само становится сигналом. Закреплено
`middleboxSilentCutFloor` в `client/ws_pool_keepalive_test.go`, константа
`keepaliveDefaultBase = 5*time.Second` (`client/ws_pool.go:579`).

## 7. Полевая эмпирика — невосстановимо

**Распределение, породившее всю age-модель.** 126× close 1006. По
`last_write_age_ms`: 58× активных (0–2s) против 8× тихих (10s+). По
`slot_age_ms`: 66× на 2–4 мин. 94× при `down_bytes` < 50KB. Вывод: **рез по
ВОЗРАСТУ, не по тишине и не по объёму.** Сервер признан невиновным.

**Чистая база (канарейка graceful-drain, 8h).** 7h55m, 4043 MB вниз / 384 MB
вверх, 700 295 расшифровок, **0 decrypt_fails / 0 ws_died / 0 ERROR**, пик 482
Mbps. Дренажи: 895, natural 60.3%, p50=45s, p95=77s. `tryForceEvictIdleSlot`
сработал 238 раз без зависания.

**Отрицательный результат — самый ценный.** Per-stream idle tracking дал 55.8%
против 56.0% базы при **прогнозе 77.6%**. Почему гипотеза была неверна: в 231
hard-cap событии **100% имели `diag_min_stream_age_ms < 30000`** — это реальные
активные стримы. И факт, переопределяющий задачу: **hard cap не убивает стримы —
3275/3275 (100%) закрылись чисто**. 69.4% аплинков живут дольше 90s hard cap, то
есть частые hard cap — **норма, а не патология**. Документ заканчивается вопросом
«что мы вообще оптимизируем?» — защита от гонки за метрикой.

**Развилка «сервер vs middlebox» решена.** 30s стойка downlink на слотах, только
что прокачавших 142–332 MB; по логу pl1 сервер здоров → middlebox.

**5-часовой дедлок (причина существования `tryForceEvictIdleSlot`).**
`alive=16 dead=0`, 9410 предупреждений «no free cell», **0 ротаций, отпечатки
слотов стабильны всю сессию** — анти-TSPU цель молча не выполнялась. Плюс
`rotationStormBrakeFraction=0.25` и инварианты тормоза.

**Concurrency-lift.** 100% отложек тормоза упирались в inflight-cap
(`InflightCapDeferredTotal=12497` против `CapacityFloorDeferredTotal=0`) — поэтому
`maxConcurrentDrains` и `readyCapacityFloor` разделили на две независимые ручки.
Плюс 24 события исчерпания TIME_WAIT на Windows.

## 8. Эмпирика decoy — переизмерять дорого

**Зондирование живых сайтов (curl, 10–12 сайтов) исправило четыре ошибочных
решения спеки:** `X-Powered-By` — 2/10 и только `Next.js`, никогда
`Brand/X.Y.Z` · `X-Region` — 1/10, и значение это продукт, не регион ·
`X-Request-ID` в ответах — 0/10 · `Server` — 9/10 присутствует, но **ни одного с
версией**. CSP 9/10, HSTS 10/10, XFO SAMEORIGIN(5) > DENY(2). Поведение 404 на 12
сайтах: реальный 404 — 58%, 200+SPA fallback — 33% → выбор архитектурный, значит
задаётся **на персону**. `security.txt` — 100% у tier-1 SaaS, 0% у утилит.

**Модель, на которой были построены две предыдущие спеки, неверна:** nginx **не
отдаёт ни одного decoy-файла**, всё идёт в Go (`server/decoy.go::DecoyHandler`).
⚠ Сверено 2026-08-07: транспорт до Go — TCP `127.0.0.1:10443`, не unix-сокет;
на вывод про decoy это не влияет.

**Почему nginx — инвариант, а не предпочтение деплоя:** серверный JA3S это Go
`crypto/tls` (uTLS только клиентский). Это единственная формулировка причины.

**Forward-pool сознательно похоронен 2026-05-26** (Aparecium, SNITCH NDSS'25) —
защита от повторного предложения. При ≥1k клиентов на одном IP режим
direct-primary упирается в классификатор, и полировкой decoy это не лечится.

## 9. Открытые находки — не потерять

**A5 — ПРИПАРКОВАНО, не решено.** `client/bypassroute/` протекает неявную карту
назначений: не-RU → origin IP, RU → напрямую. **Провайдер** (не TSPU — это внутри
его инфраструктуры) строит покликентную карту «куда этот юзер ходит через VPN».
Две меры, обе дорогие: гнать часть RU-трафика через VPN как decoy (~10× RTT) либо
убрать bypass (−30% воспринимаемой скорости RU). Решение не принято, митигации в
коде нет.

**Антипаттерн jitter-театра.** `idx × JitteredInterval(step, 0.5)` неверен: один
сэмпл умножается, соотношения между слотами остаются детерминированными, пик FFT
выживает. Правильная форма — аддитивная сетка
`idx×step + uniform(-step/2, +step/2)`.

**Калибровка модели угрозы.** Побайтовые счётчики на поток — документированная
возможность TSPU (Citizen Lab, авг 2024). **FFT/ACF по таймстампам в
опубликованных возможностях 2026 НЕТ** (A1 был задел на будущее). Пороги
handshake-burst ~30–50/30s, у нас 8 слотов. Без этой калибровки константы будут
перетюнены.

**Ловушка порядка блокировок (реальная 10-минутная паника у автора).**
Перепроверять `WSAttached` под `sm.mu` **нельзя** — RWMutex не апгрейдится,
самодедлок. Гейт фазы 2 ghost-sweep обязан вызываться **вне** `sm.mu`. Это
объясняет, почему остаточное окно в `CleanupDetachedGhosts` — осознанный
компромисс, а не недосмотр.

**Дисциплина `reserveMu`.** «Любой доступ к `p.slots`, чтение или запись, держит
`reserveMu`; одиночная ячейка через `slotAt`, обход через `snapshotSlots`»
(~25 мест, `client/ws_pool.go:1738,1758`, коммит `881e7a3`). В CLAUDE.md и всех
четырёх skills — **0 упоминаний**. Новый контрибьютор внесёт гонку заново.

**Декодирование миграции** обязано смотреть на `slot.migrateNegotiated`,
**никогда** на пул-широкий `p.migrateEnabled` (сервер латчит формат seq на
сессию). Счётчик `shadowlink_migration_frame_unparseable_total`
(`client/stats.go:820`) должен быть ≈0, но его нет ни в борде, ни в skill.

**W1.** Per-session `chunk_size` анонсируется в `"cs"`, но `handleNewFormatPost`
режет по **глобальному** `ChunkSize + 8192` — наблюдаемое на проводе расходится с
анонсированным.

**Долг `-race`.** impl-E/F/G все отложили `go test -race` на Linux/CI. Если
прогон не состоялся — три фикса гонок держатся на рассуждении, а не на детекторе.
Skill `testing-rules` фиксирует ограничение Windows, но долг не трекает.

**IPv6.** Публичный IPv6 **всегда TUNNEL**; bypass для .ru по v6 невозможен (trie
4-байтовый). `fec0::/10` сознательно не в DROP.

## 10. Протокольные детали, отсутствующие в `docs/protocols/`

**Протокол миграции** (`core/migrate.go` живой, спеки в `docs/protocols/` нет):
формат `[StreamID(2 BE)][downSeq(8 BE)][data]`; **`downSeq==0` зарезервирован под
control, первые данные = 1, счётчик НИКОГДА не сбрасывается при
переассоциации**. Плюс четыре отвергнутые альтернативы с причинами.

**Origin death.** `entry.tc` и `binding.writer` — это **два разных TCP**: смерть
origin не означает смерть слота, живой writer донесёт сигнал сразу.
`CONNECT_FAIL` как FlagData работает mid-stream; **`FlagFin` использовать
НЕЛЬЗЯ** (broadcast на сессию убьёт всё).

**Sticky-stream.** `_STICKY_MAX_TOTAL_BYTES` через env отключить нельзя **вообще,
by design** (анти-TSPU потолок). Про `=0` в `_STICKY_MAX_DRAIN_AGE`: в коде уже
вылечено трансляцией в `-1` (`engine_shadowlink.go:479-482`), но в таблицах skill
пояснения нет. Честная цена: обычная жизнь слота `[120s, ~232s]`, sticky до 10m
это **выброс ×2.6, видимый в гистограмме возрастов потоков TSPU**. Заранее
согласованное ужесточение, если хвост окажется значимым: 10m→5m,
auto→poolSize/4.

**Инвариант registry-fallback (был BLOCKER B1 — uplink молча терялся после
миграции).** Проверены **все 8 case-веток** reader-loop, ни одной без fallback:
`FlagData` (последняя дыра, закрыта — `websocket.go:810-844`) · `FlagConnect`
(регистрирует relay) · `FlagFin` (`:1182`) · `FlagKeepalive` (не per-stream) ·
`FlagUDP` (не migratable, отдельный relay) · `FlagWindowUpdate` (`:1276`) ·
`FlagMigrate`/`FlagResume` (`:1286`) · `FlagStreamAck` (`:1309`).

Механика: при `s == nil && len(payload)>0 && migrateEnabled && migrateClientID != ""`
резолвится `h.relayRegistry.find(migrateClientID, streamID)` и пишется
`entry.tc.Write(payload)`. **`entry.tc` — set-once на CONNECT, никогда не niled и
не replaced**; reassociate меняет только binding session/writer, не `tc`. Legacy
non-migration (`migrateClientID == ""`) не задет — гейтится на непустой clientID.

Почему нет гонки записи: барьер §5.3 (`WaitStreamMigrateBarrier`) держит
клиентский uplink off старого слота до резолва MIGRATE/RESUME → uplink
сериализован на один слот → у `entry.tc` единственный писатель. `relayLoop`
только **читает** egress (`e.tc.Read`, `relay_registry.go:572`) — half-duplex по
направлению.

Тест non-vacuous, проверено revert-пробой:
`TestE2E_UplinkAfterMigration_NoByteLoss` (`migrate_e2e_test.go:655`) — с
занейтраленным fallback **падает** («uplink byte loss», таймаут на 65536/131072),
с фиксом проходит; sha256 над 131072 байтами совпадает.

**Порядок в reassociate (был BLOCKER-2).** `bound.Store(B)` обязан идти **до**
`CAS(stOrphaned→stActive)`. Origin-death-хелпер читает только `bound.Load()` +
`state`, поэтому в выигрышной из-`stActive` ветке гарантированно видит живой B, а
не мёртвый A. Проверены все 4 читателя `bound` в новом промежуточном окне
«bound=B, CAS не сделан, state=stOrphaned»: `entriesForSession`,
`hasBoundEntriesForSession`, `evictIdleOrphan`, `relayLoop`/`routeDownFrame` —
новых гонок нет.

**Ловушка реализации:** спека говорит «переезжает только `bound.Store(B)`», но в
коде `bound.Store` сидит **внутри** `reassociate` (`relay_registry.go:735`).
Наивная реализация создаст две разные `*binding`-структуры. Карта кода:
`reassociate` 732-763 (`bound.Store` :735, drainAll :739, resend :742, Broadcast
:750) · `handleMigrateOrResume` 570-627 (CAS :600, releaseOrphanFD :610,
reassociate-call :620) · WS-death cleanup 1375-1478.

## 10b. Half-open drain: непокрытый класс стримов

Ложная постановка, которую пришлось исправлять: «миграции в drain нет».
**Точная:** `scheduleSlotMigration` существует, но per-slot CAS-гейт
`slot.migrationScheduled` делает **однократный snapshot** стримов на ~60s. Стрим,
привязавшийся к aging-слоту **после** первого вызова, никогда не получает
preemptive `AfterFunc` — это и есть непокрытый класс. Лечится re-arm
**per-stream**, а не per-slot. Подтверждено кодом:
`migrate_watchdog.go:176`, `ws_pool.go:1809-1814`.

Два зафиксированных решения:
- Примитив — **`CloseRead`**, не `SetReadDeadline` (второй в tun2socks v2.6.0
  ставится один раз и не перевзводится, см. §5).
- Интерфейс-гард `interface{ CloseRead() error }` + фолбэк на `Close`.
- `defer wakeUplink(conn, socks5Replies)` в downlink-goroutine рядом с
  `defer cancel()` — одно место покрывает все 6 return-путей; точечные вставки
  отвергнуты.

## 11. Стратегические дельты

- **VLESS PQ в Xray v26.4.x** → наш MLKEM768 это **паритет, а не отрыв**.
- **Бан RU по DTLS JA3/JA4** (net4people #603) закрывает все будущие идеи
  DTLS/QUIC/WebRTC для РФ.
- **22 из 30 российских приложений детектят VPN на устройстве** — стелс
  протокола тут не помогает вообще.
- sing-box публично дискредитировал uTLS.
- `docs/plans/2026-05-01-may-audit-action-plan.md` — **не удалять**, живой
  трекер: открыты B7, **C3** (бамп uTLS-профиля, отложен по upstream — до сих пор
  верно), **C13** (`findSessionByHint` после Rekey), **S5** (от него зависят C1
  cover-GET, C5 AckJitter, C6 padding). Плюс раздел «Don't bother — explicitly
  out»: DTLS/WebRTC для РФ мёртв, паритет Trojan-GFW, чистый uTLS как маркетинг —
  отрицательное знание против повторных предложений.

## 12. Прочее

- `docs/alerts/cold-start.yaml` — это **не отчёт**, а рабочий файл правил
  Prometheus и операционная пара к выжившему
  `docs/grafana/cold-start-bypass-board.json`. Удаление рвёт пару. (Но три его
  алерта структурно нерабочие — см. MASTER §В4.)
- `NIKOLAY-README.md` — **не аудит**, а онбординг для нативных iOS/Android
  клиентов: рационал Engine-интерфейса, контракт
  `GET /api/v1/client/full-config`, рецепт split-routing
  (`0.0.0.0/1 + 128.0.0.0/1` + escape route). В CLAUDE.md этого нет вообще.
  Спасать, если мобильные клиенты в планах.
- **OK.ru** — неисследованная нога кластера whitecall: гостевой звонок по ссылке
  без регистрации, юридически строго лучше VK (там телефон = паспорт). Дописать
  в `docs/ideas/2026-06-05-allowlist-circumvention-branch.md`. Юридический
  рейтинг ног: VK худший (телефон); WB Stream и Jitsi вообще без аккаунта.
- **Мастер-дизайн whitecall** (own go.mod, отдельный продукт) — **спросить
  пользователя** перед удалением: если ветка жива, ей нужен свой репозиторий.

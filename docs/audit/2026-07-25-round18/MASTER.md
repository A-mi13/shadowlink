# ShadowLink — Аудит, раунд 18 (2026-07-25)

Шесть параллельных треков: core/крипто · транспорт/DPI · сервер · клиент/leakguard/DNS ·
docs/дрейф · web-research актуальности.

**Статус кода на момент аудита:** `go build ./...` · `go vet ./...` ·
`go test ./... -count=1` — всё зелёное, 12 пакетов. Найденные дефекты
существующими тестами не выявляются, а два — тестами **закреплены как
желаемое поведение**.

Пометка `[ПРОВЕРЕНО]` = находка подтверждена ведущим аудитором независимо от
субагента: чтением первоисточника либо исполняемым тестом (тесты после проверки
удалены, рабочее дерево чисто).

---

## 1. Сводка: что делать в первую очередь

Порядок отражает «ломает основную задачу продукта» → «отказ/выход за периметр»
→ «долг».

| # | Находка | Severity | Почему первым |
|---|---|---|---|
| 1 | `shiftBitmap` — anti-replay не работает | CRITICAL | Защиты нет вообще, на всех путях. Дешёвый фикс (2 строки), но требует правки теста, который закрепляет баг |
| 2 | Пустое тело decoy при nil-снапшоте | CRITICAL | Детерминированный оракул за 19 запросов, без знания протокола. Ломает маскировку — основную задачу продукта |
| 3 | `X-SL-RL` — plaintext-сигнатура ShadowLink | HIGH | Одно имя заголовка = однозначная классификация хоста активным зондом. Обоснование (CDN) устарело — удалить |
| 4 | ALPS `h3` в hot-path при ALPN `http/1.1` | HIGH | JA4-расхождение двух TLS-стеков одного клиента; 60% населения. Фикс = одна строка |
| 5 | `LEAKGUARD_STRICT` default OFF | CRITICAL* | Fail-open: kill-switch не включается при ошибке. Обесценивает всю глубину защиты ниже |
| 6 | Повторный `FlagConnect` перезатирает стрим | HIGH | Утечка FD+горутин, `maxStreamsPerSession` не срабатывает → отказ для всех клиентов |
| 7 | Rate-limit сервера 18/30 против клиента под 90/120 | HIGH | **Операционный риск прямо сейчас**: 429 → слоты не пересоздаются → просадка ёмкости |
| 8 | POST'ы без `sec-ch-ua`/`sec-fetch-*` | HIGH | Асимметрия GET vs POST в одной сессии = «разные кодовые пути» |
| 9 | SSRF: `[::]` не в `privateCIDRs` | HIGH | Доступ к локальным сервисам на VPS |
| 10 | Plaintext-DNS окно 15–25с на старте | HIGH | Утечка имён + сигнал «клиент включает VPN» в самый заметный момент |

\* Формально классифицирован субагентом как CRITICAL; я оставляю его на 5-м
месте, потому что требует стороннего сбоя (нет прав/WFP недоступен), тогда как
#1–#4 срабатывают в штатной работе.

---

## 2. CRITICAL

### C-1. `shiftBitmap` сдвигает биты в обратную сторону — anti-replay окно не работает
`core/session.go:511` (`>>=` → должно `<<=`), `:513` (из `[i-1]<<` → из `[i+1]>>`).

> **✅ ИСПРАВЛЕНО 2026-07-25.** `shiftBitmap` переписан на сдвиг влево
> (`<<=` + перенос из `[i-1] >> (64-bitShift)`), докблок объясняет соглашение
> битмапа. Прежний `TestSessionSlidingWindowEdge`, закреплявший баг, удалён —
> на его месте оставлен комментарий-указатель. Регрессия закрыта 6 тестами в
> `core/session_replay_window_test.go`: монотонный прогон + полный реплей,
> механика сдвига на один, край окна, out-of-order, word-aligned/unaligned
> прыжки (1/63/64/65/127/128/WindowSize-1), property-тест на 200 итераций
> случайных перестановок. Проверено: тесты **падают** до фикса (реплей
> принимался с seq=137), проходят после. `go test ./... -count=1` — 13 пакетов ok.

**[ПРОВЕРЕНО собственным тестом].** Монотонный приём seq 1..10, затем повтор тех
же seq: **9 из 10 повторов приняты**. Точный механизм (второй тест): после
`accept(5)` битмап `00000001`; после `accept(6)` — снова `00000001` (должно
`00000011`); `getBit(1)` для seq 5 даёт `false` — история стёрта, а не сдвинута.

Соглашение битмапа: бит 0 = самый новый seq, бит N = на N позиций старше. При
продвижении окна история должна уезжать в **старшие** биты. `>>=` выбрасывает её
в младшие и обнуляет; `|=` из `[i-1]` подмешивает мусор не из того слова.

Потребители (все затронуты): `server/handler.go:847`, `server/websocket.go:168,861`,
`client/ws_pool.go:3377`, `client/client.go:987,1051,1075`,
`client/split_transport.go:639`.

Последствие: on-path наблюдатель, захвативший аутентичный кадр, воспроизводит его
неограниченно — AEAD-тег валиден, freshness-фильтр пропускает. Дублирование байт
в проксируемом TCP-потоке, повторные `FlagConnect`/`FlagFin`.

**Тест закрепляет баг [ПРОВЕРЕНО чтением]:** `core/session_test.go:38-43`
`TestSessionSlidingWindowEdge`, строка 42 повторно принимает `seq=0` с
комментарием «still within window». Фикс кода не пройдёт CI без правки теста.
Все существующие тесты проверяли только `diff==0` — единственный путь, не
задействующий сломанный примитив.

Почему не заметили: плотность комментариев вокруг («M1 closed», «sliding window»,
«freshness») создала ложную уверенность. Комментарий `:488-490` показывает, что
функцию правили ради переполнения индексов — направление сдвига не проверяли.

### C-2. `SentinelEmitter` при отсутствии снапшота отдаёт `200 OK` с пустым телом
`server/sentinel_emitter.go:67-75`, `server/decoy_timing.go:255-271`,
`cmd/shadowlink-server/main.go:225-236`.

**[ПРОВЕРЕНО чтением].** При `snap == nil || len(snap.HTML) == 0` ставится только
заголовок и `return` — без `WriteHeader`, без `Write`. Вызывающий
`failClosedToDecoyRateLimitedV2` тоже ничего не пишет. Go `net/http` отдаёт
`200 OK`, `Content-Length: 0`.

Путь достижим в штатной работе: `main.go` при ошибке `LoadDecoySnapshots`
выставляет `snapshots = nil` и **всё равно** создаёт emitter
(`-decoy-snapshot-strict` по умолчанию выключен, это задокументированная
«graceful degradation» для роллаута).

Атака: 19 WS-upgrade на любой путь из `wsURLPool` (список публичный — он же в
клиентском бинаре) → бакет `ws_upgrade` burst=18 → 19-й запрос отдаёт `200` с
пустым телом. Тот же путь без превышения отдаёт полноценный HTML. «Сайт, который
после 19 быстрых запросов начинает отдавать 200 с нулевым телом» — поведение,
которого не бывает у реальных сайтов. Оракул детерминированный, 19 запросов, без
криптографии и знания протокола.

**Тест утверждает это как желаемое:** `server/sentinel_emitter_test.go:109,132` —
`assert.Empty(t, w.Body.Bytes(), "body must be empty on header-only path")`.
DPI-последствия просто не оценивались.

> **✅ ИСПРАВЛЕНО 2026-07-25.** `Emit` теперь возвращает `bool` — записан ли
> ответ полностью. `failClosedToDecoyRateLimitedV2` при `false` отдаёт тело
> обычным decoy-путём (заголовок `X-SL-RL` уже проставлен внутри `Emit` и уезжает
> вместе с этим телом), сохраняя `ackJitter()` для timing-parity. Оба теста,
> закреплявших пустое тело, переписаны: теперь утверждают `Emit → false`.
> Регрессия закрыта в `server/decoy_body_invariant_test.go` (nil-снапшоты,
> снапшот есть, оба на rate-limit-пути). **Revert-проба:** при нейтрализации
> фикса тесты падают.

### C-3. `SHADOWLINK_LEAKGUARD_STRICT` по умолчанию OFF — архитектурный fail-open
`cmd/nixavpn-client/main.go:330-345`, чтение env — `main.go:810`.

**[ПРОВЕРЕНО чтением].** При падении `lg.Enable()` (нет прав администратора, WFP
недоступен, netsh отказал, backup политики не прочитался) печатается WARN и
работа **продолжается с поднятым туннелем и без kill-switch**. Строгий режим —
opt-**in**.

Утечка: при последующем обрыве туннеля split-маршруты `0/1 + 128/1` остаются, но
при их снятии/невалидности трафик уходит через физический шлюз с реальным IP.
Kill-switch, который обязан это поймать, не установлен.

Сравнение, доказывающее ошибку в направлении default: `splitTunnelEnabledFromEnv`
сделан opt-in **правильно** — там безопасное значение = off. Здесь наоборот.

> **✅ ИСПРАВЛЕНО 2026-07-25.** `leakguardStrictFromEnv` инвертирован на
> fail-secure: default strict=**ON**, opt-**out** через `=0/false/no/off`.
> Мусор и пустое значение → strict (не ослабляют защиту). Сообщение
> пользователю в `main.go` переписано под новую семантику. Тест
> `TestLeakguardStrictFromEnv` переписан (прежний утверждал `"" → false`, то
> есть закреплял fail-open), добавлен
> `TestLeakguardStrict_DefaultIsFailSecure` на полностью неустановленную
> переменную.

---

## 3. HIGH — маскировка и DPI

### H-1. `X-SL-RL` — plaintext-маркер ShadowLink
`server/decoy_timing.go:117-121`, `server/sentinel_emitter.go:64`,
`server/websocket.go:512`.

Ответ несёт `X-SL-RL: v1;bucket=ws_upgrade;refill_in=3;burst_left=0;exempt=0`.
TSPU пассивно не видит (TLS терминирует nginx), но **активный зонд видит** — он
сам TLS-клиент. Ни один реальный сайт такого заголовка не отдаёт: одно имя →
однозначная классификация хоста → решение о блокировке диапазона.

Обоснование существования header-carrier'а (`decoy_timing.go:246-254`) — «нужен,
когда CF вырезает body-marker». Но CDN официально запрещён моделью. Обоснование
устарело вместе с отказом от CDN; body-marker (Schema.org JSON-LD) остаётся
достаточным и wire-neutral. Заголовок — долг с отрицательной ценностью.

### H-2. ~~ALPS-расхождение cold-path vs hot-path~~ — ❌ НЕ ПОДТВЕРЖДЕНО (2026-07-25)

> **❌ ЛОЖНАЯ НАХОДКА. Опровергнута замером 2026-07-25.**
>
> Трек 2 утверждал, что hot-path (bogdanfinn) объявляет ALPS `["h3","h2"]`
> против `["h2"]` у cold-path (utls). **Замер показал обратное:**
>
> ```
> chrome120  hot RAW  ALPN=[h2 http/1.1]  ALPS=[h2]
> chrome131  hot RAW  ALPN=[h2 http/1.1]  ALPS=[h2]
> chrome133  hot RAW  ALPN=[h2 http/1.1]  ALPS=[h2]
> chrome133  cold RAW ALPN=[h2 http/1.1]  ALPS=[h2]
> ```
>
> `h3` не присутствует в ALPS ни в одном профиле ни одного из стеков —
> расхождения нет. Моя первоначальная пометка «[ПРОВЕРЕНО чтением]» была
> некорректной: я подтвердил лишь **отсутствие вызова `WithDisableHttp3()`** в
> `connmanager.go:206`, но не сам вывод о наличии `h3` — а из отсутствия вызова
> он не следует.
>
> **Что сделано всё равно:** `WithDisableHttp3()` добавлен как страховка
> инварианта — если будущий бамп профиля (открытый C3) принесёт `h3`, он будет
> вычищен, а не уедет на провод при ALPN=http/1.1. Паритет закреплён тестами
> `client/alps_parity_test.go` (все три профиля пула + сравнение составов
> ALPS между стеками).
>
> **Часть про порядок extensions** (шафл в cold-path против фиксированного в
> hot-path) замером не проверялась и остаётся **непроверенной гипотезой**.
> Приоритет — низкий: research (§7 RESEARCH.md) не нашёл публичных данных, что
> это используется как дискриминатор.
>
> **Урок:** утверждение субагента «проверено байтовым сравнением спеков в module
> cache» оказалось неверным. Проверять надо сам вывод, а не косвенный признак.

Исходная формулировка находки (для истории): «`validateProfile` сверяет числа
мажоров, а не байты на проводе, поэтому расхождение ALPS прошло незамеченным».
Механизм описан верно — `validateProfile` действительно сверяет только мажоры, —
но конкретного расхождения, на которое он указывал, не существует.

### H-3. Прод-POST'ы без `sec-ch-ua` и `sec-fetch-*`
**[ПРОВЕРЕНО].** В `client/datapath.go` — **0** упоминаний `sec-*`; в
`client/ws_transport.go` — 8.

`datapath.go:81-105` (data POST) и `client/transport.go:455-474` (handshake) —
прод-путь direct-режима, `sec-*` нет вообще. При этом warmup GET, decoy GET,
WS upgrade и DoH POST — все с CHUA/Sec-Fetch.

Chrome шлёт `sec-ch-ua*` безусловно на каждом HTTPS-запросе с v90, `sec-fetch-*`
на каждом fetch/XHR с v76. Наблюдатель видит на одном соединении
`GET /assets/main.css` с полным набором, затем `POST /api/v2/batch` без единого
`sec-*`. Это не «старый браузер», а «разные кодовые пути».

Плюс: `x-request-id` (`datapath.go:84`) — не Chrome-заголовок и стоит в
HeaderOrderKey **до** `user-agent`. Плюс `ws_transport.go:198-207` — 4 заголовка
через `net/http` = stdlib alphabetical, не Chrome-order.

### H-4. Lockstep разрывается на трёх call-sites
`client/ech.go:57,72`, `client/decoy_traffic.go:61`, `client/probe.go:152` — все
берут chrome133 напрямую (`NewFingerprint` игнорирует аргумент,
`fingerprint.go:192`), обходя per-клиентский выбор 120/131/133 (веса 10/30/60).

Сегодня wire-эффект ≈0: DoH идёт через туннель, `DecoyTraffic` живёт только в
SplitTransport (CDN-путь), `ProbeEngine` мёртв. **Латентно:** включение любого из
путей в прод даст на одном IP UA `Chrome/120` вместе с `Chrome/133` при одном JA3.
Тестов, которые это ловят, нет.

Смежное: `skins/browser/request.go:73-85` — экспортированные
`UserAgents`/`PickUserAgent()` содержат **Safari 18.2 и Firefox 133 UA** в
Chrome-only модели.

### H-5. `failClosedToDecoy*` теряет `Host` — расхождение персоны в multi-domain
`server/handler.go:2222-2225` (`httpPlaceholderRequest` = `NewRequest("GET","/",nil)`
→ `r.Host == ""`), `server/decoy_timing.go:203`, `server/decoy.go:138-179`.

Multi-domain — прошитая прод-фича (`domain_decoy_map`, `DomainPersonaMap`,
per-dir FileServer, персональные security-заголовки). При `Host == ""`
`resolvePersona` и `resolveDecoyDir` возвращают default.

Дискриминатор: `GET /` с `Host: blog.example.com` → каталог блога + его CSP;
`POST /` с мусорным JSON и тем же Host → default-каталог + default-персона.
Разный набор заголовков, разный размер тела. Зонд сравнивает два ответа с одним
Host → «этот хост обслуживает не только статику».

Санитизация URL-эхо (чтобы длина тела не зависела от `r.URL.Path`) сама по себе
правильная — но применена слишком широко и выбросила `Host`.

> **✅ ИСПРАВЛЕНО 2026-07-25.** Добавлена `decoyRequestFor(r)`
> (`server/handler.go`): путь по-прежнему санитизируется в `/` (и query
> отбрасывается), но **`Host` проносится**. Заменены оба call-site'а —
> `failClosedToDecoyWithReason` (`decoy_timing.go:203`) и новый
> rate-limit-путь. nil-safe. Регрессия закрыта в
> `server/decoy_body_invariant_test.go`: тест поднимает реальный
> `DecoyHandler` с двумя каталогами и проверяет, что fail-closed ответ на
> `Host: blog.example.com` приходит из каталога блога, а не из default.
> **Revert-проба:** при возврате `httpPlaceholderRequest()` тест падает.

### H-6. WS-путь для не-whitelisted URL обходит timing-parity
`server/websocket.go:472-477` — единственный вызов decoy в `server/`, минующий и
`decoyWithTimingParity`, и `failClosedToDecoy*`. Остальные платят
`runSyntheticDispatch()` (3× X25519 ScalarMult, ~5 ms) + `ackJitter()`.

`GET /random-path` с `Upgrade: websocket` → ответ <1 ms; без `Upgrade` → ~5 ms +
jitter. Тела идентичны. «Добавление `Upgrade` ускоряет ответ в 10 раз» —
бессмыслица для статики за nginx.

Комментарий `:473-474` был верен до появления timing-parity; после — устарел.

### H-7. 10 разнородных WS-путей с per-dial выборкой при 16 слотах
`client/ws_paths.go` смешивает `/socket.io/` (Socket.IO) + `/cable` (Rails
ActionCable) + три proprietary realtime-эндпоинта. Реальный SPA говорит с
**одним** realtime-эндпоинтом.

CRIT-4 (единственный `/ws`) закрыт корректно, но открыт сигнал другого класса —
stack heterogeneity, который CLAUDE.md прямо запрещает для decoy. Фикс:
sticky-выбор одного пути на сессию/профиль закрывает оба.

### H-8. Plaintext-DNS окно 15–25 с между `PreLock` и `setupRoutes`
`client/leakguard/guard_windows.go:64-94`, `cmd/nixavpn-client/main.go:310-316`,
`tunnel.go:318` (`waitForTUNReady` 15s), `tunnel.go:655-660` (bind-retry ~10s).

`PreLock` прибивает физические NIC к `1.1.1.1,8.8.8.8` **до** `tun.Start()`. В
этот момент нет ни TUN, ни split-маршрутов, ни kill-switch → все DNS-запросы ОС
уходят plaintext, напрямую, с реального IP.

Двойной вред: утечка имён + сильный поведенческий сигнал «клиент включает VPN»
(ISP-DNS резко сменился на CF/Google) — в самый заметный для DPI момент.

Docstring `guard_windows.go:339-343` утверждает, что запросы физических NIC
«captured by the 0/1+128/1 split route» — верно только **после** `setupRoutes`,
а `PreLock` по определению работает до него. Комментарий описывает не тот момент
времени, что и маскировало дефект.

Ирония: `PreLock` введён ради закрытия leak-окна, а на DNS-плоскости его
открывает.

---

## 4. HIGH — отказ обслуживания и ресурсы

### H-9. Повторный `FlagConnect` с тем же `streamID` перезатирает стрим
`server/websocket.go:941-944`, `server/handler.go:1473-1484` — безусловная
перезапись `streams[streamID] = pendingStream`.

Старый объект теряется из map, но `targetConn` **не закрывается**, writer-горутина
(`websocket.go:348-392`) продолжает жить (выходит только по `s.done`, а `s.Close()`
уже никто не вызовет — ссылки нет), `relayStreamFromTarget` тоже крутится.

Проверка лимита стоит **перед** вставкой и смотрит на `len(streams)` — при
повторном использовании одного `streamID` размер map остаётся 1, значит
**`maxStreamsPerSession = 256` не срабатывает никогда**.

Аутентифицированный клиент в цикле шлёт `FlagConnect(streamID=1, target=...)`:
каждая итерация +1 подвешенный TCP-сокет, +1 горутина, +1 запись в
`relayRegistry`. Через тысячи итераций — исчерпание FD на весь процесс, включая
listener → отказ для **всех** клиентов. Orphan-FD-бюджет
(`handler.go:343-354`) считает только orphaned relays и этого не ловит.

Есть готовый `DecoyReasonStreamDuplicate` (используется только в
`handler.go:1233`) — либо отклонять дубликат, либо закрывать старый стрим.

### H-10. Rate-limit сервера остался 18/30 при клиенте, затюненном под 90/120
`server/ratelimiters.go:85,104-108` — fallback `ws_upgrade burst=18 / refill=30`.

Дизайн age-window tuning требует `ws_upgrade burst=90 / refill=120` и
`handshake burst=80 / refill=300`, потому что ускоренная ротация слотов (6s
stagger вместо 15s) жжёт токены быстрее. Значения 18/30 — ровно те, что в поле
дали 4× HTTP 429 ещё на **старой** каденции.

YAML с 90/120 в репозитории нет (генератор — `internal/deploy/steps_shadowlink.go`
в дереве NixaVPN). Дизайн прямо предупреждает: клиентский тюнинг небезопасен в
этом состоянии — 429 → слоты не пересоздаются → просадка ёмкости.

Числа валидны для direct single-client-per-IP; CF/NAT требует пересчёта.
**Это операционный риск в текущем состоянии прода, а не гипотеза.**

### H-11. `Destroy()` не выводит сессию из строя — шифрование под all-zero ключом
`core/session.go:654-666`; fallback-ветки `:384-410`, `:412-479`. Дубли в
`:766-776`, `:861-871`, `:253-270`.

**[ПРОВЕРЕНО собственным тестом].** После `Destroy()` `len(SendKey) == 32` (все
нули), `EncryptChunk` **успешно** возвращает 43 байта под общеизвестным нулевым
ключом. `ZeroBytes` зануляет на месте, не меняя длину, поэтому
`aes.NewCipher(32 нуля)` работает.

Достижимость: `client/ws_pool.go:2738,3963` (ротация, Close),
`client/client.go:1436-1467` — отложенный `Destroy()` через 5 с в goroutine при
живых in-flight SOCKS5-хендлерах: окно заведомо конкурентное.

Комментарий `client/ws_transport.go:686-691` утверждает «empty key → AES-GCM init
fails → soft-fail by contract». **Ложная предпосылка:** ключ не пустой,
инициализация не падает. Вся стратегия «Holistic review I-1» не срабатывает
никогда.

Фикс: `destroyed atomic.Bool` + fail-closed в `EncryptChunk`/`DecryptChunkSafe`.

### H-12. SSRF: `[::]` не входит в `privateCIDRs`
**[ПРОВЕРЕНО].** В `server/safedial.go` нет ни `"::"`, ни `::/128`, ни упоминания
unspecified. Тот же список используется для UDP (`server/handler.go:1668`).

`FlagConnect` с target `[::]:6379` → `LookupIPAddr("::")` → `isPrivateIP` =
false → dial. На Linux подключение к unspecified идёт на loopback → доступ к
локальному Redis/PostgreSQL/admin-API на том же VPS.

IPv4-mapped формы (`::ffff:127.0.0.1`) нормализуются Go и блокируются корректно.
Отсутствуют также: `64:ff9b::/96` (NAT64), `2002::/16` (6to4), `224.0.0.0/4`,
`255.255.255.255/32`, `192.0.2.0/24`, `198.18.0.0/15`.

### H-13. Linux/Darwin: нет allow для Yandex plain-UDP → split-DNS не работает
**[ПРОВЕРЕНО].** `DefaultYandexIPs`/`77.88.8` не упоминаются в
`rules_linux.go` и `rules_darwin.go` **вообще**; в `rules_windows.go:74-80`
правило `SL-Allow-DNS-RU` есть.

`setupRoutes` безусловно ставит `/32` escape-маршруты для Yandex
(`tunnel.go:826-832`) → пакеты идут мимо TUN → упираются в финальный
`drop`/`block out all`. Yandex-нога арбитража мертва при поднятом kill-switch →
`dnsproxy` всегда получает `!yOK` → деградирует в CF-only.

Fail-secure по IP (не утечка), но анти-цензурная функция не работает. Правило
единого источника истины, декларированное в `rules_windows.go:66-73`, соблюдено
на одной платформе из трёх.

### H-14. `decoyLogPerIP` — неограниченный глобальный map
`server/decoy_log.go:73-77,89-94,100-129`. Комментарий признаёт отсутствие LRU/TTL
и оценивает 100 B на запись → 100 MB на 1M IP.

Оценка занижена: ключ-строка (16 B header + до 39 B для IPv6) +
`*decoyLogIPState` (8 + 40, с округлением 48 B) + bucket-оверхед ~50–60% → факт
~130–160 B. При `DefaultConfig()`, документированной как «2 vCPU / 2 GB RAM VPS»
(`config.go:275`), 10M уникальных IP → **1.3–1.6 GB** = OOM.

10M достижимо: `logDecoyServed` вызывается на **каждом** `failClosedToDecoy*`,
включая `DecoyReasonBodyInvalid` — то есть на любой мусорный POST с
`application/json`. Одна `/64` IPv6-подсеть даёт 2^64 адресов.

Это единственная структура в `server/` без верхней границы (`TokenBucket` — LRU
10k, `ClientIDExemption` — LRU + callback, `RateLimiter` — 10000).

**Важно:** сам per-IP rate-limit от подмены XFF защищён корректно —
`clientIPFromRequest` (`ratelimit.go:373-414`) идёт по цепочке справа и берёт
первый недоверенный хоп; nginx с `$proxy_add_x_forwarded_for` дописывает реальный
peer справа. H-14 — не XFF-усиление, а честный рост на распределённом скане.

### H-15. `BackpressureCheck` — мёртвый gate + STW на каждом handshake
`server/metrics.go:673-703`, вызов `server/handler.go:646`.

**(а) Условие недостижимо.** Пороги = `Sys × 0.8/0.9`, сравниваются с `Alloc`. Но
`MemStats.Sys` — вся память у ОС (heap + spans + stacks + GC-метаданные + idle-арены),
`Alloc` — только живые объекты. `Alloc < Sys` всегда, в здоровом процессе
отношение 0.3–0.6. Ветки `:691`/`:696` не срабатывают,
`RejectedOverload`/`DecoyReasonBackpressure` не тикают. Заявленная спека («RAM>80%
→ max_conns=4; >90% → отказ») не реализована. Более того, возвращаемый `maxConns`
отбрасывается: `_, rejectNew :=` (`handler.go:646`).

**(б) Цена.** `runtime.ReadMemStats` — stop-the-world, без кэша, **на каждом
handshake**, до всей криптографии. Дешёвый мусорный POST → гарантированная
STW-пауза, тормозящая все горутины включая активные relay'и. Функция, задуманная
как защита от перегрузки, сама является её усилителем и при этом ничего не
защищает.

### H-16. SOCKS5 UDP ASSOCIATE: пиннинг по первой датаграмме, не по peer TCP
`proxy/socks5/udp.go:45-54,143-160`. `conn.RemoteAddr()` — единственный
достоверный источник по RFC1928 §7 — не читается **нигде** в обоих хендлерах.

Локальный процесс, выигравший гонку (порт находится через
`GetExtendedUdpTable`/скан loopback), пиннит себя: датаграммы жертвы молча
дропаются (`continue`, `:159`) = DoS на её DNS/QUIC, а трафик атакующего
релеится через туннель на стриме жертвы, ответы пишутся атакующему.

Ограничитель: бинд жёстко `127.0.0.1:0` (`:90`, `:258`) → только same-host,
поэтому HIGH, не CRITICAL. Пиннинг по IP на loopback функционально no-op — у всех
локальных процессов один IP.

Тест `udp_test.go:10 TestPinClientAddr_FirstWins` закрепляет это как спеку.
Комментарий `udp.go:41-43` утверждает прямо противоположное поведению кода.

### H-17. Регрессия rate-limit: новый IP всегда получает полный burst
`server/tokenbucket.go:49-75` vs легаси `server/ratelimit.go:41-69`.

Легаси при заполненной карте отказывал новым IP (fail-closed). Новый token-bucket
создаёт запись с полным burst и вытесняет LRU — отказа нет. Атакующий с `/64`
ротирует адреса: каждый свежий IP получает свежие 50 handshake / 18 ws_upgrade /
100 data токенов. Ёмкость LRU 10000 роли не играет.

Не CRITICAL: per-IP лимит в принципе слаб против ротации адресов, есть второй
эшелон (`MaxClients`, replay-cache, стоимость X25519). Но это **регрессия** в
рамках работы, позиционированной как hardening — стоит зафиксировать выбор
осознанно.

### H-18. `SessionTimeout`/`CleanupInterval` откатаны к инцидентным значениям и не настраиваются
`cmd/shadowlink-server/main.go:109-111` vs `server/config.go:275-296`.

`DefaultConfig()` несёт ретроспективу инцидента 2026-05-17 и ставит
`SessionTimeout: 90s`, `CleanupInterval: 10s`. `main.go` сразу после этого
присваивает `5 * time.Minute` и `30 * time.Second` — ровно те значения, которые
ретроспектива называет причиной decoy lockout.

`FileConfig` **не содержит** ни `session_timeout`, ни `cleanup_interval`; CLI-флагов
тоже нет. Прод гарантированно работает на 5m/30s, изменить нельзя без пересборки.
Частично компенсируется поздними ghost-sweep (15s) и newborn-orphan (30s), но
базовый idle-таймаут в 3.3 раза шире задуманного, а комментарий в `config.go`
описывает значения, которые в проде не применяются.

---

## 5. MEDIUM (сгруппировано)

**Device limit.** `CheckDeviceLimit` берёт RLock, читает, отпускает; через 20
строк `OnSessionCreated` делает append — TOCTOU, N одновременных handshake
превышают лимит на N-1 (`handler.go:724,744`, `ratelimit.go:178-206`). Хуже:
reconnect fast-path `if _, has := ca.clientSession[clientID]; has { return true }`
(`ratelimit.go:185-188`) даёт одному clientID **неограниченное** число сессий →
один пользователь занимает все `MaxClients=500`, остальные получают decoy = полный
отказ. Асимметрия: лимит считается по `userID`, fast-path ключуется по полному
`clientID`.

**Open relay.** `NewClientAuth(nil)` → `openMode` → `IsAuthorized` true для любого
расшифровавшегося clientID, и он ещё exempt-eligible. `ApplyTo` копирует
`authorized_clients` только при непустом списке — опечатка в секции даёт open
relay. Есть громкий WARN, но нет ни fail-fast флага, ни метрики. В сочетании с
H-9/M-device это превращает «внутреннюю модель угроз» в «любой, кто знает
публичный ключ».

**Management API без таймаутов.** `server/server.go:97` — ни `ReadHeaderTimeout`,
ни `ReadTimeout`, ни `WriteTimeout`, ни `MaxHeaderBytes` (основной сервер их
имеет). Проверка ключа — после дочитывания заголовков → **pre-auth slowloris**
пинит горутины. Bind по умолчанию loopback, но `-mgmt-bind` позволяет наружу.
Post-auth: `json.NewDecoder(r.Body).Decode` без `MaxBytesReader`. Минимальная
длина `ManagementKey` не проверяется.

**UDP без границ.** `defaultUDPRespCap = 0` (выключен), `SetMaxResp` не имеет
прод-вызовов, opt-in-механизма (YAML/CLI/ENV) не существует — защита от
UDP-амплификации заявлена, фактически недоступна. Независимо: **нет верхней
границы на `r.flows`** — до 65536 flow на сессию, каждый = FD + горутина + 64 KiB
буфер ≈ 65k FD и 4 GiB. `maxStreamsPerSession` к UDP не применяется.

**WFP per-sublayer (требует проверки на живом хосте).** Permit-фильтры в приватном
sublayer, вероятно, не переопределяют `blockoutbound` Windows Firewall — арбитраж
WFP per-sublayer, block из любого sublayer побеждает. Значит RU split-tunnel на
Windows молча не работает (направление fail-secure). Вывод сделан из семантики
WFP, **не из наблюдения** — подтверждать на реальном Windows с админом.

**Legacy DNS-режим.** При `SPLIT_DNS=0` или неподнявшемся forwarder'е
`tunDNSPlan` возвращает Yandex+CF, Yandex имеет `/32` escape → plaintext DNS мимо
туннеля без арбитража и детекта stub → RKN-заглушка `89.221.226.6` залипает в
кэше ОС. При этом `SL-Allow-DNS-RU` на Windows добавляется **безусловно**, то есть
firewall это разрешает и в legacy-режиме — правило шире оправдывающего его условия.

**Прочее MEDIUM.** `router.Decide` не вызывается в UDP вообще (block-list не
действует, ActionDirect игнорируется) · UDP ASSOCIATE и poll-mode TCP не шлют FIN
(`UnregisterStream` вместо `CloseStream`) → утечка стримов против лимита 256,
ограничено idle-reaper'ом · IPv6 transition-диапазоны не классифицированы
(`::/96`, `64:ff9b::/96`, `2002::/16`, `2001::/32`) — `::127.0.0.1` → routeTunnel →
сервер диалит свой localhost; **не** утечка клиентского IP, а server-side
SSRF-шум; асимметрия: `::ffff:169.254.169.254` дропается, `::169.254.169.254` нет;
также нет `100.64.0.0/10` (CGNAT) и `198.18.0.0/15` (свой TUN → петля) ·
`staggerOffsetCap` схлопывает 8 reserve-ячеек в одно 6-сек окно (idx8..15 все
base=45s → [117s,123s]) → всплеск 8 SYN, воспроизводимо каждый цикл; FFT-пик,
который A1-фикс убирал для primary · cover-POST мёртв (`CoverBudget()` требует
`down>0`, а `RecordDownload` только в неиспользуемом в проде
`SendChunkRawBody`); плюс инвертированная семантика: docstring обещает down>up,
формула требует up ≥ 2.5×down · hot path без padding вообще (padding только в
недостижимом `SendChunk`) → control-фреймы имеют узкие детерминированные размеры ·
`sendSeq uint32` без защиты (`RekeyNeeded()` не вызывается в проде) — недостижимо
на практике, но комментарий обещает защиту, которой нет · остаточное окно
ghost-sweep (gate вне `sm.mu`) — **но перепроверка под локом невозможна**: RWMutex
не апгрейдится, автор получил реальную 10-минутную панику; значит осознанный
компромисс, документировать · TOCTOU в exemption: `soft`/`byteState` могут
получить запись без записи в LRU · `Config` несёт 10 `yaml:`-тегов, которые
никогда не читаются (единственный `yaml.Unmarshal` — в `FileConfig`) → оператор
думает, что настроил `replay_cache_max_size`, а сервер на дефолте ·
`Config.DefaultDecoyPersona` не заполняется никогда · `X-Real-IP` есть в
документированном nginx-конфиге, но **не читается ни одним `.go`-файлом**.

---

## 6. LOW и технический долг

**Мёртвый код.** `core/pool.go` целиком (230 строк + 303 строки тестов; реальный
пул — в `client/ws_pool.go`) · `skins/browser/shaping.go` целиком (99 строк) ·
`skins/browser/fingerprint_lock.go` целиком (81 строка, вытеснен
`client/fpstate.go`) · `Rekey`/`RekeyNeeded`/`OldRecvKey` (включение немедленно
ломает `findSessionByHint` — H2 из 2026-05-01 до сих пор открыт) ·
`ForEach`, `LastActivity`, `WindowResetCount` (метрика заведена, не читается),
`BuildFlowCtlMarker`, `NewPaddingChunk`, `HandleClientHello` ·
`ClientAuth.RemoveClient` (ноль ссылок даже в тестах), `ClientIPFromRequest`,
`HasContent`, `AllWSPaths`, `ActiveSessionCount`, `NewRateLimiters` ·
`MimicryEngine`, `PayloadDistribution` методы (`_ = pd` в `request.go:580`),
`DefaultCoverPaths`, `NextDecoyInterval` unimodal · `fwpActionBlock`.

**Комментарии, противоречащие коду** (класс, а не отдельные случаи —
см. §7): `proxy/socks5/udp.go:41-43` утверждает противоположное поведению ·
`proxy/socks5/server.go:234` неверно описывает свой фикс (`ReadAtLeast(...,7)` —
минимум для IPv4, фрагментированный DOMAINNAME ложно отвергается) ·
`client/ws_transport.go:686-691` (ложная предпосылка, H-11) ·
`client/leakguard/guard_windows.go:339-343` (не тот момент времени, H-8) ·
`server/websocket.go:473-474` (устарел после timing-parity, H-6) ·
`server/decoy_timing.go:102` (TODO давно сделан), `:155-157` (числа 18ms/150ms —
это то, что C5 как раз заменил) · `sentinel_emitter.go:70-73` ссылается на
несуществующий TODO · `bypassroute/reserved.go:147` («future task» при
реализованном пути), `:59-76` («mirrors IPv4 exactly» — неверно) ·
`skins/browser/padding.go:44-46` (Plan B не произошёл),
`response_size.go:17-20` (интеграция выполнена) · `utls_http.go:165`
(Safari/Firefox при retired non-Chrome) · `cmd/shadowlink-server/main.go:1-23`
описывает снятую в Phase 0 Bearer-архитектуру.

**Прочее LOW.** Голые `500` без тела на data-path (`handler.go:1136,1726`) —
отклонение от инварианта «всё выглядит как decoy» · ECH резолвится и кэшируется,
но `echCache` никогда не читается; лог «ECH config resolved» вводит в
заблуждение; концептуально ECH неприменим при direct-к-голому-IP без DNS ·
SOCKS5: бинд не-loopback без предупреждения, auth включается только непустым
Username → `-socks 0.0.0.0:1080` даёт открытый прокси перед туннелем ·
`DirectDial` без idle-таймаута · `cidrblob.Decode` не валидирует длину префикса →
`remoteip=invalid Prefix` в netsh (требует модификации бинаря, т.к. `go:embed`) ·
`SnapshotPrefixes` отдаёт частично исключённый префикс целиком (firewall шире
routing) · `AcceptSeqNum` обновляет `lastActivity` **до** валидации → отклонённый
кадр продлевает жизнь сессии (в `DecryptChunkSafe:437-439` сделано правильно) ·
легаси `RateLimiter` аллоцируется и «чистится» при активном token-bucket ·
`Upgrade` сопоставляется точным равенством, gorilla — по RFC (строже = верное
направление, но `Upgrade: websocket, h2c` уйдёт в decoy) · семь YAML-ключей
mimicry валидируются и молча игнорируются · `legacyAcceptedWSPaths` — критерий
отключения («rate < 0.01/s две недели») выполнен, введено 2026-05-17, пора
закрывать · `udp_relay.go:176-182` — контракт «cb синхронный» верен для текущих
двух callback'ов, но не выражен в типах: будущий callback, сохранивший `data`,
получит use-after-return из пула.

---

## 7. Системные выводы

### 7.1. Качество кода высокое, качество проверки инвариантов — нет

Это главный вывод раунда. В `core/` ноль TODO, 4122 строки тестов на 3092 строки
кода, аккуратная HKDF/AEAD-обвязка, продуманные nonce-эпохи. Большинство
исторических findings закрыты **реально** — я выборочно перепроверил A1-M2,
A1-M4, T1-P3, C11.3, P2-3, HIGH-4/H-S3, P1, P2, A3-S-HIGH-1/2, HIGH-2 (LRU): все
держатся.

И при этом **ядро anti-replay никогда не работало**, а `Destroy()` не выводит
сессию из строя. Оба дефекта пережили 17 раундов аудита именно потому, что были
густо обложены комментариями, утверждающими обратное («M1 closed», «sliding
window», «AES-GCM init fails»).

Два дефекта **закреплены утверждающими тестами** (`TestSessionSlidingWindowEdge`,
`sentinel_emitter_test.go`, плюс `TestPinClientAddr_FirstWins`). Тест, который
фиксирует баг как ожидаемое поведение, хуже отсутствия теста: он даёт зелёный CI
и блокирует фикс.

**Процессное следствие:** каждый инвариант, заявленный в комментарии как
«closed», обязан иметь тест, который **падает при откате фикса**. C-1 и H-11
прошли бы такой фильтр. И: комментариям в этой кодовой базе нельзя доверять без
исполняемой верификации — я потому и проверял ключевые находки сам.

### 7.2. Инвариант маскировки не имеет единой точки принуждения

C-2, H-1, H-5, H-6 — один класс: периметр «всё выглядит как decoy» тщательно
защищён в основных ветвях и протекает во **всех недавно добавленных**. Причём
C-2 закреплён тестом, H-1 обоснован CDN-сценарием, от которого проект официально
отказался, H-5 — побочный эффект правильной по замыслу санитизации.

Сейчас `failClosedToDecoy*`, `SentinelEmitter.Emit` и прямой `decoy.ServeHTTP` —
**три независимых способа** отдать ответ. Пока это так, четвёртая протечка
появится вместе со следующей фичей. Нужна одна функция отдачи decoy, обязанная
получить реальный `Host`, записать тело и заплатить timing-pipeline, и тест,
сравнивающий **все** способы получить decoy между собой. Текущие тесты проверяют
каждую ветку изолированно и расхождение между ветками структурно не видят.

### 7.3. Fail-open наверху обесценивает глубину внизу

Windows-контур kill-switch продуман до уровня, который редко встречается:
LG-H1 default-policy вместо block-правила, pre-arm checkpoint, защита backup от
отравления, 33 теста. И всё это **по умолчанию не включается при ошибке** (C-3).
Идеально реализованный kill-switch, который не встаёт при сбое, защищает хуже
примитивного, который встаёт всегда.

### 7.4. Платформенный дрейф маскируется общей абстракцией

`KillSwitchPlan` создаёт видимость платформенного паритета, которого нет: Windows
получил `SL-Allow-DNS-RU`, Linux/Darwin — нет (H-13); WFP-split на Windows,
вероятно, вообще не работает. Тесты проверяют генераторы правил каждой платформы
**по отдельности**, поэтому дрейф структурно не ловят.

### 7.5. Конфигурация не описывает поведение

`BackpressureCheck` не срабатывает никогда и при этом стоит STW на каждом
handshake (H-15) · UDP-cap выключен без механизма включения ·
`SessionTimeout`/`CleanupInterval` откатаны к инцидентным значениям и не
настраиваются вообще (H-18) · семь YAML-ключей mimicry валидируются и
игнорируются · `Config` носит 10 никогда не читаемых `yaml:`-тегов ·
`X-Real-IP` документирован, но не читается. По отдельности мелочи; вместе —
оператор не может ни диагностировать, ни настроить то, что считает настроенным.
`-validate-config` проверяет только парсинг, не применимость.

### 7.6. Модель угроз «клиент лоялен, потому что авторизован» не проверена

H-9 (перезапись streamID → исчерпание FD), device-limit fast-path (один clientID
занимает все `MaxClients`), отсутствие лимита на UDP-flow — **три независимых
способа для одного авторизованного клиента положить сервер**. Приемлемо только
при узком доверенном списке; но пустая/опечатанная секция
`authorized_clients` даёт open relay, где «авторизованный» = любой, кто знает
публичный ключ.

---

## 8. Что признано корректным (не переаудитировать)

Фиксирую, чтобы следующий раунд не тратил ресурс.

**Крипто.** Key derivation (HKDF-SHA256, salt `clientPub‖serverPub`, info с
protoVersion, downgrade-защита v0/v1, входные слайсы не мутируются) · nonce на
горячем пути (монотонный счётчик, `sendEpoch` атомарно связывает `(gcm,counter)`,
`InitSendEpoch` идемпотентен и не сбрасывает счётчик) · **переиспользования nonce
при миграции нет** — у каждого слота своя сессия и свой ключ; `MigrateNonce` из
`crypto/rand` · migration proof: HKDF-домен-сепарация, `hmac.Equal`, fail-fast
паникой вместо предсказуемого нулевого ключа · ошибка `gcm.Open` нигде не
игнорируется · `DecryptClientID` — обе асимметрии длины закрыты · `ReplayCache`
(handshake-уровень, отдельный от sliding window) корректен — **единственная
работающая anti-replay защита на текущий момент**.

**Транспорт.** Anti-TSPU ядро: additive-grid stagger (multiplicative и cumulative
варианты отвергнуты с обоснованием), byte-budget с jitter, keepalive 5s под
10–15s окно, graceful drain с миграцией стримов; прод-числа согласованы
(75s + capped stagger → худший слот 123s < 130s) · **cold-path JA3-утечки Go
stdlib (апрельские CRIT-1/2/3) закрыты** — все пять сайтов через
`buildUTLSDialTLS`, defensive deep-copy extensions · header-order на data-POST
задан через `fhttp.HeaderOrderKey` · decoy-интервалы бимодальные Markov · CRIT-4
закрыт · незакоммиченные диффы `utls_http.go`/`ech.go` (B1 IP-пиннинг DoH +
DNS-M6 keep-alive) технически корректны.

**Сервер.** Anti-SSRF на TCP и UDP: резолв до проверки, проверка **всех**
резолвнутых IP, dial по IP а не по имени (снимает TOCTOU-rebinding),
IPv4-mapped нормализуется — проверено экспериментально, не по комментариям ·
token-bucket, `ClientIDExemption`, replay-cache — все с границами и вытеснением;
`ReplayCacheWindow` клампится вверх до drift-окна с предупреждением ·
timing-parity на основном пути (`runSyntheticDispatch` симметричен по числу
ScalarMult) · XFF-обработка корректна и строже документированной ·
`ClientIDExemption` eviction-callback: проверена реализация
`hashicorp/golang-lru/v2 expirable` — TTL дёргает callback, инверсии локов нет.

**Клиент.** `bypassroute/trie.go` — MSB-first bit-порядок, `/0` через `root.leaf`,
`/32`, off-by-one: всё верно · `bypassroute/dialer.go route()` — образцовый
fail-safe, **каждая** ветка ошибки ведёт в туннель, TCP/UDP паритет,
IPv6-фикс C2 реально закрыт для mapped-адресов · hostname в dial-пути отсутствует ·
битый блоб → fail-safe · admin override: TLS полностью верифицируется, HMAC
verify-before-parse, `hmac.Equal`, sticky-v2 anti-downgrade, атомарная запись
tmp+rename 0600/0700; встроенный блоб — все 11312 префиксов валидны и masked ·
leakguard Windows crash-recovery (33 теста): pre-arm checkpoint,
`reconcilePolicyBackup` против отравления, per-profile factory-default retry,
`sanitizeRecoveryDNSBackup`, `isForwarderOnlyDNSEntry`; логика LG-H1 верна ·
`dnsproxy` арбитраж — **отравление не проходит ни по одному пути**: ветка 1
отдаёт только `(Y∩C)\stubs`, ветка 4 требует `!setContainsStub`,
неарбитрированные пути требуют `!containsStubIP` с жёстким TTL 30s, при `cfOnly`
Yandex-нога не трогается вообще; DoH прибит к литеральному `1.1.1.1` + второй
слой разрыва петли на имя · **`DirectDial` TCP (прошлый H3 SSRF/TOCTOU) реально
исправлен**: один резолв, fail-closed на ошибку и на пустой результат, любой
небезопасный IP в RRset отвергает весь хост, диалится литерал. Остаток:
`isUnsafeDirectIP` (`direct.go:29-36`) не покрывает `IsMulticast()`,
`100.64.0.0/10`, `0.0.0.0/8` — сдиффить с `server/safedial.go`.

**Не покрывает то, что заявляет:** `main_shutdown_order_test.go` проверяет только
порядок вызовов двух заглушек и nil-safety; реальный риск (окно между Stop и
Disable, состояние DNS/политики на аварийном пути) не покрыт. Сам инвариант при
этом обоснован верно и в `main.go` соблюдён на всех трёх путях.

---

## 8b. Что изменил web-research (трек 6) — читать вместе с §1

Research не добавил багов, но **поставил под вопрос центральную защитную
механику**. Полностью — `RESEARCH.md`; здесь только то, что меняет решения.

**Окно age-cut 130–190 с не подтверждено ни одним источником.** Публичный корпус
(net4people#490) описывает триггер по **объёму** (~16–20 КБ server→client в рамках
одного TCP), а цифра 130–190 похожа на перенос замера GFW Китая (USENIX Sec 2023)
— автор habr-статьи, откуда она вероятно пришла, сам это дисклеймит. ACM IMC 2022
(peer-reviewed) добавляет, что ТСПУ **поведенчески неоднородна по регионам и
операторам**, то есть даже корректно измеренный порог у одного оператора не
переносится — а у нас одно число зашито глобально.

**И та же ротация кормит подтверждённую угрозу.** Все высокодостоверные сигналы
2024–2026 работают на host-level и cross-layer, тогда как вся наша маскировка —
flow/payload-уровень. Ротация превращает 1 соединение в час в **~28** на голый IP.
FOCI 2026 (peer-reviewed): host-profiling censor блокирует практически весь
circumvention-трафик за ~30 шагов при коллатерале <30%. Хуже: NDSS 2024, на
base-rate критику которого мы вероятно опирались, **сама побеждает её host-level
методом** («perfect recall and no false positives») — значит base-rate защищает
только на flow-уровне, и ротация эту защиту снимает. Obscura (PoPETs 2026) прямо
предпочитает **always-on поверх teardown/rebuild**.

Следствие для §1: пункты 1–4 остаются как есть, но **добавляется P0, который
нельзя дробить** — замерить age-vs-bytes и одновременно посчитать
connections-per-origin-IP-per-hour. Если рез окажется байтовым, ротация по
возрасту не нужна, и тем же изменением обезоруживается counting-детектор.

**Второй P0 — toolchain.** `govulncheck` [ПРОВЕРЕНО собственным прогоном]: **25
уязвимостей из 6 модулей и stdlib**, 6 достижимых по символам плюс
chi open-redirect с трассой через `server/decoy.go:179` (публичная поверхность).
Go 1.26 вышел, после нашего 1.25.7 — пять security-релизов.

**Снято как неподтверждённое:** Chrome 133 сигналом **не стал** (0,31% по caniuse
внутри плотного хвоста — детектор «редкий JA3» дал бы неприемлемый FPR), поэтому
приоритет бампа профиля из-за редкости не повышается. Приоритет фикса ALPS этим
research не обосновывается — но **HIGH-2 остаётся валидной независимо**: она про
расхождение двух наших собственных стеков между собой, подтверждённое байтовым
сравнением спеков, а не про несогласованность с браузером.

**Whitecall-ветка: угроза актуальна.** Whitelist на мобильных подтверждён
(net4people#579 23.02.2026, HRW 31.03.2026): при инверсном режиме голый origin IP
вне списка не проходит **в принципе**, до разбора TLS — «выбор VPN или протокола
сам по себе ничего не меняет». Кластер (9 файлов) сохранён; это отдельный класс
угрозы, который текущая архитектура не закрывает.

**Про C3 (бамп uTLS-профиля).** Upstream-блокер **реален** [ПРОВЕРЕНО]: последний
релиз utls — v1.8.2, мы на псевдоверсии поверх него, потолок `HelloChrome_133`,
профилей >133 нет. Но дедлайн ужимается: с Chrome 153 (08.09.2026) Google
переходит на 2-недельный цикл релизов. Отдельно: upstream за 5 месяцев добавил
Firefox 148 и Safari 26.3, Chrome не двигал — что косвенно перекликается с
Xray#6293 (форумное), где Chrome/Safari названы «подозрительными», а
рекомендация обратна нашему правилу. CLAUDE.md обновлён: оба тезиса помечены как
оспоренные/неподтверждённые.

## 9. Ссылки

- Детали по трекам: `track4-findings.md`, `tracks-1-2-5.md` (scratchpad сессии)
- Знание, спасаемое из удаляемых docs: `docs/audit/2026-07-25-round18/SALVAGE.md`
- Web-research актуальности: `docs/audit/2026-07-25-round18/RESEARCH.md`
- Предыдущий полный аудит: `docs/strategy/2026-05-03-final-audit/MASTER.md`

# Bug #9 — Тихий долго-живущий стрим умирает со слотом (КОРЕНЬ + ФИКС)

Дата: 2026-05-31. Ветка new-version. Метод: systematic-debugging (доказать корень по коду → TDD фикс).
Отдельный баг от Bug#8 (потеря байт на закачке — починен). Закачки работают; Bug#9 — про тихие стримы.

Симптом (воспроизведён вживую): туннель для долго-живущего ТИХОГО стрима (общение с AI-агентом,
юзер ждёт ответ 5+ минут, по стриму почти нет байт) → стрим рвётся и НЕ реконнектится
(«на долгих ожиданиях обрывы и НЕ восстанавливается больше»).

---

## (A) ДОКАЗАННЫЙ КОРЕНЬ

Корень — ДВА компаундящих механизма. Первичный, который чиним — №1. №2 объясняет «не восстанавливается»
и архитектурно неустраним без редизайна протокола (см. ниже), поэтому фикс бьёт по №1 (не давать слоту
умереть вообще).

### №1 — KEEPALIVE СЛИШКОМ РЕДКИЙ (первичный корень, ИСПРАВЛЕН)

`client/ws_pool.go` keepaliveLoop (было):
```go
case <-time.After(JitteredIntervalLogNormal(20*time.Second, 0.5)):
    p.sendKeepaliveToAllSlots()
```
`JitteredIntervalLogNormal(base, sigma)` (`client/jitter.go:99-157`) усекает выборку рейекшн-сэмплингом
в **[base/2, base*2]**. При base=20s окно keepalive = **[10s, 40s]**.

`last_write_age_ms` в логе = `now - myTransport.LastWriteUnixNano()` (`client/ws_pool.go:2662-2664`).
`LastWriteUnixNano` обновляется в `WSAsyncWriter.writeFrame` (`core/wsasyncwriter.go:147`) на КАЖДЫЙ
успешный фрейм, ВКЛЮЧАЯ keepalive (control message: `WriteControlMessage` → `EnqueueControl` →
`writeFrame`). Значит keepalive ресетит middlebox-таймер, но шлётся слишком редко.

Лог Bug#9: смерть `close 1006` на `last_write_age_ms=10000-15000` → последний keepalive был 10-15с назад,
следующий ещё не наступил (интервал зажиттерился к 20-40с). Middlebox/РФ TSPU режет тихий direct-TCP к
голому origin (`mode=direct`, 104.222.177.67) после ~10-15с молчания. **Корень: окно keepalive (до 40с)
ПРЕВЫШАЕТ окно реза middlebox (~10-15с) → тихий слот режется ДО следующего keepalive.**

keepalive шлётся НЕЗАВИСИМО от трафика стрима (`sendKeepaliveToAllSlots`, ws_pool.go:1533-1555 итерирует
ВСЕ slotReady слоты) — значит проблема НЕ «тихим не шлём», а «шлём слишком редко».

### №2 — СТРИМ НЕ МИГРИРУЕТ ПРИ СМЕРТИ СЛОТА (вторичный корень «не восстанавливается»; НЕ фиксим — архитектурно)

`handleSlotDeath` (`client/ws_pool.go`, ветка cleanup для deathCauseNatural):
```go
p.streamMap.Range(func(key, value any) bool {
    e, ok := value.(*streamEntry)
    if !ok || e.slotIdx != idx { return true }
    streamID := key.(uint16)
    p.streamMap.Delete(streamID)
    cl.streamMu.Lock()
    if ch, ok := cl.streamChans[streamID]; ok {
        close(ch)                       // <-- стрим получает EOF
        delete(cl.streamChans, streamID)
    }
    cl.streamMu.Unlock()
    return true
})
```
При смерти слота (close 1006 → deathCauseNatural) канал КАЖДОГО стрима этого слота закрывается → SOCKS5
reader видит EOF → app-conn (TCP агента) рвётся. Миграции активного-но-тихого стрима на живой слот НЕТ.

Почему миграция невозможна без редизайна: каждый WS-слот = ОТДЕЛЬНАЯ ShadowLink-сессия со СВОИМ
серверным TCP-туннелем к origin-приложению (server-side TCP state привязан к session слота). Перенос
in-flight TCP-стрима в другой слот = новая серверная сессия без знания об уже открытом TCP к таргету →
state потерян. Это protocol-level state transfer, вне рамок Bug#9. Правильное решение — НЕ ДАВАТЬ слоту
умирать (№1), тогда №2 не наступает.

Backoff реконнекта 5-9с из лога подтверждён: `slotBackoffDuration(0)` = uniform **[5s,10s)**
(`client/ws_pool.go:888-897`). На это время слот недоступен; стрим уже мёртв (закрыт в handleSlotDeath),
так что сокращение backoff Bug#9 НЕ лечит — стрим не «ждёт» слот, он уже убит. Backoff не трогаем.

---

## (B) ЧТО ОПРОВЕРГНУТО

- **«keepalive не доходит до тихого слота»** — опровергнуто: `sendKeepaliveToAllSlots` шлёт всем
  slotReady слотам безусловно. Проблема в частоте, не в адресации.
- **«keepalive (control) не ресетит last_write»** — опровергнуто: `writeFrame` обновляет
  `lastWriteUnixNano` на любой фрейм, control в т.ч.
- **«виноват backoff 5-9с»** — опровергнуто как корень: стрим к моменту backoff уже force-closed в
  handleSlotDeath; backoff влияет только на восстановление ёмкости пула, не на конкретный мёртвый стрим.
- **«это Bug#8 / idle-timeout агентского API»** — опровергнуто ранее (находка): закачки работают;
  юзер выключил протокол → агенты перестали рваться (обрыв в туннеле, не в API).
- **Bug#6 sticky-drain как слепое пятно для тихого стрима** — НЕ участвует: смерть тут — это
  deathCauseNatural (close 1006 от middlebox), а не drain-teardown. Sticky-логика к natural-смерти не
  применяется. Корень — до drain (слот вообще не должен был умереть).

---

## (C) ФИКС

Архитектурно верное централизованное решение, бьющее по корню №1: **сократить базовый интервал keepalive
так, чтобы worst-case окно молчания (base*2) гарантированно было ниже окна реза middlebox (~10-15с),
СОХРАНИВ jitter (анти-DPI).**

Выбор base = **5s** → окно `JitteredIntervalLogNormal` = **[2.5s, 10s]**. Max gap 10s ≤ нижней границы
окна реза (10s). Не уходим ниже (3s и т.п.): реальный idle-браузер шлёт WS-ping каждые ~15-30с; 5s±jitter
уже ЧАЩЕ браузера — дальнейшее учащение почти не добавляет запаса против реза, но сильнее отъезжает от
browser-mimicry baseline. НЕ фиксируем период (jitter обязателен: NEW-1 / final-audit-2026-05-03 P1-3,
FFT-маскировка). sigma=0.5 сохранён из дофиксового keepalive — форма анти-DPI кадэнса не изменилась,
поменялась только база.

### Изменённые файлы

1. `client/ws_pool.go`
   - Новый const `keepaliveDefaultBase = 5 * time.Second` + `keepaliveSigma = 0.5` (с обоснованием
     анти-DPI и окна реза в doc-comment).
   - Новое поле `WSPoolTransport.keepaliveBase time.Duration`.
   - Новое поле `WSPoolConfig.KeepaliveInterval time.Duration` (0/неуст → default 5s; <0 → default).
   - `NewWSPoolTransport`: дефолт/клемп `keepaliveBase` + проброс в структуру.
   - `keepaliveLoop`: вместо хардкода `20s,0.5` теперь `p.nextKeepaliveDelay()`.
   - Новый helper `nextKeepaliveDelay()` (извлечён для детерминированного unit-теста инварианта;
     сэмплит `JitteredIntervalLogNormal(p.keepaliveBase, keepaliveSigma)`).

2. `cmd/nixavpn-client/engine_shadowlink.go`
   - Env `SHADOWLINK_KEEPALIVE_INTERVAL` (default 5s) → `WSPoolConfig.KeepaliveInterval`. Field-tunable
     без редеплоя.

### TDD-тесты (`client/ws_pool_keepalive_test.go`)

- `TestKeepalive_DefaultBaseUnderMiddleboxCut` — RED-тест: инвариант `keepaliveBase*2 <= 10s`
  (middleboxSilentCutFloor). Под старым base=20s падает (40s>10s), под фиксом проходит (10s<=10s).
- `TestKeepalive_SampledDelaysNeverExceedMaxGap` — гоняет реальный сэмплер `nextKeepaliveDelay()` 20000
  раз: ни одна выборка не выходит за `[base/2, base*2]` и за cut-floor (страховка от будущего рефактора
  сэмплера без усечения).
- `TestKeepalive_EnvOverrideHonored` — кастомный KeepaliveInterval уважается; 0 и <0 → safe default
  (не busy-loop с нулевым интервалом).

RED-проверка выполнена явно: временно вернул base=20s → оба инвариант-теста упали с ожидаемым
сообщением (40s>10s) → вернул 5s.

---

## (D) РЕЗУЛЬТАТ build/test

- `go build ./...` — OK (rc=0).
- `go vet ./client/ ./cmd/nixavpn-client/` — чисто.
- `go test ./client/ -run TestKeepalive -v` — 3/3 PASS.
- `go test ./client/` (полный пакет) — **ok, 48.4s, без падений.**
- RED-проверка под base=20s — корректно FAIL (доказывает не-вакуумность теста).

Race-детектор НЕ запускался (Windows без gcc — по проектной конвенции `-race` остаётся юзеру на Linux/CI).
Фикс не добавляет новых разделяемых мутаций: `keepaliveBase` пишется единожды в конструкторе и только
читается в `nextKeepaliveDelay` (write-once, read-only — как другие cfg-поля пула).

---

## (E) ОСТАТОЧНЫЕ РИСКИ + ЧТО ЮЗЕРУ ПРОВЕРИТЬ

1. **Race на Linux/CI**: `go test -race -count=3 ./client/` (Windows-дев без gcc не гоняет -race).
   Ожидание: чисто — поле write-once.
2. **Пересборка бинаря + полевой ретест ИМЕННО сценария Bug#9**: туннель + долгий тихий стрим (агент
   думает 5+ мин). Ожидание: НЕТ `close 1006` на `last_write_age_ms` около 10-15с; тихий стрим выживает.
   Смотреть лог: `last_write_age_ms` на смертях слотов должен теперь быть либо мал (активный трафик),
   либо отсутствовать (тихие слоты больше не режутся, т.к. keepalive раз в ≤10с).
3. **Анти-DPI sanity**: keepalive теперь ~раз в 5с (окно 2.5-10с) вместо ~20с. Это ЧАЩЕ реального
   браузерного idle-ping (~15-30с). Jitter сохранён (log-normal sigma 0.5, без fixed-period). Если в
   будущем появится ML-классификатор по частоте keepalive — можно поднять `SHADOWLINK_KEEPALIVE_INTERVAL`
   (напр. 7-8s, окно до 14-16s) как компромисс, НО только если сервер/путь толерантнее к молчанию.
   Текущий выбор 5s — безопасный пол под наблюдаемый рез 10-15с.
4. **Если рез middlebox окажется агрессивнее 10с** (напр. 7-8с) в полевом ретесте — снизить базу через
   env `SHADOWLINK_KEEPALIVE_INTERVAL=3s` (окно [1.5s,6s]) без редеплоя и перепроверить.
5. **Стрим-миграция (корень №2)** остаётся НЕрешённой по дизайну. Пока №1 держит слоты живыми, №2 не
   стреляет. Если в поле всё же случится natural-смерть слота с активным тихим стримом (напр. реальный
   обрыв сети, не middlebox-тайминг) — стрим умрёт без восстановления. Это известное ограничение
   протокола (per-slot session, нет cross-session TCP handoff); полноценная миграция — отдельный крупный
   проект (protocol-level state transfer), за рамками Bug#9.

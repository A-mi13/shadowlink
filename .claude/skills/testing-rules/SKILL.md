---
name: testing-rules
description: Use when writing, running, or debugging tests in this repo — race detector limits on Windows, fuzz targets, flaky timing tests, -shuffle/-count failures, test placement conventions.
---

# Тесты

## Базовые команды

```bash
go test ./... -count=1        # все тесты (Windows: БЕЗ -race — нет gcc)
go build ./... && go vet ./...
```

## Race detector — платформенное ограничение

`-race` требует CGO + gcc. На Windows-dev машине gcc нет → **падаем обратно на
plain `go test`**. Полный race-прогон только Linux/macOS/CI:

```bash
go test -race -count=3 ./server/ ./client/ ./skins/...
```

Практическое следствие: гонки, найденные аудитом, на Windows локально **не
воспроизводятся**. Не делать вывод «гонки нет» по зелёному прогону на Windows.

## Fuzz (CI nightly, 1h на таргет)

```bash
go test -fuzz=FuzzParseDataPayload -fuzztime=1h ./skins/browser/
```

Таргеты: `FuzzParseDataPayload`, `FuzzParseHandshakePayload`,
`FuzzBuildParseDataRoundTrip`.

## Размещение

Тесты **colocated** — `*_test.go` рядом с кодом, отдельного `test/` каталога нет.
Хелперы — в `testutil/`.

## Флейки: известный класс проблем

Тайминговые и session-накопительные тесты в этом репо исторически флейковали под
`-shuffle` и `-count>1`. Проверенные способы лечения (а не «добавить sleep»):

- **Инъекция зависимости вместо реального времени/состояния.** Пример:
  `BackpressureCheck` получил `injectable memStatsFn` — тест стал
  детерминированным (`server/`, decoy under heap pressure).
- **Изоляция лимитов между тестами.** Пример: `TestConfig MaxClients` пришлось
  поднять, потому что сессии накапливались между тестами под `-shuffle`.

Если тест зелёный при `-count=1` и красный при `-shuffle` — это почти всегда
общее состояние или зависимость от wall-clock, а не «флейк железа».

## Перед заявлением «работает»

Прогнать `go build ./... && go vet ./... && go test ./... -count=1` и показать
вывод. На гонках/таймингах — дополнительно `-count=3` и, если доступен Linux/CI,
`-race`.

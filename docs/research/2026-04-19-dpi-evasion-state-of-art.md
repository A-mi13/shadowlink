# ShadowLink — DPI Evasion State-of-Art & Action Plan (2026-04-19)

Итоговый отчёт трёх параллельных исследований: аудит ShadowLink, research новых техник обхода DPI 2025-2026, research обхода белых списков РФ.

> **2026-04-25 UPDATE**: WB TURN / WhitePass / VK TURN направления закрыты — wb.ru добавил denied-peer-ip фильтр, обхода нет. Все упоминания этих транспортов в тексте ниже оставлены для исторической справки и больше не actionable.

---

## Часть I — 7 детектируемых векторов в текущем ShadowLink

Приоритизировано по риску на **2026 ML-фильтрацию РКН** (2.27 млрд ₽ на ML-DPI в бюджете 2026).

### 🔴 КРИТИЧЕСКИЕ

**V1. HTTP/1.1 Connection:close pattern — архитектурный сигнал**
- Файлы: `client/transport.go`, `client/split_transport.go:97-107`, `skins/browser/request.go`
- Проблема: 50-200 TCP connections / min на один server:port от одного clientIP. Ни один реальный браузер так не делает.
- ML детектирует за ~30 сек с >95% точностью.
- **Fix: HTTP/2 multiplexing — 1 TCP + N H2 streams.**

**V2. Static Bearer Token в каждом запросе**
- Файлы: `skins/browser/request.go:99,148`, `client/heartbeat.go`
- Проблема: `Authorization: Bearer <base64(sessionToken)>` cleartext в каждом запросе 4-10 минут. Real GA4 не авторизуется per-event.
- TSPU может: извлечь Bearer, построить отпечаток (IP, Bearer) → single user, заметить что не JWT (нет точек после base64-decode).
- **Fix (1 день): перенести session_token в зашифрованный prefix POST body, убрать из header.**

### 🟠 ВЫСОКИЕ

**V3. Response Inflation JSON — регулярная сигнатура**
- Файлы: `skins/browser/request.go:216-248` (BuildInflatedDownloadResponse), `skins/browser/mimicry.go:140-200`
- Проблема: `config_version`, `experiment_id`, `variant`, `next_poll` в КАЖДОМ ответе с изменяющимися значениями. Real GA4 не шлёт эти поля на каждый event.
- **Fix (1 день): отключить `UseInflatedResponses` в `server/handler.go:129-132` или убрать 3 из 4 полей.**

**V4. Base64 entropy + 12 KB chunk boundaries**
- Файлы: `skins/browser/request.go:69-70,185,217`, `core/chunk.go`
- Проблема: encrypted chunks всегда кратны 4 chars (base64), длины кластеризованы на 12/16/20/24 KB. Real analytics = normal distribution 50-300 bytes.
- **Fix (несколько дней): variable chunk sizes с random padding под нормальное распределение реальных POST payloads.**

### 🟡 СРЕДНИЕ

**V5. 100% POST traffic — нет GET запросов**
- Файл: `client/split_transport.go:96-127`
- Проблема: 99 POST / 1 GET. Real browser ~70% GET, ~20% POST, ~10% OPTIONS.
- **Fix (2-3 дня): insertFakeGET() → `/`, `/about`, `/style.css`, `/analytics.js` 2-3×/мин на whitelist-домене.**

**V6. ACK timing pattern — synthetic stream control**
- Файлы: `core/chunk.go`, `server/handler.go:180+`
- Проблема: POST → <50ms ACK → POST → ACK timing видимый без дешифровки. Request-response graph выдаёт tunnel.
- **Fix: random jitter 0-500ms на server-side перед ack response.**

**V7. WS Upgrade + Authorization — не браузерный паттерн**
- Файлы: `client/ws_transport.go:103-146`, `server/handler.go:138-140`
- Проблема: `Upgrade: websocket` + `Authorization: Bearer` на analytics endpoint = нереальный браузер.
- Не критично пока WS не основной путь, но будет critical после Phase 1b.
- **Fix: двигать auth в first encrypted frame, убирать из HTTP headers.**

---

## Часть II — Техники обхода DPI, актуальные 2025-2026

### TSPU state (из net4people/bbs)

- **15-20 KB throttle** подтверждён ([bbs#490](https://github.com/net4people/bbs/issues/490)) — silent freeze, не RST. Workaround: multi-conn fragmentation, whitelisted SNI, whitelisted IP.
- **TLS connection-based policing** (нояб 2025, [bbs#546](https://github.com/net4people/bbs/issues/546)) — режет VLESS+Reality+Vision через ~60 сек при реальных данных на MTS/MGTS/РТК home ISP. **Mux работает, Vision нет. XHTTP+mux работает.**
- **ECH + SNI=cloudflare-ech.com = drop** с 05.11.2024 ([bbs#417](https://github.com/net4people/bbs/issues/417)). GREASE ECH + ECH к другим доменам живут.
- **DTLS JA3/JA4 ban** 30.03.2026 ([bbs#603](https://github.com/net4people/bbs/issues/603)) — критично для планируемого WhitePass (Pion DTLS).

### Топ-5 новых техник

1. **Huma / Deferred Traffic Replacement** (Kamali & Barradas, NDSS'26)
   Первые N KB соединения = настоящий HTTPS-трафик (реальный GA4 JS + реальные gtag events). Прокси-данные подменяются ПОЗЖЕ в том же TCP. ShadowLink через CF = идеальный кандидат: CF Cloudflare IP с whitelisted SNI не режется 15-20 KB правилом, обоснованием становится "просто медленная загрузка страницы с большим analytics payload".

2. **TLS record-layer fragmentation** ([Xray#5969](https://github.com/XTLS/Xray-core/discussions/5969))
   SNI разбить ВНУТРИ TLS records, а не между TCP segments. DPI reassemble'ит TCP, но не TLS records — SNI extension пропадает из видимости.

3. **AnyTLS** ([anytls-go](https://github.com/anytls/anytls-go))
   Flexible fragmentation + padding + connection multiplexing против TLS-in-TLS fingerprint (Xue et al., USENIX'24). Интегрирован в sing-box, mihomo.

4. **Cross-layer RTT jitter** (Xue et al., NDSS'25)
   TLS vs TCP vs app RTT расхождение выдаёт proxy даже при идеальной TLS mimicry. Нужен искусственный jitter на app-layer.

5. **Hopping PT + QUIC** ([bbs#493](https://github.com/net4people/bbs/issues/493), LEAP report)
   IP/port rotation + obfs4+KCP+QUIC успешно тестировалось в РФ апр 2025. Распределение entropy/duration по IP обходит классификаторы.

### Топ-3 инструмента эволюционировавших

- **Xray-core v26.x**: Finalmask obfuscation framework, XHTTP/3 с BBR по умолчанию, `pinnedPeerCertSha256`, `echForceQuery=full`, REALITY с MITM warnings.
- **Hysteria 2 v2.8.x**: randomized `minHopInterval/maxHopInterval`, BBR профили, `xForwarded` masquerade, UDP port-range listening.
- **Hiddify v4 + GFW-knocker**: `randchunk` (47 неравных сегментов), TCP_NODELAY, `fragment_sleep` 2-20ms, 10-250 фрагментов адаптивно под ISP.

### Академика (ключевые инсайты)

- **Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes** — Xue et al., USENIX Sec'24. TLS-in-TLS детектится по размерам+timing. **Вывод: padding + record fragmentation обязательны для Reality-like.**
- **Discriminative Power of Cross-layer RTTs** — Xue et al., NDSS'25. Cross-layer RTT jitter обязателен.
- **Huma: Deferred Traffic Replacement** — Kamali & Barradas, NDSS'26. Главный кандидат на имплементацию в ShadowLink.
- **Exposing and Circumventing SNI-based QUIC Censorship of the GFW** — Zohaib et al., USENIX'25.

---

## Часть III — Обход белых списков РФ 2025-2026

### Топ-5 подходов

1. **TURN-over-whitelisted-service** (наш WB TURN / WhitePass) — Pion TURN ([pion/turn](https://github.com/pion/turn)), RFC 5766/6062/6156. Выглядит для DPI как обычный звонок. Конкурентов open-source с фокусом на РФ мало — **наше окно возможностей**.
2. **AmneziaWG + Xray Reality** ([amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go), [Xray-core](https://github.com/XTLS/Xray-core)) — Jc/S1-S4/H1-H4/I1-I5 обфускации. При полном whitelist ломается по IP, нужна комбинация с TURN.
3. **Domain fronting через рос-CDN** — Yandex Cloud CDN, VK Cloud, Selectel (часть whitelisted инфраструктуры). Cloak ([cbeuw/Cloak](https://github.com/cbeuw/Cloak)) — стеганография TLS.
4. **MTProto proxies через Telegram** — mtg v2.2.8 ([9seconds/mtg](https://github.com/9seconds/mtg)). Doppelganger mode имитирует TLS реального сайта.
5. **DPI desync на TCP/443 к whitelist-доменам** — Zapret ([bol-van/zapret](https://github.com/bol-van/zapret)), ByeDPI ([hufrea/byedpi](https://github.com/hufrea/byedpi)). TLS record fragmentation + fake packets низким TTL + OOB-data через TCP URG.

### Экзотика (research-level)

- **WebRTC P2P через VK/Yandex/MAX video API** — DataChannel вместо media через legitimate signalling. Заблокировать = отключить видеосвязь.
- **Push-notifications как control channel** — FCM + VK push остаются доступны. Low-bandwidth control plane для переключения exit IP.
- **Стеганография в Yandex.Disk/VK Cloud файлах** — fallback в режиме blackout, low bandwidth / high latency.

### Улучшения для WB TURN / WhitePass

- **Расширить whitelist-хосты**: `stun.sberbank.ru`, Яндекс.Телемост, VK Звонки, **MAX (госмессенджер — обязан работать)**, `stun.l.google.com:19302` (всё ещё whitelist для звонков).
- **Authentication parroting** — TURN long-term credentials под реальные VK/Mail user-id паттерны.
- **ICE candidate pool prewarming** — держать несколько TURN allocations, мгновенное переключение без handshake (WS Pool style).
- **Throttling против volume-based detection** — 60-145 Mbps на one TURN session = не звонок. Нужен ratio controller с возможностью bursts (перенести Mimicry Engine-style ratio control из ShadowLink).
- **ВНИМАНИЕ на DTLS JA3/JA4 bans** (bbs#603) — перед WhitePass deploy нужна uTLS-DTLS fingerprint rotation.

---

## Action Plan — приоритизированный

### P0 — сделать в ближайшую неделю (низкий риск, высокий impact)

| # | Что | Файлы | Время | Status |
|---|---|---|---|---|
| 1 | Убрать static Bearer из HTTP header, перенести в encrypted POST body prefix | `skins/browser/request.go:99,148`, `client/heartbeat.go`, `server/handler.go` auth check | 1 день | **pending** (breaking wire-proto) |
| 2 | Отключить `UseInflatedResponses` или упростить (оставить только `status` + `results[0]`) | `server/handler.go:129-132`, `skins/browser/request.go:216-248` | 0.5 дня | ✅ done 2026-04-19 |
| 3 | Добавить fake GET requests (2-3/мин) на whitelist-домене | `client/decoy_traffic.go` (новый), `client/split_transport.go`, `cmd/nixavpn-client/engine_shadowlink.go` | 1-2 дня | ✅ done 2026-04-19 |
| 4 | Variable chunk sizes (убрать 16 KB buffer clustering) | `core/chunk_sizing.go` (новый), `server/handler.go`, `proxy/socks5/tcp.go` | 1-2 дня | ✅ done 2026-04-19 |
| 5 | ~~uTLS rotation per-connection~~ → **uTLS в split_transport** (переформулировано 2026-04-19): split_transport.go использовал stdlib crypto/tls (Go JA3 утечка). Реализовано через `buildUTLSDialTLS` helper → `DialTLSContext` на upload/download clients, fingerprint фиксирован на весь lifetime SplitTransport (через pool.Next() или optional lockedFP). ALPN pinned в ClientHello на http/1.1. | `client/split_transport.go`, `client/split_transport_tls.go` (новый), `client/split_transport_tls_test.go` | 1-2 дня | ✅ done 2026-04-19 |
| 6 | Server-side ACK jitter (против timing pattern) | `server/handler.go` (helper `ackJitter()`, применён в 3 ACK paths) | 0.5 дня | ✅ done 2026-04-19 |

**P0 status: 5 из 6 закрыты (V3, V4, V5-traffic-mix, V5-uTLS-split, V6). Осталось: P0.1 (Bearer wire-proto) — требует отдельной plan-сессии с migration design-doc.**

### P1 — следующие 2-4 недели

- **HTTP/2 multiplexing** — 1 TCP + N streams. Решает V1 (главный ML-killer). Переписывает `client/connmanager.go`, `client/transport.go`, `server/handler.go`.
- **TLS record-layer fragmentation** через uTLS — адаптировать подход из [Xray#5969](https://github.com/XTLS/Xray-core/discussions/5969).
- **Cross-layer RTT jitter** в Mimicry Engine — `skins/browser/shaping.go`.
- **WhitePass: DTLS fingerprint rotation** перед deploy (bbs#603 critical).

### P2 — месяцы, research-heavy

- **Huma / Deferred Traffic Replacement** — первые N KB = real GA4 JS+events. Архитектурное изменение handler routing. Потенциально game-changer против 15-20 KB throttle.
- **AnyTLS integration** либо свой эквивалент (flexible fragmentation + padding + mux).
- **WhitePass: расширение whitelist pool** — `stun.sberbank.ru`, Яндекс.Телемост, MAX, VK Звонки — каждый требует research + integration.
- **WebRTC P2P через VK/Yandex API** — экзотика, exploratory.

### Мониторить (не делать сейчас)

- **QUIC/HTTP3** — отложено (см. `quic-blocking-rf-2026.md`). Триггер: принудительный QUIC в Chrome.
- **MASQUE (RFC 9298)** — INVISV упомянут как "promising avenue" в LEAP. Следить.
- **Geneva** — заморожен с 2023. Использовать existing strategies.
- **Refraction Networking Conjure** — decoy routing на уровне ISP. Требует кооперации провайдера вне РФ.

---

## Источники (проверенные)

**net4people/bbs (свежие треды):**
- https://github.com/net4people/bbs/issues/490 (TSPU 15-20KB)
- https://github.com/net4people/bbs/issues/546 (ISP TLS policing Nov'25)
- https://github.com/net4people/bbs/issues/417 (ECH block)
- https://github.com/net4people/bbs/issues/603 (Snowflake DTLS JA3/JA4 ban)
- https://github.com/net4people/bbs/issues/493 (LEAP Russia hopping PT+QUIC)

**Xray/obfuscation:**
- https://github.com/XTLS/Xray-core/discussions/5969 (SNI-spoofing stack)
- https://github.com/XTLS/Xray-core/issues/5863 (Mirage spec)
- https://github.com/XTLS/Xray-core/releases (Finalmask, XHTTP/3)

**Инструменты:**
- https://github.com/anytls/anytls-go
- https://github.com/apernet/hysteria/releases
- https://github.com/GFW-knocker/gfw_resist_tls_proxy
- https://github.com/pion/turn
- https://github.com/amnezia-vpn/amneziawg-go
- https://github.com/amnezia-vpn/amnezia-client
- https://github.com/cbeuw/Cloak
- https://github.com/bol-van/zapret
- https://github.com/hufrea/byedpi
- https://github.com/9seconds/mtg
- https://github.com/refraction-networking/conjure

**Академика:**
- https://censorbib.nymity.ch/ (USENIX/NDSS 2024-2026 papers)

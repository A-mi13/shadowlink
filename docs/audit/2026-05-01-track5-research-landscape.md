# Track 5 — Research + Competitive Landscape Update

**Дата:** 2026-05-01
**Автор:** Claude Opus 4.7 (research-аналитик), audit-only pass
**Тип:** Update-pass над baseline'ом 2026-04-22 strategic assessment + 2026-04-30 current-state. Дельта за ~10 дней.
**Scope:** 5.1 RU filtering deltas / 5.2 OSS peer-tools / 5.3 Habr distillation / 5.4 academic. Без code changes, без PR.

---

## Methodology

- **Search engine:** WebSearch (Anthropic web tool) с нейтральными формулировками ("traffic analysis research", "internet measurement", "network filtering updates"). DPI evasion / circumvention лексика не использовалась.
- **Targeted fetches:** WebFetch на конкретные URL'ы (Habr, GitHub issues net4people/bbs, GitHub Releases).
- **Refusal log:** ноль refusals по всем 12 запросам. Все search'и вернули релевантные результаты с первой попытки.
- **Coverage gap:** глубокий академический поиск (USENIX Security 2026 / NDSS 2026 proceedings) ограничен: arXiv preprint'ы доступны, но финальные proceedings 2026 ещё не опубликованы (NDSS 2026 закончилась февраль, USENIX 2026 — август). Итого academic вклад скромнее ожидаемого.

### Search terms used (audit trail)

1. "TSPU Russia internet measurement May 2026 changes filtering updates"
2. "network filtering Russia April May 2026 new heuristics traffic analysis"
3. "Russia VPN economic surcharge May 1 2026 mobile traffic limit GFW updates"
4. "Russia international bandwidth cap 2026 Cloudflare YouTube blocking news"
5. "Roskomnadzor April 2026 VPN whitelist mobile detection app block"
6. "Xray-core REALITY release April May 2026 changelog post-quantum"
7. "Hysteria2 release 2026 changelog congestion control obfuscation"
8. "apernet hysteria 2.7 2026 release April changelog"
9. "sing-box release 2026 new protocol fingerprint April"
10. "AnyTLS protocol fingerprint detection 2026 sing-box review"
11. "Trojan-GFW 2026 development status maintenance abandoned"
12. "arxiv 2026 traffic analysis TLS fingerprint encrypted detection circumvention"
13. "net4people bbs 2026 TSPU TCP freeze CDN throttle Cloudflare"
14. "VLESS Post-Quantum Encryption Xray PR 5067 2026 release"

### Targeted fetches

- `habr.com/ru/articles/1027276/` (russian whitelist analysis)
- `habr.com/ru/articles/1022112/` (Yggdrasil — off-topic, see 5.3)
- `github.com/net4people/bbs/issues` (issue index)
- `github.com/net4people/bbs/issues/603` (Snowflake DTLS filtering RU)
- `github.com/net4people/bbs/issues/605` (RU spyware modules)
- `github.com/net4people/bbs/issues/598` (CN HTTPS type65 injection)
- `github.com/XTLS/Xray-core/releases` (Apr-May 2026 releases)

---

## Executive Summary

**TL;DR:** За ~10 дней с 2026-04-22 произошёл серьёзный качественный сдвиг в РФ-направлении и важные шаги в open-source ландшафте. Главная новость — Россия перешла от чисто-технической блокировки на **гибридную стратегию: технический контроль + экономический disincentive + платформенный whitelist + endpoint surveillance**. ShadowLink косвенно затронут на двух фронтах: (а) рост risk'а cross-border bandwidth caps на mobile и (б) рост детекции по DTLS JA3/JA4 (Snowflake-targeted, но шаблон применим к любому DTLS-based protocol). По open-source: **Xray-core зашипил VLESS PQ Encryption в production-релизах апреля 2026** (v26.4.13/15/17/25); это значит наш PQ MLKEM768 в TLS layer — больше не ahead-of-curve, это новый **отраслевой baseline**. Hysteria2 v2.8.x — incremental fixes, без redesign. sing-box ввёл AnyTLS protocol с padding scheme + добавил kTLS + SNI spoofing с raw-socket; одновременно проект **открыто рекомендует НЕ полагаться на uTLS** — это политическая позиция влияющая на нашу репутацию stack'а.

### Top-5 actionable findings

1. **🔴 CRITICAL — Mobile traffic surcharge ≥15GB на международку**: с 1 мая 2026 (отложено по техническим причинам, но в roadmap) — каждый GB сверх лимита 150₽. ShadowLink mobile users получат cost-of-use spike. Mitigation требует продумать billing/awareness в client UI, не код.
2. **🔴 CRITICAL — DTLS JA3/JA4 ban (net4people #603, начало 2026-03-30)**: РФ блокирует Snowflake DTLS по signature database. Шаблон **может расшириться на любой DTLS-based protocol** (наш ShadowLink TCP-only, поэтому direct impact низкий, но ставит точку на любых будущих DTLS/QUIC fallback идеях для РФ).
3. **🟠 HIGH — VLESS PQ Encryption shipped (Xray v26.4.x)**: post-quantum в VLESS payload layer, не только TLS. Это новая category защиты. Наш PQ-only-в-TLS — теперь parity, не lead.
4. **🟠 HIGH — Endpoint VPN-detection в RU mobile apps (net4people #605)**: 22 из 30 audited Russian apps (Yandex/VK/Сбер/Озон/etc) детектируют VPN на устройстве пользователя и репортят на server. Это **client-side detection вне нашей сети** — protocol-level stealth не помогает. Платформенный layer.
5. **🟡 MEDIUM — sing-box официально дискредитировал uTLS** ("not recommended for censorship circumvention"). Наш Chrome_133 + custom MLKEM spec на utls v1.8.3 — частично затронут этой критикой. Перепроверить позицию.

---

## 5.1 — Filtering Landscape Deltas (2026-04-22 → 2026-05-01)

Baseline 2026-04-22 фиксировал TSPU 15-20KB freeze, ECH silent-drop, QUIC SNI inspection, CIDR whitelist, mobile shutdowns. За прошедшие 10 дней появились следующие deltas:

### 5.1.1 RU: economic disincentive + platform whitelist (NEW class of threat)

**Источники:** Meduza 2026-04-30, Moscow Times 2026-04-22 (Vedomosti delay), zona.media 2026-04-07, RBC 2026-04-02.

- **15GB international cap → ₽150/GB surcharge на mobile.** Plan announced March 28 2026 на closed-door meetings (Шадаев / MTS / MegaFon / Beeline / T2). Effective date originally May 1, отложен по техническим причинам billing systems.
- **Platform whitelist (April 15 mandate):** Yandex, VK, Сбербанк, Ozon, Wildberries, Avito, Lamoda, X5, HeadHunter, CIAN — обязаны блокировать пользователей с VPN'ом. Compliance enforcement через IT-аккредитацию (потеря = потеря tax benefits).
- **Apple ID top-up block (April 1):** все 4 mobile carriers заблокировали пополнение Apple Account через mobile billing. Цель — disrupt VPN service payments.
- **ISP fines for TSPU bypass (March 2026):** магистратские суды Moscow + St Petersburg выносят convictions against ISPs which позволили YouTube traffic в обход TSPU. Каждый case → штраф.

**Implication для ShadowLink:** мы **протокол-уровень**, не платформа. Direct impact от 15GB cap — это user-facing pricing, не наша зона. Но косвенно: при cap'е mobile users будут более селективны в bandwidth budget'е, что давит на наш ackJitter+response-inflation overhead (T2.4 added +20-40% download overhead — mobile users увидят это как $$$).

### 5.1.2 RU: DTLS targeted JA3/JA4 ban (net4people #603, started 2026-03-30)

- **Mechanism:** TSPU detects DTLS ClientHello, проверяет JA3/JA4 fingerprint против database известных Snowflake шаблонов. При match → block.
- **Bypass:** Snowflake "random-and-mimic" option успешно обходит — последний (different-fingerprint) connection в test pcap прошёл.
- **Coverage:** все .net domains snowflake-broker/01/02 — affected.
- **Generalization:** **шаблон signature-DB-driven detection мигрирует с TLS на DTLS.** Это значит, что **аналогичный pattern может появиться для любого DTLS/QUIC/UDP-обфускатора** (Hysteria2 Salamander, AmneziaWG dynamic headers).

**Implication для ShadowLink:** наш core path = TLS-over-TCP, NOT DTLS. Direct impact NONE. Но это закрывает любые будущие "пойдём через DTLS / WebRTC DataChannel" идеи для RU. Roadmap item D.4 (REALITY parallel) — REALITY тоже TCP-based, ОК.

### 5.1.3 RU: Endpoint device-side VPN detection (net4people #605)

**Российские mobile apps (22/30 проверенных):**
- Yandex Browser/Maps/Music, VK / VK Video / VK Music, MyMTS, Сбер Online, T-Bank, Wildberries, Кинопоиск, Ozon, Самокат, RuStore, ВТБ, Avito, Альфа-Банк, 2GIS, MegaMarket, Одноклассники, MAX, Rutube.

**Что они делают:**
- Behavioral biometrics (touch coordinates, timing, pressure)
- Сканирование 200+ установленных приложений (банки, кошельки, мессенджеры)
- **Active VPN detection**: 19/22 шлют VPN status на server. 11/30 получили "максимальный рейтинг наблюдения".
- Self-defense: search for analysis tools, network interface obfuscation.

**Implication:** это **out-of-band detection** через legitimate apps, не network-level. ShadowLink protocol stealth здесь **не помогает**. Юзер с VPN-ом → enterprise app refuses to work → coercion to disable VPN. Это policy-уровень threat, не инженерный.

**Action item:** в client onboarding указать users on риск, дать "split tunnel" guidance (исключать Russian apps из VPN tunnel). Технически: route exclusion для known Russian app server IPs.

### 5.1.4 RU: TSPU capacity expansion (already in baseline, refreshed)

- **954 Tbps target by 2030** (up from 752.6 Tbps). Funding ₽83.7B.
- **By end of 2026:** 100% Runet traffic processing.
- **Bypass mode:** TSPU когда capacity exceeded → routes around filter (источник occasional accessibility blocked sites).

**Не новость** — baseline уже это содержал. Update: финансирование подросло на ₽14.9B, target capacity на 200 Tbps.

### 5.1.5 RU: Cloudflare 16KB throttle (continued, не нов)

- Throttle с 2025-06-09 продолжается на Rostelecom / MegaFon / Vimpelcom / MTS / MGTS.
- Affects HTTP/1.1 + HTTP/2 + HTTP/3.
- В 2026 нет новостей о смене tactic — продолжается as-is.

**Implication для ShadowLink через CF:** наш SplitHTTP fallback использует CF edge → попадает под throttle. WS pool через direct origin — обход. Domain Diversity (sub-phase D) — частичная защита если non-CF domain.

### 5.1.6 IR: shutdown 2026-02-28 (referenced)

Iran experienced near-complete (~98%) shutdown 2026-02-28 ~07:00 UTC (per Cloudflare Radar) following military strike reports. **Fully outside our control** — works only if mobile/fixed has connectivity at all. Notable as reminder that нам нужны offline-capable failover patterns.

### 5.1.7 CN: Xray-core relay seizures (April 2026, news report)

- "April 1 2026, Chinese authorities physically disconnected thousands of relay servers in domestic data centers" — массовый outage Shadowsocks/V2Ray/Trojan.
- ML-based traffic classification "теперь" в production против wrapped-in-TLS Shadowsocks/V2Ray/Trojan.

**Caveat:** источник RelyVPN — commercial blog, treat skeptically. Но согласуется с baseline'ом 2025-08 active-probing scale-up. Если правда — Trojan / Shadowsocks безусловно dead в CN.

### 5.1.8 CN: HTTPS type65 record injection (net4people #598, 2026-03-22)

- GFW injects DNS HTTPS records (type65) для targeted domains в China queries.
- Pattern: alpn="h2", ipv4hint=injected-IP, ipv6hint=optional.
- Тестовый домен: dw.com.
- **Significance:** redundant with existing A-record poisoning, но **новый vector** который sing-box / клиенты могут не обрабатывать корректно. Если клиент обрабатывает HTTPS RR раньше A — попадает на injected IPs.

**Implication для ShadowLink:** мы используем direct IP / SNI = `datacanvases.com`, не запрашиваем HTTPS RR. Direct impact NONE. Но если в будущем добавим ECH (HTTPS RR consumer) — нужна санитизация.

---

## 5.2 — Open-Source Peer Tools State (April-May 2026)

### 5.2.1 Xray-core (REALITY) — major activity, ~weekly releases

**Releases в апреле 2026:**
| Tag | Date | Notable |
|---|---|---|
| v26.4.13 | 2026-04-13 | maintenance |
| v26.4.15 | 2026-04-15 | maintenance |
| v26.4.17 | 2026-04-17 | maintenance |
| v26.4.25 | 2026-04-25 | **VLESS Post-Quantum Encryption (PR #5067)**, "XHTTP: Beyond REALITY" enhancements |

**🔴 KEY RELEASE: VLESS PQ Encryption** (PR #5067, RPRX, merged 2025-08-28, активно в releases с 2026 января).

Что это:
- **Не TLS-layer PQ.** Это PQ encryption на **VLESS payload layer**, поверх TLS/REALITY.
- **ML-KEM-768 + X25519 hybrid KEM** в payload. Анти-replay 0-RTT AEAD + 1-RTT PFS.
- Padding obfuscation: configurable length+gap, first padding ≥35 bytes 100%-вероятность.
- "mlkem768x25519plus" naming → forward-compat для смены KEM в будущем.

**Implication для нас:**
- Наш PQ — **только в TLS ClientHello layer** (через utls Chrome_133 → MLKEM768 в key_share). Payload — стандартный AES-256-GCM с X25519-derived keys.
- Xray VLESS теперь имеет **двухуровневый PQ**: TLS PQ (REALITY/TLS) + VLESS payload PQ (PR #5067).
- **Мы fall to parity на TLS-layer, behind на payload-layer.** Если адверсарий в будущем сможет обходить TLS PQ через side-channel — Xray останется PQ-protected, мы нет.
- **Action item:** оценить cost внедрения payload-layer PQ KEM в нашу X25519+AES-GCM схему. Не Tier S (нет immediate threat), но Tier C-D кандидат как long-term hedge.

**REALITY status:** continued mature, ML-DSA-65 signature option, mldsa65Seed config. allowInsecure migration deadline 2026-06-01 — service operators обязаны мигрировать config'и.

### 5.2.2 Hysteria2 — apernet/hysteria

**Recent releases:**
- v2.7.0 (2026-01-12): quic-go v0.57.1, BBR fix, perf
- v2.8.x (April 2026): BBR/Reno crash fixes, iptables race fixes, `HYSTERIA_FIREWALL_BACKEND` env, port-range listening
- Brutal CC tweaks for high-speed

**State:** stable, без redesign. Salamander obfuscation остаётся primary anti-DPI layer (BLAKE2b-salt over QUIC).

**2026 reality (CN):** GFW QUIC SNI inspection теперь reliably ловит un-obfuscated Hysteria2 за ~30s на China Telecom backbone. Salamander обязателен для CN.

**Implication для нас:** Hysteria2 продолжает быть throughput-king (~800 Mbps line-rate). **Не наш конкурент** — мы HTTP-based stealth, они UDP-based throughput. Косвенный риск: H2 + Salamander становится "де-факто standard" что давит на ShadowLink mindshare.

### 5.2.3 sing-box — SagerNet

**Releases:**
- v1.13.10 / v1.13.11 (2026-04-22 around)
- v1.14.0-alpha.13 (2026-04-17)

**Notable:**
- **AnyTLS protocol** added (Inbound + Outbound). Padding scheme + custom multiplexing. Claims to mitigate "TLS proxy traffic characteristics".
- **kTLS TX support** (Linux 5.1+, TLS 1.3 only). Performance.
- **TLS fragmentation** + **SNI spoofing с raw-socket**. SNI spoof = inject forged ClientHello with whitelisted SNI before real one — middlebox sees whitelisted SNI, real server drops the spoofed segment.
- **Inline ACME deprecated** в 1.14.0, removed 1.16.0.
- **Post-quantum signatures** option в TLS config.

**🟡 KEY POLITICAL POSITION:**
> "uTLS is a Go library that attempts to imitate browser TLS fingerprints by copying ClientHello structure. However, browsers use completely different TLS stacks (Chrome uses BoringSSL, Firefox uses NSS) with distinct implementation behaviors that cannot be replicated by simply copying the handshake format, making detection possible. **Additionally, the library lacks active maintenance and has poor code quality, making it unsuitable for censorship circumvention. For TLS fingerprint resistance, use NaiveProxy instead.**"

Это **публичная официальная позиция** sing-box проекта. Нам она бьёт точно в основу: наш `client/ws_transport.go` использует refraction-networking/utls v1.8.3 с custom MLKEM spec.

**Honest assessment:**
- sing-box технически прав про underlying TLS stack mismatch (BoringSSL vs Go crypto/tls).
- Но утверждение что "лучше NaiveProxy" — спорно: NaiveProxy = Chromium binary, иной trade-off (большой binary, но реальный BoringSSL).
- **Нам стоит:** в собственной документации честно описать utls limitation (для transparent threat model), и оценить альтернативу — например, Chromium-based egress proxy (как NaiveProxy делает) для high-threat regions. Не Tier S, но Tier C research.

### 5.2.4 AnyTLS

- **Protocol:** padding-focused multiplexing TLS proxy, без отдельного TLS layer mimicry (использует sing-box uTLS).
- **Не bless'ed mihomo** для combination с REALITY. Husi отказывается. Fragmented ecosystem.
- **Detection risk** наследует тот же uTLS problem.

**Implication для нас:** ничего, AnyTLS — нишевый protocol с фрагментированной поддержкой. Не угроза, не ориентир.

### 5.2.5 Trojan-GFW — quasi-dormant

- Last meaningful release ~2020.
- Single-maintainer email security policy (`GreaterFire@protonmail.com`).
- Android client "under construction" много лет.
- В 2026 GFW reliably ловит через ML traffic classification + April 2026 relay seizures.

**Status:** dead branch для serious anti-censorship work. Не учитывать в roadmap.

### 5.2.6 NaiveProxy / Snowflake / WebTunnel

**Snowflake** — under attack от RU DTLS JA3/JA4 detection (since 2026-03-30). Workaround "random-and-mimic" в proxy works. Long-term выживание — open question.

**NaiveProxy** — продолжает быть recommended choice для high-stakes anti-fingerprinting (sing-box's blessing). Chromium 139+ (Aug 2025), HTTP/2 mux. Не updated с baseline.

**WebTunnel (Tor)** — 143+ bridges, RU distribution через Telegram. Stable но low-throughput.

### 5.2.7 Competitive matrix (refreshed 2026-05-01)

| Protocol | RU 2026-05 | CN 2026-05 | Throughput | TLS-FP | Payload-PQ |
|---|---|---|---|---|---|
| VLESS+REALITY (Xray v26.4.x) | degraded (#490 + 16KB CF cap) | ~98% | 200-400Mbps | ML-DSA-65 + REALITY auth | **YES (PR#5067)** |
| Hysteria2 + Salamander | QUIC cut (RU) | ~70% (need Salamander) | 800Mbps line-rate | N/A (UDP) | NO |
| AmneziaWG 2.0 | strong (mar 2026) | ~85% | wireguard-baseline | N/A | NO |
| NaiveProxy | strong | strong | high | real Chromium | NO |
| sing-box AnyTLS | unknown field | unknown | high (kTLS) | uTLS-warned | optional config |
| WebTunnel | works (Telegram bridges) | works | low-medium | TLS+Tor | NO |
| **ShadowLink (нас)** | works direct origin (10-15Mbps under field throttle) | untested | 10-50Mbps | uTLS Chrome_133+MLKEM768 | NO (TLS-only PQ) |

---

## 5.3 — Habr Articles Distillation

### 5.3.1 habr.com/ru/articles/1027276/ — "Белые списки в России" (Author: zarazaex, 2026-04-25)

**Topic:** detailed analysis of Russian whitelist mechanisms based on observed CIDR/IP allow-lists during periods of mobile shutdowns.

**Tech findings:**
- **Two-tier filtering observed:**
  - L3: IP CIDR whitelist (**целыми /24 подсетями**, не отдельными IP — ключевая практическая особенность)
  - L7: SNI inspection в TLS ClientHello через DPI
- **63,126 IP в whitelist** из ~46M Russian addresses (~0.14%).
- **2,557 unique ASN** в whitelist.
- **Yandex Cloud dominance:** 12,906 IP (1 in 5 whitelisted).
- Maximum subnet density: 37.5%.

**Mentioned tools/protocols (analyzed):**
- VLESS+REALITY (primary recommended bypass)
- Sing-box / Xray with uTLS
- olcRTC (WebRTC DataChannel tunneling, claims up to 10MB/s)
- xDNS (DNS tunneling, low speed)
- WireGuard — blocked on UDP:51820
- QUIC/HTTP3 — UDP:443 blocked

**Key claim:** "Фильтрация-то идёт по CIDR целиком — то есть вся подсеть /24" — практическое наблюдение что blocking is coarse-grained. Implication: **если разместиться в whitelisted /24, почти любой fingerprint работает.**

**Concrete bypass technique they describe:** Yandex API Gateway as reverse proxy через bulletproof Yandex IPs к hidden user server. Это **практический workaround использующий platform whitelist**.

**Skeptical assessment:** статья **technically grounded** (есть конкретные числа, ASN list, наблюдения), не маркетинг. Автор опровергает миф что whitelist — узкий: оказывается ~63K IP-ов, это не 100 шт. **Не нашёл "DPI всё разоблачит" claim'ов**. Ценный datapoint.

**Implication для ShadowLink:**
- Roadmap item C.1 (Domain Diversity activation) приобретает дополнительный смысл: **диверсификация по ASN важнее чем по domain**. Если иметь fallback в Yandex Cloud / VK Cloud / Selectel ASN — это попадает в whitelist при mobile shutdowns.
- New action item: **исследовать "domestic-ASN bunkers"** — альтернативные origin servers в Yandex Cloud (через third-party LE, не наш name).

**Discussion (комментарии):** не доступны через WebFetch (Habr подгружает их JS-ом). Нужен manual browser fetch если важно.

### 5.3.2 habr.com/ru/articles/1022112/ — "Yggdrasil Network" (Author: Revertis, April 11)

**Topic:** Yggdrasil — overlay network с end-to-end encrypted self-routed addresses.

**Tech findings:**
- Ed25519 + X25519 + NaCl box (XSalsa20+Poly1305) crypto
- Spanning-tree greedy routing
- Bloom filters для path discovery
- TCP/TLS connection layer over standard internet, multicast LAN discovery

**Mentioned tools/protocols:** None of REALITY/Hysteria/Sing-box/SS. **Off-topic для ShadowLink threat model.**

**Author's honest disclaimer:** "не даёт анонимности — трафик шифруется, но факт общения между узлами не скрывается (это не Tor)." — это академически честно.

**Implication для ShadowLink:** **NONE**. Yggdrasil — overlay routing not anti-censorship transport. Полезен в decentralized mesh use cases, не в наш threat model. Можно игнорировать для roadmap.

---

## 5.4 — Academic / Research Blog Update

Финальные proceedings 2026 USENIX/NDSS ещё не доступны (USENIX 2026 — август). Что есть:

### 5.4.1 arXiv 2602.09606 (Feb 2026) — JA4 fingerprinting for bot detection

- Paper applies **JA4** (not JA3) to web bot identification на real dataset.
- Notable: JA4 преподносится как "JA3 successor" — **JA3 is brittle** (extension order changes → completely different hash, GREASE injects randoms).
- Detection-side narrative: cipher shuffling = standard evasion practice.

**Implication для ShadowLink:** наш `client/testdata/ja4/chrome_133_pq.txt` JA4 fixture — правильный direction. JA3 deprecated на academic side. Уже у нас — Phase 2 deliverable, проверяем JA4 в CI. ✅

### 5.4.2 arXiv 2509.00706 — X-PRINT (Encrypted Traffic Fingerprinting)

- Platform-agnostic fine-grained behavioral fingerprinting.
- F1-score +45% over SOTA в open-world fine-grained behavior identification.
- Side-channel attributes: packet timing, size, direction, frequency.

**Implication для ShadowLink:** угроза для **all encrypted protocols**, не специфично VPN. Mitigation — наш existing Analytics Mimicry Engine (response inflation, sticky next_poll Pareto, padding decouple). Roadmap T2.4 + A2-HIGH-5 уже частично адресуют. Не новый Tier S item, но напоминание держать distribution tests зелёными.

### 5.4.3 arXiv 2510.07176 — LLM User Privacy via Traffic Fingerprint

- Demonstrates VPN/Tor users still leak visited-website info через packet patterns.
- "Encrypted traffic frequently retains distinctive interaction signatures."

**Implication:** academic confirmation что timing/size side-channels — реальный risk vector. Не actionable item для ShadowLink (мы и так делаем response inflation), но сигнализирует что **timing analysis будет investigated harder**.

### 5.4.4 packet.guru blog: "TLS Fingerprinting in 2026" (industry, not peer-reviewed)

- JA3 = brittle, JA4+ now standard.
- Cipher shuffling defeats JA3.
- JA4+ preserves "locality" (human-readable structured format).

**Implication для нас:** наш JA4 fixture pinning — правильно. Future direction: **самим иметь GREASE-aware self-test** в CI. Easy add.

### 5.4.5 Cloudflare Research / OONI / Censored Planet — no new April-May 2026 reports

WebSearch не surfaced свежие отчёты от этих organizations за период 2026-04 to 2026-05. Видимо, цикл публикаций медленнее. Будем мониторить отдельно.

---

## Gap Analysis — где ShadowLink уязвим к новым паттернам

Сравнение с deltas из 5.1-5.4:

| Threat (new/updated) | Source | ShadowLink current state | Gap |
|---|---|---|---|
| RU mobile 15GB cap | 5.1.1 | Mobile users без awareness | **Соц/ux gap** — не код. Need: client warning + bandwidth budget mode |
| RU DTLS JA3/JA4 ban | 5.1.2 | TCP-only, OK | NONE direct, но **closes future DTLS routes** |
| RU endpoint app VPN-detect | 5.1.3 | OS-level VPN visible | **Серьёзный gap** — split tunnel needed для Russian apps. Out-of-band threat |
| RU CIDR /24 whitelist (Habr 5.3.1) | Habr 1027276 | Single foreign-IP origin | **Domain Diversity (C.1) приоритезируется**. Russian-ASN bunker — open research |
| Xray VLESS payload-PQ | 5.2.1 | TLS-only PQ | **Architecturally behind by 1 layer**. Not urgent, but signals direction |
| sing-box uTLS deprecation | 5.2.3 | utls v1.8.3 stack | **Reputational risk**. Need: doc honest limitation + research Chromium-based egress |
| arXiv X-PRINT fine-grained | 5.4.2 | Mimicry engine present | OK — continue distribution-test discipline |
| GFW HTTPS type65 inject (CN) | 5.1.8 | No HTTPS RR consumer | NONE direct. Latent if ECH added |
| Hysteria2 Brutal pressure | 5.2.2 | We're not throughput-king | NONE strategic — different niche |

### What's NOT changed (still ahead-of-curve)

- **Vendor-analytics JSON mimicry** — public whitespace, no peer match. Both Xray and Hysteria2 are protocol-distinct, not application-mimic.
- **Live decoy reverse-proxy (T1.3 habr)** — we're literally the only ones doing rebrand-of-real-site decoy at this scope.
- **Body-prefix wire format** — cryptographically sound, version-binding.
- **Timing-matched failClosedToDecoy** — class-leading anti-probing.

---

## Action items в Tier ranking

### Tier S — adjust to новой landscape (1-3 days each)

| ID | Item | Rationale |
|---|---|---|
| **S.6** | **Mobile bandwidth budget mode** (client UI + lower-overhead protocol path) | RU 15GB cap пресс на mobile users; need user-visible bandwidth budget + option "save mode" disable cover GET / response inflation |
| **S.7** | **Split-tunnel guidance for Russian apps** (config doc + maybe IP exclusion list) | Endpoint VPN-detection в Yandex/VK/Сбер/Ozon. Документировать риск + supply default-exclusion list для known surveillance apps |

Tier S existing (R.1-R.5 from 2026-04-30 roadmap) **остаются приоритетом**, новые S.6/S.7 — additive, social/UX-centric.

### Tier A — throughput unchanged (existing A.1-A.4)

Без изменений из baseline. Hysteria2 Brutal — не наш бой, мы в HTTP-stealth нише.

### Tier B — adaptive stealth-vs-throughput unchanged

### Tier C — diversity & operational maturity (приоритезировано)

| ID | Item | Rationale (new) |
|---|---|---|
| **C.1** | **Domain Diversity activation in production** (already ready in code) | **Habr 1027276 datapoint:** RU CIDR whitelist /24 — multi-ASN origin spread становится FIRST-LINE defense |
| **C.5** (new) | **Domestic-ASN origin research** (Yandex Cloud / Selectel / VK Cloud LE-fronted egress) | Habr 1027276 §3 method demonstrates Yandex API Gateway viable. ShadowLink could expose origin service via 3rd-party Russian PaaS as one of multiple domains. Risk: legal/compliance — separate analysis |

### Tier D — strategic (some refresh, some new)

| ID | Item | Rationale |
|---|---|---|
| **D.5** (existing) | Web research новые TSPU 2026 capabilities | **DONE in this report** ✅ |
| **D.6** (new) | **Payload-layer PQ KEM evaluation** | Xray VLESS PR#5067 raises bar. Not urgent, but research timeline before Jan 2027 |
| **D.7** (new) | **Chromium-egress proxy variant research** | sing-box deprecation of uTLS challenges our reputation. Investigate NaiveProxy-style approach as optional adjunct (not replacement) |
| **D.8** (new) | **GREASE-aware self-test in CI** | Industry baseline JA3→JA4. Easy addition to fingerprint regression suite |
| **D.9** (refresh) | T1.5 Mixpanel schema lock | Now reinforced — endpoint detection apps + cross-correlated traffic mimicry threat |

### Tier "Don't bother"

- DTLS / WebRTC fallback for RU — **dead end** per net4people #603.
- Trojan-GFW protocol parity — **dead branch**.
- Pure-uTLS marketing positioning — **sing-box just deprecated this story**. Move to "honest limitations" framing.

---

## Risk recalibration vs 2026-04-22 baseline

| Threat | 2026-04-22 priority | 2026-05-01 priority | Δ |
|---|---|---|---|
| TSPU 15-20KB freeze | P0 | P0 | unchanged |
| ECH silent-drop | P0 | P0 | unchanged |
| RU CIDR whitelist | P1 (in baseline) | **P0** (Habr datapoint reinforces) | ↑ |
| RU mobile economic disincentive | not in baseline | **P1 social/UX** | NEW |
| RU endpoint app detection | not in baseline | **P1 out-of-band** | NEW |
| DTLS JA3/JA4 ban | speculative | **P0 confirmed** (closes DTLS routes) | NEW confirmed |
| CN ML traffic classification | P1 speculative | **P1 reported in news** (Trojan dead) | ↑ confirmation |
| sing-box uTLS deprecation | not relevant | **P2 reputational** | NEW |
| Xray VLESS payload-PQ | not relevant | **P2 architectural** | NEW |
| HTTP type65 GFW inject | not relevant | **P3 latent** | NEW |

Net effect: **2 confirmed P0 threats** (RU CIDR + DTLS), **2 new P1 social-layer threats** (15GB cap + endpoint detection), **3 P2-P3 architectural pressures** (uTLS deprecation, payload-PQ, type65 inject). Roadmap re-prioritization recommended: **C.1 (Domain Diversity) перейти в Tier S** учитывая Habr CIDR finding + DTLS ban (closing fallback routes).

---

## Open questions / honest unknowns

1. **Какой реальный enforcement rate** RU 15GB mobile cap, теперь когда отложен? Watch for May 2026 news.
2. **Whether Russian-ASN Yandex Cloud bunker plays well legally** для нашего use case. Compliance + ToS review требуется.
3. **Field-test ShadowLink через известные RU /24 CIDR whitelist** — есть ли user сообщающие о connectivity problems specifically related to ASN, не protocol?
4. **Whether sing-box anti-uTLS stance** будет принята mass-adoption тоже Xray, или это minority view. Нужен sentiment-watch на reddit/Telegram.
5. **DTLS JA3/JA4 ban — рост на TLS** возможен? Если RU начнёт TLS JA4 signature DB targeting (не только DTLS), наш Chrome_133+MLKEM custom spec может попасть в pattern. Watch net4people для follow-ups.

---

## Sources

### News / journalism

- [Russia’s internet censorship in 2026: VPN crackdowns, mobile shutdowns, Telegram blocks and the state messenger Max — Mediazona](https://en.zona.media/article/2026/04/07/russian_internet_censorship_2026)
- [The 16-kilobyte curtain. How Russia's new data-capping censorship is throttling Cloudflare — Mediazona](https://en.zona.media/article/2025/06/19/cloudflare)
- [Russia blocks VPN access to major platforms, moves to charge for mobile VPN traffic — Meduza](https://meduza.io/en/feature/2026/04/30/russia-blocks-vpn-access-to-major-platforms-moves-to-charge-for-mobile-vpn-traffic)
- [Russia's Planned VPN Traffic Charges Hit by Technical Delays — Vedomosti / Moscow Times](https://www.themoscowtimes.com/2026/04/22/russias-planned-vpn-traffic-charges-hit-by-technical-delays-vedomosti-a92570)
- [RBC: Russia asks major online platforms to block users with active VPNs by April 15 — Meduza](https://meduza.io/en/news/2026/04/02/rbc-russia-asks-major-online-platforms-to-block-users-with-active-vpns-by-april-15)
- [Russia is dialling up the pressure on VPNs – but stopping short of an outright ban — Tom's Guide](https://www.tomsguide.com/computing/vpns/russia-is-dialling-up-the-pressure-on-vpns-but-stopping-short-of-an-outright-ban)
- [Russia moves to 'reduce VPN usage' with new blocking, fines and fees — TechRadar](https://www.techradar.com/vpn/vpn-privacy-security/russia-moves-to-reduce-vpn-usage-with-new-blocking-fines-and-fees)
- [Russian Internet users are unable to access the open Internet — Cloudflare Blog](https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/)
- [VPN in Russia: New Mobile Restrictions from 2026 — russiable.com](https://russiable.com/russia-vpn-mobile-restrictions/)
- [Russia Is Building a Digital Great Firewall: TSPU Capacity to Grow 2.5x by 2030 — abit.ee](https://abit.ee/en/cybersecurity/tspu-asbi-internet-censorship-russia-traffic-filtering-dpi-runet-digital-ministry-internet-blocks-en)
- [Internet Traffic Filtering System in Russia to be Significantly Strengthened by 2030 — www1.ru](https://www1.ru/en/news/2026/03/25/sistemu-filtracii-internet-trafika-v-rossii-xotiat-serezno-usilit-k-2030-godu.amp.html)
- [ACF / FBK Internet Report Mar 2026](https://fbk.info/files/acf-internet-report-EN.pdf)
- [Internet loopholes: Russia struggles to block restricted online resources — Novaya Gazeta Europe](https://novayagazeta.eu/articles/2026/03/19/internet-loopholes-russia-struggles-to-block-restricted-online-resources-en-news)
- [Russia tightens its grip on internet access — Cybernews](https://cybernews.com/security/russia-blocks-cloudflare-protected-sites/)
- [bne IntelliNews — Russia's VPN crackdown disrupts banks](https://www.intellinews.com/russia-s-vpn-crackdown-disrupts-banks-marketplaces-and-government-services-439809/)
- [My phone is a brick: Russians scramble for information as data blocked — Al Jazeera](https://www.aljazeera.com/features/2026/3/26/my-phone-is-a-brick-russians-scramble-for-information-as-data-blocked)
- [Blocked and Bypassed: Russians Evade Internet Censorship — CEPA](https://cepa.org/article/blocked-and-bypassed-russians-evade-internet-censorship/)
- [Russia Begins Blocking VLESS VPN Protocol — Mezha](https://mezha.net/eng/bukvy/russia-begins-blocking-vless-vpn-protocol-increasing-internet-restrictions/)

### net4people / community tracking

- [net4people/bbs #603 — Snowflake-targeted DTLS filtering in Russia, starting 2026-03-30](https://github.com/net4people/bbs/issues/603)
- [net4people/bbs #605 — Russian government spyware/surveillance modules required to be integrated into popular programs](https://github.com/net4people/bbs/issues/605)
- [net4people/bbs #598 — HTTPS (type65) record injection rolled out in China](https://github.com/net4people/bbs/issues/598)
- [net4people/bbs #607 — China hijacked TLD .icu](https://github.com/net4people/bbs/issues/607)
- [net4people/bbs #586 — Iran Internet shutdown 2026-02-28](https://github.com/net4people/bbs/issues/586)
- [net4people/bbs #578 — TSPU architecture & operating principles](https://github.com/net4people/bbs/issues/578)
- [net4people/bbs #571 — TLSOS: Censorship Circumvention via CDNs](https://github.com/net4people/bbs/issues/571)
- [net4people/bbs #490 — RU TLS 1.3 + foreign-ASN TCP freeze](https://github.com/net4people/bbs/issues/490)
- [net4people/bbs #417 — RU blocking of Cloudflare ECH](https://github.com/net4people/bbs/issues/417)

### OSS releases / changelogs

- [XTLS/Xray-core releases](https://github.com/xtls/xray-core/releases)
- [Xray-core PR #5067 — VLESS Post-Quantum Encryption (RPRX)](https://github.com/XTLS/Xray-core/pull/5067)
- [XTLS/REALITY repository](https://github.com/XTLS/REALITY)
- [apernet/hysteria releases](https://github.com/apernet/hysteria/releases)
- [Hysteria 2 Changelog](https://v2.hysteria.network/docs/Changelog/)
- [SagerNet/sing-box releases](https://github.com/SagerNet/sing-box/releases)
- [sing-box Changelog](https://sing-box.sagernet.org/changelog/)
- [sing-box AnyTLS protocol docs](https://sing-box.sagernet.org/configuration/outbound/anytls/)
- [trojan-gfw/trojan repo](https://github.com/trojan-gfw/trojan)

### Habr articles (русский)

- [Habr 1027276 — Белые списки в России (zarazaex, 2026-04-25)](https://habr.com/ru/articles/1027276/)
- [Habr 1022112 — Yggdrasil Network (Revertis, April 11)](https://habr.com/ru/articles/1022112/)

### Academic / research

- [arXiv 2602.09606 — When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS Fingerprints (Feb 2026)](https://arxiv.org/html/2602.09606v1)
- [arXiv 2509.00706 — X-PRINT: Platform-Agnostic and Scalable Fine-Grained Encrypted Traffic Fingerprinting](https://arxiv.org/html/2509.00706)
- [arXiv 2510.07176 — Exposing LLM User Privacy via Traffic Fingerprint Analysis](https://arxiv.org/html/2510.07176v1)
- [arXiv 2109.03878 — Unsupervised Detection and Clustering of Malicious TLS Flows](https://arxiv.org/pdf/2109.03878)
- [Encrypted Network Traffic Analysis for Real-time Cybersecurity Threat Detection — IJRASET March 2026](https://www.ijraset.com/best-journal/encrypted-network-traffic-analysis-for-realtime-cybersecurity-threat-detection)
- [TLS Fingerprinting in 2026: JA3, JA4+, and the Death of Privacy? — packet.guru](https://packet.guru/blog/TLS-Fingerprinting-JA3-JA4)
- [TSPU: Russia's Decentralized Censorship System — IMC22](https://ensa.fi/papers/tspu-imc22.pdf)

### Industry / commercial (skeptical-handle)

- [Best VPNs for Russia 2026 — trustedvpnreviews.com](https://trustedvpnreviews.com/best-vpns-for-russia-2026/)
- [April 2026: China's Mass VPN Crackdown Explained — RelyVPN](https://relyvpn.com/blog/china-vpn-crackdown-2026.html)
- [Studying the Great Firewall's obfuscation and detection techniques — DEV Community](https://dev.to/mint_tea_592935ca2745ae07/bypassing-the-great-firewall-in-2026-active-filtering-protocol-obfuscation-37oj)
- [Russia's Internet Filtering Infrastructure: Evolution and Architecture — DEV.to](https://dev.to/shinomontaz/russias-internet-filtering-infrastructure-evolution-and-architecture-cel)

---

**Document status:** track 5 update-pass complete. Recommended consumer: roadmap maintainer + stakeholder review для C.1 promotion to Tier S и evaluation S.6/S.7/D.6/D.7/D.8 как backlog candidates.

# Track 5B Supplement — awesome-proxy aggregate repo scan (2026-05-01)

**Source:** https://github.com/drsoft-oss/awesome-proxy  
**Fetched:** 2026-05-01  
**Purpose:** Cross-reference against ShadowLink April baseline to surface new/missed items.

---

## Что в репо

Репозиторий — CC0-curated list с 14 коммитами, 50 stars, мейнтейнится drsoft-oss + anonymous-proxies.net.
Структура по группам:

| Группа | Примеры инструментов |
|--------|---------------------|
| Shadowsocks & variants | shadowsocks-libev, shadowsocks-rust, go-shadowsocks2, ShadowsocksR |
| Anti-detection / censorship | Xray-core (Reality), trojan-gfw, trojan-go, naiveproxy, sing-box |
| Anonymity networks | Tor, I2P, i2pd, OnionCat |
| WireGuard & VPN | wireguard-linux/go, algo, firezone, OpenVPN, IKEv2/IPsec |
| Forward proxies | goproxy, squid, mitmproxy, bytedance/g3proxy, XX-Net |
| Reverse proxies / LB | nginx, Caddy, Traefik, HAProxy, Envoy, pangolin, pipy |
| DNS proxies | dnscrypt-proxy, Pi-hole, AdGuardHome, Unbound |
| Proxy clients & GUI | Clash (mihomo), sing-box clients, v2rayA, v2rayN, hiddify, NekoBox |
| Proxy scrapers / validators | proxybench, proxyscrape, proxy-list aggregators |
| Web scraping with proxies | crawlee, scrapy, firecrawl, proxy-pool |

Репо не имеет "rating" как такового — автор даёт краткие аннотации без формального ранжирования. Ниже — все явные авторские оценки.

---

## Авторские комментарии и акценты

Прямые цитаты / near-quotes из аннотаций:

- **Xray-core** — "anti-detection tunneling" (Reality protocol). Явно выделен как state-of-the-art в категории censorship-resistant tools.
- **trojan-gfw** — "unidentifiable by DPI" (HTTPS mimicry). Один из двух инструментов с explicit anti-detection claim.
- **naiveproxy** — Chrome network stack camouflage (implicit anti-detection via realistic fingerprint).
- **shadowsocks-rust** — отмечен как "superior to C variant" по async I/O (performance edge, не anti-detection).
- **mihomo (MetaCubeX)** — "enhanced Clash with TUIC, Hysteria2, VLESS Reality" — позиционирован как современная замена классическому Clash.
- **sing-box** — "universal proxy platform" (Shadowsocks + V2Ray + Trojan + TUIC + Hysteria2). Отмечен как multi-protocol hub.
- **Free proxy lists** — явный caveat автора: "unreliable and slow." Категория не приоритетная.
- **drsoft-oss/proxyrotator** — "zero-drop connection draining, latency prioritisation" (собственный инструмент мейнтейнера).
- **bytedance/g3proxy** — ByteDance internal tool (HTTP/SOCKS/SNI + MITM), заслуживает внимания как production-grade.

Никакого сводного "use X for Y" сравнения автор не приводит. Позиция косвенно читается из порядка и аннотаций: Reality/sing-box/naiveproxy = modern tier, Shadowsocks-libev = canonical-legacy, WireGuard = solid baseline.

---

## 2026 highlights — что актуально

На основе аннотаций репо (без явных дат, но по контексту):

1. **Reality (Xray-core)** — безусловный reference point для anti-detection в этом агрегаторе. Наш baseline (апрель 2026) подтверждает: Xray v1.260206.0 с PQ по умолчанию, работает в RU с деградацией (15-20KB freeze bbs#490). Репо это не отражает — статичная curated list без changelog.

2. **mihomo (MetaCubeX/mihomo)** — в репо позиционирован как апгрейд Clash с Hysteria2 + VLESS Reality. Активно развивается, экосистема стабильна.

3. **sing-box (SagerNet/sing-box)** — Universal platform появляется в нескольких категориях (как сервер и как клиент). Это самый "full-stack" конкурент в репо: поддерживает почти все актуальные протоколы через единый конфиг.

4. **hiddify-app** — Multi-platform client на базе sing-box, упомянут как серьёзная cross-platform альтернатива v2rayN/NG.

5. **bytedance/g3proxy** — Production-grade proxy из ByteDance с SNI routing и MITM capability. В baseline апреля не упомянут. Интересен как reference для SNI-aware архитектуры.

6. **fosrl/pangolin** — "Identity-aware VPN" в категории reverse proxies. Новое имя, стоит иметь на радаре как self-hosted VPN + identity layer combo.

---

## Diff с April baseline (2026-04-22)

### Подтверждения (то что baseline уже покрывает)

| Инструмент из репо | Статус в April baseline |
|--------------------|------------------------|
| Xray-core + Reality | Зафиксирован как top-tier конкурент (Tier 1). PQ shipped февраль 2026. |
| Hysteria2 | Зафиксирован, оценён как degraded в RU/IR из-за QUIC blocking. |
| sing-box | Упомянут в контексте клиентских экосистем (NekoBox, hiddify). |
| naiveproxy | В baseline: "At parity with ShadowLink на уровне HTTP/2 mux". Chrome_139 (aug 2025). |
| trojan-gfw / trojan-go | В baseline: "active probing detection 90% within hours" (TSPU 2025-08). |
| AmneziaWG | В baseline: "strong в RU, 2.0 с dynamic headers март 2026". **В репо НЕ упомянут** — gap на стороне репо. |
| WebTunnel (Tor) | В baseline. **В репо** Tor упомянут только как anonymity network, без акцента на WebTunnel bridges. |

### Новые имена (не упомянутые в April baseline)

| Инструмент | Категория | Потенциальная релевантность для ShadowLink |
|------------|-----------|------------------------------------------|
| **bytedance/g3proxy** | SNI proxy + MITM | Reference для SNI-aware routing архитектуры. Не конкурент, но техническая ссылка. |
| **fosrl/pangolin** | Identity-aware VPN | Подход к identity + VPN layering. Архитектурно интересен для multi-tenant режима. |
| **flomesh-io/pipy** | Programmable proxy (IoT/edge) | Scripting на edge proxy. Не прямой конкурент. |
| **mihomo (MetaCubeX)** | Enhanced Clash client | Клиент поддерживает VLESS Reality + Hysteria2 + TUIC. Полезен как reference для client-side multi-protocol failover (наш Domain Diversity аналогичен). |
| **hiddify-app** | sing-box frontend | Multi-platform; если ShadowLink пойдёт в open-source, это конкурентная точка сравнения. |

### Gap: инструменты из baseline, которых нет в репо

Репо не покрывает:
- **AmneziaWG** (наш топ-конкурент в RU) — отсутствует полностью.
- **WebTunnel (Tor)** — упомянут только косвенно через Tor.
- **TUIC v5 / Juicity** — есть только через mihomo (не как отдельный проект).
- **v2ray-plugin** (обфускация поверх Shadowsocks) — в репо Shadowsocks-R, но не plugin.

Это ожидаемо: репо — общий прокси-агрегатор, не анти-цензурный специализированный.

---

## Direct links для peer-tools из ShadowLink-контекста

| Tool | URL |
|------|-----|
| Xray-core (Reality, PQ) | https://github.com/XTLS/Xray-core |
| sing-box | https://github.com/SagerNet/sing-box |
| mihomo (Enhanced Clash) | https://github.com/MetaCubeX/mihomo |
| naiveproxy | https://github.com/klzgrad/naiveproxy |
| trojan-gfw | https://github.com/trojan-gfw/trojan |
| trojan-go | https://github.com/p4gefau1t/trojan-go |
| shadowsocks-rust | https://github.com/shadowsocks/shadowsocks-rust |
| v2fly/v2ray-core | https://github.com/v2fly/v2ray-core |
| hiddify-app | https://github.com/hiddify/hiddify-app |
| bytedance/g3proxy | https://github.com/bytedance/g3proxy |
| fosrl/pangolin | https://github.com/fosrl/pangolin |
| NekoBoxForAndroid | https://github.com/MatsuriDayo/NekoBoxForAndroid |
| dnscrypt-proxy | https://github.com/jedisct1/dnscrypt-proxy |
| v2rayA | https://github.com/v2rayA/v2rayA |

---

## Выводы для ShadowLink roadmap

1. **Без сюрпризов по конкурентам.** Репо подтверждает April baseline: Reality + sing-box + naiveproxy = mainstream anti-detection trio. Новых прорывных протоколов с момента April не зафиксировано.

2. **sing-box как ecosystem hub** встречается в нескольких категориях — это сигнал что multi-protocol-через-единый-конфиг становится ожиданием рынка. Наш Domain Diversity (multi-domain failover) движется в этом направлении.

3. **bytedance/g3proxy** — единственное реально новое имя с архитектурной ценностью (SNI-aware + MITM). Полезен для изучения подходов к per-domain routing.

4. **Репо не отслеживает AmneziaWG** — что означает mainstream proxy-community ещё не интегрировал его в стандартный тулчейн. Это может быть конкурентное окно для ShadowLink.

5. **Репо не является свежим источником** (14 коммитов всего, без явных дат обновлений 2026). Использовать как general reference, не как leading-edge сигнал.

---

DONE: D:\NIXAVPN\shadowlink\docs\audit\2026-05-01-track5b-awesome-proxy-supplement.md

# T5 — Web Research 2026-05 (Final Audit)

**Cutoff:** 2026-05-03
**Citations:** 38
**Research areas:** TSPU+DPI 2026-05 | Reality/Vision evolution | Hysteria2 | JA4 cluster | PQ DPI | ML-decoy detection | Reference implementations
**Baseline:** `shadowlink/docs/research/2026-04-19-dpi-evasion-state-of-art.md` (40+ citations) и `shadowlink/docs/strategy/2026-04-22-strategic-assessment.md`. Ниже фокус только на **новом** материале с 2026-04-19 cutoff.

---

## Executive Summary

### Top 3 emerging threats since 2026-04-19 baseline

1. **AmneziaWG 2.0 ranged-headers/CPS feature parity gap (released 2026-03-25).** Дикие конкуренты ушли вперёд: каждый сервер AWG 2.0 имеет уникальные magic-headers (H1-H4) из настраиваемых ranges + CPS protocol mimicry под QUIC/DNS/SIP, плюс universal padding на ВСЕХ packet types (не только handshake). У ShadowLink padding частично distribution-decoupled (A2-HIGH-5), но wire-shape единый: один сервер = один TLS handshake шаблон. AWG-2.0 уже интегрирован в Windscribe и Nym. Источник [1][2].
2. **VLESS Encryption (PR #5067 / RPRX) — пост-квантовое VLESS *внутри* TLS.** Xray-core добавляет ML-KEM-768 + X25519 hybrid encryption на уровне VLESS-протокола (`mlkem768x25519plus.native.0rtt.…`) с 1-RTT PFS, anti-replay 0-RTT и встроенным padding. Это первый сценарий, где даже после raspberry-pi-style decryption proxy-сессия даст forward secrecy + 0-RTT. ShadowLink даёт PFS на уровне X25519 ECDH, но не имеет ML-KEM ВНУТРИ payload — только в ClientHello (за счёт uTLS Chrome_133). Источник [3][6].
3. **Flow correlation в encrypted proxies стал устойчив к size-padding (ProxyCorr, Computer Networks 2025).** Self-attention spatio-temporal модель работает «across diverse encrypted proxy protocols» с устойчивостью к random size padding. Это бьёт *именно* нашу A2-HIGH-5 padding distribution и part of T2.4 response inflation. Mitigation требует не статистического padding, а **timing-channel jitter** на уровне burst correlation (cross-layer RTT, Xue et al. NDSS'25). Источник [22][27].

### New techniques worth importing into ShadowLink: **5**
(P-classified findings ниже — 2× P0, 2× P1, 1× P2)

### ShadowLink coverage gaps surfaced: **5** (см. P-classified ниже).

---

## Section 1: TSPU/SORM Updates (2026-04 → 2026-05)

### 1.1 Habr article 990236 — "Clumsy hands or new DPI level?" (2026-02, refreshed для 2026-04)

Февраль 2026 РКН раскатал в регионах новые TSPU-сигнатуры. Ключевые наблюдения, не отражённые в апрельском baseline [4]:

- **Port 443 теперь is the trigger.** VLESS+Reality на порту 443 = instant drop / throttle to zero. Тот же конфиг на random high port (47000+) проходит до 80% packets. TSPU «too lazy» делать deep-inspection всех портов — экономит hardware. *Действие для ShadowLink:* мы захардкодены на 443 (см. `shadowlink/CLAUDE.md` ServerConfig defaults `:443`) → **P1 finding ниже**.
- **Empty SNI bypass в 100% случаев.** Removing the fingerprint (default Go fingerprint) тоже работает. Это парадоксально — обычно empty SNI = anomaly. Гипотеза автора: TSPU пишет «modify first bytes of TLS Client Hello или random bit-flip» — Chrome/Firefox через TCP retransmission восстановят, а Xray на Go falls back to non-decryptable.
- **Collateral: Selectel, Ru-VPS, Cloudflare IP-ranges попадают под whitelist у мобильных операторов (Yota, MegaFon).** Sber, Gosuslugi выпали из whitelist'а — пользователям нужно VPN, чтобы зайти в банк. Это означает: **white-list approach у мобильных операторов RU расширяется**, а не сужается.

### 1.2 Habr article 1009542 — "Как ТСПУ ловит VLESS в 2026 и почему XHTTP — следующий шаг"

Статья (март 2026) детализирует current TSPU detection vector [5]:
- **JA3 fingerprint detection продолжает работать.** Go's stdlib `crypto/tls` JA3 hash is in databases. Xray *без* uTLS fingerprint сразу выдаёт себя. Mitigation: жёстко привязать Chrome_133 fingerprint, что мы делаем (см. `shadowlink/skins/browser/fingerprint.go::LockedUTLSChromeID`).
- **Real Chrome inserts random GREASE extensions в ClientHello.** uTLS Chrome_133 *должен* делать GREASE, но без verification — потенциально gap.
- **WebSocket dies because of HTTP-Upgrade-then-bidirectional-stream pattern.** Это конкретный wire-pattern alarm. Наш WS pool делает именно так. **Это означает что WS pool is primary detection signal, even with Chrome_133 fingerprint** — XHTTP separately делает upload/download через separate HTTP transactions, что is "статистически неотличимо от browser loading content".
- **XHTTP recommended over WS уже сейчас.** Наша SplitHTTP fallback концептуально близка к XHTTP, но:
  - SplitHTTP fallback active только когда WS pool fails — primary path is WS.
  - У нас base64 + JSON envelope wrapping (33% overhead) против XHTTP's binary chunks.
  - У нас POST upload + streaming download через SAME endpoint — XHTTP отделяет upload domain от download domain (можно даже разные IPv4/IPv6 CDN).

### 1.3 net4people/bbs #578, #579 (2026-02)

- **#578 (Feb 20)** — AI-compiled TSPU operation manual (Russian) — academic-quality reference на architecture. Ссылка: `https://github.com/net4people/bbs/issues/578` [6].
- **#579 (Feb 23)** — Mobile network destination allowlisting threads. Active discussion supports что **whitelist на мобильных операторах продолжает расширяться**.

### 1.4 ASBI capacity scaling (2026-03, Kommersant)

Минцифры: TSPU/ASBI capacity → **954 Tbps к 2030**, бюджет ≈ $186M. На 2026: **100% Runet traffic пройдёт через ASBI** [7]. Mediazona (March 2026): магистраты в Москве и СПб начали штрафовать провайдеров за траффик мимо TSPU [9].

### 1.5 469 VPN services blocked (Feb 2026, HRW)

70% YoY growth в количестве заблокированных VPN-сервисов [10]. Geographic concentration: РФ ведёт.

---

## Section 2: Reality/Vision/XTLS Evolution (2026-04 → 2026-05)

### 2.1 VLESS Encryption (PR #5067) — major architectural shift

RPRX добавляет **post-quantum encryption layer внутри VLESS** (поверх REALITY/TLS) [3][6]:
- Configuration string: `mlkem768x25519plus.native.0rtt.100-111-1111.75-0-111.50-0-3333.<authkey>` — 5 dot-separated blocks: KE alg, encryption mode, session params, padding pattern, auth key.
- **Modes:** `native` (full transparency, use ReadV/Splice), `xorpub` (XOR public-key), `random` (5-byte header XORed; only 0.06% traffic affected).
- **Quantum-resistant rationale:** even if attacker captures ciphertext today, future quantum computer cannot decrypt. RPRX cites GFW blacklisting "fully random traffic" as motivation для `native` mode (TLSv1.3 record header pattern `23 3 3 l>>8 l AEAD`).
- **0-RTT replay protection** через session params.
- **Padding spec:** `padding.delay.padding.delay` alternating, variable length.

Discussion #5847 (March 2026): users asking should они enable VLESS Encryption *поверх* REALITY+XHTTP, or is mldsa65 in REALITY enough.

### 2.2 REALITY post-quantum signature (mldsa65)

REALITY теперь поддерживает **ML-DSA-65 signature verification** через optional `VerifyPeerCertificate` callback [3]. HMAC-SHA512(AuthKey, PublicKey) verified via mldsa65.Verify. Это закрывает quantum-resistant authentication, не только confidentiality.

### 2.3 XTLS Vision: forced UDP/443 → TCP fallback

xtls-rprx-vision flow перехватывает UDP/443 (QUIC) и **forces browsers to use standard HTTPS**, чтобы увеличить traffic, способный пройти Splice. Это elegant solution к QUIC SNI inspection issue, который мы deferrили (см. memory `quic-blocking-rf-2026.md`). У ShadowLink нет аналогичного UDP-suppression mechanism.

### 2.4 Текущий VLESS bypass status в РФ — сохраняется

Несмотря на TSPU pressure, **Reality + правильные настройки + Cloudflare CDN** остаётся «98% bypass в CN» и degraded-but-working в РФ (через chains). FBK report (March 2026) [8]: «most VPN providers responded by issuing new configurations to their users».

---

## Section 3: Hysteria2 Evolution

### 3.1 Hysteria 2.8.x release notes [11][12]

- **v2.8.2 (security):** crafted malicious QUIC packets могли вызвать server OOM при `sniff=enabled` — fixed. Salamander obfs thread-safety fix.
- **SNI guard:** server теперь terminate'ит TLS handshake если SNI не match'ит сертификат (default behavior). Configurable via `sniGuard` в `tls` секции.
- **Server-side sniffing:** HTTP, TLS (HTTPS), QUIC (HTTP/3) sniffing.
- **BBR variants:** standard / conservative / aggressive presets для congestion control.
- **Randomized port-hopping:** `minHopInterval`/`maxHopInterval` (server UDP port-range listening, Linux only через nftables/iptables).
- **xForwarded masquerade:** client теперь прикидывается reverse-proxy чтобы proxy-headers выглядели правдоподобно при masquerade mode.
- **ACME DNS challenge:** Cloudflare, GoDaddy, Name.com providers added.

### 3.2 Salamander obfuscation algorithm

QUIC-packets обёрнуты в random bytes pattern: `BLAKE2b-256(salt || PSK)` [12]. Это делает Hysteria2 incompatible со стандартным QUIC (теряет HTTP/3 server camouflage), но проходит DPI rule "block QUIC".

### 3.3 MASQUE/QUIC ecosystem 2026

Из reviews 2026 [13][14]: «Hysteria2 / MASQUE / TrustTunnel считаются best для high-risk censorship environments, давая naиболее indistinguishable traffic ценой operational complexity». Major clouds и CDN начали продавать managed MASQUE gateways корпоративно.

---

## Section 4: JA4 Cluster Analysis

### 4.1 Academic baseline shift — JA4DB-trained CatBoost (arXiv 2602.09606v1, Feb 2026)

Ключевая работа: **"When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS Fingerprints"** [15]:
- **Dataset:** real TLS fingerprints database JA4DB.
- **Models:** CatBoost AUC=0.998, F1=0.9734, accuracy 0.9863. XGBoost — почти идентично.
- **Most influential features:** `ja4_b` (cipher hash), `cipher_count`, `ext_count`. Меняя эти параметры — изменяется детектируемость.
- **Future work:** HTTP/3 fingerprinting + device-fingerprinting features.

**Implication для ShadowLink:** Chrome_133 даёт нам legitimate `ja4_b`, но **`cipher_count` и `ext_count` зависят от utls v1.8.3 build**, который не gets обновлён. Если CatBoost trained на JA4DB видит, что наш Chrome_133 fingerprint редкий в популяции (популяция уже Chrome 138+), мы попадаем в low-density region модели = подозреваемый bot.

### 4.2 JA4 vs JA3 — почему JA4 победил [16][17][18]

- **JA3 brittleness:** GREASE injection rotates extension order → static JA3 hash unreliable. Cipher stunting (просто перемешать cipher list) обходил детект.
- **JA4 design:** stable несмотря на extension reordering, encodes transport (TCP/QUIC), TLS version, SNI presence, cipher/ext counts, first ALPN, truncated SHA-256 hashes. **Не ломается от GREASE.**
- **2026 adoption:** Cloudflare, AWS, VirusTotal, NetWitness, Akamai, Zeek (Jan 2026 official integration) [19].

### 4.3 Detection-by-mismatch стало доминирующим

Modern WAFs (Cloudflare, Akamai, DataDome) больше не блокируют по static hash [20]:
- **User-Agent rarity:** «Does this JA4 hash typically claim to be Chrome 134?»
- **Protocol consistency:** TCP fingerprint says Linux, JA4 says iOS → bot.
- **Cross-layer:** TLS layer != HTTP headers → mismatch alarm.

**ShadowLink coverage:** sec-ch-ua, UA, JA4 — все pinned to Chrome 133 (NEW-2 fix from May audit). **Хорошо.** Однако CatBoost трогает population density, не только consistency. Это *новый* сигнал.

### 4.4 ECH meta-impact

ECH (Encrypted Client Hello) collapse'ит client-distinguishability metadata behind CDN [16]. Defenders forced shift from "metadata analysis" to **"behavioral analysis"** — request timing, volume, HTTP/3 vs HTTP/2 ratios. Это поднимает важность response inflation (T2.4) и cover GET (мы retiredretired в F3 follow-up — стоит **переоценить!** см. P0 finding ниже).

---

## Section 5: Post-Quantum DPI Signal

### 5.1 X25519MLKEM768 как fingerprint signal (early 2026)

Ключевые цифры [21]:
- **57.4% browser-initiated connections** к началу 2026 включают X25519MLKEM768 key share (1,088 bytes added).
- **Akamai:** PQ default для всех client-to-Akamai connections с **31 января 2026**. Full network rollout March 2026. **Отсутствие PQ key share = baseline anomaly**.
- **Chrome 131+ (Nov 2024):** PQ default. By Chrome 138, users не могут disable.
- **Firefox 135 (Feb 2025):** PQ default.
- **Apple ecosystem:** Oct 2025.
- **TLS codepoint:** 0x11EC (X25519MLKEM768) replaces 0x6399 (X25519+Kyber). Older clients стучат 0x6399 — это уже indicator legacy stack.

### 5.2 ML-KEM size / MTU effects

ML-KEM-768 public key ≈ 1.2 KB → ClientHello часто *не помещается* в один packet (MTU 1500). Some old TLS libraries crash on multi-packet ClientHello [21]. **Для ShadowLink это означает:** наша ClientHello через uTLS Chrome_133 + MLKEM (Phase 2 T1.1 закрытие) уже emits multi-packet handshakes — OK, мы alignned with реальной популяцией.

### 5.3 Hybrid scheme rationale

`X25519 || ML-KEM-768` соединяет classical curve + PQ KEM в одном key share. Защищает от:
- (а) classical attacks today (X25519);
- (б) "harvest now, decrypt later" quantum attacks.

### 5.4 Downgrade risk — PQ → x25519 fallback

State-of-the-art client может непреднамеренно fallback к X25519 (quantum-insecure) если server отвечает HelloRetryRequest неправильно. **Мониторинг для ShadowLink:** наш `SHADOWLINK_TLS_PQ=0` opt-out — это контролируемый downgrade, но **field логирование fallbacks** не сделано. Counter `shadowlink_tls_pq_handshake_total{result}` пишет success/fallback/error — нужно проверить, что server side актуально включает ML-KEM в обмене (см. Phase 2 closure).

### 5.5 Wire-effect: PQ adoption fundamentally shifts CDN baseline

Akamai's 31.01.2026 cutoff — **conceptual shift**: PQ-readiness теперь baseline, not premium. Любой proxy/scraper без PQ key share стучит до first HTTP byte [21]. Cloudflare PQ adoption ≈ 43% у legitimate human traffic уже к апрелю 2026 (per 2026-04-22 strategic assessment). **Тренд: бан клиентов без PQ через ~6 месяцев.**

---

## Section 6: ML-Based Decoy Detection

### 6.1 Transformer-based VPN/proxy detection (Scientific Reports, 2026)

**TPA-SSTM** (Temporal Patch Attention with Self-Supervised Traffic Masking) [22] — hybrid CNN-Transformer. Авторы прямо отмечают: «Existing deep learning models, primarily CNNs, are highly vulnerable to obfuscation techniques such as **WTF-PAD, Walkie-Talkie, Front**, which disrupt local burst signatures and degrade classification accuracy». Их новая модель устойчива.

Что это значит для нас: статистические padding/inflation tricks (T2.4, A2-HIGH-5, C6 padding shift) бьют CNN-baseline, но не Transformer-baseline. Detection переходит на attention-based architectures, которым local burst patterns не нужны — они смотрят long-range temporal dependencies.

### 6.2 ProxyCorr (Computer Networks, October 2025) — flow correlation attack

**Самая опасная работа для нас.** Авторы: «ProxyCorr, a model that achieves accurate traffic correlation across diverse encrypted proxy protocols» [27]. Ключевые insights:
- Modeling: network flows как state sequences + temporal dependencies через state transitions; spatial similarity через 2D trajectories + Gaussian filter (mitigates jitter).
- **Robustness: stable even under tunnel re-encapsulation and obfuscation techniques such as random size padding.** ← Это прямо про наш A2-HIGH-5 / C6 / T2.4.
- Self-attention correlation module + adaptive spatio-temporal feature integration.
- Tested across 3 encryption protocols без frequent retraining.

**Defense direction:** ProxyCorr использует state transitions across packets. Mitigation требует **inject false transitions** — шум на уровне когда client начинает / останавливает burst, что bias'ит state estimates. Не статистический padding, а **timing-channel jitter в burst boundaries**. Cross-layer RTT jitter (Xue NDSS'25, baseline) и AmneziaWG 2.0's pre-handshake noise packets — exact answers.

### 6.3 Multi-tab WF (ScienceDirect 2025, ACMF) [23]

Realistic threat model: пользователь open multiple tabs одновременно → inter-tab interference + temporal overlap. Attention-augmented LSTM (CBAM) + Transformer (DTAM) с per-slot gating. **Implication:** одиночный pure-tunnel flow (мы) выглядит ещё более anomalous т.к. real пользователи не "single flow stream".

### 6.4 SwitchTAD (2025) — defensive deployment in programmable switches

Defense, не attack [24]. RNN на data-plane P4 switches injects dummy packets per-packet decision. Не релевантно нам как разработчикам клиента, но индикатор: **arms race shifts от endpoint → in-network.** Если CDN провайдер deployит attack model — мы не можем убежать через client-side трюки.

### 6.5 NDSS 2026 evasion attack (Hard-Label Black-Box)

«A Hard-Label Black-Box Evasion Attack against ML-based Malicious Traffic Detection Systems» [25]. Полезно нам как defenders: даже без access к training data ML-based detector можно evade'ить. Конкретные техники TBD после full paper read.

### 6.6 LLM Network Intrusion Detection (arXiv 2510.23313, 2025) [26]

Survey говорит, что LLMs collaborate с classifiers — "agentic" multi-step reasoning над network traffic. Tier 2 threat для нас (когда attacker bandwidth-unlimited).

---

## Section 7: Reference Implementations

### 7.1 AmneziaWG 2.0 (released 2026-03-25) — **major competitive gap**

Новые features [1][2]:
- **Ranged headers (H1-H4):** каждый сервер уникален. Random magic-header from configurable range вместо fixed 32-bit message type (WireGuard signature).
- **CPS (Custom Protocol Signature):** builder, обворачивающий VPN traffic под legitimate UDP session profile (DNS / QUIC / SIP).
- **Signature Packets I1-I5:** look like DNS query / QUIC handshake / etc. — sent BEFORE real WireGuard handshake → DPI sees "legitimate UDP flow", не VPN handshake.
- **Pre-handshake noise (Jc series):** Jmin..Jmax pseudorandom packets blur timing+size profile of session start.
- **Universal padding:** before — only handshake variable-size; now ALL packets include padding (S1..S4 prefixes 0..32/64 bytes).
- **Cookie reply obfuscation:** message_type → magic header H3 + random padding prefix.
- **Crypto unchanged:** Noise_IK + Curve25519 + ChaCha20-Poly1305 (WireGuard mainline). Auth via MAC.
- **Linux kernel module + SIMD-optimized AEAD.** High performance.

**Adoption:** Windscribe, NymVPN integrate AWG 2.0 [2]. Tom's Guide calls это "fundamental shift". Independent tester: "successfully bypasses Russian DPI, at least for now".

**Coverage gap для ShadowLink:**
- ✅ uTLS Chrome_133 + MLKEM (analog of CPS for TCP)
- ✅ Per-domain pool (analog of "each server own dialect")
- ❌ **Pre-handshake noise** — у нас Warmup ≠ Jc. Warmup = real GETs к decoy, AWG 2.0 Jc = noise UDP packets. Concept similar, но AWG 2.0 рандомизирует packet count в run-time, мы — deterministic 1-4 GETs.
- ❌ **Universal padding на ВСЕХ message types.** У нас payload padding есть, но binary-frame headers (4-byte hint + 32-byte token) deterministic. **P1 finding.**
- ❌ **No analog of "ranged headers"** на per-server basis. Все ShadowLink-сервера share одинаковую wire-shape WS frames + одинаковый POST envelope. **P0 finding.**

### 7.2 V2Ray VMess-AEAD

VMess AEAD detected by GFW since Oct 2022 (false positive 0.6%, false negative ~0%) [29]. Conclusion в community: **drop random-looking protocols, switch to TLS-mimicry**. Не релевантно нам напрямую (мы и так TLS-mimic), но baseline для argumentation: «encryption only» = dead.

### 7.3 Shadowsocks-2022 (SIP022)

Crypto modernization: BLAKE3 KDF, full replay protection per-message-type, base64 PSK, no EVP_BytesToKey [28]. **Однако wire profile = random bytes stream** — fingerprintable by entropy analysis (printable-char ratio, popcount). Habr 2026 article рекомендует SS-2022 only because RKN focusing на VLESS. **Long-term: same fate как VMess-AEAD.**

ShadowLink advantage: мы НЕ random-bytes (мы JSON envelope под Mixpanel/GA4). Concept-level superior к SS-2022 для long-term. Но overhead price ~30%.

### 7.4 Conjure / Refraction Networking

Active dev на 2026-02-03 (`refraction-networking/conjure`), uTLS update Mar 11 2026 [30]. Deployed via Psiphon в Iran для нескольких миллионов users. Registration via domain-fronting fallback (since direct API blocked).

**Не релевантно нам как direct integration target** — refraction networking требует ISP cooperation вне РФ. Используется как inspiration: idea "registration over domain-fronting, data over normal flow" близка к нашей body-prefix v1 (auth in first frame, data via WS).

### 7.5 AnyTLS [31]

Released 2025-Q1, mainlined в sing-box 1.12+. Ключевые отличия от REALITY:
- **Configurable padding scheme** — string DSL: `[ "stop=8", "0=30-30", "1=100-400", "2=400-500,c,500-1000,c,500-1000,…", … ]`. Per-message size+timing schedule.
- **Idle session multiplexing.** Keep-warm sessions (default `idle_session_timeout=30s`) **reduces handshake fingerprinting** (handshakes — самая характерная часть TLS-in-TLS).
- **HTTP fallback for non-proxy probes.** Better чем REALITY's static SNI redirect.
- **uTLS fingerprinting on client side.** Standard.

**Coverage gap для ShadowLink:** наш handshake происходит **per-WS-slot** (× 8) на старте. Это 8 handshakes за короткий window — anomaly. AnyTLS amortizes это через session reuse. **P2 finding.**

### 7.6 MASQUE (RFC 9298) — CONNECT-UDP over HTTP/3

Production deployments: Cloudflare WARP, Apple Private Relay [32]. URI Template: `/.well-known/masque/udp/{target_host}/{target_port}/`. **Conceptually closest к ShadowLink архитектуре** — proxying *внутри* legitimate HTTP transaction. Difference: MASQUE uses HTTP/3 + extended CONNECT (handshake `:protocol = connect-udp`), мы — POST + WS upgrade.

**Длинно-term roadmap implication:** если QUIC eventually unblocked в РФ (вряд ли в 2026, но к 2027+ возможно), переход на MASQUE-shape сделает нас statistically indistinguishable от Apple Private Relay traffic. *Мониторинг.*

### 7.7 Oblivious DoH (RFC 9230)

Cloudflare + Apple production [33]. F5 BIG-IP enterprise integration Jan 2026. ODoH разделяет identity (proxy) и query content (resolver) через HPKE-encrypted messages. **Не proxy protocol для нас**, но importantly: ODoH обеспечивает что наш bypass routing (`shadowlink/client/bypassroute/`) для `.ru` domain resolution может работать без leak в TSPU — если клиент использует ODoH instead of regular DoH/DoT.

### 7.8 Geedge Networks / MESA Lab Leak (2025-09-11) — *the* event of late 2025

572 GiB GFW source code, deployed в CN + Kazakhstan + Pakistan + Myanmar + Ethiopia [34][35][36]. Academic analysis [37][38]:
- FOCI 2026 paper "Geedge Cases" published (peer-reviewed): documents censorship measurement insights.
- 39C3 talk "A Tale of Two Leaks" — relates к Wallbleed.
- **InterSecLab** — 9 months consortium analysis ongoing.
- **TSGX hardware:** Nettrix-based servers, sanctions-resilient interop.

**Implications для ShadowLink в 2026-Q3+:**
- **Detection rules will leak.** Specific entropy classifier (5-heuristic mentioned в 2026-04-22 baseline) likely originates in Geedge code. Future academic papers будут показывать exact rules.
- **Russian TSPU may borrow Geedge tech** через proxy contracts (already historical Belt-and-Road relationships).
- **Pre-emptive defensive posture:** не оптимизироваться под current rule set, потому что rules — moving targets after leak release. Investment в robust class of defenses (timing, distribution-shape) rather than specific signatures.

---

## P-Classified Findings (gaps в текущем ShadowLink)

### P0 — Hardcoded port 443 + SAME wire shape across all servers

**Source:** Habr 990236 [4] + AmneziaWG 2.0 ranged-headers concept [1].
**Threat:** TSPU "lazy" detection focuses на 443 (per Habr testimony). All ShadowLink servers share identical: WS endpoint paths, JSON envelope schema, binary frame layout `[hint(4)+token(32)+chunk]`, Mixpanel-mimic responses. ОДИН universal DPI rule срабатывает на ВСЕ наши инстансы. AmneziaWG 2.0 решает это: каждый сервер shapes traffic своим уникальным dialect.
**Current ShadowLink state:**
- `shadowlink/server/server.go` + `shadowlink/server/config.go` defaults `:443`.
- Per-domain pool *активирован* (Sub-phase D), но wire-shape единый.
- `shadowlink/client/transport.go`: same URL pool everywhere.
**Mitigation direction:**
- **(a)** Allow per-server alternate port via admin config (e.g., 47000-49999) + client config.
- **(b)** Per-server randomized URL path pool (хеш domain → 6-12 unique URL paths).
- **(c)** Per-server randomized binary-frame magic prefix (analog AWG H1-H4): random 1-4 bytes prepended to chunk header, specified в client domain pool config.

### P0 — Cover GET retired but ProxyCorr correlates flows even с padding

**Source:** ProxyCorr [27] + Habr 1009542 XHTTP analysis [5] + 2026-05-02 wire-trigger followup F3 (cover GET retire).
**Threat:** F3 pulled cover GET because peers (Reality/Hysteria2) ship without it. **Однако** ProxyCorr's spatial+temporal correlation works even через padding — needs *behavioral* counter-signals. ProxyCorr trains on encrypted proxies *with* padding, gets >X% accuracy. Habr подтверждает: WS-Upgrade-then-bidirectional pattern is detectable wire-pattern signature, separate from content padding.
**Current ShadowLink state:**
- `shadowlink/CLAUDE.md` says cover GET retired 2026-05-02 (F3 wire-trigger followup).
- WarmupRequests one-shot pre-WS-upgrade, 1-4 GETs.
- After WS upgrade: pure WS frames + occasional POST upload via SplitHTTP if pool fails.
**Mitigation direction:**
- НЕ возвращать periodic cover GET (он давал FFT signature) — instead **inject rare but high-volume browsing simulation bursts**: каждые 5-30 минут (heavy-tail distribution) launch "browser tab open" simulation: 5-15 GETs к decoy site, varying paths (`/blog/post-N`, `/static/img-N.jpg`, `/api/v2/search?q=X`), distributed timings 50-3000ms. Burst-and-quiet pattern мимикрирует real тab navigation. 
- Reconsider XHTTP-style upload/download split: separate domains для upload (POST) и download (long-poll GET) — даже HTTP-level это раскладывает single wire-shape на две различных, **breaking ProxyCorr's state-transition assumptions**.
- Cross-layer RTT jitter via app-layer artificial delays, applied to handshake POST and chunk ACKs. Already partially via `ackJitter()` (см. May audit C5) — but ProxyCorr would adapt against ACK-only jitter.

### P1 — Universal padding отсутствует на binary frame headers

**Source:** AmneziaWG 2.0 universal-padding feature [1].
**Threat:** Каждый WS frame в нашем pool has deterministic `[hint(4) + token(32) + encrypted_chunk]` layout. Token = always 32 bytes. Hint = always 4 bytes. Even if `encrypted_chunk` has variable padding (T2.4), **first 36 bytes have fixed structure**. Any DPI looking at WS payload sees `[36 bytes constant-shape header || variable_blob]` = signature.
**Current ShadowLink state:**
- `shadowlink/skins/browser/padding.go`: padding только на encrypted chunk size, не на frame structure.
- `shadowlink/server/websocket.go::authenticateFirstFrame`: parser hardcodes 4-byte hint + 32-byte token offsets.
**Mitigation direction:**
- Add variable-length leading padding `[pad(rand 0-32) || hint(4) || token(32) || encrypted_chunk]`. Random bytes ahead делают token offset variable per-frame. Server reads first byte as length и skips. Cost: 1-byte length field + ~16 bytes overhead.
- Optionally encrypt the hint+token themselves with session key (currently encrypted only chunk; hint and token are partially-cleartext indices and identifiers).

### P1 — JA4 cluster density vs Chrome 133 — population shift to 138+

**Source:** JA4DB CatBoost paper [15] + ML-KEM Chrome 131+ adoption stats [21].
**Threat:** uTLS v1.8.3 supports HelloChrome_133 как highest non-PSK ID. Real Chrome population in 2026 — Chrome 138+. Это значит наш JA4 sits в low-density cluster — рare → bot likelihood. Akamai's Jan 2026 PQ baseline shift cements это.
**Current ShadowLink state:**
- `shadowlink/skins/browser/fingerprint.go::LockedChromeMajor = 133`, hard-locked.
- utls upstream lacks Chrome_135+. Phase 2 closure F2 lockstep tied bogdanfinn + uTLS to Chrome_133.
**Mitigation direction:**
- **Upstream contribution:** PR to refraction-networking/utls добавить HelloChrome_138/146. Если accepted в utls v1.9+, флипнуть LockedChromeMajor.
- **Workaround:** custom ClientHelloSpec (как мы уже делаем для PQ MLKEM in `shadowlink/client/utls_http.go::pqClientHelloSpec`) для Chrome 138 features: новый extensions order, новые cipher additions (TLS_AES_128_CCM_SHA256?), новые ALPS values, etc. Trade-off: maintenance burden + risk of mistakes (one wrong byte = unique fingerprint).
- **Decision criterion:** field measurement what JA4 hash наши клиенты emit + сравнить с public JA4 distributions (https://ja4db.com).

### P2 — Per-WS-slot handshake amortization (AnyTLS-style session reuse)

**Source:** AnyTLS sing-box implementation [31].
**Threat:** WS pool of 8 slots означает 8 TLS handshakes за короткий window при slot rotation events. Каждый handshake — major fingerprint surface. Amortized handshakes (idle session reuse) делают per-handshake density меньше.
**Current ShadowLink state:**
- `shadowlink/client/ws_pool.go`, `shadowlink/client/ws_ready_pool.go`: per-slot independent connections.
- TLS session ticket reuse in stdlib utls — depends on transport reuse settings (default: ticket-based resumption when supported by server).
- No explicit session-reuse manager + idle keepalive batching.
**Mitigation direction:**
- Add **TLS session ticket cache** explicit in `ConnManager`. Resume on slot reconnect → 0-RTT handshake (1 packet instead of 4-5).
- AnyTLS-style "min-idle-session" config: hold N ready connections — reuse before opening new.
- Trade-off: 0-RTT has replay considerations; должны coordinate с WS first-frame auth replay window.

---

## Open Questions / Future Work

- **PQ flip impact на actual MLKEM rate.** We default-on, but `shadowlink_tls_pq_handshake_total{result="success"}` field rate after PQ flip — какая? Если success<99%, есть downgrade attacks.
- **Когда utls v1.9+ выйдет с Chrome_138+?** Tracking: https://github.com/refraction-networking/utls/releases. Без этого Chrome_133 lock-step становится detection signal сам по себе.
- **Geedge leak source code analysis status.** InterSecLab 9-month timeline ставит публикацию full analysis где-то 2026-Q3. После этого — wave of academic papers на specific TSPU/ASBI rules. **Pre-emptive: invest in distribution-shape defenses, not signature-specific.**
- **Should we adopt VLESS Encryption (PR #5067) shape?** PFS + 0-RTT + ML-KEM inside-payload — concept good. Implementation cost: high (replaces our X25519 ECDH layer). Не делать прямо сейчас, но monitoring upstream Xray adoption metrics.
- **Mobile client integration** для Android/iOS via NixaVPN orchestrator + `/api/v1/client/shadowlink/config` (already wired backend-side per Sub-phase C). Field deployment в SDK pending.

---

## Citations

- [1] gHacks Tech News — "Amnezia Releases AmneziaWG 2.0..." — https://www.ghacks.net/2026/03/25/amnezia-releases-amneziawg-2-0-to-bypass-advanced-internet-censorship-systems/ — accessed 2026-05-03
- [2] Tom's Guide — "AmneziaVPN launches AmneziaWG 2.0" — https://www.tomsguide.com/computing/vpns/amneziavpn-launches-amneziawg-2-0-and-its-a-fundamental-shift-from-its-predecessor — accessed 2026-05-03
- [3] XTLS/Xray-core PR #5067 — VLESS Post-Quantum ML-KEM-768 — https://github.com/XTLS/Xray-core/pull/5067 — accessed 2026-05-03
- [4] Habr article 990236 (en) — "Clumsy Hands or a New Level of DPI?" — https://habr.com/en/articles/990236/ — accessed 2026-05-03
- [5] Habr article 1009542 (ru) — "Как ТСПУ ловит VLESS в 2026 и почему XHTTP — следующий шаг" — https://habr.com/ru/articles/1009542/ — accessed 2026-05-03
- [6] XTLS/Xray-core Discussion #5847 — "VLESS Encryption + Reality + mldsa65 + XHTTP" — https://github.com/XTLS/Xray-core/discussions/5847 — accessed 2026-05-03
- [7] abit.ee (ASBI capacity scaling) — "Russia Is Building a Digital Great Firewall: TSPU Capacity to Grow 2.5x by 2030" — https://abit.ee/en/cybersecurity/tspu-asbi-internet-censorship-russia-traffic-filtering-dpi-runet-digital-ministry-internet-blocks-en — accessed 2026-05-03
- [8] FBK ACF Internet Report (March 2026) — https://fbk.info/files/acf-internet-report-EN.pdf — accessed 2026-05-03
- [9] Zona.media — "Russia's internet censorship in 2026" — https://en.zona.media/article/2026/04/07/russian_internet_censorship_2026 — accessed 2026-05-03
- [10] Human Rights Watch — "Disrupted, Throttled, and Blocked" — https://www.hrw.org/report/2025/07/30/disrupted-throttled-and-blocked/ — accessed 2026-05-03
- [11] Hysteria 2 official changelog — https://v2.hysteria.network/docs/Changelog/ — accessed 2026-05-03
- [12] Hysteria 2 protocol spec — https://v2.hysteria.network/docs/developers/Protocol/ — accessed 2026-05-03
- [13] factually.co — Best VPNs With QUIC or TLS Obfuscation (2026) — https://factually.co/product-reviews/electronics-tech/best-vpns-with-quic-tls-obfuscation-fallback-modes-2026-2df1ce — accessed 2026-05-03
- [14] vpn.how — "QUIC-based VPN: Future or Hype?" — https://vpn.how/en/pages/quic-based-vpn-future-or-hype-exploring-protocols-speed-and-bypassing-blocks.html — accessed 2026-05-03
- [15] arXiv 2602.09606v1 (Feb 2026) — "When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS Fingerprints" — https://arxiv.org/html/2602.09606v1 — accessed 2026-05-03
- [16] packet.guru — "TLS Fingerprinting in 2026: JA3, JA4+, and the Death of Privacy?" — https://packet.guru/blog/TLS-Fingerprinting-JA3-JA4 — accessed 2026-05-03
- [17] proxies.sx — "TLS Fingerprinting Guide 2026 | JA4+ Detection" — https://www.proxies.sx/use-cases/privacy/tls-fingerprint — accessed 2026-05-03
- [18] WebDecoy — "JA4 Fingerprinting: Detect AI Scrapers by TLS" — https://webdecoy.com/blog/ja4-fingerprinting-ai-scrapers-practical-guide/ — accessed 2026-05-03
- [19] Zeek — "How to Use JA4 Network Fingerprints in Zeek" (Jan 2026) — https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/ — accessed 2026-05-03
- [20] Cloudflare — "JA3/JA4 fingerprint" docs — https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/ — accessed 2026-05-03
- [21] Scrapfly — "Post-Quantum TLS: Why Scraping Tools Are Now Exposed" — https://scrapfly.io/blog/posts/post-quantum-tls-bot-detection — accessed 2026-05-03
- [22] Nature Scientific Reports (2026) — "Advanced website fingerprinting for detecting VPN-based censorship evasion: a transformer-based approach" — https://www.nature.com/articles/s41598-026-41976-4 — accessed 2026-05-03
- [23] ScienceDirect (2025) — ACMF Adaptive Context-Aware Multi-Tab WF — https://www.sciencedirect.com/science/article/pii/S1084804525002711 — accessed 2026-05-03
- [24] ScienceDirect (Dec 2025) — "SwitchTAD: Defending deep learning-based website fingerprinting attacks with programmable switches" — https://www.sciencedirect.com/science/article/abs/pii/S1389128625008874 — accessed 2026-05-03
- [25] NDSS 2026 — "A Hard-Label Black-Box Evasion Attack against ML-based Malicious Traffic Detection Systems" — https://www.ndss-symposium.org/ — accessed 2026-05-03
- [26] arXiv 2510.23313 (2025) — "Network Intrusion Detection: Evolution from Conventional Approaches to LLM Collaboration..." — https://arxiv.org/html/2510.23313v1 — accessed 2026-05-03
- [27] ScienceDirect (Oct 2025) — "ProxyCorr: robust traffic correlation attacks via mixed spatio-temporal analysis in encrypted proxy networks" — https://www.sciencedirect.com/science/article/abs/pii/S1389128625007297 — accessed 2026-05-03
- [28] Shadowsocks SIP022 docs — https://shadowsocks.org/doc/sip022.html — accessed 2026-05-03
- [29] net4people/bbs #136 — "Sharing a modified Shadowsocks..." — https://github.com/net4people/bbs/issues/136 — accessed 2026-05-03
- [30] refraction-networking/conjure GitHub — https://github.com/refraction-networking/conjure — accessed 2026-05-03
- [31] sing-box AnyTLS docs — https://sing-box.sagernet.org/configuration/outbound/anytls/ — accessed 2026-05-03
- [32] RFC 9298 — "Proxying UDP in HTTP" — https://datatracker.ietf.org/doc/html/rfc9298 — accessed 2026-05-03
- [33] Cloudflare blog — "Improving DNS Privacy with Oblivious DoH in 1.1.1.1" — https://blog.cloudflare.com/oblivious-dns/ — accessed 2026-05-03
- [34] gfw.report — "Geedge & MESA Leak: Analyzing the Great Firewall's Largest Document Leak" — https://gfw.report/blog/geedge_and_mesa_leak/en/ — accessed 2026-05-03
- [35] cybernews.com — "China's Great Firewall exposed: massive leak..." — https://cybernews.com/security/china-great-firewall-leak-exposes-global-exports/ — accessed 2026-05-03
- [36] hackread.com — "600 GB of Alleged Great Firewall of China Data..." — https://hackread.com/great-firewall-of-china-data-published-largest-leak/ — accessed 2026-05-03
- [37] FOCI 2026 — "Geedge Cases: Censorship Measurement Insights from the Geedge Networks Leak" — https://petsymposium.org/foci/2026/foci-2026-0006.pdf — accessed 2026-05-03
- [38] media.ccc.de 39C3 — "A Tale of Two Leaks: How Hackers Breached the Great Firewall" — https://media.ccc.de/v/39c3-a-tale-of-two-leaks-how-hackers-breached-the-great — accessed 2026-05-03

---

**Word count:** ~2700 words (target ≥1500 met).
**Citation count:** 38 (target ≥30 met).
**Status:** Ready for final-audit consolidation.

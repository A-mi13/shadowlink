# ShadowLink: Current State & Improvement Roadmap

**Дата:** 2026-04-30
**Статус:** Field-tested на datacanvases.com, обнаружены два data-plane drift бага → исправлены → работает.

---

## 1. Что у нас сейчас

### 1.1 Архитектура высокого уровня

```
┌─────────────┐         ┌──────────────────┐         ┌──────────────────┐
│   Client    │──TLS───▶│ Cloudflare edge  │──TLS───▶│  nginx (origin)  │
│ (Win/Linux) │  443    │  (orange cloud)  │  443    │  104.222.177.67  │
│             │         │  ИЛИ direct      │         │                  │
└─────────────┘         └──────────────────┘         │  ↓ unix socket   │
                                                      │  shadowlink-srv  │
                                                      └──────────────────┘
```

- **Текущий деплой:** `datacanvases.com` (104.222.177.67), CF orange cloud as fallback, sha=24d1edb4.
- **Direct mode:** client обращается напрямую к origin IP с TLS SNI=datacanvases.com (uTLS Chrome 133 + MLKEM768 PQ key share). По умолчанию активен — быстрее, без CF rate limits.
- **CF fallback mode:** если provider блокирует origin IP — переключение на CF edge IP. Sub-phase D Domain Diversity (multi-domain pool) задокументирован, но в проде не активирован.

### 1.2 Транспорты (multi-layered)

| Слой | Протокол | Назначение |
|------|----------|------------|
| Network | TCP/443 | Looks like HTTPS на 443 |
| TLS | TLS 1.3 + uTLS Chrome 133 + X25519MLKEM768 (PQ) | Browser-identical handshake, JA3/JA4 совпадает |
| Application | HTTP/1.1 + WebSocket | Multiple POST + 1 long-lived WS upgrade |
| Steganography | JSON analytics envelope `{"events":[{"type":"page_view","data":"<base64>"}]}` | Mimics Mixpanel/GA4 SDK |
| Crypto | X25519 ECDH → AES-256-GCM, NaCl Box for clientID | E2E encrypted, perfect forward secrecy |

### 1.3 Транспортные пути (3-tier)

1. **WS Pool** (primary) — 8 параллельных WebSocket соединений, каждое с собственной session, balanced load. После handshake — binary frames `[hint(4) + token(32) + encrypted_chunk]`, **минимальный overhead ~1-2%**.
2. **SplitHTTP fallback** — если WS pool fails: разделение upload (POST) + download (long-running streaming GET). Использует JSON-envelope обёртку с base64 → overhead больше (~33%).
3. **POST-poll fallback** — последняя линия защиты, если streaming не работает: client посылает POST'ы, сервер отвечает encrypted chunks в response body.

### 1.4 Anti-DPI features (что закрыто)

| Угроза | Защита | Источник fix |
|---|---|---|
| Static signature TLS handshake | uTLS HelloChrome_133 + PQ MLKEM768 | T1.1 (Phase 2) |
| Static signature URL paths | URL pool ротация (`/api/v2/events`, `/api/v2/telemetry`, etc.) | Phase B |
| Replay attack handshake | ReplayCache по encClientID nonce, sliding-window 5min | 2026-04-30 fix |
| Replay attack data chunks | Per-session sliding bitmap window 16384 seq | core/session.go |
| ML behavior — request cadence | Cover GET requests sticky ratio 0.25-0.45 | T1.6 (Phase 2) |
| ML behavior — response sizes | Response inflation log-normal distribution + sticky next_poll Pareto | T2.4 (Phase 3 Plan A) |
| Active probing | failClosedToDecoy на любую невалидную форму, decoy site `/blog/*` через rebranded habr | T1.3 |
| Timing fingerprint (proxy gap) | ackJitter 18ms exp distribution | V6 audit fix |
| BroadcastClose serial slowdown | errgroup parallel close, 2s SLA для 10k tunnels | T1.7 (Phase 2) |
| Padding correlation | Handshake/data padding distributions decoupled (KS D=0.3710) | A2-HIGH-5 |
| Bearer header retire | Phase 0 closure, all data through body-prefix | 2026-04-26 |
| WS Bearer auth retire | First-frame auth, 1.5s timeout | 2026-04-26 |

### 1.5 Operational state

- **Server:** datacanvases.com:443, sha=24d1edb4, systemd unit + nginx reverse proxy
  (⚠ снимок на 2026-04-30; сверка 2026-08-07: проксирование идёт на TCP
  `127.0.0.1:10443`, а не на unix-сокет — CDN-ветка тоже более неактуальна)
- **Client binary:** `bin/nixavpn-client.exe` 51 MB, Apr 30 20:36, fixes shipped
- **Tests:** все unit + integration зелёные (`./client/`, `./server/`, `./core/`)
- **Известная VPS лимитация:** превышен лимит трафика → throttle от хостера → cascade failures под нагрузкой. **Это не код, это hosting-уровень.**

---

## 2. Известные слабые места

### 2.1 Throughput

- **Pareto-frontier:** ShadowLink впереди REALITY/XTLS-Vision при behavioral DPI, но позади Hysteria2/QUIC по raw line-rate.
- **WS pool real overhead:** ~1-2% на 12KB chunks (малый).
- **SplitHTTP fallback overhead:** ~33% (base64 + JSON wrap). Проявляется только когда pool deead.
- **CONNECT round-trip:** 100-400ms на новый stream open. Optimistic CONNECT_OK уже есть.
- **AckJitter:** 18ms на каждый ack response — намеренно для timing evasion. Cumulative effect на RTT-критичных протоколах.
- **Response inflation:** +20-40% bandwidth на download path. Намеренно для ML evasion.

### 2.2 Resilience

- **Reconnect storm под throttle:** 8 slots × cascading reconnect → handshake rate limit hit → all dies. Backoff 800ms initial → too aggressive.
- **Single-slot starvation:** если N-1 slot dies, oставшийся 1 ловит всю нагрузку → pending=200+ → uplink errors.
- **No graceful degradation:** SplitHTTP fallback не активируется когда **часть** pool жива но overloaded.
- **TLS state corruption (наблюдалось):** WS reader получает `RSV1/2/3 set + bad opcode` под throttle — traffic shaper hostera ломает byte alignment в TLS records. Slot dies, reader exits cascade.
- **Domain diversity не активна:** sub-phase D код есть, но в проде один домен. Если domain blocked — нет автоматического failover.

### 2.3 Operational

- **Ручной деплой:** safe-redeploy через admin UI работает, но требует ручного клика. Нет canary автоматики.
- **Mobile client:** `/api/v1/client/shadowlink/config` endpoint готов, но интеграция в мобильное приложение не done.
- **Live decoy ops:** habr proxy через `/blog/*` работает, метрики экспортируются, но dashboard ещё не настроен в проде.
- **Metrics retention:** `/metrics?format=prom` экспонирует, scraper в админке ходит каждые 60s, retention 7 дней. Нет долгосрочного хранения.

---

## 3. Roadmap улучшений

Приоритет: **stealth × resilience × throughput**, в этом порядке. На геополитике 2026 stealth важнее throughput.

### Tier S — Resilience hotfixes (критично, 1-3 дня каждое)

| ID | Item | Cost | Effect |
|---|---|---|---|
| **R.1** | Slow-start reconnect (5s base, max 60s, не 800ms exp) | 1д | Предотвращает handshake rate limit storm |
| **R.2** | Adaptive SplitHTTP fallback при `ready_slots < poolSize/2` (parallel, не replace) | 2д | Graceful degradation вместо cascading death |
| **R.3** | Per-slot health watcher: detect RSV-bits / TLS corruption → kill slot до overload остальных | 2д | Изоляция аномального slot'а |
| **R.4** | Server: per-clientID handshake rate limit (separate from per-IP), для авторизованных clients +1000/min | 1д | Legit reconnect не попадает в general rate limit |
| **R.5** | Bursty connect coalescing: дождаться 50ms перед `assignStream` чтобы не дублировать stream до одного dest | 1д | Снижает SOCKS5 connection storm |

### Tier A — Throughput (без потери stealth)

| ID | Item | Cost | Effect |
|---|---|---|---|
| **A.1** | Adaptive chunk size: bump 12KB → 32-64KB при detected bulk transfer | 2д | +5-10% throughput на streams >1MB |
| **A.2** | Stream-of-chunks pipeline: 2-4 chunks per WS message при backlog | 3д | -RTT overhead, +5-15% uplink |
| **A.3** | Buffer pool в encrypt path (zero-copy AES-GCM) | 1д | -10% CPU |
| **A.4** | Pre-warmed CONNECT cache к популярным destinations (TG, Google CDN) | 3д | -300ms tail на first byte |

### Tier B — Throughput (с adaptive snipping stealth)

| ID | Item | Cost | Effect |
|---|---|---|---|
| **B.1** | Adaptive ackJitter: off на bulk transfers (>5s sustained) | 2д | +50-150ms ниже RTT |
| **B.2** | Adaptive response inflation: off на streams >1MB | 2д | +20-40% download throughput |

### Tier C — Diversity & operational maturity

| ID | Item | Cost | Effect |
|---|---|---|---|
| **C.1** | Активировать Sub-phase D Domain Diversity в проде, multi-domain pool | 2д | Failover при blocked domain |
| **C.2** | Mobile client integration с `/shadowlink/config` API | 5д | iOS/Android поддержка |
| **C.3** | Auto-canary deploy: новый бинарь → 1% users → metrics → 100% | 5д | Безопасная раскатка |
| **C.4** | Long-term metrics storage (Prometheus + Grafana) | 3д | Видимость trend'ов в проде |

### Tier D — Strategic (требует spec/design сессии)

| ID | Item | Cost | Effect |
|---|---|---|---|
| **D.1** | Live decoy expansion: больше реальных rebranded sites (не только habr) | 7д | Plausibility +1, harder для probe-based detection |
| **D.2** | T1.5 Mixpanel schema lock — pin event JSON shape под актуальную Mixpanel SDK | 5д | Closes phantom signal — ML на event structure |
| **D.3** | T1.2 binary transport — отказ от base64+JSON для data path (только handshake mimikry) | 14д | Throughput +30%, но **retired ранее** как phantom signal — ТСПУ не парсит body |
| **D.4** | Multi-protocol concurrent (REALITY + ShadowLink на одном клиенте, выбор по latency probe) | 14д | Fastest-wins, перешагивает single-protocol weakness |
| **D.5** | Web research новых TSPU 2026 capabilities — обновить threat model | 3д | Roadmap recalibration |

---

## 4. Рекомендуемый порядок работ

**Если приоритет = stability в проде сейчас:**
1. R.1 (slow-start reconnect) — 1д
2. R.2 (adaptive SplitHTTP fallback) — 2д
3. R.3 (slot health watcher) — 2д
4. R.4 (per-clientID handshake limit) — 1д

ИТОГО Tier S: ~6 дней работы → значительный jump в reliability.

**Если приоритет = "переплюнуть всех" по throughput:**
- Tier S фундамент сначала (resilience должна быть надёжной)
- Затем A.1 + A.2 + A.3 = ~6д
- B.1 опционально

**Если приоритет = долгосрочная stealth позиция:**
- Tier S (1 неделя)
- D.5 web research обновление threat model (3д)
- C.1 Domain Diversity активация (2д)
- D.1 Live decoy expansion (1 неделя)

---

## 5. Открытые вопросы для сессии завтра

1. **Throttle hostера** — переходим на другой VPS или меняем тариф? Влияет на R.1/R.2 design.
2. **Mobile client integration** — приоритет vs новые server-side improvements?
3. **REALITY parallel** (D.4) — стратегически интересно, но 2 недели работы; стоит ли?
4. **Throughput target** — какой реальный SLA нужен? 50 Mbps? 200? 500?
5. **Domain Diversity** — есть ли резервный домен (Cloudflare account, домены готовы к настройке)?

---

## 6. Reference

- Server fix shipped 2026-04-30: replay cache key clientID → encClientID (memory `data-plane-drift-2026-04-30.md`)
- Client fix shipped 2026-04-30: WS pool `_v` parsing (memory `data-plane-drift-2026-04-30.md`)
- Phase 2 closure 2026-04-28: PQ ClientHello default-on
- Phase 3 Plan A 2026-04-28: server-only audit closures
- Domain Diversity series done 2026-04-30: A+B+C+D (memory `domain-diversity-complete.md`)
- Master roadmap: `docs/strategy/2026-04-22-strategic-assessment.md` (Tier 1, 7 items)
- Audit baseline: `docs/audit/2026-04-25-final-review-*` (4 audits)
